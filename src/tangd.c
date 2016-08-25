/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */
/*
 * Copyright (c) 2016 Red Hat, Inc.
 * Author: Nathaniel McCallum <npmccallum@redhat.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "plugin.h"

#include <http_parser.h>

#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/un.h>

#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define UDP_MAX 65507

struct http_request {
    char *path;
    size_t plen;

    char *body;
    size_t blen;

    bool  done;
};

static int
on_url(http_parser *parser, const char *at, size_t length)
{
    struct http_request *req = parser->data;

    if (!req->path)
        req->path = (char *) at;

    req->plen += length;
    return 0;
}

static int
on_body(http_parser *parser, const char *at, size_t length)
{
    struct http_request *req = parser->data;

    if (!req->body)
        req->body = (char *) at;

    req->blen += length;
    return 0;
}

static int
on_message_complete(http_parser *parser)
{
    struct http_request *req = parser->data;
    req->done = true;
    return 0;
}

static const http_parser_settings parser_settings = {
    .on_url = on_url,
    .on_body = on_body,
    .on_message_complete = on_message_complete,
};

_EXPORT_ struct tang_plugin_map *tang_plugin_maps = NULL;

static const char *METHOD_NAMES[] = {
#define XX(num, name, string) [num] = # string,
HTTP_METHOD_MAP(XX)
#undef XX
    NULL
};

static ssize_t
on_http(enum http_method method, struct http_request *request,
        char pkt[], size_t pktl)
{
    bool pathmatch = false;
    bool methmatch = false;
    const char *msg = NULL;
    int status = 0;
    ssize_t r = 0;

    for (struct tang_plugin_map *m = tang_plugin_maps; m && r == 0; m = m->next) {
        regmatch_t match[m->nmatches];
        regex_t re = {};

        memset(match, 0, sizeof(match));

        r = regcomp(&re, m->re, REG_EXTENDED) == 0 ? 0 : -EINVAL;
        if (r == 0) {
            if (regexec(&re, request->path, m->nmatches, match, 0) == 0) {
                pathmatch = true;

                if (((1 << method) & m->methods) != 0) {
                    methmatch = true;

                    r = m->func(request->path, match,
                                request->body, method,
                                pkt, pktl);
                }
            }

            regfree(&re);
        }
    }

    if (r > 0 && r <= (int) pktl) {
        return r;
    } else if (r == 0) {
        if (!pathmatch) {
            status = 404;
            msg = "Not Found";
        } else if (!methmatch) {
            status = 405;
            msg = "Method Not Allowed";
        } else {
            status = 500;
            msg = "Internal Server Error";
        }
    } else {
        status = 500;
        msg = "Internal Server Error";
    }

    snprintf(pkt, pktl,
             "HTTP/1.1 %d %s\r\n"
             "Connection: close\r\n"
             "\r\n", status, msg);
    return strlen(pkt);
}

static int
plugin_load(int epoll, const char *path, const char *cfg, void **dll)
{
    typeof(tang_plugin_init) *func = NULL;
    int r = 0;

    *dll = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (!*dll) {
        fprintf(stderr, "Plugin load error: %s: %s\n", path, dlerror());
        return -ENOENT;
    }

    func = dlsym(*dll, "tang_plugin_init");
    if (func) {
        r = func(epoll, cfg);
        if (r < 0) {
            fprintf(stderr, "Plugin init error: %s: %s\n", path, strerror(-r));
            dlclose(*dll);
            *dll = NULL;
            return r;
        }
    }

    return 0;
}

int
main(int argc, char *argv[])
{
    static const int sigs[] = { SIGPIPE, SIGTERM, SIGINT };
    struct http_request request = {};
    struct http_parser parser = {};
    void *dlls[argc / 2 + 1];
    const char *addr = NULL;
    char rep[UDP_MAX] = {};
    char req[UDP_MAX] = {};
    size_t read = 0;
    size_t prsd = 0;
    int epoll = -1;
    sigset_t ss;
    int r = 0;

    http_parser_init(&parser, HTTP_REQUEST);
    memset(dlls, 0, sizeof(dlls));
    addr = getenv("REMOTE_ADDR");
    parser.data = &request;

    if (argc < 2 || argc % 2 != 1) {
        fprintf(stderr, "Usage: %s MOD CFG [MOD CFG ...]\n", argv[0]);
        return EXIT_FAILURE;
    }

    if (sigfillset(&ss) < 0)
        return EXIT_FAILURE;

    if (sigprocmask(SIG_SETMASK, &ss, NULL) < 0)
        return EXIT_FAILURE;

    for (size_t i = 0; i < sizeof(sigs) / sizeof(*sigs); i++) {
        if (sigdelset(&ss, sigs[i]) < 0)
            return EXIT_FAILURE;
    }

    epoll = epoll_create1(EPOLL_CLOEXEC);
    if (epoll < 0)
        return EXIT_FAILURE;

    for (size_t i = 0; (int) i * 2 + 1 < argc; i++) {
        r = plugin_load(epoll, argv[i * 2 + 1], argv[i * 2 + 2], &dlls[i]);
        if (r < 0)
            goto egress;
    }

    r = epoll_ctl(epoll, EPOLL_CTL_ADD, STDIN_FILENO,
                  &(struct epoll_event) { .events = EPOLLIN | EPOLLPRI });
    if (r < 0) {
        fprintf(stderr, "Error setting adding IO listener.\n");
        goto egress;
    }

    for (struct epoll_event event = {};
         epoll_pwait(epoll, &event, 1, -1, &ss) == 1; ) {
        tang_plugin_epoll func = event.data.ptr;

        if (func) {
            func();
            continue;
        }

        if (event.events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP))
            break;

        if (sizeof(req) - read - 1 == 0)
            break;

        r = recv(STDIN_FILENO, &req[read], sizeof(req) - read - 1, 0);
        if (r < 0)
            break;
        read += r;

        r = http_parser_execute(&parser, &parser_settings,
                                &req[prsd], read - prsd);
        if (parser.http_errno != 0) {
            r = -EINVAL;
            break;
        }
        prsd += r;

        if (!request.done)
            continue;

        if (request.path)
            request.path[request.plen] = 0;

        if (request.body)
            request.body[request.blen] = 0;

        fprintf(stderr, "D %s => %s %s\n",
                addr ? addr : "<unknown>",
                METHOD_NAMES[parser.method],
                request.path);

        r = on_http(parser.method, &request, rep, sizeof(rep));
        if (r > 0)
            send(STDOUT_FILENO, rep, r, 0);

        read -= prsd;
        memmove(req, &req[prsd], read);
        memset(&request, 0, sizeof(request));
    }

egress:
    for (size_t i = 0; dlls[i]; i++)
        dlclose(dlls[i]);

    close(epoll);
    return r == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
