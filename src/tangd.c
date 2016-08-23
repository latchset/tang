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
#include "http.h"

#include <systemd/sd-journal.h>
#include <systemd/sd-daemon.h>
#include <systemd/sd-event.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/un.h>

#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define TIMEOUT 60000000ULL
#define UDP_MAX 65507
#define TCP_BUF 4096

#define container(ptr, type, field) \
    ((type *)((char *)(ptr) - offsetof(type, field)))

struct link {
    struct link *next;
    struct link *prev;
};

struct address {
    union {
        struct sockaddr_storage storage;
        struct sockaddr_in6 in6;
        struct sockaddr_in in;
        struct sockaddr_un un;
        struct sockaddr addr;
    };

    socklen_t len;
};

struct connection {
    struct link link;

    sd_event_source *time;
    sd_event_source *io;
    char buf[TCP_BUF];
    size_t len;

    struct http_request request;
    struct http_parser parser;
    struct address addr;
};

_EXPORT_ struct tang_plugin_map *tang_plugin_maps = NULL;

static const int sigs[] = { SIGPIPE, SIGTERM, SIGINT };
static struct link conns = { &conns, &conns };
static int nfds;

static void
conn_close(struct connection *conn)
{
    if (!conn)
        return;

    conn->link.next->prev = conn->link.prev;
    conn->link.prev->next = conn->link.next;

    if (conn->io)
        close(sd_event_source_get_io_fd(conn->io));
    sd_event_source_unref(conn->time);
    sd_event_source_unref(conn->io);
    free(conn->request.body);
    free(conn->request.path);
    free(conn);

    if (--nfds == 0) {
        sd_event *e = NULL;

        if (sd_event_default(&e) >= 0)
            sd_event_exit(e, EXIT_SUCCESS);
    }
}

static const char *METHOD_NAMES[] = {
#define XX(num, name, string) [num] = # string,
HTTP_METHOD_MAP(XX)
#undef XX
    NULL
};

static const char *
addr2str(struct address *addr)
{
    static char buf[INET6_ADDRSTRLEN] = {};

    switch (addr->addr.sa_family) {
    case AF_INET6:
        return inet_ntop(AF_INET6, &addr->in6.sin6_addr, buf, sizeof(buf));
    case AF_INET:
        return inet_ntop(AF_INET, &addr->in.sin_addr, buf, sizeof(buf));
    case AF_UNIX:
        return addr->un.sun_path;
    default:
        return "UNKNOWN";
    }
}

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
on_time(sd_event_source *s, uint64_t usec, void *userdata)
{
    conn_close(userdata);
    return 0;
}

static int
on_data(sd_event_source *s, int fd, uint32_t revents, void *userdata)
{
    struct connection *conn = userdata;
    char pkt[UDP_MAX] = {};
    ssize_t r = 0;

    if (revents & (EPOLLERR | EPOLLHUP | EPOLLRDHUP))
        goto egress;

    r = recv(fd, &conn->buf[conn->len], sizeof(conn->buf) - conn->len, 0);
    if (r < 0) {
        r = -errno;
        goto egress;
    }

    conn->len += r;

    r = http_parser_execute(&conn->parser, &tang_parser_settings,
                            conn->buf, conn->len);
    if (conn->parser.http_errno != 0) {
        r = -EINVAL;
        goto egress;
    }

    conn->len -= r;
    memmove(conn->buf, &conn->buf[r], conn->len);

    if (!conn->request.done)
        return 0;

    sd_journal_print(LOG_DEBUG, "S %s => %s %s",
                     addr2str(&conn->addr),
                     METHOD_NAMES[conn->parser.method],
                     conn->request.path);

    r = on_http(conn->parser.method, &conn->request, pkt, sizeof(pkt));
    if (r > 0)
        send(fd, pkt, r, 0);

egress:
    conn_close(conn);
    return r < 0 ? r : 0;
}

static int
on_conn(sd_event_source *s, int fd, uint32_t revents, void *userdata)
{
    sd_event *e = s ? sd_event_source_get_event(s) : userdata;
    struct connection *conn = NULL;
    uint64_t usec = 0;
    int sock = -1;
    int r = 0;

    r = sd_event_now(e, CLOCK_MONOTONIC, &usec);
    if (r < 0)
        return r;

    conn = calloc(1, sizeof(*conn));
    if (!conn)
        return -ENOMEM;

    http_parser_init(&conn->parser, HTTP_REQUEST);
    conn->parser.data = &conn->request;
    conn->addr.len = sizeof(conn->addr);

    if (!userdata) {
        sock = accept(fd, &conn->addr.addr, &conn->addr.len);
    } else {
        sock = fd;
        if (getpeername(fd, &conn->addr.addr, &conn->addr.len) < 0)
            sock = -1;
    }

    if (sock < 0) {
        free(conn);
        return -errno;
    }

    conn->link.next = conns.next;
    conn->link.prev = &conns;
    conns.next->prev = &conn->link;
    conns.next = &conn->link;

    if (s)
        nfds++;

    r = sd_event_add_io(e, &conn->io, sock, EPOLLIN | EPOLLRDHUP | EPOLLPRI,
                        on_data, conn);
    if (r < 0) {
        conn_close(conn);
        return r;
    }

    r = sd_event_add_time(e, &conn->time, CLOCK_MONOTONIC,
                          usec + TIMEOUT, TIMEOUT, on_time, conn);
    if (r < 0) {
        conn_close(conn);
        return r;
    }

    return 0;
}

static int
on_pckt(sd_event_source *s, int fd, uint32_t revents, void *userdata)
{
    struct address addr = { .len = sizeof(addr.storage) };
    struct http_request request = {};
    struct http_parser parser = {};
    char pkt[UDP_MAX] = {};
    ssize_t r = 0;

    http_parser_init(&parser, HTTP_REQUEST);
    parser.data = &request;

    r = recvfrom(fd, pkt, sizeof(pkt), 0, &addr.addr, &addr.len);
    if (r < 0)
        return -errno;

    r = http_parser_execute(&parser, &tang_parser_settings, pkt, r);
    if (parser.http_errno != 0 || !request.done) {
        free(request.path);
        free(request.body);
        return -EINVAL;
    }

    sd_journal_print(LOG_DEBUG, "D %s => %s %s",
                     addr2str(&addr),
                     METHOD_NAMES[parser.method],
                     request.path);

    r = on_http(parser.method, &request, pkt, sizeof(pkt));
    free(request.path);
    free(request.body);
    if (r < 0)
        return r;

    sendto(fd, pkt, r, 0, &addr.addr, addr.len);
    return 0;
}

static int
plugin_load(const char *path, const char *cfg, void **dll)
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
        r = func(cfg);
        if (r < 0) {
            fprintf(stderr, "Plugin init error: %s: %s\n", path, strerror(-r));
            dlclose(*dll);
            *dll = NULL;
            return r;
        }
    }

    return 0;
}

static int
setup_signals(sd_event *event)
{
    sigset_t ss;
    int r;

    if (sigemptyset(&ss) < 0)
        return -errno;

    for (size_t i = 0; i < sizeof(sigs) / sizeof(*sigs); i++) {
        if (sigaddset(&ss, sigs[i]) < 0)
            return -errno;
    }

    if (sigprocmask(SIG_BLOCK, &ss, NULL) < 0)
        return -errno;

    for (size_t i = 0; i < sizeof(sigs) / sizeof(*sigs); i++) {
        r = sd_event_add_signal(event, NULL, sigs[i], NULL, NULL);
        if (r < 0)
            return r;
    }

    return 0;
}

static int
setup_sockets(sd_event *event)
{
    int r = -EINVAL;

    nfds = sd_listen_fds(1);
    if (nfds <= 0) {
        fprintf(stderr, "No sockets provided! Try systemd-socket-activate.\n");
        return -ENOTCONN;
    }

    for (int i = 0; i < nfds; i++) {
        int fd = SD_LISTEN_FDS_START + i;

        if (sd_is_socket(fd, AF_UNSPEC, SOCK_DGRAM, false)) {
            r = sd_event_add_io(event, NULL, fd, EPOLLIN, on_pckt, NULL);
        } else if (sd_is_socket(fd, AF_UNSPEC, SOCK_STREAM, true)) {
            r = sd_event_add_io(event, NULL, fd, EPOLLIN, on_conn, NULL);
        } else if (sd_is_socket(fd, AF_UNSPEC, SOCK_STREAM, false)) {
            r = on_conn(NULL, fd, EPOLLIN, event);
        } else {
            fprintf(stderr, "Unsupported socket provided!\n");
            r = -ENOTSUP;
        }

        if (r < 0)
            break;
    }

    return r;
}

int
main(int argc, char *argv[])
{
    sd_event __attribute__((cleanup(sd_event_unrefp))) *e = NULL;
    void *dlls[argc / 2 + 1];
    int r = 0;

    memset(dlls, 0, sizeof(dlls));

    if (argc < 2 || argc % 2 != 1) {
        fprintf(stderr, "Usage: %s MOD CFG [MOD CFG ...]\n", argv[0]);
        return EXIT_FAILURE;
    }

    r = sd_event_default(&e);
    if (r < 0)
        goto egress;

    for (size_t i = 0; (int) i * 2 + 1 < argc; i++) {
        r = plugin_load(argv[i * 2 + 1], argv[i * 2 + 2], &dlls[i]);
        if (r < 0)
            goto egress;
    }

    r = setup_signals(e);
    if (r >= 0) {
        r = setup_sockets(e);
        if (r >= 0)
            r = sd_event_loop(e);
    }

egress:
    for (size_t i = 0; dlls[i]; i++)
        dlclose(dlls[i]);

    while (conns.next != &conns)
        conn_close(container(conns.next, struct connection, link));

    return r == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
