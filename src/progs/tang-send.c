/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab: */
/*
 * Copyright (c) 2015 Red Hat, Inc.
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

#include "srv.h"
#include <limits.h>

#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <ctype.h>
#include <error.h>
#include <errno.h>
#include <getopt.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>

#include <signal.h>

#define _stringify(x) # x
#define stringify(x) _stringify(x)

static int s = -1;

static void
onsig(int sig)
{
    close(s);
}

static int
parse(char *argx, const char **hostname, const char **port)
{
    static char tmp[PATH_MAX];

    strncpy(tmp, argx, sizeof(tmp));

    for (ssize_t i = strlen(tmp) - 1; i >= 0; i--) {
        if (isdigit(tmp[i]))
            continue;

        if (tmp[i] != ':')
            break;

        if (tmp[i+1] == '\0')
            return EINVAL;

        if (strchr(tmp, ':') == &tmp[i]) {
            *hostname = tmp;
            *port = &tmp[i + 1];
            tmp[i] = '\0';
            return 0;
        }

        if (tmp[0] == '[' && tmp[i - 1] == ']') {
            *hostname = &tmp[1];
            *port = &tmp[i + 1];
            tmp[i - 1] = '\0';
            return 0;
        }

        *hostname = tmp;
        *port = stringify(TANG_PORT);
        return 0;
    }

    *hostname = tmp;
    *port = stringify(TANG_PORT);
    return 0;
}

static int
req(int sock, TANG_MSG **req, void *misc)
{
    const unsigned char *position = NULL;
    pkt_t *pkt = misc;
    int r;

    r = recv(sock, &pkt->data[pkt->size], sizeof(pkt->data) - pkt->size, 0);
    if (r < 0) return errno;
    if (r == 0) return 0;
    pkt->size += r;

    position = pkt->data;
    *req = d2i_TANG_MSG(NULL, &position, pkt->size);
    if (!*req)
        return pkt->size == sizeof(pkt->data) ? EINVAL : EAGAIN;

    pkt->size -= position - pkt->data;
    memmove(pkt->data, position, pkt->size);
    return 0;
}

static int
rep(int sock, const pkt_t *pkt, void *misc)
{
    pkt_t out = *pkt;
    ssize_t r = 0;

    while (out.size > 0) {
        r = send(sock, out.data, out.size, 0);
        if (r < 0)
            return errno;

        memmove(out.data, &out.data[r], out.size - r);
        out.size -= r;
    }

    return 0;
}

int
main(int argc, char *argv[])
{
    const char *dbdir = TANG_DB;
    const char *host = NULL;
    const char *port = NULL;
    int timeout = 10000;
    pkt_t pkt = {};
    int epoll = -1;
    int r;

    signal(SIGTERM, onsig);
    signal(SIGINT, onsig);

    for (int c; (c = getopt(argc, argv, "hd:t:")) != -1; ) {
        switch (c) {
        case 'd':
            dbdir = optarg;
            break;

        case 't':
            errno = 0;
            timeout = strtol(optarg, NULL, 10);
            if (errno == 0)
                break;

        default:
            fprintf(stderr,
                    "Usage: %s [-h] [-d DBDIR] [-t timeout] host[:port]\n",
                    argv[0]);
            return EXIT_FAILURE;
        }
    }

    epoll = epoll_create(1024);
    if (epoll < 0)
        error(EXIT_FAILURE, errno, "Error calling epoll_create()");

    for (int i = optind; i < argc; i++) {
        r = parse(argv[i], &host, &port);
        if (r != 0)
            error(EXIT_FAILURE, r, "Invalid host/port: %s", argv[i]);
    }

    for (int i = optind; i < argc && s < 0; i++) {
        struct addrinfo *infos;

        r = parse(argv[i], &host, &port);
        if (r != 0)
            error(EXIT_FAILURE, r, "Invalid host/port: %s", argv[i]);

        r = getaddrinfo(host, port, &(struct addrinfo) {
            .ai_family = AF_UNSPEC,
            .ai_socktype = SOCK_STREAM,
        }, &infos);
        if (r != 0)
            error(EXIT_FAILURE, r, "Resolution failed: %s", argv[i]);

        for (struct addrinfo *info = infos; info; info = info->ai_next) {
            s = socket(info->ai_family, info->ai_socktype, info->ai_protocol);
            if (s < 0)
                continue;

            r = connect(s, info->ai_addr, info->ai_addrlen);
            if (r == 0) {
                if (epoll_ctl(epoll, EPOLL_CTL_ADD, s, &(struct epoll_event) {
                    .events = EPOLLIN | EPOLLRDHUP | EPOLLPRI,
                    .data.fd = s
                }) != 0)
                    error(EXIT_FAILURE, errno, "Error calling epoll_ctl()");

                if (srv_main(dbdir, epoll, req, rep, &pkt, timeout) != 0)
                    error(EXIT_FAILURE, r, "Error during srv_main()");
                close(s);
                break;
            }

            fprintf(stderr, "Error connecting to %s\n", argv[i]);
            close(s);
            s = -1;
        }

        freeaddrinfo(infos);
    }

    close(epoll);
    return s < 0;
}
