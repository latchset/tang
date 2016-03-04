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

#include <sys/epoll.h>
#include <sys/socket.h>

#include <errno.h>
#include <error.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "srv.h"

#define LISTEN_FD_START 3

struct addr {
  struct sockaddr addr;
  socklen_t size;
};

static int fds;

static void
onsig(int sig)
{
    for (int i = 0; i < fds; i++)
        close(i + LISTEN_FD_START);
}

static int
req(int sock, TANG_MSG **req, void *misc)
{
    struct addr *addr = misc;
    pkt_t pkt = {};

    addr->size = sizeof(addr->addr);
    pkt.size = recvfrom(sock, pkt.data, sizeof(pkt.data), 0,
                        &addr->addr, &addr->size);
    if (pkt.size < 0)
        return EAGAIN;

    *req = d2i_TANG_MSG(NULL, &(const uint8_t *) { pkt.data }, pkt.size);
    return *req ? 0 : EAGAIN;
}

static int
rep(int sock, const pkt_t *pkt, void *misc)
{
    struct addr *addr = misc;
    sendto(sock, pkt->data, pkt->size, 0, &addr->addr, addr->size);
    return 0;
}

int
main(int argc, char *argv[])
{
    const char *dbdir = TANG_DB;
    const char *lfds = NULL;
    struct addr addr = {};
    int epoll;
    int r;

    for (int c; (c = getopt(argc, argv, "hd:")) != -1; ) {
        switch (c) {
        case 'd':
            dbdir = optarg;
            break;

        default:
            fprintf(stderr, "Usage: %s [-h] [-d DBDIR]\n", argv[0]);
            return EXIT_FAILURE;
        }
    }

    epoll = epoll_create(1024);
    if (epoll < 0)
        error(EXIT_FAILURE, errno, "Error calling epoll_create()");

    /* Setup listening sockets. */
    lfds = getenv("LISTEN_FDS");
    if (!lfds)
        error(EXIT_FAILURE, 0, "No listening sockets");

    errno = 0;
    fds = strtol(lfds, NULL, 10);
    if (errno != 0 || fds == 0)
        error(EXIT_FAILURE, errno, "Invalid LISTEN_FDS: %s", lfds);

    for (int i = 0; i < fds; i++) {
        int fd = i + LISTEN_FD_START;

        if (epoll_ctl(epoll, EPOLL_CTL_ADD, fd, &(struct epoll_event) {
            .events = EPOLLIN | EPOLLRDHUP | EPOLLPRI,
            .data.fd = fd
        }) != 0)
            error(EXIT_FAILURE, errno, "Error calling epoll_ctl()");
    }

    signal(SIGTERM, onsig);
    signal(SIGINT, onsig);

    r = srv_main(dbdir, epoll, req, rep, &addr, -1);
    if (r != 0)
        error(EXIT_FAILURE, r, "Error calling srv_main()");

    close(epoll);
    return 0;
}
