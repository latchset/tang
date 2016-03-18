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

#include "msg.h"
#include "../core/pkt.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <string.h>
#include <unistd.h>

TANG_MSG *
msg_rqst(const msg_t *params, const TANG_MSG *req)
{
    const struct addrinfo hint = { .ai_socktype = SOCK_DGRAM };
    struct addrinfo *res = NULL;
    TANG_MSG *msg = NULL;
    size_t naddr = 0;
    pkt_t out = {};

    if (pkt_encode(req, &out) != 0)
        return NULL;

    for (int r = 1; r != 0; ) {
        r = getaddrinfo(params->hostname, params->service, &hint, &res);
        if (r != 0 && r != EAI_AGAIN)
            return NULL;
    }

    for (const struct addrinfo *ai = res; ai; ai = ai->ai_next)
        naddr++;
    if (naddr < 1 || naddr > 99) {
        freeaddrinfo(res);
        return NULL;
    }

    struct pollfd ifds[naddr];
    int timeout = params->timeout * 1000 / naddr / 3;

    naddr = 0;
    for (const struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        ifds[naddr].events = POLLIN | POLLPRI;
        ifds[naddr].fd = socket(ai->ai_family,
                                ai->ai_socktype,
                                ai->ai_protocol);
        if (ifds[naddr].fd < 0)
            continue;

        if (connect(ifds[naddr].fd, ai->ai_addr, ai->ai_addrlen) != 0)
            continue;

        naddr++;
        for (size_t i = 0; i < 3; i++) {
            struct pollfd ofds[naddr];
            int r = 0;

            send(ifds[naddr - 1].fd, out.data, out.size, 0);

            memcpy(ofds, ifds, sizeof(struct pollfd) * naddr);
            r = poll(ofds, naddr, timeout > 5 ? timeout : 5);
            for (int j = 0; j < r; j++) {
                pkt_t in = {};

                if ((ofds[j].revents & (POLLIN | POLLPRI)) == 0)
                    continue;

                in.size = recv(ofds[j].fd, &in.data, sizeof(in.data), 0);
                if (in.size <= 0)
                    continue;

                msg = pkt_decode(&in);
                if (msg)
                    goto egress;
            }
        }
    }

egress:
    for (size_t j = 0; j < naddr; j++)
        close(ifds[j].fd);

    freeaddrinfo(res);
    return msg;
}

int
msg_save(const TANG_MSG *msg, const char *filename)
{
    pkt_t out = {};
    ssize_t r = 0;
    int fd = 0;

    r = pkt_encode(msg, &out);
    if (r != 0)
        return r;

    fd = open(filename, O_WRONLY | O_CREAT);
    if (fd < 0)
        return errno;

    for (ssize_t wr = 0; wr < out.size; wr += r) {
        r = write(fd, &out.data[wr], out.size - wr);
        if (r < 1) {
            r = r < 0 ? errno : EIO;
            close(fd);
            return r;
        }
    }

    close(fd);
    return 0;
}

TANG_MSG *
msg_read(const char *filename)
{
    pkt_t in = {};
    int fd = 0;

    fd = open(filename, O_RDONLY);
    if (fd < 0)
        return NULL;

    if (read(fd, in.data, sizeof(in.data)) < 0) {
        close(fd);
        return NULL;
    }

    close(fd);

    return pkt_decode(&in);
}
