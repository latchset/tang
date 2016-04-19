/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */
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

#define _GNU_SOURCE
#include "iface.h"

#include <errno.h>
#include <unistd.h>

#include <netinet/in.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>

static int
request_existing(int sock, int family)
{
    struct {
        struct nlmsghdr h;
        struct rtmsg m;
    } req = {
        { NLMSG_LENGTH(sizeof(struct rtmsg)),
          RTM_GETROUTE, NLM_F_REQUEST | NLM_F_DUMP, 0, getpid() },
        { family }
    };

    return send(sock, &req, sizeof(req), 0);
}

int
iface_new(struct pollfd *fd)
{
    struct sockaddr_nl addr = {
        .nl_family = AF_NETLINK,
        .nl_groups = RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_ROUTE
    };

    fd->events = POLLIN | POLLPRI;
    fd->fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (fd->fd < 0)
        return errno;

    if (bind(fd->fd, (struct sockaddr *) &addr, sizeof(addr)) < 0)
        return errno;

    (void) request_existing(fd->fd, AF_INET);
    (void) request_existing(fd->fd, AF_INET6);

    return 0;
}

bool
iface_new_route(struct pollfd *fd)
{
    struct nlmsghdr buf[256];
    size_t bytes;
    int len;

    if ((fd->revents & fd->events) == 0)
        return false;
    fd->revents = 0;

    while ((len = read(fd->fd, buf, sizeof(buf))) < 0) {
        if (errno != EAGAIN)
            return false;
    }

    bytes = len;
    for (struct nlmsghdr *msghdr = buf;
         NLMSG_OK(msghdr, bytes) && msghdr->nlmsg_type != NLMSG_DONE;
         msghdr = NLMSG_NEXT(msghdr, bytes)) {
        struct rtmsg *rtmsg = NLMSG_DATA(msghdr);

        switch (msghdr->nlmsg_type) {
        case RTM_NEWROUTE:
            switch (rtmsg->rtm_type) {
            case RTN_LOCAL:
            case RTN_UNICAST:
                return true;
            }
        }
    }

    return false;
}
