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

#include "srv/srv.h"
#include <limits.h>

#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <ctype.h>
#include <error.h>
#include <errno.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>
#include <argp.h>
#include <signal.h>
#include <sysexits.h>

#define _STR(x) # x
#define STR(x) _STR(x)
#define SUMMARY 192

struct options {
    const char *dbdir;
    const char *host;
    const char *svc;
    time_t timeout;
};

const char *argp_program_version = VERSION;

static int s = -1;

static void
onsig(int sig)
{
    close(s);
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

static error_t
parser(int key, char* arg, struct argp_state* state)
{
    struct options *opts = state->input;

    switch (key) {
    case SUMMARY:
        fprintf(stderr, "Send a key to a listening client");
        return EINVAL;

    case 'd':
        opts->dbdir = arg;
        return 0;

    case 't':
        opts->timeout = atoi(arg);
        return 0;

    case ARGP_KEY_ARG:
        if (!opts->host)
            opts->host = arg;
        else if (!opts->svc)
            opts->svc = arg;
        else
            return ARGP_ERR_UNKNOWN;

        return 0;

    case ARGP_KEY_END:
        if (!opts->host) {
            fprintf(stderr, "Host MUST be specified!\n\n");
            argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
            return EINVAL;
        }

        if (opts->timeout < 1 || opts->timeout > 600) {
            fprintf(stderr, "Invalid timeout value\n\n");
            argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
            return EINVAL;
        }

        if (!opts->dbdir)
            opts->dbdir = TANG_DB;

        if (!opts->svc)
            opts->svc = STR(TANG_PORT);

        return 0;

    default:
        return ARGP_ERR_UNKNOWN;
    }
}

int
main(int argc, char *argv[])
{
    struct options opts = { .timeout = 10 };
    const struct argp argp = {
        .options = (const struct argp_option[]) {
            { "summary", SUMMARY, .flags = OPTION_HIDDEN },
            { "dbdir", 'd', "dir", .doc = "database directory" },
            { "timeout", 't', .doc = "timeout (between 1 and 600 seconds" },
            {}
        },
        .parser = parser,
        .args_doc = "HOSTNAME [SERVICE]"
    };
    struct addrinfo *infos = NULL;
    pkt_t pkt = {};
    int epoll = -1;
    int r;

    signal(SIGTERM, onsig);
    signal(SIGINT, onsig);

    if (argp_parse(&argp, argc, argv, 0, NULL, &opts) != 0)
        return EX_OSERR;

    epoll = epoll_create(1024);
    if (epoll < 0)
        return EX_IOERR;

    r = getaddrinfo(opts.host, opts.svc, &(struct addrinfo) {
        .ai_family = AF_UNSPEC,
        .ai_socktype = SOCK_STREAM,
    }, &infos);
    if (r != 0) {
        fprintf(stderr, "Resolution failed: %s %s\n", opts.host, opts.svc);
        goto error;
    }

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
                goto error;

            if (srv_main(opts.dbdir, epoll, req, rep,
                         &pkt, opts.timeout * 1000) != 0)
                goto error;
            close(s);
            break;
        }

        fprintf(stderr, "Error connecting to %s %s\n", opts.host, opts.svc);
        close(s);
        s = -1;
    }

error:
    freeaddrinfo(infos);
    close(epoll);
    return s < 0 ? EX_IOERR : 0;
}

