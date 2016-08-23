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

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <pthread.h>

#define REP_PRFX "HTTP/1.1 200"

union address {
    struct sockaddr_storage storage;
    struct sockaddr_in6 in6;
    struct sockaddr_in in;
    struct sockaddr addr;
};

struct param {
    union address addr;
    const char *pckt;
    int type;
    int secs;
};

struct state {
    const struct param *param;
    size_t count;
};

static pthread_barrier_t barrier;

static double
gettime(void)
{
    struct timespec ts = {};

    if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0)
        return 0.0;

    return ((double) ts.tv_sec) + ((double) ts.tv_nsec) / 1000000000;
}

static void *
thread(void *misc)
{
    struct state *state = misc;
    const ssize_t size = strlen(state->param->pckt);
    char rep[65536] = {};
    double end = 0.0;
    double now = 0.0;
    int fd = -1;

    pthread_barrier_wait(&barrier);

    end = gettime();
    if (end == 0)
        goto egress;

    end += state->param->secs;

    for (now = gettime(); now > 0.0 && now < end; now = gettime()) {
        ssize_t r = 0;

        if (fd < 0) {
            fd = socket(state->param->addr.addr.sa_family,
                        state->param->type, 0);
            if (fd < 0)
                goto egress;

            r = connect(fd, &state->param->addr.addr,
                        sizeof(state->param->addr));
            if (r < 0)
                goto egress;
        }

        r = send(fd, state->param->pckt, size, 0);
        if (r != size)
            goto egress;

        r = recv(fd, rep, sizeof(rep), 0);
        if (r <= (ssize_t) strlen(REP_PRFX))
            goto egress;

        if (strncmp(rep, REP_PRFX, strlen(REP_PRFX)) != 0)
            goto egress;

        if (state->param->type == SOCK_STREAM) {
            close(fd);
            fd = -1;
        }

        state->count++;
    }

egress:
    if (fd >= 0)
        close(fd);
    return now > end ? state : NULL;
}

static bool
run_test(size_t ncpus, const struct param *param)
{
    bool fail = false;
    size_t cnt = 0;

    ncpus *= 2;
    pthread_t threads[ncpus];
    struct state states[ncpus];

    memset(threads, 0, sizeof(threads));
    memset(states, 0, sizeof(states));

    if (pthread_barrier_init(&barrier, NULL, ncpus + 1) < 0)
        return false;

    for (size_t i = 0; i < ncpus; i++) {
        states[i].param = param;
        if (pthread_create(&threads[i], NULL, thread, &states[i]) < 0) {
            pthread_barrier_destroy(&barrier);

            for (size_t j = 0; j < i; j++)
                pthread_cancel(threads[j]);

            for (size_t j = 0; j < i; j++)
                pthread_join(threads[j], NULL);

            return false;
        }
    }

    pthread_barrier_wait(&barrier);
    pthread_barrier_destroy(&barrier);

    for (size_t i = 0; i < ncpus; i++) {
        void *out = NULL;
        pthread_join(threads[i], &out);
        fail |= out == NULL;
        cnt += states[i].count;
    }

    if (!fail)
        fprintf(stderr, "requests: %zu / sec\n", cnt / param->secs);

    return !fail;
}

int
main(int argc, char *argv[])
{
    char pckt[65536] = {};
    char *port = NULL;
    char *addr = NULL;
    long ncpus = 0;

    struct param param = {
        .pckt = pckt,
        .secs = 3
    };

    for (int c; (c = getopt(argc, argv, "hsd46a:p:")) >= 0; ) {
        switch (c) {
        case 'h': goto usage;
        case 's': param.type = SOCK_STREAM; break;
        case 'd': param.type = SOCK_DGRAM; break;
        case '4': param.addr.addr.sa_family = AF_INET; break;
        case '6': param.addr.addr.sa_family = AF_INET6; break;
        case 'p': port = optarg; break;
        case 'a': addr = optarg; break;
        default:
            fprintf(stderr, "Invalid option: %c!\n", c);
            goto usage;
        }
    }

    if (!port || !addr)
        goto usage;

    switch (param.type) {
    case SOCK_STREAM: break;
    case SOCK_DGRAM: break;
    default: goto usage;
    }

    switch (param.addr.addr.sa_family) {
    case AF_INET6:
        if (addr[0] == '[') {
            char *e = &addr[strlen(addr) - 1];
            if (*e != ']')
                goto usage;

            *e = 0;
            addr++;
        }

        param.addr.in6.sin6_port = htons(atoi(port));
        if (inet_pton(AF_INET6, addr, &param.addr.in6.sin6_addr) < 1)
            goto usage;
        break;
    case AF_INET:
        param.addr.in.sin_port = htons(atoi(port));
        if (inet_pton(AF_INET, addr, &param.addr.in.sin_addr) < 1)
            goto usage;
        break;
    default: goto usage;
    }

    if (fread(pckt, 1, sizeof(pckt), stdin) == 0)
        return EXIT_FAILURE;

    ncpus = sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpus < 0)
        return EXIT_FAILURE;

    return run_test(ncpus, &param) ? EXIT_SUCCESS : EXIT_FAILURE;

usage:
    fprintf(stderr,
            "Usage: %s [-h] -s|-d -4|-6 -a ADDR -p PORT < PKT\n",
            argv[0]);
    return EXIT_FAILURE;
}
