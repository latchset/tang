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
#include "askp.h"
#include "iface.h"
#include "../asn1.h"
#include "../luks.h"
#include "../meta.h"
#include "../../rec.h"
#include "../../msg.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <error.h>
#include <resolv.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

#include <string.h>

#include <argp.h>
#include <sysexits.h>

#define TIMEOUT_BASE 5000
#define TIMEOUT_EXT (rand() % 295000)
#define ALLCNT (sizeof(struct named) / sizeof(struct pollfd))

union fds {
    struct named {
        struct pollfd askp;
        struct pollfd iface;
    } named;
    struct pollfd all[ALLCNT];
};

static void
on_signal(int sig)
{
}

static bool
TANG_LUKS_get_params(const TANG_LUKS *tl, msg_t *params)
{
    if (!tl || !tl->hostname || !tl->service)
        return false;

    if (tl->hostname->length >= (int) sizeof(params->hostname))
        return false;

    if (tl->service->length >= (int) sizeof(params->service))
        return false;

    strncpy(params->hostname, (char *) tl->hostname->data,
            tl->hostname->length);
    strncpy(params->service, (char *) tl->service->data,
            tl->service->length);

    return true;
}

static sbuf_t *
get_key(const char *device, const sbuf_t *buf)
{
    TANG_LUKS *tl = NULL;
    EC_KEY *eckey = NULL;
    TANG_MSG *msg = NULL;
    sbuf_t *key = NULL;
    BN_CTX *ctx = NULL;
    msg_t params = {};

    ctx = BN_CTX_new();
    if (!ctx)
        goto error;

    tl = TANG_LUKS_from_sbuf(buf);
    if (!tl) {
        fprintf(stderr, "Error parsing metadata from %s\n", device);
        goto error;
    }

    eckey = rec_req(tl->rec, ctx);
    if (!eckey)
        goto error;

    if (!TANG_LUKS_get_params(tl, &params))
        goto error;

    msg = msg_rqst(&params, &(TANG_MSG) {
        .type = TANG_MSG_TYPE_REC_REQ,
        .val.rec.req = tl->rec
    });

    if (!msg || msg->type != TANG_MSG_TYPE_REC_REP) {
        fprintf(stderr, "Unable to contact %s (%s)\n",
                params.hostname, params.service);
        goto error;
    }

    key = rec_rep(msg->val.rec.rep, eckey, ctx);

error:
    TANG_LUKS_free(tl);
    EC_KEY_free(eckey);
    TANG_MSG_free(msg);
    BN_CTX_free(ctx);
    return key;
}

static void
answer_question(const question_t *q)
{
    for (int slot = 0; slot < LUKS_NUMKEYS; slot++) {
        sbuf_t *key = NULL;
        sbuf_t *buf = NULL;

        buf = meta_read(q->device, slot);
        if (!buf)
            continue;

        key = get_key(q->device, buf);
        sbuf_free(buf);
        if (key) {
            question_answer(q, key);
            sbuf_free(key);
            break;
        }
    }
}

const char *argp_program_version = VERSION;

int
main(int argc, char *argv[])
{
    const struct argp argp = {};
    int timeout = TIMEOUT_BASE;
    int ret = EXIT_FAILURE;
    askp_t *askp = NULL;
    union fds fds;

    if (argp_parse(&argp, argc, argv, 0, NULL, NULL) != 0)
        return EX_OSERR;

    if (askp_new(&askp, &fds.named.askp) != 0)
        goto error;

    if (iface_new(&fds.named.iface) != 0)
        goto error;

    signal(SIGINT, on_signal);
    signal(SIGQUIT, on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGUSR1, on_signal);
    signal(SIGUSR2, on_signal);

    for (size_t i = 0; i < ALLCNT; i++)
        fds.all[i].events |= POLLRDHUP;

    for (int events; (events = poll(fds.all, ALLCNT, timeout)) >= 0; ) {
        res_init();
        bool process = false;

        for (size_t i = 0; i < ALLCNT; i++) {
            short mask = ~fds.all[i].events | POLLRDHUP;
            if (fds.all[i].revents & mask)
                goto error;
        }

        if (events == 0) {
            LIST_FOREACH(&askp->questions, question_t, q, list)
                answer_question(q);

            if (LIST_EMPTY(&askp->questions))
                break;

            timeout = TIMEOUT_BASE + TIMEOUT_EXT;
            continue;
        }

        timeout = TIMEOUT_BASE;
        process |= iface_new_route(&fds.named.iface);
        process |= askp_new_question(askp, &fds.named.askp);
        if (process) {
            LIST_FOREACH(&askp->questions, question_t, q, list)
                answer_question(q);
        }
    }

    if (errno == EINTR || errno == 0)
        ret = EXIT_SUCCESS;

error:
    close(fds.named.iface.fd);
    close(fds.named.askp.fd);
    askp_free(askp);
    return ret;
}


