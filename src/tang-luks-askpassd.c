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
#include "askpass/askp.h"
#include "askpass/iface.h"
#include "luks/asn1.h"
#include "luks/meta.h"
#include "clt/rec.h"
#include "clt/msg.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <error.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

#include <libcryptsetup.h>
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
    params->listen = tl->listen != 0;

    return true;
}

static skey_t *
get_key(const char *device, int slot)
{
    TANG_LUKS *tl = NULL;
    EC_KEY *eckey = NULL;
    uint8_t *data = NULL;
    TANG_MSG *msg = NULL;
    skey_t *skey = NULL;
    BN_CTX *ctx = NULL;
    msg_t params = {};
    size_t size = 0;

    ctx = BN_CTX_new();
    if (!ctx)
        goto error;

    data = meta_read(device, slot, &size);
    if (!data) {
        fprintf(stderr, "Error reading metadata from %s (%d)\n", device, slot);
        goto error;
    }

    tl = d2i_TANG_LUKS(NULL, &(const uint8_t *) { data }, size);
    if (!tl) {
        fprintf(stderr, "Error parsing metadata from %s (%d)\n", device, slot);
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

    skey = rec_rep(msg->val.rec.rep, eckey, ctx);

error:
    TANG_LUKS_free(tl);
    EC_KEY_free(eckey);
    TANG_MSG_free(msg);
    BN_CTX_free(ctx);
    free(data);
    return skey;
}

static void
answer_question(const question_t *q)
{
    struct crypt_device *cd = NULL;
    const char *type = NULL;
    int nerr = 0;

    nerr = crypt_init(&cd, q->device);
    if (nerr != 0) {
        fprintf(stderr, "Unable to open device (%s): %s\n",
                q->device, strerror(-nerr));
        goto error;
    }

    nerr = crypt_load(cd, NULL, NULL);
    if (nerr != 0) {
        fprintf(stderr, "Unable to load device (%s): %s\n",
                q->device, strerror(-nerr));
        goto error;
    }

    type = crypt_get_type(cd);
    if (type == NULL) {
        fprintf(stderr, "Unable to determine device type\n");
        goto error;
    }

    if (strcmp(type, CRYPT_LUKS1) != 0) {
        fprintf(stderr, "%s (%s) is not a LUKS device\n", q->device, type);
        goto error;
    }

    for (int slot = 0; slot < crypt_keyslot_max(CRYPT_LUKS1); slot++) {
        skey_t *skey = NULL;

        switch (crypt_keyslot_status(cd, slot)) {
        case CRYPT_SLOT_ACTIVE:
        case CRYPT_SLOT_ACTIVE_LAST:
            skey = get_key(q->device, slot);
            if (skey) {
                question_answer(q, skey);
                skey_free(skey);
                break;
            }

        default:
            break;
        }
    }

error:
    crypt_free(cd);
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


