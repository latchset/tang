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

#include "adv.h"
#include "msg.h"
#include "../conv.h"

#include <openssl/objects.h>

#include <argp.h>
#include <string.h>

#define _STR(x) # x
#define STR(x) _STR(x)

struct options {
    msg_t params;
};

static error_t
argp_parser(int key, char* arg, struct argp_state* state)
{
    struct options *opts = state->input;

    switch (key) {
    case 'h':
        strncpy(opts->params.hostname, arg, sizeof(opts->params.hostname) - 1);
        return 0;

    case 's':
        strncpy(opts->params.service, arg, sizeof(opts->params.service) - 1);
        return 0;

    case ARGP_KEY_END:
        if (strlen(opts->params.hostname) == 0) {
            fprintf(stderr, "Host MUST be specified!\n");
            argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
            return EINVAL;
        }

        if (strlen(opts->params.service) == 0)
            strcpy(opts->params.service, STR(TANG_PORT));

        return 0;

    default:
        return ARGP_ERR_UNKNOWN;
    }
}

const char *argp_program_version = VERSION;

static const struct argp_option argp_options[] = {
    { "hostname", 'h', "hostname", .doc = "Remote server hostname (required)" },
    { "service",  's', "service",  .doc = "Remote server service" },
    {}
};

static const struct argp argp = {
    .options = argp_options,
    .parser = argp_parser,
    .args_doc = ""
};

static bool
validate_adv(TANG_MSG_ADV_REP *adv, BN_CTX *ctx)
{
    for (int i = 0; i < SKM_sk_num(TANG_KEY, adv->body->sigs); i++) {
        TANG_KEY *tkey = SKM_sk_value(TANG_KEY, adv->body->sigs, i);
        EC_KEY *eckey = NULL;

        eckey = conv_tkey2eckey(tkey, ctx);
        if (!eckey)
            return false;

        if (!adv_signed_by(adv, eckey, ctx)) {
            EC_KEY_free(eckey);
            return false;
        }

        EC_KEY_free(eckey);
    }

    return SKM_sk_num(TANG_KEY, adv->body->sigs) > 0;
}

static bool
validate_rec(const msg_t *params, TANG_KEY *tkey, BN_CTX *ctx)
{
    TANG_MSG req = { .type = TANG_MSG_TYPE_REC_REQ };
    TANG_MSG *rep = NULL;
    EC_KEY *eckey = NULL;
    EC_POINT *p = NULL;
    bool valid = false;

    req.val.rec.req = TANG_MSG_REC_REQ_new();
    if (!req.val.rec.req)
        goto error;

    eckey = conv_tkey2eckey(tkey, ctx);
    if (!eckey)
        goto error;

    if (conv_point2os(EC_KEY_get0_group(eckey),
                      EC_GROUP_get0_generator(EC_KEY_get0_group(eckey)),
                      req.val.rec.req->x, ctx) != 0)
        goto error;

    TANG_KEY_free(req.val.rec.req->key);
    req.val.rec.req->key = TANG_KEY_copy(tkey);
    if (!req.val.rec.req->key)
        goto error;

    rep = msg_rqst(params, &req);
    if (!rep)
        goto error;

    switch (rep->type) {
    case TANG_MSG_TYPE_REC_REP: break;
    default: goto error;
    }

    p = EC_POINT_new(EC_KEY_get0_group(eckey));
    if (!p)
        goto error;

    if (conv_os2point(EC_KEY_get0_group(eckey),
                      rep->val.rec.rep->y,
                      p, ctx) != 0)
        goto error;

    if (EC_POINT_cmp(EC_KEY_get0_group(eckey),
                     EC_KEY_get0_public_key(eckey),
                     p, ctx) != 0)
        goto error;

    valid = true;

error:
    TANG_MSG_REC_REQ_free(req.val.rec.req);
    TANG_MSG_free(rep);
    EC_KEY_free(eckey);
    EC_POINT_free(p);
    return valid;
}

static bool
validate_recs(const msg_t *params, TANG_MSG_ADV_REP *adv, BN_CTX *ctx)
{
    for (int i = 0; i < SKM_sk_num(TANG_KEY, adv->body->recs); i++) {
        TANG_KEY *tkey = SKM_sk_value(TANG_KEY, adv->body->recs, i);

        if (!validate_rec(params, tkey, ctx))
            return false;
    }

    return true;
}

int
main(int argc, char *argv[])
{
    struct options opts = { .params.timeout = 10 };
    TANG_MSG *rep = NULL;
    BN_CTX *ctx = NULL;
    TANG_MSG req = {};
    int ret = 2;

    ctx = BN_CTX_new();
    if (!ctx)
        goto error;

    if (argp_parse(&argp, argc, argv, 0, NULL, &opts) != 0)
        goto error;

    req.type = TANG_MSG_TYPE_ADV_REQ;
    req.val.adv.req = adv_req(NULL);
    if (!req.val.adv.req)
        goto error;

    rep = msg_rqst(&opts.params, &req);
    TANG_MSG_ADV_REQ_free(req.val.adv.req);
    if (!rep)
        goto error;

    switch (rep->type) {
    case TANG_MSG_TYPE_ADV_REP:
        break;
    default:
        printf("Received invalid advertisement response!\n");
        TANG_MSG_free(rep);
        goto error;
    }

    if (SKM_sk_num(TANG_KEY, rep->val.adv.rep->body->sigs) <= 0) {
        printf("Advertisement does not contain any signing keys!\n");
        goto error;
    }

    if (SKM_sk_num(TANG_KEY, rep->val.adv.rep->body->recs) <= 0) {
        printf("Advertisement does not contain any recovery keys!\n");
        goto error;
    }

    if (!validate_adv(rep->val.adv.rep, ctx)) {
        printf("Signature validation failed for one or more keys!\n");
        TANG_MSG_free(rep);
        goto error;
    }


    if (!validate_recs(&opts.params, rep->val.adv.rep, ctx)) {
        printf("Recovery failed for one or more keys!\n");
        TANG_MSG_free(rep);
        goto error;
    }

    ret = 0;

error:
    TANG_MSG_free(rep);
    BN_CTX_free(ctx);
    return ret;
}
