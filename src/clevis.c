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

#include <clevis.h>
#include "clt/adv.h"
#include "clt/rec.h"
#include "clt/msg.h"
#include <string.h>

#include <openssl/sha.h>

#define _STR(x) # x
#define STR(x) _STR(x)

static bool
adv_trusted(TANG_MSG_ADV_REP *rep)
{
    int nkeys = SKM_sk_num(TANG_KEY, rep->body->keys);
    int c = 'a';

    printf("The server advertised the following signing key%s:\n\n",
           nkeys > 1 ? "s" : "");

    for (int i = 0; i < nkeys; i++) {
        TANG_KEY *key = SKM_sk_value(TANG_KEY, rep->body->keys, i);
        uint8_t md[SHA256_DIGEST_LENGTH] = {};

        if (ASN1_ENUMERATED_get(key->use) != TANG_KEY_USE_SIG)
            continue;

        if (!SHA256(key->key->data, key->key->length, md))
            return false;

        printf("  sha256:");
        for (size_t j = 0; j < sizeof(md); j++)
            printf("%02X", md[j]);
        printf("\n");
    }

    printf("\n");

    while (!strchr("YyNn", c)) {
        printf("Do you wish to trust %s? [yn] ",
               nkeys > 1 ? "these keys" : "this key");
        c = getc(stdin);
    }

    return strchr("Yy", c);
}

static json_t *
copy_config(const json_t *cfg)
{
    json_t *data = NULL;
    json_t *tmp = NULL;

    data = json_object();
    if (!data)
        return NULL;

    tmp = json_object_get(cfg, "hostname");
    if (!json_is_string(tmp)) {
        fprintf(stderr, "Missing hostname parameter!\n");
        goto error;
    }
    if (json_object_set(data, "hostname", tmp) < 0)
        goto error;

    tmp = json_incref(json_object_get(cfg, "service"));
    if (!json_is_string(tmp))
        tmp = json_string(STR(TANG_PORT));
    if (json_object_set_new(data, "service", tmp) < 0)
        goto error;

    tmp = json_incref(json_object_get(cfg, "timeout"));
    if (!json_is_integer(tmp))
        tmp = json_integer(10);
    if (json_object_set_new(data, "timeout", tmp) < 0)
        goto error;

    return data;

error:
    json_decref(data);
    return NULL;
}

static json_t *
encode_rec(TANG_MSG_REC_REQ *rec)
{
    clevis_buf_t *tmp = NULL;
    json_t *out = NULL;
    int len = 0;

    len = i2d_TANG_MSG_REC_REQ(rec, NULL);
    if (len <= 0)
        goto egress;

    tmp = clevis_buf_make(len, NULL);
    if (!tmp)
        goto egress;

    if (i2d_TANG_MSG_REC_REQ(rec, &(uint8_t *) { tmp->buf }) != len)
        goto egress;

    out = clevis_buf_encode(tmp);

egress:
    clevis_buf_free(tmp);
    return out;
}

static TANG_MSG_REC_REQ *
decode_rec(const json_t *val)
{
    TANG_MSG_REC_REQ *rec = NULL;
    clevis_buf_t *tmp = NULL;

    if (!json_is_string(val))
        return NULL;

    tmp = clevis_buf_decode(val);
    if (!tmp)
        return NULL;

    rec = d2i_TANG_MSG_REC_REQ(NULL, &(const uint8_t *) { tmp->buf },
                               tmp->len);
    clevis_buf_free(tmp);
    return rec;
}

static bool
make_params(const json_t *data, msg_t *params)
{
    const char *tmp = NULL;

    tmp = json_string_value(json_object_get(data, "hostname"));
    if (!tmp || strlen(tmp) >= sizeof(params->hostname))
        return false;
    strcpy(params->hostname, tmp);

    tmp = json_string_value(json_object_get(data, "service"));
    if (!tmp || strlen(tmp) >= sizeof(params->service))
        return false;
    strcpy(params->service, tmp);

    params->timeout = json_integer_value(json_object_get(data, "timeout"));
    return true;
}

static json_t *
provision(const clevis_provision_f *funcs,
          const json_t *cfg, const clevis_buf_t *key)
{
    TANG_MSG_REC_REQ *rec = NULL;
    const json_t *adv = NULL;
    clevis_buf_t *okey = NULL;
    TANG_MSG *msg = NULL;
    json_t *data = NULL;
    sbuf_t *tmp = NULL;
    BN_CTX *ctx = NULL;
    msg_t params = {};

    ctx = BN_CTX_new();
    if (!ctx)
        goto error;

    data = copy_config(cfg);
    if (!data)
        goto error;

    if (!make_params(data, &params))
        goto error;

    adv = json_object_get(cfg, "adv");
    if (json_is_string(adv)) {
        msg = msg_read(json_string_value(adv));
    } else {
        TANG_MSG req = { .type = TANG_MSG_TYPE_ADV_REQ };

        req.val.adv.req = adv_req(NULL);
        if (!req.val.adv.req)
            goto error;

        msg = msg_rqst(&params, &req);
        TANG_MSG_ADV_REQ_free(req.val.adv.req);
    }
    if (!msg || msg->type != TANG_MSG_TYPE_ADV_REP)
        goto error;

    if (!json_is_string(adv) && !adv_trusted(msg->val.adv.rep))
        goto error;

    rec = adv_rep(msg->val.adv.rep, NULL, key->len, &tmp, ctx);
    if (!rec)
        goto error;

    okey = clevis_buf_make(tmp->size, tmp->data);
    if (!okey)
        goto error;

    if (json_object_set_new(data, "rec", encode_rec(rec)) < 0)
        goto error;

    if (json_object_set_new(data, "ct", funcs->encrypt(okey, key)) < 0)
        goto error;

    TANG_MSG_REC_REQ_free(rec);
    clevis_buf_free(okey);
    TANG_MSG_free(msg);
    BN_CTX_free(ctx);
    sbuf_free(tmp);
    return data;

error:
    TANG_MSG_REC_REQ_free(rec);
    clevis_buf_free(okey);
    TANG_MSG_free(msg);
    json_decref(data);
    BN_CTX_free(ctx);
    sbuf_free(tmp);
    return NULL;
}

static clevis_buf_t *
acquire(const clevis_acquire_f *funcs, const json_t *data)
{
    TANG_MSG req = { .type = TANG_MSG_TYPE_REC_REQ };
    const TANG_MSG_REC_REP *rep = NULL;
    clevis_buf_t *okey = NULL;
    clevis_buf_t *out = NULL;
    TANG_MSG *msg = NULL;
    EC_KEY *eckey = NULL;
    sbuf_t *key = NULL;
    BN_CTX *ctx = NULL;
    msg_t params = {};

    ctx = BN_CTX_new();
    if (!ctx)
        goto egress;

    req.val.rec.req = decode_rec(json_object_get(data, "rec"));
    if (!req.val.rec.req)
        goto egress;

    eckey = rec_req(req.val.rec.req, ctx);
    if (!eckey)
        goto egress;

    if (!make_params(data, &params))
        goto egress;

    msg = msg_rqst(&params, &req);
    if (!msg)
        goto egress;

    if (msg->type == TANG_MSG_TYPE_REC_REP)
        rep = msg->val.rec.rep;

    if (!rep)
        goto egress;

    key = rec_rep(rep, eckey, ctx);
    if (!key)
        goto egress;

    okey = clevis_buf_make(key->size, key->data);
    if (!okey)
        goto egress;

    out = funcs->decrypt(okey, json_object_get(data, "ct"));

egress:
    TANG_MSG_REC_REQ_free(req.val.rec.req);
    clevis_buf_free(okey);
    TANG_MSG_free(msg);
    EC_KEY_free(eckey);
    BN_CTX_free(ctx);
    sbuf_free(key);
    return out;
}

clevis_pin_f CLEVIS_PIN = {
    .provision = provision,
    .acquire = acquire
};

