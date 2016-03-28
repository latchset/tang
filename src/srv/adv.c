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

#include "../core/conv.h"
#include "adv.h"
#include "rec.h"

#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/sha.h>

#include <errno.h>

#define KEYLEN(k) ((k)->grp->length + (k)->key->length)

typedef struct {
    TANG_SIG *sig;
    TANG_KEY *key;
    bool adv;
} sig_t;

struct adv {
    TANG_MSG_ADV_REP *rep;
    sig_t **sigs;
};

static const struct {
    int sign;
    int hash;
} supported[] = {
    { NID_ecdsa_with_SHA224, NID_sha224 },
    { NID_ecdsa_with_SHA256, NID_sha256 },
    { NID_ecdsa_with_SHA384, NID_sha384 },
    { NID_ecdsa_with_SHA512, NID_sha512 },
    { NID_undef, NID_undef }
};

static void
sig_free(sig_t *sig)
{
    if (!sig)
        return;

    TANG_SIG_free(sig->sig);
    TANG_KEY_free(sig->key);
    free(sig);
}

static sig_t *
make_sig(int nid, const db_key_t *key, const unsigned char *hash, size_t hlen,
         BN_CTX *ctx)
{
    unsigned char *buf = NULL;
    ECDSA_SIG *tmp = NULL;
    sig_t *sig = NULL;
    int len = 0;

    sig = calloc(1, sizeof(sig_t));
    if (!sig)
        goto error;

    sig->adv = key->adv;

    sig->key = TANG_KEY_new();
    if (!sig->key)
        goto error;

    if (conv_eckey2tkey(key->key, key->use, sig->key, ctx) != 0)
        goto error;

    sig->sig = TANG_SIG_new();
    if (!sig->sig)
        goto error;

    ASN1_OBJECT_free(sig->sig->type);
    sig->sig->type = OBJ_nid2obj(nid);
    if (!sig->sig->type)
        goto error;

    tmp = ECDSA_do_sign(hash, hlen, key->key);
    if (!tmp)
        goto error;

    len = i2d_ECDSA_SIG(tmp, &buf);
    ECDSA_SIG_free(tmp);
    if (len < 1)
        goto error;

    if (ASN1_OCTET_STRING_set(sig->sig->sig, buf, len) <= 0)
        goto error;

    OPENSSL_free(buf);
    return sig;

error:
    OPENSSL_free(buf);
    sig_free(sig);
    return NULL;
}

int
adv_init(adv_t **adv)
{
    adv_t *tmp = NULL;

    tmp = calloc(1, sizeof(*tmp));
    if (!tmp)
        return ENOMEM;

    tmp->sigs = calloc(1, sizeof(*tmp->sigs));
    if (!tmp->sigs)
        goto error;

    tmp->rep = TANG_MSG_ADV_REP_new();
    if (!tmp->rep)
        goto error;

    *adv = tmp;
    return 0;

error:
    adv_free(tmp);
    return ENOMEM;
}

static void
adv_free_contents(adv_t *adv)
{
    if (!adv)
        return;

    TANG_MSG_ADV_REP_free(adv->rep);
    for (size_t i = 0; adv->sigs && adv->sigs[i]; i++)
        sig_free(adv->sigs[i]);
    free(adv->sigs);
}

void
adv_free(adv_t *adv)
{
    adv_free_contents(adv);
    free(adv);
}

int
adv_update(adv_t *adv, const db_t *db, BN_CTX *ctx)
{
    unsigned char *buf = NULL;
    size_t nkeys = 0;
    adv_t tmp = {};
    int len = 0;
    int r = 0;

    /* Create the new reply structure. */
    LIST_FOREACH(&db->keys, db_key_t, k, list)
        nkeys++;
    tmp.sigs = calloc(nkeys + 1, sizeof(*tmp.sigs));
    tmp.rep = TANG_MSG_ADV_REP_new();
    if (!tmp.sigs || !tmp.rep)
        goto error;

    /* Create the reply body from the loaded keys. */
    LIST_FOREACH(&db->keys, db_key_t, k, list) {
        TANG_KEY *key = NULL;

        if (!k->adv)
            continue;

        key = TANG_KEY_new();
        if (!key)
            goto error;

        if (SKM_sk_push(TANG_KEY, tmp.rep->body->keys, key) <= 0) {
            TANG_KEY_free(key);
            goto error;
        }

        if (conv_eckey2tkey(k->key, k->use, key, ctx) != 0)
            goto error;
    }

    /* Encode the reply body. */
    len = i2d_TANG_MSG_ADV_REP_BDY(tmp.rep->body, &buf);
    if (len <= 0)
        goto error;

    /* Create all signature combinations. */
    nkeys = 0;
    for (size_t i = 0; supported[i].sign != NID_undef; i++) {
        unsigned char hash[EVP_MAX_MD_SIZE] = {};
        unsigned int hlen = sizeof(hash);
        const EVP_MD *md = NULL;

        md = EVP_get_digestbynid(supported[i].hash);
        if (!md)
            continue;

        if (EVP_Digest(buf, len, hash, &hlen, md, NULL) <= 0)
            goto error;

        LIST_FOREACH(&db->keys, db_key_t, k, list) {
            if (k->use != TANG_KEY_USE_SIG)
                continue;

            tmp.sigs[nkeys] = make_sig(supported[i].sign, k, hash, hlen, ctx);
            if (!tmp.sigs[nkeys++])
                goto error;
        }

        break;
    }

    /* Clean up. */
    adv_free_contents(adv);
    OPENSSL_free(buf);
    *adv = tmp;
    return 0;

error:
    OPENSSL_free(buf);
    adv_free_contents(&tmp);
    return r == 0 ? ENOMEM : r;
}

static TANG_KEY *
find_key(STACK_OF(TANG_KEY) *keys, TANG_KEY *key)
{
    for (int i = 0; i < SKM_sk_num(TANG_KEY, keys); i++) {
        TANG_KEY *k = SKM_sk_value(TANG_KEY, keys, i);

        if (TANG_KEY_equals(key, k))
            return k;
    }

    return NULL;
}

TANG_MSG_ERR
adv_sign(adv_t *adv, const TANG_MSG_ADV_REQ *req, pkt_t *pkt)
{
    int r;

    /* Select the key used for the signature. */
    for (size_t i = 0; adv->sigs[i]; i++) {
        if (!adv->sigs[i]->adv && !find_key(req->keys, adv->sigs[i]->key))
            continue;

        if (SKM_sk_push(TANG_SIG, adv->rep->sigs, adv->sigs[i]->sig) <= 0) {
            SKM_sk_zero(TANG_SIG, adv->rep->sigs);
            return TANG_MSG_ERR_INTERNAL;
        }
    }

    /* Encode the output. */
    r = pkt_encode(&(TANG_MSG) {
        .type = TANG_MSG_TYPE_ADV_REP,
        .val.adv.rep = adv->rep
    }, pkt);

    SKM_sk_zero(TANG_SIG, adv->rep->sigs);
    return r == 0 ? TANG_MSG_ERR_NONE : TANG_MSG_ERR_INTERNAL;
}
