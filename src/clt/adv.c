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
#include "../conv.h"

#include <openssl/evp.h>
#include <openssl/ecdsa.h>
#include <openssl/objects.h>
#include <openssl/rand.h>

static bool
valid_sig(TANG_SIG *sig, EC_KEY *key, const uint8_t *body, size_t size)
{
    unsigned char hash[EVP_MAX_MD_SIZE] = {};
    unsigned int hlen = sizeof(hash);
    ECDSA_SIG *ecdsa = NULL;
    const EVP_MD *md = NULL;
    int r;

    switch (OBJ_obj2nid(sig->type)) {
    case NID_ecdsa_with_SHA224: md = EVP_sha224(); break;
    case NID_ecdsa_with_SHA256: md = EVP_sha256(); break;
    case NID_ecdsa_with_SHA384: md = EVP_sha384(); break;
    case NID_ecdsa_with_SHA512: md = EVP_sha512(); break;
    default: return false;
    }

    if (EVP_Digest(body, size, hash, &hlen, md, NULL) <= 0)
      return false;

    ecdsa = d2i_ECDSA_SIG(NULL,
                          &(const unsigned char *) { sig->sig->data },
                          sig->sig->length);
    if (!ecdsa)
      return false;

    r = ECDSA_do_verify(hash, hlen, ecdsa, key);
    ECDSA_SIG_free(ecdsa);
    return r == 1;
}

bool
adv_signed_by(const TANG_MSG_ADV_REP *rep, EC_KEY *key, BN_CTX *ctx)
{
    uint8_t *body = NULL;
    bool ret = false;
    int len = 0;

    len = i2d_TANG_MSG_ADV_REP_BDY(rep->body, &body);
    if (len <= 0)
        goto egress;

    for (int j = 0; !ret && j < SKM_sk_num(TANG_SIG, rep->sigs); j++) {
        TANG_SIG *sig = SKM_sk_value(TANG_SIG, rep->sigs, j);
        ret = valid_sig(sig, key, body, len);
    }

egress:
    OPENSSL_free(body);
    return ret;
}

static bool
valid_adv(const TANG_MSG_ADV_REP *rep, STACK_OF(TANG_KEY) *keys, BN_CTX *ctx)
{
    bool sig = keys ? SKM_sk_num(TANG_KEY, keys) == 0 : true;
    size_t rcnt = 0;
    size_t acnt = 0;

    /* Ensure the advertisement is signed by all advertised signing keys.
     * Also, count the number of signing and recovery keys. */
    for (int i = 0; i < SKM_sk_num(TANG_KEY, rep->body->keys); i++) {
        TANG_KEY *tkey = NULL;
        EC_KEY *eckey = NULL;

        tkey = SKM_sk_value(TANG_KEY, rep->body->keys, i);
        if (!tkey)
            return false;

        switch (ASN1_ENUMERATED_get(tkey->use)) {
        case TANG_KEY_USE_REC:
            rcnt++;
            break;

        case TANG_KEY_USE_SIG:
            eckey = conv_tkey2eckey(tkey, ctx);
            if (!eckey)
                return false;

            if (!adv_signed_by(rep, eckey, ctx)) {
                EC_KEY_free(eckey);
                return false;
            }

            EC_KEY_free(eckey);
            acnt++;
            break;

        default:
            return false;
        }
    }

    /* Ensure the advertisement is signed by at least one requested key. */
    for (int i = 0; !sig && i < SKM_sk_num(TANG_KEY, keys); i++) {
        TANG_KEY *tkey = NULL;
        EC_KEY *eckey = NULL;

        tkey = SKM_sk_value(TANG_KEY, keys, i);
        if (!tkey)
            return false;

        if (ASN1_ENUMERATED_get(tkey->use) != TANG_KEY_USE_SIG)
            continue;

        eckey = conv_tkey2eckey(tkey, ctx);
        if (!eckey)
            return false;

        sig = adv_signed_by(rep, eckey, ctx);
        EC_KEY_free(eckey);
    }

    return rcnt > 0 && acnt > 0 && sig;
}

TANG_MSG_ADV_REQ *
adv_req(STACK_OF(TANG_KEY) *keys)
{
    TANG_MSG_ADV_REQ *adv = NULL;

    adv = TANG_MSG_ADV_REQ_new();
    if (!adv)
        return NULL;

    if (!keys)
        return adv;

    for (int i = 0; i < SKM_sk_num(TANG_KEY, keys); i++) {
        TANG_KEY *key;

        key = TANG_KEY_copy(SKM_sk_value(TANG_KEY, keys, i));
        if (!key)
            goto error;

        if (SKM_sk_push(TANG_KEY, adv->keys, key) <= 0) {
            TANG_KEY_free(key);
            goto error;
        }
    }

    return adv;

error:
    TANG_MSG_ADV_REQ_free(adv);
    return NULL;
}

static EC_KEY *
select_key(STACK_OF(TANG_KEY) *keys, int min, BN_CTX *ctx)
{
    for (int i = 0; i < SKM_sk_num(TANG_KEY, keys); i++) {
    	TANG_KEY *key = SKM_sk_value(TANG_KEY, keys, i);
    	EC_KEY *eckey = NULL;

        if (!key || ASN1_ENUMERATED_get(key->use) != TANG_KEY_USE_REC)
            continue;

        eckey = conv_tkey2eckey(key, ctx);
        if (!eckey)
            continue;

        if (EC_GROUP_get_degree(EC_KEY_get0_group(eckey)) < min * 2) {
            EC_KEY_free(eckey);
            continue;
        }

        return eckey;
    }

    return NULL;
}

TANG_MSG_REC_REQ *
adv_rep(const TANG_MSG_ADV_REP *adv, STACK_OF(TANG_KEY) *keys,
        size_t min, sbuf_t **key, BN_CTX *ctx)
{
    TANG_MSG_REC_REQ *req = NULL;
    const EC_GROUP *g = NULL;
    EC_POINT *p = NULL;
    EC_KEY *r = NULL;
    EC_KEY *l = NULL;
    int bytes = 0;

    if (!valid_adv(adv, keys, ctx))
    	return NULL;


    r = select_key(adv->body->keys, min, ctx);
    if (!r)
    	return NULL;
    g = EC_KEY_get0_group(r);
    if (!g)
    	goto error;


    bytes = (EC_GROUP_get_degree(g) + 7) / 8;
    if (RAND_load_file("/dev/random", bytes) != bytes)
        goto error;


    l = EC_KEY_new();
    if (!l)
    	goto error;

    if (EC_KEY_set_group(l, g) <= 0)
    	goto error;

    if (EC_KEY_generate_key(l) <= 0)
    	goto error;


    req = TANG_MSG_REC_REQ_new();
    if (!req)
        goto error;

    if (conv_eckey2tkey(r, TANG_KEY_USE_REC, req->key, ctx) != 0)
    	goto error;

    if (conv_point2os(g, EC_KEY_get0_public_key(l), req->x, ctx) != 0)
        goto error;


    p = EC_POINT_new(g);
    if (!p)
    	goto error;

    if (EC_POINT_mul(g, p, NULL, EC_KEY_get0_public_key(r),
                     EC_KEY_get0_private_key(l), ctx) <= 0)
        goto error;

    *key = sbuf_from_point(g, p, ctx);
    if (!*key)
    	goto error;

    return req;

error:
    TANG_MSG_REC_REQ_free(req);
    EC_POINT_free(p);
    EC_KEY_free(r);
    EC_KEY_free(l);
    return NULL;
}
