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

#include "common.h"
#include "../conv.h"
#include <string.h>
#include <openssl/evp.h>
#include <openssl/ecdsa.h>

static clevis_buf_t *
buf_encode(const TANG_MSG *msg)
{
    clevis_buf_t *buf = NULL;
    int size = 0;

    size = ASN1_item_ex_i2d(&(ASN1_VALUE *) { (ASN1_VALUE *) msg },
                            NULL, &TANG_MSG_it, -1, 0);
    if (size <= 0)
        return NULL;

    buf = clevis_buf_make(size, NULL);
    if (!buf)
        return NULL;

    size = ASN1_item_ex_i2d(&(ASN1_VALUE *) { (ASN1_VALUE *) msg },
                            &(uint8_t *) { (uint8_t *) buf->buf },
                            &TANG_MSG_it, -1, 0);
    if (size <= 0) {
        clevis_buf_free(buf);
        return NULL;
    }

    return buf;
}

static bool
sig_valid(TANG_SIG *sig, EC_KEY *key, const uint8_t *body, size_t size)
{
    unsigned char hash[EVP_MAX_MD_SIZE] = {};
    unsigned int hlen = sizeof(hash);
    ECDSA_SIG *ecdsa = NULL;
    const EVP_MD *md = NULL;
    int r;

    switch (OBJ_obj2nid(sig->type)) {
    case NID_ecdsa_with_SHA224:
      md = EVP_get_digestbynid(NID_sha224);
      break;
    case NID_ecdsa_with_SHA256:
      md = EVP_get_digestbynid(NID_sha256);
      break;
    case NID_ecdsa_with_SHA384:
      md = EVP_get_digestbynid(NID_sha384);
      break;
    case NID_ecdsa_with_SHA512:
      md = EVP_get_digestbynid(NID_sha512);
      break;
    default:
      return false;
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

static bool
adv_valid(TANG_MSG_ADV_REP *rep, BN_CTX *ctx)
{
    uint8_t *body = NULL;
    size_t count = 0;
    int len = 0;

    if (SKM_sk_num(TANG_SIG, rep->sigs) < 1 ||
        SKM_sk_num(TANG_KEY, rep->body->keys) < 2)
        return false;

    len = i2d_TANG_MSG_ADV_REP_BDY(rep->body, &body);
    if (len <= 0)
        return false;

    for (int i = 0; i < SKM_sk_num(TANG_KEY, rep->body->keys); i++) {
        TANG_KEY *tkey = NULL;
        EC_KEY *eckey = NULL;

        tkey = SKM_sk_value(TANG_KEY, rep->body->keys, i);
        if (!tkey)
            goto error;

        if (ASN1_ENUMERATED_get(tkey->use) != TANG_KEY_USE_SIG)
            continue;

        eckey = tkey2eckey(tkey, ctx);
        if (!eckey)
            goto error;

        for (int j = 0; j < SKM_sk_num(TANG_SIG, rep->sigs); j++) {
            TANG_SIG *sig = SKM_sk_value(TANG_SIG, rep->sigs, j);
            if (sig_valid(sig, eckey, body, len))
                count++;
        }

        EC_KEY_free(eckey);
    }

    OPENSSL_free(body);
    return count == SKM_sk_num(TANG_SIG, rep->sigs);

error:
    OPENSSL_free(body);
    return false;
}

static bool
adv_trusted(TANG_MSG_ADV_REP *rep, BN_CTX *ctx)
{
	int nkeys = SKM_sk_num(TANG_KEY, rep->body->keys);
	int c = 'a';

    fprintf(stderr, "\nThe server advertised the following signing key%s:\n",
    		nkeys > 1 ? "s" : "");

    for (int i = 0; i < nkeys; i++) {
        TANG_KEY *key = SKM_sk_value(TANG_KEY, rep->body->keys, i);

        if (ASN1_ENUMERATED_get(key->use) != TANG_KEY_USE_SIG)
            continue;

        fprintf(stderr, "\t");
        for (int j = 0; j < key->key->length; j++) {
        	if (j % 20 == 0)
        		fprintf(stderr, "\n\t");
            fprintf(stderr, "%02X", key->key->data[j]);
        }
        fprintf(stderr, "\n");
    }

    fprintf(stderr, "\n");

    while (!strchr("YyNn", c)) {
        fprintf(stderr, "Do you wish to trust the key%s? [yn] ",
        		nkeys > 1 ? "s" : "");
        c = getc(stdin);
    }

    return strchr("Yy", c);
}

static json_t *
make_rec(const TANG_KEY *key, const EC_KEY *x, BN_CTX *ctx)
{
    TANG_MSG_REC_REQ req = { .key = (TANG_KEY *) key };
    TANG_MSG msg = { .type = TANG_MSG_TYPE_REC_REQ, .val.rec.req = &req };
    clevis_buf_t *buf = NULL;
    json_t *tmp = NULL;

    req.x = ASN1_OCTET_STRING_new();
    if (!req.x)
        return false;

    if (conv_point2os(EC_KEY_get0_group(x),
                      EC_KEY_get0_public_key(x),
                      req.x, ctx) != 0) {
        ASN1_OCTET_STRING_free(req.x);
        return false;
    }

    buf = buf_encode(&msg);
    ASN1_OCTET_STRING_free(req.x);
    if (!buf)
        return false;

    tmp = clevis_buf_encode(buf);
    clevis_buf_free(buf);
    return tmp;
}

static clevis_buf_t *
make_key(const EC_KEY *rem, const EC_KEY *lcl, BN_CTX *ctx)
{
    clevis_buf_t *key = NULL;
    EC_POINT *p = NULL;
    size_t s;

    p = EC_POINT_new(EC_KEY_get0_group(rem));
    if (!p)
        goto error;

    if (EC_POINT_mul(EC_KEY_get0_group(rem), p, NULL,
                     EC_KEY_get0_public_key(rem),
                     EC_KEY_get0_private_key(lcl), ctx) <= 0)
        goto error;

    key = point2key(EC_KEY_get0_group(rem), p, ctx);
    EC_POINT_free(p);
    return key;

error:
    clevis_buf_free(key);
    EC_POINT_free(p);
    return NULL;
}

static bool
process_key(const clevis_provision_f *funcs, const clevis_buf_t *key,
            const TANG_KEY *remote, json_t *data, BN_CTX *ctx)
{
    clevis_buf_t *ekey = NULL;
    EC_KEY *lcl = NULL;
    EC_KEY *rem = NULL;
    bool ret = false;
    size_t s = 0;

    rem = tkey2eckey(remote, ctx);
    if (!rem)
        goto error;

    /* Ensure that the point has >= 2x entropy than the key. */
    s = EC_POINT_point2oct(EC_KEY_get0_group(rem), EC_KEY_get0_public_key(rem),
                           POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
    if (s == 0 || key->len * 2 >= s)
        goto error;

    lcl = random_key(EC_GROUP_get_curve_name(EC_KEY_get0_group(rem)));
    if (!lcl)
        goto error;

    if (json_object_set_new(data, "rec", make_rec(remote, lcl, ctx)) < 0)
        goto error;

    ekey = make_key(rem, lcl, ctx);
    if (!ekey)
        goto error;

    if (json_object_set_new(data, "ct", funcs->encrypt(ekey, key)) < 0)
        goto error;

    ret = true;

error:
    clevis_buf_free(ekey);
    EC_KEY_free(rem);
    EC_KEY_free(lcl);
    return ret;
}

static json_t *
copy_config(const json_t *cfg)
{
    bool listen = false;
    json_t *data = NULL;
    json_t *tmp = NULL;

    data = json_object();
    if (!data)
        return NULL;

    tmp = json_object_get(cfg, "listen");
    if (json_is_boolean(tmp))
        listen = json_boolean_value(tmp);
    if (json_object_set_new(data, "listen", json_boolean(listen)) < 0)
        goto error;

    tmp = json_object_get(cfg, "host");
    if (json_is_string(tmp) && json_object_set(data, "host", tmp) < 0)
        goto error;
    if (!json_is_string(tmp) && !listen)
        goto error;

    tmp = json_object_get(cfg, "port");
    if (json_is_integer(tmp)) {
        if (json_integer_value(tmp) <= 0)
            goto error;
        if (json_integer_value(tmp) > UINT16_MAX)
            goto error;
        if (json_object_set(data, "port", tmp) < 0)
            goto error;
    } else {
        if (json_object_set_new(data, "port", json_integer(TANG_PORT)) < 0)
            goto error;
    }

    return data;

error:
    json_decref(data);
    return NULL;
}

json_t *
provision(const clevis_provision_f *funcs,
          const json_t *cfg, const clevis_buf_t *key)
{
    clevis_buf_t *buf = NULL;
    TANG_MSG *adv = NULL;
    json_t *data = NULL;
    BN_CTX *ctx = NULL;
    int nkeys;

    ctx = BN_CTX_new();
    if (!ctx)
        goto error;

    data = copy_config(cfg);
    if (!data) {
        fprintf(stderr, "Configuration is invalid!\n");
        goto error;
    }

    if (json_object_get(cfg, "adv"))
        adv = adv_load(cfg);
    else
        adv = adv_rqst(data);
    if (!adv || adv->type != TANG_MSG_TYPE_ADV_REP) {
        fprintf(stderr, "Unable to get advertisement!\n");
        goto error;
    }

    if (!adv_valid(adv->val.adv.rep, ctx)) {
        fprintf(stderr, "Advertisement is invalid!\n");
        goto error;
    }

    if (!json_object_get(cfg, "adv") && !adv_trusted(adv->val.adv.rep, ctx)) {
        fprintf(stderr, "Advertisement is not trusted!\n");
        goto error;
    }

    buf = buf_encode(adv);
    if (!buf)
        goto error;

    if (json_object_set_new(data, "adv", clevis_buf_encode(buf)) < 0)
        goto error;

    nkeys = SKM_sk_num(TANG_KEY, adv->val.adv.rep->body->keys);
    for (int i = 0; i < nkeys; i++) {
        TANG_KEY *tkey = NULL;

        tkey = SKM_sk_value(TANG_KEY, adv->val.adv.rep->body->keys, i);
        if (!tkey)
            continue;

        if (ASN1_ENUMERATED_get(tkey->use) != TANG_KEY_USE_REC)
            continue;

        if (process_key(funcs, key, tkey, data, ctx)) {
            clevis_buf_free(buf);
            TANG_MSG_free(adv);
            BN_CTX_free(ctx);
            return data;
        }
    }

    fprintf(stderr, "No suitable key found in the advertisement!\n");

error:
    clevis_buf_free(buf);
    TANG_MSG_free(adv);
    json_decref(data);
    BN_CTX_free(ctx);
    return NULL;
}
