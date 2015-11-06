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

#include "../conv.h"
#include "rec.h"

#include <openssl/objects.h>

#include <errno.h>
#include <string.h>

TANG_MSG_ERR
rec_decrypt(const db_t *db, const TANG_MSG_REC_REQ *req, pkt_t *pkt,
            BN_CTX *ctx)
{
    TANG_MSG_ERR err = TANG_MSG_ERR_INTERNAL;
    ASN1_OCTET_STRING *os = NULL;
    const db_key_t *key = NULL;
    const EC_GROUP *grp = NULL;
    const BIGNUM *prv = NULL;
    EC_POINT *x = NULL;
    int r;

    LIST_FOREACH(&db->keys, db_key_t, k, list) {
        const EC_POINT *pub;
        int nid;

        if (k->use != TANG_KEY_USE_REC)
            continue;

        grp = EC_KEY_get0_group(k->key);
        if (!grp)
            continue;

        nid = EC_GROUP_get_curve_name(grp);
        if (nid == NID_undef)
            continue;

        if (OBJ_obj2nid(req->key->grp) != nid)
            continue;

        pub = EC_KEY_get0_public_key(k->key);
        if (!pub)
            continue;

        if (!x) {
            x = EC_POINT_new(grp);
            if (!x)
                goto error;

            switch (conv_os2point(grp, req->key->key, x, ctx)) {
            case 0:
                break;
            case EINVAL:
                err = TANG_MSG_ERR_INVALID_REQUEST;
                goto error;
            default:
                goto error;
            }
        }

        if (EC_POINT_cmp(grp, pub, x, ctx) == 0) {
            key = k;
            break;
        }
    }

    if (!key) {
        err = TANG_MSG_ERR_NOTFOUND_KEY;
        goto error;
    }

    prv = EC_KEY_get0_private_key(key->key);
    grp = EC_KEY_get0_group(key->key);
    os = ASN1_OCTET_STRING_new();
    if (!prv || !grp || !os)
        goto error;

    r = conv_os2point(grp, req->x, x, ctx);
    if (r != 0) {
        err = TANG_MSG_ERR_INVALID_REQUEST;
        goto error;
    }

    if (EC_POINT_mul(grp, x, NULL, x, prv, ctx) <= 0)
        goto error;

    r = conv_point2os(grp, x, os, ctx);
    if (r != 0)
        goto error;

    r = pkt_encode((ASN1_VALUE *) &(TANG_MSG) {
        .type = TANG_MSG_TYPE_REC_REP,
        .val.rec.rep = &(TANG_MSG_REC_REP) {
            .y = os
        }
    }, &TANG_MSG_it, pkt);

    ASN1_BIT_STRING_free(os);
    EC_POINT_free(x);
    return r == 0 ? TANG_MSG_ERR_NONE : TANG_MSG_ERR_INTERNAL;

error:
    ASN1_BIT_STRING_free(os);
    EC_POINT_free(x);
    return err == TANG_MSG_ERR_NONE ? TANG_MSG_ERR_INTERNAL : err;
}
