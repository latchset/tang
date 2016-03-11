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

#include "rec.h"
#include "../core/conv.h"

#include <openssl/objects.h>

EC_KEY *
rec_req(TANG_MSG_REC_REQ *rec, BN_CTX *ctx)
{
    const EC_GROUP *g = NULL;
    EC_POINT *p = NULL;
    EC_POINT *q = NULL;
    EC_KEY *r = NULL;
    EC_KEY *l = NULL;
    EC_KEY *o = NULL;

    r = conv_tkey2eckey(rec->key, ctx);
    if (!r)
        goto error;

    g = EC_KEY_get0_group(r);
    if (!g)
        goto error;

    p = EC_POINT_new(g);
    if (!p)
        goto error;

    if (conv_os2point(g, rec->x, p, ctx) != 0)
        goto error;

    l = EC_KEY_new_by_curve_name(EC_GROUP_get_curve_name(g));
    if (!l)
        goto error;

    if (EC_KEY_generate_key(l) <= 0)
        goto error;

    q = EC_POINT_new(g);
    if (!q)
        goto error;

    /* p = ag^X */
    if (EC_POINT_add(g, p, p, EC_KEY_get0_public_key(l), ctx) <= 0)
        goto error;

    /* q = inv(b^X) */
    if (EC_POINT_mul(g, q, NULL, EC_KEY_get0_public_key(r),
                     EC_KEY_get0_private_key(l), ctx) <= 0)
        goto error;
    if (EC_POINT_invert(g, q, ctx) <= 0)
        goto error;
    o = EC_KEY_new_by_curve_name(EC_GROUP_get_curve_name(g));
    if (!o)
        goto error;
    if (EC_KEY_set_public_key(o, q) <= 0)
        goto error;

    if (conv_point2os(g, p, rec->x, ctx) != 0)
        goto error;

    EC_POINT_clear_free(p);
    EC_POINT_clear_free(q);
    EC_KEY_free(r);
    EC_KEY_free(l);
    return o;

error:
    EC_POINT_clear_free(p);
    EC_POINT_clear_free(q);
    EC_KEY_free(r);
    EC_KEY_free(l);
    EC_KEY_free(o);
    return NULL;
}

skey_t *
rec_rep(const TANG_MSG_REC_REP *rec, const EC_KEY *key, BN_CTX *ctx)
{
    const EC_GROUP *g = NULL;
    EC_POINT *p = NULL;
    skey_t *out = NULL;

    g = EC_KEY_get0_group(key);
    if (!g)
        goto egress;

    p = EC_POINT_new(g);
    if (!p)
        goto egress;

    if (conv_os2point(g, rec->y, p, ctx) != 0)
        goto egress;

    if (EC_POINT_add(g, p, p, EC_KEY_get0_public_key(key), ctx) <= 0)
        goto egress;

    out = skey_from_point(g, p, ctx);

egress:
    EC_POINT_clear_free(p);
    return out;
}

