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

static TANG_MSG *
decode(const json_t *msg)
{
    clevis_buf_t *buf = NULL;
    TANG_MSG *tmp = NULL;

    buf = clevis_buf_decode(msg);
    if (!buf)
        return NULL;

    tmp = d2i_TANG_MSG(NULL, &(const uint8_t *) { buf->buf }, buf->len);
    clevis_buf_free(buf);
    return tmp;
}

clevis_buf_t *
acquire(const clevis_acquire_f *funcs, const json_t *data)
{
    const EC_GROUP *grp = NULL;
    clevis_buf_t *okey = NULL;
    clevis_buf_t *ikey = NULL;
    TANG_MSG *req = NULL;
    TANG_MSG *rep = NULL;
    EC_KEY *xkey = NULL;
    EC_KEY *rpub = NULL;
    EC_POINT *p = NULL;
    EC_POINT *q = NULL;
    BN_CTX *ctx = NULL;
    int nid;

    /* Prepare basic values. */
    ctx = BN_CTX_new();
    if (!ctx)
        goto egress;

    req = decode(json_object_get(data, "rec"));
    if (!req || req->type != TANG_MSG_TYPE_REC_REQ)
        goto egress;

    rpub = tkey2eckey(req->val.rec.req->key, ctx);
    if (!rpub)
        goto egress;

    grp = EC_KEY_get0_group(rpub);
    if (!grp)
        goto egress;

    p = EC_POINT_new(grp);
    if (!p)
        goto egress;

    q = EC_POINT_new(grp);
    if (!q)
        goto egress;

    xkey = random_key(EC_GROUP_get_curve_name(grp));
    if (!xkey)
        goto egress;

    /* x = ag^X */
    if (conv_os2point(grp, req->val.rec.req->x, p, ctx) != 0)
        goto egress;

    if (EC_POINT_add(grp, p, p, EC_KEY_get0_public_key(xkey), ctx) <= 0)
        goto egress;

    if (conv_point2os(grp, p, req->val.rec.req->x, ctx) != 0)
        goto egress;

    /* Perform request. */
    rep = request(data, req);
    if (!rep || rep->type != TANG_MSG_TYPE_REC_REP)
        goto egress;

    /* Calculate outer key. */
    if (conv_os2point(grp, rep->val.rec.rep->y, p, ctx) != 0)
        goto egress;

    if (EC_POINT_mul(grp, q, NULL, EC_KEY_get0_public_key(rpub),
                     EC_KEY_get0_private_key(xkey), ctx) <= 0)
        goto egress;

    if (EC_POINT_invert(grp, q, ctx) <= 0)
        goto egress;

    if (EC_POINT_add(grp, p, p, q, ctx) <= 0)
        goto egress;

    okey = point2key(grp, p, ctx);
    if (!okey)
        goto egress;

    /* Decrypt inner key. */
    ikey = funcs->decrypt(okey, json_object_get(data, "ct"));

egress:
    clevis_buf_free(okey);
    TANG_MSG_free(req);
    TANG_MSG_free(rep);
    EC_KEY_free(xkey);
    EC_KEY_free(rpub);
    EC_POINT_free(p);
    EC_POINT_free(q);
    BN_CTX_free(ctx);
    return ikey;
}
