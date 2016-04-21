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

#include "conv.h"
#include <errno.h>

#include <openssl/objects.h>

int
conv_point2tkey(const EC_GROUP *grp, const EC_POINT *pnt, TANG_KEY *tkey,
                BN_CTX *ctx)
{
    int r;

    if (!grp)
        return EINVAL;

    ASN1_OBJECT_free(tkey->grp);
    tkey->grp = OBJ_nid2obj(EC_GROUP_get_curve_name(grp));
    if (!tkey->grp)
        return ENOMEM;

    r = conv_point2os(grp, pnt, tkey->key, ctx);
    if (r != 0)
        return ENOMEM;

    return 0;
}

int
conv_eckey2tkey(const EC_KEY *key, TANG_KEY *tkey,
                BN_CTX *ctx)
{
    return conv_point2tkey(EC_KEY_get0_group(key),
                           EC_KEY_get0_public_key(key),
                           tkey, ctx);
}

EC_KEY *
conv_tkey2eckey(const TANG_KEY *tkey, BN_CTX *ctx)
{
    EC_KEY *eckey = NULL;
    EC_POINT *p = NULL;
    int nid;

    nid = OBJ_obj2nid(tkey->grp);
    if (nid == NID_undef)
        goto error;

    eckey = EC_KEY_new_by_curve_name(nid);
    if (!eckey)
        goto error;

    p = EC_POINT_new(EC_KEY_get0_group(eckey));
    if (!p)
        goto error;

    if (conv_os2point(EC_KEY_get0_group(eckey), tkey->key, p, ctx) != 0)
        goto error;

    if (EC_KEY_set_public_key(eckey, p) <= 0)
        goto error;

    EC_POINT_free(p);
    return eckey;

error:
    EC_POINT_free(p);
    EC_KEY_free(eckey);
    return NULL;
}


int
conv_point2os(const EC_GROUP *grp, const EC_POINT *p, ASN1_OCTET_STRING *os,
              BN_CTX *ctx)
{
    size_t s;

    s = EC_POINT_point2oct(grp, p, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
    if (s == 0)
        return ENOMEM;

    unsigned char buf[s];

    s = EC_POINT_point2oct(grp, p, POINT_CONVERSION_COMPRESSED, buf, s, ctx);
    if (s == 0)
        return ENOMEM;

    if (ASN1_OCTET_STRING_set(os, buf, s) <= 0)
        return ENOMEM;

    return 0;
}

int
conv_os2point(const EC_GROUP *grp, const ASN1_OCTET_STRING *os, EC_POINT *p,
              BN_CTX *ctx)
{
    if (EC_POINT_oct2point(grp, p, os->data, os->length, ctx) <= 0)
        return ENOMEM;

    if (EC_POINT_is_on_curve(grp, p, ctx) == 0)
        return EINVAL;

    if (EC_POINT_is_at_infinity(grp, p))
        return EINVAL;

    return 0;
}

