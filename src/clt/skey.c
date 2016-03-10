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

#include "skey.h"

#include <sys/mman.h>
#include <stdlib.h>

skey_t *
skey_new(size_t size)
{
    skey_t *tmp = NULL;

    tmp = malloc(sizeof(skey_t) + size);
    if (!tmp)
        return NULL;

    if (mlock(tmp, sizeof(skey_t) + size) != 0) {
        free(tmp);
        return NULL;
    }

    tmp->size = size;
    return tmp;
}

skey_t *
skey_from_point(const EC_GROUP *g, const EC_POINT *p, BN_CTX *ctx)
{
    skey_t *key = NULL;
    size_t len = 0;

    len = EC_POINT_point2oct(g, p, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
    if (len == 0)
        return NULL;

    key = skey_new(len);
    if (!key)
        return NULL;

    if (EC_POINT_point2oct(g, p, POINT_CONVERSION_COMPRESSED,
                           key->data, key->size, ctx) != len) {
        skey_free(key);
        return NULL;
    }

    return key;
}

void
skey_free(skey_t *key)
{
    if (!key)
        return;

    munlock(key, sizeof(skey_t) + key->size);
    free(key);
}
