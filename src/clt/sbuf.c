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

#include "sbuf.h"

#include <sys/mman.h>
#include <stdlib.h>
#include <string.h>

sbuf_t *
sbuf_new(size_t size)
{
    sbuf_t *tmp = NULL;

    tmp = malloc(sizeof(sbuf_t) + size);
    if (!tmp)
        return NULL;

    if (mlock(tmp, sizeof(sbuf_t) + size) != 0) {
        free(tmp);
        return NULL;
    }

    tmp->size = size;
    return tmp;
}

sbuf_t *
sbuf_from_point(const EC_GROUP *g, const EC_POINT *p, BN_CTX *ctx)
{
    sbuf_t *key = NULL;
    size_t len = 0;

    len = EC_POINT_point2oct(g, p, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
    if (len == 0)
        return NULL;

    key = sbuf_new(len);
    if (!key)
        return NULL;

    if (EC_POINT_point2oct(g, p, POINT_CONVERSION_COMPRESSED,
                           key->data, key->size, ctx) != len) {
        sbuf_free(key);
        return NULL;
    }

    return key;
}

static uint8_t
half2hex(uint8_t c)
{
    c &= 0x0f;

    if (c < 10)
        return '0' + c;

    return 'A' + c - 10;
}

sbuf_t *
sbuf_to_hex(const sbuf_t *sbuf, const char *prefix)
{
    const size_t plen = strlen(prefix);
    sbuf_t *hex = NULL;

    hex = sbuf_new(sbuf->size * 2 + 1 + plen);
    if (!hex)
        return NULL;

    memcpy(hex->data, prefix, plen);

    for (size_t i = 0; i < sbuf->size; i++) {
        hex->data[i * 2 + plen] = half2hex(sbuf->data[i] >> 4);
        hex->data[i * 2 + 1 + plen] = half2hex(sbuf->data[i]);
    }

    hex->data[sbuf->size * 2 + 1 + plen] = '\0';
    return hex;
}

void
sbuf_free(sbuf_t *key)
{
    if (!key)
        return;

    munlock(key, sizeof(sbuf_t) + key->size);
    free(key);
}
