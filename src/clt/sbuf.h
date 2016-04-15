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

#pragma once

#include <stddef.h>
#include <stdint.h>

#include <openssl/ec.h>

typedef struct {
    size_t size;
    uint8_t data[];
} sbuf_t;

sbuf_t *
sbuf_new(size_t size);

sbuf_t *
sbuf_from_point(const EC_GROUP *g, const EC_POINT *p, BN_CTX *ctx);

sbuf_t *
sbuf_to_hex(const sbuf_t *sbuf, const char *prefix);

void
sbuf_free(sbuf_t *sbuf);
