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

#pragma once

#include "asn1.h"

/* Converts an EC_KEY into a TANG_KEY. */
int
conv_eckey2gkey(EC_KEY *key, TANG_KEY_USE use, TANG_KEY *gkey, BN_CTX *ctx);

/* Converts a point to a OCTET STRING. */
int
conv_point2os(const EC_GROUP *grp, const EC_POINT *p, ASN1_OCTET_STRING *os,
              BN_CTX *ctx);

/* Converts a OCTET STRING to a point, verifying curve membership. */
int
conv_os2point(const EC_GROUP *grp, const ASN1_OCTET_STRING *os, EC_POINT *p,
              BN_CTX *ctx);
