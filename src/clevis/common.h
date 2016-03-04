/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab: */
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

#include <clevis.h>
#include "../asn1.h"

#include <openssl/evp.h>

EC_KEY *
tkey2eckey(const TANG_KEY *tkey, BN_CTX *ctx);

clevis_buf_t *
point2key(const EC_GROUP *grp, const EC_POINT *pnt, BN_CTX *ctx);

EC_KEY *
random_key(int nid);

TANG_MSG *
request(const json_t *cfg, TANG_MSG *req);

TANG_MSG *
adv_rqst(const json_t *cfg);

TANG_MSG *
adv_load(const json_t *cfg);

json_t *
provision(const clevis_provision_f *funcs,
          const json_t *cfg, const clevis_buf_t *key);

clevis_buf_t *
acquire(const clevis_acquire_f *funcs, const json_t *data);
