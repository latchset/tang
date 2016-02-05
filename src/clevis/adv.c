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
#include "../pkt.h"

#include <openssl/ecdsa.h>

static bool
add_supported_sigtypes(STACK_OF(ASN1_OBJECT) *types)
{
  static const int methods[] = {
    NID_ecdsa_with_SHA224,
    NID_ecdsa_with_SHA256,
    NID_ecdsa_with_SHA384,
    NID_ecdsa_with_SHA512,
    NID_undef
  };

  for (int i = 0; methods[i] != NID_undef; i++) {
    ASN1_OBJECT *obj = NULL;

    obj = OBJ_nid2obj(methods[i]);
    if (!obj)
      continue;

    if (sk_ASN1_OBJECT_push(types, obj) <= 0)
      return false;
  }

  return true;
}

static bool
add_supported_groups(STACK_OF(ASN1_OBJECT) *grps)
{
  EC_builtin_curve *curves = NULL;
  size_t ncurves = 0;

  ncurves = EC_get_builtin_curves(NULL, 0);
  if (ncurves == 0)
    return false;

  curves = alloca(sizeof(*curves) * ncurves);
  if (!curves)
    return false;

  if (EC_get_builtin_curves(curves, ncurves) != ncurves)
    return false;

  for (size_t i = 0; i < ncurves; i++) {
    ASN1_OBJECT *obj = NULL;

    obj = OBJ_nid2obj(curves[i].nid);
    if (!obj)
      continue;

    if (sk_ASN1_OBJECT_push(grps, obj) <= 0)
      return false;
  }

  return true;
}

TANG_MSG *
adv_rqst(const json_t *cfg)
{
    TANG_MSG *req = NULL;
    TANG_MSG *rep = NULL;

    req = TANG_MSG_new();
    if (!req)
        goto error;

    req->type = TANG_MSG_TYPE_ADV_REQ;
    req->val.adv.req = TANG_MSG_ADV_REQ_new();
    if (!req->val.adv.req)
        goto error;

    req->val.adv.req->body->type = TANG_MSG_ADV_REQ_BDY_TYPE_GRPS;
    req->val.adv.req->body->val.grps = sk_ASN1_OBJECT_new_null();
    if (!req->val.adv.req->body->val.grps)
        goto error;

    if (!add_supported_sigtypes(req->val.adv.req->types) ||
        !add_supported_groups(req->val.adv.req->body->val.grps))
        goto error;

    rep = request(cfg, req);
    if (!rep)
        goto error;

    switch (rep->type) {
    case TANG_MSG_TYPE_ADV_REP:
        break;
    case TANG_MSG_TYPE_ERR:
        fprintf(stderr, "Error: %d\n", ASN1_ENUMERATED_get(rep->val.err));
        goto error;
    default:
        fprintf(stderr, "Received invalid message!\n");
        goto error;
    }

    TANG_MSG_free(req);
    return rep;

error:
    TANG_MSG_free(req);
    TANG_MSG_free(rep);
    return NULL;
}

TANG_MSG *
adv_load(const json_t *cfg)
{
    const json_t *fn = NULL;
    TANG_MSG *rep = NULL;
    FILE *file = NULL;
    pkt_t pkt = {};

    fn = json_object_get(cfg, "adv");
    if (!fn)
        return NULL;

    file = fopen(json_string_value(fn), "r");
    if (!file)
        return NULL;

    pkt.size = fread(pkt.data, 1, sizeof(pkt.data), file);
    fclose(file);
    if (pkt.size <= 0)
        return NULL;

    rep = d2i_TANG_MSG(NULL, &(const unsigned char *) { pkt.data }, pkt.size);
    if (rep || rep->type == TANG_MSG_TYPE_ADV_REP)
        goto error;

    return rep;

error:
    TANG_MSG_free(rep);
    return NULL;
}
