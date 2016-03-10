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

#include "asn1.h"

#include <errno.h>

#include <openssl/objects.h>

ASN1_SEQUENCE(TANG_KEY) = {
    ASN1_EXP(TANG_KEY, grp, ASN1_OBJECT, 0),
    ASN1_EXP(TANG_KEY, key, ASN1_OCTET_STRING, 1),
    ASN1_EXP(TANG_KEY, use, ASN1_ENUMERATED, 2),
} ASN1_SEQUENCE_END(TANG_KEY)

ASN1_SEQUENCE(TANG_SIG) = {
    ASN1_EXP(TANG_SIG, type, ASN1_OBJECT, 0),
    ASN1_EXP(TANG_SIG, sig, ASN1_OCTET_STRING, 1),
} ASN1_SEQUENCE_END(TANG_SIG)

ASN1_SEQUENCE(TANG_MSG_ADV_REP_BDY) = {
    ASN1_EXP_SET_OF(TANG_MSG_ADV_REP_BDY, keys, TANG_KEY, 0),
} ASN1_SEQUENCE_END(TANG_MSG_ADV_REP_BDY)

ASN1_SEQUENCE(TANG_MSG_ADV_REP) = {
    ASN1_EXP(TANG_MSG_ADV_REP, body, TANG_MSG_ADV_REP_BDY, 0),
    ASN1_EXP_SET_OF(TANG_MSG_ADV_REP, sigs, TANG_SIG, 1),
} ASN1_SEQUENCE_END(TANG_MSG_ADV_REP)

ASN1_CHOICE(TANG_MSG_ADV_REQ_BDY) = {
    ASN1_EXP_SET_OF(TANG_MSG_ADV_REQ_BDY, val.grps, ASN1_OBJECT, TANG_MSG_ADV_REQ_BDY_TYPE_GRPS),
    ASN1_EXP_SET_OF(TANG_MSG_ADV_REQ_BDY, val.keys, TANG_KEY, TANG_MSG_ADV_REQ_BDY_TYPE_KEYS),
} ASN1_CHOICE_END(TANG_MSG_ADV_REQ_BDY)

ASN1_SEQUENCE(TANG_MSG_ADV_REQ) = {
    ASN1_EXP_SET_OF(TANG_MSG_ADV_REQ, types, ASN1_OBJECT, 0),
    ASN1_EXP(TANG_MSG_ADV_REQ, body, TANG_MSG_ADV_REQ_BDY, 1),
} ASN1_SEQUENCE_END(TANG_MSG_ADV_REQ)

ASN1_SEQUENCE(TANG_MSG_REC_REP) = {
    ASN1_EXP(TANG_MSG_REC_REP, y, ASN1_OCTET_STRING, 0),
} ASN1_SEQUENCE_END(TANG_MSG_REC_REP)

ASN1_SEQUENCE(TANG_MSG_REC_REQ) = {
    ASN1_EXP(TANG_MSG_REC_REQ, key, TANG_KEY, 0),
    ASN1_EXP(TANG_MSG_REC_REQ, x, ASN1_OCTET_STRING, 1),
} ASN1_SEQUENCE_END(TANG_MSG_REC_REQ)

ASN1_CHOICE(TANG_MSG) = {
    ASN1_EXP(TANG_MSG, val.err, ASN1_ENUMERATED, TANG_MSG_TYPE_ERR),
    ASN1_EXP(TANG_MSG, val.rec.req, TANG_MSG_REC_REQ, TANG_MSG_TYPE_REC_REQ),
    ASN1_EXP(TANG_MSG, val.rec.rep, TANG_MSG_REC_REP, TANG_MSG_TYPE_REC_REP),
    ASN1_EXP(TANG_MSG, val.adv.req, TANG_MSG_ADV_REQ, TANG_MSG_TYPE_ADV_REQ),
    ASN1_EXP(TANG_MSG, val.adv.rep, TANG_MSG_ADV_REP, TANG_MSG_TYPE_ADV_REP),
} ASN1_CHOICE_END(TANG_MSG)


IMPLEMENT_ASN1_FUNCTIONS(TANG_KEY)
IMPLEMENT_ASN1_FUNCTIONS(TANG_SIG)

IMPLEMENT_ASN1_FUNCTIONS(TANG_MSG_ADV_REP_BDY)
IMPLEMENT_ASN1_FUNCTIONS(TANG_MSG_ADV_REP)
IMPLEMENT_ASN1_FUNCTIONS(TANG_MSG_ADV_REQ_BDY)
IMPLEMENT_ASN1_FUNCTIONS(TANG_MSG_ADV_REQ)

IMPLEMENT_ASN1_FUNCTIONS(TANG_MSG_REC_REQ)
IMPLEMENT_ASN1_FUNCTIONS(TANG_MSG_REC_REP)

IMPLEMENT_ASN1_FUNCTIONS(TANG_MSG)

TANG_KEY *
TANG_KEY_copy(const TANG_KEY *key)
{
	TANG_KEY *tmp = NULL;
	uint8_t *buf = NULL;
	int len = 0;

    len = i2d_TANG_KEY((TANG_KEY *) key, &buf);
    if (len <= 0)
        return NULL;

    tmp = d2i_TANG_KEY(NULL, &(const uint8_t *) { buf }, len);
    OPENSSL_free(buf);
    return tmp;
}

bool
TANG_KEY_equals(const TANG_KEY *a, const TANG_KEY *b)
{
    bool eq = true;

    eq &= OBJ_obj2nid(a->grp) == OBJ_obj2nid(b->grp);
    eq &= OBJ_obj2nid(a->grp) != NID_undef;
    eq &= M_ASN1_OCTET_STRING_cmp(a->key, b->key) == 0;

    return eq;
}
