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

#include <openssl/asn1t.h>
#include <openssl/ec.h>
#include <stdbool.h>

typedef enum {
    TANG_KEY_USE_NONE = 0,
    TANG_KEY_USE_SIG = 1,
    TANG_KEY_USE_REC = 2,
} TANG_KEY_USE;

typedef struct {
    ASN1_OBJECT *grp;
    ASN1_OCTET_STRING *key;
    ASN1_ENUMERATED *use;
} TANG_KEY;

typedef struct {
    ASN1_OBJECT *type;
    ASN1_OCTET_STRING *sig;
} TANG_SIG;

typedef struct {
    STACK_OF(TANG_KEY) *keys;
} TANG_MSG_ADV_REP_BDY;

typedef struct {
    TANG_MSG_ADV_REP_BDY *body;
    STACK_OF(TANG_SIG) *sigs;
} TANG_MSG_ADV_REP;

typedef enum {
    TANG_MSG_ADV_REQ_BDY_TYPE_GRPS = 0,
    TANG_MSG_ADV_REQ_BDY_TYPE_KEY = 1,
} TANG_MSG_ADV_REQ_BDY_TYPE;

typedef struct {
    TANG_MSG_ADV_REQ_BDY_TYPE type;
    union {
        STACK_OF(ASN1_OBJECT) *grps;
        TANG_KEY *key;
    } val;
} TANG_MSG_ADV_REQ_BDY;

typedef struct {
    STACK_OF(ASN1_OBJECT) *types;
    TANG_MSG_ADV_REQ_BDY *body;
} TANG_MSG_ADV_REQ;

typedef struct {
    ASN1_OCTET_STRING *y;
} TANG_MSG_REC_REP;

typedef struct {
    TANG_KEY *key;
    ASN1_OCTET_STRING *x;
} TANG_MSG_REC_REQ;

typedef enum {
    TANG_MSG_ERR_NONE = 0,
    TANG_MSG_ERR_INTERNAL = 1,
    TANG_MSG_ERR_INVALID_REQUEST = 2,
    TANG_MSG_ERR_NOTFOUND_KEY = 3,
} TANG_MSG_ERR;

typedef enum {
    TANG_MSG_TYPE_ERR = 0,
    TANG_MSG_TYPE_REC_REQ = 1,
    TANG_MSG_TYPE_REC_REP = 2,
    TANG_MSG_TYPE_ADV_REQ = 3,
    TANG_MSG_TYPE_ADV_REP = 4,
} TANG_MSG_TYPE;

typedef struct {
    TANG_MSG_TYPE type;
    union {
        ASN1_ENUMERATED *err;

        union {
            TANG_MSG_REC_REQ *req;
            TANG_MSG_REC_REP *rep;
        } rec;

        union {
            TANG_MSG_ADV_REQ *req;
            TANG_MSG_ADV_REP *rep;
        } adv;
    } val;
} TANG_MSG;


DECLARE_ASN1_FUNCTIONS(TANG_KEY)
DECLARE_ASN1_FUNCTIONS(TANG_SIG)

DECLARE_ASN1_FUNCTIONS(TANG_MSG_ADV_REP_BDY)
DECLARE_ASN1_FUNCTIONS(TANG_MSG_ADV_REP)
DECLARE_ASN1_FUNCTIONS(TANG_MSG_ADV_REQ_BDY)
DECLARE_ASN1_FUNCTIONS(TANG_MSG_ADV_REQ)

DECLARE_ASN1_FUNCTIONS(TANG_MSG_REC_REQ)
DECLARE_ASN1_FUNCTIONS(TANG_MSG_REC_REP)

DECLARE_ASN1_FUNCTIONS(TANG_MSG)


bool
TANG_KEY_equals(const TANG_KEY *a, const TANG_KEY *b);
