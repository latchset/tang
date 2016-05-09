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

/**
 * The sole purpose of this file is to encapsulate all code related
 * to parsing the LUKS v1 header. It is used to calculate the hole
 * in the LUKS v1 header that arises due to alignment. We will
 * exploit this hole for metadata storage.
 */

#pragma once

#include "../../asn1.h"
#include "../sbuf.h"
#include <luksmeta.h>

static const luksmeta_uuid_t TANG_LUKS_UUID = {
    0x08, 0x02, 0x32, 0x6e, 0xc7, 0x97, 0x2c, 0x59,
    0x00, 0x61, 0x1b, 0xde, 0x16, 0x27, 0xbd, 0x83
};

typedef struct {
    TANG_MSG_REC_REQ *rec;
    ASN1_UTF8STRING *hostname;
    ASN1_UTF8STRING *service;
} TANG_LUKS;

DECLARE_ASN1_FUNCTIONS(TANG_LUKS)

