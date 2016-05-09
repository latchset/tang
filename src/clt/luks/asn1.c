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

#include "asn1.h"
#include "../msg.h"

ASN1_SEQUENCE(TANG_LUKS) = {
    ASN1_EXP(TANG_LUKS, rec, TANG_MSG_REC_REQ, 0),
    ASN1_EXP(TANG_LUKS, hostname, ASN1_UTF8STRING, 1),
    ASN1_EXP(TANG_LUKS, service, ASN1_UTF8STRING, 2),
} ASN1_SEQUENCE_END(TANG_LUKS)

IMPLEMENT_ASN1_FUNCTIONS(TANG_LUKS)

