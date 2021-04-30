/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */
/*
 * Copyright (c) 2020 Red Hat, Inc.
 * Author: Sergio Correia <scorreia@redhat.com>
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

#include <jansson.h>
#include <stddef.h>

struct tang_keys_info {
    /* Arrays. */
    json_t* m_keys;               /* Regular keys. */
    json_t* m_rotated_keys;       /* Rotated keys. */

    json_t* m_payload;            /* Payload made of regular keys capable of
                                   * either signing+verifying or deriving new
                                   * keys. */

    json_t* m_sign;               /* Set of signing keys made from regular
                                     keys. */

    size_t m_keys_count;          /* Number of regular keys. */
    size_t m_rotated_keys_count;  /* Number of rotated keys. */
};

void cleanup_tang_keys_info(struct tang_keys_info**);
void free_tang_keys_info(struct tang_keys_info*);
struct tang_keys_info* read_keys(const char* /* jwkdir */);
json_t* find_jws(struct tang_keys_info* /* tki */, const char* /* thp */);
json_t* find_jwk(struct tang_keys_info* /* tki */, const char* /* thp */);
