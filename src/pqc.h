/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */
/*
 * Copyright (c) 2025 Red Hat, Inc.
 * Author: Sergio Arroutbi <sarroutbi@redhat.com>
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

#include <string.h>

#include "http.h"
#include "keys.h"

#define KEM_ALG_512   "ML-KEM-512"
#define KEM_ALG_768   "ML-KEM-768"
#define KEM_ALG_1024  "ML-KEM-1024"

static inline int
is_valid_kem_alg(const char *alg)
{
    return alg
        && (strcmp(alg, KEM_ALG_512) == 0
            || strcmp(alg, KEM_ALG_768) == 0
            || strcmp(alg, KEM_ALG_1024) == 0);
}

int pqc_is_available(void);

int adv_kem(http_method_t method, const char *path, const char *body,
            regmatch_t matches[], void *misc);

int adv_kem_thp(http_method_t method, const char *path, const char *body,
                regmatch_t matches[], void *misc);

int rec_kem(http_method_t method, const char *path, const char *body,
            regmatch_t matches[], void *misc);
