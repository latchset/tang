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

#pragma once
#include <stdbool.h>
#include <limits.h>

#include "../asn1.h"
#include "list.h"

#include <openssl/ec.h>

typedef struct {
    char path[PATH_MAX];
    list_t keys;
    int fd;
} db_t;

typedef struct {
    char name[NAME_MAX];
    list_t list;
    EC_KEY *key;
    TANG_KEY_USE use;
    bool adv;
} db_key_t;

int
db_open(const char *dbdir, db_t **db);

void
db_free(db_t *db);

int
db_event(db_t *db);
