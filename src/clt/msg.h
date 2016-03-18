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

#include "../core/asn1.h"
#include <unistd.h>

typedef struct {
    char hostname[HOST_NAME_MAX];
    char service[HOST_NAME_MAX];
    time_t timeout;
} msg_t;

TANG_MSG *
msg_rqst(const msg_t *params, const TANG_MSG *req);

/** Saves msg to filename. */
int
msg_save(const TANG_MSG *msg, const char *filename);

/** Reads msg from filename. */
TANG_MSG *
msg_read(const char *filename);
