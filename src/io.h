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

#pragma once

#include <jansson.h>
#include <stdbool.h>

#define _EXPORT_ __attribute__((visibility("default")))

json_t *
tang_io_get_adv(const char *thp);

json_t *
tang_io_get_rec_jwk(const char *thp);

bool
tang_io_is_blocked(const char *bid);

int _EXPORT_
tang_io_add_jwk(bool adv, const json_t *jwk);

int _EXPORT_
tang_io_del_jwk(const json_t *jwk);

int _EXPORT_
tang_io_add_bid(const char *bid);

int _EXPORT_
tang_io_del_bid(const char *bid);
