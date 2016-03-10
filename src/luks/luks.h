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

#include <stdbool.h>
#include <stdint.h>

#define LUKS_ALIGN_KEYSLOTS 4096
#define LUKS_NUMKEYS 8

int
luks_hole(const char *device, bool write, uint32_t *length);
