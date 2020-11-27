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

#include <stdarg.h>

#define ARRAY_COUNT(arr) (sizeof(arr)/sizeof(0[arr]))
#define MAX_BUF_LEN 2048

void
assert_func(const char* /* filename */,
            int /* line number */,
            const char* /* function name */,
            const char* /* expression */,
            const char*  /* format */,
            ...);

#define ASSERT_WITH_MSG(expr, fmt, ...) \
     if (!(expr)) \
        assert_func(__FILE__, __LINE__, __FUNCTION__, #expr, fmt, ##__VA_ARGS__)

#define ASSERT(expr) \
    ASSERT_WITH_MSG(expr, NULL)

char*
create_tempdir(void);

int
remove_tempdir(const char* /* path */);
