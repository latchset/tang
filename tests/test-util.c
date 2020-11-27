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

#define  _XOPEN_SOURCE 500L

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <ftw.h>

#include "test-util.h"

void
assert_func(const char* filename,
            int lineno,
            const char* funcname,
            const char* expr,
            const char* fmt,
            ...)
{
    char buffer[MAX_BUF_LEN] = {};
    if (fmt) {
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(buffer, MAX_BUF_LEN, fmt, ap);
        va_end(ap);
        buffer[strcspn(buffer, "\r\n")] = '\0';
    }
    fprintf(stderr, "%s:%d: assertion '%s' failed in %s(). %s\n", filename,
                                                                  lineno,
                                                                  expr,
                                                                  funcname,
                                                                  buffer);
    abort();
}

static int
nftw_remove_callback(const char* path, const struct stat* stat,
                     int type, struct FTW* ftw)
{
    return remove(path);
}

char*
create_tempdir(void)
{
    char template[] = "/tmp/tang.test.XXXXXX";
    char *tmpdir = mkdtemp(template);
    return strdup(tmpdir);
}

int
remove_tempdir(const char* path)
{
    return nftw(path, nftw_remove_callback, FOPEN_MAX, FTW_DEPTH|FTW_MOUNT|FTW_PHYS);
}

