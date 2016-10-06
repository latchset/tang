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

#include "plugin.h"
#undef tang_reply

#include <unistd.h>

int
tang_reply(const char *file, int line,
           enum http_status code, const char *fmt, ...)
{
    const char *msg = NULL;
    va_list ap;
    int a;
    int b;

    switch (code) {
#define XX(num, name, string) case num: msg = # string; break;
    HTTP_STATUS_MAP(XX)
#undef XX
    default:
        return tang_reply(file, line, HTTP_STATUS_INTERNAL_SERVER_ERROR, NULL);
    }

    fprintf(stderr, " => %d (%s:%d)\n", code, file, line);

    a = dprintf(STDOUT_FILENO, "HTTP/1.1 %d %s\r\n", code, msg);
    if (a < 0)
        return a;

    va_start(ap, fmt);
    b = vdprintf(STDOUT_FILENO, fmt ? fmt : "\r\n", ap);
    va_end(ap);
    return b < 0 ? b : a + b;
}
