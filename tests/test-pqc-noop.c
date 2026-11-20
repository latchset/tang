/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */
/*
 * Copyright (c) 2026 Red Hat, Inc.
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

#include "http.h"
#undef http_reply

#include <stdarg.h>

/* Stub http_reply: returns the status code without writing to stdout. */
int
http_reply(const char *file, int line,
           http_status_t code, const char *fmt, ...)
{
    return (int)code;
}

#define http_reply(code, ...) \
    http_reply(__FILE__, __LINE__, code, __VA_ARGS__)

#include "pqc_noop.c"
#include "test-util.h"

/* Without PQC support (pqc_noop.c), the hybrid KEM endpoints are
 * hidden: every handler replies 404 and pqc_is_available() is off. */
static void
test_pqc_noop(void)
{
    regmatch_t matches[2] = {0};

    ASSERT(pqc_is_available() == 0);

    ASSERT(adv_kem(HTTP_GET, "/adv-kem?alg=ML-KEM-768", NULL, matches,
                   NULL) == HTTP_STATUS_NOT_FOUND);
    ASSERT(adv_kem_thp(HTTP_GET, "/adv-kem/AAAAAAAA", NULL, matches,
                       NULL) == HTTP_STATUS_NOT_FOUND);
    ASSERT(rec_kem(HTTP_POST, "/rec-kem/AAAAAAAA", "{}", matches,
                   NULL) == HTTP_STATUS_NOT_FOUND);
}

int
main(void)
{
    test_pqc_noop();
    return 0;
}
