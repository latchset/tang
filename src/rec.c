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

#include <jose/jose.h>

#include <errno.h>
#include <string.h>

static int
rec(enum http_method method, const char *path, const char *body,
    regmatch_t matches[])
{
    const json_t *jwk = NULL;
    json_auto_t *req = NULL;
    json_auto_t *rep = NULL;
    const char *kid = NULL;
    const char *kty = NULL;
    char *enc = NULL;
    int r = 0;

    req = json_loads(body, 0, NULL);
    if (!req)
        return tang_reply(HTTP_STATUS_BAD_REQUEST, NULL);

    if (json_unpack(req, "{s:s,s:s}", "kty", &kty, "kid", &kid) != 0)
        return tang_reply(HTTP_STATUS_BAD_REQUEST, NULL);

    if (strcmp(kty, "EC") != 0)
        return tang_reply(HTTP_STATUS_BAD_REQUEST, NULL);

    jwk = tang_db_get_rec_jwk(kid);
    if (!jwk)
        return tang_reply(HTTP_STATUS_BAD_REQUEST, NULL);

    if (!jose_jwk_allowed(jwk, true, NULL, "deriveKey"))
        return tang_reply(HTTP_STATUS_FORBIDDEN, NULL);

    rep = jose_jwk_exchange(jwk, req);
    if (!rep)
        return tang_reply(HTTP_STATUS_BAD_REQUEST, NULL);

    enc = json_dumps(rep, JSON_SORT_KEYS | JSON_COMPACT);
    if (!enc)
        return tang_reply(HTTP_STATUS_INTERNAL_SERVER_ERROR, NULL);

    r = tang_reply(HTTP_STATUS_OK,
                   "Content-Type: application/jwk+json\r\n"
                   "Content-Length: %zu\r\n"
                   "\r\n%s", strlen(enc), enc);
    free(enc);
    return r;
}

static void __attribute__((constructor))
constructor(void)
{
    static struct tang_plugin_map map = {
        rec, 1 << HTTP_POST, 1, "^/+rec/*$"
    };

    map.next = tang_plugin_maps;
    tang_plugin_maps = &map;
}
