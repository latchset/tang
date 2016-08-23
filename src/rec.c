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

#include <systemd/sd-journal.h>

#include <jose/b64.h>
#include <jose/jwk.h>
#include <jose/jwe.h>

#include <errno.h>
#include <string.h>

static void
json_decrefp(json_t **json)
{
    if (json)
        json_decref(*json);
}

static ssize_t
rec(const char *path, regmatch_t matches[],
    const char *body, enum http_method method,
    char pkt[], size_t pktl)
{
    json_t __attribute__((cleanup(json_decrefp))) *req = NULL;
    json_t __attribute__((cleanup(json_decrefp))) *rep = NULL;
    const json_t *jwk = NULL;
    const char *ct = NULL;
    char *thp = NULL;
    char *enc = NULL;
    int r = 0;

    if (matches[1].rm_so >= matches[1].rm_eo)
        return snprintf(pkt, pktl, ERR_TMPL, 400, "Bad Request");

    thp = strndup(&path[matches[1].rm_so],
                  matches[1].rm_eo - matches[1].rm_so);
    if (!thp)
        return snprintf(pkt, pktl, ERR_TMPL, 500, "Internal Server Error");

    jwk = tang_io_get_rec_jwk(thp);
    free(thp);
    if (!jwk)
        return snprintf(pkt, pktl, ERR_TMPL, 404, "Not Found");

    req = json_loads(body, 0, NULL);
    if (!req)
        return snprintf(pkt, pktl, ERR_TMPL, 400, "Bad Request");

    if (jose_jwk_allowed(jwk, true, NULL, "deriveKey")) {
        ct = "application/jwk+json";

        rep = jose_jwk_exchange(jwk, req);
        if (!rep)
            return snprintf(pkt, pktl, ERR_TMPL, 400, "Bad Request");
    } else if (jose_jwk_allowed(jwk, true, NULL, "unwrapKey")) {
        json_t __attribute__((cleanup(json_decrefp))) *hdr = NULL;
        json_t __attribute__((cleanup(json_decrefp))) *jwe = NULL;
        json_t __attribute__((cleanup(json_decrefp))) *cek = NULL;
        const char *bid = NULL;
        uint8_t *pt = NULL;
        bool ret = false;
        size_t ptl = 0;

        ct = "application/jose+json";

        /* Perform outer decryption. */
        cek = jose_jwe_unwrap(req, NULL, jwk);
        if (!cek)
            return snprintf(pkt, pktl, ERR_TMPL, 400, "Bad Request");

        jwe = jose_jwe_decrypt_json(req, cek);
        if (!jwe)
            return snprintf(pkt, pktl, ERR_TMPL, 400, "Bad Request");

        /* Verify tang.bid in the protected header isn't blocked. */
        hdr = jose_b64_decode_json_load(json_object_get(jwe, "protected"));
        if (!hdr)
            return snprintf(pkt, pktl, ERR_TMPL, 400, "Bad Request");

        if (json_unpack(hdr, "{s:s}", "tang.bid", &bid) != 0)
            return snprintf(pkt, pktl, ERR_TMPL, 400, "Bad Request");

        if (tang_io_is_blocked(bid))
            return snprintf(pkt, pktl, ERR_TMPL, 403, "Forbidden");

        /* Perform inner decryption. */
        json_decref(cek);
        cek = jose_jwe_unwrap(jwe, NULL, jwk);
        if (!cek)
            return snprintf(pkt, pktl, ERR_TMPL, 400, "Bad Request");

        pt = jose_jwe_decrypt(jwe, cek, &ptl);
        if (!pt)
            return snprintf(pkt, pktl, ERR_TMPL, 400, "Bad Request");

        /* Perform re-encryption. */
        if (json_unpack(jwe, "{s:{s:o}}",
                        "unprotected", "tang.jwk", &jwk) != 0) {
            memset(pt, 0, ptl);
            free(pt);
            return snprintf(pkt, pktl, ERR_TMPL, 400, "Bad Request");
        }

        json_decref(cek);
        cek = json_object();
        rep = json_object();
        if (!jose_jwe_wrap(rep, cek, jwk, NULL)) {
            memset(pt, 0, ptl);
            free(pt);
            return snprintf(pkt, pktl, ERR_TMPL, 500, "Internal Server Error");
        }

        ret = jose_jwe_encrypt(rep, cek, pt, ptl);
        memset(pt, 0, ptl);
        free(pt);
        if (!ret)
            return snprintf(pkt, pktl, ERR_TMPL, 500, "Internal Server Error");
    }

    /* Dump output. */
    enc = json_dumps(rep, JSON_SORT_KEYS | JSON_COMPACT);
    if (!enc)
        return snprintf(pkt, pktl, ERR_TMPL, 500, "Internal Server Error");

    r = snprintf(pkt, pktl, "HTTP/1.1 200 OK\r\n"
                            "Content-Type: %s\r\n"
                            "Connection: close\r\n"
                            "Content-Length: %zu\r\n"
                            "\r\n%s", ct, strlen(enc), enc);
    free(enc);
    return r;
}

static void __attribute__((constructor))
constructor(void)
{
    static struct tang_plugin_map map = {
        rec, 1 << HTTP_POST, 2, "^/+rec/+([0-9A-Za-z_-]+)$"
    };

    map.next = tang_plugin_maps;
    tang_plugin_maps = &map;
}
