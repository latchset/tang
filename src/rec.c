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

#include <jose/b64.h>
#include <jose/jwk.h>
#include <jose/jwe.h>

#include <errno.h>
#include <string.h>

static jose_buf_t *
decrypt(json_t *jwe, bool *forbidden, const char *fmt, ...)
{
    const json_t *jwk = NULL;
    json_auto_t *arr = NULL;
    json_auto_t *cek = NULL;
    const char *kid = NULL;

    arr = json_incref(json_object_get(jwe, "recipients"));
    if (!arr) {
        arr = json_pack("[O]", jwe);
        if (!arr)
            return NULL;
    }

    for (size_t i = 0; i < json_array_size(arr); i++) {
        json_t *rcp = json_array_get(arr, i);
        jose_buf_auto_t *tmp = NULL;
        json_auto_t *hdr = NULL;
        char *thp = NULL;
        va_list ap;

        hdr = jose_jwe_merge_header(jwe, rcp);
        if (!hdr)
            return NULL;

        if (json_unpack(hdr, "{s:s}", "kid", &kid) != 0)
            return NULL;

        jwk = tang_db_get_rec_jwk(kid);
        if (!jwk)
            continue;

        *forbidden = !jose_jwk_allowed(jwk, true, NULL, "unwrapKey");
        if (*forbidden)
            return NULL;

        cek = jose_jwe_unwrap(jwe, jwk, NULL);
        if (!cek)
            return NULL;

        thp = tang_db_thumbprint(cek);
        if (!thp)
            return NULL;

        fprintf(stderr, " => %s", thp);

        *forbidden = tang_db_is_blocked(cek);
        free(thp);
        if (*forbidden)
            return NULL;

        tmp = jose_jwe_decrypt(jwe, cek);
        if (tmp) {
            if (fmt) {
                va_start(ap, fmt);
                if (json_vunpack_ex(hdr, NULL, 0, fmt, ap) != 0) {
                    va_end(ap);
                    return NULL;
                }
                va_end(ap);
            }

            return jose_buf_incref(tmp);
        }
    }

    return NULL;
}

static int
rec(enum http_method method, const char *path, const char *body,
    regmatch_t matches[])
{
    json_auto_t *req = NULL;
    json_auto_t *rep = NULL;
    const char *kid = NULL;
    const char *kty = NULL;
    const char *ct = NULL;
    char *enc = NULL;
    int r = 0;

    req = json_loads(body, 0, NULL);
    if (!req)
        return tang_reply(HTTP_STATUS_BAD_REQUEST, NULL);

    /* Perform outer decryption if necessary. */
    if (json_object_get(req, "ciphertext")) {
        jose_buf_auto_t *pt = NULL;
        bool forbidden = false;

        pt = decrypt(req, &forbidden, NULL);
        if (!pt) {
            if (forbidden)
                return tang_reply(HTTP_STATUS_FORBIDDEN, NULL);
            return tang_reply(HTTP_STATUS_BAD_REQUEST, NULL);
        }

        json_decref(req);
        req = json_loadb((char *) pt->data, pt->size, 0, NULL);
        if (!req)
            return tang_reply(HTTP_STATUS_BAD_REQUEST, NULL);
    }

    /* Anonymous mode */
    if (json_unpack(req, "{s:s,s:s}", "kty", &kty, "kid", &kid) == 0) {
        const json_t *jwk = NULL;

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

        ct = "application/jwk+json";

    /* Wrap mode */
    } else if (json_object_get(req, "ciphertext")) {
        jose_buf_auto_t *pt = NULL;
        json_auto_t *jwk = NULL;
        json_auto_t *cek = NULL;
        bool forbidden = false;
        bool ret = false;

        /* Perform inner decryption. */
        pt = decrypt(req, &forbidden, "{s:O}", "tang.jwk", &jwk);
        if (!pt) {
            if (forbidden)
                return tang_reply(HTTP_STATUS_FORBIDDEN, NULL);
            return tang_reply(HTTP_STATUS_BAD_REQUEST, NULL);
        }

        /* Perform re-encryption. */
        cek = json_object();
        rep = json_object();
        if (!jose_jwe_wrap(rep, cek, jwk, NULL))
            return tang_reply(HTTP_STATUS_INTERNAL_SERVER_ERROR, NULL);

        ret = jose_jwe_encrypt(rep, cek, pt->data, pt->size);
        if (!ret)
            return tang_reply(HTTP_STATUS_INTERNAL_SERVER_ERROR, NULL);

        ct = "application/jose+json";
    } else {
        return tang_reply(HTTP_STATUS_BAD_REQUEST, NULL);
    }

    /* Dump output. */
    enc = json_dumps(rep, JSON_SORT_KEYS | JSON_COMPACT);
    if (!enc)
        return tang_reply(HTTP_STATUS_INTERNAL_SERVER_ERROR, NULL);

    r = tang_reply(HTTP_STATUS_OK,
                   "Content-Type: %s\r\n"
                   "Content-Length: %zu\r\n"
                   "\r\n%s", ct, strlen(enc), enc);
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
