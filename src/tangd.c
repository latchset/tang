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

#include "http.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <jose/jose.h>
#include "keys.h"

static void
str_cleanup(char **str)
{
    if (str)
        free(*str);
}

static int
adv(enum http_method method, const char *path, const char *body,
    regmatch_t matches[], void *misc)
{
    __attribute__((cleanup(str_cleanup))) char *adv = NULL;
    __attribute__((cleanup(str_cleanup))) char *thp = NULL;
    __attribute__((cleanup(cleanup_tang_keys_info))) struct tang_keys_info *tki = NULL;
    json_auto_t *jws = NULL;
    const char *jwkdir = misc;

    tki = read_keys(jwkdir);
    if (!tki || tki->m_keys_count == 0) {
        return http_reply(HTTP_STATUS_INTERNAL_SERVER_ERROR, NULL);
    }

    if (matches[1].rm_so < matches[1].rm_eo) {
        size_t size = matches[1].rm_eo - matches[1].rm_so;
        thp = strndup(&path[matches[1].rm_so], size);
        if (!thp)
            return http_reply(HTTP_STATUS_INTERNAL_SERVER_ERROR, NULL);
    }

    jws = find_jws(tki, thp);
    if (!jws) {
        return http_reply(HTTP_STATUS_NOT_FOUND, NULL);
    }

    adv = json_dumps(jws, 0);
    if (!adv)
        return http_reply(HTTP_STATUS_INTERNAL_SERVER_ERROR, NULL);

    return http_reply(HTTP_STATUS_OK,
                      "Content-Type: application/jose+json\r\n"
                      "Content-Length: %zu\r\n"
                      "\r\n%s", strlen(adv), adv);
}

static int
rec(enum http_method method, const char *path, const char *body,
    regmatch_t matches[], void *misc)
{
    __attribute__((cleanup(str_cleanup))) char *enc = NULL;
    __attribute__((cleanup(str_cleanup))) char *thp = NULL;
    __attribute__((cleanup(cleanup_tang_keys_info))) struct tang_keys_info *tki = NULL;
    size_t size = matches[1].rm_eo - matches[1].rm_so;
    const char *jwkdir = misc;
    json_auto_t *jwk = NULL;
    json_auto_t *req = NULL;
    json_auto_t *rep = NULL;
    const char *alg = NULL;
    const char *kty = NULL;
    const char *d = NULL;

    /*
     * Parse and validate the request JWK
     */

    req = json_loads(body, 0, NULL);
    if (!req)
        return http_reply(HTTP_STATUS_BAD_REQUEST, NULL);

    if (!jose_jwk_prm(NULL, req, false, "deriveKey"))
        return http_reply(HTTP_STATUS_FORBIDDEN, NULL);

    if (json_unpack(req, "{s:s,s?s}", "kty", &kty, "alg", &alg) < 0)
        return http_reply(HTTP_STATUS_BAD_REQUEST, NULL);

    if (strcmp(kty, "EC") != 0)
        return http_reply(HTTP_STATUS_BAD_REQUEST, NULL);

    if (alg && strcmp(alg, "ECMR") != 0)
        return http_reply(HTTP_STATUS_BAD_REQUEST, NULL);

    /*
     * Parse and validate the server-side JWK
     */
    tki = read_keys(jwkdir);
    if (!tki || tki->m_keys_count == 0) {
        return http_reply(HTTP_STATUS_INTERNAL_SERVER_ERROR, NULL);
    }

    thp = strndup(&path[matches[1].rm_so], size);
    if (!thp)
        return http_reply(HTTP_STATUS_INTERNAL_SERVER_ERROR, NULL);

    jwk = find_jwk(tki, thp);
    if (!jwk)
        return http_reply(HTTP_STATUS_NOT_FOUND, NULL);

    if (!jose_jwk_prm(NULL, jwk, true, "deriveKey"))
        return http_reply(HTTP_STATUS_FORBIDDEN, NULL);

    if (json_unpack(jwk, "{s:s,s?s}", "d", &d, "alg", &alg) < 0)
        return http_reply(HTTP_STATUS_FORBIDDEN, NULL);

    if (alg && strcmp(alg, "ECMR") != 0)
        return http_reply(HTTP_STATUS_FORBIDDEN, NULL);

    /*
     * Perform the exchange and return
     */
    rep = jose_jwk_exc(NULL, jwk, req);
    if (!rep)
        return http_reply(HTTP_STATUS_BAD_REQUEST, NULL);

    if (json_object_set_new(rep, "alg", json_string("ECMR")) < 0)
        return http_reply(HTTP_STATUS_INTERNAL_SERVER_ERROR, NULL);

    if (json_object_set_new(rep, "key_ops", json_pack("[s]", "deriveKey")) < 0)
        return http_reply(HTTP_STATUS_INTERNAL_SERVER_ERROR, NULL);

    enc = json_dumps(rep, JSON_SORT_KEYS | JSON_COMPACT);
    if (!enc)
        return http_reply(HTTP_STATUS_INTERNAL_SERVER_ERROR, NULL);

    return http_reply(HTTP_STATUS_OK,
                      "Content-Type: application/jwk+json\r\n"
                      "Content-Length: %zu\r\n"
                      "\r\n%s", strlen(enc), enc);
}

static struct http_dispatch dispatch[] = {
    { adv, 1 << HTTP_GET,  2, "^/+adv/+([0-9A-Za-z_-]+)$" },
    { adv, 1 << HTTP_GET,  2, "^/+adv/*$" },
    { rec, 1 << HTTP_POST, 2, "^/+rec/+([0-9A-Za-z_-]+)$" },
    {}
};

int
main(int argc, char *argv[])
{
    struct http_state state = { .dispatch = dispatch, .misc = argv[1] };
    struct http_parser parser = { .data = &state };
    struct stat st = {};
    char req[4096] = {};
    size_t rcvd = 0;
    int r = 0;

    http_parser_init(&parser, HTTP_REQUEST);

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <jwkdir>\n", argv[0]);
        return EXIT_FAILURE;
    }

    if (stat(argv[1], &st) != 0) {
        fprintf(stderr, "Error calling stat() on path: %s: %m\n", argv[1]);
        return EXIT_FAILURE;
    }

    if (!S_ISDIR(st.st_mode)) {
        fprintf(stderr, "Path is not a directory: %s\n", argv[1]);
        return EXIT_FAILURE;
    }

    for (;;) {
        r = read(STDIN_FILENO, &req[rcvd], sizeof(req) - rcvd - 1);
        if (r == 0)
            return rcvd > 0 ? EXIT_FAILURE : EXIT_SUCCESS;
        if (r < 0)
            return EXIT_FAILURE;

        rcvd += r;

        r = http_parser_execute(&parser, &http_settings, req, rcvd);
        if (parser.http_errno != 0) {
            fprintf(stderr, "HTTP Parsing Error: %s\n",
                    http_errno_description(parser.http_errno));
            return EXIT_SUCCESS;
        }

        memmove(req, &req[r], rcvd - r);
        rcvd -= r;
    }

    return EXIT_SUCCESS;
}
