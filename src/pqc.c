/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */
/*
 * Copyright (c) 2025 Red Hat, Inc.
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

#include <stdlib.h>
#include <string.h>

#include <jose/jose.h>
#include <jose/b64.h>

#include "pqc.h"

int
pqc_is_available(void)
{
    return 1;
}

static void
str_cleanup(char **str)
{
    if (str)
        free(*str);
}

static void
secure_zero(void *p, size_t len)
{
    volatile unsigned char *v = p;
    while (len--)
        *v++ = 0;
}

static void
str_cleanse(char **str)
{
    if (str && *str) {
        secure_zero(*str, strlen(*str));
        free(*str);
    }
}

static json_t *
jwe_from_compact(const char *compact)
{
    const char *dots[4];
    int n = 0;

    for (const char *c = compact; *c && n < 4; c++) {
        if (*c == '.')
            dots[n++] = c;
    }
    if (n != 4)
        return NULL;

    const char *p0 = compact;
    const char *p1 = dots[0] + 1;
    const char *p2 = dots[1] + 1;
    const char *p3 = dots[2] + 1;
    const char *p4 = dots[3] + 1;

    json_auto_t *jwe = json_object();
    if (!jwe)
        return NULL;

    json_object_set_new(jwe, "protected",
        json_stringn(p0, dots[0] - p0));
    json_object_set_new(jwe, "encrypted_key",
        json_stringn(p1, dots[1] - p1));
    json_object_set_new(jwe, "iv",
        json_stringn(p2, dots[2] - p2));
    json_object_set_new(jwe, "ciphertext",
        json_stringn(p3, dots[3] - p3));
    json_object_set_new(jwe, "tag", json_string(p4));

    return json_incref(jwe);
}

static char *
jwe_to_compact(const json_t *jwe)
{
    const char *prot = json_string_value(
        json_object_get(jwe, "protected"));
    const char *ekey = json_string_value(
        json_object_get(jwe, "encrypted_key"));
    const char *iv   = json_string_value(json_object_get(jwe, "iv"));
    const char *ct   = json_string_value(
        json_object_get(jwe, "ciphertext"));
    const char *tag  = json_string_value(json_object_get(jwe, "tag"));

    if (!prot || !iv || !ct || !tag)
        return NULL;
    if (!ekey)
        ekey = "";

    size_t len = strlen(prot) + strlen(ekey) + strlen(iv)
               + strlen(ct) + strlen(tag) + 5;
    char *out = malloc(len);
    if (!out)
        return NULL;
    snprintf(out, len, "%s.%s.%s.%s.%s", prot, ekey, iv, ct, tag);
    return out;
}

static int
rec_kem_secure(json_t *tang_kem_priv, const json_t *req, char **out)
{
    const char *clevis_encrypted_blob = NULL;
    const char *clevis_transport_ct = NULL;

    if (json_unpack((json_t *)req, "{s:s, s:s}",
                    "clevis_encrypted_blob", &clevis_encrypted_blob,
                    "clevis_transport_ct", &clevis_transport_ct) < 0)
        return HTTP_STATUS_BAD_REQUEST;

    json_auto_t *fwd_ct_json = json_string(clevis_transport_ct);
    if (!fwd_ct_json)
        return HTTP_STATUS_BAD_REQUEST;

    json_auto_t *clevis_transport_key =
        jose_jwk_kem_dec(NULL, tang_kem_priv, fwd_ct_json);
    if (!clevis_transport_key)
        return HTTP_STATUS_BAD_REQUEST;

    json_auto_t *blob_jwe = jwe_from_compact(clevis_encrypted_blob);
    if (!blob_jwe)
        return HTTP_STATUS_BAD_REQUEST;

    size_t ptl = 0;
    void *pt = jose_jwe_dec(NULL, blob_jwe, NULL,
                            clevis_transport_key, &ptl);
    json_decref(clevis_transport_key);
    clevis_transport_key = NULL;
    if (!pt)
        return HTTP_STATUS_BAD_REQUEST;

    json_auto_t *payload = json_loadb(pt, ptl, 0, NULL);
    secure_zero(pt, ptl);
    free(pt);
    if (!payload)
        return HTTP_STATUS_BAD_REQUEST;

    const char *clevis_kem_ct = NULL;
    const char *ek_digest = NULL;
    json_t *clevis_kem_pub = NULL;
    if (json_unpack(payload, "{s:s, s:o, s:s}",
                    "clevis_kem_ct", &clevis_kem_ct,
                    "clevis_kem_pub", &clevis_kem_pub,
                    "ek_digest", &ek_digest) < 0)
        return HTTP_STATUS_BAD_REQUEST;

    json_auto_t *kem_ct_json = json_string(clevis_kem_ct);
    if (!kem_ct_json)
        return HTTP_STATUS_BAD_REQUEST;

    json_auto_t *enc_key =
        jose_jwk_kem_dec(NULL, tang_kem_priv, kem_ct_json);
    if (!enc_key)
        return HTTP_STATUS_BAD_REQUEST;

    size_t dlen = jose_jwk_thp_buf(NULL, NULL, "S256", NULL, 0);
    if (dlen == SIZE_MAX)
        return HTTP_STATUS_INTERNAL_SERVER_ERROR;

    size_t elen = jose_b64_enc_buf(NULL, dlen, NULL, 0);
    if (elen == SIZE_MAX)
        return HTTP_STATUS_INTERNAL_SERVER_ERROR;

    uint8_t hash_buf[dlen];
    char thp_buf[elen + 1];

    if (!jose_jwk_thp_buf(NULL, enc_key, "S256", hash_buf, dlen))
        return HTTP_STATUS_INTERNAL_SERVER_ERROR;

    if (jose_b64_enc_buf(hash_buf, dlen, thp_buf, elen) != elen)
        return HTTP_STATUS_INTERNAL_SERVER_ERROR;

    thp_buf[elen] = '\0';

    if (strcmp(thp_buf, ek_digest) != 0)
        return HTTP_STATUS_BAD_REQUEST;

    json_auto_t *ret_encap = jose_jwk_kem_enc(NULL, clevis_kem_pub);
    if (!ret_encap)
        return HTTP_STATUS_INTERNAL_SERVER_ERROR;

    const char *tang_transport_ct =
        json_string_value(json_object_get(ret_encap, "ct"));
    json_t *tang_transport_key =
        json_object_get(ret_encap, "ss");
    if (!tang_transport_ct || !tang_transport_key)
        return HTTP_STATUS_INTERNAL_SERVER_ERROR;

    __attribute__((cleanup(str_cleanse))) char *enc_key_json =
        json_dumps(enc_key, JSON_SORT_KEYS | JSON_COMPACT);
    if (!enc_key_json)
        return HTTP_STATUS_INTERNAL_SERVER_ERROR;

    json_auto_t *resp_jwe = json_pack(
        "{s:{s:s,s:s}}", "protected", "alg", "dir", "enc", "A256GCM");
    if (!resp_jwe)
        return HTTP_STATUS_INTERNAL_SERVER_ERROR;

    if (!jose_jwe_enc(NULL, resp_jwe, NULL, tang_transport_key,
                      enc_key_json, strlen(enc_key_json)))
        return HTTP_STATUS_INTERNAL_SERVER_ERROR;

    __attribute__((cleanup(str_cleanup))) char *tang_encrypted_key =
        jwe_to_compact(resp_jwe);
    if (!tang_encrypted_key)
        return HTTP_STATUS_INTERNAL_SERVER_ERROR;

    json_auto_t *response = json_pack(
        "{s:s, s:s}",
        "tang_encrypted_key", tang_encrypted_key,
        "tang_transport_ct", tang_transport_ct);
    if (!response)
        return HTTP_STATUS_INTERNAL_SERVER_ERROR;

    *out = json_dumps(response, JSON_SORT_KEYS | JSON_COMPACT);
    return *out ? HTTP_STATUS_OK : HTTP_STATUS_INTERNAL_SERVER_ERROR;
}

static json_t*
find_jws_kem(struct tang_keys_info* tki)
{
    if (!tki || json_array_size(tki->m_kem_payload) == 0) {
        return NULL;
    }

    json_auto_t* jws = jwk_sign(tki->m_kem_payload, tki->m_sign);
    if (!jws) {
        return NULL;
    }
    return json_incref(jws);
}

int
adv_kem(http_method_t method, const char *path, const char *body,
        regmatch_t matches[], void *misc)
{
    __attribute__((cleanup(str_cleanup))) char *out = NULL;
    __attribute__((cleanup(cleanup_tang_keys_info)))
        struct tang_keys_info *tki = NULL;
    json_auto_t *jws = NULL;
    const char *jwkdir = misc;

    tki = read_keys(jwkdir);
    if (!tki || tki->m_keys_count == 0)
        return http_reply(HTTP_STATUS_INTERNAL_SERVER_ERROR, NULL);

    jws = find_jws_kem(tki);
    if (!jws)
        return http_reply(HTTP_STATUS_NOT_FOUND, NULL);

    out = json_dumps(jws, 0);
    if (!out)
        return http_reply(HTTP_STATUS_INTERNAL_SERVER_ERROR, NULL);

    return http_reply(HTTP_STATUS_OK,
                      "Content-Type: application/jose+json\r\n"
                      "Content-Length: %zu\r\n"
                      "\r\n%s", strlen(out), out);
}

int
rec_kem(http_method_t method, const char *path, const char *body,
        regmatch_t matches[], void *misc)
{
    __attribute__((cleanup(str_cleanup))) char *enc = NULL;
    __attribute__((cleanup(str_cleanup))) char *thp = NULL;
    __attribute__((cleanup(cleanup_tang_keys_info)))
        struct tang_keys_info *tki = NULL;
    size_t size = matches[1].rm_eo - matches[1].rm_so;
    const char *jwkdir = misc;
    json_auto_t *tang_kem_priv = NULL;
    json_auto_t *req = NULL;
    const char *kty = NULL;
    int status;

    req = json_loads(body, 0, NULL);
    if (!req)
        return http_reply(HTTP_STATUS_BAD_REQUEST, NULL);

    tki = read_keys(jwkdir);
    if (!tki || tki->m_keys_count == 0)
        return http_reply(HTTP_STATUS_INTERNAL_SERVER_ERROR, NULL);

    thp = strndup(&path[matches[1].rm_so], size);
    if (!thp)
        return http_reply(HTTP_STATUS_INTERNAL_SERVER_ERROR, NULL);

    tang_kem_priv = find_jwk(tki, thp);
    if (!tang_kem_priv)
        return http_reply(HTTP_STATUS_NOT_FOUND, NULL);

    if (json_unpack(tang_kem_priv, "{s:s}", "kty", &kty) < 0)
        return http_reply(HTTP_STATUS_FORBIDDEN, NULL);

    if (strcmp(kty, "AKP") != 0)
        return http_reply(HTTP_STATUS_FORBIDDEN, NULL);

    if (!jose_jwk_prm(NULL, tang_kem_priv, true, "deriveKey"))
        return http_reply(HTTP_STATUS_FORBIDDEN, NULL);

    status = rec_kem_secure(tang_kem_priv, req, &enc);
    if (status != HTTP_STATUS_OK)
        return http_reply(status, NULL);

    return http_reply(HTTP_STATUS_OK,
                      "Content-Type: application/jwk+json\r\n"
                      "Content-Length: %zu\r\n"
                      "\r\n%s", strlen(enc), enc);
}
