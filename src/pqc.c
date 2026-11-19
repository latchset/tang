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

#include <openssl/crypto.h>
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

/* Wipes the base64url-encoded "k" secret of a JWK in place and removes
 * the member from the object.
 *
 * NOTE: this mutates a shared json_t: any other holder of the object
 * loses access to "k". The string is owned exclusively by the json_t
 * (jansson exposes it as const only to discourage modification), so
 * cleansing it in place is safe; the NUL terminator is part of the
 * allocation and is cleansed too. */
static void
wipe_jwk_secret(json_t *jwk)
{
    json_t *k = json_object_get(jwk, "k");
    if (k) {
        const char *str = json_string_value(k);
        if (str)
            OPENSSL_cleanse((void *)str, json_string_length(k) + 1);
        json_object_del(jwk, "k");
    }
}

static json_t *
jwe_from_compact(const char *compact)
{
    const char *dots[4];
    int n = 0;

    /* Count every separator: a compact JWE has exactly four dots, and
     * inputs with more must be rejected outright instead of having the
     * extra segments folded into the tag, which would only be rejected
     * later by jose_jwe_dec() after an unnecessary private-key
     * decapsulation. */
    for (const char *c = compact; *c; c++) {
        if (*c != '.')
            continue;
        if (n < 4)
            dots[n] = c;
        n++;
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

    if (json_object_set_new(jwe, "protected",
        json_stringn(p0, dots[0] - p0)) != 0
        || json_object_set_new(jwe, "encrypted_key",
        json_stringn(p1, dots[1] - p1)) != 0
        || json_object_set_new(jwe, "iv",
        json_stringn(p2, dots[2] - p2)) != 0
        || json_object_set_new(jwe, "ciphertext",
        json_stringn(p3, dots[3] - p3)) != 0
        || json_object_set_new(jwe, "tag", json_string(p4)) != 0)
        return NULL;

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

static void
wipe_and_release(json_t **jwk)
{
    if (jwk && *jwk) {
        wipe_jwk_secret(*jwk);
        json_decref(*jwk);
        *jwk = NULL;
    }
}

/* Maximum decoded size accepted for a request protected header. The
 * legitimate header is a few hundred bytes, so anything larger is
 * rejected before allocating, to prevent stack/heap exhaustion through
 * oversized unauthenticated input. */
#define MAX_PROTECTED_HEADER_LEN 4096

static int
is_valid_suite(const char *suite)
{
    if (!suite || strncmp(suite, ECMR_ALG, sizeof(ECMR_ALG) - 1) != 0)
        return 0;
    if (suite[sizeof(ECMR_ALG) - 1] != '+')
        return 0;

    return is_valid_kem_alg(suite + sizeof(ECMR_ALG));
}

static int
header_field_matches(const json_t *header, const char *field,
                     const char *expected)
{
    const char *val = json_string_value(json_object_get(header, field));
    return val && strcmp(val, expected) == 0;
}

/* Extension parameters this implementation understands, i.e. the only
 * entries accepted in a request crit list. "kid" is a standard JOSE
 * header (RFC 7515 section 4.1.4) and therefore never listed in crit;
 * the response crit carries exactly these four entries. */
static const char *const known_crit[] = {
    "kem_ver", "suite", "kem_kid", "msg_dir", NULL
};

/* RFC 7515 section 4.1.11: critical parameters that are not understood
 * MUST cause the input to be rejected. crit itself is optional, but
 * when present it must be a non-empty array of distinct, known
 * extension names. */
static int
crit_entries_known(const json_t *header)
{
    const json_t *crit = json_object_get(header, "crit");
    if (!crit)
        return 1;

    if (!json_is_array(crit))
        return 0;

    if (json_array_size(crit) == 0)
        return 0;

    size_t idx;
    json_t *entry;
    json_array_foreach((json_t *)crit, idx, entry) {
        const char *name = json_string_value(entry);
        if (!name)
            return 0;

        /* RFC 7515 section 4.1.11: duplicate entries are invalid. */
        for (size_t prev = 0; prev < idx; prev++) {
            const char *other = json_string_value(
                json_array_get(crit, prev));
            if (other && strcmp(name, other) == 0)
                return 0;
        }

        int known = 0;
        for (size_t i = 0; known_crit[i]; i++) {
            if (strcmp(name, known_crit[i]) == 0) {
                known = 1;
                break;
            }
        }
        if (!known)
            return 0;
    }
    return 1;
}

static int
validate_request_protected(const json_t *blob_jwe,
                           struct tang_keys_info *tki,
                           const char *path_kem_kid,
                           const char *expected_suite,
                           char **out_ecmr_kid)
{
    const char *protected_b64 = json_string_value(
        json_object_get(blob_jwe, "protected"));
    if (!protected_b64)
        return 0;

    size_t dec_len = jose_b64_dec_buf(
        protected_b64, strlen(protected_b64), NULL, 0);
    if (dec_len == SIZE_MAX)
        return 0;

    /* The protected header is attacker-controlled input on an
     * unauthenticated endpoint: cap its size and keep it off the stack
     * (no VLAs) so it cannot be used to exhaust stack memory. */
    if (dec_len > MAX_PROTECTED_HEADER_LEN)
        return 0;

    uint8_t *dec_buf = malloc(dec_len);
    if (!dec_buf)
        return 0;

    json_auto_t *header = NULL;
    if (jose_b64_dec_buf(protected_b64, strlen(protected_b64),
                         dec_buf, dec_len) == dec_len) {
        /* The protected header is base64-decoded plaintext, so feed
         * json_loadb() the exact decoded length: json_loads() would
         * stop at the first embedded NUL and silently accept trailing
         * garbage. Reject duplicate members as required by
         * RFC 8725 §3.12. */
        header = json_loadb((const char *)dec_buf, dec_len,
                            JSON_REJECT_DUPLICATES, NULL);
    }
    free(dec_buf);

    if (!header)
        return 0;

    /* Pin the JWE algorithms (RFC 8725) before anything else: only
     * direct encryption with an empty encrypted_key is accepted, and
     * compression is rejected entirely. Without this, an
     * unauthenticated client could pick other jose-supported
     * algorithms against the raw shared secret, or use RFC 7516
     * "zip": "DEF" to inflate a decompression bomb inside
     * jose_jwe_dec(). */
    if (!header_field_matches(header, "alg", "dir")
        || !header_field_matches(header, "enc", "A256GCM")
        || !header_field_matches(blob_jwe, "encrypted_key", "")
        || json_object_get(header, "zip") != NULL)
        return 0;

    if (!header_field_matches(header, "msg_dir", DIR_REQUEST)
        || !header_field_matches(header, "kem_kid", path_kem_kid)
        || !header_field_matches(header, "kem_ver", KEM_VERSION))
        return 0;

    if (!crit_entries_known(header))
        return 0;

    /* The declared suite must match the suite derived from the algorithm
     * of the KEM key selected through the request path, so that a client
     * cannot make tang assert a false (e.g., stronger) parameter set. */
    const char *suite = json_string_value(
        json_object_get(header, "suite"));
    if (!is_valid_suite(suite) || strcmp(suite, expected_suite) != 0)
        return 0;

    /* The classical (ECMR) key identifier must belong to a key actually
     * held by this server: tang must never echo identifiers of keys it
     * does not hold. */
    const char *kid = json_string_value(
        json_object_get(header, "kid"));
    if (!kid)
        return 0;

    json_auto_t *ecmr_key = find_jwk(tki, kid);
    if (!ecmr_key)
        return 0;

    const char *ecmr_alg = json_string_value(
        json_object_get(ecmr_key, "alg"));
    if (!ecmr_alg || strcmp(ecmr_alg, ECMR_ALG) != 0)
        return 0;

    /* Match the key validation rec() applies to its server-side JWK:
     * "kty": "EC" and private key material (req = true), so /rec-kem
     * cannot bind to a public-only or malformed key that /rec would
     * reject. */
    const char *ecmr_kty = json_string_value(
        json_object_get(ecmr_key, "kty"));
    if (!ecmr_kty || strcmp(ecmr_kty, "EC") != 0)
        return 0;

    if (!jose_jwk_prm(NULL, ecmr_key, true, "deriveKey"))
        return 0;

    *out_ecmr_kid = strdup(kid);
    return *out_ecmr_kid != NULL;
}

static int
rec_kem_secure(json_t *tang_kem_priv, struct tang_keys_info *tki,
               const char *path_kem_kid, const json_t *req, char **out)
{
    const char *clevis_encrypted_blob = NULL;
    const char *clevis_transport_ct = NULL;
    int status = HTTP_STATUS_BAD_REQUEST;

    /* The suite is derived from the algorithm of the KEM key selected
     * through the request path, never from client-declared data, so that
     * tang cannot be made to assert a parameter set stronger than the
     * key actually used (anti-downgrade). */
    const char *tang_kem_alg = json_string_value(
        json_object_get(tang_kem_priv, "alg"));
    if (!is_valid_kem_alg(tang_kem_alg))
        return HTTP_STATUS_INTERNAL_SERVER_ERROR;

    char suite[strlen(ECMR_ALG) + 1 + strlen(tang_kem_alg) + 1];
    snprintf(suite, sizeof(suite), "%s+%s", ECMR_ALG, tang_kem_alg);

    if (json_unpack((json_t *)req, "{s:s, s:s}",
                    "clevis_encrypted_blob", &clevis_encrypted_blob,
                    "clevis_transport_ct", &clevis_transport_ct) < 0)
        return HTTP_STATUS_BAD_REQUEST;

    json_auto_t *blob_jwe = jwe_from_compact(clevis_encrypted_blob);
    if (!blob_jwe)
        return HTTP_STATUS_BAD_REQUEST;

    /* Validate the protected header before any expensive crypto: it is
     * base64-encoded plaintext, so garbage is rejected cheaply here,
     * before the transport KEM decapsulation and AES-GCM decrypt. */
    __attribute__((cleanup(str_cleanup))) char *ecmr_kid = NULL;
    if (!validate_request_protected(blob_jwe, tki, path_kem_kid,
                                    suite, &ecmr_kid))
        return HTTP_STATUS_BAD_REQUEST;

    json_auto_t *fwd_ct_json = json_string(clevis_transport_ct);
    if (!fwd_ct_json)
        return HTTP_STATUS_BAD_REQUEST;

    json_t *clevis_transport_key =
        jose_jwk_kem_dec(NULL, tang_kem_priv, fwd_ct_json);
    if (!clevis_transport_key)
        return HTTP_STATUS_BAD_REQUEST;

    size_t plaintext_len = 0;
    void *plaintext = jose_jwe_dec(NULL, blob_jwe, NULL,
                            clevis_transport_key, &plaintext_len);
    wipe_and_release(&clevis_transport_key);
    if (!plaintext)
        return HTTP_STATUS_BAD_REQUEST;

    json_auto_t *payload = json_loadb(plaintext, plaintext_len,
                                      JSON_REJECT_DUPLICATES, NULL);
    /* jose_jwe_dec() returns a libc-allocated buffer: cleanse it and
     * release it with free(), never with OPENSSL_clear_free(), whose
     * OPENSSL_free() is only valid on OPENSSL_malloc() memory. */
    OPENSSL_cleanse(plaintext, plaintext_len);
    free(plaintext);
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

    const char *pub_kty = json_string_value(
        json_object_get(clevis_kem_pub, "kty"));
    if (!pub_kty || strcmp(pub_kty, "AKP") != 0)
        return HTTP_STATUS_BAD_REQUEST;

    const char *pub_alg = json_string_value(
        json_object_get(clevis_kem_pub, "alg"));
    if (!is_valid_kem_alg(pub_alg))
        return HTTP_STATUS_BAD_REQUEST;

    /* The client KEM key must use the same parameter set as the tang KEM
     * key selected through the request path. */
    if (strcmp(pub_alg, tang_kem_alg) != 0)
        return HTTP_STATUS_BAD_REQUEST;

    if (!jose_jwk_prm(NULL, clevis_kem_pub, false, "deriveKey"))
        return HTTP_STATUS_BAD_REQUEST;

    json_auto_t *kem_ct_json = json_string(clevis_kem_ct);
    if (!kem_ct_json)
        return HTTP_STATUS_BAD_REQUEST;

    size_t dlen = jose_jwk_thp_buf(NULL, NULL, "S256", NULL, 0);
    if (dlen == SIZE_MAX)
        return HTTP_STATUS_INTERNAL_SERVER_ERROR;

    size_t elen = jose_b64_enc_buf(NULL, dlen, NULL, 0);
    if (elen == SIZE_MAX)
        return HTTP_STATUS_INTERNAL_SERVER_ERROR;

    uint8_t hash_buf[dlen];
    char thp_buf[elen + 1];

    json_t *enc_key =
        jose_jwk_kem_dec(NULL, tang_kem_priv, kem_ct_json);
    if (!enc_key)
        return HTTP_STATUS_BAD_REQUEST;

    json_t *ret_encap = NULL;
    json_t *tang_transport_key = NULL;
    char *enc_key_json = NULL;
    json_t *resp_jwe = NULL;
    char *tang_encrypted_key = NULL;
    json_t *response = NULL;

    if (!jose_jwk_thp_buf(NULL, enc_key, "S256", hash_buf, dlen)) {
        status = HTTP_STATUS_INTERNAL_SERVER_ERROR;
        goto cleanup;
    }

    if (jose_b64_enc_buf(hash_buf, dlen, thp_buf, elen) != elen) {
        status = HTTP_STATUS_INTERNAL_SERVER_ERROR;
        goto cleanup;
    }

    thp_buf[elen] = '\0';

    /* ek_digest is the proof of knowledge of enc_key, the only thing
     * preventing tang from acting as a decapsulation oracle for an
     * intercepted clevis_kem_ct: compare it in constant time, so the
     * digest cannot be recovered byte-by-byte through a timing side
     * channel. The length check runs first both to reject mismatches
     * cheaply and to keep CRYPTO_memcmp within the string. */
    if (strlen(ek_digest) != elen
        || CRYPTO_memcmp(thp_buf, ek_digest, elen) != 0)
        goto cleanup;

    ret_encap = jose_jwk_kem_enc(NULL, clevis_kem_pub);
    if (!ret_encap) {
        status = HTTP_STATUS_INTERNAL_SERVER_ERROR;
        goto cleanup;
    }

    const char *tang_transport_ct =
        json_string_value(json_object_get(ret_encap, "ct"));
    tang_transport_key = json_object_get(ret_encap, "ss");
    if (!tang_transport_ct || !tang_transport_key) {
        status = HTTP_STATUS_INTERNAL_SERVER_ERROR;
        goto cleanup;
    }

    enc_key_json = json_dumps(enc_key, JSON_SORT_KEYS | JSON_COMPACT);
    if (!enc_key_json) {
        status = HTTP_STATUS_INTERNAL_SERVER_ERROR;
        goto cleanup;
    }

    resp_jwe = json_pack(
        "{s:{s:s, s:s, s:[ssss], s:s, s:s, s:s, s:s, s:s}}",
        "protected",
        "alg", "dir",
        "enc", "A256GCM",
        "crit", "kem_ver", "suite", "kem_kid",
                "msg_dir",
        "kem_ver", KEM_VERSION,
        "suite", suite,
        "kid", ecmr_kid,
        "kem_kid", path_kem_kid,
        "msg_dir", DIR_RESPONSE);
    if (!resp_jwe) {
        status = HTTP_STATUS_INTERNAL_SERVER_ERROR;
        goto cleanup;
    }

    if (!jose_jwe_enc(NULL, resp_jwe, NULL, tang_transport_key,
                      enc_key_json, strlen(enc_key_json))) {
        status = HTTP_STATUS_INTERNAL_SERVER_ERROR;
        goto cleanup;
    }

    tang_encrypted_key = jwe_to_compact(resp_jwe);
    if (!tang_encrypted_key) {
        status = HTTP_STATUS_INTERNAL_SERVER_ERROR;
        goto cleanup;
    }

    response = json_pack(
        "{s:s, s:s}",
        "tang_encrypted_key", tang_encrypted_key,
        "tang_transport_ct", tang_transport_ct);
    if (!response) {
        status = HTTP_STATUS_INTERNAL_SERVER_ERROR;
        goto cleanup;
    }

    *out = json_dumps(response, JSON_SORT_KEYS | JSON_COMPACT);
    status = *out ? HTTP_STATUS_OK : HTTP_STATUS_INTERNAL_SERVER_ERROR;

cleanup:
    OPENSSL_cleanse(hash_buf, sizeof(hash_buf));
    OPENSSL_cleanse(thp_buf, sizeof(thp_buf));
    if (tang_transport_key)
        wipe_jwk_secret(tang_transport_key);
    wipe_and_release(&enc_key);
    if (enc_key_json) {
        /* json_dumps() uses Jansson's allocator: cleanse and free(),
         * not OPENSSL_clear_free(). */
        OPENSSL_cleanse(enc_key_json, strlen(enc_key_json) + 1);
        free(enc_key_json);
    }
    free(tang_encrypted_key);
    json_decref(ret_encap);
    json_decref(resp_jwe);
    json_decref(response);
    return status;
}

#define MAX_ALG_LEN 32

static int
is_valid_alg_param(const char *alg)
{
    size_t len = strlen(alg);
    if (len == 0 || len > MAX_ALG_LEN)
        return 0;
    for (size_t i = 0; i < len; i++) {
        char c = alg[i];
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') || c == '-'))
            return 0;
    }
    return 1;
}

static char *
parse_query_alg(const char *query, size_t len)
{
    if (!query || len == 0 || query[0] != '?')
        return NULL;

    const char *p = query + 1;
    const char *end = query + len;
    const char *key = "alg=";
    size_t klen = 4;

    while (p < end) {
        if ((size_t)(end - p) >= klen && strncmp(p, key, klen) == 0) {
            const char *val = p + klen;
            const char *vend = memchr(val, '&', end - val);
            if (!vend)
                vend = end;
            if (vend == val)
                return NULL;
            return strndup(val, vend - val);
        }
        const char *next = memchr(p, '&', end - p);
        if (!next)
            break;
        p = next + 1;
    }
    return NULL;
}

static json_t*
find_jws_kem(struct tang_keys_info *tki, const char *alg)
{
    if (!tki)
        return NULL;

    if (!alg)
        return NULL;

    json_auto_t *payload = json_array();
    if (!payload)
        return NULL;

    size_t idx;
    json_t *jwk;
    json_array_foreach(tki->m_kem_payload, idx, jwk) {
        const char *key_alg = json_string_value(
            json_object_get(jwk, "alg"));
        if (key_alg && strcmp(key_alg, alg) == 0) {
            if (json_array_append(payload, jwk) < 0)
                return NULL;
        }
    }
    if (json_array_size(payload) == 0)
        return NULL;

    json_auto_t *jws = jwk_sign(payload, tki->m_sign);
    if (!jws)
        return NULL;
    return json_incref(jws);
}

int
adv_kem(http_method_t method, const char *path, const char *body,
        regmatch_t matches[], void *misc)
{
    __attribute__((cleanup(str_cleanup))) char *out = NULL;
    __attribute__((cleanup(str_cleanup))) char *alg = NULL;
    __attribute__((cleanup(cleanup_tang_keys_info)))
        struct tang_keys_info *tki = NULL;
    json_auto_t *jws = NULL;
    const char *jwkdir = misc;

    /* Validate the query before touching the key directory: a
     * malformed request must not read or (re)generate keys. */
    if (matches[1].rm_so < matches[1].rm_eo) {
        size_t qlen = matches[1].rm_eo - matches[1].rm_so;
        alg = parse_query_alg(&path[matches[1].rm_so], qlen);
        if (alg && !is_valid_alg_param(alg))
            return http_reply(HTTP_STATUS_BAD_REQUEST, NULL);
    }

    if (!alg)
        return http_reply(HTTP_STATUS_BAD_REQUEST, NULL);

    /* An algorithm that is not a supported ML-KEM variant can never
     * match any key in m_kem_payload, so reject it before
     * read_keys(): an unsupported algorithm must not read or
     * (re)generate keys on disk. */
    if (!is_valid_kem_alg(alg))
        return http_reply(HTTP_STATUS_NOT_FOUND, NULL);

    tki = read_keys(jwkdir);
    if (!tki || tki->m_keys_count == 0)
        return http_reply(HTTP_STATUS_INTERNAL_SERVER_ERROR, NULL);

    jws = find_jws_kem(tki, alg);
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

static json_t*
find_jws_kem_by_thp(struct tang_keys_info *keys_info, const char *thumbprint)
{
    if (!keys_info || !thumbprint)
        return NULL;

    json_auto_t *key = find_jwk(keys_info, thumbprint);
    if (!key)
        return NULL;

    const char *key_type = json_string_value(json_object_get(key, "kty"));
    if (!key_type || strcmp(key_type, "AKP") != 0)
        return NULL;

    /* RFC 9864: "AKP" also covers post-quantum signature algorithms
     * (e.g. ML-DSA); only supported ML-KEM exchange keys are
     * advertised, and only with the same deriveKey predicate /rec-kem
     * enforces (req = true), so clients cannot bind to a key that
     * /rec-kem would later reject. */
    const char *key_alg = json_string_value(json_object_get(key, "alg"));
    if (!is_valid_kem_alg(key_alg))
        return NULL;

    if (!jose_jwk_prm(NULL, key, true, "deriveKey"))
        return NULL;

    json_auto_t *payload = json_array();
    if (!payload)
        return NULL;
    if (json_array_append(payload, key) < 0)
        return NULL;

    json_auto_t *signed_keys = jwk_sign(payload, keys_info->m_sign);
    if (!signed_keys)
        return NULL;
    return json_incref(signed_keys);
}

/* Extracts the thumbprint captured in matches[1] and loads the key
 * store from jwkdir, so the KEM endpoints share a single status
 * mapping instead of diverging copies: 400 when the path carries no
 * thumbprint, 500 when the key store cannot be read. Returns the
 * thumbprint (owned by the caller) and stores the owning key set info
 * in *out_tki, or NULL with *out_status set. */
static char *
load_thp_keys(const char *path, regmatch_t matches[], const char *jwkdir,
              struct tang_keys_info **out_tki, int *out_status)
{
    *out_tki = NULL;
    *out_status = HTTP_STATUS_INTERNAL_SERVER_ERROR;

    if (matches[1].rm_so >= matches[1].rm_eo) {
        *out_status = HTTP_STATUS_BAD_REQUEST;
        return NULL;
    }

    struct tang_keys_info *tki = read_keys(jwkdir);
    if (!tki || tki->m_keys_count == 0)
        return NULL;
    *out_tki = tki;

    size_t size = matches[1].rm_eo - matches[1].rm_so;
    return strndup(&path[matches[1].rm_so], size);
}

int
adv_kem_thp(http_method_t method, const char *path, const char *body,
            regmatch_t matches[], void *misc)
{
    __attribute__((cleanup(str_cleanup))) char *output = NULL;
    __attribute__((cleanup(str_cleanup))) char *thumbprint = NULL;
    __attribute__((cleanup(cleanup_tang_keys_info)))
        struct tang_keys_info *keys_info = NULL;
    json_auto_t *signed_keys = NULL;
    const char *jwkdir = misc;
    int status;

    thumbprint = load_thp_keys(path, matches, jwkdir, &keys_info,
                               &status);
    if (!thumbprint)
        return http_reply(status, NULL);

    signed_keys = find_jws_kem_by_thp(keys_info, thumbprint);
    if (!signed_keys)
        return http_reply(HTTP_STATUS_NOT_FOUND, NULL);

    output = json_dumps(signed_keys, 0);
    if (!output)
        return http_reply(HTTP_STATUS_INTERNAL_SERVER_ERROR, NULL);

    return http_reply(HTTP_STATUS_OK,
                      "Content-Type: application/jose+json\r\n"
                      "Content-Length: %zu\r\n"
                      "\r\n%s", strlen(output), output);
}

int
rec_kem(http_method_t method, const char *path, const char *body,
        regmatch_t matches[], void *misc)
{
    __attribute__((cleanup(str_cleanup))) char *enc = NULL;
    __attribute__((cleanup(str_cleanup))) char *thp = NULL;
    __attribute__((cleanup(cleanup_tang_keys_info)))
        struct tang_keys_info *tki = NULL;
    const char *jwkdir = misc;
    json_auto_t *tang_kem_priv = NULL;
    json_auto_t *req = NULL;
    const char *kty = NULL;
    int status;

    /* Reject duplicate members (RFC 8725 §3.12) in the request body. */
    req = json_loadb(body, strlen(body), JSON_REJECT_DUPLICATES, NULL);
    if (!req)
        return http_reply(HTTP_STATUS_BAD_REQUEST, NULL);

    thp = load_thp_keys(path, matches, jwkdir, &tki, &status);
    if (!thp)
        return http_reply(status, NULL);

    tang_kem_priv = find_jwk(tki, thp);
    if (!tang_kem_priv)
        return http_reply(HTTP_STATUS_NOT_FOUND, NULL);

    if (json_unpack(tang_kem_priv, "{s:s}", "kty", &kty) < 0)
        return http_reply(HTTP_STATUS_FORBIDDEN, NULL);

    if (strcmp(kty, "AKP") != 0)
        return http_reply(HTTP_STATUS_FORBIDDEN, NULL);

    /* RFC 9864: AKP keys are not necessarily supported ML-KEM exchange
     * keys; rec_kem_secure() cannot derive a suite from an unsupported
     * algorithm, so refuse the key here instead of failing later with
     * an internal error. */
    const char *kalg = json_string_value(
        json_object_get(tang_kem_priv, "alg"));
    if (!is_valid_kem_alg(kalg))
        return http_reply(HTTP_STATUS_FORBIDDEN, NULL);

    if (!jose_jwk_prm(NULL, tang_kem_priv, true, "deriveKey"))
        return http_reply(HTTP_STATUS_FORBIDDEN, NULL);

    status = rec_kem_secure(tang_kem_priv, tki, thp, req, &enc);
    if (status != HTTP_STATUS_OK)
        return http_reply(status, NULL);

    return http_reply(HTTP_STATUS_OK,
                      /* The response is a custom JSON envelope
                       * ({"tang_encrypted_key", "tang_transport_ct"}),
                       * not an RFC 7517 JWK. */
                      "Content-Type: application/json\r\n"
                      "Content-Length: %zu\r\n"
                      "\r\n%s", strlen(enc), enc);
}
