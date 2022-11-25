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

#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <stdio.h>

#include <jose/b64.h>
#include <jose/jwk.h>
#include <jose/jws.h>

#include "keys.h"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

/* Default hash to use with JWK thumbprints (S256 = SHA-256). */
#define DEFAULT_THP_HASH "S256"

static const char**
supported_hashes(void)
{
    /* TODO: check if jose has a way to export the hash algorithms it
     * supports. */
    static const char* hashes[] = {"S1", "S224", "S256", "S384", "S512", NULL};
    return hashes;
}

static int
is_hash(const char* alg)
{
    if (!alg) {
        return 0;
    }

    const char** algs = supported_hashes();
    for (size_t a = 0; algs[a]; a++) {
        if (strcmp(alg, algs[a]) == 0) {
            return 1;
        }
    }
    return 0;
}

static json_t*
jwk_generate(const char* alg)
{
    json_auto_t* jalg = json_pack("{s:s}", "alg", alg);
    if (!jalg) {
        fprintf(stderr, "Error packing JSON with alg %s\n", alg);
        return NULL;
    }

    if (!jose_jwk_gen(NULL, jalg)) {
        fprintf(stderr, "Error generating JWK with alg %s\n", alg);
        return NULL;
    }

    return json_incref(jalg);
}

static char*
jwk_thumbprint(const json_t* jwk, const char* alg)
{
    size_t elen = 0;
    size_t dlen = 0;

    if (!jwk) {
        fprintf(stderr, "Invalid JWK\n");
        return NULL;
    }

    if (!alg || !is_hash(alg)) {
        fprintf(stderr, "Invalid hash algorithm (%s)\n", alg);
        return NULL;
    }

    dlen = jose_jwk_thp_buf(NULL, NULL, alg, NULL, 0);
    if (dlen == SIZE_MAX) {
        fprintf(stderr, "Error determining hash size for %s\n", alg);
        return NULL;
    }

    elen = jose_b64_enc_buf(NULL, dlen, NULL, 0);
    if (elen == SIZE_MAX) {
        fprintf(stderr, "Error determining encoded size for %s\n", alg);
        return NULL;
    }

    uint8_t dec[dlen];
    char enc[elen];

    if (!jose_jwk_thp_buf(NULL, jwk, alg, dec, sizeof(dec))) {
        fprintf(stderr, "Error making thumbprint\n");
        return NULL;
    }

    if (jose_b64_enc_buf(dec, dlen, enc, sizeof(enc)) != elen) {
        fprintf(stderr, "Error encoding data Base64\n");
        return NULL;
    }

    return strndup(enc, elen);
}

void
free_tang_keys_info(struct tang_keys_info* tki)
{
    if (!tki) {
        return;
    }

    json_t* to_free[] = {tki->m_keys, tki->m_rotated_keys,
                         tki->m_payload, tki->m_sign
    };
    size_t len = sizeof(to_free) / sizeof(to_free[0]);

    for (size_t i = 0; i < len; i++) {
        if (to_free[i] == NULL) {
            continue;
        }
        json_decref(to_free[i]);
    }
    free(tki);
}

void
cleanup_tang_keys_info(struct tang_keys_info** tki)
{
    if (!tki || !*tki) {
        return;
    }
    free_tang_keys_info(*tki);
    *tki = NULL;
}

static struct tang_keys_info*
new_tang_keys_info(void)
{
    struct tang_keys_info* tki = calloc(1, sizeof(*tki));
    if (!tki) {
        return NULL;
    }

    tki->m_keys = json_array();
    tki->m_rotated_keys = json_array();
    tki->m_payload = json_array();
    tki->m_sign = json_array();

    if (!tki->m_keys || !tki->m_rotated_keys ||
        !tki->m_payload || !tki->m_sign) {
        free_tang_keys_info(tki);
        return NULL;
    }
    tki->m_keys_count = 0;
    return tki;
}

static int
jwk_valid_for(const json_t* jwk, const char* use)
{
    if (!jwk || !use) {
        return 0;
    }
    return jose_jwk_prm(NULL, jwk, false, use);
}

static int
jwk_valid_for_signing_and_verifying(const json_t* jwk)
{
    const char* uses[] = {"sign", "verify", NULL};
    int ret = 1;
    for (int i = 0; uses[i]; i++) {
        if (!jwk_valid_for(jwk, uses[i])) {
            ret = 0;
            break;
        }
    }
    return ret;
}

static int
jwk_valid_for_signing(const json_t* jwk)
{
    return jwk_valid_for(jwk, "sign");
}

static int
jwk_valid_for_deriving_keys(const json_t* jwk)
{
    return jwk_valid_for(jwk, "deriveKey");
}

static void
cleanup_str(char** str)
{
    if (!str || !*str) {
        return;
    }
    free(*str);
    *str = NULL;
}

static json_t*
jwk_sign(const json_t* to_sign, const json_t* sig_keys)
{
    if (!sig_keys || !json_is_array(sig_keys) || !json_is_array(to_sign)) {
        return NULL;
    }

    json_auto_t* to_sign_copy = json_deep_copy(to_sign);
    if (!jose_jwk_pub(NULL, to_sign_copy)) {
        fprintf(stderr, "Error removing private material from data to sign\n");
        return NULL;
    }

    json_auto_t* payload = json_pack("{s:O}", "keys", to_sign_copy);
    json_auto_t* sig_template = json_pack("{s:{s:s}}",
                                          "protected", "cty", "jwk-set+json");

    __attribute__ ((__cleanup__(cleanup_str))) char* data_to_sign = json_dumps(payload, 0);
    json_auto_t* jws = json_pack("{s:o}", "payload",
                                 jose_b64_enc(data_to_sign, strlen(data_to_sign)));

    if (!jose_jws_sig(NULL, jws, sig_template, sig_keys)) {
        fprintf(stderr, "Error trying to jose_jws_sign\n");
        return NULL;
    }
    return json_incref(jws);
}

static json_t*
find_by_thp(struct tang_keys_info* tki, const char* target)
{
    if (!tki) {
        return NULL;
    }

    json_auto_t* keys = json_deep_copy(tki->m_keys);
    json_array_extend(keys, tki->m_rotated_keys);

    size_t idx;
    json_t* jwk;
    const char** hashes = supported_hashes();
    json_array_foreach(keys, idx, jwk) {
        for (int i = 0; hashes[i]; i++) {
            __attribute__ ((__cleanup__(cleanup_str))) char* thumbprint = jwk_thumbprint(jwk, hashes[i]);
            if (!thumbprint || strcmp(thumbprint, target) != 0) {
                continue;
            }
            return json_incref(jwk);
        }
    }
    return NULL;
}

static int
prepare_payload_and_sign(struct tang_keys_info* tki)
{
    if (!tki) {
        return 0;
    }

    size_t idx;
    json_t* jwk;
    json_array_foreach(tki->m_keys, idx, jwk) {
        if (jwk_valid_for_signing_and_verifying(jwk)) {
            if (json_array_append(tki->m_sign, jwk) == -1) {
                continue;
            }
            if (json_array_append(tki->m_payload, jwk) == -1) {
                continue;
            }
        } else if (jwk_valid_for_deriving_keys(jwk)) {
            if (json_array_append(tki->m_payload, jwk) == -1) {
                continue;
            }
        }
    }
    if (json_array_size(tki->m_sign) == 0 || json_array_size(tki->m_payload) == 0) {
        return 0;
    }
    return 1;
}

static int
create_new_keys(const char* jwkdir)
{
    const char* alg[] = {"ES512", "ECMR", NULL};
    char path[PATH_MAX];
    for (int i = 0; alg[i] != NULL; i++) {
        json_auto_t* jwk = jwk_generate(alg[i]);
        if (!jwk) {
            return 0;
        }
        __attribute__ ((__cleanup__(cleanup_str))) char* thp = jwk_thumbprint(jwk, DEFAULT_THP_HASH);
        if (!thp) {
            return 0;
        }
        if (snprintf(path, PATH_MAX, "%s/%s.jwk", jwkdir, thp) < 0) {
            fprintf(stderr, "Unable to prepare variable with file full path (%s)\n", thp);
            return 0;
        }
        path[sizeof(path) - 1] = '\0';
        if (json_dump_file(jwk, path, 0) == -1) {
            fprintf(stderr, "Error saving JWK to file (%s)\n", path);
            return 0;
        }

        /* Set 0440 permission for the new key. */
        if (chmod(path, S_IRUSR | S_IRGRP) == -1) {
            fprintf(stderr, "Unable to set permissions for JWK file (%s)\n", path);
            return 0;
        }
    }
    return 1;
}

static struct tang_keys_info*
load_keys(const char* jwkdir)
{
    struct tang_keys_info* tki = new_tang_keys_info();
    if (!tki) {
        return NULL;
    }

    struct dirent* d;
    DIR* dir = opendir(jwkdir);
    if (!dir) {
        free_tang_keys_info(tki);
        return NULL;
    }

    char filepath[PATH_MAX];
    const char* pattern = ".jwk";
    while ((d = readdir(dir)) != NULL) {
        if (strcmp(d->d_name, ".") == 0 || strcmp(d->d_name, "..") == 0) {
            continue;
        }

        char* dot = strrchr(d->d_name, '.');
        if (!dot) {
            continue;
        }

        if (strcmp(dot, pattern) == 0) {
            /* Found a file with .jwk extension. */
            if (snprintf(filepath, PATH_MAX, "%s/%s", jwkdir, d->d_name) < 0) {
                fprintf(stderr, "Unable to prepare variable with file full path (%s); skipping\n", d->d_name);
                continue;
            }
            filepath[sizeof(filepath) - 1] = '\0';
            json_error_t error;
            json_auto_t* json = json_load_file(filepath, 0, &error);
            if (!json) {
                fprintf(stderr, "Cannot load JSON file (%s); skipping\n", filepath);
                fprintf(stderr, "error text %s, line %d, col %d, pos %d\n",
                    error.text, error.line, error.column, error.position);
                continue;
            }

            json_t* arr = tki->m_keys;
            if (d->d_name[0] == '.') {
                arr = tki->m_rotated_keys;
                tki->m_rotated_keys_count++;
            } else {
                tki->m_keys_count++;
            }

            if (json_array_append(arr, json) == -1) {
                fprintf(stderr, "Unable to append JSON (%s) to array; skipping\n", d->d_name);
                continue;
            }
        }
    }
    closedir(dir);
    return tki;
}

struct tang_keys_info*
read_keys(const char* jwkdir)
{
    struct tang_keys_info* tki = load_keys(jwkdir);
    if (!tki) {
        return NULL;
    }

    if (tki->m_keys_count == 0) {
        /* Let's attempt to create a new pair of keys. */
        free_tang_keys_info(tki);
        if (!create_new_keys(jwkdir)) {
            return NULL;
        }
        tki = load_keys(jwkdir);
    }

    if (!prepare_payload_and_sign(tki)) {
        free_tang_keys_info(tki);
        return NULL;
    }
    return tki;
}

json_t*
find_jws(struct tang_keys_info* tki, const char* thp)
{
    if (!tki) {
        return NULL;
    }

    if (thp == NULL) {
        /* Default advertisement. */
        json_auto_t* jws = jwk_sign(tki->m_payload, tki->m_sign);
        if (!jws) {
            return NULL;
        }
        return json_incref(jws);
    }

    json_auto_t* jwk = find_by_thp(tki, thp);
    if (!jwk_valid_for_signing(jwk)) {
        return NULL;
    }

    json_auto_t* sign = json_deep_copy(tki->m_sign);
    if (json_array_append(sign, jwk) == -1) {
        return NULL;
    }
    json_auto_t* jws = jwk_sign(tki->m_payload, sign);
    if (!jws) {
        return NULL;
    }
    return json_incref(jws);
}

json_t*
find_jwk(struct tang_keys_info* tki, const char* thp)
{
    if (!tki || !thp) {
        return NULL;
    }
    return find_by_thp(tki, thp);
}
