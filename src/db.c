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

#include "db.h"

#include <jose/jose.h>

#include <ctype.h>
#include <errno.h>
#include <string.h>

static const char *hashes[] = {
    "sha224", /* NOTE: the first hash type is the default hash. */
    "sha256",
    "sha384",
    "sha512",
    NULL
};

/**
 * The ctx structure looks like this: {
 *   "pub": { <thumbprint(default hash)>: <jwk> },
 *   "sig": { <thumbprint(hashes)>: <jwk> },
 *   "rec": { <thumbprint(hashes)>: <jwk> },
 *
 *   "adv": {
 *     "default": <adv>,
 *     <thumbprint(hashes)>: <adv>,
 *     ...
 *   },
 * }
 *
 * The "pub" subtree contains all advertised keys indexed by their thumbprints
 * using the default hash.
 *
 * The "sig" and "rec" subtrees contain the signing and recovery keys,
 * respectively, indexed by thumbprints calculated using all supported hashes.
 *
 * Whenever tang_db_add_jwk() or tang_db_del_jwk() are called, all possible
 * advertisements are computed in the "adv" portion of the tree. This way,
 * whenever we receive an advertisement request, we can just hand off the
 * pre-calculated advertisement rather than performing signatures during the
 * request itself.
 */

static json_t *ctx;

static json_t *
make_jwkset(void)
{
    json_auto_t *jwkset = NULL;
    const char *thp = NULL;
    json_t *jwk = NULL;

    jwkset = json_pack("{s:[]}", "keys");
    if (!jwkset)
        return NULL;

    json_object_foreach(json_object_get(ctx, "pub"), thp, jwk) {
        if (json_array_append(json_object_get(jwkset, "keys"), jwk) < 0)
            return NULL;
    }

    return json_incref(jwkset);
}

static json_t *
make_jws(void)
{
    const char *thp = NULL;
    json_t *jwkset = NULL;
    json_t *jws = NULL;
    json_t *jwk = NULL;

    jwkset = make_jwkset();
    if (!jwkset)
        return NULL;

    jws = json_pack("{s:o}", "payload", jose_b64_encode_json_dump(jwkset));
    json_decref(jwkset);
    if (!jws)
        return NULL;

    json_object_foreach(json_object_get(ctx, "sig"), thp, jwk) {
        json_auto_t *sig = NULL;

        if (!json_object_get(json_object_get(ctx, "pub"), thp))
            continue;

        sig = json_pack("{s:{s:s}}", "protected", "cty", "jwk-set+json");
        if (!jose_jws_sign(jws, jwk, sig))
            fprintf(stderr, "Signing failed for %s:%s!\n", hashes[0], thp);
    }

    return jws;
}

static json_t *
make_adv(void)
{
    const char *thp = NULL;
    json_t *jwk = NULL;
    json_t *jws = NULL;
    json_t *adv = NULL;

    jws = make_jws();
    if (!jws)
        return NULL;

    adv = json_pack("{s:o}", "default", jws);
    if (!adv)
        return NULL;

    json_object_foreach(json_object_get(ctx, "sig"), thp, jwk) {
        char pub[jose_jwk_thumbprint_len(hashes[0]) + 1];
        json_auto_t *sigs = NULL;
        json_auto_t *sig = NULL;

        if (!jose_jwk_thumbprint_buf(jwk, hashes[0], pub))
            continue;

        if (json_object_get(json_object_get(ctx, "pub"), pub)) {
            json_object_set(adv, thp, jws);
            continue;
        }

        sigs = json_deep_copy(jws);
        if (!sigs)
            continue;

        sig = json_pack("{s:{s:s}}", "protected", "cty", "jwk-set+json");
        if (!sig)
            continue;

        if (!jose_jws_sign(sigs, jwk, sig))
            continue;

        json_object_set(adv, thp, sigs);
    }

    return adv;
}

char *
tang_db_thumbprint(const json_t *jwk)
{
    return jose_jwk_thumbprint(jwk, hashes[0]);
}

json_t *
tang_db_get_adv(const char *thp)
{
    if (!thp)
        thp = "default";

    return json_object_get(json_object_get(ctx, "adv"), thp);
}

json_t *
tang_db_get_rec_jwk(const char *thp)
{
    return json_object_get(json_object_get(ctx, "rec"), thp);
}

bool
tang_db_is_blocked(const json_t *jwk)
{
    for (size_t i = 0; hashes[i]; i++) {
        char thp[jose_jwk_thumbprint_len(hashes[i]) + 1];

        if (!jose_jwk_thumbprint_buf(jwk, hashes[i], thp))
            return true;

        if (json_object_get(json_object_get(ctx, "blk"), thp))
            return true;
    }

    return false;
}

int
tang_db_add_jwk(bool adv, const json_t *jwk)
{
    json_auto_t *key = NULL;
    json_auto_t *pub = NULL;

    key = json_deep_copy(jwk);
    if (!key)
        return -ENOMEM;

    pub = json_deep_copy(key);
    if (!pub)
        return -ENOMEM;

    if (!jose_jwk_clean(pub))
        return -EINVAL;

    for (size_t i = 0; hashes[i]; i++) {
        char thp[jose_jwk_thumbprint_len(hashes[i]) + 1];

        if (!jose_jwk_thumbprint_buf(key, hashes[i], thp)) {
            fprintf(stderr, "Unable to make JWK thumbprint!\n");
            return -EINVAL;
        }

        if (i == 0) {
            if (json_object_set_new(key, "kid", json_string(thp)) != 0 ||
                json_object_set_new(pub, "kid", json_string(thp)) != 0) {
                fprintf(stderr, "Error setting default thumbprint!\n");
                return -ENOMEM;
            }
        }

        if (jose_jwk_allowed(key, true, NULL, "sign") &&
            jose_jwk_allowed(key, true, NULL, "verify")) {
            if (json_object_set(json_object_get(ctx, "sig"), thp, key) < 0)
                return -ENOMEM;
        } else if (jose_jwk_allowed(key, true, NULL, "wrapKey") &&
                   jose_jwk_allowed(key, true, NULL, "unwrapKey")) {
            if (json_object_set(json_object_get(ctx, "rec"), thp, key) < 0)
                return -ENOMEM;
        } else if (jose_jwk_allowed(key, true, NULL, "deriveKey")) {
            if (json_object_set(json_object_get(ctx, "rec"), thp, key) < 0)
                return -ENOMEM;
        } else {
            fprintf(stderr, "JWK has invalid key_ops!\n");
            return -EINVAL;
        }

        if (i == 0)
            fprintf(stderr, "Added JWK: %s\n", thp);
        else
            fprintf(stderr, "Alias JWK: %s\n", thp);

        if (adv && i == 0) {
            if (json_object_set(json_object_get(ctx, "pub"), thp, pub) < 0)
                return -ENOMEM;
        }
    }

    if (json_object_set_new(ctx, "adv", make_adv()) == 0)
        fprintf(stderr, "Rebuilt advertisement\n");
    else
        fprintf(stderr, "Rebuilding advertisment failed!\n");

    return 0;
}

int
tang_db_del_jwk(const json_t *jwk)
{
    bool found = false;

    for (size_t i = 0; hashes[i]; i++) {
        char thp[jose_jwk_thumbprint_len(hashes[i]) + 1];

        if (!jose_jwk_thumbprint_buf(jwk, hashes[i], thp)) {
            fprintf(stderr, "Unable to make JWK thumbprint!\n");
            return -EINVAL;
        }

        if (i == 0 && json_object_del(json_object_get(ctx, "pub"), thp) == 0)
            found = true;

        if (json_object_del(json_object_get(ctx, "sig"), thp) == 0)
            found = true;

        if (json_object_del(json_object_get(ctx, "rec"), thp) == 0)
            found = true;

        if (i == 0)
            fprintf(stderr, "Deleted JWK: %s\n", thp);
    }


    if (json_object_set_new(ctx, "adv", make_adv()) == 0)
        fprintf(stderr, "Rebuilt advertisement\n");
    else
        fprintf(stderr, "Rebuilding advertisment failed!\n");

    return found ? 0 : -ENOENT;
}

static void __attribute__((constructor))
constructor(void)
{
    ctx = json_pack("{s:{},s:{},s:{},s:{},s:{}}",
                    "pub", "sig", "rec", "blk", "adv");
}


static void __attribute__((destructor))
destructor(void)
{
    json_decref(ctx);
}
