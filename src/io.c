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

#include "io.h"

#include <systemd/sd-journal.h>
#include <systemd/sd-event.h>

#include <jose/b64.h>
#include <jose/jwk.h>
#include <jose/jws.h>

#include <ctype.h>
#include <errno.h>
#include <string.h>

const char *hashes[] = {
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
 *   "blk": { <bid>: true, ... },
 *
 *   "adv": {
 *     "default": <adv>,
 *     <thumbprint(hashes)>: <adv>,
 *     ...
 *   },
 * }
 *
 * The "blk" subtree is managed by tang_io_add_bid() and tang_io_del_bid().
 *
 * The "pub" subtree contains all advertised keys indexed by their thumbprints
 * using the default hash.
 *
 * The "sig" and "rec" subtrees contain the signing and recovery keys,
 * respectively, indexed by thumbprints calculated using all supported hashes.
 *
 * Whenever tang_io_add_jwk() or tang_io_del_jwk() are called, a transient
 * defer event is created to create all possible advertisements in the "adv"
 * portion of the tree. This way, whenever we receive an advertisement request,
 * we can just hand off the pre-calculated advertisement rather than performing
 * signatures during the request itself.
 */

static json_t *ctx;
static bool regen;

static void
json_decrefp(json_t **json)
{
    if (json)
        json_decref(*json);
}

static json_t *
make_jwkset(void)
{
    const char *thp = NULL;
    json_t *jwkset = NULL;
    json_t *jwk = NULL;

    jwkset = json_pack("{s:[]}", "keys");
    if (!jwkset)
        return NULL;

    json_object_foreach(json_object_get(ctx, "pub"), thp, jwk) {
        if (json_array_append(json_object_get(jwkset, "keys"), jwk) < 0) {
            json_decref(jwkset);
            return NULL;
        }
    }

    return jwkset;
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
        json_t *sig = NULL;

        if (!json_object_get(json_object_get(ctx, "pub"), thp))
            continue;

        sig = json_pack("{s:{s:s}}", "protected", "cty", "jwk-set+json");
        if (!jose_jws_sign(jws, jwk, sig)) {
            sd_journal_print(LOG_WARNING, "Signing failed for %s:%s!\n",
                             hashes[0], thp);
        }
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
        json_t __attribute__((cleanup(json_decrefp))) *sig = NULL;
        char pub[jose_jwk_thumbprint_len(hashes[0]) + 1];

        if (!jose_jwk_thumbprint_buf(jwk, hashes[0], pub))
            continue;

        if (json_object_get(json_object_get(ctx, "pub"), pub)) {
            json_object_set(adv, thp, jws);
            continue;
        }

        sig = json_deep_copy(jws);
        if (!sig)
            continue;

        if (!jose_jws_sign(sig, jwk, json_pack("{s:{s:s}}", "protected",
                                               "cty", "jwk-set+json")))
            continue;

        json_object_set(adv, thp, sig);
    }

    return adv;
}

static int
on_change(sd_event_source *s, void *userdata)
{
    if (json_object_set_new(ctx, "adv", make_adv()) == 0)
        sd_journal_print(LOG_DEBUG, "Rebuilt advertisement");
    else
        sd_journal_print(LOG_ERR, "Rebuilding advertisment failed!");

    sd_event_source_unref(s);
    regen = false;
    return 0;
}

json_t *
tang_io_get_adv(const char *thp)
{
    if (!thp)
        thp = "default";

    return json_object_get(json_object_get(ctx, "adv"), thp);
}

json_t *
tang_io_get_rec_jwk(const char *thp)
{
    return json_object_get(json_object_get(ctx, "rec"), thp);
}

bool
tang_io_is_blocked(const char *bid)
{
    return json_object_get(json_object_get(ctx, "blk"), bid) != NULL;
}

int
tang_io_add_jwk(bool adv, const json_t *jwk)
{
    sd_event __attribute__((cleanup(sd_event_unrefp))) *e = NULL;
    json_t __attribute__((cleanup(json_decrefp))) *key = NULL;
    json_t __attribute__((cleanup(json_decrefp))) *pub = NULL;

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
            sd_journal_print(LOG_WARNING, "Unable to make JWK thumbprint!");
            return -EINVAL;
        }

        if (i == 0) {
            if (json_object_set_new(key, "kid", json_string(thp)) != 0 ||
                json_object_set_new(pub, "kid", json_string(thp)) != 0) {
                sd_journal_print(LOG_WARNING,
                                 "Error setting default thumbprint!");
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
            sd_journal_print(LOG_WARNING, "JWK has invalid key_ops!");
            return -EINVAL;
        }

        if (i == 0)
            sd_journal_print(LOG_DEBUG, "Added JWK: %s", thp);
        else
            sd_journal_print(LOG_DEBUG, "Alias JWK: %s", thp);

        if (adv && i == 0) {
            if (json_object_set(json_object_get(ctx, "pub"), thp, pub) < 0)
                return -ENOMEM;
        }
    }

    if (!regen) {
        if (sd_event_default(&e) >= 0)
            regen = sd_event_add_defer(e, NULL, on_change, NULL) == 0;
    }

    return 0;
}

int
tang_io_del_jwk(const json_t *jwk)
{
    sd_event __attribute__((cleanup(sd_event_unrefp))) *e = NULL;
    bool found = false;

    for (size_t i = 0; hashes[i]; i++) {
        char thp[jose_jwk_thumbprint_len(hashes[i]) + 1];

        if (!jose_jwk_thumbprint_buf(jwk, hashes[i], thp)) {
            sd_journal_print(LOG_WARNING, "Unable to make JWK thumbprint!");
            return -EINVAL;
        }

        if (i == 0 && json_object_del(json_object_get(ctx, "pub"), thp) == 0)
            found = true;

        if (json_object_del(json_object_get(ctx, "sig"), thp) == 0)
            found = true;

        if (json_object_del(json_object_get(ctx, "rec"), thp) == 0)
            found = true;

        if (i == 0)
            sd_journal_print(LOG_DEBUG, "Deleted JWK: %s", thp);
    }

    if (!regen) {
        if (sd_event_default(&e) >= 0)
            regen = sd_event_add_defer(e, NULL, on_change, NULL) == 0;
    }

    return found ? 0 : -ENOENT;
}

int
tang_io_add_bid(const char *bid)
{
    for (size_t i = 0; bid[i]; i++) {
        if (!isalnum(bid[i]) && !strchr("-_", bid[i]))
            return -EINVAL;
    }

    if (json_object_set_new(json_object_get(ctx, "blk"), bid, json_true()) < 0)
        return -ENOMEM;

    sd_journal_print(LOG_DEBUG, "Added Blacklist ID: %s", bid);

    return 0;
}

int
tang_io_del_bid(const char *bid)
{
    for (size_t i = 0; bid[i]; i++) {
        if (!isalnum(bid[i]) && !strchr("-_", bid[i]))
            return -EINVAL;
    }

    if (json_object_del(json_object_get(ctx, "blk"), bid) < 0)
        return -ENOENT;

    sd_journal_print(LOG_DEBUG, "Deleted Blacklist ID: %s", bid);

    return 0;
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
