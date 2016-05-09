/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */
/*
 * Copyright (c) 2015 Red Hat, Inc.
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

#include "../adv.h"
#include "../msg.h"
#include "asn1.h"

#include <libcryptsetup.h>
#include <openssl/sha.h>

#include <argp.h>
#include <stdbool.h>
#include <string.h>
#include <sysexits.h>

#define _STR(x) # x
#define STR(x) _STR(x)

struct options {
    const char *device;
    const char *file;
    msg_t params;
};

static struct crypt_device *
open_device(const char *device)
{
    struct crypt_device *cd = NULL;
    const char *type = NULL;
    int nerr = 0;

    nerr = crypt_init(&cd, device);
    if (nerr != 0) {
        fprintf(stderr, "Unable to open device (%s): %s\n",
                device, strerror(-nerr));
        return NULL;
    }

    nerr = crypt_load(cd, NULL, NULL);
    if (nerr != 0) {
        fprintf(stderr, "Unable to load device (%s): %s\n",
                device, strerror(-nerr));
        goto error;
    }

    type = crypt_get_type(cd);
    if (type == NULL) {
        fprintf(stderr, "Unable to determine device type for %s\n", device);
        goto error;
    }

    if (strcmp(type, CRYPT_LUKS1) != 0) {
        fprintf(stderr, "%s (%s) is not a LUKS device\n", device, type);
        goto error;
    }

    return cd;

error:
    crypt_free(cd);
    return NULL;
}

static bool
adv_trusted(TANG_MSG_ADV_REP *rep)
{
    int nkeys = SKM_sk_num(TANG_KEY, rep->body->sigs);
    int c = 'a';

    printf("The server advertised the following signing key%s:\n\n",
           nkeys > 1 ? "s" : "");

    for (int i = 0; i < nkeys; i++) {
        TANG_KEY *key = SKM_sk_value(TANG_KEY, rep->body->sigs, i);
        uint8_t md[SHA256_DIGEST_LENGTH] = {};

        if (!SHA256(key->key->data, key->key->length, md))
            return false;

        printf("  sha256:");
        for (size_t j = 0; j < sizeof(md); j++)
            printf("%02X", md[j]);
        printf("\n");
    }

    printf("\n");

    while (!strchr("YyNn", c)) {
        printf("Do you wish to trust %s? [yn] ",
               nkeys > 1 ? "these keys" : "this key");
        c = getc(stdin);
    }

    return strchr("Yy", c);
}

/* Steals rec */
static TANG_LUKS *
TANG_LUKS_make(const msg_t *params, TANG_MSG_REC_REQ *rec)
{
    TANG_LUKS *tl = NULL;

    tl = TANG_LUKS_new();
    if (!tl) {
        TANG_MSG_REC_REQ_free(rec);
        return NULL;
    }

    tl->rec = rec;

    if (ASN1_STRING_set(tl->hostname, params->hostname,
                        strlen(params->hostname)) <= 0)
        goto error;

    if (ASN1_STRING_set(tl->service, params->service,
                        strlen(params->service)) <= 0)
        goto error;

    return tl;

error:
    TANG_LUKS_free(tl);
    return NULL;
}

/* Steals rec */
static bool
store(const struct options *opts, TANG_MSG_REC_REQ *rec,
      struct crypt_device *cd, int slot)
{
    static const char *msg =
        "The specified block device is not initialized for metadata storage. "
        "Attempting to initialize it may result in data loss if data was "
        "already written into the LUKS header gap in a different format."
        "A backup is advised before initialization is performed.\n\n";

    TANG_LUKS *tl = NULL;
    int r = 0;

    tl = TANG_LUKS_make(&opts->params, rec);
    if (!tl)
        return false;

    const int tsz = i2d_TANG_LUKS(tl, NULL);
    if (tsz < 1)
        return false;

    uint8_t tmp[tsz];

    r = i2d_TANG_LUKS(tl, &(uint8_t *) { tmp });
    if (r != tsz)
        return false;

    r = luksmeta_set(cd, slot, TANG_LUKS_UUID, tmp, tsz);
    if (r == -ENOENT) {
        char c = 'X';

        fprintf(stderr, "%s", msg);

        while (!strchr("YyNn", c)) {
            printf("Do you wish to initialize %s? [yn] ",
                   crypt_get_device_name(cd));
            c = getc(stdin);
        }

        if (strchr("Nn", c))
            return false;

        r = luksmeta_init(cd);
        if (r >= 0)
            r = luksmeta_set(cd, slot, TANG_LUKS_UUID, tmp, tsz);
    }

    if (r < 0)
        fprintf(stderr, "Error during metadata write: %s\n", strerror(-r));

    return r >= 0;
}

static error_t
argp_parser(int key, char* arg, struct argp_state* state)
{
    struct options *opts = state->input;

    switch (key) {
    case 'a':
        opts->file = arg;
        return 0;

    case 'd':
        opts->device = arg;
        return 0;

    case 'h':
        strncpy(opts->params.hostname, arg, sizeof(opts->params.hostname) - 1);
        return 0;

    case 's':
        strncpy(opts->params.service, arg, sizeof(opts->params.service) - 1);
        return 0;

    case ARGP_KEY_END:
        if (!opts->device) {
            fprintf(stderr, "Device MUST be specified!\n");
            argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
            return EINVAL;
        }

        if (strlen(opts->params.hostname) == 0) {
            fprintf(stderr, "Host MUST be specified!\n");
            argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
            return EINVAL;
        }

        if (strlen(opts->params.service) == 0)
            strcpy(opts->params.service, STR(TANG_PORT));

        return 0;

    default:
        return ARGP_ERR_UNKNOWN;
    }
}

const char *argp_program_version = VERSION;

static const struct argp_option argp_options[] = {
    { "device",   'd', "device",   .doc = "LUKSv1 device (required)" },
    { "hostname", 'h', "hostname", .doc = "Remote server hostname (required)" },
    { "service",  's', "service",  .doc = "Remote server service" },
    { "adv",      'a', "file",     .doc = "Advertisement file" },
    {}
};

static const struct argp argp = {
    .options = argp_options,
    .parser = argp_parser,
    .args_doc = ""
};

int
main(int argc, char *argv[])
{
    struct options opts = { .params.timeout = 10 };
    struct crypt_device *cd = NULL;
    TANG_MSG_REC_REQ *rec = NULL;
    int status = EX_IOERR;
    TANG_MSG *msg = NULL;
    BN_CTX *ctx = NULL;
    sbuf_t *key = NULL;
    sbuf_t *hex = NULL;
    int keysize = 0;
    int slot = 0;

    if (argp_parse(&argp, argc, argv, 0, NULL, &opts) != 0)
        return EX_OSERR;

    ctx = BN_CTX_new();
    if (!ctx)
        goto egress;

    cd = open_device(opts.device);
    if (!cd)
        goto egress;

    keysize = crypt_get_volume_key_size(cd);
    if (keysize < 16) { /* Less than 128-bits. */
        fprintf(stderr, "Key size (%d) is too small", keysize);
        status = EX_CONFIG;
        goto egress;
    }

    if (opts.file) {
        msg = msg_read(opts.file);
    } else {
        TANG_MSG req = { .type = TANG_MSG_TYPE_ADV_REQ };

        req.val.adv.req = adv_req(NULL);
        if (!req.val.adv.req)
            goto egress;

        msg = msg_rqst(&opts.params, &req);
        TANG_MSG_ADV_REQ_free(req.val.adv.req);
    }
    if (!msg || msg->type != TANG_MSG_TYPE_ADV_REP)
        goto egress;

    if (!opts.file && !adv_trusted(msg->val.adv.rep))
        goto egress;

    rec = adv_rep(msg->val.adv.rep, NULL, keysize, &key, ctx);
    if (!rec)
        goto egress;

    hex = sbuf_to_hex(key, "");
    if (!hex)
        goto egress;

    slot = crypt_keyslot_add_by_passphrase(cd, CRYPT_ANY_SLOT, NULL,
                                           0, (char *) hex->data,
                                           hex->size - 1);
    if (slot < 0) {
        TANG_MSG_REC_REQ_free(rec);
        goto egress;
    }

    if (!store(&opts, rec, cd, slot)) {
        crypt_keyslot_destroy(cd, slot);
        goto egress;
    }

    status = 0;

egress:
    TANG_MSG_free(msg);
    BN_CTX_free(ctx);
    sbuf_free(key);
    sbuf_free(hex);
    crypt_free(cd);
    return status;
}

