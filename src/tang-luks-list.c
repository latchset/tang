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

#include "luks/asn1.h"
#include "luks/meta.h"

#include <libcryptsetup.h>

#include <argp.h>
#include <string.h>
#include <sysexits.h>

struct options {
    const char *device;
};

static bool
ASN1_UTF8STRING_equals(ASN1_UTF8STRING *a, const char *b)
{
    uint8_t *tmp = NULL;
    int r = 0;

    r = ASN1_STRING_to_UTF8(&tmp, a);
    if (r <= 0)
        return false;

    r = strncmp((char *) tmp, b, r);
    OPENSSL_free(tmp);
    return r == 0;
} 

static int
list(const struct options *opts)
{
    struct crypt_device *cd = NULL;
    const char *type = NULL;
    int nerr = 0;

    nerr = crypt_init(&cd, opts->device);
    if (nerr != 0) {
        fprintf(stderr, "Unable to open device (%s): %s\n",
                opts->device, strerror(-nerr));
        goto error;
    }

    nerr = crypt_load(cd, NULL, NULL);
    if (nerr != 0) {
        fprintf(stderr, "Unable to load device (%s): %s\n",
                opts->device, strerror(-nerr));
        goto error;
    }

    type = crypt_get_type(cd);
    if (type == NULL) {
        fprintf(stderr, "Unable to determine device type\n");
        goto error;
    }
    if (strcmp(type, CRYPT_LUKS1) != 0) {
        fprintf(stderr, "%s (%s) is not a LUKS device\n", opts->device, type);
        goto error;
    }

    for (int slot = 0; slot < crypt_keyslot_max(CRYPT_LUKS1); slot++) {
        TANG_LUKS *tluks = NULL;
        uint8_t *data = NULL;
        size_t size = 0;

        switch (crypt_keyslot_status(cd, slot)) {
        case CRYPT_SLOT_ACTIVE:
        case CRYPT_SLOT_ACTIVE_LAST:
            data = meta_read(opts->device, slot, &size);
            if (!data)
                continue;

            tluks = d2i_TANG_LUKS(NULL, &(const uint8_t *) { data }, size);
            free(data);
            if (!tluks)
                continue;

            fprintf(stderr, "%c %*s:%*s\n",
                    tluks->listen ? 'L' : 'S',
                    tluks->hostname->length, tluks->hostname->data,
                    tluks->service->length, tluks->service->data);
            break;

        default:
            break;
        }
    }

    crypt_free(cd);
    return 0;

error:
    crypt_free(cd);
    return EX_IOERR;
}

#define _STR(x) # x
#define STR(x) _STR(x)
#define SUMMARY 192

static error_t
parser(int key, char* arg, struct argp_state* state)
{
    struct options *opts = state->input;

    switch (key) {
    case SUMMARY:
        fprintf(stderr, "List bindings on a LUKS device");
        return EINVAL;


    case ARGP_KEY_END:
        if (!opts->device) {
            fprintf(stderr, "Device MUST be specified!\n");
            argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
            return EINVAL;
        }

        return 0;

    case ARGP_KEY_ARG:
        if (opts->device)
            return ARGP_ERR_UNKNOWN;

        opts->device = arg;
        return 0;

    default:
        return ARGP_ERR_UNKNOWN;
    }
}

const char *argp_program_version = VERSION;

int
main(int argc, char *argv[])
{
    struct options options = {};
    const struct argp argp = {
        .options = (const struct argp_option[]) {
            { "summary", SUMMARY, .flags = OPTION_HIDDEN },
            {}
        },
        .parser = parser,
        .args_doc = "DEVICE"
    };

    if (argp_parse(&argp, argc, argv, 0, NULL, &options) != 0)
        return EX_OSERR;

    return list(&options);
}

