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

#define _STR(x) # x
#define STR(x) _STR(x)
#define SUMMARY 192

struct options {
    const char *device;
};

static error_t
argp_parser(int key, char* arg, struct argp_state* state)
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

static const struct argp_option argp_options[] = {
    { "summary", SUMMARY, .flags = OPTION_HIDDEN },
    {}
};

static const struct argp argp = {
    .options = argp_options,
    .parser = argp_parser,
    .args_doc = "DEVICE"
};

int
main(int argc, char *argv[])
{
    struct crypt_device *cd = NULL;
    struct options opts = {};
    const char *type = NULL;
    int nerr = 0;

    if (argp_parse(&argp, argc, argv, 0, NULL, &opts) != 0)
        return EX_OSERR;

    nerr = crypt_init(&cd, opts.device);
    if (nerr != 0) {
        fprintf(stderr, "Unable to open device (%s): %s\n",
                opts.device, strerror(-nerr));
        goto error;
    }

    nerr = crypt_load(cd, NULL, NULL);
    if (nerr != 0) {
        fprintf(stderr, "Unable to load device (%s): %s\n",
                opts.device, strerror(-nerr));
        goto error;
    }

    type = crypt_get_type(cd);
    if (type == NULL) {
        fprintf(stderr, "Unable to determine device type\n");
        goto error;
    }
    if (strcmp(type, CRYPT_LUKS1) != 0) {
        fprintf(stderr, "%s (%s) is not a LUKS device\n", opts.device, type);
        goto error;
    }

    for (int slot = 0; slot < crypt_keyslot_max(CRYPT_LUKS1); slot++) {
        TANG_LUKS *tluks = NULL;
        uint8_t *data = NULL;
        size_t size = 0;

        switch (crypt_keyslot_status(cd, slot)) {
        case CRYPT_SLOT_ACTIVE:
        case CRYPT_SLOT_ACTIVE_LAST:
            data = meta_read(opts.device, slot, &size);
            if (!data)
                continue;

            tluks = d2i_TANG_LUKS(NULL, &(const uint8_t *) { data }, size);
            free(data);
            if (!tluks)
                continue;

            fwrite(tluks->hostname->data, tluks->hostname->length, 1, stderr);
            fwrite(":", 1, 1, stderr);
            fwrite(tluks->service->data, tluks->service->length, 1, stderr);
            fwrite("\n", 1, 1, stderr);
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

