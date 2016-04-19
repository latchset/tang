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

#include "asn1.h"
#include "luks.h"
#include "meta.h"
#include "../msg.h"

#include <libcryptsetup.h>

#include <argp.h>
#include <string.h>
#include <sysexits.h>

#define _STR(x) # x
#define STR(x) _STR(x)

struct options {
    const char *device;
    msg_t params;
};

static error_t
argp_parser(int key, char* arg, struct argp_state* state)
{
    struct options *opts = state->input;

    switch (key) {
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
    { "hostname", 'h', "hostname", .doc = "Remote server hostname" },
    { "service",  's', "service",  .doc = "Remote server service" },
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
    struct crypt_device *cd = NULL;
    struct options opts = {};
    const char *type = NULL;
    int nerr = 0;

    if (argp_parse(&argp, argc, argv, 0, NULL, &opts) != 0)
        return EX_OSERR;

    if (strlen(opts.params.hostname) == 0) {
        for (int slot = 0; slot < LUKS_NUMKEYS; slot++) {
            TANG_LUKS *tl = NULL;
            sbuf_t *buf = NULL;

            buf = meta_read(opts.device, slot);
            if (!buf)
                continue;

            tl = TANG_LUKS_from_sbuf(buf);
            sbuf_free(buf);
            if (!tl)
                continue;

            fwrite(tl->hostname->data, tl->hostname->length, 1, stderr);
            fwrite(":", 1, 1, stderr);
            fwrite(tl->service->data, tl->service->length, 1, stderr);
            fwrite("\n", 1, 1, stderr);

            TANG_LUKS_free(tl);
        }

        return 0;
    }

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
        TANG_LUKS *tl = NULL;
        sbuf_t *buf = NULL;

        switch (crypt_keyslot_status(cd, slot)) {
        case CRYPT_SLOT_ACTIVE:
        case CRYPT_SLOT_ACTIVE_LAST:
            buf = meta_read(opts.device, slot);
            if (!buf)
                continue;

            tl = TANG_LUKS_from_sbuf(buf);
            sbuf_free(buf);
            if (!tl)
                continue;

            if (strncmp((char *) tl->hostname->data, opts.params.hostname,
                        tl->hostname->length) != 0) {
                TANG_LUKS_free(tl);
                continue;
            }

            if (strncmp((char *) tl->service->data, opts.params.service,
                        tl->service->length) != 0) {
                TANG_LUKS_free(tl);
                continue;
            }

            TANG_LUKS_free(tl);

            if (crypt_keyslot_destroy(cd, slot) == 0)
                meta_erase(opts.device, slot);
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

