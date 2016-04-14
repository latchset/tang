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
#include "luks/luks.h"
#include "luks/meta.h"

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
    struct options opts = {};

    if (argp_parse(&argp, argc, argv, 0, NULL, &opts) != 0)
        return EX_OSERR;

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

