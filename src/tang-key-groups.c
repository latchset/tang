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

#include <sys/types.h>
#include <sys/xattr.h>
#include <argp.h>
#include <stdbool.h>
#include <string.h>
#include <sysexits.h>

#include <openssl/ec.h>
#include <openssl/objects.h>

#define SUMMARY 192

const char *argp_program_version = VERSION;

static error_t
parser(int key, char* arg, struct argp_state* state)
{
    switch (key) {
    case SUMMARY:
        fprintf(stderr, "List supported groups");
        return EINVAL;

    case ARGP_KEY_ARG:
        return ARGP_ERR_UNKNOWN;

    default:
        return ARGP_ERR_UNKNOWN;
    }
}

int
main(int argc, char *argv[])
{
    const struct argp argp = {
        .options = (const struct argp_option[]) {
            { "summary", SUMMARY, .flags = OPTION_HIDDEN },
            {}
        },
        .parser = parser,
    };

    if (argp_parse(&argp, argc, argv, 0, NULL, NULL) != 0)
        return EX_OSERR;

    size_t ncurves = 0;

    ncurves = EC_get_builtin_curves(NULL, 0);
    if (ncurves == 0)
        return EX_OSERR;

    EC_builtin_curve curves[ncurves];
    if (EC_get_builtin_curves(curves, ncurves) != ncurves)
        return EX_OSERR;

    for (size_t i = 0; i < ncurves; i++) {
        EC_GROUP *grp = NULL;

        grp = EC_GROUP_new_by_curve_name(curves[i].nid);
        if (!grp)
            continue;

        EC_GROUP_free(grp);
        printf("%s\n", OBJ_nid2sn(curves[i].nid));
    }

    return true;
}


