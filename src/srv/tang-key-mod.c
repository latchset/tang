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

#include <sys/types.h>
#include <sys/xattr.h>
#include <argp.h>
#include <stdbool.h>
#include <string.h>
#include <sysexits.h>

#define ADV "user.tang.adv"
#define _STR(x) # x
#define STR(x) _STR(x)
#define SUMMARY 192

struct options {
    char filename[PATH_MAX];
    const char *dbdir;
    const char *file;
    bool show;
    bool hide;
};

const char *argp_program_version = VERSION;

static error_t
parser(int key, char* arg, struct argp_state* state)
{
    struct options *opts = state->input;
    int r;

    switch (key) {
    case SUMMARY:
        fprintf(stderr, "Modify an existing key");
        return EINVAL;

    case 'A':
        opts->show = true;
        return 0;

    case 'a':
        opts->hide = true;
        return 0;

    case 'd':
        opts->dbdir = arg;
        return 0;

    case ARGP_KEY_ARG:
        if (!opts->file)
            opts->file = arg;
        else
            return ARGP_ERR_UNKNOWN;

    case ARGP_KEY_END:
        if (!opts->file) {
            fprintf(stderr, "A file or name MUST be specified!\n\n");
            argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
            return EINVAL;
        }

        if (!(opts->hide ^ opts->show)) {
            fprintf(stderr, "You MUST specify either show or hide\n\n");
            return EINVAL;
        }

        if (!opts->dbdir)
            opts->dbdir = TANG_DB;

        if (strchr(opts->file, '/')) {
            r = snprintf(opts->filename, sizeof(opts->filename),
                         "%s", opts->filename);
        } else {
            r = snprintf(opts->filename, sizeof(opts->filename),
                         "%s/%s", opts->dbdir, opts->filename);
        }
        if (r >= (int) sizeof(opts->filename)) {
            fprintf(stderr, "File name is too long\n\n");
            return EINVAL;
        }

        return 0;

    default:
        return ARGP_ERR_UNKNOWN;
    }
}

int
main(int argc, char *argv[])
{
    struct options opts = {};
    const struct argp argp = {
        .options = (const struct argp_option[]) {
            { "summary", SUMMARY, .flags = OPTION_HIDDEN },
            { "dbdir", 'd', "dir", .doc = "database directory" },
            { "show", 'A', .doc = "key advertisement" },
            { "hide", 'a', .doc = "key advertisement" },
            {}
        },
        .parser = parser,
        .args_doc = "<FILE|NAME>"
    };

    if (argp_parse(&argp, argc, argv, 0, NULL, &opts) != 0)
        return EX_OSERR;

    if (opts.show && !opts.hide) {
        if (setxattr(opts.filename, ADV, "", 0, 0) != 0) {
            fprintf(stderr, "Unable to show\n");
            return EX_IOERR;
        }
    } else {
        if (removexattr(opts.filename, ADV) != 0 && errno != ENODATA) {
            fprintf(stderr, "Unable to hide\n");
            return EX_IOERR;
        }
    }

    return 0;
}


