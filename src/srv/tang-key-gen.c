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

#include <openssl/ec.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#include <sys/types.h>
#include <sys/xattr.h>
#include <sys/stat.h>
#include <argp.h>
#include <libgen.h>
#include <stdbool.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#define _STR(x) # x
#define STR(x) _STR(x)
#define SUMMARY 192

struct options {
    const char *dbdir;
    EC_GROUP *grp;
    struct {
        bool show : 1;
        bool hide : 1;
        bool rec : 1;
        bool sig : 1;
    };
};

const char *argp_program_version = VERSION;

static error_t
parser(int key, char* arg, struct argp_state* state)
{
    struct options *opts = state->input;
    int nid;

    switch (key) {
    case SUMMARY:
        fprintf(stderr, "Generate a new key");
        return EINVAL;

    case 'A':
        opts->show = true;
        return 0;

    case 'a':
        opts->hide = true;
        return 0;

    case 'r':
        opts->rec = true;
        return 0;

    case 's':
        opts->sig = true;
        return 0;

    case 'd':
        if (strlen(arg) > PATH_MAX / 2) {
            fprintf(stderr, "The specified dbdir is too long\n");
            return E2BIG;
        }

        opts->dbdir = arg;
        return 0;

    case 'g':
        if (opts->grp)
           EC_GROUP_free(opts->grp);

        if (strcmp(arg, "list") == 0) {
            size_t ncurves = 0;

            ncurves = EC_get_builtin_curves(NULL, 0);
            if (ncurves == 0)
                exit(EX_OSERR);

            EC_builtin_curve curves[ncurves];
            if (EC_get_builtin_curves(curves, ncurves) != ncurves)
                exit(EX_OSERR);

            for (size_t i = 0; i < ncurves; i++) {
                EC_GROUP *grp = NULL;

                grp = EC_GROUP_new_by_curve_name(curves[i].nid);
                if (!grp)
                    continue;

                EC_GROUP_free(grp);
                printf("%s\n", OBJ_nid2sn(curves[i].nid));
            }

            exit(EX_OK);
        }

        nid = OBJ_txt2nid(arg);
        if (nid == NID_undef) {
            fprintf(stderr, "Invalid group: %s\n", arg);
            return EINVAL;
        }

        opts->grp = EC_GROUP_new_by_curve_name(nid);
        if (!opts->grp) {
            fprintf(stderr, "Unsupported group: %s\n", arg);
            return EINVAL;
        }

        return 0;

    case ARGP_KEY_END:
        if (!opts->grp) {
            fprintf(stderr, "Group MUST be specified!\n\n");
            argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
            return EINVAL;
        }

        if (!(opts->hide ^ opts->show)) {
            fprintf(stderr, "Either show or hide is required\n\n");
            argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
            return EINVAL;
        }

        if (!(opts->rec ^ opts->sig)) {
            fprintf(stderr, "Either recovery or signature is required\n\n");
            argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
            return EINVAL;
        }

        if (!opts->dbdir)
            opts->dbdir = TANG_DB;

        return 0;

    default:
        return ARGP_ERR_UNKNOWN;
    }
}

static size_t
curftime(char *out, size_t max)
{
    struct tm tm = {};
    time_t t = -1;

    if (time(&t) == -1)
        return 0;

    if (!gmtime_r(&t, &tm))
        return 0;

    return strftime(out, max, "%Y%m%dT%H%M%S", &tm);
}

int
main(int argc, char *argv[])
{
    struct options opts = {};
    const struct argp argp = {
        .options = (const struct argp_option[]) {
            { "summary", SUMMARY, .flags = OPTION_HIDDEN },
            { "dbdir", 'd', "dir", .doc = "Key database directory" },
            { "show", 'A', .doc = "Advertise the key" },
            { "hide", 'a', .doc = "Do not advertise the key" },
            { "signature", 's', .doc = "Use key for signatures" },
            { "recovery", 'r', .doc = "Use key for recovery" },
            { "group", 'g', "group", .doc = "Key group ('list' for options)" },
            {}
        },
        .parser = parser,
    };
    EC_KEY *key = NULL;
    FILE *file = NULL;
    char fn[PATH_MAX];
    int bytes = 0;

    if (argp_parse(&argp, argc, argv, 0, NULL, &opts) != 0)
        return EX_OSERR;

    umask(S_IXUSR | S_IXGRP | S_IRWXO);

    EC_GROUP_set_asn1_flag(opts.grp, OPENSSL_EC_NAMED_CURVE);
    EC_GROUP_set_point_conversion_form(opts.grp, POINT_CONVERSION_COMPRESSED);

    bytes = (EC_GROUP_get_degree(opts.grp) + 7) / 8;
    if (RAND_load_file("/dev/random", bytes) != bytes) {
        EC_GROUP_free(opts.grp);
        return EX_IOERR;
    }

    key = EC_KEY_new();
    if (!key
        || EC_KEY_set_group(key, opts.grp) <= 0
        || EC_KEY_generate_key(key) <= 0) {
        fprintf(stderr, "Error generating key\n");
        EC_GROUP_free(opts.grp);
        EC_KEY_free(key);
        return EX_OSERR;
    }

    while (true) {
        char timestamp[16] = {};

        if (curftime(timestamp, sizeof(timestamp)) == 0) {
            fprintf(stderr, "Unable to get current time\n");
            EC_GROUP_free(opts.grp);
            EC_KEY_free(key);
            return EX_OSERR;
        }

        strcpy(fn, opts.dbdir);
        strcat(fn, "/");

        if (opts.hide)
            strcat(fn, ".");

        strcat(fn, timestamp);

        if (opts.rec)
            strcat(fn, ".rec");
        else if (opts.sig)
            strcat(fn, ".sig");

        file = fopen(fn, "wx");
        if (file || errno != EEXIST)
            break;

        sleep(1);
    }

    if (!file) {
        fprintf(stderr, "Unable to create output file\n");
        EC_GROUP_free(opts.grp);
        EC_KEY_free(key);
        return EX_IOERR;
    }

    if (PEM_write_ECPKParameters(file, opts.grp) <= 0 ||
        PEM_write_ECPrivateKey(file, key, NULL, NULL, 0, NULL, NULL) <= 0) {
        fprintf(stderr, "Error writing key\n");
        unlink(fn);
        EC_GROUP_free(opts.grp);
        EC_KEY_free(key);
        fclose(file);
        return EX_IOERR;
    }

    fprintf(stdout, "%s\n", basename(fn));

    EC_GROUP_free(opts.grp);
    EC_KEY_free(key);
    fclose(file);
    return 0;
}

