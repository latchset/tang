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
    const char *file;
    const char *use;
    EC_GROUP *grp;
    bool show;
    bool hide;
};

const char *argp_program_version = VERSION;

/* Generate len random bytes. Convert to null-terminated hex (2 * len + 1). */
static bool
hexrandom(size_t len, char *hex)
{
    static const char chrs[] = "0123456789abcdef";
    unsigned char bin[len];
    FILE *file = NULL;

    file = fopen("/dev/urandom", "r");
    if (!file)
        return errno;

    if (fread(bin, 1, sizeof(bin), file) != sizeof(bin)) {
        fclose(file);
        return EIO;
    }
    fclose(file);

    for (size_t i = 0; i < len; i++) {
        hex[i * 2 + 0] = chrs[bin[i] >> 0 & 0x0f];
        hex[i * 2 + 1] = chrs[bin[i] >> 4 & 0x0f];
    }

    hex[len * 2] = 0;
    return 0;
}

static int
keyfilegen(const char *dbdir, char path[PATH_MAX])
{
    char hex[33];

    hexrandom(sizeof(hex) / 2, hex);

    if (strlen(dbdir) + 34 > PATH_MAX)
        return E2BIG;

    strcpy(path, dbdir);
    strcat(path, "/");
    strcat(path, hex);
    return 0;
}

static const char *
get_use(const char *use)
{
    static const char *uses[] = {
        "recovery",
        "signature",
        NULL
    };

    if (strlen(use) < 3)
        return false;

    for (int i = 0; uses[i]; i++) {
        if (strncmp(uses[i], use, strlen(use)) == 0)
          return uses[i];
    }

    return use;
}

static error_t
parser(int key, char* arg, struct argp_state* state)
{
    struct options *opts = state->input;

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

    case 'd':
        opts->dbdir = arg;
        return 0;

    case 'f':
        opts->file = arg;
        return 0;

    case ARGP_KEY_ARG:
        if (!opts->grp) {
            int nid = 0;

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
        } else if (!opts->use) {
            opts->use = get_use(arg);
            if (!opts->use) {
                fprintf(stderr, "Invalid use: %s\n", arg);
                return EINVAL;
            }

            return 0;
        }

        return ARGP_ERR_UNKNOWN;

    case ARGP_KEY_END:
        if (!opts->grp) {
            fprintf(stderr, "Group MUST be specified!\n\n");
            argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
            return EINVAL;
        }

        if (!opts->use) {
            fprintf(stderr, "Use MUST be specified!\n\n");
            argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
            return EINVAL;
        }

        if (!(opts->hide ^ opts->show)) {
            fprintf(stderr, "You MUST specify either show or hide\n\n");
            return EINVAL;
        }

        if (!opts->dbdir)
            opts->dbdir = TANG_DB;

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
            { "file", 'f', "file", .doc = "output key file" },
            { "show", 'A', .doc = "key advertisement" },
            { "hide", 'a', .doc = "key advertisement" },
            {}
        },
        .parser = parser,
        .args_doc = "GROUP <recovery|signature>"
    };
    char filename[PATH_MAX];
    EC_KEY *key = NULL;
    FILE *file = NULL;
    int bytes = 0;

    if (argp_parse(&argp, argc, argv, 0, NULL, &opts) != 0)
        return EX_OSERR;

    umask(S_IRWXG | S_IRWXO);

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

    if (opts.file) {
        if (strlen(opts.file) > sizeof(filename) - 1) {
            fprintf(stderr, "Filename too long: %s\n", opts.file);
            EC_GROUP_free(opts.grp);
            EC_KEY_free(key);
            return EX_USAGE;
        }

        strcpy(filename, opts.file);
        file = fopen(filename, "wx");
    } else {
        do {
            if (keyfilegen(opts.dbdir, filename) != 0) {
                fprintf(stderr, "Error generating keyfile name\n");
                EC_GROUP_free(opts.grp);
                EC_KEY_free(key);
                return EX_OSERR;
            }

            file = fopen(filename, "wx");
        } while (!file && errno == EEXIST);
    }
    if (!file) {
        fprintf(stderr, "Unable to create output file\n");
        EC_GROUP_free(opts.grp);
        EC_KEY_free(key);
        return EX_IOERR;
    }

    if (setxattr(filename, "user.tang.use", opts.use, 3, XATTR_CREATE) != 0) {
        fprintf(stderr, "Error setting key usage\n");
        EC_GROUP_free(opts.grp);
        unlink(filename);
        EC_KEY_free(key);
        fclose(file);
        return EX_IOERR;
    }

    if (opts.show && !opts.hide) {
        if (setxattr(filename, "user.tang.adv", "", 0, XATTR_CREATE) != 0) {
            fprintf(stderr, "Error setting key advertisement\n");
            EC_GROUP_free(opts.grp);
            unlink(filename);
            EC_KEY_free(key);
            fclose(file);
            return EX_IOERR;
        }
    }

    if (PEM_write_ECPKParameters(file, opts.grp) <= 0 ||
        PEM_write_ECPrivateKey(file, key, NULL, NULL, 0, NULL, NULL) <= 0) {
        unlink(filename);
        fprintf(stderr, "Error writing key\n");
        EC_GROUP_free(opts.grp);
        EC_KEY_free(key);
        fclose(file);
        return EX_IOERR;
    }

    if (!opts.file)
        fprintf(stdout, "%s\n", basename(filename));

    EC_GROUP_free(opts.grp);
    EC_KEY_free(key);
    fclose(file);
    return 0;
}

