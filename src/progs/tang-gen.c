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

#include <stdbool.h>
#include <string.h>
#include <limits.h>
#include <getopt.h>
#include <errno.h>
#include <error.h>
#include <unistd.h>

#include <libgen.h>

#include <sys/types.h>
#include <sys/xattr.h>

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

static bool
valid_use(const char *use)
{
    static const char *uses[] = {
        "recover",
        "sign",
        NULL
    };

    if (strlen(use) < 3)
        return false;

    for (int i = 0; uses[i]; i++) {
        if (strncmp(uses[i], use, strlen(use)) == 0)
          return true;
    }

    return false;
}

int
main(int argc, char **argv)
{
    const char *dbdir = TANG_DB;
    const char *group = NULL;
    char filename[PATH_MAX];
    const char *use = NULL;
    EC_GROUP *grp = NULL;
    EC_KEY *key = NULL;
    FILE *file = NULL;
    bool adv = false;
    int r;

    for (int c; (c = getopt(argc, argv, "haAd:")) != -1; ) {
        switch (c) {
        case 'A':
        case 'a':
            adv = c == 'A';
            break;

        case 'd':
            dbdir = optarg;
            break;

        default:
            goto usage;
        }
    }

    if (argc - optind != 2 && argc - optind != 3)
        goto usage;

    group = argv[optind++];
    r = OBJ_txt2nid(group);
    if (r == NID_undef)
        error(EXIT_FAILURE, EINVAL, "Invalid group: %s", group);

    grp = EC_GROUP_new_by_curve_name(r);
    if (!grp)
        error(EXIT_FAILURE, 0, "Unsupported group: %s", group);

    EC_GROUP_set_asn1_flag(grp, OPENSSL_EC_NAMED_CURVE);
    EC_GROUP_set_point_conversion_form(grp, POINT_CONVERSION_COMPRESSED);

    key = EC_KEY_new();
    if (!key
        || EC_KEY_set_group(key, grp) <= 0
        || EC_KEY_generate_key(key) <= 0)
        error(EXIT_FAILURE, 0, "Error generating key");

    use = argv[optind++];
    if (!valid_use(use))
        error(EXIT_FAILURE, EINVAL, "Invalid use: %s", use);

    if (optind < argc) {
        if (strlen(argv[optind]) > sizeof(filename) - 1)
            error(EXIT_FAILURE, E2BIG, "Filename too long: %s", argv[optind]);
        strcpy(filename, argv[optind]);

        file = fopen(filename, "wx");
    } else {
        do {
            r = keyfilegen(dbdir, filename);
            if (r != 0)
                error(EXIT_FAILURE, r, "Error generating keyfile name");

            file = fopen(filename, "wx");
        } while (!file && errno == EEXIST);
    }
    if (!file)
        error(EXIT_FAILURE, errno, "Unable to create file: %s", filename);

    r = setxattr(filename, "user.tang.use", use, 3, XATTR_CREATE);
    if (r != 0) {
        r = errno;
        unlink(filename);
        error(EXIT_FAILURE, r, "Error setting key usage");
    }

    if (adv) {
        r = setxattr(filename, "user.tang.adv", "", 0, XATTR_CREATE);
        if (r != 0) {
            r = errno;
            unlink(filename);
            error(EXIT_FAILURE, r, "Error setting key advertisement");
        }
    }

    if (PEM_write_ECPKParameters(file, grp) <= 0 ||
        PEM_write_ECPrivateKey(file, key, NULL, NULL, 0, NULL, NULL) <= 0) {
        unlink(filename);
        error(EXIT_FAILURE, 0, "Error writing key");
    }

    if (optind == argc)
        fprintf(stdout, "%s\n", basename(filename));

    EC_GROUP_free(grp);
    EC_KEY_free(key);
    fclose(file);
    return 0;

usage:
    fprintf(stderr, "Usage: %s [-h] [-A|-a] [-d DBDIR] GROUP USE [FILE]\n", argv[0]);
    return EXIT_FAILURE;
}
