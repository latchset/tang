/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab: */
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
#include <errno.h>
#include <error.h>
#include <getopt.h>
#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int
main(int argc, char **argv)
{
    char filename[PATH_MAX] = {};
    const char *dbdir = TANG_DB;
    bool adv = false;
    size_t len;
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

    if (optind >= argc)
        goto usage;

    len = strlen(argv[optind]);
    if (!strchr(argv[optind], '/'))
        len += strlen(dbdir) + 1;

    if (len >= sizeof(filename))
        error(EXIT_FAILURE, E2BIG, "Filename too long");

    if (!strchr(argv[optind], '/')) {
        strcat(filename, dbdir);
        strcat(filename, "/");
    }

    strcat(filename, argv[optind]);

    if (adv) {
        r = setxattr(filename, "user.tang.adv", "", 0, 0);
        if (r != 0)
            error(EXIT_FAILURE, errno, "Unable to advertise");
    } else {
        r = removexattr(filename, "user.tang.adv");
        if (r != 0 && errno != ENODATA)
            error(EXIT_FAILURE, errno, "Unable to unadvertise");
    }

    return 0;

usage:
    fprintf(stderr, "Usage: %s [-h] [-A|-a] [-d DBDIR] [FILE|NAME]\n", argv[0]);
    return EXIT_FAILURE;
}
