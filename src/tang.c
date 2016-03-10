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

#include <libgen.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include <sys/types.h>
#include <dirent.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#include <ctype.h>

static void
normname(const char *path, char *(*func)(char *path), char *out)
{
    char *tmp = NULL;
    strcpy(out, path);
    tmp = func(out);
    memmove(out, tmp, strlen(tmp) + 1);
}

static bool
valid(const char *str)
{
   for (size_t i = 0; str[i]; i++) {
       if (!islower(str[i]) && str[i] != '-')
           return false;
   }

   return true;
}

static bool
summary(const char *dirname, const char *prfx)
{
    DIR *dir = NULL;

    dir = opendir(dirname);
    if (!dir)
        return false;

    for (struct dirent *de  = readdir(dir); de; de = readdir(dir)) {
        char cmd[PATH_MAX] = {};

        if (strncmp(de->d_name, prfx, strlen(prfx)) != 0)
            continue;

        if (!valid(&de->d_name[strlen(prfx)]))
            continue;

        fprintf(stderr, "%-16s ", &de->d_name[strlen(prfx)]);
        snprintf(cmd, sizeof(cmd), "%s/%s --summary", dirname, de->d_name);
        system(cmd);
        fprintf(stderr, "\n");
    }

    closedir(dir);
    return true;
}

static char *
getpath(void)
{
    char *env = NULL;
    size_t len = 0;

    env = getenv("PATH");
    if (env)
        return strdup(env);

    len = confstr(_CS_PATH, NULL, 0);
    if (len == 0)
        return NULL;

    char tmp[len + 2];

    strcpy(tmp, ".:");
    if (confstr(_CS_PATH, &tmp[2], len - 2) == 0)
        return NULL;

    return strdup(tmp);
}

int
main(int argc, char *argv[])
{
    char bname[PATH_MAX] = {};

    if (argc < 2 || strlen(argv[0]) + strlen(argv[1]) + 2 > PATH_MAX) {
        const char *cmd = basename(argv[0]);
        fprintf(stderr, "Usage: %s COMMAND [...]\n", cmd);
        fprintf(stderr, "       %s commands\n", cmd);
        return EX_USAGE;
    }

    if (strcmp(argv[1], "commands") != 0) {
        char cmd[PATH_MAX] = {};
        strcpy(cmd, argv[0]);
        strcat(cmd, "-");
        strcat(cmd, argv[1]);

        argv[1] = cmd;
        execvp(argv[1], &argv[1]);
        return EX_OSERR;
    }

    normname(argv[0], basename, bname);
    strcat(bname, "-");

    if (strchr(argv[0], '/') == NULL) {
        char *path = NULL;

        path = getpath();
        if (!path)
            return EX_OSERR;

        for (char *p = NULL, *iter = path; (p = strsep(&iter, ":")); ) {
            if (!summary(p, bname)) {
                free(path);
                return EX_OSERR;
            }
        }

        free(path);
    } else {
        char dname[PATH_MAX] = {};
        normname(argv[0], dirname, dname);
        if (!summary(dname, bname))
            return EX_OSERR;
    }

    return EX_USAGE;
}
