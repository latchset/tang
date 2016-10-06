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

#include "plugin.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static const char *dir;

static int
blmod(enum http_method method, const char *path, const char *body,
      regmatch_t matches[])
{
    size_t size = matches[1].rm_eo - matches[1].rm_so;
    char *id = NULL;
    int status = 0;
    int r = -1;

    id = malloc(strlen(dir) + size + 2);
    if (!id)
        return tang_reply(HTTP_STATUS_INTERNAL_SERVER_ERROR, NULL);

    strcpy(id, dir);
    strcat(id, "/");
    strncat(id, &path[matches[1].rm_so], size);

    switch (method) {
    case HTTP_DELETE:
        r = unlink(id);
        break;

    case HTTP_PUT:
        r = open(id, O_WRONLY | O_CREAT | O_EXCL, S_IRGRP | S_IWGRP);
        if (r >= 0)
            close(r);
        break;

    default:
        free(id);
        return -EINVAL;
    }

    free(id);

    switch (r >= 0 ? 0 : errno) {
    case 0:      status = HTTP_STATUS_OK;                    break;
    case ENOENT: status = HTTP_STATUS_NOT_FOUND;             break;
    case EEXIST: status = HTTP_STATUS_CONFLICT;              break;
    default:     status = HTTP_STATUS_INTERNAL_SERVER_ERROR; break;
    }

    return tang_reply(status, NULL);
}

static int
bllst(enum http_method method, const char *path, const char *body,
      regmatch_t matches[])
{
    json_auto_t *arr = NULL;
    char *out = NULL;
    DIR *d = NULL;
    int r = 0;

    arr = json_array();
    if (!arr)
        return tang_reply(HTTP_STATUS_INTERNAL_SERVER_ERROR, NULL);

    d = opendir(dir);
    if (!d)
        return tang_reply(HTTP_STATUS_INTERNAL_SERVER_ERROR, NULL);

    for (struct dirent *de = readdir(d); de; de = readdir(d)) {
        bool valid = true;

        for (size_t i = 0; valid && de->d_name[i]; i++)
            valid = isalnum(de->d_name[i]) || strchr("-_", de->d_name[i]);

        if (valid)
            json_array_append_new(arr, json_string(de->d_name));
    }

    out = json_dumps(arr, JSON_COMPACT);
    closedir(d);
    if (!out)
        return tang_reply(HTTP_STATUS_INTERNAL_SERVER_ERROR, NULL);

    r = tang_reply(HTTP_STATUS_OK,
                   "Content-Length: %zu\r\n"
                   "Content-Type: application/json\r\n"
                   "\r\n%s", strlen(out), out);
    free(out);
    return r;
}

int __attribute__((visibility("default")))
tang_plugin_init(int epoll, const char *cfg)
{
    static struct tang_plugin_map maps[] = {
        { blmod, (1 << HTTP_DELETE) | (1 << HTTP_PUT),
          2, "^/+blk/+([0-9A-Za-z_-]+)$" },
        { bllst, 1 << HTTP_GET, 1, "^/+blk/*$" },
    };

    maps[0].next = tang_plugin_maps;
    maps[1].next = &maps[0];
    tang_plugin_maps = &maps[1];
    dir = cfg;
    return 0;
}

