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

#include <sys/epoll.h>
#include <sys/inotify.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>

static const char *path = NULL;
static json_t *ctx = NULL;
static int fd = -1;

static void
load_jwks(const char *db, const char *name)
{
    char fn[PATH_MAX] = {};
    json_t *jwkset = NULL;
    json_t *jwk = NULL;
    json_t *arr = NULL;
    size_t i = 0;

    snprintf(fn, sizeof(fn) - 1, "%s/%s", db, name);

    jwkset = json_load_file(fn, 0, NULL);
    if (!jwkset) {
        fprintf(stderr, "Error loading JWK(Set): %s!\n", fn);
        return;
    }

    arr = json_incref(json_object_get(jwkset, "keys"));
    if (!json_is_array(arr)) {
        json_decref(arr);
        arr = json_pack("[O]", jwkset);
    }

    json_decref(jwkset);
    if (json_object_set_new(ctx, name, arr) != 0)
        return;

    json_array_foreach(arr, i, jwk)
        tang_io_add_jwk(name[0] != '.', jwk);

    return;
}

static void
on_change(void)
{
    unsigned char buf[sizeof(struct inotify_event) + NAME_MAX + 1] = {};
    const struct inotify_event *ev;
    ssize_t bytes = 0;

    bytes = read(fd, buf, sizeof(buf));
    if (bytes < 0)
        return;

    for (ssize_t i = 0; i < bytes; i += sizeof(*ev) + ev->len) {
        const json_t *jwk = NULL;

        ev = (struct inotify_event *) &buf[i];
        if (ev->len == 0)
            continue;

        jwk = json_object_get(ctx, ev->name);
        if (jwk) {
            tang_io_del_jwk(jwk);
            json_object_del(ctx, ev->name);
        }

        if (ev->mask & (IN_MOVED_TO | IN_CREATE | IN_CLOSE_WRITE))
            load_jwks(path, ev->name);
    }
}

int __attribute__((visibility("default")))
tang_plugin_init(int epoll, const char *cfg)
{
    DIR *dir = NULL;

    errno = 0;

    ctx = json_object();
    if (!ctx)
        return -ENOMEM;

    dir = opendir(cfg);
    if (!dir) {
        fprintf(stderr, "Unable to open directory: %s\n", cfg);
        return -errno;
    }

    fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (fd < 0)
        goto egress;

    if (inotify_add_watch(fd, cfg, IN_ONLYDIR | IN_CLOSE_WRITE | IN_MOVE |
                                   IN_CREATE  | IN_DELETE) < 0)
        goto egress;

    if (epoll_ctl(epoll, EPOLL_CTL_ADD, fd,
                  &(struct epoll_event) {
                      .events = EPOLLIN,
                      .data.ptr = on_change
                  }) < 0)
        goto egress;

    for (struct dirent *de = readdir(dir); de; de = readdir(dir)) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;

        load_jwks(cfg, de->d_name);
    }

egress:
    closedir(dir);
    path = cfg;
    return -errno;
}

static void __attribute__((destructor))
destructor(void)
{
    json_decref(ctx);
    if (fd >= 0) {
        close(fd);
        fd = -1;
    }
}
