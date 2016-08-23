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

#include <systemd/sd-event.h>

#include <sys/inotify.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>

static int
on_change(sd_event_source *s, int fd, uint32_t revents, void *userdata)
{
    unsigned char buf[sizeof(struct inotify_event) + NAME_MAX + 1] = {};
    const struct inotify_event *ev;
    ssize_t bytes = 0;

    bytes = read(fd, buf, sizeof(buf));
    if (bytes < 0)
        return -errno;

    for (ssize_t i = 0; i < bytes; i += sizeof(*ev) + ev->len) {
        ev = (struct inotify_event *) &buf[i];
        if (ev->len == 0)
            continue;

        tang_io_del_bid(ev->name);
        if (ev->mask & (IN_MOVED_TO | IN_CREATE))
            tang_io_add_bid(ev->name);
    }

    return 0;
}

int __attribute__((visibility("default")))
tang_plugin_init(const char *cfg)
{
    sd_event __attribute__((cleanup(sd_event_unrefp))) *e = NULL;
    DIR *dir = NULL;
    int fd = -1;

    dir = opendir(cfg);
    if (!dir) {
        fprintf(stderr, "Unable to open directory: %s\n", cfg);
        return -errno;
    }

    fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (fd < 0)
        goto error;

    if (inotify_add_watch(fd, cfg, IN_ONLYDIR| IN_MOVE |
                                   IN_CREATE | IN_DELETE) < 0)
        goto error;

    errno = -sd_event_default(&e);
    if (errno > 0)
        goto error;

    errno = -sd_event_add_io(e, NULL, fd, EPOLLIN, on_change, NULL);
    if (errno > 0)
        goto error;

    for (struct dirent *de = readdir(dir); de; de = readdir(dir))
        tang_io_add_bid(de->d_name);

    closedir(dir);
    return 0;

error:
    closedir(dir);
    if (fd >= 0)
        close(fd);
    return -errno;
}
