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

static int fd = -1;

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
        ev = (struct inotify_event *) &buf[i];
        if (ev->len == 0)
            continue;

        tang_db_del_bid(ev->name);
        if (ev->mask & (IN_MOVED_TO | IN_CREATE))
            tang_db_add_bid(ev->name);
    }
}

int __attribute__((visibility("default")))
tang_plugin_init(int epoll, const char *cfg)
{
    DIR *dir = NULL;

    errno = 0;

    dir = opendir(cfg);
    if (!dir) {
        fprintf(stderr, "Unable to open directory: %s\n", cfg);
        return -errno;
    }

    fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (fd < 0)
        goto egress;

    if (inotify_add_watch(fd, cfg, IN_ONLYDIR| IN_MOVE |
                                   IN_CREATE | IN_DELETE) < 0)
        goto egress;

    if (epoll_ctl(epoll, EPOLL_CTL_ADD, fd,
                  &(struct epoll_event) {
                      .events = EPOLLIN,
                      .data.ptr = on_change
                  }) < 0)
        goto egress;

    for (struct dirent *de = readdir(dir); de; de = readdir(dir))
        tang_db_add_bid(de->d_name);

egress:
    closedir(dir);
    return -errno;
}

static void __attribute__((destructor))
destructor(void)
{
    if (fd >= 0) {
        close(fd);
        fd = -1;
    }
}
