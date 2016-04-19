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

#define _GNU_SOURCE
#include "askp.h"

#include <sys/inotify.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define ASK_DIR "/run/systemd/ask-password"

#define unwrap(a) \
    (a ? LIST_UNWRAP(&a->questions, askpi_t, askp.questions) : NULL)

typedef struct {
    askp_t askp;
    int ifd;
    int wfd;
} askpi_t;

static struct inotify_event *
for_event(struct inotify_event *e, struct inotify_event *buf, size_t len)
#define for_event(n, b, l) \
    for (struct inotify_event *n = NULL; (n = for_event(n, b, l)); )
{
    uint8_t *tmp;

    if (e == NULL)
        return buf;

    tmp = (uint8_t *) &e[1] + e->len;
    if (tmp < (uint8_t *) buf + len)
        return (struct inotify_event *) tmp;

    return NULL;
}

int
askp_new(askp_t **askp, struct pollfd *fd)
{
    askpi_t *askpi = NULL;
    DIR *dir = NULL;
    int ret;

    askpi = calloc(1, sizeof(askpi_t));
    if (!askpi)
        return ENOMEM;

    askpi->askp.questions = LIST_INIT(askpi->askp.questions);
    askpi->ifd = -1;
    askpi->wfd = -1;

    askpi->ifd = inotify_init();
    if (askpi->ifd < 0)
        goto error;

    askpi->wfd = inotify_add_watch(askpi->ifd, ASK_DIR,
                                   IN_CLOSE_WRITE | IN_MOVED_TO);
    if (askpi->wfd < 0)
        goto error;

    dir = opendir(ASK_DIR);
    if (dir == NULL)
        goto error;

    for (struct dirent *de = readdir(dir); de; de = readdir(dir)) {
        question_t *q;

        if (strncmp("ask.", de->d_name, 4) != 0)
            continue;

        q = question_new(ASK_DIR, de->d_name);
        if (q != NULL)
            list_add_after(&askpi->askp.questions, &q->list);
    }

    closedir(dir);

    fd->events = POLLIN | POLLPRI;
    fd->fd = askpi->ifd;
    *askp = &askpi->askp;
    return 0;

error:
    ret = errno;
    askp_free(&askpi->askp);
    return ret;
}

bool
askp_new_question(askp_t *askp, struct pollfd *fd)
{
    struct inotify_event buf[512];
    bool havenew = false;
    ssize_t len;

    if ((fd->revents & fd->events) == 0)
        return false;
    fd->revents = 0;

    while ((len = read(fd->fd, buf, sizeof(buf))) < 0) {
        if (errno != EAGAIN)
            return false;
    }

    for_event(e, buf, len) {
        if (strncmp("ask.", e->name, 4) != 0)
            continue;

        if (e->mask & IN_MOVED_TO) {
            question_t *q;

            q = question_new(ASK_DIR, e->name);
            if (q != NULL) {
                list_add_after(&askp->questions, &q->list);
                havenew = true;
            }

            continue;
        }

        LIST_FOREACH(&askp->questions, question_t, q, list) {
            if (question_named(q, e->name)) {
                list_pop(&q->list);
                question_free(q);
                break;
            }
        }
    }

    return havenew;
}

void
askp_free(askp_t *askp)
{
    askpi_t *askpi = unwrap(askp);

    if (!askpi)
        return;

    LIST_FOREACH(&askp->questions, question_t, q, list)
        question_free(q);

    close(askpi->wfd);
    close(askpi->ifd);
    free(askpi);
}

