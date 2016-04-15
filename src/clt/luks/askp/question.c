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
#include "question.h"

#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#define SECTION "[Ask]\n"
#define PREFIX_ID "\nId=cryptsetup:"
#define PREFIX_SOCKET "\nSocket="
#define PREFIX_NOTAFTER "\nNotAfter="

#define unwrap(q) \
    (q ? LIST_UNWRAP(&q->list, questioni_t, q.list) : NULL)

typedef struct {
    struct sockaddr_un sock;
    struct timespec time;
    char name[PATH_MAX];
    question_t q;
} questioni_t;

static int
find_prefix_in_section(const char *start, const char *end, const char *prefix,
                       char *out, long olen)
{
    char *startl = NULL;
    char *endl = NULL;
    ssize_t plen;

    if (start == NULL || end == NULL || prefix == NULL)
        return EINVAL;

    plen = strlen(prefix);

    startl = memmem(start, end - start, prefix, plen);
    if (startl == NULL)
        return ENOENT;
    startl += plen;

    endl = memchr(startl, '\n', end - startl);
    if (endl == NULL)
        return ENOENT;

    if (olen < endl - startl + 1)
        return E2BIG;

    plen = snprintf(out, endl - startl + 1, "%s", startl);
    if (plen < 0)
        return errno;

    return 0;
}

question_t *
question_new(const char *dir, const char *name)
{
    questioni_t *qi = NULL;
    struct stat st = {};
    char tmp[PATH_MAX];
    char *start = NULL;
    char *file = NULL;
    char *end = NULL;
    int fd = -1;
    int err;

    qi = calloc(1, sizeof(questioni_t));
    if (!qi)
        goto error;
    qi->sock.sun_family = AF_UNIX;

    if (snprintf(qi->name, sizeof(qi->name), "%s", name) < 0)
        goto error;

    err = snprintf(tmp, sizeof(tmp), "%s/%s", dir, name);
    if (err < 0)
        goto error;

    fd = open(tmp, O_RDONLY);
    if (fd < 0)
        goto error;

    if (fstat(fd, &st) != 0)
        goto error;

    file = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (!file)
        goto error;

    start = memmem(file, st.st_size, SECTION, strlen(SECTION));
    if (!start)
        goto error;

    end = memmem(start, st.st_size - (start - file), "\n[", 2);
    if (!end)
        end = file + st.st_size;

    err = find_prefix_in_section(start, end, PREFIX_ID,
                                 qi->q.device, sizeof(qi->q.device));
    if (err != 0)
        goto error;

    err = find_prefix_in_section(start, end, PREFIX_NOTAFTER,
                                 tmp, sizeof(tmp));
    if (err != 0) {
        long long usec;

        errno = 0;
        usec = strtoll(tmp, NULL, 10);
        if (errno != 0)
            goto error;

        qi->time.tv_sec = usec / 1000000;
        qi->time.tv_nsec = usec % 1000000 * 1000;
    }

    err = find_prefix_in_section(start, end, PREFIX_SOCKET,
                                 qi->sock.sun_path, sizeof(qi->sock.sun_path));
    if (err != 0)
        goto error;

    munmap(file, st.st_size);
    close(fd);
    return &qi->q;

error:
    if (file)
        munmap(file, st.st_size);

    close(fd);
    free(qi);
    return NULL;
}

void
question_free(question_t *q)
{
    if (q)
        list_pop(&q->list);

    free(unwrap(q));
}

bool
question_named(const question_t *q, const char *name)
{
    const questioni_t *qi = unwrap(q);
    return strcmp(name, qi->name) == 0;
}

bool
question_expired(const question_t *q)
{
    questioni_t *qi = unwrap(q);
    struct timespec now;

    if (!qi)
        return true;

    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return true;

    if (qi->time.tv_sec == 0 && qi->time.tv_nsec == 0)
        return false;

    if (qi->time.tv_sec < now.tv_sec)
        return true;

    if (qi->time.tv_sec == now.tv_sec &&
        qi->time.tv_nsec < now.tv_nsec)
        return true;

    return false;
}

void
question_answer(const question_t *q, const sbuf_t *key)
{
    questioni_t *qi = unwrap(q);
    sbuf_t *hex = NULL;
    int s = -1;

    if (!qi || !key || question_expired(q))
        return;

    hex = sbuf_to_hex(key, "+");
    if (!hex)
        return;

    s = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (s >= 0)
        (void) sendto(s, hex->data, hex->size, 0, &qi->sock, sizeof(qi->sock));

    sbuf_free(hex);
    close(s);
}

