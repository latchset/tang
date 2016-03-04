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

#include "db.h"

#include <openssl/pem.h>

#include <sys/inotify.h>
#include <sys/types.h>
#include <sys/xattr.h>

#include <dirent.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#define MIN(a, b) \
    ({ typeof(a) __a = a; typeof(a) __b = b; __a > __b ? __b : __a; })

static void
db_key_free(db_key_t *key)
{
    if (!key)
        return;

    EC_KEY_free(key->key);
    free(key);
}

static int
load_attrs(db_t *db, db_key_t *key)
{
    char path[PATH_MAX+1];
    char attr[NAME_MAX];
    int r;

    r = snprintf(path, sizeof(path), "%s/%s", db->path, key->name);
    if (r >= (typeof(r)) sizeof(path)) return E2BIG;
    if (r < 0) return errno;

    key->adv = false;
    r = getxattr(path, "user.tang.adv", attr, sizeof(attr));
    if (r >= 0)
        key->adv = true;

    key->use = TANG_KEY_USE_NONE;
    r = getxattr(path, "user.tang.use", attr, sizeof(attr));
    if (r >= 0) {
        if (strncmp(attr, "rec", MIN(r, 3)) == 0)
            key->use = TANG_KEY_USE_REC;
        else if (strncmp(attr, "sig", MIN(r, 3)) == 0)
            key->use = TANG_KEY_USE_SIG;
    }

    return 0;
}

static int
load(db_t *db, const char *name)
{
    char path[PATH_MAX+1];
    EC_GROUP *grp = NULL;
    db_key_t *key = NULL;
    FILE *file = NULL;
    ssize_t r;

    r = snprintf(path, sizeof(path), "%s/%s", db->path, name);
    if (r >= (typeof(r)) sizeof(path)) return E2BIG;
    if (r < 0) return errno;

    key = calloc(1, sizeof(*key));
    if (!key)
        return errno;

    if (strlen(name) >= sizeof(key->name)) {
        db_key_free(key);
        return E2BIG;
    }
    strncpy(key->name, name, sizeof(key->name));

    file = fopen(path, "r");
    if (!file) {
        db_key_free(key);
        return errno;
    }

    grp = PEM_read_ECPKParameters(file, NULL, NULL, NULL);
    if (!grp || EC_GROUP_get_curve_name(grp) == NID_undef) {
        EC_GROUP_free(grp);
        db_key_free(key);
        fclose(file);
        return EINVAL;
    }

    key->key = PEM_read_ECPrivateKey(file, NULL, NULL, NULL);
    fclose(file);
    if (!key->key) {
        EC_GROUP_free(grp);
        db_key_free(key);
        return EINVAL;
    }

    if (EC_KEY_set_group(key->key, grp) <= 0) {
        EC_GROUP_free(grp);
        db_key_free(key);
        return EINVAL;
    }
    EC_GROUP_free(grp);

    r = load_attrs(db, key);
    if (r != 0) {
        db_key_free(key);
        return r;
    }

    list_add_after(&db->keys, &key->list);
    return 0;
}

int
db_open(const char *dbdir, db_t **db)
{
    db_t *tmp = NULL;
    DIR *dir = NULL;
    int r;

    tmp = calloc(1, sizeof(*tmp));
    if (tmp == NULL)
        return errno;

    tmp->keys = LIST_INIT(tmp->keys);

    if (strlen(dbdir) >= sizeof(tmp->path)) {
        db_free(tmp);
        return E2BIG;
    }
    strcpy(tmp->path, dbdir);

    tmp->fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (tmp->fd < 0) {
        db_free(tmp);
        return errno;
    }

    r = inotify_add_watch(tmp->fd, tmp->path,
                          IN_DELETE | IN_MOVE | IN_CLOSE_WRITE | IN_ATTRIB);
    if (r < 0) {
        db_free(tmp);
        return errno;
    }

    dir = opendir(tmp->path);
    if (!dir) {
        db_free(tmp);
        return errno;
    }

    for (struct dirent *de = readdir(dir); de; de = readdir(dir)) {
        if (de->d_name[0] == '.')
            continue;

        r = load(tmp, de->d_name);
        if (r != 0) {
            closedir(dir);
            db_free(tmp);
            return r;
        }
    }

    *db = tmp;
    closedir(dir);
    return 0;
}

void
db_free(db_t *db)
{
    if (!db)
        return;

    LIST_FOREACH(&db->keys, db_key_t, k, list) {
        list_pop(&k->list);
        db_key_free(k);
    }

    close(db->fd);
    free(db);
}

int
db_event(db_t *db)
{
    unsigned char buf[(sizeof(struct inotify_event) + NAME_MAX + 1) * 20] = {};
    const struct inotify_event *ev;
    ssize_t bytes = 0;
    int r;

    bytes = read(db->fd, buf, sizeof(buf));
    if (bytes < 0)
        return errno == EAGAIN ? 0 : errno;

    for (ssize_t i = 0; i < bytes; i += sizeof(*ev) + ev->len) {
        ev = (struct inotify_event *) &buf[i];

        if (ev->len == 0 || ev->name[0] == '.')
            continue;

        LIST_FOREACH(&db->keys, db_key_t, k, list) {
            if (strcmp(ev->name, k->name) == 0) {
                if (ev->mask == IN_ATTRIB) {
                    r = load_attrs(db, k);
                    if (r != 0)
                        return r;
                } else {
                    list_pop(&k->list);
                    db_key_free(k);
                }
            }
        }

        if (ev->mask & (IN_MOVED_TO | IN_CLOSE_WRITE)) {
            r = load(db, ev->name);
            if (r != 0)
                return r;
        }
    }

    return 0;
}

