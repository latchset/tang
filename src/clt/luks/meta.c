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

#include "meta.h"
#include "luks.h"

#include <stdlib.h>
#include <string.h>
#include <endian.h>

#include <sys/types.h>
#include <unistd.h>

#include <openssl/sha.h>

static const char META_MAGIC[] = { 'T', 'A', 'N', 'G', 'S', 'L', 'O', 'T' };

typedef struct {
    char     magic[sizeof(META_MAGIC)];
    uint64_t length;
    uint8_t  digest[SHA256_DIGEST_LENGTH];
} meta_t;

static sbuf_t *
slot_read(int fd, uint32_t slen)
{
    uint8_t digest[SHA256_DIGEST_LENGTH] = {};
    sbuf_t *buf = NULL;
    uint64_t size = 0;
    meta_t meta = {};

    if (slen < sizeof(meta))
        return NULL;

    if (read(fd, &meta, sizeof(meta)) != sizeof(meta))
        return NULL;

    if (memcmp(meta.magic, META_MAGIC, sizeof(META_MAGIC)) != 0)
        return NULL;

    size = be64toh(meta.length);
    if (slen < sizeof(meta) + size)
        return NULL;

    buf = sbuf_new(size);
    if (!buf)
        return NULL;

    if (read(fd, buf->data, size) == (ssize_t) size) {
        if (SHA256(buf->data, size, digest)) {
            if (memcmp(meta.digest, digest, sizeof(digest)) == 0)
                return buf;
        }
    }

    sbuf_free(buf);
    return NULL;
}

sbuf_t *
meta_read(const char *device, uint8_t slot)
{
    sbuf_t *output = NULL;
    uint32_t length = 0;
    uint32_t slen = 0;
    int fd = -1;

    if (slot >= LUKS_NUMKEYS)
        return false;

    fd = luks_hole(device, slot, false, &length);
    if (fd < 0)
        return false;

    slen = length / LUKS_NUMKEYS / LUKS_ALIGN_KEYSLOTS * LUKS_ALIGN_KEYSLOTS;
    if (slot == 0 || lseek(fd, slot * slen, SEEK_CUR) != (off_t) -1)
        output = slot_read(fd, slen);

    close(fd);
    return output;
}

bool
meta_write(const char *device, uint8_t slot, const sbuf_t *buf)
{
    bool success = false;
    uint32_t length = 0;
    sbuf_t *tmp = NULL;
    uint32_t slen = 0;
    off_t offset = 0;
    meta_t meta = {};
    int fd = -1;

    if (slot >= LUKS_NUMKEYS || !buf)
        return false;

    memcpy(meta.magic, META_MAGIC, sizeof(META_MAGIC));

    meta.length = htobe64(buf->size);
    if (!SHA256(buf->data, buf->size, meta.digest))
        return false;

    fd = luks_hole(device, slot, true, &length);
    if (fd < 0)
        return false;

    slen = length / LUKS_NUMKEYS / LUKS_ALIGN_KEYSLOTS * LUKS_ALIGN_KEYSLOTS;
    if (sizeof(meta_t) + buf->size > slen)
        goto error;

    offset = lseek(fd, slot * slen, SEEK_CUR);
    if (offset == -1)
        goto error;

    if (write(fd, &meta, sizeof(meta)) != sizeof(meta))
        goto error;

    if (write(fd, buf->data, buf->size) != (ssize_t) buf->size)
        goto error;

    if (lseek(fd, offset, SEEK_SET) == -1)
        goto error;

    tmp = slot_read(fd, slen);

    success = tmp != NULL;

error:
    sbuf_free(tmp);
    close(fd);
    return success;
}

bool
meta_erase(const char *device, uint8_t slot)
{
    uint8_t zero[LUKS_ALIGN_KEYSLOTS] = {};
    bool success = false;
    uint32_t length = 0;
    uint32_t slen = 0;
    int fd = -1;

    if (slot >= LUKS_NUMKEYS)
        return false;

    fd = luks_hole(device, slot, true, &length);
    if (fd < 0)
        return false;

    slen = length / LUKS_NUMKEYS / LUKS_ALIGN_KEYSLOTS * LUKS_ALIGN_KEYSLOTS;
    if (slot > 0 && lseek(fd, slot * slen, SEEK_CUR) != 0)
        goto error;

    for (size_t i = 0; i < slen / LUKS_ALIGN_KEYSLOTS; i++) {
        if (write(fd, zero, sizeof(zero)) != sizeof(zero))
            goto error;
    }

    success = true;

error:
    close(fd);
    return success;
}
