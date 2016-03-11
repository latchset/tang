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

typedef struct {
    char     magic[8];
    uint64_t length;
    uint8_t  digest[SHA256_DIGEST_LENGTH];
} meta_t;

static const meta_t DEFAULT = { { 'T', 'A', 'N', 'G', 'S', 'L', 'O', 'T' }, };

static uint8_t *
slot_read(int fd, uint32_t slen, size_t *size)
{
    uint8_t digest[SHA256_DIGEST_LENGTH] = {};
    uint8_t *buf = NULL;
    meta_t meta = {};

    if (slen < sizeof(meta))
        return NULL;

    if (read(fd, &meta, sizeof(meta)) != sizeof(meta))
        return NULL;

    if (memcmp(meta.magic, DEFAULT.magic, sizeof(meta.magic)) != 0)
        return NULL;

    *size = be64toh(meta.length);
    if (slen < sizeof(meta) + *size)
        return NULL;

    buf = malloc(*size);
    if (!buf)
        return NULL;

    if (read(fd, buf, *size) == (ssize_t) *size) {
        if (SHA256(buf, *size, digest)) {
            if (memcmp(meta.digest, digest, sizeof(digest)) == 0)
                return buf;
        }
    }

    free(buf);
    return NULL;
}

uint8_t *
meta_read(const char *device, uint8_t slot, size_t *size)
{
    uint8_t *output = NULL;
    uint32_t length = 0;
    uint32_t slen = 0;
    int fd = -1;

    if (slot >= LUKS_NUMKEYS)
        return false;

    fd = luks_hole(device, false, &length);
    if (fd < 0)
        return false;

    slen = length / LUKS_NUMKEYS / LUKS_ALIGN_KEYSLOTS * LUKS_ALIGN_KEYSLOTS;
    if (slot == 0 || lseek(fd, slot * slen, SEEK_CUR) != (off_t) -1)
        output = slot_read(fd, slen, size);

    close(fd);
    return output;
}

bool
meta_write(const char *device, uint8_t slot, const uint8_t *buf, size_t size)
{
    meta_t meta = DEFAULT;
    bool success = false;
    uint32_t length = 0;
    uint8_t *tmp = NULL;
    uint32_t slen = 0;
    off_t offset = 0;
    int fd = -1;

    if (slot >= LUKS_NUMKEYS || size > UINT64_MAX)
        return false;

    meta.length = htobe64(size);
    if (!SHA256(buf, size, meta.digest))
        return false;

    fd = luks_hole(device, true, &length);
    if (fd < 0)
        return false;

    slen = length / LUKS_NUMKEYS / LUKS_ALIGN_KEYSLOTS * LUKS_ALIGN_KEYSLOTS;
    if (sizeof(meta_t) + size > slen)
        goto error;

    offset = lseek(fd, slot * slen, SEEK_CUR);
    if (offset == -1)
        goto error;

    if (write(fd, &meta, sizeof(meta)) != sizeof(meta))
        goto error;

    if (write(fd, buf, size) != (ssize_t) size)
        goto error;

    if (lseek(fd, offset, SEEK_SET) != offset)
        goto error;

    tmp = slot_read(fd, slen, &size);

    success = tmp != NULL;

error:
    free(tmp);
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

    fd = luks_hole(device, true, &length);
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
