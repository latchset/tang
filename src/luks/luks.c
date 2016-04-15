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

/**
 * The sole purpose of this file is to encapsulate all code related
 * to parsing the LUKS v1 header. It is used to calculate the hole
 * in the LUKS v1 header that arises due to alignment. We will
 * exploit this hole for metadata storage.
 */

#include "luks.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <endian.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#define LUKS_CIPHERNAME_L 32
#define LUKS_CIPHERMODE_L 32
#define LUKS_HASHSPEC_L 32
#define LUKS_DIGESTSIZE 20
#define LUKS_STRIPES 4000
#define LUKS_SALTSIZE 32
#define UUID_STRING_L 40
#define SECTOR_SIZE 512
#define LUKS_MAGIC_L 6

#define LUKS_KEY_ENABLED  0x00AC71F3

typedef struct {
    uint32_t active;
    uint32_t passwordIterations;
    char     passwordSalt[LUKS_SALTSIZE];
    uint32_t keyMaterialOffset;
    uint32_t stripes;
} luks_kb_t;

typedef struct {
    char      magic[LUKS_MAGIC_L];
    uint16_t  version;
    char      cipherName[LUKS_CIPHERNAME_L];
    char      cipherMode[LUKS_CIPHERMODE_L];
    char      hashSpec[LUKS_HASHSPEC_L];
    uint32_t  payloadOffset;
    uint32_t  keyBytes;
    char      mkDigest[LUKS_DIGESTSIZE];
    char      mkDigestSalt[LUKS_SALTSIZE];
    uint32_t  mkDigestIterations;
    char      uuid[UUID_STRING_L];
    luks_kb_t keyblock[LUKS_NUMKEYS];
    char      _padding[432];
} luks_hdr_t;

typedef enum { up, down } direction_t;

static const char LUKS_MAGIC[] = { 'L', 'U', 'K', 'S', 0xba, 0xbe };

static inline uint32_t
align(uint32_t val, direction_t dir)
{
    if (dir == up)
        val += LUKS_ALIGN_KEYSLOTS - 1;
    return val / LUKS_ALIGN_KEYSLOTS * LUKS_ALIGN_KEYSLOTS;
}

static inline uint32_t
hole_start(const luks_hdr_t *hdr)
{
    uint32_t out = 0;

    for (size_t i = 0; i < LUKS_NUMKEYS; i++) {
        const luks_kb_t *lkb = &hdr->keyblock[i];
        uint32_t len = hdr->keyBytes * lkb->stripes;
        uint32_t off = lkb->keyMaterialOffset * SECTOR_SIZE;
        if (off + len > out)
            out = off + len;
    }

    return align(out, up);
}

static inline uint32_t
hole_end(const luks_hdr_t *hdr)
{
    return align(hdr->payloadOffset * SECTOR_SIZE, down);
}

int
luks_hole(const char *device, int slot, bool write, uint32_t *length)
{
    luks_hdr_t hdr = {};
    uint32_t offset = 0;
    int fd = -1;

    if (slot >= LUKS_NUMKEYS)
        return -EBADSLT;

    fd = open(device, write ? O_RDWR : O_RDONLY);
    if (fd < 0)
        return -errno;

    for (ssize_t r = 0, total = 0; total < (ssize_t) sizeof(hdr); ) {
        r = read(fd, ((uint8_t *) &hdr) + total, sizeof(hdr) - total);
        if (r < 0) {
            close(fd);
            return -errno;
        } else if (r == 0) {
            close(fd);
            return -ENODATA;
        }
        total += r;
    }

    if (memcmp(hdr.magic, LUKS_MAGIC, sizeof(hdr.magic)) != 0) {
        close(fd);
        return -EINVAL;
    }

    hdr.version = be16toh(hdr.version);
    hdr.payloadOffset = be32toh(hdr.payloadOffset);
    hdr.keyBytes = be32toh(hdr.keyBytes);
    hdr.mkDigestIterations = be32toh(hdr.mkDigestIterations);

    if (hdr.version != 1) {
        close(fd);
        return -EINVAL;
    }

    for (size_t i = 0; i < LUKS_NUMKEYS; i++) {
        luks_kb_t *kb = &hdr.keyblock[i];
        kb->active = be32toh(kb->active);
        kb->passwordIterations = be32toh(kb->passwordIterations);
        kb->keyMaterialOffset = be32toh(kb->keyMaterialOffset);
        kb->stripes = be32toh(kb->stripes);

        if (kb->keyMaterialOffset > hdr.payloadOffset) {
            close(fd);
            return -EINVAL;
        }
    }

    if (hdr.keyblock[slot].active != LUKS_KEY_ENABLED) {
        close(fd);
        return -EBADSLT;
    }

    offset = hole_start(&hdr);
    if (offset >= hole_end(&hdr)) {
        close(fd);
        return -EINVAL;
    }

    if (lseek(fd, offset, SEEK_SET) == -1) {
        close(fd);
        return -errno;
    }
        goto error;

    *length = hole_end(&hdr) - offset;
    return fd;

error:
    close(fd);
    return -1;
}

