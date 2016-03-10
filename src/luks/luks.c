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

#include <endian.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

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
align(uint32_t val, uint32_t alignment, direction_t dir)
{
    if (dir == up)
        val += alignment - 1;
    return val / alignment * alignment;
}

static inline void
ntoh(luks_hdr_t *hdr)
{
    hdr->version = be16toh(hdr->version);
    hdr->payloadOffset = be32toh(hdr->payloadOffset);
    hdr->keyBytes = be32toh(hdr->keyBytes);
    hdr->mkDigestIterations = be32toh(hdr->mkDigestIterations);

    for (size_t i = 0; i < LUKS_NUMKEYS; i++) {
        luks_kb_t *kb = &hdr->keyblock[i];
        kb->active = be32toh(kb->active);
        kb->passwordIterations = be32toh(kb->passwordIterations);
        kb->keyMaterialOffset = be32toh(kb->keyMaterialOffset);
        kb->stripes = be32toh(kb->stripes);
    }
}

static inline uint32_t
slots_end(const luks_hdr_t *hdr)
{
    const luks_kb_t *lkb = &hdr->keyblock[LUKS_NUMKEYS - 1];
    uint32_t out = 0;

    out  = align(hdr->keyBytes * lkb->stripes, LUKS_ALIGN_KEYSLOTS, up);
    out += lkb->keyMaterialOffset * SECTOR_SIZE;

    return out;
}

static inline uint32_t
luks_end(const luks_hdr_t *hdr)
{
    return hdr->payloadOffset * SECTOR_SIZE;
}

static inline bool
process(const luks_hdr_t *hdr, off_t *offset, uint32_t *length)
{
    long page_size = 0;

    page_size = sysconf(_SC_PAGE_SIZE);
    if (page_size < 0)
        return false;

    if (memcmp(hdr->magic, LUKS_MAGIC, sizeof(hdr->magic)) != 0)
        return false;

    if (hdr->version != 1)
        return false;

    *offset = align(slots_end(hdr), page_size, up);
    *length = luks_end(hdr);
    if (*length <= *offset)
        return false;

    *length = align(*length - *offset,  page_size, down);
    if (*length == 0)
        return false;

    return true;
}

int
luks_hole(const char *device, bool write, uint32_t *length)
{
    luks_hdr_t hdr = {};
    off_t offset = 0;
    int fd = -1;

    fd = open(device, write ? O_RDWR : O_RDONLY);
    if (fd < 0)
        return fd;

    if (read(fd, &hdr, sizeof(hdr)) != sizeof(hdr))
        goto error;

    ntoh(&hdr);
    if (!process(&hdr, &offset, length))
        goto error;

    if (lseek(fd, offset, SEEK_SET) != offset)
        goto error;

    return fd;

error:
    close(fd);
    return -1;
}

