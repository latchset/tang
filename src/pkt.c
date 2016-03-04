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

#include "pkt.h"

#include <errno.h>

int
pkt_encode(const TANG_MSG *msg, pkt_t *pkt)
{
    pkt_t tmp = {};

    tmp.size = i2d_TANG_MSG((TANG_MSG *) msg, NULL);
    if (tmp.size > (typeof(tmp.size)) sizeof(tmp.data))
        return E2BIG;
    if (tmp.size <= 0)
        return EINVAL;

    tmp.size = i2d_TANG_MSG((TANG_MSG *) msg, &(uint8_t *) { tmp.data });
    if (tmp.size <= 0)
        return EINVAL;

    *pkt = tmp;
    return 0;
}

TANG_MSG *
pkt_decode(const pkt_t *pkt)
{
    return d2i_TANG_MSG(NULL, &(const uint8_t *) { pkt->data }, pkt->size);
}
