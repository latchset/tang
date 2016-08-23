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

#include <errno.h>
#include <string.h>

static ssize_t
adv(const char *path, regmatch_t matches[],
    const char *body, enum http_method method,
    char pkt[], size_t pktl)
{
    const json_t *jws = NULL;
    char *adv = NULL;
    char *thp = NULL;
    int r = 0;

    if (matches[1].rm_so < matches[1].rm_eo) {
        size_t size = matches[1].rm_eo - matches[1].rm_so;
        thp = strndup(&path[matches[1].rm_so], size);
        if (!thp)
            return -ENOMEM;
    }

    jws = tang_io_get_adv(thp);
    free(thp);
    if (!jws)
        return snprintf(pkt, pktl, ERR_TMPL, 404, "Not Found");

    adv = json_dumps(jws, JSON_SORT_KEYS | JSON_COMPACT);
    if (!adv)
        return snprintf(pkt, pktl, ERR_TMPL, 500, "Internal Server Error");

    r = snprintf(pkt, pktl,
                 "HTTP/1.1 200 OK\r\n"
                 "Content-Type: application/jose+json\r\n"
                 "Content-Length: %zu\r\n"
                 "Connection: close\r\n"
                 "\r\n%s", strlen(adv), adv);
    free(adv);
    return r;
}

static void __attribute__((constructor))
constructor(void)
{
    static struct tang_plugin_map maps[] = {
        { adv, 1 << HTTP_GET, 2, "^/+adv/+([0-9A-Za-z_-]+)$" },
        { adv, 1 << HTTP_GET, 2, "^/+adv/*$" },
    };

    maps[1].next = tang_plugin_maps;
    maps[0].next = &maps[1];
    tang_plugin_maps = &maps[0];
}
