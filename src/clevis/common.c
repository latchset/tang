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

#include "common.h"
#include "../conv.h"
#include "../pkt.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <poll.h>
#include <string.h>
#include <unistd.h>

EC_KEY *
tkey2eckey(const TANG_KEY *tkey, BN_CTX *ctx)
{
    EC_KEY *eckey = NULL;
    EC_POINT *p = NULL;
    int nid;

    nid = OBJ_obj2nid(tkey->grp);
    if (nid == NID_undef)
        goto error;

    eckey = EC_KEY_new_by_curve_name(nid);
    if (!eckey)
        goto error;

    p = EC_POINT_new(EC_KEY_get0_group(eckey));
    if (!p)
        goto error;

    if (conv_os2point(EC_KEY_get0_group(eckey), tkey->key, p, ctx) != 0)
        goto error;

    if (EC_KEY_set_public_key(eckey, p) <= 0)
        goto error;

    EC_POINT_free(p);
    return eckey;

error:
    EC_POINT_free(p);
    EC_KEY_free(eckey);
    return NULL;
}

clevis_buf_t *
point2key(const EC_GROUP *grp, const EC_POINT *pnt, BN_CTX *ctx)
{
    clevis_buf_t *key = NULL;
    size_t s;

    s = EC_POINT_point2oct(grp, pnt, POINT_CONVERSION_COMPRESSED,
                           NULL, 0, ctx);
    if (s == 0)
        return NULL;

    key = clevis_buf_make(s, NULL);
    if (!key)
        return NULL;

    s = EC_POINT_point2oct(grp, pnt, POINT_CONVERSION_COMPRESSED,
                           key->buf, key->len, ctx);
    if (s != key->len) {
        clevis_buf_free(key);
        return NULL;
    }

    return key;

}

EC_KEY *
random_key(int nid)
{
    EC_KEY *eckey = NULL;

    eckey = EC_KEY_new_by_curve_name(nid);
    if (!eckey)
        return NULL;

    if (EC_KEY_generate_key(eckey) <= 0) {
        EC_KEY_free(eckey);
        return NULL;
    }

    return eckey;
}

TANG_MSG *
request(const json_t *cfg, TANG_MSG *req)
{
    const struct addrinfo hint = { .ai_socktype = SOCK_DGRAM };
    struct addrinfo *res = NULL;
    const json_t *tmp = NULL;
    const char *host = NULL;
    char port[6] = {};
    size_t naddr = 0;
    pkt_t out = {};
    int r = 0;

    if (json_boolean_value(json_object_get(cfg, "listen")))
        return NULL; // TODO

    if (pkt_encode(req, &out) != 0)
        return NULL;

    tmp = json_object_get(cfg, "host");
    if (!json_is_string(tmp))
        return NULL;
    host = json_string_value(tmp);

    tmp = json_object_get(cfg, "port");
    if (!json_is_integer(tmp)
        || json_integer_value(tmp) <= 0
        || json_integer_value(tmp) > UINT16_MAX)
        return NULL;
    snprintf(port, sizeof(port), "%u", json_integer_value(tmp));

    while ((r = getaddrinfo(host, port, &hint, &res)) != 0) {
        if (r != EAI_AGAIN)
            return NULL;
    }

    for (struct addrinfo *ai = res; ai; ai = ai->ai_next)
        naddr++;

    struct pollfd ifds[naddr];

    naddr = 0;
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        ifds[naddr].events = POLLIN | POLLPRI;
        ifds[naddr].fd = socket(ai->ai_family,
                                ai->ai_socktype,
                                ai->ai_protocol);
        if (ifds[naddr].fd < 0)
            continue;

        if (connect(ifds[naddr].fd, ai->ai_addr, ai->ai_addrlen) != 0)
            continue;

        naddr++;
        for (int i = 0; i < 3; i++) {
            struct pollfd ofds[naddr];

            send(ifds[naddr - 1].fd, out.data, out.size, 0);

            memcpy(ofds, ifds, sizeof(struct pollfd) * naddr);
            r = poll(ofds, naddr, 1000);
            for (int j = 0; j < r; j++) {
                TANG_MSG *rep = NULL;
                pkt_t in = {};

                if (ofds[j].revents & (POLLIN | POLLPRI) == 0)
                    continue;

                in.size = recv(ofds[j].fd, &in.data, sizeof(in.data), 0);
                if (in.size <= 0)
                    continue;

                rep = d2i_TANG_MSG(NULL, &(const uint8_t *) { in.data },
                                   in.size);
                if (rep) {
                    for (int k = 0; k < naddr; k++)
                        close(ifds[k].fd);
                    freeaddrinfo(res);
                    return rep;
                }
            }
        }
    }

    for (int j = 0; j < naddr; j++)
        close(ifds[j].fd);

    freeaddrinfo(res);
    return NULL;
}

clevis_pin_f CLEVIS_PIN = {
  .provision = provision,
  .acquire = acquire
};
