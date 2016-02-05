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

#include "srv.h"
#include "adv.h"
#include "rec.h"

#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>

#include <openssl/evp.h>

#define NEVTS 5

int
srv_main(const char *dbdir, int epoll, srv_req *req, srv_rep *rep,
         void *misc, int timeout)
{
    struct epoll_event evts[NEVTS] = {};
    BN_CTX *ctx = NULL;
    adv_t *adv = NULL;
    db_t *db = NULL;
    int r;

    OpenSSL_add_all_algorithms();

    ctx = BN_CTX_new();
    if (!ctx)
        return ENOMEM;

    /* Open database. */
    r = db_open(dbdir, &db);
    if (r != 0)
        goto egress;

    r = epoll_ctl(epoll, EPOLL_CTL_ADD, db->fd, &(struct epoll_event) {
        .events = EPOLLIN | EPOLLRDHUP | EPOLLPRI,
        .data.fd = db->fd
    });
    if (r != 0) {
        r = errno;
        goto egress;
    }

    /* Create ADV state. */
    r = adv_init(&adv);
    if (r != 0)
        goto egress;

    r = adv_update(adv, db, ctx);
    if (r != 0)
        goto egress;

    /* Main loop. */
    for (int nevts; (nevts = epoll_wait(epoll, evts, NEVTS, timeout)) > 0; ) {
        for (int i = 0; i < nevts; i++) {
            TANG_MSG_ERR err = TANG_MSG_ERR_NONE;
            TANG_MSG *msg = NULL;
            pkt_t pkt = {};

            if (evts[i].data.fd == db->fd) {
                r = db_event(db);
                if (r == 0)
                    r = adv_update(adv, db, ctx);
                if (r != 0)
                    fprintf(stderr, "Error updating advertisement!\n");
                continue;
            }

            r = req(evts[i].data.fd, &msg, misc);
            if (r != 0 || !msg) {
                if (r == EAGAIN)
                    continue;

                return r;
            }

            switch (msg->type) {
            case TANG_MSG_TYPE_ADV_REQ:
                err = adv_sign(adv, msg->val.adv.req, &pkt);
                break;

            case TANG_MSG_TYPE_REC_REQ:
                err = rec_decrypt(db, msg->val.rec.req, &pkt, ctx);
                break;

            default:
                err = TANG_MSG_ERR_INVALID_REQUEST;
                break;
            }

            TANG_MSG_free(msg);

            if (err != TANG_MSG_ERR_NONE) {
                r = pkt_encode(&(TANG_MSG) {
                    .type = TANG_MSG_TYPE_ERR,
                    .val.err = &(ASN1_ENUMERATED) {
                        .data = &(unsigned char) { err },
                        .type = V_ASN1_ENUMERATED,
                        .length = 1,
                    }
                }, &pkt);
                if (r != 0)
                    pkt.size = 0;
            }

            if (pkt.size > 0) {
                r = rep(evts[i].data.fd, &pkt, misc);
                if (r != 0)
                    goto egress;
            }
        }
    }

egress:
    BN_CTX_free(ctx);
    adv_free(adv);
    db_free(db);

    EVP_cleanup();
    return r;
}
