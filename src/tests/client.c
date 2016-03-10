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

#include "../core/asn1.h"
#include "../core/conv.h"
#include "../core/pkt.h"

#include <sys/types.h>
#include <sys/socket.h>

#include <errno.h>
#include <error.h>
#include <limits.h>
#include <unistd.h>

#include <openssl/pem.h>

static void
test(bool cond, const char *str, const char *f0, int l0, const char *f1, int l1)
{
    if (cond)
      return;

    error(EXIT_FAILURE, 0, "FAILURE: %s:%d:%s:%d:\n%s", f0, l0, f1, l1, str);
}

#define _str(x) # x
#define test(x) test((x), _str(x), __FILE__, __LINE__, file, line)

static TANG_MSG *
request(int sock, const TANG_MSG *req, const char *file, int line)
{
    TANG_MSG *msg = NULL;
    pkt_t pkt = {};
    int r = 0;

    test((r = pkt_encode(req, &pkt)) == 0);
    test((r = send(sock, pkt.data, pkt.size, 0)) == pkt.size);
    test((pkt.size = recv(sock, pkt.data, sizeof(pkt.data), 0)) > 0);
    test(msg = d2i_TANG_MSG(NULL, &(const unsigned char *) { pkt.data }, pkt.size));
    return msg;
}

static EC_KEY *
keygen(const char *dbdir, const char *name,
       const char *grpname, const char *use, bool adv,
       const char *file, int line)
{
    char fname[PATH_MAX];
    char cmd[PATH_MAX*2];
    EC_GROUP *grp = NULL;
    EC_KEY *key = NULL;
    FILE *f = NULL;

    test(snprintf(fname, sizeof(fname), "%s/%s", dbdir, name) > 0);
    test(snprintf(cmd, sizeof(cmd),
                  "../tang-key-gen -%c %s %s -f %s >/dev/null",
                  adv ? 'A' : 'a', grpname, use, fname) > 1);

    test(system(cmd) == 0);
    test(f = fopen(fname, "r"));

    test(grp = PEM_read_ECPKParameters(f, NULL, NULL, NULL));
    test(EC_GROUP_get_curve_name(grp) != NID_undef);

    test(key = PEM_read_ECPrivateKey(f, NULL, NULL, NULL));
    test(EC_KEY_set_group(key, grp) > 0);

    EC_GROUP_free(grp);
    fclose(f);
    return key;
}
#define keygen(d, n, g, u, a) keygen(d, n, g, u, a, __FILE__, __LINE__)

static TANG_MSG *
rec(int sock, EC_KEY *key, const char *file, int line)
{
    TANG_MSG_REC_REQ *req = NULL;
    const EC_GROUP *grp = NULL;
    TANG_MSG *rep = NULL;

    test(grp = EC_KEY_get0_group(key));
    test(req = TANG_MSG_REC_REQ_new());
    test(conv_eckey2tkey(key, TANG_KEY_USE_REC, req->key, NULL) == 0);
    test(conv_point2os(grp, EC_GROUP_get0_generator(grp), req->x, NULL) == 0);
    test(rep = request(sock, &(TANG_MSG) {
        .type = TANG_MSG_TYPE_REC_REQ,
        .val.rec.req = req
    }, file, line));

    TANG_MSG_REC_REQ_free(req);
    return rep;
}
#define rec(s, k) rec(s, k, __FILE__, __LINE__)

static TANG_MSG *
adv(int sock, int type, int grp, EC_KEY *key, TANG_KEY_USE use,
    const char *file, int line)
{
    TANG_MSG_ADV_REQ *req = NULL;
    TANG_MSG *rep = NULL;

    test(!(grp != NID_undef && key));
    test(req = TANG_MSG_ADV_REQ_new());

    if (type != NID_undef)
        test(sk_ASN1_OBJECT_push(req->types, OBJ_nid2obj(type)) > 0);

    if (key) {
        TANG_KEY *tkey = TANG_KEY_new();
        test(conv_eckey2tkey(key, use, tkey, NULL) == 0);
        req->body->type = TANG_MSG_ADV_REQ_BDY_TYPE_KEYS;
        test(req->body->val.keys = SKM_sk_new_null(TANG_KEY));
        test(SKM_sk_push(TANG_KEY, req->body->val.keys, tkey) > 0);
    } else {
        req->body->type = TANG_MSG_ADV_REQ_BDY_TYPE_GRPS;
        test(req->body->val.grps = sk_ASN1_OBJECT_new_null());
        if (grp != NID_undef)
            test(sk_ASN1_OBJECT_push(req->body->val.grps, OBJ_nid2obj(grp)) > 0);
    }

    test(rep = request(sock, &(TANG_MSG) {
        .type = TANG_MSG_TYPE_ADV_REQ,
        .val.adv.req = req
    }, file, line));

    TANG_MSG_ADV_REQ_free(req);
    return rep;
}
#define adv(s, t, g, k, u) adv(s, t, g, k, u, __FILE__, __LINE__)

static void
err_verify(TANG_MSG *rep, TANG_MSG_ERR err, const char *file, int line)
{
    test(rep->type == TANG_MSG_TYPE_ERR);
    test(rep->val.err->length == 1);
    test(rep->val.err->data[0] == err);
}
#define err_verify(r, e) err_verify(r, e, __FILE__, __LINE__)

static void
rec_verify(TANG_MSG *rep, EC_KEY *key, const char *file, int line)
{
    const EC_GROUP *grp = NULL;
    EC_POINT *p = NULL;

    test(rep->type == TANG_MSG_TYPE_REC_REP);
    test(grp = EC_KEY_get0_group(key));
    test(p = EC_POINT_new(grp));
    test(conv_os2point(grp, rep->val.rec.rep->y, p, NULL) == 0);
    test(EC_POINT_cmp(grp, p, EC_KEY_get0_public_key(key), NULL) == 0);
    EC_POINT_free(p);
}
#define rec_verify(r, k) rec_verify(r, k, __FILE__, __LINE__)

static void
adv_verify(TANG_MSG *rep, EC_KEY *key, int nkeys, int nsigs,
           const char *file, int line)
{
    unsigned char *buf = NULL;
    int len;

    test(rep->type == TANG_MSG_TYPE_ADV_REP);
    test(SKM_sk_num(TANG_KEY, rep->val.adv.rep->body->keys) == nkeys);
    test(SKM_sk_num(TANG_SIG, rep->val.adv.rep->sigs) == nsigs);

    test((len = i2d_TANG_MSG_ADV_REP_BDY(rep->val.adv.rep->body, &buf)) > 0);

    for (int i = 0; i < SKM_sk_num(TANG_SIG, rep->val.adv.rep->sigs); i++) {
        TANG_SIG *sig = SKM_sk_value(TANG_SIG, rep->val.adv.rep->sigs, i);
        unsigned char hash[EVP_MAX_MD_SIZE] = {};
        unsigned int hlen = sizeof(hash);
        ECDSA_SIG *ecdsa = NULL;
        const EVP_MD *md = NULL;
        int r;

        switch (OBJ_obj2nid(sig->type)) {
        case NID_ecdsa_with_SHA224:
            test(md = EVP_get_digestbynid(NID_sha224));
            break;
        case NID_ecdsa_with_SHA256:
            test(md = EVP_get_digestbynid(NID_sha256));
            break;
        case NID_ecdsa_with_SHA384:
            test(md = EVP_get_digestbynid(NID_sha384));
            break;
        case NID_ecdsa_with_SHA512:
            test(md = EVP_get_digestbynid(NID_sha512));
            break;
        default:
            continue;
        }

        test(EVP_Digest(buf, len, hash, &hlen, md, NULL) > 0);
        test(ecdsa = d2i_ECDSA_SIG(NULL, &(const unsigned char *) {
                                       sig->sig->data
                                   }, sig->sig->length));

        r = ECDSA_do_verify(hash, hlen, ecdsa, key);
        ECDSA_SIG_free(ecdsa);
        if (r == 1) {
            OPENSSL_free(buf);
            return;
        }
    }

    test(false);
}
#define adv_verify(r, k, nk, ns) adv_verify(r, k, nk, ns, __FILE__, __LINE__)

static double
gettime(void)
{
    struct timespec ts;
    double t;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    t = ts.tv_nsec;
    t /= 1000000000;
    t += ts.tv_sec;
    return t;
}

static void
rec_benchmark(int sock, EC_KEY *key, int iter, const char *file, int line)
{
    TANG_MSG req = { .type = TANG_MSG_TYPE_REC_REQ };
    const EC_GROUP *grp = NULL;
    pkt_t out = {};
    pkt_t in = {};
    double t;

    test(grp = EC_KEY_get0_group(key));
    test(req.val.rec.req = TANG_MSG_REC_REQ_new());
    test(conv_eckey2tkey(key, TANG_KEY_USE_REC, req.val.rec.req->key, NULL) == 0);
    test(conv_point2os(grp, EC_GROUP_get0_generator(grp), req.val.rec.req->x, NULL) == 0);
    test(pkt_encode(&req, &out) == 0);
    TANG_MSG_REC_REQ_free(req.val.rec.req);

    t = gettime();
    for (int i = 0; i < iter; i++) {
        test(send(sock, out.data, out.size, 0) == out.size);
        test(recv(sock, in.data, sizeof(in.data), 0) > 0);
    }
    t = gettime() - t;

    fprintf(stderr, "REC (%d): %f (%d/sec)\n", iter, t, (int) (iter / t));
}

static void
adv_benchmark(int sock, int iter, const char *file, int line)
{
    TANG_MSG req = { .type = TANG_MSG_TYPE_ADV_REQ };
    pkt_t out = {};
    pkt_t in = {};
    double t;

    test(req.val.adv.req = TANG_MSG_ADV_REQ_new());
    test(req.val.adv.req->body->val.grps = sk_ASN1_OBJECT_new_null());
    req.val.adv.req->body->type = TANG_MSG_ADV_REQ_BDY_TYPE_GRPS;
    test(pkt_encode(&req, &out) == 0);
    TANG_MSG_ADV_REQ_free(req.val.adv.req);

    t = gettime();
    for (int i = 0; i < iter; i++) {
        test(send(sock, out.data, out.size, 0) == out.size);
        test(recv(sock, in.data, sizeof(in.data), 0) > 0);
    }
    t = gettime() - t;

    fprintf(stderr, "ADV (%d): %f (%d/sec)\n", iter, t, (int) (iter / t));
}

void
client_checks(int sock, const char *dbdir);

void
client_checks(int sock, const char *dbdir)
{
    TANG_MSG *rep = NULL;
    EC_KEY *reca = NULL;
    EC_KEY *recA = NULL;
    EC_KEY *recB = NULL;
    EC_KEY *siga = NULL;
    EC_KEY *sigA = NULL;
    EC_KEY *sigB = NULL;

    /* Make sure we get TANG_MSG_ERR_NOTFOUND_KEY when no keys exist. */
    rep = adv(sock, NID_undef, NID_undef, NULL, TANG_KEY_USE_NONE);
    err_verify(rep, TANG_MSG_ERR_NOTFOUND_KEY);
    TANG_MSG_free(rep);

    /* Make some keys. */
    reca = keygen(dbdir, "reca", "secp384r1", "rec", false);
    siga = keygen(dbdir, "siga", "secp384r1", "sig", false);
    if (!reca || !siga)
        error(EXIT_FAILURE, errno, "Error generating keys");
    usleep(100000); /* Let the daemon have time to pick up the new files. */

    /* Make sure the unadvertised keys aren't advertised. */
    rep = adv(sock, NID_undef, NID_undef, NULL, TANG_KEY_USE_NONE);
    err_verify(rep, TANG_MSG_ERR_NOTFOUND_KEY);
    TANG_MSG_free(rep);

    /* Make sure the server won't sign with recovery keys. */
    rep = adv(sock, NID_undef, NID_undef, reca, TANG_KEY_USE_REC);
    err_verify(rep, TANG_MSG_ERR_NOTFOUND_KEY);
    TANG_MSG_free(rep);

    /* Make sure changing the key use won't expose it. */
    rep = adv(sock, NID_undef, NID_undef, reca, TANG_KEY_USE_SIG);
    err_verify(rep, TANG_MSG_ERR_NOTFOUND_KEY);
    TANG_MSG_free(rep);

    /* Request signature with a valid, but unadvertised key. */
    rep = adv(sock, NID_undef, NID_undef, siga, TANG_KEY_USE_SIG);
    adv_verify(rep, siga, 0, 4);
    TANG_MSG_free(rep);

    /* Test recovery of an unadvertised key. */
    rep = rec(sock, reca);
    rec_verify(rep, reca);
    TANG_MSG_free(rep);

    /* Test recovery using an unadvertised signature key. */
    rep = rec(sock, siga);
    err_verify(rep, TANG_MSG_ERR_NOTFOUND_KEY);
    TANG_MSG_free(rep);

    /* Make some advertised keys. */
    recA = keygen(dbdir, "recA", "secp384r1", "rec", true);
    sigA = keygen(dbdir, "sigA", "secp384r1", "sig", true);
    if (!recA || !sigA)
        error(EXIT_FAILURE, errno, "Error generating keys");
    usleep(100000); /* Let the daemon have time to pick up the new files. */

    /* Request signature with a valid, but unadvertised key. */
    rep = adv(sock, NID_undef, NID_undef, siga, TANG_KEY_USE_SIG);
    adv_verify(rep, siga, 2, 4);
    TANG_MSG_free(rep);

    /* Request signature with a valid, advertised key. */
    rep = adv(sock, NID_undef, NID_undef, sigA, TANG_KEY_USE_SIG);
    adv_verify(rep, sigA, 2, 4);
    TANG_MSG_free(rep);

    /* Don't request a key. Make sure it uses the advertised key. */
    rep = adv(sock, NID_undef, NID_undef, NULL, TANG_KEY_USE_SIG);
    adv_verify(rep, sigA, 2, 4);
    TANG_MSG_free(rep);

    /* Test for a limit on the signing method. */
    rep = adv(sock, NID_ecdsa_with_SHA224, NID_undef, NULL, TANG_KEY_USE_SIG);
    adv_verify(rep, sigA, 2, 1);
    TANG_MSG_free(rep);

    /* Test for a limit on the signing method with a specified key. */
    rep = adv(sock, NID_ecdsa_with_SHA224, NID_undef, siga, TANG_KEY_USE_SIG);
    adv_verify(rep, siga, 2, 1);
    TANG_MSG_free(rep);

    /* Test recovery of an advertised key. */
    rep = rec(sock, recA);
    rec_verify(rep, recA);
    TANG_MSG_free(rep);

    /* Test recovery using an advertised signature key. */
    rep = rec(sock, sigA);
    err_verify(rep, TANG_MSG_ERR_NOTFOUND_KEY);
    TANG_MSG_free(rep);

    /* Make some advertised keys. */
    recB = keygen(dbdir, "recB", "secp521r1", "rec", true);
    sigB = keygen(dbdir, "sigB", "secp521r1", "sig", true);
    if (!recB || !sigB)
        error(EXIT_FAILURE, errno, "Error generating keys");
    usleep(100000); /* Let the daemon have time to pick up the new files. */

    /* Ensure that both keys are used to sign in the default case. */
    rep = adv(sock, NID_ecdsa_with_SHA224, NID_undef, NULL, TANG_KEY_USE_SIG);
    adv_verify(rep, sigA, 4, 2);
    adv_verify(rep, sigB, 4, 2);
    TANG_MSG_free(rep);

    /* Filter by group: secp384r1. */
    rep = adv(sock, NID_ecdsa_with_SHA224, NID_secp384r1, NULL, TANG_KEY_USE_SIG);
    adv_verify(rep, sigA, 4, 1);
    TANG_MSG_free(rep);

    /* Filter by group: secp521r1. */
    rep = adv(sock, NID_ecdsa_with_SHA224, NID_secp521r1, NULL, TANG_KEY_USE_SIG);
    adv_verify(rep, sigB, 4, 1);
    TANG_MSG_free(rep);

    /* Test recovery of an advertised key. */
    rep = rec(sock, recB);
    rec_verify(rep, recB);
    TANG_MSG_free(rep);

    /* Test recovery using an advertised signature key. */
    rep = rec(sock, sigB);
    err_verify(rep, TANG_MSG_ERR_NOTFOUND_KEY);
    TANG_MSG_free(rep);

    /* Benchmark. */
    adv_benchmark(sock, 10000, __FILE__, __LINE__);
    rec_benchmark(sock, sigB, 10000, __FILE__, __LINE__);

    EC_KEY_free(reca);
    EC_KEY_free(recA);
    EC_KEY_free(recB);
    EC_KEY_free(siga);
    EC_KEY_free(sigA);
    EC_KEY_free(sigB);
}
