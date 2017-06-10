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
 * NOTE WELL: This code is completely insecure for real-world workflows!
 *
 * In particular, it has two glaring security problems:
 *
 *   1. Server keys are implicitly trusted.
 *   2. No ephemeral keys are used to protect the recovery phase.
 *
 * However, the goal of this Nagios plugin is to determine if the server is
 * alive and properly handles well-formed requests. So we don't care about
 * security. If you are looking for an example of how to securely use Tang,
 * check out the Clevis project.
 */

#define _GNU_SOURCE

#include <http_parser.h>
#include <jose/jose.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define conn_auto_t conn_t __attribute__((cleanup(conn_cleanup)))

enum {
    NAGIOS_OK = 0,
    NAGIOS_WARN = 1,
    NAGIOS_CRIT = 2,
    NAGIOS_UNKN = 3
};

typedef struct {
    char data[4096];
    size_t used;
    int sock;
} conn_t;

typedef struct {
    char *data;
    size_t size;
} body_t;

typedef struct {
    char schm[PATH_MAX];
    char host[PATH_MAX];
    char srvc[PATH_MAX];
    char path[PATH_MAX];
} url_t;

static void
conn_cleanup(conn_t **conn)
{
    if (conn && *conn) {
        close((*conn)->sock);
        free(*conn);
    }
}

static conn_t *
conn_open(const char *host, const char *srvc, int family)
{
    const struct addrinfo hint = {
        .ai_socktype = SOCK_STREAM,
        .ai_family = family,
    };

    struct addrinfo *ais = NULL;
    conn_t *conn = NULL;
    int sock = -1;

    sock = getaddrinfo(host, srvc, &hint, &ais);
    switch (sock) {
        case 0: break;
        case EAI_AGAIN:    errno = -EAGAIN;  return NULL;
        case EAI_BADFLAGS: errno = -EINVAL;  return NULL;
        case EAI_FAMILY:   errno = -ENOTSUP; return NULL;
        case EAI_MEMORY:   errno = -ENOMEM;  return NULL;
        case EAI_SERVICE:  errno = -EINVAL;  return NULL;
        default:           errno = -EIO;     return NULL;
    }

    conn = calloc(1, sizeof(*conn));
    if (!conn) {
        freeaddrinfo(ais);
        return NULL;
    }

    for (const struct addrinfo *ai = ais; ai; ai = ai->ai_next) {
        conn->sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (conn->sock < 0)
            continue;

        if (connect(conn->sock, ai->ai_addr, ai->ai_addrlen) != 0) {
            close(conn->sock);
            continue;
        }

        freeaddrinfo(ais);
        return conn;
    }

    freeaddrinfo(ais);
    free(conn);

    errno = -ENOENT;
    return NULL;
}

static int
conn_send(const conn_t *conn, const char *fmt, ...)
{
    va_list ap;
    int r;

    va_start(ap, fmt);
    r = vdprintf(conn->sock, fmt, ap);
    va_end(ap);
    return r;
}

static int
on_body(http_parser *parser, const char *at, size_t length)
{
    body_t *body = parser->data;
    char *tmp = NULL;

    tmp = realloc(body->data, body->size + length + 1);
    if (!tmp)
        return -errno;

    memcpy(&tmp[body->size], at, length);
    body->size += length;
    body->data = tmp;

    body->data[body->size] = 0;
    return 0;
}

static int
on_message_complete(http_parser *parser)
{
    http_parser_pause(parser, true);
    return 0;
}

static int
conn_recv(conn_t *conn, char **body)
{
    static const http_parser_settings settings = {
        .on_body = on_body,
        .on_message_complete = on_message_complete
    };

    body_t data = {};
    http_parser parser = { .data = &data };

    http_parser_init(&parser, HTTP_RESPONSE);

    for (;;) {
        ssize_t rcvd = 0;
        size_t prsd = 0;

        rcvd = recv(conn->sock, &conn->data[conn->used],
                    sizeof(conn->data) - conn->used, 0);
        if (rcvd < 0) {
            free(data.data);
            return -errno;
        } else if (rcvd == 0) {
            free(data.data);
            return -EIO;
        }

        conn->used += rcvd;

        prsd = http_parser_execute(&parser, &settings, conn->data, conn->used);

        conn->used -= prsd;
        memmove(conn->data, &conn->data[prsd], conn->used);

        switch (parser.http_errno) {
        case HPE_OK: /* We need to process more data. */
            break;

        case HPE_PAUSED: /* We got one request. */
            *body = data.data;
            return parser.status_code;

        default: /* An error occurred. */
            free(data.data);
            return -EBADMSG;
        }
    }
}

static double
curtime(void)
{
    struct timespec ts = {};
    double out = 0;

    if (clock_gettime(CLOCK_MONOTONIC_RAW, &ts) == 0) {
        out = ts.tv_nsec;
        out /= 1000000000L;
        out += ts.tv_sec;
    }

    return out;
}

static void
dump_perf(json_t *time)
{
    const char *key = NULL;
    bool first = true;
    json_t *val = 0;

    json_object_foreach(time, key, val) {
        int v = 0;

        if (!first)
            printf(" ");
        else
            first = false;

        if (json_is_integer(val))
            v = json_integer_value(val);
        else if (json_is_real(val))
            v = json_real_value(val) * 1000000;

        printf("%s=%d", key, v);
    }
}

static int
parse_url(const char *url, url_t *parts)
{
    static const uint16_t mask = (1 << UF_SCHEMA) | (1 << UF_HOST);
    struct http_parser_url purl = {};

    if (http_parser_parse_url(url, strlen(url), false, &purl) != 0)
        return -EINVAL;

    if ((purl.field_set & mask) != mask)
        return -EINVAL;

    if (purl.field_data[UF_SCHEMA].len >= sizeof(parts->schm) ||
        purl.field_data[UF_HOST].len >= sizeof(parts->host) ||
        purl.field_data[UF_PORT].len >= sizeof(parts->srvc) ||
        purl.field_data[UF_PATH].len >= sizeof(parts->path))
        return -E2BIG;

    strncpy(parts->schm, &url[purl.field_data[UF_SCHEMA].off],
            purl.field_data[UF_SCHEMA].len);

    strncpy(parts->host, &url[purl.field_data[UF_HOST].off],
            purl.field_data[UF_HOST].len);

    if (purl.field_set & (1 << UF_PORT)) {
        strncpy(parts->srvc, &url[purl.field_data[UF_PORT].off],
                purl.field_data[UF_PORT].len);
    } else {
        strcpy(parts->srvc, parts->schm);
    }

    if (purl.field_set & (1 << UF_PATH)) {
        strncpy(parts->path, &url[purl.field_data[UF_PATH].off],
                purl.field_data[UF_PATH].len);
    }

    return 0;
}

static json_t *
validate(const json_t *jws)
{
    json_auto_t *jwkset = NULL;
    json_t *keys = NULL;
    size_t sigs = 0;

    jwkset = jose_b64_dec_load(json_object_get(jws, "payload"));
    if (!jwkset)
        return NULL;

    keys = json_object_get(jwkset, "keys");
    if (!json_is_array(keys))
        return NULL;

    for (size_t i = 0; i < json_array_size(keys); i++) {
        json_t *key = json_array_get(keys, i);

        if (!jose_jwk_prm(NULL, key, true, "verify"))
            continue;

        if (!jose_jws_ver(NULL, jws, NULL, key, true))
            return NULL;

        sigs++;
    }

    if (sigs == 0)
        return NULL;

    return json_incref(keys);
}

static bool
nagios_recover(conn_t *con, const char *host, const char *path,
               const json_t *jwk, size_t *sig, size_t *rec, json_t *time)
{
    json_auto_t *exc = NULL;
    json_auto_t *rep = NULL;
    json_auto_t *lcl = NULL;
    json_auto_t *kid = NULL;
    char *body = NULL;
    double s = 0;
    double e = 0;
    int r = 0;

    if (jose_jwk_prm(NULL, jwk, true, "verify")) {
        *sig += 1;
        return true;
    }

    if (!jose_jwk_prm(NULL, jwk, true, "deriveKey"))
        return true;

    kid = jose_jwk_thp(NULL, jwk, "S256");
    if (!kid)
        return true;

    lcl = json_pack("{s:O,s:O,s:s,s:[s]}",
                    "kty", json_object_get(jwk, "kty"),
                    "crv", json_object_get(jwk, "crv"),
                    "alg", "ECMR",
                    "key_ops", "deriveKey");
    if (!lcl)
        return false;

    if (!jose_jwk_gen(NULL, lcl))
        return false;

    exc = jose_jwk_exc(NULL, lcl, jwk);
    if (!exc)
        return false;

    if (!jose_jwk_pub(NULL, lcl))
        return false;

    body = json_dumps(lcl, JSON_SORT_KEYS | JSON_COMPACT);
    if (!body)
        return false;

    r = conn_send(con,
                  "POST %s/rec/%s HTTP/1.1\r\n"
                  "Content-Type: application/jwk+json\r\n"
                  "Accept: application/jwk+json\r\n"
                  "Content-Length: %zu\r\n"
                  "Host: %s\r\n"
                  "\r\n%s",
                  path, json_string_value(kid), strlen(body), host, body);
    free(body);
    body = NULL;
    if (r < 0)
        return false;

    s = curtime();
    r = conn_recv(con, &body);
    e = curtime();
    if (r != 200) {
        if (r < 0)
            printf("Error performing recovery! %s\n", strerror(-r));
        else
            printf("Error performing recovery! HTTP Status %d\n", r);

        free(body);
        return false;
    }

    rep = json_loads(body, 0, NULL);
    free(body);
    if (!rep) {
        printf("Received invalid JSON in response body!\n");
        return false;
    }

    if (s == 0.0 || e == 0.0 ||
        json_array_append_new(time, json_real(e - s)) < 0) {
        printf("Error calculating performance metrics!\n");
        return false;
    }

    if (!jose_jwk_eql(NULL, exc, rep)) {
        printf("Recovered key doesn't match!\n");
        return false;
    }

    *rec += 1;
    return true;
}

static const struct option opts[] = {
    { "help",   no_argument,      .val = INT_MAX },
    { "url",   required_argument, .val = 'u' },
    {}
};

int
main(int argc, char *argv[])
{
    json_auto_t *perf = NULL;
    json_auto_t *time = NULL;
    json_auto_t *keys = NULL;
    json_auto_t *adv = NULL;
    conn_auto_t *con = NULL;
    const char *url = NULL;
    char *body = NULL;
    url_t parts = {};
    size_t sig = 0;
    size_t exc = 0;
    double sum = 0;
    double s = 0;
    double e = 0;
    int r = 0;

    perf = json_object();
    time = json_array();
    if (!perf || !time)
        return NAGIOS_CRIT;

    for (int c; (c = getopt_long(argc, argv, "u:", opts, NULL)) >= 0; ) {
        switch (c) {
        case 'u': url = optarg; break;
        default: goto usage;
        }
    }

    if (!url)
        goto usage;

    r = parse_url(url, &parts);
    if (r < 0)
        return NAGIOS_CRIT;

    con = conn_open(parts.host, parts.srvc, AF_UNSPEC);
    if (!con) {
        printf("Unable to connect to server!\n");
        return NAGIOS_CRIT;
    }

    r = conn_send(con,
                  "GET %s/adv HTTP/1.1\r\n"
                  "Accept: application/jose+json\r\n"
                  "Content-Length: 0\r\n"
                  "Host: %s\r\n"
                  "\r\n", parts.path, parts.host);
    if (r < 0)
        return NAGIOS_CRIT;

    s = curtime();
    r = conn_recv(con, &body);
    e = curtime();
    if (r != 200) {
        if (r < 0)
            printf("Error fetching advertisement! %s\n", strerror(-r));
        else
            printf("Error fetching advertisement! HTTP Status %d\n", r);

        free(body);
        return NAGIOS_CRIT;
    }

    if (s == 0.0 || e == 0.0 ||
        json_object_set_new(perf, "adv", json_real(e - s)) != 0) {
        printf("Error calculating performance metrics!\n");
        free(body);
        return NAGIOS_CRIT;
    }

    adv = json_loads(body, 0, NULL);
    free(body);
    if (!adv) {
        printf("Received invalid advertisement!\n");
        return NAGIOS_CRIT;
    }

    keys = validate(adv);
    if (!keys) {
        printf("Error validating advertisement!\n");
        return NAGIOS_CRIT;
    }

    for (size_t i = 0; i < json_array_size(keys); i++) {
        json_t *jwk = json_array_get(keys, i);
        if (!nagios_recover(con, parts.host, parts.path, jwk,
                            &sig, &exc, time))
            return NAGIOS_CRIT;
    }

    if (exc == 0) {
        printf("Advertisement contains no exchange keys!\n");
        return NAGIOS_CRIT;
    }

    for (size_t i = 0; i < json_array_size(time); i++)
        sum += json_real_value(json_array_get(time, i));

    json_object_set_new(perf, "exc", json_real(sum / json_array_size(time)));
    json_object_set_new(perf, "nkeys", json_integer(json_array_size(keys)));
    json_object_set_new(perf, "nsigk", json_integer(sig));
    json_object_set_new(perf, "nexck", json_integer(exc));

    printf("OK|");
    dump_perf(perf);
    printf("\n");
    return NAGIOS_OK;

usage:
    fprintf(stderr,
            "Usage: %s -u URL\n"
            "\n"
            "            --help       Show this usage message\n"
            "    -u URL, --url URL    Test the server at this URL\n"
            "", argv[0]);
    return NAGIOS_CRIT;
}
