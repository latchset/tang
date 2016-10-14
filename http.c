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

#include "http.h"
#undef http_reply

#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char *METHOD_NAMES[] = {
#define XX(num, name, string) [num] = # string,
HTTP_METHOD_MAP(XX)
#undef XX
    NULL
};

static int
on_url(http_parser *parser, const char *at, size_t length)
{
    struct http_state *state = parser->data;

    if (state->req.status == 0) {
        if (strlen(state->req.path) + length >= sizeof(state->req.path))
            state->req.status = HTTP_STATUS_URI_TOO_LONG;
        else
            strncat(state->req.path, at, length);
    }

    return 0;
}

static int
on_body(http_parser *parser, const char *at, size_t length)
{
    struct http_state *state = parser->data;

    if (state->req.status == 0) {
        if (strlen(state->req.body) + length >= sizeof(state->req.body))
            state->req.status = HTTP_STATUS_PAYLOAD_TOO_LARGE;
        else
            strncat(state->req.body, at, length);
    }

    return 0;
}

static int
on_message_complete(http_parser *parser)
{
    struct http_state *state = parser->data;
    const char *addr = NULL;
    bool pathmatch = false;
    bool methmatch = false;
    int r = 0;

    if (state->req.status != 0)
        goto error;

    addr = getenv("REMOTE_ADDR");
    fprintf(stderr, "%s %s %s",
            addr ? addr : "<unknown>",
            METHOD_NAMES[parser->method],
            state->req.path);

    for (size_t i = 0; state->dispatch[i].re && r == 0; i++) {
        const struct http_dispatch *d = &state->dispatch[i];
        regmatch_t match[d->nmatches];
        regex_t re = {};

        memset(match, 0, sizeof(match));

        r = regcomp(&re, d->re, REG_EXTENDED) == 0 ? 0 : -EINVAL;
        if (r != 0) {
            state->req.status = HTTP_STATUS_INTERNAL_SERVER_ERROR;
            goto error;
        }

        if (regexec(&re, state->req.path, d->nmatches, match, 0) == 0) {
            pathmatch = true;

            if (((1 << parser->method) & d->methods) != 0) {
                methmatch = true;

                r = d->func(parser->method, state->req.path,
                            state->req.body, match, state->misc);
            }
        }

        regfree(&re);
    }

    if (r > 0)
        goto egress;

    if (r == 0) {
        if (!pathmatch)
            state->req.status = HTTP_STATUS_NOT_FOUND;
        else if (!methmatch)
            state->req.status = HTTP_STATUS_METHOD_NOT_ALLOWED;
        else
            state->req.status = HTTP_STATUS_INTERNAL_SERVER_ERROR;
    } else {
        state->req.status = HTTP_STATUS_INTERNAL_SERVER_ERROR;
    }

error:
    http_reply(__FILE__, __LINE__, state->req.status, NULL);

egress:
    memset(&state->req, 0, sizeof(state->req));
    return 0;
}

const http_parser_settings http_settings = {
    .on_url = on_url,
    .on_body = on_body,
    .on_message_complete = on_message_complete,
};

int
http_reply(const char *file, int line,
           enum http_status code, const char *fmt, ...)
{
    const char *msg = NULL;
    va_list ap;
    int a;
    int b;

    switch (code) {
#define XX(num, name, string) case num: msg = # string; break;
    HTTP_STATUS_MAP(XX)
#undef XX
    default:
        return http_reply(file, line, HTTP_STATUS_INTERNAL_SERVER_ERROR, NULL);
    }

    fprintf(stderr, " => %d (%s:%d)\n", code, file, line);

    a = dprintf(STDOUT_FILENO, "HTTP/1.1 %d %s\r\n", code, msg);
    if (a < 0)
        return a;

    va_start(ap, fmt);
    b = vdprintf(STDOUT_FILENO, fmt ? fmt : "\r\n", ap);
    va_end(ap);
    return b < 0 ? b : a + b;
}
