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

#include <errno.h>
#include <malloc.h>
#include <string.h>

static int
on_url(http_parser *parser, const char *at, size_t length)
{
    struct http_request *req = parser->data;
    size_t slen = 0;
    size_t len = 0;

    if (req->path)
        slen = strlen(req->path);

    if (slen + length >= 65536)
        return -E2BIG;

    if (!req->path) {
        req->path = strndup(at, length);
        return req->path ? 0 : -ENOMEM;
    }

    len = malloc_usable_size(req->path);
    if (slen + length >= len) {
        char *tmp = NULL;

        tmp = realloc(req->path, slen + length + 1);
        if (!tmp)
            return -ENOMEM;
    }

    strncat(req->path, at, length);
    return 0;
}

static int
on_body(http_parser *parser, const char *at, size_t length)
{
    struct http_request *req = parser->data;
    size_t slen = 0;
    size_t len = 0;

    if (req->body)
        slen = strlen(req->body);

    if (slen + length >= 65536)
        return -E2BIG;

    if (!req->body) {
        req->body = strndup(at, length);
        return req->body ? 0 : -ENOMEM;
    }

    len = malloc_usable_size(req->body);
    if (slen + length >= len) {
        char *tmp = NULL;

        tmp = realloc(req->body, slen + length + 1);
        if (!tmp)
            return -ENOMEM;
    }

    strncat(req->body, at, length);
    return 0;
}

static int
on_message_complete(http_parser *parser)
{
    struct http_request *req = parser->data;
    req->done = true;
    return 0;
}

const http_parser_settings tang_parser_settings = {
    .on_url = on_url,
    .on_body = on_body,
    .on_message_complete = on_message_complete,
};
