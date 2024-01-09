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

#pragma once

#include <sys/types.h>
#include <regex.h>

#ifdef USE_LLHTTP
#include <llhttp.h>

typedef llhttp_method_t http_method_t;
typedef llhttp_status_t http_status_t;
typedef llhttp_settings_t http_settings_t;
typedef llhttp_t http_parser_t;
#define tang_http_parser_init(parser, settings) llhttp_init(parser, HTTP_REQUEST, settings)
#define tang_http_parser_execute(parser, settings, req, rcvd) llhttp_execute(parser, req, rcvd)
#define tang_http_parser_errno(parser) parser.error
#define tang_http_errno_description(parser, errno) llhttp_get_error_reason(parser)

#else
/* Legacy http-parser. */
#include <http_parser.h>

typedef enum http_method http_method_t;
typedef enum http_status http_status_t;
typedef http_parser_settings http_settings_t;
typedef struct http_parser http_parser_t;

#define tang_http_parser_init(parser, settings) http_parser_init(parser, HTTP_REQUEST)
#define tang_http_parser_execute(parser, settings, req, rcvd) http_parser_execute(parser, settings, req, rcvd)
#define tang_http_parser_errno(parser) parser.http_errno
#define tang_http_errno_description(parser, errno) http_errno_description(errno)

#endif /* USE_LLHTTP */

struct http_dispatch {
    int (*func)(http_method_t method, const char *path,
                const char *body, regmatch_t matches[], void *misc);
    uint64_t methods;
    size_t nmatches;
    const char *re;
};

struct http_request {
    int status;
    char path[1024 * 4];
    char body[1024 * 64];
};

struct http_state {
    const struct http_dispatch *dispatch;
    struct http_request req;
    void *misc;
};

extern const http_settings_t http_settings;

int __attribute__ ((format(printf, 4, 5)))
http_reply(const char *file, int line,
           http_status_t code, const char *fmt, ...);

#define http_reply(code, ...) \
    http_reply(__FILE__, __LINE__, code, __VA_ARGS__)
