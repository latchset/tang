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

#include <http_parser.h>
#include <sys/types.h>
#include <regex.h>

struct http_dispatch {
    int (*func)(enum http_method method, const char *path,
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

extern const http_parser_settings http_settings;

int __attribute__ ((format(printf, 4, 5)))
http_reply(const char *file, int line,
           enum http_status code, const char *fmt, ...);

#define http_reply(code, ...) \
    http_reply(__FILE__, __LINE__, code, __VA_ARGS__)
