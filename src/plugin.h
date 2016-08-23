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

#include "io.h"

#include <http_parser.h>
#include <sys/types.h>
#include <regex.h>

#define ERR_TMPL "HTTP/1.1 %d %s\r\nConnection: close\r\n\r\n"

struct tang_plugin_map {
    ssize_t (*func)(const char *path, regmatch_t matches[],
                    const char *body, enum http_method method,
                    char pkt[], size_t pktl);
    uint64_t methods;
    size_t nmatches;
    const char *re;
    struct tang_plugin_map *next;
};

extern struct tang_plugin_map *tang_plugin_maps;

extern int
tang_plugin_init(const char *cfg);
