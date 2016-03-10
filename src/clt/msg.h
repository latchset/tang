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

#pragma once

#include "../core/asn1.h"

/** Sends the reqs to host:port using UDP and returns the replies. */
STACK_OF(TANG_MSG) *
msg_rqst(const TANG_MSG **reqs, const char *host, const char *port, time_t to);

/** Listens to host:port (TCP). On connect, send reqs and return replies. */
STACK_OF(TANG_MSG) *
msg_wait(const TANG_MSG **reqs, const char *host, const char *port, time_t to);

/** Saves msg to filename. */
int
msg_save(const TANG_MSG *msg, const char *filename);

/** Reads msg from filename. */
TANG_MSG *
msg_read(const char *filename);
