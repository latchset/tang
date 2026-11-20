/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */
/*
 * Copyright (c) 2026 Red Hat, Inc.
 * Author: Sergio Arroutbi <sarroutbi@redhat.com>
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

/* Linked into tangd-unavailable via -Wl,--wrap=jose_jwk_gen: every
 * key generation inside that binary fails, so the runtime ML-KEM
 * probe of a PQC build reports unavailable. Only the wrapped binary
 * is affected; the jose CLI and the regular tangd are not.
 *
 * The linker mandates the __wrap_ prefix, but gcovr strips
 * "__"-prefixed symbols as compiler-generated and crashes on them in
 * C (the demangled name equals the mangled name, so the removal
 * yields every line twice). Defining the shim under a regular name
 * and exporting the __wrap_ symbol as an alias keeps the "__"-prefixed
 * function record out of the coverage data. */

#include <jose/jwk.h>

static bool
wrap_jose_jwk_gen(const jose_cfg_t *cfg, json_t *jwk)
{
    (void)cfg;
    (void)jwk;
    return false;
}

bool __wrap_jose_jwk_gen(const jose_cfg_t *cfg, json_t *jwk)
    __attribute__((alias("wrap_jose_jwk_gen")));
