# vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80:
#
# Copyright (c) 2026 Red Hat, Inc.
# Author: Sergio Arroutbi <sarroutbi@redhat.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

# Shared shell helpers for the tangd scripts. Sourced by tangd-keygen
# and tangd-rotate-keys; not executable on its own.

# Algorithms supported by the installed jose. Used to tell an unsupported
# algorithm (a benign skip) from a real generation failure (fatal: key
# generation must never silently degrade the key set).
SUPPORTED_ALGS="$(jose alg 2>/dev/null || true)"

alg_supported() {
    printf '%s\n' "${SUPPORTED_ALGS}" | grep -qx "${1}"
}
