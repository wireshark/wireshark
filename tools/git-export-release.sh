#!/bin/bash
#
# creates a release tarball directly from git
#
# Copyright 2011 Balint Reczey <balint@balintreczey.hu>
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

# First paremeter, if set, is a git commit, like v1.12.0-rc1 or 54819e5699f
# By default HEAD is used.
# Note, that filtering takes place base on the _exported_ version's
# .gitattributes files thus archives generated from older commits will contain
# the whole tree.
COMMIT="HEAD"
if test -n "$1"; then
  COMMIT="$1"
fi
VERSION=$(git describe --tags ${COMMIT} | sed 's/^v//')

git archive --prefix=wireshark-${VERSION}/ ${COMMIT}  | xz > wireshark-${VERSION}.tar.xz
