#!/bin/bash
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

set -e

if test -z $1; then
    echo "Usage:"
    echo " $0 <distribution>"
    echo " e.g: $0 xenial"
    exit 1
fi

DIST=$1
VERSION=$(git describe --tags | sed 's/v//;s/-/~/g;s/rc/~rc/')
rm debian/changelog || true
EDITOR=touch dch -p --package wireshark --create --force-distribution -v${VERSION}~${DIST}1 -D $DIST
sed -i 's/\* Initial release.*/* Nightly build for '${DIST^}'/' debian/changelog
dpkg-buildpackage -S -d
