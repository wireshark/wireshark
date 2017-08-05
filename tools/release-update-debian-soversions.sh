#!/bin/sh
#
# Compare ABIs of two Wireshark working copies
#
# Copyright 2017 Balint Reczey <balint.reczey@canonical.com>
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

# Set shared library package names and library versions in Debian packaging
# matching the new major release's so versions

set -e

for i in wireshark wiretap wscodecs wsutil; do
    NEW_VERSION=$(grep SOVERSION $(grep -l lib${i} */CMakeLists.txt) | sed 's/.*SOVERSION \([0-9]*\).*/\1/')
    rename "s/0\./${NEW_VERSION}./" debian/lib${i}0.*
    grep -l -R "lib${i}0" debian/ | xargs sed -i "s/lib${i}0/lib${i}${NEW_VERSION}/"
    grep -l -R "lib${i}\.so\.0" debian/ | xargs sed -i "s/lib${i}\.so\.0/lib${i}.so.${NEW_VERSION}/"
done
