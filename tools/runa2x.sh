#!/bin/sh -xv

#
# runa2x.sh
# Wrapper script for running Cygwin's a2x via CMake.
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 2015 Gerald Combs
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#

# Bugs:
# - This script shouldn't exist. Unfortunately there doesn't appear
#   to be a way to construct a Windows command line that can set the
#   environment variables below, then run /usr/bin/a2x (which is a symlink).

# Ensure cygwin bin dir is on the path if running under it
if [[ $OSTYPE == "cygwin" ]]; then
	PATH="$PATH:/usr/bin"
else
    >&2 echo "We're trying to limit the scope of this insanity to CMake + Cygwin"
    exit 1
fi

LC_ALL=C
export LC_ALL

TZ=UTC
export TZ

PATH=/usr/bin
export PATH

PYTHONHOME=/
export PYTHONHOME

echo "running a2x with args $@"

a2x "$@"
