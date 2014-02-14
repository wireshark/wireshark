#!/bin/bash
#
# checks if Wireshark's ABI has been changes since last release (tag)
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

set -e

if test -z "$1"; then
	echo "Usage:"
	echo "$0 \"<build commands>\""
	echo "e.g. $0 \"./autogen.sh && ./configure && make -j3 && make dumpabi\""
	exit 1
fi

# build current version
bash -c "$1"

cd `git rev-parse --show-toplevel`
# we are at top level

# Stable branches with releases
#LAST_TAG=`git describe --tags --abbrev=0`
#LAST_TAG_DIR=$LAST_TAG

# Use latest commit
LAST_TAG=HEAD
LAST_TAG_DIR=master

rm -rf $LAST_TAG_DIR
mkdir $LAST_TAG_DIR
git archive $LAST_TAG | tar -x -C $LAST_TAG_DIR

# build latest tag
(cd $LAST_TAG_DIR && bash -c "$1")

exec tools/compare-abis.sh `pwd`/$LAST_TAG_DIR `pwd`

