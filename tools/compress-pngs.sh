#!/bin/bash
#
# compress-pngs.sh
# Run various compression and optimization utilities on one or more PNGs
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 2013 Gerald Combs
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

FILE_LIST_CMD="find . -type f -name \"*.png\""

if [ -n "$1" ] ; then
    FILE_LIST_CMD="echo $1"
fi

# Other utilities:
# PNGOUT (http://advsys.net/ken/utils.htm). Closed source.
# pngquant (https://pngquant.org/). Lossy.

JOBS=8
export FILE_LIST_CMD
(
    echo -n "PNG_FILES ="
    bash -c "$FILE_LIST_CMD" | while read PNG_FILE ; do
        echo -e " \\"
        echo -e -n "\t${PNG_FILE}"

    done
    cat <<"FIN"


all: $(PNG_FILES)

$(PNG_FILES): FORCE
	@echo Compressing $@
	@hash optipng 2>/dev/null  && optipng -o3 -quiet "$@"
	@hash advpng 2>/dev/null   && advpng -z -4 "$@"
	@hash advdef 2>/dev/null   && advdef -z -4 "$@"
	@hash pngcrush 2>/dev/null && pngcrush -q -ow -brute -reduce -noforce "$@" pngout.$$$$.png

FORCE:
FIN

) | make -j $JOBS -f -
