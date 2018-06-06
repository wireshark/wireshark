#!/bin/bash
#
# compress-pngs.sh
# Run various compression and optimization utilities on one or more PNGs
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 2013 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
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
    bash -c "$FILE_LIST_CMD" | while read -r PNG_FILE ; do
        echo -e " \\"
        echo -e -n "\\t${PNG_FILE}"

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
