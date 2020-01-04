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

while getopts h OPTCHAR
do
    case $OPTCHAR in
    h|?)
        echo "Usage: compress-pngs.sh file1.png [file2.png] ..." 1>&1
        exit 0
        ;;
    esac
done

# Other utilities:
# PNGOUT (http://advsys.net/ken/utils.htm). Closed source.
# pngquant (https://pngquant.org/). Lossy.

JOBS=8
PNG_FILES=$(printf "%q " "$@")
export PNG_FILES
(
    cat <<"FIN"

all: $(PNG_FILES)

$(PNG_FILES): FORCE
	@echo Compressing $@
	@hash oxipng   2>/dev/null && oxipng --opt 4 --strip safe "$@"
	@hash optipng  2>/dev/null && optipng -o3 -quiet "$@"
	@hash advpng   2>/dev/null && advpng --recompress --shrink-insane "$@"
	@hash advdef   2>/dev/null && advdef --recompress --shrink-insane "$@"
	@hash pngcrush 2>/dev/null && pngcrush -q -ow -brute -reduce -noforce "$@" pngout.$$$$.png

FORCE:
FIN

) | make -j $JOBS -f -
