#!/bin/bash
# layouts-to-png
# Convert SVG files to 1x and 2x PNGs. Dump a list of Qt resource
# file entries upon successful completion.
#
# Copyright 2014 Gerald Combs <gerald [AT] wireshark.org>
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# COMMON_ARGS="--export-area-page"

#SVGCLEANER=$( type -p svgcleaner )

# Running on WSL. Set as needed for Mac/linux.
INKSCAPE_EXE="inkscape.com"

ICONS="
    layout_1
    layout_2
    layout_3
    layout_4
    layout_5
    layout_6
    "

if [ -n "$*" ] ; then
    ICONS="$*"
fi

QRC_FILES=""

for SIZE in 16x16 24x24 ; do
    WIDTH=${SIZE/x*/}
    HEIGHT=${SIZE/*x/}
    SIZE_DIR=${SIZE}

    TWO_X_WIDTH=$(( WIDTH * 2 ))
    TWO_X_HEIGHT=$(( HEIGHT * 2 ))
    ONE_X_ARGS="--export-width=${WIDTH} --export-height=${HEIGHT}"
    TWO_X_ARGS="--export-width=${TWO_X_WIDTH} --export-height=${TWO_X_HEIGHT}"

    echo "Converting $SIZE_DIR"
    cd $SIZE_DIR || exit 1

    for ICON in $ICONS ; do
        echo "Converting $ICON"

        ONE_X_SVG="../../layouts.svg"
        TWO_X_SVG=$ONE_X_SVG

        ICONNAME="x-reset-$ICON"
        ONE_X_PNG=${ICONNAME}.png
        TWO_X_PNG=${ICONNAME}@2x.png

        if [ "$ONE_X_SVG" -nt "$ONE_X_PNG" ] ; then
            # shellcheck disable=SC2086
            $INKSCAPE_EXE $COMMON_ARGS $ONE_X_ARGS --export-id="$ICON" \
                --export-filename="$ONE_X_PNG" $ONE_X_SVG || exit 1
            QRC_FILES="${QRC_FILES} ${SIZE_DIR}/${ONE_X_PNG}"
        fi

        if [ "$TWO_X_SVG" -nt "$TWO_X_PNG" ] ; then
            # shellcheck disable=SC2086
            $INKSCAPE_EXE $COMMON_ARGS $TWO_X_ARGS --export-id="$ICON" \
                --export-filename="$TWO_X_PNG" $TWO_X_SVG || exit 1
            QRC_FILES="${QRC_FILES} ${SIZE_DIR}/${TWO_X_PNG}"
        fi

    done

    cd ..

done

for QRC_FILE in $QRC_FILES ; do
    echo "        <file>stock_icons/${QRC_FILE}</file>"
done

echo "--------------------------------------"
QRC_FILES=""

for SIZE in 48x48 96x96 ; do
    WIDTH=${SIZE/x*/}
    HEIGHT=${SIZE/*x/}
    OUT_DIR=".."

    TWO_X_WIDTH=$(( WIDTH * 2 ))
    TWO_X_HEIGHT=$(( HEIGHT * 2 ))
    ONE_X_ARGS="--export-width=${WIDTH} --export-height=${HEIGHT}"
    TWO_X_ARGS="--export-width=${TWO_X_WIDTH} --export-height=${TWO_X_HEIGHT}"

    echo "Converting $OUT_DIR"

    for ICON in $ICONS ; do
        echo "Converting $ICON"

        ONE_X_SVG=${OUT_DIR}/layouts.svg
        TWO_X_SVG=$ONE_X_SVG

        ICONNAME="$ICON"
        ONE_X_PNG=${OUT_DIR}/${ICONNAME}.png
        TWO_X_PNG=${OUT_DIR}/${ICONNAME}@2x.png

        if [ "$ONE_X_SVG" -nt "$ONE_X_PNG" ] ; then
            # shellcheck disable=SC2086
            $INKSCAPE_EXE $COMMON_ARGS $ONE_X_ARGS --export-id="$ICON" \
                --export-filename="$ONE_X_PNG" $ONE_X_SVG || exit 1
            QRC_FILES="${QRC_FILES} ${ICONNAME}.png"
        fi

        if [ "$TWO_X_SVG" -nt "$TWO_X_PNG" ] ; then
            # shellcheck disable=SC2086
            $INKSCAPE_EXE $COMMON_ARGS $TWO_X_ARGS --export-id="$ICON" \
                --export-filename="$TWO_X_PNG" $TWO_X_SVG || exit 1
            QRC_FILES="${QRC_FILES} ${ICONNAME}@2x.png"
        fi

    done

done

for QRC_FILE in $QRC_FILES ; do
    echo "        <file>${QRC_FILE}</file>"
done
#
# Editor modelines  -  https://www.wireshark.org/tools/modelines.html
#
# Local variables:
# c-basic-offset: 4
# tab-width: 8
# indent-tabs-mode: nil
# End:
#
# vi: set shiftwidth=4 tabstop=8 expandtab:
# :indentSize=4:tabSize=8:noTabs=true:
#
