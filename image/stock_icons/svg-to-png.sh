#!/bin/bash
# svg-to-png
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

COMMON_ARGS="--export-area-page"

#SVGCLEANER=$( type -p svgcleaner )

set_source_svgs() {
    local out_icon=$1
    case $out_icon in
    x-capture-options)
        out_icon=x-capture-options-gear
        ;;
    x-capture-restart)
        out_icon=x-capture-restart-fin
        ;;
    x-capture-stop)
        out_icon=x-capture-stop-red
        ;;
    esac
    ONE_X_SVG=${out_icon}.svg
    TWO_X_SVG=${out_icon}@2x.svg
    if [ ! -f ${TWO_X_SVG} ] ; then
        TWO_X_SVG=$ONE_X_SVG
    fi
}

ICONS="
    edit-find.template
    go-first
    go-jump
    go-last
    go-next
    go-previous
    x-capture-file-close
    x-capture-file-save
    x-capture-file-reload
    x-capture-filter-bookmark
    x-capture-filter-bookmark.active
    x-capture-filter-bookmark.selected
    x-capture-options
    x-capture-restart
    x-capture-start.on
    x-capture-start
    x-capture-stop
    x-colorize-packets
    x-display-filter-bookmark
    x-display-filter-bookmark.active
    x-display-filter-bookmark.selected
    x-filter-apply
    x-filter-apply.active
    x-filter-apply.selected
    x-filter-clear
    x-filter-clear.active
    x-filter-clear.selected
    x-filter-deprecated
    x-filter-dropdown.dark
    x-filter-dropdown.light
    x-filter-invalid
    x-filter-matching-bookmark
    x-filter-matching-bookmark.active
    x-filter-matching-bookmark.selected
    x-resize-columns
    x-stay-last
    zoom-in.template
    zoom-original.template
    zoom-out.template
    "

if [ -n "$*" ] ; then
    ICONS="$*"
fi

QRC_FILES=""

# 12x12
for SIZE in 14x14 16x16 24x14 24x24 ; do
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

        # XXX This seems to modify the SVG too much. Need to
        # investigate.
        #if [ -n "$SVGCLEANER" ] ; then
        #    mv "$ICON.svg" "$ICON.dirty.svg"
        #    $SVGCLEANER "$ICON.dirty.svg" "$ICON.svg"
        #    rm "$ICON.dirty.svg"
        #fi

        set_source_svgs "$ICON"

        if [ ! -f ${ONE_X_SVG} ] ; then
            >&2 echo "Skipping ${ONE_X_SVG}"
            continue
        fi

        ONE_X_PNG=${ICON}.png
        TWO_X_PNG=${ICON}@2x.png

        if [ $ONE_X_SVG -nt "$ONE_X_PNG" ] ; then
            # shellcheck disable=SC2086
            inkscape $COMMON_ARGS $ONE_X_ARGS \
                --file="$PWD/$ONE_X_SVG" --export-png="$PWD/$ONE_X_PNG" || exit 1
            QRC_FILES="${QRC_FILES} ${SIZE_DIR}/${ONE_X_PNG}"
        fi

        if [ $TWO_X_SVG -nt "$TWO_X_PNG" ] ; then
            # shellcheck disable=SC2086
            inkscape $COMMON_ARGS $TWO_X_ARGS \
                --file="$PWD/$TWO_X_SVG" --export-png="$PWD/$TWO_X_PNG" || exit 1
            QRC_FILES="${QRC_FILES} ${SIZE_DIR}/${TWO_X_PNG}"
        fi

    done

    cd ..

done

for QRC_FILE in $QRC_FILES ; do
    echo "        <file>stock_icons/${QRC_FILE}</file>"
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
