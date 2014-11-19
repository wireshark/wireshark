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

COMMON_ARGS="--export-area-page"

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
    edit-find
    go-first
    go-jump
    go-last
    go-next
    go-previous
    media-playback-start
    x-capture-file-close
    x-capture-file-save
    x-capture-file-reload
    x-capture-options
    x-capture-restart
    x-capture-start.on
    x-capture-start
    x-capture-stop
    x-colorize-packets
    x-resize-columns
    x-stay-last
    zoom-in
    zoom-original
    zoom-out
    "

QRC_FILES=""

# XXX Add support for 16 pixel icons.
for SIZE in 12 16 24 ; do
    SIZE_DIR=${SIZE}x${SIZE}

    TWO_X_SIZE=`expr $SIZE \* 2`
    ONE_X_ARGS="--export-width=${SIZE} --export-height=${SIZE}"
    TWO_X_ARGS="--export-width=${TWO_X_SIZE} --export-height=${TWO_X_SIZE}"

    cd $SIZE_DIR

    for ICON in $ICONS ; do
        set_source_svgs $ICON

        if [ ! -f ${ONE_X_SVG} ] ; then
            >&2 echo "Skipping ${ONE_X_SVG}"
            continue
        fi

        ONE_X_PNG=${ICON}.png
        TWO_X_PNG=${ICON}@2x.png

        if [ $ONE_X_SVG -nt $ONE_X_PNG ] ; then
            inkscape $COMMON_ARGS $ONE_X_ARGS \
                --file=$ONE_X_SVG --export-png=$ONE_X_PNG || exit 1
        fi

        if [ $TWO_X_SVG -nt $TWO_X_PNG ] ; then
            inkscape $COMMON_ARGS $TWO_X_ARGS \
                --file=$TWO_X_SVG --export-png=$TWO_X_PNG || exit 1
        fi

        QRC_FILES="${QRC_FILES} ${SIZE_DIR}/${ONE_X_PNG} ${SIZE_DIR}/${TWO_X_PNG}"
    done

    cd ..

done

for QRC_FILE in $QRC_FILES ; do
    echo "        <file>toolbar/${QRC_FILE}</file>"
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
