#!/bin/bash
#
# Text file conversion script for packaging on Windows
#
# This script copies a text file from a source to a destination,
# converting line endings and adding a ".txt" filename extension
# if needed. If the destination is a directory the source file
# name is used. Newer files will not be overwritten.
#
# The destination file should be double-clickable and usable
# when Notepad is the default editor.
#
# Copyright 2013 Gerald Combs <gerald@wireshark.org>
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

SRC="$1"
DST="$2"

err_exit () {
    for str in "$@" ; do
        echo "ERROR: $str"
    done
    echo "Usage:"
    echo "  $0 <source file> <destination file>"
    echo ""
    exit 1
}

if [ -z "$SRC" -o -z "$DST" ] ; then
    err_exit
fi

if [ ! -r "$SRC" ] ; then
    err_exit "Can't read $SRC"
fi    

if [ -f "$DST" -a "$DST" -nt "SRC" ]; then
    exit 0
fi

if [ -d "$DST" ] ; then
    DSTBASE=`basename "$SRC" txt`
    DST="$DST/$DSTBASE.txt"
else
    DSTDIR=`dirname "$DST"`
    DSTBASE=`basename "$DST" txt`
    DST="$DSTDIR/$DSTBASE.txt"
fi

cp "$SRC" "$DST"
u2d "$DST"