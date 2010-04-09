#!/bin/bash
#
# $Id$
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