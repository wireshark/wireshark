#!/bin/bash

# A small script to export some variables and run tshark or wireshark in
# valgrind on a given capture file.
#
# Copyright 2012 Jeff Morriss <jeff.morriss.ws [AT] gmail.com>
#
# $Id$
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

# Directory containing tshark or wireshark.  Default current directory.
BIN_DIR=.

# Use tshark by default
COMMAND=tshark
COMMAND_ARGS="-nVxr"
COMMAND_ARGS2=
VALID=0
PCAP=""

while getopts ":2b:C:lntwce" OPTCHAR ; do
    case $OPTCHAR in
        2) COMMAND_ARGS="-2 $COMMAND_ARGS" ;;
        b) BIN_DIR=$OPTARG ;;
        C) COMMAND_ARGS="-C $OPTARG $COMMAND_ARGS" ;;
        l) LEAK_CHECK="--leak-check=full" ;;
        n) COMMAND_ARGS="-v"
           VALID=1 ;;
        t) TRACK_ORIGINS="--track-origins=yes" ;;
        w) COMMAND=wireshark
           COMMAND_ARGS="-nr" ;;
        c) COMMAND=capinfos
           COMMAND_ARGS="" ;;
        e) COMMAND=editcap
           COMMAND_ARGS="-E 0.02"
           # We don't care about the output of editcap
           COMMAND_ARGS2="/dev/null" ;;
    esac
done
shift $(($OPTIND - 1))

if [ $# -ge 1 ]
then
    PCAP=$1
    VALID=1
fi

if [ $VALID -eq 0 ]
then
    printf "Usage: $0 [-2] [-b bin_dir] [-C config_profile] [-l] [-n] [-t] [-w] /path/to/file.pcap\n"
    exit 1
fi

if [ "$BIN_DIR" = "." ]; then
    export WIRESHARK_RUN_FROM_BUILD_DIRECTORY=
fi

export WIRESHARK_DEBUG_EP_NO_CHUNKS=
export WIRESHARK_DEBUG_SE_NO_CHUNKS=
export G_SLICE=always-malloc # or debug-blocks

libtool --mode=execute valgrind $LEAK_CHECK $TRACK_ORIGINS $BIN_DIR/$COMMAND $COMMAND_ARGS $PCAP $COMMAND_ARGS2 > /dev/null
