#!/bin/bash
#
# $Id$
#
# A small script to export some variables and run tshark or wireshark in
# valgrind on a given capture file.

# Directory containing tshark or wireshark.  Default current directory.
BIN_DIR=.

# Use tshark by default
COMMAND=tshark
COMMAND_ARGS="-nVxr"
COMMAND_ARGS2=

while getopts ":b:lwce" OPTCHAR ; do
    case $OPTCHAR in
        b) BIN_DIR=$OPTARG ;;
        l) LEAK_CHECK="--leak-check=full" ;;
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

if [ $# -ne 1 ]
then
	printf "Usage: $0 [-b bin_dir] [-l] [-w] /path/to/file.pcap\n"
	exit 1
fi

if [ "$BIN_DIR" = "." ]; then
    export WIRESHARK_RUN_FROM_BUILD_DIRECTORY=
fi

export WIRESHARK_DEBUG_EP_NO_CHUNKS=
export WIRESHARK_DEBUG_SE_NO_CHUNKS=
export G_SLICE=always-malloc # or debug-blocks

libtool --mode=execute valgrind $LEAK_CHECK $BIN_DIR/$COMMAND $COMMAND_ARGS $1 $COMMAND_ARGS2 > /dev/null
