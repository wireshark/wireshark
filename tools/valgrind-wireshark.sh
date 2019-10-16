#!/bin/bash

# A small script to export some variables and run tshark or wireshark in
# valgrind on a given capture file.
#
# Copyright 2012 Jeff Morriss <jeff.morriss.ws [AT] gmail.com>
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Directory containing tshark or wireshark.  Default: cmake run directory.
if [ -z "$WIRESHARK_BIN_DIR" ]; then
    WIRESHARK_BIN_DIR=run
fi

# Use tshark by default
COMMAND=tshark
COMMAND_ARGS="-nr"
COMMAND_ARGS2=
VALID=0
PCAP=""
TOOL="memcheck"

while getopts ":2a:b:C:lmnpP:rstTYwcevWdG" OPTCHAR ; do
    case $OPTCHAR in
        2) COMMAND_ARGS="-2 $COMMAND_ARGS" ;;
        a) ADDITIONAL_SUPPRESSION_FILE="$ADDITIONAL_SUPPRESSION_FILE --suppressions=$OPTARG" ;;
        b) WIRESHARK_BIN_DIR=$OPTARG ;;
        C) COMMAND_ARGS="-C $OPTARG $COMMAND_ARGS" ;;
        l) LEAK_CHECK="--leak-check=full" ;;
        m) TOOL="massif" ;;
        n) COMMAND_ARGS="-v"
           VALID=1 ;;
        p) TOOL="callgrind" ;;
        P) TOOL="callgrind"
           CALLGRIND_OUT_FILE="--callgrind-out-file=$OPTARG" ;;
        r) REACHABLE="--show-reachable=yes" ;;
        s) GEN_SUPPRESSIONS="--gen-suppressions=yes" ;;
        t) TRACK_ORIGINS="--track-origins=yes" ;;
        T) COMMAND_ARGS="-Vx $COMMAND_ARGS" ;; # "build the Tree"
        Y) COMMAND_ARGS="-Y frame $COMMAND_ARGS" ;; # Run with a read filter (but no tree)
        w) COMMAND=wireshark
           COMMAND_ARGS="-nr" ;;
        c) COMMAND=capinfos
           COMMAND_ARGS="" ;;
        e) COMMAND=editcap
           COMMAND_ARGS="-E 0.02"
           # We don't care about the output of editcap
           COMMAND_ARGS2="/dev/null" ;;
        v) VERBOSE="--num-callers=256 -v" ;;
        W) COMMAND=wireshark
           COMMAND_ARGS=""
           VALID=1 ;;
        d) COMMAND=dumpcap
           COMMAND_ARGS="-i eth1 -c 3000"
           VALID=1 ;;
        *) printf "Unknown option: %s\\n" "$OPTARG"
           exit ;;
    esac
done
shift $(( OPTIND - 1 ))

# Sanitize parameters
if [ "$COMMAND" != "tshark" ] && [[ $COMMAND_ARGS =~ Vx ]]
then
    printf "\\nYou can't use -T if you're not using tshark\\n\\n" >&2
    exit 1
fi

if [ $# -ge 1 ]
then
    PCAP=$1
    VALID=1
fi

if [ $VALID -eq 0 ]
then
    printf "\\nUsage: %s [-2] [-a file] [-b bin_dir] [-c] [-e] [-C config_profile] " "$(basename "$0")"
    printf "[-l] [-m] [-n] [-p] [-r] [-s] [-t] [-T] [-w] [-v] /path/to/file.pcap\\n"
    printf "\\n"
    printf "[-2]: run tshark with 2-pass analysis\\n"
    printf "[-a]: additional valgrind suppression file\\n"
    printf "[-b]: tshark binary dir\\n"
    printf "[-e]: use 'editcap -E 0.02' instead of tshark\\n"
    printf "[-c]: use capinfos instead of tshark\\n"
    printf "[-C]: binary profile file\\n"
    printf "[-l]: add valgrind option --leak-check=full\\n"
    printf "[-m]: use valgrind massif tool\\n"
    printf "[-n]: print binary version\\n"
    printf "[-p]: use callgrind massif tool\\n"
    printf "[-r]: add valgrind option --show-reachable=yes\\n"
    printf "[-s]: add valgrind option --gen-suppressions=yes\\n"
    printf "[-t]: add valgrind option --track-origins=yes\\n"
    printf "[-T]: build the tshark tree (-Vx)\\n"
    printf "[-w]: use wireshark instead of tshark\\n"
    printf "[-v]: run in verbose mode (--num-callers=256)\\n"
    exit 1
fi

if [ "$WIRESHARK_BIN_DIR" = "." ]; then
    export WIRESHARK_RUN_FROM_BUILD_DIRECTORY=
fi

if [ "$TOOL" != "callgrind" ]; then
    export WIRESHARK_DEBUG_WMEM_OVERRIDE=simple
    export G_SLICE=always-malloc # or debug-blocks
fi

COMMAND="$WIRESHARK_BIN_DIR/$COMMAND"

cmdline="valgrind --suppressions=$( dirname "$0" )/vg-suppressions $ADDITIONAL_SUPPRESSION_FILE \
--tool=$TOOL $CALLGRIND_OUT_FILE $VERBOSE $LEAK_CHECK $REACHABLE $GEN_SUPPRESSIONS $TRACK_ORIGINS \
$COMMAND $COMMAND_ARGS $PCAP $COMMAND_ARGS2"

if [ "$VERBOSE" != "" ];then
  echo -e "\\n$cmdline\\n"
fi

# shellcheck disable=SC2086
exec $cmdline > /dev/null
