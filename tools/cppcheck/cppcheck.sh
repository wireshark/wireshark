#!/bin/bash

#
# cppcheck.sh
# Script to run CppCheck Static Analyzer.
# http://cppcheck.sourceforge.net/
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 2012 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

CPPCHECK=`which cppcheck`
CPPCHECK_DIR=`dirname $0`

THREADS=4
QUIET="--quiet"
SUPPRESSIONS="--suppressions-list=$CPPCHECK_DIR/suppressions"
INCLUDES="--includes-file=$CPPCHECK_DIR/includes"
MODE="gcc"

while getopts "ahj:v" OPTCHAR ; do
    case $OPTCHAR in
        a) SUPPRESSIONS=" " ;;
        h) MODE="html" ;;
        j) THREADS="$OPTARG" ;;
        v) QUIET=" " ;;
    esac
done
shift $(($OPTIND-1))

if [ "$MODE" = "gcc" ]; then
    TEMPLATE="gcc"
elif [ "$MODE" = "html" ]; then
    echo "<html><body><table border=1>"
    echo "<tr><th>File</th><th>Line</th><th>Severity</th>"
    echo "<th>Message</th><th>ID</th></tr>"
    TEMPLATE="<tr><td>{file}</td><td>{line}</td><td>{severity}</td><td>{message}</td><td>{id}</td></tr>"
fi

if [ $# -eq 0 ]; then
    TARGET="."
else
    TARGET=$@
fi

# Use a little-documented feature of the shell to pass SIGINTs only to the
# child process (cppcheck in this case). That way the final 'echo' still
# runs and we aren't left with broken HTML.
trap : INT

$CPPCHECK --force --enable=style $QUIET  \
          $SUPPRESSIONS $INCLUDES        \
          --std=c89 --template=$TEMPLATE \
          -j $THREADS $TARGET 2>&1

if [ "$MODE" = "html" ]; then
    echo "</table></body></html>"
fi

#
# Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
