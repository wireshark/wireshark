#!/bin/bash

#
# cppcheck.sh
# Script to run CppCheck Static Analyzer.
# http://cppcheck.sourceforge.net/
#
# Usage: tools/cppcheck/cppcheck.sh [options] [file]
# Where options can be:
#       -a      disable suppression list (see $CPPCHECK_DIR/suppressions)
#       -c      colorize html output
#       -h      html output (default is gcc)
#       -t      threads (default: 4)
#       -v      quiet mode
# If argument file is omitted then checking all files in the current directory.
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
COLORIZE_HTML_MODE="no"

colorize_worker()
{
    # always uses stdin/stdout
    [ "$COLORIZE_HTML_MODE" = "yes" ] && \
        sed -e '/<td>warning<\/td>/s/^<tr>/<tr bgcolor="#ff3">/' \
            -e '/<td>error<\/td>/s/^<tr>/<tr bgcolor="#faa">/' \
        || sed ''
}

# switcher
colorize()
{
    [ -z "$1" ] && colorize_worker || colorize_worker <<< "$1"
}

while getopts "achj:v" OPTCHAR ; do
    case $OPTCHAR in
        a) SUPPRESSIONS=" " ;;
        c) COLORIZE_HTML_MODE="yes" ;;
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

# Ensure that the COLORIZE_HTML_MODE option is used only with HTML-mode and not with GCC-mode.
[ "$MODE" = "html" ] && [ "$COLORIZE_HTML_MODE" = "yes" ] || COLORIZE_HTML_MODE="no"

if [ $# -eq 0 ]; then
    TARGET="."
else
    TARGET=$@
fi

# Use a little-documented feature of the shell to pass SIGINTs only to the
# child process (cppcheck in this case). That way the final 'echo' still
# runs and we aren't left with broken HTML.
trap : INT

$CPPCHECK --force --enable=style $QUIET    \
          $SUPPRESSIONS $INCLUDES -i asn1/ \
          --std=c99 --template=$TEMPLATE   \
          -j $THREADS $TARGET 2>&1 | colorize

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
