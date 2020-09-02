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
#       -x      xml output (default is gcc)
#       -j n    threads (default: 4)
#       -l n    check files from the last [n] commits
#       -o      check modified files
#       -v      quiet mode
# If argument file is omitted then checking all files in the current directory.
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 2012 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

CPPCHECK=$(type -p cppcheck)
CPPCHECK_DIR=$(dirname "$0")

if [ -z "$CPPCHECK" ] ; then
    echo "cppcheck not found"
    exit 1
fi

THREADS=4
LAST_COMMITS=0
TARGET=""
QUIET="--quiet"
SUPPRESSIONS="--suppressions-list=$CPPCHECK_DIR/suppressions"
INCLUDES="--includes-file=$CPPCHECK_DIR/includes"
MODE="gcc"
COLORIZE_HTML_MODE="no"
OPEN_FILES="no"
XML_ARG=""

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

exit_cleanup() {
    if [ "$MODE" = "html" ]; then
        echo "</table></body></html>"
    fi
    if [ -n "$1" ] ; then
        exit "$1"
    fi
}

while getopts "achxj:l:ov" OPTCHAR ; do
    case $OPTCHAR in
        a) SUPPRESSIONS=" " ;;
        c) COLORIZE_HTML_MODE="yes" ;;
        h) MODE="html" ;;
        x) MODE="xml" ;;
        j) THREADS="$OPTARG" ;;
        l) LAST_COMMITS="$OPTARG" ;;
        o) OPEN_FILES="yes" ;;
        v) QUIET=" " ;;
        *) printf "Unknown option %s" "$OPTCHAR"
    esac
done
shift $(( OPTIND - 1 ))

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

if [ "$LAST_COMMITS" -gt 0 ] ; then
    TARGET=$( git diff --name-only HEAD~"$LAST_COMMITS".. | grep -E '\.(c|cpp)$' )
    if [ -z "${TARGET//[[:space:]]/}" ] ; then
        echo "No C or C++ files found in the last $LAST_COMMITS commit(s)."
        exit_cleanup 0
    fi
fi

if [ "$OPEN_FILES" = "yes" ] ; then
    TARGET=$(git diff --name-only  | grep -E '\.(c|cpp)$' )
    TARGET="$TARGET $(git diff --staged --name-only  | grep -E '\.(c|cpp)$' )"
    if [ -z "${TARGET//[[:space:]]/}" ] ; then
        echo "No C or C++ files are currently opened (modified or added for next commit)."
        exit_cleanup 0
    fi
fi

if [ $# -gt 0 ]; then
    TARGET="$TARGET $*"
fi

if [ -z "$TARGET" ] ; then
    TARGET=.
fi

if [ "$MODE" = "xml" ]; then
    XML_ARG="--xml"
fi

# Use a little-documented feature of the shell to pass SIGINTs only to the
# child process (cppcheck in this case). That way the final 'echo' still
# runs and we aren't left with broken HTML.
trap : INT

echo "Examining:"
echo $TARGET
echo

# shellcheck disable=SC2086
$CPPCHECK --force --enable=style $QUIET    \
    $SUPPRESSIONS $INCLUDES \
    -i doc/ \
    -i epan/dissectors/asn1/ \
    --std=c99 --template=$TEMPLATE   \
    -j $THREADS $TARGET $XML_ARG 2>&1 | colorize

exit_cleanup

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
