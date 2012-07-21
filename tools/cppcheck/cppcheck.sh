#!/bin/sh

#
# cppcheck.sh
# Script to run CppCheck Static Analyzer.
# http://cppcheck.sourceforge.net/
#
# $Id$
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 2012 Gerald Combs
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
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#

CPPCHECK=`which cppcheck`
CPPCHECK_DIR=`dirname $0`

THREADS=4
QUIET="--quiet"
SUPPRESSIONS="$CPPCHECK_DIR/suppressions"
INCLUDES="$CPPCHECK_DIR/includes"

if [ $# -gt 0 ]; then
    TEMPLATE="gcc"
    TARGET=$*
else
    echo "<html><body><table border=1>"
    echo "<tr><th>File</th><th>Line</th><th>Severity</th>"
    echo "<th>Message</th><th>ID</th></tr>"
    TEMPLATE="<tr><td>{file}</td><td>{line}</td><td>{severity}</td><td>{message}</td><td>{id}</td></tr>"
    TARGET="."
fi

# Use a little-documented feature of the shell to pass SIGINTs only to the
# child process (cppcheck in this case). That way the final 'echo' still
# runs and we aren't left with broken HTML.
trap : INT

$CPPCHECK --force --enable=style $QUIET     \
          --suppressions-list=$SUPPRESSIONS \
          --includes-file=$INCLUDES         \
          --template=$TEMPLATE              \
          -j $THREADS $TARGET 2>&1

if [ $# -eq 0 ]; then
    echo "</table></body></html>"
fi
