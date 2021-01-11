#!/bin/sh
# Copyright 2018, Alexis La Goutte (See AUTHORS file)
#
# Verifies last commit with clang-check (like scan-build) for Petri Dish
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

COMMIT_FILES=$( git diff-index --cached --name-status HEAD^ | grep -v "^D" | cut -f2 | grep "\\.c$\|cpp$" )
CLANG_CHECK_CMD=clang-check

while getopts c: OPTCHAR
do
    case $OPTCHAR in
    c)
        CLANG_CHECK_CMD="clang-check-$OPTARG"
        exit 0
        ;;
    *)
        echo "Usage: $( basename "$0" ) [ -c <clang version> ]"
    esac
done

for FILE in $COMMIT_FILES; do
    # Skip some special cases
    FILE_BASENAME="$( basename "$FILE" )"
    # iLBC: the file is not even compiled when ilbc is not installed
    if test "$FILE_BASENAME" = "iLBCdecode.c"
    then
        continue
    fi
    # extcap/{etwdump.c,etl.c,etw_message.c}: those compile, and are compiled,
    # only on Windows
    if test \( "$FILE_BASENAME" = "etwdump.c" -o \
               "$FILE_BASENAME" = "etl.c" -o \
               "$FILE_BASENAME" = "etw_message.c" \)
    then
        continue
    fi

    "$CLANG_CHECK_CMD" "../$FILE"
    "$CLANG_CHECK_CMD" -analyze "../$FILE"
done
