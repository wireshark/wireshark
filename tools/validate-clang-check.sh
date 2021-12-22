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
        ;;
    *)
        echo "Usage: $( basename "$0" ) [ -c <clang version> ]"
        exit 0
    esac
done

for FILE in $COMMIT_FILES; do
    # Skip some special cases
    FILE_BASENAME="$( basename "$FILE" )"
    # iLBC: the file is not even compiled when ilbc is not installed
    if test \( "$FILE_BASENAME" = "iLBCdecode.c" -o \
               "$FILE_BASENAME" = "packet-PROTOABBREV.c" \)
    then
        continue
    fi
    # This is a template file, not a final '.c' file.
    if test "$FILE_BASENAME" = "packet-asterix-template.c"
    then
        continue
    fi
    # extcap/{etwdump.c,etl.c,etw_message.c}: those compile, and are compiled,
    # only on Windows
    # The same applies to capture-wpcap.c
    if test \( "$FILE_BASENAME" = "etwdump.c" -o \
               "$FILE_BASENAME" = "etl.c" -o \
               "$FILE_BASENAME" = "etw_message.c" -o \
               "$FILE_BASENAME" = "capture-wpcap.c" \)
    then
        continue
    fi

    "$CLANG_CHECK_CMD" "../$FILE"
    "$CLANG_CHECK_CMD" -analyze "../$FILE"
done
