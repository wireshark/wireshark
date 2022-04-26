#!/bin/bash
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
    # If we don't have a build rule for this file, it's probably because we're missing
    # necessary includes.
    for BUILD_RULE_FILE in compile_commands.json build.ninja ; do
        if [[ -f $BUILD_RULE_FILE ]] && ! grep "/$FILE_BASENAME\." $BUILD_RULE_FILE &> /dev/null ; then
            echo "Don't know how to build $FILE_BASENAME. Skipping."
            continue 2
        fi
    done
    # iLBC: the file is not even compiled when ilbc is not installed
    if test "$FILE_BASENAME" = "iLBCdecode.c"
    then
        continue
    fi
    # This is a template file, not a final '.c' file.
    if echo "$FILE_BASENAME" | grep -Eq "packet-.*-template.c"
    then
        continue
    fi

    "$CLANG_CHECK_CMD" "../$FILE"
    "$CLANG_CHECK_CMD" -analyze "../$FILE"
done
