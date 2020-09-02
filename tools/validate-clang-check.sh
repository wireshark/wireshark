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

for FILE in $COMMIT_FILES; do

    clang-check ../$FILE
    clang-check -analyze ../$FILE

done
