#!/bin/env python
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

import sys
import os
import fnmatch

IGNORE_CONF = "pre-commit-ignore.conf"

if len(sys.argv) > 2:
    print("Usage: {0} [path/to/ignore.conf]".format(sys.argv[0]))
    sys.exit(1)

if len(sys.argv) == 2:
    ignore_path = sys.argv[1]
else:
    ignore_path = IGNORE_CONF

# Function to load our patterns from 'path' for modified files
# to be ignored (skipping any comments)
def load_checkignore(path):
    try:
        with open(path) as f:
            patterns = f.read()
    except OSError as err:
        sys.exit(str(err))
    ign = [l.strip() for l in patterns.splitlines()]
    ign = [l for l in ign if l and not l.startswith("#")]
    return ign

ignore_list = load_checkignore(ignore_path)

def ignore_match(f):
    for p in ignore_list:
        if fnmatch.fnmatchcase(f, p):
            return True
    return False

for line in sys.stdin:
    line = line.strip()
    if not ignore_match(line):
        print(line)

#
#  Editor modelines
#
#  Local Variables:
#  c-basic-offset: 4
#  indent-tabs-mode: nil
#  End:
#
#  ex: set shiftwidth=4 expandtab:
#  :indentSize=4:noTabs=true:
#
