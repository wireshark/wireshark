#!/bin/env python
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
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
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

import sys
import os
import re
import fnmatch
import filecmp

TOOLS_DIR = "tools"
CHECK_CONF = "pre-commit-check.conf"

CHECK_LIST = ["checkhf.pl", "checkAPIs.pl -p", "fix-encoding-args.pl", "checkfiltername.pl"]

if len(sys.argv) > 2:
    print("Usage: {0} [COMMIT]".format(sys.argv[0]))
    sys.exit(1)

# If the commit identifier is not given, use HEAD instead.
if len(sys.argv) == 2:
    COMMIT_ID = sys.argv[1]
else:
    COMMIT_ID = "HEAD"

# Function to load our patterns from 'path' for modified files
# to be ignored (skipping any comments)
def load_checkignore(path):
    try:
        with open(path) as f:
            patterns = f.read()
    except OSError as err:
        print("'" + path + "':", str(err))
        return []
    ign = [l.strip() for l in patterns.splitlines()]
    ign = [l for l in ign if l and not l.startswith("#")]
    return ign

IGNORE_LIST = load_checkignore(os.path.join(TOOLS_DIR, CHECK_CONF))

# Run git-diff index and process/filter output
def run_diff_index():
    ret = []
    with os.popen("git diff-index --cached --name-status " + COMMIT_ID) as p:
        diff = p.read()
    for l in diff.splitlines():
        l = l.lstrip()
        if l.startswith("D"):
            continue
        l = l.split()
        f = l[1].strip()
        if not re.search("\.[ch]$", f):
            continue
        for pattern in IGNORE_LIST:
            if fnmatch.fnmatchcase(f, pattern):
                f = None
                break
        if f:
            ret.append(f)
    return ret

exit_status = 0

# For each valid modified file run our checks
for f in run_diff_index():
    for c in CHECK_LIST:
        script = os.path.join(TOOLS_DIR, c)
        cmd = "perl {0} {1}".format(script, f)
        ret = os.system(cmd)
        if ret != 0:
            exit_status = 1

sys.exit(exit_status)

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
