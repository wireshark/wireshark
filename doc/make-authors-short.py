#!/usr/bin/env python3
#
# Generate the AUTHORS-SHORT file.
# Ported from make-authors-short.pl, copyright 2004 Ulf Lamping <ulf.lamping@web.de>
#
# By Gerald Combs <gerald@wireshark.org
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
'''\
Remove tasks from individual author entries from the AUTHORS file
for use in the "About" dialog.
'''

import io
import re
import sys

def main():
    stdinu8 = io.TextIOWrapper(sys.stdin.buffer, encoding='utf8')
    stdoutu8 = io.TextIOWrapper(sys.stdout.buffer, encoding='utf8')
    stderru8 = io.TextIOWrapper(sys.stderr.buffer, encoding='utf8')
    in_subinfo = False

    # Assume the first line is blank and skip it. make-authors-short.pl
    # skipped over the UTF-8 BOM as well. Do we need to do that here?

    stdinu8.readline()

    for line in stdinu8:

        sub_m = re.search(r'(.*?)\s*\{', line)
        if sub_m:
            in_subinfo = True
            stdoutu8.write(sub_m.group(1) + '\n')
        elif '}' in line:
            in_subinfo = False
            nextline = next(stdinu8)
            if not re.match('^\s*$', nextline):
                if '{' in nextline:
                    stderru8.write("No blank line after '}', found " + nextline)
                stdoutu8.write(nextline)
        elif in_subinfo:
            continue
        else:
            stdoutu8.write(line)

if __name__ == '__main__':
    main()
