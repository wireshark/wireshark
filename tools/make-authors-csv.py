#!/usr/bin/env python3
#
# Generate the authors.csv file.
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


def remove_tasks(stdinu8):
    in_subinfo = False
    all_lines = []

    # Assume the first line is blank and skip it. make-authors-short.pl
    # skipped over the UTF-8 BOM as well. Do we need to do that here?

    stdinu8.readline()

    for line in stdinu8:

        sub_m = re.search(r'(.*?)\s*\{', line)
        if sub_m:
            in_subinfo = True
            all_lines.append(sub_m.group(1))
        elif '}' in line:
            in_subinfo = False
            nextline = next(stdinu8)
            if not re.match(r'^\s*$', nextline):
                # if '{' in nextline:
                #    stderru8.write("No blank line after '}', found " + nextline)
                all_lines.append(nextline)
        elif in_subinfo:
            continue
        else:
            all_lines.append(line)
    return all_lines


def main():
    stdinu8 = io.TextIOWrapper(sys.stdin.buffer, encoding='utf8')
    stdoutu8 = io.TextIOWrapper(sys.stdout.buffer, encoding='utf8')
    stderru8 = io.TextIOWrapper(sys.stderr.buffer, encoding='utf8')

    lines = remove_tasks(stdinu8)
    patt = re.compile("(.*)[<(]([\\s'a-zA-Z0-9._%+-]+(\\[[Aa][Tt]\\])?[a-zA-Z0-9._%+-]+)[>)]")

    for line in lines:
        match = patt.match(line)
        if match:
            name = match.group(1).strip()
            mail = match.group(2).strip().replace("[AT]", "@")
            stdoutu8.write("{},{}\n".format(name, mail))


if __name__ == '__main__':
    main()
