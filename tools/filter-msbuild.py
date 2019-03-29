#!/usr/bin/env python
# Reduce msbuild output by folding unimportant messages.
#
# Copyright (C) 2019 Peter Wu <peter@lekensteyn.nl>
# SPDX-License-Identifier: GPL-2.0-or-later

import subprocess
import sys


def print_lines(f):
    # If an important message is present, print it with a newline.
    # Otherwise skip the newline but print the next line with a carriage return.
    # If the end of build is reached, just print the trailing messages (includes
    # elapsed time, warning/error counts, etc.).

    start_of_line = ''
    end_of_build = False
    for line in iter(f.readline, ''):
        line = line.rstrip('\r\n')

        if line.startswith('Build succeeded.'):
            end_of_build = True
        is_important = end_of_build or any([
            ': error ' in line,
            ': warning ' in line,
            '-- FAILED.' in line,
        ])

        if is_important:
            eol = '\n'
            if start_of_line == '\r':
                start_of_line = '\n'
        else:
            eol = ''

        sys.stdout.write("%s%s%s" % (start_of_line, line, eol))
        sys.stdout.flush()

        if is_important:
            start_of_line = ''
        else:
            start_of_line = '\r'

    # If the last line was not important, its LF was omitted so print it.
    if not is_important:
        sys.stdout.write('\n')


command = sys.argv[1:]
if command:
    # Execute the given command and parse its output.
    proc = subprocess.Popen(command,
                            bufsize=1,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT,
                            universal_newlines=True
                            )
    try:
        print_lines(proc.stdout)
    finally:
        sys.exit(proc.wait())
else:
    # Assume a file read from stdin.
    print_lines(sys.stdin)
