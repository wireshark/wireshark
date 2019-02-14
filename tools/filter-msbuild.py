#!/usr/bin/env python
# Reduce msbuild output by folding unimportant messages.
#
# Copyright (C) 2019 Peter Wu <peter@lekensteyn.nl>
# SPDX-License-Identifier: GPL-2.0-or-later

import sys


# If an important message is present, print it with a newline.
# Otherwise skip the newline but print the next line with a carriage return.
# If the end of build is reached, just print the trailing messages (includes
# elapsed time, warning/error counts, etc.).

start_of_line = ''
end_of_build = False
for line in sys.stdin:
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
