#!/usr/bin/env python3
#
# rdps.py
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

'''\
takes the file listed as the first argument and creates the file listed
as the second argument. It takes a PostScript file and creates a C source
with 2 functions:
	print_ps_preamble()
	print_ps_finale()

Ported to Python from rdps.c.
'''

import sys
import os.path


def ps_clean_string(raw_str):
    ps_str = ''
    for c in raw_str:
        if c == '\\':
            ps_str += '\\\\'
        elif c == '\n':
            ps_str += '\\n'
        else:
            ps_str += c
    return ps_str


def start_code(fd, name):
    fd.write("static const char ps_%s[] =\n" % name)
    

def write_code(fd, raw_str):
    ps_str = ps_clean_string(raw_str)
    fd.write("\t\"%s\"\n" % ps_str)


def end_code(fd, name):
    fd.write(";\n")
    fd.write("\n")
    fd.write("void print_ps_%s(FILE *fd) {\n" % name)
    fd.write("\tfwrite(ps_%s, sizeof ps_%s - 1, 1, fd);\n" % ( name, name ) )
    fd.write("}\n\n\n")


def exit_err(msg=None, *param):
    if msg is not None:
        sys.stderr.write(msg % param)
    sys.exit(1)


# Globals
STATE_NULL = 'null'
STATE_PREAMBLE = 'preamble'
STATE_FINALE = 'finale'


def main():
    state = STATE_NULL

    if len(sys.argv) != 3:
        exit_err("%s: input_file output_file\n", __file__)

    input = open(sys.argv[1], 'r')
    output = open(sys.argv[2], 'w')

    script_name = os.path.split(__file__)[-1]

    output.write('''\
/* DO NOT EDIT
 *
 * Created by %s.
 *
 * ps.c
 * Definitions for generating PostScript(R) packet output.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <stdio.h>

#include "ps.h"

''' % script_name)

    for line in input:
        #line = line.rstrip()
        if state == STATE_NULL:
            if line.startswith("% ---- wireshark preamble start ---- %"):
                state = STATE_PREAMBLE
                start_code(output, "preamble")
                continue
            elif line.startswith("% ---- wireshark finale start ---- %"):
                state = STATE_FINALE
                start_code(output, "finale")
                continue
        elif state == STATE_PREAMBLE:
            if line.startswith("% ---- wireshark preamble end ---- %"):
                state = STATE_NULL
                end_code(output, "preamble")
                continue
            else:
                write_code(output, line)
        elif state == STATE_FINALE:
            if line.startswith("% ---- wireshark finale end ---- %"):
                state = STATE_NULL
                end_code(output, "finale")
                continue
            else:
                write_code(output, line)
        else:
            exit_err("NO MATCH:%s", line)

    sys.exit(0)

if __name__ == "__main__":
    main()

#
# Editor modelines  -  https://www.wireshark.org/tools/modelines.html
#
# Local variables:
# c-basic-offset: 4
# indent-tabs-mode: nil
# End:
#
# vi: set shiftwidth=4 expandtab:
# :indentSize=4:noTabs=true:
#
