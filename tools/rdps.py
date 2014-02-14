#!/usr/bin/env python
#
# rdps.py
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
        elif c == '%':
            ps_str += '%%'
        elif c == '\n':
            ps_str += '\\n'
        else:
            ps_str += c
    return ps_str

def start_code(fd, func):
    script_name = os.path.split(__file__)[-1]
    fd.write("void print_ps_%s(FILE *fd) {\n" % func)

def write_code(fd, raw_str):
    ps_str = ps_clean_string(raw_str)
    fd.write("\tfprintf(fd, \"%s\");\n" % ps_str)

def end_code(fd):
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
    state = STATE_NULL;

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
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <stdio.h>

#include "ps.h"

''' % script_name)

    for line in input:
        #line = line.rstrip()
        if state is STATE_NULL:
            if line.startswith("% ---- wireshark preamble start ---- %"):
                state = STATE_PREAMBLE
                start_code(output, "preamble")
                continue
            elif line.startswith("% ---- wireshark finale start ---- %"):
                state = STATE_FINALE
                start_code(output, "finale")
                continue
        elif state is STATE_PREAMBLE:
            if line.startswith("% ---- wireshark preamble end ---- %"):
                state = STATE_NULL
                end_code(output)
                continue
            else:
                write_code(output, line)
        elif state is STATE_FINALE:
            if line.startswith("% ---- wireshark finale end ---- %"):
                state = STATE_NULL
                end_code(output)
                continue
            else:
                write_code(output, line)
        else:
            exit_err("NO MATCH:%s", line)

    sys.exit(0)

if __name__ == "__main__":
    main()

#
# Editor modelines  -  http://www.wireshark.org/tools/modelines.html
#
# Local variables:
# c-basic-offset: 4
# indent-tabs-mode: nil
# End:
#
# vi: set shiftwidth=4 expandtab:
# :indentSize=4:noTabs=true:
#
