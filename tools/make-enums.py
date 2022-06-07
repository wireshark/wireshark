#!/usr/bin/env python3
#
# Copyright 2021, João Valverde <j@v6e.pt>
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
#
# Uses pyclibrary to parse C headers for enums and integer macro
# definitions. Exports that data to a C file for the introspection API.
#
# Requires: https://github.com/MatthieuDartiailh/pyclibrary
#

import os
import sys
import argparse
from pyclibrary import CParser

default_infiles = [
    "epan/address.h",
    "epan/ipproto.h",
    "epan/proto.h",
    "epan/ftypes/ftypes.h",
]

default_outfile = "epan/introspection-enums.c"

argp = argparse.ArgumentParser()
argp.add_argument("-o", "--outfile")
argp.add_argument("infiles", nargs="*")
args = argp.parse_args()

if args.infiles:
    infiles = args.infiles
else:
    infiles = default_infiles

if args.outfile:
    outfile = args.outfile
else:
    outfile = default_outfile

print("input: {}".format(infiles))
print("output: {}".format(outfile))

parser = CParser(infiles)

source = """\
/*
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Generated automatically from %s.
 *
 * It can be re-created using "make gen-enums".
 *
 * It is fine to edit this file by hand. Particularly if a symbol
 * disappears from the API it can just be removed here. There is no
 * requirement to re-run the generator script.
 *
 */
""" % (os.path.basename(sys.argv[0]))

for f in infiles:
    source += '#include <{}>\n'.format(f)

source += """
#define ENUM(arg) { #arg, arg }

static ws_enum_t all_enums[] = {
"""

definitions = parser.defs['values']
symbols = list(definitions.keys())
symbols.sort()

for s in symbols:
    if isinstance(definitions[s], int):
        source += '    ENUM({}),\n'.format(s)

source += """\
    { NULL, 0 },
};
"""

try:
    fh = open(outfile, 'w')
except OSError:
    sys.exit('Unable to write ' + outfile + '.\n')

fh.write(source)
fh.close()


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
