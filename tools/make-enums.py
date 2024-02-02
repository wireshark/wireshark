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

def parse_files(infiles, outfile):

    print("Input: {}".format(infiles))
    print("Output: '{}'".format(outfile))

    parser = CParser(infiles)

    source = """\
/*
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Generated automatically from %s. It can be re-created by running
 * "tools/make-enums.py" from the top source directory.
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

static ws_enum_t const all_enums[] = {
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

epan_files = [
    "epan/address.h",
    "epan/ipproto.h",
    "epan/proto.h",
    "epan/ftypes/ftypes.h",
    "epan/stat_groups.h",
]
parse_files(epan_files, "epan/introspection-enums.c")

wtap_files = [
    "wiretap/wtap.h",
]
parse_files(wtap_files, "wiretap/introspection-enums.c")

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
