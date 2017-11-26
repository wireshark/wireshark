#!/usr/bin/env python
#
# Looks for registration routines in the plugin dissectors,
# and assembles C code to call all the routines.
#

import os
import sys
import re

#
# The first argument is the directory in which the source files live.
#
srcdir = sys.argv[1]
#
# The second argument is either "plugin" or "plugin_wtap".
#
registertype = sys.argv[2]
#
# All subsequent arguments are the files to scan.
#
files = sys.argv[3:]

final_filename = "plugin.c"
preamble = """\
/*
 * Do not modify this file. Changes will be overwritten.
 *
 * Generated automatically from %s.
 */
""" % (sys.argv[0])

# Create the proper list of filenames
filenames = []
for file in files:
    if os.path.isfile(file):
        filenames.append(file)
    else:
        filenames.append(os.path.join(srcdir, file))

if len(filenames) < 1:
    print("No files found")
    sys.exit(1)


# Look through all files, applying the regex to each line.
# If the pattern matches, save the "symbol" section to the
# appropriate set.
regs = {
        'proto_reg': set(),
        'handoff_reg': set(),
        'wtap_register': set(),
        }

# For those that don't know Python, r"" indicates a raw string,
# devoid of Python escapes.
proto_regex = r"(?P<symbol>\bproto_register_[_A-Za-z0-9]+)\s*\(\s*void\s*\)[^;]*$"

handoff_regex = r"(?P<symbol>\bproto_reg_handoff_[_A-Za-z0-9]+)\s*\(\s*void\s*\)[^;]*$"

wtap_reg_regex = r"(?P<symbol>\bwtap_register_[_A-Za-z0-9]+)\s*\([^;]+$"

# This table drives the pattern-matching and symbol-harvesting
patterns = [
        ( 'proto_reg', re.compile(proto_regex, re.MULTILINE) ),
        ( 'handoff_reg', re.compile(handoff_regex, re.MULTILINE) ),
        ( 'wtap_register', re.compile(wtap_reg_regex, re.MULTILINE) ),
        ]

# Grep
for filename in filenames:
    file = open(filename)
    # Read the whole file into memory
    contents = file.read()
    for action in patterns:
        regex = action[1]
        for match in regex.finditer(contents):
            symbol = match.group("symbol")
            sym_type = action[0]
            regs[sym_type].add(symbol)
    # We're done with the file contents
    del contents
    file.close()

# Make sure we actually processed something
if len(regs['proto_reg']) < 1:
    print("No protocol registrations found")
    sys.exit(1)

# Convert the sets into sorted lists to make the output pretty
regs['proto_reg'] = sorted(regs['proto_reg'])
regs['handoff_reg'] = sorted(regs['handoff_reg'])
regs['wtap_register'] = sorted(regs['wtap_register'])

reg_code = ""

reg_code += preamble

reg_code += """
#include "config.h"

#include <gmodule.h>

#include "moduleinfo.h"

/* plugins are DLLs */
#define WS_BUILD_DLL
#include "ws_symbol_export.h"

WS_DLL_PUBLIC_DEF void plugin_register (void);

WS_DLL_PUBLIC_DEF const gchar plugin_version[] = VERSION;
WS_DLL_PUBLIC_DEF const gchar plugin_release[] = VERSION_RELEASE;

"""

for symbol in regs['proto_reg']:
    reg_code += "extern void %s(void);\n" % (symbol)

reg_code += """
WS_DLL_PUBLIC_DEF void
plugin_register (void)
{
"""

for symbol in regs['proto_reg']:
    reg_code += "    %s();\n" % (symbol)

reg_code += "}\n\n"

for symbol in regs['handoff_reg']:
    reg_code += "extern void %s(void);\n" % (symbol)

reg_code += """
WS_DLL_PUBLIC_DEF void plugin_reg_handoff(void);

WS_DLL_PUBLIC_DEF void
plugin_reg_handoff(void)
{
"""

for symbol in regs['handoff_reg']:
    reg_code += "    %s();\n" % (symbol)
reg_code += "}\n"

if registertype == "plugin_wtap":
    reg_code += """
WS_DLL_PUBLIC_DEF void
register_wtap_module(void)
{
"""

    for symbol in regs['wtap_register']:
        reg_code += "    {extern void %s (void); %s ();}\n" % (symbol, symbol)
    reg_code += "}"

try:
    print(('Updating ' + final_filename))
    fh = open(final_filename, 'w')
    fh.write(reg_code)
    fh.close()
except OSError:
    sys.exit('Unable to write ' + final_filename + '.\n')

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
