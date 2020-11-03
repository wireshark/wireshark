#!/usr/bin/env python3
#
# Looks for registration routines in the plugins
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
# The second argument is either "plugin", "plugin_wtap" or "plugin_codec".
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
        'codec_register': set(),
        }

# For those that don't know Python, r"" indicates a raw string,
# devoid of Python escapes.
proto_regex = r"\bproto_register_(?P<symbol>[_A-Za-z0-9]+)\s*\(\s*void\s*\)[^;]*$"

handoff_regex = r"\bproto_reg_handoff_(?P<symbol>[_A-Za-z0-9]+)\s*\(\s*void\s*\)[^;]*$"

wtap_reg_regex = r"\bwtap_register_(?P<symbol>[_A-Za-z0-9]+)\s*\([^;]+$"

codec_reg_regex = r"\bcodec_register_(?P<symbol>[_A-Za-z0-9]+)\s*\([^;]+$"

# This table drives the pattern-matching and symbol-harvesting
patterns = [
        ( 'proto_reg', re.compile(proto_regex, re.MULTILINE) ),
        ( 'handoff_reg', re.compile(handoff_regex, re.MULTILINE) ),
        ( 'wtap_register', re.compile(wtap_reg_regex, re.MULTILINE) ),
        ( 'codec_register', re.compile(codec_reg_regex, re.MULTILINE) ),
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
if (len(regs['proto_reg']) < 1 and len(regs['wtap_register']) < 1 and len(regs['codec_register']) < 1):
    print("No plugin registrations found")
    sys.exit(1)

# Convert the sets into sorted lists to make the output pretty
regs['proto_reg'] = sorted(regs['proto_reg'])
regs['handoff_reg'] = sorted(regs['handoff_reg'])
regs['wtap_register'] = sorted(regs['wtap_register'])
regs['codec_register'] = sorted(regs['codec_register'])

reg_code = ""

reg_code += preamble

reg_code += """
#include "config.h"

#include <gmodule.h>

/* plugins are DLLs */
#define WS_BUILD_DLL
#include "ws_symbol_export.h"

"""

if registertype == "plugin":
    reg_code += "#include \"epan/proto.h\"\n\n"
if registertype == "plugin_wtap":
    reg_code += "#include \"wiretap/wtap.h\"\n\n"
if registertype == "plugin_codec":
    reg_code += "#include \"wsutil/codecs.h\"\n\n"

for symbol in regs['proto_reg']:
    reg_code += "void proto_register_%s(void);\n" % (symbol)
for symbol in regs['handoff_reg']:
    reg_code += "void proto_reg_handoff_%s(void);\n" % (symbol)
for symbol in regs['wtap_register']:
    reg_code += "void wtap_register_%s(void);\n" % (symbol)
for symbol in regs['codec_register']:
    reg_code += "void codec_register_%s(void);\n" % (symbol)

reg_code += """
WS_DLL_PUBLIC_DEF const gchar plugin_version[] = PLUGIN_VERSION;
WS_DLL_PUBLIC_DEF const int plugin_want_major = VERSION_MAJOR;
WS_DLL_PUBLIC_DEF const int plugin_want_minor = VERSION_MINOR;

WS_DLL_PUBLIC void plugin_register(void);

void plugin_register(void)
{
"""

if registertype == "plugin":
    for symbol in regs['proto_reg']:
        reg_code +="    static proto_plugin plug_%s;\n\n" % (symbol)
        reg_code +="    plug_%s.register_protoinfo = proto_register_%s;\n" % (symbol, symbol)
        if symbol in regs['handoff_reg']:
            reg_code +="    plug_%s.register_handoff = proto_reg_handoff_%s;\n" % (symbol, symbol)
        else:
            reg_code +="    plug_%s.register_handoff = NULL;\n" % (symbol)
        reg_code += "    proto_register_plugin(&plug_%s);\n" % (symbol)
if registertype == "plugin_wtap":
    for symbol in regs['wtap_register']:
        reg_code += "    static wtap_plugin plug_%s;\n\n" % (symbol)
        reg_code += "    plug_%s.register_wtap_module = wtap_register_%s;\n" % (symbol, symbol)
        reg_code += "    wtap_register_plugin(&plug_%s);\n" % (symbol)
if registertype == "plugin_codec":
    for symbol in regs['codec_register']:
        reg_code += "    static codecs_plugin plug_%s;\n\n" % (symbol)
        reg_code += "    plug_%s.register_codec_module = codec_register_%s;\n" % (symbol, symbol)
        reg_code += "    codecs_register_plugin(&plug_%s);\n" % (symbol)

reg_code += "}\n"

try:
    fh = open(final_filename, 'w')
    fh.write(reg_code)
    fh.close()
    print('Generated {} for {}.'.format(final_filename, os.path.basename(srcdir)))
except OSError:
    sys.exit('Unable to write ' + final_filename + '.\n')

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
