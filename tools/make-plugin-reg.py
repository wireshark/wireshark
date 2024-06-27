#!/usr/bin/env python3
#
# Looks for registration routines in the plugins
# and assembles C code to call all the routines.
# A new "plugin.c" file will be written in the current directory.
#

import os
import sys
import re

#
# The first argument is the directory in which the source files live.
#
srcdir = sys.argv[1]
#
# The second argument is either "plugin", "plugin_wtap", "plugin_codec",
# or "plugin_tap".
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
""" % (os.path.basename(sys.argv[0]))

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
        'register_tap_listener': set(),
        }

# For those that don't know Python, r"" indicates a raw string,
# devoid of Python escapes.
proto_regex = r"\bproto_register_(?P<symbol>[\w]+)\s*\(\s*void\s*\)\s*{"

handoff_regex = r"\bproto_reg_handoff_(?P<symbol>[\w]+)\s*\(\s*void\s*\)\s*{"

wtap_reg_regex = r"\bwtap_register_(?P<symbol>[\w]+)\s*\(\s*void\s*\)\s*{"

codec_reg_regex = r"\bcodec_register_(?P<symbol>[\w]+)\s*\(\s*void\s*\)\s*{"

tap_reg_regex = r"\bregister_tap_listener_(?P<symbol>[\w]+)\s*\(\s*void\s*\)\s*{"

# This table drives the pattern-matching and symbol-harvesting
patterns = [
        ( 'proto_reg', re.compile(proto_regex, re.MULTILINE | re.ASCII) ),
        ( 'handoff_reg', re.compile(handoff_regex, re.MULTILINE | re.ASCII) ),
        ( 'wtap_register', re.compile(wtap_reg_regex, re.MULTILINE | re.ASCII) ),
        ( 'codec_register', re.compile(codec_reg_regex, re.MULTILINE | re.ASCII) ),
        ( 'register_tap_listener', re.compile(tap_reg_regex, re.MULTILINE | re.ASCII) ),
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
if (len(regs['proto_reg']) < 1 and len(regs['wtap_register']) < 1 and len(regs['codec_register']) < 1 and len(regs['register_tap_listener']) < 1):
    print("No plugin registrations found")
    sys.exit(1)

# Convert the sets into sorted lists to make the output pretty
regs['proto_reg'] = sorted(regs['proto_reg'])
regs['handoff_reg'] = sorted(regs['handoff_reg'])
regs['wtap_register'] = sorted(regs['wtap_register'])
regs['codec_register'] = sorted(regs['codec_register'])
regs['register_tap_listener'] = sorted(regs['register_tap_listener'])

reg_code = ""

reg_code += preamble

reg_code += """
#include "config.h"

#include <gmodule.h>

/* plugins are DLLs on Windows */
#define WS_BUILD_DLL
#include "ws_symbol_export.h"
#include <wsutil/plugins.h>

"""

if registertype == "plugin":
    reg_code += "#include \"epan/proto.h\"\n\n"
if registertype == "plugin_wtap":
    reg_code += "#include \"wiretap/wtap.h\"\n\n"
if registertype == "plugin_codec":
    reg_code += "#include \"wsutil/codecs.h\"\n\n"
if registertype == "plugin_tap":
    reg_code += "#include \"epan/tap.h\"\n\n"

for symbol in regs['proto_reg']:
    reg_code += "void proto_register_%s(void);\n" % (symbol)
for symbol in regs['handoff_reg']:
    reg_code += "void proto_reg_handoff_%s(void);\n" % (symbol)
for symbol in regs['wtap_register']:
    reg_code += "void wtap_register_%s(void);\n" % (symbol)
for symbol in regs['codec_register']:
    reg_code += "void codec_register_%s(void);\n" % (symbol)
for symbol in regs['register_tap_listener']:
    reg_code += "void register_tap_listener_%s(void);\n" % (symbol)

DESCRIPTION_FLAG = {
    'plugin': 'WS_PLUGIN_DESC_DISSECTOR',
    'plugin_wtap': 'WS_PLUGIN_DESC_FILE_TYPE',
    'plugin_codec': 'WS_PLUGIN_DESC_CODEC',
    'plugin_tap': 'WS_PLUGIN_DESC_TAP_LISTENER'
}

reg_code += """
WS_DLL_PUBLIC_DEF const char plugin_version[] = PLUGIN_VERSION;
WS_DLL_PUBLIC_DEF const int plugin_want_major = VERSION_MAJOR;
WS_DLL_PUBLIC_DEF const int plugin_want_minor = VERSION_MINOR;

WS_DLL_PUBLIC void plugin_register(void);
WS_DLL_PUBLIC uint32_t plugin_describe(void);

uint32_t plugin_describe(void)
{
    return %s;
}

void plugin_register(void)
{
""" % DESCRIPTION_FLAG[registertype]

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
if registertype == "plugin_tap":
    for symbol in regs['register_tap_listener']:
        reg_code += "    static tap_plugin plug_%s;\n\n" % (symbol)
        reg_code += "    plug_%s.register_tap_listener = register_tap_listener_%s;\n" % (symbol, symbol)
        reg_code += "    tap_register_plugin(&plug_%s);\n" % (symbol)

reg_code += "}\n"

try:
    fh = open(final_filename, 'w')
    fh.write(reg_code)
    fh.close()
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
