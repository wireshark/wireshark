#!/usr/bin/env python
# Parses the nl80211.h interface and generate appropriate enums and fields
# (value_string) for packet-netlink-nl80211.c
#
# Copyright (c) 2017, Peter Wu <peter@lekensteyn.nl>
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
#
# To update the dissector source file, run this from the source directory:
#
#   python tools/generate-nl80211-fields.py --update
#

import argparse
import re
import requests
import sys

# Begin of comment, followed by the actual array definition
HEADER = "/* Definitions from linux/nl80211.h {{{ */\n"
FOOTER = "/* }}} */\n"
# Enums to extract from the header file
EXPORT_ENUMS = ("nl80211_commands", "nl80211_attrs")
# File to be patched
SOURCE_FILE = "epan/dissectors/packet-netlink-nl80211.c"
# URL where the latest version can be found
URL = "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/include/uapi/linux/nl80211.h"

def make_enum(name, values, indent):
    code = 'enum ws_%s {\n' % name
    for value in values:
        code += '%sWS_%s,\n' % (indent, value)
    code += '};\n'
    return code

def make_value_string(name, values, indent):
    code = 'static const value_string ws_%s_vals[] = {\n' % name
    align = 40
    for value in values:
        code += indent + ('{ WS_%s,' % value).ljust(align - 1) + ' '
        code += '"%s" },\n' % value
    code += '%s{ 0, NULL }\n' % indent
    code += '};\n'
    code += 'static value_string_ext ws_%s_vals_ext =' % name
    code += ' VALUE_STRING_EXT_INIT(ws_%s_vals);\n' % name
    return code

class EnumStore(object):
    def __init__(self, name):
        self.name = name
        self.values = []
        self.active = True

    def update(self, line):
        if not self.active:
            return

        # Skip comments and remove trailing comma
        line = re.sub(r'\s*/\*.*?\*/\s*', '', line).rstrip(",")
        if not line:
            return

        # Try to match a name. Allow aliases only for the previous item.
        m = re.match(r'^(?P<name>\w+)(?: *= *(?P<alias_of>\w+))?$', line)
        assert m, "Failed to find match in %r" % line
        name, alias_of = m.groups()
        if alias_of:
            # Alias must match previous item, skip it otherwise.
            assert alias_of == self.values[-1]
        elif name.startswith("__"):
            # Skip after hitting "__NL80211_CMD_AFTER_LAST"
            self.active = False
        else:
            self.values.append(name)

    def finish(self):
        assert not self.active
        assert self.values
        return self.name, self.values

def parse_header(f):
    enum_store = None
    enums = []
    for line in f:
        line = line.strip()
        if line.startswith("enum "):
            assert not enum_store
            enum_keyword, enum_name, trailer = line.split()
            assert trailer == "{"
            if enum_name in EXPORT_ENUMS:
                enum_store = EnumStore(enum_name)
        elif enum_store:
            if line == "};":
                enums.append(enum_store.finish())
                enum_store = None
            elif line:
                enum_store.update(line)
    return enums

def parse_source():
    """
    Reads the source file and tries to split it in the parts before, inside and
    after the block.
    """
    begin, block, end = '', '', ''
    # Stages: 1 (before block), 2 (in block, skip), 3 (after block)
    stage = 1
    with open(SOURCE_FILE) as f:
        for line in f:
            if line == FOOTER and stage == 2:
                stage = 3   # End of block
            if stage == 1:
                begin += line
                if line == HEADER:
                    stage = 2   # Begin of block
            elif stage == 2:
                block += line
            elif stage == 3:
                end += line
    if stage != 3:
        raise RuntimeError("Could not parse file (in stage %d)" % stage)
    return begin, block, end

parser = argparse.ArgumentParser()
parser.add_argument("--update", action="store_true",
        help="Update %s as needed instead of writing to stdout" % SOURCE_FILE)
parser.add_argument("--indent", default=" " * 4,
        help="indentation (use \\t for tabs, default 4 spaces)")
parser.add_argument("header_file", nargs="?", default=URL,
        help="nl80211.h header file (use - for stdin or a HTTP(S) URL, "
             "default %(default)s)")

def main():
    args = parser.parse_args()

    indent = args.indent.replace("\\t", "\t")

    if any(args.header_file.startswith(proto) for proto in ('http:', 'https')):
        r = requests.get(args.header_file)
        r.raise_for_status()
        enums = parse_header(r.text.splitlines())
    elif args.header_file == "-":
        enums = parse_header(sys.stdin)
    else:
        with open(args.header_file) as f:
            enums = parse_header(f)

    assert len(enums) == len(EXPORT_ENUMS), \
            "Could not parse data, found %d/%d results" % \
            (len(enums), len(EXPORT_ENUMS))

    code_enums, code_vals = '', ''
    for enum_name, enum_values in enums:
        code_enums += make_enum(enum_name, enum_values, indent) + '\n'
        code_vals += make_value_string(enum_name, enum_values, indent) + '\n'

    code = code_enums + code_vals
    code = code.rstrip("\n") + "\n"

    if args.update:
        begin, block, end = parse_source()
        if block == code:
            print("File is up-to-date")
        else:
            with open(SOURCE_FILE, "w") as f:
                f.write(begin)
                f.write(code)
                f.write(end)
            print("Updated %s" % SOURCE_FILE)
    else:
        print(code)

if __name__ == '__main__':
    main()

#
# Editor modelines  -  https://www.wireshark.org/tools/modelines.html
#
# Local variables:
# c-basic-offset: 4
# tab-width: 8
# indent-tabs-mode: nil
# End:
#
# vi: set shiftwidth=4 tabstop=8 expandtab:
# :indentSize=4:tabSize=8:noTabs=true:
#
