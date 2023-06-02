#!/usr/bin/env python3
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
'''\
convert-glib-types.py - Convert glib types to their C and C99 eqivalents.
'''

# Imports

import argparse
import re
import sys

type_map = {
    'gboolean': 'bool',
    'gchar': 'char',
    'gint': 'int',
    'guint': 'unsigned', # Matches README.developer
    'gint8': 'int8_t',
    'gint16': 'int16_t',
    'gint32': 'int32_t',
    'gint64': 'int64_t',
    'guint8': 'uint8_t',
    'guint16': 'uint16_t',
    'guint32': 'uint32_t',
    'guint64': 'uint64_t',
    'gfloat': 'float',
    'gdouble': 'double',
    'gpointer': 'void *',
    # Is gsize the same as size_t on the platforms we support?
    # https://gitlab.gnome.org/GNOME/glib/-/issues/2493
    'gsize': 'size_t',
    'gssize': 'ssize_t',

    'TRUE': 'true',
    'FALSE': 'false',
}

def convert_file(file):
    lines = ''
    with open(file, 'r') as f:
        lines = f.read()
        for glib_type, c99_type in type_map.items():
            lines = re.sub(rf'([^"])\b{glib_type}\b([^"])', rf'\1{c99_type}\2', lines, flags=re.MULTILINE)
    with open(file, 'w') as f:
        f.write(lines)
    print(f'Converted {file}')

def main():
    parser = argparse.ArgumentParser(description='Convert glib types to their C and C99 eqivalents.')
    parser.add_argument('files', metavar='FILE', nargs='*')
    args = parser.parse_args()

    for file in args.files:
        convert_file(file)

# On with the show

if __name__ == "__main__":
    sys.exit(main())
