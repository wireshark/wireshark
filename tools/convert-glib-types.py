#!/usr/bin/env python3
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
'''\
convert-glib-types.py - Convert glib types to their C and C99 equivalents.
'''

# Imports

import argparse
import glob
import platform
import re
import sys

padded_type_map = {}

type_map = {
    'gboolean': 'bool',
    'gchar': 'char',
    'guchar': 'unsigned char',
    'gint': 'int',
    'guint': 'unsigned', # Matches README.developer
    # Our remaining glong instances probably shouldn't be converted, e.g.
    # sequence_analysis.c:350
    # 'glong': 'long',
    'gulong': 'unsigned long',
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
    'gpointer ': 'void *', # 'void *foo' instead of 'void * foo'
    'gpointer': 'void *',
    'gconstpointer ': 'const void *', # 'void *foo' instead of 'void * foo'
    'gconstpointer': 'const void *',
    # Is gsize the same as size_t on the platforms we support?
    # https://gitlab.gnome.org/GNOME/glib/-/issues/2493
    'gsize': 'size_t',
    'gssize': 'ssize_t',
}

definition_map = {
    'G_MAXINT8': 'INT8_MAX',
    'G_MAXINT16': 'INT16_MAX',
    'G_MAXINT32': 'INT32_MAX',
    'G_MAXINT64': 'INT64_MAX',
    'G_MAXINT': 'INT_MAX',
    'G_MAXUINT8': 'UINT8_MAX',
    'G_MAXUINT16': 'UINT16_MAX',
    'G_MAXUINT32': 'UINT32_MAX',
    'G_MAXUINT64': 'UINT64_MAX',
    'G_MAXUINT': 'UINT_MAX',
    'G_MININT8': 'INT8_MIN',
    'G_MININT16': 'INT16_MIN',
    'G_MININT32': 'INT32_MIN',
    'G_MININT64': 'INT64_MIN',
    'G_MININT': 'INT_MIN',
    'G_MINFLOAT': 'FLT_MIN',
    'G_MAXFLOAT': 'FLT_MAX',
    'G_MINDOUBLE': 'DBL_MIN',
    'G_MAXDOUBLE': 'DBL_MAX',
    'G_GINT64_CONSTANT': 'INT64_C',
    'G_GUINT64_CONSTANT': 'UINT64_C',
}

tf_definition_map = {
    'TRUE': 'true',
    'FALSE': 'false',
}

format_spec_map = {
    'G_GINT64_FORMAT': 'PRId64',
    'G_GUINT64_FORMAT': 'PRIu64',
}

tvb_api_map = {
    'tvb_get_guint8': 'tvb_get_uint8',
    'tvb_get_gint8': 'tvb_get_int8',
    'tvb_get_guint16': 'tvb_get_uint16',
    'tvb_get_gint16': 'tvb_get_int16',
    'tvb_get_guint24': 'tvb_get_uint24',
    'tvb_get_gint24': 'tvb_get_int24',
    'tvb_get_guint32': 'tvb_get_uint32',
    'tvb_get_gint32': 'tvb_get_int32',
    'tvb_get_guint40': 'tvb_get_uint40',
    'tvb_get_gint40': 'tvb_get_int40',
    'tvb_get_guint48': 'tvb_get_uint48',
    'tvb_get_gint48': 'tvb_get_int48',
    'tvb_get_guint56': 'tvb_get_uint56',
    'tvb_get_gint56': 'tvb_get_int56',
    'tvb_get_guint64': 'tvb_get_uint64',
    'tvb_get_gint64': 'tvb_get_int64',
}

def convert_file(file):
    lines = ''
    try:
        with open(file, 'r') as f:
            lines = f.read()
            for glib_type, c99_type in padded_type_map.items():
                lines = lines.replace(glib_type, c99_type)
            for glib_type, c99_type in type_map.items():
                lines = re.sub(rf'([^"])\b{glib_type}\b([^"])', rf'\1{c99_type}\2', lines, flags=re.MULTILINE)
            for glib_define, c99_define in definition_map.items():
                lines = re.sub(rf'\b{glib_define}\b', rf'{c99_define}', lines, flags=re.MULTILINE)
            for glib_tf_define, c99_define in tf_definition_map.items():
                lines = re.sub(rf'\b{glib_tf_define}\b([^\'"])', rf'{c99_define}\1', lines, flags=re.MULTILINE)
            for glib_fmt_spec, c99_fmt_spec in format_spec_map.items():
                lines = re.sub(rf'\b{glib_fmt_spec}\b', rf'{c99_fmt_spec}', lines, flags=re.MULTILINE)
            for glib_api, c99_api in tvb_api_map.items():
                lines = re.sub(rf'\b{glib_api}\b', rf'{c99_api}', lines, flags=re.MULTILINE)
    except IsADirectoryError:
        sys.stderr.write(f'{file} is a directory.\n')
        return
    except UnicodeDecodeError:
        sys.stderr.write(f"{file} isn't valid UTF-8.\n")
        return
    except Exception:
        sys.stderr.write(f'Unable to open {file}.\n')
        return

    with open(file, 'w') as f:
        f.write(lines)
    print(f'Converted {file}')

def main():
    parser = argparse.ArgumentParser(description='Convert glib types to their C and C99 equivalents.')
    parser.add_argument('files', metavar='FILE', nargs='*')
    args = parser.parse_args()

    # Build a padded version of type_map which attempts to preserve alignment
    for glib_type, c99_type in type_map.items():
        pg_type = glib_type + '  '
        pc_type = c99_type + ' '
        pad_len = max(len(pg_type), len(pc_type))
        padded_type_map[f'{pg_type:{pad_len}s}'] = f'{pc_type:{pad_len}s}'

    files = []
    if platform.system() == 'Windows':
        for arg in args.files:
            files += glob.glob(arg)
    else:
        files = args.files

    for file in files:
        convert_file(file)

# On with the show

if __name__ == "__main__":
    sys.exit(main())
