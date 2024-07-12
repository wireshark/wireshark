#!/usr/bin/env python3
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
'''\
convert-proto-init.py - Remove explicit init of proto variables.
'''

# Imports

import argparse
import glob
import platform
import re
import sys

def convert_file(file):
    lines = ''
    try:
        with open(file, 'r') as f:
            lines = f.read()
            # Match the following proto, header field, expert info and subtree variables:
            #
            # static int proto_a = -1;
            # int proto_b=-1;
            #
            # static int hf_proto_a_value_1     = -1;
            #        int hf_proto_a_value_2     = - 1;
            # int hf_proto_a_value_3=-1;
            # /* static int hf_proto_a_unused_1   = -1; */
            #
            # static gint ett_proto_a_tree_1=-1;
            # gint ett_proto_a_tree_2 = -1; /* A comment. */
            #
            # static expert_field ei_proto_a_expert_1 = EI_INIT;
            #
            lines = re.sub(r'^((?://\s*|/[*]+\s*)?(?:static\s*|       )?(?:g?int|expert_field)\s*(?:proto|hf|ett|ei)_[\w_]+)\s*=\s*(?:-\s*1|EI_INIT)\s*', r'\1', lines, flags=re.MULTILINE)
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
    parser = argparse.ArgumentParser(description='Initialize static proto values to 0.')
    parser.add_argument('files', metavar='FILE', nargs='*')
    args = parser.parse_args()

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
