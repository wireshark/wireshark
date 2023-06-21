#!/usr/bin/env python3
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
'''\
convert-proto-init.py - Initialize static proto values to 0.
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
            lines = re.sub(rf'(static\s*(?:g?int|expert_field)\s*(?:proto|hf|ett|ei)_[\w_]+)\s*=\s*(?:-1|EI_INIT)\s*', rf'\1', lines, flags=re.MULTILINE)
            # Some dissectors are checking if proto or field is registered.
            lines = re.sub(rf'((?:proto|hf|ett)_[\w_]+)\s*(?:==\s*-1|<\s*0)', rf'\1 <= 0', lines, flags=re.MULTILINE)
            lines = re.sub(rf'((?:proto|hf|ett)_[\w_]+)\s*(?:!=\s*-1|>\s*-1|>=\s*0)', rf'\1 > 0', lines, flags=re.MULTILINE)
    except IsADirectoryError:
        sys.stderr.write(f'{file} is a directory.\n')
        return
    except UnicodeDecodeError:
        sys.stderr.write(f"{file} isn't valid UTF-8.\n")
        return
    except:
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
