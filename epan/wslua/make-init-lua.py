#!/usr/bin/env python3
#
# make-init-lua.py
#
# By Gerald Combs <gerald@wireshark.org>
# Based on make-init-lua.pl by Luis E. Garcia Onatnon <luis.ontanon@gmail.com>
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

import argparse
import os
import re

from enum import Enum
from string import Template

def main():
    parser = argparse.ArgumentParser(description="Generate the registration macros for Lua code.")
    parser.add_argument("template", metavar='template', help="template file")
    parser.add_argument("output", metavar='output', help="output file")
    args = parser.parse_args()

    this_dir = os.path.dirname(__file__)
    src_root = os.path.join(this_dir, '..', '..')

    replacements = {
        'WTAP_ENCAPS': '-- Wiretap encapsulations XXX\nwtap_encaps = {',
        'WTAP_TSPRECS': '-- Wiretap timestamp precision types\nwtap_tsprecs = {',
        'WTAP_COMMENT_TYPES': '-- Wiretap file comment types\nwtap_comments = {',
        'WTAP_REC_TYPES': '-- Wiretap record_types\nwtap_rec_types = {',
        'WTAP_PRESENCE_FLAGS': '-- Wiretap presence flags\nwtap_presence_flags = {',
    }

    with open(args.template, encoding='utf-8') as tmpl_f:
        template = Template(tmpl_f.read())

    wtap_encaps = []
    wtap_tsprecs = []
    wtap_comment_types = []
    wtap_rec_types = []
    wtap_presence_flags = []
    with open(os.path.join(src_root, 'wiretap', 'wtap.h'), encoding='utf-8') as wtap_f:
        for line in wtap_f:
            m = re.search(r'#define WTAP_ENCAP_([A-Z0-9_]+)\s+(-?\d+)', line)
            if m:
                wtap_encaps.append(f'\n\t["{m.group(1)}"] = {m.group(2)}')

            m = re.search(r'#define WTAP_TSPREC_([A-Z0-9_]+)\s+(\d+)', line)
            if m:
                wtap_tsprecs.append(f'\n\t["{m.group(1)}"] = {m.group(2)}')

            m = re.search(r'#define WTAP_COMMENT_([A-Z0-9_]+)\s+(0x\d+)', line)
            if m:
                wtap_comment_types.append(f'\n\t["{m.group(1)}"] = {m.group(2)}')

            m = re.search(r'#define REC_TYPE_([A-Z0-9_]+)\s+(\d+)\s+\/\*\*<([^\*]+)\*\/', line)
            if m:
                wtap_rec_types.append(f'\n\t["{m.group(1)}"] = {m.group(2)},  --{m.group(3)}')

            m = re.search(r'#define WTAP_HAS_([A-Z0-9_]+)\s+(0x\d+)\s+\/\*\*<([^\*]+)\*\/', line)
            if m:
                wtap_presence_flags.append(f'\n\t["{m.group(1)}"] = {int(m.group(2), 16)},  --{m.group(3)}')

    replacements['WTAP_ENCAPS'] += ','.join(wtap_encaps) + '\n}\nwtap = wtap_encaps -- for bw compatibility\n'
    replacements['WTAP_TSPRECS'] += ','.join(wtap_tsprecs) + '\n}\n'
    replacements['WTAP_COMMENT_TYPES'] += ','.join(wtap_comment_types) + '\n}\n'
    replacements['WTAP_REC_TYPES'] += ''.join(wtap_rec_types) + '\n}\n'
    replacements['WTAP_PRESENCE_FLAGS'] += ''.join(wtap_presence_flags) + '\n}\n'

    with open(args.output, mode='w', encoding='utf-8') as out_f:
        out_f.write(template.substitute(replacements))


if __name__ == '__main__':
    main()
