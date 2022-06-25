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

class ExpertState(Enum):
    NONE = 0
    IN_GROUP = 1
    IN_SEVERITY = 2

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
        'FT_TYPES': '-- Field Types\nftypes = {',
        'FT_FRAME_TYPES': '-- Field Type FRAMENUM Types\nframetype = {',
        'WTAP_REC_TYPES': '-- Wiretap record_types\nwtap_rec_types = {',
        'WTAP_PRESENCE_FLAGS': '-- Wiretap presence flags\nwtap_presence_flags = {',
        'BASES': '-- Display Bases\nbase = {',
        'ENCODINGS': '-- Encodings',
        'EXPERT': '-- Expert flags and facilities (deprecated - see \'expert\' table below)',
        'EXPERT_TABLE': '-- Expert flags and facilities\nexpert = {',
        'MENU_GROUPS': '-- menu groups for register_menu',
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

    frametypes = []
    ftypes = []
    with open(os.path.join(src_root, 'epan', 'ftypes', 'ftypes.h'), encoding='utf-8') as ftypes_f:
        for line in ftypes_f:
            m = re.match(r'\s+FT_FRAMENUM_([A-Z0-9a-z_]+)\s*,', line)
            if m:
                idx = len(frametypes)
                frametypes.append(f'\n\t["{m.group(1)}"] = {idx}');
                continue

            m = re.match(r'\s+FT_([A-Z0-9a-z_]+)\s*,', line)
            if m:
                idx = len(ftypes)
                ftypes.append(f'\n\t["{m.group(1)}"] = {idx}');

    replacements['FT_TYPES'] += ','.join(ftypes) + '\n}\n'
    replacements['FT_FRAME_TYPES'] += ','.join(frametypes) + '\n}\n'


    bases = []
    encodings = []
    expert = []
    expert_group = []
    expert_severity = []
    expert_state = ExpertState.NONE
    prev_comment = ''
    with open(os.path.join(src_root, 'epan', 'proto.h'), encoding='utf-8') as proto_f:
        for line in proto_f:
            skip_this = False

            m = re.match(r'\s+(?:BASE|SEP|ABSOLUTE_TIME)_([A-Z_]+)[ ]*=[ ]*([0-9]+)[,\s]+(?:\/\*\*< (.*?) \*\/)?', line)
            if m:
                bases.append(f'\n\t["{m.group(1)}"] = {m.group(2)},  -- {m.group(3)}')

            m = re.match(r'#define\s+BASE_(RANGE_STRING)[ ]*((?:0x)?[0-9]+)[ ]+(?:\/\*\*< (.*?) \*\/)?', line)
            if m:
                # Handle BASE_RANGE_STRING
                bases.append(f'\n\t["{m.group(1)}"] = {int(m.group(2), 16)},  -- {m.group(3)}')

            m = re.match(r'^#define\s+BASE_(UNIT_STRING)[ ]*((?:0x)?[0-9]+)[ ]+(?:\/\*\*< (.*?) \*\/)?', line)
            if m:
                # Handle BASE_UNIT_STRING as a valid base value in Lua
                bases.append(f'\n\t["{m.group(1)}"] = {int(m.group(2), 16)},  -- {m.group(3)}')

            if re.match(r'#define\s+PI_GROUP_MASK ', line):
                expert_state = ExpertState.IN_GROUP
                skip_this = True

            if re.match(r'.define\s+PI_SEVERITY_MASK ', line):
                expert_state = ExpertState.IN_SEVERITY
                skip_this = True

            m = re.search(r'/\*\* (.*?) \*\/', line)
            if m:
                prev_comment = m.group(1)

            m = re.match(r'#define\s+(PI_([A-Z_]+))\s+((0x)?[0-9A-Fa-f]+)', line)
            if m:
                name = m.group(1)
                abbr = m.group(2)
                value = int(m.group(3), 16)

                # I'm keeping this here for backwards-compatibility
                expert.append(f'\n{name} = {value}')

                if not skip_this and expert_state == ExpertState.IN_GROUP:
                    expert_group.append(f'\n\t\t-- {prev_comment}\n\t\t["{abbr}"] = {value},')
                elif not skip_this and expert_state == ExpertState.IN_SEVERITY:
                    expert_severity.append(f'\n\t\t-- {prev_comment}\n\t\t["{abbr}"] = {value},')

            m = re.match(r'^.define\s+(ENC_[A-Z0-9_]+)\s+((0x)?[0-9A-Fa-f]+)', line)
            if m:
                encodings.append(f'\n{m.group(1)} = {int(m.group(2), 16)}')

    menu_groups = []
    in_stat_group_enum = False
    with open(os.path.join(src_root, 'epan', 'stat_groups.h'), encoding='utf-8') as stat_groups_f:
        for line in stat_groups_f:
            # need to skip matching words in comments, and get to the enum
            if re.match(r'^typedef enum register_stat_group_e \{', line):
                in_stat_group_enum = True
            elif re.match('^\} register_stat_group_t\;/', line):
                in_stat_group_enum = False
            # the problem here is we need to pick carefully, so we don't break existing scripts
            if in_stat_group_enum:
                m = re.search('REGISTER_([A-Z0-9_]+)_GROUP_([A-Z0-9_]+),? ', line)
                if m:
                    idx = len(menu_groups)
                    menu_groups.append(f'\nMENU_{m.group(1)}_{m.group(2)} = {idx}')

    replacements['BASES'] += ''.join(bases) + '\n}\n'
    replacements['ENCODINGS'] += ''.join(encodings) + '\n\n'
    replacements['EXPERT'] += ''.join(expert) + '\n\n'
    replacements['EXPERT_TABLE'] += '\n\t-- Expert event groups\n\tgroup = {'
    replacements['EXPERT_TABLE'] += ''.join(expert_group) + '\n\t},'
    replacements['EXPERT_TABLE'] += '\n\t-- Expert severity levels\n\tseverity = {'
    replacements['EXPERT_TABLE'] += ''.join(expert_severity) + '\n\t},\n}\n'
    replacements['MENU_GROUPS'] += ''.join(menu_groups) + '\n\n'
    replacements['MENU_GROUPS'] += '''\
-- Old / deprecated menu groups. These shoudn't be used in new code.
MENU_ANALYZE_UNSORTED = MENU_PACKET_ANALYZE_UNSORTED
MENU_ANALYZE_CONVERSATION = MENU_ANALYZE_CONVERSATION_FILTER
MENU_STAT_CONVERSATION = MENU_STAT_CONVERSATION_LIST
MENU_STAT_ENDPOINT = MENU_STAT_ENDPOINT_LIST
MENU_STAT_RESPONSE = MENU_STAT_RESPONSE_TIME
MENU_STAT_UNSORTED = MENU_PACKET_STAT_UNSORTED
'''

    with open(args.output, mode='w', encoding='utf-8') as out_f:
        out_f.write(template.substitute(replacements))


if __name__ == '__main__':
    main()
