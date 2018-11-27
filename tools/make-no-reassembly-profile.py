#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Generate preferences for a "No Reassembly" profile.
# By Gerald Combs <gerald@wireshark.org>
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
'''Generate preferences for a "No Reassembly" profile.'''

import argparse
import os.path
import re
import subprocess
import sys

def main():
    if sys.version_info[0] < 3:
        print("This requires Python 3")
        sys.exit(2)

    parser = argparse.ArgumentParser(description='No reassembly profile generator')
    parser.add_argument('-p', '--program-path', default=os.path.curdir, help='Path to TShark.')
    parser.add_argument('-v', '--verbose', action='store_const', const=True, default=False, help='Verbose output.')
    args = parser.parse_args()

    this_dir = os.path.dirname(__file__)
    profile_path = os.path.join(this_dir, '..', 'profiles', 'No Reassembly', 'preferences')

    tshark_path = os.path.join(args.program_path, 'tshark')
    if not os.path.isfile(tshark_path):
        print('tshark not found at {}\n'.format(tshark_path))
        parser.print_usage()
        sys.exit(1)

    rd_pref_re = re.compile('^#\s*(.*(reassembl|desegment)):')
    nr_prefs = []
    prefs_changed = 0
    cp = subprocess.run([tshark_path, '-G', 'defaultprefs'], stdout=subprocess.PIPE, check=True, encoding='utf-8')
    for pref_line in cp.stdout.split('\n'):
        nr_prefs.append(pref_line)
        m = rd_pref_re.search(pref_line)
        if m:
            pref = m.group(1) + ': FALSE'
            if args.verbose is True:
                print(pref_line + '\n' + pref)
            nr_prefs.append(pref)
            prefs_changed += 1

    if len(nr_prefs) < 5000:
        print("Too few preference lines.")
        sys.exit(1)

    if len(nr_prefs) < 50:
        print("Too few changed preferences.")
        sys.exit(1)

    with open(profile_path, 'w') as profile_f:
        for pref_line in nr_prefs:
            profile_f.write(pref_line + '\n')

if __name__ == '__main__':
    main()
