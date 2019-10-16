#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# update-tools-help.py - Update the command line help output in docbook/wsug_src.
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
'''Update tools help

For each file that matches docbook/wsug_src/<command>-<flag>.txt, run
that command and flag. Update the file if the output differs.
'''

import argparse
import difflib
import glob
import io
import os
import re
import subprocess
import sys

def main():
    if sys.version_info[0] < 3:
        print("This requires Python 3")
        sys.exit(2)

    parser = argparse.ArgumentParser(description='Update Wireshark tools help')
    parser.add_argument('-p', '--program-path', nargs=1, default=os.path.curdir, help='Path to Wireshark executables.')
    args = parser.parse_args()

    this_dir = os.path.dirname(__file__)
    wsug_src_dir = os.path.join(this_dir, '..', 'docbook', 'wsug_src')

    tools_help_files = glob.glob(os.path.join(wsug_src_dir, '*-*.txt'))
    tools_help_files.sort()
    tool_pat = re.compile('(\w+)(-\w).txt')

    # If tshark is present, assume that our other executables are as well.
    program_path = args.program_path[0]
    if not os.path.isfile(os.path.join(program_path, 'tshark')):
        print('tshark not found at {}\n'.format(program_path))
        parser.print_usage()
        sys.exit(1)

    null_fd = open(os.devnull, 'w')

    for thf in tools_help_files:
        thf_base = os.path.basename(thf)
        m = tool_pat.match(thf_base)
        thf_command = os.path.join(program_path, m.group(1))
        thf_flag = m.group(2)

        if not os.path.isfile(thf_command):
            print('{} not found. Skipping.'.format(thf_command))
            continue

        with io.open(thf, 'r', encoding='UTF-8') as fd:
            cur_help = fd.read()

        try:
            new_help_data = subprocess.check_output((thf_command, thf_flag), stderr=null_fd)
        except subprocess.CalledProcessError as e:
            if thf_flag == '-h':
                raise e

        new_help = new_help_data.decode('UTF-8', 'replace')

        cur_lines = cur_help.splitlines()
        new_lines = new_help.splitlines()
        if ' (v' in cur_lines[0]:
            # Assume we have a version. Strip it.
            cur_lines[0] = ' '.join(cur_lines[0].split()[:-1])
            new_lines[0] = ' '.join(new_lines[0].split()[:-1])
        diff = list(difflib.unified_diff(cur_lines, new_lines))

        if (len(diff) > 0):
            print('Updating {} {}'.format(thf_command, thf_flag))
            with io.open(thf, 'w', encoding='UTF-8') as fd:
                fd.write(new_help)
        else:
            print('{} {} output unchanged.'.format(thf_command, thf_flag))

if __name__ == '__main__':
    main()
