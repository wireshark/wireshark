#!/usr/bin/env python3
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

import sys
import os
import signal
import argparse

# Run battery of tests on one or more dissectors.

# For text colouring/highlighting.
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    ADDED = '\033[45m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


# Try to exit soon after Ctrl-C is pressed.
should_exit = False

def signal_handler(sig, frame):
    global should_exit
    should_exit = True
    print('You pressed Ctrl+C - exiting')

signal.signal(signal.SIGINT, signal_handler)

# Command-line args
parser = argparse.ArgumentParser(description="Run gamut of tests on dissector(s)")
parser.add_argument('--file', action='append',
                    help='specify individual dissector file to test')
parser.add_argument('--file-list', action='store',
                    help='file with list of dissectors')
parser.add_argument('--build-folder', action='store',
                    help='build folder')

args = parser.parse_args()

if not args.file and not args.file_list:
    print('Need to specify --file or --file-list')
    exit(1)

# TODO: verify build-folder if set.

# Get list of files to check.
dissectors = []

# Individually-selected files
if args.file:
    for f in args.file:
            if not os.path.isfile(f):
                print('Chosen file', f, 'does not exist.')
                exit(1)
            else:
                dissectors.append(f)

# List of dissectors stored in a file
if args.file_list:
    if not os.path.isfile(args.file_list):
        print('Dissector-list file', args.file_list, 'does not exist.')
        exit(1)
    else:
        with open(args.file_list, 'r') as f:
            contents = f.read().splitlines()
            for f in contents:
                if not os.path.isfile(f):
                    print('Chosen file', f, 'does not exist.')
                    exit(1)
                else:
                    dissectors.append(f)

# Tools that should be run on selected files.
# Boolean arg is for whether build-dir is needed in order to run it.
# 3rd is Windows support.
tools = [
    ('tools/delete_includes.py --folder .',               True,   True),
    ('tools/check_spelling.py --comments --no-wikipedia', False,  True),
    ('tools/check_tfs.py --check-value-strings',          False,  True),
    ('tools/check_typed_item_calls.py --all-checks',      False,  True),
    ('tools/check_static.py',                             True,   False),
    ('tools/check_dissector_urls.py',                     False,  True),
    ('tools/check_val_to_str.py',                         False,  True),
    ('tools/cppcheck/cppcheck.sh',                        False,  True),
    ('tools/checkhf.pl',                                  False,  True),
    ('tools/checkAPIs.pl',                                False,  True),
    ('tools/fix-encoding-args.pl',                        False,  True),
    ('tools/checkfiltername.pl',                          False,  True)
]


def run_check(tool, dissectors, python):
    # Create command-line with all dissectors included
    command = ''

    # Don't trust shebang on windows.
    if sys.platform.startswith('win'):
        if python:
            command += 'python.exe '
        else:
            command += 'perl.exe '

    command += tool[0]
    if tool[1]:
        command += ' --build-folder ' + args.build_folder

    for d in dissectors:
        # Add this dissector file to command-line args
        command += ((' --file' if python else '') + ' ' + d)

    # Run it
    print(bcolors.BOLD + command + bcolors.ENDC)
    os.system(command)


# Run all checks on all of my dissectors.
for tool in tools:
    if should_exit:
        exit(1)
    if ((not sys.platform.startswith('win') or tool[2]) and # Supported on this platform?
        (not tool[1] or (tool[1] and args.build_folder))):   # Have --build-folder if needed?

        # Run it.
        run_check(tool, dissectors, tool[0].find('.py') != -1)
