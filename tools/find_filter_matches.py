#!/usr/bin/env python3
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

import os
import sys
import subprocess
import signal
import argparse
import pathlib

# Search for capture files that match a given filter

# Try to exit soon after Ctrl-C is pressed.
should_exit = False

def signal_handler(sig, frame):
    global should_exit
    should_exit = True
    print('You pressed Ctrl+C - exiting')

signal.signal(signal.SIGINT, signal_handler)

# TODO: others?
capture_exts = set(['.pcap', '.pcapng', '.out'])

def isCaptureFile(filename):
    return pathlib.Path(filename).suffix in capture_exts

def findFilesInFolder(folder):
    files_to_check = []

    for root, subfolders, files in os.walk(folder):
        for f in files:
            if should_exit:
                return
            f = os.path.join(root, f)
            if isCaptureFile(f):
                files_to_check.append(f)

    return files_to_check


# command-line args.  Controls which files should be checked.
# If no args given, will just scan epan/dissectors folder.
parser = argparse.ArgumentParser(description='Check spellings in specified files')
parser.add_argument('--filter', required=True, action='append',
                    help='display filter to search for')
parser.add_argument('--folder', action='store', default='.',
                    help='specify folder to test')
parser.add_argument('--tshark', action='store', default='tshark',
                    help='version of tshark to run')
args = parser.parse_args()


# Find files worth checking.
files = findFilesInFolder(args.folder)
print('Checking', len(files), 'files...')
found = []

for file in files:
    if should_exit:
        exit(1)

    # N.B. if have multiple filters, must invoke tshark for each one, for cases where OR will not work
    lines_matching = {}
    for filter in args.filter:
        # TODO: should show any non-default columns?
        command = [ args.tshark, '-r', file, '-Y', filter ]
        try:
            output = subprocess.check_output(command)
        except Exception as e:
            print('oops, exception', e)
            # Check for WS_EXIT_INVALID_FILTER (4)
            if str(e).find("exit status 4") != -1:
                print('Please use a valid display filter!')
                exit(4)

            break

        if len(output):
            sys.stdout.write('\n')
            sys.stdout.flush()

            lines_matching[filter] = output.splitlines()
        else:
            # Print single character to show progress..
            sys.stdout.write('.')
            sys.stdout.flush()
            # All filters must match so give up
            break

    # Show each match in output.
    if len(lines_matching) == len(args.filter):
        found.append(file)
        for filter in args.filter:
            for line in lines_matching[filter]:
                print(file, ':', filter, ':', line)


# Summary
print('------------------------------')
print('Found', len(found), 'files matching "' + args.filter[0] + '"', 'in folder', args.folder)
for find in found:
    print(find)
print('------------------------------')

# TODO: return error code if no matches?