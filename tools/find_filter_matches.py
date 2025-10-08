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
import datetime
import time

# Search for capture files that match a given filter (or filters)

def show_progress(filenum, num_files, filename, num_matching):
    print('')
    print('=== Progress: checking', filename, '-', filenum, 'of', num_files, 'files -', num_matching, 'matching so far ===')
    print('=== Press Ctrl-C again within 5 seconds to really exit ===')
    time.sleep(1.5)

def show_results(complete):
    print('------------------------------')
    print('Found', len(files_matching), 'files matching "' + args.filter[0] + '"', 'in folder', args.folder,
          '' if complete else '(interrupted!)')
    for find in files_matching:
        print(find)
    print('------------------------------')
    # TODO: vary exit code depending upon how we got here, or if there were matches?
    exit(0)



# When Ctrl-C is pressed, show summary of progress - a 2nd press soon afterwards will cause exit
previous_interrupt_time = datetime.datetime.now()
should_exit = False
should_show_progress = False

def signal_handler(sig, frame):
    global should_exit
    global should_show_progress
    global previous_interrupt_time
    this_interrupt_time = datetime.datetime.now()
    if should_show_progress:
        return

    delta = (this_interrupt_time - previous_interrupt_time).seconds
    if delta <= 2:
        should_exit = True
        print('You pressed Ctrl+C - exiting')

        # Show any partial results anyway
        show_results(False)
    else:
        should_show_progress = True

    previous_interrupt_time = this_interrupt_time


signal.signal(signal.SIGINT, signal_handler)

# TODO: others?
capture_exts = set(['.pcap', '.pcapng', '.out', '.cap'])

def isCaptureFile(filename):
    return pathlib.Path(filename).suffix in capture_exts

def findFilesInFolder(folder):
    files_to_check = []

    for root, subfolders, files in os.walk(folder):
        for f in files:
            # Just get out and exit if user aborts now...
            if should_exit or should_show_progress:
                exit(1)

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
parser.add_argument('--profile', action='store',
                    help='profile to invoke tshark with (-C)')
parser.add_argument('--max-packets', action='store',
                    help='maximum number of packets to read - tshark -c')
parser.add_argument('--tshark', action='store', default='tshark',
                    help='version of tshark to run')
args = parser.parse_args()


# Make sure there is a usable tshark
try:
    version_info = subprocess.check_output([ args.tshark, '--version']).decode('utf-8')
    #print(version_info)
except Exception as e:
    print(e)
    print('Could not run tshark(', args.tshark, ') - please specify a working version using --tshark <path-to-tshark>')
    exit(1)

# Find files worth checking.
print('Compiling list of files to check.')
files = findFilesInFolder(args.folder)
print('Checking', len(files), 'files...')


# Check files
files_matching = []

for filenum,file in enumerate(files):
    if should_exit:
        exit(1)

    # May want to show progress here..
    if should_show_progress:
        show_progress(filenum, len(files), file, len(files_matching))
        should_show_progress = False

    # N.B. if have multiple filters, must invoke tshark for each one, for cases where OR will not work
    lines_matching = {}
    for filter in args.filter:
        # TODO: Other args could usefully set?
        command = [ args.tshark, '-r', file, '-Y', filter ]
        if args.profile:
            command.extend(['-C', args.profile])
        if args.max_packets:
            command.extend(['-c', args.max_packets])
        try:
            output = subprocess.check_output(command)
        except Exception as e:
            #print('oops, exception', e)
            # Check for WS_EXIT_INVALID_FILTER (4)
            # TODO: other errors possible, e.g., bad profile name..
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

        # Show each match in output, but only if every filter has at least one match in this file.
        if len(lines_matching) == len(args.filter):
            files_matching.append(file)
            for filter in args.filter:
                for line in lines_matching[filter]:
                    print(file, ':', filter, ':', line.decode('utf-8'))



# Show results if get to end
show_results(True)

