#!/usr/bin/env python3
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

import os
import re
import argparse
import signal

# This utility scans for tfs items, and works out if standard ones
# could have been used intead (from epan/tfs.c)

# TODO:
# - check how many of the definitions in epan/tfs.c are used in other dissectors
# - see if there are other values that should be in epan/tfs.c and shared


# Try to exit soon after Ctrl-C is pressed.
should_exit = False

def signal_handler(sig, frame):
    global should_exit
    should_exit = True
    print('You pressed Ctrl+C - exiting')

signal.signal(signal.SIGINT, signal_handler)

class TFS:
    def __init__(self, file, name, val1, val2):
        self.file = file
        self.name = name
        self.val1 = val1
        self.val2 = val2

        # Do some extra checks on values.
        if val1.startswith(' ') or val1.endswith(' '):
            print('N.B.: file=' + self.file + ' ' + self.name + ' - false val begins or ends with space \"' + self.val1 + '\"')
        if val2.startswith(' ') or val2.endswith(' '):
            print('N.B.: file=' + self.file + ' ' + self.name + ' - true val begins or ends with space \"' + self.val2 + '\"')

    def __str__(self):
        return '{' + self.val1 + ',' + self.val2 + '}'


def removeComments(code_string):
    code_string = re.sub(re.compile("/\*.*?\*/",re.DOTALL ) ,"" ,code_string) # C-style comment
    code_string = re.sub(re.compile("//.*?\n" ) ,"" ,code_string)             # C++-style comment
    return code_string


# Look for hf items in a dissector file.
def find_items(filename):
    items = {}

    with open(filename, 'r') as f:
        contents = f.read()
        # Example: const true_false_string tfs_true_false = { "True", "False" };

        # Remove comments so as not to trip up RE.
        contents = removeComments(contents)

        matches =   re.finditer(r'.*const\s*true_false_string\s*([a-z_]*)\s*=\s*{\s*\"([a-zA-Z_ ]*)\"\s*,\s*\"([a-zA-Z_ ]*)\"', contents)
        for m in matches:
            name = m.group(1)
            val1 = m.group(2)
            val2 = m.group(3)
            # Store this entry.
            items[name] = TFS(filename, name, val1, val2)

    return items



def isDissectorFile(filename):
    p = re.compile('.*packet-.*\.c')
    return p.match(filename)

def findDissectorFilesInFolder(folder):
    # Look at files in sorted order, to give some idea of how far through is.
    files = []

    for f in sorted(os.listdir(folder)):
        if should_exit:
            return
        if isDissectorFile(f):
            filename = os.path.join(folder, f)
            files.append(filename)
    return files

issues_found = 0

# Check the given dissector file.
def checkFile(filename, tfs_items):
    global issues_found

    # Find items.
    items = find_items(filename)

    # See if any of these items already existed in tfs.c
    for i in items:
        for t in tfs_items:
            if tfs_items[t].val1 == items[i].val1 and tfs_items[t].val2 == items[i].val2:
                print(filename, i, "- could have used", t, 'from tfs.c instead: ', tfs_items[t])
                issues_found += 1


#################################################################
# Main logic.

# command-line args.  Controls which dissector files should be checked.
# If no args given, will just scan epan/dissectors folder.
parser = argparse.ArgumentParser(description='Check calls in dissectors')
parser.add_argument('--file', action='store', default='',
                    help='specify individual dissector file to test')
parser.add_argument('--commits', action='store',
                    help='last N commits to check')
parser.add_argument('--open', action='store_true',
                    help='check open files')

args = parser.parse_args()


# Get files from wherever command-line args indicate.
files = []
if args.file:
    # Add single specified file..
    if not args.file.startswith('epan'):
        files.append(os.path.join('epan', 'dissectors', args.file))
    else:
        files.append(args.file)
elif args.commits:
    # Get files affected by specified number of commits.
    command = ['git', 'diff', '--name-only', 'HEAD~' + args.commits]
    files = [f.decode('utf-8')
             for f in subprocess.check_output(command).splitlines()]
    # Will examine dissector files only
    files = list(filter(lambda f : isDissectorFile(f), files))
elif args.open:
    # Unstaged changes.
    command = ['git', 'diff', '--name-only']
    files = [f.decode('utf-8')
             for f in subprocess.check_output(command).splitlines()]
    # Only interested in dissector files.
    files = list(filter(lambda f : isDissectorFile(f), files))
    # Staged changes.
    command = ['git', 'diff', '--staged', '--name-only']
    files_staged = [f.decode('utf-8')
                    for f in subprocess.check_output(command).splitlines()]
    # Only interested in dissector files.
    files_staged = list(filter(lambda f : isDissectorFile(f), files_staged))
    for f in files:
        files.append(f)
    for f in files_staged:
        if not f in files:
            files.append(f)
else:
    # Find all dissector files from folder.
    files = findDissectorFilesInFolder(os.path.join('epan', 'dissectors'))


# If scanning a subset of files, list them here.
print('Examining:')
if args.file or args.commits or args.open:
    if files:
        print(' '.join(files), '\n')
    else:
        print('No files to check.\n')
else:
    print('All dissector modules\n')


# Get standard/ shared ones.
tfs_entries = find_items(os.path.join('epan', 'tfs.c'))

# Now check the files to see if they could have used shared ones instead.
for f in files:
    if should_exit:
        exit(1)
    checkFile(f, tfs_entries)

# Show summary.
print(issues_found, 'issues found')
