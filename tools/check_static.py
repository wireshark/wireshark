#!/usr/bin/env python3
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

import os
import re
import subprocess
import argparse
import signal

# Look for dissector symbols that could/should be static.
# This will not run on Windows..

# Try to exit soon after Ctrl-C is pressed.
should_exit = False

def signal_handler(sig, frame):
    global should_exit
    should_exit = True
    print('You pressed Ctrl+C - exiting')

signal.signal(signal.SIGINT, signal_handler)

# Allow this as a default build folder name...
build_folder = os.getcwd() + '-build' 

# Record which symbols are referred to (by a set of files).
class CalledSymbols:
    def __init__(self):
        self.referred = set()

    def addCalls(self, file):
        # Make sure that file is built.
        last_dir = os.path.split(os.path.dirname(file))[-1]
        if file.find('ui/cli') != -1:
            # A tshark target-only file
            object_file = os.path.join(build_folder, 'CMakeFiles', ('tshark' + '.dir'), file + '.o')
        elif file.find('ui/qt') != -1:
            object_file = os.path.join(build_folder, os.path.dirname(file), 'CMakeFiles', ('qtui' + '.dir'), os.path.basename(file) + '.o')
        else:
            object_file = os.path.join(build_folder, os.path.dirname(file), 'CMakeFiles', last_dir + '.dir', os.path.basename(file) + '.o')
        if not os.path.exists(object_file):
            print('Warning -', object_file, 'does not exist')
            return
        command = ['nm', object_file]
        for f in subprocess.check_output(command).splitlines():
            l = str(f)[2:-1]
            # Lines might or might not have an address before letter and symbol.
            p1 = re.compile(r'[0-9a-f]* ([a-zA-Z]) (.*)')
            p2 = re.compile(r'[ ]* ([a-zA-Z]) (.*)')

            m = p1.match(l)
            if not m:
                m = p2.match(l)
            if m:
                letter = m.group(1)
                function_name = m.group(2)

                # Only interested in undefined references to symbols.
                if letter == 'U':
                    self.referred.add(function_name)



# Record which symbols are defined in a single file.
class DefinedSymbols:
    def __init__(self, file):
        self.filename = file
        self.global_dict = {}
        self.header_file_contents = None

        # Make sure that file is built.
        object_file = os.path.join(build_folder, 'epan', 'dissectors', 'CMakeFiles', 'dissectors.dir', os.path.basename(file) + '.o')
        if not os.path.exists(object_file):
            print('Warning -', object_file, 'does not exist')
            return

        header_file= file.replace('.c', '.h')
        try:
            f = open(header_file, 'r')
            self.header_file_contents = f.read()
        except IOError:
            pass


        command = ['nm', object_file]
        for f in subprocess.check_output(command).splitlines():
            l = str(f)[2:-1]
            p = re.compile(r'[0-9a-f]* ([a-zA-Z]) (.*)')
            m = p.match(l)
            if m:
                letter = m.group(1)
                function_name = m.group(2)
                # Locally-defined symbols.
                if letter in 'TD':
                    self.add(function_name, l)

    def add(self, letter, function_name):
        self.global_dict[letter] = function_name

    def mentionedInHeaders(self, symbol):
        if self.header_file_contents:
             if self.header_file_contents.find(symbol) != -1:
                return True
        # Also check some of the 'common' header files that don't match the dissector file name.
        # TODO: could cache the contents of these files, but it's not that slow.
        common_mismatched_headers = [ os.path.join('epan', 'dissectors', 'packet-ncp-int.h'),
                                      os.path.join('epan', 'dissectors', 'packet-mq.h'),
                                      os.path.join('epan', 'dissectors', 'packet-ip.h'),
                                      os.path.join('epan', 'dissectors', 'packet-gsm_a_common.h'),
                                      os.path.join('epan', 'dissectors', 'packet-epl.h'),
                                      os.path.join('epan', 'dissectors', 'packet-bluetooth.h'),
                                      os.path.join('epan', 'dissectors', 'packet-dcerpc.h'),
                                      os.path.join('epan', 'ip_opts.h'),
                                      os.path.join('epan', 'eap.h')]
        for hf in common_mismatched_headers:
            try:
                f = open(hf)
                contents = f.read()
                if contents.find(symbol) != -1:
                    return True
            except EnvironmentError:
                pass

        return False

    def check(self, called_symbols):
        global issues_found
        for f in self.global_dict:
            if not f in called_symbols:
                mentioned_in_header = self.mentionedInHeaders(f)
                fun = self.global_dict[f]
                print(self.filename, '(' + fun + ')', 'is not referred to so could be static?', '(in header)' if mentioned_in_header else '')
                issues_found += 1



# Helper functions.

def isDissectorFile(filename):
    p = re.compile(r'(packet|file)-.*\.c')
    return p.match(filename)

# Test for whether the given dissector file was automatically generated.
def isGeneratedFile(filename):
    if not filename.endswith('.c'):
        return False

    # Open file
    f_read = open(os.path.join(filename), 'r')
    lines_tested = 0
    for line in f_read:
        # The comment to say that its generated is near the top, so give up once
        # get a few lines down.
        if lines_tested > 10:
            f_read.close()
            return False
        if (line.find('Generated automatically') != -1 or
            line.find('Autogenerated from') != -1 or
            line.find('is autogenerated') != -1 or
            line.find('automatically generated by Pidl') != -1 or
            line.find('Created by: The Qt Meta Object Compiler') != -1 or
            line.find('This file was generated') != -1 or
            line.find('This filter was automatically generated') != -1):

            f_read.close()
            return True
        lines_tested = lines_tested + 1

    # OK, looks like a hand-written file!
    f_read.close()
    return False


def findDissectorFilesInFolder(folder, include_generated):
    # Look at files in sorted order, to give some idea of how far through is.
    tmp_files = []

    for f in sorted(os.listdir(folder)):
        if should_exit:
            return
        if isDissectorFile(f):
            if include_generated or not isGeneratedFile(os.path.join('epan', 'dissectors', f)):
                filename = os.path.join(folder, f)
                tmp_files.append(filename)
    return tmp_files

def findFilesInFolder(folder):
    # Look at files in sorted order, to give some idea of how far through is.
    tmp_files = []

    for f in sorted(os.listdir(folder)):
        if should_exit:
            return
        if f.endswith('.c') or f.endswith('.cpp'):
            filename = os.path.join(folder, f)
            tmp_files.append(filename)
    return tmp_files


def is_dissector_file(filename):
    p = re.compile(r'.*packet-.*\.c')
    return p.match(filename)


issues_found = 0



#################################################################
# Main logic.

# command-line args.  Controls which dissector files should be checked.
# If no args given, will just scan epan/dissectors folder.
parser = argparse.ArgumentParser(description='Check calls in dissectors')
parser.add_argument('--build', action='store', default='',
                    help='build folder', required=False)
parser.add_argument('--file', action='store', default='',
                    help='specify individual dissector file to test')
parser.add_argument('--commits', action='store',
                    help='last N commits to check')
parser.add_argument('--open', action='store_true',
                    help='check open files')
parser.add_argument('--common', action='store_true',
                    help='check for potential new entries for tfs.c')

args = parser.parse_args()


# Get files from wherever command-line args indicate.
files = []

if args.build:
    build_folder = args.build

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
    files = list(filter(lambda f : is_dissector_file(f), files))
elif args.open:
    # Unstaged changes.
    command = ['git', 'diff', '--name-only']
    files = [f.decode('utf-8')
             for f in subprocess.check_output(command).splitlines()]
    # Only interested in dissector files.
    files = list(filter(lambda f : is_dissector_file(f), files))
    # Staged changes.
    command = ['git', 'diff', '--staged', '--name-only']
    files_staged = [f.decode('utf-8')
                    for f in subprocess.check_output(command).splitlines()]
    # Only interested in dissector files.
    files_staged = list(filter(lambda f : is_dissector_file(f), files_staged))
    for f in files:
        files.append(f)
    for f in files_staged:
        if not f in files:
            files.append(f)
else:
    # Find all dissector files from folder.
    files = findDissectorFilesInFolder(os.path.join('epan', 'dissectors'),
                                       include_generated=False)


# If scanning a subset of files, list them here.
print('Examining:')
if args.file or args.commits or args.open:
    if files:
        print(' '.join(files), '\n')
    else:
        print('No files to check.\n')
else:
    print('All dissector modules\n')


if not os.path.isdir(build_folder):
    print('Build directory not valid', build_folder, '- please set with --build')
    exit(1)


# Get the set of called functions and referred-to data.
called = CalledSymbols()
for d in findDissectorFilesInFolder(os.path.join('epan', 'dissectors'), include_generated=True):
    called.addCalls(d)
called.addCalls(os.path.join('epan', 'dissectors', 'dissectors.c'))
# Also check calls from GUI code
for d in findFilesInFolder('ui'):
    called.addCalls(d)
for d in findFilesInFolder(os.path.join('ui', 'qt')):
    called.addCalls(d)
# These are from tshark..
for d in findFilesInFolder(os.path.join('ui', 'cli')):
    called.addCalls(d)


# Now check identified files.
for f in files:
    if should_exit:
        exit(1)
    DefinedSymbols(f).check(called.referred)

# Show summary.
print(issues_found, 'issues found')
