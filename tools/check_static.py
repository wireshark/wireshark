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
import concurrent.futures
from check_common import findDissectorFilesInFolder, getFilesFromOpen, getFilesFromCommits, isGeneratedFile, Result

# Look for dissector symbols that could/should be static.
# This will not run on Windows, unless/until we check the platform
# and use (I think) dumpbin.exe
#
# N.B. Will report false positives if symbols are extern'd rather than
# declared in a header file.

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

    def getCalls(self, file):
        referred = set()
        if should_exit:
            exit(1)

        # Make sure that file is built.
        last_dir = os.path.split(os.path.dirname(file))[-1]
        if 'ui/cli' in file:
            # A tshark target-only file
            object_file = os.path.join(build_folder, 'CMakeFiles', ('tshark' + '.dir'), file + '.o')
        elif 'ui/qt' in file:
            object_file = os.path.join(build_folder, os.path.dirname(file), 'CMakeFiles', ('qtui' + '.dir'), os.path.basename(file) + '.o')
        else:
            if file.endswith('dissectors.c'):
                object_file = os.path.join(build_folder, os.path.dirname(file), 'CMakeFiles', 'dissector-registration' + '.dir', os.path.basename(file) + '.o')
            else:
                object_file = os.path.join(build_folder, os.path.dirname(file), 'CMakeFiles', last_dir + '.dir', os.path.basename(file) + '.o')
        if not os.path.exists(object_file):
            # Not built for whatever reason..
            return referred

        # Run command to check symbols.
        command = ['nm', object_file]
        for f in subprocess.check_output(command).splitlines():
            line = str(f)[2:-1]
            # Lines might, or might not, have an address before letter and symbol.
            p1 = re.compile(r'[0-9a-f]* ([a-zA-Z]) (.*)')
            p2 = re.compile(r'[ ]* ([a-zA-Z]) (.*)')

            m = p1.match(line)
            if not m:
                m = p2.match(line)
            if m:
                letter = m.group(1)
                function_name = m.group(2)

                # Only interested in undefined/external references to symbols.
                if letter == 'U':
                    referred.add(function_name)
        return referred

    def addCalls(self, calls):
        self.referred.update(calls)

# Record which symbols are defined in a single dissector file.
class DefinedSymbols:
    def __init__(self, file, result):
        self.filename = file
        self.result = result
        self.global_symbols = {}       # map from defined symbol -> whole output-line
        self.header_file_contents = None
        self.from_generated_file = isGeneratedFile(file)

        # Make sure that file is built by looking for object file
        if self.filename.startswith('epan'):
            object_file = os.path.join(build_folder, 'epan', 'dissectors', 'CMakeFiles', 'dissectors.dir', os.path.basename(file) + '.o')
        elif self.filename.startswith('plugins'):
            plugin_base_dir = os.path.dirname(file)
            plugin_base_name = os.path.basename(plugin_base_dir)
            object_file = os.path.join(build_folder, plugin_base_dir, 'CMakeFiles', plugin_base_name + '.dir', os.path.basename(file) + '.o')
        else:
            return
        if not os.path.exists(object_file):
            return

        # Get header file contents if available
        header_file = file.replace('.c', '.h')
        try:
            f = open(header_file, 'r')
            self.header_file_contents = f.read()
        except IOError:
            pass

        # Run command to see which symbols are defined
        command = ['nm', object_file]
        for f in subprocess.check_output(command).splitlines():
            # Line consists of whitespace, [address], letter, symbolName
            line = str(f)[2:-1]
            p = re.compile(r'[0-9a-f]* ([a-zA-Z]) (.*)')
            m = p.match(line)
            if m:
                letter = m.group(1)
                function_name = m.group(2)
                # Globally-defined symbols. Would be 't' or 'd' if already static..
                if letter in 'TD':
                    self.addDefinedSymbol(function_name, line)

    def addDefinedSymbol(self, symbol, line):
        self.global_symbols[symbol] = line

    def isSymbolInContents(self, contents, symbol):
        if not contents:
            return False
        # Check that string appears
        if symbol not in contents:
            return False
        else:
            # Look for in context.  In particular don't want to match if there is
            # longer symbol with symbol as a prefix..
            p = re.compile(r'[\s\*\()]' + symbol + r'[\(\s\[;]+', re.MULTILINE)
            m = p.search(contents, re.MULTILINE)
            return m is not None

    # Check if a given symbol is mentioned in headers
    def mentionedInHeaders(self, symbol):
        if self.isSymbolInContents(self.header_file_contents, symbol):
            return True

        # Also check some of the 'common' header files that don't match the dissector file name.
        for contents in common_mismatched_header_contents.values():
            if self.isSymbolInContents(contents, symbol):
                return True

        return False

    def checkIfSymbolsAreCalled(self, called_symbols):
        for f in self.global_symbols:
            if f not in called_symbols:
                mentioned_in_header = self.mentionedInHeaders(f)
                fun = self.global_symbols[f]
                self.result.note(self.filename, '' if not self.from_generated_file else '(GENERATED)',
                                 '(' + fun + ')',
                                 'is not referred to so could be static?', '(declared in header but not referred to)' if mentioned_in_header else '')


# Helper functions.

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


if __name__ == '__main__':
    #################################################################
    # command-line args.  Controls which dissector files should be checked.
    # If no args given, will just scan epan/dissectors folder.
    parser = argparse.ArgumentParser(description='Check calls in dissectors')
    parser.add_argument('--build-folder', action='store', default='',
                        help='build folder', required=False)
    parser.add_argument('--file', action='append',
                        help='specify individual dissector file to test')
    parser.add_argument('--commits', action='store',
                        help='last N commits to check')
    parser.add_argument('--open', action='store_true',
                        help='check open files')

    args = parser.parse_args()

    # header-file -> contents for files that will be checked often, so only read once.
    common_mismatched_header_contents = {}
    common_mismatched_headers = [os.path.join('epan', 'dissectors', 'packet-ncp-int.h'),
                                 os.path.join('epan', 'dissectors', 'packet-mq.h'),
                                 os.path.join('epan', 'dissectors', 'packet-ip.h'),
                                 os.path.join('epan', 'dissectors', 'packet-gsm_a_common.h'),
                                 os.path.join('epan', 'dissectors', 'packet-epl.h'),
                                 os.path.join('epan', 'dissectors', 'packet-bluetooth.h'),
                                 os.path.join('epan', 'dissectors', 'packet-dcerpc.h'),
                                 os.path.join('epan', 'ip_opts.h')]
    for h in common_mismatched_headers:
        with open(h, 'r') as f:
            common_mismatched_header_contents[h] = f.read()


    issues_found = 0

    # Get files from wherever command-line args indicate.
    files = []

    if args.build_folder:
        build_folder = args.build_folder

    if args.file:
        # Add specified file(s)
        for f in args.file:
            if not os.path.isfile(f) and not f.startswith('epan'):
                f = os.path.join('epan', 'dissectors', f)
            if not os.path.isfile(f):
                print('Chosen file', f, 'does not exist.')
                exit(1)
            else:
                files.append(f)
    elif args.commits:
        files = getFilesFromCommits(args.commits)
    elif args.open:
        # Unstaged changes.
        files = getFilesFromOpen()
    else:
        # Find all dissector files from folder.
        files = findDissectorFilesInFolder(os.path.join('epan', 'dissectors'),
                                           recursive=False, include_generated=True)

    # Ensure that all source files exist (i.e., cope with deletes/renames)
    files = [f for f in files if os.path.exists(f)]


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
        print('Build directory not valid', build_folder, '- please set with --build-folder')
        exit(1)


    # Get the set of called functions and referred-to data.
    called = CalledSymbols()

    call_files = findDissectorFilesInFolder(os.path.join('epan', 'dissectors'), include_generated=True)
    call_files.append(os.path.join('epan', 'dissectors', 'dissectors.c'))
    call_files.append(os.path.join('epan', 'dissectors', 'event-dissectors.c'))
    call_files += findFilesInFolder(os.path.join('ui', 'qt'))
    call_files += findFilesInFolder(os.path.join('ui', 'cli'))


    def getCalls(file):
        return called.getCalls(file)


    # Gather a list of undefined/external references.
    with concurrent.futures.ProcessPoolExecutor() as executor:
        future_to_file_referred = {executor.submit(getCalls, file): file for file in call_files}
        for future in concurrent.futures.as_completed(future_to_file_referred):
            referred = future.result()
            called.addCalls(referred)


    # Now check identified dissector files.
    def checkIfSymbolsAreCalled(file):
        result = Result()
        DefinedSymbols(file, result).checkIfSymbolsAreCalled(called.referred)
        return result

    with concurrent.futures.ProcessPoolExecutor() as executor:
        future_to_file_output = {executor.submit(checkIfSymbolsAreCalled, file): file for file in files}
        for future in concurrent.futures.as_completed(future_to_file_output):
            if should_exit:
                exit(1)

            result = future.result()
            output = result.out.getvalue()
            if len(output):
                print(output[:-1])

            issues_found += result.notes

    # Show summary.
    print(issues_found, 'issues found')
