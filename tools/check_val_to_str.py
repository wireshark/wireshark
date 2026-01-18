#!/usr/bin/env python3
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Scan dissectors for calls to val_to_str() and friends,
# checking for appropriate format specifier strings in
# 'unknown' arg.
# TODO:
# - more detailed format specifier checking (check letter, that there is only 1)
# - scan conformance (.cnf) files for ASN1 dissectors?

import os
import re
import argparse
import signal
import concurrent.futures
from check_common import findDissectorFilesInFolder, getFilesFromCommits, getFilesFromOpen, isDissectorFile, isGeneratedFile, removeComments, Result


# Try to exit soon after Ctrl-C is pressed.
should_exit = False


def signal_handler(sig, frame):
    global should_exit
    should_exit = True
    print('You pressed Ctrl+C - exiting')

signal.signal(signal.SIGINT, signal_handler)

warnings_found = 0
errors_found = 0


# Check the given dissector file.
def checkFile(filename, generated):
    result = Result()

    # Check file exists - e.g. may have been deleted in a recent commit.
    if not os.path.exists(filename):
        result.note(filename, 'does not exist!')
        return

    with open(filename, 'r', encoding="utf8") as f:
        contents = f.read()

        # Remove comments so as not to trip up RE.
        contents = removeComments(contents)

        matches = re.finditer(r'(?<!try_)(?<!char_)(?<!bytes)(r?val_to_str(?:_ext|)(?:_const|))\(.*?,.*?,\s*(".*?\")\s*\)', contents)
        for m in matches:
            function = m.group(1)
            format_string = m.group(2)

            # Ignore what appears to be a macro.
            if '#' in format_string:
                continue

            if function.endswith('_const'):
                # These ones shouldn't have a specifier - its an error if they do.
                # TODO: I suppose it could be escaped, but haven't seen this...
                if '%' in format_string:
                    # This is an error as format specifier would show in app
                    result.error(filename, "  ", m.group(0),
                                 '   - should not have specifiers in unknown string',
                                 '(GENERATED)' if generated else '')
            else:
                # These ones need to have a specifier, and it should be suitable for an int
                count = format_string.count('%')
                if count == 0:
                    result.warn(filename, "  ", m.group(0),
                                '   - should have suitable format specifier in unknown string (or use _const()?)',
                                '(GENERATED)' if generated else '')
                elif count > 1:
                    result.warn(filename, "  ", m.group(0),
                                '   - has more than one specifier?',
                                '(GENERATED)' if generated else '')
                # TODO: check allowed specifiers (d, u, x, ?) and modifiers (0-9*) in re ?
                if '%s' in format_string:
                    # This is an error as this likely causes a crash
                    result.error(filename, "  ", m.group(0),
                                 '    - inappropriate format specifier in unknown string',
                                 '(GENERATED)' if generated else '')

    return result


if __name__ == '__main__':
    #################################################################
    # command-line args.  Controls which dissector files should be checked.
    # If no args given, will scan all dissectors.
    parser = argparse.ArgumentParser(description='Check calls in dissectors')
    parser.add_argument('--file', action='append',
                        help='specify individual dissector file to test')
    parser.add_argument('--commits', action='store',
                        help='last N commits to check')
    parser.add_argument('--open', action='store_true',
                        help='check open files')

    args = parser.parse_args()


    # Get files from wherever command-line args indicate.
    files = []
    if args.file:
        # Add specified file(s)
        for f in args.file:
            if os.path.isfile(f):
                if isDissectorFile(f):
                    files.append(f)
            else:
                print('Chosen file', f, 'does not exist.')
                exit(1)
    elif args.commits:
        files = getFilesFromCommits(args.commits)
    elif args.open:
        # Unstaged changes.
        files = getFilesFromOpen()
    else:
        # Find all dissector files from folder.
        files = findDissectorFilesInFolder(os.path.join('epan', 'dissectors'))
        files += findDissectorFilesInFolder(os.path.join('plugins', 'epan'), recursive=True)
        files += findDissectorFilesInFolder(os.path.join('epan', 'dissectors', 'asn1'), recursive=True)


    # If scanning a subset of files, list them here.
    print('Examining:')
    if args.file or args.commits or args.open:
        if files:
            print(' '.join(files), '\n')
        else:
            print('No files to check.\n')
    else:
        print('All dissectors\n')


    # Now check the chosen files
    with concurrent.futures.ProcessPoolExecutor() as executor:
        future_to_file_output = {executor.submit(checkFile, file,
                                 isGeneratedFile(file)): file for file in files}
        for future in concurrent.futures.as_completed(future_to_file_output):
            if should_exit:
                exit(1)
            # File is done - show any output and update warning, error counts
            result = future.result()
            output = result.out.getvalue()
            if len(output):
                print(output)

            warnings_found += result.warnings
            errors_found += result.errors


    # Show summary.
    print(warnings_found, 'warnings found')
    if errors_found:
        print(errors_found, 'errors found')
        exit(1)
