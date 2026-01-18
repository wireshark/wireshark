#!/usr/bin/env python3
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Scan dissectors for calls to col_[set|add|append]_[f]str
# to check that most appropriate API is being used

import os
import re
import argparse
import signal
import concurrent.futures
from check_common import removeComments, getFilesFromCommits, getFilesFromOpen, findDissectorFilesInFolder, isGeneratedFile, Result

# Try to exit soon after Ctrl-C is pressed.
should_exit = False


def signal_handler(sig, frame):
    global should_exit
    should_exit = True
    print('You pressed Ctrl+C - exiting')

signal.signal(signal.SIGINT, signal_handler)

warnings_found = 0
errors_found = 0


class ColCall:
    def __init__(self, file, line_number, name, last_args, generated, verbose):
        self.filename = file
        self.line_number = line_number
        self.name = name
        self.last_args = last_args
        self.generated = generated
        self.verbose = verbose

    def issue_prefix(self):
        generated = '(GENERATED) ' if self.generated else ''
        return self.filename + ':' + generated + str(self.line_number) + ' : called ' + self.name + ' with ' + self.last_args

    def check(self, result):
        self.last_args = self.last_args.replace('\\\"', "'")
        self.last_args = self.last_args.strip()

        # Empty string never a good idea
        if self.last_args == r'""':
            if 'append' not in self.name:
                result.warn(self.issue_prefix(), '- if want to clear column, use col_clear() instead')
            else:
                # TODO: pointless if appending, but unlikely to see
                pass

        # This is never a good idea..
        if self.last_args.startswith(r'"%s"'):
            result.warn(self.issue_prefix(), " - don't need fstr API?")

        # Unlikely, but did someone accidentally include a specifier but call str() function with no args?
        if self.last_args.startswith('"') and "%" in self.last_args and 'fstr' not in self.name:
            result.warn(self.issue_prefix(), " - meant to call fstr version of function?")

        ternary_re = re.compile(r'.*\s*\?\s*.*\".*\"\s*:\s*.*\".*\"')

        # String should be static, or at least persist.
        # TODO: how persistent does it need to be.  Which memory scope is appropriate?
        if self.name == 'col_set_str':
            # Literal strings are safe, as well as some other patterns..
            if self.last_args.startswith('"'):
                return
            elif self.last_args.startswith('val_to_str_const') or self.last_args.startswith('val_to_str_ext_const'):
                return
            # TODO: substitute macros to avoid some special cases..
            elif self.last_args.upper() == self.last_args:
                return
            # Ternary test with both outcomes being literal strings?
            elif ternary_re.match(self.last_args):
                return
            else:
                if self.verbose:
                    # Not easy/possible to judge lifetime of string..
                    result.note(self.issue_prefix(), '- is this persistent enough??')

        if self.name == 'col_add_str':
            # If literal string, could have used col_set_str instead?
            self.last_args = self.last_args.replace('\\\"', "'")
            self.last_args = self.last_args.strip()
            if self.last_args.startswith('"'):
                result.warn(self.issue_prefix(), '- could call col_set_str() instead')
            elif self.last_args.startswith('val_to_str_const'):
                result.warn(self.issue_prefix(), '- const so could use col_set_str() instead')
            elif self.last_args.startswith('val_to_str_ext_const'):
                result.warn(self.issue_prefix(), '- const so could use col_set_str() instead')

        if self.name == 'col_append_str':
            pass
        if self.name == 'col_add_fstr' or self.name == 'col_append_fstr':
            # Look at format string
            self.last_args = self.last_args.replace('\\\"', "'")
            m = re.search(r'"(.*?)"', self.last_args)
            if m:
                # Should contain at least one format specifier!
                format_string = m.group(1)
                if '%' not in format_string:
                    result.warn(self.issue_prefix(), 'with no format specifiers  - "' + format_string + '" - use _str() version instead')


# Check the given dissector file.
def checkFile(filename, generated, verbose=False):
    result = Result()

    # Check file exists - e.g. may have been deleted in a recent commit.
    if not os.path.exists(filename):
        result.note(filename, 'does not exist!')
        return result

    with open(filename, 'r', encoding="utf8") as f:
        full_contents = f.read()

        # Remove comments so as not to trip up RE.
        contents = removeComments(full_contents)

        # Look for all calls in this file
        matches = re.finditer(r'(col_set_str|col_add_str|col_add_fstr|col_append_str|col_append_fstr)\((.*?)\)\s*\;',
                              contents, re.MULTILINE | re.DOTALL)
        col_calls = []

        last_line_number = 1
        last_char_offset = 0

        for m in matches:
            args = m.group(2)

            line_number = -1
            # May fail to find there were comments inside call...
            # Make search partial to:
            # - avoid finding an earlier identical call
            # - speed up searching by making it shorter
            remaining_lines_text = full_contents[last_char_offset:]
            match_offset = remaining_lines_text.find(m.group(0))
            if match_offset != -1:
                match_in_lines = len(remaining_lines_text[0:match_offset].splitlines())
                line_number = last_line_number + match_in_lines-1
                last_line_number = line_number
                last_char_offset += match_offset + 1  # enough to not match again

            # Match first 2 args plus remainder
            args_m = re.match(r'(.*?),\s*(.*?),\s*(.*)', args)
            if args_m:
                col_calls.append(ColCall(filename, line_number, m.group(1), last_args=args_m.group(3),
                                         generated=generated, verbose=verbose))

        # Check them all
        for call in col_calls:
            call.check(result)

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
    parser.add_argument('--verbose', action='store_true',
                        help='show extra info')


    args = parser.parse_args()


    # Get files from wherever command-line args indicate.
    files = []
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
        # Get files affected by specified number of commits.
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
        future_to_file_output = {executor.submit(checkFile, file, isGeneratedFile(file), args.verbose): file for file in files}
        for future in concurrent.futures.as_completed(future_to_file_output):
            if should_exit:
                exit(1)
            # File is done - show any output and update warning, error counts
            result = future.result()
            output = result.out.getvalue()
            if len(output):
                print(output[:-1])

            warnings_found += result.warnings
            errors_found += result.errors

    # Show summary.
    print(warnings_found, 'warnings found')
    if errors_found:
        print(errors_found, 'errors found')
        exit(1)
