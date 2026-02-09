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
import concurrent.futures
from check_common import isGeneratedFile, findDissectorFilesInFolder, getFilesFromCommits, getFilesFromOpen, removeComments, Result

# This utility scans for tfs items, and works out if standard ones
# could have been used instead (from epan/tfs.c)
# Can also check for value_string where common tfs could be used instead.

# TODO:
# - consider merging Item class with check_typed_item_calls.py ?


# Try to exit soon after Ctrl-C is pressed.
should_exit = False


def signal_handler(sig, frame):
    global should_exit
    should_exit = True
    print('You pressed Ctrl+C - exiting')

signal.signal(signal.SIGINT, signal_handler)


# Keep track of custom entries that might appear in multiple dissectors,
# so we can consider adding them to tfs.c
# (true_val, false_val) -> list of filenames
custom_tfs_entries = {}


# Individual parsed TFS entry
class TFS:
    def __init__(self, file, name, true_val, false_val, result):
        self.file = file
        self.name = name
        self.true_val = true_val
        self.false_val = false_val

        # Should not be empty
        if not len(true_val) or not len(false_val):
            result.warn(file, name, 'has an empty field', self)
        # else:
            # Strange if one begins with capital but other doesn't?
            # if true_val[0].isalpha() and false_val[0].isalpha():
            #    if true_val[0].isupper() != false_val[0].isupper():
            #        result.note(file, name, 'one starts lowercase and the other upper', self)

        # Leading or trailing space should not be needed.
        if true_val.startswith(' ') or true_val.endswith(' '):
            result.note(self.file + ' ' + self.name + ' - true val begins or ends with space \"' + self.true_val + '\"')
        if false_val.startswith(' ') or false_val.endswith(' '):
            result.note(self.file + ' ' + self.name + ' - false val begins or ends with space \"' + self.false_val + '\"')

        # Should really not be identical...
        if true_val.lower() == false_val.lower():
            result.warn(file, name, 'true and false strings are the same', self)

        # Shouldn't both be negation (with exception..)
        if (file != os.path.join('epan', 'dissectors', 'packet-smb.c') and 'not ' in true_val.lower() and 'not' in false_val.lower()):
            result.warn(file, name, self, 'both strings contain not')

        # Not expecting full-stops inside strings..
        if '.' in true_val or '.' in false_val:
            result.warn(file, name, 'Period found in string', self)

    def __str__(self):
        return '{' + '"' + self.true_val + '", "' + self.false_val + '"}'


# Only looking at in terms of could/should it be TFS instead.
class ValueString:
    def __init__(self, file, name, vals):
        self.file = file
        self.name = name
        self.raw_vals = vals
        self.parsed_vals = {}
        self.looks_like_tfs = True

        no_lines = self.raw_vals.count('{')
        if no_lines != 3:
            self.looks_like_tfs = False
            return

        # Now parse out each entry in the value_string
        matches = re.finditer(r'\{([\"a-zA-Z\s\d\,]*)\}', self.raw_vals)
        for m in matches:
            entry = m[1]
            # Check each entry looks like part of a TFS entry.
            match = re.match(r'\s*([01])\,\s*\"([a-zA-Z\d\s]*\s*)\"', entry)
            if match:
                if match[1] == '1':
                    self.parsed_vals[True] = match[2]
                else:
                    self.parsed_vals[False] = match[2]

                # Now have both entries
                if len(self.parsed_vals) == 2:
                    break
            else:
                self.looks_like_tfs = False
                break

    def __str__(self):
        return '{' + '"' + self.raw_vals + '"}'


field_widths = {
    'FT_BOOLEAN': 64,   # TODO: Width depends upon 'display' field
    'FT_CHAR':    8,
    'FT_UINT8':   8,
    'FT_INT8':    8,
    'FT_UINT16':  16,
    'FT_INT16':   16,
    'FT_UINT24':  24,
    'FT_INT24':   24,
    'FT_UINT32':  32,
    'FT_INT32':   32,
    'FT_UINT40':  40,
    'FT_INT40':   40,
    'FT_UINT48':  48,
    'FT_INT48':   48,
    'FT_UINT56':  56,
    'FT_INT56':   56,
    'FT_UINT64':  64,
    'FT_INT64':   64
}


# Simplified version of class that is in check_typed_item_calls.py
class Item:

    previousItem = None

    def __init__(self, filename, hf, filter, label, item_type, type_modifier, strings, macros, mask=None,
                 check_mask=False):
        self.filename = filename
        self.hf = hf
        self.filter = filter
        self.label = label
        self.strings = strings
        self.mask = mask

        # N.B. Not setting mask by looking up macros.

        self.item_type = item_type
        self.type_modifier = type_modifier

        self.set_mask_value(macros)

        self.bits_set = 0
        for n in range(0, self.get_field_width_in_bits()):
            if self.check_bit(self.mask_value, n):
                self.bits_set += 1

    def __str__(self):
        return 'Item ({0} "{1}" {2} type={3}:{4} strings={5} mask={6})'.format(self.filename, self.label, self.filter,
                                                                               self.item_type, self.type_modifier, self.strings, self.mask)

    def set_mask_value(self, macros):
        try:
            self.mask_read = True

            # Substitute mask if found as a macro..
            if self.mask in macros:
                self.mask = macros[self.mask]
            elif any(c not in '0123456789abcdefABCDEFxX' for c in self.mask):
                self.mask_read = False
                self.mask_value = 0
                return

            # Read according to the appropriate base.
            if self.mask.startswith('0x'):
                self.mask_value = int(self.mask, 16)
            elif self.mask.startswith('0'):
                self.mask_value = int(self.mask, 8)
            else:
                self.mask_value = int(self.mask, 10)
        except Exception:
            self.mask_read = False
            self.mask_value = 0

    # Return true if bit position n is set in value.
    def check_bit(self, value, n):
        return (value & (0x1 << n)) != 0

    def get_field_width_in_bits(self):
        if self.item_type == 'FT_BOOLEAN':
            if self.type_modifier == 'NULL':
                return 8  # i.e. 1 byte
            elif self.type_modifier == 'BASE_NONE':
                return 8
            elif self.type_modifier == 'SEP_DOT':   # from proto.h, only meant for FT_BYTES
                return 64
            else:
                try:
                    # For FT_BOOLEAN, modifier is just numerical number of bits. Round up to next nibble.
                    return int((int(self.type_modifier) + 3)/4)*4
                except Exception:
                    return 0
        else:
            if self.item_type in field_widths:
                # Lookup fixed width for this type
                return field_widths[self.item_type]
            else:
                return 0


# Look for true_false_string items in a dissector file.
def findTFS(filename, result):
    tfs_found = {}

    with open(filename, 'r', encoding="utf8", errors="ignore") as f:
        contents = f.read()
        # Example: const true_false_string tfs_yes_no = { "Yes", "No" };

        # Remove comments so as not to trip up RE.
        contents = removeComments(contents)

        matches = re.finditer(r'\sconst\s*true_false_string\s*([a-zA-Z0-9_]*)\s*=\s*{\s*\"([a-zA-Z_0-9/:! ]*)\"\s*,\s*\"([a-zA-Z_0-9/:! ]*)\"', contents)
        for m in matches:
            name = m.group(1)
            true_val = m.group(2)
            false_val = m.group(3)
            # Store this entry.
            tfs_found[name] = TFS(filename, name, true_val, false_val, result)

        return tfs_found


# Look for value_string entries in a dissector file.
def findValueStrings(filename):
    vals_found = {}

    # static const value_string radio_type_vals[] =
    # {
    #     { 0,      "FDD"},
    #     { 1,      "TDD"},
    #     { 0, NULL }
    # };

    with open(filename, 'r', encoding="utf8", errors="ignore") as f:
        contents = f.read()

        # Remove comments so as not to trip up RE.
        contents = removeComments(contents)

        matches = re.finditer(r'.*const value_string\s*([a-zA-Z0-9_]*)\s*\[\s*\]\s*\=\s*\{([\{\}\d\,a-zA-Z0-9\s\"]*)\};', contents)
        for m in matches:
            name = m.group(1)
            vals = m.group(2)
            vals_found[name] = ValueString(filename, name, vals)

    return vals_found


# Look for hf items (i.e. full item to be registered) in a dissector file.
def find_items(filename, macros, check_mask=False, mask_exact_width=False, check_label=False, check_consecutive=False):
    items = {}
    with open(filename, 'r', encoding="utf8", errors="ignore") as f:
        contents = f.read()
        # Remove comments so as not to trip up RE.
        contents = removeComments(contents)

        # N.B. re extends all the way to HFILL to avoid greedy matching
        matches = re.finditer(r'.*\{\s*\&(hf_[a-z_A-Z0-9]*)\s*,\s*{\s*\"(.*?)\"\s*,\s*\"(.*?)\"\s*,\s*(.*?)\s*,\s*([0-9A-Z_\|\s]*?)\s*,\s*(.*?)\s*,\s*(.*?)\s*,\s*([a-zA-Z0-9\W\s_\u00f6\u00e4]*?)\s*,\s*HFILL', contents)
        for m in matches:
            # Store this item.
            hf = m.group(1)
            items[hf] = Item(filename, hf, filter=m.group(3), label=m.group(2), item_type=m.group(4),
                             type_modifier=m.group(5),
                             strings=m.group(6),
                             macros=macros,
                             mask=m.group(7))
    return items


def find_macros(filename):
    macros = {}
    with open(filename, 'r', encoding="utf8", errors="ignore") as f:
        contents = f.read()
        # Remove comments so as not to trip up RE.
        contents = removeComments(contents)

        matches = re.finditer(r'#define\s*([A-Z0-9_]*)\s*([0-9xa-fA-F]*)\n', contents)
        for m in matches:
            # Store this mapping.
            macros[m.group(1)] = m.group(2)
    return macros


# Global counts
warnings_found = 0
errors_found = 0


# Check the given dissector file.
def checkFile(filename, common_tfs, look_for_common=False, check_value_strings=False, count_common_usage=False):
    result = Result()

    # Check file exists - e.g. may have been deleted in a recent commit.
    if not os.path.exists(filename):
        print(filename, 'does not exist!')
        return result

    # Find items.
    file_tfs = findTFS(filename, result)

    # See if any of these items already existed in tfs.c
    for f in file_tfs:
        for c in common_tfs:
            found = False

            #
            # Do not do this check for plugins; plugins cannot import
            # data values from libwireshark (functions, yes; data
            # values, no).
            #
            # Test whether there's a common prefix for the file name
            # and "plugin/epan/"; if so, this is a plugin, and there
            # is no common path and os.path.commonprefix returns an
            # empty string, otherwise it returns the common path, so
            # we check whether the common path is an empty string.
            #
            if os.path.commonprefix([filename, 'plugin/epan/']) == '':
                exact_case = False
                if file_tfs[f].true_val == common_tfs[c].true_val and file_tfs[f].false_val == common_tfs[c].false_val:
                    found = True
                    exact_case = True
                elif file_tfs[f].true_val.upper() == common_tfs[c].true_val.upper() and file_tfs[f].false_val.upper() == common_tfs[c].false_val.upper():
                    found = True

                if found:
                    if exact_case:
                        result.error(filename, f, "- could have used", c, 'from tfs.c instead: ', common_tfs[c])
                    else:
                        result.warn(filename, f, "- could have used", c, 'from tfs.c instead: ', common_tfs[c], '  (capitalisation differs)')
                    break
        if not found:
            if look_for_common:
                vals = (file_tfs[f].true_val, file_tfs[f].false_val)
                result.custom_entries.add(vals)

    if check_value_strings:
        # Get macros
        macros = find_macros(filename)

        # Get value_string entries.
        vs = findValueStrings(filename)

        # Also get hf items
        items = find_items(filename, macros, check_mask=True)

        for v in vs:
            if vs[v].looks_like_tfs:
                found = False
                exact_case = False

                for c in common_tfs:
                    found = False

                    #
                    # Do not do this check for plugins; plugins cannot import
                    # data values from libwireshark (functions, yes; data
                    # values, no).
                    #
                    # Test whether there's a common prefix for the file name
                    # and "plugin/epan/"; if so, this is a plugin, and there
                    # is no common path and os.path.commonprefix returns an
                    # empty string, otherwise it returns the common path, so
                    # we check whether the common path is an empty string.
                    #
                    if os.path.commonprefix([filename, 'plugin/epan/']) == '':
                        exact_case = False
                        if common_tfs[c].true_val == vs[v].parsed_vals[True] and common_tfs[c].false_val == vs[v].parsed_vals[False]:
                            found = True
                            exact_case = True
                        elif common_tfs[c].true_val.upper() == vs[v].parsed_vals[True].upper() and common_tfs[c].false_val.upper() == vs[v].parsed_vals[False].upper():
                            found = True

                        # Do values match?
                        if found:
                            # OK, now look for items that:
                            # - have VALS(v)  AND
                            # - have a mask width of 1 bit (no good if field can have values > 1...)
                            for i in items:
                                if re.match(r'VALS\(\s*'+v+r'\s*\)', items[i].strings):
                                    if items[i].bits_set == 1:
                                        if exact_case:
                                            result.warn(filename, 'value_string', "'"+v+"'", '- could have used tfs.c entry instead: for', i,
                                                        ' - "FT_BOOLEAN,', str(items[i].get_field_width_in_bits()) + ', TFS(&' + c + '),"')
                                        else:
                                            result.note(filename, 'value_string', "'"+v+"'", '- could have used tfs.c entry instead: for', i,
                                                        ' - "FT_BOOLEAN,', str(items[i].get_field_width_in_bits()) + ', TFS(&' + c + '),"',
                                                        '  (capitalisation differs)')

    if count_common_usage:
        # Look for TFS(&<name>) in dissector
        with open(filename, 'r') as f:
            contents = f.read()
            for c in common_tfs:
                m = re.search(r'TFS\(\s*\&' + c + r'\s*\)', contents)
                if m:
                    if c not in result.common_usage:
                        result.common_usage[c] = 1
                    else:
                        result.common_usage[c] += 1

    result.should_exit = should_exit
    return result


if __name__ == '__main__':
    #################################################################
    # command-line args.  Controls which dissector files should be checked.
    # If no args given, will just scan epan/dissectors folder.
    parser = argparse.ArgumentParser(description='Check calls in dissectors')
    parser.add_argument('--file', action='append',
                        help='specify individual dissector file to test')
    parser.add_argument('--commits', action='store',
                        help='last N commits to check')
    parser.add_argument('--open', action='store_true',
                        help='check open files')
    parser.add_argument('--check-value-strings', action='store_true',
                        help='check whether value_strings could have been tfs?')
    parser.add_argument('--common', action='store_true',
                        help='check for potential new entries for tfs.c')
    parser.add_argument('--common-usage', action='store_true',
                        help='count how many dissectors are using common tfs entries')

    args = parser.parse_args()


    # Get files from wherever command-line args indicate.
    files = set()

    if args.file:
        # Add specified file(s)
        for f in args.file:
            if not os.path.isfile(f) and not f.startswith('epan'):
                f = os.path.join('epan', 'dissectors', f)
            if not os.path.isfile(f):
                print('Chosen file', f, 'does not exist.')
                exit(1)
            else:
                files.add(f)
    elif args.commits:
        files = getFilesFromCommits(args.commits)
    elif args.open:
        # Unstaged changes.
        files = getFilesFromOpen()

    else:
        # Find all dissector files from folders.
        files = findDissectorFilesInFolder(os.path.join('epan', 'dissectors')) + \
                    findDissectorFilesInFolder(os.path.join('plugins', 'epan'), recursive=True)

    # If scanning a subset of files, list them here.
    print('Examining:')
    if args.file or args.commits or args.open:
        if files:
            print(' '.join(sorted(files)), '\n')
        else:
            print('No files to check.\n')
    else:
        print('All dissector modules\n')


    # Get standard/ shared ones.
    common_result = Result()
    common_tfs_entries = findTFS(os.path.join('epan', 'tfs.c'), common_result)

    # Global data for these optional checks.
    all_common_usage = {}
    all_custom_entries = {}


    # Now check the files to see if they could have used shared ones instead.
    # Look at files in sorted order, to give some idea of how far through we are.
    with concurrent.futures.ProcessPoolExecutor() as executor:
        future_to_file_output = {executor.submit(checkFile, file,
                                                 common_tfs_entries, args.common,
                                                 args.check_value_strings,
                                                 args.common_usage): file for file in sorted(files) if not isGeneratedFile(file)}
        for future in concurrent.futures.as_completed(future_to_file_output):
            # Unpack result
            result = future.result()
            output = result.out.getvalue()
            if len(output):
                print(output[:-1])

            if result.should_exit:
                exit(1)

            # Add to issue counts
            warnings_found += result.warnings
            errors_found += result.errors

            # Update common usage stats
            if args.common_usage:
                for name, count in result.common_usage.items():
                    if name not in all_common_usage:
                        all_common_usage[name] = count
                    else:
                        all_common_usage[name] += count

            # Update 'common' custom counts
            if args.common:
                for entry in result.custom_entries:
                    if entry not in all_custom_entries:
                        all_custom_entries[entry] = [future_to_file_output[future]]
                    else:
                        all_custom_entries[entry].append(future_to_file_output[future])


    # Report on commonly-defined values.
    if args.common:
        # Looking for items that could potentially be moved to tfs.c
        for c in all_custom_entries:
            # Only want to see items that have 3 or more occurrences.
            # Even then, probably only want to consider ones that sound generic.
            if len(all_custom_entries[c]) > 2:
                print(c, 'appears', len(all_custom_entries[c]), 'times, in: ', all_custom_entries[c])

    # Show how often 'common' entries are used
    if args.common_usage:
        actual_usage = []

        for c in common_tfs_entries:
            if c in all_common_usage:
                actual_usage.append((c, all_common_usage[c]))
            else:
                actual_usage.append((c, 0))

        # Show in order sorted by usage
        actual_usage.sort(reverse=True, key=lambda e: e[1])
        for use in actual_usage:
            emphasis = '**' if use[1] == 0 else ''
            print(emphasis, use[0], 'used in', use[1], 'dissectors', emphasis)

    # Summary.
    print(warnings_found, 'warnings found')
    if errors_found:
        print(errors_found, 'errors found')
        exit(1)
