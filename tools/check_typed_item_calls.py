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
import subprocess

# This utility scans the dissector code for proto_tree_add_...() calls constrain the type of the
# item added, and checks that the used item is acceptable.
#
# Note that this can only work where the hf_item variable is passed in directly - where it
# is assigned to a different variable it isn't tracked.

# TODO:
# Attempt to check length (where literal value is given). Arg position differs among functions.
# Currently assuming we'll find call + first 2 args in same line...
# Attempt to check for allowed encoding types (most likely will be literal values |'d)?


# Try to exit soon after Ctrl-C is pressed.
should_exit = False

def signal_handler(sig, frame):
    global should_exit
    should_exit = True
    print('You pressed Ctrl+C - exiting')

signal.signal(signal.SIGINT, signal_handler)


issues_found = 0

# A call is an individual call to an API we are interested in.
# Internal to APICheck below.
class Call:
    def __init__(self, hf_name, line_number):
       self.hf_name = hf_name
       self.line_number = line_number


# A check for a particular API function.
class APICheck:
    def __init__(self, fun_name, allowed_types):
        self.fun_name = fun_name
        self.allowed_types = allowed_types
        self.calls = []
        # RE captures function name + 1st 2 args (always tree + hfindex)
        self.p = re.compile('.*' +  self.fun_name + '\(([a-zA-Z0-9_]+),\s*([a-zA-Z0-9_]+)')
        self.file = None

    def find_calls(self, file):
        self.file = file
        self.calls = []
        with open(file, 'r') as f:
            for line_number, line in enumerate(f, start=1):
                m = self.p.match(line)
                if m:
                    self.calls.append(Call(m.group(2), line_number))

    def check_against_items(self, items):
        for call in self.calls:
            if call.hf_name in items:
                if not items[call.hf_name].item_type in self.allowed_types:
                    # Report this issue.
                    print('Error: ' +  self.fun_name + '(.., ' + call.hf_name + ', ...) called at ' +
                          self.file + ':' + str(call.line_number) +
                          ' with type ' + items[call.hf_name].item_type)
                    print('    (allowed types are', self.allowed_types, ')\n')
                    # Inc global count of issues found.
                    global issues_found
                    issues_found += 1


##################################################################################################
# This is a set of items (by filter name) where we know that the bitmask is non-contiguous,
# but is still believed to be correct.
known_non_contiguous_fields = { 'wlan.fixed.capabilities.cfpoll.sta',
                                'wlan.wfa.ie.wme.qos_info.sta.reserved',
                                'btrfcomm.frame_type',   # https://os.itec.kit.edu/downloads/sa_2006_roehricht-martin_flow-control-in-bluez.pdf
                                'capwap.control.message_element.ac_descriptor.dtls_policy.r', # RFC 5415
                                'couchbase.extras.subdoc.flags.reserved',
                                'wlan.fixed.capabilities.cfpoll.ap',   # These are 3 separate bits...
                                'wlan.wfa.ie.wme.tspec.ts_info.reserved', # matches other fields in same sequence
                                'zbee_zcl_se.pp.attr.payment_control_configuration.reserved', # matches other fields in same sequence
                                'zbee_zcl_se.pp.snapshot_payload_cause.reserved'  # matches other fields in same sequence
                              }
##################################################################################################


field_widths = {
    'FT_BOOLEAN' : 64,   # Width depends upon 'display' field, not checked.
    'FT_UINT8'   : 8,
    'FT_INT8'    : 8,
    'FT_UINT16'  : 16,
    'FT_INT16'   : 16,
    'FT_UINT24'  : 24,
    'FT_INT24'   : 24,
    'FT_UINT32'  : 32,
    'FT_INT32'   : 32,
    'FT_UINT40'  : 40,
    'FT_INT40'   : 40,
    'FT_UINT64'  : 64,
    'FT_INT64'   : 64
}


# The relevant parts of an hf item.  Used as value in dict where hf variable name is key.
class Item:
    def __init__(self, filename, filter, label, item_type, mask=None, check_mask=False, check_label=False):
        self.filename = filename
        self.filter = filter
        self.label = label

        # Optionally check label.
        if check_label:
            if label.startswith(' ') or label.endswith(' '):
                print('Warning:  ' + filename + 'filter=' + filter +  ' \"' + label + '\" begins or ends with a space')

        self.item_type = item_type

        # Optionally check that mask bits are contiguous
        if check_mask:
            if not mask in { 'NULL', '0x0', '0'}:
                self.check_contiguous_bits(mask)


    # Return true if bit position n is set in value.
    def check_bit(self, value, n):
        return (value & (0x1 << n)) != 0

    # Output a warning if non-contigous bits are found in the the mask (guint64).
    # Note that this legimately happens in several dissectors where multiple reserved/unassigned
    # bits are conflated into one field.
    # TODO: there is probably a cool/efficient way to check this?
    def check_contiguous_bits(self, mask):
        try:
            # Read according to the appropriate base.
            if mask.startswith('0x'):
                value = int(mask, 16)
            elif mask.startswith('0'):
                value = int(mask, 8)
            else:
                value = int(mask, 10)

            # Walk past any l.s. 0 bits
            n = 0
            while not self.check_bit(value, n) and n <= 63:
                n += 1
            if n==63:
                return

            mask_start = n
            # Walk through any bits that are set
            while self.check_bit(value, n) and n <= 63:
                n += 1
            n += 1

            if n >= 63:
                return

            # Look up the field width
            field_width = 0
            if not self.item_type in field_widths:
                print('unexpected item_type is ', self.item_type)
                field_width = 64
            else:
                field_width = field_widths[self.item_type]


            # Its a problem is the mask_width is > field_width - some of the bits won't get looked at!?
            mask_width = n-1-mask_start
            if mask_width > field_width:
                print('Error: ', self.filename, 'filter=', self.filter, self.item_type, 'so field_width=', field_width,
                      'but mask is', mask, 'which is', mask_width, 'bits wide!')
                global issues_found
                issues_found += 1

            # Now, any more zero set bits are an error!
            if self.filter in known_non_contiguous_fields:
                # Don't report if we know this one is Ok.
                return
            while n <= 63:
                if self.check_bit(value, n):
                    print('Warning: ', self.filename, 'filter=', self.filter, ' - mask with non-contiguous bits', mask)
                    return
                n += 1

        except:
            # Sometimes, macro is used for item type so catch and keep going.
            pass


# These are APIs in proto.c that check a set of types at runtime and can print '.. is not of type ..' to the console
# if the type is not suitable.
apiChecks = []
apiChecks.append(APICheck('proto_tree_add_item_ret_uint', { 'FT_CHAR', 'FT_UINT8', 'FT_UINT16', 'FT_UINT24', 'FT_UINT32'}))
apiChecks.append(APICheck('proto_tree_add_item_ret_int', { 'FT_INT8', 'FT_INT16', 'FT_INT24', 'FT_INT32'}))
apiChecks.append(APICheck('ptvcursor_add_ret_uint', { 'FT_CHAR', 'FT_UINT8', 'FT_UINT16', 'FT_UINT24', 'FT_UINT32'}))
apiChecks.append(APICheck('ptvcursor_add_ret_int', { 'FT_INT8', 'FT_INT16', 'FT_INT24', 'FT_INT32'}))
apiChecks.append(APICheck('ptvcursor_add_ret_string', { 'FT_STRING', 'FT_STRINGZ', 'FT_UINT_STRING', 'FT_STRINGZPAD'}))
apiChecks.append(APICheck('ptvcursor_add_ret_boolean', { 'FT_BOOLEAN'}))
apiChecks.append(APICheck('proto_tree_add_item_ret_uint64', { 'FT_UINT40', 'FT_UINT48', 'FT_UINT56', 'FT_UINT64'}))
apiChecks.append(APICheck('proto_tree_add_item_ret_int64', { 'FT_INT40', 'FT_INT48', 'FT_INT56', 'FT_INT64'}))
apiChecks.append(APICheck('proto_tree_add_item_ret_boolean', { 'FT_BOOLEAN'}))
apiChecks.append(APICheck('proto_tree_add_item_ret_string_and_length', { 'FT_STRING', 'FT_STRINGZ', 'FT_UINT_STRING', 'FT_STRINGZPAD'}))
apiChecks.append(APICheck('proto_tree_add_item_ret_display_string_and_length', { 'FT_STRING', 'FT_STRINGZ', 'FT_UINT_STRING',
                                                                                 'FT_STRINGZPAD', 'FT_BYTES', 'FT_UINT_BYTES'}))
apiChecks.append(APICheck('proto_tree_add_item_ret_time_string', { 'FT_ABSOLUTE_TIME', 'FT_RELATIVE_TIME'}))
apiChecks.append(APICheck('proto_tree_add_uint', {  'FT_CHAR', 'FT_UINT8', 'FT_UINT16', 'FT_UINT24', 'FT_UINT32', 'FT_FRAMENUM'}))
apiChecks.append(APICheck('proto_tree_add_uint_format_value', {  'FT_CHAR', 'FT_UINT8', 'FT_UINT16', 'FT_UINT24', 'FT_UINT32', 'FT_FRAMENUM'}))
apiChecks.append(APICheck('proto_tree_add_uint_format', {  'FT_CHAR', 'FT_UINT8', 'FT_UINT16', 'FT_UINT24', 'FT_UINT32', 'FT_FRAMENUM'}))
apiChecks.append(APICheck('proto_tree_add_uint64', { 'FT_UINT40', 'FT_UINT48', 'FT_UINT56', 'FT_UINT64', 'FT_FRAMENUM'}))
apiChecks.append(APICheck('proto_tree_add_int64', { 'FT_INT40', 'FT_INT48', 'FT_INT56', 'FT_INT64'}))
apiChecks.append(APICheck('proto_tree_add_int64_format_value', { 'FT_INT40', 'FT_INT48', 'FT_INT56', 'FT_INT64'}))
apiChecks.append(APICheck('proto_tree_add_int64_format', { 'FT_INT40', 'FT_INT48', 'FT_INT56', 'FT_INT64'}))
apiChecks.append(APICheck('proto_tree_add_int', { 'FT_INT8', 'FT_INT16', 'FT_INT24', 'FT_INT32'}))
apiChecks.append(APICheck('proto_tree_add_int_format_value', { 'FT_INT8', 'FT_INT16', 'FT_INT24', 'FT_INT32'}))
apiChecks.append(APICheck('proto_tree_add_int_format', { 'FT_INT8', 'FT_INT16', 'FT_INT24', 'FT_INT32'}))
apiChecks.append(APICheck('proto_tree_add_boolean', { 'FT_BOOLEAN'}))
apiChecks.append(APICheck('proto_tree_add_boolean64', { 'FT_BOOLEAN'}))
apiChecks.append(APICheck('proto_tree_add_float', { 'FT_FLOAT'}))
apiChecks.append(APICheck('proto_tree_add_float_format', { 'FT_FLOAT'}))
apiChecks.append(APICheck('proto_tree_add_float_format_value', { 'FT_FLOAT'}))
apiChecks.append(APICheck('proto_tree_add_double', { 'FT_DOUBLE'}))
apiChecks.append(APICheck('proto_tree_add_double_format', { 'FT_DOUBLE'}))
apiChecks.append(APICheck('proto_tree_add_double_format_value', { 'FT_DOUBLE'}))
apiChecks.append(APICheck('proto_tree_add_string', { 'FT_STRING', 'FT_STRINGZ', 'FT_STRINGZPAD'}))
apiChecks.append(APICheck('proto_tree_add_string_format', { 'FT_STRING', 'FT_STRINGZ', 'FT_STRINGZPAD'}))
apiChecks.append(APICheck('proto_tree_add_string_format_value', { 'FT_STRING', 'FT_STRINGZ', 'FT_STRINGZPAD'}))
apiChecks.append(APICheck('proto_tree_add_guid', { 'FT_GUID'}))
apiChecks.append(APICheck('proto_tree_add_oid', { 'FT_OID'}))
apiChecks.append(APICheck('proto_tree_add_none_format', { 'FT_NONE'}))
# TODO: add proto_tree_add_ret_varint, eui APIs, uint64_bits, float_bits, boolean_bits?


def removeComments(code_string):
    code_string = re.sub(re.compile("/\*.*?\*/",re.DOTALL ) ,"" ,code_string) # C-style comment
    code_string = re.sub(re.compile("//.*?\n" ) ,"" ,code_string)             # C++-style comment
    return code_string

# Look for hf items in a dissector file.
def find_items(filename, check_mask=False, check_label=False):
    items = {}
    with open(filename, 'r') as f:
        contents = f.read()
        # Remove comments so as not to trip up RE.
        contents = removeComments(contents)
        matches = re.finditer(r'.*\{\s*\&(hf_.*),\s*{\s*\"(.+)\",\s*\"([a-zA-Z0-9_\-\.]+)\",\s*([A-Z0-9_]*),\s*.*,\s*([A-Z0-9x]*)\s*,', contents)
        for m in matches:
            # Store this item.
            hf = m.group(1)
            items[hf] = Item(filename, filter=m.group(3), label=m.group(2), item_type=m.group(4), mask=m.group(5),
                             check_mask=check_mask, check_label=check_label)
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


# Check the given dissector file.
def checkFile(filename, check_mask=False, check_label=False):
    # Find important parts of items.
    items = find_items(filename, check_mask, check_label)

    # Check each API
    for c in apiChecks:
        c.find_calls(filename)
        c.check_against_items(items)


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
parser.add_argument('--mask', action='store_true',
                   help='when set, check mask field too')
parser.add_argument('--label', action='store_true',
                   help='when set, check label field too')


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


# Now check the files.
for f in files:
    if should_exit:
        exit(1)
    checkFile(f, check_mask=args.mask, check_label=args.label)

# Show summary.
print(issues_found, 'issues found')
