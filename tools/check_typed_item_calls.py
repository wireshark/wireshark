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

# This utility scans the dissector code for proto_tree_add_...() calls that constrain the type
# or length of the item added, and checks that the used item is acceptable.
#
# Note that this can only work where the hf_item variable or length is passed in directly - where it
# is assigned to a different variable or a macro is used, it isn't tracked.

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
    def __init__(self, hf_name, line_number=None, length=None):
       self.hf_name = hf_name
       self.line_number = line_number
       self.length = None
       if length:
           try:
               self.length = int(length)
           except:
               pass


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
                    self.calls.append(Call(m.group(2), line_number=line_number))

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


class ProtoTreeAddItemCheck(APICheck):
    def __init__(self):
        # proto_item *
        # proto_tree_add_item(proto_tree *tree, int hfindex, tvbuff_t *tvb,
        #                     const gint start, gint length, const guint encoding)
        # RE will capture whole call.  N.B. only looking at calls with literal numerical length field.
        self.p = re.compile('.*proto_tree_add_item\(([a-zA-Z0-9_]+),\s*([a-zA-Z0-9_]+),\s*([a-zA-Z0-9_]+),\s*([a-zA-Z0-9_]+),\s*([0-9]+),\s*([a-zA-Z0-9_]+)')

        self.lengths = {}
        self.lengths['FT_CHAR']  = 1
        self.lengths['FT_UINT8']  = 1
        self.lengths['FT_INT8']   = 1
        self.lengths['FT_UINT16'] = 2
        self.lengths['FT_INT16']  = 2
        self.lengths['FT_UINT24'] = 3
        self.lengths['FT_INT24']  = 3
        self.lengths['FT_UINT32'] = 4
        self.lengths['FT_INT32']  = 4
        self.lengths['FT_UINT40'] = 5
        self.lengths['FT_INT40']  = 5
        self.lengths['FT_UINT48'] = 6
        self.lengths['FT_INT48']  = 6
        self.lengths['FT_UINT56'] = 7
        self.lengths['FT_INT56']  = 7
        self.lengths['FT_UINT64'] = 8
        self.lengths['FT_INT64']  = 8
        # TODO: for FT_BOOLEAN, could take length from 2nd arg (which is in bits...)
        self.lengths['FT_ETHER']  = 6
        # TODO: other types...

    def find_calls(self, file):
        self.file = file
        self.calls = []
        with open(file, 'r') as f:
            # TODO: would be better to just iterate over those found in whole file,
            # but extra effort would be needed to still know line number.
            for line_number, line in enumerate(f, start=1):
                m = self.p.match(line)
                if m:
                    self.calls.append(Call(m.group(2), line_number=line_number, length=m.group(5)))

    def check_against_items(self, items):
        # For now, only complaining if length if call is longer than the item type implies.
        #
        # Could also be bugs where the length is always less than the type allows.
        # Would involve keeping track (in the item) of whether any call had used the full length.

        for call in self.calls:
            if call.hf_name in items:
                if call.length and items[call.hf_name].item_type in self.lengths:
                    if self.lengths[items[call.hf_name].item_type] < call.length:
                        print(self.file + ':' + str(call.line_number),
                              'proto_tree_add_item called for', call.hf_name, ' - ',
                              'item type is', items[call.hf_name].item_type, 'but call has len', call.length)

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
                                'zbee_zcl_se.pp.snapshot_payload_cause.reserved',  # matches other fields in same sequence
                                'ebhscr.eth.rsv',  # matches other fields in same sequence
                                'v120.lli'  # non-contiguous field (http://www.acacia-net.com/wwwcla/protocol/v120_l2.htm)
                              }
##################################################################################################


field_widths = {
    'FT_BOOLEAN' : 64,   # TODO: Width depends upon 'display' field, not checked.
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
    'FT_UINT48'  : 48,
    'FT_INT48'   : 48,
    'FT_UINT56'  : 56,
    'FT_INT56'   : 56,
    'FT_UINT64'  : 64,
    'FT_INT64'   : 64
}


# The relevant parts of an hf item.  Used as value in dict where hf variable name is key.
class Item:

    previousItem = None

    def __init__(self, filename, filter, label, item_type, mask=None, check_mask=False, check_label=False, check_consecutive=False):
        self.filename = filename
        self.filter = filter
        self.label = label

        self.mask = mask
        if check_mask or check_consecutive:
            self.set_mask_value()

        if check_consecutive:
            if Item.previousItem and Item.previousItem.filter == filter:
                if label != Item.previousItem.label:
                    print('Warn: ' + filename + ': - filter "' + filter +
                          '" appears consecutively - labels are "' + Item.previousItem.label + '" and "' + label + '"')
            if Item.previousItem and self.mask_value and (Item.previousItem.mask_value == self.mask_value):
                if label != Item.previousItem.label:
                    print('Warn: ' + filename + ': - mask ' + self.mask +
                          ' appears consecutively - labels are "' + Item.previousItem.label + '" and "' + label + '"')

            Item.previousItem = self


        # Optionally check label.
        if check_label:
            if label.startswith(' ') or label.endswith(' '):
                print('Warning:  ' + filename + 'filter=' + filter +  ' \"' + label + '\" begins or ends with a space')

        self.item_type = item_type

        # Optionally check that mask bits are contiguous
        if check_mask:
            if not mask in { 'NULL', '0x0', '0'}:
                self.check_contiguous_bits(mask)

    def set_mask_value(self):
        try:
            # Read according to the appropriate base.
            if self.mask.startswith('0x'):
                self.mask_value = int(self.mask, 16)
            elif self.mask.startswith('0'):
                self.mask_value = int(self.mask, 8)
            else:
                self.mask_value = int(self.mask, 10)
        except:
            self.mask_value = 0


    # Return true if bit position n is set in value.
    def check_bit(self, value, n):
        return (value & (0x1 << n)) != 0

    # Output a warning if non-contigous bits are found in the the mask (guint64).
    # Note that this legimately happens in several dissectors where multiple reserved/unassigned
    # bits are conflated into one field.
    # TODO: there is probably a cool/efficient way to check this?
    def check_contiguous_bits(self, mask):
        if not self.mask_value:
            return

        # Walk past any l.s. 0 bits
        n = 0
        while not self.check_bit(self.mask_value, n) and n <= 63:
            n += 1
        if n==63:
            return

        mask_start = n
        # Walk through any bits that are set
        while self.check_bit(self.mask_value, n) and n <= 63:
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
            # N.B. No call, so no line number.
            print(self.filename + ':', 'filter=', self.filter, self.item_type, 'so field_width=', field_width,
                  'but mask is', mask, 'which is', mask_width, 'bits wide!')
            global issues_found
            issues_found += 1

        # Now, any more zero set bits are an error!
        if self.filter in known_non_contiguous_fields:
            # Don't report if we know this one is Ok.
            return
        while n <= 63:
            if self.check_bit(self.mask_value, n):
                print('Warning: ', self.filename, 'filter=', self.filter, ' - mask with non-contiguous bits', mask)
                return
            n += 1



# These are APIs in proto.c that check a set of types at runtime and can print '.. is not of type ..' to the console
# if the type is not suitable.
apiChecks = []
apiChecks.append(APICheck('proto_tree_add_item_ret_uint', { 'FT_CHAR', 'FT_UINT8', 'FT_UINT16', 'FT_UINT24', 'FT_UINT32'}))
apiChecks.append(APICheck('proto_tree_add_item_ret_int', { 'FT_INT8', 'FT_INT16', 'FT_INT24', 'FT_INT32'}))
apiChecks.append(APICheck('ptvcursor_add_ret_uint', { 'FT_CHAR', 'FT_UINT8', 'FT_UINT16', 'FT_UINT24', 'FT_UINT32'}))
apiChecks.append(APICheck('ptvcursor_add_ret_int', { 'FT_INT8', 'FT_INT16', 'FT_INT24', 'FT_INT32'}))
apiChecks.append(APICheck('ptvcursor_add_ret_string', { 'FT_STRING', 'FT_STRINGZ', 'FT_UINT_STRING', 'FT_STRINGZPAD', 'FT_STRINGZTRUNC'}))
apiChecks.append(APICheck('ptvcursor_add_ret_boolean', { 'FT_BOOLEAN'}))
apiChecks.append(APICheck('proto_tree_add_item_ret_uint64', { 'FT_UINT40', 'FT_UINT48', 'FT_UINT56', 'FT_UINT64'}))
apiChecks.append(APICheck('proto_tree_add_item_ret_int64', { 'FT_INT40', 'FT_INT48', 'FT_INT56', 'FT_INT64'}))
apiChecks.append(APICheck('proto_tree_add_item_ret_boolean', { 'FT_BOOLEAN'}))
apiChecks.append(APICheck('proto_tree_add_item_ret_string_and_length', { 'FT_STRING', 'FT_STRINGZ', 'FT_UINT_STRING', 'FT_STRINGZPAD', 'FT_STRINGZTRUNC'}))
apiChecks.append(APICheck('proto_tree_add_item_ret_display_string_and_length', { 'FT_STRING', 'FT_STRINGZ', 'FT_UINT_STRING',
                                                                                 'FT_STRINGZPAD', 'FT_STRINGZTRUNC', 'FT_BYTES', 'FT_UINT_BYTES'}))
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
apiChecks.append(APICheck('proto_tree_add_string', { 'FT_STRING', 'FT_STRINGZ', 'FT_STRINGZPAD', 'FT_STRINGZTRUNC'}))
apiChecks.append(APICheck('proto_tree_add_string_format', { 'FT_STRING', 'FT_STRINGZ', 'FT_STRINGZPAD', 'FT_STRINGZTRUNC'}))
apiChecks.append(APICheck('proto_tree_add_string_format_value', { 'FT_STRING', 'FT_STRINGZ', 'FT_STRINGZPAD', 'FT_STRINGZTRUNC'}))
apiChecks.append(APICheck('proto_tree_add_guid', { 'FT_GUID'}))
apiChecks.append(APICheck('proto_tree_add_oid', { 'FT_OID'}))
apiChecks.append(APICheck('proto_tree_add_none_format', { 'FT_NONE'}))
apiChecks.append(APICheck('proto_tree_add_item_ret_varint', { 'FT_INT8', 'FT_INT16', 'FT_INT24', 'FT_INT32', 'FT_INT40', 'FT_INT48', 'FT_INT56', 'FT_INT64',
                                                              'FT_CHAR', 'FT_UINT8', 'FT_UINT16', 'FT_UINT24', 'FT_UINT32', 'FT_FRAMENUM',
                                                              'FT_UINT40', 'FT_UINT48', 'FT_UINT56', 'FT_UINT64',}))
apiChecks.append(APICheck('proto_tree_add_boolean_bits_format_value', { 'FT_BOOLEAN'}))
apiChecks.append(APICheck('proto_tree_add_boolean_bits_format_value64', { 'FT_BOOLEAN'}))
apiChecks.append(APICheck('proto_tree_add_ascii_7bits_item', { 'FT_STRING'}))
apiChecks.append(APICheck('proto_tree_add_checksum', { 'FT_UINT8', 'FT_UINT16', 'FT_UINT24', 'FT_UINT32'}))
apiChecks.append(APICheck('proto_tree_add_int64_bits_format_value', { 'FT_INT40', 'FT_INT48', 'FT_INT56', 'FT_INT64'}))

# Also try to check proto_tree_add_item() calls (for length)
apiChecks.append(ProtoTreeAddItemCheck())


def removeComments(code_string):
    code_string = re.sub(re.compile(r"/\*.*?\*/",re.DOTALL ) ,"" , code_string) # C-style comment
    code_string = re.sub(re.compile(r"//.*?\n" ) ,"" , code_string)             # C++-style comment
    return code_string

# Test for whether the given file was automatically generated.
def isGeneratedFile(filename):
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

# Look for hf items in a dissector file.
def find_items(filename, check_mask=False, check_label=False, check_consecutive=False):
    is_generated = isGeneratedFile(filename)
    items = {}
    with open(filename, 'r') as f:
        contents = f.read()
        # Remove comments so as not to trip up RE.
        contents = removeComments(contents)
        matches = re.finditer(r'.*\{\s*\&(hf_.*),\s*{\s*\"(.+)\",\s*\"([a-zA-Z0-9_\-\.]+)\",\s*([A-Z0-9_]*),\s*.*,\s*([A-Za-z0-9x]*)\s*,', contents)
        for m in matches:
            # Store this item.
            hf = m.group(1)
            items[hf] = Item(filename, filter=m.group(3), label=m.group(2), item_type=m.group(4), mask=m.group(5),
                             check_mask=check_mask,
                             check_label=check_label,
                             check_consecutive=(not is_generated and check_consecutive))
    return items



def is_dissector_file(filename):
    p = re.compile(r'.*packet-.*\.c')
    return p.match(filename)


def findDissectorFilesInFolder(folder, dissector_files=None, recursive=False):
    if dissector_files is None:
        dissector_files = []
    if recursive:
        for root, subfolders, files in os.walk(folder):
            for f in files:
                if should_exit:
                    return
                f = os.path.join(root, f)
                dissector_files.append(f)
    else:
        for f in sorted(os.listdir(folder)):
            if should_exit:
                return
            filename = os.path.join(folder, f)
            dissector_files.append(filename)

    return [x for x in filter(is_dissector_file, dissector_files)]



# Run checks on the given dissector file.
def checkFile(filename, check_mask=False, check_label=False, check_consecutive=False):
    # Check file exists - e.g. may have been deleted in a recent commit.
    if not os.path.exists(filename):
        print(filename, 'does not exist!')
        return

    # Find important parts of items.
    items = find_items(filename, check_mask, check_label, check_consecutive)

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
parser.add_argument('--consecutive', action='store_true',
                    help='when set, copy copy/paste errors between consecutive items')


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
    command = ['git', 'diff', '--name-only', '--diff-filter=d', 'HEAD~' + args.commits]
    files = [f.decode('utf-8')
             for f in subprocess.check_output(command).splitlines()]
    # Will examine dissector files only
    files = list(filter(lambda f : is_dissector_file(f), files))
elif args.open:
    # Unstaged changes.
    command = ['git', 'diff', '--name-only', '--diff-filter=d']
    files = [f.decode('utf-8')
             for f in subprocess.check_output(command).splitlines()]
    # Only interested in dissector files.
    files = list(filter(lambda f : is_dissector_file(f), files))
    # Staged changes.
    command = ['git', 'diff', '--staged', '--name-only', '--diff-filter=d']
    files_staged = [f.decode('utf-8')
                    for f in subprocess.check_output(command).splitlines()]
    # Only interested in dissector files.
    files_staged = list(filter(lambda f : is_dissector_file(f), files_staged))
    for f in files_staged:
        if not f in files:
            files.append(f)
else:
    # Find all dissector files.
    files = findDissectorFilesInFolder(os.path.join('epan', 'dissectors'))
    files = findDissectorFilesInFolder(os.path.join('plugins', 'epan'), recursive=True, dissector_files=files)


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
    checkFile(f, check_mask=args.mask, check_label=args.label, check_consecutive=args.consecutive)

# Show summary.
print(issues_found, 'issues found')
