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
# Attempt to check for allowed encoding types (most likely will be literal values |'d)?


# Try to exit soon after Ctrl-C is pressed.
should_exit = False

def signal_handler(sig, frame):
    global should_exit
    should_exit = True
    print('You pressed Ctrl+C - exiting')

signal.signal(signal.SIGINT, signal_handler)


warnings_found = 0
errors_found = 0

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


# These are variable names that have been seen to be used in calls..
common_hf_var_names = { 'hf_index', 'hf_item', 'hf_idx', 'hf_x', 'hf_id', 'hf_cookie', 'hf_flag',
                        'hf_dos_time', 'hf_dos_date', 'hf_value', 'hf_num',
                        'hf_cause_value', 'hf_uuid',
                        'hf_endian', 'hf_ip', 'hf_port', 'hf_suff', 'hf_string', 'hf_uint',
                        'hf_tag', 'hf_type', 'hf_hdr', 'hf_field', 'hf_opcode', 'hf_size',
                        'hf_entry' }

# A check for a particular API function.
class APICheck:
    def __init__(self, fun_name, allowed_types, positive_length=False):
        self.fun_name = fun_name
        self.allowed_types = allowed_types
        self.positive_length = positive_length
        self.calls = []

        if fun_name.startswith('ptvcursor'):
            # RE captures function name + 1st 2 args (always ptvc + hfindex)
            self.p = re.compile('[^\n]*' +  self.fun_name + '\(([a-zA-Z0-9_]+),\s*([a-zA-Z0-9_]+)')
        elif fun_name.find('add_bitmask') == -1:
            # Normal case.
            # RE captures function name + 1st 2 args (always tree + hfindex + length)
            self.p = re.compile('[^\n]*' +  self.fun_name + '\(([a-zA-Z0-9_]+),\s*([a-zA-Z0-9_]+),\s*[a-zA-Z0-9_]+,\s*[a-zA-Z0-9_]+,\s*([a-zA-Z0-9_]+)')
        else:
            # _add_bitmask functions.
            # RE captures function name + 1st + 4th args (always tree + hfindex)
            self.p = re.compile('[^\n]*' +  self.fun_name + '\(([a-zA-Z0-9_]+),\s*[a-zA-Z0-9_]+,\s*[a-zA-Z0-9_]+,\s*([a-zA-Z0-9_]+)')

        self.file = None


    def find_calls(self, file):
        self.file = file
        self.calls = []

        with open(file, 'r') as f:
            contents = f.read()
            lines = contents.splitlines()
            total_lines = len(lines)
            for line_number,line in enumerate(lines):
                # Want to check this, and next few lines
                to_check = lines[line_number-1] + '\n'
                # Nothing to check if function name isn't in it
                if to_check.find(self.fun_name) != -1:
                    # Ok, add the next file lines before trying RE
                    for i in range(1, 4):
                        if to_check.find(';') != -1:
                            break
                        elif line_number+i < total_lines:
                            to_check += (lines[line_number-1+i] + '\n')
                    m = self.p.search(to_check)
                    if m:
                        # Add call. We have length if re had 3 groups.
                        num_groups = self.p.groups
                        self.calls.append(Call(m.group(2),
                                               line_number=line_number,
                                               length=(m.group(3) if (num_groups==3) else None)))



    def check_against_items(self, items_defined, items_declared, items_declared_extern, check_missing_items=False):
        global errors_found
        global warnings_found

        for call in self.calls:
            if self.positive_length and call.length != None:
                if call.length != -1 and call.length <= 0:
                    print('Error: ' +  self.fun_name + '(.., ' + call.hf_name + ', ...) called at ' +
                          self.file + ':' + str(call.line_number) +
                          ' with length ' + str(call.length) + ' - must be > 0 or -1')
                    # Inc global count of issues found.
                    errors_found += 1
            if call.hf_name in items_defined:
                if not items_defined[call.hf_name].item_type in self.allowed_types:
                    # Report this issue.
                    print('Error: ' +  self.fun_name + '(.., ' + call.hf_name + ', ...) called at ' +
                          self.file + ':' + str(call.line_number) +
                          ' with type ' + items_defined[call.hf_name].item_type)
                    print('    (allowed types are', self.allowed_types, ')\n')
                    # Inc global count of issues found.
                    errors_found += 1
            elif check_missing_items:
                if call.hf_name in items_declared and not call.hf_name in items_declared_extern:
                #not in common_hf_var_names:
                    print('Warning:', self.file + ':' + str(call.line_number),
                          self.fun_name + ' called for "' + call.hf_name + '"', ' - but no item found')
                    warnings_found += 1



class ProtoTreeAddItemCheck(APICheck):
    def __init__(self, ptv=None):

        # RE will capture whole call.  N.B. only looking at calls with literal numerical length field.

        if not ptv:
            # proto_item *
            # proto_tree_add_item(proto_tree *tree, int hfindex, tvbuff_t *tvb,
            #                     const gint start, gint length, const guint encoding)
            self.fun_name = 'proto_tree_add_item'
            self.p = re.compile('[^\n]*' + self.fun_name + '\([a-zA-Z0-9_]+,\s*([a-zA-Z0-9_]+),\s*[a-zA-Z0-9_]+,\s*[a-zA-Z0-9_]+,\s*([0-9]+),\s*([a-zA-Z0-9_]+)')
        else:
            # proto_item *
            # ptvcursor_add(ptvcursor_t *ptvc, int hfindex, gint length,
            #               const guint encoding)
            self.fun_name = 'ptvcursor_add'
            self.p = re.compile('[^\n]*' + self.fun_name + '\([a-zA-Z0-9_]+,\s*([a-zA-Z0-9_]+),\s*([a-zA-Z_0-9]+),\s*([a-zA-Z0-9_]+)')


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
        self.lengths['FT_ETHER']  = 6
        # TODO: other types...

    def find_calls(self, file):
        self.file = file
        self.calls = []
        with open(file, 'r') as f:

            contents = f.read()
            lines = contents.splitlines()
            total_lines = len(lines)
            for line_number,line in enumerate(lines):
                # Want to check this, and next few lines
                to_check = lines[line_number-1] + '\n'
                # Nothing to check if function name isn't in it
                if to_check.find(self.fun_name) != -1:
                    # Ok, add the next file lines before trying RE
                    for i in range(1, 5):
                        if to_check.find(';') != -1:
                            break
                        elif line_number+i < total_lines:
                            to_check += (lines[line_number-1+i] + '\n')
                    m = self.p.search(to_check)
                    if m:
                        self.calls.append(Call(m.group(1), line_number=line_number, length=m.group(2)))

    def check_against_items(self, items_defined, items_declared, items_declared_extern, check_missing_items=False):
        # For now, only complaining if length if call is longer than the item type implies.
        #
        # Could also be bugs where the length is always less than the type allows.
        # Would involve keeping track (in the item) of whether any call had used the full length.

        global warnings_found

        for call in self.calls:
            if call.hf_name in items_defined:
                if call.length and items_defined[call.hf_name].item_type in self.lengths:
                    if self.lengths[items_defined[call.hf_name].item_type] < call.length:
                        print('Warning:', self.file + ':' + str(call.line_number),
                              self.fun_name + ' called for', call.hf_name, ' - ',
                              'item type is', items_defined[call.hf_name].item_type, 'but call has len', call.length)
                        warnings_found += 1
            elif check_missing_items:
                if call.hf_name in items_declared and not call.hf_name in items_declared_extern:
                #not in common_hf_var_names:
                    print('Warning:', self.file + ':' + str(call.line_number),
                          self.fun_name + ' called for "' + call.hf_name + '"', ' - but no item found')
                    warnings_found += 1



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
                                'v120.lli',  # non-contiguous field (http://www.acacia-net.com/wwwcla/protocol/v120_l2.htm)
                                'stun.type.class',
                                'bssgp.csg_id',
                                'telnet.auth.mod.enc', 'osc.message.midi.bender', 'btle.data_header.rfu'

                              }
##################################################################################################


field_widths = {
    'FT_BOOLEAN' : 64,   # TODO: Width depends upon 'display' field
    'FT_CHAR'    : 8,
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

    def __init__(self, filename, filter, label, item_type, type_modifier, mask=None, check_mask=False, check_label=False, check_consecutive=False):
        self.filename = filename
        self.filter = filter
        self.label = label

        self.mask = mask

        global warnings_found

        if check_mask or check_consecutive:
            self.set_mask_value()

        if check_consecutive:
            if Item.previousItem and Item.previousItem.filter == filter:
                if label != Item.previousItem.label:
                    print('Warning: ' + filename + ': - filter "' + filter +
                          '" appears consecutively - labels are "' + Item.previousItem.label + '" and "' + label + '"')
                    warnings_found += 1

            Item.previousItem = self


        # Optionally check label.
        if check_label:
            if label.startswith(' ') or label.endswith(' '):
                print('Warning: ' + filename + ' filter "' + filter +  '" label' + label + '" begins or ends with a space')
                warnings_found += 1

            if (label.count('(') != label.count(')') or
                label.count('[') != label.count(']') or
                label.count('{') != label.count('}')):
                print('Warning: ' + filename + ': - filter "' + filter + '" label', '"' + label + '"', 'has unbalanced parens/braces/brackets')
                warnings_found += 1
            if item_type != 'FT_NONE' and label.endswith(':'):
                print('Warning: ' + filename + ': - filter "' + filter + '" label', '"' + label + '"', 'ends with an unnecessary colon')
                warnings_found += 1

        self.item_type = item_type
        self.type_modifier = type_modifier

        # Optionally check that mask bits are contiguous
        if check_mask:
            if self.mask_read and not mask in { 'NULL', '0x0', '0', '0x00'}:
                self.check_contiguous_bits(mask)
                #self.check_mask_too_long(mask)
                self.check_num_digits(mask)
                self.check_digits_all_zeros(mask)


    def set_mask_value(self):
        try:
            self.mask_read = True
            if any(not c in '0123456789abcdefABCDEFxX' for c in self.mask):
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
        except:
            self.mask_read = False
            self.mask_value = 0


    # Return true if bit position n is set in value.
    def check_bit(self, value, n):
        return (value & (0x1 << n)) != 0

    # Output a warning if non-contigous bits are found in the mask (guint64).
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
            field_width = self.get_field_width_in_bits()


        # Its a problem is the mask_width is > field_width - some of the bits won't get looked at!?
        mask_width = n-1-mask_start
        if mask_width > field_width:
            # N.B. No call, so no line number.
            print(self.filename + ':', 'filter=', self.filter, self.item_type, 'so field_width=', field_width,
                  'but mask is', mask, 'which is', mask_width, 'bits wide!')
            global warnings_found
            warnings_found += 1

        # Now, any more zero set bits are an error!
        if self.filter in known_non_contiguous_fields or self.filter.startswith('rtpmidi'):
            # Don't report if we know this one is Ok.
            return
        while n <= 63:
            if self.check_bit(self.mask_value, n):
                print('Warning:', self.filename, 'filter=', self.filter, ' - mask with non-contiguous bits', mask)
                warnings_found += 1
                return
            n += 1

    def get_field_width_in_bits(self):
        if self.item_type == 'FT_BOOLEAN':
            if self.type_modifier == 'NULL':
                return 8  # i.e. 1 byte
            elif self.type_modifier == 'BASE_NONE':
                return 8
            elif self.type_modifier == 'SEP_DOT':
                return 64
            else:
                # Round up to next nibble.
                return int(self.type_modifier)+3
        else:
            return field_widths[self.item_type]

    def check_mask_too_long(self, mask):
        if not self.mask_value:
            return
        if mask.startswith('0x00') or mask.endswith('00'):
            # There may be good reasons for having a wider field/mask, e.g. if there are 32 related flags, showing them
            # all lined up as part of the same word may make it clearer.  But some cases have been found
            # where the grouping does not seem to be natural..
            print('Warning:', self.filename, 'filter=', self.filter, ' - mask with leading or trailing 0 bytes suggests field', self.item_type, 'may be wider than necessary?', mask)
            global warnings_found
            warnings_found += 1

    def check_num_digits(self, mask):
        if mask.startswith('0x') and len(mask) > 3:
            global warnings_found
            global errors_found
            if len(mask) % 2:
                print('Warning:', self.filename, 'filter=', self.filter, ' - mask has odd number of digits', mask,
                      'expected max for', self.item_type, 'is', int((self.get_field_width_in_bits())/4))
                warnings_found += 1

            if self.item_type in field_widths:
                if len(mask)-2 > self.get_field_width_in_bits()/4:
                    extra_digits = mask[2:2+(len(mask)-2 - int(self.get_field_width_in_bits()/4))]
                    # Its an error if any of these are non-zero, as they won't have any effect!
                    if extra_digits != '0'*len(extra_digits):
                        print('Error:', self.filename, 'filter=', self.filter, self.mask, "with len is", len(mask)-2,
                              "but type", self.item_type, " indicates max of", int(self.get_field_width_in_bits()/4),
                              "and extra digits are non-zero (" + extra_digits + ")")
                        errors_found += 1
                    else:
                        # If has leading zeros, still confusing, so warn.
                        print('Warning:', self.filename, 'filter=', self.filter, self.mask, "with len is", len(mask)-2,
                              "but type", self.item_type, " indicates max of", int(self.get_field_width_in_bits()/4))
                        warnings_found += 1

            else:
                print('Warning:', self.filename, 'filter=', self.filter, ' - item has type', self.item_type, 'but mask set:', mask)
                warnings_found += 1

    def check_digits_all_zeros(self, mask):
        if mask.startswith('0x') and len(mask) > 3:
            if mask[2:] == '0'*(len(mask)-2):
                print('Warning:', self.filename, 'filter=', self.filter, ' - item has all zeros - this is confusing! :', mask)
                global warnings_found
                warnings_found += 1


class CombinedCallsCheck:
    def __init__(self, file, apiChecks):
        self.file = file
        self.apiChecks = apiChecks
        self.get_all_calls()

    def get_all_calls(self):
        self.all_calls = []
        # Combine calls into one list.
        for check in self.apiChecks:
            self.all_calls += check.calls

        # Sort by line number.
        self.all_calls.sort(key=lambda x:x.line_number)

    def check_consecutive_item_calls(self):
        lines = open(self.file, 'r').read().splitlines()

        prev = None
        for call in self.all_calls:
            if prev and call.hf_name == prev.hf_name:
                # More compelling if close together..
                if call.line_number>prev.line_number and call.line_number-prev.line_number <= 4:
                    scope_different = False
                    for l in range(prev.line_number, call.line_number-1):
                        if lines[l].find('{') != -1 or lines[l].find('}') != -1 or lines[l].find('else') != -1 or lines[l].find('break;') != -1 or lines[l].find('if ') != -1:
                            scope_different = True
                            break
                    # Also more compelling if check for and scope changes { } in lines in-between?
                    if not scope_different:
                        print('Warning:', f + ':' + str(call.line_number),
                              call.hf_name + ' called consecutively at line', call.line_number, '- previous at', prev.line_number)
                        global warnings_found
                        warnings_found += 1
            prev = call




# These are APIs in proto.c that check a set of types at runtime and can print '.. is not of type ..' to the console
# if the type is not suitable.
apiChecks = []
apiChecks.append(APICheck('proto_tree_add_item_ret_uint', { 'FT_CHAR', 'FT_UINT8', 'FT_UINT16', 'FT_UINT24', 'FT_UINT32'}, positive_length=True))
apiChecks.append(APICheck('proto_tree_add_item_ret_int', { 'FT_INT8', 'FT_INT16', 'FT_INT24', 'FT_INT32'}))
apiChecks.append(APICheck('ptvcursor_add_ret_uint', { 'FT_CHAR', 'FT_UINT8', 'FT_UINT16', 'FT_UINT24', 'FT_UINT32'}, positive_length=True))
apiChecks.append(APICheck('ptvcursor_add_ret_int', { 'FT_INT8', 'FT_INT16', 'FT_INT24', 'FT_INT32'}, positive_length=True))
apiChecks.append(APICheck('ptvcursor_add_ret_string', { 'FT_STRING', 'FT_STRINGZ', 'FT_UINT_STRING', 'FT_STRINGZPAD', 'FT_STRINGZTRUNC'}))
apiChecks.append(APICheck('ptvcursor_add_ret_boolean', { 'FT_BOOLEAN'}, positive_length=True))
apiChecks.append(APICheck('proto_tree_add_item_ret_uint64', { 'FT_UINT40', 'FT_UINT48', 'FT_UINT56', 'FT_UINT64'}, positive_length=True))
apiChecks.append(APICheck('proto_tree_add_item_ret_int64', { 'FT_INT40', 'FT_INT48', 'FT_INT56', 'FT_INT64'}, positive_length=True))
apiChecks.append(APICheck('proto_tree_add_item_ret_boolean', { 'FT_BOOLEAN'}, positive_length=True))
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
# TODO: positions are different, and takes 2 hf_fields..
#apiChecks.append(APICheck('proto_tree_add_checksum', { 'FT_UINT8', 'FT_UINT16', 'FT_UINT24', 'FT_UINT32'}))
apiChecks.append(APICheck('proto_tree_add_int64_bits_format_value', { 'FT_INT40', 'FT_INT48', 'FT_INT56', 'FT_INT64'}))

# TODO: add proto_tree_add_bytes_item, proto_tree_add_time_item ?

bitmask_types = { 'FT_CHAR', 'FT_UINT8', 'FT_UINT16', 'FT_UINT24', 'FT_UINT32',
                  'FT_INT8', 'FT_INT16', 'FT_INT24', 'FT_INT32',
                  'FT_UINT40', 'FT_UINT48', 'FT_UINT56', 'FT_UINT64',
                  'FT_INT40', 'FT_INT48', 'FT_INT56', 'FT_INT64',
                   'FT_BOOLEAN'}
apiChecks.append(APICheck('proto_tree_add_bitmask', bitmask_types))
apiChecks.append(APICheck('proto_tree_add_bitmask_tree', bitmask_types))
apiChecks.append(APICheck('proto_tree_add_bitmask_ret_uint64', bitmask_types))
apiChecks.append(APICheck('proto_tree_add_bitmask_with_flags', bitmask_types))
apiChecks.append(APICheck('proto_tree_add_bitmask_with_flags_ret_uint64', bitmask_types))
apiChecks.append(APICheck('proto_tree_add_bitmask_value', bitmask_types))
apiChecks.append(APICheck('proto_tree_add_bitmask_value_with_flags', bitmask_types))
apiChecks.append(APICheck('proto_tree_add_bitmask_len', bitmask_types))
# TODO: doesn't even have an hf_item !
#apiChecks.append(APICheck('proto_tree_add_bitmask_text', bitmask_types))

# Check some ptvcuror calls too.
apiChecks.append(APICheck('ptvcursor_add_ret_uint', { 'FT_CHAR', 'FT_UINT8', 'FT_UINT16', 'FT_UINT24', 'FT_UINT32'}))
apiChecks.append(APICheck('ptvcursor_add_ret_int', { 'FT_INT8', 'FT_INT16', 'FT_INT24', 'FT_INT32'}))
apiChecks.append(APICheck('ptvcursor_add_ret_boolean', { 'FT_BOOLEAN'}))


# Also try to check proto_tree_add_item() calls (for length)
apiChecks.append(ProtoTreeAddItemCheck())
apiChecks.append(ProtoTreeAddItemCheck(True)) # for ptvcursor_add()



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
            line.find('This filter was automatically generated') != -1 or
            line.find('This file is auto generated, do not edit!') != -1):

            f_read.close()
            return True
        lines_tested = lines_tested + 1

    # OK, looks like a hand-written file!
    f_read.close()
    return False

# Look for hf items (i.e. full item to be registered) in a dissector file.
def find_items(filename, check_mask=False, check_label=False, check_consecutive=False):
    is_generated = isGeneratedFile(filename)
    items = {}
    with open(filename, 'r') as f:
        contents = f.read()
        # Remove comments so as not to trip up RE.
        contents = removeComments(contents)
        matches = re.finditer(r'.*\{\s*\&(hf_[a-z_A-Z0-9]*)\s*,\s*{\s*\"*(.+)\"*\s*,\s*\"([a-zA-Z0-9_\-\.]+)\"\s*,\s*([a-zA-Z0-9_]*)\s*,\s*(.*)\s*,\s*([\&A-Za-z0-9x_<\|\s\(\)]*)\s*,\s*([ a-zA-Z0-9x_\<\~\|\(\)]*)\s*,', contents)
        for m in matches:
            # Store this item.
            hf = m.group(1)
            items[hf] = Item(filename, filter=m.group(3), label=m.group(2), item_type=m.group(4), mask=m.group(7),
                             type_modifier=m.group(5),
                             check_mask=check_mask,
                             check_label=check_label,
                             check_consecutive=(not is_generated and check_consecutive))
    return items

def find_item_declarations(filename):
    items = set()

    with open(filename, 'r') as f:
        lines = f.read().splitlines()
        p = re.compile(r'^static int (hf_[a-zA-Z0-9_]*)\s*\=\s*-1;')
        for line in lines:
            m = p.search(line)
            if m:
                items.add(m.group(1))
    return items

def find_item_extern_declarations(filename):
    items = set()
    with open(filename, 'r') as f:
        lines = f.read().splitlines()
        p = re.compile(r'^\s*(hf_[a-zA-Z0-9_]*)\s*\=\s*proto_registrar_get_id_byname\s*\(')
        for line in lines:
            m = p.search(line)
            if m:
                items.add(m.group(1))
    return items


def is_dissector_file(filename):
    p = re.compile(r'.*(packet|file)-.*\.c$')
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
def checkFile(filename, check_mask=False, check_label=False, check_consecutive=False, check_missing_items=False):
    # Check file exists - e.g. may have been deleted in a recent commit.
    if not os.path.exists(filename):
        print(filename, 'does not exist!')
        return

    # Find important parts of items.
    items_defined = find_items(filename, check_mask, check_label, check_consecutive)
    items_extern_declared = {}

    items_declared = {}
    if check_missing_items:
        items_declared = find_item_declarations(filename)
        items_extern_declared = find_item_extern_declarations(filename)


    # Check each API
    for c in apiChecks:
        c.find_calls(filename)
        c.check_against_items(items_defined, items_declared, items_extern_declared, check_missing_items)



#################################################################
# Main logic.

# command-line args.  Controls which dissector files should be checked.
# If no args given, will just scan epan/dissectors folder.
parser = argparse.ArgumentParser(description='Check calls in dissectors')
parser.add_argument('--file', action='append',
                    help='specify individual dissector file to test')
parser.add_argument('--folder', action='store', default='',
                    help='specify folder to test')
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
parser.add_argument('--missing-items', action='store_true',
                    help='when set, look for used items that were never registered')



args = parser.parse_args()


# Get files from wherever command-line args indicate.
files = []
if args.file:
    # Add specified file(s)
    for f in args.file:
        if not f.startswith('epan'):
            f = os.path.join('epan', 'dissectors', f)
        if not os.path.isfile(f):
            print('Chosen file', f, 'does not exist.')
            exit(1)
        else:
            files.append(f)
elif args.folder:
    # Add all files from a given folder.
    folder = args.folder
    if not os.path.isdir(folder):
        print('Folder', folder, 'not found!')
        exit(1)
    # Find files from folder.
    print('Looking for files in', folder)
    files = findDissectorFilesInFolder(folder, recursive=True)
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
    checkFile(f, check_mask=args.mask, check_label=args.label,
              check_consecutive=args.consecutive, check_missing_items=args.missing_items)

    # Do checks against all calls.
    if args.consecutive:
        combined_calls = CombinedCallsCheck(f, apiChecks)
        combined_calls.check_consecutive_item_calls()


# Show summary.
print(warnings_found, 'warnings')
if errors_found:
    print(errors_found, 'errors')
    exit(1)
