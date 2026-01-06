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
from pathlib import Path
import concurrent.futures
from check_common import getFilesFromOpen, findDissectorFilesInFolder, getFilesFromCommits, removeComments, isGeneratedFile, Result


# This utility scans the dissector code for various issues.
# TODO:
# - Create maps from type -> display types for hf items (see display (FIELDDISPLAY (1.2))) in docs/README.dissector


# Try to exit soon after Ctrl-C is pressed.
should_exit = False


def signal_handler(sig, frame):
    global should_exit
    should_exit = True
    print('You pressed Ctrl+C - exiting')

signal.signal(signal.SIGINT, signal_handler)

warnings_found = 0
errors_found = 0


def name_has_one_of(name, substring_list):
    name_lower = name.lower()
    for word in substring_list:
        if word in name_lower:
            return True
    return False


# An individual call to an API we are interested in.
# Used by APICheck below.
class Call:
    def __init__(self, function_name, hf_name, macros, line_number=None, offset=None, length=None, fields=None, enc=None):
        self.hf_name = hf_name
        self.line_number = line_number
        self.function_name = function_name
        self.fields = fields
        self.enc = enc
        if enc:
            self.enc = self.enc.strip()
        self.length = None

        # Substitute length if necessary
        if length:
            try:
                # if '*' in offset and offset.find('*') != 0 and '8' in offset:
                #    print(hf_name, function_name, offset)
                self.length = int(length)
            except Exception:
                if length.isupper():
                    if length in macros:
                        try:
                            self.length = int(macros[length])
                        except Exception:
                            pass
                pass


# These are variable names that have been seen to be used in calls..
common_hf_var_names = {'hf_index', 'hf_item', 'hf_idx', 'hf_x', 'hf_id', 'hf_cookie', 'hf_flag',
                       'hf_dos_time', 'hf_dos_date', 'hf_value', 'hf_num',
                       'hf_cause_value', 'hf_uuid',
                       'hf_endian', 'hf_ip', 'hf_port', 'hf_suff', 'hf_string', 'hf_uint',
                       'hf_tag', 'hf_type', 'hf_hdr', 'hf_field', 'hf_opcode', 'hf_size',
                       'hf_entry', 'field'}

item_lengths = {}
item_lengths['FT_CHAR'] = 1
item_lengths['FT_UINT8'] = 1
item_lengths['FT_INT8'] = 1
item_lengths['FT_UINT16'] = 2
item_lengths['FT_INT16'] = 2
item_lengths['FT_UINT24'] = 3
item_lengths['FT_INT24'] = 3
item_lengths['FT_UINT32'] = 4
item_lengths['FT_INT32'] = 4
item_lengths['FT_UINT40'] = 5
item_lengths['FT_INT40'] = 5
item_lengths['FT_UINT48'] = 6
item_lengths['FT_INT48'] = 6
item_lengths['FT_UINT56'] = 7
item_lengths['FT_INT56'] = 7
item_lengths['FT_UINT64'] = 8
item_lengths['FT_INT64'] = 8
item_lengths['FT_ETHER'] = 6
item_lengths['FT_IPv4'] = 4
item_lengths['FT_IPv6'] = 16

# TODO: other types...


# Checking encoding args against item types.

# item type -> set<encodings>
# TODO: need to capture that they may include endian *and* some other property..
# TODO: should ENC_NA be allowed when e.g., FT_UINT16 field is called with 1-byte width?
compatible_encoding_args = {
    # doc/README.dissector says these should all be ENC_NA
    'FT_NONE':       set(['ENC_NA']),
    'FT_BYTES':      set(['ENC_NA']),
    'FT_ETHER':      set(['ENC_NA']),  # TODO: consider allowing 'ENC_LITTLE_ENDIAN' ?
    'FT_IPv6':       set(['ENC_NA']),
    'FT_IPXNET':     set(['ENC_NA']),
    'FT_OID':        set(['ENC_NA']),
    'FT_REL_OID':    set(['ENC_NA']),
    'FT_AX25':       set(['ENC_NA']),
    'FT_VINES':      set(['ENC_NA']),
    'FT_SYSTEM_ID':  set(['ENC_NA']),
    'FT_FCWWN':      set(['ENC_NA']),

    # TODO: FT_UINT_BYTES should have e.g., ENC_LITTLE_ENDIAN|ENC_NA

    'FT_IPv4':      set(['ENC_LITTLE_ENDIAN', 'ENC_BIG_ENDIAN', 'ENC_HOST_ENDIAN']),


    'FT_STRING':     set(['ENC_ASCII',
                          'ENC_UTF_8',
                          'ENC_UTF_16',
                          'ENC_UCS_2',
                          'ENC_UCS_4',
                          'ENC_WINDOWS_1250', 'ENC_WINDOWS_1251', 'ENC_WINDOWS_1252',
                          'ENC_ISO_646_BASIC',
                          'ENC_ISO_8859_1', 'ENC_ISO_8859_2', 'ENC_ISO_8859_3', 'ENC_ISO_8859_4',
                          'ENC_ISO_8859_5', 'ENC_ISO_8859_6', 'ENC_ISO_8859_7', 'ENC_ISO_8859_8',
                          'ENC_ISO_8859_9', 'ENC_ISO_8859_10', 'ENC_ISO_8859_11', 'ENC_ISO_8859_12',
                          'ENC_ISO_8859_13', 'ENC_ISO_8859_14', 'ENC_ISO_8859_15', 'ENC_ISO_8859_16',
                          'ENC_3GPP_TS_23_038_7BITS',
                          'ENC_3GPP_TS_23_038_7BITS_UNPACKED',
                          'ENC_ETSI_TS_102_221_ANNEX_A',
                          'ENC_APN_STR',
                          'ENC_EBCDIC',
                          'ENC_EBCDIC_CP037',
                          'ENC_EBCDIC_CP500',
                          'ENC_MAC_ROMAN',
                          'ENC_CP437',
                          'ENC_CP855',
                          'ENC_CP866',
                          'ENC_ASCII_7BITS',
                          'ENC_T61',
                          'ENC_BCD_DIGITS_0_9', 'ENC_BCD_SKIP_FIRST', 'ENC_BCD_ODD_NUM_DIG',
                          'ENC_LITTLE_ENDIAN', 'ENC_BIG_ENDIAN',   # These are allowed if ENC_BCD_DIGITS_0_9 is set..
                          'ENC_KEYPAD_ABC_TBCD',
                          'ENC_KEYPAD_BC_TBCD',
                          'ENC_GB18030',
                          'ENC_EUC_KR',
                          'ENC_DECT_STANDARD_8BITS',
                          'ENC_DECT_STANDARD_4BITS_TBCD',
                          # Are these right..?
                          # 'ENC_STR_HEX',       # Should also have at least one ENC_SEP_* flag!
                          # 'ENC_STR_NUM',       # Should also have at least one ENC_SEP_* flag!
                          # 'ENC_STRING',        # OR of previous 2 values

                          'ENC_LITTLE_ENDIAN'  # Only meaniningful for some encodings (ENC_UTF_16, ENC_UCS_2, ENC_UCS_4)
                          ]),

    'FT_CHAR':      set(['ENC_ASCII', 'ENC_VARIANT_QUIC', 'ENC_ASCII_7BITS']),  # TODO: others?

    # Integral types
    'FT_UINT8':     set(['ENC_LITTLE_ENDIAN', 'ENC_BIG_ENDIAN', 'ENC_HOST_ENDIAN', 'ENC_NA']),
    'FT_INT8':      set(['ENC_LITTLE_ENDIAN', 'ENC_BIG_ENDIAN', 'ENC_HOST_ENDIAN', 'ENC_NA']),
    'FT_UINT16':    set(['ENC_LITTLE_ENDIAN', 'ENC_BIG_ENDIAN', 'ENC_HOST_ENDIAN']),
    'FT_INT16':     set(['ENC_LITTLE_ENDIAN', 'ENC_BIG_ENDIAN', 'ENC_HOST_ENDIAN']),
    'FT_UINT24':    set(['ENC_LITTLE_ENDIAN', 'ENC_BIG_ENDIAN', 'ENC_HOST_ENDIAN']),
    'FT_INT24':     set(['ENC_LITTLE_ENDIAN', 'ENC_BIG_ENDIAN', 'ENC_HOST_ENDIAN']),
    'FT_UINT32':    set(['ENC_LITTLE_ENDIAN', 'ENC_BIG_ENDIAN', 'ENC_HOST_ENDIAN']),
    'FT_INT32':     set(['ENC_LITTLE_ENDIAN', 'ENC_BIG_ENDIAN', 'ENC_HOST_ENDIAN']),
    'FT_UINT40':    set(['ENC_LITTLE_ENDIAN', 'ENC_BIG_ENDIAN', 'ENC_HOST_ENDIAN']),
    'FT_INT40':     set(['ENC_LITTLE_ENDIAN', 'ENC_BIG_ENDIAN', 'ENC_HOST_ENDIAN']),
    'FT_UINT48':    set(['ENC_LITTLE_ENDIAN', 'ENC_BIG_ENDIAN', 'ENC_HOST_ENDIAN']),
    'FT_INT48':     set(['ENC_LITTLE_ENDIAN', 'ENC_BIG_ENDIAN', 'ENC_HOST_ENDIAN']),
    'FT_UINT56':    set(['ENC_LITTLE_ENDIAN', 'ENC_BIG_ENDIAN', 'ENC_HOST_ENDIAN']),
    'FT_INT56':     set(['ENC_LITTLE_ENDIAN', 'ENC_BIG_ENDIAN', 'ENC_HOST_ENDIAN']),
    'FT_UINT64':    set(['ENC_LITTLE_ENDIAN', 'ENC_BIG_ENDIAN', 'ENC_HOST_ENDIAN']),
    'FT_INT64':     set(['ENC_LITTLE_ENDIAN', 'ENC_BIG_ENDIAN', 'ENC_HOST_ENDIAN']),

    'FT_GUID':      set(['ENC_LITTLE_ENDIAN', 'ENC_BIG_ENDIAN']),
    'FT_EUI64':     set(['ENC_LITTLE_ENDIAN', 'ENC_BIG_ENDIAN']),

    # It does seem harsh to need to set this when field is 8 bits of less..
    'FT_BOOLEAN':   set(['ENC_LITTLE_ENDIAN', 'ENC_BIG_ENDIAN']),


    # N.B., these fields should also have an endian order...
    'FT_ABSOLUTE_TIME':   set(['ENC_LITTLE_ENDIAN', 'ENC_BIG_ENDIAN',
                               'ENC_TIME_SECS_NSECS', 'ENC_TIME_NTP', 'ENC_TIME_TOD',
                               'ENC_TIME_RTPS', 'ENC_TIME_SECS_USECS', 'ENC_TIME_SECS',
                               'ENC_TIME_MSECS', 'ENC_TIME_USECS',
                               'ENC_TIME_NSECS', 'ENC_TIME_SECS_NTP', 'ENC_TIME_RFC_3971',
                               'ENC_TIME_MSEC_NTP', 'ENC_TIME_MIP6', 'ENC_TIME_CLASSIC_MAC_OS_SECS',
                               'ENC_TIME_ZBEE_ZCL', 'ENC_TIME_MP4_FILE_SECS']),
    'FT_RELATIVE_TIME':   set(['ENC_LITTLE_ENDIAN', 'ENC_BIG_ENDIAN',
                               'ENC_TIME_SECS_NSECS', 'ENC_TIME_SECS_USECS', 'ENC_TIME_SECS',
                               'ENC_TIME_MSECS', 'ENC_TIME_USECS', 'ENC_TIME_NSECS'])
}

# TODO: look into FT_STRINGZPAD, FT_STRINGZTRUNC, FT_UINT_STRING
compatible_encoding_args['FT_STRINGZ'] = compatible_encoding_args['FT_STRING']

compatible_encoding_multiple_flags_allowed = set(['FT_ABSOLUTE_TIME', 'FT_RELATIVE_TIME', 'FT_STRING', 'FT_STRINGZ'])


class EncodingCheckerBasic:
    def __init__(self, type, allowed_encodings, allow_multiple):
        self.type = type
        self.allowed_encodings = allowed_encodings
        self.allow_multiple = allow_multiple
        self.encodings_seen = 0

    def check(self, encoding, call, api_check, item, result):
        type = self.type

        # Doesn't even really have an encoding type..
        if '_add_none' in call.function_name:
            return

        # Are more encodings allowed?
        if not self.allow_multiple and self.encodings_seen >= 1:
            # Would ideally make this error once confident about result
            result.warn(api_check.file + ':' + str(call.line_number),
                        api_check.fun_name + ' called for ' + type + ' field "' + call.hf_name + '"', ' with encoding', encoding, 'but only one encoding flag allowed for type')

        # Is this encoding allowed for this type?
        if encoding not in self.allowed_encodings:
            # Have an exemption for UINT fields if the length is only 1.
            if encoding == 'ENC_NA' and 'FT_UINT' in item.item_type and call.length == 1:
                return

            result.warn(api_check.file + ':' + str(call.line_number),
                        api_check.fun_name + ' called for ' + type + ' field "' + call.hf_name + '"', ' - with bad encoding - ' + '"' + encoding + '"', '-',
                        compatible_encoding_args[type], 'allowed')
        self.encodings_seen += 1


# Factory for appropriate checker object
# TODO: separate checker for string types?
def create_enc_checker(type):
    if type in compatible_encoding_args:
        allow_multiple = type in compatible_encoding_multiple_flags_allowed
        checker = EncodingCheckerBasic(type, compatible_encoding_args[type], allow_multiple)
        return checker
    else:
        return None


def check_call_enc_matches_item(items_defined, call, api_check, result):
    if call.enc is None:
        return

    if '|' in call.enc:
        encs = call.enc.split('|')
        encs = [enc.strip() for enc in encs]
    else:
        encs = [call.enc.strip()]

    if call.hf_name in items_defined:
        item = items_defined[call.hf_name]
        type = item.item_type
        # TODO: checking each ENC_ value that appears, but not enforcing cases where there should be 2 values |d together
        # TODO: should check extra logic here, like flags that should be given or only have significance sometimes, like
        # order within a byte of ENC_BCD_DIGITS_0_9 for FT_STRING

        checker = create_enc_checker(type)
        if checker is not None:
            for enc in encs:
                if enc.startswith('ENC_'):
                    if type != 'FT_BOOLEAN' or item.get_field_width_in_bits() > 8:
                        checker.check(enc, call, api_check, item, result)


# A check for a particular API function.
# N.B., not appropriate to pass result in here, as outlive any given file check..
class APICheck:
    def __init__(self, fun_name, allowed_types, positive_length=False):
        self.fun_name = fun_name
        self.allowed_types = allowed_types
        self.positive_length = positive_length
        self.calls = []

        if fun_name.startswith('ptvcursor'):
            # RE captures function name + 1st 2 args (always ptvc + hfindex)
            self.p = re.compile('[^\n]*' + self.fun_name + r'\s*\(([a-zA-Z0-9_]+),\s*([a-zA-Z0-9_]+)')
        elif 'add_bitmask' not in fun_name:
            # Normal case.
            # RE captures function name + 1st 2 args (always tree + hfindex + length)
            self.p = re.compile('[^\n]*' + self.fun_name + r'\s*\(([a-zA-Z0-9_]+),\s*([a-zA-Z0-9_]+),\s*[a-zA-Z0-9_]+,\s*[a-zA-Z0-9_]+,\s*([a-zA-Z0-9_]+)')
        else:
            # _add_bitmask functions.
            # RE captures function name + 1st + 4th args (always tree + hfindex)
            # 6th arg is 'fields'
            self.p = re.compile('[^\n]*' + self.fun_name + r'\s*\(([a-zA-Z0-9_]+),\s*[a-zA-Z0-9_]+,\s*[a-zA-Z0-9_]+,\s*([a-zA-Z0-9_]+)\s*,\s*[a-zA-Z0-9_]+\s*,\s*([a-zA-Z0-9_]+)\s*,')

        self.file = None
        self.mask_allowed = True
        if 'proto_tree_add_bits_' in fun_name:
            self.mask_allowed = False

    def find_calls(self, file, contents, lines, macros, result=None):
        self.file = file
        self.calls = []

        total_lines = len(lines)
        for line_number, line in enumerate(lines):
            # Want to check this, and next few lines
            to_check = lines[line_number-1] + '\n'
            # Nothing to check if function name isn't in it
            if self.fun_name in to_check:
                # Ok, add the next file lines before trying RE
                for i in range(1, 4):
                    if ';' in to_check:
                        break
                    elif line_number+i < total_lines:
                        to_check += (lines[line_number-1+i] + '\n')
                m = self.p.search(to_check)
                if m:
                    fields = None
                    length = None

                    if 'add_bitmask' in self.fun_name:
                        fields = m.group(3)
                    else:
                        if self.p.groups == 3:
                            length = m.group(3)

                    # Look for encoding arg
                    # N.B. REs often won't extend to end of call, so may not include any encoding args..  TODO: extend them to );
                    enc = None
                    enc_start_index = to_check.find('ENC_')
                    if enc_start_index != -1:
                        enc_to_end = to_check[enc_start_index:]

                        p = re.compile(r'(ENC_[A-Z_0-9\|\s]*)')
                        enc_m = p.match(enc_to_end)

                        if enc_m:
                            enc = enc_m.group(1)
                            # print(enc_m.group(1))

                    # Add call. We have length if re had 3 groups.
                    self.calls.append(Call(self.fun_name,
                                           m.group(2),
                                           macros,
                                           line_number=line_number,
                                           length=length,
                                           fields=fields,
                                           enc=enc))

    # Return true if bit position n is set in value.
    def check_bit(self, value, n):
        return (value & (0x1 << n)) != 0

    def does_mask_cover_value(self, mask, value):
        # Walk past any l.s. 0 bits in value
        n = 0

        # Walk through any bits that are set and check they are in mask
        while self.check_bit(value, n) and n <= 63:
            if not self.check_bit(mask, n):
                return False
            n += 1

        return True

    def check_against_items(self, items_defined, items_declared, items_declared_extern,
                            result,
                            check_missing_items=False, field_arrays=None):

        for call in self.calls:

            # Check lengths, but for now only for APIs that have length in bytes.
            if 'add_bits' not in self.fun_name and call.hf_name in items_defined:
                if call.length and items_defined[call.hf_name].item_type in item_lengths:
                    if item_lengths[items_defined[call.hf_name].item_type] < call.length:
                        # Don't warn if adding value - value is unlikely to just be bytes value
                        if '_add_uint' not in self.fun_name:
                            result.warn(self.file + ':' + str(call.line_number),
                                        self.fun_name + ' called for', call.hf_name, ' - ',
                                        'item type is', items_defined[call.hf_name].item_type, 'but call has len', call.length)

            # Needs a +ve length
            if self.positive_length and call.length is not None:
                if call.length != -1 and call.length <= 0:
                    result.error(self.fun_name + '(.., ' + call.hf_name + ', ...) called at ' +
                                 self.file + ':' + str(call.line_number) +
                                 ' with length ' + str(call.length) + ' - must be > 0 or -1')

            if call.hf_name in items_defined:
                # Is type allowed?
                if items_defined[call.hf_name].item_type not in self.allowed_types:
                    result.error(self.fun_name + '(.., ' + call.hf_name + ', ...) called at ' +
                                 self.file + ':' + str(call.line_number) +
                                 ' with type ' + items_defined[call.hf_name].item_type,
                                 '    (allowed types are', self.allowed_types, ')\n')
                # No mask allowed
                if not self.mask_allowed and items_defined[call.hf_name].mask_value != 0:
                    result.error(self.fun_name + '(.., ' + call.hf_name + ', ...) called at ' +
                                 self.file + ':' + str(call.line_number) +
                                 ' with mask ' + items_defined[call.hf_name].mask + '    (must be zero!)\n')

            if 'add_bitmask' in self.fun_name and call.hf_name in items_defined and field_arrays:
                if call.fields in field_arrays:
                    if (items_defined[call.hf_name].mask_value and
                            field_arrays[call.fields][1] != 0 and items_defined[call.hf_name].mask_value != field_arrays[call.fields][1]):
                        # TODO: only really a problem if bit is set in array but not in top-level item?
                        if not self.does_mask_cover_value(items_defined[call.hf_name].mask_value,
                                                          field_arrays[call.fields][1]):
                            result.warn(self.file, call.hf_name, call.fields, "masks don't match. root=",
                                        items_defined[call.hf_name].mask,
                                        "array has", hex(field_arrays[call.fields][1]))

            if check_missing_items:
                if call.hf_name in items_declared and call.hf_name not in items_defined and call.hf_name not in items_declared_extern:
                    # not in common_hf_var_names:
                    result.warn(self.file + ':' + str(call.line_number),
                                self.fun_name + ' called for "' + call.hf_name + '"', ' - but no item found')

            # Checking that encoding arg is compatible with item type
            check_call_enc_matches_item(items_defined, call, self, result)


# Specialization of APICheck for add_item() calls
class ProtoTreeAddItemCheck(APICheck):
    def __init__(self, ptv=None):

        # RE will capture whole call.

        if not ptv:
            # proto_item *
            # proto_tree_add_item(proto_tree *tree, int hfindex, tvbuff_t *tvb,
            #                     const gint start, gint length, const unsigned encoding)
            self.fun_name = 'proto_tree_add_item'
            self.p = re.compile('[^\n]*' + self.fun_name + r'\s*\(\s*[a-zA-Z0-9_]+?,\s*([a-zA-Z0-9_]+?),\s*[a-zA-Z0-9_\+\s]+?,\s*([^,.]+?),\s*(.+),\s*([^,.]+?)\);')
        else:
            # proto_item *
            # ptvcursor_add(ptvcursor_t *ptvc, int hfindex, gint length,
            #               const unsigned encoding)
            self.fun_name = 'ptvcursor_add'
            self.p = re.compile('[^\n]*' + self.fun_name + r'\s*\([^,.]+?,\s*([^,.]+?),\s*([^,.]+?),\s*([a-zA-Z0-9_\-\>]+)')

    def find_calls(self, file, contents, lines, macros, result):
        self.file = file
        self.calls = []

        total_lines = len(lines)
        for line_number, line in enumerate(lines):
            # Want to check this, and next few lines
            to_check = lines[line_number-1] + '\n'
            # Nothing to check if function name isn't in it
            fun_idx = to_check.find(self.fun_name)
            if fun_idx != -1:
                # Ok, add the next file lines before trying RE
                for i in range(1, 5):
                    if ';' in to_check:
                        break
                    elif line_number+i < total_lines:
                        to_check += (lines[line_number-1+i] + '\n')
                # Lose anything before function call itself.
                to_check = to_check[fun_idx:]
                m = self.p.search(to_check)
                if m:
                    # Throw out if parens not matched
                    if m.group(0).count('(') != m.group(0).count(')'):
                        continue

                    enc = m.group(4)
                    hf_name = m.group(1)
                    if not enc.startswith('ENC_') and 'endian' not in enc.lower():
                        if enc not in {'encoding', 'enc', 'client_is_le', 'cigi_byte_order', 'endian', 'endianess', 'machine_encoding', 'byte_order', 'bLittleEndian',
                                       'p_mq_parm->mq_str_enc', 'p_mq_parm->mq_int_enc',
                                       'iEnc', 'strid_enc', 'iCod', 'nl_data->encoding',
                                       'argp->info->encoding', 'gquic_info->encoding', 'writer_encoding',
                                       'tds_get_int2_encoding(tds_info)',
                                       'tds_get_int4_encoding(tds_info)',
                                       'tds_get_char_encoding(tds_info)',
                                       'info->encoding',
                                       'item->encoding',
                                       'DREP_ENC_INTEGER(drep)', 'string_encoding', 'item', 'type',
                                       'dvb_enc_to_item_enc(encoding)',
                                       'packet->enc',
                                       'IS_EBCDIC(uCCS) ? ENC_EBCDIC : ENC_ASCII',
                                       'DREP_ENC_INTEGER(hdr->drep)',
                                       'payload_le',
                                       'local_encoding',
                                       'hf_data_encoding',
                                       'IS_EBCDIC(eStr) ? ENC_EBCDIC : ENC_ASCII',
                                       'pdu_info->sbc', 'pdu_info->mbc',
                                       'seq_info->txt_enc | ENC_NA',
                                       'BASE_SHOW_UTF_8_PRINTABLE',
                                       'is_mdns ? ENC_UTF_8|ENC_NA : ENC_ASCII|ENC_NA',
                                       'xl_encoding',
                                       'my_frame_data->encoding_client', 'my_frame_data->encoding_results',
                                       'seq_info->txt_enc'
                                       }:

                            result.warn(self.file + ':' + str(line_number),
                                        self.fun_name + ' called for "' + hf_name + '"',  'check last/enc param:', enc, '?')
                    self.calls.append(Call(self.fun_name, hf_name, macros, line_number=line_number, offset=m.group(2), length=m.group(3), fields=None, enc=enc))

    def check_against_items(self, items_defined, items_declared, items_declared_extern,
                            result,
                            check_missing_items=False, field_arrays=None):
        # For now, only complaining if length if call is longer than the item type implies.
        #
        # Could also be bugs where the length is always less than the type allows.
        # Would involve keeping track (in the item) of whether any call had used the full length.

        for call in self.calls:
            if call.hf_name in items_defined:
                if call.length and items_defined[call.hf_name].item_type in item_lengths:
                    if item_lengths[items_defined[call.hf_name].item_type] < call.length:
                        # On balance, it is not worth complaining about these - the value is unlikely to be
                        # just the value found in these bytes..
                        if '_add_uint' not in self.fun_name:
                            result.warn(self.file + ':' + str(call.line_number),
                                        self.fun_name + ' called for', call.hf_name, ' - ',
                                        'item type is', items_defined[call.hf_name].item_type, 'but call has len', call.length)

                    # If have mask and length is too short, that is likely to be a problem.
                    # N.B. shouldn't be from width of field, but how many bytes a mask spans (e.g., 0x0ff0 spans 2 bytes)
                    if (item_lengths[items_defined[call.hf_name].item_type] > call.length and
                            items_defined[call.hf_name].mask_value != 0 and
                            int((items_defined[call.hf_name].mask_width + 7) / 8) > call.length):

                        result.warn(self.file + ':' + str(call.line_number),
                                    self.fun_name + ' called for', call.hf_name, ' - ',
                                    'item type is', items_defined[call.hf_name].item_type, 'but call has len', call.length,
                                    'and mask is', hex(items_defined[call.hf_name].mask_value))

                # Checking that encoding arg is compatible with item type
                check_call_enc_matches_item(items_defined, call, self, result)

            elif check_missing_items:
                if call.hf_name in items_declared and call.hf_name not in items_declared_extern:
                    # not in common_hf_var_names:
                    result.warn(self.file + ':' + str(call.line_number),
                                self.fun_name + ' called for "' + call.hf_name + '"', ' - but no item found')


class TVBGetBits:
    def __init__(self, name, maxlen):
        self.name = name
        self.maxlen = maxlen
        self.calls = []
        pass

    def find_calls(self, file, contents, lines, macros, result):
        self.file = file
        self.calls = []
        matches = re.finditer(self.name + r'\([a-zA-Z0-9_]+\s*,\s*(.*?)\s*,\s*([0-9a-zA-Z_]+)', contents)
        for m in matches:
            try:
                length = int(m.group(2))
            except Exception:
                # Not parsable as literal decimal, so ignore
                # TODO: could subst macros if e.g., do check in check_against_items()
                continue

            if length > self.maxlen:
                # Error if some bits would get chopped off.
                result.error(file + ' ' + m.group(0) + '...  has length of ' + m.group(2) + ', which is > API limit of ' + str(self.maxlen))
            elif self.maxlen > 8 and length <= self.maxlen/2:
                result.note(file + ' ' + m.group(0) + '...  has length of ' + m.group(2) + ', could have used smaller version of function?')

        return []

    def calls(self):
        return []

    def check_against_items(self, items_defined, items_declared, items_declared_extern, result,
                            check_missing_items=False, field_arrays=None):
        pass


##################################################################################################
# This is a set of items (by filter name) where we know that the bitmask is non-contiguous,
# but is still believed to be correct.
known_non_contiguous_fields = {'wlan.fixed.capabilities.cfpoll.sta',
                               'wlan.wfa.ie.wme.qos_info.sta.reserved',
                               'btrfcomm.frame_type',   # https://os.itec.kit.edu/downloads/sa_2006_roehricht-martin_flow-control-in-bluez.pdf
                               'capwap.control.message_element.ac_descriptor.dtls_policy.r',  # RFC 5415
                               'couchbase.extras.subdoc.flags.reserved',
                               'wlan.fixed.capabilities.cfpoll.ap',   # These are 3 separate bits...
                               'wlan.wfa.ie.wme.tspec.ts_info.reserved',   # matches other fields in same sequence
                               'zbee_zcl_se.pp.attr.payment_control_configuration.reserved',   # matches other fields in same sequence
                               'zbee_zcl_se.pp.snapshot_payload_cause.reserved',  # matches other fields in same sequence
                               'ebhscr.eth.rsv',  # matches other fields in same sequence
                               'v120.lli',  # non-contiguous field (http://www.acacia-net.com/wwwcla/protocol/v120_l2.htm)
                               'stun.type.class',
                               'bssgp.csg_id', 'tiff.t6.unused', 'artnet.ip_prog_reply.unused',
                               'telnet.auth.mod.enc', 'osc.message.midi.bender', 'btle.data_header.rfu',
                               'stun.type.method',  # figure 3 in rfc 5389
                               'tds.done.status',  # covers all bits in bitset
                               'hf_iax2_video_csub',  # RFC 5456, table 8.7
                               'iax2.video.subclass',
                               'dnp3.al.ana.int',
                               'pwcesopsn.cw.lm',
                               'gsm_a.rr.format_id',  # EN 301 503
                               'siii.mst.phase',  # comment in code seems convinced
                               'xmcp.type.class',
                               'xmcp.type.method',
                               'hf_hiqnet_flags',
                               'hf_hiqnet_flagmask',
                               'hf_h223_mux_mpl',
                               'rdp.flags.pkt',
                               'erf.flags.if_raw',  # confirmed by Stephen Donnelly
                               'oran_fh_cus.sReSMask',
                               'ttl.trace_data.entry.status_info.can_flags',
                               'ttl.trace_data.entry.status_info.fr_flags',
                               'ttl.trace_data.entry.status_info.fr_pulse_flags',
                               'gsm_sim.select.return_data'     #  ETSI TS 102 221 Table 11.2: Coding of P2
                               }
##################################################################################################


field_widths = {
    'FT_BOOLEAN':  64,   # TODO: Width depends upon 'display' field
    'FT_CHAR':     8,
    'FT_UINT8':    8,
    'FT_INT8':     8,
    'FT_UINT16':   16,
    'FT_INT16':    16,
    'FT_UINT24':   24,
    'FT_INT24':    24,
    'FT_UINT32':   32,
    'FT_INT32':    32,
    'FT_UINT40':   40,
    'FT_INT40':    40,
    'FT_UINT48':   48,
    'FT_INT48':    48,
    'FT_UINT56':   56,
    'FT_INT56':    56,
    'FT_UINT64':   64,
    'FT_INT64':    64,
    'FT_UINT1632': 32  # from packet-dcerpc.h
}


def is_ignored_consecutive_filter(filter):
    ignore_filters = {
        'elf.sh_type',
        'elf.p_type',
        'btavrcp.pdu_id',
        'netlogon.dummy_string',
        'opa.reserved',
        'wassp.data.mu_mac',
        'thrift.type',
        'quake2.game.client.command.move.angles',
        'ipp.enum_value',
        'idrp.error.subcode',
        'ftdi-ft.lValue',
        '6lowpan.src',
        'couchbase.flex_frame.frame.id',
        'rtps.param.id',
        'rtps.locator.port',
        'sigcomp.udvm.value',
        'opa.mad.attributemodifier.n',
        'smb.cmd',
        'sctp.checksum',
        'dhcp.option.end',
        'nfapi.num.bf.vector.bf.value',
        'dnp3.al.range.abs',
        'dnp3.al.range.quantity',
        'dnp3.al.index',
        'dnp3.al.size',
        'ftdi-ft.hValue',
        'homeplug_av.op_attr_cnf.data.sw_sub',
        'radiotap.he_mu.preamble_puncturing',
        'ndmp.file',
        'ocfs2.dlm.lvb',
        'oran_fh_cus.reserved',
        'qnet6.kif.msgsend.msg.read.xtypes0-7',
        'qnet6.kif.msgsend.msg.write.xtypes0-7',
        'mih.sig_strength',
        'couchbase.flex_frame.frame.len',
        'nvme-rdma.read_to_host_req',
        'rpcap.dummy',
        'sflow.flow_sample.output_interface',
        'socks.results',
        'opa.mad.attributemodifier.p',
        'v5ua.efa',
        'zbncp.data.tx_power',
        'zbncp.data.nwk_addr',
        'zbee_zcl_hvac.pump_config_control.attr.ctrl_mode',
        'nat-pmp.external_port',
        'zbee_zcl.attr.float',
        'wpan-tap.phr.fsk_ms.mode',
        'mysql.exec_flags',
        'pim.metric_pref',
        'modbus.regval_float',
        'alcap.cau.value',
        'bpv7.crc_field',
        'at.chld.mode',
        'btl2cap.psm',
        'srvloc.srvtypereq.nameauthlistlen',
        'a11.ext.code',
        'adwin_config.port',
        'afp.unknown',
        'ansi_a_bsmap.mid.digit_1',
        'ber.unknown.OCTETSTRING',
        'btatt.handle',
        'btl2cap.option_flushto',
        'cip.network_segment.prod_inhibit',
        'cql.result.rows.table_name',
        'dcom.sa.vartype',
        'f5ethtrailer.slot',
        'ipdr.cm_ipv6_addr',
        'mojito.kuid',
        'mtp3.priority',
        'pw.cw.length',
        'rlc.ciphered_data',
        'vp8.pld.pictureid',
        'gryphon.sched.channel',
        'pn_io.ioxs',
        'pn_dcp.block_qualifier_reset',
        'pn_dcp.suboption_device_instance',
        'nfs.attr',
        'nfs.create_session_flags',
        'rmt-lct.toi64',
        'gryphon.data.header_length',
        'quake2.game.client.command.move.movement',
        'isup.parameter_type',
        'cip.port',
        'adwin.fifo_no',
        'bthci_evt.hci_vers_nr',
        'gryphon.usdt.stmin_active',
        'dnp3.al.anaout.int',
        'dnp3.al.ana.int',
        'dnp3.al.cnt',
        'bthfp.chld.mode',
        'nat-pmp.pml',
        'isystemactivator.actproperties.ts.hdr',
        'rtpdump.txt_addr',
        'unistim.vocoder.id',
        'mac.ueid',
        'cip.symbol.size',
        'dnp3.al.range.start',
        'dnp3.al.range.stop',
        'gtpv2.mp',
        'gvcp.cmd.resend.firstpacketid',
        'gvcp.cmd.resend.lastpacketid',
        'wlan.bf.reserved',
        'opa.sa.reserved',
        'rmt-lct.ext_tol_transfer_len',
        'pn_io.error_code2',
        'gryphon.ldf.schedsize',
        'wimaxmacphy.burst_opt_mimo_matrix_indicator',
        'ccsds.packet_type',
        'iso15765.flow_control.stmin',
        'msdo.PieceSize',
        'opa.clasportinfo.redirect.reserved',
        'p_mul.unused',
        'opa.pm.dataportcounters.reserved',
        'opa.switchinfo.switchcapabilitymask.reserved',
        'nvme-rdma.read_from_host_resp',
        'nvme-rdma.write_to_host_req',
        'netlink-route.ifla_linkstats.rx_errors.fifo_errs',
        'mtp3mg.japan_spare',
        'ixveriwave.errors.ip_checksum_error',
        'bpsec.asb.result_count',
        'btle.control.phys.le_coded_phy',
        'gsm_rlcmac.ul.gprs_multislot_class_exist',
        'tpm.resp.size',
        'sasp.flags.quiesce',
        'canopen.sdo.n',
        'cigi.celestial_sphere_control.date',
        'corosync_totemsrp.orf_token.seq',
        'dec_dna.flags.msglen',
        'hiqnet.device',
        'ipdr.cm_ipv6_addr_len',
        'ipdr.cm_ipv6_addr_string',
        'mpeg_descr.phone.nat_code_len'
    }
    if filter in ignore_filters:
        return True

    ignore_patterns = [
        re.compile(r'^nstrace.trcdbg.val(\d+)'),
        re.compile(r'^mpls_pm.timestamp\d\..*'),
        re.compile(r'alcap.*bwt.*.[b|f]w'),
        re.compile(r'btle.control.phys.le_[1|2]m_phy'),
        re.compile(r'ansi_a_bsmap.cm2.scm.bc_entry.opmode[0|1]'),
        re.compile(r'cemi.[n|x]')
    ]
    for patt in ignore_patterns:
        if patt.match(filter):
            return True

    return False


class ValueString:
    def __init__(self, file, name, vals, macros, result, ext, do_extra_checks=False):
        self.file = file
        self.name = name
        self.ext = ext
        self.raw_vals = vals
        self.parsed_vals = {}
        self.seen_labels = set()
        self.valid = True
        self.min_value = 99999
        self.max_value = -99999

        self.out_of_order = False
        previous_value = -99999
        previous_label = ''

        # Now parse out each entry in the value_string
        matches = re.finditer(r'\{\s*([0-9_A-Za-z]*)\s*,\s*(".*?")\s*}\s*,', self.raw_vals)

        for m in matches:
            value, label = m.group(1), m.group(2)
            if value in macros:
                value = macros[value]
            elif any(c not in '0123456789abcdefABCDEFxX' for c in value):
                self.valid = False
                return

            try:
                # Read according to the appropriate base.
                if value.lower().startswith('0x'):
                    value = int(value, 16)
                elif value.startswith('0b'):
                    value = int(value[2:], 2)
                elif value.startswith('0'):
                    value = int(value, 8)
                else:
                    value = int(value, 10)
            except Exception:
                return

            # Are the entries not in strict ascending order?
            if do_extra_checks and not self.out_of_order:
                if value <= previous_value:
                    result.warn(self.file, ': value_string', self.name, 'not in ascending order - label',
                                label, 'with value', value, 'comes after', previous_label, 'with value', previous_value)
                    self.out_of_order = True
                previous_value = value
                previous_label = label

            # Check for value conflict before inserting
            if do_extra_checks and value in self.parsed_vals and label == self.parsed_vals[value]:
                result.warn(self.file, ': value_string', self.name, '- value ', value, 'repeated with same string - ', label)

            # Same value, different label
            if value in self.parsed_vals and label != self.parsed_vals[value]:

                result.warn(self.file, ': value_string', self.name, '- value ', value, 'repeated with different values - was',
                            self.parsed_vals[value], 'now', label)
            else:
                # Add into table, while checking for repeated label
                self.parsed_vals[value] = label
                if do_extra_checks and label in self.seen_labels:
                    # These are commonly repeated..
                    exceptions = ['reserved', 'invalid', 'unused', 'not used', 'unknown', 'undefined', 'spare',
                                  'unallocated', 'not assigned', 'implementation specific', 'unspecified',
                                  'other', 'for further study', 'future', 'vendor specific', 'obsolete', 'none',
                                  'shall not be used', 'national use', 'unassigned', 'oem', 'user defined',
                                  'manufacturer specific', 'not specified', 'proprietary', 'operator-defined',
                                  'dynamically allocated', 'user specified', 'xxx', 'default', 'planned', 'not req',
                                  'deprecated', 'not measured', 'unspecified', 'nationally defined', 'nondisplay', 'general',
                                  'tbd']
                    excepted = False
                    for ex in exceptions:
                        if ex in label.lower():
                            excepted = True
                            break

                    if not excepted and len(label) > 2:
                        previous_values = [str(v) for v in self.parsed_vals if self.parsed_vals[v] == label]
                        result.warn(self.file, ': value_string', self.name, '- label', label, 'repeated, value now', value,
                                    'previously', ','.join(previous_values[:-1]))
                else:
                    self.seen_labels.add(label)

                if value > self.max_value:
                    self.max_value = value
                if value < self.min_value:
                    self.min_value = value

    def extraChecks(self, result):
        # Look for one value missing in range (quite common...)
        num_items = len(self.parsed_vals)
        span = self.max_value - self.min_value + 1
        if num_items > 4 and span > num_items and (span-num_items <= 1):
            for val in range(self.min_value, self.max_value):
                if val not in self.parsed_vals:
                    result.warn(self.file, ': value_string', self.name, '- value', val, 'missing?', '(', num_items, 'entries )',
                                'USED AS EXT!' if self.name in self.ext else '')

        # N.B., arbitrary threshold for suggesting value_string_ext
        ext_threshold = 64
        if not self.out_of_order and span >= ext_threshold and span == len(self.parsed_vals) and self.name not in self.ext:
            # print(self.ext)
            result.note(self.file, ': value_string', self.name, 'has', span, 'consecutive entries - possible candidate for value_string_ext?')

        # Do most of the labels match the number?
        matching_label_entries = set()
        for val in self.parsed_vals:
            if str(val) in self.parsed_vals[val]:
                # TODO: pick out multiple values rather than concat into wrong number
                parsed_value = int(''.join(d for d in self.parsed_vals[val] if d.isdecimal()))
                if val == parsed_value:
                    matching_label_entries.add(val)

        if len(matching_label_entries) >= 4 and len(matching_label_entries) > 0 and len(matching_label_entries) < num_items and len(matching_label_entries) >= num_items-1:
            # Be forgiving about first or last entry
            first_val = list(self.parsed_vals)[0]
            last_val = list(self.parsed_vals)[-1]
            if first_val not in matching_label_entries or last_val not in matching_label_entries:
                return
            result.warn(self.file, ': value_string', self.name, 'Labels match value except for 1!', matching_label_entries, num_items, self)

        # Do all labels start with lower-or-upper char?
        startLower, startUpper = 0, 0
        for val in self.parsed_vals:
            first_letter = self.parsed_vals[val][1]
            if first_letter.isalpha():
                if first_letter.isupper():
                    startUpper += 1
                else:
                    startLower += 1
        if startLower > 0 and startUpper > 0:
            if (startLower + startUpper) > 10 and (startLower <= 3 or startUpper <= 3):
                standouts = []
                if startLower < startUpper:
                    standouts += [self.parsed_vals[val] for val in self.parsed_vals if self.parsed_vals[val][1].islower()]
                if startLower > startUpper:
                    standouts += [self.parsed_vals[val] for val in self.parsed_vals if self.parsed_vals[val][1].isupper()]

                result.note(self.file, ': value_string', self.name, 'mix of upper', startUpper, 'and lower', startLower, standouts)

    def __str__(self):
        return self.name + '= { ' + self.raw_vals + ' }'


class RangeStringEntry:
    def __init__(self, min, max, label):
        self.min = min
        self.max = max
        self.label = label

    def hides(self, min, max):
        return min >= self.min and max <= self.max

    def __str__(self):
        return '(' + str(self.min) + ', ' + str(self.max) + ') -> ' + self.label


class RangeString:
    def __init__(self, file, name, vals, macros, result, do_extra_checks=False):
        self.file = file
        self.name = name
        self.raw_vals = vals
        self.parsed_vals = []
        self.seen_labels = set()
        self.valid = True
        self.min_value = 99999
        self.max_value = -99999

        # Now parse out each entry in the value_string
        matches = re.finditer(r'\{\s*([0-9_A-Za-z]*)\s*,\s*([0-9_A-Za-z]*)\s*,\s*(".*?")\s*\}\s*,', self.raw_vals)
        for m in matches:
            min, max, label = m.group(1), m.group(2), m.group(3)
            if min in macros:
                min = macros[min]
            elif any(c not in '0123456789abcdefABCDEFxX' for c in min):
                self.valid = False
                return
            if max in macros:
                max = macros[max]
            elif any(c not in '0123456789abcdefABCDEFxX' for c in max):
                self.valid = False
                return

            try:
                # Read according to the appropriate base.
                if min.lower().startswith('0x'):
                    min = int(min, 16)
                elif min.startswith('0b'):
                    min = int(min[2:], 2)
                elif min.startswith('0'):
                    min = int(min, 8)
                else:
                    min = int(min, 10)

                if max.lower().startswith('0x'):
                    max = int(max, 16)
                elif max.startswith('0b'):
                    max = int(max[2:], 2)
                elif max.startswith('0'):
                    max = int(max, 8)
                else:
                    max = int(max, 10)
            except Exception:
                return

            # Now check what we've found.

            if min < self.min_value:
                self.min_value = min
            # For overall max value, still use min of each entry.
            # It is common for entries to extend to e.g. 0xff, but at least we can check for items
            # that can never match if we only check the min.
            if min > self.max_value:
                self.max_value = min

            # This value should not be entirely hidden by earlier entries
            for prev in self.parsed_vals:
                if prev.hides(min, max):
                    result.warn(self.file, ': range_string label', label, 'hidden by', prev)

            # Min should not be > max
            if min > max:
                result.warn(self.file, ': range_string', self.name, 'entry', label, 'min', min, '>', max)

            # Check label.
            if label[1:-1].startswith(' ') or label[1:-1].endswith(' '):
                result.warn(self.file, ': range_string', self.name, 'entry', label, 'starts or ends with space')

            # OK, add this entry
            self.parsed_vals.append(RangeStringEntry(min, max, label))

        # TODO: mark as not valid if not all pairs were successfully parsed?

    def extraChecks(self, result):
        # if in all cases min==max, suggest value_string instead?
        could_use_value_string = True
        for val in self.parsed_vals:
            if val.min != val.max:
                could_use_value_string = False
                break

        # Look for gaps
        gaps = []    # N.B. could become huge if added every number, so only record first number inside each gap
        current = None
        for val in self.parsed_vals:
            if current:
                if val.min > current+1:
                    gaps.append(current+1)
            current = val.max

        # Check whether each gap is actually covered.
        for n in gaps:
            covered = False
            for val in self.parsed_vals:
                if n >= val.min and n <= val.max:
                    covered = True
                    break
            if not covered:
                result.warn(self.file, ': range_string', self.name, 'value', str(n) + '-?', '(' + str(hex(n)) + '-?)', 'not covered by any entries')

        if could_use_value_string:
            result.warn(self.file, ': range_string', self.name, 'could be value_string instead!')

        # TODO: can multiple values be coalesced into fewer?
        # TODO: Partial overlapping?


class StringString:
    def __init__(self, file, name, vals, macros, result, do_extra_checks=False):
        self.file = file
        self.name = name
        self.raw_vals = vals
        self.parsed_vals = {}

        terminated = False

        # Now parse out each entry in the string_string
        matches = re.finditer(r'\{\s*(["0-9_A-Za-z\s\-]*?)\s*,\s*(["0-9_A-Za-z\s\-]*)\s*', self.raw_vals)
        for m in matches:
            key = m.group(1).strip()
            value = m.group(2).strip()
            if key in self.parsed_vals:
                result.error(self.file, ': string_string', self.name, 'entry', key, 'has been added twice (values',
                             self.parsed_vals[key], 'and now', value, ')')

            else:
                self.parsed_vals[key] = value
                # TODO: Also allow key to be "0" ?
                if (key in {"NULL"}) and value == "NULL":
                    terminated = True

        if not terminated:
            result.error(self.file, ': string_string', self.name, "is not terminated with { NULL, NULL }")

    def extraChecks(self, result):
        pass
        # TODO: ?


# Look for value_string entries in a dissector file.  Return a dict name -> ValueString
def findValueStrings(filename, contents, macros, result, do_extra_checks=False):
    vals_found = {}

    # Find value_strings that are used as ext
    ext = set()
    matches = re.finditer(r'value_string_ext\s*([a-zA-Z0-9_]+)\s*\=\s*VALUE_STRING_EXT_INIT\((.*)\)', contents)
    for m in matches:
        ext.add(m.group(2))

    # static const value_string radio_type_vals[] =
    # {
    #    { 0,      "FDD"},
    #    { 1,      "TDD"},
    #    { 0, NULL }
    # };

    matches = re.finditer(r'.*const value_string\s*([a-zA-Z0-9_]*)\s*\[\s*\]\s*\=\s*\{([\{\}\d\,a-zA-Z0-9_\-\*\#\.:\/\(\)\'\s\"]*)\};', contents)
    for m in matches:
        name = m.group(1)
        vals = m.group(2)
        vals_found[name] = ValueString(filename, name, vals, macros, result, ext, do_extra_checks)

    return vals_found


# Look for range_string entries in a dissector file.  Return a dict name -> RangeString
def findRangeStrings(filename, contents, macros, result, do_extra_checks=False):
    vals_found = {}

    # static const range_string symbol_table_shndx_rvals[] = {
    #    { 0x0000, 0x0000,  "Undefined" },
    #    { 0x0001, 0xfeff,  "Normal Section" },
    #    { 0, 0, NULL }
    # };

    matches = re.finditer(r'.*const range_string\s*([a-zA-Z0-9_]*)\s*\[\s*\]\s*\=\s*\{([\{\}\d\,a-zA-Z0-9_\-\*\#\.:\/\(\)\'\s\"]*)\};', contents)
    for m in matches:
        name = m.group(1)
        vals = m.group(2)
        vals_found[name] = RangeString(filename, name, vals, macros, result, do_extra_checks)

    return vals_found


# Look for string_string entries in a dissector file.  Return a dict name -> StringString
def findStringStrings(filename, contents, macros, result, do_extra_checks=False):
    vals_found = {}

    # static const string_string ice_candidate_types[] = {
    #    { "host",       "Host candidate" },
    #    { "srflx",      "Server reflexive candidate" },
    #    { 0, NULL }
    # };

    matches = re.finditer(r'.*const string_string\s*([a-zA-Z0-9_]*)\s*\[\s*\]\s*\=\s*\{([\{\}\d\,a-zA-Z0-9_\-\*\#\.:\/\(\)\'\s\"]*)\};', contents)
    for m in matches:
        name = m.group(1)
        vals = m.group(2)
        vals_found[name] = StringString(filename, name, vals, macros, do_extra_checks, result)

    return vals_found


# Look for expert entries in a dissector file.  Return ExpertEntries object
def findExpertItems(filename, contents, macros, result):
    # Look for array of definitions. Looks something like this
    # static ei_register_info ei[] = {
    #    { &ei_oran_unsupported_bfw_compression_method, { "oran_fh_cus.unsupported_bfw_compression_method", PI_UNDECODED, PI_WARN, "Unsupported BFW Compression Method", EXPFILL }},
    #    { &ei_oran_invalid_sample_bit_width, { "oran_fh_cus.invalid_sample_bit_width", PI_UNDECODED, PI_ERROR, "Unsupported sample bit width", EXPFILL }},
    # };

    expertEntries = ExpertEntries(filename, result)

    definition_matches = re.finditer(r'static ei_register_info\s*([a-zA-Z0-9_]*)\s*\[\]\s*=\s*\{(.*?)\};',
                                     contents, re.MULTILINE | re.DOTALL)
    for d in definition_matches:
        entries = d.group(2)

        # Now separate out each entry
        matches = re.finditer(r'\{\s*&([a-zA-Z0-9_]*)\s*\,\s*\{\s*\"(.*?)\"\s*\,\s*([A-Z_]*)\,\s*([A-Z_]*)\,\s*\"(.*?)\".*?\,\s*EXPFILL\s*\}\s*\}',
                              entries, re.MULTILINE | re.DOTALL)
        for match in matches:
            expertEntry = ExpertEntry(filename, name=match.group(1), filter=match.group(2), group=match.group(3),
                                      severity=match.group(4), summary=match.group(5), result=result)
            expertEntries.AddEntry(expertEntry)

    return expertEntries


def findDeclaredTrees(filename, contents):
    trees = []

    definition_matches = re.finditer(r'static int\s*\s*(ett_[a-zA-Z0-9_]*)\s*;',
                                     contents, re.MULTILINE | re.DOTALL)
    for d in definition_matches:
        trees.append(d.group(1))

    return trees


def findDefinedTrees(filename, contents, declared):
    # Look for array of definitions. Looks something like this
    # static int *ett[] = {
    #    &ett_oran,
    #    &ett_oran_ecpri_pcid,
    #    &ett_oran_ecpri_rtcid,
    #    &ett_oran_ecpri_seqid
    # };

    trees = set()

    # Not insisting that this array is static..
    definition_matches = re.finditer(r'int\s*\*\s*(?:const|)\s*[a-zA-Z0-9_]*?ett[a-zA-Z0-9_]*\s*\[\]\s*=\s*\{(.*?)\};',
                                     contents, re.MULTILINE | re.DOTALL)
    for d in definition_matches:
        entries = d.group(1)

        # Now separate out each entry
        matches = re.finditer(r'\&(ett_[a-zA-Z0-9_]+)',
                              entries, re.MULTILINE | re.DOTALL)
        for match in matches:
            ett = match.group(1)

            if ett not in declared:
                # N.B., this check will avoid matches with arrays (which won't match 'declared' re)
                continue

            # Don't think this can happen..
            # if ett in trees:
            #    print('Warning:', filename, ett, 'appears twice!!!')
            trees.add(match.group(1))
    return trees


def checkExpertCalls(filename, expertEntries, result):
        with open(filename, 'r', encoding="utf8") as f:
            contents = f.read()

            expert_add_info_re = re.compile(r'expert_add_info\s*\(([a-zA-Z_0-9]*)\s*,\s*([a-zA-Z_0-9]*)\s*,\s*(&[a-zA-Z_0-9]*)')
            expert_add_info_format_re = re.compile(r'expert_add_info_format\s*\(([a-zA-Z_0-9]*)\s*,\s*([a-zA-Z_0-9]*)\s*,\s*(&[a-zA-Z_0-9]*)\s*,\s*\"(.*?)\"')

            # Remove comments so as not to trip up RE.
            contents = removeComments(contents)

            # Look for array of definitions. Looks something like this
            # expert_add_info(NULL, tree, &ei_oran_invalid_eaxc_bit_width);
            # OR
            # expert_add_info_format(pinfo, ti_data_length, &ei_data_length, "Data Length %d is too small, should be %d", data_length, payload_size - ECPRI_MSG_TYPE_4_PAYLOAD_MIN_LENGTH);

            #########################################################
            # First pass through just to get number of calls
            matches = expert_add_info_re.finditer(contents, re.MULTILINE | re.DOTALL)
            for m in matches:
                # Lose '&'
                item = m.group(3)[1:]
                expertEntries.AddCall(item)

            matches = expert_add_info_format_re.finditer(contents, re.MULTILINE | re.DOTALL)
            for m in matches:
                # Lose '&'
                item = m.group(3)[1:]
                expertEntries.AddCall(item)

            #########################################################
            # Second pass, look at in more details
            matches = expert_add_info_re.finditer(contents, re.MULTILINE | re.DOTALL)
            for m in matches:
                # Lose '&'
                item = m.group(3)[1:]
                expertEntries.VerifyCall(item)

            matches = expert_add_info_format_re.finditer(contents, re.MULTILINE | re.DOTALL)
            for m in matches:
                # Lose '&'
                item = m.group(3)[1:]
                format_string = m.group(4)
                if '%' not in format_string:
                    default_string = expertEntries.GetDefaultStringForItem(item)
                    # The problem is that this is the number of calls *so far*...
                    number_of_calls = expertEntries.NumberOfCalls(item)
                    exact_match = (format_string == default_string)

                    # Exact match is bad if there is only 1 call to it...
                    if number_of_calls == 1 and exact_match:
                        result.error(filename, 'calling expert_add_info_format() for', item, '- no format specifiers in',
                                     '"' + format_string + '" - which exactly matches expert item default! (only call)')
                        # if not isGeneratedFile(filename):
                        #    errors += 1
                    else:
                        # There may be good reasons for this - they could be specializations..
                        # TODO: noteworthy if all usages had same string?
                        # result.note(filename, 'calling expert_add_info_format() for', item, '- no format specifiers in',
                        #            '"' + format_string + '" - default is ' +
                        #            ('"' + default_string + '"') if default_string is not None else '<??>',
                        #            '- total calls', number_of_calls, '(EXACT MATCH)' if exact_match else '')
                        pass
                expertEntries.VerifyCall(item)


# These are the valid values from expert.h
valid_groups = set(['PI_GROUP_MASK', 'PI_CHECKSUM', 'PI_SEQUENCE',
                    'PI_RESPONSE_CODE', 'PI_REQUEST_CODE', 'PI_UNDECODED', 'PI_REASSEMBLE',
                    'PI_MALFORMED', 'PI_DEBUG', 'PI_PROTOCOL', 'PI_SECURITY', 'PI_COMMENTS_GROUP',
                    'PI_DECRYPTION', 'PI_ASSUMPTION', 'PI_DEPRECATED', 'PI_RECEIVE',
                    'PI_INTERFACE', 'PI_DISSECTOR_BUG'])

valid_levels = set(['PI_COMMENT', 'PI_CHAT', 'PI_NOTE',
                    'PI_WARN', 'PI_ERROR'])


# An individual entry
class ExpertEntry:
    def __init__(self, filename, name, filter, group, severity, summary, result):
        self.name = name
        self.filter = filter
        self.group = group
        self.severity = severity
        self.summary = summary
        self.calls = 0

        # Remove any line breaks
        summary = re.sub(re.compile(r'\"\s*\n\s*\"'), '', summary)

        # Some immediate checks (already covered by other scripts)
        if group not in valid_groups:
            result.error(filename, name, 'Expert group', group, 'is not in', valid_groups)

        if severity not in valid_levels:
            result.error(filename, name, 'Expert severity', severity, 'is not in', valid_levels)

        # Checks on the summary field
        if summary.startswith(' '):
            result.warn(filename, 'Expert info summary', '"' + summary + '"', 'for', name, 'starts with space')
        if summary.endswith(' '):
            result.warn(filename, 'Expert info summary', '"' + summary + '"', 'for', name, 'ends with space')
        if '  ' in summary:
            result.warn(filename, 'Expert info summary', '"' + summary + '"', 'for', name, 'has a double space')

        # The summary field is shown in the expert window without substituting args..
        if '%' in summary:
            result.warn(filename, 'Expert info summary', '"' + summary + '"', 'for', name, 'has format specifiers in it?')


# Collection of entries for this dissector
class ExpertEntries:
    def __init__(self, filename, result):
        self.filename = filename
        self.result = result
        self.entries = []
        self.summaries = set()  # key is (name, severity)
        self.summary_reverselookup = {}  # summary -> item-name
        self.filter_reverselookup = {}   # filter  -> item-name
        self.filters = set()

    def AddEntry(self, entry):
        self.entries.append(entry)

        # If summaries are not unique, can't tell apart from expert window (need to look into frame to see details)
        # TODO: summary strings will never be seen if all calls to that item use expert_add_info_format()
        if (entry.summary, entry.severity) in self.summaries:
            self.result.note(self.filename, 'Expert summary', '"' + entry.summary + '"',
                             'has already been seen (now in', entry.name, '- previously in', self.summary_reverselookup[entry.summary], ')')
        self.summaries.add((entry.summary, entry.severity))
        self.summary_reverselookup[entry.summary] = entry.name

        # Not sure if anyone ever filters on these, but check if are unique
        if entry.filter in self.filters:
            self.result.error(self.filename, 'Expert filter', '"' + entry.filter + '"',
                              'has already been seen (now in', entry.name, '- previously in', self.filter_reverselookup[entry.filter], ')')
        self.filters.add(entry.filter)
        self.filter_reverselookup[entry.filter] = entry.name

    def AddCall(self, item):
        for entry in self.entries:
            if entry.name == item:
                # Found
                entry.calls += 1
                return

    def VerifyCall(self, item):
        # TODO: ignore if wasn't declared in self.filename?
        for entry in self.entries:
            if entry.name == item:
                # Found
                return

        # None matched...
        if item not in ['hf', 'dissect_hf']:
            self.result.warn(self.filename, 'Expert info added with', '"' + item + '"', 'was not registered (in this file)?')

    def NumberOfCalls(self, item):
        for entry in self.entries:
            if entry.name == item:
                return entry.calls
        return 0

    def GetDefaultStringForItem(self, item):
        for entry in self.entries:
            if entry.name == item:
                # Found,
                return entry.summary


# The relevant parts of an hf item.  Used as value in dict where hf variable name is key.
class Item:

    # Keep the previous few items
    previousItems = []

    def __init__(self, filename, hf, filter, label, item_type, display, strings, macros,
                 result, value_strings, range_strings,
                 mask=None, check_mask=False, mask_exact_width=False, check_label=False,
                 check_consecutive=False, blurb=''):
        self.filename = filename
        self.hf = hf
        self.filter = filter
        self.label = label
        self.blurb = blurb
        self.mask = mask
        self.mask_value_invalid = False
        self.strings = strings
        self.mask_exact_width = mask_exact_width
        self.result = result

        if blurb == '0':
            result.error(filename, hf, ': - filter "' + filter +
                         '" has blurb of 0 - if no string, please set NULL instead')

        if check_consecutive:
            for previous_index, previous_item in enumerate(Item.previousItems):
                if previous_item.filter == filter:
                    if label != previous_item.label:
                        if not is_ignored_consecutive_filter(self.filter):
                            result.warn('Warning:', filename, hf, ': - filter "' + filter +
                                        '" appears ' + str(previous_index+1) + ' items before - labels are "' + previous_item.label + '" and "' + label + '"')

            # Add this one to front of (short) previous list
            Item.previousItems = [self] + Item.previousItems
            if len(Item.previousItems) > 5:
                # Get rid of oldest one now
                # Item.previousItems = Item.previousItems[:-1]
                Item.previousItems.pop()

        self.item_type = item_type

        self.display = display
        self.set_display_value(macros)

        self.set_mask_value(macros)

        # Optionally check label (short and long).
        if check_label:
            self.check_label(label, 'label')
            # self.check_label(blurb, 'blurb')
            self.check_blurb_vs_label()

        # Optionally check that mask bits are contiguous
        if check_mask:
            if self.mask_read and mask not in {'NULL', '0x0', '0', '0x00'}:
                self.check_contiguous_bits(mask)
                self.check_num_digits(self.mask)
                # N.B., if last entry in set is removed, see around 18,000 warnings
                self.check_digits_all_zeros(self.mask)

        # N.B. these checks are already done by checkApis.pl
        if 'RVALS' in strings and 'BASE_RANGE_STRING' not in display:
            result.warn(filename, hf, 'filter "' + filter + ' strings has RVALS but display lacks BASE_RANGE_STRING')

        # For RVALS, is BASE_RANGE_STRING also set (checked by checkApis.pl)?
        if 'VALS_EXT_PTR' in strings and 'BASE_EXT_STRING' not in display:
            result.warn(filename, hf, 'filter "' + filter + ' strings has VALS_EXT_PTR but display lacks BASE_EXT_STRING')

        # For VALS, lookup the corresponding ValueString and try to check range.
        vs_re = re.compile(r'VALS\(([a-zA-Z0-9_]*)\)')
        m = vs_re.search(strings)
        if m:
            self.vs_name = m.group(1)
            if self.vs_name in value_strings:
                vs = value_strings[self.vs_name]
                self.check_value_string_range(vs.min_value, vs.max_value)

        # For RVALS, lookup the corresponding RangeString and try to check range.
        rs_re = re.compile(r'RVALS\(([a-zA-Z0-9_]*)\)')
        m = rs_re.search(strings)
        if m:
            self.rs_name = m.group(1)
            if self.rs_name in range_strings:
                rs = range_strings[self.rs_name]
                self.check_range_string_range(rs.min_value, rs.max_value)

        # Could/should this item be FT_FRAMENUM ?
        # if (' frame' in self.label.lower() or 'frame ' in self.label.lower()) and 'frames' not in self.label.lower() and
        #    ('in' in self.label.lower() or 'for' in self.label.lower()) and
        #    self.item_type == 'FT_UINT32' and self.mask_value == 0x0):
        #    result.warn(self.filename, self.hf, 'filter "' + self.filter + '", label "' + label + '"', 'item type is', self.item_type, '- could be FT_FRANENUM?')

        if item_type == 'FT_IPv4':
            if label.endswith('6') or filter.endswith('6'):
                result.warn(filename, hf, 'filter ' + filter + 'label "' + label + '" but is a v4 field')
        if item_type == 'FT_IPv6':
            if label.endswith('4') or filter.endswith('4'):
                result.warn(filename, hf, 'filter ' + filter + 'label "' + label + '" but is a v6 field')

        # Could/should this entry use one of the port type display types?
        if False:
            if item_type == 'FT_UINT16' and not display.startswith('BASE_PT_') and display != 'BASE_CUSTOM':
                desc = str(self).lower()
                # TODO: use re to avoid matching 'transport' ?
                if 'port' in desc.lower():
                    if 'udp' in desc or 'tcp' in desc or 'sctp' in desc:
                        result.warn(filename, hf, 'filter "' + filter + '" label "' + label + '" field might be a transport port - should use e.g., BASE_PT_UDP as display??')
                        # print(self)

    def __str__(self):
        return 'Item ({0} {1} "{2}" "{3}" type={4}:{5} {6} mask={7})'.format(self.filename, self.hf, self.label, self.filter, self.item_type, self.display, self.strings, self.mask)

    def check_label(self, label, label_name):

        # TODO: this is masking a bug where the re for the item can't cope with macro for containing ',' for mask arg..
        if label.count('"') == 1:
            return

        if label.startswith(' ') or label.endswith(' '):
            self.result.warn(self.filename, self.hf, 'filter "' + self.filter, label_name,  '"' + label + '" begins or ends with a space')

        if (label.count('(') != label.count(')') or
           label.count('[') != label.count(']') or
           label.count('{') != label.count('}')):
            # Ignore if includes quotes, as may be unbalanced.
            if "'" not in label:
                self.result.warn(self.filename, self.hf, 'filter "' + self.filter + '"', label_name, '"' + label + '"', 'has unbalanced parens/braces/brackets')
        if self.item_type != 'FT_NONE' and label.endswith(':'):
            self.result.warn(self.filename, self.hf, 'filter "' + self.filter + '"', label_name, '"' + label + '"', 'with type', self.item_type, 'ends with an unnecessary colon')

    def check_blurb_vs_label(self):
        if self.blurb == "NULL":
            return

        # Is the label longer than the blurb?
        # Generated dissectors tend to write the type into the blurb field...
        # if len(self.label) > len(self.blurb):
        #    self.warn(self.filename, self.hf, 'label="' + self.label + '" blurb="' + self.blurb + '"', "- label longer than blurb!!!")

        # Is the blurb just the label in a different order?
        label_words = self.label.lower().split(' ')
        label_words.sort()
        blurb_words = self.blurb.lower().split(' ')
        blurb_words.sort()

        # Subset - often happens when part specific to that field is dropped
        if set(label_words) > set(blurb_words):
            self.result.warn(self.filename, self.hf, 'label="' + self.label + '" blurb="' + self.blurb + '"', "- words in blurb are subset of label words")

        # Just a re-ordering (but may also contain capitalization changes.)
        if blurb_words == label_words:
            self.result.warn(self.filename, self.hf, 'label="' + self.label + '" blurb="' + self.blurb + '"', "- blurb words are label words (re-ordered?)")

        # TODO: could have item know protocol name(s) from file this item was found in, and complain if blurb is just prot-name + label ?

    def set_mask_value(self, macros):
        self.mask_width = 0
        try:
            self.mask_read = True
            # PIDL generator adds annoying parenthesis and spaces around mask..
            self.mask = self.mask.strip('() ')

            # Substitute mask if found as a macro..
            if self.mask in macros:
                self.mask = macros[self.mask]
            elif any(c not in '0123456789abcdefABCDEFxX' for c in self.mask):
                self.mask_read = False
                # Didn't manage to parse, set to a full value to avoid warnings.
                self.mask_value = 0xffffffff
                self.mask_width = 32
                self.mask_value_invalid = True
                # print(self.filename, 'Could not read:', '"' + self.mask + '"')
                return

            # Read according to the appropriate base.
            if self.mask.startswith('0x'):
                self.mask_value = int(self.mask, 16)
            elif self.mask.startswith('0'):
                self.mask_value = int(self.mask, 8)
            else:
                self.mask_value = int(self.mask, 10)

            # Also try to set mask_width
            if self.mask_value > 0:
                # Distance between first and last '1'
                bitBools = bin(self.mask_value)[2:]
                self.mask_width = bitBools.rfind('1') - bitBools.find('1') + 1
            else:
                # No mask is effectively a full mask..
                self.mask_width = self.get_field_width_in_bits()

        except Exception:
            self.mask_read = False
            # Didn't manage to parse, set to a full value to avoid warnings.
            self.mask_value = 0xffffffff
            self.mask_width = 32
            self.mask_value_invalid = True

        # if not self.mask_read:
        #    print('Could not read:', self.mask)

    def set_display_value(self, macros):
        try:
            self.display_read = True
            display = self.display

            # Substitute display if found as a macro..
            if display in macros:
                display = macros[display]
            elif any(c not in '0123456789abcdefABCDEFxX' for c in display):
                self.display_read = False
                self.display_value = 0
                return

            # Read according to the appropriate base.
            if self.display.startswith('0x'):
                self.display_value = int(display, 16)
            elif self.display.startswith('0'):
                self.display_value = int(display, 8)
            else:
                self.display_value = int(display, 10)
        except Exception:
            self.display_read = False
            self.display_value = 0

    def check_value_string_range(self, vs_min, vs_max):
        item_width = self.get_field_width_in_bits()

        if item_width is None:
            # Type field defined by macro?
            return

        item_max = (2 ** self.mask_width)
        if vs_max > item_max:
            self.result.warn(self.filename, self.hf, 'filter=', self.filter,
                             self.strings, "has max value", vs_max, '(' + hex(vs_max) + ')', "which doesn't fit into", self.mask_width, 'bits',
                             '( mask is', hex(self.mask_value), ')')

    def check_range_string_range(self, rs_min, rs_max):
        item_width = self.get_field_width_in_bits()

        if item_width is None:
            # Type field defined by macro?
            return

        item_max = (2 ** self.mask_width)
        if rs_max > item_max:
            self.result.warn(self.filename, self.hf, 'filter=', self.filter,
                             self.strings, "has values", rs_min, rs_max, '(' + hex(rs_max) + ')', "which doesn't fit into", self.mask_width, 'bits',
                             '( mask is', hex(self.mask_value), ')')

    # Return true if bit position n is set in value.
    def check_bit(self, value, n):
        return (value & (0x1 << n)) != 0

    # Output a warning if non-contiguous bits are found in the mask (uint64_t).
    # Note that this legitimately happens in several dissectors where multiple reserved/unassigned
    # bits are conflated into one field.
    # - there is probably a cool/efficient way to check this (+1 => 1-bit set?)
    def check_contiguous_bits(self, mask):
        if not self.mask_value:
            return

        # Do see legitimate non-contiguous bits often for these..
        if name_has_one_of(self.hf, ['reserved', 'unknown', 'unused', 'spare']):
            return
        if name_has_one_of(self.label, ['reserved', 'unknown', 'unused', 'spare']):
            return

        # Walk past any l.s. 0 bits
        n = 0
        while not self.check_bit(self.mask_value, n) and n <= 63:
            n += 1
        if n == 63:
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
        if self.item_type not in field_widths:
            # print('unexpected item_type is ', self.item_type)
            field_width = 64
        else:
            field_width = self.get_field_width_in_bits()

        # Its a problem is the mask_width is > field_width - some of the bits won't get looked at!?
        mask_width = n-1-mask_start
        if field_width is not None and (mask_width > field_width):
            # N.B. No call, so no line number.
            self.result.warn(self.filename + ':', self.hf, 'filter=', self.filter, self.item_type, 'so field_width=', field_width,
                             'but mask is', mask, 'which is', mask_width, 'bits wide!')
        # Now, any more zero set bits are an error!
        if self.filter in known_non_contiguous_fields or self.filter.startswith('rtpmidi'):
            # Don't report if we know this one is Ok.
            # TODO: also exclude items that are used as root in add_bitmask() calls?
            return
        while n <= 63:
            if self.check_bit(self.mask_value, n):
                self.result.warn(self.filename, self.hf, 'filter=', self.filter, ' - mask with non-contiguous bits',
                                 mask, '(', hex(self.mask_value), ')')
                return
            n += 1

    def get_field_width_in_bits(self):
        if self.item_type == 'FT_BOOLEAN':
            if self.display == 'BASE_NONE':    # 'NULL' ?
                return 8  # i.e. 1 byte
            elif self.display == 'SEP_DOT':   # from proto.h, only meant for FT_BYTES
                return 64
            else:
                try:
                    # For FT_BOOLEAN, modifier is just numerical number of bits. Round up to next nibble.
                    return int((int(self.display) + 3)/4)*4
                except Exception:
                    return 8
        else:
            if self.item_type in field_widths:
                # Lookup fixed width for this type
                return field_widths[self.item_type]
            else:
                # Unknown type..
                return 0

    def check_num_digits(self, mask):
        if mask.startswith('0x') and len(mask) > 3:

            width_in_bits = self.get_field_width_in_bits()
            # Warn if odd number of digits.  TODO: only if >= 5?
            if len(mask) % 2 and self.item_type != 'FT_BOOLEAN':
                self.result.warn(self.filename, self.hf, 'filter=', self.filter, ' - mask has odd number of digits', mask,
                                 'expected max for', self.item_type, 'is', int(width_in_bits/4))

            if self.item_type in field_widths:
                # Longer than it should be?
                if width_in_bits is None:
                    return
                if len(mask)-2 > width_in_bits/4:
                    extra_digits = mask[2:2+(len(mask)-2 - int(width_in_bits/4))]
                    # Its definitely an error if any of these are non-zero, as they won't have any effect!
                    if extra_digits != '0'*len(extra_digits):
                        self.result.error(self.filename, self.hf, 'filter=', self.filter, 'mask', self.mask, "with len is", len(mask)-2,
                                          "but type", self.item_type, " indicates max of", int(width_in_bits/4),
                                          "and extra digits are non-zero (" + extra_digits + ")")
                    else:
                        # Has extra leading zeros, still confusing, so warn.
                        self.result.warn(self.filename, self.hf, 'filter=', self.filter, 'mask', self.mask, "with len", len(mask)-2,
                                         "but type", self.item_type, " indicates max of", int(width_in_bits/4))

                # Strict/fussy check - expecting mask length to match field width exactly!
                # Currently only doing for FT_BOOLEAN, and don't expect to be in full for 64-bit fields!
                if self.mask_exact_width:
                    ideal_mask_width = int(width_in_bits/4)
                    if self.item_type == 'FT_BOOLEAN' and ideal_mask_width < 16 and len(mask)-2 != ideal_mask_width:
                        self.result.warn(self.filename, self.hf, 'filter=', self.filter, 'mask', self.mask, "with len", len(mask)-2,
                                         "but type", self.item_type, "|", self.display,  " indicates should be", int(width_in_bits/4))

            else:
                # This type shouldn't have a mask set at all.
                self.result.warn(self.filename, self.hf, 'filter=', self.filter, ' - item has type', self.item_type, 'but mask set:', mask)

    def check_digits_all_zeros(self, mask):
        if mask.startswith('0x') and len(mask) > 3:
            if mask[2:] == '0'*(len(mask)-2):
                self.result.warn(self.filename, self.hf, 'filter=', self.filter, ' - item mask has all zeros - this is confusing! :', '"' + mask + '"')

    # A mask where all bits are set should instead be 0.
    # Exceptions might be where:
    # - in add_bitmask()
    # - represents flags, but dissector is not yet decoding them
    def check_full_mask(self, mask, field_arrays):
        if self.item_type == "FT_BOOLEAN":
            return
        if 'mask' in self.label.lower() or 'flag' in self.label.lower() or 'bitmap' in self.label.lower():
            return
        if mask.startswith('0x') and len(mask) > 3:
            width_in_bits = self.get_field_width_in_bits()
            if not width_in_bits:
                return
            num_digits = int(width_in_bits / 4)
            if num_digits is None:
                return
            if (mask[2:] == 'f' * num_digits) or (mask[2:] == 'F' * num_digits):
                # Don't report if appears in a 'fields' array
                for arr in field_arrays:
                    list = field_arrays[arr][0]
                    if self.hf in list:
                        # These need to have a mask - don't judge for being 0
                        return

                # No point in setting all bits if only want decimal number..
                if self.display == "BASE_DEC":
                    self.result.note(self.filename, self.hf, 'filter=', self.filter, " - mask is all set - if only want value (rather than bits), set 0 instead? :", '"' + mask + '"')

    # An item that appears in a bitmask set, needs to have a non-zero mask.
    def check_mask_if_in_field_array(self, mask, field_arrays):
        # Work out if this item appears in a field array
        found = False
        for arr in field_arrays:
            list = field_arrays[arr][0]
            if self.hf in list:
                # These need to have a mask - don't judge for being 0
                found = True
                break
        if found:
            # It needs to have a non-zero mask.
            if self.mask_read and self.mask_value == 0:
                self.result.error(self.filename, self.hf, 'is in fields array', arr, 'but has a zero mask - this is not allowed')

    # Return True if appears to be a match
    def check_label_vs_filter(self, reportError=True, reportNumericalMismatch=True):

        last_filter = self.filter.split('.')[-1]
        last_filter_orig = last_filter
        last_filter = last_filter.replace('-', '')
        last_filter = last_filter.replace('_', '')
        last_filter = last_filter.replace(' ', '')
        label = self.label
        label_orig = label
        label = label.replace(' ', '')
        label = label.replace('-', '')
        label = label.replace('_', '')
        label = label.replace('(', '')
        label = label.replace(')', '')
        label = label.replace('/', '')
        label = label.replace("'", '')

        # OK if filter is abbrev of label.
        label_words = self.label.split(' ')
        label_words = [w for w in label_words if len(w)]
        if len(label_words) == len(last_filter):
            abbrev_letters = [w[0] for w in label_words]
            abbrev = ''.join(abbrev_letters)
            if abbrev.lower() == last_filter.lower():
                return True

        # If both have numbers, they should probably match!
        label_numbers = [int(n) for n in re.findall(r'\d+', label_orig)]
        filter_numbers = [int(n) for n in re.findall(r'\d+', last_filter_orig)]
        if len(label_numbers) == len(filter_numbers) and label_numbers != filter_numbers:
            if reportNumericalMismatch:
                self.result.note(self.filename, self.hf, 'label="' + self.label + '" has different **numbers** from  filter="' + self.filter + '"',
                                 label_numbers, filter_numbers)
            return False

        # If they match after trimming number from filter, they should match.
        if label.lower() == last_filter.lower().rstrip("0123456789"):
            return True

        # Are they just different?
        if last_filter.lower() not in label.lower():
            if reportError:
                self.result.warn(self.filename, self.hf, 'label="' + self.label + '" does not seem to match filter="' + self.filter + '"')
            return False

        return True

    def check_boolean_length(self):
        # If mask is 0, display must be BASE_NONE.
        if self.item_type == 'FT_BOOLEAN' and self.mask_read and self.mask_value == 0 and self.display.find('BASE_NONE') == -1:
            self.result.error(self.filename, self.hf, 'type is FT_BOOLEAN, no mask set (', self.mask, ') - display should be BASE_NONE, is instead', self.display)
        # TODO: check for length > 64?

    def check_string_display(self):
        if self.item_type in {'FT_STRING', 'FT_STRINGZ', 'FT_UINT_STRING'}:
            if 'BASE_NONE' not in self.display and 'BASE_STR_WSP' not in self.display:
                self.result.warn(self.filename, self.hf, 'type is', self.item_type, 'display must be BASE_NONE or BASE_STR_WSP, is instead', self.display)

    def check_ipv4_display(self):
        if self.item_type == 'FT_IPv4' and self.display not in {'BASE_NETMASK', 'BASE_NONE'}:
            self.result.error(self.filename, self.hf, 'type is FT_IPv4, should be BASE_NETMASK or BASE_NONE, is instead', self.display)


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
        self.all_calls.sort(key=lambda x: x.line_number)

    # Not currently called
    def check_consecutive_item_calls(self):
        lines = open(self.file, 'r', encoding="utf8").read().splitlines()

        prev = None
        for call in self.all_calls:

            # These names commonly do appear together..
            if name_has_one_of(call.hf_name, ['unused', 'unknown', 'spare', 'reserved', 'default']):
                return

            if prev and call.hf_name == prev.hf_name:
                # More compelling if close together..
                if call.line_number > prev.line_number and (call.line_number - prev.line_number <= 4):
                    scope_different = False
                    for no in range(prev.line_number, call.line_number-1):
                        if '{' in lines[no] or '}' in lines[no] or 'else' in lines[no] or 'break;' in lines[no] or 'if ' in lines[no]:
                            scope_different = True
                            break
                    # Also more compelling if check for and scope changes { } in lines in-between?
                    if not scope_different:
                        self.result.warn(f + ':' + str(call.line_number),
                                         call.hf_name + ' called consecutively at line', call.line_number, '- previous at', prev.line_number)
            prev = call


# These are APIs in proto.c that check a set of types at runtime and can print '.. is not of type ..' to the console
# if the type is not suitable.
apiChecks = []
apiChecks.append(APICheck('proto_tree_add_item_ret_uint', {'FT_CHAR', 'FT_UINT8', 'FT_UINT16', 'FT_UINT24', 'FT_UINT32'}, positive_length=True))
apiChecks.append(APICheck('proto_tree_add_item_ret_int', {'FT_INT8', 'FT_INT16', 'FT_INT24', 'FT_INT32'}))
apiChecks.append(APICheck('ptvcursor_add_ret_uint', {'FT_CHAR', 'FT_UINT8', 'FT_UINT16', 'FT_UINT24', 'FT_UINT32'}, positive_length=True))
apiChecks.append(APICheck('ptvcursor_add_ret_int', {'FT_INT8', 'FT_INT16', 'FT_INT24', 'FT_INT32'}, positive_length=True))
apiChecks.append(APICheck('ptvcursor_add_ret_string', {'FT_STRING', 'FT_STRINGZ', 'FT_UINT_STRING', 'FT_STRINGZPAD', 'FT_STRINGZTRUNC'}))
apiChecks.append(APICheck('ptvcursor_add_ret_boolean', {'FT_BOOLEAN'}, positive_length=True))
apiChecks.append(APICheck('proto_tree_add_item_ret_uint64', {'FT_UINT40', 'FT_UINT48', 'FT_UINT56', 'FT_UINT64'}, positive_length=True))
apiChecks.append(APICheck('proto_tree_add_item_ret_int64', {'FT_INT40', 'FT_INT48', 'FT_INT56', 'FT_INT64'}, positive_length=True))
apiChecks.append(APICheck('proto_tree_add_item_ret_boolean', {'FT_BOOLEAN'}, positive_length=True))
apiChecks.append(APICheck('proto_tree_add_item_ret_string_and_length', {'FT_STRING', 'FT_STRINGZ', 'FT_UINT_STRING', 'FT_STRINGZPAD', 'FT_STRINGZTRUNC'}))
apiChecks.append(APICheck('proto_tree_add_item_ret_display_string_and_length', {'FT_STRING', 'FT_STRINGZ', 'FT_UINT_STRING',
                                                                                'FT_STRINGZPAD', 'FT_STRINGZTRUNC', 'FT_BYTES', 'FT_UINT_BYTES'}))
apiChecks.append(APICheck('proto_tree_add_item_ret_time_string', {'FT_ABSOLUTE_TIME', 'FT_RELATIVE_TIME'}))
apiChecks.append(APICheck('proto_tree_add_uint', {'FT_CHAR', 'FT_UINT8', 'FT_UINT16', 'FT_UINT24', 'FT_UINT32', 'FT_FRAMENUM'}))
apiChecks.append(APICheck('proto_tree_add_uint_format_value', {'FT_CHAR', 'FT_UINT8', 'FT_UINT16', 'FT_UINT24', 'FT_UINT32', 'FT_FRAMENUM'}))
apiChecks.append(APICheck('proto_tree_add_uint_format', {'FT_CHAR', 'FT_UINT8', 'FT_UINT16', 'FT_UINT24', 'FT_UINT32', 'FT_FRAMENUM'}))
apiChecks.append(APICheck('proto_tree_add_uint64', {'FT_UINT40', 'FT_UINT48', 'FT_UINT56', 'FT_UINT64', 'FT_FRAMENUM'}))
apiChecks.append(APICheck('proto_tree_add_int64', {'FT_INT40', 'FT_INT48', 'FT_INT56', 'FT_INT64'}))
apiChecks.append(APICheck('proto_tree_add_int64_format_value', {'FT_INT40', 'FT_INT48', 'FT_INT56', 'FT_INT64'}))
apiChecks.append(APICheck('proto_tree_add_int64_format', {'FT_INT40', 'FT_INT48', 'FT_INT56', 'FT_INT64'}))
apiChecks.append(APICheck('proto_tree_add_int', {'FT_INT8', 'FT_INT16', 'FT_INT24', 'FT_INT32'}))
apiChecks.append(APICheck('proto_tree_add_int_format_value', {'FT_INT8', 'FT_INT16', 'FT_INT24', 'FT_INT32'}))
apiChecks.append(APICheck('proto_tree_add_int_format', {'FT_INT8', 'FT_INT16', 'FT_INT24', 'FT_INT32'}))
apiChecks.append(APICheck('proto_tree_add_boolean', {'FT_BOOLEAN'}))
apiChecks.append(APICheck('proto_tree_add_boolean64', {'FT_BOOLEAN'}))
apiChecks.append(APICheck('proto_tree_add_float', {'FT_FLOAT'}))
apiChecks.append(APICheck('proto_tree_add_float_format', {'FT_FLOAT'}))
apiChecks.append(APICheck('proto_tree_add_float_format_value', {'FT_FLOAT'}))
apiChecks.append(APICheck('proto_tree_add_double', {'FT_DOUBLE'}))
apiChecks.append(APICheck('proto_tree_add_double_format', {'FT_DOUBLE'}))
apiChecks.append(APICheck('proto_tree_add_double_format_value', {'FT_DOUBLE'}))
apiChecks.append(APICheck('proto_tree_add_string', {'FT_STRING', 'FT_STRINGZ', 'FT_UINT_STRING', 'FT_STRINGZPAD', 'FT_STRINGZTRUNC'}))
apiChecks.append(APICheck('proto_tree_add_string_format', {'FT_STRING', 'FT_STRINGZ', 'FT_UINT_STRING', 'FT_STRINGZPAD', 'FT_STRINGZTRUNC'}))
apiChecks.append(APICheck('proto_tree_add_string_format_value', {'FT_STRING', 'FT_STRINGZ', 'FT_UINT_STRING', 'FT_STRINGZPAD', 'FT_STRINGZTRUNC'}))
apiChecks.append(APICheck('proto_tree_add_guid', {'FT_GUID'}))
apiChecks.append(APICheck('proto_tree_add_oid', {'FT_OID'}))
apiChecks.append(APICheck('proto_tree_add_none_format', {'FT_NONE'}))
apiChecks.append(APICheck('proto_tree_add_item_ret_varint', {'FT_INT8', 'FT_INT16', 'FT_INT24', 'FT_INT32', 'FT_INT40', 'FT_INT48', 'FT_INT56', 'FT_INT64',
                                                             'FT_CHAR', 'FT_UINT8', 'FT_UINT16', 'FT_UINT24', 'FT_UINT32', 'FT_FRAMENUM',
                                                             'FT_UINT40', 'FT_UINT48', 'FT_UINT56', 'FT_UINT64'}))
apiChecks.append(APICheck('proto_tree_add_boolean_bits_format_value', {'FT_BOOLEAN'}))
apiChecks.append(APICheck('proto_tree_add_ascii_7bits_item', {'FT_STRING'}))
# TODO: positions are different, and takes 2 hf_fields..
# apiChecks.append(APICheck('proto_tree_add_checksum', { 'FT_UINT8', 'FT_UINT16', 'FT_UINT24', 'FT_UINT32'}))
apiChecks.append(APICheck('proto_tree_add_int64_bits_format_value', {'FT_INT40', 'FT_INT48', 'FT_INT56', 'FT_INT64'}))

# TODO: add proto_tree_add_bytes_item, proto_tree_add_time_item ?

bitmask_types = {'FT_CHAR', 'FT_UINT8', 'FT_UINT16', 'FT_UINT24', 'FT_UINT32',
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
# N.B., proto_tree_add_bitmask_list does not have a root item, just a subtree...

add_bits_types = {'FT_CHAR', 'FT_BOOLEAN',
                  'FT_UINT8', 'FT_UINT16', 'FT_UINT24', 'FT_UINT32', 'FT_UINT40', 'FT_UINT48', 'FT_UINT56', 'FT_UINT64',
                  'FT_INT8', 'FT_INT16', 'FT_INT24', 'FT_INT32', 'FT_INT40', 'FT_INT48', 'FT_INT56', 'FT_INT64',
                  'FT_BYTES'}
apiChecks.append(APICheck('proto_tree_add_bits_item',    add_bits_types))
apiChecks.append(APICheck('proto_tree_add_bits_ret_val', add_bits_types))

# TODO: doesn't even have an hf_item !
# apiChecks.append(APICheck('proto_tree_add_bitmask_text', bitmask_types))

# Check some ptvcuror calls too.
apiChecks.append(APICheck('ptvcursor_add_ret_uint', {'FT_CHAR', 'FT_UINT8', 'FT_UINT16', 'FT_UINT24', 'FT_UINT32'}))
apiChecks.append(APICheck('ptvcursor_add_ret_int', {'FT_INT8', 'FT_INT16', 'FT_INT24', 'FT_INT32'}))
apiChecks.append(APICheck('ptvcursor_add_ret_boolean', {'FT_BOOLEAN'}))


# Also try to check proto_tree_add_item() calls (for length)
apiChecks.append(ProtoTreeAddItemCheck())
apiChecks.append(ProtoTreeAddItemCheck(True))  # for ptvcursor_add()

apiChecks.append(TVBGetBits('tvb_get_bits8',  maxlen=8))
apiChecks.append(TVBGetBits('tvb_get_bits16', maxlen=16))
apiChecks.append(TVBGetBits('tvb_get_bits32', maxlen=32))
apiChecks.append(TVBGetBits('tvb_get_bits64', maxlen=64))


# Looking for simple #define macros or enumerations.
def find_macros(filename, contents):
    # Pre-populate with some useful values..
    macros = {'BASE_NONE': 0,  'BASE_DEC': 1}

    # Also look for macros from corresponding header file, if present
    files_to_check = [filename]
    header = Path(filename).with_suffix('.h')
    if os.path.exists(header):
        files_to_check.append(header)

    # TODO: also/instead look for directly included files of form packet-xxx.h ?

    for file in files_to_check:
        if file == filename:
            contents_to_check = contents
        else:
            with open(file, 'r', encoding="utf8") as f:
                contents_to_check = f.read()
                # Remove comments so as not to trip up RE.
                contents_to_check = removeComments(contents_to_check)

        # Allowing optional parenthesis around value part.
        matches = re.finditer(r'#define\s*([A-Za-z0-9_]*)\s*\(?([0-9xa-fA-F]*)\)?\s*\n', contents_to_check)
        for m in matches:
            # Store this mapping.
            macros[m.group(1)] = m.group(2)

        # Also look for what could be enumeration assignments
        matches = re.finditer(r'\s*([A-Za-z0-9_]*)\s*=\s*([0-9xa-fA-F]*)\s*,?\n', contents_to_check)
        for m in matches:
            # Store this mapping.
            macros[m.group(1)] = m.group(2)

    return macros


# Look for hf items (i.e. full item to be registered) in a dissector file.
def find_items(filename, contents, macros, result, value_strings, range_strings,
               check_mask=False, mask_exact_width=False, check_label=False, check_consecutive=False):
    is_generated = isGeneratedFile(filename)
    items = {}

    # N.B. re extends all the way to HFILL to avoid greedy matching
    # TODO: fix a problem where re can't cope with mask that involve a macro with commas in it...
    matches = re.finditer(r'.*\{\s*\&(hf_[a-z_A-Z0-9]*)\s*,\s*{\s*\"(.*?)\"\s*,\s*\"(.*?)\"\s*,\s*(.*?)\s*,\s*([0-9A-Z_\|\s]*?)\s*,\s*(.*?)\s*,\s*(.*?)\s*,\s*([a-zA-Z0-9\W\s_\u00f6\u00e4]*?)\s*,\s*HFILL', contents)
    for m in matches:
        # Store this item.
        hf = m.group(1)

        blurb = m.group(8)
        if blurb.startswith('"'):
            blurb = blurb[1:-1]

        items[hf] = Item(filename, hf, filter=m.group(3), label=m.group(2), item_type=m.group(4),
                         display=m.group(5),
                         strings=m.group(6),
                         macros=macros,
                         result=result,
                         value_strings=value_strings,
                         range_strings=range_strings,
                         mask=m.group(7),
                         blurb=blurb,
                         check_mask=check_mask,
                         mask_exact_width=mask_exact_width,
                         check_label=check_label,
                         check_consecutive=(not is_generated and check_consecutive))
    return items


# Looking for args to ..add_bitmask_..() calls that are not NULL-terminated or  have repeated items.
# TODO: some dissectors have similar-looking hf arrays for other reasons, so need to cross-reference with
# the 6th arg of ..add_bitmask_..() calls...
# TODO: return items (rather than local checks) from here so can be checked against list of calls for given filename
def find_field_arrays(filename, contents, all_fields, all_hf, result):
    field_entries = {}

    # Find definition of hf array
    matches = re.finditer(r'static\s*g?int\s*\*\s*const\s+([a-zA-Z0-9_]*)\s*\[\]\s*\=\s*\{([a-zA-Z0-9,_\&\s]*)\}', contents)
    for m in matches:
        name = m.group(1)
        # Ignore if not used in a call to an _add_bitmask_ API
        if name not in all_fields:
            continue

        fields_text = m.group(2)
        fields_text = fields_text.replace('&', '')
        fields_text = fields_text.replace(',', '')

        # Get list of each hf field in the array
        fields = fields_text.split()

        if fields[0].startswith('ett_'):
            continue
        if 'NULL' not in fields[-1] and fields[-1] != '0':
            result.warn(filename, name, 'is not NULL-terminated - {', ', '.join(fields), '}')
            continue

        # Do any hf items reappear?
        seen_fields = set()
        for f in fields:
            if f in seen_fields:
                result.warn(filename, name, f, 'already added!')
            seen_fields.add(f)

        # Check for duplicated flags among entries..
        combined_mask = 0x0
        for f in fields[0:-1]:
            if f in all_hf:
                # Don't use invalid mask.
                new_mask = all_hf[f].mask_value if not all_hf[f].mask_value_invalid else 0
                if new_mask & combined_mask:
                    result.warn(filename, name, 'has overlapping mask - {', ', '.join(fields), '} combined currently', hex(combined_mask), f, 'adds', hex(new_mask))
                combined_mask |= new_mask

        # Make sure all entries have the same width
        set_field_width = None
        for f in fields[0:-1]:
            if f in all_hf:
                new_field_width = all_hf[f].get_field_width_in_bits()
                if set_field_width is not None and new_field_width != set_field_width:
                    # Its not uncommon for fields to be used in multiple sets, some of which can be different widths..
                    result.note(filename, name, 'set items not all same width - {', ', '.join(fields), '} seen', set_field_width, 'now', new_field_width)
                set_field_width = new_field_width

        # Add entry to table
        field_entries[name] = (fields[0:-1], combined_mask)

    return field_entries


def find_item_declarations(filename, lines):
    items = set()

    p = re.compile(r'^static int (hf_[a-zA-Z0-9_]*)\s*\=\s*-1;')
    for line in lines:
        m = p.search(line)
        if m:
            items.add(m.group(1))
    return items


def find_item_extern_declarations(filename, lines):
    items = set()
    p = re.compile(r'^\s*(hf_[a-zA-Z0-9_]*)\s*\=\s*proto_registrar_get_id_byname\s*\(')
    for line in lines:
        m = p.search(line)
        if m:
            items.add(m.group(1))
    return items

fetch_functions = [ 'tvb_get_ntohl', 'tvb_get_letohl' ]

def line_has_fetch_function(line):
    for f in fetch_functions:
        if f in line:
            return True
    return False


def check_double_fetches(filename, contents, items, result):
    lines = contents.splitlines()
    contents = '\n'.join(line for line in lines if line.strip())

    line_re = r'([\*a-zA-Z0-9_= ;\(\)\+\"\-\{\}\*\,\&\+\[\]\!]*?)\n'

    # Look for all calls in this file - note line before and after item added
    matches = re.finditer(r'\n' + line_re +
                          r'([\sa-z_\*=]*?)(proto_tree_add_item)\s*\(([a-zA-Z0-9_]+)\s*,\s*([a-zA-Z0-9_]+).*?\)\;\s*\n' +
                          line_re,
                          contents, re.MULTILINE | re.DOTALL)

    for m in matches:
        full_hf_name = m.group(5)
        hf_name = m.group(5).split('_')[-1]

        prev_line = m.group(1)
        prev_line_tokens = prev_line.strip().split(' ')

        next_line = m.group(6)
        next_line_tokens = next_line.strip().split(' ')

        first_prev_token = prev_line_tokens[0]
        first_next_token = next_line_tokens[0]

        mask_value = 'unknown'
        item_type = 'unknown'
        if full_hf_name in items:
            mask_value = items[full_hf_name].mask_value
            item_type = items[full_hf_name].item_type

        # TODO: verify same value of offset for both calls?

        # Make sure item is a known integer type
        if 'FT_UINT' in item_type:
            signed_type = False
        elif 'FT_INT' in item_type:
            signed_type = True
        else:
            continue

        # Need to get a notion of the width
        if item_type in field_widths:
            field_width = int(field_widths[item_type] / 8)
        else:
            field_width = 0

        if field_width != 4:
            continue

        # Use width and signedness to decide which combined function to suggest
        if signed_type:
            suggest = 'proto_tree_add_item_ret_int'
        else:
            suggest = 'proto_tree_add_item_ret_uint'

        if line_has_fetch_function(prev_line) and hf_name.endswith(first_prev_token) and '=' in prev_line_tokens:
            result.warn(filename, 'PREV: val=', first_prev_token, 'hfname=', hf_name,
                        'mask=', mask_value, 'type=', item_type,
                        '- use', suggest + '() ?\n',
                        m.group(0))
        elif line_has_fetch_function(next_line) and hf_name.endswith(first_next_token) and '=' in next_line_tokens:
            result.warn(filename, 'NEXT: val=', first_next_token, 'hfname=', hf_name,
                        'mask=', mask_value, 'type=', item_type,
                        '- use', suggest + '() ?\n',
                        m.group(0))


# Run checks on the given dissector file.
def checkFile(filename, check_mask=False, mask_exact_width=False, check_label=False, check_consecutive=False,
              check_missing_items=False, check_bitmask_fields=False, label_vs_filter=False, extra_value_string_checks=False,
              check_expert_items=False, check_subtrees=False, check_double_fetch=False):

    result = Result()

    # Check file exists - e.g. may have been deleted in a recent commit.
    if not os.path.exists(filename):
        result.note(filename, 'does not exist!')
        return result

    # Get file contents with and without comments, and pass into functions below
    with open(filename, 'r', encoding="utf8") as f:
        contents = f.read()
        # Remove comments so as not to trip up RE.
        contents_no_comments = removeComments(contents)
        lines = contents.splitlines()

    # Find simple macros so can substitute into items and calls.
    macros = find_macros(filename, contents_no_comments)

    # Find (and sanity-check) value_strings
    value_strings = findValueStrings(filename, contents_no_comments, macros, result, do_extra_checks=extra_value_string_checks)
    if extra_value_string_checks:
        for name in value_strings:
            value_strings[name].extraChecks(result)

    # Find (and sanity-check) range_strings
    range_strings = findRangeStrings(filename, contents_no_comments, macros, result, do_extra_checks=extra_value_string_checks)
    if extra_value_string_checks:
        for name in range_strings:
            range_strings[name].extraChecks(result)

    # Find (and sanity-check) string_strings
    string_strings = findStringStrings(filename, contents_no_comments, macros, result, do_extra_checks=extra_value_string_checks)
    if extra_value_string_checks:
        for name in string_strings:
            string_strings[name].extraChecks(result)

    # Find expert items
    if check_expert_items:
        expert_items = findExpertItems(filename, contents_no_comments, macros, result)
        checkExpertCalls(filename, expert_items, result)

    # Find important parts of items.
    items_defined = find_items(filename, contents_no_comments, macros, result, value_strings, range_strings,
                               check_mask, mask_exact_width, check_label, check_consecutive)
    items_extern_declared = {}

    # Check that ett_ variables are registered
    if check_subtrees:
        ett_declared = findDeclaredTrees(filename, contents_no_comments)
        ett_defined = findDefinedTrees(filename, contents_no_comments, ett_declared)
        for d in ett_declared:
            if d not in ett_defined:
                result.warn(filename, 'subtree identifier', d, 'is declared but not found in an array for registering')

    items_declared = {}
    if check_missing_items:
        items_declared = find_item_declarations(filename, lines)
        items_extern_declared = find_item_extern_declarations(filename, lines)

    fields = set()

    # Get 'fields' out of calls
    for c in apiChecks:
        c.find_calls(filename, contents, lines, macros, result)
        for call in c.calls:
            # From _add_bitmask() calls
            if call.fields:
                fields.add(call.fields)

    # Checking for lists of fields for add_bitmask calls
    field_arrays = {}
    if check_bitmask_fields:
        field_arrays = find_field_arrays(filename, contents_no_comments, fields, items_defined, result)

    if check_mask and check_bitmask_fields:
        for i in items_defined:
            item = items_defined[i]
            item.check_full_mask(item.mask, field_arrays)
            item.check_mask_if_in_field_array(item.mask, field_arrays)

    # Now actually check the calls
    for c in apiChecks:
        c.check_against_items(items_defined, items_declared, items_extern_declared, result, check_missing_items, field_arrays)

    if label_vs_filter:
        matches = 0
        for hf in items_defined:
            if items_defined[hf].check_label_vs_filter(reportError=False, reportNumericalMismatch=True):
                matches += 1

        # Only checking if almost every field does match.
        checking = len(items_defined) and matches < len(items_defined) and ((matches / len(items_defined)) > 0.93)
        if checking:
            result.note(filename, ':', matches, 'label-vs-filter matches out of', len(items_defined), 'so reporting mismatches')
            for hf in items_defined:
                items_defined[hf].check_label_vs_filter(reportError=True, reportNumericalMismatch=False)

    if check_double_fetch:
        check_double_fetches(filename, contents_no_comments, items_defined, result)

    for hf in items_defined:
        items_defined[hf].check_boolean_length()
        items_defined[hf].check_string_display()
        items_defined[hf].check_ipv4_display()

    return result


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
parser.add_argument('--mask-exact-width', action='store_true',
                    help='when set, check width of mask against field width')
parser.add_argument('--label', action='store_true',
                    help='when set, check label field too')
parser.add_argument('--consecutive', action='store_true',
                    help='when set, copy copy/paste errors between consecutive items')
parser.add_argument('--missing-items', action='store_true',
                    help='when set, look for used items that were never registered')
parser.add_argument('--check-bitmask-fields', action='store_true',
                    help='when set, attempt to check arrays of hf items passed to add_bitmask() calls')
parser.add_argument('--label-vs-filter', action='store_true',
                    help='when set, check whether label matches last part of filter')
parser.add_argument('--extra-value-string-checks', action='store_true',
                    help='when set, do extra checks on parsed value_strings')
parser.add_argument('--check-expert-items', action='store_true',
                    help='when set, do extra checks on expert items')
parser.add_argument('--check-subtrees', action='store_true',
                    help='when set, do extra checks ett variables')
parser.add_argument('--check-double-fetch', action='store_true',
                    help='when set, attempt to warn for values being double-fetched')

parser.add_argument('--all-checks', action='store_true',
                    help='when set, apply all checks to selected files')


args = parser.parse_args()

# Turn all checks on.
if args.all_checks:
    args.mask = True
    args.mask_exact_width = True
    args.consecutive = True
    args.check_bitmask_fields = True
    args.label = True
    args.label_vs_filter = True
    # args.extra_value_string_checks = True
    args.check_expert_items = True
    # args.check_subtrees = True
    args.check_double_fetch = True

if args.check_bitmask_fields:
    args.mask = True


# Get files from wherever command-line args indicate.
files = []

if args.file:
    # Add specified file(s)
    for f in args.file:
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
    files = getFilesFromCommits(args.commits)
elif args.open:
    # Unstaged changes.
    files = getFilesFromOpen()
else:
    # Find all dissector files.
    files = findDissectorFilesInFolder(os.path.join('epan', 'dissectors'))
    files += findDissectorFilesInFolder(os.path.join('plugins', 'epan'), recursive=True)


# If scanning a subset of files, list them here.
print('Examining:')
if args.file or args.commits or args.open:
    if files:
        print(' '.join(files), '\n')
    else:
        print('No files to check.\n')
else:
    print('All dissector modules\n')


# Now check the chosen files
with concurrent.futures.ProcessPoolExecutor() as executor:
    future_to_file_output = {executor.submit(checkFile, file,
                                             check_mask=args.mask, mask_exact_width=args.mask_exact_width, check_label=args.label,
                                             check_consecutive=args.consecutive, check_missing_items=args.missing_items,
                                             check_bitmask_fields=args.check_bitmask_fields, label_vs_filter=args.label_vs_filter,
                                             extra_value_string_checks=args.extra_value_string_checks,
                                             check_expert_items=args.check_expert_items, check_subtrees=args.check_subtrees,
                                             check_double_fetch=args.check_double_fetch): file for file in files}
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
print(warnings_found, 'warnings')
if errors_found:
    print(errors_found, 'errors')
    exit(1)
