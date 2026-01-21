#!/usr/bin/env python3
#
# Generate epan/dissectors/packet-midi-sysex-id.c and
# epan/dissectors/packet-midi-sysex-id.h using data fetched from
# https://midi.org/SysExIDtable .
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

from html.parser import HTMLParser
import os
import re
import string
import sys
import unicodedata
import urllib.request

class HTMLTableExtractor(HTMLParser):
    """Parse the contents of HTML tables found in the given content, and
       produce a corresponding data structure carrying the cell contents."""
    def __init__(self):
        super().__init__()
        self.row = None
        self.cell = None
        self.table = None
        self.tables = []

    def handle_starttag(self, tag, attrs):
        if tag == 'table':
            if self.table is not None:
                raise ValueError('New table started with prior table unclosed.')
            self.table = []
        elif tag == 'tr':
            if self.row is not None:
                raise ValueError('New row started with prior row unclosed.')
            self.row = []
        elif tag == 'td':
            if self.cell is not None:
                raise ValueError('New cell started with prior cell unclosed.')
            self.cell = ''

    def handle_endtag(self, tag):
        if tag == 'table':
            if self.table is None:
                raise ValueError('Closed a nonexistent table.')
            self.tables.append(self.table)
            self.table = None
        elif tag == 'tr':
            if self.row is None:
                raise ValueError('Closed a nonexistent row.')
            self.table.append(self.row)
            self.row = None
        elif tag == 'td':
            if self.cell is None:
                raise ValueError('Closed a nonexistent cell.')
            self.row.append(self.cell)
            self.cell = None

    def handle_data(self, data):
        if self.cell is not None:
            self.cell = self.cell + data

# A SysEx ID, in hexadecimal, is a sequence of one or more bytes valued 0x00-0x7F.
hexid_pattern = re.compile(r'[0-7][0-9A-F]H( [0-7][0-9A-F]H)*', re.IGNORECASE)

def extract_id(st):
    if not hexid_pattern.fullmatch(st):
        return None

    return ''.join(filter(lambda c: c in string.hexdigits, st.upper()))

macro_name_re = re.compile(r'[A-Z_][A-Z_0-9]*')
macro_multiple_underscores_filter_re = re.compile('[_ ]+') # (r'[^A-Z0-9]+')
all_macros = set()
duplicate_macros = set()

def make_C_string_char(c):
    """Filter a character from a SysEx ID name into something suitable for inclusion in a C string."""
    if c in ['\\', '"']:
        return '\\' + c
    if ord(c) >= 32 and ord(c) < 127:
        return c
    return f'\\u{ord(c):04X}'

def make_macro_name_char(c):
    """Filter a character from a SysEx ID name into something suitable for a C macro name."""
    if c in string.ascii_uppercase:
        return c
    if c in string.digits:
        return c
    if c in [' ', '_']:
        return c
    if ord(c) in [0x2018, 0x2019]:
        return ''
    # Try to map it to an ASCII character, brutally if necessary.  Strip combining characters.
    dc = unicodedata.decomposition(c)
    if len(dc) < 1:
        return '_' # Doesn't seem possible to represent it with any ASCII character.
    dc0 = dc.split()[0]
    uc = chr(int(dc0, base=16))
    return uc if uc in string.ascii_uppercase or uc in string.digits else '_'

def postprocess_name(st):
    """Generate two strings from the SysEx ID name: The name for a C macro
    (all uppercase ASCII characters or digits or underscores) and the C string
    of the text (with suitable escaping)."""
    text = st.strip()
    text_C_string = ''.join(map(make_C_string_char, text))
    macro = ''.join(map(make_macro_name_char, text.upper())).strip('_')
    # A macro name mustn't start with a digit, but the common prefix means we don't need to fix that up here.
    macro = 'MIDI_SYSEX_ID_' + macro
    macro = macro_multiple_underscores_filter_re.sub('_', macro)
    return {
        'text': text_C_string,
        'macro': macro
    }

def record_macro_name(macro):
    """Duplicate names need special treatment.  Keep track of which macro names
    are duplicated."""
    if macro in all_macros:
        duplicate_macros.add(macro)
    else:
        all_macros.add(macro)

def format_defines(data, value_length):
    """Produce the text of a "#define" for the SysEx ID."""
    max_len = max(len(v["macro"]) for v in data.values())
    return [f'#define {v["macro"]:{max_len}} 0x{k:0{value_length}X}' for k, v in data.items()]

def format_table(name, data):
    """Produce the text for a SysEx ID's row in a value_string table."""
    max_len = max(len(v["macro"]) for v in data.values())
    return [f'static const value_string {name}_vals[] = {{'] + \
           [f'    {{{v["macro"]+",":{max_len+1}} "{v["text"]}"}},' for k,v in data.items()] + \
           [f'    {{{"0,":{max_len+1}} NULL}}'] + \
           ['};'] + \
           [f'value_string_ext {name}_vals_ext = VALUE_STRING_EXT_INIT({name}_vals);']

req_headers = { 'User-Agent': 'Wireshark make-midi-sysex' }
req = urllib.request.Request('https://midi.org/SysExIDtable', headers=req_headers)
response = urllib.request.urlopen(req)
data = response.read().decode('UTF-8', 'replace')

t = HTMLTableExtractor()
t.feed(data)
t.close()

sysex_id = {}
sysex_extended_id = {}

for table in t.tables:
    # Don't try to track which entries belong in which tables; When we have a
    # row with a hex ID, count the number of bytes and store it accordingly.
    prev_hexid = None
    for row in table:
        if len(row) != 2:
            continue
        hexid, sysex_id_name = row
        hexid = extract_id(hexid)
        if hexid:
            # Patch up a mistake in the source table as of 2025-10-31:
            if hexid == '004800' and prev_hexid == '004803':
                hexid = '004804'

            hexid_val = int(hexid, base=16)
            if len(hexid) == 2:
                if hexid == '00':
                    # This is in the source table, but is only used only to indicate another two bytes of ID follow.
                    sysex_id_name = 'Indicator for extended MIDI SysEx ID'
                elif hexid in ['7D', '7E', '7F']:
                    # These should not be in the table.  Special IDs.  We manually add them below.
                    raise ValueError(f'hexid "{hexid}" should not appear in the table.')
                sysex_id_name = postprocess_name(sysex_id_name)
                if hexid_val in sysex_id:
                    # Allow duplicated identical records.
                    if sysex_id_name != sysex_id[hexid_val]:
                        raise ValueError(f'Non-identical duplicate entries found for "{hexid}".')
                else:
                    record_macro_name(sysex_id_name['macro'])
                    sysex_id[hexid_val] = sysex_id_name
            elif len(hexid) == 6:
                if hexid[:2] != '00':
                    raise ValueError(f'hexid "{hexid}" is an extended ID but does not start with 00')

                sysex_id_name = postprocess_name(sysex_id_name)
                if hexid_val in sysex_extended_id:
                    # Allow duplicated identical records.
                    if sysex_id_name != sysex_extended_id[hexid_val]:
                        raise ValueError(f'Non-identical duplicate entries found for "{hexid}": '
                                f'"{sysex_id_name["text"]}" and "{sysex_extended_id[hexid_val]["text"]}".')
                else:
                    record_macro_name(sysex_id_name['macro'])
                sysex_extended_id[hexid_val] = sysex_id_name
            else:
                raise ValueError(f'hexid "{hexid}" seems invalid.')
            prev_hexid = hexid

# Special SysEx IDs defined in the MIDI 1.0 specification.
for k, v in (
    (0x7D, "Educational/Non-Commercial Use"),
    (0x7E, "Non-Real Time Universal System Exclusive"),
    (0x7F, "Real Time Universal System Exclusive"),
):
    sysex_id_name = postprocess_name(v)
    record_macro_name(sysex_id_name['macro']) # Really shouldn't be duplicates here, but be paranoid...
    sysex_id[k] = sysex_id_name

# Function record_macro_name keeps track of which macro names are unique and
# which would be duplicates.  When a macro name is not unique, force uniqueness
# by suffixing each instance with the bytes of the ID.
for k, v in sysex_id.items():
    if v["macro"] in duplicate_macros:
        v["macro"] = f'{v["macro"]}_{k:02X}'
for k, v in sysex_extended_id.items():
    if v["macro"] in duplicate_macros:
        v["macro"] = f'{v["macro"]}_{k:06X}'

def file_header(filename):
    return f"""/*
 * {os.path.basename(filename)}
 *
 * This file was generated by running {sys.argv[0]} .
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
"""

header_filename = 'epan/dissectors/data-midi-sysex-id.h'
with open(header_filename, 'w+') as f:
    guard = '__PACKET_MIDI_SYSEX_ID_H__'
    print(file_header(header_filename), file=f)
    print(f'#ifndef {guard}', file=f)
    print(f'#define {guard}', file=f)
    print('\n/* One-byte MIDI SysEx identifiers. */', file=f)
    print('\n'.join(format_defines(sysex_id, 2)), file=f)
    print('\n/* Three-byte (extended) MIDI SysEx identifiers. */', file=f)
    print('\n'.join(format_defines(sysex_extended_id, 6)), file=f)
    print('\nextern value_string_ext midi_sysex_id_vals_ext;', file=f)
    print('extern value_string_ext midi_sysex_extended_id_vals_ext;', file=f)
    print(f'\n#endif /* {guard} */', file=f)

table_filename = 'epan/dissectors/data-midi-sysex-id.c'
with open(table_filename, 'w+') as f:
    print(file_header(table_filename), file=f)
    print('#include <wsutil/value_string.h>', file=f)
    print(f'#include <{os.path.basename(header_filename)}>', file=f)
    print(file=f)
    print('/* One-byte MIDI SysEx Identifiers. */', file=f)
    print('\n'.join(format_table('midi_sysex_id', sysex_id)), file=f)
    print('\n/* Three-byte (extended) MIDI SysEx Identifiers. */', file=f)
    print('\n'.join(format_table('midi_sysex_extended_id', sysex_extended_id)), file=f)
