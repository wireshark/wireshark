#!/usr/bin/env python3
"""
USB PTP Dissector
   Extracts PTP response codes from libgphoto2
 This is then hand-merged into packet-usb-ptp.h

 (c)2013 Max Baker <max@warped.org>
 Python port 2026

 SPDX-License-Identifier: GPL-2.0-or-later
"""

import os
import re
import sys
import requests


# URL where the latest version can be found
URL = "https://raw.githubusercontent.com/gphoto/libgphoto2/master/camlibs/ptp2/ptp.h"

# Command line parsing (defaulting to git repo)
file_path = sys.argv[1] if len(sys.argv) > 1 else URL
outfile = 'epan/dissectors/packet-usb-ptp.h'

tables = {
    'PTP_AC': 'StorageInfo Access Capability',
    'PTP_AT': 'Association Types',
    'PTP_DPC': 'Device Properties Codes',
    'PTP_DPFF': 'Device Property Form Flag',
    'PTP_DPGS': 'Device Property GetSet type',
    'PTP_DTC': 'Data Type Codes',
    'PTP_EC': 'Event Codes',
    'PTP_FST': 'FilesystemType Values',
    'PTP_GOH': 'GetObjectHandles',
    'PTP_OC': 'Operation Codes',
    'PTP_OFC': 'Object Format Codes',
    'PTP_OPC': 'MTP Object Properties',
    'PTP_OPFF': 'MTP Device Property Codes',
    'PTP_PS': 'Protection Status',
    'PTP_RC': 'Response Codes',
    'PTP_ST': 'Storage Types',
    'PTP_VENDOR': 'Vendor IDs',
}

manual_entries = {
    'PTP_OC': [
        'USB_PTP_FLAVOR_NIKON     , 0xfc01, "ServiceModeStart"',
        'USB_PTP_FLAVOR_NIKON     , 0xfc02, "ServiceModeStop"',
    ]
}

flavors = {
    'ANDROID': 'USB_PTP_FLAVOR_ANDROID',
    'CANON': 'USB_PTP_FLAVOR_CANON',
    'CANON_EOS': 'USB_PTP_FLAVOR_CANON',
    'CASIO': 'USB_PTP_FLAVOR_CASIO',
    'EK': 'USB_PTP_FLAVOR_KODAK',
    'FUJI': 'USB_PTP_FLAVOR_FUJI',
    'LEICA': 'USB_PTP_FLAVOR_LEICA',
    'MTP': 'USB_PTP_FLAVOR_MTP',
    'NIKON': 'USB_PTP_FLAVOR_NIKON',
    'OLYMPUS': 'USB_PTP_FLAVOR_OLYMPUS',
    'OLYMPUS_OMD': 'USB_PTP_FLAVOR_OLYMPUS',
    'PARROT': 'USB_PTP_FLAVOR_PARROT',
    'PANASONIC': 'USB_PTP_FLAVOR_PANASONIC',
    'SONY': 'USB_PTP_FLAVOR_SONY',
    'SONY_QX': 'USB_PTP_FLAVOR_SONY',
}

# Dictionary to hold the definitions parsed from ptp.h
D = {}

def parse_content(content):
    """Reads the C header file and extracts #define statements."""

    for line in content:
        # Regex matching: #define DEFINE_NAME value
        match = re.match(r'^\s*#define\s+(\S+)\s+(.*)$', line)
        if not match:
            continue

        define, val = match.group(1), match.group(2)

        # Strip C-style multiline (/*...*/) and inline (//...) comments
        val = re.sub(r'/\*.*\*/', '', val)
        val = re.sub(r'//.*', '', val)
        val = val.strip()

        D[define] = val

def parse_header():
    """Determines where to get the C header file and extracts #define statements."""

    if any(file_path.startswith(proto) for proto in ('http:', 'https')):
        r = requests.get(file_path)
        r.raise_for_status()
        parse_content(r.text.splitlines())
    else:
        try:
            with open(file_path) as f:
                parse_content(f.read().splitlines())
        except FileNotFoundError:
            print(f"Can't find gphoto2 header '{file_path}'", file=sys.stderr)
            sys.exit(1)

def sort_key_d(key):
    """
    Emulates the specific Perl sort_D quirk.
    
    If the raw macro value is an unadorned hex (0x...) or decimal, 
    it sorts numerically. If it contains bitwise syntax like '(0x4000 | 0x0009)',
    it defaults to string sorting. Since '(' comes before '0' in ASCII, 
    these jump to the top.
    """
    val = D[key]

    # Handle hex values (0x...)
    if re.match(r'^0x[0-9a-fA-F]+$', val):
        return (True, int(val, 16), key)

    # Handle standard integer values
    if re.match(r'^\d+$', val):
        return (True, int(val), key)

    # String Fallback (e.g., '(0x4000 | 0x0009)' or plain macro text)
    # Using False for index 0 forces text strings to sort BEFORE numbers,
    # because False < True. Then we sort alphabetically by the raw value string.
    return (False, val, key)


def output_unmasked_table(table, desc, out_file):
    """Outputs standard Wireshark value_string tables (e.g., PTP_VENDOR)."""
    table_id = table.lower().replace('ptp_', '', 1)
    out_file.write(f"/* {table} {desc} */\n")
    out_file.write(f"static const value_string usb_ptp_{table_id}_vals[] = {{\n")

    vals = []
    # Filtering and sorting matching keys
    sorted_keys = sorted([k for k in D if k.upper().startswith(f"{table.upper()}_")], key=sort_key_d)

    for define in sorted_keys:
        subdefine = re.sub(f'^{table}_', '', define, flags=re.IGNORECASE)
        value = D[define]
        vals.append(f'    {{{value}, "{subdefine}"}}')

    # Add manual entries if configured
    if table in manual_entries:
        for entry in manual_entries[table]:
            vals.append(f'    {{{entry}}}')

    # Trailing null entry termination
    vals.append("    {0, NULL}")
    out_file.write(",\n".join(vals) + "\n")
    out_file.write("};\n")


def output_table(table, desc, out_file):
    """Outputs masked Wireshark tables mapping vendors/flavors to specific opcodes."""
    is_masked = table != "PTP_VENDOR"

    if not is_masked:
        return output_unmasked_table(table, desc, out_file)

    table_id = table.lower().replace('ptp_', '', 1)
    out_file.write(f"/* {table} {desc} */\n")
    out_file.write(f"static const usb_ptp_value_string_masked_t usb_ptp_{table_id}_mvals[] = {{\n")

    vals = []
    sorted_keys = sorted([k for k in D if k.upper().startswith(f"{table.upper()}_")], key=sort_key_d)

    for define in sorted_keys:
        if re.search(r'_MASK$', define, re.IGNORECASE):
            continue

        subdefine = re.sub(f'^{table}_', '', define, flags=re.IGNORECASE)
        flavor_type = 'USB_PTP_FLAVOR_ALL'

        # Match specific camera flavors (sorting longest keys first prevents partial prefix matches)
        sorted_flavors = sorted(flavors.keys(), key=len, reverse=True)
        for flavor in sorted_flavors:
            # Check if subdefine starts with flavor prefix, strip it if true
            pattern = f'^{flavor}_'
            if re.match(pattern, subdefine, re.IGNORECASE):
                subdefine = re.sub(pattern, '', subdefine, flags=re.IGNORECASE)
                flavor_type = flavors[flavor]
                break

        value = D[define]
        if re.match(r'^0x[0-9a-fA-F]+$|^\d+$', value):
            value = value.lower()
        else:
            # Handle standard nested macro definitions like (A | B)
            bit_match = re.match(r'^\(\s*([A-Z_][A-Z0-9_]*)\s*\|\s*([A-Z_][A-Z0-9_]*)\s*\)$', value, re.IGNORECASE)
            if bit_match:
                value = f"({D.get(bit_match.group(1), bit_match.group(1))} | {D.get(bit_match.group(2), bit_match.group(2))})"
            else:
                print(f"Error: unrecognized value {value} for {subdefine}", file=sys.stderr)
                sys.exit(1)

        vals.append(f'    {{{flavor_type:<25}, {value}, "{subdefine}"}}')

    if table in manual_entries:
        for entry in manual_entries[table]:
            vals.append(f'    {{{entry}}}')

    # Trailing null entry termination
    vals.append(f'    {{{"USB_PTP_FLAVOR_NONE":<25}, 0, NULL}}')
    out_file.write(",\n".join(vals) + "\n")
    out_file.write("};\n")


def main():
    parse_header()

    tmp_outfile = f"{outfile}.tmp"
    in_autogen = False

    try:
        with open(outfile, 'r', encoding='utf-8', errors='replace') as src, \
             open(tmp_outfile, 'w', encoding='utf-8') as out:

            for line in src:
                if "START AUTOGENERATED CODE" in line or "END AUTOGENERATED CODE" in line:
                    out.write(line)
                    if "START" in line:
                        in_autogen = True
                        # Run through sorted tables list and drop content in
                        for table in sorted(tables.keys()):
                            output_table(table, tables[table], out)
                    else:
                        in_autogen = False
                    continue

                if not in_autogen:
                    out.write(line)

        # Atomically swap the temporary output file with original target 
        os.replace(tmp_outfile, outfile)

    except FileNotFoundError:
        print(f"Can't read destination file template '{outfile}'", file=sys.stderr)
        if os.path.exists(tmp_outfile):
            os.remove(tmp_outfile)
        sys.exit(1)


if __name__ == '__main__':
    main()
