#!/usr/bin/env python3
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
'''Update the IANA Address family numbers and IP protocol numbers file.

Make-iana-constants creates a file containing Address family numbers.
'''

import io
import os
import sys
import urllib.request
import urllib.error
import urllib.parse
import xml.etree.ElementTree as ET

def exit_msg(msg=None, status=1):
    if msg is not None:
        sys.stderr.write(msg + '\n\n')
    sys.stderr.write(__doc__ + '\n')
    sys.exit(status)

class AddressFamilyNumber:
    def __init__(self, value, description):
        self.value = value
        self.description = description.replace('"', '\'')
        self.define = self.make_define(description)

    def make_define(self, text):
        name = text
        remove_data_index = name.find('(')
        if remove_data_index != -1:
            name = name[:remove_data_index]

        name = name.strip()
        name = name.upper()
        name = name.replace('-', ' ')
        name = name.replace('/', ' ')
        name = name.replace('.', '')
        name = ''.join(c if c.isalnum() else ' ' for c in name)
        name = '_'.join(name.split())

        #Special handling for RESERVED because it appears multiple times
        if name == 'RESERVED':
            name = 'RESERVED_' + self.value
        return f"AFNUM_{name}"

class IPProtocolNumber:
    def __init__(self, value, name, description):
        self.value = value
        self.name = name
        self.description = description.replace('\n', '')
        self.define = self.make_define(name)
    def make_define(self, text):
        name = text
        name = name.strip()
        name = name.upper()
        name = name.replace('-', ' ')
        name = name.replace('/', ' ')
        name = name.replace('.', '')
        name = ''.join(c if c.isalnum() else ' ' for c in name)
        name = '_'.join(name.split())
        return f"IP_PROTO_{name}"

afnum_url = "https://www.iana.org/assignments/address-family-numbers/address-family-numbers.xml"
afnum_ns = "http://www.iana.org/assignments"
ipproto_url = "http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xml"

def get_afnum_data():
    print('Loading Address Family Numbers data from {}'.format(afnum_url))

    try:
        req = urllib.request.Request(afnum_url)
        response = urllib.request.urlopen(req)
        body = response.read().decode('UTF-8', 'replace')
    except Exception:
        exit_msg('Error opening ' + afnum_url)


    tree = ET.fromstring(body)
    registry = tree.find(f"{{{afnum_ns}}}registry")

    #Convert XML records to list of AddressFamilyNumber
    records = []
    for record in registry.findall(f"{{{afnum_ns}}}record"):
        value = record.find(f"{{{afnum_ns}}}value").text
        description = record.find(f"{{{afnum_ns}}}description").text
        records.append(AddressFamilyNumber(value, description))

    return records

def generate_afnum_header_data(file, afnum_data):
    iana_h_data = '''\
/*
 * Address family numbers, from
 *
 *  http://www.iana.org/assignments/address-family-numbers
 */
'''

    iana_h_tail = '''\

WS_DLL_PUBLIC const value_string afn_vals[];

'''

    file.write(iana_h_data)
    for record in afnum_data:
        if record.value.find('-') != -1:
            #Skip ranges
            continue

        define = record.define.ljust(50)
        value = record.value.ljust(10)
        file.write(f"#define {define}{value}/* {record.description} */\n")
    file.write(iana_h_tail)

def generate_afnum_source_data(file, afnum_data):

    iana_c_data = '''\
const value_string afn_vals[] = {
'''

    iana_c_tail = '''\
\t{ 0, NULL },
};
'''
    file.write(iana_c_data)
    for record in afnum_data:
        if record.value.find('-') != -1:
            #Skip ranges
            continue

        predefine = record.define + ','
        define = predefine.ljust(50)
        file.write(f"\t{{ {define}\"{record.description}\"}},\n")
    file.write(iana_c_tail)


def get_ipproto_data():
    print('Loading IP Protocol Numbers data from {}'.format(ipproto_url))
        
    try:
            req = urllib.request.Request(ipproto_url)
            response = urllib.request.urlopen(req)
            body = response.read().decode('UTF-8', 'replace')
    except Exception:
            exit_msg('Error opening ' + ipproto_url)
        
        
    tree = ET.fromstring(body)
    registry = tree.find(f"{{{afnum_ns}}}registry")

    #Convert XML records to list of IPProtocolNumber
    records = []
    for record in registry.findall(f"{{{afnum_ns}}}record"):
            value = record.find(f"{{{afnum_ns}}}value").text

            name = record.find(f"{{{afnum_ns}}}name")
            raw_description = record.find(f"{{{afnum_ns}}}description")
            if name is not None:
                if raw_description is not None:
                    description = raw_description.text
                else:
                    description = ""

                records.append(IPProtocolNumber(value, name.text, description))
            else:
                if raw_description is not None and raw_description.text == "Unassigned":
                    records.append(IPProtocolNumber(value, raw_description.text, raw_description.text))
        
    return records

def generate_ipproto_header_data(file, ipproto_data):
    iana_h_data = '''\
/*
 * IP protocol numbers.
 * http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xml
 */
'''

    iana_h_tail = '''\

WS_DLL_PUBLIC value_string_ext ipproto_val_ext;
'''

    file.write(iana_h_data)
    for record in ipproto_data:
        if record.value.find('-') != -1:
            #Skip ranges
            continue

        define = record.define.ljust(50)
        if record.description != "":
            value = record.value.ljust(10)
            comment = f"/* {record.description} */"
        else:
            value = record.value
            comment = record.description
        file.write(f"#define {define}{value}{comment}\n")
    file.write(iana_h_tail)

def generate_ipproto_source_data(file, ipproto_data):
    iana_h_data = '''\


static const value_string ipproto_val[] = {
'''

    iana_c_tail = '''\
\t{ 0, NULL },
};

value_string_ext ipproto_val_ext = VALUE_STRING_EXT_INIT(ipproto_val);
'''

    file.write(iana_h_data)
    for record in ipproto_data:

        if record.value.find('-') != -1:
            #Range handling
            start_str, end_str = record.value.split('-')
            start = int(start_str)
            end = int(end_str)
            for i in range(start, end + 1):
                define = f"{i},".ljust(35)
                name = f"\"{record.name}\" }},".ljust(20)
                file.write(f"\t{{ {define}{name} /* {i} {record.description} */\n")
        else:
            define = f"{record.define},".ljust(35)
            name = f"\"{record.name}\" }},".ljust(20)
            file.write(f"\t{{ {define}{name} /* {record.value} {record.description} */\n")

    file.write(iana_c_tail)

iana_header_data = '''\
/*
 * This file was generated by running ./tools/make-iana-constants.py.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef __PACKET_IANA_DATA_H__
#define __PACKET_IANA_DATA_H__

#include "ws_symbol_export.h"
#include <wsutil/value_string.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

'''

iana_header_tail = '''\
#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __PACKET_IANA_DATA_H__ */
'''

iana_source_data = '''\
/*
 * This file was generated by running ./tools/make-iana-constants.py.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "config.h"

#include "packet-iana-data.h"

'''

def main():

    iana_h_path = os.path.join(os.path.dirname(__file__), '..', 'epan', 'dissectors', 'packet-iana-data.h')
    iana_c_path = os.path.join(os.path.dirname(__file__), '..', 'epan', 'dissectors', 'packet-iana-data.c')

    print(f"Generating {iana_h_path} and {iana_c_path}")

    afnum_data = get_afnum_data()
    ipproto_data = get_ipproto_data()
    if afnum_data is not None and ipproto_data is not None:
        try:
            with io.open(iana_h_path, 'w', encoding='UTF-8') as iana_f:
                iana_f.write(iana_header_data)
                generate_afnum_header_data(iana_f, afnum_data)
                generate_ipproto_header_data(iana_f, ipproto_data)
                iana_f.write(iana_header_tail)

        except Exception:
            exit_msg("Couldn't open \"{}\" file for writing".format(iana_h_path))

        try:
            with io.open(iana_c_path, 'w', encoding='UTF-8') as iana_f:
                iana_f.write(iana_source_data)
                generate_afnum_source_data(iana_f, afnum_data)
                generate_ipproto_source_data(iana_f, ipproto_data)
        except Exception:
            exit_msg("Couldn't open \"{}\" file for writing".format(iana_c_path))


if __name__ == '__main__':
    main()
