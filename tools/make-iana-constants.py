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
import ipaddress
import re
from enum import Enum
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

class IPv4SpecialBlock(ipaddress.IPv4Network):
    @staticmethod
    def ip_get_subnet_mask(bits):
        masks = (
            0x00000000,
            0x80000000, 0xc0000000, 0xe0000000, 0xf0000000,
            0xf8000000, 0xfc000000, 0xfe000000, 0xff000000,
            0xff800000, 0xffc00000, 0xffe00000, 0xfff00000,
            0xfff80000, 0xfffc0000, 0xfffe0000, 0xffff0000,
            0xffff8000, 0xffffc000, 0xffffe000, 0xfffff000,
            0xfffff800, 0xfffffc00, 0xfffffe00, 0xffffff00,
            0xffffff80, 0xffffffc0, 0xffffffe0, 0xfffffff0,
            0xfffffff8, 0xfffffffc, 0xfffffffe, 0xffffffff)
        if bits > 32:
            ValueError("Expected bit mask less or equal to 32")
        return masks[bits]

    def __str__(self):
        addr = self.network_address
        mask = self.prefixlen
        line = '{{ .ipv4 = {{ {:#x}, {:#010x} }} }}'.format(addr, self.ip_get_subnet_mask(mask))
        return line

class IPv6SpecialBlock(ipaddress.IPv6Network):
    @staticmethod
    def addr_c_array(byte_array):
        if len(byte_array) != 16:
            raise ValueError("Expected byte array of length 16")
        c_array = ", ".join(f"0x{byte:02x}" for byte in byte_array)
        return f"{{ {c_array} }}"

    def __str__(self):
        addr = self.network_address.packed
        mask = self.prefixlen
        line = '{{ .ipv6 = {{ {{ {} }}, {} }} }}'.format(self.addr_c_array(addr), mask)
        return line

class IPRegistry(list):
    def append(self, record, ip_processor):
        termin_date = record.find(f"{{{iana_ns}}}termination")
        if termin_date is not None:
            # skip allocations that have expired
            return

        address = record.find(f"{{{iana_ns}}}address").text
        name = record.find(f"{{{iana_ns}}}name").text
        if name[0] != '"':
            name = f'"{name}"'
        source = record.find(f"{{{iana_ns}}}source").text.strip().lower()
        destination = record.find(f"{{{iana_ns}}}destination").text.strip().lower()
        forward = record.find(f"{{{iana_ns}}}forwardable").text.strip().lower()
        glob = record.find(f"{{{iana_ns}}}global").text.strip().lower()
        if glob == 'n/a':
            glob = 'false'
        reserved = record.find(f"{{{iana_ns}}}reserved").text.strip().lower()
        ip_list = address.split(',')
        for ip in ip_list:
            super().append([ip_processor(ip.strip()), name, source, destination, forward, glob, reserved])

class IPv4Registry(IPRegistry):
    @staticmethod
    def ipv4_addr_and_mask(s):
        ip = IPv4SpecialBlock(s)
        return ip

    def append(self, record):
        super().append(record, self.ipv4_addr_and_mask)

    def fill(self):
        self.sort()
        fill_data = 'static const struct ws_iana_ip_special_block __ipv4_special_block[] = {\n'
        for row in self:
            line = '\t{{ 4, {}, {}, {}, {}, {}, {}, {} }},\n'.format(*row)
            fill_data += line
        fill_data += '};\n'
        return fill_data

class IPv6Registry(IPRegistry):
    @staticmethod
    def ipv6_addr_and_mask(s):
        ip_str = s.split()[0]
        ip = IPv6SpecialBlock(ip_str)
        return ip

    def append(self, record):
        super().append(record, self.ipv6_addr_and_mask)

    def fill(self):
        self.sort()
        fill_data = 'static const struct ws_iana_ip_special_block __ipv6_special_block[] = {\n'
        for row in self:
            line = \
'''\t{{ 6, {},
\t\t{}, {}, {}, {}, {}, {} }},\n'''.format(*row)
            fill_data += line
        fill_data += '};\n'
        return fill_data

class EnterpriseOrganization:
    def __init__(self, number, organization):
        self.number = number
        self.organization = organization.replace("\\", "\\\\").replace('"', '').strip()

class ServicePortName:
    def __init__(self, name, description, port):
        self.name = name
        if description is None:
            self.description = ""
        else:
            self.description = description.replace('\n', '').replace('"', '\\"')

        if self.name == self.description:
            self.description = ""
        self.port = port

afnum_url = "https://www.iana.org/assignments/address-family-numbers/address-family-numbers.xml"
iana_ns = "http://www.iana.org/assignments"
ipproto_url = "http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xml"
ipv4reg_url = "https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xml"
ipv6reg_url = "https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xml"
enterprise_numbers_url = "https://www.iana.org/assignments/enterprise-numbers/enterprise-numbers"
service_names_port_numbers_url = "https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xml"


def get_afnum_data():
    print('Loading Address Family Numbers data from {}'.format(afnum_url))

    try:
        req = urllib.request.Request(afnum_url)
        response = urllib.request.urlopen(req)
        body = response.read().decode('UTF-8', 'replace')
    except Exception:
        exit_msg('Error opening ' + afnum_url)


    tree = ET.fromstring(body)
    registry = tree.find(f"{{{iana_ns}}}registry")

    #Convert XML records to list of AddressFamilyNumber
    records = []
    for record in registry.findall(f"{{{iana_ns}}}record"):
        value = record.find(f"{{{iana_ns}}}value").text
        description = record.find(f"{{{iana_ns}}}description").text
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
    registry = tree.find(f"{{{iana_ns}}}registry")

    #Convert XML records to list of IPProtocolNumber
    records = []
    for record in registry.findall(f"{{{iana_ns}}}record"):
            value = record.find(f"{{{iana_ns}}}value").text

            name = record.find(f"{{{iana_ns}}}name")
            raw_description = record.find(f"{{{iana_ns}}}description")
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

def get_ip_special_data(name, url, reg, min_entries):
    print('Loading {} special data from {}'.format(name, url))

    try:
        req = urllib.request.Request(url)
        response = urllib.request.urlopen(req)
        body = response.read().decode('UTF-8', 'replace')
    except Exception:
        exit_msg('Error opening ' + url)


    tree = ET.fromstring(body)
    registry = tree.find(f"{{{iana_ns}}}registry")

    #Convert XML records to list of IP registry entries
    for record in registry.findall(f"{{{iana_ns}}}record"):
         reg.append(record)

    if len(reg) < min_entries:
        exit_msg("Too few {} entries. Got {}, wanted {}".format(name, len(reg), min_entries))

    return reg.fill()

def get_enterprise_entries():
    print('Loading Enterprise data from {}'.format(enterprise_numbers_url))

    with urllib.request.urlopen(enterprise_numbers_url) as f:
        if f.status != 200:
            raise Exception("request for " + enterprise_numbers_url + " failed with result code " + f.status)
        data = f.read().decode('utf-8').replace(u'\u200e', '')

    records = []
    # We only care about the "Decimal" and "Organization",
    # not the contact or email
    DECIMAL_PATTERN = r"^(\d+)"
    # up to three spaces because of formatting errors in the source
    ORGANIZATION_PATTERN = r"^   ?(\S.*)"
    FORMERLY_PATTERN = r" \(((formerly|previously) .*)\)"

    last_updated = ""
    end_seen = False
    for line in data.splitlines():
        decimal_match = re.match(DECIMAL_PATTERN, line)
        if decimal_match:
            decimal = decimal_match.group(0)
        elif re.match(ORGANIZATION_PATTERN, line):
            organization = line.strip()
            if organization.lower() == "unassigned":
                continue
            organization = re.sub(FORMERLY_PATTERN, '', organization)
            records.append(EnterpriseOrganization(decimal, organization))
        elif "last updated" in line.lower():
            last_updated = line
        elif "end of document" in line.lower():
            end_seen = True

    if not end_seen:
        raise Exception('"End of Document" not found. Truncated source file?')

    return (records, last_updated)

def generate_enterprise_header_data(file):
    iana_enterprise_data = '''\
/*
 * Enterprise numbers, from
 * {}
 */
WS_DLL_PUBLIC value_string_ext enterprise_val_ext;
'''
    file.write(iana_enterprise_data.format(enterprise_numbers_url))

def generate_enterprise_source_data(file, enterprise_data, last_updated):

    prefix_data = '''\


static const value_string enterprise_val[] = {
'''

    suffix_data = '''\
\t{ 0, NULL }
};

value_string_ext enterprise_val_ext = VALUE_STRING_EXT_INIT(enterprise_val);


'''

    file.write(f"/* {last_updated} */\n")
    file.write(prefix_data)

    for record in enterprise_data:
        define = f"{record.number},".ljust(10)
        name = f"\"{record.organization}\" }},"
        file.write(f"\t{{ {define}{name}\n")

    file.write(suffix_data)

def get_service_data():

    print('Loading service port/name data from {}'.format(service_names_port_numbers_url))
        
    try:
            req = urllib.request.Request(service_names_port_numbers_url)
            response = urllib.request.urlopen(req)
            body = response.read().decode('UTF-8', 'replace')
    except Exception:
            exit_msg('Error opening ' + service_names_port_numbers_url)

    ns = {'iana': iana_ns}        

    tree = ET.fromstring(body)

    tcp_udp_table = {}
    tcp_table = []
    udp_table = []
    sctp_table = []
    dccp_table = []

    for record in tree.findall('iana:record', ns):
        raw_protocol = record.find('iana:protocol', ns)
        if raw_protocol is None:
            continue
        protocol = raw_protocol.text.lower()
        raw_name = record.find('iana:name', ns)
        if raw_name is None:
            continue

        name = raw_name.text
        description = record.find('iana:description', ns)
        port = record.find('iana:number', ns)
        if port is None:
            continue

        if protocol == "tcp":
            tcp_udp_table[port.text] = ServicePortName(name, description.text, port.text)
            tcp_table.append(ServicePortName(name, description.text, port.text))
        elif protocol == "udp":
            tcp_udp_table[port.text] = ServicePortName(name, description.text, port.text)
            udp_table.append(ServicePortName(name, description.text, port.text))
        elif protocol == "sctp":
            sctp_table.append(ServicePortName(name, description.text, port.text))
        elif protocol == "dccp":
            dccp_table.append(ServicePortName(name, description.text, port.text))

    return (tcp_udp_table, tcp_table, udp_table, sctp_table, dccp_table)

def generate_service_source_data(file, data):
    tcp_udp_table = data[0]
    tcp_table = data[1]
    udp_table = data[2]
    sctp_table = data[3]
    dccp_table = data[4]
    max_port = 0

    def write_entry(f, e, max_port):
        if e.port.find('-') != -1:
            #Range handling
            start_str, end_str = e.port.split('-')
            start = int(start_str)
            end = int(end_str)
            for i in range(start, end + 1):
                port = f"{i},".ljust(7)
                name = f"\"{e.name}\",".ljust(24)
                description = f"\"{e.description}\""
                file.write(f"\t{{ {port}{name}{description}}},\n")
            if end > int(max_port):
                max_port = end
        else:
            port = f"{e.port},".ljust(10)
            name = f"\"{e.name}\",".ljust(20)
            description = f"\"{e.description}\""
            file.write(f"\t{{ {port}{name}{description}}},\n")

            if int(e.port) > int(max_port):
                max_port = e.port

        return max_port

    try:
        file.write("static const ws_services_entry_t global_tcp_udp_services_table[] = {\n")
        for e in tcp_udp_table:
            max_port = write_entry(file, tcp_udp_table[e], max_port)
        file.write("};\n\n")

        file.write("static const ws_services_entry_t global_tcp_services_table[] = {\n")
        for e in tcp_table:
            max_port = write_entry(file, e, max_port)
        file.write("};\n\n")

        file.write("static const ws_services_entry_t global_udp_services_table[] = {\n")
        for e in udp_table:
            max_port = write_entry(file, e, max_port)
        file.write("};\n\n")

        file.write("static const ws_services_entry_t global_sctp_services_table[] = {\n")
        for e in sctp_table:
            max_port = write_entry(file, e, max_port)
        file.write("};\n\n")

        file.write("static const ws_services_entry_t global_dccp_services_table[] = {\n")
        for e in dccp_table:
            max_port = write_entry(file, e, max_port)
        file.write("};\n\n")

        file.write("static const uint16_t _services_max_port = {};\n".format(max_port))
    except Exception as e:
        print(e)

class SourceStage(Enum):
    BEGIN = 1
    IN_GENERATED_BLOCK = 2
    END = 3

def parse_source(source_path):
    """
    Reads the source file and tries to split it in the parts before, inside and
    after the block.
    """
    begin, block, end = '', '', ''
    # Stages: BEGIN (before block), IN_GENERATED_BLOCK (skip), END
    stage = SourceStage.BEGIN
    with open(source_path, 'r', encoding='UTF-8') as f:
        for line in f:
            if line.startswith('/* <BEGIN GENERATED SOURCE> '):
                begin += line
                stage = SourceStage.IN_GENERATED_BLOCK
                continue

            if stage == SourceStage.BEGIN:
                begin += line
            elif stage == SourceStage.IN_GENERATED_BLOCK:
                block += line
                if line.startswith('/* <END GENERATED SOURCE>'):
                    end += line
                    stage = SourceStage.END
            elif stage == SourceStage.END:
                end += line

    if stage != SourceStage.END:
        raise RuntimeError("Could not parse file (in stage %s)" % stage.name)
    return begin, block, end

def main():

    iana_h_path = os.path.join(os.path.dirname(__file__), '..', 'epan', 'iana-info.h')
    iana_c_path = os.path.join(os.path.dirname(__file__), '..', 'epan', 'iana-info.c')

    print(f"Updating {iana_h_path} and {iana_c_path}")

    afnum_data = get_afnum_data()
    ipproto_data = get_ipproto_data()
    ipv4_special_data = get_ip_special_data("IPv4", ipv4reg_url, IPv4Registry(), 2)
    ipv6_special_data = get_ip_special_data("IPv6", ipv6reg_url, IPv6Registry(), 2)
    enterprise_data,enterprise_last_updated = get_enterprise_entries()
    service_data = get_service_data()
    if afnum_data is not None and \
       ipproto_data is not None and \
       ipv4_special_data is not None and \
       ipv6_special_data is not None and \
       enterprise_data is not None and \
       service_data is not None:

        #Pull out the existing header file parts
        start, block, end = parse_source(iana_h_path)
        try:
            with io.open(iana_h_path, 'w', encoding='UTF-8') as iana_f:
                iana_f.write(start)
                generate_afnum_header_data(iana_f, afnum_data)
                generate_ipproto_header_data(iana_f, ipproto_data)
                generate_enterprise_header_data(iana_f)
                iana_f.write(end)

        except Exception:
            exit_msg("Couldn't open \"{}\" file for writing".format(iana_h_path))

        #Pull out the existing source file parts
        start, block, end = parse_source(iana_c_path)
        try:
            with io.open(iana_c_path, 'w', encoding='UTF-8') as iana_f:
                iana_f.write(start)
                generate_afnum_source_data(iana_f, afnum_data)
                generate_ipproto_source_data(iana_f, ipproto_data)
                iana_f.write("\n\n")
                iana_f.write(ipv4_special_data)
                iana_f.write("\n\n")
                iana_f.write(ipv6_special_data)
                iana_f.write("\n\n")
                generate_enterprise_source_data(iana_f, enterprise_data, enterprise_last_updated)
                generate_service_source_data(iana_f, service_data)
                iana_f.write(end)
        except Exception:
            exit_msg("Couldn't open \"{}\" file for writing".format(iana_c_path))


if __name__ == '__main__':
    main()
