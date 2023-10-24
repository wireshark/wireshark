#!/usr/bin/env python3
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
'''Update the IANA IP registry file.

Make-iana-ip creates a file containing information about IPv4/IPv6 allocation blocks.
'''

import csv
import html
import io
import ipaddress
import os
import re
import sys
import ctypes
import urllib.request, urllib.error, urllib.parse

def exit_msg(msg=None, status=1):
    if msg is not None:
        sys.stderr.write(msg + '\n\n')
    sys.stderr.write(__doc__ + '\n')
    sys.exit(status)

def open_url(url):
    '''Open a URL.
    Returns a tuple containing the body and response dict. The body is a
    str in Python 3 and bytes in Python 2 in order to be compatibile with
    csv.reader.
    '''

    if len(sys.argv) > 1:
        url_path = os.path.join(sys.argv[1], url[1])
        url_fd = open(url_path)
        body = url_fd.read()
        url_fd.close()
    else:
        url_path = '/'.join(url)

        req_headers = { 'User-Agent': 'Wireshark iana-ip' }
        try:
            req = urllib.request.Request(url_path, headers=req_headers)
            response = urllib.request.urlopen(req)
            body = response.read().decode('UTF-8', 'replace')
        except Exception:
            exit_msg('Error opening ' + url_path)

    return body

class IPv4SpecialBlock(ipaddress.IPv4Network):
    def __str__(self):
        addr = int(self.network_address)
        mask = self.prefixlen
        line = '{{ {:d}, {:d} }}'.format(addr, mask)
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
        line = '{{ {}, {} }}'.format(self.addr_c_array(addr), mask)
        return line

class IPRegisty(list):
    @staticmethod
    def true_or_false(val):
        if val == 'True':
            return '1'
        elif val == 'False':
            return '0'
        else:
            return '-1'

    def append(self, row):
        ip, name, _, _, termin_date, source, destination, forward, glob, reserved = row
        if termin_date[0].isdigit():
            # skip allocations that have expired
            return
        name = re.sub(r'\[.*\]', '', name)
        name = '"' + name.replace('"', '\\"') + '"'
        source = self.true_or_false(source)
        destination = self.true_or_false(destination)
        forward = self.true_or_false(forward)
        glob = self.true_or_false(glob)
        reserved = self.true_or_false(reserved)
        super().append([ip, name, source, destination, forward, glob, reserved])

class IPv4Registry(IPRegisty):
    @staticmethod
    def ipv4_addr_and_mask(s):
        ip = IPv4SpecialBlock(s)
        return ip

    def append(self, row):
        # some lines contain multiple (comma separated) blocks
        ip_list = row[0].split(',')
        for s in ip_list:
            # remove annotations like "1.1.1.1 [2]"
            ip_str = s.split()[0]
            row = [self.ipv4_addr_and_mask(ip_str)] + row[1:]
            super().append(row)

    def dump(self, fd):
        fd.write('_U_ static const struct ws_ipv4_special_block __ipv4_special_block[] = {\n')
        for row in self:
            line = '    {{ {}, {}, {}, {}, {}, {}, {} }},\n'.format(*row)
            fd.write(line)
        fd.write('};\n')

class IPv6Registry(IPRegisty):
    @staticmethod
    def ipv6_addr_and_mask(s):
        ip_str = s.split()[0]
        ip = IPv6SpecialBlock(ip_str)
        return ip

    def append(self, row):
        # remove annotations like "1.1.1.1 [2]"
        ip_str = row[0].split()[0]
        row = [self.ipv6_addr_and_mask(ip_str)] + row[1:]
        super().append(row)

    def dump(self, fd):
        fd.write('// GCC bug?\n')
        fd.write('DIAG_OFF(missing-braces)\n')
        fd.write('_U_ static const struct ws_ipv6_special_block __ipv6_special_block[] = {\n')
        for row in self:
            line = \
'''    {{ {},
            {}, {}, {}, {}, {}, {} }},\n'''.format(*row)
            fd.write(line)
        fd.write('};\n')
        fd.write('DIAG_ON(missing-braces)\n')

IANA_URLS = {
    'IPv4':   { 'url': ["https://www.iana.org/assignments/iana-ipv4-special-registry/", "iana-ipv4-special-registry-1.csv"], 'min_entries': 2 },
    'IPv6':   { 'url': ["https://www.iana.org/assignments/iana-ipv6-special-registry/", "iana-ipv6-special-registry-1.csv"], 'min_entries': 2 },
}

def dump_registry(db, fd, reg):
    db_url = IANA_URLS[db]['url']
    print('Loading {} data from {}'.format(db, db_url))
    body = open_url(db_url)
    iana_csv = csv.reader(body.splitlines())

    # Pop the title row.
    next(iana_csv)
    for iana_row in iana_csv:
        # Address Block,Name,RFC,Allocation Date,Termination Date,Source,Destination,Forwardable,Globally Reachable,Reserved-by-Protocol
        # ::1/128,Loopback Address,[RFC4291],2006-02,N/A,False,False,False,False,True
        reg.append(iana_row)

    if len(reg) < IANA_URLS[db]['min_entries']:
        exit_msg("Too few {} entries. Got {}, wanted {}".format(db, len(reg), IANA_URLS[db]['min_entries']))

    reg.dump(fd)

def main():
    this_dir = os.path.dirname(__file__)
    iana_path = os.path.join('epan', 'iana-ip-data.c')

    try:
        fd = io.open(iana_path, 'w', encoding='UTF-8')
    except Exception:
        exit_msg("Couldn't open \"{}\" file for reading".format(iana_path))

    fd.write('''/*
 * This file was generated by running ./tools/make-iana-ip.py.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "iana-ip.h"

''')

    dump_registry('IPv4', fd, IPv4Registry())
    fd.write('\n')
    dump_registry('IPv6', fd, IPv6Registry())
    fd.close()

if __name__ == '__main__':
    main()
