#!/usr/bin/env python3
# Generates test/captures/symantec_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the Symantec firewall coverage captures: mksymantec.py <outdir> [-v].  All data is synthetic."""
import os
import struct
import sys
import socket
from c17lib import Cap, ipv4, ipv6, csum

def v2(ifaddr, etype, payload):
    """44 byte header: interface IPv4 address, 2 octets of 0, Ethernet type, 36 octets of 0."""
    return socket.inet_aton(ifaddr) + b'\0\0' + struct.pack('>H', etype) + b'\0' * 36 + payload

def v3(ifaddr, etype, payload):
    """56 byte header: interface IPv4 address, 6 octets of 0, Ethernet type, 44 octets of 0."""
    return socket.inet_aton(ifaddr) + b'\0' * 6 + struct.pack('>H', etype) + b'\0' * 44 + payload

def udp4(n):
    p = b'symantec test %d' % n
    u = struct.pack('>HHHH', 41000 + n, 42000, 8 + len(p), 0) + p
    return ipv4(17, u)

def arp(n):
    return struct.pack('>HHBBH', 1, 0x0800, 6, 4, 1) + b'\x02\0\0\0\0\x01' + socket.inet_aton('192.0.2.1') + b'\0' * 6 + socket.inet_aton('192.0.2.%d' % (10 + n))

def udp6(n):
    p = b'v6 %d' % n
    u = struct.pack('>HHHH', 41100 + n, 42000, 8 + len(p), 0) + p
    ps = socket.inet_pton(socket.AF_INET6, '2001:db8::1') + socket.inet_pton(socket.AF_INET6, '2001:db8::2') + struct.pack('>IBBBB', len(u), 0, 0, 0, 17)
    u = u[:6] + struct.pack('>H', csum(ps + u) or 0xffff) + u[8:]
    return ipv6(17, u)

def main(out, verbose):
    c = Cap(99)
    c.mark('Older (SEF, SGS v2) 44 octet header carrying IPv4/UDP, ARP and IPv6/UDP')
    c.add(v2('192.0.2.254', 0x0800, udp4(1)))
    c.add(v2('192.0.2.253', 0x0806, arp(1)))
    c.add(v2('192.0.2.254', 0x86dd, udp6(1)))
    c.mark('Older header with an Ethernet type that no dissector handles, and with no payload')
    c.add(v2('10.0.0.1', 0x88b5, b'local experimental'))
    c.add(v2('10.0.0.2', 0x88b5, b''))
    c.mark('SGS v3 56 octet header carrying IPv4/UDP, ARP and IPv6/UDP')
    c.add(v3('192.0.2.254', 0x0800, udp4(2)))
    c.add(v3('192.0.2.253', 0x0806, arp(2)))
    c.add(v3('192.0.2.254', 0x86dd, udp6(2)))
    c.mark('SGS v3 header with an unknown Ethernet type and with no payload')
    c.add(v3('10.0.0.3', 0x88b5, b'local experimental'))
    c.add(v3('10.0.0.4', 0x88b5, b''))
    c.mark('Neither a v2 nor a v3 header (both Ethernet type fields 0, then both set): the dissector returns without decoding')
    c.add(socket.inet_aton('10.0.0.5') + b'\0' * 60)
    c.add(socket.inet_aton('10.0.0.6') + b'\0\0\x08\x00\0\0\x08\x00' + b'\0' * 50)

    m = Cap(99)
    m.mark('Header shorter than the Ethernet type fields (exception)')
    m.add(socket.inet_aton('10.0.0.7') + b'\0\0\x08')
    m.add(socket.inet_aton('10.0.0.8') + b'\0\0\0\0\0')
    m.add(v2('10.0.0.2', 0x0800, b''))
    m.add(v3('10.0.0.4', 0x0800, b''))
    m.mark('Header cut short before the end of the 44 and 56 octet variants, payload truncated')
    m.add(v2('10.0.0.9', 0x0800, udp4(3))[:44 + 10])
    m.add(v3('10.0.0.9', 0x0800, udp4(3))[:30])
    c.write(os.path.join(out, 'symantec-coverage.pcap'))
    m.write(os.path.join(out, 'symantec-coverage-malformed.pcap'))
    if verbose:
        for n, tx in c.marks:
            print(n, tx)
        print(len(c.frames), 'frames')

if __name__ == '__main__':
    main(sys.argv[1], '-v' in sys.argv)
