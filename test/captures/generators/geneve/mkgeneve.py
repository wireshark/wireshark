#!/usr/bin/env python3
# Generates test/captures/geneve_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generate the Geneve coverage captures. Usage: mkgeneve.py <outdir>
# Geneve runs over UDP port 6081 (registered by default).
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
import socket
from common import pcap, ip4, udp, eth

M1 = bytes.fromhex('0200000000a1'); M2 = bytes.fromhex('0200000000a2')

def inner_eth_ip(sport=1234, dport=80, payload=b'inner payload'):
    return eth(M2, M1, 0x0800, ip4('192.168.1.1', '192.168.1.2', 17, udp(sport, dport, payload)))

def inner_ipv4():
    return ip4('192.168.1.1', '192.168.1.2', 17, udp(1234, 4321, b'ip payload'))

def inner_ipv6():
    pl = b'v6 payload'
    hdr = struct.pack('>IHBB', 0x60000000, len(pl), 59, 64) + socket.inet_pton(socket.AF_INET6, '2001:db8::1') + socket.inet_pton(socket.AF_INET6, '2001:db8::2')
    return hdr + pl

def opt(cls, typ, data=b'', flags=0, length=None):
    assert len(data) % 4 == 0
    n = len(data) // 4 if length is None else length
    return struct.pack('>HBB', cls, typ, (flags << 5) | n) + data

def geneve(proto, vni, opts=b'', ver=0, flags=0, reserved=0, optlen=None):
    ol = len(opts) // 4 if optlen is None else optlen
    hdr = struct.pack('>BBH', (ver << 6) | ol, flags, proto) + struct.pack('>I', (vni << 8) | reserved)
    return hdr + opts

def pkt(gen, sport=50000, dport=6081, src='10.0.0.1', dst='10.0.0.2'):
    return eth(M2, M1, 0x0800, ip4(src, dst, 17, udp(sport, dport, gen)))

def build():
    ethp = inner_eth_ip()
    fr = []
    A = fr.append
    A(pkt(geneve(0x6558, 0x123456, b'', flags=0) + ethp))                       # no options, Ethernet
    A(pkt(geneve(0x0800, 1) + inner_ipv4()))                                    # IPv4
    A(pkt(geneve(0x86dd, 2) + inner_ipv6()))                                    # IPv6
    A(pkt(geneve(0x1234, 3) + b'unknown ethertype payload'))                    # data
    A(pkt(geneve(0x6558, 0xabcdef, flags=0x80) + ethp))                         # OAM
    A(pkt(geneve(0x6558, 4, flags=0x40) + ethp))                                # critical options present flag
    A(pkt(geneve(0x6558, 5, flags=0x3f) + ethp))                                # reserved flag bits
    A(pkt(geneve(0x6558, 6, reserved=0x55) + ethp))                             # reserved byte set
    A(pkt(geneve(0x6558, 7, ver=1) + ethp))                                     # unknown version
    A(pkt(geneve(0x6558, 7, ver=3) + ethp))
    # options
    def withopts(o, vni=10):
        A(pkt(geneve(0x6558, vni, o) + ethp))
    withopts(opt(0x0132, 0x01, struct.pack('>I', 0x8badf00d)))                  # GCP VNID (direction bit set)
    withopts(opt(0x0132, 0x01, struct.pack('>I', 0x0012345 << 4)))
    withopts(opt(0x0132, 0x02, bytes(range(8))))                                # GCP endpoint
    withopts(opt(0x0132, 0x02, b''))                                            # endpoint, no data
    withopts(opt(0x0132, 0x03, struct.pack('>Q', 0x1122334455667788)))          # GCP profile, 8 octets
    withopts(opt(0x0132, 0x03, bytes(4)))                                       # profile, 4 octets (shown as unknown data after the fix)
    withopts(opt(0x0132, 0x03, bytes(12)))                                      # profile, 12 octets
    withopts(opt(0x0132, 0x03, b''))                                            # profile, no data
    withopts(opt(0x0132, 0x0f, struct.pack('>Q', 1700000000123456789)))         # GCP timestamp
    withopts(opt(0x0132, 0x10, struct.pack('>QQ', 123456789012, 987654321098))) # network stable id
    withopts(opt(0x0132, 0x11, bytes([10, 1, 2, 3])))                           # primary IPv4
    withopts(opt(0x0132, 0x13, struct.pack('>Q', 1700000001000000001)))         # FOPiC timestamp
    withopts(opt(0x014b, 0x81, bytes([10, 96, 0, 1]) + struct.pack('>H', 8080) + b'\0\0'))     # Cilium IPv4 (len 12)
    withopts(opt(0x014b, 0x81, socket.inet_pton(socket.AF_INET6, 'fd00::1') + struct.pack('>H', 443) + b'\0\0'))   # Cilium IPv6 (len 24)
    withopts(opt(0x014b, 0x81, bytes(12)))                                      # Cilium, other length: unknown data
    cp = struct.pack('>IHBB', 0xcafe0001, 1500, 0, 2) + (1700000000).to_bytes(6, 'big') + struct.pack('>I', 999) + struct.pack('>H', 77) + struct.pack('>HH', 3, 4)
    withopts(opt(0x0164, 0x00, cp))                                             # cPacket metadata, 24 octets of data
    withopts(opt(0x0164, 0x00, cp, flags=0))
    withopts(opt(0x0000, 0x01, b'\x01\x02\x03\x04'))                            # unknown option
    withopts(opt(0x0100, 0x80, b'', flags=0))                                   # critical, empty
    withopts(opt(0x0101, 0x05, b'abcd' * 3, flags=5))                           # reserved option flags
    withopts(opt(0xfff0, 0x7f, b'x' * 124))                                     # maximum option length (31 words)
    withopts(opt(0x0105, 0x01, b'amzn') + opt(0x0132, 0x11, bytes([1, 2, 3, 4])) + opt(0x0145, 0x02, b'') + opt(0x016a, 0x00, b'1234'))  # several options, class names
    withopts(opt(0x0136, 0x01, b'') + opt(0x0141, 0x01, b'') + opt(0x014a, 0x01, b'') + opt(0x014d, 0x01, b'') + opt(0x0162, 0x01, b'') + opt(0x0168, 0x01, b'') + opt(0x0169, 0x01, b'') + opt(0x0103, 0x01, b''))
    # invalid option length: option claims more than the options area
    A(pkt(geneve(0x6558, 11, opt(0x0132, 0x02, bytes(8), length=10), optlen=3) + ethp))
    None
    # a port that is not 6081 is not Geneve: no entry (Decode As in runcov.sh only)
    return fr

def build_mal():
    ethp = inner_eth_ip()
    fr = []
    A = fr.append
    A(pkt(b'\x00'))                                                          # shorter than the header
    A(pkt(geneve(0x6558, 1, b'', optlen=5) + b''))                           # options area missing
    A(pkt(geneve(0x6558, 1, opt(0x0132, 0x0f, bytes(4))) + ethp))           # GCP timestamp with 4 octets of data
    A(pkt(geneve(0x6558, 1, opt(0x0132, 0x10, bytes(8))) + ethp))           # network stable id with 8
    A(pkt(geneve(0x6558, 1, opt(0x0132, 0x01, b'')) + ethp))                # GCP VNID with no data
    A(pkt(geneve(0x6558, 1, opt(0x0132, 0x11, b'')) + ethp))                # primary IPv4 no data
    A(pkt(geneve(0x6558, 1, opt(0x0132, 0x13, bytes(4))) + ethp))           # FOPiC timestamp short
    A(pkt(geneve(0x6558, 1, opt(0x0164, 0x00, bytes(8))) + ethp))           # cPacket metadata short
    A(pkt(geneve(0x6558, 1, opt(0x014b, 0x81, bytes(8)) ) + ethp))          # Cilium (len 12) is fine
    A(pkt(geneve(0x6558, 1, opt(0x0132, 0x03, bytes(4))) [:-len(ethp)] + b'')) # truncated frame inside options
    A(pkt(geneve(0x6558, 1, opt(0x0132, 0x02, bytes(8), length=10), optlen=63) + ethp))
    A(pkt(geneve(0x6558, 1, opt(0x0132, 0x02, bytes(8))) + b'\x00' * 3))    # truncated inner Ethernet
    return fr

if __name__ == '__main__':
    out = sys.argv[1]
    pcap(os.path.join(out, 'geneve-coverage.pcap'), build())
    pcap(os.path.join(out, 'geneve-coverage-malformed.pcap'), build_mal())
