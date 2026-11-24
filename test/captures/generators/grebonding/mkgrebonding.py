#!/usr/bin/env python3
# Generates test/captures/grebonding_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the GRE bonding coverage captures. Usage: mkgrebonding.py <outdir>"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from common import eth, ip4, pcap

EM = bytes.fromhex('020000000002'), bytes.fromhex('020000000001')

def ipv4(payload, proto=47, src='192.0.2.1', dst='192.0.2.2'):
    return ip4(src, dst, proto, payload)

def ipv6(payload, nh=47):
    a = b'\x20\x01\x0d\xb8' + b'\0' * 11
    return struct.pack('>IHBB', 0x60000000, len(payload), nh, 64) + a + b'\x01' + a + b'\x02' + payload

def gre(proto, p):
    return struct.pack('>HH', 0, proto) + p

def frame(proto, p, v6=False):
    if v6:
        return eth(EM[0], EM[1], 0x86dd, ipv6(gre(proto, p)))
    return eth(EM[0], EM[1], 0x0800, ipv4(gre(proto, p)))

def attr(t, v): return bytes([t]) + struct.pack('>H', len(v)) + v

def item(t, en, desc, val):
    return struct.pack('>HHHH', t, 4 + len(desc) + len(val), en, len(desc)) + desc + val

def flist(commit, total, pid, items):
    return struct.pack('>IHH', commit, total, pid) + b''.join(items)

def msg(mt, tt, *attrs):
    return bytes([(mt << 4) | tt]) + b''.join(attrs)

def main(outdir):
    F, marks = [], []
    def add(p, proto=0xB7EA, v6=False): F.append(frame(proto, p, v6))
    def mark(s): marks.append((len(F) + 1, s))

    mark('message types and tunnel types, no attributes')
    for mt, tt in ((1, 1), (2, 2), (3, 1), (4, 2), (5, 1), (6, 2), (10, 0), (1, 8), (7, 3)):
        add(msg(mt, tt))
    mark('GRE protocol 0x0101 (used by Deutsche Telekom) and IPv6 transport')
    add(msg(1, 0, attr(3, b'CIN-0001')), proto=0x0101)
    add(msg(4, 8, attr(4, struct.pack('>I', 0x01020304))), v6=True)
    mark('tunnel setup request: addresses, CIN, session id, time, rates, intervals')
    add(msg(1, 1, attr(1, bytes([192, 0, 2, 10])), attr(2, bytes([0x20, 0x01, 0x0d, 0xb8]) + bytes(11) + b'\x05'),
            attr(3, b'CIN-0002'), attr(4, struct.pack('>I', 0xdeadbeef)),
            attr(5, struct.pack('>II', 1700000000, 250000)), attr(6, struct.pack('>I', 5000)),
            attr(7, struct.pack('>I', 100000))))
    add(msg(1, 2, attr(1, bytes([1, 2])), attr(2, bytes([1, 2, 3])), attr(9, struct.pack('>H', 50)),
            attr(10, struct.pack('>H', 1000)), attr(11, b'\x01'), attr(12, b'\x00')))
    mark('IPv6 prefixes, hello and idle timers, error attributes, bonding key')
    add(msg(2, 1, attr(13, bytes([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1]) + bytes(8) + b'\x40'),
            attr(21, bytes([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 2]) + bytes(8) + b'\x38'),
            attr(14, struct.pack('>H', 3)), attr(15, b'\x05'), attr(16, struct.pack('>H', 300))))
    add(msg(3, 1, attr(17, struct.pack('>I', 9)), attr(18, b'\x01'), attr(19, b'\x01'),
            attr(20, struct.pack('>Q', 0x1122334455667788))))
    add(msg(5, 1, attr(22, struct.pack('>I', 1000)), attr(23, struct.pack('>I', 20000)),
            attr(24, struct.pack('>H', 5)), attr(25, struct.pack('>H', 95))))
    add(msg(6, 2, attr(26, b'\x01'), attr(27, b'\x01'), attr(29, b''), attr(31, struct.pack('>H', 10)),
            attr(32, struct.pack('>H', 20)), attr(33, b'\x01'), attr(34, b'\x00'), attr(35, b'\x01')))
    mark('every error code')
    codes = list(range(1, 13)) + list(range(401, 408)) + [501, 502, 503, 999]
    for i in range(0, len(codes), 5):
        add(msg(3, 1, *[attr(17, struct.pack('>I', c)) for c in codes[i:i+5]]))
    mark('Telekom attributes: DSL protocol (every value), BRAS name, reorder, burst, upstream rate, FIN, unknown')
    for p in (0, 1, 2, 3, 4, 5):
        add(msg(10, 8, attr(53, bytes([p]))))
    add(msg(10, 8, attr(54, b'bras01.example.net'), attr(56, struct.pack('>H', 80)),
            attr(57, struct.pack('>H', 40)), attr(59, struct.pack('>I', 25000)), attr(255, b''), attr(200, b'\x07')))
    mark('filter list: every filter type, several items, empty description, empty value')
    items = []
    for t in range(1, 16):
        items.append(item(t, t & 1, b'filter-%d' % t, (b'value-%d' % t) if t % 4 else b''))
    add(msg(1, 1, attr(8, flist(7, 2, 1, items[:8]))))
    add(msg(1, 1, attr(8, flist(7, 2, 2, items[8:]))))
    add(msg(1, 1, attr(8, flist(8, 1, 1, [item(1, 1, b'', b'www.example.org'), item(99, 0, b'x', b'')]))))
    add(msg(1, 1, attr(8, flist(9, 1, 1, [])), attr(3, b'CIN-0003')))
    mark('filter list ACK: acknowledged, no old list, old list used')
    for ack in (0, 1, 2, 3):
        add(msg(6, 1, attr(30, struct.pack('>IB', 7, ack)), attr(4, struct.pack('>I', 0x01020304))))
    mark('zero length attributes and attribute types without value handling')
    add(msg(4, 1, attr(3, b''), attr(1, b''), attr(8, b'\0' * 8), attr(30, b'\0' * 5)))
    add(msg(4, 1, attr(1, b'\x01\x02\x03'), attr(6, bytes(8)), attr(5, bytes(8))))

    mark('lengths larger than the packet are clamped; filter list after a 24 octet attribute (reproducer of the offset fix)')
    add(msg(1, 1, bytes([3, 0xff, 0xff]) + b'truncated'))
    add(msg(1, 1, attr(8, flist(1, 1, 1, [struct.pack('>HHHH', 1, 2, 1, 7)]))))
    add(msg(1, 1, attr(8, flist(1, 1, 1, [struct.pack('>HHHH', 1, 6, 1, 9) + b'ab']))))
    add(msg(1, 1, attr(3, b'C' * 24), attr(8, flist(7, 1, 1, [item(1, 1, b'web', b'example')]))))
    add(msg(1, 1, attr(8, flist(7, 1, 1, [item(1, 1, b'web', b'example')])), attr(3, b'CIN-0001')))

    mal = []
    m = lambda p, proto=0xB7EA: mal.append(frame(proto, p))
    m(b'')                                                    # message type missing
    m(msg(1, 1, b'\x03'))                                      # attribute without length
    m(msg(1, 1, attr(3, b'CIN') [:3] + b'\x00'))
    m(msg(1, 1, bytes([8, 0, 4]) + b'\0\0\0\1'))               # filter list shorter than its header
    m(msg(1, 1, bytes([8, 0, 8]) + b'\0\0\0\1\0\1\0\1'))       # filter list with no item, then packet ends
    m(msg(1, 1, attr(8, flist(1, 1, 1, [b'\0\1\0'])) ))        # item cut after 3 octets
    m(msg(1, 1, attr(8, flist(1, 1, 1, [struct.pack('>HHHH', 1, 0xffff, 1, 0xffff) + b'abc']))))  # lengths past the packet
    m(msg(1, 1, attr(30, b'\x01')))                            # ACK attribute of 1 octet
    m(msg(1, 1, attr(30, b'\x01\x02\x03')))
    m(msg(1, 1, attr(30, b'\x01\x02\x03\x04\x05\x06')))        # commit longer than 4
    m(msg(1, 1, attr(13, bytes(1))))                           # IPv6 prefix with just the length octet
    m(msg(1, 1, attr(13, bytes(20))))                          # prefix longer than an address
    m(msg(1, 1, attr(2, bytes(9))))                            # 9 octets: more than a 64-bit number
    m(msg(1, 1, attr(5, bytes(3))))                            # time of 3 octets
    m(msg(1, 1, attr(17, bytes(5))))                           # error of 5 octets
    m(msg(1, 1, attr(53, bytes(3))))
    m(msg(1, 1, attr(6, bytes(12))))
    m(msg(1, 1, attr(54, b'')))
    m(msg(1, 1, attr(3, b'a' * 300)))
    m(msg(1, 1, b'\xff\xff'))

    pcap(outdir + '/grebonding-coverage.pcap', F)
    pcap(outdir + '/grebonding-coverage-malformed.pcap', mal)
    for n, s in marks:
        print(n, s)
    print(len(F), 'frames;', len(mal), 'malformed')

main(sys.argv[1])
