#!/usr/bin/env python3
# Generates test/captures/miop_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the MIOP coverage captures. Usage: mkmiop.py <outdir> [-v]
Synthetic; addresses from 192.0.2.0/24 and the multicast group 233.252.0.1."""
import struct
import sys
import os

def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff
def eth(payload, ethertype=0x0800, src=1, dst=2):
    return bytes([2, 0, 0, 0, 0, dst]) + bytes([2, 0, 0, 0, 0, src]) + struct.pack('!H', ethertype) + payload
def ipv4(payload, proto=17, src='192.0.2.1', dst='233.252.0.1'):
    s = bytes(int(x) for x in src.split('.')); d = bytes(int(x) for x in dst.split('.'))
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0, s, d)
    h = h[:10] + struct.pack('!H', csum(h)) + h[12:]
    return h + payload
def udp(payload, sport, dport):
    return struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
def write_pcap(fn, frames):
    with open(fn, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)

def giop(mtype, body=b'', minor=2, le=False):
    e = '<' if le else '>'
    return b'GIOP' + bytes([1, minor, 1 if le else 0, mtype]) + struct.pack(e + 'I', len(body)) + body

def giop_request(le=False):
    e = '<' if le else '>'
    b = struct.pack(e + 'I', 7) + bytes([3, 0, 0, 0])               # request id, response flags + reserved
    b += struct.pack(e + 'H', 0) + b'\0\0' + struct.pack(e + 'I', 4) + b'key1'   # KeyAddr
    b += b'\0' * (-len(b) % 4)
    b += struct.pack(e + 'I', 5) + b'ping\0'                         # operation
    b += b'\0' * (-len(b) % 4) + struct.pack(e + 'I', 0)             # no service contexts
    b += b'\0' * (-len(b) % 8)
    return giop(0, b, 2, le)

def miop(pn=0, n=1, uid=b'uid-0001', flags=0, ver=16, payload=b'', ulen=None, plen=None, le=None, magic=b'MIOP'):
    le = bool(flags & 1) if le is None else le
    e = '<' if le else '>'
    ulen = len(uid) if ulen is None else ulen
    plen = (20 + len(uid) + len(payload)) if plen is None else plen
    return (magic + bytes([ver, flags]) + struct.pack(e + 'H', plen & 0xffff) + struct.pack(e + 'III', pn, n, ulen) + uid + payload)

frames = []
ranges = []
def add(m, sport=40000, dport=5000, dst='233.252.0.1'):
    frames.append(eth(ipv4(udp(m, sport, dport), dst=dst), 0x0800))
def mark(name): ranges.append((name, len(frames) + 1))

def build():
    mark('packet numbers, endianness and flags')
    add(miop(0, 3, payload=b'first fragment'))
    add(miop(1, 3, payload=b'second fragment'))
    add(miop(2, 3, flags=2, payload=b'last fragment'))
    add(miop(0, 1, flags=2, payload=b'whole'))
    add(miop(0, 3, flags=1, payload=b'first fragment'))
    add(miop(1, 3, flags=1, payload=b'second fragment'))
    add(miop(2, 3, flags=3, payload=b'last fragment'))
    add(miop(0, 1, flags=3, payload=b''))
    add(miop(1, 0xffffffff, flags=0xfc, payload=b''))
    mark('unique id lengths')
    add(miop(1, 2, uid=b''))
    add(miop(1, 2, uid=b'\x01'))
    add(miop(1, 2, uid=bytes(range(64)), flags=1))
    add(miop(1, 2, uid=bytes(251)))
    add(miop(1, 2, uid=bytes(251), flags=1))
    mark('versions')
    for v in (17, 0, 0xff, 32):
        add(miop(1, 2, ver=v, payload=b'abcdef'))
    mark('GIOP in the first packet')
    add(miop(0, 2, payload=giop(5)))
    add(miop(0, 2, payload=giop(6), flags=1))
    add(miop(0, 2, payload=giop_request()))
    add(miop(0, 2, payload=giop_request(True), flags=1))
    add(miop(0, 1, payload=b'not giop data'))
    mark('ports')
    add(miop(0, 1, payload=giop(5)), 5001, 5001)
    add(miop(0, 1, payload=giop(5)), 40000, 12345, dst='192.0.2.9')
    add(miop(1, 2), 1, 1)
    # not MIOP: too short for the heuristic, or another magic number
    add(miop(0, 1)[:19])
    add(miop(0, 1, magic=b'MIOQ'))
    add(b'\x00' * 30)

def build_malformed():
    out = []
    def f(m, dport=5000): out.append(eth(ipv4(udp(m, 40000, dport)), 0x0800))
    f(miop(0, 2, ulen=252, uid=bytes(8)))                   # unique id length over the maximum: expert info, stops
    f(miop(0, 2, ulen=1000, uid=bytes(8), flags=1))
    f(miop(0, 2, ulen=0xffffffff, uid=bytes(8)))
    f(miop(1, 2, uid=bytes(8))[:24])                    # unique id cut short
    f(miop(1, 2, ulen=200, uid=bytes(8)))                 # unique id length past the end
    f(miop(0, 1, payload=giop(0, b'\x00\x01'))[:40])      # GIOP header cut
    f(miop(0, 1, payload=giop_request()[:30]))            # GIOP request cut
    f(miop(0, 1, payload=b'GIOP\x01\x02\x00\x00\xff\xff\xff\xff'))   # GIOP length beyond the data
    f(miop(0, 1, payload=giop(6)), 9999)                 # unchanged: for Decode As
    out.append(eth(ipv4(udp(b'not miop at all, 40 bytes of ascii!!!!!!!', 40000, 9999)), 0x0800))   # Decode As only: heuristic fails
    return out

build()

if __name__ == '__main__':
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    write_pcap(os.path.join(out, 'miop-coverage.pcap'), frames)
    write_pcap(os.path.join(out, 'miop-coverage-malformed.pcap'), build_malformed())
    if '-v' in sys.argv:
        for n, s in ranges: print(n, s)
        print(len(frames), 'frames')
