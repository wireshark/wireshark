#!/usr/bin/env python3
# Generates test/captures/lsdp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic LSDP (Lenbrook Service Discovery Protocol, BluOS) coverage
# captures.  Usage: mklsdp.py <outdir>.  Writes lsdp-coverage.pcap and
# lsdp-coverage-malformed.pcap.  LSDP is on UDP port 11430 (default).
import struct
import sys
import os

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'
PORT = 11430

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def v4(payload, dst=bytes([192, 0, 2, 255]), ident=1):
    src = bytes([192, 0, 2, 1])
    u = struct.pack('!HHHH', PORT, PORT, 8 + len(payload), 0) + payload
    ph = src + dst + struct.pack('!BBH', 0, 17, len(u))
    u = u[:6] + struct.pack('!H', csum(ph + u) or 0xffff) + u[8:]
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(u), ident, 0, 64, 17, 0, src, dst)
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:] + u
    return bytes.fromhex('ffffffffffff') + bytes.fromhex('020000000001') + b'\x08\x00' + ip

def pcap(fname, frames, linktype=1):
    with open(fname, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)

HDR = b'\x06LSDP\x01'
PLAYER, SERVER, MZ, MFG, KEYPAD, SLAVE, APP, HUB, ALL = 1, 2, 3, 4, 5, 6, 7, 8, 0xffff
MAC = bytes.fromhex('0a1b2c3d4e5f')

def with_len(t, body):
    # message: length (covers itself), type, body
    return bytes([len(body) + 2, t]) + body

def node(n):
    return bytes([len(n)]) + n

def query(classes, t=0x51):
    return with_len(t, bytes([len(classes)]) + b''.join(struct.pack('>H', c) for c in classes))

def txt(k, v):
    return bytes([len(k)]) + k + bytes([len(v)]) + v

def record(cls, pairs):
    return struct.pack('>HB', cls, len(pairs)) + b''.join(txt(k, v) for k, v in pairs)

def announce(nid, addr, records):
    return with_len(0x41, node(nid) + bytes([len(addr)]) + addr + bytes([len(records)]) + b''.join(records))

def delete(nid, classes):
    return with_len(0x44, node(nid) + bytes([len(classes)]) + b''.join(struct.pack('>H', c) for c in classes))

fr = []
F = lambda *msgs: fr.append(v4(HDR + b''.join(msgs)))
F(query([ALL]))                                                   # 1 query for all classes (broadcast response)
F(query([PLAYER, SERVER, MZ, MFG, KEYPAD, SLAVE, APP, HUB, 0x0099], t=0x52))   # 2 unicast query, every class and an unknown one
F(announce(MAC, bytes([192, 0, 2, 9]), [record(PLAYER, [(b'name', b'Kitchen'), (b'model', b'N130'), (b'version', b'4.1.2'), (b'port', b'11000')])]))   # 3 IPv4, MAC node id
F(announce(b'\x01\x02\x03\x04', bytes([0x20, 0x01, 0x0d, 0xb8] + [0] * 11 + [9]),
           [record(HUB, [(b'name', b'Hub'), (b'', b'')]), record(SERVER, [])]))   # 4 IPv6, 4 octet node id, two records
F(delete(MAC, [PLAYER, MZ]))                                      # 5 delete, two classes
F(announce(MAC, bytes([192, 0, 2, 10]), [record(SLAVE, [(b'name', b'Den')])]),
  delete(MAC, [PLAYER]), query([HUB]))                            # 6 three messages in one datagram
F(announce(MAC, bytes([192, 0, 2, 11]), []))                      # 7 announce without records
F(announce(b'', bytes([192, 0, 2, 12]), [record(0x0042, [(b'x', b'y')])]))   # 8 empty node id, unknown class
F(delete(b'\x07' * 8, []))                                        # 9 delete without classes
F(query([]))                                                      # 10 query without classes
F(announce(MAC, bytes([192, 0, 2, 13]), [record(APP, [(b'name', b'x%s%n'), (b'model', b''), (b'version', b'\xc3\xa9')])]))   # 11 format characters and UTF-8 in values
pcap(os.path.join(OUT, 'lsdp-coverage.pcap'), fr)

bad = []
B = lambda p, **k: bad.append(v4(p, **k))
B(HDR + with_len(0x5a, b'\x01'))                                  # 1 unknown message type
B(HDR + announce(MAC, bytes(7), []))                              # 2 invalid address length
B(HDR[:5])                                                        # 3 header too short
B(b'\x06LSDX\x01' + query([ALL]))                                 # 4 wrong magic
B(b'\x06LSDP\x02' + query([ALL]))                                 # 5 version 2
B(b'\x07LSDP\x01' + query([ALL]))                                 # 6 wrong header length
B(HDR + bytes([7, 0x51, 2, 0, 1, 0xff, 0xff]))                    # 7 query with count 2 but one class
B(HDR + bytes([255, 0x41, 0, 7]) + bytes(7) + bytes([255]) + struct.pack('>HB', 2, 255))   # 8 counts beyond the packet
B(HDR + bytes([3, 0x44, 0]))                                      # 9 delete cut after the node id length
B(HDR + bytes([2, 0x41]))                                         # 10 announce with nothing
B(HDR + bytes([0, 0x41, 0, 0]))                                   # 11 zero length message
B(HDR + bytes([5]))                                               # 12 one octet message
B(HDR + announce(MAC, bytes([192, 0, 2, 9]), [record(PLAYER, [(b'name', b'Kitchen')])])[:-3])   # 13 truncated TXT value
B(HDR + announce(b'\x20' * 32, bytes([192, 0, 2, 9]), [])[:12])   # 14 node id longer than the packet
B(HDR + query([ALL]) + b'\x01')                                   # 15 trailing octet
B(HDR + query([ALL]) + bytes([9, 0x51]))                          # 16 second message cut
pcap(os.path.join(OUT, 'lsdp-coverage-malformed.pcap'), bad)
print(len(fr), len(bad))
