#!/usr/bin/env python3
# Generates test/captures/fefd_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures for the FEFD dissector (packet-fefd.c).
Usage: mkfefd.py <output directory>
FEFD is carried in 802.3 LLC/SNAP with the Force10 OUI 00:01:e8 and PID
0x0111. Writes fefd-coverage.pcap and fefd-coverage-malformed.pcap."""
# shared helpers (copied into each generator)
import struct
import socket

def pcap(path, frames, linktype=1):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)

def _blk(t, body):
    pad = (-len(body)) % 4
    n = 12 + len(body) + pad
    return struct.pack('<II', t, n) + body + b'\0' * pad + struct.pack('<I', n)

def pcapng(path, idbs, frames):
    """idbs: list of linktypes; frames: list of (idb index, bytes)"""
    out = _blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    for lt in idbs:
        out += _blk(1, struct.pack('<HHI', lt, 0, 65535))
    for i, (ifc, fr) in enumerate(frames):
        ts = (1700000000 + i) * 1000000
        out += _blk(6, struct.pack('<IIIII', ifc, ts >> 32, ts & 0xffffffff, len(fr), len(fr)) + fr)
    open(path, 'wb').write(out)

def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def ip4(src, dst, proto, payload, ident=1):
    h = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0, 64, proto, 0,
                    socket.inet_aton(src), socket.inet_aton(dst))
    h = h[:10] + struct.pack('>H', csum(h)) + h[12:]
    return h + payload

def udp(sp, dp, payload):
    return struct.pack('>HHHH', sp, dp, 8 + len(payload), 0) + payload

def eth(dst, src, et, payload):
    return dst + src + struct.pack('>H', et) + payload

import os
import sys

DST = bytes.fromhex('01000ccccccd')
SRC = bytes.fromhex('0200000000aa')

def llc(payload):
    """802.3 + LLC/SNAP with the Force10 OUI and PID 0x0111 (FEFD)."""
    l = bytes.fromhex('aaaa03' '0001e8') + struct.pack('>H', 0x0111) + payload
    fr = DST + SRC + struct.pack('>H', len(l)) + l
    return fr + b'\0' * max(0, 60 - len(fr))

def tlv(t, data, length=None):
    return struct.pack('>HH', t, 4 + len(data) if length is None else length) + data

def fefd(ver, op, flags, tlvs, csum=0):
    return struct.pack('>BBH', (ver << 5) | op, flags, csum) + b''.join(tlvs)

DEV = tlv(1, b'switch-1\0')
PORT = tlv(2, b'Gi1/1', 6)   # length does not cover the string: +3 rule
PORT_OK = tlv(2, b'Te0/1', 9)  # length right, next octet is 0 (next TLV)

def main(out):
    fr = []
    fr.append(fefd(1, 1, 0xc0, [DEV, PORT, tlv(4, b'\0\x0f'), tlv(5, b'\0\x3c')], 0x1234))
    fr.append(fefd(1, 1, 0x80, [DEV, PORT_OK, tlv(3, b'\x01\x02\x03\x04'), tlv(7, b'\0\0\0\x07')]))
    fr.append(fefd(1, 2, 0x40, [tlv(1, b'sw2'), tlv(2, b'Fa0/2', 9), tlv(6, b'name-2'), tlv(0x1234, b'xyz')]))
    fr.append(fefd(2, 3, 0x00, [DEV, tlv(3, b'')]))             # empty Echo TLV: stops there
    fr.append(fefd(0, 0, 0x00, []))                                # header only
    fr.append(fefd(7, 4, 0x3f, [tlv(0x00ff, b'\xaa' * 20)]))      # unknown opcode and type
    fr.append(fefd(1, 1, 0x00, [DEV, struct.pack('>HH', 6, 2), b'trailing bytes']))  # TLV with length < 4
    fr.append(fefd(1, 1, 0xc0, [struct.pack('>HH', 5, 0)]))       # length 0 and nothing after
    fr.append(fefd(1, 1, 0x00, [tlv(1, b'')]))                    # Device ID with empty string
    fr.append(fefd(1, 1, 0x00, [tlv(1, b'a\0b\0\0\0'), tlv(2, b'P', 5), tlv(5, b'\0\x0a')]))
    pcap(os.path.join(out, 'fefd-coverage.pcap'), [llc(f) for f in fr])
    mal = [
        fefd(1, 1, 0, [DEV, tlv(2, b'Gi1/1', 9)]),                # Port ID is the last TLV
        fefd(1, 1, 0, [struct.pack('>HH', 1, 200) + b'short']),  # length past the end
        fefd(1, 1, 0, [struct.pack('>HH', 3, 20) + b'short']),
        b'\x21\x80',                                               # header cut short
        fefd(1, 1, 0, [struct.pack('>HH', 1, 3)]),                # Device ID, length 3 (<4)
        fefd(1, 1, 0, [struct.pack('>HH', 2, 0xffff) + b'xx']),  # Port ID length 65535
        fefd(1, 1, 0, [b'\0\x01']),                                # TLV header cut short
    ]
    pcap(os.path.join(out, 'fefd-coverage-malformed.pcap'), [llc(f) for f in mal])

if __name__ == '__main__':
    main(sys.argv[1])
