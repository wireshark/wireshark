#!/usr/bin/env python3
# Generates test/captures/fddi_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures for the FDDI dissector (packet-fddi.c).
Usage: mkfddi.py <output directory>
Writes fddi-coverage.pcapng (FDDI link type 10, bit-swapped MACs, every
frame control class, plus FDDI inside sFlow samples over Ethernet) and
fddi-coverage-malformed.pcapng (truncated frames)."""
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

SNAP_ARP = bytes.fromhex('aaaa03000000' '0806') + struct.pack('>HHBBH6s4s6s4s', 1, 0x0800, 6, 4, 1,
    bytes.fromhex('0200000000aa'), socket.inet_aton('10.0.0.1'), bytes(6), socket.inet_aton('10.0.0.2'))
# FDDI MAC addresses are bit-swapped in the capture (canonical order is
# produced by reversing the bits of each octet)
def bs(mac):
    return bytes(int('{:08b}'.format(b)[::-1], 2) for b in mac)
A = bytes.fromhex('0200000000aa'); B = bytes.fromhex('0200000000bb'); BC = b'\xff' * 6

def fddi(fc, dst=B, src=A, payload=SNAP_ARP, swap=True):
    f = (lambda m: bs(m)) if swap else (lambda m: m)
    return bytes([fc]) + f(dst) + f(src) + payload

def sflow(frame):
    rec = struct.pack('>IIII', 4, len(frame) + 4, 0, len(frame)) + frame
    rec += b'\0' * ((-len(frame)) % 4)
    rec = struct.pack('>II', 1, len(rec)) + rec  # tag 1: raw packet header
    samp = struct.pack('>IIIIIIII', 1, 1, 400, 100, 0, 1, 2, 1) + rec
    samp = struct.pack('>II', 1, len(samp)) + samp
    return struct.pack('>II4sIIII', 5, 1, socket.inet_aton('10.1.1.1'), 0, 1, 1000, 1) + samp

def sflow_frame(fddiframe):
    pl = udp(40000, 6343, sflow(fddiframe))
    return eth(bytes.fromhex('020000000002'), bytes.fromhex('020000000001'), 0x0800,
               ip4('10.1.1.1', '10.1.1.2', 17, pl))

def main(out):
    fcs = [0x00, 0x80, 0xc0, 0x41, 0x4f, 0x40, 0x42, 0xc1, 0xc2, 0xc3, 0xc5, 0xcf,
           0x50, 0x54, 0x57, 0x58, 0x5f, 0xd0, 0xd1, 0xd7, 0x60, 0x6f, 0xe0, 0xe3,
           0x10, 0x20, 0x30, 0x70, 0xf0]
    frames = []
    for fc in fcs:
        # LLC (async) frames carry SNAP/ARP, the rest carries opaque data
        pl = SNAP_ARP if 0x50 <= fc <= 0x5f else bytes(range(fc % 7, fc % 7 + 20))
        frames.append((0, fddi(fc, dst=BC if fc == 0x41 else B, payload=pl)))
    # FDDI with canonical (not bit-swapped) addresses, reached through sFlow
    frames.append((1, sflow_frame(fddi(0x54, swap=False))))
    frames.append((1, sflow_frame(fddi(0x4f, swap=False, payload=bytes(10)))))
    pcapng(os.path.join(out, 'fddi-coverage.pcapng'), [10, 1], frames)
    mal = [(0, fddi(0x50, payload=b'')), (0, fddi(0x54)[:12]), (0, fddi(0x54)[:1]),
           (1, sflow_frame(fddi(0x54, swap=False)[:9])),
           (0, fddi(0x54, payload=SNAP_ARP[:5]))]
    pcapng(os.path.join(out, 'fddi-coverage-malformed.pcapng'), [10, 1], mal)

if __name__ == '__main__':
    main(sys.argv[1])
