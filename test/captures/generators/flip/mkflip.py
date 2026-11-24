#!/usr/bin/env python3
# Generates test/captures/flip_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures for the FLIP dissector (packet-flip.c).
Usage: mkflip.py <output directory>
FLIP runs over Ethernet with ethertype 0x8901 (registered by default).
Writes flip-coverage.pcap and flip-coverage-malformed.pcap."""
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

def tcpseg(src, dst, sp, dp, seq, ack, flags, payload=b'', ident=1, win=65535):
    """Ethernet/IPv4/TCP segment with correct checksums."""
    opts = b'\x02\x04\x05\xb4' if flags & 0x02 else b''
    if flags == 0x02:
        ack = 0
    h = struct.pack('>HHIIBBHHH', sp, dp, seq, ack, (5 + len(opts) // 4) << 4, flags, win, 0, 0)
    h = h[:20] + opts
    ps = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack('>BBH', 0, 6, len(h) + len(payload))
    c = csum(ps + h + payload)
    h = h[:16] + struct.pack('>H', c) + h[18:]
    return eth(bytes.fromhex('020000000002'), bytes.fromhex('020000000001'), 0x0800,
               ip4(src, dst, 6, h + payload, ident))

class Flow:
    """One TCP connection; client = 10.0.0.1, server = 10.0.0.2."""
    def __init__(self, cport, sport, frames, cip='10.0.0.1', sip='10.0.0.2', cseq=1000, sseq=5000):
        self.c, self.s, self.cp, self.sp, self.f = cip, sip, cport, sport, frames
        self.cseq, self.sseq = cseq, sseq
    def _send(self, from_client, flags, data=b''):
        if from_client:
            fr = tcpseg(self.c, self.s, self.cp, self.sp, self.cseq, self.sseq, flags, data)
            self.cseq += len(data) + (1 if flags & 3 else 0)
        else:
            fr = tcpseg(self.s, self.c, self.sp, self.cp, self.sseq, self.cseq, flags, data)
            self.sseq += len(data) + (1 if flags & 3 else 0)
        self.f.append(fr)
    def open(self):
        self._send(True, 0x02)
        self._send(False, 0x12)
        self._send(True, 0x10)
    def c2s(self, data): self._send(True, 0x18, data)
    def s2c(self, data): self._send(False, 0x18, data)
    def ack_c(self): self._send(True, 0x10)
    def ack_s(self): self._send(False, 0x10)
    def fin_s(self, data=b''): self._send(False, 0x19, data)
    def fin_c(self): self._send(True, 0x11)
    def close(self):
        self.fin_s(); self.fin_c(); self.ack_s()

import os
import sys

SRC = bytes.fromhex('020000000001')
DST = bytes.fromhex('020000000002')

def basic(flow, seq, length, ext=0, res=0):
    return struct.pack('>IHH', (ext << 31) | (res << 28) | flow, seq, length)

def chk(ext_follows=0, etype=1, spare=0, value=0):
    return struct.pack('>I', (etype << 24) | (spare << 17) | (ext_follows << 16) | value)

def frame(payload, pad=True):
    fr = eth(DST, SRC, 0x8901, payload)
    return fr + b'\0' * max(0, 60 - len(fr)) if pad else fr

def flip_chk(flow, seq, data, good=True, chain=0, wrong=0):
    """Basic header + checksum header(s) + data, with a correct (or not)
    checksum in the first checksum header."""
    hdrs = chk(1 if chain else 0)
    for i in range(chain):
        hdrs += chk(1 if i < chain - 1 else 0, value=0x1234)
    length = 8 + len(hdrs) + len(data)
    b = basic(flow, seq, length, ext=1)
    msg = b + hdrs + data
    # checksum: basic header + first 2 octets of the checksum header, then
    # everything after the checksum header
    s = msg[:10] + msg[12:length]
    c = csum(s)
    c = (c + wrong) & 0xffff
    return msg[:10] + struct.pack('>H', c) + msg[12:]

def main(out):
    F = []
    F.append(frame(basic(0x100, 1, 8)))                                   # basic header only
    F.append(frame(basic(0x0fffffff, 2, 28) + bytes(range(20))))         # payload
    F.append(frame(basic(0x7000123, 3, 14, res=7) + b'abcdef'))          # reserved bits
    F.append(frame(flip_chk(0x200, 4, b'checksummed payload')))          # correct checksum
    F.append(frame(flip_chk(0x200, 5, b'bad checksum payload', wrong=1)))  # incorrect checksum
    F.append(frame(flip_chk(0x201, 6, b'two chained headers', chain=1))) # second header follows
    F.append(frame(flip_chk(0x202, 7, b'three', chain=2)))
    F.append(frame(flip_chk(0x203, 8, b'')))                              # checksum header, no payload
    F.append(frame(basic(0x300, 9, 10, ext=1) + b'\x01\x00'))            # extension indicated, not enough data
    F.append(frame(basic(0x301, 10, 12, ext=1) + b'\x7f\x00\x00\x00'))   # unknown extension type
    F.append(frame(basic(0x302, 11, 12, ext=1) + chk(0, etype=1, spare=0x55, value=0xffff)))  # spare bits, wrong checksum
    F.append(frame(basic(0x400, 12, 500) + b'short'))                    # length larger than the frame
    F.append(frame(basic(0x401, 13, 4) + b'xxxx'))                       # length smaller than the basic header
    F.append(frame(basic(0x402, 14, 0) + b'xxxx'))
    F.append(frame(basic(0x403, 15, 20) + bytes(12) + b'trailing padding'))  # frame longer than the FLIP length
    F.append(frame(b'\x00\x01\x02', pad=False))                          # shorter than the basic header
    F.append(frame(b'', pad=False))
    pcap(os.path.join(out, 'flip-coverage.pcap'), F)

    M = [frame(basic(0x500, 1, 8, ext=1)), frame(flip_chk(0x501, 2, b'x')[:-1]), frame(basic(0x502, 3, 40) + b'abc', pad=False)]
    pcap(os.path.join(out, 'flip-coverage-malformed.pcap'), M)

if __name__ == '__main__':
    main(sys.argv[1])
