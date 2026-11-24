#!/usr/bin/env python3
# Generates test/captures/flexray_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures for the FlexRay dissector (packet-flexray.c).
Usage: mkflexray.py <output directory>
FlexRay is reached by the pcap link type 210 (WTAP_ENCAP_FLEXRAY). Writes
flexray-coverage.pcap and flexray-coverage-malformed.pcap."""
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

def frhdr(fid, plen_words, cc, hcrc=0x123, ppi=0, nfi=1, sfi=0, stfi=0, res=0):
    b0 = (res << 7) | (ppi << 6) | (nfi << 5) | (sfi << 4) | (stfi << 3) | (fid >> 8)
    v = (plen_words << 17) | (hcrc << 6) | cc
    return bytes([b0, fid & 0xff]) + struct.pack('>I', v)[1:]

def frame(fid, payload, cc, ch=0, err=0, wlen=None, trailer=b'', **kw):
    """Measurement header, error flags, FlexRay header, payload, trailer."""
    n = len(payload) // 2 if wlen is None else wlen
    return bytes([(ch << 7) | 1, err]) + frhdr(fid, n, cc, **kw) + payload + trailer

def symbol(length, ch=0, t=2):
    return bytes([(ch << 7) | t, length])

def main(out):
    F = []
    F.append(frame(1, b'\x01\x02\x03\x04', 0, sfi=1, stfi=1))                 # startup + sync frame
    F.append(frame(2, bytes(range(16)), 1, ch=1))                              # channel B
    F.append(frame(17, bytes(range(32, 40)), 2))                               # frame id 17 (used by the ISO 10681 runs)
    F.append(frame(17, bytes(range(32, 40)), 255 & 0x3f))
    F.append(frame(0x7ff, bytes(254), 63, ch=1))                               # largest payload: 127 words
    F.append(frame(3, b'', 4))                                                 # no payload
    F.append(frame(4, b'\xde\xad\xbe\xef', 5, nfi=0))                          # null frame with payload
    F.append(frame(5, b'', 6, nfi=0))                                          # null frame without payload
    F.append(frame(6, b'\x11\x22', 7, ppi=1))                                  # payload preamble indicator
    F.append(frame(7, b'\x11\x22', 8, res=1))                                  # reserved bit
    F.append(frame(0, b'\xaa\xbb\xcc\xdd', 9))                                 # frame id 0: no subdissector
    F.append(frame(8, b'\x01\x02\x03\x04', 10, sfi=1))                         # sync frame
    F.append(frame(9, b'\x01\x02', 11, stfi=1))                                # startup without sync: warning
    F.append(frame(10, b'\x01\x02\x03\x04', 12, trailer=b'\x12\x34\x56'))      # frame CRC trailer
    F.append(frame(11, b'\x01\x02', 13, trailer=b'\xab\xcd\xef\x01\x02'))      # longer trailer
    # error flags
    for i, e in enumerate((0x10, 0x08, 0x04, 0x02, 0x01, 0x1f, 0xe0)):
        F.append(frame(12 + i, b'\x01\x02\x03\x04', 14 + i, err=e))
    F.append(frame(19, b'\x01\x02', 20, nfi=0, trailer=b'\x11\x22\x33'))      # null frame with trailer
    # symbols and an unknown type
    F.append(symbol(12))
    F.append(symbol(0x7f, ch=1))
    F.append(bytes([3, 0, 0]))                                                 # unknown type
    F.append(bytes([0x82 & 0xff, 5]))                                          # symbol on channel B
    pcap(os.path.join(out, 'flexray-coverage.pcap'), F, 210)

    M = []
    M.append(frame(30, b'\x01\x02', 1, wlen=2))                               # payload length 2 words, 1 present
    M.append(frame(31, b'', 1, wlen=10))                                       # no payload at all
    M.append(frame(32, b'\x01', 1, wlen=1))                                    # odd short payload
    M.append(frame(33, b'\x01\x02\x03', 1, wlen=4))
    M.append(frame(34, b'', 1, nfi=0, wlen=3))                                 # null frame, payload missing
    M.append(frame(35, b'\x01\x02', 1, nfi=0, wlen=3))                         # null frame, partial payload
    M.append(frame(36, b'\x01\x02\x03\x04', 2, err=0x10, wlen=60))
    M.append(bytes([1, 0, 0x20, 0x25]))                                        # header cut short
    M.append(bytes([1]))                                                       # error flags missing
    M.append(bytes([2]))                                                       # symbol without length
    pcap(os.path.join(out, 'flexray-coverage-malformed.pcap'), M, 210)

if __name__ == '__main__':
    main(sys.argv[1])
