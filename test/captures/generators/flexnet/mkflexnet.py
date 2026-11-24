#!/usr/bin/env python3
# Generates test/captures/flexnet_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures for the FlexNet dissector (packet-flexnet.c).
Usage: mkflexnet.py <output directory>
FlexNet is AX.25 PID 0xCE (link type 3, AX25). Writes
flexnet-coverage.pcap and flexnet-coverage-malformed.pcap."""
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
    h = struct.pack('>HHIIBBHHH', sp, dp, seq, ack, 5 << 4, flags, win, 0, 0)
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

def call(cs, ssid, last=False, h=0):
    cs = cs.ljust(6).encode()
    b = bytes(c << 1 for c in cs)
    return b + bytes([0x60 | (h << 7) | (ssid << 1) | (1 if last else 0)])

def ax25(dst, src, ctl, pid, payload, digis=()):
    a = call(*dst) + call(*src, last=not digis)
    for i, dg in enumerate(digis):
        a += call(*dg, last=(i == len(digis) - 1))
    return a + bytes([ctl]) + (bytes([pid]) if pid is not None else b'') + payload

def flexnet_hdr(dst, src, ctl):
    return dst.ljust(15, b'\0') + src.ljust(15, b'\0') + ctl.ljust(15, b'\0')

def main(out):
    DST = ('DB0ABC', 1); SRC = ('DL1XYZ', 2)
    fr = []
    h = flexnet_hdr(b'DB0ABC-1', b'DL1XYZ-2', b'\x01\x02\x03')
    # UI frame, FlexNet header and user data
    fr.append(ax25(DST, SRC, 0x03, 0xce, h + b'Hello FlexNet'))
    # header only
    fr.append(ax25(DST, SRC, 0x03, 0xce, flexnet_hdr(b'A', b'B', b'')))
    # I frames with N(S)/N(R) and via digipeaters
    fr.append(ax25(SRC, DST, 0x00, 0xce, h + bytes(range(32, 80))))
    fr.append(ax25(SRC, DST, 0x22, 0xce, h + b'x', digis=[('DB0RPT', 0), ('DB0XYZ', 3)]))
    # frame with a different PID, for contrast (reaches the data dissector)
    fr.append(ax25(DST, SRC, 0x03, 0xf0, b'plain text'))
    # binary control and address contents
    fr.append(ax25(DST, SRC, 0x03, 0xce, flexnet_hdr(bytes(range(1, 16)), bytes(range(16, 31)), bytes(range(0xf0, 0xff))) + b'\xff' * 4))
    pcap(os.path.join(out, 'flexnet-coverage.pcap'), fr, 3)
    mal = [ax25(DST, SRC, 0x03, 0xce, h[:44]), ax25(DST, SRC, 0x03, 0xce, b''),
           ax25(DST, SRC, 0x03, 0xce, b'short')]
    pcap(os.path.join(out, 'flexnet-coverage-malformed.pcap'), mal, 3)

if __name__ == '__main__':
    main(sys.argv[1])
