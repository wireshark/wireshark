#!/usr/bin/env python3
# Generates test/captures/finger_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures for the Finger dissector (packet-finger.c).
Usage: mkfinger.py <output directory>
Finger runs over TCP port 79 (registered by default). Writes
finger-coverage.pcap and finger-coverage-malformed.pcap."""
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

def main(out):
    fr = []
    # 1: query and a multi-segment response closed by FIN (reassembled
    #    until FIN), then a second query on the same connection
    f = Flow(40001, 79, fr); f.open()
    f.c2s(b'alice\r\n')
    f.ack_s()
    f.s2c(b'Login: alice           Name: Alice Example\r\n')
    f.ack_c()
    f.s2c(b'Directory: /home/alice  Shell: /bin/sh\r\n')
    f.ack_c()
    f.s2c(b'No mail.\r\nNo Plan.\r\n')
    f.ack_c()
    f.close()
    # 2: query split over two segments (desegment one more segment),
    #    response in one segment that carries the FIN
    f = Flow(40002, 79, fr); f.open()
    f.c2s(b'/W bo')
    f.ack_s()
    f.c2s(b'b@host.example\r\n')
    f.ack_s()
    f.fin_s(b'Login: bob\r\nOn since Mon Nov  2 09:00 on tty1\r\n')
    f.fin_c(); f.ack_s()
    # 3: empty query (list users) and an empty response closed by FIN
    f = Flow(40003, 79, fr); f.open()
    f.c2s(b'\r\n')
    f.ack_s()
    f.s2c(b'Login     Name       TTY   Idle\r\n')
    f.ack_c()
    f.close()
    # 4: only the response side of a connection is in the capture
    f = Flow(40004, 79, fr, cseq=7000, sseq=9000)
    f.s2c(b'orphan response\r\n')
    f.ack_c()
    f.fin_s(b'last line\r\n')
    f.fin_c(); f.ack_s()
    # 5: query that is answered by an immediate close (no data)
    f = Flow(40005, 79, fr); f.open()
    f.c2s(b'nobody\r\n')
    f.ack_s()
    f.close()
    # 6: a second query on the same connection after the response
    f = Flow(40006, 79, fr); f.open()
    f.c2s(b'carol\r\n')
    f.ack_s()
    f.s2c(b'Login: carol\r\n')
    f.ack_c()
    f.c2s(b'dave\r\n')
    f.ack_s()
    f.fin_s(b'Login: dave\r\n')
    f.fin_c(); f.ack_s()
    pcap(os.path.join(out, 'finger-coverage.pcap'), fr)

    mal = []
    # query without CR LF, followed by FIN so it is never completed
    f = Flow(41001, 79, mal); f.open()
    f.c2s(b'erin')
    f.ack_s()
    f.s2c(b'Login: erin\r\n')
    f.close()
    # a one octet query
    f = Flow(41002, 79, mal); f.open()
    f.c2s(b'x')
    f.ack_s()
    f.fin_s(b'response\r\n')
    f.fin_c(); f.ack_s()
    # a lone CR at the end of the query
    f = Flow(41003, 79, mal); f.open()
    f.c2s(b'frank\r')
    f.ack_s()
    f.fin_s(b'response\r\n')
    f.fin_c()
    pcap(os.path.join(out, 'finger-coverage-malformed.pcap'), mal)

if __name__ == '__main__':
    main(sys.argv[1])
