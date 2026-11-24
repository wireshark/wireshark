#!/usr/bin/env python3
# Generates test/captures/ff_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures for the FF (FOUNDATION Fieldbus HSE)
dissector (packet-ff.c).
Usage: mkff.py <output directory>
FF is UDP ports 1089-1091 and 3622 and TCP port 1090 (registered by
default). Writes ff-coverage.pcap and ff-coverage-malformed.pcap."""
# shared helpers (copied into each generator)
import struct
import socket

def pcap(path, frames, linktype=1):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, fr in enumerate(frames):
            orig = len(fr)
            if isinstance(fr, tuple):      # (captured bytes, original length)
                fr, orig = fr
            f.write(struct.pack('<IIII', 1700000000 + i // 1000, 1000 * (i % 1000), len(fr), orig))
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
import random
import sys

# Message kinds (Protocol/Type byte, Service byte) and the shortest body
# length for which the message dissects without exceptions (found with
# ffsearch.py; all longer bodies also dissect cleanly).
MINLEN = {int(a, 16): int(b) for a, b in (x.split(':') for x in """0481:52 0483:0 0581:52 0583:0 0681:20 0683:20 0801:72 0802:100 0810:108 0883:0 088c:68 088e:96 088f:64 0983:108 098c:0 098e:8 098f:0 0a83:20 0a8c:20 0a8e:20 0a8f:20 0c00:4 0c01:8 0c02:8 0c10:8 0c11:4 0c12:8 0c70:20 0c80:0 0c81:0 0c82:4 0c83:4 0c84:8 0c87:4 0c88:4 0c89:4 0c8a:4 0c8b:8 0c8c:4 0c8d:4 0c8e:4 0c8f:4 0c90:4 0c91:4 0c92:4 0c93:4 0c94:4 0c95:4 0c96:4 0c97:4 0c98:8 0c99:8 0c9c:4 0c9d:4 0c9e:0 0c9f:4 0ca0:8 0ca1:4 0cd2:8 0cd3:8 0ce0:40 0d80:8 0d81:96 0d82:0 0d83:0 0d84:4 0d87:4 0d88:0 0d89:0 0d8a:4 0d8b:0 0d8c:0 0d8d:4 0d8e:0 0d8f:0 0d90:0 0d91:4 0d92:0 0d93:0 0d94:0 0d95:0 0d96:0 0d97:0 0d98:0 0d99:0 0d9c:0 0d9d:0 0d9e:0 0d9f:0 0da0:0 0da1:4 0dd2:0 0dd3:0 0de0:4 0e80:20 0e81:20 0e82:20 0e83:20 0e84:20 0e87:20 0e88:20 0e89:20 0e8a:20 0e8b:20 0e8c:20 0e8d:20 0e8e:20 0e8f:20 0e90:20 0e91:20 0e92:20 0e93:24 0e94:24 0e95:24 0e96:24 0e97:20 0e98:20 0e99:20 0e9c:20 0e9d:20 0e9e:24 0e9f:20 0ea0:20 0ea1:20 0ed2:20 0ed3:20 0ee0:20 1001:44 1081:0 1082:80 1083:0 1181:80 1182:80 1183:28 1281:20 1282:20 1283:20""".split())}
# kinds whose bodies must be all zero to dissect cleanly
ZONLY = {int(x, 16) for x in "0802 0810 0983 0c87 0c91 1001 1183".split()}

def udp_frame(payload, sport=40000, dport=1090):
    return eth(bytes.fromhex('020000000002'), bytes.fromhex('020000000001'), 0x0800,
               ip4('10.0.0.1', '10.0.0.2', 17, udp(sport, dport, payload)))

def ff(kind, body, options=0, fda=0x01020304, length=None, trailer=b''):
    msg = body + trailer
    if length is None:
        length = 12 + len(msg)
    return struct.pack('>BBBBII', 1, options, kind >> 8, kind & 0xff, fda, length) + msg

def fill(kind, pat, n):
    if pat == 'z' or kind in ZONLY:
        return bytes(n)
    if pat == 'a':
        return b'A' * n
    return bytes((i * 7 + 3) & 0xff for i in range(n))

def trailer_for(options):
    t = b''
    if options & 0x80: t += struct.pack('>I', 0x11223344)
    if options & 0x40: t += struct.pack('>I', 0x55667788)
    if options & 0x20: t += struct.pack('>Q', 0x0102030405060708)
    if options & 0x08: t += struct.pack('>I', 0x99aabbcc)
    return t

def main(out):
    F = []
    kinds = sorted(MINLEN)
    # 1: every message kind, a few body lengths and fill patterns, one
    #    message per UDP datagram
    for k in kinds:
        m = MINLEN[k]
        for pat, lens in (('z', (m, 36, 72, 120)), ('r', (m, 64))):
            if pat != 'z' and k in ZONLY:
                continue
            for n in lens:
                if n < m:
                    continue
                F.append(udp_frame(ff(k, fill(k, pat, n))))
    # 2: options: trailer fields (message number, invoke id, time stamp,
    #    extended control), padding bits, reserved bit
    for i, k in enumerate(kinds):
        for opt in ((0x80, 0x40, 0x20, 0x08, 0xe8, 0xf8, 0x03, 0x07, 0x10)[i % 9],):
            F.append(udp_frame(ff(k, fill(k, 'z', MINLEN[k] + 4), options=opt, trailer=trailer_for(opt)), dport=(1089, 1090, 1091, 3622)[i % 4]))
    for opt in (0x80, 0x40, 0x20, 0x08, 0xe8):
        F.append(udp_frame(ff(0x0c82, fill(0x0c82, 'z', 8), options=opt, trailer=trailer_for(opt))))
    # 3: several messages in one datagram; header-only messages (SM
    #    Identify Request has an empty body) in the middle and at the end
    #    of a datagram (these were skipped before the fix)
    idreq = ff(0x0883, b'')
    F.append(udp_frame(idreq))
    F.append(udp_frame(idreq + idreq, dport=1091))
    F.append(udp_frame(ff(0x0c80, b'') + idreq + ff(0x0c82, bytes(8)) + idreq, dport=1090))
    F.append(udp_frame(ff(0x0481, bytes(52)) + ff(0x0483, b'') + ff(0x0c81, b'')))
    # a datagram with trailing padding after the last message
    F.append(udp_frame(ff(0x0c82, bytes(8)) + b'\0\0\0'))
    # 4: unknown protocol ids, types and services
    for kind in (0x0000, 0x0001, 0x0480, 0x0485, 0x0800, 0x0804, 0x0880, 0x0b01, 0x0c55, 0x0cff, 0x0f00, 0x1480, 0x1002, 0x1084, 0x1301, 0x2000, 0xfc83, 0x0382):
        F.append(udp_frame(ff(kind, bytes(range(16)))))
    # 5: FMS over TCP (port 1090): reassembly, several messages per segment
    f = Flow(50100, 1090, F); f.open()
    tm = [ff(0x0ce0, fill(0x0ce0, 'z', 40)), ff(0x0de0, fill(0x0de0, 'z', 4)), ff(0x0c82, bytes(8)),
          ff(0x0d82, bytes(40), options=0x80, trailer=trailer_for(0x80)), ff(0x0c80, b''),
          ff(0x0d80, fill(0x0d80, 'r', 48)), ff(0x0c70, bytes(20))]
    f.c2s(tm[0] + tm[1]); f.ack_s()                 # two messages in one segment
    f.c2s(tm[2][:7]); f.ack_s()                     # a message split over three segments
    f.c2s(tm[2][7:15]); f.ack_s()
    f.c2s(tm[2][15:] + tm[3][:20]); f.ack_s()       # end of one, start of the next
    f.c2s(tm[3][20:] + tm[4]); f.ack_s()
    f.s2c(tm[5]); f.ack_c()
    f.s2c(tm[6][:12]); f.ack_c()                    # exactly the header, then the body
    f.s2c(tm[6][12:]); f.ack_c()
    f.close()
    # TCP, port 1089 and 1091 (no dissector registered for the others'
    # ports, a single segment each)
    for p in (1089, 1091, 3622):
        f = Flow(50200 + p % 7, p, F); f.open()
        f.c2s(ff(0x0883, b'')); f.ack_s()
        f.close()
    # the reproducer for the "Message Length" with the longest trailer:
    # a correct length keeps the trailer visible (the incorrect one is in
    # the malformed capture)
    F.append(udp_frame(ff(0x0883, b'', options=0xf8, trailer=b'\x11' * 20), dport=1091))
    # 6: lists with entries: the count is placed at its offset in the body
    #    (the FDA address selects the link id or the node address format)
    def with_count(kind, total, off, width, count, fda=0x01020304):
        b = bytearray(total)
        b[off:off + width] = count.to_bytes(width, 'big')
        for i in range(off + width, min(total, off + width + 4 * count)):
            b[i] = (i * 3 + 1) & 0xff
        return udp_frame(ff(kind, bytes(b), fda=fda))
    for fda in (0x00000004, 0x01020304, 0x00020304):
        F.append(with_count(0x0983, 108 + 12, 104, 4, 3, fda))   # SM Identify response, version number list
        F.append(with_count(0x0810, 108 + 12, 104, 4, 3, fda))   # SM Device Annunciation
        F.append(with_count(0x0983, 108 + 4, 104, 4, 1, fda))
    for cnt in (1, 2, 3):
        F.append(with_count(0x1001, 44 + 16 * cnt, 42, 2, cnt))  # LAN Redundancy Diagnostic Message, interface statuses
        F.append(with_count(0x1183, 28 + 4 * cnt, 24, 4, cnt))   # LAN Redundancy Get Statistics response
        F.append(with_count(0x0c91, 4 + 4 * cnt, 2, 2, cnt))     # FMS Create PI request, domain indexes
        F.append(with_count(0x0c87, 4 + 4 * cnt, 0, 4, cnt))     # FMS Define Variable List request
        F.append(with_count(0x0802, 100 + 2 * cnt, 98, 2, cnt))  # SM Find Tag Reply, FDA address selectors
    # error class and code names for every error class
    errkinds = [k for k in kinds if (k >> 8) in (0x06, 0x0a, 0x0e, 0x12)]
    for i, k in enumerate(errkinds):
        for cls in range(0, 13):
            if (i + cls) % 6:
                continue
            F.append(udp_frame(ff(k, bytes([cls, (i + cls) % 5]) + bytes(max(0, MINLEN[k] - 2)))))
    for cls in range(1, 13):
        F.append(udp_frame(ff(0x0e82, bytes([cls, 1, 0, 0]) + bytes(16))))
        F.append(udp_frame(ff(0x0e82, bytes([cls, 40, 0, 0]) + bytes(16))))
    # FDA services with the unconfirmed flag
    for kind in (0x0401, 0x0402, 0x0501, 0x0601):
        F.append(udp_frame(ff(kind, bytes(range(16)))))
    pcap(os.path.join(out, 'ff-coverage.pcap'), F)

    # malformed: Message Length smaller than header + trailer, seeded
    # random bodies for every kind and a few length / count extremes
    random.seed(20261104)
    M = []
    M.append(udp_frame(ff(0x0883, b'\0' * 8, options=0xf8, length=20) + b'\0' * 4, dport=1091))   # length wrap reproducer
    M.append(udp_frame(ff(0x0c82, b'\0' * 40, options=0xff, length=20)))
    M.append(udp_frame(ff(0x0c82, b'', options=0xff, length=12)))
    M.append(udp_frame(ff(0x0c82, bytes(8), length=11)))                  # shorter than the header
    M.append(udp_frame(ff(0x0c82, bytes(8), length=500)))                 # longer than the datagram
    M.append(udp_frame(ff(0x0c82, bytes(8))[:10]))                         # header cut short
    for k in kinds:
        for n in (0, 4, 12, 40, 120):
            M.append(udp_frame(ff(k, bytes(random.getrandbits(8) for _ in range(n)), options=random.choice([0, 0, 0x80, 0xff]))))
        for _ in range(3):
            body = bytearray(random.getrandbits(8) for _ in range(160))
            for o in range(0, 160, 2):
                if random.random() < 0.15:
                    body[o:o + 2] = b'\xff\xff'
            M.append(udp_frame(ff(k, bytes(body))))
        M.append(udp_frame(ff(k, bytes(range(255, 255 - 120, -1)))))
        M.append(udp_frame(ff(k, b'\xff' * 60)))
    # a datagram captured with a snap length that cuts the FF header
    fr = udp_frame(ff(0x0c82, bytes(8)) + ff(0x0c82, bytes(8)))
    M.append((fr[:14 + 20 + 8 + 20 + 6], len(fr)))
    # FMS over TCP: a message length of 0 / 4 / huge in the header
    f = Flow(50300, 1090, M); f.open()
    f.c2s(ff(0x0c82, bytes(8), length=0)); f.ack_s()
    f.c2s(ff(0x0c82, bytes(8), length=0xffffffff)); f.ack_s()
    f.close()
    pcap(os.path.join(out, 'ff-coverage-malformed.pcap'), M)

if __name__ == '__main__':
    main(sys.argv[1])
