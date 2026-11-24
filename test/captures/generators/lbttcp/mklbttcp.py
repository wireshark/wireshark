#!/usr/bin/env python3
# Generates test/captures/lbttcp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Build the LBT-TCP (Ultra Messaging TCP transport) coverage captures.
# Usage: mklbttcp.py <outdir> [-v]
# Transport source ports are 14371-14390, request ports 14391-14395 (the
# defaults the heuristic looks for).  The LBMC messages are the minimum that
# makes the LBT-TCP code run; LBMC itself is covered by its own capture.
import struct
import sys
import os

OUT = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('-') else '.'
VERBOSE = '-v' in sys.argv


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ip4(a):
    return bytes(int(x) for x in a.split('.'))


class Cap:
    def __init__(self):
        self.pk = []
        self.notes = []

    def add(self, d):
        self.pk.append(d)
        return len(self.pk)

    def mark(self, label):
        self.notes.append((len(self.pk) + 1, label))

    def write(self, path):
        with open(path, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
            for i, d in enumerate(self.pk):
                f.write(struct.pack('<IIII', 1700000000 + i // 1000, (i % 1000) * 1000, len(d), len(d)))
                f.write(d)


class Tcp:
    '''One TCP connection. Direction 0 is the connecting side (client)
    unless the caller says otherwise: a is (ip, port) of side 0.'''

    def __init__(self, cap, a, b):
        self.cap = cap
        self.a = [a, b]
        self.seq = [1000, 5000]
        self.ipid = 1

    def seg(self, d, flags, payload=b''):
        (si, sp), (di, dp) = self.a[d], self.a[1 - d]
        tcp = struct.pack('!HHIIBBHHH', sp, dp, self.seq[d], self.seq[1 - d] if flags & 0x10 else 0,
                          0x50, flags, 65535, 0, 0) + payload
        ph = ip4(si) + ip4(di) + struct.pack('!BBH', 0, 6, len(tcp))
        tcp = tcp[:16] + struct.pack('!H', csum(ph + tcp)) + tcp[18:]
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), self.ipid, 0, 64, 6, 0, ip4(si), ip4(di))
        ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
        self.ipid += 1
        eth = bytes([2, 0, 0, 0, 0, ip4(di)[3]]) + bytes([2, 0, 0, 0, 0, ip4(si)[3]]) + b'\x08\x00'
        return self.cap.add(eth + ip + tcp)

    def handshake(self):
        self.seg(0, 0x02); self.seq[0] += 1
        self.seg(1, 0x12); self.seq[1] += 1
        self.seg(0, 0x10)

    def send(self, d, payload):
        n = self.seg(d, 0x18, payload)
        self.seq[d] += len(payload)
        return n


# ---- LBMC messages ---------------------------------------------------------
NH_TCP_SID = 0x6B


def tcp_sid(sid, nxt=0, flags=0, hlen=8):
    return struct.pack('!BBHI', nxt, hlen, flags, sid)


def msg(data=b'payload', tidx=1, sqn=1, typ=0, sid=None, flags=0):
    hdrs = b''
    nhdr = 0
    if sid is not None:
        hdrs = tcp_sid(sid, flags=flags)
        nhdr = NH_TCP_SID
    body = hdrs + data
    return struct.pack('!BBHII', typ, nhdr, 12 + len(body), tidx, sqn) + body


def eot(tidx=1, sqn=1):
    return struct.pack('!BBHII', 0x01, 0, 12, tidx, sqn)


SRC = '192.0.2.1'
CL1 = '192.0.2.50'
CL2 = '192.0.2.51'


def build_main(c):
    c.mark('transport 1: source 192.0.2.1:14371, TCP SID 0x11223344 in the first message; client 1 (id 1)')
    t = Tcp(c, (SRC, 14371), (CL1, 41001))
    t.handshake()
    t.send(0, msg(b'first', 1, 1, sid=0x11223344))
    t.send(0, msg(b'second', 1, 2))
    t.send(0, msg(b'third', 2, 1) + msg(b'fourth', 2, 2))
    t.send(0, eot(1, 3))
    c.mark('client 1 to the source (destination port in the source range): transport client packets')
    t.send(1, msg(b'from client', 1, 1))
    t.send(1, eot(1, 2))
    c.mark('client 2 of the same transport (id 2)')
    t2 = Tcp(c, (SRC, 14371), (CL2, 41002))
    t2.handshake()
    t2.send(0, msg(b'to client 2', 1, 4))
    t2.send(0, msg(b'more', 1, 5))
    t2.send(1, msg(b'ack-ish', 1, 3))
    c.mark('transport 2: SID first seen in a message from the client side (destination port in range)')
    t3 = Tcp(c, (CL1, 41003), (SRC, 14372))
    t3.handshake()
    t3.send(0, msg(b'sid from client', 1, 1, sid=0x55667788))
    t3.send(1, msg(b'reply', 1, 1))
    t3.send(0, msg(b'next', 1, 2))
    c.mark('transport 3: a second SID for the same source address and port (new session, new channel)')
    t4 = Tcp(c, (SRC, 14372), (CL2, 41004))
    t4.handshake()
    t4.send(0, msg(b'sid again', 1, 1, sid=0x55667788))
    t4.send(0, msg(b'other sid', 1, 2, sid=0x66778899))
    t4.send(0, msg(b'after', 1, 3))
    c.mark('transport 4: TCP SID with the ignore flag; source port 14390 (last of the range)')
    t5 = Tcp(c, (SRC, 14390), (CL1, 41005))
    t5.handshake()
    t5.send(0, msg(b'ignore flag', 1, 1, sid=0x01020304, flags=0x8000))
    t5.send(0, msg(b'x', 1, 2))
    c.mark('PDU split over two and three segments, two PDUs in one segment, PDU boundary mid segment')
    t6 = Tcp(c, (SRC, 14373), (CL1, 41006))
    t6.handshake()
    t6.send(0, msg(b'sid', 1, 1, sid=0x0a0b0c0d))
    big = msg(b'B' * 200, 1, 2)
    t6.send(0, big[:20]); t6.send(0, big[20:100]); t6.send(0, big[100:])
    a = msg(b'one', 1, 3); b = msg(b'two-two-two', 1, 4)
    t6.send(0, a + b[:7]); t6.send(0, b[7:])
    t6.send(0, msg(b'p', 1, 5) + msg(b'q', 1, 6) + msg(b'r', 1, 7))
    c.mark('UIM stream: destination port 14391 (request port range), not a transport')
    u = Tcp(c, (CL1, 41007), (SRC, 14391))
    u.handshake()
    u.send(0, msg(b'uim request', 1, 1))
    u.send(1, msg(b'uim response', 1, 1))
    u.send(0, msg(b'uim msg', 1, 2) + eot(1, 3))
    u2 = Tcp(c, (CL2, 41008), (SRC, 14395))
    u2.handshake()
    u2.send(0, msg(b'last request port', 1, 1, sid=0x7f7f7f7f))
    c.mark('message types: EOT, PRORX, RETRANS as PDU types in a transport stream')
    t7 = Tcp(c, (SRC, 14374), (CL1, 41009))
    t7.handshake()
    t7.send(0, msg(b'sid', 1, 1, sid=0x0000ff00))
    t7.send(0, msg(b'', 1, 2, typ=0x02))
    t7.send(0, msg(b'', 1, 3, typ=0x0A))
    t7.send(0, eot(1, 4))
    c.mark('end of main capture')


def build_malformed(c):
    c.mark('transport without any TCP SID: channel created on the second pass only (one-pass and -2 output differ)')
    t = Tcp(c, (SRC, 14375), (CL1, 41101))
    t.handshake()
    for i in range(3):
        t.send(0, eot(1, i + 1))
    t.send(1, eot(1, 9))
    t2 = Tcp(c, (CL2, 41102), (SRC, 14375))
    t2.send(0, eot(2, 1))
    t2.send(1, eot(2, 2))
    c.mark('LBMC header with zero length, length smaller than the header, truncated PDU at the end')
    t3 = Tcp(c, (SRC, 14376), (CL1, 41103))
    t3.handshake()
    t3.send(0, msg(b'sid', 1, 1, sid=0x12121212))
    t3.send(0, struct.pack('!BBHII', 0, 0, 0, 1, 1))
    t3.send(0, struct.pack('!BBHII', 0, 0, 4, 1, 1))
    t3.send(0, msg(b'long')[:10])
    c.mark('TCP SID header cut short, zero length, with next header; SID header only')
    t4 = Tcp(c, (SRC, 14377), (CL1, 41104))
    t4.handshake()
    t4.send(0, struct.pack('!BBHII', 0, NH_TCP_SID, 14, 1, 1) + b'\0\x08')
    t4.send(0, struct.pack('!BBHII', 0, NH_TCP_SID, 12, 1, 1))
    t4.send(0, struct.pack('!BBHII', 0, NH_TCP_SID, 16, 1, 1) + tcp_sid(1, hlen=0))
    t4.send(0, struct.pack('!BBHII', 0, NH_TCP_SID, 20, 1, 1) + tcp_sid(2, nxt=0x6B) + tcp_sid(3))
    c.mark('heuristic rejects: ports outside the ranges, LBMC header not valid, empty length')
    r = Tcp(c, (SRC, 14500), (CL1, 41105))
    r.handshake()
    r.send(0, msg(b'wrong port', 1, 1))
    r2 = Tcp(c, (SRC, 14380), (CL1, 41106))
    r2.send(0, b'\x40\x00\x00\x0c' + b'\0' * 8)             # version 4
    r2.send(0, b'\x05\x00\x00\x0c' + b'\0' * 8)             # unknown type
    r2.send(0, b'\x00\xff\x00\x0c' + b'\0' * 8)             # unknown next header
    r2.send(0, b'\x00\x00\x00\x00' + b'\0' * 8)             # zero length
    r2.send(0, b'\x00\x00\x00')                             # too short
    c.mark('end of malformed capture')


if __name__ == '__main__':
    os.makedirs(OUT, exist_ok=True)
    m = Cap(); build_main(m); m.write(os.path.join(OUT, 'lbttcp-coverage.pcap'))
    x = Cap(); build_malformed(x); x.write(os.path.join(OUT, 'lbttcp-coverage-malformed.pcap'))
    if VERBOSE:
        for name, cc in (('lbttcp-coverage.pcap', m), ('lbttcp-coverage-malformed.pcap', x)):
            print(name, len(cc.pk), 'frames')
            for n, l in cc.notes:
                print('  %4d  %s' % (n, l))
