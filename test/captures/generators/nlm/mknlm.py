#!/usr/bin/env python3
# Generates test/captures/nlm_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the NLM coverage captures.  Usage: mknlm.py <outdir> [-v]

NLM (Network Lock Manager, ONC RPC program 100021, versions 1-4) over
UDP.  Every packet is built with struct; nothing comes from a real
network.  File handles, owners and cookies are placeholders."""
import struct
import sys
import os

PROG = 100021
CLI = bytes([192, 0, 2, 1])
SRV = bytes([192, 0, 2, 2])
MAC_C = bytes.fromhex('020000000001')
MAC_S = bytes.fromhex('020000000002')

NULL, TEST, LOCK, CANCEL, UNLOCK, GRANTED = 0, 1, 2, 3, 4, 5
TEST_MSG, LOCK_MSG, CANCEL_MSG, UNLOCK_MSG, GRANTED_MSG = 6, 7, 8, 9, 10
TEST_RES, LOCK_RES, CANCEL_RES, UNLOCK_RES, GRANTED_RES = 11, 12, 13, 14, 15
SHARE, UNSHARE, NM_LOCK, FREE_ALL = 20, 21, 22, 23


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def udp_frame(to_server, sport, dport, payload, ipid):
    src, dst = (CLI, SRV) if to_server else (SRV, CLI)
    ms, md = (MAC_C, MAC_S) if to_server else (MAC_S, MAC_C)
    udp = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), ipid, 0, 64, 17,
                     0, src, dst)
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    return md + ms + b'\x08\x00' + ip + udp


def xs(s):
    if isinstance(s, str):
        s = s.encode()
    return struct.pack('!I', len(s)) + s + b'\0' * ((4 - len(s) % 4) % 4)


def u32(*v):
    return b''.join(struct.pack('!I', x) for x in v)


def fh(n, fill=0x5a):
    return xs(bytes([fill]) * n)


def lock(v, caller='client1.example', fhn=32, owner=b'owner-0001', svid=1234,
         off=0, ln=100):
    """struct nlm_lock (v4 has 64 bit offset and length)"""
    b = xs(caller) + fh(fhn) + xs(owner) + u32(svid)
    if v == 4:
        b += struct.pack('!QQ', off, ln)
    else:
        b += u32(off, ln)
    return b


def holder(v, excl=1, svid=77, owner=b'holder-77', off=10, ln=20):
    b = u32(excl, svid) + xs(owner)
    if v == 4:
        b += struct.pack('!QQ', off, ln)
    else:
        b += u32(off, ln)
    return b


class Cap:
    def __init__(self, xid=0x2000, t=1700000000):
        self.frames = []
        self.xid = xid
        self.t = t
        self.marks = []

    def mark(self, name):
        self.marks.append((name, len(self.frames) + 1))

    def add(self, fr):
        self.frames.append((self.t, fr))
        self.t += 1

    def call(self, v, proc, args, port=745):
        self.xid += 1
        hdr = u32(self.xid, 0, 2, PROG, v, proc, 0, 0, 0, 0)
        self.add(udp_frame(True, port, 4045, hdr + args, self.xid))
        return self.xid

    def reply(self, xid, res, port=745, accept=0):
        hdr = u32(xid, 1, 0, 0, 0, accept)
        self.add(udp_frame(False, 4045, port, hdr + res, xid + 0x100))

    def pair(self, v, proc, args, res):
        x = self.call(v, proc, args)
        self.reply(x, res)

    def write(self, path):
        with open(path, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            for t, fr in self.frames:
                f.write(struct.pack('<IIII', t, 0, len(fr), len(fr)) + fr)


def main_cap():
    c = Cap()
    ck = lambda n: xs(b'cookie%02d' % n)
    for v in (1, 2, 3, 4):
        c.mark('v%d' % v)
        c.pair(v, NULL, b'', b'')
        # TEST: exclusive, reply granted (no holder), reply denied (holder)
        c.pair(v, TEST, ck(1) + u32(1) + lock(v), ck(1) + u32(0))
        c.pair(v, TEST, ck(2) + u32(0) + lock(v, svid=5, off=4096, ln=0),
               ck(2) + u32(1) + holder(v))
        # LOCK: block, exclusive, reclaim, state; every status value
        c.pair(v, LOCK, ck(3) + u32(1, 1) + lock(v) + u32(0, 3), ck(3) + u32(0))
        c.pair(v, LOCK, ck(4) + u32(0, 0) + lock(v, off=200, ln=50) + u32(1, 4),
               ck(4) + u32(1))
        c.pair(v, LOCK, ck(5) + u32(1, 1) + lock(v) + u32(0, 3), ck(5) + u32(3))
        c.pair(v, CANCEL, ck(6) + u32(1, 1) + lock(v), ck(6) + u32(0))
        c.pair(v, CANCEL, ck(7) + u32(0, 0) + lock(v), ck(7) + u32(2))
        c.pair(v, UNLOCK, ck(8) + lock(v), ck(8) + u32(0))
        c.pair(v, UNLOCK, ck(9) + lock(v, fhn=8), ck(9) + u32(4))
        c.pair(v, GRANTED, ck(10) + u32(1) + lock(v), ck(10) + u32(5))
        c.pair(v, GRANTED, ck(11) + u32(0) + lock(v), ck(11) + u32(6))
        # async MSG forms: the reply of a MSG is void, the result follows
        # as a RES call with the same cookie
        for n, (m, r, body) in enumerate((
                (TEST_MSG, TEST_RES, u32(1) + lock(v)),
                (LOCK_MSG, LOCK_RES, u32(1, 1) + lock(v) + u32(0, 3)),
                (CANCEL_MSG, CANCEL_RES, u32(1, 1) + lock(v)),
                (UNLOCK_MSG, UNLOCK_RES, lock(v)),
                (GRANTED_MSG, GRANTED_RES, u32(1) + lock(v)))):
            cookie = ck(20 + n)
            c.pair(v, m, cookie + body, b'')
            if r == TEST_RES:
                res = cookie + u32(1) + holder(v, 0, 8, b'h8')
            else:
                res = cookie + u32(7 + n)
            c.pair(v, r, res, b'')
        c.pair(v, TEST_RES, ck(30) + u32(0), b'')
        if v >= 3:
            c.mark('v%d-share' % v)
            sh = lambda mode, acc, rec: (xs('client1.example') + fh(24) +
                                         xs(b'share-owner') + u32(mode, acc, rec))
            c.pair(v, SHARE, ck(40) + sh(1, 3, 0), ck(40) + u32(0, 1))
            c.pair(v, SHARE, ck(41) + sh(3, 2, 1), ck(41) + u32(1, 2))
            c.pair(v, UNSHARE, ck(42) + sh(0, 1, 0), ck(42) + u32(0, 3))
            c.pair(v, UNSHARE, ck(43) + sh(2, 0, 0), ck(43) + u32(9, 0xffffffff))
            c.pair(v, NM_LOCK, ck(44) + u32(1, 1) + lock(v) + u32(0, 9),
                   ck(44) + u32(10))
            c.pair(v, FREE_ALL, xs('client2.example') + u32(12), b'')
            c.pair(v, FREE_ALL, xs('') + u32(0), b'')
    return c


def msgres_cap():
    """The async MSG/RES matching code (preference nlm.msg_res_matching):
    reproducer of the swapped request_in / reply_in frame number types,
    duplicate cookies, unmatched RES calls and cookies of other lengths.
    Decodes cleanly, so it is part of the main capture."""
    c = Cap(0x3000, 1700001000)
    v = 4
    c.mark('msgres')
    ck = xs(b'matchme1')
    c.pair(v, LOCK_MSG, ck + u32(1, 1) + lock(v) + u32(0, 3), b'')
    c.pair(v, LOCK_RES, ck + u32(0), b'')
    # a cookie of 0 octets, one of 5 (padding) and one of 12
    for ckb in (b'', b'abcde', b'0123456789ab'):
        c.pair(v, TEST_MSG, xs(ckb) + u32(1) + lock(v), b'')
        c.pair(v, TEST_RES, xs(ckb) + u32(1) + holder(v), b'')
    # same cookie in two MSG calls: the second replaces the first
    c.pair(v, CANCEL_MSG, xs(b'dupcookie') + u32(1, 1) + lock(v), b'')
    c.pair(v, CANCEL_MSG, xs(b'dupcookie') + u32(1, 1) + lock(v), b'')
    c.pair(v, CANCEL_RES, xs(b'dupcookie') + u32(0), b'')
    # RES without a MSG, and a second RES for a cookie already answered
    c.pair(v, UNLOCK_RES, xs(b'nomsg') + u32(0), b'')
    c.pair(v, CANCEL_RES, xs(b'dupcookie') + u32(0), b'')
    # same bytes XOR to the same hash, different cookies: 'ab' and 'ba'
    c.pair(v, GRANTED_MSG, xs(b'ab') + u32(1) + lock(v), b'')
    c.pair(v, GRANTED_MSG, xs(b'ba') + u32(1) + lock(v), b'')
    c.pair(v, GRANTED_RES, xs(b'ba') + u32(0), b'')
    c.pair(v, GRANTED_RES, xs(b'ab') + u32(0), b'')
    # same hash (XOR of the octets) but another length: not a match
    c.pair(v, UNLOCK_MSG, xs(b'x') + lock(v), b'')
    c.pair(v, UNLOCK_RES, xs(b'xzz') + u32(0), b'')
    # an old protocol version too
    c.pair(1, LOCK_MSG, xs(b'v1cookie') + u32(1, 1) + lock(1) + u32(0, 1), b'')
    c.pair(1, LOCK_RES, xs(b'v1cookie') + u32(0), b'')
    return c


def malformed_cap():
    c = Cap(0x4000)
    v = 4
    ck = xs(b'c1')
    # truncated calls
    c.pair(v, TEST, ck + u32(1) + xs('client')[:6], b'')
    c.pair(v, LOCK, ck + u32(1, 1) + lock(v)[:-6], b'')
    c.pair(v, TEST, ck + u32(1) + lock(v), ck + u32(1) + holder(v)[:-5])
    c.pair(3, SHARE, ck + xs('c') + fh(8), ck)
    c.pair(3, FREE_ALL, xs('abc')[:5], b'')
    c.pair(1, TEST, ck + u32(1) + lock(1)[:-3], b'')
    c.pair(2, UNLOCK, ck + lock(2)[:-1], u32(0, 0)[:6])
    # cookie length larger than the packet: the matching code ignores it
    c.pair(v, TEST_MSG, struct.pack('!I', 5000) + b'abcd', b'')
    c.pair(v, TEST_RES, struct.pack('!I', 5000) + b'abcd', b'')
    c.pair(v, LOCK_MSG, struct.pack('!I', 0xffffffff), b'')
    c.pair(v, LOCK_RES, struct.pack('!I', 0xffffffff), b'')
    c.pair(v, LOCK_MSG, b'\0\0', b'')
    # file handle length larger than the packet
    c.pair(v, UNLOCK, ck + xs('c') + struct.pack('!I', 0x10000) + b'abcd', b'')
    # an empty call and reply, a short status
    c.pair(v, LOCK, b'', b'')
    c.pair(v, LOCK, ck + u32(1, 1) + lock(v) + u32(0, 3), ck)
    return c


if __name__ == '__main__':
    out = sys.argv[1]
    m = main_cap()
    m.frames.extend([])  # keep order
    n = msgres_cap()
    base = len(m.frames)
    m.frames += n.frames
    m.marks += [(k, base + i) for k, i in n.marks]
    m.write(os.path.join(out, 'nlm-coverage.pcap'))
    malformed_cap().write(os.path.join(out, 'nlm-coverage-malformed.pcap'))
    if '-v' in sys.argv:
        print(len(m.frames), 'frames in the main capture')
        for k, i in m.marks:
            print(k, i)
