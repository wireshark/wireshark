#!/usr/bin/env python3
# Generates test/captures/hclnfsd_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the HCLNFSD coverage captures.  Usage: mkhclnfsd.py <outdir>

HCLNFSD (Hummingbird NFS daemon, ONC RPC program 0x2f00dbad version 1)
over UDP.  Every packet is built with struct; nothing comes from a real
network.  The authentication ident is a made-up placeholder."""
import struct
import sys
import os

PROG = 0x2f00dbad
CLI = bytes([192, 0, 2, 1])
SRV = bytes([192, 0, 2, 2])
MAC_C = bytes.fromhex('020000000001')
MAC_S = bytes.fromhex('020000000002')
SPORT = 33333


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
    """NFS file handle: length followed by (placeholder) bytes."""
    return xs(bytes([fill]) * n)


def obscure(plain):
    """Inverse of hclnfsd_decode_obscure()."""
    out = bytearray()
    prev = 0xff
    for p in plain:
        c = p ^ prev
        out.append(c)
        prev = c
    return bytes(out)


class Cap:
    def __init__(self):
        self.frames = []
        self.xid = 0x1000
        self.t = 1700000000

    def add(self, fr):
        self.frames.append((self.t, fr))
        self.t += 1

    def call(self, proc, args, vers=1, port=SPORT):
        self.xid += 1
        hdr = u32(self.xid, 0, 2, PROG, vers, proc, 0, 0, 0, 0)
        self.add(udp_frame(True, port, 33334, hdr + args, self.xid))
        return self.xid

    def reply(self, xid, res, port=SPORT, accept=0):
        hdr = u32(xid, 1, 0, 0, 0, accept)
        self.add(udp_frame(False, 33334, port, hdr + res, xid + 0x100))

    def pair(self, proc, args, res, **kw):
        x = self.call(proc, args)
        self.reply(x, res)

    def write(self, path):
        with open(path, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            for t, fr in self.frames:
                f.write(struct.pack('<IIII', t, 0, len(fr), len(fr)) + fr)


def main(out):
    c = Cap()
    # 1-2 NULL
    c.pair(0, b'', b'')
    # 3-4 SPOOL_INQUIRE (reply handled as unknown)
    c.pair(1, u32(7) + fh(16), u32(0, 1, 2))
    # 5-6 SPOOL_FILE
    c.pair(2, xs('lp0') + xs('job0001.ps') + u32(3), b'')
    # 7-8 AUTHORIZE, disk request. The ident is printable (the dissector
    # takes its length from the escaped string, see the README); decoded
    # it is two bytes, a made-up user name, NUL and a made-up password
    # (a repeated byte decodes to NUL).
    ident = b'PQuiicktestxyzzy'
    c.pair(3, SRV + u32(4) + xs('C:') + xs(ident),
           u32(0, 1001, 100, 3, 100, 200, 300))
    # 9-10 AUTHORIZE, printer request, status != 0 (denied)
    c.pair(3, SRV + u32(3) + xs('lpt1') + xs(ident), u32(1))
    # 11-12 AUTHORIZE, ident of 3 bytes: the decoded username has no NUL,
    # the password is clamped to the end of the buffer
    c.pair(3, SRV + u32(4) + xs('D:') + xs(b'ABC'), u32(0, 5, 6, 0))
    # 13-16 AUTHORIZE, ident of 2 bytes and of 1 byte: not decoded
    c.pair(3, SRV + u32(4) + xs('E:') + xs(b'AB'), u32(1))
    c.pair(3, SRV + u32(4) + xs('F:') + xs(b'A'), u32(1))
    # 17-18 AUTHORIZE, ident without repeated bytes: the decoded buffer
    # has no NUL (fixed heap over-read)
    c.pair(3, SRV + u32(4) + xs('dev') + xs(b'abcdefghijklmnop'),
           u32(0, 1, 2, 0))
    # 19-20 AUTHORIZE, one byte ident (reproducer of the second case)
    c.pair(3, SRV + u32(4) + xs('dev') + xs(b'a'), u32(1))
    # 23-24 GRP_NAME_TO_NUMB
    c.pair(4, xs('staff'), u32(20))
    # 25-26 GRP_TO_NUMBER
    c.pair(5, u32(2, 20, 21), xs('staff'))
    c.pair(5, u32(0), xs('nogroup'))
    # 29-30 RETURN_HOST
    c.pair(6, CLI, xs('client1'))
    # 31-32 UID_TO_NAME
    c.pair(7, u32(2, 1001, 1002), u32(2) + xs('alice') + xs('bob'))
    # 33-34 NAME_TO_UID
    c.pair(8, xs('alice'), u32(1001))
    # 35-36 SHARE (disk, then printer request)
    share = u32(4, 0xabcd) + xs('lock-a') + fh(16) + xs(b'\x01\x02\x03') + \
        u32(2, 3, 0)
    c.pair(20, share, u32(4, 0xabcd, 0, 0x11))
    c.pair(20, u32(3, 0xabce) + xs('lock-b') + fh(8) + xs(b'') +
           u32(1, 1, 0), u32(3, 0xabce, 1, 0x12))
    # 39-40 UNSHARE
    c.pair(21, share, u32(4, 0xabcd, 0, 0x13))
    # 41-42 LOCK
    lock = u32(0, 0xbeef, 0, 1) + xs('lock-c') + fh(12) + xs(b'owner01') + \
        u32(0, 100, 200)
    c.pair(22, lock, u32(4, 0xbeef, 0))
    # 43-44 REMOVE
    c.pair(23, xs('lock-c') + u32(0), b'')
    # 45-46 UNLOCK
    unlock = u32(0, 0xbeef) + xs('lock-c') + fh(12) + xs(b'owner01') + \
        u32(0, 100, 200)
    c.pair(24, unlock, u32(4, 0xbeef, 0))
    # 47-48 GET_PRINTERS
    c.pair(30, b'', u32(2) + xs('lp0') + xs('Laser printer') +
           xs('lp1') + xs('Plotter'))
    c.pair(30, b'', u32(0))
    # 51-52 GET_PRINTQ with two jobs
    job = lambda jid, more: u32(jid) + xs('alice') + xs('-n1') + u32(1, 2, 1700000000, 4096, 1) + \
        xs('comment') + u32(more)
    c.pair(31, xs('lp0') + xs('alice'),
           u32(1) + xs('queue ok') + u32(0, 1, 1) + job(11, 1) + job(12, 0))
    # 53-54 GET_PRINTQ, no jobs
    c.pair(31, xs('lp1') + xs('bob'),
           u32(2) + xs('empty') + u32(1, 2, 0))
    # 55-56 CANCEL_PRJOB, ZAP_LOCKS (unknown argument layout)
    c.pair(32, u32(11), u32(0))
    c.pair(105, u32(0), u32(0))
    c.write(os.path.join(out, 'hclnfsd-coverage.pcap'))

    # malformed: paths that throw
    m = Cap()
    m.pair(3, SRV + u32(4) + xs('C:') + xs(obscure(b'\x01\x02user\0pw')),
           u32(0, 1, 2, 0))                           # non-printable ident
    m.pair(3, SRV + u32(4) + xs('G:') + xs(b''), u32(1))   # empty ident
    m.pair(3, SRV + u32(4) + xs('C:') + xs(b'PQuiicktestxyzzy'),
           u32(0, 1, 2, 0x7fffffff))                  # huge gid count
    m.pair(7, u32(0x7fffffff), u32(0x7fffffff))        # huge uid / user count
    m.pair(31, xs('lp0') + xs('a'), u32(1) + xs('q') + u32(0, 1, 1) + u32(9))
    m.pair(30, b'', u32(0x7fffffff))
    m.pair(5, u32(0x40000000), b'')
    m.pair(3, SRV + u32(4) + xs('C:'), b'\0\0')       # no ident
    m.pair(20, u32(4, 1), u32(4))                      # short share
    m.write(os.path.join(out, 'hclnfsd-coverage-malformed.pcap'))


main(sys.argv[1])
