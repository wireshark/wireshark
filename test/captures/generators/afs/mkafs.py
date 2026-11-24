#!/usr/bin/env python3
# AFS coverage capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""AFS (epan/dissectors/packet-afs.c).

AFS is carried in RX DATA packets over UDP (packet-rx.c registers the UDP
ports 7000-7009 and 7021).  The AFS dissector looks at the server port
(destination port of a request, source port of a reply) to pick the
service, and at the opcode of the request to decode the reply, so every
reply below follows its request in the same call (same addresses, ports,
epoch, connection id and call number).  The packet layouts follow what
packet-afs.c parses; places where that differs from what AFS sends are
marked "NOTE".

Usage: mkafs.py [<output directory>]

Writes:
  afs-coverage.pcap            every AFS service and every opcode with a
                               body the dissector parses, requests and
                               replies, UBIK, multi-packet calls (for the
                               afs.defragment preference), the Store ACL
                               requests of several sizes, and an RX abort
  afs-coverage-malformed.pcap  paths that end in an exception

Nothing needs to be enabled; afs.defragment changes how the multi-packet
calls are shown. Every packet is built here; nothing comes from a real
network.
"""

import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct

from capgen import eth, ipv4, udp, write_pcap  # noqa: E402

# ---------------------------------------------------------------------------
# Frames (Ethernet / IPv4 / UDP) and addresses

CLIENT = (10, 0, 0, 1)
SERVER = (10, 0, 0, 2)
CLIENT_PORT = 40000     # above all RX ports, so UDP picks the server port

PORT_FS, PORT_CB, PORT_PROT, PORT_VLDB, PORT_KAUTH = 7000, 7001, 7002, 7003, 7004
PORT_VOL, PORT_ERROR, PORT_BOS, PORT_UPDATE, PORT_RMTSYS = 7005, 7006, 7007, 7008, 7009
PORT_BACKUP, PORT_BUTC = 7021, 7025

RX_DATA, RX_ABORT = 1, 4
F_CLIENT, F_LAST = 0x01, 0x04


class Pcap:
    def __init__(self):
        self.frames = []

    def udp(self, payload, sport, dport, src, dst):
        # UDP checksum 0: not computed, allowed for IPv4
        seg = udp(payload, sport, dport)
        ip = ipv4(seg, 17, src=bytes(src), dst=bytes(dst), ident=len(self.frames) & 0xffff,
                  flags_frag=0x4000)
        self.frames.append(eth(ip, 0x0800, dst='02:00:00:00:00:02', src='02:00:00:00:00:01'))

    def write(self, path):
        write_pcap(path, self.frames, ts=lambda i: (1700000000 + i // 100, (i % 100) * 10000))


# ---------------------------------------------------------------------------
# RX

EPOCH = 1700000000
CID = 0x12345600


def rx(callnumber, seq, ptype, flags, payload, cid=CID, epoch=EPOCH, serial=None):
    return struct.pack('>IIIIIBBBBHH', epoch, cid, callnumber, seq,
                       seq if serial is None else serial,
                       ptype, flags, 0, 0, 0, 1) + payload


class Afs:
    """Builds AFS calls: a request from the client and a reply from the server."""
    def __init__(self, cap):
        self.cap = cap
        self.call = 0

    def new_call(self):
        self.call += 1
        return self.call

    def request(self, port, call, payload, seq=1, flags=F_CLIENT | F_LAST, cport=CLIENT_PORT, **kw):
        self.cap.udp(rx(call, seq, RX_DATA, flags, payload, **kw), cport, port, CLIENT, SERVER)

    def reply(self, port, call, payload, seq=1, flags=F_LAST, cport=CLIENT_PORT, ptype=RX_DATA, **kw):
        self.cap.udp(rx(call, seq, ptype, flags, payload, **kw), port, cport, SERVER, CLIENT)

    def rpc(self, port, opcode, req=b'', rep=None, cport=CLIENT_PORT):
        """One call: request with the opcode, then the reply (if rep is not None)."""
        c = self.new_call()
        self.request(port, c, u32(opcode) + req, cport=cport)
        if rep is not None:
            self.reply(port, c, rep, cport=cport)
        return c


# ---------------------------------------------------------------------------
# XDR helpers for the AFS structures packet-afs.c decodes

def u32(*v):
    return struct.pack('>%dI' % len(v), *[x & 0xffffffff for x in v])


def u64(v):
    return struct.pack('>Q', v)


def rxstr(s):
    """RX string: 4 byte length, data, padded to 4 octets."""
    if isinstance(s, str):
        s = s.encode()
    return u32(len(s)) + s + b'\0' * (-len(s) % 4)


def strv(s, n):
    """Fixed length vectorised string: one 32-bit word per character."""
    if isinstance(s, str):
        s = s.encode()
    s = s[:n] + b'\0' * (n - len(s[:n]))
    return b''.join(u32(c) for c in s)


def fid(vol=536870913, vnode=1, uniq=1):
    return u32(vol, vnode, uniq)


def store_status(mask=0x3f):
    return u32(mask, 1700000000, 1000, 100, 0o644, 0)


def fetch_status(ftype=1):
    return u32(1, ftype, 1, 4096, 7, 1000, 1000, 0x7f, 0x09, 0o755, 1, 1, 0,
               1700000000, 1700000100, 100, 0, 0, 0, 0, 0)


def callback(cbtype=1):
    return u32(1, 1700003600, cbtype)


def volsync():
    return u32(1700000000, 0, 0, 0, 0, 0)


def ubikver(epoch, counter):
    return u32(epoch, counter)


def ubik_debug_old():
    return (u32(1700000000, 1699999990, 0x0a000002, 1, 1700000005, 0x0a000002, 1699999000,
                0x0a000002, 1699999500)
            + ubikver(1690000000, 5) + ubikver(1690000000, 6)
            + u32(1, 1700000100, 3, 0, 0)
            + ubikver(0, 5)
            + u32(0, 7, 0, 0, 0x1f, 0, 0, 1690000000))


def ubik_sdebug_old():
    return u32(0x0a000003, 1700000000, 1700000001, 1) + ubikver(1690000000, 5) + u32(1, 0, 1)


def ubik_addrs():
    """255 interface addresses: a run of zeros, an address after a zero, and trailing zeros."""
    a = [0x0a000002, 0x0a000102, 0, 0, 0x0a000202] + [0] * 250
    return u32(*a)


def acl_text(*entries, pos=None, neg=0):
    """AFS ACL text: '<pos> <neg> <name> <rights> ...' (space separated)."""
    if pos is None:
        pos = len(entries) - neg
    return ('%d %d ' % (pos, neg) + ''.join('%s %d ' % e for e in entries)).encode()


def acl(text, size=None):
    return u32(len(text) if size is None else size) + text


# ---------------------------------------------------------------------------
# The services

def fs(a):
    P = PORT_FS
    st = fetch_status
    # 130 fetch-data
    a.rpc(P, 130, fid() + u32(0, 16), st() + callback() + volsync() + b'0123456789abcdef')
    # 131 fetch-acl.  NOTE: dissect_acl() leaves the cursor after the two
    # counts, not after the ACL, so the status and volsync that follow are
    # decoded from the ACL text.  The reply carries them after the ACL
    # anyway, as AFS sends them.
    a.rpc(P, 131, fid(), acl(acl_text(('system:administrators', 127), ('system:anyuser', 9)))
          + st() + volsync())
    # 132 fetch-status
    a.rpc(P, 132, fid(), st(2) + callback(2) + volsync())
    # 133 store-data
    a.rpc(P, 133, fid() + store_status() + u32(0, 8, 8) + b'datadata', st() + volsync())
    # 134 store-acl: ACL forms that reach each exit of dissect_acl()
    acls = [
        acl(acl_text(('alice', 1), ('bob', 127), ('eve', 4), neg=1)),          # positive and negative
        acl(acl_text(*[('u%d' % r, r) for r in (1, 2, 4, 8, 16, 32, 64, 0)])),  # each right alone
        acl(b'x'),                                                              # no positive count
        acl(b'1 '),                                                             # no negative count
        acl(b'2 0 alice 1 bob'),                                                # positive entry cut short
        acl(b'0 2 alice 1 bob'),                                                # negative entry cut short
        acl(acl_text(('alice', 1), ('bob', 2), pos=2), size=6),                 # datasize ends after 1st positive
        acl(acl_text(('alice', 1), ('bob', 2), neg=2), size=6),                 # datasize ends after 1st negative
        acl(b'1\n0\nsystem:administrators\t127\n'),                             # NOTE: newline separated, as
                                                                                # AFS sends it; only the
                                                                                # positive count is decoded
        acl(b'1 0 ' + b'n' * 140 + b' 1 '),                                     # name longer than 127
        acl(acl_text(('alice', 127), *[('n%d' % r, r) for r in (1, 2, 4, 8, 16, 32, 64)], neg=7)
            + b'zzzz'),                                                         # each negative right; both
                                                                                # loops end by count
        acl(acl_text(('alice', 3)) + b'zzzz'),                                  # positive only, ends by count
    ]
    for body in acls:
        a.rpc(P, 134, fid() + body, st() + volsync())
    # 135 store-status
    a.rpc(P, 135, fid() + store_status(0), st() + volsync())
    # 136 remove-file
    a.rpc(P, 136, fid() + rxstr('file.txt'), st() + volsync())
    # 137 create-file, 141 makedir
    a.rpc(P, 137, fid() + rxstr('new') + store_status(), fid(1, 2, 3) + st() + st(2) + callback() + volsync())
    a.rpc(P, 141, fid() + rxstr('newdir') + store_status(), fid(1, 4, 5) + st(2) + st(2) + callback() + volsync())
    # 138 rename
    a.rpc(P, 138, fid() + rxstr('old') + fid(1, 2, 2) + rxstr('newname'), st(2) + st(2) + volsync())
    # 139 symlink
    a.rpc(P, 139, fid() + rxstr('link') + rxstr('/afs/target') + store_status(), fid(1, 6, 6))
    # 140 link
    a.rpc(P, 140, fid() + rxstr('hard') + fid(1, 7, 7), st())
    # 142 rmdir
    a.rpc(P, 142, fid() + rxstr('olddir'), st(2) + volsync())
    # 143-145 old locks
    a.rpc(P, 143, fid() + u32(1) + volsync(), b'')
    a.rpc(P, 144, fid() + volsync(), b'')
    a.rpc(P, 145, fid() + volsync(), b'')
    # 146 get-stats
    a.rpc(P, 146, b'', b'')
    # 147 give-up-callbacks
    a.rpc(P, 147, u32(2) + fid() + fid(1, 2, 2) + u32(2) + callback() + callback(3), b'')
    # 148 get-volume-info, 154 nget-volume-info
    a.rpc(P, 148, rxstr('root.cell'), b'')
    a.rpc(P, 154, rxstr('root.afs'), b'')
    # 149 get-volume-status
    a.rpc(P, 149, u32(536870913), rxstr('root.cell') + rxstr('') + rxstr('message of the day'))
    # 150 set-volume-status
    a.rpc(P, 150, u32(536870913) + rxstr('root.cell') + rxstr('offline') + rxstr('motd'), b'')
    # 151 get-root-volume
    a.rpc(P, 151, b'', rxstr('root.afs'))
    # 152 check-token: 1024 words of token; a byte >0x7f is not UTF-8
    a.rpc(P, 152, u32(1000) + strv(b'token\xff', 1024), b'')
    # 153 get-time
    a.rpc(P, 153, b'', u32(1700000000, 500000))
    # 155 bulk-status
    a.rpc(P, 155, u32(2) + fid() + fid(1, 2, 2),
          u32(2) + st() + st(2) + u32(0) + u32(2) + callback() + callback(2) + volsync())
    # 156-158 locks
    a.rpc(P, 156, fid() + u32(1), volsync())
    a.rpc(P, 157, fid(), volsync())
    a.rpc(P, 158, fid(), volsync())
    # 159 xstats-version, 160 get-xstats
    a.rpc(P, 159, b'', u32(1))
    # 160 get-xstats: the reply's timestamp was added to an FT_UINT32 field
    # with ENC_TIME_SECS, which hit DISSECTOR_ASSERT_NOT_REACHED
    a.rpc(P, 160, u32(1, 2), u32(1, 1700000000))
    # 161 dfs-lookup
    a.rpc(P, 161, fid() + rxstr('name'), fid(1, 8, 8) + st() + st(2) + callback() + volsync())
    # 162 dfs-flushcps
    a.rpc(P, 162, bytes([2]) + u32(1000, 1001) + bytes([1]) + u32(0x0a000001) + u32(0), u32(0, 0))
    # 163 dfs-symlink
    a.rpc(P, 163, fid() + rxstr('sl') + rxstr('target') + store_status(),
          fid(1, 9, 9) + st(3) + st(2) + callback() + volsync())
    # 164 (unassigned): no body
    a.rpc(P, 164, b'', b'')
    # 220 residency
    a.rpc(P, 220, fid(), b'')
    # 65536 inline-bulk-status
    a.rpc(P, 65536, u32(1) + fid(), u32(1) + st() + u32(1) + callback() + volsync())
    # 65537 fetch-data-64, 65538 store-data-64
    a.rpc(P, 65537, fid() + u64(0) + u64(4096), st() + callback() + volsync())
    a.rpc(P, 65538, fid() + store_status() + u64(0) + u64(4) + u64(4), b'')
    # 65539 give-up-all-callbacks, 65540 get-capabilities, 65541, 65542
    for op in (65539, 65540, 65541, 65542):
        a.rpc(P, op, b'', b'')


def cb(a):
    P = PORT_CB
    # 204 callback
    a.rpc(P, 204, u32(2) + fid() + fid(1, 2, 2) + u32(2) + callback(1) + callback(3), b'')
    for op in (205, 206, 212, 214):
        a.rpc(P, op, b'', b'')
    # 65538 get-capabilities: interfaces and capabilities
    ifs = u32(2) + bytes(range(44)) \
        + u32(0x0a000001, 0x0a000101) + b'\0' * 120 \
        + u32(0xffffff00, 0xffff0000) + b'\0' * 120 \
        + u32(1500, 9000) + b'\0' * 120
    a.rpc(P, 65538, b'', ifs + u32(1, 1))


def prot(a):
    P = PORT_PROT
    a.rpc(P, 500, rxstr('newuser') + u32(1001, 0), b'')
    for op in (501, 506, 512):
        a.rpc(P, op, u32(1001), b'')
    a.rpc(P, 502, u32(3), b'')
    for op in (503, 507, 515):
        a.rpc(P, op, u32(1001, 0xfffffe00), b'')
    # 504 name-to-id
    a.rpc(P, 504, u32(2) + strv('alice', 64) + strv('bob', 64), u32(2, 1001, 1002))
    # 505 id-to-name
    a.rpc(P, 505, u32(2, 1001, 1002), u32(2) + strv('alice', 64) + strv('bob', 64))
    # 508, 514, 517, 518, 519: id list replies
    for op in (508, 514, 517, 519):
        a.rpc(P, op, u32(1001), u32(3, 1001, 0xfffffe00, 0xfffffe01))
    a.rpc(P, 518, u32(1001, 0x0a000001), u32(1, 1001))
    a.rpc(P, 509, rxstr('group:x') + u32(2, 1001), b'')
    a.rpc(P, 510, b'', u32(2000, 0xfffff000))
    a.rpc(P, 511, u32(2000, 0), b'')
    a.rpc(P, 513, u32(1001) + rxstr('renamed') + u32(1001, 1003), b'')
    a.rpc(P, 520, u32(1001) + rxstr('updated'), b'')
    a.rpc(P, 530, u32(1001), b'')


def vldb(a):
    P = PORT_VLDB
    name = strv('root.cell', 65)
    a.rpc(P, 501, name, b'')
    a.rpc(P, 517, name, b'')
    for op in (502, 507, 508, 509):
        a.rpc(P, op, u32(536870912, 0), b'')
    # 503 get-entry-by-id, 504 get-entry-by-name: old entry with 8 servers.
    # Server 1 has partition 30, which is above /vicepz and not shown.
    old = (name + u32(0) + u32(2) + u32(0x0a000002, 0x0a000003) + b'\0' * 24
           + u32(0, 30) + b'\0' * 24 + b'\0' * 32 + u32(536870912, 536870913, 536870914, 0) + u32(0x7))
    a.rpc(P, 503, u32(536870912, 0xffffffff), old)
    a.rpc(P, 504, rxstr('root.cell'), old)
    a.rpc(P, 505, u32(1), u32(536870915))
    a.rpc(P, 506, u32(536870912, 0) + name, b'')
    a.rpc(P, 520, u32(536870912, 1) + name, b'')
    a.rpc(P, 510, u32(0), u32(1, 1))
    a.rpc(P, 521, u32(0), u32(1, 2))
    a.rpc(P, 529, b'', u32(1, 3))
    # 518, 519: N entries with 13 servers
    nent = (name + u32(3) + u32(0x0a000002, 0x0a000003, 0x0a000004) + b'\0' * 40
            + u32(0, 25, 26) + b'\0' * 40 + b'\0' * 52 + u32(536870912, 536870913, 536870914))
    a.rpc(P, 518, u32(536870912, 2), nent)
    a.rpc(P, 519, rxstr('root.cell'), nent)
    # 526, 527: U entries with server UUIDs
    uent = (name + u32(1) + bytes(range(44)) + b'\0' * 44 * 12
            + u32(7) + b'\0' * 48
            + u32(30) + b'\0' * 48
            + u32(0x10) + b'\0' * 48
            + u32(536870912, 536870913, 536870914, 0, 7) + u32(*range(9)))
    uent2 = (name + u32(1) + bytes(range(44)) + b'\0' * 44 * 12
             + u32(7) + b'\0' * 48 + u32(2) + b'\0' * 48 + u32(0x10) + b'\0' * 48
             + u32(536870912, 536870913, 536870914, 0, 7) + u32(*range(9)))
    a.rpc(P, 526, u32(536870912, 0), uent)
    a.rpc(P, 527, rxstr('root.cell'), uent2)
    a.rpc(P, 524, rxstr('root.cell'), b'')
    # 532 regaddr
    a.rpc(P, 532, bytes(range(44)) + u32(0) + u32(2, 0x0a000002, 0x0a000102), b'')
    a.rpc(P, 514, b'', b'')


def kauth(a):
    P = PORT_KAUTH
    for op in (1, 21, 22, 2, 5, 6, 7, 8, 14, 15):
        a.rpc(P, op, rxstr('admin') + rxstr('EXAMPLE.ORG') + b'\x01\x02\x03\x04', b'')
    for op in (3, 23):
        a.rpc(P, op, u32(0) + rxstr('EXAMPLE.ORG') + u32(8) + b'ticket!!' + rxstr('afs') + rxstr(''), b'')
    a.rpc(P, 4, rxstr('admin') + rxstr('EXAMPLE.ORG') + u32(3), b'')
    a.rpc(P, 12, rxstr('admin'), b'')
    a.rpc(P, 9, b'', b'')


def vol(a):
    P = PORT_VOL
    a.rpc(P, 121, u32(1, 536870912), u32(1) + strv('root.cell', 32))
    a.rpc(P, 100, b'', b'')


def bos(a):
    P = PORT_BOS
    s = rxstr
    a.rpc(P, 80, s('simple') + s('ptserver') + s('/usr/afs/bin/ptserver') + s('') * 5, b'')
    for op in (81, 83, 85, 104):
        rep = {83: u32(1) + s('currently running normally'),
               85: s('simple') + b'\0' * 40}.get(op, b'')
        a.rpc(P, op, s('ptserver'), rep)
    a.rpc(P, 82, s('ptserver') + u32(1), b'')
    a.rpc(P, 84, u32(0), s('ptserver'))
    a.rpc(P, 86, s('ptserver') + u32(0), s('/usr/afs/bin/ptserver'))
    a.rpc(P, 87, s('admin'), b'')
    a.rpc(P, 88, s('admin'), b'')
    a.rpc(P, 89, u32(0), s('admin'))
    a.rpc(P, 90, u32(0), u32(3) + b'KEYKEYKE' + u32(1700000000, 0) + u32(0x1234, 0))
    a.rpc(P, 91, u32(4) + b'NEWKEY!!', b'')
    a.rpc(P, 92, u32(4), b'')
    a.rpc(P, 93, s('example.org'), b'')
    a.rpc(P, 94, b'', s('example.org'))
    a.rpc(P, 95, u32(0), s('afsdb1.example.org'))
    a.rpc(P, 96, s('afsdb2.example.org'), b'')
    a.rpc(P, 97, s('afsdb2.example.org'), b'')
    a.rpc(P, 98, s('ptserver') + u32(1), b'')
    for op in (99, 100, 101, 103, 113):
        a.rpc(P, op, b'', b'')
    a.rpc(P, 102, u32(0), b'')
    a.rpc(P, 105, s('/usr/afs/bin/bosserver') + u32(1024, 0, 1700000000), b'')
    a.rpc(P, 106, s('/usr/afs/bin/bosserver'), b'')
    a.rpc(P, 107, s('/usr/afs/bin/bosserver'), u32(1700000000, 1690000000, 1680000000))
    a.rpc(P, 108, s('/bin/true'), b'')
    a.rpc(P, 109, u32(7), b'')
    a.rpc(P, 110, u32(1) + b'\0' * 12, b'')
    a.rpc(P, 111, u32(1), b'\0' * 12)
    a.rpc(P, 112, s('BosLog'), b'Sun Jan  1 00:00:00 2023: Server started\n')
    a.rpc(P, 114, s('ptserver'), s('') + s('') + s('') + s(''))
    a.rpc(P, 116, b'', b'')


def ubik(a):
    # UBIK calls are recognised by opcode on any port; here the VLDB, PROT
    # and BOS servers.
    P = PORT_VLDB
    a.rpc(P, 10000, u32(1, 1700000000) + ubikver(1690000000, 5) + ubikver(0, 0), b'')
    a.rpc(P, 10001, b'', ubik_debug_old())
    a.rpc(P, 10002, u32(0x0a000003), ubik_sdebug_old())
    a.rpc(P, 10003, u32(0x0a000003), b'')
    a.rpc(PORT_PROT, 10004, u32(0x0a000003), ubik_debug_old() + ubik_addrs())
    a.rpc(PORT_PROT, 10005, u32(0x0a000003), ubik_sdebug_old() + ubik_addrs())
    a.rpc(P, 10006, b'', ubik_debug_old() + ubik_addrs() + u32(0))
    a.rpc(P, 10007, b'', ubik_sdebug_old() + ubik_addrs() + u32(1))
    tid = ubikver(1690000000, 9)
    a.rpc(P, 20000, tid, b'')
    a.rpc(P, 20001, tid, b'')
    a.rpc(P, 20002, tid + u32(0, 64, 128, 2), b'')
    a.rpc(P, 20003, tid + u32(0, 64), b'')
    a.rpc(P, 20004, b'', ubikver(1690000000, 5))
    a.rpc(P, 20005, u32(0), b'')
    a.rpc(P, 20006, u32(0, 4096) + ubikver(1690000000, 5), b'')
    for op in (20007, 20008, 20010):
        a.rpc(P, op, b'', b'')
    a.rpc(P, 20009, tid + u32(0, 64), b'')
    a.rpc(P, 20011, tid, b'')
    a.rpc(PORT_BOS, 20012, ubik_addrs(), ubik_addrs())
    a.rpc(P, 20013, tid + ubikver(1690000000, 5) + ubikver(1690000000, 6), b'')


def other_services(a):
    # ERROR, UPDATE and RMTSYS: no body dissector, only the opcode
    a.rpc(PORT_ERROR, 1, b'\0' * 4, b'')
    a.rpc(PORT_UPDATE, 1, rxstr('/usr/afs/bin'), b'')
    a.rpc(PORT_RMTSYS, 1, b'', b'')
    # BACKUP
    a.rpc(PORT_BACKUP, 100, b'\0' * 8, b'')
    # BUTC (7025 and up) is not an RX port: the client uses port 7008, which
    # UDP tries first because it is lower, and AFS then looks at 7025
    a.rpc(PORT_BUTC, 100, b'\0' * 8, b'', cport=PORT_UPDATE)
    # A server port that is no AFS service: 7010, again reached from 7008
    a.rpc(7010, 1, b'', b'', cport=PORT_UPDATE)
    # An opcode outside the valid ranges: shown as "Encrypted"
    a.rpc(PORT_FS, 70000, b'\x5a' * 16, b'\xa5' * 16)
    # A negative opcode is not valid either
    a.rpc(PORT_FS, 0x80000000, b'', b'')
    # Calls whose request keys hash alike (the hash is the sum of the
    # conversation, epoch, connection id and call number) but differ in the
    # epoch or the connection id: they must not be taken for each other
    for epoch, cid, call, op in ((EPOCH, CID, 5000, 132), (EPOCH + 1, CID, 4999, 153),
                                 (EPOCH, CID + 1, 4999, 151)):
        a.request(PORT_FS, call, u32(op) + (fid() if op == 132 else b''), epoch=epoch, cid=cid)
    for epoch, cid, call, rep in ((EPOCH, CID, 5000, fetch_status() + callback() + volsync()),
                                  (EPOCH + 1, CID, 4999, u32(1700000000, 0)),
                                  (EPOCH, CID + 1, 4999, rxstr('root.afs'))):
        a.reply(PORT_FS, call, rep, epoch=epoch, cid=cid)
    # A reply whose request is not in the capture: opcode 0
    a.reply(PORT_FS, 99999, b'\0' * 8)
    # An RX abort: RX dissects it, AFS is not called
    c = a.rpc(PORT_FS, 132, fid())
    a.reply(PORT_FS, c, u32(5), ptype=RX_ABORT)


def multi_packet(a):
    """Calls that span RX packets: reassembled with afs.defragment."""
    P = PORT_FS
    # store-data request in three packets
    c = a.new_call()
    body = u32(133) + fid() + store_status() + u32(0, 24, 24) + b'A' * 24
    # The first packet holds everything up to the data, so it also
    # dissects cleanly without reassembly
    a.request(P, c, body[:60], seq=1, flags=F_CLIENT)
    a.request(P, c, body[60:68], seq=2, flags=F_CLIENT)
    a.request(P, c, body[68:], seq=3, flags=F_CLIENT | F_LAST)
    a.reply(P, c, fetch_status() + volsync())
    # fetch-data reply in two packets
    c = a.new_call()
    a.request(P, c, u32(130) + fid() + u32(0, 64))
    rep = fetch_status() + callback() + volsync() + b'B' * 64
    a.reply(P, c, rep[:130], seq=1, flags=0)
    a.reply(P, c, rep[130:], seq=2, flags=F_LAST)
    # A request without the last packet flag that never completes
    c = a.new_call()
    a.request(P, c, u32(132) + fid(), seq=1, flags=F_CLIENT)
    # A packet with sequence number 0 and no last packet flag: with
    # afs.defragment the fragment number seq-1 wraps to 0xffffffff
    c = a.new_call()
    a.request(P, c, u32(132) + fid(), seq=0, flags=F_CLIENT)


def reproducers(a):
    """Store ACL requests of different sizes and padding."""
    P = PORT_FS
    # a small ACL
    a.rpc(P, 134, fid(1, 2, 3) + acl(b'2 1 alice 1 bob 127 eve 4 '))
    # positive count 2147483647 and a 20000 octet padded ACL.  With
    # zero padding it ends in an exception (see malformed()); here the
    # padding is spaces
    t = b'2147483647 0 a 0 ' + b' ' * 20000
    a.rpc(P, 134, fid(1, 2, 3) + acl(t))
    # the same with 47000 octets of 'a'
    t = b'2147483647 0 a 0 ' + b'a' * 47000
    a.rpc(P, 134, fid(1, 2, 3) + acl(t))
    # 16000 entries in one 64 KB datagram
    t = b'16000 0 ' + b'a 0 ' * 16000
    a.rpc(P, 134, fid(1, 2, 3) + acl(t))


def malformed(a):
    P = PORT_FS
    # positive count 2147483647 and 20000 zero
    # octets.  tvb_format_text() turns each zero into the 4 characters
    # "\\000", so dissect_acl() keeps finding 128 character "entries" and
    # steps through the packet 4 times too fast until an entry is added
    # past its end
    a.rpc(P, 134, fid(1, 2, 3) + acl(b'2147483647 0 a 0 ' + b'\0' * 20000))
    # fetch-data request cut short
    a.rpc(P, 130, fid()[:6])
    # kauth getticket with a ticket length beyond the packet
    a.rpc(PORT_KAUTH, 23, u32(0) + rxstr('X') + u32(0x7fffffff) + b'tk')
    # CB get-capabilities with more than 32 interfaces: NOTE the skip of
    # 4*(32-numint) octets goes backwards
    a.rpc(PORT_CB, 65538, b'', u32(40) + b'\0' * 44 + u32(*range(40)) * 3 + u32(1, 1))
    # PROT name-to-id with a huge count
    a.rpc(PORT_PROT, 504, u32(0xffffffff) + strv('alice', 64))
    # Store ACL with control characters in the name: tvb_format_text()
    # escapes them, so the text is longer than the packet data and the
    # entry is added past the end of the packet
    a.rpc(P, 134, fid() + acl(b'1 0 \x01\x01\x01\x01\x01\x01\x01\x01name 1 '))
    # A short RX data packet: no room for the opcode
    c = a.new_call()
    a.request(P, c, b'\0\0')


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    cap = Pcap()
    a = Afs(cap)
    for f in (fs, cb, prot, vldb, kauth, vol, bos, ubik, other_services, multi_packet, reproducers):
        f(a)
    cap.write(os.path.join(out, 'afs-coverage.pcap'))
    bad = Pcap()
    malformed(Afs(bad))
    bad.write(os.path.join(out, 'afs-coverage-malformed.pcap'))


if __name__ == '__main__':
    main()
