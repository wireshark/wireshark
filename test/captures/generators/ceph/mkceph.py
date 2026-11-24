#!/usr/bin/env python3
# Generates test/captures/ceph_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the Ceph dissector
(packet-ceph.c).

Ceph (msgr v1) is found by the TCP heuristic "ceph_tcp" (enabled by
default), which looks for the "ceph v" banner at the start of a segment.
Each side of a connection sends a banner and its addresses; the client also
sends a ceph_msg_connect, the server answers with a tag and a
ceph_msg_connect_reply. After that each side sends tagged items: MSG
(header, front, middle, data, footer), ACK, KEEPALIVE, KEEPALIVE2, CLOSE...
Every packet is built from scratch with struct; no captured traffic is used.
All addresses are from the documentation ranges.

Usage: mkceph.py <output directory>

Writes:
  ceph-coverage.pcap            client/monitor, client/OSD, monitor/monitor,
                                OSD/monitor and client/MDS connections with
                                every message type the dissector decodes,
                                connection setup variants (server or client
                                first, IPv4 and IPv6, SEQ, reply tags),
                                messages split over several TCP segments
                                and several messages in one segment, plus
                                the reproducers of the fixes on the branch
  ceph-coverage-malformed.pcap  the reproducers that throw, unknown tags,
                                wrong encoding versions, unused and overrun
                                data, an object locator with key and hash,
                                too many OSD ops, invalid banners, ...
"""

import os
import struct
import sys

def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


def ip4(s):
    return bytes(map(int, s.split('.')))


def mac(ip):
    return b'\x02\x00' + ip


def tcp_frame(src, dst, sport, dport, payload, seq, ack, flags=0x18, ident=1):
    opts = struct.pack('>BBHBBBB', 2, 4, 1460, 4, 2, 1, 1) if flags & 0x02 else b''
    tcp = struct.pack('>HHIIBBHHH', sport, dport, seq, ack, (5 + len(opts) // 4) << 4, flags,
                      65535, 0, 0) + opts
    pseudo = struct.pack('>4s4sBBH', src, dst, 0, 6, len(tcp) + len(payload))
    c = csum(pseudo + tcp + payload)
    tcp = tcp[:16] + struct.pack('>H', c) + tcp[18:]
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp) + len(payload), ident & 0xffff,
                     0x4000, 64, 6, 0, src, dst)
    ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
    return mac(dst) + mac(src) + b'\x08\x00' + ip + tcp + payload


class Capture:
    def __init__(self):
        self.frames = []

    def write(self, path):
        with open(path, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            for i, fr in enumerate(self.frames):
                f.write(struct.pack('<IIII', 1700000000 + i // 100, (i % 100) * 10000,
                                    len(fr), len(fr)))
                f.write(fr)


class Conn:
    """One TCP connection, with a handshake, so sequence numbers are
    tracked from the start. 'c' is the side that connects."""

    def __init__(self, cap, cip, cport, sip, sport, handshake=True):
        self.cap = cap
        self.c = (ip4(cip), cport)
        self.s = (ip4(sip), sport)
        self.seq = {True: 1000, False: 50000}
        if handshake:
            self.add(True, b'', 0x02)
            self.add(False, b'', 0x12)
            self.add(True, b'', 0x10)
        else:
            self.seq[True] += 1
            self.seq[False] += 1

    def add(self, from_client, data, flags=0x18):
        a, b = (self.c, self.s) if from_client else (self.s, self.c)
        ack = 0 if flags == 0x02 else self.seq[not from_client]
        self.cap.frames.append(tcp_frame(a[0], b[0], a[1], b[1], data, self.seq[from_client],
                                         ack, flags, ident=len(self.cap.frames) + 1))
        self.seq[from_client] += len(data) + (1 if flags & 0x03 else 0)

    def c2s(self, data):
        self.add(True, data)

    def s2c(self, data):
        self.add(False, data)

    def fin(self):
        self.add(True, b'', 0x11)
        self.add(False, b'', 0x11)
        self.add(True, b'', 0x10)


# ---------------------------------------------------------------- encoders

def u8(v): return struct.pack('<B', v)
def u16(v): return struct.pack('<H', v)
def u32(v): return struct.pack('<I', v & 0xffffffff)
def i32(v): return struct.pack('<i', v)
def u64(v): return struct.pack('<Q', v & 0xffffffffffffffff)
def i64(v): return struct.pack('<q', v)
def f64(v): return struct.pack('<d', v)


def cstr(s):
    if isinstance(s, str):
        s = s.encode()
    return u32(len(s)) + s


blob = cstr


def enc(ver, body, compat=None):
    return struct.pack('<BBI', ver, ver if compat is None else compat, len(body)) + body


def ts(sec, nsec=0):
    return struct.pack('<II', sec, nsec)


def sockaddr(af=0, port=0, ip='0.0.0.0'):
    if af == 2:
        b = struct.pack('>HH', 2, port) + ip4(ip)
    elif af == 10:
        b = struct.pack('>HHI', 10, port, 0) + bytes.fromhex(ip) + struct.pack('>I', 0)
    else:
        b = struct.pack('>H', af)
    return b + b'\0' * (128 - len(b))


def eaddr(af=2, port=0, ip='0.0.0.0', typ=0, nonce=0):
    return struct.pack('<II', typ, nonce) + sockaddr(af, port, ip)


def ename(typ, num):
    return struct.pack('<BQ', typ, num & 0xffffffffffffffff)


def pg(pool, seed, pref=-1):
    return struct.pack('<BqIi', 1, pool, seed, pref)


def ev(ver, epoch):
    return struct.pack('<QI', ver, epoch)


def paxos(ver=1, mon=0, tid=0):
    return struct.pack('<QHQ', ver, mon, tid)


FSID = bytes.fromhex('d1f2c3b4a5968778695a4b3c2d1e0f00')
IP6_MON = '20010db8000000000000000000000010'
IP6_CLI = '20010db8000000000000000000000001'

T_MON, T_MDS, T_OSD, T_CLIENT = 1, 2, 4, 8

BANNER = b'ceph v027'


def server_hello(saddr, caddr):
    return BANNER + saddr + caddr


def connect(features=0x3ffddff8eea4fffb, host_type=T_CLIENT, gseq=1, cseq=0, proto=24,
            auth_proto=2, auth=b'', flags=0):
    return (u64(features) + struct.pack('<IIIIII', host_type, gseq, cseq, proto, auth_proto,
                                        len(auth)) + u8(flags) + auth)


def client_hello(caddr, **kw):
    return BANNER + caddr + connect(**kw)


def connect_reply(tag=1, features=0x3ffddff8eea4fffb, gseq=2, cseq=1, proto=24, auth=b'',
                  flags=0):
    return u8(tag) + u64(features) + struct.pack('<IIII', gseq, cseq, proto, len(auth)) \
        + u8(flags) + auth


class Sender:
    """Builds MSG items for one side, with its entity name and sequence."""

    def __init__(self, typ, num):
        self.typ, self.num = typ, num
        self.seq = 0

    def msg(self, mtype, front=b'', middle=b'', data=b'', ver=1, tid=0, prio=127, compat=1,
            lens=None, flags=0):
        self.seq += 1
        fl, ml, dl = lens if lens else (len(front), len(middle), len(data))
        head = struct.pack('<QQHHH', self.seq, tid, mtype, prio, ver)
        head += struct.pack('<IIIH', fl, ml, dl, 0)
        head += ename(self.typ, self.num)
        head += struct.pack('<HHI', compat, 0, 0x12345678)
        foot = struct.pack('<IIIQB', 0x1111, 0x2222 if middle else 0, 0x3333 if data else 0,
                           0, flags)
        return b'\x07' + head + front + middle + data + foot


def tag_ack(seq):
    return b'\x08' + u64(seq)


def keepalive2(tag=0x0e, sec=1700000000):
    return u8(tag) + ts(sec, 5000)


# ---------------------------------------------------------------- structures

def monmap(nmons=2, epoch=3):
    body = FSID + u32(epoch) + u32(nmons)
    for i in range(nmons):
        body += cstr('abc'[i]) + eaddr(2, 6789, '192.0.2.%d' % (10 + i), 0, i)
    body += ts(1700000100) + ts(1700000000)
    e = enc(3, body)
    return u32(len(e)) + e


def snapinfo(sid, name):
    return enc(2, u64(sid) + ts(1700000200, 1) + cstr(name))


def hitset(kind):
    if kind == 0:
        return enc(1, u8(0))
    if kind == 1:
        return enc(1, u8(1) + enc(1, u64(16) + u32(2) + u32(0xaaaa) + u32(0xbbbb)))
    # Bloom filter: not decoded, skipped as a whole
    return enc(1, u8(3) + b'\x01\x01' + u32(4) + b'\0\0\0\0')


def pgpool(kind=0, snaps=1):
    b = u8(1) + u8(3) + u8(0) + u8(0) + u32(64) + u32(64) + b'\0' * 8
    b += u32(5) + u64(snaps) + u32(4)
    b += u32(snaps)
    for i in range(snaps):
        b += u64(i + 1) + snapinfo(i + 1, 'snap%d' % (i + 1))
    b += u32(1) + u64(10) + u64(12)                 # removed snaps
    b += u64(0) + u32(7) + u32(0) + u32(60) + u8(2)  # auid, flags, crash replay, min size
    b += u64(1 << 30) + u64(1000)                   # quotas
    b += u32(2) + u64(5) + u64(6)                   # tiers
    b += i64(-1) + u8(1) + i64(5) + i64(6)          # tier of, cache mode, read/write tier
    b += u32(1) + cstr('owner') + cstr('alice')     # properties
    b += hitset(kind)
    b += u32(3600) + u32(4) + u32(4096) + u64(1 << 40) + u64(1 << 20)
    b += u32(400000) + u32(800000) + u32(600) + u32(1200)
    b += cstr('default') + u32(9)
    return enc(15, b, 5)


def osdinfo():
    return u8(1) + struct.pack('<6I', 1, 2, 3, 4, 5, 6)


def xinfo(ver):
    b = ts(1700000300) + u32(0x8000) + u32(30)
    if ver >= 2:
        b += u64(0x3ffddff8eea4fffb)
    if ver >= 3:
        b += u32(0x10000)
    return enc(ver, b)


def osdmap(cver=3, pools=((1, 0), (2, 1), (3, 2))):
    c = FSID + u32(20) + ts(1700000000) + ts(1700000400)
    c += u32(len(pools))
    for pid, kind in pools:
        c += u64(pid) + pgpool(kind, snaps=1 if kind == 0 else 0)
    c += u32(2) + u64(1) + cstr('rbd') + u64(2) + cstr('data')
    c += u32(3) + u32(0) + u32(2)                    # pool max, flags, osd max
    c += u32(2) + b'\x03\x01'                         # osd state
    c += u32(2) + u32(0x10000) + u32(0x8000)          # weights
    c += u32(2) + eaddr(2, 6800, '192.0.2.20') + eaddr(2, 6801, '192.0.2.21')
    c += u32(1) + pg(1, 7) + u32(2) + u32(0) + u32(1)  # pg_temp
    c += u32(1) + pg(1, 8) + u32(1)                   # primary_temp
    if cver >= 2:
        c += u32(2) + u32(0x10000) + u32(0x10000)
    c += blob(b'CRUSHMAP')
    if cver >= 3:
        c += u32(1) + cstr('ec42') + u32(2) + cstr('k') + cstr('4') + cstr('m') + cstr('2')
    o = u32(1) + eaddr(2, 6802, '192.0.2.20')
    o += u32(2) + osdinfo() + osdinfo()
    o += u32(1) + eaddr(2, 0, '192.0.2.99') + ts(1700001000)
    o += u32(1) + eaddr(2, 6803, '198.51.100.20')
    o += u32(0) + cstr('snap')
    o += u32(1) + bytes(range(16))
    o += u32(2) + xinfo(3) + xinfo(1)
    o += u32(1) + eaddr(2, 6804, '192.0.2.20')
    e = enc(7, enc(cver, c, 1) + enc(1, o))
    return u32(len(e)) + e


def osdmap_inc():
    e = enc(7, enc(3, FSID, 1) + enc(1, b''))
    return u32(len(e)) + e


def oloc(ver=6, pool=1, key=b'', nspace=b'', hsh=-1):
    b = i64(pool) + i32(-1) + cstr(key)
    if ver >= 5:
        b += cstr(nspace)
    if ver >= 6:
        b += i64(hsh)
    return enc(ver, b, 3)


def osd_op(op, payload=0, flags=0, args=None):
    if args is None:
        args = u64(0) + u64(payload) + u64(0) + u32(0)
    assert len(args) == 28
    return u16(op) + u32(flags) + args + u32(payload)


OP_READ, OP_STAT, OP_WRITE, OP_WRITEFULL, OP_TRUNCATE, OP_ZERO, OP_DELETE = \
    0x1201, 0x1202, 0x2201, 0x2202, 0x2203, 0x2204, 0x2205
OP_CALL, OP_GETXATTR = 0x1401, 0x1301


def redirect(obj=b'', instr=b''):
    b = oloc(5, 7, b'', b'ns')
    b += cstr(obj) if obj else u32(0)
    b += blob(instr)
    return enc(1, b)


def statsum(ver):
    b = b''.join(u64(i + 1) for i in range(12))
    n = {3: 0, 4: 0, 5: 3, 6: 5, 7: 7, 8: 8, 9: 9}[ver]
    b += b''.join(u64(100 + i) for i in range(n))
    return enc(ver, b, 3)


def statcollection(cats=(), ver=9):
    b = statsum(ver) + u32(len(cats))
    for c in cats:
        b += cstr(c) + statsum(5)
    return enc(2, b)


def osd_stat(ver=4):
    b = u64(1 << 30) + u64(1 << 20) + u64((1 << 30) - (1 << 20)) + u32(3) + u32(1)
    b += u32(2) + u32(1) + u32(2) + u32(1) + u32(3)
    if ver >= 3:
        b += enc(1, u32(2) + u32(17) + u32(18))
    if ver >= 4:
        b += enc(1, u32(12) + u32(7))
    return enc(ver, b, 2)


def pg_stat(ver):
    b = ev(10, 20) + u64(5) + u32(20) + u32(2) + ev(1, 2) + ev(1, 3) + u32(4) + u32(19)
    b += pg(1, 3) + u32(4) + ev(9, 19) + ts(1700000500)
    b += statcollection(('cat',) if ver >= 10 else ())
    b += u64(100) + u64(99) + u32(2) + u32(0) + u32(1) + u32(1) + u32(0)
    if ver >= 9:
        b += ts(1) + ts(2) + ts(3) + ts(4) + ts(5) + u32(20)
    if ver >= 10:
        b += ev(8, 18) + ts(6)
    if ver >= 11:
        b += u8(0)
    if ver >= 12:
        b += ts(7)
    if ver >= 13:
        b += ts(8)
    if ver >= 14:
        b += u8(1)
    if ver >= 15:
        b += i32(0) + i32(0)
    if ver >= 16:
        b += u8(0)
    if ver >= 17:
        b += u8(1)
    return enc(ver, b, 8)


def featureset(names):
    b = u64(sum(1 << v for v, _ in names)) + u32(len(names))
    for v, n in names:
        b += u64(v) + cstr(n)
    return b


def superblock(ver):
    b = FSID + u32(0) + u32(20) + u32(1) + u32(20) + f64(1.0)
    b += featureset([(1, 'initial feature set(~v.18)')]) + featureset([]) \
        + featureset([(1, 'initial feature set(~v.18)'), (2, 'pginfo object')])
    b += u32(19) + u32(19)
    if ver >= 4:
        b += bytes(range(0x40, 0x50))
    if ver >= 6:
        b += u32(0)
    return enc(ver, b, 5)


def pg_create():
    return enc(1, u32(15) + pg(1, 0) + u32(3))


def mds_release(ino):
    return u64(ino) + u64(1) + struct.pack('<6I', 1, 2, 3, 4, 5, 6) + cstr('file')


def path(ino, rel):
    return u8(1) + u64(ino) + cstr(rel)


def entityinst(typ, num, ip):
    return ename(typ, num) + eaddr(2, 6789, ip)


# ---------------------------------------------------------------- messages
#  Each function returns (type, kwargs for Sender.msg)

def m_auth_none(epoch=True):
    payload = u8(1) + u32(2) + u32(2) + u32(1) + u32(8) + cstr('admin') + u64(0)
    f = paxos() + u32(0) + u32(len(payload)) + payload
    if epoch:
        f += u32(3)
    return 0x11, dict(front=f)


def m_auth_cephx():
    payload = u16(0x0100)
    return 0x11, dict(front=paxos() + u32(2) + u32(len(payload)) + payload)


def m_auth_reply():
    return 0x12, dict(front=u32(2) + i32(0) + u64(4100) + u32(0) + cstr(''))


# ---------------------------------------------------------------- captures

def reproducer_hello():
    """client_hello() of the reproducers (ceph_common.py)."""
    return BANNER + eaddr(0) + struct.pack('<QIIIIII', 0, 0, 0, 0, 0, 0, 0) + b'\0'


def reproducer_msg(mtype, front=b'', middle=b'', data=b'', ver=1, lens=None):
    fl, ml, dl = lens if lens else (len(front), len(middle), len(data))
    head = struct.pack('<QQHHH', 1, 1, mtype, 0, ver)
    head += struct.pack('<IIIH', fl, ml, dl, 0)
    head += struct.pack('<BQ', 8, 1)
    head += struct.pack('<HHI', 0, 0, 0)
    return b'\x07' + head + front + middle + data + b'\0' * 21


def repro_redirect_obj():
    p = pg(1, 0)
    ol = struct.pack('<BBI', 3, 3, 16) + struct.pack('<qiI', 1, -1, 0)
    rb = ol + struct.pack('<I', 3) + b'obj' + struct.pack('<I', 0)
    rd = struct.pack('<BBI', 1, 1, len(rb)) + rb
    front = (u32(0) + p + u32(0) + u32(0) + i32(0) + ev(0, 0) + u32(1) + u32(0) + u32(0)
             + ev(0, 0) + u64(0) + rd)
    front += b'\0' * 64
    return reproducer_msg(0x2B, front=front, ver=6)


def repro_pgstat_stats():
    p = pg(1, 0)
    e0 = ev(0, 0)
    ss = enc(3, b'\0' * 96)
    sc = enc(2, ss + u32(1) + cstr('cat') + ss)
    ps = enc(8, e0 + struct.pack('<QII', 0, 0, 0) + e0 + e0 + struct.pack('<II', 0, 0)
             + p + u32(0) + e0 + u64(0) + sc + struct.pack('<QQII', 0, 0, 0, 0))
    os_ = enc(2, struct.pack('<QQQII', 0, 0, 0, 0, 0) + struct.pack('<II', 0, 0))
    front = paxos(0) + b'\x33' * 16 + os_ + u32(1) + p + ps + struct.pack('<IQ', 0, 0)
    return reproducer_msg(0x57, front=front)


def repro_poolopreply_datai():
    front = paxos(0) + b'\x44' * 16 + struct.pack('<iIB', 0, 1, 1) + cstr('abc')
    return reproducer_msg(0x30, front=front)


def repro_msglen_wrap():
    return reproducer_msg(0x0002, lens=(0, 0, (1 << 32) - 75))


def repro_nosavedstate():
    h = reproducer_hello()
    h = h[:9 + 136 + 28] + struct.pack('<I', (1 << 32) - 178) + h[9 + 136 + 32:]
    return h


def repro_encoded_backwards():
    p = pg(1, 0)
    pgc = struct.pack('<BBI', 1, 1, (1 << 32) - 23) + u32(0) + p + u32(0)
    front = struct.pack('<QI', 1, 0xffffffff) + p + pgc
    return reproducer_msg(0x59, front=front)


def repro_snapinfo():
    f = bytearray()
    f += b'\x11' * 16 + u32(0) + u32(1) + u32(1)
    size_at = len(f); f += b'\0' * 4
    enc1_at = len(f); f += struct.pack('<BBI', 7, 7, 0)
    enc2_at = len(f); f += struct.pack('<BBI', 1, 1, 0)
    f += b'\x22' * 16 + u32(1) + b'\0' * 16
    f += u32(1) + u64(1)
    pool_at = len(f); f += struct.pack('<BBI', 5, 5, 0)
    f += bytes([1, 1, 0, 0]) + struct.pack('<II', 8, 8) + b'\0' * 8
    f += struct.pack('<IQI', 0, 0, 0) + u32(0xffffffff)
    P = len(f)
    f += u64(1) + struct.pack('<BBI', 2, 2, P) + struct.pack('<QII', 1, 0, 0) + u32(0)
    f += b'\0' * 400
    n = len(f)
    struct.pack_into('<I', f, size_at, n - size_at - 4)
    struct.pack_into('<I', f, enc1_at + 2, n - enc1_at - 6)
    struct.pack_into('<I', f, enc2_at + 2, n - enc2_at - 6)
    struct.pack_into('<I', f, pool_at + 2, n - pool_at - 6)
    return reproducer_msg(0x29, front=bytes(f))


def setup(cap, cip, cport, sip, sport, ctype, cnum, stype, snum, server_first=True, v6=False,
          seq=False, auth=b'', split_hello=False, split_reply=False):
    """Handshake plus the banner exchange; returns the connection and the
    two senders."""
    c = Conn(cap, cip, cport, sip, sport)
    if v6:
        sa = eaddr(10, sport, IP6_MON, 0, 7)
        ca = eaddr(10, cport, IP6_CLI, 0, 0)
    else:
        sa = eaddr(2, sport, sip, 0, 7)
        ca = eaddr(2, cport, cip, 0, 0)
    sh = server_hello(sa, ca)
    ch = client_hello(eaddr(2, 0, cip, 0, 1234), host_type=ctype, auth=auth)
    if server_first:
        c.s2c(sh)
        if split_hello:
            # 160 octets: enough to tell client from server, not enough for
            # the authorizer length; then the rest
            c.c2s(ch[:160])
            c.c2s(ch[160:])
        else:
            c.c2s(ch)
    else:
        if split_hello:
            # too short to tell client from server
            c.c2s(ch[:100])
            c.c2s(ch[100:])
        else:
            c.c2s(ch)
        c.s2c(sh)
    if seq:
        # The server knows this session: SEQ, then the client's sequence
        r = connect_reply(0x0d, auth=b'\xaa' * 4) + u64(7)
        if split_reply:
            c.s2c(r[:12])
            c.s2c(r[12:])
        else:
            c.s2c(r)
        c.c2s(u64(9))
    else:
        r = connect_reply(1, auth=b'\xbb' * 8 if auth else b'')
        if split_reply:
            c.s2c(r[:12])
            c.s2c(r[12:])
        else:
            c.s2c(r)
    return c, Sender(ctype, cnum), Sender(stype, snum)


def main_capture():
    cap = Capture()

    # ---- A: client.4100 <-> mon.0 (server speaks first, IPv4)
    c, cl, mon = setup(cap, '192.0.2.1', 41000, '192.0.2.10', 6789, T_CLIENT, 4100, T_MON, 0,
                       auth=b'AUTHORIZER')
    t, kw = m_auth_none()
    c.c2s(cl.msg(t, **kw))
    t, kw = m_auth_reply()
    c.s2c(mon.msg(t, **kw))
    t, kw = m_auth_cephx()
    c.c2s(cl.msg(t, **kw))
    t, kw = m_auth_reply()
    c.s2c(mon.msg(t, **kw) + tag_ack(2))
    # Mon subscribe and ack
    sub = u32(3) + cstr('monmap') + u64(0) + u8(0) + cstr('osdmap') + u64(20) + u8(0) \
        + cstr('mdsmap') + u64(0) + u8(1)
    c.c2s(cl.msg(0x0f, front=sub, ver=2))
    c.s2c(mon.msg(0x10, front=u32(300) + FSID))
    # Mon map
    c.s2c(mon.msg(0x04, front=monmap(3)))
    # Get version and reply
    c.c2s(cl.msg(0x13, front=u64(1) + cstr('osdmap')))
    c.s2c(mon.msg(0x14, front=u64(1) + u64(20) + u64(1)))
    # Stat FS and reply
    c.c2s(cl.msg(0x0d, front=paxos(0) + FSID))
    c.s2c(mon.msg(0x0e, front=FSID + u64(20) + u64(1 << 30) + u64(1 << 20) + u64(1 << 29)
                  + u64(42)))
    # OSD map: two incrementals and one full map (header version 3), sent
    # in three TCP segments
    front = FSID + u32(2) + u32(19) + osdmap_inc() + u32(20) + osdmap_inc() \
        + u32(1) + u32(20) + osdmap(3, ()) + u32(1) + u32(20)
    m = mon.msg(0x29, front=front, ver=3)
    c.s2c(m[:30])          # not even the lengths: one more segment
    c.s2c(m[30:700])
    c.s2c(m[700:])
    # OSD map, header version 1, client map version 1, no maps after it
    c.s2c(mon.msg(0x29, front=FSID + u32(0) + u32(1) + u32(21) + osdmap(1, ())))
    # MDS map
    c.s2c(mon.msg(0x15, front=FSID + u32(5) + blob(b'MDSMAPDATA')))
    # Pool operations, header versions 1-4, and replies with and without data
    c.c2s(cl.msg(0x31, front=paxos(20) + FSID + u32(3) + cstr('newpool') + u32(1) + u64(0)
                 + u64(0), ver=1))
    c.s2c(mon.msg(0x30, front=paxos(20) + FSID + i32(0) + u32(21) + u8(0)))
    c.c2s(cl.msg(0x31, front=paxos(21) + FSID + u32(3) + u32(0x11) + u64(0) + u64(0)
                 + cstr('newpool'), ver=2))
    c.c2s(cl.msg(0x31, front=paxos(22) + FSID + u32(3) + u32(0x21) + u64(0) + u64(5)
                 + cstr('newpool') + u8(2), ver=3))
    c.c2s(cl.msg(0x31, front=paxos(23) + FSID + u32(0) + u32(0x01) + u64(0) + u64(0)
                 + cstr('pool2') + u8(0) + u16(1), ver=4))
    c.s2c(mon.msg(0x30, front=paxos(23) + FSID + i32(0) + u32(22) + u8(1) + blob(b'\x05\0\0\0')))
    # Mon command and result (with data)
    c.c2s(cl.msg(0x32, front=paxos(0) + FSID + u32(2) + cstr('{"prefix": "status"}')
                 + cstr('{"format": "json"}')))
    c.s2c(mon.msg(0x33, front=paxos(0) + i32(0) + cstr('ok') + u32(1) + cstr('status'),
                  data=b'{"health": "HEALTH_OK"}'))
    # Pool stats and reply
    c.c2s(cl.msg(0x3a, front=paxos(0) + FSID + u32(2) + cstr('rbd') + cstr('data')))
    st = enc(5, statcollection(('cat1',), 9) + u64(100) + u64(90))
    st2 = enc(5, statcollection((), 3) + u64(10) + u64(9))
    c.s2c(mon.msg(0x3b, front=paxos(0) + FSID + u32(2) + cstr('rbd') + st + cstr('data') + st2))
    # Ping, an ACK, keepalives
    c.c2s(cl.msg(0x02) + tag_ack(5) + b'\x09' + keepalive2(0x0e))
    c.s2c(keepalive2(0x0f) + tag_ack(17))
    # A message type the dissector does not decode
    c.c2s(cl.msg(0x0050, front=b'\x01\x02\x03\x04', middle=b'\x05\x06', data=b'\x07'))
    # Close
    c.c2s(b'\x06')
    c.fin()

    # ---- B: client.4101 <-> osd.0 (IPv6 server hello, SEQ, split hello)
    c, cl, osd = setup(cap, '192.0.2.1', 41001, '192.0.2.20', 6800, T_CLIENT, 4101, T_OSD, 0,
                       v6=True, seq=True, split_hello=True, split_reply=True)
    # OSD op: write (64 octets) and read, object locator v6 with hash,
    # header version 4
    ops = osd_op(OP_WRITE, 64) + osd_op(OP_READ, 0, args=u64(0) + u64(4096) + u64(8192)
                                           + u32(3))
    front = u32(1) + u32(20) + u32(0x24) + ts(1700000600, 7) + ev(0, 0) \
        + oloc(6, 1, b'', b'', 0x1234) + pg(1, 0x1234) + cstr('rbd_data.1') \
        + u16(2) + ops + u64(0xfffffffffffffffe) + u64(0) + u32(2) + u64(3) + u64(4) + u32(0)
    c.c2s(cl.msg(0x2a, front=front, data=bytes(range(64)), ver=4, tid=1))
    # Reply version 6: two ops, rvals, replay version, redirect with object
    rops = osd_op(OP_WRITE, 0) + osd_op(OP_READ, 16)
    front = cstr('rbd_data.1') + pg(1, 0x1234) + u32(0x25) + u32(0) + i32(0) + ev(0, 0) \
        + u32(20) + u32(2) + rops + u32(0) + i32(0) + i32(0) + ev(5, 20) + u64(5) \
        + redirect(b'other_obj', b'\x01\x02')
    c.s2c(osd.msg(0x2b, front=front, data=b'R' * 16, ver=6, tid=1))
    # OSD op: header version 3 (no retry), key in the locator (v3),
    # ops whose arguments are not decoded (call, getxattr) and the other
    # extent ops
    ops = osd_op(OP_STAT) + osd_op(OP_TRUNCATE, args=u64(10) + u64(0) + u64(10) + u32(1)) \
        + osd_op(OP_ZERO) + osd_op(OP_DELETE) + osd_op(OP_WRITEFULL, 8) \
        + osd_op(OP_CALL, 9, args=b'\x03\x04\x00\x02\0\0\0' + b'\0' * 21)
    front = u32(1) + u32(20) + u32(0x10) + ts(1700000601) + ev(3, 19) \
        + oloc(3, 2, b'mykey') + pg(2, 5, 3) + cstr('obj2') + u16(6) + ops \
        + u64(0xfffffffffffffffe) + u64(0) + u32(0)
    c.c2s(cl.msg(0x2a, front=front, data=b'W' * 8 + b'rbdlocks!', ver=3, tid=2))
    # Replies version 4 and 5 (version 3 replies trip the op count check,
    # see the malformed capture)
    front = cstr('obj2') + pg(2, 5) + u32(0x11) + u32(0) + i32(0) + ev(0, 0) + u32(20) \
        + u32(1) + osd_op(OP_READ, 32) + u32(0) + i32(32)
    c.s2c(osd.msg(0x2b, front=front, data=b'DATA' * 8, ver=4, tid=3))
    front = cstr('obj2') + pg(2, 5) + u32(0x11) + u32(0) + i32(0) + ev(0, 0) + u32(20) \
        + u32(1) + osd_op(OP_READ, 8) + u32(0) + i32(8) + ev(6, 20) + u64(6)
    c.s2c(osd.msg(0x2b, front=front, data=b'EIGHTOCT', ver=5, tid=4))
    # Version 6 with an empty redirect
    front = cstr('obj2') + pg(2, 5) + u32(0x11) + u32(0) + i32(0) + ev(0, 0) + u32(20) \
        + u32(1) + osd_op(OP_READ, 8) + u32(0) + i32(8) + ev(6, 20) + u64(6) + redirect()
    c.s2c(osd.msg(0x2b, front=front, data=b'EIGHTOCT', ver=6, tid=4))
    # OSD op with the namespace (locator v5) in two segments, the second
    # one followed by a ping in the same segment
    front = u32(1) + u32(20) + u32(0x10) + ts(1700000602) + ev(0, 0) \
        + oloc(5, 1, b'', b'myns') + pg(1, 9) + cstr('obj3') + u16(1) + osd_op(OP_READ) \
        + u64(0xfffffffffffffffe) + u64(0) + u32(0) + u32(1)
    m = cl.msg(0x2a, front=front, ver=4, tid=5) + cl.msg(0x02)
    c.c2s(m[:100])
    c.c2s(m[100:])
    c.fin()

    # ---- C: mon.1 <-> mon.0 (client speaks first)
    c, m1, m0 = setup(cap, '192.0.2.11', 41002, '192.0.2.10', 6789, T_MON, 1, T_MON, 0,
                      server_first=False, split_hello=True)
    c.c2s(m1.msg(0x43, front=FSID + u32(1) + cstr('b') + u32(0) + u32(0) + u8(0) + u64(0)
                 + u64(0), ver=5))
    c.s2c(m0.msg(0x43, front=FSID + u32(2) + cstr('a') + u32(2) + u32(0) + u32(1)
                 + monmap(2) + u8(1) + u64(1) + u64(100) + u64(0x3ffddff8eea4fffb), ver=6))
    for op in (1, 2, 4):
        c.c2s(m1.msg(0x41, front=FSID + u32(op) + u32(7) + monmap(2) + u32(2) + u32(0) + u32(1)
                     + u64(0x3ffddff8eea4fffb) + u64(0) + u64(0) + blob(b'share')))
    c.s2c(m0.msg(0x42, front=u32(7) + u32(1) + u64(1) + u64(100) + u64(0) + u64(200) + u64(0)
                 + ts(1700000700) + u64(100) + blob(b'') + u32(0), ver=0))
    c.c2s(m1.msg(0x42, front=u32(7) + u32(3) + u64(1) + u64(101) + u64(200) + u64(200) + u64(0)
                 + ts(1700000700) + ts(1700000701) + u64(101) + blob(b'latest')
                 + u32(2) + u64(100) + blob(b'v100') + u64(101) + blob(b'v101'), ver=1))
    c.s2c(m0.msg(0x600, front=u32(1) + u64(7) + u64(1) + ts(0) + u32(0) + u32(0)))
    c.c2s(m1.msg(0x600, front=u32(2) + u64(7) + u64(1) + ts(1700000800, 250000000)
                 + u32(0) + u32(0)))
    c.s2c(m0.msg(0x600, front=u32(3) + u64(7) + u64(1) + ts(0)
                 + u32(2) + entityinst(T_MON, -1, '192.0.2.10') + f64(0.0)
                 + entityinst(T_MON, 1, '192.0.2.11') + f64(0.5)
                 + u32(1) + entityinst(T_MON, 1, '192.0.2.11') + f64(0.25)))
    c.s2c(m0.msg(0x3c, front=paxos(1) + u64(5000)))
    c.fin()

    # ---- D: osd.0 <-> mon.0
    c, o0, m0 = setup(cap, '192.0.2.20', 41003, '192.0.2.10', 6789, T_OSD, 0, T_MON, 0,
                       split_reply=True)
    meta = u32(2) + cstr('arch') + cstr('x86_64') + cstr('hostname') + cstr('osd-host')
    c.c2s(o0.msg(0x47, front=paxos(19) + superblock(6) + eaddr(2, 6800, '192.0.2.20')
                 + eaddr(2, 6801, '198.51.100.20') + u32(19) + eaddr(2, 6802, '192.0.2.20')
                 + meta, ver=5))
    c.c2s(o0.msg(0x47, front=paxos(19) + superblock(5) + eaddr(2, 6800, '192.0.2.20'), ver=1))
    front = paxos(20) + FSID + osd_stat(4) + u32(2) + pg(1, 3) + pg_stat(17) \
        + pg(1, 4) + pg_stat(8) + u32(20) + ts(1700000900)
    c.c2s(o0.msg(0x57, front=front))
    c.c2s(o0.msg(0x57, front=paxos(20) + FSID + osd_stat(2) + u32(0) + u32(20) + ts(1)))
    c.s2c(m0.msg(0x59, front=u64(20) + u32(2) + pg(1, 10) + pg_create() + pg(1, 11)
                 + pg_create()))
    c.s2c(m0.msg(0x46, front=FSID + u32(20) + u32(19) + u8(4) + enc(1, ts(1700000950)),
                 ver=1))
    c.c2s(o0.msg(0x46, front=FSID + u32(20) + u32(20) + u8(5) + enc(1, ts(1700000951))
                 + ts(1700000951), ver=2))
    c.fin()

    # ---- E: client.4102 <-> mds.0
    c, cl, mds = setup(cap, '192.0.2.1', 41004, '192.0.2.30', 6800, T_CLIENT, 4102, T_MDS, 0)
    c.c2s(cl.msg(0x16, front=u32(0) + u64(1) + ts(1700001000) + u32(0) + u32(0)))
    c.s2c(mds.msg(0x16, front=u32(1) + u64(1) + ts(1700001000) + u32(16384) + u32(256)))
    front = u64(1) + u32(5) + u32(0) + u8(0) + u8(0) + u16(2) + u32(0x1301) + u32(1000) \
        + u32(1000) + u64(0x10000000000) + b'\0' * 48 + path(1, 'dir/file') + path(0, '') \
        + mds_release(0x10000000001) + mds_release(0x10000000002) + ts(1700001001)
    c.c2s(cl.msg(0x18, front=front, ver=2, tid=1))
    front = u64(1) + u32(5) + u32(0) + u8(1) + u8(0) + u16(0) + u32(0x0100) + u32(0) \
        + u32(0) + u64(1) + b'\0' * 48 + path(1, 'x') + path(0, '')
    c.c2s(cl.msg(0x18, front=front, ver=1, tid=2))
    c.s2c(mds.msg(0x19, front=u32(1) + u32(1) + u8(1), tid=2))
    c.s2c(mds.msg(0x1a, front=u32(0x1301) + i32(0) + u32(5) + u8(1) + u8(1) + u8(1)
                  + blob(b'trace') + blob(b'') + blob(b'snaps'), tid=1))
    caps = u32(4) + u64(0x10000000001) + u64(1) + u64(77) + u32(1) + u32(1) + u32(0xd55) \
        + u32(0) + u32(0) + u32(0) + u64(0) + u32(4) + u32(1000) + u32(1000) + u32(0o100644) \
        + u32(1) + u32(6) + u64(1) + b'\0' * 84 + b'SNAP' + blob(b'') + b'\0' * 21 \
        + u64(1) + blob(b'inline')
    c.s2c(mds.msg(0x310, front=caps, middle=b'xattrs', ver=4))
    caps = u32(5) + u64(0x10000000001) + u64(1) + u64(77) + u32(2) + u32(1) + u32(0xd55) \
        + u32(0) + u32(0) + u32(0) + u64(0) + u32(0) + u32(1000) + u32(1000) + u32(0o100644) \
        + u32(1) + u32(0) + u64(1) + b'\0' * 84
    c.c2s(cl.msg(0x310, front=caps, ver=1))
    c.c2s(cl.msg(0x313, front=u32(2) + u64(0x10000000001) + u64(77) + u32(0) + u32(2)
                 + u64(0x10000000002) + u64(78) + u32(0) + u32(3)))
    c.fin()

    # ---- F: a server that answers WAIT
    c = Conn(cap, '192.0.2.1', 41005, '192.0.2.10', 6789)
    c.s2c(server_hello(eaddr(2, 6789, '192.0.2.10'), eaddr(2, 41005, '192.0.2.1')))
    c.c2s(client_hello(eaddr(2, 0, '192.0.2.1')))
    c.s2c(connect_reply(3))
    c.fin()

    # ---- Reproducers of the fixes on the branch, each in
    # its own connection from the reproducer's client hello
    for port, payload in ((41010, reproducer_hello() + repro_msglen_wrap()),
                          (41011, repro_nosavedstate()),
                          (41012, BANNER + b'\0' * 20),
                          (41013, reproducer_hello() + repro_redirect_obj()),
                          (41014, reproducer_hello() + repro_pgstat_stats()),
                          (41015, reproducer_hello() + repro_poolopreply_datai())):
        c = Conn(cap, '192.0.2.1', port, '192.0.2.10', 6789)
        c.c2s(payload)
        c.fin()
    return cap


def malformed_capture():
    cap = Capture()

    def one(port, *payloads, server=None):
        c = Conn(cap, '192.0.2.1', port, '192.0.2.10', 6789)
        if server:
            c.s2c(server)
        for p in payloads:
            c.c2s(p)
        c.fin()

    cl = Sender(T_CLIENT, 1)
    h = reproducer_hello()
    # Reproducers that throw
    one(42000, h + repro_encoded_backwards())
    one(42001, h + repro_snapinfo())
    # Unknown tags
    one(42002, h + b'\x7f\x7e\x7d' + cl.msg(0x02))
    # Banner too long / too short (C_INVALID from c_dissect_new)
    one(42003, b'ceph v0270' + b'\0' * 200)
    one(42004, b'ceph v1\0\0' + b'\0' * 200)
    # Wrong versions, unused and overrun data
    one(42005, h + cl.msg(0x29, front=FSID + u32(0) + u32(1) + u32(1)
                          + (lambda e: u32(len(e)) + e)(enc(6, b'\0' * 40))))
    # Object locator with both a key and a hash: the expert info is added
    # with a NULL tvb (packet-ceph.c:2388), a dissector bug
    one(42006, h + cl.msg(0x2a, front=u32(1) + u32(1) + u32(0) + ts(0) + ev(0, 0)
                          + oloc(6, 1, b'key', b'', 5) + pg(1, 0)
                          + cstr('o') + u16(0) + u64(0) + u64(0) + u32(0)))
    # pg_t version 2, a locator with unused octets, octets after the front
    one(42020, h + cl.msg(0x2a, front=u32(1) + u32(1) + u32(0) + ts(0) + ev(0, 0)
                          + enc(4, i64(1) + i32(-1) + cstr('') + b'??', 3)
                          + struct.pack('<BqIi', 2, 1, 0, -1)
                          + cstr('o') + u16(0) + u64(0) + u64(0) + u32(0) + b'extra'))
    one(42007, h + cl.msg(0x2a, front=u32(1) + u32(1) + u32(0) + ts(0) + ev(0, 0)
                          + oloc(6) + pg(1, 0) + cstr('o') + u16(500) + b'\0' * 40))
    one(42008, h + cl.msg(0x2b, front=cstr('o') + pg(1, 0) + u32(0) + u32(0) + i32(0)
                          + ev(0, 0) + u32(0) + u32(50) + b'\0' * 40, ver=1))
    # Auth with an unknown supported-protocol version and an unknown proto
    one(42009, h + cl.msg(0x11, front=paxos() + u32(0) + u32(17) + u8(2) + u32(0) + u32(8)
                          + cstr('x') + u64(0) + b'zz'))
    one(42010, h + cl.msg(0x11, front=paxos() + u32(1) + u32(0)))
    # Client caps with xattrs shorter than the middle; caps with data
    one(42011, h + cl.msg(0x310, front=u32(4) + b'\0' * 64 + u32(0) + b'\0' * 16 + u32(10)
                          + u64(0) + b'\0' * 84 + b'\0' * 21, middle=b'xx', ver=3))
    # Unknown message types, an empty monmap, a hitset of an unknown kind
    one(42012, h + cl.msg(0x0601, front=b'\0' * 4))
    one(42013, h + cl.msg(0x43, front=FSID + u32(1) + cstr('a') + u32(0) + u32(0) + u8(0)
                          + u64(0) + u64(0), ver=5))
    # Truncated message: lengths say more than the TCP stream has
    one(42014, h + cl.msg(0x0f, front=u32(1) + cstr('osdmap'), lens=(100, 0, 0)))
    # Server hello split before the role is known, then a FIN
    one(42015, server=BANNER + b'\0' * 50)
    # OSD maps with pools: pg_pool_t throws a dissector bug with a tree
    # (proto_tree_add_bitmask() with an empty field list for the high flags)
    front = FSID + u32(0) + u32(1) + u32(20) + osdmap(3)
    one(42017, h + cl.msg(0x29, front=front))
    one(42018, h + cl.msg(0x29, front=FSID + u32(0) + u32(1) + u32(20)
                          + osdmap(2, ((9, 1),))))
    # OSD op reply version 3 with one op: valid, but the op count check
    # (opslen >= remaining / 34) rejects it
    front = cstr('obj2') + pg(2, 5, 3) + u32(0x11) + u32(0) + i32(-2) + ev(0, 0) + u32(20) \
        + u32(1) + osd_op(OP_STAT) + u32(1)
    one(42019, h + cl.msg(0x2b, front=front, ver=3))
    # Version too new
    one(42016, h + cl.msg(0x59, front=u64(1) + u32(1) + pg(1, 0) + enc(2, u32(0) + pg(1, 0)
                                                                       + u32(0))))
    return cap


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    main_capture().write(os.path.join(out, 'ceph-coverage.pcap'))
    malformed_capture().write(os.path.join(out, 'ceph-coverage-malformed.pcap'))


if __name__ == '__main__':
    main()
