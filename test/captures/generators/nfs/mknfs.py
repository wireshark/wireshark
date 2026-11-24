#!/usr/bin/env python3
# Generates test/captures/nfs_coverage.pcap.gz, nfs_coverage_malformed.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic NFSv2 / NFSv3 / NFSv4.x capture generator.
# usage: mknfs.py <outdir>   (writes nfs-coverage.pcap, nfs-coverage-malformed.pcap)
import struct
import sys
import os

def u32(v): return struct.pack('>I', v & 0xffffffff)
def u64(v): return struct.pack('>Q', v & 0xffffffffffffffff)
def opq(b):
    if isinstance(b, str): b = b.encode()
    return u32(len(b)) + b + b'\0' * ((4 - len(b) % 4) % 4)
def fixed(b, n):
    return b + b'\0' * (n - len(b))
def arr(items):
    return u32(len(items)) + b''.join(items)
def boolean(v): return u32(1 if v else 0)

def _csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff

class Cap:
    def __init__(self):
        self.frames = []
        self.xid = 0x1000
    def raw_udp(self, payload, to_server, sport=800, dport=2049):
        cli, srv = bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2])
        src, dst = (cli, srv) if to_server else (srv, cli)
        sp, dp = (sport, dport) if to_server else (dport, sport)
        udp = struct.pack('>HHHH', sp, dp, 8 + len(payload), 0) + payload
        ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0, src, dst)
        ip = ip[:10] + struct.pack('>H', _csum(ip)) + ip[12:]
        macs = (b'\x02\x00\x00\x00\x00\x02' + b'\x02\x00\x00\x00\x00\x01') if to_server else (b'\x02\x00\x00\x00\x00\x01' + b'\x02\x00\x00\x00\x00\x02')
        self.frames.append(macs + b'\x08\x00' + ip + udp)
    def call(self, prog, vers, proc, body, sport=800, dport=2049, cred=None):
        self.xid += 1
        if cred is None:
            cred = u32(0) + u32(0)
        pl = u32(self.xid) + u32(0) + u32(2) + u32(prog) + u32(vers) + u32(proc) + cred + u32(0) + u32(0) + body
        self.raw_udp(pl, True, sport, dport)
        return self.xid
    def reply(self, xid, body, sport=800, dport=2049):
        pl = u32(xid) + u32(1) + u32(0) + u32(0) + u32(0) + u32(0) + body
        self.raw_udp(pl, False, sport, dport)
    def rpc(self, prog, vers, proc, args, res, **kw):
        x = self.call(prog, vers, proc, args, **kw)
        self.reply(x, res, **{k: v for k, v in kw.items() if k in ('sport', 'dport')})
    def write(self, fname):
        with open(fname, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
            for i, fr in enumerate(self.frames):
                f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
                f.write(fr)

NFS = 100003

# ---------------------------------------------------------------- NFSv2
def fh2(n): return fixed(b'FH2-%04d' % n, 32)
def fattr2(ftype=1, size=4096):
    return (u32(ftype) + u32(0o100644) + u32(1) + u32(1000) + u32(1000) + u32(size) +
            u32(4096) + u32(0) + u32(8) + u32(7) + u32(1234) +
            u32(1700000000) + u32(1) + u32(1700000001) + u32(2) + u32(1700000002) + u32(3))
def sattr2():
    return u32(0o644) + u32(1000) + u32(1000) + u32(0) + u32(1700000000) + u32(0) + u32(1700000001) + u32(0)

def v2(c):
    P = lambda proc, a, r: c.rpc(NFS, 2, proc, a, r)
    P(2, fh2(1) + u32(0xffffffff) * 4 + u32(0xffffffff) * 2 + u32(0xffffffff) * 2, u32(0) + fattr2())
    P(9, fh2(1) + opq('nv') + u32(0xffffffff) * 8, u32(0) + fh2(4) + fattr2())
    P(0, b'', b'')
    P(1, fh2(1), u32(0) + fattr2())
    P(2, fh2(1) + sattr2(), u32(0) + fattr2())
    P(3, b'', b'')
    P(4, fh2(1) + opq('hello.txt'), u32(0) + fh2(2) + fattr2())
    P(4, fh2(1) + opq('missing'), u32(2))
    P(5, fh2(3), u32(0) + opq('/target/path'))
    P(6, fh2(2) + u32(0) + u32(100) + u32(100), u32(0) + fattr2() + opq(b'x' * 100))
    P(7, b'', b'')
    P(8, fh2(2) + u32(0) + u32(0) + u32(8) + opq(b'12345678'), u32(0) + fattr2())
    P(9, fh2(1) + opq('new') + sattr2(), u32(0) + fh2(4) + fattr2())
    P(10, fh2(1) + opq('new'), u32(0))
    P(11, fh2(1) + opq('a') + fh2(1) + opq('b'), u32(0))
    P(12, fh2(2) + fh2(1) + opq('link'), u32(0))
    P(13, fh2(1) + opq('sym') + opq('/to/where') + sattr2(), u32(0))
    P(14, fh2(1) + opq('dir') + sattr2(), u32(0) + fh2(5) + fattr2(2))
    P(15, fh2(1) + opq('dir'), u32(0))
    ent = lambda fid, name, ck: u32(1) + u32(fid) + opq(name) + u32(ck)
    P(16, fh2(1) + u32(0) + u32(512),
      u32(0) + ent(10, 'f1', 1) + ent(11, 'f2', 2) + u32(0) + u32(1))
    P(17, fh2(1), u32(0) + u32(8192) + u32(4096) + u32(1000) + u32(500) + u32(400))
    P(4, fh2(1) + opq('x'), u32(70))   # stale

# ---------------------------------------------------------------- NFSv3
def fh3(n): return opq(b'FH3-%04d-xxxxxxxx' % n)
def nt(s=1700000000, n=5): return u32(s) + u32(n)
def fattr3(ftype=1, size=4096):
    return (u32(ftype) + u32(0o100644) + u32(1) + u32(1000) + u32(1000) + u64(size) + u64(4096) +
            u32(0) + u32(0) + u64(7) + u64(1234) + nt() + nt(1700000001) + nt(1700000002))
def poa(a=True): return boolean(a) + (fattr3() if a else b'')
def wcc(pre=True, post=True):
    p = (boolean(1) + u64(4096) + nt() + nt()) if pre else boolean(0)
    return p + poa(post)
def sattr3(full=True):
    if not full:
        return boolean(0) * 4 + u32(0) + u32(0)
    return (boolean(1) + u32(0o644) + boolean(1) + u32(1000) + boolean(1) + u32(1000) +
            boolean(1) + u64(0) + u32(2) + nt() + u32(1))
def verf(n=1): return u64(0x1122334455667700 + n)
def pofh(n=9): return boolean(1) + fh3(n)

def v3(c):
    P = lambda proc, a, r, **kw: c.rpc(NFS, 3, proc, a, r, **kw)
    P(0, b'', b'')
    P(1, fh3(1), u32(0) + fattr3(2))
    P(1, fh3(1), u32(70))
    P(2, fh3(1) + sattr3() + boolean(1) + nt(), u32(0) + wcc())
    P(2, fh3(1) + sattr3(False) + boolean(0), u32(13) + wcc(False, False))
    P(3, fh3(1) + opq('hello.txt'), u32(0) + fh3(2) + poa() + poa())
    P(3, fh3(1) + opq('missing'), u32(2) + poa())
    P(4, fh3(2) + u32(0x3f), u32(0) + poa() + u32(0x1f))
    P(5, fh3(3), u32(0) + poa() + opq('/the/target'))
    P(6, fh3(2) + u64(0) + u32(64), u32(0) + poa() + u32(64) + boolean(0) + opq(b'r' * 64))
    P(6, fh3(2) + u64(64) + u32(64), u32(0) + poa() + u32(0) + boolean(1) + opq(b''))
    for st in (0, 1, 2):
        P(7, fh3(2) + u64(0) + u32(8) + u32(st) + opq(b'12345678'),
          u32(0) + wcc() + u32(8) + u32(st) + verf())
    P(7, fh3(2) + u64(0) + u32(8) + u32(0) + opq(b'12345678'), u32(28) + wcc(False, False))
    P(8, fh3(1) + opq('c0') + u32(0) + sattr3(), u32(0) + pofh() + poa() + wcc())
    P(8, fh3(1) + opq('c1') + u32(1) + sattr3(), u32(0) + pofh() + poa() + wcc())
    P(8, fh3(1) + opq('c2') + u32(2) + verf(), u32(0) + pofh() + poa() + wcc())
    P(8, fh3(1) + opq('c3') + u32(1) + sattr3(False), u32(17) + wcc())
    P(9, fh3(1) + opq('dir') + sattr3(), u32(0) + pofh(10) + poa() + wcc())
    P(10, fh3(1) + opq('sl') + sattr3() + opq('/some/target'), u32(0) + pofh(11) + poa() + wcc())
    P(11, fh3(1) + opq('chr') + u32(3) + sattr3() + u32(4) + u32(5), u32(0) + pofh(12) + poa() + wcc())
    P(11, fh3(1) + opq('blk') + u32(4) + sattr3() + u32(8) + u32(1), u32(0) + pofh(13) + poa() + wcc())
    P(11, fh3(1) + opq('sock') + u32(6) + sattr3(), u32(0) + pofh(14) + poa() + wcc())
    P(11, fh3(1) + opq('fifo') + u32(7) + sattr3(), u32(0) + pofh(15) + poa() + wcc())
    P(11, fh3(1) + opq('reg') + u32(1), u32(10004) + wcc())
    P(12, fh3(1) + opq('rm'), u32(0) + wcc())
    P(13, fh3(1) + opq('rd'), u32(0) + wcc())
    P(13, fh3(1) + opq('rd'), u32(66) + wcc())
    P(14, fh3(1) + opq('a') + fh3(1) + opq('b'), u32(0) + wcc() + wcc())
    P(15, fh3(2) + fh3(1) + opq('hl'), u32(0) + poa() + wcc())
    ent = lambda fid, name, ck: boolean(1) + u64(fid) + opq(name) + u64(ck)
    P(16, fh3(1) + u64(0) + verf() + u32(1024),
      u32(0) + poa() + verf() + ent(1, '.', 1) + ent(2, '..', 2) + ent(20, 'f1', 3) + boolean(0) + boolean(1))
    P(16, fh3(1) + u64(3) + verf() + u32(1024), u32(0) + poa() + verf() + boolean(0) + boolean(0))
    P(16, fh3(1) + u64(3) + verf() + u32(1024), u32(10001) + poa(False))
    entp = lambda fid, name, ck, n: ent(fid, name, ck) + poa() + pofh(n)
    P(17, fh3(1) + u64(0) + verf() + u32(512) + u32(4096),
      u32(0) + poa() + verf() + entp(30, 'e1', 1, 31) + entp(32, 'e2', 2, 33) +
      ent(34, 'e3', 3) + boolean(0) + poa(False) + boolean(0) + boolean(1))
    P(18, fh3(1), u32(0) + poa() + u64(10**9) + u64(5 * 10**8) + u64(4 * 10**8) + u64(1000) + u64(500) + u64(400) + u32(0))
    P(19, fh3(1), u32(0) + poa() + u32(65536) + u32(32768) + u32(512) + u32(65536) + u32(32768) + u32(512) + u32(4096) +
      u64(2**40) + nt(0, 1) + u32(0x1b))
    P(20, fh3(1), u32(0) + poa() + u32(32000) + u32(255) + boolean(1) + boolean(0) + boolean(0) + boolean(1))
    P(21, fh3(2) + u64(0) + u32(0), u32(0) + wcc() + verf())
    P(21, fh3(2) + u64(0) + u32(0), u32(5) + wcc(False, False))

# ---------------------------------------------------------------- NFSv4
def bitmap(bits):
    n = (max(bits) // 32 + 1) if bits else 0
    w = [0] * n
    for b in bits:
        w[b // 32] |= 1 << (b % 32)
    return u32(n) + b''.join(u32(x) for x in w)
def nfstime4(s=1700000000, n=7): return u64(s) + u32(n)
def fh4(n): return opq(b'FH4-%04d-yyyyyyyy' % n)
def stateid(n=1): return u32(n) + fixed(b'SID%d' % n, 12)
def sessid(): return b'SESSION-ID-0123.'
def devid(n=1): return fixed(b'DEVICE%02d' % n, 16)
def cinfo(): return boolean(1) + u64(10) + u64(11)
def ace(t=0, flag=0, mask=0x1f01ff, who='OWNER@'): return u32(t) + u32(flag) + u32(mask) + opq(who)
def acl(aces): return arr(aces)
def pathname(*comps): return arr([opq(c) for c in comps])

def fattr(d):
    """d: dict attrnum -> value bytes; returns bitmap + opaque attrlist"""
    ks = sorted(d)
    vals = b''.join(d[k] for k in ks)
    return bitmap(ks) + opq(vals)

FS_LOC = b''
def fs_locations():
    return pathname('root') + arr([arr([opq('srv1'), opq('srv2')]) + pathname('exp', 'dir')])

def attrs_all(ftype=1):
    acls = acl([ace(0, 0, 0x1f01ff, 'OWNER@'), ace(1, 0x1, 0x7, 'GROUP@'),
                ace(2, 0x8, 0x1, 'EVERYONE@'), ace(3, 0x40, 0x80, 'bob@example.com'),
                ace(0, 0x10, 0x1, 'carol@example.com')])
    d = {
        0: bitmap([0, 1, 3, 4, 8, 20, 33]),
        1: u32(ftype), 2: u32(0x2), 3: u64(99), 4: u64(12345), 5: boolean(1), 6: boolean(1),
        7: boolean(0), 8: u64(1) + u64(2), 9: boolean(1), 10: u32(90), 11: u32(0),
        12: acls, 13: u32(0xf), 14: boolean(0), 15: boolean(1), 16: boolean(0), 17: boolean(1),
        18: boolean(1), 19: fh4(5), 20: u64(777), 21: u64(10), 22: u64(20), 23: u64(30),
        24: fs_locations(), 25: boolean(0), 26: boolean(1), 27: u64(2**44), 28: u32(32000),
        29: u32(255), 30: u64(1048576), 31: u64(1048576), 32: opq('text/plain'),
        33: u32(0o100755), 34: boolean(1), 35: u32(2), 36: opq('alice@example.com'),
        37: opq('staff@example.com'), 38: u64(1), 39: u64(2), 40: u64(3), 41: u32(8) + u32(1),
        42: u64(100), 43: u64(200), 44: u64(300), 45: u64(400), 46: boolean(0),
        47: nfstime4(), 48: u32(1) + nfstime4(), 49: nfstime4(), 50: nfstime4(), 51: nfstime4(0, 1),
        52: nfstime4(), 53: nfstime4(), 54: u32(0), 55: u64(778), 56: nfstime4(), 57: nfstime4(),
        58: u32(0x7) + acl([ace(0, 0, 0x1, 'OWNER@')]), 59: u32(0x1) + acl([ace(2, 0x40, 0x1, 'EVERYONE@')]),
        62: arr([u32(1), u32(5), u32(0x80000003)]), 65: u32(4096), 68: arr([u32(1) + bitmap([0, 1, 2, 3]) + opq(u64(4096) + u64(8192) + u64(16384) + u64(32768)), u32(4) + bitmap([]) + opq(b'')]),
        76: u32(3), 77: u32(4096), 78: u64(55), 79: u32(2),
        80: u32(0) + u32(0) + opq('system_u:object_r:nfs_t:s0'), 81: u32(0o755) + u32(0o022),
        82: boolean(1), 83: boolean(0), 84: nfstime4(), 85: nfstime4(),
    }
    return d

# One v4 compound
class Comp:
    def __init__(self, c, minor=0, tag=''):
        self.c, self.minor, self.tag = c, minor, tag
        self.ops = []; self.res = []; self.rstatus = 0
    def op(self, code, args=b'', res=b'', status=0, rawres=None):
        self.ops.append(u32(code) + args)
        self.res.append(u32(code) + u32(status) + (res if rawres is None else rawres))
        if status:
            self.rstatus = status
        return self
    def send(self, **kw):
        a = opq(self.tag) + u32(self.minor) + u32(len(self.ops)) + b''.join(self.ops)
        r = u32(self.rstatus) + opq(self.tag) + u32(len(self.res)) + b''.join(self.res)
        self.c.rpc(NFS, 4, 1, a, r, **kw)

def v4(c, minor=0, **kw):
    return Comp(c, minor, **kw)

def seq(comp, slot=0):
    comp.op(53, sessid() + u32(slot + 1) + u32(slot) + u32(3) + boolean(0),
            sessid() + u32(slot + 1) + u32(slot) + u32(3) + u32(7) + u32(0x1001))

def v40_basic(c):
    c.rpc(NFS, 4, 0, b'', b'')
    # SETCLIENTID / CONFIRM / RENEW
    cb = u32(0x40000000) + opq('tcp') + opq('192.0.2.1.8.1')
    v4(c, tag='setclientid').op(35, u64(0x1122334455667788) + opq('client-id-A') + cb + u32(77),
                         u64(0xabc) + u64(0xdef)).send()
    v4(c).op(36, u64(0xabc) + u64(0xdef)).send()
    v4(c).op(30, u64(0xabc)).send()
    # SETCLIENTID with IPv6 and unusual r_addr forms
    cb6 = u32(0x40000000) + opq('tcp') + opq('fe:80:00:00:00:00:00:01.8.1')
    v4(c).op(35, u64(1) + opq('client-id-B') + cb6 + u32(78), u64(2) + u64(3)).send()
    cbx = u32(0x40000000) + opq('tcp') + opq('8.1')
    v4(c).op(35, u64(1) + opq('client-id-C') + cbx + u32(79), u64(2) + u64(3)).send()
    cby = u32(0x40000000) + opq('tcp') + opq('garbage')
    v4(c).op(35, u64(1) + opq('client-id-D') + cby + u32(80), u64(2) + u64(3)).send()
    cbz = u32(0x40000000) + opq('udp') + opq('1.2.3.4.5.6')
    v4(c).op(35, u64(1) + opq('client-id-E') + cbz + u32(81), u64(2) + u64(3)).send()
    # CLID_INUSE reply with clientaddr
    v4(c).op(35, u64(1) + opq('client-id-F') + cb + u32(82), status=10017,
             res=opq('tcp') + opq('192.0.2.9.3.4')).send()
    # PUTROOTFH / GETFH / LOOKUP / GETATTR
    v4(c, tag='mount').op(24).op(10, b'', fh4(1)).op(9, bitmap([0, 1, 3, 4, 8, 33]),
        fattr({0: bitmap([0, 1, 3, 4, 8, 33]), 1: u32(2), 3: u64(1), 4: u64(4096), 8: u64(1) + u64(2), 33: u32(0o755)})).send()
    v4(c).op(23).op(10, b'', fh4(2)).send()
    v4(c).op(22, fh4(1)).op(15, opq('dir1')).op(10, b'', fh4(3)).op(16).op(
        9, bitmap([1, 3, 4, 20, 33, 47, 53]),
        fattr({1: u32(2), 3: u64(1), 4: u64(0), 20: u64(5), 33: u32(0o755), 47: nfstime4(), 53: nfstime4()})).send()
    # the big attribute set, one per object type
    for ft in (1, 2, 3, 4, 5, 6, 7, 8, 9):
        d = attrs_all(ft)
        keys = sorted(d)
        v4(c).op(22, fh4(3)).op(9, bitmap(keys), fattr(d)).send()
    # requests with attribute values
    d = attrs_all(1)
    v4(c).op(22, fh4(3)).op(34, stateid(0) + fattr({k: d[k] for k in (4, 33, 36, 37, 48, 54, 12)}), bitmap([4, 12, 33, 36, 37, 48, 54])).send()
    v4(c).op(22, fh4(3)).op(37, fattr({k: d[k] for k in (3, 4, 53)})).send()
    v4(c).op(22, fh4(3)).op(17, fattr({k: d[k] for k in (3, 4)}), status=10009).send()
    v4(c).op(22, fh4(3)).op(37, fattr({3: u64(1)}), status=10027).send()
    # ACCESS
    v4(c).op(22, fh4(3)).op(3, u32(0x3f), u32(0x3f) + u32(0x1f)).send()
    v4(c).op(22, fh4(3)).op(3, u32(0x3f), u32(0x0f) + u32(0x03)).send()
    # CREATE (directory, symlink, block/char, fifo/socket)
    v4(c).op(22, fh4(3)).op(6, u32(2) + opq('newdir') + fattr({33: u32(0o755)}), cinfo() + bitmap([33])).send()
    v4(c).op(22, fh4(3)).op(6, u32(5) + opq('/link/target') + opq('newlink') + fattr({}), cinfo() + bitmap([])).send()
    v4(c).op(22, fh4(3)).op(6, u32(3) + u32(4) + u32(5) + opq('blk') + fattr({33: u32(0o600)}), cinfo() + bitmap([33])).send()
    v4(c).op(22, fh4(3)).op(6, u32(4) + u32(6) + u32(7) + opq('chr') + fattr({}), cinfo() + bitmap([])).send()
    v4(c).op(22, fh4(3)).op(6, u32(7) + opq('fifo') + fattr({}), cinfo() + bitmap([])).send()
    v4(c).op(22, fh4(3)).op(6, u32(6) + opq('sock') + fattr({}), cinfo() + bitmap([])).send()
    v4(c).op(22, fh4(3)).op(6, u32(2) + opq('baddir') + fattr({}), status=17).send()
    # OPEN variants
    own = u64(0xabc) + opq('owner1')
    op_ = lambda acc, deny, how, claim: u32(5) + u32(acc) + u32(deny) + own + how + claim
    nocr = u32(0); claim_null = u32(0) + opq('file.txt')
    rflags = u32(0x2 | 0x4 | 0x8 | 0x20)
    ores = lambda dg=u32(0): stateid(2) + cinfo() + rflags + bitmap([4, 33]) + dg
    read_deleg = u32(1) + stateid(3) + boolean(0) + ace(0, 0, 0x1, 'OWNER@')
    write_deleg = u32(2) + stateid(4) + boolean(1) + u32(1) + u64(1 << 20) + ace(1, 0, 0x6, 'GROUP@')
    write_deleg_blk = u32(2) + stateid(4) + boolean(0) + u32(2) + u32(100) + u32(4096) + ace(1, 0, 0x6, 'GROUP@')
    v4(c).op(22, fh4(3)).op(18, op_(1, 0, nocr, claim_null), ores(read_deleg)).op(10, b'', fh4(4)).send()
    v4(c).op(22, fh4(3)).op(18, op_(2, 0, u32(1) + u32(0) + fattr({33: u32(0o644)}), claim_null), ores(write_deleg)).send()
    v4(c).op(22, fh4(3)).op(18, op_(3, 1, u32(1) + u32(1) + fattr({33: u32(0o644)}), claim_null), ores(write_deleg_blk)).send()
    v4(c).op(22, fh4(3)).op(18, op_(3, 2, u32(1) + u32(2) + u64(0x1234), claim_null), ores()).send()
    v4(c).op(22, fh4(3)).op(18, op_(3, 0, u32(1) + u32(3) + u64(0x99) + fattr({33: u32(0o600)}), claim_null), ores()).send()
    v4(c).op(22, fh4(3)).op(18, op_(3, 0, u32(1) + u32(9), claim_null), ores()).send()
    v4(c).op(22, fh4(3)).op(6, u32(9) + opq('badtype') + fattr({}), status=10007).send()
    v4(c).op(22, fh4(3)).op(18, op_(1, 3, nocr, u32(1) + u32(1)), ores()).send()
    v4(c).op(22, fh4(3)).op(18, op_(1, 0, nocr, u32(2) + stateid(9) + opq('cur')), ores()).send()
    v4(c).op(22, fh4(3)).op(18, op_(1, 0, nocr, u32(3) + opq('prev')), ores()).send()
    v4(c).op(22, fh4(3)).op(18, op_(1, 0, nocr, u32(9)), ores()).send()
    v4(c).op(22, fh4(3)).op(18, op_(1, 0, nocr, claim_null), status=2).send()
    v4(c).op(19, boolean(1)).send()
    v4(c).op(20, stateid(2) + u32(6), stateid(2)).send()
    v4(c).op(21, stateid(2) + u32(7) + u32(1) + u32(0), stateid(2)).send()
    v4(c).op(4, u32(8) + stateid(2), u32(0xffffffff) + b'\0' * 12).send()
    # READ / WRITE / COMMIT / READDIR / READLINK
    v4(c).op(22, fh4(4)).op(25, stateid(2) + u64(0) + u32(100), u32(0) + opq(b'd' * 100)).send()
    v4(c).op(22, fh4(4)).op(38, stateid(2) + u64(0) + u32(2) + opq(b'wdata'), u32(5) + u32(2) + u64(0x55)).send()
    v4(c).op(22, fh4(4)).op(38, stateid(2) + u64(0) + u32(0) + opq(b'w'), u32(1) + u32(0) + u64(0x55)).send()
    v4(c).op(22, fh4(4)).op(38, stateid(2) + u64(0) + u32(1) + opq(b'w'), u32(1) + u32(1) + u64(0x55)).send()
    v4(c).op(22, fh4(4)).op(5, u64(0) + u32(0), u64(0x55)).send()
    def dent(ck, name, d):
        return boolean(1) + u64(ck) + opq(name) + fattr(d)
    v4(c).op(22, fh4(3)).op(26, u64(0) + u64(0) + u32(1024) + u32(4096) + bitmap([1, 4, 20, 33]),
          u64(0x77) + dent(1, 'e1', {1: u32(1), 4: u64(10), 20: u64(11), 33: u32(0o644)}) +
          dent(2, 'e2', {1: u32(2), 4: u64(0), 20: u64(12), 33: u32(0o755)}) + boolean(0) + boolean(1)).send()
    v4(c).op(22, fh4(3)).op(26, u64(2) + u64(0x77) + u32(1024) + u32(4096) + bitmap([]), u64(0x77) + boolean(0) + boolean(1)).send()
    v4(c).op(22, fh4(3)).op(27, b'', opq('/sym/target')).send()
    v4(c).op(22, fh4(3)).op(27, b'', status=22).send()
    # REMOVE / RENAME / LINK / SAVEFH / RESTOREFH
    v4(c).op(22, fh4(3)).op(28, opq('old'), cinfo()).send()
    v4(c).op(22, fh4(3)).op(32).op(22, fh4(6)).op(29, opq('a') + opq('b'), cinfo() + cinfo()).op(31).op(11, opq('lnk'), cinfo()).send()
    # LOCK / LOCKT / LOCKU
    lo = u64(0xabc) + opq('lockowner')
    v4(c).op(22, fh4(4)).op(12, u32(1) + boolean(0) + u64(0) + u64(100) + boolean(1) + u32(10) + stateid(2) + u32(3) + lo, stateid(6)).send()
    v4(c).op(22, fh4(4)).op(12, u32(2) + boolean(1) + u64(0) + u64(2**64 - 1) + boolean(0) + stateid(6) + u32(4), stateid(6)).send()
    v4(c).op(22, fh4(4)).op(12, u32(3) + boolean(0) + u64(0) + u64(1) + boolean(0) + stateid(6) + u32(4),
             status=10010, res=u64(0) + u64(5) + u32(2) + lo).send()
    v4(c).op(22, fh4(4)).op(13, u32(1) + u64(0) + u64(10) + lo, status=10010, res=u64(0) + u64(5) + u32(2) + lo).send()
    v4(c).op(22, fh4(4)).op(13, u32(1) + u64(0) + u64(10) + lo).send()
    v4(c).op(22, fh4(4)).op(14, u32(1) + u32(5) + stateid(6) + u64(0) + u64(2**64 - 1), stateid(7)).send()
    v4(c).op(39, lo).send()
    v4(c).op(7, u64(0xabc)).send()
    v4(c).op(8, stateid(3)).send()
    # SECINFO
    v4(c).op(22, fh4(3)).op(33, opq('name'), arr([u32(1), u32(0), u32(6) + opq(b'\x2a\x86\x48\x86\xf7\x12\x01\x02\x02') + u32(0) + u32(1)])).send()
    v4(c).op(22, fh4(3)).op(33, opq('name'), arr([u32(3)])).send()
    # unknown / illegal ops
    v4(c).op(10044, b'', status=10044).send()
    v4(c).op(10, b'', status=10020).send()
    # RPC level error status
    cc = v4(c); cc.op(24).op(10, b'', fh4(1)); cc.rstatus = 0; cc.send()

def v41(c):
    # EXCHANGE_ID with SP4_NONE, MACH_CRED, SSV
    impl = arr([opq('example.com') + opq('Linux nfs') + nfstime4()])
    spo = bitmap([9, 15, 28, 53]) + bitmap([3, 4])
    for how, body in ((0, b''), (1, spo), (2, spo + arr([opq(b'\x60\x86\x48\x01\x65\x03\x04\x02\x01')]) + arr([opq(b'\x60\x86\x48\x01\x65\x03\x04\x01\x2e')]) + u32(4) + u32(2))):
        rbody = {0: b'', 1: spo, 2: spo + u32(1) + u32(2) + u32(32) + u32(4) + opq(b'gss-handle-0')}[how]
        v4(c, 1).op(42, u64(0x77) + opq('co-owner') + u32(0x101) + u32(how) + body + impl,
                    u64(0x4242) + u32(1) + u32(0x10001) + u32(how) + rbody + u64(1) + opq('major-id') + opq('scope') + impl).send()
    ca = u32(0) + u32(1048576) + u32(1048576) + u32(8192) + u32(16) + u32(64) + u32(2) + u32(1) + u32(2)
    ca0 = u32(0) + u32(4096) + u32(4096) + u32(0) + u32(2) + u32(2) + u32(0)
    sec = arr([u32(0), u32(1) + u32(5) + opq('host') + u32(0) + u32(0) + u32(2) + u32(1) + u32(2),
               u32(6) + u32(1) + opq(b'h1') + opq(b'h2')])
    v4(c, 1).op(43, u64(0x4242) + u32(1) + u32(0x3) + ca + ca0 + u32(0x40000000) + sec,
                sessid() + u32(1) + u32(0x3) + ca + ca0).send()
    seqc = Comp(c, 1); seq(seqc); seqc.op(22, fh4(1)).op(9, bitmap([1]), fattr({1: u32(2)})); seqc.send()
    s = v4(c, 1); seq(s, 1); s.op(58, boolean(0), b''); s.send()
    s = v4(c, 1); seq(s, 2); s.op(58, boolean(1), b''); s.send()
    v4(c, 1).op(41, sessid() + u32(3) + boolean(0), sessid() + u32(3) + boolean(1)).send()
    v4(c, 1).op(40, u32(0x40000000) + sec).send()
    v4(c, 1).op(44, sessid()).send()
    v4(c, 1).op(45, stateid(2)).send()
    v4(c, 1).op(55, arr([stateid(1), stateid(2)]), arr([u32(0), u32(10025)])).send()
    v4(c, 1).op(57, u64(0x4242)).send()
    None
    v4(c, 1).op(52, u32(2), arr([u32(1), u32(0)])).send()
    v4(c, 1).op(52, u32(0), arr([u32(1)])).send()
    # directory delegation
    cdl = nfstime4(1, 0)[:0]
    v4(c, 1).op(22, fh4(1)).op(46, boolean(1) + bitmap([0, 1, 2, 3, 4, 5]) + u64(0) + u32(1) + u64(0) + u32(2) + bitmap([1, 4]) + bitmap([3, 4]),
                  u32(0) + u64(0x99) + stateid(8) + bitmap([0, 1, 2]) + bitmap([1]) + bitmap([3])).send()
    v4(c, 1).op(22, fh4(1)).op(46, boolean(0) + bitmap([]) + u64(0) + u32(0) + u64(0) + u32(0) + bitmap([]) + bitmap([]),
                  u32(1) + u32(1)).send()
    v4(c, 1).op(22, fh4(1)).op(46, boolean(0) + bitmap([]) + u64(0) + u32(0) + u64(0) + u32(0) + bitmap([]) + bitmap([]),
                  u32(2)).send()
    # want delegation / reclaim complete / destroy clientid
    v4(c, 1).op(58, boolean(1)).send()
    # open with NONE_EXT and attr delegations (4.1/4.2)
    own = u64(0xabc) + opq('owner1')
    for acc in (0x103, 0x00100001, 0x00020001):
        pass
    ores = lambda dg: stateid(2) + cinfo() + u32(0) + bitmap([]) + dg
    for why, extra in ((0, b''), (1, boolean(1)), (2, boolean(0)), (3, b'')):
        v4(c, 1).op(22, fh4(3)).op(18, u32(5) + u32(0x0100 | 1) + u32(0) + own + u32(0) + u32(4) ,
                   ores(u32(3) + u32(why) + extra)).send()
    v4(c, 1).op(22, fh4(3)).op(18, u32(5) + u32(0x00130001) + u32(0) + own + u32(0) + u32(4),
               ores(u32(4) + stateid(3) + boolean(0) + ace(0, 0, 0x1, 'OWNER@'))).send()
    v4(c, 1).op(22, fh4(3)).op(18, u32(5) + u32(0x00100002) + u32(0) + own + u32(0) + u32(0) + opq('fl'),
               ores(u32(5) + stateid(3) + boolean(0) + u32(1) + u64(1 << 20) + ace(0, 0, 0x6, 'OWNER@'))).send()

def v41_pnfs(c):
    # LAYOUTGET: files, flex files, SCSI, other
    lg = lambda lt: boolean(0) + u32(lt) + u32(1) + u64(0) + u64(2**64 - 1) + u64(4096) + stateid(2) + u32(65536)
    files_body = devid(1) + u32(0x8001000) + u32(0) + u64(0) + arr([fh4(11), fh4(12)])
    seg = lambda lt, body: u64(0) + u64(1 << 20) + u32(2) + u32(lt) + opq(body)
    v4(c, 1).op(22, fh4(4)).op(50, lg(1), boolean(1) + stateid(5) + arr([seg(1, files_body)])).send()
    ds = devid(2) + u32(1) + stateid(6) + arr([fh4(13)]) + opq('nobody') + opq('nogroup')
    flex_body = u64(65536) + arr([arr([ds]), arr([ds, ds])]) + u32(7) + u32(30)
    v4(c, 1).op(22, fh4(4)).op(50, lg(4), boolean(0) + stateid(5) + arr([seg(4, flex_body)])).send()
    scsi_body = arr([devid(3) + u64(0) + u64(4096) + u64(8192) + u32(0), devid(4) + u64(4096) + u64(4096) + u64(0) + u32(2)])
    v4(c, 1).op(22, fh4(4)).op(50, lg(5), boolean(0) + stateid(5) + arr([seg(5, scsi_body)])).send()
    v4(c, 1).op(22, fh4(4)).op(50, lg(9), boolean(0) + stateid(5) + arr([seg(9, b'opaque-layout')])).send()
    v4(c, 1).op(22, fh4(4)).op(50, lg(1), status=10058).send()
    # LAYOUTCOMMIT, LAYOUTRETURN
    v4(c, 1).op(22, fh4(4)).op(49, u64(0) + u64(4096) + boolean(0) + stateid(5) + boolean(1) + u64(4095) + boolean(1) + nfstime4() + u32(1) + opq(b'lcupdate'),
                boolean(1) + u64(4096)).send()
    v4(c, 1).op(22, fh4(4)).op(49, u64(0) + u64(4096) + boolean(1) + stateid(5) + boolean(0) + boolean(0) + u32(1) + opq(b''),
                boolean(0)).send()
    v4(c, 1).op(22, fh4(4)).op(51, boolean(0) + u32(1) + u32(1) + u32(1) + u64(0) + u64(4096) + stateid(5) + opq(b'lrbody'),
                boolean(1) + stateid(5)).send()
    v4(c, 1).op(22, fh4(4)).op(51, boolean(0) + u32(1) + u32(2) + u32(2),
                boolean(0)).send()
    # layoutreturn flex files with stats and io errors
    ioerr = u64(0) + u64(4096) + stateid(5) + arr([devid(2) + u32(5) + u32(25)])
    lat = u64(1) + u64(2) + u64(3) + u64(4) + u64(5) + nfstime4() + nfstime4()
    stats = (u64(0) + u64(4096) + stateid(5) + u64(10) + u64(11) + u64(12) + u64(13) +
             devid(2) + b'' )
    ffstat = (u64(0) + u64(4096) + stateid(5) + u64(10) + u64(11) + u64(12) + u64(13) + devid(2) +
              opq('tcp') + opq('192.0.2.7.8.1') + fh4(13) + lat + lat + nfstime4() + boolean(1))
    # note: dissect_nfs4_ff_io_stats -> layoutstats(has_layout_type=false) reads io_info, io_info, deviceid, ds addr, fh, lat, lat, time, bool
    ffstat = (u64(0) + u64(4096) + stateid(5) + u64(10) + u64(11) + u64(12) + u64(13) + devid(2) +
              opq('tcp') + opq('192.0.2.7.8.1') + fh4(13) + lat + lat + nfstime4() + boolean(1))
    v4(c, 1).op(22, fh4(4)).op(51, boolean(0) + u32(4) + u32(2) + u32(1) + u64(0) + u64(4096) + stateid(5) +
                u32(0) + arr([ioerr, ioerr]) + arr([ffstat]), boolean(0)).send()
    # GETDEVINFO / GETDEVLIST
    gdi = lambda lt: devid(1) + u32(lt) + u32(4096) + bitmap([1])
    def gdres(lt, body):
        return u32(lt) + opq(body) + bitmap([1, 2])
    devs_file = arr([u32(0), u32(1)]) + arr([arr([opq('tcp') + opq('192.0.2.5.8.1')]),
                                             arr([opq('tcp') + opq('192.0.2.6.8.1'), opq('tcp6') + opq('::1.8.1')])])
    devs_flex = arr([opq('tcp') + opq('192.0.2.5.8.1'), opq('tcp') + opq('192.0.2.6.8.1')]) + arr([
        u32(3) + u32(1) + u32(1048576) + u32(1048576) + boolean(1),
        u32(4) + u32(0) + u32(65536) + u32(65536) + boolean(0)])
    def vol_base(desig=b'\xde\xad\xbe\xef'):
        return u32(4) + u32(1) + u32(3) + opq(desig) + b'PRIVKEY8'
    scsi = arr([vol_base(), vol_base(b'\x60\x01\x40\x50\x01\x02\x03\x04'),
                u32(1) + u64(4096) + u64(1 << 30) + u32(0),
                u32(2) + arr([u32(0), u32(1), u32(2)]),
                u32(3) + u64(65536) + arr([u32(0), u32(1)]),
                u32(2) + arr([])])
    for lt, body in ((1, devs_file), (4, devs_flex), (5, scsi), (9, b'unknown-dev-body')):
        v4(c, 1).op(47, gdi(lt), gdres(lt, body)).send()
    v4(c, 1).op(47, gdi(5), status=10049).send()
    v4(c, 1).op(48, u32(1) + u32(4096) + u64(0) + u64(0),
                u64(3) + u64(0x1234) + u32(2) + devid(1) + devid(2) + u32(1)).send()

def errors_v2_v3(c):
    # error replies of every v2 and v3 procedure
    for proc, a in ((1, fh2(1)), (2, fh2(1) + sattr2()), (5, fh2(1)), (6, fh2(1) + u32(0) + u32(8) + u32(8)),
                    (8, fh2(1) + u32(0) + u32(0) + u32(1) + opq(b'x')), (9, fh2(1) + opq('n') + sattr2()),
                    (10, fh2(1) + opq('n')), (11, fh2(1) + opq('a') + fh2(1) + opq('b')),
                    (12, fh2(1) + fh2(1) + opq('n')), (13, fh2(1) + opq('n') + opq('t') + sattr2()),
                    (14, fh2(1) + opq('n') + sattr2()), (15, fh2(1) + opq('n')), (16, fh2(1) + u32(0) + u32(10)),
                    (17, fh2(1))):
        c.rpc(NFS, 2, proc, a, u32(13))
    W = wcc(); P = poa()
    for proc, a, r in (
            (2, fh3(1) + sattr3() + boolean(0), W), (3, fh3(1) + opq('n'), P), (4, fh3(1) + u32(1), P),
            (5, fh3(1), P), (6, fh3(1) + u64(0) + u32(8), P),
            (7, fh3(1) + u64(0) + u32(1) + u32(0) + opq(b'x'), W),
            (8, fh3(1) + opq('n') + u32(0) + sattr3(), W), (9, fh3(1) + opq('n') + sattr3(), W),
            (10, fh3(1) + opq('n') + sattr3() + opq('t'), W), (11, fh3(1) + opq('n') + u32(6) + sattr3(), W),
            (12, fh3(1) + opq('n'), W), (13, fh3(1) + opq('n'), W),
            (14, fh3(1) + opq('a') + fh3(1) + opq('b'), W + W), (15, fh3(1) + fh3(1) + opq('n'), P + W),
            (17, fh3(1) + u64(0) + verf() + u32(1) + u32(1), P), (18, fh3(1), P), (19, fh3(1), P),
            (20, fh3(1), P), (21, fh3(1) + u64(0) + u32(0), W)):
        c.rpc(NFS, 3, proc, a, u32(13) + r)

def v3_odd(c):
    P = lambda proc, a, r: c.rpc(NFS, 3, proc, a, r)
    # READDIR with attributes absent, MKNOD with pre-op attrs only, WRITE count mismatch
    P(16, fh3(1) + u64(0) + verf() + u32(64), u32(0) + poa(False) + verf() + boolean(0) + boolean(1))
    P(7, fh3(2) + u64(1 << 40) + u32(4) + u32(2) + opq(b'abcd'), u32(0) + wcc(False, True) + u32(4) + u32(2) + verf())
    P(6, fh3(2) + u64(1 << 40) + u32(5), u32(0) + poa(False) + u32(5) + boolean(1) + opq(b'12345'))
    P(1, fh3(1), u32(0) + fattr3(5))
    for ft in (2, 3, 4, 6, 7):
        P(1, fh3(ft), u32(0) + fattr3(ft))
    # a call that never gets a reply, a reply with an error accept state
    c.call(NFS, 3, 1, fh3(77))
    # sattr with times set to client time
    P(2, fh3(1) + (boolean(1) + u32(0o755) + boolean(0) + boolean(0) + boolean(0) + u32(1) + u32(2) + nt() + nt(2)) + boolean(0), u32(0) + wcc())

# snooping sequence: LOOKUPs build a tree, READs and GETATTRs use the file handles
def snoop(c):
    P3 = lambda proc, a, r: c.rpc(NFS, 3, proc, a, r)
    P2 = lambda proc, a, r: c.rpc(NFS, 2, proc, a, r)
    # MOUNT replies give the root of the tree: a name without a parent
    c.rpc(100005, 3, 1, opq('/export'), u32(0) + fh3(100) + arr([u32(1), u32(6)]))
    c.rpc(100005, 1, 1, opq('/export2'), u32(0) + fh2(100))
    P3(3, fh3(100) + opq('export'), u32(0) + fh3(101) + poa() + poa())
    P3(3, fh3(101) + opq('dir'), u32(0) + fh3(102) + poa() + poa())
    P3(3, fh3(102) + opq('file.txt'), u32(0) + fh3(103) + poa() + poa())
    P3(3, fh3(102) + opq('/abs/'), u32(0) + fh3(104) + poa() + poa())
    P3(3, fh3(104) + opq('sub/'), u32(0) + fh3(105) + poa() + poa())
    P3(6, fh3(103) + u64(0) + u32(16), u32(0) + poa() + u32(16) + boolean(0) + opq(b'0123456789abcdef'))
    P3(7, fh3(103) + u64(0) + u32(4) + u32(0) + opq(b'abcd'), u32(0) + wcc() + u32(4) + u32(0) + verf())
    P3(1, fh3(105), u32(0) + fattr3())
    P3(1, fh3(102), u32(0) + fattr3(2))
    None
    P3(8, fh3(102) + opq('created') + u32(0) + sattr3(), u32(0) + pofh(106) + poa() + wcc())
    P3(1, fh3(106), u32(0) + fattr3())
    P3(9, fh3(102) + opq('mk') + sattr3(), u32(0) + pofh(107) + poa() + wcc())
    P3(1, fh3(107), u32(0) + fattr3(2))
    P3(10, fh3(102) + opq('sl') + sattr3() + opq('t'), u32(0) + pofh(108) + poa() + wcc())
    P3(1, fh3(108), u32(0) + fattr3(5))
    ent = lambda fid, name, ck: boolean(1) + u64(fid) + opq(name) + u64(ck)
    entp = lambda fid, name, ck, n: ent(fid, name, ck) + poa() + pofh(n)
    P3(17, fh3(101) + u64(0) + verf() + u32(512) + u32(4096),
       u32(0) + poa() + verf() + entp(1, '.', 1, 101) + entp(2, '..', 2, 100) + entp(30, 'e1', 3, 110) + entp(31, 'e2', 4, 111) +
       ent(32, 'noh', 5) + poa(False) + boolean(0) + boolean(0) + boolean(1))
    P3(1, fh3(110), u32(0) + fattr3())
    P3(1, fh3(111), u32(0) + fattr3())
    P3(16, fh3(101) + u64(0) + verf() + u32(512), u32(0) + poa() + verf() + ent(40, 'only', 1) + boolean(0) + boolean(1))
    # READDIRPLUS whose reply has no matching call is covered by the lookups
    P3(17, fh3(120) + u64(0) + verf() + u32(512) + u32(4096),
       u32(0) + poa() + verf() + entp(50, 'x', 1, 121) + boolean(0) + boolean(1))
    P3(1, fh3(121), u32(0) + fattr3())
    # the reproducer of the empty snooped name (READDIRPLUS entry named "\0")
    P3(17, fh3(130) + u64(0) + verf() + u32(512) + u32(4096),
       u32(0) + poa() + verf() + boolean(1) + u64(42) + opq(b'\0') + u64(1) + boolean(0) + pofh(131) + boolean(0) + boolean(1))
    P3(1, fh3(131), u32(0) + fattr3())
    # empty LOOKUP name
    P3(3, fh3(100) + opq(b''), u32(0) + fh3(132) + poa() + poa())
    P3(1, fh3(132), u32(0) + fattr3())
    # a file system cycle: 150 -> 151 -> 150
    P3(3, fh3(100) + opq('cyc'), u32(0) + fh3(150) + poa() + poa())
    P3(3, fh3(150) + opq('sub'), u32(0) + fh3(151) + poa() + poa())
    P3(3, fh3(151) + opq('back'), u32(0) + fh3(150) + poa() + poa())
    P3(1, fh3(150), u32(0) + fattr3(2))
    P3(1, fh3(151), u32(0) + fattr3(2))
    # v2
    P2(4, fh2(100) + opq('export'), u32(0) + fh2(101) + fattr2())
    P2(4, fh2(101) + opq('file'), u32(0) + fh2(102) + fattr2())
    P2(6, fh2(102) + u32(0) + u32(8) + u32(8), u32(0) + fattr2() + opq(b'12345678'))
    P2(9, fh2(101) + opq('mk') + sattr2(), u32(0) + fh2(103) + fattr2())
    P2(1, fh2(103), u32(0) + fattr2())
    P2(14, fh2(101) + opq('mkd') + sattr2(), u32(0) + fh2(104) + fattr2(2))
    P2(1, fh2(104), u32(0) + fattr2(2))
    P2(16, fh2(101) + u32(0) + u32(512), u32(0) + u32(1) + u32(60) + opq('ent') + u32(1) + u32(0) + u32(1))
    # v4: PUTROOTFH LOOKUP GETFH, OPEN CLAIM_NULL + GETFH, CREATE + GETFH, then GETATTR with the new handles
    v4(c).op(24).op(15, opq('exp'), b'').op(10, b'', fh4(200)).send()
    v4(c).op(22, fh4(200)).op(15, opq('sub'), b'').op(10, b'', fh4(201)).send()
    v4(c).op(22, fh4(201)).op(18, u32(5) + u32(1) + u32(0) + u64(1) + opq('o') + u32(0) + u32(0) + opq('f.txt'),
            stateid(2) + cinfo() + u32(0) + bitmap([]) + u32(0)).op(10, b'', fh4(202)).send()
    v4(c).op(22, fh4(202)).op(9, bitmap([1]), fattr({1: u32(1)})).op(25, stateid(0) + u64(0) + u32(8), u32(1) + opq(b'12345678')).send()
    v4(c).op(22, fh4(201)).op(6, u32(2) + opq('nd') + fattr({}), cinfo() + bitmap([])).op(10, b'', fh4(203)).send()
    v4(c).op(22, fh4(203)).op(9, bitmap([1]), fattr({1: u32(2)})).send()
    v4(c).op(24).op(10, b'', fh4(204)).op(9, bitmap([1]), fattr({1: u32(2)})).send()
    v4(c).op(24).op(9, bitmap([1]), fattr({1: u32(2)})).op(10, b'', fh4(204)).send()
    v4(c).op(23).op(10, b'', fh4(205)).send()
    # READDIR with FILEHANDLE (19) attr in each entry
    ent4 = lambda ck, name, fh: boolean(1) + u64(ck) + opq(name) + fattr({1: u32(1), 19: fh4(fh)})
    v4(c).op(22, fh4(201)).op(26, u64(0) + u64(0) + u32(512) + u32(4096) + bitmap([1, 19]),
            u64(1) + ent4(1, 'rd1', 210) + ent4(2, 'rd2', 211) + boolean(0) + boolean(1)).send()
    v4(c).op(22, fh4(210)).op(9, bitmap([1]), fattr({1: u32(1)})).send()

def fhandles(c):
    """Opaque file handles in the shapes of the file handle decoders (Decode As nfs_fhandle.type)."""
    H = []
    le32 = lambda v: struct.pack('<I', v); be32 = lambda v: struct.pack('>I', v)
    le16 = lambda v: struct.pack('<H', v); be16 = lambda v: struct.pack('>H', v)
    # SVR4 / Linux: fsid, fstype, len1, data (pad2 inode gen), len2, data, [flag]
    for (e16, e32, flag) in ((le16, le32, 0), (le16, le32, 1), (be16, be32, 0), (be16, be32, 1)):
        d = e16(0) + e32(1234) + e32(5)
        h = e32(0x00010002) + e32(3) + e16(10) + d + e16(10) + d + (e32(0x80) if flag else b'')
        H.append(h)
    # Linux knfsd little endian (28 bytes)
    H.append(le32(1) + le32(2) + le32(3) + le16(0x0102) + le16(0) + le16(0x0304) + le16(0) + le32(9) + le32(10))
    H.append(le32(1) + le32(2) + le32(3) + le16(0) + le16(0) + le16(0) + le16(0) + le32(9) + le32(10))
    # Linux nfsd little endian (pseudo inode, hash path)
    H.append(le32(0x1234) + bytes([8]) + bytes(range(1, 9)))
    # NetApp ONTAP v3 (32), ONTAP v4 (28) with handle type 0 and 5
    for ht in (0,):
        H.append(le32(7) + le32(8) + b'\x01\x02\x03\x04' + be32(4444) + le32(55) + le32(66) + le32(77) + b'\x01\x00\x00\x03')
    for ht in (0, 5):
        H.append(le32(7) + le32(8) + b'\x01\x02\x03\x04' + be32(4444) + le32(55) + le32(66) + le32(ht))
    # NetApp GX v3 (>= 44): ONTAP flag set and clear
    for fl in (0x00, 0x40, 0x03):
        H.append(bytes([0x07, 2]) + le16(5) + be32(11) + be16(12) + bytes([0]) + bytes([fl]) + le32(13) + le32(14) +
                 be32(15) + be16(16) + bytes([0]) + bytes([fl]) + le32(17) + le32(18) + le32(19) + le32(20) + le32(21))
    # Linux knfsd new format: version 1, auth, fsid type, fileid type; version 2 too
    base = lambda a, f, t: bytes([1, a, f, t]) + be16(8) + be16(1) + le32(99)
    H.append(base(0, 0, 0))
    H.append(base(0, 0, 1) + le32(100) + le32(5))
    H.append(base(1, 0, 2) + le32(100) + le32(5) + le32(6))
    H.append(base(0, 1, 1) + le32(100) + le32(5))
    H.append(bytes([2, 0, 0, 0]) + b'\0' * 20)
    # Gluster
    H.append(b':OGL' + b'G' * 16 + b'H' * 16)
    H.append(b'xxxx' + b'G' * 16 + b'H' * 16)
    # dCache
    H.append(be32(0x01CAFFEE) + be32(5) + be32(6) + b'\0\0\0' + bytes([2, 3]) + b'abc' + b'\0' * 8)
    # Primary Data v0, v1, v2, v3
    for v in (0, 1, 2, 3):
        H.append(le32(0x1111) + le32((v << 28) | 0x7) + struct.pack('<QQ', 0x1234, 0x5678) + le32(1))
    # Celerra/VNX 32 and 40
    H.append(b'V' * 32)
    H.append(le32(3) + b'N' * 36)
    H.append(le32(0) + b'N' * 36)
    for i, h in enumerate(H):
        c.rpc(NFS, 3, 1, opq(h), u32(0) + fattr3())
    return len(H)

def v42(c):
    ss = arr([u32(1) + opq('srv.example.com'), u32(2) + opq('nfs://srv/x'), u32(3) + opq('tcp') + opq('192.0.2.9.8.1'), opq(b'rawdata12')])
    wr = arr([stateid(4), stateid(5)]) + u64(4096) + u32(2) + u64(0x66)
    v4(c, 2).op(22, fh4(4)).op(59, stateid(1) + u64(0) + u64(4096)).send()
    v4(c, 2).op(22, fh4(4)).op(32).op(22, fh4(5)).op(60, stateid(1) + stateid(2) + u64(0) + u64(4096) + u64(8192) + boolean(1) + boolean(0) + ss,
                wr + boolean(1) + boolean(0)).send()
    v4(c, 2).op(22, fh4(4)).op(60, stateid(1) + stateid(2) + u64(0) + u64(0) + u64(0) + boolean(0) + boolean(0) + arr([]),
                status=10036, rawres=b'').send()
    v4(c, 2).op(60, stateid(1) + stateid(2) + u64(0) + u64(0) + u64(0) + boolean(0) + boolean(0) + arr([]),
                status=10090, res=boolean(1) + boolean(1)).send()
    v4(c, 2).op(22, fh4(4)).op(61, stateid(1) + u32(3) + opq('tcp') + opq('192.0.2.1.8.1'),
                nfstime4() + stateid(7) + ss).send()
    v4(c, 2).op(22, fh4(4)).op(62, stateid(1) + u64(0) + u64(1 << 20)).send()
    v4(c, 2).op(22, fh4(4)).op(63, stateid(1) + u64(0) + u64(4096) + bitmap([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10]), bitmap([0, 2])).send()
    v4(c, 2).op(22, fh4(4)).op(64, u64(0) + u64(4096) + stateid(1) + arr([devid(1) + u32(5) + u32(25), devid(2) + u32(70) + u32(26)])).send()
    io = u64(5) + u64(500) + u64(6) + u64(600)
    v4(c, 2).op(22, fh4(4)).op(65, u64(0) + u64(4096) + stateid(1) + io + devid(1) + u32(1) + opq(b'opaque-stats'), b'').send()
    lat = u64(1) + u64(2) + u64(3) + u64(4) + u64(5) + nfstime4() + nfstime4()
    ffs = opq('tcp') + opq('192.0.2.7.8.1') + fh4(13) + lat + lat + nfstime4() + boolean(0)
    v4(c, 2).op(22, fh4(4)).op(65, u64(0) + u64(4096) + stateid(1) + io + devid(1) + u32(4) + u32(len(ffs)) + ffs, b'').send()
    v4(c, 2).op(66, stateid(1)).send()
    v4(c, 2).op(67, stateid(1), u64(8192) + arr([u32(0), u32(10025)])).send()
    v4(c, 2).op(22, fh4(4)).op(68, stateid(1) + u64(0) + u32(8192),
                u32(1) + arr([u32(0) + u64(0) + opq(b'data-bytes'), u32(1) + u64(10) + u64(4096)])).send()
    v4(c, 2).op(22, fh4(4)).op(69, stateid(1) + u64(0) + u32(0), u32(0) + u64(4096)).send()
    v4(c, 2).op(22, fh4(4)).op(69, stateid(1) + u64(0) + u32(1), u32(1) + u64(8192)).send()
    app = u64(0) + u32(512) + u32(8) + u32(0) + u32(1) + u32(0) + opq(b'PATTERN!')
    v4(c, 2).op(22, fh4(4)).op(70, stateid(1) + u32(2) + app, wr).send()
    v4(c, 2).op(22, fh4(5)).op(32).op(22, fh4(4)).op(71, stateid(1) + stateid(2) + u64(0) + u64(0) + u64(4096)).send()
    v4(c, 2).op(22, fh4(4)).op(72, opq('user.attr'), opq(b'xattr-data')).send()
    v4(c, 2).op(22, fh4(4)).op(73, u32(1) + opq('user.attr') + opq(b'xattr-data'), cinfo()).send()
    v4(c, 2).op(22, fh4(4)).op(74, u64(0) + u32(4096), u64(7) + arr([opq('user.a'), opq('user.b')]) + u32(1)).send()
    v4(c, 2).op(22, fh4(4)).op(75, opq('user.attr'), cinfo()).send()

def callbacks(c):
    CBP = 0x40000000
    def cb(ops, rops, minor=1, **kw):
        a = opq('cbtag') + u32(minor) + u32(55) + u32(len(ops)) + b''.join(ops)
        r = u32(0) + opq('cbtag') + u32(len(rops)) + b''.join(rops)
        c.rpc(CBP, 1, 1, a, r, sport=2049, dport=4000)
    c.rpc(CBP, 1, 0, b'', b'', sport=2049, dport=4000)
    sess = sessid()
    cb([u32(11) + sess + u32(5) + u32(0) + u32(1) + boolean(0) + arr([sess + arr([u32(3) + u32(1)])]),
        u32(4) + stateid(3) + boolean(0) + fh4(1),
        u32(3) + fh4(1) + bitmap([1, 4, 33])],
       [u32(11) + u32(0) + sess + u32(5) + u32(0) + u32(1) + u32(1),
        u32(4) + u32(0),
        u32(3) + u32(0) + fattr({1: u32(1), 4: u64(10), 33: u32(0o644)})])
    cb([u32(5) + u32(1) + u32(1) + boolean(1) + u32(1) + fh4(2) + u64(0) + u64(4096) + stateid(2),
        u32(5) + u32(1) + u32(2) + boolean(0) + u32(2) + u64(1) + u64(2),
        u32(5) + u32(1) + u32(3) + boolean(0) + u32(3)],
       [u32(5) + u32(0), u32(5) + u32(0), u32(5) + u32(10050)])
    cb([u32(8) + u32(3) + bitmap([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18]),
        u32(9) + b'', u32(10), u32(7) + b'',
        u32(12) + b'', u32(14) + b'',
        u32(13) + fh4(3) + u64(1) + opq('lockowner')],
       [u32(8) + u32(0), u32(9) + u32(0), u32(10) + u32(0), u32(7) + u32(0), u32(12) + u32(0), u32(14) + u32(0), u32(13) + u32(0)])
    # CB_NOTIFY with all change kinds
    ea = opq('name') + fattr({1: u32(1), 4: u64(7)})
    rem = ea + u64(5)
    add = u32(1) + rem + ea + u32(1) + u64(9) + u32(1) + rem + boolean(1)
    add0 = u32(0) + ea + u32(0) + u32(0) + boolean(0)
    ren = rem + add
    def nvals(mask_bits, body):
        return bitmap(mask_bits) + opq(body)
    ch = [nvals([0], ea), nvals([1], ea), nvals([2], rem), nvals([3], add), nvals([3], add0), nvals([4], ren), nvals([0, 1, 2, 3, 4], ea + ea + rem + add + ren)]
    cb([u32(6) + stateid(1) + fh4(1) + arr(ch)], [u32(6) + u32(0)])
    cb([u32(6) + stateid(1) + fh4(1) + arr([])], [u32(6) + u32(0)])
    cb([u32(15) + fh4(1) + stateid(1) + u32(0) + wr_resp() , u32(15) + fh4(1) + stateid(1) + u32(10) + u64(77)],
       [u32(15) + u32(0), u32(15) + u32(0)])
    cb([u32(10044)], [u32(10044) + u32(10044)])
    None
    cb([u32(4) + stateid(3) + boolean(1) + fh4(1)], [u32(4) + u32(10025)], minor=0)

def wr_resp():
    return arr([stateid(4)]) + u64(4096) + u32(2) + u64(0x66)

def v4_misc(c):
    impl = arr([])
    v4(c, 1).op(42, u64(0x77) + opq('co-owner') + u32(0x101) + u32(7) + impl,
                u64(0x4242) + u32(1) + u32(0x10001) + u32(7) + u64(1) + opq('major-id') + opq('scope') + impl).send()
    own = u64(0xabc) + opq('owner1')
    ores = lambda dg: stateid(2) + cinfo() + u32(0) + bitmap([]) + dg
    v4(c, 1).op(22, fh4(3)).op(18, u32(5) + u32(1) + u32(0) + own + u32(0) + u32(0) + opq('f'), ores(u32(9))).send()
    v4(c, 1).op(22, fh4(3)).op(18, u32(5) + u32(2) + u32(0) + own + u32(0) + u32(0) + opq('f'),
               ores(u32(2) + stateid(4) + boolean(0) + u32(9) + ace(1, 0, 0x6, 'GROUP@'))).send()
    v4(c, 1).op(22, fh4(3)).op(18, u32(5) + u32(1) + u32(0) + own + u32(0) + u32(0) + opq('f'),
               ores(u32(0))).send()
    v4(c, 2).op(22, fh4(4)).op(68, stateid(1) + u64(0) + u32(8), u32(0) + arr([u32(9)])).send()
    v4(c, 1).op(22, fh4(3)).op(9, bitmap([1]), fattr({1: u32(2)})).op(28, opq('gone'), status=2).send()
    # create_session with a callback security parameter list that has no entries
    ca0 = u32(0) + u32(4096) + u32(4096) + u32(0) + u32(2) + u32(2) + u32(0)
    v4(c, 1).op(43, u64(0x4242) + u32(2) + u32(0) + ca0 + ca0 + u32(0x40000000) + arr([]), sessid() + u32(2) + u32(0) + ca0 + ca0).send()
    # COPY failing with NFS4ERR_OFFLOAD_NO_REQS returns the copy requirements
    v4(c, 2).op(60, stateid(1) + stateid(2) + u64(0) + u64(0) + u64(0) + boolean(0) + boolean(0) + arr([]),
                status=10094, res=boolean(1) + boolean(0)).send()
    # SETATTR failing still returns the attributes it did set
    v4(c).op(22, fh4(3)).op(34, stateid(0) + fattr({33: u32(0o644)}), status=13, res=bitmap([])).send()
    v4(c).op(22, fh4(3)).op(34, stateid(0) + fattr({33: u32(0o644)}), status=10032, res=bitmap([33])).send()

def build_main(c):
    v2(c)
    v3(c)
    errors_v2_v3(c)
    v3_odd(c)
    v40_basic(c)
    v41(c)
    v41_pnfs(c)
    v42(c)
    v4_misc(c)
    callbacks(c)
    snoop(c)
    fhandles(c)

def build_malformed(c):
    # --- reproducers of the fixes (see README)
    # 1. file name snooping: directory file handle length 0x80000000
    c.call(NFS, 3, 17, u32(0x80000000) + b'A' * 8 + u64(0) + u64(0) + u32(512) + u32(4096))
    # 2. SCSI layout: CONCAT / STRIPE volume with 0xffffffff indices
    gd = lambda body: v4(c, 1).op(47, devid(1) + u32(5) + u32(4096) + bitmap([]), u32(5) + opq(body) + bitmap([]))
    for vt, pre in ((2, b''), (3, u64(65536))):
        gd(u32(1) + u32(vt) + pre + u32(0xffffffff) + b'\0' * 16).send()
    # 3. device list with 0xffffffff devices
    v4(c, 1).op(48, u32(1) + u32(4096) + u64(0) + u64(0), u64(0) + u64(0) + u32(0xffffffff) + b'\0' * 16 + u32(1)).send()
    # --- snooping with unusable file handle lengths (zero, larger than 128)
    c.call(NFS, 3, 17, opq(b'') + u64(0) + u64(0) + u32(512) + u32(4096))
    c.call(NFS, 3, 17, opq(b'D' * 200) + u64(0) + u64(0) + u32(512) + u32(4096))
    x = c.call(NFS, 3, 3, fh3(9) + opq('n'))
    c.reply(x, u32(0) + opq(b'E' * 200) + poa() + poa())
    x = c.call(NFS, 3, 3, fh3(9) + opq('n'))
    c.reply(x, u32(0) + u32(0) + poa() + poa())
    x = c.call(NFS, 4, 1, opq('') + u32(0) + u32(3) + u32(24) + u32(15) + opq('a') + u32(10))
    c.reply(x, u32(0) + opq('') + u32(3) + u32(24) + u32(0) + u32(15) + u32(0) + u32(10) + u32(0) + u32(0x80000000))
    None
    # --- too many operations (129 PUTROOTFH) in a call and a reply
    cc = v4(c)
    for _ in range(129):
        cc.op(24)
    cc.send()
    # --- bitmap with far too many words
    v4(c).op(22, fh4(1)).op(9, u32(1000)).send()
    v4(c).op(22, fh4(1)).op(9, bitmap([1]), u32(1000)).send()
    # --- operation numbers outside the table
    v4(c).op(100, b'', b'').send()
    v4(c).op(2, b'', b'').send()
    # --- unknown security flavour in a callback security parameter list
    ca0 = u32(0) + u32(4096) + u32(4096) + u32(0) + u32(2) + u32(2) + u32(0)
    v4(c, 1).op(43, u64(1) + u32(1) + u32(0) + ca0 + ca0 + u32(0x40000000) + arr([u32(99)]), b'').send()
    # --- layout with a huge segment count, huge notify change count, huge stateid array
    v4(c, 1).op(22, fh4(4)).op(50, boolean(0) + u32(1) + u32(1) + u64(0) + u64(1) + u64(1) + stateid(1) + u32(1),
                boolean(0) + stateid(5) + u32(0xffffff)).send()
    v4(c, 1).op(55, u32(0xffffffff), u32(0xffffffff)).send()
    # --- directory entry whose name length is far larger than the frame
    v4(c).op(22, fh4(3)).op(26, u64(0) + u64(0) + u32(100) + u32(100) + bitmap([]),
          u64(0) + boolean(1) + u64(1) + u32(0x7fffffff) + b'abcd').send()
    # --- truncated frames: a v3 reply, a v2 call, a v4 reply in the middle of an attribute
    x = c.call(NFS, 3, 1, fh3(1)); c.reply(x, u32(0) + fattr3()[:30])
    c.call(NFS, 2, 4, fh2(1)[:20])
    d = attrs_all(1)
    x = c.call(NFS, 4, 1, opq('') + u32(0) + u32(2) + u32(22) + fh4(3) + u32(9) + bitmap(sorted(d)))
    c.reply(x, u32(0) + opq('') + u32(2) + u32(22) + u32(0) + u32(9) + u32(0) + fattr(d)[:300])
    # attribute list whose opaque length is shorter than the values
    x = c.call(NFS, 4, 1, opq('') + u32(0) + u32(2) + u32(22) + fh4(3) + u32(9) + bitmap([4, 20]))
    c.reply(x, u32(0) + opq('') + u32(2) + u32(22) + u32(0) + u32(9) + u32(0) + bitmap([4, 20]) + opq(u64(5)))
    # CLOSE reply with a real stateid (deprecated, expert info), attributes without a dissector
    v4(c).op(22, fh4(3)).op(4, u32(8) + stateid(2), stateid(5)).send()
    d = {60: u64(1) + u64(2), 63: u32(1) + opq(b'xx'), 4: u64(9)}
    v4(c).op(22, fh4(3)).op(9, bitmap([4, 60, 63]), bitmap(sorted(d)) + opq(u64(9) + u64(1) + u64(2) + u32(1) + opq(b'xx'))).send()
    v4(c).op(22, fh4(3)).op(9, bitmap([4, 100]), bitmap([4, 100]) + opq(u64(9) + u32(7))).send()
    v4(c).op(22, fh4(3)).op(9, bitmap([4, 20]), bitmap([4, 20]) + opq(u64(9))).send()
    # callback with an operation count that does not fit
    c.rpc(0x40000000, 1, 1, opq('') + u32(1) + u32(1) + u32(129) + u32(10044), u32(0) + opq('') + u32(129) + u32(10044) + u32(10044), sport=2049, dport=4000)
    # RPC reply that is not accepted, and a call of an unknown NFS version
    c.call(NFS, 5, 1, b'')
    c.call(NFS, 4, 7, b'')

if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    c = Cap(); build_main(c); c.write(os.path.join(out, 'nfs-coverage.pcap'))
    print(len(c.frames), 'frames')
    m = Cap(); m.xid = 0x9000; build_malformed(m); m.write(os.path.join(out, 'nfs-coverage-malformed.pcap'))
    print(len(m.frames), 'malformed frames')
