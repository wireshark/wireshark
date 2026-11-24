#!/usr/bin/env python3
# Generates test/captures/glusterd_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generates glusterd-coverage.pcap and glusterd-coverage-malformed.pcap
# GlusterD management, brick and friend programs (ONC-RPC 1238433, 4867634, 1238437)
# Usage: mkglusterd.py <outdir>  (synthetic; nothing comes from a real network)
import struct
import sys
import os

# ---- pcap / frame helpers ----------------------------------------------
def pcap(path, frames, linktype=1):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i // 1000, 1000 * (i % 1000), len(fr), len(fr)))
            f.write(fr)

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff

CLI = [192, 0, 2, 1]
SRV = [192, 0, 2, 2]
CMAC = bytes([2, 0, 0, 0, 0, 1])
SMAC = bytes([2, 0, 0, 0, 0, 2])
_ipid = [1]

def ip4(src, dst, proto, payload):
    _ipid[0] += 1
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), _ipid[0] & 0xffff, 0, 64, proto, 0, bytes(src), bytes(dst))
    h = h[:10] + struct.pack('!H', csum(h)) + h[12:]
    return h + payload

def eth(from_client, ippkt):
    if from_client:
        return SMAC + CMAC + b'\x08\x00' + ippkt
    return CMAC + SMAC + b'\x08\x00' + ippkt

def udp_frame(from_client, sport, dport, payload):
    src, dst = (CLI, SRV) if from_client else (SRV, CLI)
    u = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    return eth(from_client, ip4(src, dst, 17, u))

class Tcp:
    """One TCP connection; every send() is one PSH|ACK segment."""
    def __init__(self, frames, sport, dport, hs=True):
        self.f = frames; self.sport = sport; self.dport = dport
        self.cseq = 1000; self.sseq = 5000; self.acks = True
        if hs:
            self.seg(True, 0x02, b'')
            self.cseq += 1
            self.seg(False, 0x12, b'')
            self.sseq += 1
            self.seg(True, 0x10, b'')
    def seg(self, c, flags, data, seq=None):
        src, dst = (CLI, SRV) if c else (SRV, CLI)
        sp, dp = (self.sport, self.dport) if c else (self.dport, self.sport)
        s = (self.cseq if c else self.sseq) if seq is None else seq
        a = self.sseq if c else self.cseq
        if flags == 0x02:
            a = 0
        opts = b'\x02\x04\x05\xb4\x04\x02\x01\x01' if flags & 2 else b''
        h = struct.pack('!HHIIBBHHH', sp, dp, s, a, (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts
        ps = struct.pack('!4s4sBBH', bytes(src), bytes(dst), 0, 6, len(h) + len(data))
        ck = csum(ps + h + data)
        h = h[:16] + struct.pack('!H', ck) + h[18:]
        self.f.append(eth(c, ip4(src, dst, 6, h + data)))
    def send(self, c, data):
        self.seg(c, 0x18, data)
        if c: self.cseq += len(data)
        else: self.sseq += len(data)
        if self.acks: self.seg(not c, 0x10, b'')
    def fin(self):
        self.seg(True, 0x11, b''); self.cseq += 1
        self.seg(False, 0x11, b''); self.sseq += 1
        self.seg(True, 0x10, b'')

# ---- XDR / ONC RPC ------------------------------------------------------
def U(v): return struct.pack('!I', v & 0xffffffff)
def Q(v): return struct.pack('!Q', v & 0xffffffffffffffff)
def pad4(b): return b + b'\0' * ((4 - len(b) % 4) % 4)
def opaque(b): return U(len(b)) + pad4(b)
def xstr(s):
    if isinstance(s, str): s = s.encode()
    return opaque(s)
def rpc_call(xid, prog, vers, proc, body):
    return struct.pack('!IIIIII', xid, 0, 2, prog, vers, proc) + U(0) * 4 + body
def rpc_reply(xid, body):
    return struct.pack('!IIIIII', xid, 1, 0, 0, 0, 0) + body
def rm(b, last=True):
    return U((0x80000000 if last else 0) | len(b)) + b

def gfid(n): return bytes([(n * 7 + i * 13 + 1) & 0xff for i in range(16)])

# ---- gluster dicts -------------------------------------------------------
def dict_old(items, extra=0):
    """Old (v1) dict: size, count, then keylen vallen key\\0 value; padded."""
    body = U(len(items))
    for k, v in items:
        if isinstance(k, str): k = k.encode()
        if isinstance(v, str): v = v.encode()
        body += U(len(k)) + U(len(v)) + k + b'\0' + v
    return U(len(body)) + pad4(body)
EMPTY_D = U(0)
def dict4(items):
    """Version 4 dict: xdr_size, count, pairs_len, then (key, type, value)."""
    body = b''
    for k, t, v in items:
        if isinstance(k, str): k = k.encode()
        body += opaque(k + b'\0') + U(t)
        if t == 2: body += struct.pack('!q', v)
        elif t == 3: body += Q(v)
        elif t == 4: body += struct.pack('!d', v)
        elif t == 5: body += opaque(v if isinstance(v, bytes) else v.encode() + b'\0')
        elif t in (1, 6): body += opaque(v)
        elif t == 7: body += v
        elif t == 8: body += v
        else: raise ValueError(t)
    return U(len(body) + 8) + U(len(items)) + U(len(items)) + body
EMPTY_X = U(0) + U(0) + U(0)

# ---- gluster structures --------------------------------------------------
def iatt(n=0, ino=7):
    return (gfid(n) + Q(ino) + Q(2049) + U(0o100644) + U(1 + n) + U(1000) + U(100) +
            Q(0) + Q(4096 * (n + 1)) + U(4096) + Q(8 * (n + 1)) +
            U(1700000000) + U(11) + U(1700000001) + U(22) + U(1700000002) + U(33))
def iattx(n=0, ino=7):
    return (gfid(n) + Q(0x7ff) + Q(ino) + Q(2049) + Q(0) + Q(4096 * (n + 1)) + Q(8) +
            Q(0x10) + Q(0x20) + Q(1700000000) + Q(1700000001) + Q(1700000002) + Q(1700000003) +
            U(11) + U(22) + U(33) + U(44) + U(1 + n) + U(1000) + U(100) + U(4096) + U(0o100644))
def flock_old(t=1):
    return U(t) + U(0) + Q(0) + Q(100) + U(1234) + b'OWNER123'
def flock2(t=1, owner=b'ABCDE'):
    return U(t) + U(0) + Q(0) + Q(100) + U(1234) + opaque(owner)

# ---- transports ------------------------------------------------------------
class Udp:
    def __init__(self, frames, sport, dport=24007):
        self.f = frames; self.sport = sport; self.dport = dport
    def call(self, b): self.f.append(udp_frame(True, self.sport, self.dport, b))
    def reply(self, b): self.f.append(udp_frame(False, self.dport, self.sport, b))
class TcpRpc:
    def __init__(self, frames, sport, dport=24007):
        self.t = Tcp(frames, sport, dport)
    def call(self, b): self.t.send(True, rm(b))
    def reply(self, b): self.t.send(False, rm(b))

_xid = [0x1000]
def xid():
    _xid[0] += 1
    return _xid[0]
def pair(tr, prog, vers, proc, cbody, rbody, x=None):
    x = x or xid()
    tr.call(rpc_call(x, prog, vers, proc, cbody))
    tr.reply(rpc_reply(x, rbody))
    return x
def R(ret=0, err=0): return U(ret) + U(err)

# ---- token based payload encoder (gluster FOP structures) -------------------
ERRS = [0, 2, 13, 17, 28, 61, 107, 1024, 99999, 5]
FLAGS = [0, 1, 2, 3, 0x42, 0x8241, 0x2400, 0xffffffff, 0x10002, 0x1000]
MODES = [0o100644, 0o4755, 0o41777, 0, 0xffffffff, 0o2777, 0o600]
def pick(lst, v): return lst[v % len(lst)]
def dict_variants():
    return [EMPTY_D,
            dict_old([('key1', 'value')]),
            dict_old([('gfid-req', gfid(1)), ('trusted.afr.vol-client-0', b'\1\0\0\0\2\0\0\0\3\0\0\0'),
                      ('transaction_id', gfid(2)), ('originator_uuid', gfid(3)), ('path', '/a/b')]),
            dict_old([('glusterfs.xattr', 'x' * 7), ('empty', ''), ('k', 'v' * 3)])]
def dict4_variants():
    return [EMPTY_X,
            dict4([('k-int', 2, -5), ('k-uint', 3, 2 ** 40), ('k-double', 4, 1.5), ('k-str', 5, 'str'),
                   ('k-ptr', 6, b'opaque12'), ('k-gfid', 7, gfid(3)), ('k-iatt', 8, iattx(1)),
                   ('k-old-str', 1, b'old'), ('gfid-req', 6, gfid(2)),
                   ('trusted.afr.vol-client-1', 6, b'\1\0\0\0\2\0\0\0\3\0\0\0'),
                   ('transaction_id', 6, gfid(4)), ('originator_uuid', 6, gfid(5))]),
            dict4([('only', 5, 'x')]),
            dict4([('a', 3, 1), ('bb', 3, 2), ('ccc', 3, 3)])]
DV = dict_variants(); XV = dict4_variants()
_fc = [0]

def enc(toks, v, name=''):
    """toks: space separated token string. v: variant number."""
    out = b''
    k = 0
    toks = toks.split(' ') if isinstance(toks, str) else toks
    # re-join list tokens "L(Q Q U ...)" that were split on spaces
    j = []; cur = None
    for t in toks:
        if cur is not None:
            cur += ' ' + t
            if t.endswith(')'): j.append(cur); cur = None
        elif t.startswith('L(') and not t.endswith(')'):
            cur = t
        else:
            j.append(t)
    for t in j:
        k += 1
        if t == 'G': out += gfid(v * 5 + k)
        elif t == 'S':
            out += xstr('' if (name == 'LOOKUP' and v == 1 and k == 3) else pick(['/dir/file%d' % k, 'name-%d' % k, '', 'a-longer-brick-or-path-name/%d' % v], v + k))
        elif t == 'U': out += U(pick([0, 1, 4096, 0xffffffff, 7, 2], v + k))
        elif t == 'Q': out += Q(pick([0x1234, 0, 0x7fffffffffffffff, 65536, 99], v + k))
        elif t == 'F':
            out += U(pick(FLAGS, _fc[0])); _fc[0] += 1
        elif t == 'M': out += U(pick(MODES, v + k))
        elif t == 'P': out += U(pick([0x01, 0x7f, 0, 0x08, 0x30, 0x06, 0xffffffff], v))
        elif t == 'T': out += Q(4096) + Q(4096) + Q(1000000) + Q(500000) + Q(400000) + Q(65536) + Q(60000) + Q(55000) + Q(0xabc) + Q(pick([0x1, 0x3ff, 0, 0x0fff], v)) + Q(255)
        elif t == 'D': out += pick(DV, v + k)
        elif t == 'X': out += pick(XV, v + k)
        elif t == 'I': out += iatt(v + k)
        elif t == 'J': out += iattx(v + k)
        elif t == 'R':
            e = pick(ERRS, v)
            out += R(0 if e == 0 else -1, e)
        elif t == 'N': out += U(2 - v if v < 3 else 0) + U(pick([0, 2, 5], v))
        elif t == 'K': out += flock2(pick([0, 1, 2, 3], v), pick([b'ABCDE', b'', b'1234', b'x', b'0123456789abcdef'], v + k))
        elif t == 'Z': out += flock_old(pick([0, 1, 2], v))
        elif t == 'Y': out += U(pick([1, 2, 3], v)) + U(pick([0, 1, 2], v)) + bytes(range(16)) + U(v)
        elif t == 'O': out += opaque(pick([b'strongchecksum20bytes!', b'', b'abcde'], v))
        elif t.startswith('L('):
            inner = t[2:-1]
            n = 2 if v == 0 else (1 if v == 1 else 0)
            for i in range(n):
                out += U(1) + enc(inner, v + i, name)
            out += U(0)
        elif t == 'UNK':
            out += bytes(range(8 * (v + 1)))
        else:
            raise ValueError(t)
    return out


MGMT = 1238433
BRICK = 4867634
FRIEND = 1238437

def uuid(n):
    """glusterd UUIDs travel as 16 XDR words of one octet value each"""
    return b''.join(U((n * 17 + i * 5) & 0xff) for i in range(16))

def build(outdir):
    f = []
    d = dict_variants()
    def run(tr):
        # ---- GD_MGMT version 1 ------------------------------------------------------------
        pair(tr, MGMT, 1, 0, b'', b'')
        pair(tr, MGMT, 1, 1, uuid(1) + xstr('peer1.example.net') + U(24007), uuid(2) + xstr('peer2.example.net') + U(24007) + R(0, 0))
        pair(tr, MGMT, 1, 1, uuid(3) + xstr('') + U(0), uuid(4) + xstr('x') + U(1) + R(-1, 107))
        pair(tr, MGMT, 1, 2, uuid(1) + xstr('peer1.example.net') + U(24007) + d[2], uuid(2) + xstr('peer2.example.net') + R(0, 0) + U(24007))
        pair(tr, MGMT, 1, 2, uuid(1) + xstr('peer1.example.net') + U(24007) + EMPTY_D, uuid(2) + xstr('peer2') + R(-1, 17) + U(0))
        pair(tr, MGMT, 1, 3, uuid(5), uuid(6) + R(0, 0))
        pair(tr, MGMT, 1, 4, uuid(5), uuid(6) + R(-1, 16))
        pair(tr, MGMT, 1, 5, uuid(5) + U(1) + d[1], uuid(6) + R(0, 0) + xstr('') + d[3])
        pair(tr, MGMT, 1, 5, uuid(5) + U(14) + EMPTY_D, uuid(6) + R(-1, 22) + xstr('stage failed on peer') + EMPTY_D)
        pair(tr, MGMT, 1, 6, uuid(5) + U(2) + d[2], uuid(6) + R(0, 0) + d[1] + xstr(''))
        pair(tr, MGMT, 1, 6, uuid(5) + U(30) + d[0], uuid(6) + R(-1, 5) + d[0] + xstr('commit failed'))
        pair(tr, MGMT, 1, 8, uuid(7) + d[1] + U(24007), uuid(8) + U(3) + R(0, 0))
        for proc in (7, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34):
            pair(tr, MGMT, 1, proc, bytes(range(12)), R(0, 0) + bytes(range(4)))
        pair(tr, MGMT, 1, 35, b'', b'')                                   # past the end of the table
        # ---- GD_MGMT version 2 ---------------------------------------------------------------
        pair(tr, MGMT, 2, 0, b'', b'')
        pair(tr, MGMT, 2, 1, uuid(1), uuid(2) + R(0, 0))
        pair(tr, MGMT, 2, 2, uuid(1), uuid(2) + R(-1, 16))
        pair(tr, MGMT, 2, 3, uuid(1) + U(7) + d[1], uuid(2) + U(7) + R(0, 0) + xstr('') + d[2])
        pair(tr, MGMT, 2, 3, uuid(1) + U(8) + EMPTY_D, uuid(2) + U(8) + R(-1, 22) + xstr('error string') + EMPTY_D)
        pair(tr, MGMT, 2, 4, uuid(1) + U(9) + d[3], uuid(2) + U(9) + R(0, 0) + d[1] + xstr(''))
        pair(tr, MGMT, 2, 4, uuid(1) + U(10) + d[0], uuid(2) + U(10) + R(-1, 5) + d[0] + xstr('commit failed'))
        # ---- GD_MGMT version 3 (the mgmt_v3 transaction) --------------------------------------
        pair(tr, MGMT, 3, 0, b'', b'')
        pair(tr, MGMT, 3, 1, uuid(1) + uuid(9) + U(3) + d[1], uuid(2) + uuid(9) + d[2] + R(0, 0))
        pair(tr, MGMT, 3, 6, uuid(1) + uuid(9) + U(3) + d[0], uuid(2) + uuid(9) + d[0] + R(-1, 16))
        for proc in (2, 3):
            pair(tr, MGMT, 3, proc, uuid(1) + U(11 + proc) + d[1], uuid(2) + U(11 + proc) + R(0, 0) + xstr('') + d[2])
        pair(tr, MGMT, 3, 4, uuid(1) + U(15) + d[3], uuid(2) + U(15) + R(0, 0) + d[1] + xstr(''))
        pair(tr, MGMT, 3, 4, uuid(1) + U(16) + d[0], uuid(2) + U(16) + R(-1, 22) + d[0] + xstr('commit error'))
        pair(tr, MGMT, 3, 5, uuid(1) + U(17) + U(0) + d[1], uuid(2) + U(17) + R(0, 0) + xstr('') + d[2])
        pair(tr, MGMT, 3, 5, uuid(1) + U(18) + U(0xffffffff) + d[0], uuid(2) + U(18) + R(-1, 5) + xstr('post validation failed') + d[0])
        pair(tr, MGMT, 3, 7, b'', b'')                                    # past the end of the table
        # ---- GD_BRICK version 2 --------------------------------------------------------------------
        pair(tr, BRICK, 2, 0, b'', b'')
        for proc in range(1, 9):
            pair(tr, BRICK, 2, proc, xstr('/bricks/b%d' % proc) + U(proc) + d[proc % 4],
                 R(0 if proc % 2 else -1, 0 if proc % 2 else 2) + xstr('' if proc % 2 else 'brick op failed') + d[(proc + 1) % 4])
        pair(tr, BRICK, 2, 9, b'', b'')
        # ---- GD_FRIEND version 2 (not decoded) -------------------------------------------------
        pair(tr, FRIEND, 2, 0, b'', b'')
        for proc in range(1, 5):
            pair(tr, FRIEND, 2, proc, bytes(range(16)), R(0, 0) + bytes(range(4)))
    # the glusterd operation values: every value of the operation enum
    tcp = TcpRpc(f, 45001, 24007); tcp.t.acks = False
    run(tcp)
    n_tcp = len(f)
    t = Udp(f, 45002)
    for op in range(0, 60, 3):
        pair(t, MGMT, 2, 3, uuid(op) + U(op) + d[op % 4], uuid(op + 1) + U(op) + R(0, 0) + xstr('') + d[(op + 1) % 4])
    run(t)
    pcap(os.path.join(outdir, 'glusterd-coverage.pcap'), f)
    print('TCP: 1-%d, UDP: %d-%d' % (n_tcp, n_tcp + 1, len(f)))

    m = []
    u = Udp(m, 46001)
    pair(u, MGMT, 1, 1, uuid(1)[:30], uuid(1)[:20])                    # cut in the UUID
    pair(u, MGMT, 1, 1, uuid(1) + U(1000) + b'abc', uuid(1) + xstr('h'))
    pair(u, MGMT, 1, 2, uuid(1) + xstr('h') + U(1), uuid(2) + xstr('h') + R(0, 0))
    pair(u, MGMT, 1, 5, uuid(1) + U(1), uuid(2) + R(0, 0) + U(0x7fffffff))
    pair(u, MGMT, 1, 6, uuid(1) + U(1) + U(0x40) + U(0xffffffff) + b'\0' * 8, uuid(2) + R(0, 0) + U(0x40) + U(0xffffffff))
    pair(u, MGMT, 1, 8, uuid(1) + d[1], uuid(2) + U(3))
    pair(u, MGMT, 2, 3, uuid(1), uuid(2) + U(7))
    pair(u, MGMT, 3, 1, uuid(1) + uuid(2)[:40], uuid(1) + uuid(2))
    pair(u, MGMT, 3, 5, uuid(1) + U(3), uuid(1) + U(3) + R(0, 0))
    pair(u, BRICK, 2, 1, xstr('b') , R(0, 0))
    pair(u, BRICK, 2, 2, U(5000) + b'ab', b'')
    pcap(os.path.join(outdir, 'glusterd-coverage-malformed.pcap'), m)
    print('malformed frames: %d' % len(m))

if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    build(out)
