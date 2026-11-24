#!/usr/bin/env python3
# Generates test/captures/glusterfs_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generates glusterfs-coverage.pcap and glusterfs-coverage-malformed.pcap
# GlusterFS FOP program (ONC-RPC program 1298437, versions 310, 330 and 400)
# Usage: mkglusterfs.py <outdir>  (synthetic; nothing comes from a real network)
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


GFS = 1298437
OPS = ['NULL', 'STAT', 'READLINK', 'MKNOD', 'MKDIR', 'UNLINK', 'RMDIR', 'SYMLINK', 'RENAME', 'LINK', 'TRUNCATE', 'OPEN', 'READ', 'WRITE', 'STATFS', 'FLUSH', 'FSYNC', 'SETXATTR', 'GETXATTR', 'REMOVEXATTR', 'OPENDIR', 'FSYNCDIR', 'ACCESS', 'CREATE', 'FTRUNCATE', 'FSTAT', 'LK', 'LOOKUP', 'READDIR', 'INODELK', 'FINODELK', 'ENTRYLK', 'FENTRYLK', 'XATTROP', 'FXATTROP', 'FGETXATTR', 'FSETXATTR', 'RCHECKSUM', 'SETATTR', 'FSETATTR', 'READDIRP', 'RELEASE', 'RELEASEDIR', 'FREMOVEXATTR', 'FALLOCATE', 'DISCARD', 'ZEROFILL', 'IPC', 'SEEK', 'COMPOUND', 'LEASE', 'GETACTIVELK', 'SETACTIVELK', 'ICREATE', 'NAMELINK', 'PUT', 'COPY_FILE_RANGE']
V310 = [
    ('NULL', 'NULL', None, None),
    ('STAT', 'STAT', 'UNK', 'UNK'),
    ('READLINK', 'READLINK', 'UNK', 'UNK'),
    ('MKNOD', 'MKNOD', 'UNK', 'UNK'),
    ('MKDIR', 'MKDIR', 'UNK', 'UNK'),
    ('UNLINK', 'UNLINK', 'G S S', 'I I'),
    ('RMDIR', 'RMDIR', 'UNK', 'UNK'),
    ('SYMLINK', 'SYMLINK', 'UNK', 'UNK'),
    ('RENAME', 'RENAME', 'UNK', 'UNK'),
    ('LINK', 'LINK', 'UNK', 'UNK'),
    ('TRUNCATE', 'TRUNCATE', 'UNK', 'UNK'),
    ('OPEN', 'OPEN', 'UNK', 'UNK'),
    ('READ', 'READ', 'UNK', 'UNK'),
    ('WRITE', 'WRITE', 'UNK', 'UNK'),
    ('STATFS', 'STATFS', 'G S', 'R T'),
    ('FLUSH', 'FLUSH', 'G Q', 'R'),
    ('FSYNC', 'FSYNC', 'UNK', 'UNK'),
    ('SETXATTR', 'SETXATTR', 'G F D S', 'R'),
    ('GETXATTR', 'GETXATTR', 'UNK', 'UNK'),
    ('REMOVEXATTR', 'REMOVEXATTR', 'UNK', 'UNK'),
    ('OPENDIR', 'OPENDIR', 'G S', 'R Q'),
    ('FSYNCDIR', 'FSYNCDIR', 'UNK', 'UNK'),
    ('ACCESS', 'ACCESS', 'UNK', 'UNK'),
    ('CREATE', 'CREATE', 'G F M S S D', 'R I Q I I'),
    ('FTRUNCATE', 'FTRUNCATE', 'UNK', 'UNK'),
    ('FSTAT', 'FSTAT', 'UNK', 'UNK'),
    ('LK', 'LK', 'UNK', 'UNK'),
    ('LOOKUP', 'LOOKUP', 'G G F S S D', 'R I I D'),
    ('READDIR', 'READDIR', 'UNK', 'UNK'),
    ('INODELK', 'INODELK', 'G U U Z S S', 'R'),
    ('FINODELK', 'FINODELK', 'UNK', 'UNK'),
    ('ENTRYLK', 'ENTRYLK', 'UNK', 'UNK'),
    ('FENTRYLK', 'FENTRYLK', 'UNK', 'UNK'),
    ('XATTROP', 'XATTROP', 'UNK', 'UNK'),
    ('FXATTROP', 'FXATTROP', 'UNK', 'UNK'),
    ('FGETXATTR', 'FGETXATTR', 'UNK', 'UNK'),
    ('FSETXATTR', 'FSETXATTR', 'UNK', 'UNK'),
    ('RCHECKSUM', 'RCHECKSUM', 'UNK', 'UNK'),
    ('SETATTR', 'SETATTR', 'G I P S', 'R I I'),
    ('FSETATTR', 'FSETATTR', 'G I P S', 'R I I'),
    ('READDIRP', 'READDIRP', 'G Q Q U', 'N L(Q Q U U S I)'),
    ('RELEASE', 'RELEASE', 'UNK', 'UNK'),
    ('RELEASEDIR', 'RELEASEDIR', 'UNK', 'UNK'),
]
V330 = [
    ('NULL', 'NULL', None, None),
    ('STAT', 'STAT', 'G D', 'R I D'),
    ('READLINK', 'READLINK', 'G U D', 'R I S D'),
    ('MKNOD', 'MKNOD', 'G Q M M S D', 'R I I I D'),
    ('MKDIR', 'MKDIR', 'G M M S D', 'R I I I D'),
    ('UNLINK', 'UNLINK', 'G S U D', 'R I I D'),
    ('RMDIR', 'RMDIR', 'G U S D', 'R I I D'),
    ('SYMLINK', 'SYMLINK', 'G S M S D', 'R I I I D'),
    ('RENAME', 'RENAME', 'G G S S D', 'R I I I I I D'),
    ('LINK', 'LINK', 'G G S D', 'R I I I D'),
    ('TRUNCATE', 'TRUNCATE', 'G Q D', 'R I I D'),
    ('OPEN', 'OPEN', 'G F D', 'R Q D'),
    ('READ', 'READ', 'G Q Q U F D', 'R I U D'),
    ('WRITE', 'WRITE', 'G Q Q U F D', 'R I I D'),
    ('STATFS', 'STATFS', 'G D', 'R T D'),
    ('FLUSH', 'FLUSH', 'G Q D', 'R D'),
    ('FSYNC', 'FSYNC', 'G Q U D', 'R I I D'),
    ('SETXATTR', 'SETXATTR', 'G F D D', 'R D'),
    ('GETXATTR', 'GETXATTR', 'G U S D', 'R D D'),
    ('REMOVEXATTR', 'REMOVEXATTR', 'G S D', 'R D'),
    ('OPENDIR', 'OPENDIR', 'G D', 'R Q D'),
    ('FSYNCDIR', 'FSYNCDIR', 'G Q U D', 'R D'),
    ('ACCESS', 'ACCESS', 'G U D', 'R D'),
    ('CREATE', 'CREATE', 'G F M M S D', 'R I Q I I D'),
    ('FTRUNCATE', 'FTRUNCATE', 'G Q Q D', 'R I I D'),
    ('FSTAT', 'FSTAT', 'G Q D', 'R I D'),
    ('LK', 'LK', 'G Q U U K D', 'R K D'),
    ('LOOKUP', 'LOOKUP', 'G G F S D', 'R I I D'),
    ('READDIR', 'READDIR', 'G Q Q U D', 'N L(Q Q U U S) D'),
    ('INODELK', 'INODELK', 'G U U K S D', 'R D'),
    ('FINODELK', 'FINODELK', 'G Q U U K S D', 'R D'),
    ('ENTRYLK', 'ENTRYLK', 'G U U Q S S D', 'R D'),
    ('FENTRYLK', 'FENTRYLK', 'G Q U U Q S S D', 'R D'),
    ('XATTROP', 'XATTROP', 'G F D D', 'R D D'),
    ('FXATTROP', 'FXATTROP', 'G F Q D D', 'R D D'),
    ('FGETXATTR', 'FGETXATTR', 'G Q U S D', 'R D D'),
    ('FSETXATTR', 'FSETXATTR', 'G Q F D D', 'R D'),
    ('RCHECKSUM', 'RCHECKSUM', 'UNK', 'UNK'),
    ('SETATTR', 'SETATTR', 'G I P D', 'R I I D'),
    ('FSETATTR', 'FSETATTR', 'G I P D', 'R I I D'),
    ('READDIRP', 'READDIRP', 'G Q Q U D', 'N L(Q Q U U S I D) D'),
    ('RELEASE', 'RELEASE', 'G Q D', 'R D'),
    ('RELEASEDIR', 'RELEASEDIR', 'G Q D', 'R D'),
    ('FREMOVEXATTR', 'FREMOVEXATTR', 'G Q S D', 'R D'),
    ('FALLOCATE', 'FALLOCATE', 'G Q F Q U D', 'R I I D'),
    ('DISCARD', 'DISCARD', 'G Q Q U D', 'R I I D'),
    ('ZEROFILL', 'ZEROFILL', 'G Q Q Q', 'R I I D'),
    ('SEEK', 'SEEK', 'G Q Q U D', 'R Q D'),
]
V400 = [
    ('NULL', 'NULL', None, None),
    ('STAT', 'STAT', 'G X', 'R X J'),
    ('READLINK', 'READLINK', 'G U X', 'R X J S'),
    ('MKNOD', 'MKNOD', 'G Q M M S X', 'R X J J J'),
    ('MKDIR', 'MKDIR', 'G M M S X', 'R X J J J'),
    ('UNLINK', 'UNLINK', 'G S U X', 'R X J J'),
    ('RMDIR', 'RMDIR', 'G U S X', 'R X J J'),
    ('SYMLINK', 'SYMLINK', 'G S M S X', 'R X J J J'),
    ('RENAME', 'RENAME', 'G G S S X', 'R X J J J J J'),
    ('LINK', 'LINK', 'G G S X', 'R X J J J'),
    ('TRUNCATE', 'TRUNCATE', 'G Q X', 'R X J J'),
    ('OPEN', 'OPEN', 'G F X', 'R X Q'),
    ('READ', 'READ', 'G Q Q U F X', 'R J U X'),
    ('WRITE', 'WRITE', 'G Q Q U F X', 'R X J J'),
    ('STATFS', 'STATFS', 'G X', 'R X T'),
    ('FLUSH', 'FLUSH', 'G Q X', 'R X'),
    ('FSYNC', 'FSYNC', 'G Q U X', 'R X J J'),
    ('SETXATTR', 'SETXATTR', 'G F X X', 'R X'),
    ('GETXATTR', 'GETXATTR', 'G U S X', 'R X X J J'),
    ('REMOVEXATTR', 'REMOVEXATTR', 'G S X', 'R X'),
    ('OPENDIR', 'OPENDIR', 'G X', 'R X Q'),
    ('FSYNCDIR', 'FSYNCDIR', 'G Q U X', 'R X'),
    ('ACCESS', 'ACCESS', 'G U X', 'R X'),
    ('CREATE', 'CREATE', 'G F M M S X', 'R X J Q J J'),
    ('FTRUNCATE', 'FTRUNCATE', 'G Q Q X', 'R X J J'),
    ('FSTAT', 'FSTAT', 'G Q X', 'R X J'),
    ('LK', 'LK', 'G Q U U K X', 'R X K'),
    ('LOOKUP', 'LOOKUP', 'G G F S X', 'R X J J'),
    ('READDIR', 'READDIR', 'G Q Q U X', 'N X L(Q Q U U S)'),
    ('INODELK', 'INODELK', 'G U U K S X', 'R X'),
    ('FINODELK', 'FINODELK', 'G Q U U K S X', 'R X'),
    ('ENTRYLK', 'ENTRYLK', 'G U U Q S S X', 'R X'),
    ('FENTRYLK', 'FENTRYLK', 'G Q U U Q S S X', 'R X'),
    ('XATTROP', 'XATTROP', 'G F X X', 'R X X J J'),
    ('FXATTROP', 'FXATTROP', 'G Q F X X', 'R X X J J'),
    ('FGETXATTR', 'FGETXATTR', 'G Q U S X', 'R X X J J'),
    ('FSETXATTR', 'FSETXATTR', 'G Q F X X', 'R X'),
    ('RCHECKSUM', 'RCHECKSUM', 'G Q Q U U X', 'R X U U O'),
    ('SETATTR', 'SETATTR', 'G J P X', 'R X J J'),
    ('FSETATTR', 'FSETATTR', 'G Q J P X', 'R X J J'),
    ('READDIRP', 'READDIRP', 'G Q Q U X', 'N X L(Q Q U U S J X)'),
    ('RELEASE', 'RELEASE', 'G Q X', 'R X'),
    ('RELEASEDIR', 'RELEASEDIR', 'G Q X', 'R X'),
    ('FREMOVEXATTR', 'FREMOVEXATTR', 'G Q S X', 'R X'),
    ('FALLOCATE', 'FALLOCATE', 'G Q F Q Q X', 'R X J J'),
    ('DISCARD', 'DISCARD', 'G Q Q Q X', 'R X J J'),
    ('ZEROFILL', 'ZEROFILL', 'G Q Q Q X', 'R X J J'),
    ('IPC', 'IPC', 'U X', 'R X'),
    ('SEEK', 'SEEK', 'G Q Q U X', 'R X Q'),
    ('COMPOUND', 'COMPOUND', 'UNK', 'UNK'),
    ('LEASE', 'LEASE', 'G Y X', 'R X Y'),
    ('GETACTIVELK', 'GETACTIVELK', 'G X', 'R X L(K S U)'),
    ('SETACTIVELK', 'SETACTIVELK', 'G L(K S U) X', 'R X'),
    ('ICREATE', 'ICREATE', 'G M X', 'R X J'),
    ('NAMELINK', 'NAMELINK', 'G S X', 'R X J J'),
    ('PUT', 'PUT', 'G S M M U Q U X X', 'R X J J J'),
    ('COPY_FILE_RANGE', 'COPY_FILE_RANGE', 'G G Q Q Q Q U U X', 'R X J J J'),
]

def fop_pairs(tr, ver, table, variants, trunc=None):
    """One call/reply pair for every procedure of a table and variant."""
    for op, name, c, r in table:
        proc = OPS.index(op)
        for v in variants(name):
            if c is None:
                pair(tr, GFS, ver, proc, b'', b'')
                continue
            if c == 'UNK':
                cb = bytes(range(20 + v * 4)); rb = R(0, 0) + bytes(range(12))
            else:
                cb = enc(c, v, name); rb = enc(r, v, name)
            if trunc is None:
                pair(tr, GFS, ver, proc, cb, rb)
            else:
                pair(tr, GFS, ver, proc, trunc(cb), trunc(rb))

def build(outdir):
    f = []
    vs = lambda name: (0, 1)
    # 3.1.0 over UDP
    fop_pairs(Udp(f, 41310), 310, [(o,) + (n, c, r) for o, n, c, r in V310], vs)
    n310 = len(f)
    # 3.3 over TCP (one connection)
    t = TcpRpc(f, 41330, 49152); t.t.acks = False
    fop_pairs(t, 330, V330, lambda name: (0, 1, 2) if name in ('LOOKUP', 'READDIRP', 'READDIR', 'LK', 'GETXATTR', 'XATTROP', 'RENAME') else (0, 1))
    n330 = len(f)
    # 4.0 over TCP
    t = TcpRpc(f, 41400, 49153); t.t.acks = False
    fop_pairs(t, 400, V400, lambda name: (0, 1, 2) if name in ('LOOKUP', 'READDIRP', 'READDIR', 'LK', 'GETACTIVELK', 'SETACTIVELK', 'GETXATTR', 'XATTROP', 'RCHECKSUM', 'LEASE') else (0, 1))
    n400 = len(f)
    # reproducers of the fixes: an iattx dict value, a lock owner of 5 octets
    u = Udp(f, 41999)
    iattx_v = iattx(0)
    pairs = opaque(b'abcd') + U(5) + opaque(b'val1') + opaque(b'iatt') + U(8) + iattx_v
    dict4_repro = U(len(pairs) + 8) + U(2) + U(2) + pairs
    pair(u, GFS, 400, OPS.index('IPC'), U(1) + dict4_repro, R(0, 0) + EMPTY_X)
    entry = flock2(1, b'ABCDE') + opaque(b'uid') + U(0x55)
    pair(u, GFS, 400, OPS.index('SETACTIVELK'), b'\x22' * 16 + U(1) + entry + U(0) + EMPTY_X, R(0, 0) + EMPTY_X)
    nrep = len(f)
    pcap(os.path.join(outdir, 'glusterfs-coverage.pcap'), f)
    print('3.1 UDP: 1-%d, 3.3 TCP: %d-%d, 4.0 TCP: %d-%d, reproducers: %d-%d' % (n310, n310 + 1, n330, n330 + 1, n400, n400 + 1, nrep))

    # ---- malformed: calls and replies cut short -------------------------------------
    m = []
    for ver, tbl_, port in ((310, V310, 42310), (330, V330, 42330), (400, V400, 42400)):
        u = Udp(m, port)
        fop_pairs(u, ver, tbl_, lambda name: (0,), trunc=lambda b: b[:max(4, len(b) * 3 // 5)])
    u = Udp(m, 42500)
    # values that run past the end
    pair(u, GFS, 330, OPS.index('LK'), b'\1' * 16 + Q(1) + U(0) + U(0) + U(1) + U(0) + Q(0) + Q(0) + U(1) + U(0x7fffffff) + b'abc', R(0, 0) + U(1))
    pair(u, GFS, 330, OPS.index('LOOKUP'), gfid(1) + gfid(2) + U(0) + U(0xfffffff0) + b'ab', R(0, 0))
    big = U(0x100) + U(0xffffffff) + b'\0' * 24     # dict with a huge item count
    pair(u, GFS, 330, OPS.index('GETXATTR'), gfid(1) + U(0) + xstr('x') + big, R(0, 0) + big)
    bigx = U(0x100) + U(0xffffffff) + U(0xffffffff) + b'\0' * 24
    pair(u, GFS, 400, OPS.index('GETXATTR'), gfid(1) + U(0) + xstr('x') + bigx, R(0, 0) + bigx)
    pair(u, GFS, 400, OPS.index('READDIRP'), gfid(1) + Q(1) + Q(0) + U(100) + EMPTY_X, U(5) + U(0) + EMPTY_X + (U(1) + Q(1) + Q(2) + U(3) + U(4) + U(0xffffff) + b'x') * 2)
    pair(u, GFS, 400, OPS.index('GETACTIVELK'), gfid(1) + EMPTY_X, R(0, 0) + EMPTY_X + U(1) + flock2(1, b'ABCDE'))
    pair(u, GFS, 400, OPS.index('SETACTIVELK'), gfid(1) + U(1) + U(1) + U(0) + Q(0) + Q(0) + U(0) + U(0x80000000) + b'xx', R(0, 0) + EMPTY_X)
    pair(u, GFS, 400, OPS.index('RCHECKSUM'), gfid(1) + Q(1) + Q(0) + U(1) + U(0) + EMPTY_X, R(0, 0) + EMPTY_X + U(0) + U(1) + U(0x7ffffff0) + b'ab')
    pair(u, GFS, 999, 1, b'', b'')       # unknown version
    pcap(os.path.join(outdir, 'glusterfs-coverage-malformed.pcap'), m)
    print('malformed frames: %d' % len(m))

if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    build(out)
