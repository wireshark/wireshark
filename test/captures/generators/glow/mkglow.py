#!/usr/bin/env python3
# Generates test/captures/glow_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generates glow-coverage.pcap and glow-coverage-malformed.pcap
# Glow (Ember+) BER PDUs inside S101 over TCP port 9000
# Usage: mkglow.py <outdir>  (synthetic; nothing comes from a real network)
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


import math

# ---- BER helpers ---------------------------------------------------------------
def blen(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(b)]) + b
def T(tag, *parts):
    c = b''.join(parts)
    return bytes([tag]) + blen(len(c)) + c
def ctx(n, *p): return T(0xa0 | n, *p)       # [n] EXPLICIT (constructed)
def app(n, *p): return T(0x60 | n, *p)       # [APPLICATION n] constructed
def INT(v, tag=2):
    n = 1
    while not (-(1 << (8 * n - 1)) <= v < (1 << (8 * n - 1))):
        n += 1
    return bytes([tag, n]) + v.to_bytes(n, 'big', signed=True)
def UTF(s): return T(0x0c, s.encode() if isinstance(s, str) else s)
def BOOL(b): return bytes([1, 1, 0xff if b else 0])
def NUL(): return b'\x05\x00'
def OCT(b): return T(0x04, b)
def REAL(x):
    if x != x: return b'\x09\x01\x42'
    if x == math.inf: return b'\x09\x01\x40'
    if x == -math.inf: return b'\x09\x01\x41'
    if x == 0: return b'\x09\x00'
    m, e = math.frexp(abs(x))
    mant = int(m * (1 << 53)); e -= 53
    while mant % 2 == 0:
        mant //= 2; e += 1
    eb = e.to_bytes((e.bit_length() + 8) // 8, 'big', signed=True)
    mb = mant.to_bytes((mant.bit_length() + 7) // 8, 'big')
    first = 0x80 | (0x40 if x < 0 else 0) | (len(eb) - 1)
    return T(0x09, bytes([first]), eb, mb)
def ROID(arcs):
    out = b''
    for a_ in arcs:
        chunk = [a_ & 0x7f]
        a_ >>= 7
        while a_:
            chunk.append(0x80 | (a_ & 0x7f)); a_ >>= 7
        out += bytes(reversed(chunk))
    return T(0x0d, out)
def VAL(v):
    if v is None: return NUL()
    if isinstance(v, bool): return BOOL(v)
    if isinstance(v, int): return INT(v)
    if isinstance(v, float): return REAL(v)
    if isinstance(v, str): return UTF(v)
    if isinstance(v, bytes): return OCT(v)
    if isinstance(v, tuple): return v[0]           # pre-encoded
    raise ValueError(v)
def SEQ(*p): return T(0x30, *p)
def SET(*p): return T(0x31, *p)
def opt(n, enc_, v):
    return ctx(n, enc_(v)) if v is not None else b''

# ---- Glow types -------------------------------------------------------------------
def Tuple(vals): return SEQ(*[ctx(0, VAL(v)) for v in vals])
def ElemColl(elems): return app(4, *[ctx(0, e) for e in elems])
def ch(children): return ctx(2, ElemColl(children)) if children is not None else b''
def enum_map(pairs): return app(8, *[ctx(0, app(7, ctx(0, UTF(s)), ctx(1, INT(i)))) for s, i in pairs])
def stream_desc(fmt, off): return app(12, ctx(0, INT(fmt)), ctx(1, INT(off)))

def ParamContents(f):
    p = b''
    if 'identifier' in f: p += ctx(0, UTF(f['identifier']))
    if 'description' in f: p += ctx(1, UTF(f['description']))
    if 'value' in f: p += ctx(2, VAL(f['value']))
    if 'minimum' in f: p += ctx(3, VAL(f['minimum']))
    if 'maximum' in f: p += ctx(4, VAL(f['maximum']))
    if 'access' in f: p += ctx(5, INT(f['access']))
    if 'format' in f: p += ctx(6, UTF(f['format']))
    if 'enumeration' in f: p += ctx(7, UTF(f['enumeration']))
    if 'factor' in f: p += ctx(8, INT(f['factor']))
    if 'isOnline' in f: p += ctx(9, BOOL(f['isOnline']))
    if 'formula' in f: p += ctx(10, UTF(f['formula']))
    if 'step' in f: p += ctx(11, INT(f['step']))
    if 'default' in f: p += ctx(12, VAL(f['default']))
    if 'type' in f: p += ctx(13, INT(f['type']))
    if 'streamIdentifier' in f: p += ctx(14, INT(f['streamIdentifier']))
    if 'enumMap' in f: p += ctx(15, enum_map(f['enumMap']))
    if 'streamDescriptor' in f: p += ctx(16, stream_desc(*f['streamDescriptor']))
    if 'schemaIdentifiers' in f: p += ctx(17, UTF(f['schemaIdentifiers']))
    if 'templateReference' in f: p += ctx(18, ROID(f['templateReference']))
    return SET(p)
def Parameter(num, f=None, children=None):
    return app(1, ctx(0, INT(num)), ctx(1, ParamContents(f)) if f is not None else b'', ch(children))
def QParameter(path, f=None, children=None):
    return app(9, ctx(0, ROID(path)), ctx(1, ParamContents(f)) if f is not None else b'', ch(children))
def NodeContents(f):
    p = b''
    if 'identifier' in f: p += ctx(0, UTF(f['identifier']))
    if 'description' in f: p += ctx(1, UTF(f['description']))
    if 'isRoot' in f: p += ctx(2, BOOL(f['isRoot']))
    if 'isOnline' in f: p += ctx(3, BOOL(f['isOnline']))
    if 'schemaIdentifiers' in f: p += ctx(4, UTF(f['schemaIdentifiers']))
    if 'templateReference' in f: p += ctx(5, ROID(f['templateReference']))
    return SET(p)
def Node(num, f=None, children=None):
    return app(3, ctx(0, INT(num)), ctx(1, NodeContents(f)) if f is not None else b'', ch(children))
def QNode(path, f=None, children=None):
    return app(10, ctx(0, ROID(path)), ctx(1, NodeContents(f)) if f is not None else b'', ch(children))
def Command(num, mask=None, invocation=None):
    p = ctx(0, INT(num))
    if mask is not None: p += ctx(1, INT(mask))
    if invocation is not None: p += ctx(2, invocation)
    return app(2, p)
def Invocation(iid=None, args=None):
    return app(22, ctx(0, INT(iid)) if iid is not None else b'', ctx(1, Tuple(args)) if args is not None else b'')
def InvocationResult(iid, success=None, result=None):
    return app(23, ctx(0, INT(iid)), ctx(1, BOOL(success)) if success is not None else b'',
               ctx(2, Tuple(result)) if result is not None else b'')
def MatrixContents(f):
    p = ctx(0, UTF(f['identifier']))
    if 'description' in f: p += ctx(1, UTF(f['description']))
    if 'type' in f: p += ctx(2, INT(f['type']))
    if 'addressingMode' in f: p += ctx(3, INT(f['addressingMode']))
    p += ctx(4, INT(f['targetCount'])) + ctx(5, INT(f['sourceCount']))
    if 'maximumTotalConnects' in f: p += ctx(6, INT(f['maximumTotalConnects']))
    if 'maximumConnectsPerTarget' in f: p += ctx(7, INT(f['maximumConnectsPerTarget']))
    if 'parametersLocation' in f:
        pl = f['parametersLocation']
        p += ctx(8, ROID(pl) if isinstance(pl, list) else INT(pl))
    if 'gain' in f: p += ctx(9, INT(f['gain']))
    if 'labels' in f: p += ctx(10, SEQ(*[ctx(0, app(18, ctx(0, ROID(b)), ctx(1, UTF(d)))) for b, d in f['labels']]))
    if 'schemaIdentifiers' in f: p += ctx(11, UTF(f['schemaIdentifiers']))
    if 'templateReference' in f: p += ctx(12, ROID(f['templateReference']))
    return SET(p)
def Connection(target, sources=None, op=None, disp=None):
    return app(16, ctx(0, INT(target)), ctx(1, ROID(sources)) if sources is not None else b'',
               ctx(2, INT(op)) if op is not None else b'', ctx(3, INT(disp)) if disp is not None else b'')
def matrix_tail(targets, sources, conns):
    p = b''
    if targets is not None: p += ctx(3, SEQ(*[ctx(0, app(14, ctx(0, INT(t)))) for t in targets]))
    if sources is not None: p += ctx(4, SEQ(*[ctx(0, app(15, ctx(0, INT(t)))) for t in sources]))
    if conns is not None: p += ctx(5, SEQ(*[ctx(0, c_) for c_ in conns]))
    return p
def Matrix(num, f=None, children=None, targets=None, sources=None, conns=None):
    return app(13, ctx(0, INT(num)), ctx(1, MatrixContents(f)) if f is not None else b'', ch(children), matrix_tail(targets, sources, conns))
def QMatrix(path, f=None, children=None, targets=None, sources=None, conns=None):
    return app(17, ctx(0, ROID(path)), ctx(1, MatrixContents(f)) if f is not None else b'', ch(children), matrix_tail(targets, sources, conns))
def FunctionContents(f):
    p = b''
    if 'identifier' in f: p += ctx(0, UTF(f['identifier']))
    if 'description' in f: p += ctx(1, UTF(f['description']))
    for n, k in ((2, 'arguments'), (3, 'result')):
        if k in f:
            p += ctx(n, SEQ(*[ctx(0, app(21, ctx(0, INT(t)), ctx(1, UTF(nm)) if nm is not None else b'')) for t, nm in f[k]]))
    if 'templateReference' in f: p += ctx(4, ROID(f['templateReference']))
    return SET(p)
def Function(num, f=None, children=None):
    return app(19, ctx(0, INT(num)), ctx(1, FunctionContents(f)) if f is not None else b'', ch(children))
def QFunction(path, f=None, children=None):
    return app(20, ctx(0, ROID(path)), ctx(1, FunctionContents(f)) if f is not None else b'', ch(children))
def Template(num, element=None, desc=None):
    return app(24, ctx(0, INT(num)), ctx(1, element) if element is not None else b'', ctx(2, UTF(desc)) if desc is not None else b'')
def QTemplate(path, element=None, desc=None):
    return app(25, ctx(0, ROID(path)), ctx(1, element) if element is not None else b'', ctx(2, UTF(desc)) if desc is not None else b'')
def Root(elements):
    return app(0, app(11, *[ctx(0, e) for e in elements]))
def RootStreams(entries):
    return app(0, app(6, *[ctx(0, app(5, ctx(0, INT(i)), ctx(1, VAL(v)))) for i, v in entries]))
def RootResult(res):
    return app(0, res)

# ---- S101 framing ---------------------------------------------------------------------
def crc_upd(reg, b):
    reg ^= b
    for _ in range(8):
        reg = (reg >> 1) ^ 0x8408 if reg & 1 else reg >> 1
    return reg
def esc(b):
    out = b''
    for x in b:
        out += bytes([0xfd, x ^ 0x20]) if x >= 0xf8 else bytes([x])
    return out
def s101(payload, flags=0xc0):
    hdr = bytes([0x00, 0x0e, 0x00, 0x01, flags, 0x01, 0x02, 0x1f, 0x02])
    reg = 0xffff
    for x in hdr + payload:
        reg = crc_upd(reg, x)
    fcs = (~reg) & 0xffff
    return bytes([0xfe]) + hdr + esc(payload + bytes([fcs & 0xff, fcs >> 8])) + b'\xff'
def s101_keepalive(resp=False):
    body = bytes([0x00, 0x0e, 0x02 if resp else 0x01, 0x01])
    reg = 0xffff
    for x in body:
        reg = crc_upd(reg, x)
    fcs = (~reg) & 0xffff
    return bytes([0xfe]) + body + esc(bytes([fcs & 0xff, fcs >> 8])) + b'\xff'

# ---- the messages ----------------------------------------------------------------------
def messages():
    M = []          # (from_client, payload bytes)
    C = lambda p: M.append((True, p))
    S = lambda p: M.append((False, p))
    # consumer requests
    C(Root([Command(32, -1)]))
    C(Root([Command(32, 0)]))
    for mask in (-2, 1, 2, 3, 4, 5):
        C(Root([Node(1, None, [Command(32, mask)])]))
    C(Root([Node(1, None, [Command(30)]), Node(2, None, [Command(31)])]))
    C(Root([Node(1, None, [Node(2, None, [Parameter(3, None, [Command(30)])])])]))
    C(Root([Command(33, invocation=Invocation(1, [1, 'text', True, None, 2.5, b'\x01\x02']))]))
    C(Root([Function(1, None, [Command(33, invocation=Invocation(7, [-5, 'x']))])]))
    C(Root([Function(2, None, [Command(33, invocation=Invocation(None, None))])]))
    C(Root([Function(2, None, [Command(33, invocation=Invocation(8, []))])]))
    # provider replies: the tree
    S(Root([Node(0, {'identifier': 'Root', 'description': 'Root of the tree', 'isRoot': True, 'isOnline': True,
                      'schemaIdentifiers': 'de.example.schema', 'templateReference': [1, 2, 3]},
                 [Node(1, {'identifier': 'Device', 'description': 'A device', 'isRoot': False, 'isOnline': False},
                       [Parameter(1, {'identifier': 'Gain'}), Parameter(2, {'identifier': 'Mute'})]),
                  Node(2, {'identifier': 'Empty'}, []),
                  Node(3)])]))
    # parameters: every contents field
    S(Root([Parameter(1, {'identifier': 'p-int', 'description': 'An integer', 'value': 42, 'minimum': 0, 'maximum': 100,
                         'access': 3, 'format': '%d dB', 'enumeration': 'off\non', 'factor': 10, 'isOnline': True,
                         'formula': 'x*2', 'step': 1, 'default': 7, 'type': 1, 'streamIdentifier': 5,
                         'schemaIdentifiers': 's1', 'templateReference': [4, 5]})]))
    S(Root([Parameter(2, {'identifier': 'p-real', 'value': 3.14159, 'minimum': -1.5, 'maximum': 1e10, 'default': 0.0, 'type': 2, 'access': 1})]))
    S(Root([Parameter(3, {'identifier': 'p-str', 'value': 'hello', 'minimum': None, 'maximum': None, 'default': '', 'type': 3, 'access': 2})]))
    S(Root([Parameter(4, {'identifier': 'p-bool', 'value': False, 'default': True, 'type': 4, 'access': 0})]))
    S(Root([Parameter(5, {'identifier': 'p-trigger', 'type': 5, 'access': 2})]))
    S(Root([Parameter(6, {'identifier': 'p-enum', 'value': 1, 'type': 6, 'enumMap': [('off', 0), ('on', 1), ('auto', 2)], 'access': 3})]))
    S(Root([Parameter(7, {'identifier': 'p-octets', 'value': b'\xde\xad\xbe\xef', 'default': b'', 'type': 7})]))
    S(Root([Parameter(8, {'identifier': 'p-null', 'value': None, 'type': 0, 'streamDescriptor': (4, 12)})]))
    S(Root([Parameter(9, {'identifier': 'p-stream', 'streamIdentifier': 77, 'streamDescriptor': (23, 0), 'value': -(2 ** 40)})]))
    S(Root([Parameter(10, {'minimum': 2 ** 40, 'maximum': 2 ** 62, 'value': 2 ** 62}), Parameter(11, {'value': -7, 'minimum': -2 ** 63})]))
    for fmt in (0, 2, 3, 5, 6, 7, 8, 10, 11, 12, 13, 14, 15, 20, 21, 22):
        S(Root([Parameter(20 + fmt, {'streamDescriptor': (fmt, fmt * 2)})]))
    S(Root([Parameter(30, {'value': math.inf}), Parameter(31, {'value': -math.inf, 'minimum': math.nan}), Parameter(32, {'value': 0.5, 'maximum': -0.0})]))
    S(Root([Parameter(33, {'value': (b'\x09\x07\x03' + b'1.5E-1',)})]))
    # nested elements inside parameters, nodes, a function
    S(Root([Node(1, {'identifier': 'a'}, [Node(2, {'identifier': 'b'}, [Node(3, {'identifier': 'c'}, [Parameter(4, {'identifier': 'd', 'value': 1}, [Parameter(5, {'identifier': 'e'})])])])])]))
    # qualified elements
    S(Root([QParameter([1, 2, 3], {'identifier': 'q', 'value': 5}), QParameter([1, 128, 16384], None, [Parameter(1)]),
            QNode([1, 2], {'identifier': 'qn', 'isOnline': True}), QNode([1, 3], None, [Node(1)])]))
    S(Root([QNode([1, 2], None, [Node(1, {'identifier': 'child'})])]))
    # matrix
    S(Root([Matrix(1, {'identifier': 'm1', 'description': 'matrix', 'type': 2, 'addressingMode': 1, 'targetCount': 4, 'sourceCount': 8,
                       'maximumTotalConnects': 16, 'maximumConnectsPerTarget': 4, 'parametersLocation': [1, 2], 'gain': 3,
                       'labels': [([1, 2, 1], 'targets'), ([1, 2, 2], 'sources')], 'schemaIdentifiers': 'ms', 'templateReference': [9]},
                  [Node(1, {'identifier': 'labels'})], [0, 1, 2, 3], [0, 1, 2, 3, 4, 5, 6, 7],
                  [Connection(0, [1, 2], 0, 0), Connection(1, [], 1, 1), Connection(2, [3], 2, 2), Connection(3, None, None, 3), Connection(4)])]))
    S(Root([Matrix(2, {'identifier': 'm2', 'targetCount': 2, 'sourceCount': 2, 'parametersLocation': 5})]))
    S(Root([Matrix(3, {'identifier': 'm3', 'type': 0, 'addressingMode': 0, 'targetCount': 1, 'sourceCount': 1}, None, [], [], [])]))
    S(Root([Matrix(4)]))
    S(Root([QMatrix([1, 4], {'identifier': 'qm', 'type': 1, 'targetCount': 3, 'sourceCount': 3}, [Node(1)], [0], [0, 1],
                    [Connection(0, [1], 0, 1)]), QMatrix([1, 5])]))
    C(Root([QMatrix([1, 4], None, None, None, None, [Connection(0, [2], 0), Connection(1, [], 2)])]))
    # functions
    S(Root([Function(1, {'identifier': 'add', 'description': 'adds', 'arguments': [(1, 'a'), (1, 'b'), (3, None)],
                         'result': [(1, 'sum'), (4, 'ok')], 'templateReference': [7, 8]}),
            Function(2, {'identifier': 'noargs'}, [Node(1)]), Function(3)]))
    S(Root([QFunction([2, 1], {'identifier': 'qf', 'arguments': [(2, 'x')], 'result': []}, [Parameter(1)]), QFunction([2, 2])]))
    # templates
    S(Root([Template(1, Parameter(1, {'identifier': 'tp'}), 'param template'), Template(2, Node(1, {'identifier': 'tn'})),
            Template(3, Matrix(1, {'identifier': 'tm', 'targetCount': 1, 'sourceCount': 1})),
            Template(4, Function(1, {'identifier': 'tf'}), 'function template'), Template(5, None, 'empty'), Template(6)]))
    S(Root([QTemplate([3, 1], Node(1, {'identifier': 'qt'}), 'qualified template'), QTemplate([3, 2], Parameter(1)), QTemplate([3, 3])]))
    # command inside elements, in a response too
    S(Root([Node(1, None, [Parameter(1, {'identifier': 'x'}), Command(32, 0), Node(2), Matrix(3), Function(4), Template(5)])]))
    # streams
    S(RootStreams([(1, 10), (2, 2.5), (3, 'str'), (4, True), (5, b'\x00\x01'), (6, None)]))
    S(RootStreams([]))
    # invocation results
    S(RootResult(InvocationResult(1, True, [3, 'ok'])))
    S(RootResult(InvocationResult(2, False)))
    S(RootResult(InvocationResult(3, None, [])))
    S(RootResult(InvocationResult(4)))
    # a deeper tree, still within the dissection depth limit
    n = Parameter(1, {'identifier': 'leaf'})
    for i in range(12):
        n = Node(i + 1, {'identifier': 'n%d' % i}, [n])
    S(Root([n]))
    return M

def build(outdir):
    f = []
    M = messages()
    t = Tcp(f, 51000, 9000); t.acks = False
    nm = 0
    for from_client, p in M:
        t.send(from_client, s101(p))
        nm += 1
    n1 = len(f)
    # keepalives
    t.send(True, s101_keepalive(False)); t.send(False, s101_keepalive(True))
    # two S101 frames in one segment
    t.send(True, s101(M[0][1]) + s101(M[1][1]))
    t.send(False, s101(M[11][1]) + s101_keepalive(True) + s101(M[12][1]))
    n2 = len(f)
    # a message sent as first / middle / last fragments (one segment each)
    big = Root([Node(1, {'identifier': 'frag'}, [Parameter(i, {'identifier': 'p%d' % i, 'value': i * 1000}) for i in range(1, 30)])])
    k = len(big) // 3
    t.send(False, s101(big[:k], 0x80))
    t.send(False, s101(big[k:2 * k], 0x00))
    t.send(False, s101(big[2 * k:], 0x40))
    # a payload with bytes that need escaping (0xf8..0xff)
    t.send(False, s101(Root([Parameter(1, {'identifier': 'esc', 'value': b'\xf8\xfd\xfe\xff\x00\xfc'})])))
    n3 = len(f)
    # a second connection (consumer on another port) with the multi-fragment message again
    t2 = Tcp(f, 51001, 9000); t2.acks = False
    t2.send(False, s101(big[:k], 0x80))
    t2.send(False, s101(big[k:2 * k], 0x00))
    t2.send(False, s101(big[2 * k:], 0x40))
    t2.send(True, s101(M[2][1]))
    t2.send(False, s101(M[14][1]))
    pcap(os.path.join(outdir, 'glow-coverage.pcap'), f)
    print('messages: %d, 1-%d S101 frames, to %d keepalives and two-frame segments, to %d fragments, total %d' % (nm, n1, n2, n3, len(f)))

    # ---- malformed / BER errors ---------------------------------------------------------------
    m = []
    t = Tcp(m, 52000, 9000); t.acks = False
    good = Root([Node(1, {'identifier': 'x', 'isOnline': True}, [Parameter(1, {'identifier': 'p', 'value': 5, 'access': 3})])])
    # truncated and corrupted copies of valid messages
    samples = [good, M[17][1], M[20][1], M[35][1], M[36][1], M[41][1], M[48][1]]
    for s in samples:
        for cut in range(3, len(s) - 1, max(1, len(s) // 9)):
            t.send(False, s101(s[:cut]))
    for s in samples:
        for pos in range(2, len(s), max(1, len(s) // 7)):
            b = bytearray(s); b[pos] ^= 0x55
            t.send(False, s101(bytes(b)))
    # wrong tags, wrong lengths, too-long lengths
    t.send(False, s101(b'\x30\x03\x02\x01\x05'))
    t.send(False, s101(app(0, ctx(0, INT(1)))))
    t.send(False, s101(app(0, app(11, ctx(0, INT(1))))))
    t.send(False, s101(app(0, app(6, ctx(0, app(5, ctx(0, UTF('x')), ctx(1, INT(1))))))))
    t.send(False, s101(app(0, app(11, ctx(0, Parameter(1, {'identifier': 'p', 'value': 1, 'access': 99, 'type': 99})))) ))
    t.send(False, s101(app(0, app(11, ctx(0, Command(99, 5))))))
    t.send(False, s101(b'\x60\x84\xff\xff\xff\xff\x6b\x00'))
    t.send(False, s101(b'\x60\x80\x6b\x80\x00\x00\x00\x00'))
    t.send(False, s101(app(0, app(11, ctx(0, app(10, ctx(0, ROID([1])), ctx(1, SET(ctx(0, INT(5))))))))))
    t.send(False, s101(Root([Parameter(1, {'value': (b'\x09\x03\x80\x7f\xff',)})])))
    t.send(False, s101(Root([Parameter(1, {'value': (b'\x09\x05\xc0\x00\x00\x00\x00',)})])))
    t.send(False, s101(Root([Parameter(1, {'value': (b'\x09\x02\x03\x31',)})])))
    t.send(False, s101(Root([Parameter(1, {'value': (b'\x02\x09\x01\x02\x03\x04\x05\x06\x07\x08\x09',)})])))
    # the nesting from the review: Node/children 3000 deep stops at the dissection depth limit
    n = None
    for i in range(3000):
        c_ = ctx(0, INT(1))
        if n is not None:
            c_ += ctx(2, app(4, ctx(0, n)))
        n = app(3, c_)
    t.send(False, s101(Root([n])))
    pcap(os.path.join(outdir, 'glow-coverage-malformed.pcap'), m)
    print('malformed frames: %d' % len(m))

if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    build(out)
