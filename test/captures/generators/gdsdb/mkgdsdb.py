# Generates test/captures/gdsdb_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

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
import sys
import os

def u32(*v): return struct.pack('>%dI' % len(v), *v)
def ustr(s):
    return u32(len(s)) + s + b'\0' * ((4 - len(s) % 4) % 4)
def u64(v): return struct.pack('>Q', v)

def connect(op=19, ver=3, arch=36, fname=b'/db/test.fdb', user=b'\x01\x04user\x04\x04host', prefs=((10, 1, 0, 5, 2),)):
    return u32(1, op, ver, arch) + ustr(fname) + u32(len(prefs)) + ustr(user) + b''.join(u32(*p) for p in prefs)

def accept(ver=0x8000000a, arch=1, typ=5): return u32(3, ver, arch, typ)
def request(op, typ=1, obj=2, partner=0x0102030405060708): return u32(op, typ, obj) + u64(partner)
def attach(op, dbid=0, path=b'/db/test.fdb', params=b'\x01\x1c\x06SYSDBA'): return u32(op, dbid) + ustr(path) + ustr(params)
def compile_(db=1, blr=b'\x05\x02\x04\x00'): return u32(22, db) + ustr(blr)
def rcv(op, req=1, inc=2, trans=3, msgnr=4, msgs=1, dirs=()):
    return u32(op, req, inc, trans, msgnr, msgs) + b''.join(u32(d) + u64(o) for d, o in dirs)
def snd(op, req=1, inc=2, trans=3, msgnr=4, msgs=1): return u32(op, req, inc, trans, msgnr, msgs)
def status(*items):
    out = b''
    for kind, val in items:
        out += u32(kind)
        if kind in (2, 5, 19): out += ustr(val)
        elif kind == 0: pass
        else: out += u32(val)
    return out
def response(op=9, obj=1, blob=0x1122334455667788, data=b'', st=()):
    return u32(op, obj) + u64(blob) + ustr(data) + status(*st)

STATUS_ALL = ((1, 335544321), (4, 7), (2, b'table'), (5, b'interpreted text'), (19, b'42000'),
              (7, 13), (0, 0))

def build(outdir):
    f = []
    # ---- connection setup (default port TCP 3050)
    c = Flow(41000, 3050, f); c.open()
    c.c2s(connect())                                                          # op_connect: one version preference
    c.s2c(accept())
    c.c2s(connect(op=20, ver=2, arch=13, fname=b'', user=b'', prefs=()))      # empty names, no preferences
    c.s2c(accept(ver=10, arch=3, typ=3))
    c.c2s(connect(fname=b'a', user=b'bb', prefs=((10, 1, 0, 5, 2), (11, 36, 0, 5, 4), (12, 99, 1, 2, 3))))   # padded 1/2 octet strings
    c.c2s(connect(fname=b'abc', user=b'abcd', prefs=tuple((i, i, 0, 5, i) for i in range(255))))  # 255 preferences
    c.c2s(connect(fname=b'/home/db/x.fdb'))
    c.c2s(accept() + request(53) + accept())                                 # three PDUs in one segment
    # ---- connect split over two segments (the reproducer: used to be an invalid length)
    big = connect(fname=b'/db/split.fdb', user=b'\x01\x08splituser')
    c2 = Flow(41001, 3050, f); c2.open()
    c2.c2s(big[:20]); c2.c2s(big[20:])
    # one byte per segment
    cc = Flow(41002, 3050, f, cseq=2000, sseq=9000); cc.open()
    pkt = attach(19)
    for i in range(0, len(pkt), 12):
        cc.c2s(pkt[i:i + 12])
    # ---- every opcode handled
    d = Flow(41003, 3050, f, cseq=3000, sseq=8000); d.open()
    d.c2s(request(53)); d.c2s(request(54, 4, 5, 0))
    for op in (19, 20, 82):
        d.c2s(attach(op, dbid=op))
    d.c2s(attach(19, path=b'', params=b''))
    d.c2s(compile_()); d.c2s(compile_(blr=b''))
    d.c2s(rcv(23)); d.c2s(rcv(26, dirs=((1, 0x10),))); d.c2s(rcv(73, dirs=((0, 1), (1, 2), (2, 3))))
    d.c2s(rcv(26) + b'\0' * 3)                                               # trailing octets shorter than an opcode
    for op in (24, 25, 74):
        d.c2s(snd(op))
    d.c2s(snd(25) + snd(25) + attach(19))                                   # PDUs after a send
    d.s2c(response())
    d.s2c(response(data=b'x'))
    d.s2c(response(op=72, data=b'datadata12', st=STATUS_ALL))
    d.s2c(response(data=b'', st=((1, 335544345), (0, 0))))
    d.s2c(response(st=((4, 100), (0, 0))) + response(op=72, st=((2, b'abc'), (0, 0))))
    d.s2c(response(st=((1, 1), (4, 1))))                                     # status vector without terminator
    d.c2s(u32(79, 5, 6)); d.s2c(u32(80, 3))                                  # transact, transact response
    for op in (34, 56, 57):
        d.c2s(u32(op) + ustr(b'\x01\x02\x03') + u32(7) + u64(0x0102030405060708))
    d.c2s(u32(35, 7) + u64(0x0102030405060708))
    for op in (36, 37, 44, 61):
        d.c2s(u32(op, 1, 2, 3, 4))
    for op in (29, 33):
        d.c2s(u32(op, 9) + ustr(b'/db/reconnect.fdb'))
    d.c2s(u32(29, 9) + ustr(b''))
    for op in (40, 41, 42, 43, 70):
        d.c2s(u32(op, 1, 2) + ustr(b'\x01\x02\x03\x04\x05') + u32(1024))
    d.c2s(u32(84, 1, 2) + ustr(b'\x01\x02\x03\x00\x00\x00\x00') + ustr(b'\x09\x08') + u32(512))   # service info: both item lists
    d.c2s(u32(84, 1, 2) + ustr(b'\x00\x00\x00\x00') + ustr(b'') + u32(512))
    d.c2s(u32(85, 1, 2, 3, 4))                                               # service start
    for op in (21, 27, 28, 30, 31, 32, 38, 39, 50, 62, 81, 83, 86):
        d.c2s(u32(op, 5))                                                    # the release group
    d.c2s(u32(48, 1) + ustr(b'EVENT') + u32(0, 1, 2)); d.c2s(u32(52, 1) + ustr(b'EVENT') + u32(0, 1, 2))
    d.c2s(u32(49, 1, 2))
    d.c2s(u32(55, 1, 2) + ustr(b'ddl'))
    d.c2s(u32(58, 1, 2, 3, 4, 5)); d.c2s(u32(59, 1, 2, 3, 4, 5)); d.s2c(u32(60, 12))
    d.c2s(u32(63, 1, 2, 3, 4)); d.c2s(u32(76, 5, 6, 7, 8))
    for op in (64, 68):
        d.c2s(u32(op, 1, 2, 3) + ustr(b'select * from rdb$relations') + u32(2048))
    d.c2s(u32(64, 1, 2, 3) + ustr(b'') + u32(0))
    d.c2s(u32(65, 1, 2, 3)); d.s2c(u32(66, 100, 0)); d.s2c(u32(66, 0, 1))
    d.c2s(u32(67, 4, 2))
    d.c2s(u32(69, 1, 2, 3))
    d.c2s(u32(75) + b'\0' * 40)
    d.c2s(u32(77, 1, 2, 3)); d.s2c(u32(78, 1))
    # dummy handlers: each consumes the rest of the segment
    for op in (0, 2, 4, 5, 6, 7, 8, 10, 11, 12, 13, 14, 15, 16, 17, 18, 45, 46, 47, 71, 87, 88, 89, 90, 91):
        d.c2s(u32(op) + b'\0' * 8)
    d.c2s(u32(51, 1))
    d.close()
    # ---- reassembly of larger PDUs
    r = Flow(41004, 3050, f, cseq=4000, sseq=7000); r.open()
    big = response(op=9, data=b'D' * 100, st=STATUS_ALL)
    r.s2c(big[:30]); r.s2c(big[30:90]); r.s2c(big[90:])
    q = u32(68, 1, 2, 3) + ustr(b'select ' + b'x' * 40 + b' from t') + u32(8192)
    r.c2s(q[:15]); r.c2s(q[15:])
    r.c2s(u32(84, 1, 2) + ustr(b'\x01\x02\x03\x00\x00\x00\x00')[:8])           # service info: items cut short
    r.close()
    # ---- values over the limit of one PDU: opcode out of range after a valid PDU, short segment
    e = Flow(41005, 3050, f, cseq=5000, sseq=6000); e.open()
    e.c2s(accept() + u32(0xffff))                                            # unknown opcode ends the segment
    e.c2s(b'\x00\x00\x00')                                                   # shorter than an opcode: not GDSDB
    e.c2s(u32(92, 1, 2, 3))                                                  # opcode >= op_max: not GDSDB
    e.close()
    pcap(os.path.join(outdir, 'gdsdb-coverage.pcap'), f)

    m = []
    port = [42000]
    def case(*segs):
        port[0] += 1
        x = Flow(port[0], 3050, m, cseq=1000 + port[0], sseq=5000 + port[0]); x.open()
        for sg in segs:
            x.c2s(sg)
        x.close()
    case(accept()[:3], accept()[3:])                                        # segment shorter than an opcode, then data that is not an opcode
    case(connect(prefs=tuple((i, 0, 0, 0, 0) for i in range(256))))        # count > 255: invalid length
    case(u32(1, 19, 3, 36, 0xffffffff) + b'\0' * 12)                       # file name of 4 GiB (clamped to 256 MiB): needs more data
    case(u32(1) + b'\0' * 8)                                               # connect cut short
    case(u32(1, 19, 3, 36) + ustr(b'abc') + u32(1))                        # connect cut after the count
    case(u32(1, 19, 3, 36) + ustr(b'abc') + u32(3) + ustr(b'u'))           # three preferences announced, none present
    case(u32(9, 1) + u64(1) + u32(4) + b'abcd' + u32(2, 0xffffffff))        # status string of 4 GiB: exception
    case(u32(9, 1) + u64(1) + u32(0xffffffff) + b'\0' * 12)                # data size of 4 GiB: needs more data
    case(u32(9, 1) + u64(1) + u32(0) + u32(2, 0x10000000) + b'\0' * 20)    # status string clamped to 256 MiB: exception
    case(u32(68, 1, 2, 3) + u32(0xfffffff0) + b'\0' * 8)                  # query string length near 2^32: needs more data
    case(u32(19, 0, 0xfffffffc))                                           # path length near 2^32: needs more data
    case(u32(19, 0) + ustr(b'/x') + u32(0xfffffff0))                       # parameter length near 2^32: needs more data
    case(u32(84, 1, 2) + ustr(b'abcd') + u32(0x7fffffff) + u32(0))        # service info: the length read from the items data
    case(u32(26, 1, 2, 3))                                                 # receive cut short
    case(u32(3, 1, 2))                                                     # accept cut short
    case(u32(9, 1))                                                        # response cut short
    case(u32(21))                                                          # release without object
    case(u32(22, 1))                                                       # compile cut short
    case(u32(22, 1, 0xfffffff0))                                           # compile: blr length near 2^32
    case(u32(34) + u32(0xfffffff0))                                        # open blob 2: bpb length near 2^32
    case(u32(29, 1, 0xfffffff0))                                           # reconnect: database length near 2^32
    case(u32(40, 1, 2, 0xfffffff0))                                        # info: items length near 2^32
    case(u32(40, 1, 2, 4) + b'abcd')                                       # info cut short
    case(u32(53, 1, 2))                                                    # request cut short
    case(u32(35, 1))                                                       # open blob cut short
    case(u32(79, 1))                                                       # transact cut short
    case(u32(80))                                                          # transact response cut short
    case(u32(66, 1))                                                       # fetch response cut short
    case(u32(67, 1))                                                       # free statement cut short
    case(u32(63, 1, 2, 3))                                                 # execute cut short
    case(u32(24, 1, 2, 3))                                                 # send cut short
    case(u32(84, 1, 2) + ustr(b'abc'))                                     # service info cut short
    case(u32(34) + u32(0x1000, 0, 0))                                      # open blob 2: bpb longer than the segment
    case(u32(29, 1)); case(u32(36, 1, 2)); case(u32(61, 1))                                  # get segment, seek blob cut short
    case(u32(29, 1, 0x1000) + b'\0' * 4)                                   # reconnect: database name longer than the segment
    case(u32(48, 1, 2)); case(u32(49, 1)); case(u32(55, 1, 2))             # que events, cancel events, ddl cut short
    case(u32(60)); case(u32(65, 1, 2)); case(u32(77, 1, 2)); case(u32(69, 1, 2)); case(u32(78))   # slice response, fetch, insert, set cursor, sql response
    case(u32(85, 1)); case(u32(58, 1, 2)); case(u32(75, 1))               # service start, get slice, exec immediate 2 cut short
    pcap(os.path.join(outdir, 'gdsdb-coverage-malformed.pcap'), m)

if __name__ == '__main__':
    build(sys.argv[1] if len(sys.argv) > 1 else '.')
