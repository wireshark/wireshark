#!/usr/bin/env python3
# Generates test/captures/moqt_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Builds the MoQT coverage captures (Exported PDU only: native QUIC needs ciphertext).
# Usage: mkmoqt.py <outdir> [-v]
import struct
import sys
import os

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def ip4(a):
    return bytes(int(x) for x in a.split('.'))

ETH = b'\x02\x00\x00\x00\x00\x02' + b'\x02\x00\x00\x00\x00\x01'

def ethip(proto, payload, src, dst, ident=1):
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0, 64, proto, 0, ip4(src), ip4(dst))
    ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
    return ETH + b'\x08\x00' + ip + payload

def udp(payload, sport, dport, src='192.0.2.1', dst='192.0.2.2'):
    u = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    return ethip(17, u, src, dst)

def tcp(payload, sport, dport, seq, ack, flags=0x18, src='192.0.2.1', dst='192.0.2.2'):
    t = struct.pack('>HHIIBBHHH', sport, dport, seq & 0xffffffff, ack & 0xffffffff, 0x50, flags, 65535, 0, 0) + payload
    pseudo = ip4(src) + ip4(dst) + struct.pack('>BBH', 0, 6, len(t))
    c = csum(pseudo + t)
    t = t[:16] + struct.pack('>H', c) + t[18:]
    return ethip(6, t, src, dst)

def exp_pdu(name, payload, extra=b''):
    n = name.encode()
    pad = (4 - len(n) % 4) % 4
    return struct.pack('>HH', 12, len(n) + pad) + n + b'\0' * pad + extra + struct.pack('>HH', 0, 0) + payload

def rtp(pt, seq, ts, payload, ssrc=0x11223344, marker=0):
    return struct.pack('>BBHII', 0x80, (marker << 7) | pt, seq & 0xffff, ts & 0xffffffff, ssrc) + payload

class Cap:
    """pcapng writer with interface 0 = Ethernet, 1 = Exported PDU (252)."""
    def __init__(self):
        self.frames = []
    def eth(self, data, note=None):
        self.frames.append((1, data, len(data))); return len(self.frames)
    def epdu(self, name, payload, extra=b'', snap=None):
        d = exp_pdu(name, payload, extra)
        self.frames.append((252, d, len(d) if snap is None else len(d) - snap)); return len(self.frames)
    def write(self, fname):
        def blk(t, body):
            body += b'\0' * ((4 - len(body) % 4) % 4)
            return struct.pack('<II', t, len(body) + 12) + body + struct.pack('<I', len(body) + 12)
        out = blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
        out += blk(1, struct.pack('<HHI', 1, 0, 0))
        out += blk(1, struct.pack('<HHI', 252, 0, 0))
        for i, (lt, d, orig) in enumerate(self.frames):
            cap = min(len(d), orig)
            out += blk(6, struct.pack('<IIIII', 0 if lt == 1 else 1, 0, 1000 + i, cap, len(d)) + d[:cap])
        open(fname, 'wb').write(out)

def pcap(fname, linktype, pkts):
    with open(fname, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, p in enumerate(pkts):
            f.write(struct.pack('<IIII', 1000 + i, 0, len(p), len(p)) + p)

def vi(value):
    """MOQT variable-length integer (draft 18 and 22)."""
    length = max(1, min(9, (value.bit_length() + 6) // 7))
    if length == 9:
        return b'\xff' + value.to_bytes(8, 'big')
    enc = bytearray(value.to_bytes(length, 'big'))
    enc[0] |= ((1 << (length - 1)) - 1) << (9 - length)
    return bytes(enc)

def lp(b):
    return vi(len(b)) + b

def ns(*fields):
    return vi(len(fields)) + b''.join(lp(f) for f in fields)

def msg(t, payload):
    return vi(t) + len(payload).to_bytes(2, 'big') + payload

def params(*entries):
    prev = 0
    out = vi(len(entries))
    for t, v in entries:
        out += vi(t - prev) + v
        prev = t
    return out

def kv(*entries):
    prev = 0
    out = b''
    for t, v in entries:
        out += vi(t - prev) + v
        prev = t
    return out

def tok(alias_type, alias=1, ttype=0, value=b'tok'):
    b = vi(alias_type)
    if alias_type in (0, 1, 2):
        b += vi(alias)
    if alias_type in (1, 3):
        b += vi(ttype) + value
    return b

def loc(g, o):
    return vi(g) + vi(o)

TRACK = ns(b'example', b'live') + lp(b'video')
PROP_NAMES18 = (0x02, 0x04, 0x06, 0x0b, 0x0e, 0x22, 0x30, 0x3c, 0x3e)
PROP_NAMES22 = (0x02, 0x04, 0x06, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x22, 0x30, 0x32, 0x3c, 0x3e)

def prop_entries(names):
    out = []
    for t in names:
        if t == 0x0b:
            continue
        out.append((t, lp(b'\x01\x02') if t & 1 else vi(t * 3)))
    return out

def control(d):
    """Control and request stream messages for a draft; returns a list of (label, bytes)."""
    f = []
    A = f.append
    names = PROP_NAMES18 if d == 18 else PROP_NAMES22
    props = kv(*prop_entries(names))
    props_imm = kv((0x0b, lp(kv((0x02, vi(1)), (0x04, vi(2)), (0x07, lp(b'xy'))))), (0x0e, vi(64)))
    all_params = [
        (0x02, vi(130)), (0x03, lp(tok(3))), (0x04, vi(131)), (0x06, vi(132)), (0x08, vi(133)),
        (0x09, loc(7, 12)), (0x0a, vi(134)), (0x10, b'\x01'), (0x20, b'\x2a'),
    ]
    if d == 18:
        all_params += [(0x21, lp(vi(4) + loc(1, 2) + vi(3))), (0x22, b'\x01'), (0x32, vi(135)),
                       (0x34, ns(b'a', b'b'))]
    else:
        all_params += [(0x21, vi(4) + vi(1) + vi(2) + vi(3) + vi(4)), (0x22, b'\x01'),
                       (0x23, lp(params((0x0a, vi(9)), (0x20, b'\x05')))),
                       (0x25, lp(b'\x01' + vi(1) + vi(2) + vi(0) + vi(5))),
                       (0x26, lp(b'\x02' + vi(3) + vi(2))),
                       (0x27, lp(b'\x03' + vi(1))),
                       (0x28, lp(b'\x04' + vi(0x0c) + vi(4) + vi(4))),
                       (0x29, lp(b'\x05' + vi(0x0c) + vi(1))),
                       (0x32, vi(135)), (0x34, ns(b'a', b'b')), (0x35, b'\x01')]
    A(('subscribe all params', msg(0x03, vi(0) + TRACK + params(*all_params))))
    # authorization token alias types
    for at in (0, 1, 2, 3, 4):
        A(('token %d' % at, msg(0x03, vi(2) + TRACK + params((0x03, lp(tok(at)))))))
    A(('subscribe no params', msg(0x03, vi(4) + ns(b'x') + lp(b'trk-name.\xff') + params())))
    A(('subscribe 3 fields', msg(0x03, vi(6) + ns(b'a b', b'c', b'') + lp(b'') + params())))
    if d == 18:
        for ft in (1, 2, 3, 4):
            val = {1: b'', 2: b'', 3: loc(5, 6), 4: loc(5, 6) + vi(2)}[ft]
            A(('sub filter %d' % ft, msg(0x02, vi(8) + params((0x21, lp(vi(ft) + val))))))
    else:
        for lt, n in ((0, 0), (1, 1), (2, 2), (3, 3), (4, 4), (5, 0)):
            A(('loc filter %d' % lt, msg(0x02, vi(8) + params((0x21, vi(lt) + b''.join(vi(i + 1) for i in range(n)))))))
        A(('range filters', msg(0x02, vi(8) + params(
            (0x25, lp(b'')), (0x26, lp(b'\x02' + vi(3) + vi(2) + vi(1) + vi(0))),
            (0x27, lp(b'\x01' + vi(5))),
            (0x28, lp(b'\x01' + vi(0x0c) + vi(4) + vi(4) + vi(1))),
            (0x29, lp(b''))))))
        A(('fill params', msg(0x02, vi(10) + params((0x23, lp(params((0x0a, vi(250)), (0x20, b'\x09'))))))))
        A(('fill params empty', msg(0x02, vi(10) + params((0x23, lp(params()))))))
    A(('subscribe_ok', msg(0x04, vi(7) + params((0x08, vi(5000)), (0x09, loc(3, 4))) + props)))
    A(('subscribe_ok immutable', msg(0x04, vi(8) + params() + props_imm)))
    A(('subscribe_ok no props', msg(0x04, vi(9) + params())))
    A(('subscribe_ok unknown props', msg(0x04, vi(9) + params() + kv((0x40, vi(1)), (0x41, lp(b'abc')), (0x44, vi(0))))))
    A(('request_update', msg(0x02, vi(6) + params((0x10, b'\x01'), (0x20, b'\x0a')))))
    errs = (0, 1, 2, 3, 4, 5, 6, 9, 0x10, 0x11, 0x12, 0x20, 0x30, 0x31, 0x33, 0x77)
    errs += (0x19, 0x32) if d == 18 else (0x35, 0x36)
    for e in errs:
        A(('request_error %x' % e, msg(0x05, vi(e) + vi(100) + lp(b'reason %x' % e))))
    A(('request_error redirect', msg(0x05, vi(0x34) + vi(0) + lp(b'moved') + lp(b'moqt://other.example') + ns(b'alt') + lp(b'v2'))))
    A(('request_ok', msg(0x07, params((0x08, vi(5000))) + kv((0x0e, vi(25))))))
    A(('request_ok bare', msg(0x07, params())))
    A(('namespace', msg(0x08, ns(b'participant', b'1'))))
    A(('namespace_done', msg(0x0e, ns(b'participant'))))
    A(('namespace long', msg(0x08, ns(*[b'f%d' % i for i in range(32)]))))
    for c in (0, 1, 2, 3, 4, 5, 6, 8, 9, 0x12, 0x77) + ((3,) if d == 18 else ()):
        A(('publish_done %x' % c, msg(0x0b, vi(c) + vi(3) + lp(b'done'))))
    A(('track_status', msg(0x0d, vi(14) + TRACK + params())))
    A(('publish_blocked', msg(0x0f, ns(b'participant') + lp(b'audio'))))
    A(('publish', msg(0x1d, vi(8) + TRACK + vi(12) + params((0x03, lp(tok(1))), (0x10, b'\x01')) + kv((0x30, vi(1))))))
    A(('publish no props', msg(0x1d, vi(8) + TRACK + vi(12) + params())))
    A(('fetch_ok', msg(0x18, b'\x01' + loc(5, 6) + params((0x20, b'\x0a')) + kv((0x04, vi(500))))))
    A(('fetch_ok bare', msg(0x18, b'\x00' + loc(0, 0) + params())))
    A(('subscribe_namespace', msg(0x50, vi(18) + ns(b'ex', b'chan') + params())))
    A(('subscribe_tracks', msg(0x51, vi(20) + ns(b'ex') + params((0x10, b'\x00')))))
    A(('publish_namespace', msg(0x06, (vi(16) if d == 18 else vi(16)) + ns(b'ex', b'chan') + params())))
    if d == 18:
        A(('fetch standalone', msg(0x16, vi(10) + vi(1) + TRACK + loc(1, 0) + loc(20, 0) + params())))
        A(('fetch joining rel', msg(0x16, vi(12) + vi(2) + vi(3) + vi(4) + params((0x0a, vi(250))))))
        A(('fetch joining abs', msg(0x16, vi(12) + vi(3) + vi(3) + vi(4) + params())))
        A(('publish_ok', msg(0x1e, params())))
        A(('publish_ok params', msg(0x1e, params((0x10, b'\x01')) + props)))
        A(('goaway request', msg(0x10, lp(b'moqt://new.example') + vi(100))))
        A(('goaway empty', msg(0x10, lp(b'') + vi(0))))
    else:
        A(('fetch', msg(0x16, vi(4) + TRACK + params((0x21, vi(4) + vi(0) + vi(0) + vi(2) + vi(5)), (0x35, b'\x00')))))
        A(('publish_state_notify', msg(0x22, params((0x09, loc(12, 0)), (0x10, b'\x00')))))
        A(('publish_state_notify bare', msg(0x22, params())))
        A(('goaway', msg(0x10, lp(b'moqt://new.example') + vi(100))))
        A(('goaway empty', msg(0x10, lp(b'') + vi(0))))
    return f

def setup_frames(d):
    f = []
    opts = kv((0x01, lp(b'/moq')), (0x03, lp(tok(3))), (0x04, vi(1000)), (0x05, lp(b'example.com')),
              (0x07, lp(b'implementation 1.0')))
    f.append(('setup', msg(0x2f00, opts)))
    f.append(('setup tokens', msg(0x2f00, kv((0x03, lp(tok(0))), (0x03, lp(tok(1))), (0x03, lp(tok(2))), (0x03, lp(tok(4)))))))
    f.append(('setup empty', msg(0x2f00, b'')))
    f.append(('setup unknown', msg(0x2f00, kv((0x09, lp(b'z')), (0x0a, vi(1)), (0x0b, lp(b'zz'))))))
    if d == 22:
        f.append(('setup d22', msg(0x2f00, kv((0x06, vi(8)), (0x08, vi(4))))))
    if d == 18:
        # GOAWAY on the control stream carries the Request ID
        f.append(('setup+goaway', msg(0x2f00, opts) + msg(0x10, lp(b'moqt://new') + vi(100) + vi(7))))
    else:
        f.append(('setup+goaway', msg(0x2f00, opts) + msg(0x10, lp(b'moqt://new') + vi(100))))
    return f

def streams(d):
    f = []
    A = f.append
    # subgroup streams: every combination of PROPERTIES(1) ID mode(6) END_OF_GROUP(8) MARKER(0x10) DEFAULT_PRIO(0x20) FIRST(0x40)
    for t in range(0x10, 0x80):
        if (t & 6) == 6 or not t & 0x10:
            continue
        mode = t & 6
        hdr = vi(t) + vi(7) + vi(10)
        if mode == 4:
            hdr += vi(3)
        if not (t & 0x20):
            hdr += b'\x09'
        props = b''
        if t & 1:
            props = lp(kv((0x02, vi(1))))
        obj1 = vi(0) + props + vi(3) + b'abc'
        obj2 = vi(1) + (lp(b'') if t & 1 else b'') + vi(0) + vi(3)       # status End of Group
        obj3 = vi(0) + (lp(b'') if t & 1 else b'') + vi(0) + vi(4)       # status End of Track
        obj4 = vi(2) + (lp(b'') if t & 1 else b'') + vi(0) + vi(0)       # status Normal, zero payload
        A(('subgroup %02x' % t, hdr + obj1 + obj2 + obj3 + obj4))
    # object with properties
    A(('subgroup props', vi(0x31) + vi(1) + vi(2) + vi(0) + lp(kv((0x02, vi(1)), (0x0b, lp(kv((0x04, vi(1)))), ))) + vi(2) + b'hi'))
    A(('subgroup big deltas', vi(0x30) + vi(1) + vi(2) + vi(1 << 40) + vi(1) + b'a' + vi(1 << 20) + vi(1) + b'b'))
    A(('subgroup end', vi(0x30) + vi(1) + vi(2)))
    # fetch streams
    fo = lambda fl, body: vi(fl) + body
    A(('fetch stream', vi(5) + vi(4) +
       fo(0x1c, vi(10) + vi(0) + b'\x05' + lp(b'\xaa\xbb')) +
       fo(0x00, lp(b'\xcc')) +
       fo(0x8c, loc(11, 0)) + fo(0x10c, loc(12, 0))))
    A(('fetch flags', vi(5) + vi(4) + b''.join(
        fo(fl, ((vi(1) if fl & 8 else b'') + (vi(2) if (fl & 0x43) == 3 else b'') + (vi(3) if fl & 4 else b'') +
                (b'\x07' if fl & 0x10 else b'') + (lp(kv((0x02, vi(1)))) if fl & 0x20 else b'') + lp(b'p')))
        for fl in range(0, 0x7f))))
    for fl in (0x41, 0x43, 0x5f, 0x7f):
        pass
    A(('fetch datagram obj', vi(5) + vi(4) + fo(0x7f, vi(1) + vi(1) + b'\x07' + lp(kv((0x02, vi(1)))) + lp(b'x'))))
    if d == 22:
        A(('fetch timed out', vi(5) + vi(4) + fo(0x20c, loc(1, 2))))
    A(('fetch only header', vi(5) + vi(6)))
    A(('padding stream', vi(0x132b3e28) + bytes(40)))
    A(('padding stream empty', vi(0x132b3e28)))
    return f

def datagrams(d):
    f = []
    A = f.append
    for t in range(0, 0x30):
        if t & 0x10 or (t & 0x20 and t & 2):
            continue
        body = vi(1) + vi(2)
        if not t & 4:
            body += vi(3)
        if not t & 8:
            body += b'\x04'
        if t & 1:
            body += lp(kv((0x02, vi(1)), (0x0b, lp(kv((0x04, vi(1)))))))
        if t & 0x20:
            body += vi(0)
        else:
            body += b'payload'
        A(('datagram %02x' % t, vi(t) + body))
    A(('datagram status eot', vi(0x20) + vi(1) + vi(2) + vi(3) + b'\x04' + vi(4)))
    A(('datagram status eog', vi(0x20) + vi(1) + vi(2) + vi(3) + b'\x04' + vi(3)))
    A(('datagram nonempty props', vi(0x01) + vi(1) + vi(2) + vi(3) + b'\x04' + lp(kv((0x02, vi(1)))) + b'x'))
    A(('padding datagram', vi(0x132b3e29) + bytes(8)))
    A(('padding datagram empty', vi(0x132b3e29)))
    A(('datagram wide', vi(0x0c) + vi(2 ** 64 - 1) + vi(2 ** 56) + b'wide'))
    return f

def malformed(d):
    f = []
    A = f.append
    # control messages
    A(('unknown message', msg(0x7e, b'\x01\x02')))                       # unknown stream type with EPDU
    A(('unknown param', msg(0x02, vi(1) + params((0x7f, vi(1))))))
    A(('subscribe truncated', msg(0x03, vi(0) + vi(2) + lp(b'a'))))
    A(('namespace 33 fields', msg(0x08, ns(*[b'x'] * 33))))
    A(('bad filter type', msg(0x02, vi(1) + params((0x21, lp(vi(9)) if d == 18 else vi(9))))))
    A(('bad fetch type', msg(0x16, vi(1) + vi(9) + params()) if d == 18 else msg(0x16, vi(1) + TRACK[:-3])))
    A(('type delta overflow', msg(0x02, vi(1) + vi(2) + vi(2 ** 64 - 1) + b'\x00' + vi(2) + b'\x00')))
    inner = lp(kv((0x02, vi(1))))
    mid = lp(kv((0x0b, inner)))
    A(('immutable in immutable', msg(0x04, vi(1) + params() + kv((0x0b, mid)))))
    A(('property value > 65535', vi(0x31) + vi(1) + vi(2) + vi(0) + lp(kv((0x01, lp(b'a' * 70000)))) + vi(1) + b'x'))
    A(('message length beyond data', vi(0x03) + (500).to_bytes(2, 'big') + b'\x00' * 10))
    A(('control huge length', vi(0x02) + b'\xff' * 3))
    A(('empty body request', msg(0x03, b'')))
    A(('request_error short', msg(0x05, vi(0x34) + vi(0) + lp(b'x'))))
    A(('request_error redirect cut', msg(0x05, vi(0x34) + vi(0) + lp(b'x') + lp(b'uri'))))
    A(('fetch_ok cut', msg(0x18, b'\x01')))
    A(('publish_done cut', msg(0x0b, vi(2))))
    A(('track alias cut', msg(0x04, b'')))
    A(('param cut', msg(0x02, vi(1) + vi(1) + vi(0x20))))
    A(('param value cut', msg(0x02, vi(1) + params((0x08, b'\xff')))))
    A(('token cut', msg(0x03, vi(2) + TRACK + params((0x03, lp(vi(1)))))))
    A(('kv cut', msg(0x04, vi(2) + params() + vi(1) + vi(10) + b'ab')))
    A(('kv delta overflow', msg(0x04, vi(2) + params() + kv((0x20, vi(1))) + vi(2 ** 64 - 1))))
    A(('nested truncated', msg(0x04, vi(2) + params() + kv((0x0b, lp(vi(1) + vi(10) + b'a'))))))
    # object status / properties
    A(('subgroup bad status', vi(0x30) + vi(1) + vi(2) + vi(0) + vi(0) + vi(9)))
    A(('subgroup props nonnormal', vi(0x31) + vi(1) + vi(2) + vi(0) + lp(kv((0x02, vi(1)))) + vi(0) + vi(3)))
    A(('subgroup empty props bit', vi(0x31) + vi(1) + vi(2) + vi(0) + lp(b'') + vi(1) + b'a'))
    A(('subgroup object id overflow', vi(0x30) + vi(1) + vi(2) + vi(0) + vi(1) + b'a' + vi(2 ** 64 - 1) + vi(1) + b'b'))
    A(('subgroup payload cut', vi(0x30) + vi(1) + vi(2) + vi(0) + vi(10) + b'abc'))
    A(('subgroup header cut', vi(0x34) + vi(1) + vi(2)))
    A(('subgroup header cut2', vi(0x30) + vi(1)))
    A(('subgroup object cut', vi(0x31) + vi(1) + vi(2) + vi(0) + vi(5) + b'ab'))
    A(('unknown unidirectional', vi(0x77) + b'abcdef'))
    A(('unknown uni 0x16', vi(0x16)))
    A(('fetch bad flags', vi(5) + vi(4) + vi(0x80) + b'bad'))
    A(('fetch cut', vi(5) + vi(4) + vi(0x1c) + vi(10)))
    A(('fetch eor cut', vi(5) + vi(4) + vi(0x8c) + vi(10)))
    A(('fetch payload len', vi(5) + vi(4) + vi(0x00) + vi(99) + b'a'))
    A(('fetch header cut', vi(5)))
    A(('nonzero padding', vi(0x132b3e28) + b'\x00\x00\x01\x00'))
    A(('setup then unknown message', msg(0x2f00, b'') + msg(0x7e, b'zz')))
    A(('request_error empty', msg(0x05, b'')))
    A(('token empty', msg(0x03, vi(2) + TRACK + params((0x03, lp(b''))))))
    A(('param block cut', msg(0x03, vi(2) + TRACK + params((0x03, vi(50) + b'ab')))))
    A(('namespace field length huge', msg(0x08, vi(1) + vi(2 ** 40) + b'abc')))
    A(('fetch type cut', msg(0x16, vi(1))))
    if d == 22:
        big = b'\xff' + (2 ** 64 - 2).to_bytes(8, 'big')
        huge = b'\xff' + (2 ** 64 - 1).to_bytes(8, 'big')
        def rf(t, body):
            return msg(0x02, vi(1) + params((t, lp(body))))
        A(('range start overflow', rf(0x26, b'\x01' + vi(0) + big + vi(5))))
        A(('range end overflow', rf(0x26, b'\x01' + vi(10) + huge)))
        A(('range end cut', rf(0x26, b'\x01' + vi(10) + b'\xff\x01')))
        A(('range property cut', rf(0x28, b'\x01')))
        A(('fill in fill', rf(0x23, params((0x23, lp(params()))))))
        A(('fill cut', rf(0x23, vi(1))))
    A(('subgroup mode 6', vi(0x16) + vi(1) + vi(2)))
    return f

def dgmalformed(d):
    f = []
    A = f.append
    A(('datagram bad type', vi(0x10) + vi(1) + vi(2)))
    A(('datagram status+eog', vi(0x22) + vi(1) + vi(2) + vi(3) + b'\x04' + vi(0)))
    A(('datagram bad status', vi(0x20) + vi(1) + vi(2) + vi(3) + b'\x04' + vi(2)))
    A(('datagram empty props', vi(0x01) + vi(1) + vi(2) + vi(3) + b'\x04' + lp(b'') + b'x'))
    A(('datagram truncated', vi(0x00) + vi(1)))
    A(('datagram type cut', b'\xff'))
    A(('datagram status props', vi(0x21) + vi(1) + vi(2) + vi(3) + b'\x04' + lp(kv((0x02, vi(1)))) + vi(3)))
    A(('datagram nonzero padding', vi(0x132b3e29) + b'\x00\x01'))
    A(('datagram props cut', vi(0x01) + vi(1) + vi(2) + vi(3) + b'\x04' + vi(9) + b'x'))
    A(('datagram bad type 2', vi(0x80)))
    return f

def main(out, verbose):
    cap = Cap()
    ranges = []
    def emit(name, frames, alpn, tail=''):
        start = len(cap.frames) + 1
        for label, data in frames:
            cap.epdu(alpn + tail, data)
        ranges.append((name, start, len(cap.frames)))
    for d, alpn in ((18, 'moqt-18'), (22, 'moqt-22')):
        emit('setup d%d' % d, setup_frames(d), alpn)
        emit('control d%d' % d, control(d), alpn)
        emit('streams d%d' % d, streams(d), alpn)
        emit('datagrams d%d' % d, datagrams(d), alpn, '.datagram')
    emit('empty payload', [('empty', b'')], 'moqt-18')
    # the "moqt" names select the latest draft (22)
    emit('moqt latest', [setup_frames(22)[0], control(22)[0]], 'moqt-22')
    emit('moqt latest streams', [streams(22)[0]], 'moqt')
    emit('moqt latest datagram', [datagrams(22)[0]], 'moqt', '.datagram')
    # reproducer of the truncated PDU fix: SUBGROUP_HEADER then an object whose payload
    # length (10) runs past the end of the PDU. It gets an expert error, so it is in the malformed capture.
    cap.write(os.path.join(out, 'moqt-coverage.pcapng'))
    m = Cap()
    for d, alpn in ((18, 'moqt-18'), (22, 'moqt-22')):
        for label, data in malformed(d):
            m.epdu(alpn, data)
        for label, data in dgmalformed(d):
            m.epdu(alpn + '.datagram', data)
    # captured length shorter than the PDU (snap length): no reassembly can repair it
    for d, alpn in ((18, 'moqt-18'), (22, 'moqt-22')):
        for label, data, cut in (
                ('control', control(d)[0][1], 6), ('control2', control(d)[3][1], 3),
                ('subgroup', streams(d)[0][1], 4), ('subgroup2', streams(d)[40][1], 1),
                ('fetch', streams(d)[-6][1], 5), ('fetch2', streams(d)[-6][1], 1),
                ('setup', setup_frames(d)[0][1], 2)):
            m.epdu(alpn, data, snap=cut)
        m.epdu(alpn, msg(0x2f00, b''), snap=3)                    # only the first octet of the type is captured
        m.epdu(alpn, vi(0x132b3e28) + b'\x00', snap=5)             # padding stream type cut inside the integer
        m.epdu(alpn, msg(0x18, b''))
        m.epdu(alpn + '.datagram', datagrams(d)[0][1], snap=3)
        m.epdu(alpn + '.datagram', vi(2 ** 40) + b'\x00' * 4, snap=3)
        m.epdu(alpn, vi(0x03) + (4).to_bytes(2, 'big') + vi(2 ** 40)[:0] + b'\xff' * 4)
        m.epdu(alpn, vi(5) + vi(4) + b'\xff\x00\x00', snap=1)
    m.epdu('moqt-18', bytes([0x10, 0x01, 0x05, 0x80, 0x00, 0x0a]) + b'abc')
    m.write(os.path.join(out, 'moqt-coverage-malformed.pcapng'))
    if verbose:
        for r in ranges:
            print(r)
        print('total', len(cap.frames), 'malformed capture', len(m.frames))

if __name__ == '__main__':
    main(sys.argv[1], '-v' in sys.argv)
