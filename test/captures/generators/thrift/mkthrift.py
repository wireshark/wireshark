#!/usr/bin/env python3
# Generates test/captures/thrift_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic captures for packet-thrift.c.  Usage: mkthrift.py <outdir>
Writes thrift-coverage.pcap(.gz), thrift_coverage.pcap.gz and
thrift-coverage-malformed.pcap.

Values are described by a small type model and encoded for TBinaryProtocol
(strict and old header) and TCompactProtocol, with and without TFramedTransport.

  struct value : list of (field id, type, value)
  list/set     : (element type, [values])
  map          : (key type, value type, [(key, value), ...])
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
import shutil
import util as u

# ------------------------------------------------------------------ binary
BT = {'bool': 2, 'i8': 3, 'double': 4, 'i16': 6, 'i32': 8, 'i64': 10, 'bin': 11,
      'struct': 12, 'map': 13, 'set': 14, 'list': 15, 'uuid': 16}


def b_val(t, v):
    if t == 'bool': return bytes([1 if v else 0])
    if t == 'i8': return struct.pack('>b', v)
    if t == 'i16': return struct.pack('>h', v)
    if t == 'i32': return struct.pack('>i', v)
    if t == 'i64': return struct.pack('>q', v)
    if t == 'double': return struct.pack('>d', v)
    if t == 'uuid': return bytes(v)
    if t == 'bin':
        d = v.encode() if isinstance(v, str) else v
        return struct.pack('>i', len(d)) + d
    if t == 'struct': return b_struct(v)
    if t in ('list', 'set'):
        et, items = v
        return bytes([BT[et]]) + struct.pack('>i', len(items)) + b''.join(b_val(et, x) for x in items)
    if t == 'map':
        kt, vt, items = v
        return (bytes([BT[kt], BT[vt]]) + struct.pack('>i', len(items)) +
                b''.join(b_val(kt, k) + b_val(vt, x) for k, x in items))
    raise ValueError(t)


def b_struct(fields):
    out = b''
    for fid, t, v in fields:
        out += bytes([BT[t]]) + struct.pack('>h', fid) + b_val(t, v)
    return out + b'\x00'


def b_msg(name, mtype, seq, body, strict=True):
    n = name.encode()
    if strict:
        return struct.pack('>II', 0x80010000 | mtype, len(n)) + n + struct.pack('>i', seq) + body
    return struct.pack('>I', len(n)) + n + bytes([mtype]) + struct.pack('>i', seq) + body


# ------------------------------------------------------------------ compact
CT = {'bool': 2, 'i8': 3, 'i16': 4, 'i32': 5, 'i64': 6, 'double': 7, 'bin': 8,
      'list': 9, 'set': 10, 'map': 11, 'struct': 12, 'uuid': 13}


def varint(n):
    out = b''
    while True:
        b = n & 0x7f
        n >>= 7
        if n:
            out += bytes([b | 0x80])
        else:
            return out + bytes([b])


def zz(n, bits):
    return varint(((n << 1) ^ (n >> (bits - 1))) & ((1 << bits) - 1))


def c_val(t, v):
    if t == 'bool': return bytes([1 if v else 2])           # in containers
    if t == 'i8': return struct.pack('>b', v)
    if t == 'i16': return zz(v, 16)
    if t == 'i32': return zz(v, 32)
    if t == 'i64': return zz(v, 64)
    if t == 'double': return struct.pack('<d', v)
    if t == 'uuid': return bytes(v)
    if t == 'bin':
        d = v.encode() if isinstance(v, str) else v
        return varint(len(d)) + d
    if t == 'struct': return c_struct(v)
    if t in ('list', 'set'):
        et, items = v
        n = len(items)
        h = bytes([(n << 4) | CT[et]]) if n < 15 else bytes([0xf0 | CT[et]]) + varint(n)
        return h + b''.join(c_val(et, x) for x in items)
    if t == 'map':
        kt, vt, items = v
        if not items: return b'\x00'
        return (varint(len(items)) + bytes([(CT[kt] << 4) | CT[vt]]) +
                b''.join(c_val(kt, k) + c_val(vt, x) for k, x in items))
    raise ValueError(t)


def c_struct(fields):
    out = b''
    prev = 0
    for fid, t, v in fields:
        ct = CT[t]
        if t == 'bool':
            ct = 1 if v else 2
        d = fid - prev
        if 1 <= d <= 15:
            out += bytes([(d << 4) | ct])
        else:
            out += bytes([ct]) + zz(fid, 16)
        if t != 'bool':
            out += c_val(t, v)
        prev = fid
    return out + b'\x00'


def c_msg(name, mtype, seq, body):
    n = name.encode()
    return bytes([0x82, (mtype << 5) | 1]) + varint(seq) + varint(len(n)) + n + body


def framed(msg):
    return struct.pack('>I', len(msg)) + msg


# ------------------------------------------------------------------ values
UUID = bytes(range(16))
CALL, REPLY, EXC, ONEWAY = 1, 2, 3, 4


def all_types():
    """A struct with every type, containers of every shape."""
    inner = [(1, 'i32', 7), (2, 'bin', 'inner'), (3, 'struct', [(1, 'bool', True)])]
    return [
        (1, 'bool', True), (2, 'i8', -5), (3, 'double', 3.25), (4, 'i16', 1234),
        (5, 'i32', -70000), (6, 'i64', 1 << 40), (7, 'bin', 'héllo wörld € \U0001f600'),
        (8, 'bin', b'\x00\x01\xff\xfe'), (9, 'uuid', UUID),
        (10, 'list', ('i32', [1, -2, 3])), (11, 'set', ('bin', ['a', 'bb', 'ccc'])),
        (12, 'map', ('bin', 'list', [('k1', ('i16', [1, 2])), ('k2', ('i16', []))])),
        (13, 'struct', inner), (14, 'list', ('struct', [inner, inner])),
        (15, 'map', ('i32', 'double', [(1, 1.5), (2, -2.5)])), (16, 'bin', ''),
        (17, 'bin', 'line1\r\nline2'), (18, 'bool', False), (19, 'list', ('bool', [True, False, True])),
        (20, 'list', ('list', [('i8', [1, 2]), ('i8', []), ('i8', [3])])),
        (21, 'set', ('i64', [1, 2, 3])), (22, 'list', ('bin', ['x', b'\x80\x81', ''])),
        (23, 'map', ('bool', 'i8', [(True, 1), (False, 2)])), (24, 'list', ('uuid', [UUID, UUID])),
        (25, 'map', ('i64', 'bin', [])), (26, 'list', ('double', [0.5, 1.5])),
        (27, 'list', ('i16', [-1, 300, 32767])), (28, 'set', ('i8', [1, 2])),
        (29, 'bin', b'\x00\x00\x00'), (30, 'bin', 'caf\xe9'.encode('latin-1')),
        (31, 'bin', b'ab\x00\x00'), (32, 'bin', b'\xc0\x80'), (33, 'bin', b'\xed\xa0\x80'),
        (34, 'bin', b'\xf0\x90\x80\x80'), (35, 'bin', b'\xf5\x80\x80\x80'), (36, 'bin', b'\xe0\x80\x80'),
    ]


def big_lists():
    """Containers with 15 and more elements (long list form in compact)"""
    return [(1, 'list', ('i32', list(range(20)))), (2, 'set', ('i8', list(range(15)))),
            (3, 'map', ('i16', 'i16', [(i, i * 2) for i in range(16)])),
            (4, 'list', ('bin', ['s%d' % i for i in range(300)]))]


def nested_list(depth):
    v = ('i32', [5])
    for _ in range(depth):
        v = ('list', [v])
    return v


def nested_struct(depth):
    f = [(1, 'i32', 9)]
    for _ in range(depth):
        f = [(1, 'struct', f)]
    return f



def at_limit(kind):
    """25 nested lists (the default nesting limit) whose innermost list holds a
    `kind` (list, set, map or struct): entering it hits the limit"""
    et, ev = {'map': ('map', ('i32', 'i32', [(1, 1)])), 'struct': ('struct', [(1, 'i32', 1)]),
              'set': ('set', ('i8', [1])), 'list': ('list', ('i8', [1]))}[kind]
    v = (et, [ev])
    for _ in range(24):
        v = ('list', [v])
    return [(1, 'list', v)]


EXC_FIELDS = [(1, 'bin', 'Invalid method name: foo'), (2, 'i32', 1)]

# ------------------------------------------------------------------ frames
def tcp_flow(o, cport, sport, items, seg=None, cisn=1000, sisn=5000):
    """items: list of ('c'|'s', bytes[, segsize])"""
    c = u.Conn(o, cport, sport, cisn=cisn, sisn=sisn)
    for it in items:
        d, data = it[0], it[1]
        n = it[2] if len(it) > 2 else seg
        if d == 'c':
            c.send(data) if n is None else c.csegs(data, n)
        else:
            c.recv(data) if n is None else c.ssegs(data, n)
    c.fin()
    return c


def http_post(ctype, body, path='/thrift'):
    return (b'POST ' + path.encode() + b' HTTP/1.1\r\nHost: thrift.example.test\r\nContent-Type: ' +
            ctype.encode() + b'\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n\r\n' + body)


def http_reply(ctype, body):
    return (b'HTTP/1.1 200 OK\r\nContent-Type: ' + ctype.encode() + b'\r\nContent-Length: ' +
            str(len(body)).encode() + b'\r\n\r\n' + body)


def depth_loop(depth=25, count=0x7fffffff):
    """Reproducer of "Thrift: Stop at the nesting limit in the binary protocol":
    `depth` nested lists, the innermost claims `count` elements of type list. At
    the limit the generic code returned an error that the callers ignored, so it
    looped `count` times on the same offset."""
    body = struct.pack('>BH', 15, 1)
    for _ in range(depth - 1):
        body += struct.pack('>BI', 15, 1)
    body += struct.pack('>BI', 15, count) + b'\x0f\x00\x00\x00\x00'
    return b_msg('a', CALL, 1, body, True)


def main_frames():
    o = []
    A = all_types()
    ts = 0

    # ===== A: TCP 19090, TBinaryProtocol strict, heuristic =====
    items = []
    seq = 0
    def pair(name, req_fields, rep_fields, rmtype=REPLY, **kw):
        nonlocal seq
        seq += 1
        items.append(('c', b_msg(name, CALL, seq, b_struct(req_fields))))
        items.append(('s', b_msg(name, rmtype, seq, b_struct(rep_fields))))
    pair('everything', A, [(0, 'struct', A)])
    pair('ping', [], [])
    pair('add', [(1, 'i32', 3), (2, 'i32', 4)], [(0, 'i32', 7)])
    pair('fail', [(1, 'bin', 'x')], [(1, 'struct', [(1, 'bin', 'user exception'), (2, 'i32', 5)])])
    pair('fail2', [(1, 'bin', 'x')], [(2, 'struct', [(1, 'i32', 5)])])
    items.append(('c', b_msg('notify', ONEWAY, 90, b_struct([(1, 'bin', 'fire and forget')]))))
    # protocol exceptions (message type 3)
    for fields in (EXC_FIELDS,):
        seq += 1
        items.append(('c', b_msg('missing', CALL, seq, b_struct([]))))
        items.append(('s', b_msg('missing', EXC, seq, b_struct(fields))))
    # field ids out of order, repeated and negative
    items.append(('c', b_msg('order', CALL, 91, b_struct([(5, 'i32', 1), (3, 'i32', 2), (3, 'i32', 3), (9, 'i32', 4)]))))
    items.append(('c', b_msg('neg', CALL, 92, b_struct([(-3, 'i32', 1), (2, 'i32', 2)]))))
    items.append(('c', b_msg('', CALL, 93, b_struct([(1, 'i8', 1)]))))        # empty method name
    items.append(('c', b_msg('big', CALL, 94, b_struct(big_lists()))))
    items.append(('c', b_msg('deep', CALL, 95, b_struct([(1, 'list', nested_list(20)), (2, 'struct', nested_struct(20))]))))
    # two messages in one segment
    items.append(('c', b_msg('one', CALL, 96, b_struct([(1, 'i8', 1)])) + b_msg('two', CALL, 97, b_struct([(1, 'i8', 2)]))))
    # a message split over TCP segments
    items.append(('c', b_msg('split', CALL, 98, b_struct(A[:12])), 50))
    tcp_flow(o, 40000, 19090, items)

    # ===== B: TCP 19091, strict binary, framed =====
    items = []
    items.append(('c', framed(b_msg('everything', CALL, 1, b_struct(A)))))
    items.append(('s', framed(b_msg('everything', REPLY, 1, b_struct([(0, 'struct', A)])))))
    items.append(('c', framed(b_msg('ping', CALL, 2, b_struct([])))))
    items.append(('s', framed(b_msg('ping', REPLY, 2, b_struct([])))))
    items.append(('s', framed(b_msg('ping', EXC, 3, b_struct(EXC_FIELDS)))))
    items.append(('c', framed(b_msg('a', CALL, 4, b_struct([(1, 'i32', 1)]))) + framed(b_msg('b', CALL, 5, b_struct([(1, 'i32', 2)])))))
    # a frame spanning several TCP segments (reassembled), then a frame longer than its message
    items.append(('c', framed(b_msg('big', CALL, 6, b_struct(big_lists()))), 300))
    items.append(('c', struct.pack('>I', len(b_msg('long', CALL, 7, b_struct([(1, 'i8', 1)]))) + 3) +
                  b_msg('long', CALL, 7, b_struct([(1, 'i8', 1)])) + b'\xaa\xbb\xcc'))
    tcp_flow(o, 40001, 19091, items)

    # ===== C: TCP 19092, TCompactProtocol =====
    items = []
    seq = 0
    def cpair(name, req_fields, rep_fields, rmtype=REPLY, fr=False):
        nonlocal seq
        seq += 1
        w = framed if fr else (lambda x: x)
        items.append(('c', w(c_msg(name, CALL, seq, c_struct(req_fields)))))
        items.append(('s', w(c_msg(name, rmtype, seq, c_struct(rep_fields)))))
    cpair('everything', A, [(0, 'struct', A)])
    cpair('ping', [], [])
    cpair('add', [(1, 'i32', 3), (2, 'i32', 4)], [(0, 'i32', 7)])
    cpair('fail', [(1, 'bin', 'x')], [(1, 'struct', [(1, 'bin', 'user exception')])])
    cpair('wide', [(1, 'i32', 1), (40, 'i32', 2), (-5, 'i8', 3), (20000, 'i16', 4)], [(0, 'bool', True)])
    cpair('big', big_lists(), [(0, 'bool', False)])
    cpair('missing', [], EXC_FIELDS, EXC)
    items.append(('c', c_msg('notify', ONEWAY, 90, c_struct([(1, 'bin', 'fire and forget')]))))
    items.append(('c', c_msg('order', CALL, 91, c_struct([(5, 'i32', 1), (3, 'i32', 2), (3, 'i32', 3)]))))
    items.append(('c', c_msg('neg', CALL, 92, c_struct([(-3, 'i32', 1), (2, 'i32', 2)]))))
    items.append(('c', c_msg('deep', CALL, 93, c_struct([(1, 'list', nested_list(20)), (2, 'struct', nested_struct(20))]))))
    items.append(('c', c_msg('x' * 100, CALL, 94, c_struct([(1, 'i8', 1)]))))        # long method name (heuristic limit 127)
    items.append(('c', c_msg('seq', CALL, 1 << 30, c_struct([(1, 'i8', 1)]))))        # large sequence id
    items.append(('c', c_msg('one', CALL, 96, c_struct([(1, 'i8', 1)])) + c_msg('two', CALL, 97, c_struct([(1, 'i8', 2)]))))
    items.append(('c', c_msg('split', CALL, 98, c_struct(A[:12])), 40))
    tcp_flow(o, 40002, 19092, items)

    # ===== D: TCP 19093, compact, framed =====
    items = []
    items.append(('c', framed(c_msg('everything', CALL, 1, c_struct(A)))))
    items.append(('s', framed(c_msg('everything', REPLY, 1, c_struct([(0, 'struct', A)])))))
    items.append(('s', framed(c_msg('ping', EXC, 2, c_struct(EXC_FIELDS)))))
    items.append(('c', framed(c_msg('a', CALL, 3, c_struct([(1, 'i32', 1)]))) + framed(c_msg('b', CALL, 4, c_struct([(1, 'i32', 2)])))))
    items.append(('c', framed(c_msg('big', CALL, 5, c_struct(big_lists()))), 200))
    tcp_flow(o, 40003, 19093, items)

    # ===== E: UDP =====
    def udp(sp, dp, data):
        o.append(u.udp(sp, dp, data))
    udp(40100, 19190, b_msg('everything', CALL, 1, b_struct(A)))
    udp(19190, 40100, b_msg('everything', REPLY, 1, b_struct([(0, 'struct', A)])))
    udp(40100, 19190, c_msg('everything', CALL, 2, c_struct(A)))
    udp(19190, 40100, c_msg('ping', EXC, 2, c_struct(EXC_FIELDS)))
    udp(40100, 19190, framed(b_msg('framed', CALL, 3, b_struct([(1, 'i32', 1)]))))

    # ===== F: HTTP (media types application/x-thrift and application/vnd.apache.thrift.binary) =====
    items = [('c', http_post('application/x-thrift', b_msg('everything', CALL, 1, b_struct(A)))),
             ('s', http_reply('application/x-thrift', b_msg('everything', REPLY, 1, b_struct([(0, 'struct', A)])))),
             ('c', http_post('application/vnd.apache.thrift.binary', b_msg('add', CALL, 2, b_struct([(1, 'i32', 1), (2, 'i32', 2)])))),
             ('s', http_reply('application/vnd.apache.thrift.binary', b_msg('add', REPLY, 2, b_struct([(0, 'i32', 3)])))),
             ('c', http_post('application/x-thrift', c_msg('compact', CALL, 3, c_struct([(1, 'i32', 5)]))))]
    tcp_flow(o, 40004, 80, items)

    # ===== G: old (non-strict) TBinaryProtocol and framed old binary: reached with Decode As (tcp.port/udp.port 19290) =====
    items = []
    items.append(('c', b_msg('everything', CALL, 1, b_struct(A), strict=False)))
    items.append(('s', b_msg('everything', REPLY, 1, b_struct([(0, 'struct', A)]), strict=False)))
    items.append(('c', b_msg('add', CALL, 2, b_struct([(1, 'i32', 3), (2, 'i32', 4)]), strict=False)))
    items.append(('s', b_msg('add', EXC, 2, b_struct(EXC_FIELDS), strict=False)))
    items.append(('c', b_msg('notify', ONEWAY, 3, b_struct([(1, 'bin', 'x')]), strict=False)))
    items.append(('c', b_msg('one', CALL, 4, b_struct([(1, 'i8', 1)]), strict=False) +
                  b_msg('two', CALL, 5, b_struct([(1, 'i8', 2)]), strict=False)))
    items.append(('c', b_msg('split', CALL, 6, b_struct(A[:12]), strict=False), 50))
    # strict messages on the same connection (the dissector switches per message)
    items.append(('c', b_msg('strict', CALL, 7, b_struct([(1, 'i8', 1)]))))
    tcp_flow(o, 40005, 19290, items)
    items = []
    items.append(('c', framed(b_msg('everything', CALL, 1, b_struct(A), strict=False))))
    items.append(('s', framed(b_msg('everything', REPLY, 1, b_struct([(0, 'struct', A)]), strict=False))))
    items.append(('c', framed(b_msg('first_call', CALL, 2, b_struct([(1, 'i32', 1)]), strict=False)) +
                  framed(b_msg('second_call', CALL, 3, b_struct([(1, 'i32', 2)]), strict=False))))
    items.append(('c', framed(b_msg('strict', CALL, 4, b_struct([(1, 'i32', 1)])))))
    items.append(('c', framed(b_msg('big_message', CALL, 5, b_struct(big_lists()), strict=False)), 250))
    tcp_flow(o, 40006, 19291, items)
    udp(40200, 19290, b_msg('udp', CALL, 1, b_struct([(1, 'i32', 3)]), strict=False))
    udp(19290, 40200, b_msg('udp', REPLY, 1, b_struct([(0, 'i32', 3)]), strict=False))
    # the reproducer of "Thrift: Fix the message type of old binary headers": the byte
    # after the name is the message type CALL (1); the field data 4 + 3 bytes later is 3
    udp(40201, 19290, struct.pack('>I', 3) + b'add' + b'\x01' + struct.pack('>i', 7) +
        struct.pack('>BHi', 8, 3, 3) + struct.pack('>BHi', 8, 4, 4) + b'\x00')

    # ===== H: the end: reproducer of "Thrift: Stop at the nesting limit in the binary
    # protocol" (UDP, thrift_udp heuristic; the "too many subtypes" error is expected),
    # and the same with 28 levels (a few past the default limit of 25)
    udp(40300, 19390, depth_loop(25))
    udp(40300, 19390, depth_loop(28, 3))
    return o


def malformed_frames():
    o = []
    def udp(sp, dp, data): o.append(u.udp(sp, dp, data))
    def pk(name, fields, **kw): return b_msg(name, CALL, 1, b_struct(fields), **kw)
    # Decode As (udp.port 19400) takes anything that looks like Thrift, so errors are reachable
    P = 19400
    # strict binary: wrong versions, negative lengths, truncated
    udp(40400, P, struct.pack('>II', 0x80020000 | CALL, 1) + b'a' + b'\0\0\0\1\x00')       # unsupported version
    udp(40400, P, struct.pack('>II', 0x80010000 | CALL, 0xffffffff) + b'\0' * 8)           # negative name length
    udp(40400, P, struct.pack('>II', 0x80010000 | CALL, 100) + b'short')                   # name longer than data
    udp(40400, P, struct.pack('>II', 0x80010000 | CALL, 1) + b'a')                         # no sequence id
    udp(40400, P, struct.pack('>I', 0x80010000 | CALL))                                    # nothing else
    udp(40400, P, b'\x80\x01')                                                             # two bytes
    udp(40400, P, b'\x00')                                                                 # one byte, not 0x82
    udp(40400, P, b'\x82')                                                                 # one byte, compact id
    udp(40400, P, b'\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c')                         # old header, name too long
    udp(40400, P, b'\xff\xff\xff\xff' + b'\0' * 10)                                        # framed? negative frame length
    udp(40400, P, struct.pack('>I', 3) + b'ab')                                            # old header short
    # binary body errors
    udp(40401, P, pk('wrongtype', [(1, 'i32', 1)])[:-1] + b'\x0a\x00\x02\x00')             # unknown type 0x0a at a bad position
    udp(40401, P, b_msg('badtype', CALL, 1, b'\x09\x00\x01' + b'\0' * 8))                  # type 9 does not exist
    udp(40401, P, b_msg('badtype2', CALL, 1, b'\x01\x00\x01\x00'))                         # type 1 (void) does not exist in binary
    udp(40401, P, b_msg('neglen', CALL, 1, b'\x0b\x00\x01\xff\xff\xff\xff\x00'))           # negative string length
    udp(40401, P, b_msg('neglist', CALL, 1, b'\x0f\x00\x01\x08\xff\xff\xff\xff\x00'))      # negative list length
    udp(40401, P, b_msg('negmap', CALL, 1, b'\x0d\x00\x01\x08\x08\xff\xff\xff\xff\x00'))   # negative map length
    udp(40401, P, b_msg('trunc', CALL, 1, b'\x08\x00\x01\x00\x00'))                        # i32 cut
    udp(40401, P, b_msg('trunc2', CALL, 1, b'\x0b\x00\x01\x00\x00\x01\x00ab'))              # string cut
    udp(40401, P, b_msg('trunc3', CALL, 1, b'\x0f\x00\x01\x08\x00\x00\x00\x05\x00\x00\x00\x01'))  # list cut
    udp(40401, P, b_msg('trunc4', CALL, 1, b'\x0d\x00\x01\x08\x08\x00\x00\x00\x02\x00\x00\x00\x01'))  # map cut
    udp(40401, P, b_msg('trunc5', CALL, 1, b'\x0c\x00\x01\x08\x00\x01'))                   # struct cut
    udp(40401, P, b_msg('trunc6', CALL, 1, b'\x08'))                                       # field header cut
    for t, n in ((2, 1), (3, 1), (4, 8), (6, 2), (8, 4), (10, 8), (16, 16)):
        udp(40402, P, b_msg('cut%d' % t, CALL, 1, bytes([t]) + b'\x00\x01' + b'\0' * (n - 1)))
    # a set and a list nested in a list inside a struct (deeper than a lowered depth limit in runcov.sh)
    udp(40403, P, pk('deep', [(1, 'list', nested_list(6)), (2, 'struct', nested_struct(6)),
                              (3, 'map', ('i32', 'list', [(1, nested_list(5))])),
                              (4, 'set', nested_list(3))]))
    # nesting beyond the default limit of 25: lists, sets, maps, structs
    udp(40403, P, pk('deep26', [(1, 'list', nested_list(27))]))
    udp(40403, P, pk('deep26s', [(1, 'struct', nested_struct(27))]))
    mp = ('i32', 'i32', [(1, 1)])
    v = ('map', [mp])
    for _ in range(26):
        v = ('list', [v])
    udp(40403, P, pk('deep26m', [(1, 'list', v)]))
    for kind in ('list', 'set', 'map', 'struct'):
        udp(40403, P, pk('limit_' + kind, at_limit(kind)))
        udp(40411, P, c_msg('limit_' + kind, CALL, 1, c_struct(at_limit(kind))))
    # the depth reproducer with a set, a map and a struct as the innermost element type
    for et in (14, 13, 12):
        body = struct.pack('>BH', 15, 1)
        for _ in range(24):
            body += struct.pack('>BI', 15, 1)
        if et == 13:
            body += struct.pack('>BBI', et, 8, 0x7fffffff)
            body += struct.pack('>BBI', 8, 8, 0)
        else:
            body += struct.pack('>BI', et, 3) + (b'\x0f\x00\x00\x00\x00' if et == 14 else b'\x00')
        udp(40404, P, b_msg('limit', CALL, 1, body))
    # framed errors
    udp(40405, P, struct.pack('>I', 0) + b'\x80\x01\x00\x01\0\0\0\0\0\0\0\0\x00')          # frame length 0
    udp(40405, P, struct.pack('>I', 0x7fffffff) + b'\x80\x01\x00\x01')                      # frame longer than the data
    udp(40405, P, framed(b'\x80\x01\x00\x01\0\0\0\1a\0\0\0\1'))                             # frame ends in the header (no T_STOP)
    udp(40405, P, framed(b_msg('short', CALL, 1, b'\x08\x00\x01\x00\x00')))                 # frame ends in the data
    udp(40405, P, framed(b'\xff' * 20))                                                      # framed, neither old nor strict
    udp(40405, P, framed(b'\x82\x21\x01\x01a\x00'))                                         # framed compact through Decode As

    # compact
    def cm(name, body, seq=1, mtype=CALL):
        return c_msg(name, mtype, seq, body)
    udp(40410, P, cm('c', b'\x00')[:3])                                                      # header cut
    udp(40410, P, bytes([0x82, 0x21]) + b'\xff' * 6 + b'\x00')                               # sequence id varint too long
    udp(40410, P, bytes([0x82, 0x21, 1]) + b'\xff' * 5 + b'\x0f' + b'\x00')                  # name length varint too large
    udp(40410, P, bytes([0x82, 0x21, 1]) + b'\xff\xff\xff\xff\x07' + b'\x00')                # name length 2^31-1 (cannot be read)
    udp(40410, P, bytes([0x82, 0x21, 1, 100]) + b'ab')                                       # name longer than the data
    udp(40410, P, bytes([0x82, 0x21, 1, 1]) + b'a')                                          # no body
    udp(40410, P, cm('c', b'\x0d\x01'))                                                      # compact type 13? (uuid) cut
    udp(40410, P, cm('c', b'\x1f\x01'))                                                      # unknown compact type 15
    udp(40410, P, cm('c', b'\x1e\x00'))                                                      # unknown compact type 14
    udp(40410, P, cm('c', b'\x05\xff\xff\xff\xff\xff\x7f'))                                  # field id varint ok, i32 varint too long
    udp(40410, P, cm('c', b'\x05' + b'\xff' * 5 + b'\x01'))                                  # i32 varint 6 bytes
    udp(40410, P, cm('c', b'\x06' + b'\xff' * 10 + b'\x01'))                                 # i64 varint 11 bytes
    udp(40410, P, cm('c', b'\x04' + b'\xff' * 3 + b'\x01'))                                  # i16 varint 4 bytes
    udp(40410, P, cm('c', b'\x00\xff\xff\xff\x0f\x00'))                                      # field id varint too long (long form, type 0 is stop...)
    udp(40410, P, cm('c', b'\x03\xff\xff\xff\xff\x7f\x03\x00'))                              # long form field id too large
    udp(40410, P, cm('c', b'\x08\x7f' + b'x' * 5))                                           # binary cut
    udp(40410, P, cm('c', b'\x08\xff\xff\xff\xff\x0f'))                                      # binary length too large
    udp(40410, P, cm('c', b'\x08' + b'\xff\xff\xff\xff\x07'))                                # binary length 2^31-1
    udp(40410, P, cm('c', b'\x09\xf5' + b'\xff\xff\xff\xff\x0f'))                            # list length too large
    udp(40410, P, cm('c', b'\x19\x01\x00'))                                                  # list ok? (i32 list, 1 element cut)
    udp(40410, P, cm('c', b'\x0b\xff\xff\xff\xff\x0f'))                                      # map length too large
    udp(40410, P, cm('c', b'\x0b\x05\x55\x02'))                                              # map cut
    udp(40410, P, cm('c', b'\x0a\x23\x01'))                                                  # set cut
    udp(40410, P, cm('c', b'\x0c\x15'))                                                      # struct cut
    udp(40410, P, cm('c', b'\x03'))                                                          # i8 cut
    udp(40410, P, cm('c', b'\x07\x00\x00'))                                                  # double cut
    udp(40410, P, cm('c', b'\x0d' + b'\0' * 4))                                              # uuid cut
    udp(40410, P, cm('c', b'\x19\x7f'))                                                      # list of unknown elements
    # varints that are cut, too long or too large, in every place they are read
    for first in (b'\x18', b'\x19\xf5', b'\x1b'):          # binary length, list length, map length
        for tail in (b'', b'\x80', b'\xff' * 5, b'\xff\xff\xff\xff\x0f'):
            udp(40413, P, cm('c', first + tail))
    for ft in (b'\x14', b'\x15', b'\x16'):                      # i16, i32, i64 cut
        udp(40413, P, cm('c', ft + b'\x80'))
        udp(40413, P, cm('c', ft))
    udp(40413, P, cm('c', b'\x19'))                              # list header missing
    udp(40413, P, cm('c', b'\x1b'))
    # compact message headers with a sequence id or name length that is too long or too large
    for hdr in (bytes([0x82, 0x21]) + b'\xff' * 5 + b'\0' * 6,              # sequence id: varint too long
                bytes([0x82, 0x21]) + b'\xff\xff\xff\xff\x7f' + b'\x01a' + b'\0' * 4,   # out of the int32 range
                bytes([0x82, 0x21, 1]) + b'\xff' * 5 + b'\0' * 6,             # name length: varint too long
                bytes([0x82, 0x21, 1]) + b'\xff\xff\xff\xff\x0f' + b'\0' * 6,   # name length > 2^31
                bytes([0x82, 0x21, 1, 100]) + b'ab' + b'\0' * 6):              # name longer than the data
        udp(40414, P, hdr)
    # compact nesting beyond the default limit
    udp(40411, P, cm('deep', c_struct([(1, 'list', nested_list(27))])))
    udp(40411, P, cm('deep', c_struct([(1, 'struct', nested_struct(27))])))
    udp(40411, P, cm('deep', c_struct([(1, 'map', ('i32', 'list', [(1, nested_list(26))]))])))
    udp(40411, P, cm('deep', c_struct([(1, 'set', nested_list(27))])))
    # an HTTP body that is not Thrift (the HTTP dissector notes the failure of the sub-dissector)
    tcp_flow(o, 40450, 80, [('c', http_post('application/x-thrift', b'not thrift at all')),
                            ('c', http_post('application/vnd.apache.thrift.binary', b'\x80\x01\x00\x01'))])
    # a protocol exception with problems in its own struct (message missing, wrong order, too deep)
    for fields in ([(2, 'i32', 1)], [], [(1, 'i32', 5)], [(1, 'bin', 'm'), (2, 'bin', 'x')],
                   [(1, 'bin', 'only a message')], EXC_FIELDS + [(3, 'bin', 'extra')],
                   [(1, 'bin', 'order'), (3, 'i32', 3), (2, 'i32', 3)], [(1, 'bin', 'type is i64'), (2, 'i64', 3)]):
        udp(40412, P, b_msg('e', EXC, 1, b_struct(fields)))
        udp(40412, P, c_msg('e', EXC, 1, c_struct(fields)))
    udp(40412, P, b_msg('e', EXC, 1, b'\x0b\x00\x01\x00\x00\x00\x09ab'))                    # message cut
    udp(40412, P, b_msg('e', EXC, 1, b''))                                                    # nothing after the header
    udp(40412, P, c_msg('e', EXC, 1, b''))
    udp(40412, P, b_msg('e', REPLY, 1, b''))                                                  # reply without a body
    udp(40412, P, b_msg('e', REPLY, 1, b'\x0f\x00'))                                          # reply with a cut field header
    udp(40412, P, b_msg('e', REPLY, 1, b'\x0b\x7f\xff\x00'))                                  # reply, field id 32767
    udp(40412, P, c_msg('e', REPLY, 1, b'\x0f\x00'))                                          # compact reply, odd header
    udp(40412, P, c_msg('e', REPLY, 1, b'\x03' + b'\xff' * 3))                                # compact reply, field id varint too long
    udp(40412, P, c_msg('e', REPLY, 1, b'\x03\xfe\xff\x03\x05'))                              # compact reply, field id out of the i16 range
    udp(40412, P, c_msg('e', REPLY, 1, b'\x15\x02\x00'))                                      # compact reply, delta field id
    # strict messages followed by something else in the same segment (a TCP stream
    # in which the next header is not valid, or too short to be one)
    tcp_flow(o, 40460, 19094, [('c', b_msg('tail', CALL, 1, b_struct([(1, 'i8', 1)])) + b'\x80\x02\x00\x01\0\0\0\0\0\0\0\0\0\0'),
                               ('c', b_msg('tail', CALL, 2, b_struct([(1, 'i8', 1)])) + b'\x80\x01')])
    # old binary header with the name cut in the middle (Decode As), packets the heuristics reject
    udp(40461, P, struct.pack('>I', 5) + b'abcde' + b'\x01\x00\x00')
    for n in (1, 3, 4, 7):
        udp(40462, 19500, b'\x80\x01\x00\x01\x00\x00\x00\x01a\x00\x00\x00\x01'[:n])
    udp(40462, 19500, framed(b'\x80\x01\x00\x01\x00\x00\x00\x01a\x00\x00\x00\x01\x00')[:9])
    udp(40462, 19500, struct.pack('>I', 3) + b'\x80\x01\x00')                # framed, frame too short
    udp(40462, 19500, struct.pack('>I', 20) + b'\x80\x01\x00\x01\x00\x00\x00\x40' + b'a' * 4)   # name longer than the frame
    udp(40462, 19500, struct.pack('>II', 0x80010001, 3) + b'a\x01\x02' + b'\x00' * 6)    # name not UTF-8
    udp(40462, 19500, bytes([0x82, 0x21, 1, 3]) + b'a\x01\x02' + b'\x00' * 6)         # compact, name not UTF-8
    udp(40462, 19500, bytes([0x82, 0x21, 1, 0x90]) + b'a' * 20)                         # compact, name length > 127
    udp(40462, 19500, framed(bytes([0x82, 0x21, 1, 100]) + b'a' * 5))                  # compact, name longer than the frame
    udp(40462, 19500, bytes([0x82, 0x21]))
    udp(40462, 19500, bytes([0x82, 0x21, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]))   # compact, sequence id varint
    udp(40462, 19500, bytes([0x82, 0x21, 1, 2]) + b'a')                                  # compact, name not entirely captured
    return o


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    os.makedirs(out, exist_ok=True)
    f = main_frames()
    base = os.path.join(out, 'thrift-coverage.pcap')
    u.write_pcap(base, f)
    u.gz(base)
    shutil.copy(base + '.gz', os.path.join(out, 'thrift_coverage.pcap.gz'))
    m = malformed_frames()
    u.write_pcap(os.path.join(out, 'thrift-coverage-malformed.pcap'), m)
    print('%d frames, %d malformed-capture frames' % (len(f), len(m)))


if __name__ == '__main__':
    main()
