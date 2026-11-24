#!/usr/bin/env python3
# Generates test/captures/mongo_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the MongoDB wire protocol coverage captures: mkmongo.py <outdir> [-v]

Messages of every opcode (including OP_COMPRESSED with the noop, zlib and
zstd compressors, the latter as a stored block written by hand) and
BSON documents with every element type, on TCP port 27017 (the registered
port; the heuristic handle sets the conversation). Synthetic: addresses
192.0.2.0/24. No authentication is used or generated.
"""
import os
import struct
import sys
import zlib

# ---------------------------------------------------------------- BSON
def cstr(s): return s.encode() + b'\0'
def el(t, name, payload): return bytes([t]) + cstr(name) + payload
def doc(*els, length=None):
    body = b''.join(els) + b'\0'
    return struct.pack('<i', len(body) + 4 if length is None else length) + body
def bstr(s): return struct.pack('<i', len(s) + 1) + s.encode() + b'\0'
OID = bytes.fromhex('65a1b2c3d4e5f60718293a4b')
def all_types(skip_dbptr=True):
    return doc(
        el(1, 'double', struct.pack('<d', 2.5)), el(2, 'string', bstr('hello')),
        el(3, 'doc', doc(el(16, 'a', struct.pack('<i', 1)))),
        el(4, 'array', doc(el(16, '0', struct.pack('<i', 7)), el(2, '1', bstr('x')))),
        el(5, 'binary', struct.pack('<i', 4) + b'\x00' + b'\xde\xad\xbe\xef'),
        el(6, 'undef', b''), el(7, 'oid', OID), el(8, 'bool', b'\x01'), el(8, 'bool2', b'\x00'),
        el(9, 'datetime', struct.pack('<q', 1700000000000)), el(10, 'null', b''),
        el(11, 'regex', cstr('^a.*b$') + cstr('i')),
        el(13, 'jscode', bstr('function(){}')), el(14, 'symbol', bstr('sym')),
        el(15, 'jscope', jscope('return x;', doc(el(16, 'x', struct.pack('<i', 3))))),
        el(16, 'int32', struct.pack('<i', -5)), el(17, 'timestamp', struct.pack('<Q', (1700000000 << 32) | 1)),
        el(18, 'int64', struct.pack('<q', -1 << 40)), el(19, 'dec128', bytes(range(16))),
        el(0xff, 'minkey', b''), el(0x7f, 'maxkey', b''), el(16, 'last', struct.pack('<i', 0)))
def jscope(code, d):
    body = bstr(code) + d
    return struct.pack('<i', len(body) + 4) + body
def nested(n):
    d = doc(el(16, 'leaf', struct.pack('<i', 1)))
    for _ in range(n): d = doc(el(3, 'n', d))
    return d

# ---------------------------------------------------------------- wire
def msg(opcode, body, req=1, resp=0, length=None):
    return struct.pack('<iiiI', 16 + len(body) if length is None else length, req, resp, opcode) + body
def fcn(s): return cstr(s)
def snappy_literal(data):
    n = len(data); pre = b''; v = n
    while True:
        b = v & 0x7f; v >>= 7
        if v: pre += bytes([b | 0x80])
        else: pre += bytes([b]); break
    if n <= 60: tag = bytes([(n - 1) << 2])
    elif n <= 256: tag = bytes([60 << 2, n - 1])
    else: tag = bytes([61 << 2]) + struct.pack('<H', n - 1)
    return pre + tag + data
def crc32c(data):
    crc = 0xffffffff
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
    return crc ^ 0xffffffff
def op_reply(docs, flags=0, cursor=0, start=0, resp=1, req=100):
    return msg(1, struct.pack('<iqii', flags, cursor, start, len(docs)) + b''.join(docs), req, resp)
def op_query(coll, q, flags=0, skip=0, ret=1, sel=None, req=1):
    return msg(2004, struct.pack('<i', flags) + fcn(coll) + struct.pack('<ii', skip, ret) + q + (sel or b''), req)
def op_msg(sections, flags=0, checksum=None, req=1, resp=0, bad=False):
    body = struct.pack('<I', flags) + b''.join(sections)
    m = msg(2013, body + (b'\0\0\0\0' if checksum else b''), req, resp)
    if checksum:
        m = m[:-4] + struct.pack('>I' if checksum == 'be' else '<I', crc32c(m[:-4]) ^ (1 if bad else 0))
    return m
def sec0(d): return b'\x00' + d
def sec1(ident, docs):
    body = cstr(ident) + b''.join(docs)
    return b'\x01' + struct.pack('<i', len(body) + 4) + body
def compressed(orig_op, compressor, data, usize=None, req=1):
    return msg(2012, struct.pack('<IIB', orig_op, len(data) if usize is None else usize, compressor) + data, req)
def zstd_stored(data):
    assert len(data) < 256
    # frame: magic, descriptor (single segment, 1 octet content size), size, one last raw block
    return bytes.fromhex('28b52ffd') + b'\x20' + bytes([len(data)]) + (((len(data) << 3) | 1)).to_bytes(3, 'little') + data

def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff
class Net:
    def __init__(self): self.frames = []; self.seq = {}
    def raw(self, payload, sport, dport, seq, ack, flags, src, dst):
        s = bytes(map(int, src.split('.'))); d = bytes(map(int, dst.split('.')))
        opt = b'\x02\x04\x05\xb4' if flags & 2 else b''
        tcp = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, (5 + len(opt) // 4) << 4, flags, 65535, 0, 0) + opt
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp) + len(payload), len(self.frames) + 1, 0, 64, 6, 0, s, d)
        ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
        ph = s + d + struct.pack('!BBH', 0, 6, len(tcp) + len(payload))
        tcp = tcp[:16] + struct.pack('!H', csum(ph + tcp + payload)) + tcp[18:]
        eth = b'\x02\0\0\0\0\x02' + b'\x02\0\0\0\0\x01' + b'\x08\x00'
        if src == '192.0.2.2': eth = eth[6:12] + eth[0:6] + eth[12:]
        self.frames.append(eth + ip + tcp + payload)
    def handshake(self, c, s):
        self.seq[c] = 1000; self.seq[s] = 5000
        self.raw(b'', c, s, 1000, 0, 0x02, '192.0.2.1', '192.0.2.2')
        self.raw(b'', s, c, 5000, 1001, 0x12, '192.0.2.2', '192.0.2.1')
        self.raw(b'', c, s, 1001, 5001, 0x10, '192.0.2.1', '192.0.2.2')
        self.seq[c] = 1001; self.seq[s] = 5001
    def send(self, payload, client, c, s, retrans=False):
        sport, dport = (c, s) if client else (s, c)
        src, dst = ('192.0.2.1', '192.0.2.2') if client else ('192.0.2.2', '192.0.2.1')
        seq = self.seq[sport]
        if not retrans: self.seq[sport] = seq + len(payload)
        self.raw(payload, sport, dport, seq, self.seq[dport], 0x18, src, dst)
    def write(self, fn):
        with open(fn, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
            for i, fr in enumerate(self.frames):
                f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr))); f.write(fr)

def main(outdir, verbose=False):
    os.makedirs(outdir, exist_ok=True)
    net = Net(); ranges = []; C, S = 49400, 27017
    net.handshake(C, S)
    def snd(data, client=True): net.send(data, client, C, S)
    def mark(n, st): ranges.append((n, st, len(net.frames)))
    ping = doc(el(16, 'ping', struct.pack('<i', 1)))
    st = len(net.frames) + 1
    snd(op_query('admin.$cmd', doc(el(16, 'isMaster', struct.pack('<i', 1)))))
    snd(op_reply([doc(el(8, 'ismaster', b'\x01'), el(16, 'maxWireVersion', struct.pack('<i', 17)), el(1, 'ok', struct.pack('<d', 1.0)))]), False)
    snd(op_query('test.people', doc(el(2, 'name', bstr('Ann'))), flags=0x7e, skip=3, ret=20,
                 sel=doc(el(16, 'name', struct.pack('<i', 1)))))
    snd(op_query('test.people', doc(el(2, 'name', bstr('Ann'))), flags=0x1))
    snd(op_reply([all_types(), doc(), ping], flags=0xf, cursor=0x1234567890, start=5, resp=3), False)
    snd(op_reply([], flags=0), False)
    snd(msg(1000, cstr('a plain message')))
    snd(msg(2001, struct.pack('<i', 0) + fcn('test.people') + struct.pack('<i', 3) + doc(el(2, 'name', bstr('Ann'))) +
            doc(el(3, '$set', doc(el(16, 'age', struct.pack('<i', 31)))))))
    snd(msg(2001, struct.pack('<i', 0) + fcn('test.people') + struct.pack('<i', 0) + doc() + doc()))
    snd(msg(2002, struct.pack('<i', 1) + fcn('test.people') + doc(el(16, 'a', struct.pack('<i', 1))) + all_types()))
    snd(msg(2003, b'reserved opcode data'))
    snd(msg(2005, struct.pack('<i', 0) + fcn('test.people') + struct.pack('<i', 10) + struct.pack('<q', 0x1234567890)))
    snd(msg(2006, struct.pack('<i', 0) + fcn('test.people') + struct.pack('<i', 1) + doc(el(2, 'name', bstr('Ann')))))
    snd(msg(2006, struct.pack('<i', 0) + fcn('test.people') + struct.pack('<i', 0) + doc()))
    snd(msg(2007, struct.pack('<ii', 0, 3) + struct.pack('<qqq', 11, 22, 33)))
    snd(msg(2010, cstr('test') + cstr('find') + doc(el(2, 'k', bstr('v'))) + doc(el(2, 'find', bstr('people')))))
    snd(msg(2011, doc(el(16, 'm', struct.pack('<i', 1))) + doc(el(1, 'ok', struct.pack('<d', 1.0))), 7, 1), False)
    snd(msg(2011, doc(el(16, 'm', struct.pack('<i', 1))) + doc(el(1, 'ok', struct.pack('<d', 1.0))) + doc(el(16, 'out', struct.pack('<i', 1))), 8, 1), False)
    snd(msg(9999, b'xx'))                                                # unknown opcode
    mark('legacy opcodes: reply, query (command and normal), message, update, insert, reserved, get more, delete, kill cursors, command, command reply, unknown opcode; all BSON element types', st)

    st = len(net.frames) + 1
    snd(op_msg([sec0(doc(el(16, 'hello', struct.pack('<i', 1)), el(2, '$db', bstr('admin'))))]))
    snd(op_msg([sec0(doc(el(1, 'ok', struct.pack('<d', 1.0))))], resp=1, req=2), False)
    snd(op_msg([sec0(doc(el(2, 'insert', bstr('c')), el(2, '$db', bstr('test')))),
                sec1('documents', [doc(el(16, 'x', struct.pack('<i', 1))), doc(el(16, 'x', struct.pack('<i', 2)))])], flags=2, req=3))
    snd(op_msg([sec0(doc(el(2, 'find', bstr('c')))), sec1('empty', [])], flags=0x10000, req=4))
    snd(op_msg([sec0(ping)], flags=1, checksum='le', req=5))       # CRC-32C present
    snd(op_msg([sec0(all_types())], req=7))
    snd(op_msg([sec0(doc())], req=8))                                # empty body document
    snd(op_msg([sec0(nested(60))], req=9))                           # nested documents within the limit
    mark('OP_MSG: body, document sequence, flags, checksum, empty documents, nested documents', st)

    st = len(net.frames) + 1
    inner_q = op_query('admin.$cmd', doc(el(16, 'isMaster', struct.pack('<i', 1))))[16:]
    inner_r = op_reply([doc(el(1, 'ok', struct.pack('<d', 1.0)))])[16:]
    inner_m = op_msg([sec0(doc(el(2, 'find', bstr('c')), el(2, '$db', bstr('test'))))])[16:]
    snd(compressed(2004, 0, inner_q))                                  # noop
    snd(compressed(1, 0, inner_r, ), False)
    snd(compressed(2013, 2, zlib.compress(inner_m)))                   # zlib
    snd(compressed(2013, 3, zstd_stored(inner_m)))                     # zstd (stored block)
    snd(compressed(2013, 1, snappy_literal(inner_m), usize=len(inner_m)))   # snappy (a literal block; unsupported if Snappy is not built in)
    snd(compressed(2013, 2, b'not a zlib stream'))                     # zlib error
    snd(compressed(2013, 3, b'not a zstd frame'))                      # zstd error
    snd(compressed(2013, 9, b'xxxx'))                                  # unknown compressor
    snd(compressed(2013, 0, b'\x00\x01'[:0] + inner_m[:4]))            # noop whose payload is cut short
    # reproducers of "MongoDB: Reject a nested OP_COMPRESSED message"
    body = struct.pack('<IIB', 2012, 0, 0) * 105
    snd(msg(2012, body, 11))                                          # 105 nested noop headers
    inner = struct.pack('<IIB', 0, 1 << 20, 2) + zlib.compress(b'\0' * (1 << 20), 9)
    snd(compressed(2012, 2, zlib.compress(inner, 9), usize=len(inner), req=12))   # zlib inside zlib
    mark('OP_COMPRESSED: noop, zlib, zstd, snappy (unsupported when Snappy is not built in), errors, unknown compressor, nested reproducers', st)

    st = len(net.frames) + 1
    a = op_msg([sec0(ping)], req=20); b = op_msg([sec0(ping)], req=21)
    snd(a + b)                                                         # two messages in a segment
    big = op_reply([doc(el(2, 'blob', bstr('x' * 3000)))], req=22)
    snd(big[:1000], False); snd(big[1000:2500], False); snd(big[2500:], False)
    snd(a[:3]); snd(a[3:] + b[:10]); snd(b[10:])
    net.send(a, True, C, S, retrans=True)
    mark('TCP framing: two messages per segment, reassembly over three segments, header split, retransmission', st)
    net.write(os.path.join(outdir, 'mongo-coverage.pcap'))
    if verbose:
        for r in ranges: print('%d-%d %s' % (r[1], r[2], r[0]))
        print(len(net.frames), 'frames')

    # ------------------------------------------------ malformed capture
    net = Net(); n = [0]
    def one(data, port=27017):
        c = 49500 + n[0]; n[0] += 1
        net.handshake(c, port)
        # a valid first message so that the heuristic claims the conversation, then the bad data
        net.send(op_msg([sec0(ping)]), True, c, port)
        for d in data if isinstance(data, list) else [data]:
            net.send(d, True, c, port)
    one(op_reply([struct.pack('<i', 3) + b'\0\0\0']))                    # document length < 5
    one(op_reply([struct.pack('<i', 20000000) + b'\0' * 8]))             # document longer than the limit
    one(op_reply([nested(105)]))                                        # nesting beyond 100
    one(op_msg([b'\x00' + struct.pack('<i', -5) + b'\0' * 8]))           # negative section size
    one(op_msg([b'\x00' + struct.pack('<i', 0x7ffffffe) + b'\0' * 8]))
    one(op_msg([sec0(doc(el(2, 's', struct.pack('<i', 500) + b'abc')))]))       # string beyond the data
    one(op_msg([sec0(doc(el(5, 'b', struct.pack('<i', 500) + b'\0abc')))]))     # binary beyond the data
    one(op_msg([sec0(doc(el(12, 'dbptr', bstr('db.coll') + OID), el(16, 'after', struct.pack('<i', 4))))]))  # deprecated DBPointer: offset advances short of the pointer
    one(op_msg([sec0(doc(el(15, 'scope', struct.pack('<i', 4) + bstr('x'))))]))  # code with scope with bad length
    one(op_msg([sec0(doc(el(11, 'regex', b'abc')))]))                      # regex without terminator
    one(op_msg([sec1('seq', [struct.pack('<i', 3)])]))
    one(op_msg([b'\x01' + struct.pack('<i', 2) + b'x']))                  # document sequence shorter than its header
    one(msg(2004, b'\0\0\0\0test\0\0\0\0\0\0\0\0\0'))                    # collection name without a dot
    one(msg(2004, b'\0\0\0\0'))                                        # query cut short
    one(msg(2001, b'\0\0\0\0'))
    one(msg(2007, struct.pack('<ii', 0, 3) + b'\1\2\3'))               # cursor id cut short
    one(msg(2011, b'\x01\x00'))
    one(msg(2010, b'db\0'))
    one(msg(2004, struct.pack('<i', 0) + fcn('admin.$cmd') + struct.pack('<ii', 0, 1) + struct.pack('<i', 3) + b'\0\0\0'))        # command with a document of length 3
    one(msg(2004, struct.pack('<i', 0) + fcn('admin.$cmd') + struct.pack('<ii', 0, 1) + struct.pack('<i', 20000000) + b'\0' * 8))  # and one that is too long
    one(op_msg([sec0(ping)], flags=1, checksum='le', bad=True))                # wrong CRC-32C
    one(op_msg([b'\x02' + struct.pack('<i', 5) + b'abcde']))                    # unknown section kind
    one(op_msg([sec0(ping)], flags=1))                                  # checksum flag but no checksum octets
    one(msg(2013, b'\1\0\0\0'))
    one(msg(2013, b'\0\0\0\0\x05'))                                    # section kind only
    one(compressed(2013, 0, b''))
    one(msg(2012, b'\x01'))
    one(msg(2004, struct.pack('<i', 0) + fcn('a.b') + struct.pack('<ii', 0, 0) + ping + b'\x01\x02'))   # trailing junk after documents
    one(msg(1, struct.pack('<iqii', 0, 0, 0, 5) + ping))              # numberReturned beyond the data
    one(msg(2001, struct.pack('<i', 0) + fcn('x.y') + struct.pack('<i', 0) + ping))   # update without its second document
    one(msg(2013, b'\0\0\0\0', length=0x7fffffff))                       # message length of INT32_MAX
    one(msg(2013, b'\0\0\0\0', length=3))
    # not Mongo: heuristic rejects (short data, length below 4, unknown opcode); no valid first message
    for i, data in enumerate((b'\x10\x00\x00\x00', struct.pack('<iiiI', 2, 0, 0, 2013) + b'\0' * 4, struct.pack('<iiiI', 20, 0, 0, 4242) + b'\0' * 4)):
        c = 49700 + i; net.handshake(c, 27017); net.send(data, True, c, 27017)
    net.write(os.path.join(outdir, 'mongo-coverage-malformed.pcap'))

if __name__ == '__main__':
    main(sys.argv[1], '-v' in sys.argv)
