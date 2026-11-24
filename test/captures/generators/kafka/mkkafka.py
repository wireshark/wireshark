#!/usr/bin/env python3
# Generates test/captures/kafka_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the Kafka coverage captures: mkkafka.py <outdir>

Everything is synthetic (documentation-style addresses, made-up names).
Writes kafka-coverage.pcap (decodes cleanly) and kafka-coverage-malformed.pcap
(input that only malformed data reaches).  Compressed record batches are built
with stored (uncompressed) LZ4/zstd blocks and zlib for gzip; snappy is not
built into the Wireshark used for the measurements.
"""
import os
SRCDIR = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..', '..'))
import re
import struct
import sys
import zlib
import hashlib

HERE = os.path.dirname(os.path.abspath(__file__))
from kschema import SCHEMAS

SRC = os.path.join(SRCDIR, 'epan/dissectors/packet-kafka.c')

def read_api_table():
    src = open(SRC).read()
    keys = {m.group(1): int(m.group(2)) for m in re.finditer(r'#define\s+(KAFKA_[A-Z_0-9]+)\s+(\d+)', src)}
    return [(keys[a], n, int(mn), int(mx), int(fl)) for a, n, mn, mx, fl in
            re.findall(r'\{\s*(KAFKA_[A-Z_0-9]+),\s*"([^"]*)",\s*(-?\d+),\s*(-?\d+),\s*(-?\d+)\s*\}', src) if a in keys]

# ---------------------------------------------------------------- primitives
def varuint(u):
    out = b''
    while True:
        b = u & 0x7f; u >>= 7
        if u: out += bytes([b | 0x80])
        else: return out + bytes([b])

def zigzag(n):
    return (n << 1) ^ (n >> 63) if n < 0 else n << 1

def varint(n):
    return varuint(zigzag(n))

def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

class Net:
    """Frame writer with TCP sequence numbers per direction."""
    CLI = '10.0.0.1'; SRV = '10.0.0.2'
    def __init__(self):
        self.frames = []
        self.seq = {}
        self.t = 0
    def seg(self, payload, sport, dport, src, dst, flags=0x18):
        key = (sport, dport)
        seq = self.seq.get(key, 1000)
        ack = self.seq.get((dport, sport), 1000)
        self.seq[key] = seq + len(payload)
        sip = bytes(map(int, src.split('.'))); dip = bytes(map(int, dst.split('.')))
        tcp = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0)
        ph = sip + dip + struct.pack('!BBH', 0, 6, len(tcp) + len(payload))
        tcp = tcp[:16] + struct.pack('!H', csum(ph + tcp + payload)) + tcp[18:]
        tot = 20 + len(tcp) + len(payload)
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, tot, len(self.frames) + 1, 0, 64, 6, 0, sip, dip)
        ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
        eth = b'\x02\x00\x00\x00\x00\x02' + b'\x02\x00\x00\x00\x00\x01' + b'\x08\x00'
        if src == self.SRV: eth = b'\x02\x00\x00\x00\x00\x01' + b'\x02\x00\x00\x00\x00\x02' + b'\x08\x00'
        self.frames.append(eth + ip + tcp + payload)
    def req(self, payload, port, parts=None):
        for chunk in (split(payload, parts) if parts else [payload]):
            self.seg(chunk, port, 9092, self.CLI, self.SRV)
    def resp(self, payload, port, parts=None):
        for chunk in (split(payload, parts) if parts else [payload]):
            self.seg(chunk, 9092, port, self.SRV, self.CLI)
    def write(self, path):
        with open(path, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
            for i, fr in enumerate(self.frames):
                f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
                f.write(fr)

def split(data, parts):
    n = len(data); step = max(1, n // parts)
    out = [data[i:i + step] for i in range(0, n, step)]
    if len(out) > parts:
        out[parts - 1:] = [b''.join(out[parts - 1:])]
    return out

# ---------------------------------------------------------------- values
ERRS = [0, 1, 3, 6, 7, 15, 25, 35, 41, 87, 0, 2, 9, 22, 58, 0]
STRS = [b'orders', b'payments', b'group-1', b'member-7', b'client-x', b'key-1', b'value-2',
        b'topic-a', b'rack-1', b'broker-a.example.net', b'SCRAM-SHA-256', b'consumer', b'range']

class Gen:
    def __init__(self, mode='full', seed=0):
        self.mode = mode
        self.n = seed
    def pick(self, lst):
        self.n += 1
        return lst[self.n % len(lst)]
    def count(self):
        return {'full': 2, 'sparse': 1, 'empty': 0, 'one': 1}[self.mode]
    def string(self):
        return self.pick(STRS)
    def data(self):
        self.n += 1
        return bytes((self.n * 7 + i) & 0xff for i in range(3 + self.n % 5))

def enc_str(v, flex, nullable_none=False, data=None):
    if data is None:
        return varuint(0) if flex else struct.pack('!h', -1)
    return (varuint(len(data) + 1) if flex else struct.pack('!h', len(data))) + data

def enc_bytes(flex, data):
    if data is None:
        return varuint(0) if flex else struct.pack('!i', -1)
    return (varuint(len(data) + 1) if flex else struct.pack('!i', len(data))) + data

def tagged(items):
    out = varuint(len(items))
    for t, d in items:
        out += varuint(t) + varuint(len(d)) + d
    return out

def enc_prim(kind, g, flex, v):
    if kind == 'i8': return struct.pack('!b', g.pick([0, 1, 2, 3, 4, 5, 6, 7, 8]))
    if kind == 'i16': return struct.pack('!h', g.pick(ERRS))
    if kind == 'u16': return struct.pack('!H', 9093)
    if kind == 'i32': return struct.pack('!i', g.pick([0, 1, 2, 3, 100, 7, 5, 1000, 42, -1, -2]))
    if kind == 'i64': return struct.pack('!q', g.pick([0, 1000, -1, 5, -2, 1700000000123, 77]))
    if kind == 'ts': return struct.pack('!q', 1700000000000 + g.n * 1000)
    if kind == 'f64': return struct.pack('!d', 1.5 * g.pick([1, 2, 3]))
    if kind == 'bool': return struct.pack('!b', g.pick([0, 1]))
    if kind == 'uuid': return hashlib.md5(b'u%d' % g.pick(list(range(5)))).digest()
    if kind == 's': return enc_str(v, flex, data=g.string())
    if kind == 'cs': return enc_str(v, True, data=g.string())
    raise ValueError(kind)

def records_for(api, v, g, direction):
    return b''   # replaced by caller via RECSRC

RECSRC = {}

def enc_fields(fields, v, flex, g, api, direction, top=False, ovr=None):
    out = b''
    for idx, (kind, a, b, sub) in enumerate(fields):
        if not (a <= v <= b):
            continue
        if top and ovr and idx in ovr:
            out += ovr[idx]
            continue
        if kind in ('i8', 'i16', 'i32', 'i64', 'u16', 'f64', 'bool', 'uuid', 'ts', 'cs'):
            out += enc_prim(kind, g, flex, v)
        elif kind == 's':
            out += enc_str(v, flex, data=g.string())
        elif kind == 'rs':
            out += enc_str(v, False, data=g.string())
        elif kind == 'arr0':
            out += varuint(1) if flex else struct.pack('!i', 0)
        elif kind == 'carr':
            n = g.count()
            out += varuint(n + 1)
            for _ in range(n):
                out += enc_fields(sub, v, flex, g, api, direction)
        elif kind == 'ns':
            out += enc_str(v, flex, data=None if g.mode == 'sparse' else g.string())
        elif kind == 'b':
            out += enc_bytes(flex, g.data())
        elif kind == 'rec':
            out += enc_bytes(flex, RECSRC['fn'](api, v, g, direction))
        elif kind in ('arr', 'arrn', 'narr', 'arrp', 'narrp'):
            nullable = kind in ('narr', 'narrp')
            n = g.count()
            if nullable and g.mode == 'sparse':
                out += varuint(0) if flex else struct.pack('!i', -1)
                continue
            out += varuint(n + 1) if flex else struct.pack('!i', n)
            for _ in range(n):
                if kind in ('arrp', 'narrp'):
                    out += enc_prim(sub, g, flex, v)
                else:
                    out += enc_fields(sub, v, flex, g, api, direction)
        elif kind == 'tag':
            if flex: out += b'\x00'
        elif kind == 'rawtag':
            if sub == 'fetchpart':
                items = []
                if v >= 17: items.append((0, hashlib.md5(b'dir').digest()))
                if v >= 18: items.append((1, struct.pack('!q', 4321)))
                if g.mode == 'full': items.append((9, b'xyz'))
                out += tagged(items)
        elif kind == 'bhtag':
            items = []
            if v >= 1: items.append((0, varuint(3) + hashlib.md5(b'a').digest() + hashlib.md5(b'b').digest()))
            if v >= 2: items.append((1, varuint(2) + hashlib.md5(b'c').digest()))
            if g.mode == 'full' and v >= 1: items.append((5, b'\x01'))
            out += tagged(items)
        elif kind == 'quorumtag':
            ep = struct.pack('!i', 3) + varuint(len(b'node3.example.net') + 1) + b'node3.example.net' + struct.pack('!H', 9093) + b'\x00'
            ep2 = struct.pack('!i', 4) + varuint(len(b'node4') + 1) + b'node4' + struct.pack('!H', 9094) + b'\x00'
            items = [(0, varuint(3) + ep + ep2)]
            if g.mode == 'full': items.append((6, b'ab'))
            out += tagged(items)
        elif kind == 'cgassign':
            if g.mode == 'sparse':
                out += b'\xff'
            else:
                out += b'\x01' + varuint(g.count() + 1)
                for _ in range(g.count()):
                    out += hashlib.md5(b'tp').digest() + varuint(3) + struct.pack('!ii', 0, 1) + b'\x00'
                out += b'\x00'
        else:
            raise ValueError(kind)
    return out

# ---------------------------------------------------------------- records
def old_message(magic, key, value, codec=0, offset=0, ts=1700000000000):
    body = struct.pack('!bb', magic, codec)
    if magic > 0: body += struct.pack('!q', ts)
    body += (struct.pack('!i', -1) if key is None else struct.pack('!i', len(key)) + key)
    body += (struct.pack('!i', -1) if value is None else struct.pack('!i', len(value)) + value)
    msg = struct.pack('!I', zlib.crc32(body)) + body
    return struct.pack('!qi', offset, len(msg)) + msg

def gzip_bytes(data):
    c = zlib.compressobj(6, zlib.DEFLATED, 31)
    return c.compress(data) + c.flush()

def xxh32(data, seed=0):
    P1, P2, P3, P4, P5 = 2654435761, 2246822519, 3266489917, 668265263, 374761393
    M = 0xffffffff
    rol = lambda x, r: ((x << r) | (x >> (32 - r))) & M
    n = len(data); i = 0
    if n >= 16:
        v = [(seed + P1 + P2) & M, (seed + P2) & M, seed & M, (seed - P1) & M]
        while i <= n - 16:
            for k in range(4):
                lane = struct.unpack_from('<I', data, i)[0]; i += 4
                v[k] = (rol((v[k] + lane * P2) & M, 13) * P1) & M
        h = (rol(v[0], 1) + rol(v[1], 7) + rol(v[2], 12) + rol(v[3], 18)) & M
    else:
        h = (seed + P5) & M
    h = (h + n) & M
    while i <= n - 4:
        h = (rol((h + struct.unpack_from('<I', data, i)[0] * P3) & M, 17) * P4) & M; i += 4
    while i < n:
        h = (rol((h + data[i] * P5) & M, 11) * P1) & M; i += 1
    h ^= h >> 15; h = (h * P2) & M; h ^= h >> 13; h = (h * P3) & M; h ^= h >> 16
    return h

def lz4_frame(data, blocks=1, bd=0x40, content_size=False):
    flg = 0x60 | (0x08 if content_size else 0)
    desc = bytes([flg, bd]) + (struct.pack('<Q', len(data) * blocks) if content_size else b'')
    out = struct.pack('<I', 0x184D2204) + desc + bytes([(xxh32(desc) >> 8) & 0xff])
    for _ in range(blocks):
        out += struct.pack('<I', 0x80000000 | len(data)) + data
    return out + struct.pack('<I', 0)

def zstd_frame(data, blocks=1):
    out = b'\x28\xb5\x2f\xfd' + bytes([0x00, 0x38])
    step = max(1, len(data) // blocks)
    chunks = [data[i:i + step] for i in range(0, len(data), step)]
    for i, c in enumerate(chunks):
        last = 1 if i == len(chunks) - 1 else 0
        out += struct.pack('<I', (len(c) << 3) | last)[:3] + c
    return out

def rec_v2(key, value, headers=(), ts_delta=0, off_delta=0, attrs=0):
    body = struct.pack('!b', attrs) + varint(ts_delta) + varint(off_delta)
    body += varint(-1) if key is None else varint(len(key)) + key
    body += varint(-1) if value is None else varint(len(value)) + value
    body += varint(len(headers))
    for hk, hv in headers:
        body += (varint(-1) if hk is None else varint(len(hk)) + hk) + (varint(-1) if hv is None else varint(len(hv)) + hv)
    return varint(len(body)) + body

def batch_v2(records, count=None, codec=0, attrs_extra=0, base_offset=0, magic=2, payload=None):
    if count is None: count = len(records)
    attrs = codec | attrs_extra
    data = b''.join(records) if payload is None else payload
    # layout: leader_epoch(4) magic(1) crc(4) attrs(2) last_off_delta(4) first_ts(8) max_ts(8) pid(8) epoch(2) seq(4) count(4)
    after = struct.pack('!i', 0) + struct.pack('!b', magic) + struct.pack('!I', 0x1234abcd) + \
            struct.pack('!h', attrs) + struct.pack('!i', min(max(count - 1, 0), 0x7fffffff)) + \
            struct.pack('!qqqhi', 1700000000000, 1700000000500, 4000, 3, 17) + struct.pack('!I', count) + data
    return struct.pack('!qi', base_offset, len(after)) + after

def std_records(api, v, g, direction):
    if g.mode == 'empty':
        return b'' if g.n % 2 else None
    n = g.count()
    if v <= 2 and api in (0, 1):
        magic = 0 if v == 0 else 1
        msgs = [old_message(magic, b'k%d' % i if i % 2 == 0 or g.mode != 'sparse' else None, b'value-%d' % i, offset=i) for i in range(n)]
        if g.mode == 'full':
            inner = b''.join(msgs)
            msgs.append(old_message(magic, None, gzip_bytes(inner), codec=1, offset=5))
        return b''.join(msgs)
    recs = []
    for i in range(n):
        if g.mode == 'sparse':
            recs.append(rec_v2(None, None, [], 5, 1))
        else:
            recs.append(rec_v2(b'key-%d' % i, b'value-%d' % i, [(b'h1', b'v1'), (b'h2', None)], 10 * i, i))
    return batch_v2(recs)

RECSRC['fn'] = std_records

# ---------------------------------------------------------------- messages
APIS = {a[0]: a for a in read_api_table()}

def header_req(api, v, corr, flex, client=b'cov-client'):
    h = struct.pack('!hhi', api, v, corr)
    if not (api == 7 and v == 0):
        h += struct.pack('!h', len(client)) + client
    if flex: h += b'\x00'
    return h

def pdu(body):
    return struct.pack('!I', len(body)) + body

def build_req(api, v, corr, mode, seed=0, hver=None):
    _, name, mn, mx, fl = APIS[api]
    flex = fl != -1 and v >= fl
    bflex = flex and api != 45
    g = Gen(mode, seed)
    fields = SCHEMAS[api][0]
    ovr = None
    if api == 0:
        # acks: first i16 field at top level, after the transactional id
        idx = [i for i, f_ in enumerate(fields) if f_[0] == 'i16'][0]
        ovr = {idx: struct.pack('!h', {'full': 1, 'sparse': 0, 'empty': -1, 'one': 1}[mode])}
    body = header_req(api, hver if hver is not None else v, corr, flex) + enc_fields(fields, v, bflex, g, api, 'req', True, ovr)
    return pdu(body), (api == 0 and mode == 'sparse')

def build_resp(api, v, corr, mode, seed=0):
    _, name, mn, mx, fl = APIS[api]
    flex = fl != -1 and v >= fl
    g = Gen(mode, seed)
    hdr = struct.pack('!i', corr)
    if flex and api != 18: hdr += b'\x00'
    if api == 18:
        return pdu(hdr + api_versions_body(v, flex, mode))
    return pdu(hdr + enc_fields(SCHEMAS[api][1], v, flex and api != 45, g, api, 'resp', True))

def api_versions_body(v, flex, mode, error=0):
    table = sorted(APIS.values())
    ents = [(k, mn, mx) for k, _, mn, mx, _ in table]
    if mode == 'full':
        ents.append((99, 0, 3))            # key the dissector does not know
        ents.append((0, 0, 40))            # version range beyond what is decoded
        ents.append((27, 0, 1))            # a one-version API with a wider range
    elif mode == 'sparse':
        ents = ents[:3]
    else:
        ents = []
    body = struct.pack('!h', error)
    if flex:
        body += varuint(len(ents) + 1)
    else:
        body += struct.pack('!i', len(ents))
    for k, mn, mx in ents:
        body += struct.pack('!hhh', k, mn, mx) + (b'\x00' if flex else b'')
    if v >= 1: body += struct.pack('!i', 0)
    if flex: body += b'\x00'
    return body

# ---------------------------------------------------------------- captures
def main():
    out = sys.argv[1] if len(sys.argv) > 1 else HERE
    net = Net(); mal = Net()
    port = [40000]
    corr = [1]
    def exchange(api, v, mode, parts=None, rparts=None):
        port[0] += 1; corr[0] += 1
        req, noresp = build_req(api, v, corr[0], mode)
        net.req(req, port[0], parts)
        if not noresp:
            net.resp(build_resp(api, v, corr[0], mode), port[0], rparts)
    for api in sorted(SCHEMAS):
        _, name, mn, mx, fl = APIS[api]
        for v in range(mn, mx + 1):
            exchange(api, v, 'full', parts=2 if (v + api) % 7 == 0 else None)
            exchange(api, v, 'sparse')
            if v == mx or v == mn:
                exchange(api, v, 'empty')
    print('every API/version:', 1, '-', len(net.frames))
    n0 = len(net.frames)
    for api in (10, 21, 23, 24, 28, 9, 2):
        _, name, mn, mx, fl = APIS[api]
        for v in range(mn, mx + 1):
            for seed in (1, 2, 3):
                port[0] += 1; corr[0] += 1
                req, _x = build_req(api, v, corr[0], 'one', seed)
                net.req(req, port[0])
                net.resp(build_resp(api, v, corr[0], 'one', seed), port[0])
    print('extra seeds for value-dependent branches:', n0 + 1, '-', len(net.frames))
    n1 = len(net.frames)
    extra_frames(net, mal, port, corr)
    print('records, compression, unsupported versions, TCP framing, reproducer:', n1 + 1, '-', len(net.frames))
    net.write(os.path.join(out, 'kafka-coverage.pcap'))
    mal.write(os.path.join(out, 'kafka-coverage-malformed.pcap'))
    print(len(net.frames), 'frames main,', len(mal.frames), 'malformed')

def with_records(data, fn):
    """Build with a fixed record payload instead of the standard one."""
    old = RECSRC['fn']
    RECSRC['fn'] = lambda *a: data
    try:
        return fn()
    finally:
        RECSRC['fn'] = old

def rec_exchange(net, port, corr, api, v, data, mode='one'):
    """Produce request (api 0) or Fetch response (api 1) carrying 'data'."""
    port[0] += 1; corr[0] += 1
    if api == 0:
        req, _ = with_records(data, lambda: build_req(0, v, corr[0], mode))
        net.req(req, port[0])
        net.resp(build_resp(0, v, corr[0], mode), port[0])
    else:
        net.req(build_req(1, v, corr[0], 'one')[0], port[0])
        net.resp(with_records(data, lambda: build_resp(1, v, corr[0], mode)), port[0])

def raw_exchange(net, port, corr, api, hver, body, rbody=None, flex=False, resp=True, client=b'cov-client'):
    port[0] += 1; corr[0] += 1
    h = struct.pack('!hhi', api, hver, corr[0]) + struct.pack('!h', len(client)) + client + (b'\x00' if flex else b'')
    net.req(pdu(h + body), port[0])
    if resp and rbody is not None:
        net.resp(pdu(struct.pack('!i', corr[0]) + (b'\x00' if flex else b'') + rbody), port[0])

def record_variants():
    """Record batches / message sets for the compression and record paths."""
    out = []
    recs = [rec_v2(b'key-%d' % i, b'value-%d' % i, [(b'h1', b'v1')], i, i) for i in range(3)]
    plain = b''.join(recs)
    out.append(('v2 gzip', batch_v2(recs, codec=1, payload=gzip_bytes(plain))))
    out.append(('v2 lz4 64k', batch_v2(recs, codec=3, payload=lz4_frame(plain))))
    out.append(('v2 lz4 content size', batch_v2(recs, codec=3, payload=lz4_frame(plain, content_size=True))))
    out.append(('v2 lz4 256k', batch_v2(recs, codec=3, payload=lz4_frame(plain, bd=0x50))))
    out.append(('v2 lz4 1m', batch_v2(recs, codec=3, payload=lz4_frame(plain, bd=0x60))))
    out.append(('v2 lz4 4m', batch_v2(recs, codec=3, payload=lz4_frame(plain, bd=0x70))))
    out.append(('v2 zstd', batch_v2(recs, codec=4, payload=zstd_frame(plain))))
    out.append(('v2 zstd 2 blocks', batch_v2(recs, codec=4, payload=zstd_frame(plain, 2))))
    out.append(('v2 snappy (not built)', batch_v2(recs, codec=2, payload=b'\x82SNAPPY\x00' + struct.pack('!ii', 1, 1) + struct.pack('!I', 3) + b'\x01\x00A')))
    out.append(('v2 codec 5', batch_v2(recs, codec=5, payload=plain)))
    out.append(('v2 transactional', batch_v2(recs, attrs_extra=0x10 | 0x08)))
    out.append(('v2 control', batch_v2([rec_v2(b'\x00\x00\x00\x01', b'\x00\x00\x00\x00\x00\x00\x00\x00')], attrs_extra=0x20 | 0x10)))
    odd = [rec_v2(b'', b'', [(b'', b'x')], 0, 0), rec_v2(None, b'v', [(None, None), (b'k', None)], 1, 1),
           rec_v2(b'k', None, [], 2, 2, attrs=1)]
    out.append(('v2 empty/null fields', batch_v2(odd)))
    out.append(('v2 two batches', batch_v2(recs[:1]) + batch_v2(recs[1:], base_offset=1)))
    inner = old_message(1, b'k', b'v', offset=0) + old_message(1, None, b'w', offset=1)
    out.append(('old lz4', old_message(1, None, lz4_frame(inner), codec=3)))
    out.append(('old zstd', old_message(1, None, zstd_frame(inner), codec=4)))
    out.append(('old gzip', old_message(0, b'k', gzip_bytes(inner.replace(b'', b'')), codec=1)))
    out.append(('old snappy (not built)', old_message(1, None, b'\x82SNAPPY\x00' + struct.pack('!ii', 1, 1), codec=2)))
    out.append(('old null/empty', old_message(0, None, None) + old_message(1, b'', b'')))
    out.append(('old nested gzip', old_message(1, None, gzip_bytes(old_message(1, None, gzip_bytes(inner), codec=1)), codec=1)))
    return out

def loop_repro_records():
    """The reproducers of the bugs fixed on the branch, as record payloads."""
    # record size varint 2^32-5: record_batch loop ran 'count' (0xffffffff) times over the same bytes
    rec = varint(2 ** 32 - 5) + b'\x00' + b'\x00' + b'\x00' + varint(-2)
    loop = batch_v2([], count=0xffffffff, payload=rec)
    # LZ4 frame of 110 64 KiB blocks: more than MAX_LOOP_ITERATIONS decompress calls
    ml = 65530 - 4 - 15
    blk = bytes([0x1f, 0x00]) + struct.pack('<H', 1) + b'\xff' * (ml // 255) + bytes([ml % 255]) + bytes([0x50]) + b'\x00' * 5
    desc = bytes([0x60, 0x40])
    lz4 = struct.pack('<I', 0x184D2204) + desc + bytes([(xxh32(desc) >> 8) & 0xff])
    for _ in range(110): lz4 += struct.pack('<I', len(blk)) + blk
    lz4 += struct.pack('<I', 0)
    # zstd frame of 120 RLE blocks of 128 KiB
    z = b'\x28\xb5\x2f\xfd' + bytes([0x00, 0x38])
    for i in range(120):
        z += struct.pack('<I', (131072 << 3) | (1 << 1) | (1 if i == 119 else 0))[:3] + b'\x00'
    return loop, batch_v2([], count=1, codec=3, payload=lz4), batch_v2([], count=1, codec=4, payload=z)

def extra_frames(net, mal, port, corr):
    # unsupported versions: the dissector assumes the nearest supported one
    raw = lambda api, hv, bv, mode='one': build_req(api, bv, corr[0] + 1, mode, hver=hv)[0]
    # record sets in Produce (v3, v7, v9, v13) and Fetch responses (v4, v12)
    for i, (name, data) in enumerate(record_variants()):
        tgt = mal if name.startswith('old snappy') else net
        rec_exchange(tgt, port, corr, 0, (3, 7, 9, 13)[i % 4], data)
        rec_exchange(tgt, port, corr, 1, (4, 11, 12, 17)[i % 4], data)
    loop, lz4, zstd = loop_repro_records()
    rec_exchange(net, port, corr, 0, 7, lz4)
    rec_exchange(net, port, corr, 0, 9, zstd)
    # an unsupported (too new) version of Produce, and of WriteTxnMarkers (one version only)
    for api, mx in ((0, 13), (27, 0), (1, 18)):
        port[0] += 1; corr[0] += 1
        net.req(build_req(api, mx, corr[0], 'one', hver=mx + 1)[0], port[0])
        net.resp(build_resp(api, mx, corr[0], 'one'), port[0])
    # ApiVersions: UNSUPPORTED_VERSION answered with a version 0 body
    port[0] += 1; corr[0] += 1
    net.req(build_req(18, 5, corr[0], 'one', hver=5)[0], port[0])
    net.resp(pdu(struct.pack('!i', corr[0]) + api_versions_body(0, False, 'sparse', error=35)), port[0])
    # TCP: PDUs split in three segments, and two PDUs in one segment
    for api, v in ((3, 5), (1, 11), (0, 8)):
        port[0] += 1; corr[0] += 1
        req, _ = build_req(api, v, corr[0], 'full')
        net.req(req, port[0], 3)
        net.resp(build_resp(api, v, corr[0], 'full'), port[0], 3)
    port[0] += 1
    a, _ = build_req(12, 2, corr[0] + 1, 'one'); b, _ = build_req(12, 3, corr[0] + 2, 'one')
    net.req(a + b, port[0])
    net.resp(build_resp(12, 2, corr[0] + 1, 'one') + build_resp(12, 3, corr[0] + 2, 'one'), port[0])
    corr[0] += 2
    # the reproducers of the record-size loop (batch count 0xffffffff, record size 2^32-5): these are
    # the last two frames of the main capture; the dissector ends them with a bounds error
    rec_exchange(net, port, corr, 0, 7, loop)
    malformed_frames(mal, port, corr)
    rec_exchange(mal, port, corr, 1, 12, loop)

def malformed_frames(mal, port, corr):
    rnd = __import__('random').Random(26)
    def put(api, v, body, flex=None, rbody=None):
        _, name, mn, mx, fl = APIS.get(api, (api, '', 0, 0, -1))
        fx = (fl != -1 and v >= fl) if flex is None else flex
        raw_exchange(mal, port, corr, api, v, body, rbody, flex=fx)
    # strings / bytes / arrays with bad lengths
    put(12, 0, struct.pack('!h', -5) + b'xx')                      # Heartbeat v0, bad string length
    put(12, 4, b'\xff' * 12)                                       # compact string, bad varint
    put(17, 0, struct.pack('!h', 300) + b'x')                      # string longer than the data
    put(36, 0, struct.pack('!i', -7))                              # SaslAuthenticate bytes length -7
    put(36, 2, b'\xff' * 12)                                       # compact bytes, bad varint
    put(36, 0, struct.pack('!i', 1 << 20))
    put(13, 3, struct.pack('!h', 1) + b'g' + struct.pack('!i', 100000))        # array longer than the data
    put(13, 3, struct.pack('!h', 1) + b'g' + struct.pack('!i', -9))
    put(13, 4, b'\x02g' + b'\xff' * 12)                            # compact array, bad varint
    put(13, 4, b'\x02g' + b'\xff\xff\xff\xff\x7f')               # compact array count overflow
    put(42, 2, varuint(100000) + b'\x00')
    put(16, 3, b'')                                                # tagged fields missing
    put(16, 3, b'\xff' * 12)                                       # tagged fields count, bad varint
    put(16, 3, b'\x01\xff' * 6)                                    # tagged field with a bad tag varint
    put(16, 3, b'\x01\x05' + b'\xff' * 11)                          # tagged field with a bad length varint
    put(16, 3, b'\x01\x05\xff\xff\xff\xff\x0f')                  # tagged field with a huge length
    put(16, 3, b'\x01\x05\x03ab')                                 # tagged field longer than the data
    # tagged-field malformed on a message that decodes known tags
    put(63, 1, struct.pack('!iqq', 1, 2, 3) + b'\x00\x00' + b'\x01\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff')
    put(63, 1, struct.pack('!iqq', 1, 2, 3) + b'\x00\x00' + b'\x01\x00\xff\xff\xff\xff\x0f')      # known tag, length > INT_MAX
    put(63, 2, struct.pack('!iqq', 1, 2, 3) + b'\x00\x00' + b'\x02\x00\x02\x01\x01\x03\x00\x01\xff')
    # unknown API key and a request whose body is longer than the message
    raw_exchange(mal, port, corr, 99, 0, b'\x01\x02\x03', b'\x01\x02', flex=False)
    raw_exchange(mal, port, corr, 12, 1, struct.pack('!h', 1) + b'g' + struct.pack('!i', 1) + struct.pack('!h', 1) + b'm' + b'extra-bytes', struct.pack('!ihh', 0, 0, 0) + b'zz')
    raw_exchange(mal, port, corr, 0, 14, struct.pack('!hhi', 1, 1000, 0), None)      # too new, nothing sane in the body
    raw_exchange(mal, port, corr, 0, -1, struct.pack('!hhi', 1, 1000, 0), None)
    raw_exchange(mal, port, corr, 27, 7, struct.pack('!i', 0), None)
    # a response with no request
    mal.resp(pdu(struct.pack('!i', 4242) + b'\x00\x00'), 55000)
    # records
    recs = [rec_v2(b'key', b'value', [(b'h', b'v')], 0, 0)]
    def prec(data, v=7, api=0):
        rec_exchange(mal, port, corr, api, v, data)
    good = rec_v2(b'k', b'v', [], 0, 0)
    R = lambda *parts: (lambda body: varint(len(body)) + body)(b''.join(parts))
    A = b'\x00'            # attributes
    Z = varint(0)
    BAD = b'\xff' * 10
    prec(batch_v2([], count=1, payload=b'\xff' * 10))                          # bad varint for the record size
    prec(batch_v2([], count=1, payload=varint(3) + b'abc'))                 # record size < 6
    prec(batch_v2([], count=1, payload=varint(100) + b'abc'))               # record size > remaining
    prec(batch_v2([], count=1, payload=varint(2 ** 31) + b'abc'))
    prec(batch_v2([], count=1, payload=R(A, BAD)))                          # bad timestamp delta varint
    prec(batch_v2([], count=1, payload=R(A, Z, BAD, b'\x00\x00')))          # bad offset delta varint
    prec(batch_v2([], count=1, payload=R(A, Z, Z, varint(-5), b'\x00\x00')))    # bad key length
    prec(batch_v2([], count=1, payload=R(A, Z, Z, BAD, b'\x00\x00')))      # bad key length varint
    prec(batch_v2([], count=1, payload=R(A, Z, Z, Z, varint(-5), b'\x00')))      # bad value length
    prec(batch_v2([], count=1, payload=R(A, Z, Z, Z, Z, BAD)))              # bad header count varint
    prec(batch_v2([], count=1, payload=R(A, Z, Z, Z, Z, varint(-4), b'\x00')))   # negative header count
    prec(batch_v2([], count=1, payload=R(A, Z, Z, Z, Z, varint(1), varint(-1), Z)))   # header key null
    prec(batch_v2([], count=1, payload=R(A, Z, Z, Z, Z, varint(1), varint(-5), Z)))   # header key length invalid
    prec(batch_v2([], count=1, payload=R(A, Z, Z, Z, Z, varint(1), BAD)))   # header key length varint bad
    prec(batch_v2([], count=1, payload=R(A, Z, Z, Z, Z, varint(1), varint(1), b'h', varint(-9))))   # header value invalid
    prec(batch_v2([], count=1, payload=R(A, Z, Z, Z, Z, varint(3), Z, Z)))  # headers longer than the record
    prec(batch_v2([], count=1, payload=R(A, Z, Z, Z, Z, Z, b'\x00' * 20)))  # record longer than its content
    prec(batch_v2(recs, magic=3))                                           # unknown magic
    prec(batch_v2(recs)[:20])                                               # truncated in the batch header
    prec(batch_v2(recs) + b'\x00' * 5)                                      # trailing bytes: truncated next message
    prec(batch_v2(recs) + struct.pack('!qi', 5, 400) + b'\x00' * 30)       # next message larger than the data
    prec(batch_v2(recs, codec=1, payload=b'not gzip data'))
    prec(batch_v2(recs, codec=3, payload=b'not lz4 data'))
    prec(batch_v2(recs, codec=3, payload=b'\x04\x22\x4d\x18\x60\x40\x00'))   # lz4: header only
    prec(batch_v2(recs, codec=3, payload=lz4_frame(b'', 1)))                # lz4: empty block
    prec(batch_v2(recs, codec=3, payload=lz4_frame(b'x' * 10)[:-6]))        # lz4: truncated
    prec(batch_v2(recs, codec=3, payload=lz4_frame(b'x' * 10, bd=0x30)))    # lz4: block size ID not allowed
    prec(batch_v2(recs, codec=3, payload=b'\x04\x22\x4d\x18\x60\x40\x82' + struct.pack('<I', 4) + b'\x10\x41\x00\x00' + struct.pack('<I', 0)))   # lz4: corrupt block (match offset 0)
    prec(batch_v2(recs, codec=4, payload=b'not zstd data'))
    prec(batch_v2(recs, codec=4, payload=zstd_frame(b'x' * 10)[:-4]))
    prec(batch_v2(recs, codec=7, payload=b'zzzz'))                          # unsupported codec
    prec(batch_v2(recs, codec=1, payload=b''))                              # empty compressed payload
    mal_old = lambda key, value, codec=0: struct.pack('!qi', 0, 6 + len(key) + len(value)) + struct.pack('!Ibb', 0, 0, codec) + key + value
    prec(mal_old(struct.pack('!i', -5), b''), v=2, api=1)                   # old message: bad key length
    prec(mal_old(struct.pack('!i', -1), struct.pack('!i', -9)), v=2, api=1) # old message: bad value length
    prec(mal_old(struct.pack('!i', -1), struct.pack('!I', 0xfffffff0), 1), v=2, api=1)   # compressed size too large
    prec(mal_old(struct.pack('!i', -1), struct.pack('!I', 0), 1), v=2, api=1)  # compressed size zero
    prec(old_message(1, None, b'garbage-not-gzip', codec=1), v=2, api=1)
    prec(old_message(1, None, b'garbage-not-lz4', codec=3), v=2, api=1)
    prec(old_message(1, None, b'garbage-not-zstd', codec=4), v=2, api=1)
    prec(old_message(1, None, b'garbage', codec=6), v=2, api=1)
    prec(old_message(1, b'k', b'v')[:30], v=2, api=1)                       # truncated old message
    prec(b'\x00' * 8, v=2, api=1)                                           # fewer than 12 bytes
    prec(b'\x00' * 8 + struct.pack('!i', 10), v=2, api=1)
    # the empty/flexible record set helper: bad varint length of the record set
    port[0] += 1; corr[0] += 1
    body = struct.pack('!hhi', 0, 9, corr[0]) + struct.pack('!h', 1) + b'c' + b'\x00' + b'\x00' + struct.pack('!hi', 1, 10) + b'\x02' + b'\x02t' + b'\x02' + struct.pack('!i', 0) + b'\xff' * 11
    mal.req(pdu(body), port[0])
    # the old-version replica assignment of CreateTopics (the dissector does not skip the partition id)
    # and a null config value, which makes it throw
    raw_exchange(mal, port, corr, 19, 0, struct.pack('!i', 1) + kstr(b'topic-a') + struct.pack('!ih', 3, 2) +
                 struct.pack('!i', 1) + struct.pack('!ii', 1, 5) + struct.pack('!i', 0) + struct.pack('!i', 1000), None)
    raw_exchange(mal, port, corr, 19, 5, b'\\x02' + b'\\x08topic-a' + struct.pack('!ih', 3, 2) + b'\\x02' + b'\\x01\\x00\\x00\\x00' +
                 struct.pack('!i', 1000) + b'\\x00' + b'\\x00', None)
    raw_exchange(mal, port, corr, 19, 0, struct.pack('!i', 1) + kstr(b'topic-a') + struct.pack('!ih', 3, 2) +
                 struct.pack('!i', 0) + struct.pack('!i', 1) + kstr(b'retention.ms') + struct.pack('!h', -1) + struct.pack('!i', 1000), None)
    # branches that depend on field values
    i32 = lambda *a: b''.join(struct.pack('!i', x) for x in a)
    raw_exchange(mal, port, corr, 10, 1, kstr(b'grp') + b'\x00',
                 i32(0) + struct.pack('!h', 15) + struct.pack('!h', -1) + i32(-1) + kstr(b'') + i32(-1))
    raw_exchange(mal, port, corr, 21, 0, i32(1) + kstr(b't') + i32(1, 0) + struct.pack('!q', -1) + i32(1000),
                 i32(0, 1) + kstr(b't') + i32(1, 0) + struct.pack('!qh', 5, 0))
    for rid in (-2, -1, 7):
        raw_exchange(mal, port, corr, 23, 3, i32(rid) + i32(1) + kstr(b't') + i32(1, 0, 1, 0), i32(0) + i32(1) + kstr(b't') + i32(1) + struct.pack('!hi', 0, 0) + i32(0) + struct.pack('!q', 0))
    raw_exchange(mal, port, corr, 24, 0, kstr(b'tx') + struct.pack('!qh', 1, 2) + i32(1) + kstr(b't') + i32(1, 0),
                 i32(0, 1) + kstr(b't') + i32(1, 0) + struct.pack('!h', 0))
    raw_exchange(mal, port, corr, 28, 0, kstr(b'tx') + kstr(b'g') + struct.pack('!qh', 1, 2) + i32(1) + kstr(b't') + i32(1, 0) + struct.pack('!q', 5) + kstr(b'm'),
                 i32(0, 1) + kstr(b't') + i32(1, 0) + struct.pack('!h', 0))
    # random bodies for every API and version
    seed_frames = random_frames(rnd)
    for api, v, body in seed_frames:
        raw_exchange(mal, port, corr, api, v, body, rnd.choice([None, rbytes(rnd, 60)]), flex=False if APIS[api][4] == -1 or v < APIS[api][4] else True)

def kstr(s):
    return struct.pack('!h', len(s)) + s

def rbytes(rnd, n):
    out = bytearray()
    for _ in range(rnd.randrange(0, n)):
        r = rnd.random()
        out.append(0 if r < 0.45 else 1 if r < 0.6 else 2 if r < 0.68 else 0xff if r < 0.78 else rnd.randrange(256))
    return bytes(out)

def random_frames(rnd):
    out = []
    for api in sorted(APIS):
        _, name, mn, mx, fl = APIS[api]
        for v in range(mn, mx + 1):
            out.append((api, v, rbytes(rnd, 150)))
    return out

if __name__ == '__main__':
    main()
