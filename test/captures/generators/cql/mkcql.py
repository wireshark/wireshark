#!/usr/bin/env python3
# Generates test/captures/cql_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the CQL dissector
(packet-cql.c, Apache Cassandra CQL native protocol).

CQL runs over TCP port 9042. Protocol versions 3 and 4 (and 5 before the
negotiation is done) use 9 octet envelopes: version and direction,
flags, stream, opcode and length. A version 5 connection switches to
the v5 framing after the server's READY or AUTHENTICATE: frames with a
6 octet header (17 bit payload length, self-contained flag, CRC24) and a
CRC32 trailer, or, after STARTUP with COMPRESSION=lz4, an 8 octet header
with the compressed and uncompressed lengths. The envelopes are inside
the frames. Envelopes of versions 3 and 4 may be compressed (flag 0x01)
with LZ4 (4 octet uncompressed length and an LZ4 block).

Every packet is built from scratch with struct (the LZ4 blocks are
literal-only blocks written by hand); no captured traffic is used.

Usage: mkcql.py <output directory>

Writes:
  cql-coverage.pcap            see README.md for the frame ranges
  cql-coverage-malformed.pcap  negative counts and lengths, cut short
                               messages, values the dissector misreads
"""

import os
import struct
import sys
import zlib

SERVER_PORT = 9042
CLIENT_IP = bytes([192, 0, 2, 10])
SERVER_IP = bytes([192, 0, 2, 20])
CLIENT_MAC = bytes.fromhex('020000000010')
SERVER_MAC = bytes.fromhex('020000000020')

# Opcodes
ERROR, STARTUP, READY, AUTHENTICATE, OPTIONS, SUPPORTED, QUERY, RESULT, \
    PREPARE, EXECUTE, REGISTER, EVENT, BATCH, AUTH_CHALLENGE, AUTH_RESPONSE, \
    AUTH_SUCCESS = 0, 1, 2, 3, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16

# Data types
T_CUSTOM, T_ASCII, T_BIGINT, T_BLOB, T_BOOLEAN, T_COUNTER, T_DECIMAL, \
    T_DOUBLE, T_FLOAT, T_INT = 0, 1, 2, 3, 4, 5, 6, 7, 8, 9
T_TIMESTAMP, T_UUID, T_VARCHAR, T_VARINT, T_TIMEUUID, T_INET, T_DATE, \
    T_TIME, T_SMALLINT, T_TINYINT = 0xB, 0xC, 0xD, 0xE, 0xF, 0x10, 0x11, \
    0x12, 0x13, 0x14
T_LIST, T_MAP, T_SET, T_UDT, T_TUPLE = 0x20, 0x21, 0x22, 0x30, 0x31


# ---------------------------------------------------------------- pcap / TCP

class Pcap:
    def __init__(self):
        self.frames = []

    def add(self, fr):
        self.frames.append(fr)

    def write(self, path):
        with open(path, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
            for i, fr in enumerate(self.frames):
                f.write(struct.pack('<IIII', 1700000000 + i // 100, (i % 100) * 10000,
                                    len(fr), len(fr)))
                f.write(fr)


def cksum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


class Tcp:
    """One TCP connection between the client (port cport) and the server
    (port 9042), with a three-way handshake."""

    def __init__(self, pcap, cport):
        self.p = pcap
        self.cport = cport
        self.seq = {0: 1000 * cport, 1: 5000 * cport}
        self.ipid = 1
        self.seg(0, b'', 0x02)
        self.seq[0] += 1
        self.seg(1, b'', 0x12)
        self.seq[1] += 1
        self.seg(0, b'', 0x10)

    def seg(self, d, data, flags=0x18):
        """d = 0: client to server, 1: server to client."""
        if d == 0:
            sip, dip, sp, dp, smac, dmac = CLIENT_IP, SERVER_IP, self.cport, SERVER_PORT, CLIENT_MAC, SERVER_MAC
        else:
            sip, dip, sp, dp, smac, dmac = SERVER_IP, CLIENT_IP, SERVER_PORT, self.cport, SERVER_MAC, CLIENT_MAC
        ack = self.seq[1 - d] if flags != 0x02 else 0
        opts = struct.pack('>BBHBBBB', 2, 4, 1460, 4, 2, 1, 1) if flags & 0x02 else b''
        th = struct.pack('>HHIIBBHHH', sp, dp, self.seq[d], ack, (5 + len(opts) // 4) << 4,
                         flags, 65535, 0, 0) + opts
        ph = sip + dip + struct.pack('>BBH', 0, 6, len(th) + len(data))
        c = cksum(ph + th + data)
        th = th[:16] + struct.pack('>H', c) + th[18:]
        iph = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(th) + len(data), self.ipid,
                          0x4000, 64, 6, 0, sip, dip)
        iph = iph[:10] + struct.pack('>H', cksum(iph)) + iph[12:]
        self.ipid += 1
        self.p.add(dmac + smac + struct.pack('>H', 0x0800) + iph + th + data)
        self.seq[d] += len(data)

    def c2s(self, data):
        self.seg(0, data)

    def s2c(self, data):
        self.seg(1, data)


# ------------------------------------------------------------- CQL encoding

def s(x):
    """[string]"""
    x = x.encode() if isinstance(x, str) else x
    return struct.pack('>H', len(x)) + x


def ls(x):
    """[long string]"""
    x = x.encode() if isinstance(x, str) else x
    return struct.pack('>I', len(x)) + x


def sb(x):
    """[short bytes]"""
    return struct.pack('>H', len(x)) + x


def b(x):
    """[bytes]; None is NULL (-1), an int is a raw (negative) length."""
    if x is None:
        return struct.pack('>i', -1)
    if isinstance(x, int):
        return struct.pack('>i', x)
    return struct.pack('>i', len(x)) + x


def slist(*xs):
    return struct.pack('>H', len(xs)) + b''.join(s(x) for x in xs)


def smap(*pairs):
    return struct.pack('>H', len(pairs)) + b''.join(s(k) + s(v) for k, v in pairs)


def env(version, flags, stream, opcode, body, resp=False):
    return struct.pack('>BBhBI', version | (0x80 if resp else 0), flags, stream,
                       opcode, len(body)) + body


def crc24(value, nbytes):
    crc = 0x875060
    for i in range(nbytes):
        crc ^= ((value >> (8 * i)) & 0xff) << 16
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc ^= 0x1974F0B
    return crc & 0xffffff


def crc32(payload):
    return zlib.crc32(payload, zlib.crc32(bytes([0xFA, 0x2D, 0x55, 0xCA])))


def v5frame(payload, self_contained=True):
    hv = len(payload) | (int(self_contained) << 17)
    return (struct.pack('<I', hv)[:3] + struct.pack('<I', crc24(hv, 3))[:3] +
            payload + struct.pack('<I', crc32(payload)))


def lz4_literals(data):
    """An LZ4 block holding one literal-only sequence."""
    n = len(data)
    if n < 15:
        return bytes([n << 4]) + data
    out = bytearray([0xF0])
    n -= 15
    while n >= 255:
        out.append(255)
        n -= 255
    out.append(n)
    return bytes(out) + data


def v5cframe(payload, compress=True, uncomp_len=None, self_contained=True):
    """Compressed v5 frame: the payload LZ4 compressed, or (compress=False)
    stored with an uncompressed length of 0."""
    if compress:
        body = lz4_literals(payload)
        ul = len(payload) if uncomp_len is None else uncomp_len
    else:
        body = payload
        ul = 0
    hv = len(body) | (ul << 17) | (int(self_contained) << 34)
    return (struct.pack('<Q', hv)[:5] + struct.pack('<I', crc24(hv, 5))[:3] +
            body + struct.pack('<I', crc32(body)))


def opt(t, *sub):
    """Type option. sub: element option(s) bytes, or UDT/tuple contents."""
    return struct.pack('>H', t) + b''.join(sub)


def udt_opt(ks, name, fields):
    return opt(T_UDT, s(ks), s(name), struct.pack('>H', len(fields)),
               *[s(n) + o for n, o in fields])


def tuple_opt(*opts):
    return opt(T_TUPLE, struct.pack('>H', len(opts)), *opts)


def rows(cols, data, flags=0, global_spec=None, paging=None, ncols=None):
    """RESULT Rows body. cols: list of (ks, table, name, option) or, with
    global_spec, (name, option). data: list of rows of encoded values."""
    if global_spec:
        flags |= 1
    if paging is not None:
        flags |= 2
    body = struct.pack('>iii', 2, flags, len(cols) if ncols is None else ncols)
    if paging is not None:
        body += b(paging)
    if not flags & 4:
        if global_spec:
            body += s(global_spec[0]) + s(global_spec[1])
            for name, o in cols:
                body += s(name) + o
        else:
            for ks, tb, name, o in cols:
                body += s(ks) + s(tb) + s(name) + o
    body += struct.pack('>i', len(data))
    for r in data:
        body += b''.join(r)
    return body


def coll(items):
    """List or set value: count and [bytes] items."""
    return struct.pack('>i', len(items)) + b''.join(b(x) for x in items)


def mapv(pairs):
    return struct.pack('>i', len(pairs)) + b''.join(b(k) + b(v) for k, v in pairs)


def schema_change(change, target, ks, obj=None, args=None):
    out = s(change) + s(target) + s(ks)
    if obj is not None:
        out += s(obj)
    if args is not None:
        out += slist(*args)
    return out


def query_params(consistency, flags, values=(), names=None, page_size=None,
                 paging=None, serial=None, ts=None, keyspace=None, now=None, v5=False):
    out = struct.pack('>H', consistency)
    out += struct.pack('>I', flags) if v5 else struct.pack('>B', flags)
    if flags & 0x01:
        out += struct.pack('>H', len(values))
        for i, v in enumerate(values):
            if names:
                out += s(names[i])
            out += b(v)
    if flags & 0x04:
        out += struct.pack('>i', page_size)
    if flags & 0x08:
        out += b(paging)
    if flags & 0x10:
        out += struct.pack('>H', serial)
    if flags & 0x20:
        out += struct.pack('>q', ts)
    if v5 and flags & 0x80:
        out += s(keyspace)
    if v5 and flags & 0x100:
        out += struct.pack('>i', now)
    return out


def custom_payload(*pairs):
    return struct.pack('>H', len(pairs)) + b''.join(s(k) + b(v) for k, v in pairs)


UUID1 = bytes.fromhex('00112233445566778899aabbccddeeff')
TUUID = bytes.fromhex('e1d2c3b4a5961122b8f40242ac120002')


def all_types_result():
    """RESULT Rows with a column of every simple type, then the
    collections, a UDT and a tuple; a second row with NULL and not-set
    values."""
    ks, tb = 'shop', 'items'
    cols = [
        ('c_ascii', opt(T_ASCII)), ('c_bigint', opt(T_BIGINT)),
        ('c_blob', opt(T_BLOB)), ('c_boolean', opt(T_BOOLEAN)),
        ('c_decimal', opt(T_DECIMAL)), ('c_double', opt(T_DOUBLE)),
        ('c_float', opt(T_FLOAT)), ('c_int', opt(T_INT)),
        ('c_timestamp', opt(T_TIMESTAMP)), ('c_uuid', opt(T_UUID)),
        ('c_varchar', opt(T_VARCHAR)), ('c_varint', opt(T_VARINT)),
        ('c_timeuuid', opt(T_TIMEUUID)), ('c_inet4', opt(T_INET)),
        ('c_inet6', opt(T_INET)), ('c_counter', opt(T_COUNTER)),
        ('c_date', opt(T_DATE)), ('c_time', opt(T_TIME)),
        ('c_smallint', opt(T_SMALLINT)), ('c_tinyint', opt(T_TINYINT)),
        ('c_list', opt(T_LIST, opt(T_INT))),
        ('c_map', opt(T_MAP, opt(T_VARCHAR), opt(T_BIGINT))),
        ('c_set', opt(T_SET, opt(T_ASCII))),
        ('c_udt', udt_opt(ks, 'address', [('street', opt(T_VARCHAR)), ('zip', opt(T_INT))])),
        ('c_tuple', tuple_opt(opt(T_INT), opt(T_VARCHAR), opt(T_BOOLEAN))),
        ('c_list_of_list', opt(T_LIST, opt(T_LIST, opt(T_INT)))),
        ('c_inet_empty', opt(T_INET)), ('c_duration', opt(0x15)),
    ]
    row1 = [
        b(b'hello'), b(struct.pack('>q', -1234567890123)), b(b'\xde\xad\xbe\xef'),
        b(b'\x01'), b(struct.pack('>i', 2) + b'\x30\x39'), b(struct.pack('>d', 3.25)),
        b(struct.pack('>f', 1.5)), b(struct.pack('>i', 42)),
        b(struct.pack('>q', 1700000000000)), b(UUID1), b(b'caf\xc3\xa9'),
        b(b'\x01\x00\x00'), b(TUUID), b(bytes([198, 51, 100, 7])),
        b(bytes.fromhex('20010db8000000000000000000000001') + struct.pack('>I', 9042)),
        # The dissector does not advance past counter, date, time,
        # smallint and tinyint values, so they are empty here.
        b(b''), b(b''), b(b''), b(b''), b(b''),
        b(coll([struct.pack('>i', 1), struct.pack('>i', 2), struct.pack('>i', 3)])),
        b(mapv([(b'a', struct.pack('>q', 1)), (b'b', struct.pack('>q', 2))])),
        b(coll([b'x', b'y'])),
        b(b(b'1 Main St') + b(struct.pack('>i', 12345))),
        b(b(struct.pack('>i', 7)) + b(b'seven') + b(b'\x00')),
        b(coll([coll([struct.pack('>i', 1)]), coll([struct.pack('>i', 2), struct.pack('>i', 3)])])),
        # an empty INET and a DURATION (type 0x15, not known to the
        # dissector), both empty
        b(b''), b(b''),
    ]
    row2 = [b(None)] * 13 + [b(-2)] * 2 + [b(None)] * 5 + [
        b(None), b(-2), b(None), b(None), b(-2),
        # empty list of lists (count 0)
        b(struct.pack('>i', 0)), b(None), b(None)]
    return rows(cols, [row1, row2], global_spec=(ks, tb))


def varint_result():
    """VARINT values of 1 to 9 octets and DECIMAL values with 1 to 8
    octets of unscaled value; INET with 4 and 20 octets."""
    cols = [('ks', 'nums', 'v%d' % n, opt(T_VARINT)) for n in range(1, 10)]
    cols += [('ks', 'nums', 'd%d' % n, opt(T_DECIMAL)) for n in range(1, 9)]
    row = [b(bytes(range(1, n + 1))) for n in range(1, 10)]
    row += [b(struct.pack('>i', n) + bytes(range(0x10, 0x10 + n))) for n in range(1, 9)]
    return rows(cols, [row])


def null_complex_result():
    """NULL values of complex types (the metadata of the element types
    is skipped) and empty collections, followed by an INT column that
    must stay in sync."""
    cols = [
        ('ks', 't', 'l', opt(T_LIST, opt(T_MAP, opt(T_INT), opt(T_SET, opt(T_ASCII))))),
        ('ks', 't', 'u', udt_opt('ks', 'pt', [('x', opt(T_INT)), ('y', tuple_opt(opt(T_INT), opt(T_INT)))])),
        ('ks', 't', 'el', opt(T_LIST, opt(T_INT))),
        ('ks', 't', 'em', opt(T_MAP, opt(T_INT), opt(T_INT))),
        ('ks', 't', 'es', opt(T_SET, opt(T_INT))),
        ('ks', 't', 'i', opt(T_INT)),
    ]
    row = [b(None), b(-2), b(struct.pack('>i', 0)), b(struct.pack('>i', 0)),
           b(struct.pack('>i', 0)), b(struct.pack('>i', 99))]
    return rows(cols, [row])


def no_metadata_result():
    """Rows without metadata (flag 4): column data, NULL, not set, empty."""
    body = struct.pack('>iii', 2, 4 | 2, 4) + b(b'\x01\x02\x03')  # has more pages
    body += struct.pack('>i', 2)
    body += b(b'abc') + b(None) + b(-2) + b(b'')
    body += b(b'\x00\x01') + b(b'') + b(None) + b(-2)
    return body


def paging_result():
    """Rows with more pages (paging state of 4 octets, then one with an
    empty paging state), table spec in every column."""
    return rows([('ks', 't', 'id', opt(T_INT))], [[b(struct.pack('>i', 1))]],
                paging=b'\xaa\xbb\xcc\xdd')


def prepared_result(v5=False):
    out = struct.pack('>i', 4) + sb(b'\x11' * 16)
    if v5:
        out += sb(b'\x22' * 16)
    # metadata: global table spec, two bind columns, one partition key
    out += struct.pack('>iii', 1, 2, 1) + struct.pack('>H', 0)
    out += s('shop') + s('items') + s('id') + opt(T_INT) + s('name') + opt(T_VARCHAR)
    # result metadata: per-column table spec, one column, more pages
    out += struct.pack('>ii', 2, 1) + b(b'\x01')
    out += s('shop') + s('items') + s('price') + opt(T_DECIMAL)
    return out


def prepared_result_no_metadata():
    out = struct.pack('>i', 4) + sb(b'\x33' * 16)
    out += struct.pack('>iii', 0, 0, 0)
    out += struct.pack('>ii', 4, 0)
    return out


# ----------------------------------------------------------------- captures

def conv_v4(p):
    """Version 4: negotiation with authentication, every request and
    response type, tracing, custom payloads, reassembly."""
    c = Tcp(p, 50001)
    V = 4
    c.c2s(env(V, 0, 0, OPTIONS, b''))
    c.s2c(env(V, 0, 0, SUPPORTED, struct.pack('>H', 2) +
              s('CQL_VERSION') + slist('3.4.5') +
              s('COMPRESSION') + slist('lz4', 'snappy'), True))
    c.c2s(env(V, 0, 1, STARTUP, smap(('CQL_VERSION', '3.4.5'), ('DRIVER_NAME', 'syn'),
                                     ('DRIVER_VERSION', '1.0'))))
    c.s2c(env(V, 0, 1, AUTHENTICATE, s('org.apache.cassandra.auth.PasswordAuthenticator'), True))
    c.c2s(env(V, 0, 2, AUTH_RESPONSE, ls(b'\x00cassandra\x00cassandra')))
    c.s2c(env(V, 0, 2, AUTH_CHALLENGE, ls(b'challenge'), True))
    c.c2s(env(V, 0, 3, AUTH_RESPONSE, ls(b'')))
    c.s2c(env(V, 0, 3, AUTH_SUCCESS, ls(b'token'), True))
    c.c2s(env(V, 0, 4, REGISTER, slist('TOPOLOGY_CHANGE', 'STATUS_CHANGE', 'SCHEMA_CHANGE')))
    c.s2c(env(V, 0, 4, READY, b'', True))
    # USE: set keyspace
    c.c2s(env(V, 0, 5, QUERY, ls('USE shop') + query_params(1, 0)))
    c.s2c(env(V, 0x02, 5, RESULT, UUID1 + struct.pack('>i', 3) + s('shop'), True))
    # SELECT with every query parameter, response with every type
    c.c2s(env(V, 0, 6, QUERY, ls('SELECT * FROM items WHERE id = :id AND n = :n') +
              query_params(6, 0x7f, [struct.pack('>i', 1), None], names=['id', 'n'],
                           page_size=100, paging=b'\x01\x02', serial=9,
                           ts=1700000000000000)))
    c.s2c(env(V, 0, 6, RESULT, all_types_result(), True))
    # Custom payloads in a QUERY (with the tracing flag) and its RESULT
    # (with the warning flag; no warnings are parsed).
    c.c2s(env(V, 0x04 | 0x02, 7, QUERY, custom_payload(('k1', b'v1'), ('k2', b'')) +
              ls('SELECT v FROM nums') + query_params(10, 0x01, [b''])))
    c.s2c(env(V, 0x04 | 0x08, 7, RESULT, custom_payload(('srv', b'\x01')) +
              varint_result(), True))
    c.c2s(env(V, 0, 8, QUERY, ls('SELECT * FROM t') + query_params(0, 0x02)))
    c.s2c(env(V, 0, 8, RESULT, null_complex_result(), True))
    c.c2s(env(V, 0, 9, QUERY, ls('SELECT * FROM t2') + query_params(1, 0x04, page_size=2)))
    c.s2c(env(V, 0, 9, RESULT, no_metadata_result(), True))
    c.c2s(env(V, 0, 10, QUERY, ls('SELECT id FROM t') + query_params(2, 0x08, paging=b'')))
    c.s2c(env(V, 0, 10, RESULT, paging_result(), True))
    # PREPARE / EXECUTE
    c.c2s(env(V, 0, 11, PREPARE, ls('SELECT price FROM items WHERE id = ? AND name = ?')))
    c.s2c(env(V, 0, 11, RESULT, prepared_result(), True))
    c.c2s(env(V, 0, 12, EXECUTE, sb(b'\x11' * 16) +
              query_params(4, 0x41, [struct.pack('>i', 1), b'pen'])))
    c.s2c(env(V, 0, 12, RESULT, struct.pack('>i', 1), True))
    c.c2s(env(V, 0, 13, PREPARE, ls('UPDATE t SET a = 1')))
    c.s2c(env(V, 0, 13, RESULT, prepared_result_no_metadata(), True))
    # BATCH: logged with a query, a prepared statement and an unknown
    # kind, with every batch flag; unlogged and counter batches.
    c.c2s(env(V, 0, 14, BATCH, struct.pack('>BH', 0, 3) +
              struct.pack('>B', 0) + ls('INSERT INTO t (a) VALUES (?)') +
              struct.pack('>H', 2) + b(b'\x00\x00\x00\x01') + b(None) +
              struct.pack('>B', 1) + sb(b'\x11' * 16) + struct.pack('>H', 1) + b(b'x') +
              struct.pack('>B', 2) + struct.pack('>H', 0) +
              struct.pack('>HB', 4, 0x70)))
    c.s2c(env(V, 0, 14, RESULT, struct.pack('>i', 1), True))
    c.c2s(env(V, 0x04, 15, BATCH, custom_payload(('b', b'1')) + struct.pack('>BH', 1, 0) +
              struct.pack('>HB', 1, 0)))
    c.s2c(env(V, 0, 15, RESULT, struct.pack('>i', 1), True))
    c.c2s(env(V, 0, 16, BATCH, struct.pack('>BH', 2, 1) + struct.pack('>B', 0) +
              ls('UPDATE c SET n = n + 1') + struct.pack('>H', 0) + struct.pack('>HB', 1, 0)))
    c.s2c(env(V, 0, 16, RESULT, struct.pack('>i', 1), True))
    # Schema changes: TABLE, TYPE, KEYSPACE, FUNCTION
    c.c2s(env(V, 0, 17, QUERY, ls('CREATE TABLE t3 (a int PRIMARY KEY)') + query_params(1, 0)))
    c.s2c(env(V, 0, 17, RESULT, struct.pack('>i', 5) + schema_change('CREATED', 'TABLE', 'shop', 't3'), True))
    c.c2s(env(V, 0, 18, QUERY, ls('CREATE TYPE ty (a int)') + query_params(1, 0)))
    c.s2c(env(V, 0, 18, RESULT, struct.pack('>i', 5) + schema_change('CREATED', 'TYPE', 'shop', 'ty'), True))
    c.c2s(env(V, 0, 19, QUERY, ls('DROP KEYSPACE old') + query_params(1, 0)))
    c.s2c(env(V, 0, 19, RESULT, struct.pack('>i', 5) + schema_change('DROPPED', 'KEYSPACE', 'old'), True))
    c.c2s(env(V, 0, 20, QUERY, ls('CREATE FUNCTION f') + query_params(1, 0)))
    c.s2c(env(V, 0, 20, RESULT, struct.pack('>i', 5) +
              schema_change('CREATED', 'FUNCTION', 'shop', 'f', ['int']), True))
    # Events on stream -1 (no request): schema, topology, status change
    c.s2c(env(V, 0, -1, EVENT, s('SCHEMA_CHANGE') + schema_change('UPDATED', 'TABLE', 'shop', 'items'), True))
    c.s2c(env(V, 0, -1, EVENT, s('TOPOLOGY_CHANGE') + s('NEW_NODE') +
              bytes([4, 192, 0, 2, 30]) + struct.pack('>i', 9042), True))
    c.s2c(env(V, 0, -1, EVENT, s('STATUS_CHANGE') + s('UP') +
              bytes([4, 192, 0, 2, 30]) + struct.pack('>i', 9042), True))
    # Errors
    errs = [
        (0x0000, b''), (0x000A, b''), (0x0100, b''),
        (0x1000, struct.pack('>Hii', 4, 3, 1)), (0x1001, b''), (0x1002, b''),
        (0x1003, b''),
        (0x1100, struct.pack('>Hii', 4, 1, 2) + s('SIMPLE')),
        (0x1200, struct.pack('>HiiB', 1, 0, 1, 0)),
        (0x1300, struct.pack('>HiiiB', 6, 1, 2, 1, 1)),
        (0x1400, s('ks') + s('fn') + slist('int')),
        (0x1500, struct.pack('>Hiii', 5, 1, 3, 2) + s('BATCH')),
        (0x2000, b''), (0x2100, b''), (0x2200, b''), (0x2300, b''),
        (0x2400, s('shop') + s('t3')), (0x2500, sb(b'\x44' * 16)),
        (0x9999, b''),
    ]
    for i, (code, extra) in enumerate(errs):
        st = 100 + i
        c.c2s(env(V, 0, st, QUERY, ls('SELECT %d' % i) + query_params(1, 0)))
        c.s2c(env(V, 0, st, ERROR, struct.pack('>i', code) + s('error %04x' % code) + extra, True))
    # Two requests in one segment, their responses in one segment.
    c.c2s(env(V, 0, 200, OPTIONS, b'') + env(V, 0, 201, OPTIONS, b''))
    sup = env(V, 0, 200, SUPPORTED, struct.pack('>H', 0), True)
    c.s2c(sup + env(V, 0, 201, SUPPORTED, struct.pack('>H', 0), True))
    # A RESULT split over three segments (TCP reassembly).
    big = env(V, 0, 202, RESULT, rows([('ks', 't', 'blob', opt(T_BLOB))],
                                      [[b(bytes(range(256)) * 8)]]), True)
    c.c2s(env(V, 0, 202, QUERY, ls('SELECT blob FROM t') + query_params(1, 0)))
    c.s2c(big[:5])
    c.s2c(big[5:1000])
    c.s2c(big[1000:])
    # A response on a stream that never had a request.
    c.s2c(env(V, 0, 300, RESULT, struct.pack('>i', 1), True))
    # Stream 0 used again.
    c.c2s(env(V, 0, 0, OPTIONS, b''))
    c.s2c(env(V, 0, 0, SUPPORTED, struct.pack('>H', 0), True))


def conv_v3(p):
    """Version 3: v3 header flags, LZ4 compressed envelopes (and one that
    does not decompress), unknown opcodes."""
    c = Tcp(p, 50002)
    V = 3
    c.c2s(env(V, 0, 0, STARTUP, smap(('CQL_VERSION', '3.0.0'), ('COMPRESSION', 'lz4'))))
    c.s2c(env(V, 0, 0, READY, b'', True))
    q = ls('SELECT * FROM compressed') + query_params(1, 0)
    c.c2s(env(V, 0x01, 1, QUERY, struct.pack('>I', len(q)) + lz4_literals(q)))
    r = rows([('ks', 't', 'name', opt(T_VARCHAR))], [[b(b'compressed row %d' % i)] for i in range(3)])
    c.s2c(env(V, 0x01, 1, RESULT, struct.pack('>I', len(r)) + lz4_literals(r), True))
    # compression flag, but the body does not decompress (too large an
    # uncompressed length): shown as compressed bytes
    c.c2s(env(V, 0x01, 2, QUERY, struct.pack('>I', 0x7fffffff) + b'garbage!'))
    # compression flag with a body of 4 octets (too short to try)
    c.s2c(env(V, 0x01, 2, RESULT, b'\x00\x00\x00\x01', True))
    # compression flag with a body that is not LZ4
    c.c2s(env(V, 0x01, 3, QUERY, struct.pack('>I', 20) + b'\xff' * 6))
    c.s2c(env(V, 0, 3, RESULT, struct.pack('>i', 1), True))
    # tracing flag on a request (ignored) and reserved v3 flags
    c.c2s(env(V, 0x02 | 0x80, 4, OPTIONS, b''))
    c.s2c(env(V, 0, 4, SUPPORTED, struct.pack('>H', 1) + s('CQL_VERSION') + slist('3.0.0'), True))


def conv_v4_unknown(p):
    """Version 4: unknown request opcode, unknown response opcode,
    unknown result kind (each a "not dissected yet" warning)."""
    c = Tcp(p, 50003)
    V = 4
    c.c2s(env(V, 0, 1, 0x04, b'\x01\x02'))
    c.s2c(env(V, 0, 1, 0x11, b'\x03\x04', True))
    c.c2s(env(V, 0, 2, QUERY, ls('SELECT 1') + query_params(1, 0)))
    c.s2c(env(V, 0, 2, RESULT, struct.pack('>i', 9), True))


def conv_v2(p):
    """Version 2: not supported, dissected with the plain flags field."""
    c = Tcp(p, 50004)
    c.c2s(env(2, 0, 1, OPTIONS, b''))
    c.s2c(env(2, 0, 1, SUPPORTED, struct.pack('>H', 0), True))


def conv_v5(p):
    """Version 5 without compression: negotiation in envelopes, then v5
    frames after READY; a second READY inside a frame (the frame where
    the v5 framing starts must stay the first one, on every pass)."""
    c = Tcp(p, 50005)
    V = 5
    c.c2s(env(V, 0, 0, OPTIONS, b''))
    c.s2c(env(V, 0, 0, SUPPORTED, struct.pack('>H', 1) + s('PROTOCOL_VERSIONS') +
              slist('3/v3', '4/v4', '5/v5'), True))
    c.c2s(env(V, 0, 1, STARTUP, smap(('CQL_VERSION', '3.4.5'), ('COMPRESSION', 'lz5'))))
    c.s2c(env(V, 0, 1, READY, b'', True))
    # v5 frames
    c.c2s(v5frame(env(V, 0, 2, QUERY, ls('SELECT * FROM v5') +
                      query_params(4, 0x1A5, [struct.pack('>i', 5)], page_size=10,
                                   ts=1700000000000000, keyspace='shop', now=1700000000,
                                   v5=True))))
    c.s2c(v5frame(env(V, 0x10, 2, RESULT, rows([('shop', 't', 'v', opt(T_INT))],
                                               [[b(struct.pack('>i', 5))]]), True)))
    c.c2s(v5frame(env(V, 0, 3, PREPARE, ls('SELECT * FROM v5 WHERE id = ?'))))
    c.s2c(v5frame(env(V, 0, 3, RESULT, prepared_result(v5=True), True)))
    # two envelopes in one frame, two responses in one frame
    c.c2s(v5frame(env(V, 0, 4, EXECUTE, sb(b'\x11' * 16) + query_params(1, 0x02, v5=True)) +
                  env(V, 0, 5, QUERY, ls('SELECT 2') + query_params(1, 0, v5=True))))
    c.s2c(v5frame(env(V, 0, 4, RESULT, struct.pack('>i', 1), True) +
                  env(V, 0, 5, RESULT, struct.pack('>i', 1), True)))
    # a frame split over two segments
    fr = v5frame(env(V, 0, 6, QUERY, ls('SELECT ' + 'x' * 300) + query_params(1, 0, v5=True)))
    c.c2s(fr[:100])
    c.c2s(fr[100:])
    c.s2c(v5frame(env(V, 0, 6, RESULT, struct.pack('>i', 1), True)))
    # a READY inside a v5 frame
    c.s2c(v5frame(env(V, 0, 7, READY, b'', True)))
    c.c2s(v5frame(env(V, 0, 8, OPTIONS, b'')))
    c.s2c(v5frame(env(V, 0, 8, SUPPORTED, struct.pack('>H', 0), True), self_contained=False))


def conv_v5_auth(p):
    """Version 5: v5 framing starts after AUTHENTICATE."""
    c = Tcp(p, 50006)
    V = 5
    c.c2s(env(V, 0, 0, STARTUP, smap(('CQL_VERSION', '3.4.5'))))
    c.s2c(env(V, 0, 0, AUTHENTICATE, s('PasswordAuthenticator'), True))
    c.c2s(v5frame(env(V, 0, 1, AUTH_RESPONSE, ls(b'\x00u\x00p'))))
    c.s2c(v5frame(env(V, 0, 1, AUTH_SUCCESS, ls(b''), True)))
    c.c2s(v5frame(env(V, 0, 2, REGISTER, slist('SCHEMA_CHANGE'))))
    c.s2c(v5frame(env(V, 0, 2, READY, b'', True)))
    c.s2c(v5frame(env(V, 0, -1, EVENT, s('SCHEMA_CHANGE') +
                      schema_change('CREATED', 'KEYSPACE', 'newks'), True)))


def conv_v5_lz4(p):
    """Version 5 with COMPRESSION=lz4: compressed v5 frames, one stored
    uncompressed (uncompressed length 0)."""
    c = Tcp(p, 50007)
    V = 5
    c.c2s(env(V, 0, 0, STARTUP, smap(('CQL_VERSION', '3.4.5'), ('COMPRESSION', 'lz4'))))
    c.s2c(env(V, 0, 0, READY, b'', True))
    c.c2s(v5cframe(env(V, 0, 1, QUERY, ls('SELECT * FROM lz') + query_params(1, 0, v5=True)),
                   compress=False))
    c.s2c(v5cframe(env(V, 0, 1, RESULT, rows([('ks', 'lz', 'v', opt(T_VARCHAR))],
                                             [[b(b'row %d' % i)] for i in range(5)]), True)))
    c.c2s(v5cframe(env(V, 0, 2, OPTIONS, b''), self_contained=False))
    c.s2c(v5cframe(env(V, 0, 2, SUPPORTED, struct.pack('>H', 0), True)))


def malformed(p):
    c = Tcp(p, 50101)
    V = 4
    # negative column count, negative row count
    c.s2c(env(V, 0, 1, RESULT, struct.pack('>iii', 2, 0, -1), True))
    c.s2c(env(V, 0, 2, RESULT, struct.pack('>iii', 2, 4, 1) + struct.pack('>i', -3), True))
    # no-metadata row with a length below -2
    c.s2c(env(V, 0, 3, RESULT, struct.pack('>iii', 2, 4, 1) + struct.pack('>i', 1) + b(-5), True))
    # value length below -2 with metadata
    c.s2c(env(V, 0, 4, RESULT, rows([('k', 't', 'c', opt(T_LIST, opt(T_INT)))], [[b(-7)]]), True))
    # negative list, map and set sizes
    for t, o in ((T_LIST, opt(T_LIST, opt(T_INT))),
                 (T_MAP, opt(T_MAP, opt(T_INT), opt(T_INT))),
                 (T_SET, opt(T_SET, opt(T_INT)))):
        c.s2c(env(V, 0, 5, RESULT, rows([('k', 't', 'c', o)], [[b(struct.pack('>i', -1))]]), True))
    # prepared with negative counts
    c.s2c(env(V, 0, 6, RESULT, struct.pack('>i', 4) + sb(b'\x01') + struct.pack('>ii', 0, -1), True))
    c.s2c(env(V, 0, 7, RESULT, struct.pack('>i', 4) + sb(b'\x01') + struct.pack('>iii', 0, 0, -1), True))
    c.s2c(env(V, 0, 8, RESULT, struct.pack('>i', 4) + sb(b'\x01') + struct.pack('>iii', 0, 0, 0) +
              struct.pack('>ii', 0, -1), True))
    # a custom column with data: the class name is not skipped
    c.s2c(env(V, 0, 9, RESULT, rows([('k', 't', 'c', opt(T_CUSTOM, s('a.B')))], [[b(b'zz')]]), True))
    # INET of 16 octets (an IPv6 address; read as address and port) and 8
    c.s2c(env(V, 0, 10, RESULT, rows([('k', 't', 'c', opt(T_INET))], [[b(bytes(16))]]), True))
    c.s2c(env(V, 0, 11, RESULT, rows([('k', 't', 'c', opt(T_INET)), ('k', 't', 'd', opt(T_INT))],
                                     [[b(bytes(8)), b(struct.pack('>i', 1))]]), True))
    # a counter with data followed by an INT
    c.s2c(env(V, 0, 12, RESULT, rows([('k', 't', 'c', opt(T_COUNTER)), ('k', 't', 'd', opt(T_INT))],
                                     [[b(struct.pack('>q', 5)), b(struct.pack('>i', 1))]]), True))
    # tracing and custom payload in one RESULT: the custom payload
    # offset is added twice, the result kind is read from the wrong place
    c.s2c(env(V, 0x02 | 0x04, 17, RESULT, UUID1 + custom_payload(('srv', b'\x01')) +
              struct.pack('>i', 1), True))
    # a custom column with a NULL value: the metadata parser does not
    # skip the (empty) class name, so the row count is read from it and
    # the next two octets
    body = struct.pack('>iii', 2, 0, 1) + s('k') + s('t') + s('c') + opt(T_CUSTOM, s(''))
    body += struct.pack('>H', 1) + b(None)
    c.s2c(env(V, 0, 18, RESULT, body, True))
    # the same with a value: shown as CUSTOM
    body = struct.pack('>iii', 2, 0, 1) + s('k') + s('t') + s('c') + opt(T_CUSTOM, s(''))
    body += struct.pack('>H', 1) + b(b'custom')
    c.s2c(env(V, 0, 19, RESULT, body, True))
    # messages cut short: STARTUP, ERROR, QUERY params
    c.c2s(env(V, 0, 13, STARTUP, struct.pack('>H', 3) + s('A')))
    c.s2c(env(V, 0, 13, ERROR, struct.pack('>i', 0x1100) + s('x'), True))
    c.c2s(env(V, 0, 14, QUERY, ls('SELECT') + struct.pack('>HB', 1, 0x3f)))
    # LZ4 v4 envelope whose body decompresses to a cut RESULT
    r = struct.pack('>i', 2)
    c.s2c(env(V, 0x01, 15, RESULT, struct.pack('>I', len(r)) + lz4_literals(r), True))
    # deep nesting of list types in the metadata
    c.s2c(env(V, 0, 16, RESULT, rows([('k', 't', 'c', struct.pack('>H', T_LIST) * 200 + opt(T_INT))], []), True))
    # v5 frame whose envelope header is cut
    c2 = Tcp(p, 50102)
    c2.c2s(env(5, 0, 0, STARTUP, smap(('COMPRESSION', 'lz4'))))
    c2.s2c(env(5, 0, 0, READY, b'', True))
    # compressed frame with bad LZ4 data
    c2.c2s(v5cframe(b'\xf0\xff\xff', compress=False)[:0] +
           (lambda body: struct.pack('<Q', len(body) | (100 << 17) | (1 << 34))[:5] + b'\0\0\0' +
            body + b'\0\0\0\0')(b'\xff\xff\xff\xff\xff'))
    # compressed frame holding a cut envelope
    c2.s2c(v5cframe(env(5, 0, 1, RESULT, struct.pack('>i', 1), True)[:6]))
    # v5 uncompressed connection with a cut envelope inside a frame
    c3 = Tcp(p, 50103)
    c3.c2s(env(5, 0, 0, STARTUP, smap(('CQL_VERSION', '3.4.5'))))
    c3.s2c(env(5, 0, 0, READY, b'', True))
    c3.c2s(v5frame(env(5, 0, 1, QUERY, ls('SELECT 1') + query_params(1, 0, v5=True))[:12]))


def main(outdir):
    os.makedirs(outdir, exist_ok=True)
    p = Pcap()
    for conv in (conv_v4, conv_v3, conv_v4_unknown, conv_v2, conv_v5, conv_v5_auth, conv_v5_lz4):
        conv(p)
    p.write(os.path.join(outdir, 'cql-coverage.pcap'))
    m = Pcap()
    malformed(m)
    m.write(os.path.join(outdir, 'cql-coverage-malformed.pcap'))


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')
