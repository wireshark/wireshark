#!/usr/bin/env python3
# Generates test/captures/couchbase_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the Couchbase dissector
(packet-couchbase.c).

Couchbase (the memcached binary protocol with Couchbase extensions) runs
on TCP port 11210. Every PDU has a 24 octet header (magic, opcode, key
length, extras length, datatype, vbucket or status, body length, opaque,
CAS) followed by flexible framing extras (flex magics only), extras, key
and value. Every packet is built from scratch with struct; no captured
traffic is used.

Usage: mkcouchbase.py <output directory>

Writes:
  couchbase-coverage.pcap            every message type with valid data
                                     (frames without expert infos first,
                                     then well formed frames that the
                                     dissector flags with a warning)
  couchbase-coverage-malformed.pcap  lengths that do not fit, truncated
                                     PDUs, the reproducers of the length
                                     wrap fixed on the branch
"""

import os
import struct
import sys

CLI = (192, 0, 2, 10)
SRV = (192, 0, 2, 20)
CPORT = 50000
SPORT = 11210


def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


def ipv4(proto, payload, src, dst, ident=1):
    hdr = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0,
                      64, proto, 0, bytes(src), bytes(dst))
    return hdr[:10] + struct.pack('>H', csum(hdr)) + hdr[12:] + payload


def tcp(sport, dport, seq, ack, payload, src, dst, flags=0x18):
    hdr = struct.pack('>HHIIBBHHH', sport, dport, seq, ack, 0x50, flags,
                      65535, 0, 0)
    pseudo = struct.pack('>4s4sBBH', bytes(src), bytes(dst), 0, 6,
                         len(hdr) + len(payload))
    c = csum(pseudo + hdr + payload)
    return hdr[:16] + struct.pack('>H', c) + hdr[18:] + payload


class Conn:
    """One TCP connection; tracks the sequence numbers of both sides."""

    def __init__(self, out, cport=CPORT, sport=SPORT):
        self.out = out
        self.cport, self.sport = cport, sport
        self.cseq, self.sseq = 1000, 50000

    def send(self, to_server, payload):
        if to_server:
            seg = tcp(self.cport, self.sport, self.cseq, self.sseq, payload,
                      CLI, SRV)
            ip = ipv4(6, seg, CLI, SRV)
            self.cseq += len(payload)
            src_mac, dst_mac = '020000000001', '020000000002'
        else:
            seg = tcp(self.sport, self.cport, self.sseq, self.cseq, payload,
                      SRV, CLI)
            ip = ipv4(6, seg, SRV, CLI)
            self.sseq += len(payload)
            src_mac, dst_mac = '020000000002', '020000000001'
        self.out.append(bytes.fromhex(dst_mac + src_mac) + b'\x08\x00' + ip)


OPAQUE = [0x100]


def pdu(magic, op, key=b'', extras=b'', value=b'', vs=0, dt=0, cas=0,
        flex=b'', bodylen=None, keylen=None, extlen=None, flexlen=None):
    """vs is the vbucket (requests) or the status (responses)."""
    OPAQUE[0] += 1
    if bodylen is None:
        bodylen = len(flex) + len(extras) + len(key) + len(value)
    kl = len(key) if keylen is None else keylen
    el = len(extras) if extlen is None else extlen
    if magic in (0x08, 0x18, 0x82, 0x83):
        fl = len(flex) if flexlen is None else flexlen
        hdr = struct.pack('>BBBBBBHIIQ', magic, op, fl, kl, el, dt, vs,
                          bodylen, OPAQUE[0], cas)
    else:
        hdr = struct.pack('>BBHBBHIIQ', magic, op, kl, el, dt, vs, bodylen,
                          OPAQUE[0], cas)
    return hdr + flex + extras + key + value


def req(op, key=b'', extras=b'', value=b'', vb=0, **kw):
    return pdu(kw.pop('magic', 0x80), op, key, extras, value, vb, **kw)


def res(op, key=b'', extras=b'', value=b'', status=0, **kw):
    return pdu(kw.pop('magic', 0x81), op, key, extras, value, status, **kw)


def leb128(n):
    out = b''
    while True:
        b = n & 0x7f
        n >>= 7
        if n:
            out += bytes([b | 0x80])
        else:
            return out + bytes([b])


def ckey(cid, name):
    """A collection-encoded key: LEB128 collection ID and the name."""
    return leb128(cid) + name


def q(*vals):
    return struct.pack('>' + 'Q' * len(vals), *vals)


def i(*vals):
    return struct.pack('>' + 'I' * len(vals), *vals)


def snappy_literal(data):
    """Snappy compressed form of data as a single literal (len <= 60)."""
    assert 0 < len(data) <= 60
    return leb128(len(data)) + bytes([(len(data) - 1) << 2]) + data


def xattrs(pairs, body):
    blob = b''
    for k, v in pairs:
        p = k + b'\0' + v + b'\0'
        blob += i(len(p)) + p
    return i(len(blob)) + blob + body


def cache_item(key, value, cas=0x1122334455667788, seq=10, rev=2, flags=0,
               exp=0, dt=0, hint=1, value_len=None):
    vl = len(value) if value_len is None else value_len
    return (q(cas, seq, rev) + i(vl, flags, exp)
            + struct.pack('>HBB', len(key), dt, hint) + key + value)


def lookup_spec(op, path, flags=0):
    return struct.pack('>BBH', op, flags, len(path)) + path


def mutation_spec(op, path, value, flags=0, value_len=None):
    vl = len(value) if value_len is None else value_len
    return struct.pack('>BBHI', op, flags, len(path), vl) + path + value


def lookup_result(status, value, value_len=None):
    vl = len(value) if value_len is None else value_len
    return struct.pack('>HI', status, vl) + value


def mutation_result(index, status, value=None):
    r = struct.pack('>BH', index, status)
    if status == 0:
        r += i(len(value)) + value
    return r


def observe_entry(vb, key, status=None, cas=None):
    e = struct.pack('>HH', vb, len(key)) + key
    if status is not None:
        e += struct.pack('>BQ', status, cas)
    return e


def flex_frame(fid, data):
    """A flexible framing extras FrameInfo with escaping when needed."""
    ln = len(data)
    assert fid < 15
    if ln >= 15:
        return bytes([(fid << 4) | 0x0f, ln - 15]) + data
    return bytes([(fid << 4) | ln]) + data


JSON_CFG = b'{"rev":1234,"nodes":[{"hostname":"192.0.2.20","ports":{"direct":11210}}]}'
JSON_ERR = b'{"error":{"context":"Request failed","ref":"0f1e2d3c"}}'
JSON_SMALL = b'{"ok":true}'


def clean_frames(c, cs, sr, reproducer):
    """Frames that decode without any expert info."""
    # HELLO with features, SASL, SELECT_BUCKET, error map, cluster config
    c(req(0x1f, b'wireshark-test', value=struct.pack('>6H', 0x02, 0x06, 0x0b, 0x12, 0x10, 0x99)))
    sr(res(0x1f, value=struct.pack('>4H', 0x06, 0x0b, 0x12, 0x10)))
    c(req(0x20))
    sr(res(0x20, value=b'PLAIN SCRAM-SHA512'))
    c(req(0x21, b'PLAIN', value=b'\0Administrator\0password'))
    sr(res(0x21, value=b'Authenticated'))
    c(req(0x89, b'default'))
    sr(res(0x89))
    c(req(0xfe, value=struct.pack('>H', 2)))
    sr(res(0xfe, value=b'{"version":2,"revision":1,"errors":{}}', dt=1))
    c(req(0xb5))
    sr(res(0xb5, value=JSON_CFG, dt=1))
    # Basic KV: collection IDs with one and two octet LEB128, a key that
    # does not decode as a collection ID (continuation bit on every octet)
    c(req(0x00, ckey(0, b'doc1'), vb=12))
    sr(res(0x00, extras=i(0x02000006), value=b'{"name":"doc1"}', dt=1, cas=0x1600000000000001))
    c(req(0x00, ckey(0x88, b'doc2'), vb=13))
    sr(res(0x00, extras=i(0), value=b'binary-value'))
    c(req(0x0c, b'\x80\x81\x82', vb=14))
    sr(res(0x0c, b'\x80\x81\x82', extras=i(0), value=b'x'))
    # Six continuation octets: the shift passes 32 and decoding stops
    c(req(0x09, b'\x80\x80\x80\x80\x80\x80\x01', vb=15))
    c(req(0x01, ckey(8, b'doc1'), extras=i(0x02000006, 3600), value=b'{"name":"doc1"}', dt=1, vb=12))
    sr(res(0x01, extras=q(0xa1b2c3d4e5f60718, 42), cas=0x1600000000000002))
    c(req(0x02, ckey(8, b'doc3'), extras=i(0, 0), value=b'v3', vb=12))
    sr(res(0x02, extras=q(0xa1b2c3d4e5f60718, 43)))
    c(req(0x03, ckey(8, b'doc3'), extras=i(0, 0), value=b'v4', vb=12))
    sr(res(0x03, extras=q(0xa1b2c3d4e5f60718, 44)))
    c(req(0x0e, ckey(8, b'doc3'), value=b'-tail', vb=12))
    sr(res(0x0e, extras=q(0xa1b2c3d4e5f60718, 45)))
    c(req(0x0f, ckey(8, b'doc3'), value=b'head-', vb=12))
    sr(res(0x0f))
    c(req(0x04, ckey(8, b'doc3'), vb=12))
    sr(res(0x04, extras=q(0xa1b2c3d4e5f60718, 46)))
    c(req(0x05, ckey(8, b'counter'), extras=q(5, 100) + i(0), vb=7))
    sr(res(0x05, extras=q(0xa1b2c3d4e5f60718, 47), value=q(105)))
    c(req(0x06, ckey(8, b'counter'), extras=q(1, 0) + i(60), vb=7))
    sr(res(0x06, value=q(104)))
    c(req(0x08, extras=i(0)))
    sr(res(0x08))
    c(req(0x0a))
    sr(res(0x0a))
    c(req(0x0b))
    sr(res(0x0b, value=b'8.0.0-1234-enterprise'))
    c(req(0x10, b'vbucket-details'))
    sr(res(0x10, b'vb_0', value=b'active'))
    sr(res(0x10))
    c(req(0x1c, ckey(8, b'doc1'), extras=i(300), vb=12))
    sr(res(0x1c))
    c(req(0x1d, ckey(8, b'doc1'), extras=i(300), vb=12))
    sr(res(0x1d, extras=i(0), value=b'v'))
    c(req(0x1b, extras=i(2)))
    sr(res(0x1b))
    c(req(0x48, extras=i(1)))
    sr(res(0x48, value=struct.pack('>HQHQ', 0, 100, 1, 200)))
    c(req(0x49, ckey(8, b'doc1'), vb=12))
    sr(res(0x49, extras=i(0), value=xattrs([(b'_sync', b'{"rev":"1-a"}'), (b'meta', b'{}')], b'{"a":1}'), dt=5))
    # TAP
    c(req(0x40, b'tap-name', extras=i(0x00a5)))
    c(req(0x40, b'tap-name2', extras=i(0)))
    c(req(0x41, ckey(0, b'k')))
    # DCP
    c(req(0x50, b'dcp-conn', extras=i(0, 0x35)))
    sr(res(0x50))
    c(req(0x51, extras=i(0x07), vb=3))
    sr(res(0x51, extras=i(0x1234)))
    c(req(0x53, extras=i(0, 0) + q(0, 0xffffffffffffffff, 0x1234567890abcdef, 0, 0), vb=3))
    sr(res(0x53, value=q(0x1234567890abcdef, 0, 0xfedcba0987654321, 100)))
    c(req(0x54, vb=3))
    sr(res(0x54, value=q(0x1234567890abcdef, 0)))
    c(req(0x56, extras=q(1, 10) + i(0x3f), vb=3))
    c(req(0x56, extras=b'\x00', value=q(11, 20) + i(0x02), vb=3))
    c(req(0x56, extras=b'\x01', value=q(21, 30) + i(0x01) + q(29, 28), vb=3))
    c(req(0x56, extras=b'\x02', value=q(31, 40) + i(0x05) + q(39, 38, 1700000000000), vb=3))
    c(req(0x57, ckey(8, b'doc1'), extras=q(41, 2) + i(0, 0, 0) + struct.pack('>HB', 0, 0),
          value=b'{"name":"doc1"}', dt=1, vb=3))
    c(req(0x57, ckey(8, b'doc2'), extras=q(42, 3) + i(0, 0, 0) + struct.pack('>HB', 0, 0),
          value=xattrs([(b'_txn', b'{"id":7}')], b'{"b":2}'), dt=5, vb=3))
    c(req(0x58, ckey(8, b'doc1'), extras=q(43, 4) + struct.pack('>H', 0), vb=3))
    c(req(0x58, ckey(8, b'doc2'), extras=q(44, 5) + i(1700000000) + b'\x00', vb=3))
    c(req(0x58, ckey(8, b'doc4'), extras=q(45, 6) + i(1700000001) + b'\x00',
          value=xattrs([(b'_sync', b'{"deleted":true}')], b''), dt=4, vb=3))
    sr(res(0x58))
    c(req(0x59, ckey(8, b'doc5'), extras=q(46, 7) + i(1700000002), vb=3))
    c(req(0x59, ckey(8, b'doc6'), extras=q(47, 8) + struct.pack('>H', 0), vb=3))
    c(req(0x5a, extras=q(48, 9) + struct.pack('>H', 0), vb=3))
    c(req(0x5d, extras=i(65536)))
    c(req(0x5f, ckey(0, b'_default'), extras=q(49) + i(0) + b'\x01', value=b'\x00' * 16, vb=3))
    c(req(0x5f, ckey(0, b'scope1'), extras=q(50) + i(3) + b'\x00', value=b'\x00' * 8, vb=3))
    c(req(0x60, ckey(8, b'doc7'), extras=q(51, 1) + i(0, 0, 0) + b'\x00\x00\x01', value=b'{}', dt=1, vb=3))
    c(req(0x61, extras=q(51), vb=3))
    c(req(0x62, ckey(8, b'doc7'), extras=q(51, 52), vb=3))
    c(req(0x63, ckey(8, b'doc8'), extras=q(53, 54), vb=3))
    c(req(0x64, extras=q(55), vb=3))
    c(req(0x65, extras=i(1), vb=3))
    c(req(0x65, extras=i(2), vb=3))
    c(req(0x66, value=cache_item(ckey(8, b'doc1'), b'{"name":"doc1"}', dt=1)
          + cache_item(b'', b'') + cache_item(b'\x80\x80', b'raw'), vb=3))
    sr(res(0x66))
    c(req(0x67, vb=3))
    c(req(0x55, extras=i(0), vb=3))
    c(req(0x52, vb=3))
    sr(res(0x52))
    c(req(0x5b, extras=b'\x01', vb=3))
    c(req(0x5c))
    sr(res(0x5c))
    c(req(0x5e, b'enable_noop', value=b'true'))
    sr(res(0x5e))
    # Sub-document single path
    c(req(0xc5, ckey(8, b'doc1'), extras=struct.pack('>HB', 4, 0x04), value=b'name', vb=12))
    c(req(0xc5, ckey(8, b'doc1'), extras=struct.pack('>HBB', 4, 0x00, 0x24), value=b'name', vb=12))
    sr(res(0xc5, value=b'"doc1"', dt=1))
    c(req(0xc6, ckey(8, b'doc1'), extras=struct.pack('>HB', 4, 0), value=b'name', vb=12))
    sr(res(0xc6))
    c(req(0xc8, ckey(8, b'doc1'), extras=struct.pack('>HB', 3, 0x11), value=b'age42', vb=12))
    c(req(0xc8, ckey(8, b'doc1'), extras=struct.pack('>HBI', 3, 0x01, 600), value=b'age43', vb=12))
    c(req(0xc7, ckey(8, b'doc1'), extras=struct.pack('>HBB', 3, 0x00, 0x03), value=b'new"x"', vb=12))
    c(req(0xcf, ckey(8, b'doc1'), extras=struct.pack('>HBIB', 3, 0x00, 60, 0x01), value=b'cnt1', vb=12))
    c(req(0xc9, ckey(8, b'doc1'), extras=struct.pack('>HB', 3, 0), value=b'old', vb=12))
    sr(res(0xc9))
    # Path as long as the value: no value item
    c(req(0xcb, ckey(8, b'doc1'), extras=struct.pack('>HB', 4, 0), value=b'list', vb=12))
    sr(res(0xcf, value=b'1'))
    # Sub-document multi path
    c(req(0xd0, ckey(8, b'doc1'), extras=b'\x04',
          value=lookup_spec(0xc5, b'name') + lookup_spec(0xc6, b'_sync', 0x04)
          + lookup_spec(0x00, b''), vb=12))
    sr(res(0xd0, value=lookup_result(0, b'"doc1"') + lookup_result(0xc0, b'')
           + lookup_result(0, b'{"rev":"1-a"}')))
    c(req(0xd1, ckey(8, b'doc1'), extras=b'\x01',
          value=mutation_spec(0xc8, b'age', b'44') + mutation_spec(0xc9, b'old', b'')
          + mutation_spec(0xcf, b'cnt', b'1') + mutation_spec(0x01, b'', b'{"whole":1}'), vb=12))
    c(req(0xd1, ckey(8, b'doc1'), extras=i(3600),
          value=mutation_spec(0xc8, b'x', b'1'), vb=12))
    c(req(0xd1, ckey(8, b'doc1'), extras=i(3600) + b'\x02',
          value=mutation_spec(0xc8, b'y', b'2'), vb=12))
    sr(res(0xd1, value=mutation_result(2, 0, b'2') + mutation_result(3, 0, b'')))
    sr(res(0xd1))
    # With-meta, GET_META
    c(req(0xa2, ckey(8, b'doc1'), extras=i(0, 0) + q(5, 0x1600000000000005), value=b'{}', dt=1, vb=12))
    c(req(0xa2, ckey(8, b'doc1'), extras=i(0, 0) + q(5, 0x1600000000000006) + struct.pack('>H', 0),
          value=b'{}', vb=12))
    c(req(0xa2, ckey(8, b'doc1'), extras=i(0, 0) + q(5, 0x1600000000000007) + i(0x0f),
          value=xattrs([(b'_meta', b'1')], b'{}'), dt=4, vb=12))
    c(req(0xa8, ckey(8, b'doc1'), extras=i(0, 0) + q(6, 0x1600000000000008) + i(0x1f)
          + struct.pack('>H', 0), vb=12))
    sr(res(0xa8))
    c(req(0xa0, ckey(8, b'doc1'), vb=12))
    c(req(0xa0, ckey(8, b'doc1'), extras=b'\x02', vb=12))
    sr(res(0xa0, extras=i(0, 0x02000006, 0) + q(7)))
    sr(res(0xa0, extras=i(1, 0, 1700000000) + q(8) + b'\x01'))
    # Collections
    c(req(0xbb, value=b'_default.c1'))
    sr(res(0xbb, extras=q(0x10) + i(8)))
    c(req(0xba))
    sr(res(0xba, value=b'{"uid":"10","scopes":[]}', dt=1))
    c(req(0xbc, value=b'_default'))
    sr(res(0xbc, extras=q(0x10) + i(0)))
    # Range scans
    c(req(0xda, value=b'{"range":{"start":"YQ==","end":"eg=="}}', dt=1, vb=12))
    sr(res(0xda, value=bytes(range(16))))
    c(req(0xdb, extras=bytes(range(16)) + i(100, 1000, 65536), vb=12))
    sr(res(0xdb, value=b'\x04doc1', status=0))
    c(req(0xdc, extras=bytes(range(16)), vb=12))
    sr(res(0xdc))
    # OBSERVE (CAS holds the persist / replicate times) and OBSERVE_SEQNO
    c(req(0x92, value=observe_entry(12, ckey(8, b'doc1')) + observe_entry(13, ckey(8, b'doc2'))))
    sr(res(0x92, value=observe_entry(12, ckey(8, b'doc1'), 1, 0x1600000000000001)
           + observe_entry(13, ckey(8, b'doc2'), 0x80, 0), cas=(100 << 32) | 200))
    c(req(0x91, value=q(0x1234567890abcdef), vb=12))
    sr(res(0x91, value=b'\x00' + struct.pack('>H', 12) + q(0x1234567890abcdef, 100, 120)))
    sr(res(0x91, value=b'\x01' + struct.pack('>H', 12) + q(0x1234567890abcdef, 100, 120, 0x1111, 99)))
    # Bucket management
    c(req(0x85, b'bucket1', value=b'ep.so\0dbname=/data/bucket1;max_size=1048576;'))
    sr(res(0x85))
    c(req(0x87))
    sr(res(0x87, value=b'default bucket1'))
    c(req(0x86, b'bucket1'))
    sr(res(0x86))
    c(req(0x82, b'flush_param', extras=i(1), value=b'1'))
    c(req(0x24, b'release_free_memory'))
    c(req(0x27, extras=i(20480), value=b'{"id":20480,"name":"test"}', dt=1))
    sr(res(0x27))
    c(req(0xaf, b'list'))
    # Snapshots
    c(req(0xe0, vb=12))
    sr(res(0xe0, value=b'{"uuid":"abc","files":[]}', dt=1))
    c(req(0xe1, b'abc'))
    sr(res(0xe1))
    c(req(0xe2, value=b'{"host":"192.0.2.30","port":11210,"bucket":"default"}', dt=1, vb=12))
    sr(res(0xe2))
    c(req(0xe3, b'abc', value=b'{"id":1,"offset":0,"length":16}', dt=1))
    sr(res(0xe3, value=bytes(range(0xf0, 0x100))))
    # Fusion
    c(req(0x70, value=b'{"snapshotUuid":"s1","validity":60}', dt=1, vb=12))
    sr(res(0x70, value=b'{"logManifestName":"m"}', dt=1))
    c(req(0x71, value=b'{"snapshotUuid":"s1"}', dt=1, vb=12))
    c(req(0x72, value=b'{"mountPaths":["/fusion"]}', dt=1, vb=12))
    sr(res(0x72, value=b'{"deks":[]}', dt=1))
    c(req(0x73, vb=12))
    c(req(0x74, vb=12))
    c(req(0x75, value=b'{"term":"1"}', dt=1, vb=12))
    c(req(0x76, vb=12))
    c(req(0x77, value=b'{"namespace":"kv/default"}', dt=1))
    c(req(0x78, value=b'{"metadatastore_uri":"local://"}', dt=1))
    sr(res(0x78, value=b'["kv/default"]', dt=1))
    # Encryption keys
    c(req(0x2d, b'default', value=b'{"keystore":{},"active":"k1"}', dt=1))
    sr(res(0x2d))
    c(req(0x2e, b'default', value=b'{"keep":["k1"]}', dt=1))
    # Opcodes with nothing special, an unnamed one in the middle of the table
    c(req(0x83, ckey(8, b'doc1'), vb=12))
    sr(res(0x83, extras=i(0), value=b'r'))
    c(req(0x94, ckey(8, b'doc1'), extras=i(15), vb=12))
    c(req(0x95, ckey(8, b'doc1'), vb=12, cas=0x1600000000000009))
    c(req(0xb6, extras=i(8), vb=12))
    c(req(0xf0))
    c(req(0x29))
    # Snappy compressed value (datatype SNAPPY; decompressed when Wireshark
    # is built with Snappy)
    c(req(0x01, ckey(8, b'zdoc'), extras=i(0, 0), value=snappy_literal(b'compressed value'), dt=2, vb=12))
    # Flexible framing extras: every request frame ID (the impersonated
    # user uses an escaped length) and every response frame ID
    c(req(0x01, ckey(8, b'doc1'), extras=i(0, 0), value=b'v', vb=12, magic=0x08,
          flex=flex_frame(0, b'') + flex_frame(1, b'\x01') + flex_frame(1, b'\x03\x00\x10')
          + flex_frame(5, b'')))
    c(req(0x00, ckey(8, b'doc1'), vb=12, magic=0x08,
          flex=flex_frame(4, b'cb-impersonated-user')))
    c(req(0x57, ckey(8, b'doc9'), extras=q(56, 1) + i(0, 0, 0) + struct.pack('>HB', 0, 0),
          value=b'v', vb=3, magic=0x08, flex=flex_frame(2, b'\x00\x07')))
    sr(res(0x01, extras=q(0xa1b2c3d4e5f60718, 48), magic=0x18,
           flex=flex_frame(0, b'\x00\x64') + flex_frame(1, b'\x00\x03') + flex_frame(2, b'\x00\x01')))
    sr(res(0x00, extras=i(0), value=b'v', magic=0x18, flex=flex_frame(0, b'\x01\x00')))
    # Server initiated requests and the client responses
    sr(req(0x01, b'default', extras=q(1, 2), value=JSON_CFG, dt=1, magic=0x82))
    c(res(0x01, magic=0x83))
    sr(req(0x02, value=b'{"mechanism":"PLAIN","challenge":"AGFkbWluAHBhc3N3b3Jk"}', dt=1, magic=0x82))
    c(res(0x02, value=b'{"rbac":{"admin":{"buckets":{}}}}', dt=1, magic=0x83))
    c(res(0x02, magic=0x83))
    sr(req(0x03, value=b'["alice","bob"]', dt=1, magic=0x82))
    c(res(0x03, magic=0x83))
    sr(req(0x04, b'alice', magic=0x82))
    c(res(0x04, value=b'{"rbac":{"alice":{"domain":"external"}}}', dt=1, magic=0x83))
    c(res(0x04, magic=0x83))
    # Two PDUs in one segment
    cs(req(0x0a) + req(0x0b))
    sr(res(0x0a) + res(0x0b, value=b'8.0.0'))
    # A PDU in three segments
    big = req(0x01, ckey(8, b'bigdoc'), extras=i(0, 0), value=b'{"data":"' + b'A' * 2900 + b'"}', dt=1, vb=12)
    cs(big[:1000])
    cs(big[1000:2000])
    cs(big[2000:])
    sr(res(0x01, extras=q(0xa1b2c3d4e5f60718, 49)))
    # Reproducer of the JSON layer limit (couchbase_multipath_layers.py):
    # a SUBDOC_MULTI_LOOKUP response with 600 results
    sr(reproducer)


def warning_frames(c, sr):
    """Well formed frames that the dissector flags with a warning."""
    # Unknown client and server opcodes
    c(req(0x2a, value=b'?'))
    sr(req(0x7f, value=b'unknown push', magic=0x82))
    c(res(0x7f, value=b'unknown reply', magic=0x83))
    # Unknown server opcode with a key (the default of dissect_server_key)
    sr(req(0x7f, b'pushkey', value=b'v', magic=0x82))
    # Error responses: status warning; value as JSON for NOT_MY_VBUCKET
    # and an error with the JSON datatype; multi path failure results
    sr(res(0x00, value=b'Not found', status=0x01))
    sr(res(0x00, value=JSON_CFG, status=0x07))
    sr(res(0x01, value=JSON_ERR, status=0x24, dt=1))
    sr(res(0xd0, value=lookup_result(0, b'1') + lookup_result(0xc0, b''), status=0xcc))
    sr(res(0xd1, value=mutation_result(1, 0xc1), status=0xcc))
    sr(res(0xc5, status=0xc0))
    sr(res(0x01, status=0x86))
    sr(res(0x01, value=b'x', status=0xff, dt=1))
    c(res(0x01, value=JSON_ERR, status=0x84, dt=1, magic=0x83))
    sr(res(0x05, extras=q(1, 2), status=0x06))
    # Extras that shall not / must be there, wrong extras lengths
    c(req(0x00, ckey(8, b'doc1'), extras=i(0)))
    sr(res(0x00, value=b'v'))
    c(req(0x01, ckey(8, b'doc1'), value=b'v'))
    c(req(0x05, ckey(8, b'counter')))
    c(req(0x04, ckey(8, b'doc1'), extras=i(0)))
    c(req(0x07, extras=i(0)))
    sr(res(0x48, extras=i(1)))
    c(req(0x50, b'dcp-conn'))
    sr(res(0x50, extras=i(0)))
    c(req(0x51, vb=3))
    c(req(0x53, vb=3))
    c(req(0x56, vb=3))
    c(req(0x56, extras=b'\x00\x00', vb=3))
    sr(res(0x56, extras=b'\x00'))
    c(req(0x57, ckey(8, b'doc1'), vb=3))
    sr(res(0x57, extras=i(0)))
    c(req(0x58, ckey(8, b'doc1'), vb=3))
    c(req(0x58, ckey(8, b'doc1'), extras=q(1), vb=3))
    sr(res(0x58, extras=i(0)))
    c(req(0x59, ckey(8, b'doc1'), vb=3))
    sr(res(0x59, extras=i(0)))
    c(req(0x5a, vb=3))
    sr(res(0x5a, extras=i(0)))
    c(req(0x5d))
    sr(res(0x5d, extras=i(0)))
    c(req(0x5f, ckey(0, b'c'), extras=q(1), vb=3))
    c(req(0x60, ckey(8, b'doc1'), vb=3))
    sr(res(0x60, extras=i(0)))
    c(req(0x61, vb=3))
    sr(res(0x61, extras=i(0)))
    c(req(0x62, ckey(8, b'doc1'), vb=3))
    sr(res(0x62, extras=i(0)))
    c(req(0x63, ckey(8, b'doc1'), vb=3))
    sr(res(0x63, extras=i(0)))
    c(req(0x64, vb=3))
    sr(res(0x64, extras=i(0)))
    c(req(0x65, vb=3))
    sr(res(0x65, extras=i(0)))
    c(req(0xc5, ckey(8, b'doc1'), extras=b'\x00\x01', value=b'a'))
    c(req(0xc8, ckey(8, b'doc1'), extras=struct.pack('>HBH', 1, 0, 0), value=b'ab'))
    c(req(0xd0, ckey(8, b'doc1'), value=lookup_spec(0xc5, b'a')))
    c(req(0xd1, ckey(8, b'doc1'), extras=b'\x00\x00', value=mutation_spec(0xc8, b'a', b'1')))
    sr(res(0xc8, extras=q(1, 2)))
    c(req(0xe0, extras=i(0)))
    c(req(0x70, extras=i(0), value=b'{}', dt=1))
    c(req(0x66, extras=i(0), value=cache_item(b'', b'')))
    # TAP_CONNECT without extras still reads the flags; TAP_MUTATION extras
    # are not decoded (wrong extras length)
    c(req(0x40, b'tap-name', value=i(0x40)))
    c(req(0x41, ckey(0, b'k'), extras=i(0)))
    # With-meta, GET_META, range scans and GET_ID without (enough) extras
    c(req(0xa2, ckey(8, b'doc1'), extras=i(0, 0) + q(0, 0) + b'\x00', value=b'{}'))
    sr(res(0xa0, extras=i(0, 0, 0) + q(0) + b'\x00\x00'))
    sr(res(0xbb, extras=q(0x10) + i(8) + b'\x00'))
    c(req(0xdc, extras=bytes(range(16)) + b'\x00'))
    # Key that shall not / must be there
    c(req(0x0a, b'noop-key'))
    sr(res(0x01, ckey(8, b'doc1')))
    c(req(0x52, ckey(0, b'stream'), vb=3))
    c(req(0xe0, ckey(0, b'snap')))
    c(req(0x73, ckey(0, b'vb')))
    c(req(0x67, ckey(0, b'x')))
    c(req(0x00))
    c(req(0x2d, value=b'{}', dt=1))
    # Server initiated messages: missing / unexpected key, extras, value
    sr(req(0x01, value=JSON_CFG, dt=1, magic=0x82))
    sr(req(0x01, b'default', magic=0x82))
    sr(req(0x01, b'default', extras=q(1), value=JSON_CFG, magic=0x82))
    sr(req(0x01, b'default', extras=q(1, 2) + b'\x00', value=JSON_CFG, magic=0x82))
    sr(req(0x02, b'user', extras=q(1), magic=0x82))
    sr(req(0x03, b'user', magic=0x82))
    sr(req(0x04, magic=0x82))
    sr(req(0x04, b'alice', value=b'x', magic=0x82))
    c(res(0x01, b'default', extras=i(0), value=b'x', magic=0x83))
    c(res(0x03, value=b'x', magic=0x83))
    c(res(0x04, b'alice', magic=0x83))
    sr(req(0x01, b'default', extras=q(1, 2), value=JSON_CFG, flex=b'\x00', magic=0x82))
    # Values that shall not / must be there, wrong value lengths
    c(req(0x0a, value=b'x'))
    sr(res(0x01, value=b'x'))
    c(req(0x00, ckey(8, b'doc1'), value=b'x'))
    c(req(0x67, value=b'x', vb=3))
    sr(res(0x54))
    c(req(0xe2))
    c(req(0x70))
    c(req(0x66))
    c(req(0x2e, b'default'))
    c(req(0x91, value=q(1) + b'\x00\x00', vb=12))
    sr(res(0x05, value=q(1) + b'\x00'))
    sr(res(0x53, value=b'\x00' * 20))
    sr(res(0x48, value=b'\x00' * 12))
    c(req(0xfe, value=b'\x00\x02\x00'))
    # CREATE_BUCKET configs: no NUL, nothing after the NUL, no '=', no
    # value, no ';'
    c(req(0x85, b'b1', value=b'ep.so'))
    c(req(0x85, b'b2', value=b'ep.so\0'))
    c(req(0x85, b'b3', value=b'ep.so\0novalue'))
    c(req(0x85, b'b4', value=b'ep.so\0key='))
    c(req(0x85, b'b5', value=b'ep.so\0key=value'))
    # XATTR pairs without a NUL
    c(req(0x57, ckey(8, b'doc1'), extras=q(1, 1) + i(0, 0, 0) + struct.pack('>HB', 0, 0),
          value=i(8) + i(4) + b'keyx' + b'body', dt=4, vb=3))
    c(req(0x57, ckey(8, b'doc1'), extras=q(1, 1) + i(0, 0, 0) + struct.pack('>HB', 0, 0),
          value=i(10) + i(6) + b'k\0vvvv' + b'body', dt=4, vb=3))
    # Cache transfer with trailing octets
    c(req(0x66, value=cache_item(ckey(8, b'k'), b'v') + b'\x00' * 7, vb=3))
    # Flexible framing: illegal lengths, an ID without a decoder, escaped
    # IDs, the reserved 0xFF tag
    c(req(0x00, ckey(8, b'doc1'), magic=0x08,
          flex=flex_frame(0, b'\x00') + flex_frame(1, b'\x01\x02') + flex_frame(2, b'\x00')
          + flex_frame(5, b'\x00') + flex_frame(3, b'\x01\x02') + bytes([0xf0, 0x01])))
    c(req(0x00, ckey(8, b'doc1'), magic=0x08, flex=b'\xff'))
    sr(res(0x00, extras=i(0), value=b'v', magic=0x18,
           flex=flex_frame(0, b'\x00') + flex_frame(1, b'\x00') + flex_frame(2, b'\x00')
           + flex_frame(9, b'')))
    # A second PDU in a segment with an unknown magic: the first octet of
    # the segment is checked, the second PDU is dissected anyway
    sr(res(0x0a) + struct.pack('>BBHBBHIIQ', 0x55, 0x00, 1, 1, 0, 0, 3, 0, 0) + b'eky')


def malformed_frames(c, cs, sr):
    # Length wrap reproducers (couchbase_multipath_len_wrap.py), 600 octets:
    # lookup response, mutation response, mutation request
    sr(res(0xd0, value=b'\xff' * 600))
    sr(res(0xd1, value=(b'\xff\x00\x00\xff\xff\xff' * 100)))
    c(req(0xd1, value=(b'\xff\x00\x00\x00\xff\xff\xff' * 86)[:600]))
    # Cache transfer item and xattr length past the end
    c(req(0x66, value=cache_item(b'', b'ab', value_len=0xffffffff), vb=3))
    c(req(0x57, ckey(8, b'doc1'), extras=q(1, 1) + i(0, 0, 0) + struct.pack('>HB', 0, 0),
          value=i(0xffffffff) + b'body', dt=4, vb=3))
    # Sections longer than the body: the value length wraps
    c(req(0x00, b'abcdef', bodylen=2))
    # Sub-document path longer than the value
    c(req(0xc5, ckey(8, b'd'), extras=struct.pack('>HB', 40, 0), value=b'short', vb=12))
    # Snapshot marker value shorter than 20 octets
    c(req(0x56, extras=b'\x00', value=b'\x00' * 8, vb=3))
    # Snapshot marker value of 45 octets (the value item starts after 36)
    c(req(0x56, extras=b'\x02', value=q(31, 40) + i(0x05) + q(39, 38, 1) + b'\x00', vb=3))
    # Snapshot marker value between 20 and 36 octets
    c(req(0x56, extras=b'\x00', value=b'\x00' * 24, vb=3))
    # OBSERVE entries cut short, OBSERVE_SEQNO failover entry missing
    c(req(0x92, value=struct.pack('>HH', 1, 10) + b'abc'))
    sr(res(0x91, value=b'\x01' + struct.pack('>H', 12) + q(1, 2, 3)))
    # Extras shorter than the opcode needs
    c(req(0x53, extras=i(0), vb=3))
    # Multi path results cut short
    sr(res(0xd0, value=lookup_result(0, b'abc', value_len=10)))
    sr(res(0xd1, value=mutation_result(0, 0, b'abc')[:-1]))
    # Flexible frame lengths past the flex section / the PDU
    c(req(0x00, ckey(8, b'doc1'), magic=0x08, flex=b'\x4f\x30'))
    # Only the header in the frame (desegmentation off for the last one)
    cs(req(0x00, ckey(8, b'doc1'))[:20])


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        t = 1700000000
        for n, fr in enumerate(frames):
            f.write(struct.pack('<IIII', t + n // 1000, (n % 1000) * 1000, len(fr), len(fr)))
            f.write(fr)


def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else '.'
    # Reproducer from couchbase_multipath_layers.py
    value = b''.join(struct.pack('>HI', 0, 2) + b'{}' for _ in range(600))
    reproducer = struct.pack('>BBHBBHIIQ', 0x81, 0xd0, 0, 0, 0, 0, len(value),
                             0x11223344, 0) + value

    frames = []
    conn = Conn(frames)
    c = lambda p: conn.send(True, p)
    sr = lambda p: conn.send(False, p)
    clean_frames(c, c, sr, reproducer)
    nclean = len(frames)
    warning_frames(c, sr)
    nwarn = len(frames) - nclean
    # A segment on another connection that does not start with a known magic
    other = Conn(frames, cport=50001)
    other.send(True, b'\x00\x01\x02\x03 not couchbase')
    write_pcap(os.path.join(outdir, 'couchbase-coverage.pcap'), frames)
    print('clean frames 1-%d, warning frames %d-%d, other %d'
          % (nclean, nclean + 1, nclean + nwarn, len(frames)))

    mframes = []
    mal = []

    def one(to_server, p):
        # Each malformed PDU on its own connection so that one does not
        # swallow the next
        Conn(mframes, cport=51000 + len(mframes)).send(to_server, p)
    malformed_frames(lambda p: one(True, p), lambda p: one(True, p),
                     lambda p: one(False, p))
    write_pcap(os.path.join(outdir, 'couchbase-coverage-malformed.pcap'), mframes)
    print('malformed frames', len(mframes))


if __name__ == '__main__':
    main()
