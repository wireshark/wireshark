#!/usr/bin/env python3
# Generates test/captures/mysqlx_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the synthetic MySQL X Protocol coverage captures.

Usage: mkmysqlx.py <outdir>

mysqlx-coverage.pcap: valid X Protocol traffic on TCP 33060 (default port),
every client and server message type with a small protobuf payload,
messages split over TCP segments and several messages in one segment.
mysqlx-coverage-malformed.pcap: unknown message types and a length field
that wraps (not added to the tree).  Authentication data is placeholder bytes.
"""
import struct
import sys
import os


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


class Pcap:
    def __init__(self):
        self.pkts = []
        self.ipid = 1

    def write(self, name):
        with open(name, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            for i, p in enumerate(self.pkts):
                f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
                f.write(p)


class Flow:
    def __init__(self, pcap, cport, sport=33060, cip='192.0.2.1', sip='192.0.2.2'):
        self.pcap = pcap
        self.c = (bytes(map(int, cip.split('.'))), cport, b'\x02\x00\x00\x00\x00\x01')
        self.s = (bytes(map(int, sip.split('.'))), sport, b'\x02\x00\x00\x00\x00\x02')
        self.seq = {True: 1000, False: 5000}

    def seg(self, from_client, payload):
        src, dst = (self.c, self.s) if from_client else (self.s, self.c)
        seq = self.seq[from_client]
        ack = self.seq[not from_client]
        tcp = struct.pack('!HHIIBBHHH', src[1], dst[1], seq, ack, 5 << 4, 0x18, 65535, 0, 0)
        pseudo = src[0] + dst[0] + struct.pack('!BBH', 0, 6, len(tcp) + len(payload))
        tcp = tcp[:16] + struct.pack('!H', csum(pseudo + tcp + payload)) + tcp[18:]
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp) + len(payload),
                         self.pcap.ipid, 0, 64, 6, 0, src[0], dst[0])
        self.pcap.ipid += 1
        ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
        self.pcap.pkts.append(dst[2] + src[2] + b'\x08\x00' + ip + tcp + payload)
        self.seq[from_client] = (seq + len(payload)) & 0xffffffff

    def c2s(self, *msgs):
        self.seg(True, b''.join(msgs))

    def s2c(self, *msgs):
        self.seg(False, b''.join(msgs))


# ---- protobuf
def varint(n):
    out = b''
    while True:
        b = n & 0x7f
        n >>= 7
        if n:
            out += bytes([b | 0x80])
        else:
            return out + bytes([b])


def zz(n):
    return (n << 1) ^ (n >> 63)


def f_varint(num, v):
    return varint(num << 3) + varint(v)


def f_bytes(num, b):
    if isinstance(b, str):
        b = b.encode()
    return varint(num << 3 | 2) + varint(len(b)) + b


def f_double(num, v):
    return varint(num << 3 | 1) + struct.pack('<d', v)


def f_float(num, v):
    return varint(num << 3 | 5) + struct.pack('<f', v)


def msg(mtype, payload=b''):
    return struct.pack('<IB', len(payload) + 1, mtype) + payload


# Mysqlx.Datatypes.Scalar / Any
def scalar_uint(v): return f_varint(1, 2) + f_varint(3, v)
def scalar_sint(v): return f_varint(1, 1) + f_varint(2, zz(v))
def scalar_string(s): return f_varint(1, 8) + f_bytes(9, f_bytes(1, s))
def scalar_bool(v): return f_varint(1, 7) + f_varint(8, int(v))
def scalar_double(v): return f_varint(1, 5) + f_double(6, v)
def scalar_float(v): return f_varint(1, 6) + f_float(7, v)
def scalar_null(): return f_varint(1, 3)
def scalar_octets(b): return f_varint(1, 4) + f_bytes(5, f_bytes(1, b))
def any_scalar(sc): return f_varint(1, 1) + f_bytes(2, sc)


def capability(name, any_):
    return f_bytes(1, name) + f_bytes(2, any_)


def capabilities(*caps):
    return b''.join(f_bytes(1, c) for c in caps)


def expr_ident(name, table=None):
    ident = f_bytes(1, name)
    if table:
        ident += f_bytes(2, table)
    return f_varint(1, 1) + f_bytes(2, ident)


def expr_literal(sc):
    return f_varint(1, 2) + f_bytes(4, sc)


def expr_op(name, *params):
    return f_varint(1, 5) + f_bytes(6, f_bytes(1, name) + b''.join(f_bytes(2, p) for p in params))


def collection(name, schema):
    return f_bytes(1, name) + f_bytes(2, schema)


def build_main(pc):
    f = Flow(pc, 40001)
    # --- connection and capabilities
    f.c2s(msg(1))                                                   # CapabilitiesGet
    f.s2c(msg(2, capabilities(
        capability('tls', any_scalar(scalar_bool(True))),
        capability('authentication.mechanisms', f_varint(1, 3) + f_bytes(4, f_varint(1, 1) + f_bytes(2, scalar_string('MYSQL41')))),
        capability('doc.formats', any_scalar(scalar_string('text'))),
        capability('node_type', any_scalar(scalar_string('mysql'))))))  # Capabilities
    f.c2s(msg(2, f_bytes(1, capabilities(capability('compression', any_scalar(scalar_null()))))))   # CapabilitiesSet
    f.s2c(msg(0))                                                   # Ok
    f.s2c(msg(0, f_bytes(1, 'bye')))                                # Ok with a message
    # --- authentication (placeholder bytes)
    f.c2s(msg(4, f_bytes(1, 'MYSQL41') + f_bytes(2, b'\x01' * 4) + f_bytes(3, b'\x02' * 4)))   # AuthenticateStart
    f.s2c(msg(3, f_bytes(1, b'\x03' * 20)))                        # AuthenticateContinue (server)
    f.c2s(msg(5, f_bytes(1, b'\x04' * 20)))                        # AuthenticateContinue (client)
    f.s2c(msg(4, f_bytes(1, b'ok')))                                # AuthenticateOk
    f.s2c(msg(11, f_varint(1, 5) + f_varint(2, 1) + f_bytes(3, f_bytes(1, b'x'))))  # Notice (ServerHello style frame)
    # --- SQL
    f.c2s(msg(12, f_bytes(1, 'SELECT ?, ?, ?, ?, ?, ?, ?') + f_bytes(2, any_scalar(scalar_uint(1))) +
              f_bytes(2, any_scalar(scalar_sint(-2))) + f_bytes(2, any_scalar(scalar_string('three'))) +
              f_bytes(2, any_scalar(scalar_double(4.5))) + f_bytes(2, any_scalar(scalar_float(5.5))) +
              f_bytes(2, any_scalar(scalar_octets(b'\x06'))) + f_bytes(2, any_scalar(scalar_bool(False))) +
              f_bytes(3, 'sql') + f_varint(4, 1)))                  # StmtExecute
    for i, (t, name) in enumerate(((1, 'a'), (2, 'b'), (5, 'c'), (7, 'd'), (10, 'e'), (12, 'f'), (18, 'g'))):
        f.s2c(msg(12, f_varint(1, t) + f_bytes(2, name) + f_bytes(3, name) + f_bytes(4, 't') + f_bytes(5, 't') +
                  f_bytes(6, 'test') + f_bytes(7, 'def') + f_varint(8, 33) + f_varint(9, 2) +
                  f_varint(10, 11) + f_varint(11, 0x10) + f_varint(12, 2)))      # ColumnMetaData
    f.s2c(msg(13, f_bytes(1, b'\x02') + f_bytes(1, b'abc\x00') + f_bytes(1, b'')),
          msg(13, f_bytes(1, b'\x04')))                             # two Rows in one segment
    f.s2c(msg(14))                                                  # FetchDone
    f.s2c(msg(17))                                                  # StmtExecuteOk
    f.s2c(msg(16), msg(18), msg(15))                                # more result sets, out params, suspended
    f.s2c(msg(11, f_varint(1, 3) + f_varint(2, 2) + f_bytes(3, f_varint(1, 4) + f_bytes(2, scalar_uint(3)))))
    f.s2c(msg(1, f_varint(1, 0) + f_varint(2, 1146) + f_bytes(3, "Table 'x.y' doesn't exist") + f_bytes(4, '42S02')))  # Error
    # --- CRUD
    coll = collection('docs', 'test')
    f.c2s(msg(17, f_bytes(2, coll) + f_varint(3, 1) +
              f_bytes(4, f_bytes(1, expr_ident('a')) + f_bytes(2, 'alias')) +
              f_bytes(5, expr_op('==', expr_ident('a'), expr_literal(scalar_sint(1)))) +
              f_bytes(6, f_varint(1, 10) + f_varint(2, 5)) + f_bytes(11, scalar_uint(1))))   # Find
    f.c2s(msg(18, f_bytes(1, coll) + f_varint(2, 1) + f_bytes(3, f_bytes(1, 'a')) +
              f_bytes(4, f_bytes(1, expr_literal(scalar_sint(1)))) + f_varint(6, 1)))      # Insert
    f.c2s(msg(19, f_bytes(2, coll) + f_varint(3, 1) +
              f_bytes(4, expr_op('==', expr_ident('a'), expr_literal(scalar_sint(1))))))   # Update
    f.c2s(msg(20, f_bytes(1, coll) + f_varint(2, 1) +
              f_bytes(3, expr_op('==', expr_ident('a'), expr_literal(scalar_sint(1)))) +
              f_bytes(4, f_varint(1, 1))))                                                 # Delete
    f.c2s(msg(30, f_bytes(1, collection('v', 'test'))))             # CreateView
    f.c2s(msg(31, f_bytes(1, collection('v', 'test'))))             # ModifyView
    f.c2s(msg(32, f_bytes(1, collection('v', 'test'))))             # DropView
    # --- expectations, session
    f.c2s(msg(24, f_varint(1, 1) + f_bytes(2, f_varint(1, 1) + f_bytes(2, b'1') + f_varint(3, 0))))   # Expect.Open
    f.c2s(msg(25))                                                  # Expect.Close
    f.c2s(msg(6, f_varint(1, 1)))                                   # Session.Reset
    f.c2s(msg(7))                                                   # Session.Close
    # --- prepared statements and cursors
    stmt = f_varint(1, 5) + f_bytes(6, f_bytes(1, 'SELECT 1'))
    f.c2s(msg(40, f_varint(1, 1) + f_bytes(2, stmt)))               # Prepare
    f.c2s(msg(41, f_varint(1, 1)))                                  # Prepare.Execute
    f.c2s(msg(43, f_varint(1, 2) + f_bytes(4, f_varint(1, 0) + f_bytes(2, f_varint(1, 1))) + f_varint(5, 10)))   # Cursor.Open
    f.c2s(msg(45, f_varint(1, 2) + f_varint(5, 10)))                # Cursor.Fetch
    f.c2s(msg(44, f_varint(1, 2)))                                  # Cursor.Close
    f.c2s(msg(42, f_varint(1, 1)))                                  # Prepare.Deallocate
    # --- compression messages
    f.c2s(msg(46, f_varint(1, 100) + f_varint(2, 12) + f_bytes(4, b'\x00' * 8)))       # Connection.Compression
    f.s2c(msg(19, f_varint(1, 100) + f_bytes(4, b'\x00' * 8)))                              # Connection.Compression (server)
    f.c2s(msg(3))                                                   # Connection.Close
    f.s2c(msg(0))
    # --- reassembly: a message split over three segments, a segment holding the end of one
    #     message and a whole second one
    big = msg(12, f_bytes(1, 'SELECT ' + ','.join('%d' % i for i in range(800))))
    f.seg(True, big[:600])
    f.seg(True, big[600:1500])
    f.seg(True, big[1500:] + msg(7))
    f.s2c(msg(0))
    # the 5 byte header alone in one segment
    m = msg(0, f_bytes(1, 'split header'))
    f.seg(False, m[:3])
    f.seg(False, m[3:])


def build_malformed(pc):
    f = Flow(pc, 41001)
    # message types without an assigned message
    f.c2s(msg(99, b'\x01\x02\x03'))
    f.s2c(msg(99, b'\x01\x02\x03'))
    f.c2s(msg(0))                      # type 0 is not a client message
    f.s2c(msg(5))                      # type 5 is not a server message
    f.c2s(msg(13))
    # payloads that are not valid protobuf for the message type
    f.c2s(msg(2, b'\xff\xff\xff'))
    f.s2c(msg(1, b'\x08'))
    f.c2s(msg(12, b'\x0a\x7f'))
    # a length field of 0xFFFFFFFC: the PDU length wraps to 0 and tcp_dissect_pdus waits for one more
    # segment forever; every segment that follows is added to the same reassembly
    f = Flow(pc, 41002)
    f.seg(True, struct.pack('<IB', 0xFFFFFFFC, 1))
    for i in range(4):
        f.seg(True, b'\x00' * 1400)
    # a length of 0 (below the type byte)
    f = Flow(pc, 41003)
    f.seg(True, struct.pack('<IB', 0, 1))
    f.seg(True, msg(1))


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    os.makedirs(out, exist_ok=True)
    pc = Pcap()
    build_main(pc)
    pc.write(os.path.join(out, 'mysqlx-coverage.pcap'))
    n = len(pc.pkts)
    pc = Pcap()
    build_malformed(pc)
    pc.write(os.path.join(out, 'mysqlx-coverage-malformed.pcap'))
    print('main frames:', n, 'malformed frames:', len(pc.pkts))


if __name__ == '__main__':
    main()
