#!/usr/bin/env python3
# Generates test/captures/hdfs_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the HDFS coverage captures.  Usage: mkhdfs.py <outdir>

Hadoop HDFS client <-> namenode RPC (the pre-protobuf Writable format)
over TCP.  HDFS has no default port: the dissector is only available
through Decode As (tcp.port 8020 -> HDFS), and it decides between
request and response by comparing the source port with that preference.
Everything is built with struct; the user, host and path names are
made up and the authentication bytes are a constant placeholder."""
import struct
import sys
import os

CL = bytes([192, 0, 2, 1])
NN = bytes([192, 0, 2, 2])
MAC_C = bytes.fromhex('020000000001')
MAC_N = bytes.fromhex('020000000002')
CPORT, NPORT = 40000, 8020

LOCATED = b'org.apache.hadoop.hdfs.protocol.LocatedBlocks'
FSTATUS = b'org.apache.hadoop.hdfs.protocol.HdfsFileStatus'
FSPERM = b'org.apache.hadoop.fs.permission.FsPermission'


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


class Cap:
    def __init__(self):
        self.frames = []
        self.t = 1700000000

    def add(self, fr):
        self.frames.append((self.t, fr))
        self.t += 1

    def write(self, path):
        with open(path, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            for t, fr in self.frames:
                f.write(struct.pack('<IIII', t, 0, len(fr), len(fr)) + fr)


class Flow:
    def __init__(self, cap, cport=CPORT, nport=NPORT):
        self.cap = cap
        self.cport, self.nport = cport, nport
        self.seq = {True: 1000, False: 5000}
        self.ipid = 1

    def seg(self, to_nn, payload, flags=0x18):
        src, dst = (CL, NN) if to_nn else (NN, CL)
        ms, md = (MAC_C, MAC_N) if to_nn else (MAC_N, MAC_C)
        sp, dp = (self.cport, self.nport) if to_nn else (self.nport, self.cport)
        seq, ack = self.seq[to_nn], self.seq[not to_nn]
        tcp = struct.pack('!HHIIBBHHH', sp, dp, seq, ack, 5 << 4, flags, 65535, 0, 0)
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp) + len(payload),
                         self.ipid, 0, 64, 6, 0, src, dst)
        self.ipid += 1
        ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
        ph = src + dst + struct.pack('!BBH', 0, 6, len(tcp) + len(payload))
        tcp = tcp[:16] + struct.pack('!H', csum(ph + tcp + payload)) + tcp[18:]
        self.cap.add(md + ms + b'\x08\x00' + ip + tcp + payload)
        self.seq[to_nn] += len(payload) + (1 if flags & 3 else 0)

    def handshake(self):
        self.seg(True, b'', 0x02)
        self.seg(False, b'', 0x12)
        self.seg(True, b'', 0x10)


def s2(b):
    """2 octet length + bytes."""
    return struct.pack('>H', len(b)) + b


def s1(b):
    return bytes([len(b)]) + b


def param(typ, val):
    """A request parameter: type, then a length-prefixed value, or the raw
    numeric value for the primitive types."""
    typ = typ.encode() if isinstance(typ, str) else typ
    if typ in (b'long', b'int', b'short', b'char', b'byte', b'boolean',
               b'float', b'double'):
        return s2(typ) + val                          # Java primitive size
    return s2(typ) + s2(val)


def call(seqno, method, params, auth=None):
    """A request: [authentication length + bytes] length seqno method
    number-of-params params.  The length covers everything after it."""
    method = method.encode() if isinstance(method, str) else method
    body = struct.pack('>I', seqno) + s2(method) + struct.pack('>I', len(params)) + b''.join(params)
    pkt = struct.pack('>I', len(body)) + body
    if auth is not None:
        pkt = struct.pack('>I', len(auth)) + auth + pkt
    return pkt


def resp(seqno, status, rest=b''):
    return struct.pack('>II', seqno, status) + rest


def resp_long(seqno, value):
    return resp(seqno, 0, s2(b'long') + struct.pack('>Q', value))


def resp_status(seqno, name=FSTATUS, last=True):
    body = struct.pack('>H', 0o644) + s2(b'file.txt') + struct.pack('>QBHQQQH', 4096, 0, 3, 134217728,
                                                                      1700000000000, 1700000001000, 0o755)
    body += s1(b'hdfsuser') + s1(b'supergroup')
    return resp(seqno, 0, s2(name) + s2(name) + body)


def block(i=0):
    """Block info, 150 octets (the dissector's reassembly length rule)."""
    b = s1(b'') + s1(b'') + s1(b'') + s1(b'')                    # token identifier, password, kind, service
    b += bytes([0]) + struct.pack('>Q', 0)                       # corrupt, offset
    b += struct.pack('>QQQ', 1073741825 + i, 134217728, 1001)    # block id, size, generation
    b += struct.pack('>I', 1)                                    # locations
    b += s2(b'192.0.2.10:50010') + s2(b'DS-1234-192.0.2-500100')
    b += struct.pack('>HH', 50075, 8020)                         # info port, ipc port
    b += struct.pack('>QQQQ', 1 << 40, 1 << 30, 1 << 39, 1700000002000)
    b += struct.pack('>I', 3)                                    # active connections
    b += s1(b'/default-rack') + s1(b'node1') + s1(b'Normal')
    assert len(b) == 150, len(b)
    return b


def resp_blocks(seqno, n):
    """LocatedBlocks response: 115 octets + 150 per block; the
    dissector derives the PDU length for reassembly from this rule."""
    r = resp(seqno, 0, s2(LOCATED) + s2(LOCATED) + struct.pack('>QBI', n * 134217728, 0, n))
    assert len(r) == 115, len(r)
    return r + b''.join(block(i) for i in range(n))


def resp_other(seqno, cls=b'org.apache.hadoop.io.Text', val=b'ok'):
    return resp(seqno, 0, s2(cls) + s2(cls) + s2(val))


def main(out):
    c = Cap()
    f = Flow(c)
    f.handshake()                                                # 1-3
    # connection header "hrpc", version 4, authentication method
    f.seg(True, b'hrpc' + bytes([4, 80]))                        # 4
    # first call, with authentication bytes (placeholder)
    f.seg(True, call(0, 'getProtocolVersion',
                     [param('java.lang.String', b'org.apache.hadoop.hdfs.protocol.ClientProtocol'),
                      param('long', struct.pack('>Q', 61))], auth=b'PLACEHOLDER-AUTH'))   # 5
    f.seg(False, resp_long(0, 61))                               # 6
    f.seg(True, call(1, 'getFileInfo', [param('java.lang.String', b'/user/test/file.txt')]))  # 7
    f.seg(False, resp_status(1))                                 # 8
    f.seg(True, call(2, 'getBlockLocations', [param('java.lang.String', b'/user/test/file.txt'),
                                              param('long', struct.pack('>Q', 0)),
                                              param('long', struct.pack('>Q', 1 << 20))]))  # 9
    f.seg(False, resp_blocks(2, 2))                              # 10 two blocks, one segment
    f.seg(True, call(3, 'mkdirs', [param('java.lang.String', b'/user/test/dir'),
                                   s2(FSPERM) + s2(FSPERM) + struct.pack('>H', 0o755),   # type, value, permission
                                   param('boolean', b'\x01')]))   # 11 FsPermission value
    f.seg(False, resp_other(3, b'java.lang.Boolean', b'\x01'))    # 12 other response
    f.seg(True, call(4, 'setReplication', [param('java.lang.String', b'/user/test/file.txt'),
                                           param('short', struct.pack('>H', 3))]))   # 13 short
    f.seg(False, resp_other(4))                                   # 14
    f.seg(True, call(5, 'setSafeMode', [param('int', struct.pack('>I', 1)),
                                        param('char', struct.pack('>H', 2)),
                                        param('byte', struct.pack('>B', 3)),
                                        param('float', struct.pack('>I', 4)),
                                        param('double', struct.pack('>Q', 5))]))      # 15 numeric types
    f.seg(False, resp(5, 1))                                      # 16 error status
    f.seg(True, call(6, 'sendHeartbeat', []))                     # 17 heartbeat, parameters not parsed
    f.seg(True, call(7, 'datanodeprotocol.sendHeartbeat',
                     [param('long', struct.pack('>Q', 9))]))      # 18 longer name ending in sendHeartbeat
    f.seg(True, call(8, 'sendHeartbeats', [param('long', struct.pack('>Q', 9))]))   # 19 near miss: dissected
    f.seg(False, resp(6, 0xffffffff))                             # 20 fatal status
    # the reproducers of the global over-read (type length larger than the literal)
    t1 = b'long\0' + b'A' * 195
    body = struct.pack('>I', 7) + s2(b'mkdir') + struct.pack('>I', 1) + s2(t1) + b'\0' * 8
    f.seg(True, struct.pack('>I', len(body)) + body)              # 21 reproducer 1
    v2 = FSPERM + b'\0' + b'B' * 255
    body = struct.pack('>I', 7) + s2(b'mkdir') + struct.pack('>I', 1) + s2(b'x') + s2(v2) + b'\0\0'
    f.seg(True, struct.pack('>I', len(body)) + body)              # 22 reproducer 2
    # a response of 1615 octets: the first segment is exactly 1448 octets
    r = resp_blocks(9, 10)
    f.seg(True, call(9, 'getBlockLocations', [param('java.lang.String', b'/user/test/big.bin')]))   # 23
    f.seg(False, r[:1448])                                        # 24
    f.seg(False, r[1448:])                                        # 25
    # a response of 1465 octets: the first segment is 1321 octets
    r = resp_blocks(10, 9)
    f.seg(True, call(10, 'getBlockLocations', [param('java.lang.String', b'/user/test/mid.bin')]))  # 26
    f.seg(False, r[:1321])                                        # 27
    f.seg(False, r[1321:])                                        # 28
    f.seg(True, b'', 0x11)                                        # 29 FIN
    c.write(os.path.join(out, 'hdfs-coverage.pcap'))

    # malformed
    m = Cap()
    g = Flow(m, 40001)
    g.seg(True, b'hrpc')                                          # truncated connection header
    g.seg(True, struct.pack('>I', 0x7fffffff) + b'abcd')           # authentication length too large
    g.seg(True, call(1, 'getFileInfo', [param('java.lang.String', b'/x')])[:-5])     # cut inside the value
    g.seg(True, call(2, 'getFileInfo', [param('java.lang.String', b'/x')] * 3))      # more parameters announced than present
    body = struct.pack('>I', 3) + s2(b'f') + struct.pack('>I', 2) + s2(b'java.lang.String') + s2(b'a')
    g.seg(True, struct.pack('>I', len(body)) + body)               # parameter count too large
    g.seg(True, b'\0\0\0\x08\0\0\0\x01\0\xff')                     # method name longer than the packet
    g.seg(False, resp(1, 0)[:6])                                  # response cut in the header
    g.seg(False, resp(1, 0))                                      # no body
    g.seg(False, resp(2, 0) + s2(b'long') + b'\0\0')               # short long
    g.seg(False, resp(3, 0, s2(b'abc') + s2(b'x' * 40)))           # names cut
    g.seg(False, resp_status(4)[:-9])                              # file status cut in the owner
    g.seg(False, resp_blocks(5, 2)[:200])                          # located blocks cut in the first block
    g.seg(False, resp_blocks(6, 1)[:-3])                           # last block cut
    g.seg(False, resp_other(7)[:-1])                               # value shorter than announced
    # the reassembly length rule with segment lengths 1448 and 1321 and a block count of 0
    g.seg(False, resp_blocks(8, 0) + b'\0' * (1448 - 115))
    g.seg(False, resp_blocks(9, 0) + b'\0' * (1321 - 115))
    # huge block count with 1448 octets: asks for a very long reassembly
    r = resp_blocks(10, 9)
    g.seg(False, r[:111] + struct.pack('>I', 0xffff) + r[115:1448])
    m.write(os.path.join(out, 'hdfs-coverage-malformed.pcap'))


main(sys.argv[1])
