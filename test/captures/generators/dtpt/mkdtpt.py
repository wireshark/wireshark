#!/usr/bin/env python3
# Generates test/captures/dtpt_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the DTPT dissector
(packet-dtpt.c, Microsoft ActiveSync DeskTop PassThrough).

DTPT runs over TCP port 5721. Control messages are exactly 20 octets
(LookupBegin/Next/End) or 36 octets (Connect), version 1. A
LookupBeginRequest sets the DTPT conversation dissector on its TCP
conversation, which then also decodes the WSAQUERYSET data blocks
(raw size 60) that follow the LookupBeginRequest and LookupNextResponse
messages. Every packet is built from scratch with struct; no captured
traffic is used.

Usage: mkdtpt.py <output directory>

Writes:
  dtpt-coverage.pcap            a name lookup with every control
                                message and query sets with strings,
                                GUIDs, protocols, addresses and a blob;
                                Connect requests and responses; segments
                                that are not DTPT
  dtpt-coverage-malformed.pcap  query sets cut short
"""

import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import struct
import uuid

from pktlib import TcpConn, pcap

PORT = 5721
HANDLE = 0x0123456789abcdef


def ctl20(mtype, b4_12=bytes(8), v12=0, v16=0, version=1):
    return struct.pack('<BB2s8sII', version, mtype, b'\0\0', b4_12, v12, v16)


def handle():
    return struct.pack('<Q', HANDLE)


def connect(mtype, family, port, addr, error):
    sa = struct.pack('<I', family) + bytes(4) + struct.pack('!H', port) + bytes(addr) + bytes(16)
    return struct.pack('<BB', 1, mtype) + sa + struct.pack('<I', error)


def wstring(s):
    b = s.encode('utf-16-le')
    return struct.pack('<I', len(b)) + b + bytes(-len(b) % 4)


def guid(u):
    if u is None:
        return struct.pack('<I', 0)
    return struct.pack('<I', 16) + uuid.UUID(u).bytes_le


SVCID_INET_HOSTADDRBYNAME = '0002a803-0000-0000-c000-000000000046'
OTHER_GUID = '12345678-9abc-def0-1122-334455667788'


def sockaddr_in(port, addr, family=2):
    return struct.pack('<I', 16) + struct.pack('<H', family) + struct.pack('!H', port) + bytes(addr) + bytes(8)


def queryset(name='', cls=None, comment='', provider=None, context='', protocols=(),
             query='', addrs=(), blob=None, version_ptr=0):
    qs = struct.pack('<I', 60)
    # WSAQUERYSET with pointers (only presence matters) and counts
    qs += struct.pack('<15I', 60, 1 if name else 0, 2 if cls else 0, version_ptr,
                      3 if comment else 0, 12, 4 if provider else 0, 5 if context else 0,
                      len(protocols), 6 if protocols else 0, 7 if query else 0,
                      len(addrs), 8 if addrs else 0, 0x10, 9 if blob else 0)
    qs += wstring(name) + guid(cls) + wstring(comment) + guid(provider) + wstring(context)
    qs += struct.pack('<I', len(protocols))
    if protocols:
        qs += struct.pack('<I', 8 * len(protocols))
        for fam, proto in protocols:
            qs += struct.pack('<II', fam, proto)
    qs += wstring(query)
    qs += struct.pack('<I', len(addrs))
    if addrs:
        qs += struct.pack('<I', 24 * len(addrs))
        for i, (local, remote, stype, proto) in enumerate(addrs):
            qs += struct.pack('<6I', 0x100 + i, 16, 0x200 + i, 16, stype, proto)
        for local, remote, stype, proto in addrs:
            qs += local + remote
    if blob is None:
        qs += struct.pack('<I', 0)
    else:
        qs += struct.pack('<III', 8, len(blob), 0x300)
        qs += struct.pack('<I', len(blob)) + blob
    return qs


def main_frames():
    f = []
    c = TcpConn(1035, PORT)
    # 1-2: LookupBeginRequest with every control flag, then the query set
    q1 = queryset(name='www.example.com', cls=SVCID_INET_HOSTADDRBYNAME,
                  protocols=((2, 6), (2, 17), (2, 0)))
    f.append(c.send(ctl20(9, bytes(8), 0xbfff, len(q1))))
    f.append(c.send(q1))
    # 3: LookupBeginResponse with the handle
    f.append(c.send(ctl20(10, handle(), 0, 0), True))
    # 4-6: LookupNextRequest, LookupNextResponse, the result query set
    q2 = queryset(name='www.example.com', cls=SVCID_INET_HOSTADDRBYNAME,
                  comment='synthetic', provider=OTHER_GUID, context='ctx',
                  protocols=((2, 6),), query='q=1',
                  addrs=((sockaddr_in(0, (0, 0, 0, 0)), sockaddr_in(80, (192, 0, 2, 80)), 1, 6),
                         (sockaddr_in(0, (0, 0, 0, 0)), sockaddr_in(53, (192, 0, 2, 53)), 2, 17),
                         (sockaddr_in(0, (0, 0, 0, 0), 23), sockaddr_in(0, (0, 0, 0, 0), 23), 3, 0)),
                  blob=bytes(range(20)), version_ptr=0x44)
    f.append(c.send(ctl20(11, handle(), 0, 4096)))
    f.append(c.send(ctl20(12, bytes(8), 0, len(q2)), True))
    f.append(c.send(q2, True))
    # 7-8: LookupNextRequest and a WSASERVICE_NOT_FOUND response
    f.append(c.send(ctl20(11, handle(), 0, 4096)))
    f.append(c.send(ctl20(12, bytes(8), 10108, 0), True))
    # 9: LookupEndRequest
    f.append(c.send(ctl20(13, handle())))
    # 10: a query set with every string empty and a 4 octet blob
    # descriptor of size 0, then trailing octets (data)
    q3 = queryset(cls=OTHER_GUID)
    q3 = q3[:-4] + struct.pack('<II', 4, 0) + b'trailer'
    f.append(c.send(q3, True))
    # 11: a segment in the conversation that is neither a control
    # message nor a query set (data)
    f.append(c.send(b'\x01\x09' + bytes(10)))
    # 12-13: ConnectRequest and ConnectResponseOK on another connection
    c = TcpConn(1036, PORT)
    f.append(c.send(connect(1, 2, 80, (192, 0, 2, 80), 0)))
    f.append(c.send(connect(0x5a, 2, 80, (192, 0, 2, 80), 0), True))
    # 14-15: ConnectRequest for another family and ConnectResponseERR
    c = TcpConn(1037, PORT)
    f.append(c.send(connect(1, 23, 443, (0, 0, 0, 0), 0)))
    f.append(c.send(connect(0x5b, 2, 443, (192, 0, 2, 81), 10060), True))
    # 16-19: not DTPT: version 2, unknown type, wrong lengths
    c = TcpConn(1038, PORT)
    f.append(c.send(ctl20(9, version=2)))
    f.append(c.send(ctl20(99)))
    f.append(c.send(ctl20(9) + b'\0'))
    f.append(c.send(connect(1, 2, 80, (192, 0, 2, 80), 0)[:30]))
    return f


def malformed_frames():
    f = []
    c = TcpConn(1040, PORT)
    f.append(c.send(ctl20(9, bytes(8), 0x10, 100)))
    q = queryset(name='cut', cls=SVCID_INET_HOSTADDRBYNAME, protocols=((2, 6),))
    f.append(c.send(q[:90]))
    q = queryset(name='a', addrs=((sockaddr_in(0, (0, 0, 0, 0)), sockaddr_in(80, (192, 0, 2, 80)), 1, 6),))
    f.append(c.send(q[:-30], True))
    q = queryset(blob=bytes(10))
    f.append(c.send(q[:-6], True))
    # a wstring length beyond the segment
    q = struct.pack('<I', 60) + struct.pack('<15I', 60, *([0] * 14)) + struct.pack('<I', 0x7fffffff)
    f.append(c.send(q, True))
    return f


if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcap(os.path.join(out, 'dtpt-coverage.pcap'), main_frames())
    pcap(os.path.join(out, 'dtpt-coverage-malformed.pcap'), malformed_frames())
