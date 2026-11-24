#!/usr/bin/env python3
# Generates test/captures/dpnet_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the DPNET dissector
(packet-dpnet.c, DirectPlay 8 protocol).

DPNET runs over UDP port 6073 (registered by default). A packet starting
with 0 is an enumeration query (application GUID or all applications,
optional user data) or response (session description with flags,
players, offsets and sizes of the session name and application data
that follow the fixed part, instance and application GUIDs); otherwise
the first octet is the command: with bit 0 set a data frame (DFrame),
without it a control frame (CFrame: CONNECT, CONNECTED,
CONNECTED_SIGNED, HARD_DISCONNECT, SACK). Every packet is built from
scratch with struct; signatures and secrets are placeholder values.

Usage: mkdpnet.py <output directory>

Writes:
  dpnet-coverage.pcap            enumeration queries and responses, every
                                 control frame with every SACK mask, data
                                 frames, the clean reproducer frames
  dpnet-coverage-malformed.pcap  reproducer offsets and sizes beyond the
                                 packet, frames cut short
"""

import os
import socket
import struct
import sys
import uuid

PORT = 6073
HOST = '192.0.2.1'
PEER = '192.0.2.2'
APP = uuid.UUID('00112233-4455-6677-8899-aabbccddeeff')
INST = uuid.UUID('a1b2c3d4-e5f6-4789-8abc-def012345678')


def pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def udp(payload, rev=False, sport=PORT):
    src, dst = (PEER, HOST) if rev else (HOST, PEER)
    u = struct.pack('>HHHH', sport, PORT, 8 + len(payload), 0) + payload
    ph = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack('>BBH', 0, 17, len(u))
    u = u[:6] + struct.pack('>H', csum(ph + u) or 0xffff) + u[8:]
    h = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(u), 1, 0x4000, 64, 17, 0,
                    socket.inet_aton(src), socket.inet_aton(dst))
    h = h[:10] + struct.pack('>H', csum(h)) + h[12:]
    m = lambda ip: bytes([2, 0, 0, 0, 0, int(ip.split('.')[-1])])
    return m(dst) + m(src) + b'\x08\x00' + h + u


def enum_query(guid=None, data=b'', payload=1):
    p = b'\x00\x02' + struct.pack('<H', payload)
    if guid is not None:
        return p + b'\x01' + guid.bytes_le + data
    return p + b'\x02' + data


def enum_response(flags, maxp, curp, name=None, appdata=None, offsets=None, payload=1):
    """Fixed part (88 octets after the 4 octet header), then the session
    name (UTF-16LE) and the application data; offsets count from the end
    of the header."""
    fixed_len = 88
    tail = b''
    so = ss = ao = asz = 0
    if name is not None:
        nb = name.encode('utf-16-le') + b'\0\0'
        so, ss = fixed_len, len(nb)
        tail += nb
    if appdata is not None:
        ao, asz = fixed_len + len(tail), len(appdata)
        tail += appdata
    if offsets is not None:
        so, ss, ao, asz = offsets
    body = struct.pack('<IIIIII', 0, fixed_len + len(tail), 0x50, flags, maxp, curp)
    body += struct.pack('<II', so, ss) + struct.pack('<IIII', 0, 0, 0, 0)
    body += struct.pack('<II', ao, asz) + INST.bytes_le + APP.bytes_le
    return b'\x00\x03' + struct.pack('<H', payload) + body + tail


def cframe(ctl, rest, cmd=0x80):
    return bytes([cmd, ctl]) + rest


def connect(ctl, msgid, rspid, proto, session, ts):
    return cframe(ctl, struct.pack('<BBIII', msgid, rspid, proto, session, ts))


def sack(flags, retry, nseq, nrcv, ts, masks):
    return cframe(0x06, struct.pack('<BBBBHI', flags, retry, nseq, nrcv, 0, ts) +
                  b''.join(struct.pack('<I', m) for m in masks))


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    f = []
    # 1: reproducer dpnet_misc.pcap frame 1: enum query with an application
    # GUID (little-endian, as DirectPlay sends it) and user data
    f.append(udp(enum_query(APP, b'ud'), sport=40000))
    # 2: enum query for all applications without user data
    f.append(udp(enum_query(None), sport=40000))
    # 3: enum query for all applications with user data
    f.append(udp(enum_query(None, b'\x01\x02\x03\x04', payload=2), sport=40000))
    # 4: enum response with session name and application data, every flag
    f.append(udp(enum_response(0x0001 | 0x0004 | 0x0040 | 0x0080 | 0x0100 | 0x0200 | 0x0400,
                               16, 3, name='Coverage Session', appdata=b'\xaa\xbb\xcc'),
                 rev=True, sport=40000))
    # 5: enum response without session name or application data, no flags
    f.append(udp(enum_response(0, 8, 0), rev=True, sport=40000))
    # 6: enum response with only a session name, peer session with full signing
    f.append(udp(enum_response(0x0400, 4, 4, name='Peer'), rev=True, sport=40000, ))
    # 7: enum response with only application data
    f.append(udp(enum_response(0x0001, 2, 1, appdata=b'\x10\x20'), rev=True, sport=40000))
    # 8: lead 0 with an unknown command 5
    f.append(udp(b'\x00\x05\x01\x00\x99', sport=40000))
    # 9-10: CONNECT and CONNECTED (protocol version 6)
    f.append(udp(connect(0x01, 1, 0, 0x00010006, 0x11223344, 1000)))
    f.append(udp(connect(0x02, 2, 1, 0x00010006, 0x11223344, 1010), rev=True))
    # 11: reproducer frame 4: CONNECT, protocol 0x10006
    f.append(udp(cframe(0x01, bytes([1, 0]) + struct.pack('<III', 0x10006, 5, 6))))
    # 12: CONNECTED_SIGNED with signature, secrets, signing options, echo time
    f.append(udp(cframe(0x03, struct.pack('<BBIII', 3, 2, 0x00010006, 0x11223344, 1020) +
                        struct.pack('>QQQ', 0x0102030405060708, 0x1112131415161718,
                                    0x2122232425262728) + struct.pack('<II', 2, 1234)), rev=True))
    # 13: reproducer frame 5: CONNECTED_SIGNED, zero signature and secrets
    f.append(udp(cframe(0x03, bytes([1, 0]) + struct.pack('<III', 0x10006, 5, 6) + bytes(32))))
    # 14: HARD_DISCONNECT with a signature
    f.append(udp(cframe(0x04, struct.pack('<BBIII', 4, 3, 0x00010005, 0x11223344, 1030) +
                        struct.pack('>Q', 0x3132333435363738))))
    # 15: reproducer frame 6: HARD_DISCONNECT with one octet after the
    # timestamp (no signature)
    f.append(udp(cframe(0x04, bytes([1, 0]) + struct.pack('<III', 0x10006, 5, 6) + b'\x01')))
    # 16: HARD_DISCONNECT without anything after the timestamp, version 0
    f.append(udp(connect(0x04, 5, 4, 0x00010000, 0x11223344, 1040), rev=True))
    # 17: reproducer frame 7: SACK with every mask
    f.append(udp(bytes([0x80, 0x06, 0x1f, 0, 0, 0, 0, 0]) + struct.pack('<IIIII', 1, 2, 3, 4, 5)))
    # 18-22: SACK with no mask, and each mask alone
    f.append(udp(sack(0x00, 0, 1, 1, 2000, [])))
    f.append(udp(sack(0x02, 0, 2, 1, 2001, [0x000000ff]), rev=True))
    f.append(udp(sack(0x04, 1, 3, 2, 2002, [0x0000ff00])))
    f.append(udp(sack(0x08, 0, 4, 3, 2003, [0x00ff0000]), rev=True))
    f.append(udp(sack(0x11, 2, 5, 4, 2004, [0xff000000])))
    # 23: unknown control 0x05
    f.append(udp(cframe(0x05, b'\x00\x01')))
    # 24: control frame with every command bit but data and CFrame
    f.append(udp(bytes([0x7e, 0x01, 1, 0]) + struct.pack('<III', 0x10003, 1, 2)))
    # 25: reproducer frame 8: data frame 0x3f
    f.append(udp(bytes([0x3f, 0, 0, 0])))
    # 26-27: data frames 0x01 and 0xff
    f.append(udp(bytes([0x01, 0x10, 0x00, 0x00]) + b'payload', rev=True))
    f.append(udp(bytes([0xff, 0x11, 0x01, 0x00]) + b'x'))
    pcap(os.path.join(out, 'dpnet-coverage.pcap'), f)

    g = APP
    name = 'Sess'.encode('utf-16-le')
    m = []
    # reproducer dpnet_misc.pcap frames 2 and 3: session offset 0xfffffffc
    # (offset + 4 wrapped to 0), application offset 0xffffffff; session
    # size 0xffffffff
    r = b'\x00\x03\x01\x00' + struct.pack('<IIIIII', 0, 0, 0x50, 0, 4, 1) + \
        struct.pack('<II', 0xfffffffc, 8) + struct.pack('<IIII', 0, 0, 0, 0) + \
        struct.pack('<II', 0xffffffff, 4) + b'\x11' * 16 + g.bytes_le + name
    m.append(udp(r, rev=True))
    r = b'\x00\x03\x01\x00' + struct.pack('<IIIIII', 0, 0, 0x50, 0, 4, 1) + \
        struct.pack('<II', 88, 0xffffffff) + struct.pack('<IIII', 0, 0, 0, 0) + \
        struct.pack('<II', 0, 0) + b'\x11' * 16 + g.bytes_le + name
    m.append(udp(r, rev=True))
    # enum response cut short
    m.append(udp(enum_response(0, 1, 1)[:40], rev=True))
    # enum query with GUID cut short
    m.append(udp(enum_query(APP)[:10]))
    # CONNECTED_SIGNED cut short
    m.append(udp(cframe(0x03, bytes(12))))
    # SACK announcing all masks with none present
    m.append(udp(sack(0x1e, 0, 0, 0, 0, [])))
    # CONNECT without fields, control frame with only the command
    m.append(udp(cframe(0x01, b'')))
    m.append(udp(b'\x80'))
    pcap(os.path.join(out, 'dpnet-coverage-malformed.pcap'), m)


if __name__ == '__main__':
    main()
