#!/usr/bin/env python3
# Generates test/captures/udt_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generate the UDT coverage captures. Usage: mkudt.py <outdir>
# Ethernet/IPv4/UDP frames; the UDP heuristic recognises a handshake
# (version 4, type STREAM or DGRAM) and then owns the conversation.
import os
import struct
import sys

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def udp(src, dst, sp, dp, pl, ident=1):
    u = struct.pack('>HHHH', sp, dp, 8 + len(pl), 0) + pl
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(u), ident, 0, 64, 17, 0,
                     bytes(src), bytes(dst))
    ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
    eth = bytes.fromhex('020000000002' '020000000001') + b'\x08\x00'
    if src > dst:
        eth = bytes.fromhex('020000000001' '020000000002') + b'\x08\x00'
    return eth + ip + u

def write(fn, pkts, t0=1700000000):
    with open(fn, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, p in enumerate(pkts):
            pk, orig = p if isinstance(p, tuple) else (p, len(p))
            f.write(struct.pack('<IIII', t0 + i // 4, (i % 4) * 100000, len(pk), orig))
            f.write(pk)

A, B = [192, 0, 2, 1], [192, 0, 2, 2]

def ctl(typ, info, ts, sid, body=b''):
    return struct.pack('>IIII', 0x80000000 | (typ << 16), info, ts, sid) + body

def data(seq, msg, ts, sid, payload, first=1, last=1, order=1):
    m = (first << 31) | (last << 30) | (order << 29) | msg
    return struct.pack('>IIII', seq & 0x7fffffff, m, ts, sid) + payload

def hs(ver, typ, isn, mtu=1500, win=8192, req=1, sid=7, cookie=0x1234abcd, ip=None):
    ip = ip or (bytes([192, 0, 2, 1]) + bytes(12))
    return ctl(0, 0, 100, 0, struct.pack('>IIIIIiII', ver, typ, isn, mtu, win, req, sid, cookie) + ip)

def conv(pk, a, b, sp, dp, isn, sid, tag):
    """One UDT connection: handshakes, data, acks, naks, shutdown."""
    def fw(pl):
        pk.append(udp(a, b, sp, dp, pl, len(pk) + 1))
    def bw(pl):
        pk.append(udp(b, a, dp, sp, pl, len(pk) + 1))
    fw(hs(4, 1, isn, req=1, sid=sid))                       # induction
    bw(hs(4, 1, isn, req=-1, sid=sid + 1, cookie=0xfeedf00d))
    fw(hs(4, 1, isn, req=1, sid=sid, cookie=0xfeedf00d))    # conclusion
    s = isn
    for i in range(6):                                      # data, all indicator combos
        fw(data(s + i, i + 1, 1000 + i, sid + 1, b'payload %d' % i * (i + 1),
                first=i & 1, last=(i >> 1) & 1, order=(i >> 2) & 1))
    bw(ctl(1, 0, 2000, sid, b''))                           # keepalive
    bw(ctl(2, 5, 2001, sid, struct.pack('>I', s + 3)))      # light ack, 20 bytes
    bw(ctl(2, 6, 2002, sid, struct.pack('>IIII', s + 4, 5000, 250, 8192)))   # 32 bytes
    bw(ctl(2, 7, 2003, sid, struct.pack('>IIIIII', s + 6, 5000, 250, 8192, 100, 1000)))  # 40
    fw(ctl(6, 7, 2004, sid))                                # ack2
    # NAK: single, range, mixed, a range cut off at the end, and a list
    # longer than the 8 entries the Info column shows
    bw(ctl(3, 0, 2005, sid, struct.pack('>I', s + 2)))
    bw(ctl(3, 0, 2006, sid, struct.pack('>II', 0x80000000 | (s + 1), s + 3)))
    bw(ctl(3, 0, 2007, sid, struct.pack('>IIII', s + 5, 0x80000000 | (s + 1), s + 2, s + 9)))
    bw(ctl(3, 0, 2008, sid, struct.pack('>II', s + 4, 0x80000000 | (s + 7))))
    bw(ctl(3, 0, 2009, sid, b''.join(struct.pack('>I', s + 10 + k) for k in range(12))))
    bw(ctl(3, 0, 2010, sid, b''.join(struct.pack('>II', 0x80000000 | (s + 20 + 4 * k), s + 22 + 4 * k)
                                      for k in range(6))))
    bw(ctl(3, 0, 2011, sid, b''))                           # NAK with no entries
    fw(ctl(4, 0, 2012, sid))                                # type 4: unknown
    fw(ctl(0x7ff, 0, 2013, sid))
    fw(ctl(5, 0, 2014, sid))                                # shutdown
    fw(data(s + 6, 0x1fffffff, 3000, sid + 1, b''))         # data, empty payload

def main(outdir):
    os.makedirs(outdir, exist_ok=True)
    pk = []
    # connection 1: ISN 1000, relative sequence numbers
    conv(pk, A, B, 9000, 9001, 1000, 7, 'rel')
    # connection 2: ISN 0, the numbers equal the relative ones; a datagram
    # handshake; peer address field with an IPv6 address
    pk.append(udp(A, B, 9010, 9011, hs(4, 2, 0, ip=bytes.fromhex('20010db8000000000000000000000001')), 100))
    pk.append(udp(A, B, 9010, 9011, data(5, 1, 1, 8, b'dgram'), 101))
    pk.append(udp(B, A, 9011, 9010, ctl(2, 1, 2, 8, struct.pack('>I', 6)), 102))
    pk.append(udp(B, A, 9011, 9010, ctl(3, 0, 3, 8, struct.pack('>II', 0x80000000 | 2, 4)), 103))
    # connection 3: ISN near the top of the range, so data after the
    # wrap-around is shown relative to it
    pk.append(udp(A, B, 9020, 9021, hs(4, 1, 0x7ffffffe), 104))
    pk.append(udp(A, B, 9020, 9021, data(0x7ffffffe, 1, 1, 9, b'before wrap'), 105))
    pk.append(udp(A, B, 9020, 9021, data(0x7fffffff, 2, 2, 9, b'last'), 106))
    pk.append(udp(A, B, 9020, 9021, data(0, 3, 3, 9, b'wrapped'), 107))
    pk.append(udp(B, A, 9021, 9020, ctl(3, 0, 4, 9, struct.pack('>II', 0x80000000 | 0x7ffffffe, 1)), 108))
    # handshake with only 24 captured bytes of header after the version/type
    # fields cannot be tested here (ISN would be cut): see the malformed capture.
    # Datagrams the heuristic rejects stay plain UDP: too short, not a
    # handshake, version 3, handshake type 3
    pk.append(udp(A, B, 9030, 9031, hs(4, 1, 5)[:20], 109))
    pk.append(udp(A, B, 9032, 9033, data(1, 1, 1, 1, b'x' * 20), 110))
    pk.append(udp(A, B, 9034, 9035, hs(3, 1, 5), 111))
    pk.append(udp(A, B, 9036, 9037, hs(4, 3, 5), 112))
    pk.append(udp(A, B, 9038, 9039, ctl(1, 0, 1, 1, bytes(12)), 113))   # keepalive without handshake
    # port 9100 has no handshake: UDT only through Decode As (-d udp.port==9100,udt),
    # so no sequence number is relative
    pk.append(udp(A, B, 9100, 9101, data(77, 1, 1, 3, b'decode as data'), 114))
    pk.append(udp(B, A, 9101, 9100, ctl(2, 1, 2, 3, struct.pack('>I', 78)), 115))
    pk.append(udp(B, A, 9101, 9100, ctl(3, 0, 3, 3, struct.pack('>I', 77)), 116))
    pk.append(udp(A, B, 9100, 9101, hs(4, 1, 500), 117))   # the handshake itself, as plain UDT
    write(os.path.join(outdir, 'udt-coverage.pcap'), pk)

    bad = []
    # control packets cut short, snaplen-truncated frames, a handshake
    # that is cut before the ISN (the heuristic needs 24 bytes)
    h = hs(4, 1, 1000)
    bad.append(udp(A, B, 9500, 9501, h, 1))                          # recognised
    for n, port in ((8, 0), (14, 1), (30, 2), (50, 3)):
        bad.append(udp(A, B, 9500, 9501, h[:n], 2 + port))           # cut handshakes
    bad.append(udp(A, B, 9500, 9501, ctl(2, 1, 1, 1, b'\0\0'), 10))  # ack cut in the seqno
    bad.append(udp(A, B, 9500, 9501, ctl(2, 1, 1, 1, struct.pack('>II', 5, 6)), 11))   # ack, 24 bytes
    bad.append(udp(A, B, 9500, 9501, ctl(2, 1, 1, 1, struct.pack('>IIII', 5, 6, 7, 8))[:34], 12))
    bad.append(udp(A, B, 9500, 9501, ctl(3, 0, 1, 1, struct.pack('>II', 0x80000000 | 5, 9))[:20], 13))
    bad.append(udp(A, B, 9500, 9501, ctl(3, 0, 1, 1, b'\x80\x00'), 14))
    bad.append(udp(A, B, 9500, 9501, b'\x80\x03', 15))
    bad.append(udp(A, B, 9500, 9501, data(1, 1, 1, 1, b'')[:10], 16))
    # captured length shorter than the reported length (snaplen): NAK
    # and handshake
    nak = udp(A, B, 9500, 9501, ctl(3, 0, 1, 1, struct.pack('>IIIII', 5, 6, 7, 8, 9)), 17)
    bad.append((nak[:-6], len(nak)))
    # the heuristic with a handshake cut at 24..27 bytes: no ISN stored
    pk2 = udp(A, B, 9700, 9701, h[:26], 18)
    bad.append((pk2, len(pk2) + 38))
    bad.append(udp(A, B, 9700, 9701, data(1000, 1, 1, 1, b'after cut'), 19))
    # Pass-dependent state (not fixed on the branch: UDT keeps the
    # conversation state in the conversation, not per frame). A data
    # frame before the handshake: one pass shows UDP, -2 shows UDT data.
    bad.append(udp(A, B, 9400, 9401, data(1005, 7, 0, 1, b'hello'), 20))
    bad.append(udp(A, B, 9400, 9401, hs(4, 1, 1000), 21))
    bad.append(udp(A, B, 9400, 9401, data(1006, 7, 0, 1, b'world'), 22))
    write(os.path.join(outdir, 'udt-coverage-malformed.pcap'), bad)

main(sys.argv[1] if len(sys.argv) > 1 else '.')
