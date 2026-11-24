#!/usr/bin/env python3
# Generates test/captures/fractalgeneratorprotocol_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the FractalGeneratorProtocol
dissector (packet-fractalgeneratorprotocol.c).

FGP is carried in SCTP DATA chunks with payload protocol identifier 32
(FGP_PAYLOAD_PROTOCOL_ID) or the legacy value 0x29097601, both
registered in the "sctp.ppi" table. A message has a 1 octet type, 1 octet
flags, 2 octet length and the value: a Parameter message (type 1) holds
width, height, max iterations, algorithm id and five doubles; a Data
message (type 2) holds start x, start y, points and points * 4 octets of
data. Every packet is built with struct; no captured traffic is used.

Usage: mkfractalgeneratorprotocol.py <output directory>
"""
import os
import socket
import struct
import sys

PPI = 32
PPI_LEGACY = 0x29097601


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, (ts, fr) in enumerate(frames):
            sec = int(ts)
            usec = int(round((ts - sec) * 1000000))
            f.write(struct.pack('<IIII', 1700000000 + sec, usec, len(fr), len(fr)))
            f.write(fr)


def sctp_pkt(tsn, ppi, msg, sport=9910, dport=9911, flags=3, sid=0, ssn=0):
    chunk = struct.pack('!BBHIHHI', 0, flags, 16 + len(msg), tsn, sid, ssn, ppi) + msg
    while len(chunk) % 4:
        chunk += b'\0'
    sctp = struct.pack('!HHII', sport, dport, 1, 0) + chunk
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(sctp), tsn & 0xffff, 0, 64, 132, 0,
                     socket.inet_aton('192.0.2.1'), socket.inet_aton('192.0.2.2'))
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    eth = bytes([2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1]) + b'\x08\x00'
    return eth + ip + sctp


def param(w, h, it, alg, c1r, c1i, c2r, c2i, n, flags=0):
    v = struct.pack('!IIII', w, h, it, alg) + struct.pack('!ddddd', c1r, c1i, c2r, c2i, n)
    return struct.pack('!BBH', 1, flags, 4 + len(v)) + v


def data(x, y, points, buf=None, flags=0, length=None):
    if buf is None:
        buf = bytes((i * 7) & 0xff for i in range(points * 4))
    v = struct.pack('!III', x, y, points) + buf
    return struct.pack('!BBH', 2, flags, 4 + len(v) if length is None else length) + v


def main(out):
    good = []
    t = [0.0]

    def add(ppi, msg, dt=0.5, **kw):
        t[0] += dt
        good.append((t[0], sctp_pkt(len(good) + 1, ppi, msg, **kw)))

    # 1-2: Mandelbrot parameter, new and legacy PPI
    add(PPI, param(640, 480, 100, 1, -2.0, -1.5, 1.0, 1.5, 0.0))
    add(PPI_LEGACY, param(1024, 768, 255, 1, -2.5, -1.0, 1.0, 1.0, 0.0), 0.25)
    # 3: Mandelbrot-N
    add(PPI, param(800, 600, 500, 2, -1.5, -1.5, 1.5, 1.5, 3.0, flags=0x03), 1.0)
    # 4: algorithm id without a name
    add(PPI, param(16, 16, 10, 99, 0.0, 0.0, 1.0, 1.0, 2.0), 0.1)
    # 5-7: data with 0, 1 and 8 points (flags set on one)
    add(PPI, data(0, 0, 0), 0.7)
    add(PPI, data(10, 20, 1), 0.3, sid=1, ssn=1)
    add(PPI_LEGACY, data(100, 200, 8, flags=0x80), 2.0)
    # 8: unknown message type, no dissected value
    add(PPI, struct.pack('!BBH', 0x55, 0, 8) + b'\xde\xad\xbe\xef', 0.2)
    # 9: big data message (many points, spread over an unfragmented chunk)
    add(PPI, data(0, 0, 200), 0.4)
    # 10: small data message on another stream
    add(PPI, data(5, 5, 4), 0.1, ssn=2)
    # 11: Parameter message, then the matching data after a gap in time
    add(PPI, param(320, 200, 50, 1, -0.5, -0.5, 0.5, 0.5, 0.0), 3.0)
    # 12: the reproducer of the fixed bug in the malformed capture only
    pcap(os.path.join(out, 'fractalgeneratorprotocol-coverage.pcap'), good)

    bad = []
    # Points = 0x4001: buffer_length*4 = 0x10004 was truncated to 4
    bad.append((0.1, sctp_pkt(1, PPI_LEGACY,
        struct.pack('!BBH', 2, 0, 24) + struct.pack('!III', 1, 2, 0x4001) + b'\x11' * 8)))
    # huge points count: bigger than INT_MAX
    bad.append((0.2, sctp_pkt(2, PPI,
        struct.pack('!BBH', 2, 0, 24) + struct.pack('!III', 1, 2, 0xffffffff) + b'\x22' * 8)))
    # parameter message cut after the algorithm id
    bad.append((0.3, sctp_pkt(3, PPI, param(1, 2, 3, 1, 0, 0, 0, 0, 0)[:20])))
    # data message cut inside the header
    bad.append((0.4, sctp_pkt(4, PPI, data(1, 2, 1)[:9])))
    # message of 3 octets: length field missing
    bad.append((0.5, sctp_pkt(5, PPI, b'\x01\x00\x00')))
    pcap(os.path.join(out, 'fractalgeneratorprotocol-coverage-malformed.pcap'), bad)


if __name__ == '__main__':
    main(sys.argv[1])
