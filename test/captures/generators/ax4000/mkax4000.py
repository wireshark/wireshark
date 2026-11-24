#!/usr/bin/env python3
# Generates test/captures/ax4000_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the Spirent AX/4000 Test
Block dissector (packet-ax4000.c).

All packets are built from scratch with struct; no captured traffic is
used. A test set (10.2.0.1) sends 16 octet test blocks to a receiver
(10.2.0.2) directly in IPv4 (protocol 173), over UDP port 3357 and over
a TCP connection to port 3357.

Test block layout (as the dissector reads it): port (1), chassis (1),
fill type (top 2 bits) and index (low 12 bits) (2, big-endian), 2
unused octets, timestamp (4, little-endian, 10 us units), sequence
number (4, little-endian), CRC (2, little-endian).

Usage: mkax4000.py <output directory>

Writes:
  ax4000-coverage.pcap            test blocks over IP, UDP and TCP with
                                  every fill type, the largest index,
                                  sequence number and timestamp
  ax4000-coverage-malformed.pcap  short test blocks (exceptions)
"""

import struct
import sys

PORT = 3357
SENDER = (10, 2, 0, 1)
RECEIVER = (10, 2, 0, 2)


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


def block(port, chassis, fill, index, timestamp, seq, crc):
    return struct.pack('<BB', port, chassis) + struct.pack('>H', fill << 14 | index) + b'\0\0' + \
        struct.pack('<IIH', timestamp, seq, crc)


class Pcap:
    def __init__(self):
        self.frames = []
        self.seq = {}

    def ip(self, proto, payload, src=SENDER, dst=RECEIVER):
        h = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), len(self.frames) + 1, 0, 64,
                        proto, 0, bytes(src), bytes(dst))
        h = h[:10] + struct.pack('>H', csum(h)) + h[12:]
        self.frames.append(b'\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x08\x00' + h + payload)

    def l4(self, proto, hdr, cs_off, payload, src, dst):
        seg = hdr + payload
        c = csum(struct.pack('>4s4sBBH', bytes(src), bytes(dst), 0, proto, len(seg)) + seg)
        if proto == 17:
            c = c or 0xffff
        self.ip(proto, seg[:cs_off] + struct.pack('>H', c) + seg[cs_off + 2:], src, dst)

    def udp(self, payload, sport=40000, dport=PORT, src=SENDER, dst=RECEIVER):
        self.l4(17, struct.pack('>HHHH', sport, dport, 8 + len(payload), 0), 6, payload, src, dst)

    def tcp(self, flags, payload=b'', to_receiver=True, sport=40001):
        src, dst, sp, dp = (SENDER, RECEIVER, sport, PORT) if to_receiver else (RECEIVER, SENDER, PORT, sport)
        key = (sport, to_receiver)
        seq = self.seq.setdefault(key, 1000 if to_receiver else 9000)
        ack = self.seq.setdefault((sport, not to_receiver), 9000 if to_receiver else 1000)
        opts = b'\x02\x04\x05\xb4' if flags & 0x02 else b''  # MSS 1460 on SYN
        hdr = struct.pack('>HHIIBBHHH', sp, dp, seq, ack if flags & 0x10 else 0,
                          (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts
        self.l4(6, hdr, 16, payload, src, dst)
        self.seq[key] = seq + len(payload) + (1 if flags & 0x03 else 0)

    def write(self, path):
        out = [struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)]
        t = 1700000000
        for i, f in enumerate(self.frames):
            out.append(struct.pack('<IIII', t, i * 1000, len(f), len(f)) + f)
        with open(path, 'wb') as fh:
            fh.write(b''.join(out))


def main_capture():
    c = Pcap()
    # 1-4: IP protocol 173, port 1 chassis 1, fill types 0-3, index 1-4
    for fill in range(4):
        c.ip(173, block(1, 1, fill, fill + 1, 100000 * (fill + 1), fill, 0x1000 + fill))
    # 5: largest index (4095), timestamp, sequence number, CRC, port and chassis
    c.ip(173, block(255, 255, 3, 0xfff, 0xffffffff, 0xffffffff, 0xffff))
    # 6: zero everything
    c.ip(173, block(0, 0, 0, 0, 0, 0, 0))
    # 7-10: UDP to port 3357, a stream of sequence numbers on port 2 chassis 3
    for i in range(4):
        c.udp(block(2, 3, 1, 0x123, 123456 + i * 1000, 0x10000 + i, 0xbeef))
    # 11: UDP from port 3357
    c.udp(block(4, 5, 2, 0x800, 1, 2, 3), sport=PORT, dport=40000, src=RECEIVER, dst=SENDER)
    # 12: test block with padding after the 16 octets (shown in the tree)
    c.udp(block(6, 7, 0, 77, 7700000, 77, 0x7777) + b'\0' * 30)
    # 13-20: TCP connection to port 3357: handshake, two blocks, FIN
    c.tcp(0x02)
    c.tcp(0x12, to_receiver=False)
    c.tcp(0x10)
    c.tcp(0x18, block(8, 9, 1, 900, 900000, 0x0a0b0c0d, 0x0102))
    c.tcp(0x10, to_receiver=False)
    c.tcp(0x18, block(8, 9, 1, 901, 901000, 0x0a0b0c0e, 0x0304))
    c.tcp(0x11)
    c.tcp(0x11, to_receiver=False)
    c.tcp(0x10)
    return c


def malformed_capture():
    c = Pcap()
    # 1: three octets over IP protocol 173 (from ayiya_nested.py)
    c.ip(173, b'\x01\x02\x03')
    # 2: block cut in the sequence number, over UDP
    c.udp(block(1, 1, 0, 1, 1, 1, 1)[:12])
    # 3: block missing the CRC
    c.ip(173, block(1, 1, 0, 1, 1, 1, 1)[:14])
    return c


if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    main_capture().write(out + '/ax4000-coverage.pcap')
    malformed_capture().write(out + '/ax4000-coverage-malformed.pcap')
