#!/usr/bin/env python3
# Generates test/captures/enttec_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the ENTTEC dissector
(packet-enttec.c).

ENTTEC runs on UDP port 3333 (Poll, Poll Reply, Ack/nAck, DMX Data,
Reset) and TCP port 3333 (Config), both registered by default. A DMX
Data packet carries universe, start code, data type (uncompressed,
channel+value or RLE compressed) and a 16 bit size. Every packet is
built from scratch with struct; no captured traffic is used.

Usage: mkenttec.py <output directory>

Writes:
  enttec-coverage.pcap            every packet type, every data type,
                                  RLE runs and escapes, sizes over 512
  enttec-coverage-malformed.pcap  packets cut short
"""

import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import struct

from pktlib import pcap, udp_frame, TcpConn  # noqa: E402

PORT = 3333


def esdd(universe, start, typ, size, data):
    return b'ESDD' + struct.pack('!BBBH', universe, start, typ, size) + data


def u(payload, rev=False, ident=1):
    return udp_frame(40000, PORT, payload, rev=rev, ident=ident) if not rev else \
        udp_frame(PORT, 40000, payload, rev=True, ident=ident)


def main_frames():
    F = []
    # 1: Poll
    F.append(u(b'ESPP' + b'\x01'))
    # 2: Poll Reply: MAC, node type, version, switch, name, option, TOS, TTL
    F.append(u(b'ESPR' + bytes.fromhex('020000000002') + struct.pack('!HBB', 0x0102, 3, 0x0f)
               + b'DMXNODE-01' + bytes([0x01, 0x10, 64]), rev=True))
    # 3: Ack/nAck
    F.append(u(b'ESAP', rev=True))
    # 4: Reset
    F.append(u(b'ESZZ'))
    # 5: uncompressed DMX, 40 channels: ramps through 0..255 (incl. 255 -> "FL")
    vals = bytes([0, 1, 2, 127, 128, 254, 255, 255] + [i * 6 for i in range(32)])
    F.append(u(esdd(1, 0, 0x01, len(vals), vals)))
    # 6: uncompressed DMX, the full universe of 512 channels
    F.append(u(esdd(2, 0, 0x01, 512, bytes(i & 0xff for i in range(512)))))
    # 7: uncompressed DMX with a size over 512 (clamped to 512)
    F.append(u(esdd(3, 0, 0x01, 600, bytes((i * 3) & 0xff for i in range(600)))))
    # 8: Channel+Value data (shown only as bytes)
    F.append(u(esdd(4, 0, 0x02, 6, bytes([0, 1, 0xff, 0, 2, 0x80]))))
    # 9: RLE: a run (0xFE count value), escapes (0xFD value) and literals
    rle = bytes([0xFE, 20, 0x80, 0xFD, 0xFE, 0xFD, 0xFD, 0x10, 0x20, 0x30, 0xFE, 5, 0xff, 0x40])
    F.append(u(esdd(5, 0, 0x04, len(rle), rle)))
    # 10: RLE that expands to the full 512 channels and has bytes left over
    rle = bytes([0xFE, 255, 0x11, 0xFE, 255, 0x22, 0xFE, 10, 0x33, 0x44, 0x55])
    F.append(u(esdd(6, 0, 0x04, len(rle), rle)))
    # 11: RLE with a run of count 0
    rle = bytes([0xFE, 0, 0x99, 0x01, 0x02])
    F.append(u(esdd(7, 0, 0x04, len(rle), rle)))
    # 12: unknown data type (bytes only), non-zero start code
    F.append(u(esdd(8, 0xcc, 0x07, 4, b'\x01\x02\x03\x04')))
    # 13: DMX with size 0
    F.append(u(esdd(9, 0, 0x01, 0, b'')))
    # 14: TCP Config packet (only the header is decoded)
    c = TcpConn(40001, PORT)
    F.append(c.send(b'ESNC' + b'\x00\x01config-data'))
    # 15: a UDP packet on the port with an unknown header (not ENTTEC)
    F.append(u(b'XXXXyyyy'))
    # 16: TCP data on the port that is not a Config packet (not ENTTEC)
    F.append(c.send(b'ESPPnotcfg'))
    # 17, 18: UDP and TCP payloads shorter than the 4 octet header (not
    #     ENTTEC)
    F.append(u(b'ES'))
    F.append(c.send(b'ES'))
    return F


def malformed_frames():
    F = []
    # Poll Reply cut short
    F.append(u(b'ESPR' + bytes.fromhex('0200000000'), rev=True))
    # Poll without the type
    F.append(u(b'ESPP'))
    # DMX header cut short
    F.append(u(b'ESDD\x01\x00'))
    # uncompressed DMX with size larger than the data
    F.append(u(esdd(1, 0, 0x01, 100, bytes(10))))
    # RLE run cut short after the 0xFE marker
    F.append(u(esdd(1, 0, 0x04, 3, bytes([0xFE]))))
    # RLE escape cut short
    F.append(u(esdd(1, 0, 0x04, 2, bytes([0xFD]))))
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcap(os.path.join(out, 'enttec-coverage.pcap'), main_frames())
    pcap(os.path.join(out, 'enttec-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()
