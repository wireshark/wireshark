#!/usr/bin/env python3
# Generates test/captures/file_file_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic capture for the File (top level record) dissector.

usage: mkfile-file.py <outdir>
file-file-coverage.pcapng: Ethernet frames, a frame of a link type that
has no dissector ("UNKNOWN" and "FTAP_ENCAP = n"), and Exported PDU frames
naming the "file" dissector (the reproducer of the NULL pointer
dereference: the File dissector was called without its data argument).
"""
import struct
import sys
import os

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'


def blk(t, body):
    body += b'\0' * ((-len(body)) % 4)
    return struct.pack('<II', t, 12 + len(body)) + body + struct.pack('<I', 12 + len(body))


def opt(c, v):
    return struct.pack('<HH', c, len(v)) + v + b'\0' * ((-len(v)) % 4)


def frame(n):
    pay = b'file record %d' % n
    udp = struct.pack('>HHHH', 4000 + n, 5000, 8 + len(pay), 0) + pay
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), n, 0, 64, 17, 0,
                     bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2])) + udp
    return bytes([2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1]) + b'\x08\x00' + ip


def tcp(n, flags, seq, ack, data=b''):
    t = struct.pack('>HHIIBBHHH', 40000, 80, seq, ack, 5 << 4, flags, 8192, 0, 0) + data
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(t), n, 0, 64, 6, 0,
                     bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2])) + t
    return bytes([2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1]) + b'\x08\x00' + ip


def epb(ifid, ts, data, opts=b''):
    return blk(6, struct.pack('<IIIII', ifid, 0, ts, len(data), len(data)) + data + b'\0' * ((-len(data)) % 4) + opts)


def tlv(t, v):
    pad = (-len(v)) % 4
    return struct.pack('>HH', t, len(v) + pad) + v + b'\0' * pad


def main():
    link_unknown = int(sys.argv[2]) if len(sys.argv) > 2 else 65000
    d = blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    d += blk(1, struct.pack('<HHI', 1, 0, 0) + opt(0, b''))           # Ethernet
    d += blk(1, struct.pack('<HHI', 252, 0, 0) + opt(0, b''))         # Exported PDU
    d += blk(1, struct.pack('<HHI', link_unknown, 0, 0) + opt(0, b''))
    for i in range(3):
        d += epb(0, 1000 + i, frame(i), opt(1, b'a comment') + opt(0, b''))
    # the File dissector named by an Exported PDU: it must return without a crash
    for i, payload in enumerate((bytes(range(8)), b'')):
        d += epb(1, 2000 + i, tlv(12, b'file') + struct.pack('>HH', 0, 0) + payload)
    # TCP with sequence analysis (per record protocol data)
    d += epb(0, 3500, tcp(20, 0x02, 100, 0)) + epb(0, 3501, tcp(21, 0x18, 101, 1, b'GET / HTTP/1.0\r\n\r\n'))
    d += epb(0, 3502, tcp(22, 0x18, 101, 1, b'GET / HTTP/1.0\r\n\r\n'))
    d += epb(2, 3000, b'\x01\x02\x03\x04')
    d += epb(0, 4000, frame(9))
    open(os.path.join(OUT, 'file-file-coverage.pcapng'), 'wb').write(d)
    # the plain pcap reproducer from the review (linktype 252)
    pdu = tlv(12, b'file') + struct.pack('>HH', 0, 0) + bytes(range(8))
    with open(os.path.join(OUT, 'file-file-coverage-exppdu.pcap'), 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 252))
        f.write(struct.pack('<IIII', 1000, 0, len(pdu), len(pdu)) + pdu)


main()
