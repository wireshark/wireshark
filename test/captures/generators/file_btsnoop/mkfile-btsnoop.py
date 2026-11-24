#!/usr/bin/env python3
# Generates test/captures/file_btsnoop_coverage.btsnoop.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic btsnoop files for the btsnoop file dissector.

usage: mkfile-btsnoop.py <outdir>
file-btsnoop-coverage.btsnoop: the main capture (H4 UART HCI traffic).
file-btsnoop-coverage-{h1,monitor,bcsp,h5,simulator,unknown}.btsnoop: one
file per datalink type (the type is in the file header) and
file-btsnoop-coverage-malformed.btsnoop.  All are read with
-X read_format:"MIME Files Format" (the magic is "btsnoop\\0").
"""
import struct
import sys
import os

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'
EPOCH = 0x00dcddb30f2f8000          # 1970-01-01 in btsnoop microseconds


def hdr(datalink, version=1):
    return b'btsnoop\0' + struct.pack('>II', version, datalink)


def rec(flags, data, ts=1700000000, usec=0, drops=0, orig=None):
    t = EPOCH + ts * 1000000 + usec
    return struct.pack('>IIIIQ', len(data) if orig is None else orig, len(data), flags, drops, t) + data


# HCI packets (the first octet is the H4 packet type; the monitor and H1
# formats use other framings)
H4 = [
    (0x01, bytes.fromhex('01030c00')),                         # HCI Reset command (sent)
    (0x00, bytes.fromhex('040e0401030c00')),                   # Command Complete (received)
    (0x01, bytes.fromhex('0101200c0e0001010100000000000000')),  # LE Set Event Mask style command
    (0x00, bytes.fromhex('0403 0b 00 4000 010203040506 01 00'.replace(' ', ''))),  # Connection Complete
    (0x01, bytes.fromhex('02 4000 0400 0000 0100 41424344'.replace(' ', ''))),     # ACL data
    (0x00, bytes.fromhex('02 4000 0400 0000 0100 41424344'.replace(' ', ''))),
]


def main():
    w = lambda n, d: open(os.path.join(OUT, n), 'wb').write(d)
    d = hdr(1002)
    for i, (fl, p) in enumerate(H4):
        d += rec(fl, p, 1700000000 + i, 1000 * i, drops=i)
    d += rec(0, b'', 1700000010, 5)          # empty payload
    w('file-btsnoop-coverage.btsnoop', d)
    # H1: flags bit 0 direction (1: received? see dissector), bit 1 command/event
    h1 = hdr(1001)
    for i, (fl, p) in enumerate([(0, bytes.fromhex('01030c00')), (1, bytes.fromhex('0e0401030c00')),
                                 (2, bytes.fromhex('01030c00')), (3, bytes.fromhex('0e0401030c00')),
                                 (0, bytes.fromhex('400004000000010041424344'))]):
        h1 += rec(fl, p, 1700000000 + i)
    w('file-btsnoop-coverage-h1.btsnoop', h1)
    # Linux monitor: flags = adapter id << 16 | opcode (HCI command 0x0002, event 0x0003, ...)
    mon = hdr(2001)
    mon += rec((0 << 16) | 0, struct.pack('<6sBB', b'\0\1\2\3\4\5', 1, 0) + b'hci0\0' + b'\0' * 9 + struct.pack('<II', 0, 0)[:0])
    mon += rec((0 << 16) | 2, bytes.fromhex('01030c00'))
    mon += rec((0 << 16) | 3, bytes.fromhex('0e0401030c00'))
    mon += rec((1 << 16) | 4, bytes.fromhex('400004000000010041424344'))
    w('file-btsnoop-coverage-monitor.btsnoop', mon)
    for name, dl in (('bcsp', 1003), ('h5', 1004), ('simulator', 2002), ('unknown', 4242)):
        w('file-btsnoop-coverage-%s.btsnoop' % name,
          hdr(dl) + rec(0, b'\1\2\3\4\5\6\7\x08') + rec(1, b'xy'))
    # malformed: a frame header cut short, and a payload longer than the file
    m = hdr(1002) + rec(1, H4[0][1]) + struct.pack('>III', 4, 4, 0)       # 12 octets of a frame header
    w('file-btsnoop-coverage-malformed.btsnoop', m)
    m2 = hdr(1002) + rec(1, H4[0][1]) + struct.pack('>IIIIQ', 100, 100, 0, 0, EPOCH) + b'\1\2\3'
    w('file-btsnoop-coverage-malformed-trunc.btsnoop', m2)
    # a timestamp before the btsnoop epoch (wraps) and a header only file
    w('file-btsnoop-coverage-early.btsnoop', hdr(1002) + struct.pack('>IIIIQ', 1, 1, 0, 0, 5) + b'\1')
    w('file-btsnoop-coverage-header-only.btsnoop', hdr(1002))
    # Exported PDU naming "btsnoop": a wrong magic (not this dissector) and a good file
    pdus = [b'btsnoox\0' + b'\0' * 12, d]
    with open(os.path.join(OUT, 'file-btsnoop-coverage-exppdu.pcap'), 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 252))
        for i, b in enumerate(pdus):
            pdu = struct.pack('>HH', 12, 8) + b'btsnoop\0' + struct.pack('>HH', 0, 0) + b
            f.write(struct.pack('<IIII', 1000 + i, 0, len(pdu), len(pdu)) + pdu)


main()
