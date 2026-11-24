#!/usr/bin/env python3
# Generates test/captures/file_dlt_coverage.dlt.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic AUTOSAR DLT log files for the file-dlt dissector.

usage: mkfile-dlt.py <outdir>
Writes file-dlt-coverage.dlt (the main capture) and
file-dlt-coverage-malformed.dlt, both read with
-X read_format:"MIME Files Format" (magic "DLT\\x01").
A storage header is magic, seconds, microseconds, ECU id; then the
standard header: header type, message counter, big endian length (which
counts the standard header and the payload).
"""
import struct
import sys
import os

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'


def line(sec, usec, ecu, htyp, counter, payload, length=None):
    ln = 4 + len(payload) if length is None else length
    return (b'DLT\x01' + struct.pack('<II', sec, usec) + ecu +
            struct.pack('>BBH', htyp, counter, ln) + payload)


def main():
    w = lambda n, d: open(os.path.join(OUT, n), 'wb').write(d)
    d = b''
    ecus = [b'ECU1', b'ECU2', b'GW\0\0']
    for i in range(12):
        payload = (b'' if i == 0 else bytes(range(i * 3)) + b'text %d' % i)
        d += line(1700000000 + i, i * 1000, ecus[i % 3], 0x3d if i % 2 else 0x35, i, payload)
    # a message with only the 4 octet standard header
    d += line(1700000100, 999999, b'ECU1', 0x21, 99, b'')
    # a long message
    d += line(1700000101, 0, b'ECU1', 0x3d, 100, bytes(range(256)) * 3)
    w('file-dlt-coverage.dlt', d)
    # --- malformed
    # a length of less than 4 (the payload length underflows), a last line
    # that is too short to be read, and bytes after the last full line
    m = line(1, 2, b'ECU1', 0x3d, 1, b'abcdefgh') + line(2, 3, b'ECU1', 0x3d, 2, b'', length=0)
    w('file-dlt-coverage-malformed.dlt', m)
    m2 = line(1, 2, b'ECU1', 0x3d, 1, b'abcdefgh') + line(2, 3, b'ECU1', 0x3d, 2, b'x' * 4, length=4000)
    w('file-dlt-coverage-malformed-long.dlt', m2)
    w('file-dlt-coverage-trailing.dlt', line(1, 2, b'ECU1', 0x3d, 1, b'abcdefgh') + b'DLT\x01\0\0\0')
    # shorter than 16 octets (not this dissector, via Exported PDU)
    pdus = [b'DLT\x01' + b'\0' * 8, d[:200], b'XLT\x01' + b'\0' * 30]
    with open(os.path.join(OUT, 'file-dlt-coverage-exppdu.pcap'), 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 252))
        for i, b in enumerate(pdus):
            pdu = struct.pack('>HH', 12, 8) + b'file-dlt' + struct.pack('>HH', 0, 0) + b
            f.write(struct.pack('<IIII', 1000 + i, 0, len(pdu), len(pdu)) + pdu)


main()
