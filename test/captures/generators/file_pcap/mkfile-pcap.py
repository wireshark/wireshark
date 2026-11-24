#!/usr/bin/env python3
# Generates test/captures/file_pcap_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic pcap files for the file-pcap dissector.

usage: mkfile-pcap.py <outdir>
Writes file-pcap-coverage.pcap (little endian, microseconds: the main
capture), file-pcap-coverage-{be,nsec,nsec-be}.pcap (the other three byte
order and resolution variants) and file-pcap-coverage-malformed.pcap.
All are read with -X read_format:"MIME Files Format" (by magic).
"""
import struct
import sys
import os

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'
MAGIC = {  # name: (magic value, byte order)
    'le': (0xa1b2c3d4, '<'), 'be': (0xa1b2c3d4, '>'),
    'nsec': (0xa1b23c4d, '<'), 'nsec-be': (0xa1b23c4d, '>'),
}


def frame(n):
    pay = b'pcap file %d' % n
    udp = struct.pack('>HHHH', 4000 + n, 5000, 8 + len(pay), 0) + pay
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), n, 0, 64, 17, 0,
                     bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2])) + udp
    return bytes([2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1]) + b'\x08\x00' + ip


def pcap(kind, records, snap=65535, link=1, zone=0, sigfigs=0, ver=(2, 4)):
    magic, e = MAGIC[kind]
    out = struct.pack(e + 'IHHiIII', magic, ver[0], ver[1], zone, sigfigs, snap, link)
    for sec, frac, data, orig in records:
        out += struct.pack(e + 'IIII', sec, frac, len(data), len(data) if orig is None else orig) + data
    return out


def main():
    recs = [(1700000000 + i, i * 1000 + 7, frame(i), None) for i in range(5)]
    recs += [
        (1700000010, 999999, frame(10), None),
        (1700000011, 0, frame(11)[:30], 60),            # truncated: original longer
        (1700000012, 0, b'', 0),                          # empty record
        # fraction >= 1 s (carried into the seconds; it printed "16:28:15.-00001000")
        (1700000013, 1500000, frame(13), None),
        (1700000014, 0xFFFFFFFF, frame(14), None),
        (0xFFFFFFFF, 0xFFFFFFFF, frame(15), None),
    ]
    w = lambda n, d: open(os.path.join(OUT, n), 'wb').write(d)
    w('file-pcap-coverage.pcap', pcap('le', recs, zone=-3600, sigfigs=0))
    for kind in ('be', 'nsec', 'nsec-be'):
        w('file-pcap-coverage-%s.pcap' % kind, pcap(kind, recs[:6], link=113))
    # ----- malformed
    m = pcap('le', [
        (1700000000, 0, frame(1), None),
        (1700000001, 0, frame(2), None),
    ], snap=20)                                           # captured length > snap length
    m += struct.pack('<IIII', 1, 2, 40, 20) + b'\0' * 40  # captured > original: stops
    m += struct.pack('<IIII', 1, 2, 4, 4) + b'\0' * 4     # not reached
    w('file-pcap-coverage-malformed.pcap', m)
    # record running past the end of the file (bounds error)
    w('file-pcap-coverage-malformed-trunc.pcap',
      pcap('le', [(1, 2, frame(1), None)]) + struct.pack('<IIII', 1, 2, 1000, 1000) + b'\0' * 10)
    # Unknown magic number: not this dissector (as Exported PDU, below)
    # ----- Exported PDU naming "file-pcap": a bad magic number, a good file
    pdus = [b'\xde\xad\xbe\xef' + b'\0' * 40, pcap('le', recs[:2])]
    with open(os.path.join(OUT, 'file-pcap-coverage-exppdu.pcap'), 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 252))
        for i, b in enumerate(pdus):
            pdu = struct.pack('>HH', 12, 12) + b'file-pcap' + b'\0\0\0' + struct.pack('>HH', 0, 0) + b
            f.write(struct.pack('<IIII', 1000 + i, 0, len(pdu), len(pdu)) + pdu)


main()
