#!/usr/bin/env python3
# Generates test/captures/m2pa_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Write the synthetic M2PA coverage captures.

Usage: mkm2pa.py <outdir>

M2PA over SCTP (port 3565, PPID 5). Frames 1-N (see the printed ranges)
are RFC 4165 and draft-8 messages that decode the same at the default
M2PA version and with -o m2pa.version:draft-8. Then follow the draft-2
frames (dissected with -o m2pa.version:draft-2) and the reproducers of
the length fix (error expert info). Nothing comes from a real network.
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct

from sslib import Sctp, write_pcap, mtp3_sltm, mtp3_coo  # noqa: E402

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'
PORT, PPID = 3565, 5


def m2pa(typ, body, cls=0xb, bsn=0xffffff, fsn=0xffffff, length=None, ver=1):
    """RFC 4165 / draft 8 message: 16 octet header."""
    if length is None:
        length = 16 + len(body)
    return struct.pack('!BBBBI', ver, 0, cls, typ, length) + \
        struct.pack('!I', bsn) + struct.pack('!I', fsn) + body


def m2pa_v2(typ, body, length=None):
    """Draft 2: version, spare, 16 bit type, length (of the data), data."""
    if length is None:
        length = len(body)
    return struct.pack('!BBHI', 1, 0, typ, length) + body


def status(code, filler=b''):
    return struct.pack('!I', code) + filler


def main():
    s = Sctp(PORT, PPID, cport=3565)
    frames, ranges = [], []

    def add(payload, rev=False):
        frames.append(s.frame(payload, rev))

    def mark(name, start):
        ranges.append((name, start + 1, len(frames)))

    # --- link status, every value and unknown ones, with and without filler
    st = len(frames)
    for i, code in enumerate([1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 10, 0x7fffffff]):
        add(m2pa(2, status(code), bsn=i, fsn=i), i % 2 == 1)
    add(m2pa(2, status(4, b'\x00' * 4), bsn=100, fsn=101))
    add(m2pa(2, status(1, b'\xaa\xbb\xcc\xdd\xee\xff\x11\x22'), bsn=100, fsn=101), True)
    mark('Link Status (RFC 4165), every status, with filler', st)

    # --- user data with priority, SLTM and COO payloads
    st = len(frames)
    for i, pri in enumerate([0x00, 0x40, 0x80, 0xc0, 0x3f, 0xff]):
        add(m2pa(1, bytes([pri]) + mtp3_sltm(2, 1, i, b'TEST%d' % i), bsn=i, fsn=i + 1), i % 2 == 1)
    add(m2pa(1, b'\x00' + mtp3_coo(2, 1, 3, 9), bsn=7, fsn=8))
    add(m2pa(1, b'\x00' + mtp3_coo(1, 2, 3, 10, ni=2), bsn=8, fsn=9), True)
    # user data with a header only (no data): the priority byte is absent
    add(m2pa(1, b'', bsn=9, fsn=10))
    mark('User Data (RFC 4165): priority, SLTM, COO, empty', st)

    # --- unknown message types and class
    st = len(frames)
    add(m2pa(3, b'\x01\x02\x03\x04'))
    add(m2pa(0x7f, b'unknown type'), True)
    add(m2pa(0, b''))
    add(m2pa(2, status(1), cls=0x07))
    add(m2pa(1, b'\x00' + mtp3_sltm(), ver=2))
    mark('Unknown types, class and version', st)
    last_clean = len(frames)

    # --- draft 2 (decode with -o m2pa.version:draft-2)
    st = len(frames)
    for i, code in enumerate([1, 2, 3, 4, 5, 0, 9]):
        add(m2pa_v2(0x0602, status(code)), i % 2 == 1)
    for i, pri in enumerate([0, 1, 2, 3, 0xfc, 0xff]):
        add(m2pa_v2(0x0601, bytes([pri]) + mtp3_sltm(2, 1, i)), i % 2 == 1)
    add(m2pa_v2(0x0601, b''))
    add(m2pa_v2(0x0603, b'\x01\x02\x03\x04'))
    add(m2pa_v2(0x0604, b''))
    mark('Draft 2 (needs -o m2pa.version:draft-2)', st)
    last_v2 = len(frames)

    # --- reproducers of "M2PA: Check the message length in RFC 4165 mode":
    # message length below the header size (error expert info, no exception)
    st = len(frames)
    add(m2pa(2, struct.pack('!I', 4), length=8))
    add(m2pa(1, b'\x00\x83\x01\x02\x03\x04\x05', length=0))
    add(m2pa(2, status(1), length=15))
    mark('Reproducers: length < 16 (RFC 4165)', st)
    write_pcap(os.path.join(OUT, 'm2pa-coverage.pcap'), frames)

    # --- malformed capture: draft-8 length checks, data past the length,
    # truncated messages, the draft-2 length check
    mal = []
    s2 = Sctp(PORT, PPID, cport=3565)
    mal.append(s2.frame(m2pa(2, status(1)) + b'\x00' * 6))      # data past the length
    mal.append(s2.frame(m2pa(1, b'\x00' + mtp3_sltm()) + b'\x01' * 8, True))
    mal.append(s2.frame(m2pa(2, status(1), length=8)))
    mal.append(s2.frame(m2pa(1, b'', length=0)))
    mal.append(s2.frame(m2pa(2, status(1))[:10]))
    mal.append(s2.frame(m2pa(1, b'\x00' + mtp3_sltm())[:20]))
    mal.append(s2.frame(m2pa_v2(0x0601, b'', length=0)))
    mal.append(s2.frame(m2pa_v2(0x0602, status(1), length=0x7fffffff)))
    mal.append(s2.frame(m2pa_v2(0x0602, status(1))[:6]))
    write_pcap(os.path.join(OUT, 'm2pa-coverage-malformed.pcap'), mal)
    for r in ranges:
        print(r)
    print('clean at default (RFC 4165 / draft 8):', 1, '-', last_clean, 'draft 2:',
          last_clean + 1, '-', last_v2, 'total', len(frames), 'malformed', len(mal))


if __name__ == '__main__':
    main()
