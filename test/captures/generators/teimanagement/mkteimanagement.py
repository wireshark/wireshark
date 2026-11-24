#!/usr/bin/env python3
# Generates test/captures/teimanagement_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic captures for packet-teimanagement.c (TEI management procedure
# on LAPD SAPI 63). Usage: mkteimanagement.py <outdir>
import os
import struct
import sys
from pcaplib import Pcap

DLT_LAPD = 203

def lapd_ui(payload, sapi=63, tei=127, cr=0):
    # address: SAPI(6) C/R EA0, TEI(7) EA1; control 0x03 = UI
    return struct.pack('!BBB', (sapi << 2) | (cr << 1), (tei << 1) | 1, 0x03) + payload

def lapd_i(payload, sapi=63, tei=127, cr=0, ns=0, nr=0):
    return struct.pack('!BBBB', (sapi << 2) | (cr << 1), (tei << 1) | 1,
                       ns << 1, (nr << 1)) + payload

def tei(ref, msg, ai, ext=1, ent=0x0f):
    return struct.pack('!BHBB', ent, ref, msg, (ai << 1) | ext)

def main(out):
    p = Pcap(DLT_LAPD)
    # 1-7: the seven defined message types
    p.add(lapd_ui(tei(0x1234, 1, 127)))                  # Identity Request, any TEI
    p.add(lapd_ui(tei(0x1234, 2, 64), cr=1))             # Identity Assigned, TEI 64
    p.add(lapd_ui(tei(0x1234, 3, 127), cr=1))            # Identity Denied
    p.add(lapd_ui(tei(0x0000, 4, 127), cr=1))            # Identity Check Request
    p.add(lapd_ui(tei(0x0001, 5, 64)))                   # Identity Check Response
    p.add(lapd_ui(tei(0x0000, 6, 64), cr=1))             # Identity Remove
    p.add(lapd_ui(tei(0x0000, 7, 64)))                   # Identity Verify
    # 8-9: unknown message types
    p.add(lapd_ui(tei(0xffff, 0x00, 0)))
    p.add(lapd_ui(tei(0x8001, 0xff, 126, ext=0)))
    # 10: other management entity identifier, extension bit clear
    p.add(lapd_ui(tei(0x4242, 1, 5, ext=0, ent=0x00)))
    # 11: TEI management in an I frame (two octet control field)
    p.add(lapd_i(tei(0x0102, 1, 127)))
    # 12: a longer frame, extra octets after the five of the procedure
    p.add(lapd_ui(tei(0x0103, 2, 65) + b'\xaa\xbb\xcc'))
    # 13: SAPI 0 UI frame for contrast (not TEI management)
    p.add(lapd_ui(b'\x08\x01\x01\x5a', sapi=0, tei=64))
    p.write(os.path.join(out, 'teimanagement-coverage.pcap'))

    m = Pcap(DLT_LAPD)
    m.add(lapd_ui(b'\x0f\x12'))               # too short for the message type
    m.add(lapd_ui(b'\x0f\x12\x34\x01'))       # action indicator missing
    m.add(lapd_ui(b''))                       # no payload at all
    m.write(os.path.join(out, 'teimanagement-coverage-malformed.pcap'))

main(sys.argv[1] if len(sys.argv) > 1 else '.')
