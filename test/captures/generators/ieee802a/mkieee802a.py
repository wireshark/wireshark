#!/usr/bin/env python3
# Generates test/captures/ieee802a_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic captures for packet-ieee802a.c (IEEE 802a OUI Extended Ethertype,
0x88b7).  Usage: mkieee802a.py <outdir> [-v]   (needs pcaplib.py beside it)"""
import struct
import sys
import os
from pcaplib import eth, pcap

A, B = '02:00:00:00:00:01', '02:00:00:00:00:02'
ECP_END = struct.pack('!BBH', 1, 0, 7) + b'\x00\x00'      # ECP header (subtype 1, request, seq 7) + End of VDPDU TLV

def oui(o, pid, payload=b''):
    return struct.pack('!BBBH', (o >> 16) & 255, (o >> 8) & 255, o & 255, pid) + payload

def main(out, verbose=False):
    fr, marks = [], []
    def add(desc, f):
        fr.append(f); marks.append((len(fr), desc))
    add('OUI 00:1b:3f (802.1Qbg), PID 0: ECP', eth(A, B, 0x88B7, oui(0x001B3F, 0, ECP_END)))
    add('OUI 00:1b:3f, unknown PID 2', eth(A, B, 0x88B7, oui(0x001B3F, 2, b'\x01\x02\x03\x04' * 5)))
    add('known manufacturer OUI 00:00:0c, PID 0x0102', eth(A, B, 0x88B7, oui(0x00000C, 0x0102, b'cisco' * 4)))
    add('unknown OUI 02:aa:bb, PID 0x1234', eth(A, B, 0x88B7, oui(0x02AABB, 0x1234, bytes(range(30)))))
    add('OUI and PID only, empty payload', eth(A, B, 0x88B7, oui(0x00000C, 0xffff)))
    add('OUI 00:1b:3f PID 0 behind an 802.1Q tag', eth(A, B, 0x8100, struct.pack('!HH', 3, 0x88B7) + oui(0x001B3F, 0, ECP_END)))
    add('IEEE 802.1 OUI 00:80:c2 (no registered PIDs), PID 0', eth(A, B, 0x88B7, oui(0x0080C2, 0, b'\x01\x00\x00\x07\x00\x00')))
    add('OUI 00:00:5e (IANA), PID 0x0800', eth(A, B, 0x88B7, oui(0x00005E, 0x0800, b'\x45' + bytes(19))))
    os.makedirs(out, exist_ok=True)
    pcap(os.path.join(out, 'ieee802a-coverage.pcap'), fr)
    m = [eth(A, B, 0x88B7, b''), eth(A, B, 0x88B7, b'\x00\x80'), eth(A, B, 0x88B7, b'\x00\x80\xc2'),
         eth(A, B, 0x88B7, b'\x00\x80\xc2\x00'), eth(A, B, 0x88B7, oui(0x001B3F, 0, b'\x01\x00'))]
    pcap(os.path.join(out, 'ieee802a-coverage-malformed.pcap'), m)
    if verbose:
        for n, d in marks: print(n, d)
        print(len(fr), 'frames;', len(m), 'malformed frames')

if __name__ == '__main__':
    main(sys.argv[1], '-v' in sys.argv)
