#!/usr/bin/env python3
# Generates test/captures/hpsw_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic captures for packet-hpsw.c (HP Switch Protocol, behind HPEXT
with DXSAP 0x0623 in an 802.2 LLC frame to SAP 0xf8).
Usage: mkhpsw.py <outdir>"""
import struct
import sys
import os
from pylib import H, mac, Pcap, S

def tlv(t, v):
    return bytes([t, len(v)]) + v

def frame(msg, dxsap=0x0623, sxsap=0x0623, src=S):
    hpext = bytes(3) + struct.pack('>HH', dxsap, sxsap)
    llc = bytes([0xf8, 0xf8, 0x03]) + hpext + msg
    return mac('00:e0:52:00:00:01') + mac(src) + struct.pack('>H', len(llc)) + llc

def hp(ver, typ, tlvs):
    return bytes([ver, typ]) + b''.join(tlvs)

M = lambda n: bytes([0x00, 0x1a, 0x1b, 0x00, 0x00, n])

def main(out):
    p = Pcap(1)
    # Every TLV with its correct length
    p.add(frame(hp(1, 1, [tlv(1, b'switch-core-1'), tlv(2, b'K.15.06.0008'),
                          tlv(3, b'running-config'), tlv(4, M(1)),
                          tlv(5, bytes([192, 0, 2, 10])), tlv(6, b'\x00\x20'),
                          tlv(7, b'DOMAIN-A'), tlv(8, b'\x01\x02')])))
    p.add(frame(hp(1, 1, [tlv(9, b'\x00\x03'), tlv(10, b'\x00\x00\x00\x2a'),
                          tlv(11, M(2) + M(3)), tlv(12, b'\x07'),
                          tlv(13, M(4) + b'device specific data'),
                          tlv(14, M(5))]), src=H))
    # Neighbors: one and three addresses
    p.add(frame(hp(2, 2, [tlv(11, M(7))])))
    p.add(frame(hp(2, 2, [tlv(11, M(7) + M(8) + M(9))])))
    # Device ID with one octet of data after the MAC address
    p.add(frame(hp(1, 1, [tlv(13, M(1) + b'\xff')])))
    # Unknown TLV types
    p.add(frame(hp(1, 1, [tlv(0x55, b'unknown'), tlv(0, b'\x01'), tlv(0xff, b'\x00\x01\x02')])))
    # Only version and type
    p.add(frame(hp(3, 9, [])))
    # Bad TLV lengths (warnings): the fixed length types with a wrong length
    p.add(frame(hp(1, 1, [tlv(4, M(1)[:5]), tlv(5, bytes(3)), tlv(6, bytes(3)),
                          tlv(8, bytes(1)), tlv(9, bytes(3)), tlv(10, bytes(2)),
                          tlv(11, bytes(7)), tlv(12, bytes(2)), tlv(13, bytes(6)),
                          tlv(14, bytes(7))])))
    # Stops at a TLV with length 0 and at one that is longer than the rest
    p.add(frame(hp(1, 1, [tlv(1, b'before'), bytes([2, 0]), tlv(3, b'not shown')])))
    p.add(frame(hp(1, 1, [tlv(1, b'before'), bytes([3, 50]) + b'short'])))
    # Another DXSAP in the HPEXT header: no HPSW
    p.add(frame(hp(1, 1, [tlv(1, b'other')]), dxsap=0x9999))
    p.write(os.path.join(out, 'hpsw-coverage.pcap'))

    m = Pcap(1)
    # Nothing after HPEXT, and a version without a type
    m.add(frame(b''))
    m.add(frame(b'\x01'))
    # TLV with the type only (no length octet)
    m.add(frame(hp(1, 1, []) + b'\x01'))
    m.write(os.path.join(out, 'hpsw-coverage-malformed.pcap'))

main(sys.argv[1])
