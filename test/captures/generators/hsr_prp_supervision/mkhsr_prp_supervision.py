#!/usr/bin/env python3
# Generates test/captures/hsr_prp_supervision_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic captures for packet-hsr-prp-supervision.c (ethertype 0x88fb,
also behind an HSR tag).  Usage: mkhsr_prp_supervision.py <outdir>"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import struct
from pylib import eth, H, mac, Pcap

MA = mac('02:00:00:00:0a:01')
MB = mac('02:00:00:00:0b:01')
RB = mac('02:00:00:00:0c:01')
SUP = '01:15:4e:00:01:00'

def tlv(t, l, val=None):
    if val is None:
        val = bytes(l)
    return bytes([t, l]) + val

def sup(path, version, seq, tlvs, pad=0):
    h = struct.pack('>H', (path << 12) | version)
    if version > 0:
        h += struct.pack('>H', seq)
    return h + b''.join(tlvs) + bytes(pad)

def f(payload, src=H, etype=0x88fb):
    return eth(SUP, src, etype, payload)

def main(out):
    p = Pcap(1)
    # PRP-0 (version 0, no sequence number)
    p.add(f(sup(0, 0, 0, [tlv(20, 12, MA + MB), tlv(30, 6, RB)], 20)))
    p.add(f(sup(0, 0, 0, [tlv(20, 12, MA + MB), tlv(0, 0)], 30)))
    p.add(f(sup(1, 0, 0, [tlv(21, 12, MA + MB), tlv(31, 6, RB)], 20)))
    # PRP-1 with sequence number and a list of TLVs
    p.add(f(sup(0, 1, 5, [tlv(20, 12, MA + MB), tlv(30, 6, RB), tlv(31, 6, MB), tlv(0, 0)], 10)))
    p.add(f(sup(1, 1, 6, [tlv(21, 6, MA)], 0)))
    p.add(f(sup(1, 1, 7, [tlv(20, 6, MA), tlv(0, 0)], 30)))
    # HSR supervision (type 23), alone and with a RedBox TLV
    p.add(f(sup(2, 1, 8, [tlv(23, 6, MA), tlv(30, 6, RB), tlv(0, 0)], 20)))
    p.add(f(sup(2, 1, 9, [tlv(23, 12, MA + MB)], 0)))
    # Obsolete TLV, unknown TLV type and unexpected lengths are skipped
    p.add(f(sup(0, 1, 10, [tlv(22, 6, MA), tlv(0x55, 3), tlv(20, 8), tlv(30, 4), tlv(31, 12, MA + MB), tlv(0, 0)], 10)))
    # End of TLVs with a non-zero length
    p.add(f(sup(0, 1, 11, [tlv(0, 4), tlv(20, 6, MA)], 0)))
    # Version 2 and the top path value, no TLVs at all
    p.add(f(sup(15, 2, 12, [], 40)))
    # Behind an HSR tag (ethertype 0x892f, inner type 0x88fb)
    inner = sup(0, 1, 13, [tlv(23, 6, MA), tlv(0, 0)], 20)
    p.add(eth(SUP, H, 0x892f, struct.pack('>HHH', (1 << 12) | (6 + len(inner)), 14, 0x88fb) + inner))
    p.write(os.path.join(out, 'hsr-prp-supervision-coverage.pcap'))

    m = Pcap(1)
    # Header only half there
    m.add(f(b'\x00'))
    # Version 1 without the sequence number
    m.add(f(struct.pack('>H', 1) + b'\x00'))
    # TLV type without a length
    m.add(f(struct.pack('>HH', 1, 1) + b'\x14'))
    # TLV claims 12 octets, only 3 present
    m.add(f(struct.pack('>HH', 1, 1) + bytes([20, 12]) + MA[:3]))
    # TLV claims 6 octets, only 2 present (RedBox)
    m.add(f(struct.pack('>HH', 1, 1) + bytes([30, 6]) + MA[:2]))
    m.write(os.path.join(out, 'hsr-prp-supervision-coverage-malformed.pcap'))

main(sys.argv[1])
