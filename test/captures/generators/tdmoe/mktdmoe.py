#!/usr/bin/env python3
# Generates test/captures/tdmoe_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic captures for packet-tdmoe.c (Digium TDMoE, ethertype 0xd00d).
# Usage: mktdmoe.py <outdir>
import os
import struct
import sys
from pcaplib import Pcap, eth, hdlc_stream

DLT_EN10MB = 1
ETHERTYPE_TDMOE = 0xd00d

def tdmoe(counter, channels_data, flags=0, subaddr=0, samples=8, sigbits=None, nchan=None):
    n = len(channels_data) if nchan is None else nchan
    h = struct.pack('!HBBHH', subaddr, samples, flags, counter, n)
    if flags & 0x02:
        sb = sigbits if sigbits is not None else bytes([0x0f] * ((n + 1) // 2))
        h += sb
    return h + b''.join(channels_data)

def lapd(sapi, tei, ctrl, payload=b'', cr=0):
    return bytes([(sapi << 2) | (cr << 1), (tei << 1) | 1]) + ctrl + payload

SETUP = bytes([0x08, 0x01, 0x01, 0x05, 0x04, 0x03, 0x80, 0x90, 0xa3, 0x70, 0x03, 0x80, 0x31, 0x32])
REL = bytes([0x08, 0x01, 0x81, 0x5a, 0x08, 0x02, 0x80, 0x90])

LAPD_FRAMES = [
    lapd(0, 64, bytes([0x00, 0x00]), SETUP),                          # I frame, Q.931 SETUP
    lapd(0, 64, bytes([0x01, 0x02])),                                 # RR
    lapd(0, 64, bytes([0x02, 0x04]), REL, cr=1),                      # I frame, RELEASE COMPLETE
    lapd(0, 64, b'\x7f'),                                             # SABME
    lapd(0, 64, b'\x73'),                                             # UA
]

def build(out):
    idle = bytes([0xd5] * 8)
    p = Pcap(DLT_EN10MB)
    stream = hdlc_stream(LAPD_FRAMES, lead=2, align=8, gap=1, fcs='>', tail=8)
    chunks = [stream[i:i + 8] for i in range(0, len(stream), 8)]
    flag_chunk = chunks.pop()
    flagsets = [0x00, 0x01, 0x02, 0x03]
    for n, chunk in enumerate(chunks):
        data = [bytes([(n * 7 + c) & 0xff] * 8) for c in range(23)] + [chunk]
        flags = flagsets[n % 4] if n < 8 else 0
        p.add(eth(tdmoe(n + 1, data, flags=flags, subaddr=n // 4), ETHERTYPE_TDMOE))
    c = len(chunks)
    # 25 channels with signalling bits (odd channel count), D channel carries flags
    data = [bytes([c & 0xff] * 8) for _ in range(23)] + [flag_chunk, idle]
    p.add(eth(tdmoe(c + 1, data, flags=0x02), ETHERTYPE_TDMOE))
    # two channels only, no D channel
    p.add(eth(tdmoe(c + 2, [idle, bytes(range(8))], flags=0x00), ETHERTYPE_TDMOE))
    p.add(eth(tdmoe(c + 3, [idle], flags=0x03, subaddr=3), ETHERTYPE_TDMOE))
    # no channels at all
    p.add(eth(tdmoe(c + 4, [], flags=0x00), ETHERTYPE_TDMOE))
    # frame shorter than the eight octet header: not dissected as TDMoE
    p.add(eth(b'\x00\x01\x08\x00\x00\x01', ETHERTYPE_TDMOE))
    p.write(os.path.join(out, 'tdmoe-coverage.pcap'))

    m = Pcap(DLT_EN10MB)
    # 24 channels announced, two present
    m.add(eth(tdmoe(1, [idle, idle], nchan=24), ETHERTYPE_TDMOE))
    # signalling bits announced but not present
    m.add(eth(struct.pack('!HBBHH', 0, 8, 0x02, 1, 8) + b'\x0f', ETHERTYPE_TDMOE))
    # 25 channels, last one truncated
    m.add(eth(tdmoe(2, [idle] * 24 + [b'\x01\x02\x03'], nchan=25), ETHERTYPE_TDMOE))
    # an abort sequence (seven ones) and six ones that are not a flag in the D channel
    ab = [bytes([0x11] * 8) for _ in range(23)]
    m.add(eth(tdmoe(3, ab + [bytes([0x7e, 0x7e, 0x12, 0x34, 0xff, 0xff, 0x7e, 0x7e])]), ETHERTYPE_TDMOE))
    m.add(eth(tdmoe(4, ab + [bytes([0x7e, 0x01, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e])]), ETHERTYPE_TDMOE))
    m.write(os.path.join(out, 'tdmoe-coverage-malformed.pcap'))

build(sys.argv[1] if len(sys.argv) > 1 else '.')
