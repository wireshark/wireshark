#!/usr/bin/env python3
# Generates test/captures/cesoeth_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the Circuit Emulation
Service over Ethernet (MEF 8) dissector (packet-cesoeth.c).

CESoETH runs directly on Ethernet (ethertype 0x88D8): a 20 bit ECID and
the 12 bit reserved value 0x102, a control word (L and R bits, M bits,
fragmentation bits, a 6 bit length that is non-zero when padding
follows, a 16 bit sequence number), an optional RTP header and the TDM
payload. Every packet is built from scratch with struct; no captured
traffic is used.

Usage: mkcesoeth.py <output directory>

Writes:
  cesoeth-coverage.pcap            every control word combination, the
                                   RTP header heuristic (accepted and
                                   rejected), padding, the reproducers
                                   of the fixes on the branch
  cesoeth-coverage-malformed.pcap  frames cut short in the header and
                                   control word
"""

import os
import struct
import sys

DST = bytes.fromhex('020000000002')
SRC = bytes.fromhex('020000000001')


def pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)


def eth(payload):
    return DST + SRC + struct.pack('>H', 0x88d8) + payload


def ces(ecid=1, res=0x102, l=0, r=0, m=0, frg=0, ln=0, sn=0, tail=b''):
    cw = (l << 27) | (r << 26) | (m << 24) | (frg << 22) | (ln << 16) | sn
    return eth(struct.pack('>II', (ecid << 12) | res, cw) + tail)


def rtp(sn, pt=96, ts=160000, ssrc=0x11223344, b0=0x80, marker=0):
    return struct.pack('>BBHII', b0, (marker << 7) | pt, sn, ts, ssrc)


def tdm(n, fill=0x5a):
    return bytes([fill]) * n


def main_frames():
    f = []
    # 1-4: L clear, M bits 0-3, fragmentation bits 0-3, R clear/set
    f.append(ces(sn=1, tail=tdm(32)))
    f.append(ces(sn=2, r=1, m=2, frg=1, tail=tdm(32)))
    f.append(ces(sn=3, m=3, frg=2, tail=tdm(32)))
    f.append(ces(sn=4, m=1, frg=3, r=1, tail=tdm(32)))
    # 5-8: L set (TDM defect), M bits 0-3; payload missing in 5
    f.append(ces(sn=5, l=1))
    f.append(ces(sn=6, l=1, m=1, tail=tdm(32)))
    f.append(ces(sn=7, l=1, m=2, r=1, tail=tdm(32)))
    f.append(ces(sn=8, l=1, m=3, frg=1, tail=tdm(32)))
    # 9: RTP header found by the heuristic (version 2, marker clear,
    #    sequence number equal to the control word's), no padding
    f.append(ces(ecid=0x00abc, sn=1000, tail=rtp(1000) + tdm(32)))
    # 10: RTP header with padding: Len 26 = 4 + 12 + 10 octets payload,
    #     16 octets padding
    f.append(ces(ecid=0x00abc, sn=1001, ln=26, tail=rtp(1001) + tdm(10) + bytes(16)))
    # 11: padding without RTP: Len 20, 16 octets payload, 22 padding
    f.append(ces(sn=9, ln=20, tail=tdm(16) + bytes(22)))
    # 12: only padding (Len 4: control word only), payload length 0
    f.append(ces(sn=10, ln=4, tail=bytes(38)))
    # 13: RTP-like, but the sequence number differs: not RTP
    f.append(ces(sn=11, tail=rtp(12) + tdm(20)))
    # 14: RTP-like, but the marker bit is set: not RTP
    f.append(ces(sn=12, tail=rtp(12, marker=1) + tdm(20)))
    # 15: first octet not 0x80 (version 2 with a CSRC count): not RTP
    #     by the heuristic (RTP with the rtp_header preference)
    f.append(ces(sn=13, tail=rtp(13, b0=0x81) + struct.pack('>I', 0x55667788) + tdm(20)))
    # 16: reproducer cesoeth_rtp_short_payload: Len 10 (32 octets
    #     padding) with an RTP header and 24 more octets, so only 4
    #     octets are not padding; the header is longer than the payload
    #     and is treated as missing
    f.append(ces(sn=0x1234, ln=10, tail=rtp(0x1234, pt=0, ts=0, ssrc=0xdeadbeef) + b'\xaa' * 24))
    # 17: reproducer cesoeth_cwlen_expert: Len 50 (>= 42), the expert
    #     info is on the Len field; the length is then taken as 0
    f.append(ces(sn=7, ln=50, tail=b'\x55' * 40))
    # 18: reserved field not 0x102
    f.append(ces(sn=14, res=0x000, tail=tdm(32)))
    # 19: ECID 0x00005 carrying a SAToP control word and payload (Decode
    #     As cesoeth.ecid==5,pwsatopcw); CESoETH by default
    f.append(ces(ecid=5, sn=0x0100, tail=tdm(32, 0x3c)))
    # 20: all control word bits at their maximum, largest ECID, Len 41
    #     (1 octet padding), RTP with sequence 65535
    f.append(ces(ecid=0xfffff, l=1, r=1, m=3, frg=3, ln=41, sn=0xffff,
                 tail=rtp(0xffff, pt=127, ts=0xffffffff, ssrc=0xffffffff) + tdm(25) + b'\0'))
    # 21: reserved bits of the control word set
    f.append(eth(struct.pack('>II', (2 << 12) | 0x102, 0xf0000015) + tdm(32)))
    return f


def malformed_frames():
    f = []
    # 1: only the ECID word
    f.append(eth(struct.pack('>I', (1 << 12) | 0x102)))
    # 2: the control word cut short
    f.append(eth(struct.pack('>I', (1 << 12) | 0x102) + b'\x00\x00'))
    # 3: shorter than the ECID word
    f.append(eth(b'\x00\x01'))
    # 4: Len 20 (22 octets padding) but only 10 octets after the
    #    control word: the padding runs past the end
    f.append(ces(sn=20, ln=20, tail=tdm(10)))
    # 5: RTP header cut short (heuristic matches the first 4 octets)
    f.append(ces(sn=21, tail=rtp(21)[:6]))
    return f


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcap(os.path.join(out, 'cesoeth-coverage.pcap'), main_frames())
    pcap(os.path.join(out, 'cesoeth-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()
