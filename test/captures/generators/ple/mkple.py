#!/usr/bin/env python3
# Generates test/captures/ple_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the PLE coverage captures (Private Line Emulation, RFC 9801).
Usage: mkple.py <outdir>.  Writes ple-coverage.pcap and
ple-coverage-malformed.pcap (Ethernet).  Every packet is built with struct;
nothing comes from a real network."""
import os
import sys
import struct

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    s = (s & 0xffff) + (s >> 16)
    s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def ipv4(payload, proto=17, src=(192, 0, 2, 1), dst=(192, 0, 2, 2), ident=1):
    h = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0, 64, proto, 0, bytes(src), bytes(dst))
    h = h[:10] + struct.pack('>H', csum(h)) + h[12:]
    return h + payload

def udp(payload, sport, dport, src=(192, 0, 2, 1), dst=(192, 0, 2, 2)):
    h = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0)
    ph = bytes(src) + bytes(dst) + struct.pack('>BBH', 0, 17, 8 + len(payload))
    c = csum(ph + h + payload) or 0xffff
    return struct.pack('>HHHH', sport, dport, 8 + len(payload), c) + payload

ETH_A = bytes([2, 0, 0, 0, 0, 1])
ETH_B = bytes([2, 0, 0, 0, 0, 2])
def eth(payload, etype=0x0800, src=ETH_A, dst=ETH_B):
    return dst + src + struct.pack('>H', etype) + payload

def eth_udp(payload, sport, dport, **kw):
    return eth(ipv4(udp(payload, sport, dport), **kw))

def pcap(fn, pkts, lt=1, snaplen=262144):
    with open(fn, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, snaplen, lt))
        for i, p in enumerate(pkts):
            f.write(struct.pack('<IIII', 1000 + i, 0, len(p), len(p)))
            f.write(p)

def cw(seq, l=0, r=0, rsv=0, frg=0, ln=0, pfn=0):
    return struct.pack('>I', (pfn << 28) | (l << 27) | (r << 26) | (rsv << 24) | (frg << 22) | (ln << 16) | seq)

def rtp(seq, ts=1000, ssrc=0x11223344, pt=0x61, ver=2, marker=0):
    return struct.pack('>BBHII', (ver << 6), (marker << 7) | pt, seq, ts, ssrc)

def ple(c, r, payload=bytes(range(48))):
    return c + r + payload

def over_ip(p, **kw):     # IP protocol 147 (Bit-stream Emulation) carries PLE
    return eth(ipv4(p, proto=147, **kw))

good = []
bad = []
good.append(over_ip(ple(cw(1), rtp(1))))                                       # 1 CW and RTP sequence numbers equal
good.append(over_ip(ple(cw(0x0002), rtp(0x0002 + 0x30000 - 0x30000, ts=2000), b'\xff' * 8)))   # 2 equal again, short payload
good.append(over_ip(ple(cw(0x1234), rtp(0xabcd, ts=3000))))                    # 3 different: the 32 bit sequence number
good.append(over_ip(ple(cw(5, l=1), rtp(5, ts=4000))))                         # 4 L bit
good.append(over_ip(ple(cw(6, r=1), rtp(6, ts=5000))))                         # 5 R bit
good.append(over_ip(ple(cw(7, l=1, r=1), rtp(7, ts=6000))))                    # 6 both bits
good.append(over_ip(ple(cw(8, rsv=3, frg=1, ln=5), rtp(8, ts=7000))))          # 7 RSV, FRG and LEN set (warnings)
good.append(over_ip(ple(cw(9, pfn=0xf, frg=2), rtp(9, ts=8000))))              # 8 post-stack first nibble, last fragment
good.append(over_ip(ple(cw(10, frg=3), rtp(10, ts=9000, marker=1, pt=0x7f))))  # 9 intermediate fragment, marker bit
good.append(over_ip(cw(11) + rtp(11, ts=10000)))                               # 10 no payload after the RTP header
good.append(eth_udp(ple(cw(12), rtp(12, ts=11000)), 5000, 5000))               # 11 over UDP (reached by Decode As only)

bad.append(over_ip(cw(1) + b'\x00\x61\x00\x01' + bytes(20)))                   # 1 RTP version 0: header missing
bad.append(over_ip(cw(2) + rtp(2, ver=1) + bytes(8)))                          # 2 RTP version 1
bad.append(over_ip(cw(3)))                                                     # 3 only the control word (exception)
bad.append(over_ip(cw(4) + rtp(4)[:6]))                                        # 4 truncated RTP header
bad.append(over_ip(b'\x00\x00'))                                               # 5 truncated control word

if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcap(os.path.join(out, 'ple-coverage.pcap'), good, 1)
    pcap(os.path.join(out, 'ple-coverage-malformed.pcap'), bad, 1)
