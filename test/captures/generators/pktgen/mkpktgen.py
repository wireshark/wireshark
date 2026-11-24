#!/usr/bin/env python3
# Generates test/captures/pktgen_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the PKTGEN coverage captures (Linux pktgen over UDP, heuristic).
Usage: mkpktgen.py <outdir>.  Writes pktgen-coverage.pcap and
pktgen-coverage-malformed.pcap (Ethernet).  Every packet is built with
struct; nothing comes from a real network."""
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

MAGIC = 0xbe9be955

def pg(seq, sec=1700000000, usec=250000, data=b'', magic=MAGIC):
    return struct.pack('>IIII', magic, seq, sec, usec) + data

good = []
bad = []
good.append(eth_udp(pg(1), 40010, 40011))                                       # 1 header only (16 octets)
good.append(eth_udp(pg(2, data=bytes(range(64))), 40010, 40011))                # 2 with random data
good.append(eth_udp(pg(3, usec=0), 40010, 40011))                               # 3 microseconds 0
good.append(eth_udp(pg(4, usec=999999, data=b'\xff' * 8), 40002, 40003))  # 4 largest valid microseconds, other ports
good.append(eth_udp(pg(0xffffffff, sec=0xffffffff, usec=1), 12345, 40011))  # 5 largest sequence and seconds
good.append(eth_udp(pg(6, usec=1000000), 40010, 40011))                         # 6 microseconds out of range (the fix)
good.append(eth_udp(pg(7, usec=0xffffffff), 40010, 40011))                      # 7 microseconds 0xffffffff (negative before the fix)
good.append(eth_udp(pg(8, magic=0xbe9be954), 40010, 40011))                     # 8 wrong magic: plain UDP
good.append(eth_udp(pg(9)[:15], 40010, 40011))                                  # 9 15 octets: too short for the heuristic
good.append(eth_udp(b'', 40010, 40011))                                         # 10 empty UDP payload
good.append(eth(ipv4(udp(pg(11), 40010, 40011, src=(198, 51, 100, 1), dst=(198, 51, 100, 2)), src=(198, 51, 100, 1), dst=(198, 51, 100, 2))))  # 11 other addresses

# the malformed capture: a header cut at the UDP level, so the heuristic sees fewer octets than the UDP length says
bad.append(eth_udp(pg(1, data=b'abcdef'), 40010, 40011)[:-10])                  # 1 truncated capture
bad.append(eth_udp(pg(2), 40010, 40011)[:-4])                                   # 2 truncated inside the timestamp

if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcap(os.path.join(out, 'pktgen-coverage.pcap'), good, 1)
    pcap(os.path.join(out, 'pktgen-coverage-malformed.pcap'), bad, 1)
