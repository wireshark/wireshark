#!/usr/bin/env python3
# Generates test/captures/hsr_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic captures for packet-hsr.c (HSR tag, ethertype 0x892f).
Usage: mkhsr.py <outdir>"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import struct
from pylib import A, B, eth, H, ip4, ipv4, mac, Pcap, S, udp

def hsr(path, lsdu, seq, etype, inner):
    """path: 4 bit (net id 3 bits, lane id 1 bit)"""
    return struct.pack('>HHH', (path << 12) | lsdu, seq, etype) + inner

def frame(path, seq, etype, inner, lsdu=None, src=S, dst=H):
    if lsdu is None:
        lsdu = 6 + len(inner)
    return eth(dst, src, 0x892f, hsr(path, lsdu, seq, etype, inner))

def udp_pkt(sport, dport, n):
    return ipv4(A, B, 17, udp(sport, dport, bytes(range(n))))

def arp():
    return struct.pack('>HHBBH6s4s6s4s', 1, 0x0800, 6, 4, 1, mac(H), ip4(A), bytes(6), ip4(B))

def main(out):
    p = Pcap(1)
    # Every net id on both lanes, correct LSDU size, IPv4 payload
    for seq, path in enumerate(range(16)):
        p.add(frame(path, seq, 0x0800, udp_pkt(40000 + seq, 41000, 30)))
    # ARP inside HSR (ethertype table finds a dissector)
    p.add(frame(0, 100, 0x0806, arp()))
    p.add(frame(1, 100, 0x0806, arp(), src=H, dst='ff:ff:ff:ff:ff:ff'))
    # Unknown inner ethertype: data dissector
    p.add(frame(2, 101, 0x88b5, bytes(range(40))))
    # Wrong LSDU size, too small and too large
    p.add(frame(4, 102, 0x0800, udp_pkt(42000, 43000, 30), lsdu=10))
    p.add(frame(5, 103, 0x0800, udp_pkt(42000, 43000, 30), lsdu=0x0fff))
    # LSDU size 0 and maximum sequence number
    p.add(frame(0, 0xffff, 0x88b5, bytes(40), lsdu=0))
    # Exactly the 6 octets of the tag plus 54 octets of padding-sized data
    p.add(frame(1, 104, 0x88b5, bytes(54)))
    p.write(os.path.join(out, 'hsr-coverage.pcap'))

    m = Pcap(1)
    # Tag shorter than 6 octets (the type is missing), padded by Ethernet
    m.add(eth(H, S, 0x892f, struct.pack('>HH', 0x0006, 1)))
    m.add(eth(H, S, 0x892f, b'\x00'))
    # Tag with the type but nothing after it
    m.add(eth(H, S, 0x892f, struct.pack('>HHH', 0x0006, 2, 0x0800)))
    m.write(os.path.join(out, 'hsr-coverage-malformed.pcap'))

main(sys.argv[1])
