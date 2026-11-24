#!/usr/bin/env python3
# Generates test/captures/pa-hbbackup_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generator for the Palo Alto Heartbeat Backup coverage captures.
# Usage: mkpa-hbbackup.py <outdir> [-v]
# The protocol is registered on Ethertype 0x8988 (default). It carries 6
# unknown octets and an inner Ethertype, which is handed to the ethertype
# dissector.
import os
import struct
import sys
from pcaplib import eth, ipv4, write_pcap

def hb(inner_type, payload, unknown=bytes.fromhex('0a0b0c0d0e0f')):
    return unknown + struct.pack('>H', inner_type) + payload

def frame(payload, dst='ffffffffffff'):
    return eth(payload, 0x8988, dst=dst)

def ip_udp(sport, dport, data):
    u = struct.pack('!HHHH', sport, dport, 8 + len(data), 0) + data
    return ipv4(17, u)

def arp():
    return struct.pack('>HHBBH', 1, 0x0800, 6, 4, 1) + bytes.fromhex('020000000001') + bytes([192, 0, 2, 1]) + bytes(6) + bytes([192, 0, 2, 2])

def main_frames():
    F, marks = [], []
    def mark(n): marks.append((n, len(F) + 1))
    def add(p, **kw): F.append(frame(p, **kw))
    mark('inner Ethertypes: IPv4/UDP (carried data), ARP, an unregistered Ethertype')
    add(hb(0x0800, ip_udp(40000, 40001, b'heartbeat payload')))
    add(hb(0x0806, arp()))
    add(hb(0x88b5, b'local experimental ethertype payload'))
    mark('trailer: an IPv4 packet shorter than the frame (padding after it)')
    add(hb(0x0800, ip_udp(40000, 40001, b'short')) + bytes(14))
    mark('nesting: Heartbeat Backup inside Heartbeat Backup, three levels')
    inner = hb(0x0800, ip_udp(1, 2, b'deep'))
    for i in range(2):
        inner = hb(0x8988, inner)
    add(inner)
    return F, marks

def malformed_frames():
    F = []
    F.append(frame(b'\x01\x02\x03'))                              # header cut short
    F.append(frame(bytes(6) + b'\x08'))                           # Ethertype cut short
    F.append(frame(hb(0x0800, b'\x45\x00\x00')))                  # truncated inner IPv4
    F.append(frame(hb(0x0806, b'\x00\x01')))                      # truncated inner ARP
    pl = bytes(6) + struct.pack('>H', 0x8988)
    F.append(frame(pl * 2000))                                     # nested 2000 times (review reproducer): depth limit of the Ethertype dissector
    F.append(frame(pl * 12))                                       # nested 12 times
    F.append(frame(bytes(8)))                                      # inner Ethertype 0 with nothing after it
    return F

if __name__ == '__main__':
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    F, marks = main_frames()
    write_pcap(os.path.join(out, 'pa-hbbackup-coverage.pcap'), F)
    M = malformed_frames()
    write_pcap(os.path.join(out, 'pa-hbbackup-coverage-malformed.pcap'), M)
    if '-v' in sys.argv:
        for n, s in marks: print(s, n)
        print(len(F), 'frames', len(M), 'malformed frames')
