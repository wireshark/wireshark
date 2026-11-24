#!/usr/bin/env python3
# Generates test/captures/ipsec_udp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic coverage captures for packet-ipsec-udp.c (UDP Encapsulation of
IPsec Packets, NAT traversal on UDP port 4500).

Usage: mkipsec-udp.py <outdir> [-v]

Writes ipsec-udp-coverage.pcap (clean) and ipsec-udp-coverage-malformed.pcap.
ESP payloads are constant placeholder bytes.
"""
import struct
import sys
import os

VERBOSE = '-v' in sys.argv
args = [a for a in sys.argv[1:] if not a.startswith('-')]
OUT = args[0] if args else '.'

class Cap:
    def __init__(self):
        self.recs = []; self.ts = 1700000000; self.marks = []
    def mark(self, t):
        self.marks.append((len(self.recs) + 1, t))
    def pkt(self, p, caplen=None):
        self.ts += 1
        cl = len(p) if caplen is None else caplen
        self.recs.append(struct.pack('<IIII', self.ts, 0, cl, len(p)) + p[:cl])
    def write(self, name):
        with open(os.path.join(OUT, name), 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            f.write(b''.join(self.recs))
        if VERBOSE:
            print(name, len(self.recs), 'frames')
            for i, (n, t) in enumerate(self.marks):
                end = self.marks[i + 1][0] - 1 if i + 1 < len(self.marks) else len(self.recs)
                print('  %d-%d  %s' % (n, end, t))

M1 = b'\x02\x00\x00\x00\x00\x01'; M2 = b'\x02\x00\x00\x00\x00\x02'
A1 = b'\xc0\x00\x02\x01'; A2 = b'\xc0\x00\x02\x02'
V1 = bytes.fromhex('20010db8000000000000000000000001')
V2 = bytes.fromhex('20010db8000000000000000000000002')

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def udp(sport, dport, data):
    return struct.pack('!HHHH', sport, dport, 8 + len(data), 0x1234) + data

def v4(sport, dport, data, src=A1, dst=A2):
    p = udp(sport, dport, data)
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(p), 1, 0, 64, 17, 0, src, dst)
    h = h[:10] + struct.pack('!H', csum(h)) + h[12:]
    return M2 + M1 + b'\x08\x00' + h + p

def v6(sport, dport, data):
    p = udp(sport, dport, data)
    return M2 + M1 + b'\x86\xdd' + struct.pack('!IHBB', 0x60000000, len(p), 17, 64) + V1 + V2 + p

def esp(spi, seq, body):
    return struct.pack('!II', spi, seq) + body

def ike_hdr(exch=34, flags=0x08, resp=b'\0' * 8, version=0x20):
    return b'\x11' * 8 + resp + struct.pack('!BBBBII', 0, version, exch, flags, 0, 28)

def build():
    c = Cap()
    c.mark('ESP in UDP port 4500 (IPv4, from the client port, from the server port, SPI with high bit set, SPI 0x00000001, 8 octet ESP with no payload)')
    c.pkt(v4(4500, 4500, esp(0x8000, 1, b'\x11\x22\x33\x44' * 4)))
    c.pkt(v4(40000, 4500, esp(0x8000, 2, b'\x11\x22\x33\x44' * 4)))
    c.pkt(v4(4500, 40000, esp(0x8000, 3, b'\x11\x22\x33\x44' * 4)))
    c.pkt(v4(4500, 4500, esp(0xffffffff, 4, b'\x55' * 16)))
    c.pkt(v4(4500, 4500, esp(0x00000001, 5, b'\x66' * 16)))
    c.pkt(v4(4500, 4500, esp(0x00000100, 6, b'')))
    c.mark('NAT keepalive: 0xff, and 0xff followed by more data (an ESP packet with SPI 0xff......)')
    c.pkt(v4(4500, 4500, b'\xff'))
    c.pkt(v4(40000, 4500, b'\xff'))
    c.pkt(v4(4500, 4500, b'\xff\x00\x00\x00\x00\x00\x00\x01' + b'\x77' * 8))
    c.mark('IKE with non-ESP marker: IKEv2 (request, response), IKEv1 (main mode), marker only with a header')
    c.pkt(v4(4500, 4500, b'\x00\x00\x00\x00' + ike_hdr()))
    c.pkt(v4(4500, 4500, b'\x00\x00\x00\x00' + ike_hdr(flags=0x20, resp=b'\x22' * 8)))
    c.pkt(v4(4500, 4500, b'\x00\x00\x00\x00' + ike_hdr(exch=2, flags=0, version=0x10)))
    c.mark('IPv6')
    c.pkt(v6(4500, 4500, esp(0x9000, 1, b'\x11' * 16)))
    c.pkt(v6(4500, 4500, b'\xff'))
    c.pkt(v6(4500, 4500, b'\x00\x00\x00\x00' + ike_hdr()))
    c.write('ipsec-udp-coverage.pcap')

    m = Cap()
    m.mark('Payloads too short for the SPI (1 to 3 octets, not 0xff), an empty payload, a marker without IKE header, a cut-off IKE header, keepalive cut short')
    m.pkt(v4(4500, 4500, b'\x01'))
    m.pkt(v4(4500, 4500, b'\x00\x00'))
    m.pkt(v4(4500, 4500, b'\xff\xff\xff'))
    m.pkt(v4(4500, 4500, b''))
    m.pkt(v4(4500, 4500, b'\x00\x00\x00\x00'))
    m.pkt(v4(4500, 4500, b'\x00\x00\x00\x00' + ike_hdr()[:12]))
    m.pkt(v4(4500, 4500, esp(0x8000, 1, b'\x11' * 16)), caplen=14 + 20 + 8 + 6)
    m.pkt(v4(4500, 4500, b'\xff'), caplen=14 + 20 + 8)
    m.pkt(v4(4500, 4500, b'\xff\xff'))
    m.write('ipsec-udp-coverage-malformed.pcap')

build()
