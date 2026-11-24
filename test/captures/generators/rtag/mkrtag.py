#!/usr/bin/env python3
# Generates test/captures/rtag_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the R-TAG (IEEE 802.1CB, ethertype 0xf1c1) coverage captures.
Usage: mkrtag.py <outdir> [-v]. Everything is synthetic (192.0.2.0/24)."""
import struct
import sys
import os

def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b)//2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def ipv4(payload, proto=17, src=(192,0,2,1), dst=(192,0,2,2), pad=b''):
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0, bytes(src), bytes(dst))
    h = h[:10] + struct.pack('!H', csum(h)) + h[12:]
    return h + payload + pad

def udp(sport, dport, data):
    return struct.pack('!HHHH', sport, dport, 8 + len(data), 0) + data

def rtag(seq, etype, payload, reserved=0):
    return struct.pack('!HHH', reserved, seq, etype) + payload

def eth(etype, payload):
    return b'\x02\x00\x00\x00\x00\x02' + b'\x02\x00\x00\x00\x00\x01' + struct.pack('!H', etype) + payload

def write_pcap(path, frames, linktype=1):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)

RT = 0xf1c1
def main_frames():
    F = []
    ip = ipv4(udp(1000, 2000, b'hello'))
    F.append(eth(RT, rtag(0, 0x0800, ip)))                  # 1 IPv4/UDP, seq 0
    F.append(eth(RT, rtag(1, 0x0800, ip, reserved=0)))      # 2 seq 1
    F.append(eth(RT, rtag(65535, 0x0800, ip)))              # 3 max seq
    F.append(eth(RT, rtag(2, 0x0800, ip, reserved=0x1234))) # 4 non-zero reserved
    arp = struct.pack('!HHBBH6s4s6s4s', 1, 0x0800, 6, 4, 1, b'\2\0\0\0\0\1', bytes([192,0,2,1]), b'\0'*6, bytes([192,0,2,2]))
    F.append(eth(RT, rtag(3, 0x0806, arp)))                 # 5 ARP
    a6 = b'\x20\x01\x0d\xb8' + b'\0'*11 + b'\1'; b6 = b'\x20\x01\x0d\xb8' + b'\0'*11 + b'\2'
    u = udp(1, 2, b'abcd')
    ck = csum(a6 + b6 + struct.pack('!IBBBB', len(u), 0, 0, 0, 17) + u)
    u = u[:6] + struct.pack('!H', ck) + u[8:]
    v6 = struct.pack('!IHBB16s16s', 0x60000000, len(u), 17, 64, a6, b6) + u
    F.append(eth(RT, rtag(4, 0x86dd, v6)))                  # 6 IPv6
    vlan = struct.pack('!HH', 0x0064, 0x0800) + ip
    F.append(eth(RT, rtag(5, 0x8100, vlan)))                # 7 802.1Q then IPv4
    F.append(eth(RT, rtag(6, RT, rtag(7, 0x0800, ip))))     # 8 R-TAG inside R-TAG
    F.append(eth(RT, rtag(8, 0x88b5, b'unknown-payload')))  # 9 ethertype handled as data (local experimental)
    F.append(eth(RT, rtag(9, 0x0800, ip, ) + b''))          # 10
    # IPv4 frame with trailing octets after the IP datagram: Ethernet trailer
    F.append(eth(RT, rtag(10, 0x0800, ipv4(udp(1, 2, b'x'), pad=b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'))))  # 11 zero padding trailer
    F.append(eth(RT, rtag(11, 0x0800, ipv4(udp(1, 2, b'x'), pad=b'\xde\xad\xbe\xef\x01\x02\x03\x04'))))  # 12 non-zero trailer
    ic = struct.pack('!BBHHH', 8, 0, 0, 9, 1) + b'ping'
    ic = ic[:2] + struct.pack('!H', csum(ic)) + ic[4:]
    F.append(eth(RT, rtag(12, 0x0800, ipv4(ic, proto=1))))  # 13 ICMP echo request
    return F

def mal_frames():
    F = []
    F.append(eth(RT, b'\x00\x00\x00'))                       # tag cut after 3 octets
    F.append(eth(RT, b'\x00\x00\x00\x01\x08'))               # 5 octets: no ethertype
    F.append(eth(RT, b''))                                   # nothing after the ethertype
    F.append(eth(RT, rtag(1, 0x0800, b'\x45\x00\x00')))      # truncated IPv4
    return F

if __name__ == '__main__':
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    m = main_frames(); x = mal_frames()
    write_pcap(os.path.join(out, 'rtag-coverage.pcap'), m)
    write_pcap(os.path.join(out, 'rtag-coverage-malformed.pcap'), x)
    if '-v' in sys.argv:
        print('main frames', len(m), 'malformed frames', len(x))
