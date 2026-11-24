#!/usr/bin/env python3
# Generates test/captures/hp_erm_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures for the HP ERM dissector (packet-hp-erm.c).

HP encapsulated remote mirroring is a 12 octet header (8 octets
"Unknown1", then a 32 bit word with Unknown2 (8 bits), Priority (3 bits),
CFI, VLAN (12 bits), Is_Tagged and Unknown3 (7 bits)) in a UDP payload,
followed by the mirrored Ethernet frame without FCS. The protocol has no
registered port (Decode As on udp.port only); the captures use UDP 7933
so tshark needs "-d udp.port==7933,hp_erm". Every packet is built with
struct; addresses are from 192.0.2.0/24 and 02:00:00:00:00:xx.

Usage: mkhp_erm.py <output directory>
Writes hp_erm-coverage.pcap and hp_erm-coverage-malformed.pcap.
"""
import struct
import sys
import os

PORT = 7933

def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b)//2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def eth(dst, src, etype, payload):
    return bytes.fromhex(dst.replace(':', '')) + bytes.fromhex(src.replace(':', '')) + struct.pack('!H', etype) + payload

def ipv4(proto, payload, src=(192,0,2,10), dst=(192,0,2,20)):
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0, bytes(src), bytes(dst))
    h = h[:10] + struct.pack('!H', csum(h)) + h[12:]
    return h + payload

def udp(sport, dport, payload, src, dst):
    u = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    ps = bytes(src) + bytes(dst) + struct.pack('!BBH', 0, 17, len(u))
    c = csum(ps + u) or 0xffff
    return u[:6] + struct.pack('!H', c) + u[8:]

def pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)) + fr)

def outer(payload, sport=40000):
    s, d = (192,0,2,1), (192,0,2,2)
    u = udp(sport, PORT, payload, s, d)
    return eth('02:00:00:00:00:02', '02:00:00:00:00:01', 0x0800, ipv4(17, u, s, d))

def hdr(unk1, unk2, pri, cfi, vlan, tagged, unk3):
    w = (unk2 << 24) | (pri << 21) | (cfi << 20) | (vlan << 8) | (tagged << 7) | unk3
    return unk1 + struct.pack('!I', w)

def inner_ip(payload=b'mirrored'):
    s, d = (192,0,2,10), (192,0,2,20)
    return eth('02:00:00:00:00:20', '02:00:00:00:00:10', 0x0800,
               ipv4(17, udp(1000, 2000, payload, s, d), s, d))

def inner_arp():
    a = struct.pack('!HHBBH', 1, 0x0800, 6, 4, 1) + bytes.fromhex('020000000010') + bytes([192,0,2,10]) + bytes(6) + bytes([192,0,2,20])
    return eth('ff:ff:ff:ff:ff:ff', '02:00:00:00:00:10', 0x0806, a)

def inner_vlan(vid, pri):
    tci = (pri << 13) | vid
    return eth('02:00:00:00:00:20', '02:00:00:00:00:10', 0x8100,
               struct.pack('!HH', tci, 0x0800) + ipv4(17, udp(1000, 2000, b'tagged', (192,0,2,10), (192,0,2,20))))

U1 = bytes.fromhex('0001020304050607')

def main_frames():
    F = []
    # 1-8: every priority value, untagged, canonical
    for pri in range(8):
        F.append(outer(hdr(U1, 0, pri, 0, 1 + pri, 0, 0) + inner_ip()))
    # 9: non-canonical CFI, tagged, VLAN 4094, unknown2/3 non-zero
    F.append(outer(hdr(U1, 0xa5, 3, 1, 4094, 1, 0x55) + inner_vlan(4094, 3)))
    # 10: VLAN 0 and the max Unknown1
    F.append(outer(hdr(b'\xff' * 8, 0xff, 7, 1, 0, 1, 0x7f) + inner_arp()))
    # 11: tagged with VLAN 100 and a zero unknown1
    F.append(outer(hdr(bytes(8), 0, 5, 0, 100, 1, 0) + inner_vlan(100, 5)))
    # 12: mirrored frame that is only an Ethernet header with an unknown type
    F.append(outer(hdr(U1, 0, 2, 0, 1, 0, 0) + eth('02:00:00:00:00:20', '02:00:00:00:00:10', 0x88b5, b'x' * 20)))
    # 13: second source port (a new conversation)
    F.append(outer(hdr(U1, 1, 6, 0, 200, 0, 1) + inner_ip(b'voice'), sport=40001))
    return F

def malformed_frames():
    F = []
    # header cut short (11 octets): exception in the bitmask
    F.append(outer(hdr(U1, 0, 0, 0, 1, 0, 0)[:11]))
    # header only, no mirrored frame
    F.append(outer(hdr(U1, 0, 0, 0, 1, 0, 0)))
    # only 5 octets
    F.append(outer(U1[:5]))
    # truncated mirrored Ethernet header
    F.append(outer(hdr(U1, 0, 0, 0, 1, 0, 0) + b'\x02\x00\x00\x00\x00\x20\x02'))
    # mirrored frame with a truncated IPv4 header
    F.append(outer(hdr(U1, 0, 0, 0, 1, 0, 0) + eth('02:00:00:00:00:20', '02:00:00:00:00:10', 0x0800, b'\x45\x00\x00')))
    return F

if __name__ == '__main__':
    d = sys.argv[1]
    os.makedirs(d, exist_ok=True)
    pcap(os.path.join(d, 'hp_erm-coverage.pcap'), main_frames())
    pcap(os.path.join(d, 'hp_erm-coverage-malformed.pcap'), malformed_frames())
