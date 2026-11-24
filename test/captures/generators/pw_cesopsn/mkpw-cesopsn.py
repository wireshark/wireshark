#!/usr/bin/env python3
# Generates test/captures/pw_cesopsn_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Common helpers: pcap writer and Ethernet / MPLS / IPv4 / UDP builders.
import struct
import sys
import os

MAC_A = bytes.fromhex('020000000001')
MAC_B = bytes.fromhex('020000000002')
IP_A = bytes([192, 0, 2, 1])
IP_B = bytes([192, 0, 2, 2])


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def eth(payload, etype, dst=MAC_B, src=MAC_A):
    return dst + src + struct.pack('>H', etype) + payload


def ipv4(payload, proto=17, src=IP_A, dst=IP_B, ident=1):
    h = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0,
                    64, proto, 0, src, dst)
    h = h[:10] + struct.pack('>H', csum(h)) + h[12:]
    return h + payload


def ipv6(payload, nh=17):
    src = bytes.fromhex('20010db8000000000000000000000001')
    dst = bytes.fromhex('20010db8000000000000000000000002')
    return struct.pack('>IHBB', 0x60000000, len(payload), nh, 64) + src + dst + payload


def udp(payload, sport, dport, src=IP_A, dst=IP_B):
    n = 8 + len(payload)
    pseudo = src + dst + struct.pack('>BBH', 0, 17, n)
    h = struct.pack('>HHHH', sport, dport, n, 0)
    c = csum(pseudo + h + payload) or 0xffff
    return struct.pack('>HHHH', sport, dport, n, c) + payload


def udp_frame(payload, sport, dport, ident=1):
    return eth(ipv4(udp(payload, sport, dport), ident=ident), 0x0800)


def mpls(label, payload, ttl=64, tc=0, bos=1):
    return struct.pack('>I', (label << 12) | (tc << 9) | (bos << 8) | ttl) + payload


def mpls_frame(label, payload, **kw):
    return eth(mpls(label, payload, **kw), 0x8847)


class Pcap:
    def __init__(self):
        self.frames = []

    def add(self, data, comment=None):
        self.frames.append(data)
        return len(self.frames)

    def write(self, path):
        with open(path, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
            for i, d in enumerate(self.frames):
                t = 1700000000 + i
                f.write(struct.pack('<IIII', t, 1000 * i, len(d), len(d)))
                f.write(d)
        return len(self.frames)

# ---- pw-cesopsn ----
# CESoPSN basic mode over MPLS (Decode As mpls.label) and over UDP (Decode As udp.port).
L_CES = 1002
UDP_PORT = 9002


def cw(l=0, r=0, m=0, frg=0, ln=0, seq=0, bits03=0):
    return struct.pack('>BBH', (bits03 << 4) | (l << 3) | (r << 2) | m,
                       (frg << 6) | ln, seq)


def pay(n, start=0):
    return bytes((start + i) & 0xff for i in range(n))


def m(p, label=L_CES):
    return mpls_frame(label, p)


def u(p, port=UDP_PORT, ident=1):
    return udp_frame(p, 40000, port, ident)


def build(out):
    main = Pcap()
    main.add(m(cw(seq=1) + pay(32)))                          # 1 normal, 32 octets
    main.add(m(cw(ln=12, seq=2) + pay(8)))                    # 2 length field set (short packet)
    main.add(m(cw(m=2, seq=3) + pay(64)))                     # 3 RDI on the AC, length 0 (packet >= 64)
    main.add(m(cw(l=1, seq=4) + pay(16)))                     # 4 L bit: TDM data invalid
    main.add(m(cw(l=1, seq=5)))                               # 5 L bit, payload omitted
    main.add(m(cw(ln=20, seq=6) + pay(16) + b'\0' * 6))       # 6 padding
    main.add(m(cw(r=1, seq=7) + pay(24)))                     # 7 R bit
    main.add(m(cw(m=1, seq=8) + pay(5)))                      # 8 reserved L+M combination (warning)
    main.add(m(cw(m=3, seq=9) + pay(7)))                      # 9 M=3, reserved for CESoPSN signalling
    main.add(m(cw(l=1, m=2, seq=10) + pay(9)))                # 10 L with M=2: reserved combination
    main.add(m(cw(seq=11) + pay(256)))                        # 11 E1, 32 timeslots
    ip4 = ipv4(udp(b'x' * 8, 5000, 5001))
    main.add(m(ip4))                                          # 12 first nibble 4 -> IPv4
    main.add(m(ipv6(udp(b'y' * 8, 5000, 5001))))              # 13 first nibble 6 -> IPv6
    main.add(m(bytes.fromhex('10000027') + struct.pack('>HBB', 100, 8, 0x80)
               + struct.pack('>HHI', 0x096a, 4, 0x20)))       # 14 first nibble 1 -> PW ACH, PW OAM
    main.add(u(cw(seq=15) + pay(48), ident=15))               # 15 UDP
    main.add(u(cw(l=1, seq=16), ident=16))                    # 16 UDP, payload omitted
    main.add(u(cw(ln=12, seq=17) + pay(8) + b'\xee' * 4, ident=17))  # 17 UDP, padding
    n = main.write(os.path.join(out, 'pw-cesopsn-coverage.pcap'))

    bad = Pcap()
    bad.add(m(b'\x00\x00'))                                   # 1 shorter than the CW
    bad.add(m(cw(bits03=8, seq=1) + pay(16)))                 # 2 bits 0-3 set
    bad.add(m(cw(frg=1, seq=2) + pay(16)))                    # 3 fragmentation
    bad.add(m(cw(ln=2, seq=3) + pay(16)))                     # 4 length too small
    bad.add(m(cw(ln=60, seq=4) + pay(16)))                    # 5 length larger than the packet
    bad.add(m(cw(ln=10, seq=5) + pay(70)))                    # 6 length nonzero, packet >= 64
    bad.add(m(cw(seq=6)))                                     # 7 no payload without the L bit
    bad.add(m(cw(seq=7) + pay(13)))                           # 8 payload not a multiple of 8
    bad.add(m(cw(m=2, seq=8) + pay(3)))                       # 9 RDI, payload not a multiple of 8
    bad.add(u(b'\x00', ident=2))                              # 10 UDP shorter than the CW
    bad.add(u(cw(bits03=1, frg=3, ln=1, seq=9) + pay(5), ident=3))  # 11
    nb = bad.write(os.path.join(out, 'pw-cesopsn-coverage-malformed.pcap'))
    print('main', n, 'malformed', nb)


if __name__ == '__main__':
    build(sys.argv[1] if len(sys.argv) > 1 else '.')
