#!/usr/bin/env python3
# Generates test/captures/pw_fr_coverage.pcap.gz
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

# ---- pw-fr ----
# Frame Relay DLCI pseudowire (Decode As mpls.label).
L_FR = 3001


def cw(fecn=0, becn=0, de=0, cr=0, frg=0, ln=0, seq=0, bits03=0):
    return struct.pack('>BBH', (bits03 << 4) | (fecn << 3) | (becn << 2) | (de << 1) | cr,
                       (frg << 6) | ln, seq)


def ip_udp(n, ident=1):
    return ipv4(udp(bytes((i & 0xff) for i in range(n)), 5000, 5001), ident=ident)


def frp(p):
    # stripped FR payload: control (UI), NLPID IP
    return bytes([0x03, 0xcc]) + p


def m(p, label=L_FR):
    return mpls_frame(label, p)


def build(out):
    main = Pcap()
    p30 = frp(ip_udp(0, 1))                                     # 2 + 28 = 30 octets
    main.add(m(cw(ln=30, seq=1) + p30))                         # 1 short packet, length = payload
    main.add(m(cw(seq=2) + frp(ip_udp(48, 2))))                 # 2 payload 78 >= 64, length 0
    main.add(m(cw(ln=30, seq=3) + p30 + b'\0' * 6))             # 3 padding of 6
    main.add(m(cw(fecn=1, becn=1, de=1, cr=1, ln=30, seq=4) + p30))  # 4 all FR bits
    main.add(m(cw(frg=1, ln=30, seq=5) + p30))                  # 5 first fragment
    main.add(m(cw(frg=2, ln=30, seq=6) + p30))                  # 6 last fragment
    main.add(m(cw(frg=3, ln=30, seq=7) + p30))                  # 7 intermediate fragment
    snap = bytes([0x03, 0x80, 0x00, 0x00, 0x00, 0x08, 0x00]) + ip_udp(0, 8)
    main.add(m(cw(ln=len(snap), seq=8) + snap))                 # 8 SNAP encapsulated IP
    main.add(m(cw(seq=9) + frp(ip_udp(60, 9)) ))                # 9 exactly 64+ payload
    main.add(m(ipv4(udp(b'x' * 8, 5000, 5001))))                # 10 first nibble 4
    main.add(m(ipv6(udp(b'y' * 8, 5000, 5001))))                # 11 first nibble 6
    main.add(m(bytes.fromhex('10000027') + struct.pack('>HBB', 100, 8, 0x80)
               + struct.pack('>HHI', 0x096a, 4, 4)))            # 12 first nibble 1, PW ACH
    n = main.write(os.path.join(out, 'pw-fr-coverage.pcap'))

    bad = Pcap()
    bad.add(m(b'\x00\x00'))                                     # 1 shorter than the CW
    bad.add(m(cw(bits03=8, ln=30, seq=1) + p30))                # 2 bits 0-3 set
    bad.add(m(cw(seq=2) + p30))                                 # 3 length 0 with a short packet
    bad.add(m(cw(ln=50, seq=3) + p30))                          # 4 length larger than the packet
    bad.add(m(cw(ln=10, seq=4) + frp(ip_udp(60, 4))))           # 5 length set with a packet >= 64
    bad.add(m(cw(seq=5)))                                       # 6 CW only: zero payload
    bad.add(m(cw(ln=1, seq=6) + p30))                           # 7 length 1: one octet of payload, padding
    nb = bad.write(os.path.join(out, 'pw-fr-coverage-malformed.pcap'))
    print('main', n, 'malformed', nb)


if __name__ == '__main__':
    build(sys.argv[1] if len(sys.argv) > 1 else '.')
