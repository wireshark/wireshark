#!/usr/bin/env python3
# Generates test/captures/pw_satop_coverage.pcap.gz
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

# ---- pw-satop ----
# SAToP over MPLS (Decode As mpls.label) and over UDP (Decode As udp.port).
L_SATOP = 1001
UDP_PORT = 9001


def cw(l=0, r=0, rsv=0, frg=0, ln=0, seq=0, bits03=0):
    return struct.pack('>BBH', (bits03 << 4) | (l << 3) | (r << 2) | rsv,
                       (frg << 6) | ln, seq)


def rtp(seq, pt=0, marker=0, ts=0, ssrc=0x11223344, b0=0x80):
    return struct.pack('>BBHII', b0, (marker << 7) | pt, seq, ts, ssrc)


def pay(n, start=0):
    return bytes((start + i) & 0xff for i in range(n))


def m(p, label=L_SATOP):
    return mpls_frame(label, p)


def u(p, port=UDP_PORT, ident=1):
    return udp_frame(p, 40000, port, ident)


def build(out):
    main = Pcap()
    # 1-5: payload sizes the dissector recognises
    main.add(m(cw(seq=1) + pay(256)))                  # 1 looks like E1
    main.add(m(cw(seq=2) + pay(192)))                  # 2 T1
    main.add(m(cw(seq=3) + pay(1024)))                 # 3 E3/T3
    main.add(m(cw(ln=54, seq=4) + pay(50)))            # 4 octet-aligned T1, length set
    main.add(m(cw(seq=5) + pay(10)))                   # 5 no idea, length 0
    # 6: L bit, no payload (undecoded note)
    main.add(m(cw(l=1, seq=6) + rtp(6)))               # 6 L bit, RTP header, no payload
    # 7: R bit and L bit set with payload
    main.add(m(cw(l=1, r=1, seq=7) + pay(20)))         # 7
    # 8: padding after the payload (length 18 = 4 + 14, 6 octets padding)
    main.add(m(cw(ln=18, seq=8) + pay(14) + b'\0' * 6))  # 8
    # 9: RTP header found by the heuristic (sequence numbers match)
    main.add(m(cw(seq=9) + rtp(9) + pay(30)))          # 9
    # 10: RTP header and padding (the fix: padding follows the payload)
    main.add(m(cw(ln=26, seq=10) + rtp(10) + pay(10) + b'\xee' * 6))  # 10
    # 11-13: first nibble 4, 6 and 1 are handed to IPv4, IPv6 and PW ACH
    ip4 = ipv4(udp(b'x' * 8, 5000, 5001))
    main.add(m(ip4))                                   # 11
    main.add(m(ipv6(udp(b'y' * 8, 5000, 5001))))        # 12
    main.add(m(bytes.fromhex('10000027') + struct.pack('>HBB', 100, 8, 0x80)
               + struct.pack('>HHI', 0x096a, 4, 2)))   # 13
    # 14-19: UDP demultiplexing
    main.add(u(cw(seq=14) + pay(20), ident=14))                      # 14
    main.add(u(rtp(15) + cw(seq=15) + pay(24), ident=15))            # 15 RTP first
    main.add(u(rtp(16) + cw(ln=26, seq=16) + pay(10) + b'\xee' * 6, ident=16))  # 16
    main.add(u(cw(l=1, seq=17) + pay(12), ident=17))                 # 17
    main.add(u(cw(seq=18) + pay(192), ident=18))                     # 18 T1
    # 19: RTP header with a marker bit: not taken as RTP, so no shim
    main.add(m(cw(seq=19) + rtp(19, marker=1) + pay(20)))           # 19
    # 20: RTP header with a different sequence number: not RTP
    main.add(m(cw(seq=20) + rtp(21) + pay(20)))                      # 20
    n = main.write(os.path.join(out, 'pw-satop-coverage.pcap'))

    bad = Pcap()
    bad.add(m(b'\x00\x00'))                            # 1 shorter than the CW
    bad.add(m(cw(l=1, seq=1)))                         # 1b four octets: the RTP heuristic reads beyond the end
    bad.add(m(cw(bits03=8, seq=1) + pay(10)))          # 2 bits 0-3 set
    bad.add(m(cw(rsv=3, seq=2) + pay(10)))             # 3 reserved bits
    bad.add(m(cw(frg=2, seq=3) + pay(10)))             # 4 fragmentation
    bad.add(m(cw(ln=3, seq=4) + pay(10)))              # 5 length too small
    bad.add(m(cw(ln=40, seq=5) + pay(10)))             # 6 length larger than packet
    bad.add(m(cw(ln=10, seq=6) + pay(100)))            # 7 length nonzero, packet >= 64
    bad.add(m(cw(seq=7)))                              # 8 no payload, no L bit
    bad.add(u(cw(seq=8) + pay(4), ident=2))            # 9 UDP below 16 octets without RTP (exception)
    bad.add(u(b'\x00\x00', ident=3))                   # 10 UDP shorter than the CW
    bad.add(m(cw(seq=9) + rtp(9) + pay(3)))            # 11 RTP and little payload
    bad.add(m(cw(ln=20, seq=10) + rtp(10) + pay(2)))   # 12 RTP, length above payload
    bad.add(u(rtp(1) + cw(bits03=8, ln=2, frg=1, rsv=1, seq=1) + pay(8), ident=4))  # 13
    nb = bad.write(os.path.join(out, 'pw-satop-coverage-malformed.pcap'))
    print('main', n, 'malformed', nb)


if __name__ == '__main__':
    build(sys.argv[1] if len(sys.argv) > 1 else '.')
