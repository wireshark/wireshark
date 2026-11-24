#!/usr/bin/env python3
# Generates test/captures/pw_eth_coverage.pcap.gz
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

# ---- pw-eth ----
# Ethernet pseudowires over MPLS: reached by default through the first
# nibble (0: control word heuristic) and the MPLS heuristic (plain
# Ethernet); the three handles are also bound with Decode As.
L_CW, L_NOCW, L_HEUR = 2001, 2002, 2003

# MAC addresses whose OUIs are known (the heuristic looks them up)
CISCO_A = bytes.fromhex('00000c010000')     # 00:00:0c prefix, unicast
CISCO_B = bytes.fromhex('00000c000102')     # fifth octet odd: not a plausible Ethernet header at offset 4
HP_A = bytes.fromhex('3cd92b000001')        # first octet 0x3c: first nibble 3
HP_B = bytes.fromhex('3cd92b000002')
LOCAL_A = bytes.fromhex('020000000001')
LOCAL_B = bytes.fromhex('020001000002')   # third octet odd: not a plausible Ethernet header at offset 0


def pwcw(seq=0, flags=0):
    return struct.pack('>HH', flags, seq)


def inner_ip(dst, src, ident=1):
    return eth(ipv4(udp(b'pw-eth', 7000, 7001), ident=ident), 0x0800, dst=dst, src=src)


def inner_arp(dst, src, ip=IP_A):
    arp = struct.pack('>HHBBH', 1, 0x0800, 6, 4, 1) + src + ip + bytes(6) + IP_B
    return eth(arp, 0x0806, dst=dst, src=src)


def inner_llc(dst, src):
    # 802.3 length, LLC DSAP/SSAP 0x42 (spanning tree), control 0x03, BPDU-sized data
    data = bytes([0x42, 0x42, 0x03]) + bytes(35)
    return dst + src + struct.pack('>H', len(data)) + data


def m(label, p):
    return mpls_frame(label, p)


def build(out):
    main = Pcap()
    # first nibble 0 -> "Ethernet PW (CW heuristic)": CW chosen
    main.add(m(100, pwcw(1) + inner_ip(CISCO_A, CISCO_B)))                  # 1 CW, known OUIs
    main.add(m(100, pwcw(2) + inner_arp(LOCAL_B, LOCAL_A)))                 # 2 CW, locally administered
    main.add(m(100, pwcw(3, 0x0200) + inner_ip(LOCAL_B, LOCAL_A, 3)))       # 3 CW with flag bits
    # first nibble 0 without CW: the Ethernet header is found at offset 0
    main.add(m(101, inner_ip(CISCO_A, CISCO_B, 4)))                         # 4 no CW
    main.add(m(101, inner_arp(CISCO_A, CISCO_B, bytes([192, 0, 2, 5]))))                           # 5 no CW, ARP
    # MPLS heuristic: plain Ethernet whose first nibble is not 0, 1, 4 or 6
    main.add(m(102, inner_ip(HP_A, HP_B, 6)))                               # 6 heuristic, Ethernet II
    main.add(m(102, inner_arp(HP_A, HP_B, bytes([192, 0, 2, 6]))))                                 # 7 heuristic, ARP
    main.add(m(102, inner_llc(HP_A, HP_B)))                                 # 8 heuristic, 802.3 with LLC
    main.add(m(102, inner_llc(HP_A, LOCAL_B)))                              # 9 heuristic, LLC, locally administered SA
    # Decode As on the label: CW, no CW, heuristic
    main.add(m(L_CW, pwcw(10) + inner_ip(LOCAL_B, LOCAL_A, 10)))            # 10 pwethcw
    main.add(m(L_NOCW, inner_ip(LOCAL_B, LOCAL_A, 11)))                     # 11 pwethnocw
    main.add(m(L_HEUR, pwcw(12) + inner_ip(CISCO_A, CISCO_B, 12)))          # 12 heuristic: CW
    main.add(m(L_HEUR, inner_ip(CISCO_A, CISCO_B, 13)))                     # 13 heuristic: first nibble 0, no CW
    main.add(m(L_HEUR, inner_ip(HP_A, HP_B, 14)))                           # 14 heuristic: first nibble not 0
    # first nibble 4 / 6 / 1 on a CW handler go to IPv4, IPv6 and the PW ACH
    main.add(m(L_CW, ipv4(udp(b'x' * 8, 5000, 5001))))                      # 15
    main.add(m(L_CW, ipv6(udp(b'y' * 8, 5000, 5001))))                      # 16
    main.add(m(L_CW, bytes.fromhex('10000027') + struct.pack('>HBB', 100, 8, 0x80)
               + struct.pack('>HHI', 0x096a, 4, 2)))                        # 17 PW ACH, PW OAM
    # two labels in the stack
    main.add(eth(mpls(300, mpls(100, pwcw(18) + inner_ip(CISCO_A, CISCO_B, 18)), bos=0, ttl=64), 0x8847))  # 18
    n = main.write(os.path.join(out, 'pw-eth-coverage.pcap'))

    bad = Pcap()
    bad.add(m(100, b'\x00\x00'))                                           # 1 first nibble 0, shorter than the CW
    bad.add(m(100, pwcw(1) + inner_ip(CISCO_A, CISCO_B)[:10]))             # 2 truncated Ethernet header after the CW
    bad.add(m(100, pwcw(2)))                                               # 3 CW only
    bad.add(m(L_CW, b'\x00\x00'))                                          # 4 CW handler, shorter than the CW
    bad.add(m(L_HEUR, bytes(10)))                                          # 5 heuristic, short, first nibble 0
    bad.add(m(102, HP_A + HP_B + struct.pack('>H', 2000) + bytes(10)))     # 6 heuristic: length beyond the packet
    bad.add(m(102, HP_A + HP_B + struct.pack('>H', 3)))                    # 7 heuristic: 802.3 length 3, too short for the SAPs
    bad.add(m(102, HP_A + HP_B + struct.pack('>H', 0x05f0) + bytes(30)))   # 8 heuristic: type below 0x0600
    bad.add(m(102, HP_A + HP_B + struct.pack('>H', 0x7777) + bytes(30)))   # 9 heuristic: unknown type
    bad.add(m(102, HP_A + HP_B + struct.pack('>H', 20) + bytes([0x77, 0x77, 3]) + bytes(20)))  # 10 unknown SAP
    bad.add(m(102, HP_A + HP_B + struct.pack('>H', 20) + bytes([0x42, 0x77, 3]) + bytes(20)))  # 11 unknown SSAP
    bad.add(m(102, bytes.fromhex('3cd92b000001') + bytes.fromhex('3dd92b000002') + b'\x08\x00' + bytes(30)))  # 12 SA with group bit
    bad.add(m(102, bytes.fromhex('3cd92b000001') + bytes.fromhex('3ad92b000002') + b'\x08\x00' + bytes(30)))  # 13 SA locally administered
    bad.add(m(102, bytes.fromhex('3cd92bffffff') + bytes.fromhex('f2fffffffff0') + b'\x08\x00' + bytes(30)))  # 14 unknown SA OUI
    bad.add(m(102, bytes.fromhex('3e0000000001') + HP_B + b'\x08\x00' + bytes(30)))  # 15 DA with unknown OUI (locally administered bit)
    bad.add(m(102, bytes.fromhex('3c0000000001') + HP_B + b'\x08\x00' + bytes(30)))  # 16 DA unknown OUI
    bad.add(m(102, HP_A + HP_B + struct.pack('>H', 0)))                    # 17 heuristic: 802.3 length 0, no SAPs captured
    nb = bad.write(os.path.join(out, 'pw-eth-coverage-malformed.pcap'))
    print('main', n, 'malformed', nb)


if __name__ == '__main__':
    build(sys.argv[1] if len(sys.argv) > 1 else '.')
