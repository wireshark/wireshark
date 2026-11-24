#!/usr/bin/env python3
# Generates test/captures/arp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic coverage captures for epan/dissectors/packet-arp.c (ARP, RARP,
# DRARP, Inverse ARP, MARS/MAPOS opcodes, ATMARP, AX.25 ARP, duplicate
# address detection, request storm detection). Every packet is built with
# struct; nothing comes from a real network.
# Usage: mkarp.py <outdir>  -> arp-coverage.pcap, arp-coverage-malformed.pcap
import os
import struct
import sys

outdir = sys.argv[1] if len(sys.argv) > 1 else '.'

BCAST = b'\xff' * 6


def mac(n):
    return bytes([0x02, 0, 0, 0, 0, n])


def ip(n, net=2):
    return bytes([192, 0, net, n])


def eth(src, payload, et=0x0806, dst=BCAST):
    return dst + src + struct.pack('>H', et) + payload


def arp(hrd, pro, hln, pln, op, body):
    return struct.pack('>HHBBH', hrd, pro, hln, pln, op) + body


def atmarp(op, shtl, sstl, spln, thtl, tstl, tpln, body, pro=0x0800):
    return struct.pack('>HHBBHBBBB', 19, pro, shtl, sstl, op, spln,
                       thtl, tstl, tpln) + body


def ipv4_gre(payload, proto=0x0806):
    gre = struct.pack('>HH', 0, proto) + payload
    hdr = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(gre), 1, 0, 64, 47,
                      0, bytes([198, 51, 100, 1]), bytes([198, 51, 100, 2]))
    s = sum(struct.unpack('>10H', hdr))
    s = (s & 0xffff) + (s >> 16)
    s = (s & 0xffff) + (s >> 16)
    hdr = hdr[:10] + struct.pack('>H', ~s & 0xffff) + hdr[12:]
    return hdr + gre


class Cap:
    def __init__(self, t0):
        self.t = t0          # microseconds
        self.pkts = []

    def add(self, p, dt=1000000):
        self.pkts.append((self.t, p))
        self.t += dt

    def at(self, secs, p):
        self.pkts.append((secs * 1000000, p))

    def write(self, name):
        with open(os.path.join(outdir, name), 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            for t, p in self.pkts:
                f.write(struct.pack('<IIII', t // 1000000, t % 1000000,
                                    len(p), len(p)) + p)


T0 = 1700000000 * 1000000
c = Cap(T0)
Z6 = b'\0' * 6

# ---- Section A (frames 1-8): plain Ethernet/IPv4 ARP ------------------
c.add(eth(mac(0x11), arp(1, 0x0800, 6, 4, 1, mac(0x11) + ip(1) + Z6 + ip(2))))
c.add(eth(mac(0x12), arp(1, 0x0800, 6, 4, 2, mac(0x12) + ip(2) + mac(0x11) + ip(1)), dst=mac(0x11)))
# gratuitous request with a zero target MAC: ARP Announcement
c.add(eth(mac(0x11), arp(1, 0x0800, 6, 4, 1, mac(0x11) + ip(1) + Z6 + ip(1))))
# gratuitous request with a nonzero target MAC: not an announcement
c.add(eth(mac(0x11), arp(1, 0x0800, 6, 4, 1, mac(0x11) + ip(1) + BCAST + ip(1))))
# gratuitous reply
c.add(eth(mac(0x12), arp(1, 0x0800, 6, 4, 2, mac(0x12) + ip(2) + mac(0x12) + ip(2))))
# ARP Probe (sender IP 0), and one with a nonzero target MAC (warning)
c.add(eth(mac(0x13), arp(1, 0x0800, 6, 4, 1, mac(0x13) + b'\0' * 4 + Z6 + ip(3))))
c.add(eth(mac(0x13), arp(1, 0x0800, 6, 4, 1, mac(0x13) + b'\0' * 4 + mac(0x14) + ip(3))))
# IEEE 802 hardware type (also an Ethernet address)
c.add(eth(mac(0x14), arp(6, 0x0800, 6, 4, 2, mac(0x14) + ip(4) + mac(0x11) + ip(1)), dst=mac(0x11)))

# ---- Section B (frames 9-22): duplicate address detection -------------
D = 3  # 192.0.3.x
c.add(eth(mac(0x21), arp(1, 0x0800, 6, 4, 2, mac(0x21) + ip(10, D) + mac(0x22) + ip(11, D))))   # 9: both new
c.add(eth(mac(0x21), arp(1, 0x0800, 6, 4, 1, mac(0x21) + ip(10, D) + Z6 + ip(11, D))))          # 10: same MAC, update
c.add(eth(mac(0x23), arp(1, 0x0800, 6, 4, 2, mac(0x23) + ip(10, D) + mac(0x22) + ip(11, D))))   # 11: sender duplicate
c.add(eth(mac(0x23), arp(1, 0x0800, 6, 4, 2, mac(0x23) + ip(12, D) + mac(0x24) + ip(10, D))))   # 12: target duplicate
c.add(eth(mac(0x25), arp(1, 0x0800, 6, 4, 2, mac(0x25) + ip(13, D) + mac(0x26) + ip(13, D))))   # 13: same frame
c.add(eth(mac(0x27), arp(1, 0x0800, 6, 4, 2, mac(0x27) + ip(13, D) + mac(0x27) + ip(13, D))))   # 14: gratuitous duplicate
# addresses that are not registered: multicast/zero MAC, zero IP
c.add(eth(mac(0x28), arp(1, 0x0800, 6, 4, 2, bytes.fromhex('01005e000001') + ip(14, D) + bytes.fromhex('01005e000002') + ip(15, D))))
c.add(eth(mac(0x28), arp(1, 0x0800, 6, 4, 2, Z6 + ip(14, D) + Z6 + ip(15, D))))
c.add(eth(mac(0x28), arp(1, 0x0800, 6, 4, 2, mac(0x28) + b'\0' * 4 + mac(0x29) + b'\0' * 4)))
c.add(eth(mac(0x2a), arp(1, 0x0800, 6, 4, 2, mac(0x2a) + ip(16, D) + Z6 + ip(17, D))))
c.add(eth(mac(0x2b), arp(1, 0x0800, 6, 4, 2, mac(0x2b) + ip(18, D) + bytes.fromhex('333300000001') + ip(19, D))))
c.add(eth(mac(0x2c), arp(1, 0x0800, 6, 4, 2, mac(0x2c) + ip(20, D) + mac(0x2d) + b'\0' * 4)), dt=60000000)
# a duplicate a minute later (seconds since earlier frame)
c.add(eth(mac(0x2e), arp(1, 0x0800, 6, 4, 2, mac(0x2e) + ip(10, D) + mac(0x21) + ip(10, D))))
c.add(eth(mac(0x21), arp(1, 0x0800, 6, 4, 2, mac(0x21) + ip(11, D) + mac(0x2e) + ip(10, D))))  # 22

# ---- Section C (frames 23-48): every other opcode, Ethernet/IPv4 ------
for op in range(3, 26):
    c.add(eth(mac(0x11), arp(1, 0x0800, 6, 4, op, mac(0x11) + ip(1) + mac(0x12) + ip(2))))
for op in (0, 0xffff, 100):
    c.add(eth(mac(0x11), arp(1, 0x0800, 6, 4, op, mac(0x11) + ip(1) + mac(0x12) + ip(2))))

# ---- Section D (frames 49-58): odd sizes and types, RARP ethertype, GRE
c.add(eth(mac(0x11), arp(1, 0x0800, 6, 4, 3, mac(0x11) + b'\0' * 4 + mac(0x11) + b'\0' * 4), et=0x8035))
c.add(eth(mac(0x11), arp(1, 0x0800, 6, 4, 4, mac(0x12) + ip(2) + mac(0x11) + ip(1), ), et=0x8035, dst=mac(0x11)))
c.add(eth(mac(0x11), arp(0xffff, 0x9999, 3, 5, 1, b'abc' + b'12345' + b'def' + b'67890')))
c.add(eth(mac(0x11), arp(6, 0x1234, 255, 255, 2, bytes(range(256)) * 3 + bytes(range(252)))))
c.add(eth(mac(0x11), arp(1, 0x0800, 0, 0, 3, b'')))           # RARP, no addresses
c.add(eth(mac(0x11), arp(1, 0x0800, 6, 0, 7, mac(0x11) + mac(0x12))))  # DRARP error, no protocol address
c.add(eth(mac(0x11), arp(1, 0x0800, 6, 4, 1, mac(0x11) + ip(1) + Z6 + ip(5)) + b'\0' * 18))  # padded
c.add(eth(mac(0x11), arp(1, 0x86dd, 6, 16, 1, mac(0x11) + bytes(15) + b'\1' + Z6 + bytes(15) + b'\2')))
c.add(eth(mac(0x11), arp(1, 0x0003, 6, 7, 1, mac(0x11) + b'\x9c\x94\x6e\xa0\x40\x40\x60' + Z6 + b'\x9c\x94\x6e\xa0\x40\x40\x62')))
c.add(eth(mac(0x31), ipv4_gre(arp(1, 0x0800, 6, 4, 1, mac(0x31) + ip(1, 4) + Z6 + ip(2, 4))), et=0x0800, dst=mac(0x32)))

# ---- Section E (frames 59-62): reproducers, arp_nonipv4_probe.py ------
# Requests with short or non-IPv4 addresses: no longer malformed, and not
# taken for an ARP Probe or Announcement.
SRC = bytes.fromhex('020000000001')
c.add(eth(SRC, arp(1, 0x1234, 0, 0, 1, b'')))
c.add(eth(SRC, arp(1, 0x1234, 1, 1, 1, b'\x02\x0a\x02\x0b')))
c.add(eth(SRC, arp(1, 0x1234, 6, 2, 1, bytes.fromhex('020000000011') + b'\0\0' + Z6 + b'\0\x01')))
c.add(eth(SRC, arp(6, 0x1234, 2, 2, 1, b'\x02\x11' + b'\x0a\x0a' + b'\0\0' + b'\x0a\x0a') + b'\0' * 20))

# ---- Section F (frames 63-81): AX.25 ARP (hardware type 3) ------------
AX1 = b'\x9c\x94\x6e\xa0\x40\x40\x60'   # NJ7P
AX2 = b'\x9c\x94\x6e\xa0\x40\x40\x62'   # NJ7P-1
for op in (1, 2, 3, 4, 8, 9, 77):
    c.add(eth(mac(0x41), arp(3, 0xcc, 7, 4, op, AX1 + ip(1, 5) + AX2 + ip(2, 5))))
c.add(eth(mac(0x41), arp(3, 0xcc, 7, 4, 1, AX1 + ip(1, 5) + AX2 + ip(1, 5))))   # gratuitous request
c.add(eth(mac(0x41), arp(3, 0xcc, 7, 4, 2, AX1 + ip(1, 5) + AX2 + ip(1, 5))))   # gratuitous reply
c.add(eth(mac(0x41), arp(3, 0x0003, 7, 7, 1, AX1 + AX2 + AX2 + AX1)))          # AX.25 protocol addresses
c.add(eth(mac(0x41), arp(3, 0x0800, 6, 4, 2, mac(0x41) + ip(1, 5) + mac(0x42) + ip(2, 5))))  # hln != 7
c.add(eth(mac(0x41), arp(3, 0xcc, 0, 0, 3, b'')))                              # no addresses
# a burst of AX.25 requests 1 ms apart (storm detection)
for k in range(6):
    c.add(eth(mac(0x41), arp(3, 0xcc, 7, 4, 1, AX1 + ip(1, 5) + AX2 + ip(10 + k, 5))), dt=1000)
c.add(eth(mac(0x41), arp(3, 0xcc, 7, 4, 2, AX2 + ip(15, 5) + AX1 + ip(1, 5))))


# ---- Section G (frames 82-138): ATMARP (hardware type 19) -------------
def nsap(afi):
    return bytes([afi]) + bytes(range(1, 20))


for op in list(range(0, 26)) + [0xffff, 300]:
    body = nsap(0x39) + nsap(0x47) + ip(1, 6) + b'1234567' + nsap(0x45) + ip(2, 6)
    c.add(eth(mac(0x51), atmarp(op, 20, 20, 4, 0x47, 20, 4, body)))
# no subaddresses, so the Info column has no ",subaddress"
for op in (2, 8, 9, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23):
    body = nsap(0x47) + ip(1, 6) + nsap(0x47) + ip(2, 6)
    c.add(eth(mac(0x51), atmarp(op, 20, 0, 4, 20, 0, 4, body)))
# every AFI, and an unknown one (warning)
for afi in (0x39, 0xbd, 0x47, 0xc5, 0x45, 0xc3, 0x00):
    body = nsap(afi) + ip(1, 6) + nsap(afi) + ip(2, 6)
    c.add(eth(mac(0x51), atmarp(1, 20, 0, 4, 20, 0, 4, body)))
# short NSAPs (no breakdown), E.164 numbers with E.164-flagged subaddresses
c.add(eth(mac(0x51), atmarp(9, 8, 0, 4, 8, 0, 4, b'\x47' * 8 + ip(1, 6) + b'\x39' * 8 + ip(2, 6))))
c.add(eth(mac(0x51), atmarp(2, 0x4b, 0x48, 4, 0x4b, 0x48, 4,
                            b'15551230001' + b'\x47' * 8 + ip(1, 6) + b'15551230002' + b'\x47' * 8 + ip(2, 6))))
# maximum lengths, protocol addresses that are not IPv4, no addresses
body = b'A' * 63 + b'B' * 63 + bytes(255) + b'C' * 63 + b'D' * 63 + bytes(255)
c.add(eth(mac(0x51), atmarp(2, 0x7f, 0x7f, 255, 0x7f, 0x7f, 255, body)))
c.add(eth(mac(0x51), atmarp(2, 0x3f, 0x3f, 0, 0x3f, 0x3f, 0, b'\x39' * 63 * 4)))
c.add(eth(mac(0x51), atmarp(1, 0, 0, 0, 0, 0, 0, b'')))
c.add(eth(mac(0x51), atmarp(1, 20, 0, 16, 20, 0, 16, nsap(0x47) + bytes(16) + nsap(0x47) + bytes(15) + b'\1', pro=0x86dd)))

# ---- Section H (frames 139-149): an ARP request burst, 1 ms apart -----
for k in range(10):
    c.add(eth(mac(0x61), arp(1, 0x0800, 6, 4, 1, mac(0x61) + ip(1, 7) + Z6 + ip(10 + k, 7))), dt=1000)
c.add(eth(mac(0x62), arp(1, 0x0800, 6, 4, 2, mac(0x62) + ip(10, 7) + mac(0x61) + ip(1, 7)), dst=mac(0x61)))

# ---- Section I (frames 150-153): reproducer, arp_storm_overflow.py ----
# Four identical requests 2^29 s (about 17 years) apart. With
# arp.detect_request_storms:TRUE and detect_storm_number_of_packets:3 the
# gap used to wrap to 0 ms and frame 153 was reported as a storm.
req = arp(1, 0x0800, 6, 4, 1, mac(0x71) + ip(1, 8) + Z6 + ip(2, 8))
S = c.t // 1000000 + 10
for k in range(4):
    c.at(S + k * (1 << 29), eth(mac(0x71), req))

c.write('arp-coverage.pcap')

# ---- Malformed capture ------------------------------------------------
m = Cap(T0)
m.add(eth(mac(0x11), b'\x00'))                                       # 1: no hardware type
m.add(eth(mac(0x11), arp(1, 0x0800, 6, 4, 1, b'')[:5]))               # 2: truncated header
m.add(eth(mac(0x11), arp(1, 0x0800, 6, 4, 1, mac(0x11))))            # 3: truncated addresses
m.add(eth(mac(0x11), arp(1, 0x0800, 6, 4, 2, mac(0x11) + ip(1) + mac(0x12))))  # 4: reply, no target IP
m.add(eth(mac(0x11), arp(6, 0x1234, 255, 255, 2, bytes(range(256)) * 2)))  # 5: 1028 octets claimed
m.add(eth(mac(0x11), arp(1, 0x1234, 1, 1, 1, b'\x02\x0a')))         # 6: short request
m.add(eth(mac(0x51), atmarp(1, 20, 0, 4, 20, 0, 4, b'\x39')))        # 7: truncated ATMARP
m.add(eth(mac(0x51), struct.pack('>HHBB', 19, 0x0800, 20, 0)))       # 8: truncated ATMARP header
m.add(eth(mac(0x51), atmarp(2, 0x4b, 0x48, 4, 0x4b, 0x48, 4, b'1555')))  # 9: truncated E.164
m.add(eth(mac(0x41), arp(3, 0xcc, 7, 4, 1, AX1 + ip(1, 5))))        # 10: truncated AX.25 ARP
m.add(eth(mac(0x41), struct.pack('>HH', 3, 0xcc)))                   # 11: truncated AX.25 header
# 12-17: requests whose timestamps go backwards (negative storm gap)
for k in range(3):
    m.add(eth(mac(0x61), arp(1, 0x0800, 6, 4, 1, mac(0x61) + ip(1, 7) + Z6 + ip(10 + k, 7))), dt=1000)
m.t = T0 - 3600 * 1000000
for k in range(3):
    m.add(eth(mac(0x41), arp(3, 0xcc, 7, 4, 1, AX1 + ip(1, 5) + AX2 + ip(10 + k, 5))), dt=1000)
m.write('arp-coverage-malformed.pcap')
