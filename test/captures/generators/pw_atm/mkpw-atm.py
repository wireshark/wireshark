#!/usr/bin/env python3
# Generates test/captures/pw_atm_coverage.pcap.gz
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

    def add(self, data, snap=None):
        # snap: captured length smaller than the original length
        self.frames.append((data, snap))
        return len(self.frames)

    def write(self, path):
        with open(path, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
            for i, (d, snap) in enumerate(self.frames):
                t = 1700000000 + i
                cap = d if snap is None else d[:snap]
                f.write(struct.pack('<IIII', t, 1000 * i, len(cap), len(d)))
                f.write(cap)
        return len(self.frames)

# ---- pw-atm ----
# ATM pseudowires over MPLS (Decode As mpls.label): N-to-one with and
# without CW, one-to-one VCC/VPC and AAL5 PDU, AAL5 SDU with admin cells.
L_N1CW, L_N1NOCW, L_11, L_SDU = 5001, 5002, 5003, 5004


def crc32_aal5(data):
    crc = 0xffffffff
    for b in data:
        crc ^= b << 24
        for _ in range(8):
            crc = ((crc << 1) ^ 0x04C11DB7) & 0xffffffff if crc & 0x80000000 else (crc << 1) & 0xffffffff
    return ~crc & 0xffffffff


CRC10_TABLE = [0x0,0x233,0x255,0x66,0x299,0xaa,0xcc,0x2ff,0x301,0x132,0x154,0x367,0x198,0x3ab,0x3cd,0x1fe,0x31,0x202,0x264,0x57,0x2a8,0x9b,0xfd,0x2ce,0x330,0x103,0x165,0x356,0x1a9,0x39a,0x3fc,0x1cf,0x62,0x251,0x237,0x4,0x2fb,0xc8,0xae,0x29d,0x363,0x150,0x136,0x305,0x1fa,0x3c9,0x3af,0x19c,0x53,0x260,0x206,0x35,0x2ca,0xf9,0x9f,0x2ac,0x352,0x161,0x107,0x334,0x1cb,0x3f8,0x39e,0x1ad,0xc4,0x2f7,0x291,0xa2,0x25d,0x6e,0x8,0x23b,0x3c5,0x1f6,0x190,0x3a3,0x15c,0x36f,0x309,0x13a,0xf5,0x2c6,0x2a0,0x93,0x26c,0x5f,0x39,0x20a,0x3f4,0x1c7,0x1a1,0x392,0x16d,0x35e,0x338,0x10b,0xa6,0x295,0x2f3,0xc0,0x23f,0xc,0x6a,0x259,0x3a7,0x194,0x1f2,0x3c1,0x13e,0x30d,0x36b,0x158,0x97,0x2a4,0x2c2,0xf1,0x20e,0x3d,0x5b,0x268,0x396,0x1a5,0x1c3,0x3f0,0x10f,0x33c,0x35a,0x169,0x188,0x3bb,0x3dd,0x1ee,0x311,0x122,0x144,0x377,0x289,0xba,0xdc,0x2ef,0x10,0x223,0x245,0x76,0x1b9,0x38a,0x3ec,0x1df,0x320,0x113,0x175,0x346,0x2b8,0x8b,0xed,0x2de,0x21,0x212,0x274,0x47,0x1ea,0x3d9,0x3bf,0x18c,0x373,0x140,0x126,0x315,0x2eb,0xd8,0xbe,0x28d,0x72,0x241,0x227,0x14,0x1db,0x3e8,0x38e,0x1bd,0x342,0x171,0x117,0x324,0x2da,0xe9,0x8f,0x2bc,0x43,0x270,0x216,0x25,0x14c,0x37f,0x319,0x12a,0x3d5,0x1e6,0x180,0x3b3,0x24d,0x7e,0x18,0x22b,0xd4,0x2e7,0x281,0xb2,0x17d,0x34e,0x328,0x11b,0x3e4,0x1d7,0x1b1,0x382,0x27c,0x4f,0x29,0x21a,0xe5,0x2d6,0x2b0,0x83,0x12e,0x31d,0x37b,0x148,0x3b7,0x184,0x1e2,0x3d1,0x22f,0x1c,0x7a,0x249,0xb6,0x285,0x2e3,0xd0,0x11f,0x32c,0x34a,0x179,0x386,0x1b5,0x1d3,0x3e0,0x21e,0x2d,0x4b,0x278,0x87,0x2b4,0x2d2,0xe1]


def crc10(data):
    # same recurrence as wsutil/crc10.c
    crc = 0
    for b in data:
        crc = ((crc << 8) & 0x3ff) ^ CRC10_TABLE[(crc >> 2) & 0xff] ^ b
    return crc


def oam_payload(first=0x10):
    # OAM cell payload: type/function byte, reserved octets, 6 bit reserved + CRC-10
    p = bytearray([first]) + bytearray([0x6a] * 45) + bytearray(2)
    for v in range(1024):
        p[46] = (p[46] & 0xfc) | (v >> 8)
        p[47] = v & 0xff
        if crc10(bytes(p)) == 0:
            return bytes(p)
    raise ValueError('no CRC-10')


def user_payload(n=0):
    return bytes((n + i) & 0xff for i in range(48))


def n1_header(vpi, vci, pti, clp):
    return struct.pack('>I', (vpi << 20) | (vci << 4) | (pti << 1) | clp)


def n1_cell(vpi=1, vci=100, pti=0, clp=0, payload=None):
    if payload is None:
        payload = oam_payload() if pti in (4, 5, 6) else user_payload(vci)
    return n1_header(vpi, vci, pti, clp) + payload


def hdr_byte(m=0, v=0, rsv=0, pti=0, clp=0):
    return bytes([(m << 7) | (v << 6) | (rsv << 4) | (pti << 1) | clp])


def n1cw(flags=0, rsvd=0, ln=0, seq=0, bits03=0):
    return struct.pack('>BBH', (bits03 << 4) | flags, (rsvd << 6) | ln, seq)


def sducw(t=0, e=0, c=0, u=0, rsvd=0, ln=0, seq=0, bits03=0):
    return struct.pack('>BBH', (bits03 << 4) | (t << 3) | (e << 2) | (c << 1) | u, (rsvd << 6) | ln, seq)


def llc_ip(ident=1):
    ip = ipv4(udp(b'atm', 6000, 6001), ident=ident)
    return bytes([0xaa, 0xaa, 0x03, 0, 0, 0, 0x08, 0x00]) + ip


def aal5_pdu(sdu, cells=1, uu=0):
    # CPCS-PDU: SDU, padding, trailer (UU, CPI, length, CRC-32); cells * 48 octets
    pad = cells * 48 - len(sdu) - 8
    body = sdu + bytes(pad) + bytes([uu, 0]) + struct.pack('>H', len(sdu))
    return body + struct.pack('>I', crc32_aal5(body))


def m(label, p):
    return mpls_frame(label, p)


def c11cw(seq, byte3):
    # one-to-one / AAL5 PDU control word; byte 3 is the ATM specific byte
    return struct.pack('>BH', 0, seq) + byte3


def build(out):
    main = Pcap()
    # N-to-one without control word
    main.add(m(L_N1NOCW, n1_cell(5, 100)))                                              # 1 one user cell
    main.add(m(L_N1NOCW, n1_cell(5, 100, clp=0) + n1_cell(5, 100, clp=1)))              # 2 two cells, CLP differs
    main.add(m(L_N1NOCW, n1_cell(5, 100) + n1_cell(6, 100, pti=1) + n1_cell(5, 101, pti=2)))  # 3 three cells, everything differs
    main.add(m(L_N1NOCW, n1_cell(7, 200, pti=3, clp=1)))                                # 4 user cell PTI 3, CLP 1
    main.add(m(L_N1NOCW, n1_cell(5, 100, pti=5)))                                       # 5 end-to-end OAM F5 cell
    main.add(m(L_N1NOCW, n1_cell(5, 100, pti=4)))                                       # 6 segment OAM F5 cell
    main.add(m(L_N1NOCW, n1_cell(5, 100, pti=6)))                                       # 7 resource management cell
    main.add(m(L_N1NOCW, n1_cell(5, 100, pti=7)))                                       # 8 reserved PTI
    main.add(m(L_N1NOCW, n1_cell(5, 3, pti=0, payload=oam_payload(0x18))))              # 9 OAM F4 (VCI 3), user PTI
    # N-to-one with control word
    main.add(m(L_N1CW, n1cw(seq=1) + n1_cell(1, 32)))                                   # 10 one cell
    main.add(m(L_N1CW, n1cw(seq=2) + n1_cell(1, 32) + n1_cell(1, 32, clp=1) + n1_cell(1, 32)))  # 11 three cells
    main.add(m(L_N1CW, n1cw(seq=3) + n1_cell(1, 32, pti=5)))                            # 12 OAM cell
    # AAL5 SDU mode
    main.add(m(L_SDU, sducw(seq=1) + llc_ip(1)))                                        # 13 AAL5 SDU, length 0
    main.add(m(L_SDU, sducw(e=1, c=1, u=1, seq=2) + llc_ip(2)))                         # 14 EFCI, CLP, U bits
    main.add(m(L_SDU, sducw(ln=4 + 39, seq=3) + llc_ip(3) + bytes(5)))                  # 15 length set, padding
    main.add(m(L_SDU, sducw(t=1, seq=4) + n1_cell(1, 32, pti=5)))                       # 16 admin cell
    main.add(m(L_SDU, sducw(t=1, e=1, seq=5) + n1_cell(2, 33, pti=4)))                  # 17 admin cell, segment OAM
    # one-to-one VCC
    main.add(m(L_11, c11cw(1, hdr_byte()) + user_payload(1)))                           # 18 VCC, one cell
    main.add(m(L_11, c11cw(2, hdr_byte()) + user_payload(2) + hdr_byte(pti=1, clp=1) + user_payload(3)))  # 19 two cells
    main.add(m(L_11, c11cw(3, hdr_byte(pti=5)) + oam_payload()))                        # 20 OAM cell
    main.add(m(L_11, c11cw(4, hdr_byte(pti=7)) + user_payload(4)))                      # 21 reserved PTI
    main.add(m(L_11, c11cw(5, hdr_byte(pti=2, clp=1)) + user_payload(5)))               # 22 CLP bit, PTI 2
    # one-to-one VPC
    main.add(m(L_11, c11cw(6, hdr_byte(v=1)) + struct.pack('>H', 77) + user_payload(6)))   # 23 VPC, one cell
    main.add(m(L_11, c11cw(7, hdr_byte(v=1)) + struct.pack('>H', 77) + user_payload(7)
               + hdr_byte(v=1, pti=1) + struct.pack('>H', 78) + user_payload(8)))            # 24 VPC, two cells
    main.add(m(L_11, c11cw(8, hdr_byte(v=1, pti=4)) + struct.pack('>H', 3) + oam_payload()))   # 25 VPC, OAM cell
    # AAL5 PDU
    main.add(m(L_11, c11cw(9, hdr_byte(m=1)) + aal5_pdu(llc_ip(9), 1)))                 # 26 AAL5 PDU, one cell
    main.add(m(L_11, c11cw(10, hdr_byte(m=1, rsv=0) [:0] + bytes([0x80 | 0x04 | 0x02 | 0x01])) + aal5_pdu(llc_ip(10) + bytes(30), 2)))  # 27 U, E, CLP bits, two cells
    # first nibble 4, 6 and 1 on the CW handlers
    main.add(m(L_N1CW, ipv4(udp(b'x' * 8, 5000, 5001))))                                # 28 IPv4
    main.add(m(L_11, ipv6(udp(b'y' * 8, 5000, 5001))))                                  # 29 IPv6
    main.add(m(L_SDU, bytes.fromhex('10000027') + struct.pack('>HBB', 100, 8, 0x80)
               + struct.pack('>HHI', 0x096a, 4, 2)))                                    # 30 PW ACH carrying PW OAM
    n = main.write(os.path.join(out, 'pw-atm-coverage.pcap'))

    bad = Pcap()
    bad.add(m(L_N1CW, b'\x00\x00'))                                                     # 1 shorter than the CW
    bad.add(m(L_11, b'\x00\x00'))                                                       # 2 same
    bad.add(m(L_SDU, b'\x00\x00'))                                                      # 3 same
    bad.add(m(L_N1NOCW, b'\x00'))                                                       # 4 no complete cell
    bad.add(m(L_N1NOCW, b'\x00\x10\x00'))                                               # 5 cell header cut
    bad.add(m(L_N1NOCW, n1_cell(5, 100) + n1_cell(5, 100)[:20]))                        # 6 broken last cell
    bad.add(m(L_N1CW, n1cw(bits03=8, seq=1) + n1_cell()))                               # 7 bits 0-3 set
    bad.add(m(L_N1CW, n1cw(flags=3, seq=2) + n1_cell()))                                # 8 flags set
    bad.add(m(L_N1CW, n1cw(rsvd=1, seq=3) + n1_cell()))                                 # 9 reserved bits
    bad.add(m(L_N1CW, n1cw(ln=56, seq=4) + n1_cell()))                                  # 10 length nonzero
    bad.add(m(L_N1CW, n1cw(seq=5)))                                                     # 11 no cells
    bad.add(m(L_N1CW, n1cw(seq=6) + n1_cell()[:30]))                                    # 12 broken cell
    bad.add(m(L_N1CW, n1cw(seq=7) + n1_cell(1, 32, pti=5)[:40]))                        # 13 broken OAM cell
    bad.add(m(L_N1CW, n1cw(ln=60, seq=8) + n1_cell() + n1_cell(1, 32)[:5]))             # 14 length, padding, odd size
    bad.add(m(L_N1CW, n1cw(ln=56, seq=9) + n1_cell() + bytes(4)))                       # 15 length 56 with 4 octets of padding
    bad.add(m(L_N1CW, n1cw(ln=2, seq=10) + n1_cell()))                                  # 16 length too small
    bad.add(m(L_N1CW, n1cw(ln=63, seq=11) + n1_cell()))                                 # 17 length larger than the packet
    bad.add(m(L_N1CW, n1cw(rsvd=3, ln=56, seq=12) + n1_cell()))                         # 18 reserved bits as part of the length
    bad.add(m(L_SDU, sducw(bits03=8, seq=1) + llc_ip()))                                # 19 bits 0-3 set
    bad.add(m(L_SDU, sducw(rsvd=1, seq=2) + llc_ip()))                                  # 20 reserved bits
    bad.add(m(L_SDU, sducw(ln=2, seq=3) + llc_ip()))                                    # 21 length too small
    bad.add(m(L_SDU, sducw(ln=60, seq=4) + llc_ip()))                                   # 22 length larger than the packet
    bad.add(m(L_SDU, sducw(t=1, ln=56, seq=5) + n1_cell(1, 32, pti=5)))                 # 23 admin cell, length nonzero
    bad.add(m(L_SDU, sducw(t=1, ln=56, seq=6) + n1_cell(1, 32, pti=5) + bytes(4)))      # 24 admin cell with padding (needs the allow preference)
    bad.add(m(L_SDU, sducw(t=1, seq=7) + n1_cell(1, 32, pti=5) + bytes(4)))             # 25 admin cell, extra octets
    bad.add(m(L_SDU, sducw(t=1, seq=8) + n1_cell(1, 32, pti=0)))                        # 26 admin cell, user PTI
    bad.add(m(L_SDU, sducw(t=1, seq=9)))                                                # 27 admin cell missing
    bad.add(m(L_SDU, sducw(t=1, seq=10) + n1_cell(1, 32, pti=5) + n1_cell(1, 32, pti=5)))  # 28 two admin cells
    bad.add(m(L_SDU, sducw(seq=11)))                                                    # 29 no payload
    bad.add(m(L_11, c11cw(1, hdr_byte(m=1, v=1)) + aal5_pdu(llc_ip(), 1)))              # 30 AAL5 PDU with the V bit
    bad.add(m(L_11, c11cw(2, hdr_byte(m=1, rsv=1)) + aal5_pdu(llc_ip(), 1)))            # 31 AAL5 PDU, reserved bits
    bad.add(m(L_11, c11cw(3, hdr_byte(m=1)) + bytes(30)))                               # 32 AAL5 PDU, not a multiple of 48
    bad.add(m(L_11, c11cw(4, hdr_byte(m=1))))                                           # 33 AAL5 PDU, no payload
    bad.add(m(L_11, c11cw(5, hdr_byte()) + user_payload()[:20]))                        # 34 VCC, broken cell
    bad.add(m(L_11, c11cw(6, hdr_byte())))                                              # 35 VCC, no cell
    bad.add(m(L_11, c11cw(7, hdr_byte(v=1)) + struct.pack('>H', 77) + user_payload()[:10]))  # 36 VPC, broken cell
    bad.add(m(L_11, c11cw(8, hdr_byte(v=1)) + b'\x00'))                                 # 37 VPC, cell header cut
    bad.add(m(L_11, c11cw(9, hdr_byte(pti=5)) + oam_payload()[:30]))                    # 38 VCC, broken OAM cell
    bad.add(m(L_11, struct.pack('>BH', 0x10, 1)[:3] + hdr_byte() + user_payload()))     # 39 first nibble 1, PW ACH
    bad.add(m(L_11, c11cw(10, hdr_byte(m=1, rsv=3)) + aal5_pdu(llc_ip(), 1)))           # 40 AAL5 PDU, reserved 3 bits
    bad.add(m(L_11, c11cw(11, hdr_byte(rsv=1)) + user_payload(5)))                        # 41 reserved bits in the cell header
    bad.add(m(L_11, c11cw(12, hdr_byte(v=1)) + struct.pack('>H', 77) + user_payload(7) + hdr_byte(pti=1) + struct.pack('>H', 78) + user_payload(8)))  # 42 VPC, second cell without the V bit
    bad.add(m(L_11, bytes([0x80, 0, 13]) + hdr_byte() + user_payload()))                  # 43 bits 0-3 of the CW set
    bad.add(m(L_11, bytes([0x01, 0, 14]) + hdr_byte() + user_payload()))                  # 44 reserved bits of the CW set
    nb = bad.write(os.path.join(out, 'pw-atm-coverage-malformed.pcap'))
    print('main', n, 'malformed', nb)


if __name__ == '__main__':
    build(sys.argv[1] if len(sys.argv) > 1 else '.')
