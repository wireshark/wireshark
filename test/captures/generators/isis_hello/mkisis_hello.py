#!/usr/bin/env python3
# Generates test/captures/isis_hello_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generates isis-hello-coverage.pcap (clean) and isis-hello-coverage-malformed.pcap
# for packet-isis-hello.c (IIH: L1 LAN, L2 LAN, point to point).
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













from isislib import (
    area, auth_clear, auth_crypto, auth_md5, CKSUM, hello, ip4, ip6, sid, struct, tlv,
    with_checksum, write_pcap,
)

out = sys.argv[1] if len(sys.argv) > 1 else '.'

def bitmap(*vlans, start=1, nbytes=None):
    """Enabled/appointed VLAN bitmap: start VLAN (2 bytes) + bits."""
    last = max(vlans) - start
    n = last // 8 + 1 if nbytes is None else nbytes
    b = bytearray(n)
    for v in vlans:
        i = v - start
        b[i // 8] |= 0x80 >> (i % 8)
    return struct.pack('>H', start) + bytes(b)

def sub(t, v):
    return bytes([t, len(v)]) + v

AREA1 = tlv(1, area(b'\x49\x00\x01'))
AREAS = tlv(1, area(b'', b'\x49\x00\x01', b'\x47\x00\x05\x80\x00\x01\x00\x00'))
NBRS = tlv(6, sid(0x11) + sid(0x12))
NLPIDS = tlv(129, bytes([0xcc, 0x8e, 0xc1, 0x00, 0x83]))
IP4 = tlv(132, ip4(192, 0, 2, 1) + ip4(192, 0, 2, 2))
IP6 = tlv(232, ip6('fe80::1') + ip6('fe80::2'))
IP6G = tlv(233, ip6('2001:db8::1'))
PAD = tlv(8, bytes(20))
RESTART_RR = tlv(211, b'\x01')
RESTART_RA = tlv(211, b'\x02' + struct.pack('>H', 90) + sid(3))
RESTART_RA_NOID = tlv(211, b'\x02' + struct.pack('>H', 90))
RESTART_SA = tlv(211, b'\x04')
IIDS = tlv(7, struct.pack('>H', 5) + struct.pack('>HH', 1, 2))
MT = tlv(229, struct.pack('>HHHHHHHH', 0, 0x8002, 0x4001, 3, 4, 5, 0xc7ff, 7))

mtpc_subs = (
    sub(1, struct.pack('>HHHH', 0x0102, 0x0304, 0xf000 | 0x0abc, 0x2123)) +
    sub(2, bitmap(1, 2, 3, 4, 20, 22, 23, 24, 25, 31, 32)) +                 # ranges and singles
    sub(3, struct.pack('>HHH', 0x1001, 5, 10) + struct.pack('>HHH', 0x1002, 20, 30)) +
    sub(4, bytes(range(51)) + bytes(range(100, 151))) +
    sub(5, b'\xa0' + bytes(range(32))) +
    sub(6, struct.pack('>IH', 0x00000001, 0xc064) + struct.pack('>IH', 0x00000002, 0x0065)) +
    sub(7, b'\x00' + struct.pack('>I', 0x80000000 | 0x01000000)) +
    sub(8, bitmap(100, 101, 102, 200, 206, 207, start=96)) +
    sub(99, b'\x01\x02')
)
MTPC = tlv(143, struct.pack('>H', 1) + mtpc_subs)
MTPC_SPB = tlv(143, struct.pack('>H', 0) + sub(5, b'\x40' + bytes(32)))

TRILLN = tlv(145, b'\x00' + b'\xc0\x05\xdc' + b'\x00\x11\x22\x33\x44\x55' + b'\x40\x05\xdc' + b'\x66\x77\x88\x99\xaa\xbb')
TRILLN_S2 = tlv(145, b'\x82' + b'\x00\x05\xdc\xaa\xbb' + b'\x00\x05\xdc\xcc\xdd' + b'\x00\x05\xdc\xee\xff')
REVM = tlv(16, b'\x80' + b'\x00\x00\x64' + b'\x03' + b'\x01\x02\x03')
REVM0 = tlv(16, b'\x40' + b'\x00\x00\x65' + b'\x00')
BFD = tlv(148, struct.pack('>HB', 0, 0xcc) + struct.pack('>HB', 2, 0x8e))
IPAUTH = tlv(133, b'ippass')

frames = []
def add(p):
    frames.append(p)

# L1 LAN hellos
add(hello(1, [AREAS, NBRS, NLPIDS, IP4, IP6, auth_clear(), PAD]))                      # 1
add(hello(1, [AREA1, IIDS, RESTART_RR, IP6G, MT, BFD, REVM]))                          # 2
add(hello(1, [AREA1, RESTART_RA, REVM0]))                                              # 3
add(hello(1, [AREA1, RESTART_RA_NOID, tlv(129, b'')]))                                 # 4  RA, time only; empty NLPIDs
add(hello(1, [AREA1, RESTART_SA, tlv(211, b''), IPAUTH]))                              # 5
add(hello(1, [AREA1, auth_md5()]))                                                     # 6
add(hello(1, [AREA1, tlv(10, b'\x36' + bytes(7))]))                                    # 7  md5 with bad digest length
add(hello(1, [AREA1, auth_crypto(7, bytes(range(20)))]))                               # 8
add(hello(1, [AREA1, auth_crypto(8, bytes(range(17)))]))                               # 9  illegal digest length
add(hello(1, [AREA1, tlv(10, b'\x01')]))                                               # 10 empty clear text
add(hello(1, [AREA1, tlv(10, b'\x99\xaa\xbb')]))                                       # 11 unknown type (warning)
add(hello(1, [AREA1, tlv(10, b'')]))                                                   # 12 empty
add(hello(1, [AREA1, MTPC, TRILLN, TRILLN_S2]))                                        # 13 port capability, TRILL neighbor (+SNPA size 2 fix)
add(hello(1, [AREA1, tlv(145, b'\x03' + b'\x00\x05\xdc\xaa\xbb\xcc'), MTPC_SPB]))      # 14
add(with_checksum(hello(1, [AREA1, NBRS, CKSUM])))                                     # 15 good checksum
add(hello(1, [AREA1, tlv(12, b'\x00\x00')]))                                           # 16 no checksum
add(hello(1, [AREA1, tlv(250, b'\x00'), tlv(99, b'abc')]))                             # 17 unknown TLVs
# L2 LAN hellos
add(hello(2, [AREAS, NBRS, NLPIDS, IP4, IP6, auth_clear(), IIDS, RESTART_RA, MT, IP6G, BFD]))   # 18
add(hello(2, [AREA1, auth_md5(), IPAUTH, tlv(10, b'\x77'), PAD, tlv(145, b'\x00')]))           # 19  (TRILL neighbor is unknown here)
add(with_checksum(hello(2, [AREA1, CKSUM])))                                           # 20
add(hello(2, [AREA1, tlv(12, b'\x00\x00'), tlv(143, b'\x00\x00')]))                    # 21
# point to point hellos
add(hello(3, [AREA1, NLPIDS, IP4, IP6, IP6G, MT, IIDS, tlv(240, b'\x00')]))             # 22 adjacency state, length 1
add(hello(3, [AREA1, tlv(240, b'\x01' + struct.pack('>I', 77))]))                       # 23 length 5
add(hello(3, [AREA1, tlv(240, b'\x02' + struct.pack('>I', 78) + sid(9))]))              # 24 length 11
add(hello(3, [AREA1, tlv(240, b'\x00' + struct.pack('>I', 79) + sid(9) + struct.pack('>I', 80)), auth_md5(), MTPC, RESTART_RA, BFD]))  # 25 length 15
add(hello(3, [AREA1, auth_clear(), IPAUTH, PAD, tlv(6, sid(1))]))                       # 26 IS neighbors unknown for PTP
add(with_checksum(hello(3, [AREA1, CKSUM, tlv(240, b'\x00')])))                         # 27
add(hello(3, [AREA1, tlv(12, b'\x00\x00')]))                                            # 28
# ID length 1: the restart neighbour ID uses the system ID length
add(hello(1, [AREA1, tlv(211, b'\x02\x00\x5a' + sid(4, 1))], idlen=1))                  # 29
# Reproducers of the fixes on the branch (isis_smallfixes.py frame 6)
add(hello(1, [tlv(145, b'\x02' + b'\x00\x05\xdc\xaa\xbb' + b'\x00\x05\xdc\xcc\xdd' + b'\x00\x05\xdc\xee\xff')]))   # 30
add(hello(1, [AREA1, tlv(10, b'\x03\x00'), NBRS]))     # CRYPTO_AUTH with one octet for the Key ID (clv fix, warning)
# Over ethertype 0x22F4
add((hello(1, [AREA1, NBRS]), 'eth'))                                                   # 31
add((hello(3, [AREA1, tlv(240, b'\x00')]), 'eth'))                                      # 32
write_pcap(os.path.join(out, 'isis-hello-coverage.pcap'), frames)

mal = []
def madd(p):
    mal.append(p)
# header too small at each step
for hl in (8, 9, 9 + 6, 9 + 6 + 2, 9 + 6 + 2 + 2, 9 + 6 + 2 + 2 + 1, 9 + 6 + 2 + 2 + 1 + 6):
    madd(hello(1, [AREA1], hdrlen=hl))
for hl in (9 + 6 + 2 + 2 + 1 - 1, 8 + 6 + 2 + 2 + 1):
    madd(hello(3, [AREA1], hdrlen=hl))
madd(hello(1, [AREA1], pdulen=10))                         # PDU length smaller than header
madd(hello(1, [AREA1], pdulen=900))                        # PDU length bigger than packet
madd(hello(3, [AREA1], pdulen=10))
madd(hello(2, [AREA1, tlv(1, b'\x05\x01')]))               # short area (length beyond TLV)
madd(hello(2, [AREA1, tlv(1, b'\x03')]))                   # no payload for the area
madd(hello(1, [AREA1, tlv(6, sid(1) + b'\x01\x02')]))      # short IS neighbor
madd(hello(3, [AREA1, tlv(240, b'\x00' + struct.pack('>I', 79) + sid(9, 8) + struct.pack('>I', 80))], idlen=8))   # ID length 8: adjacency state TLV is 17 octets
madd(hello(1, [AREA1, tlv(7, b''), tlv(7, b'\x01')]))      # instance identifier too short
madd(hello(1, [AREA1, tlv(132, ip4(1, 2, 3, 4) + b'\x01')]))   # short IPv4
madd(hello(1, [AREA1, tlv(232, ip6('::1') + b'\x01')]))        # short IPv6
madd(hello(1, [AREA1, tlv(233, b'\x01')]))
madd(hello(1, [AREA1, tlv(229, b'\x00\x00\x00')]))         # odd MT length
madd(hello(3, [AREA1, tlv(240, b'\x00\x01')]))             # bad adjacency state length
madd(hello(1, [AREA1, tlv(12, b'\x00')]))                  # checksum length
madd((with_checksum(hello(1, [AREA1, CKSUM, tlv(8, bytes(40))])), 'snap:20'))   # checksum cannot be verified, capture cut short
madd(hello(1, [AREA1, tlv(12, b'\x12\x34')]))              # bad checksum
madd(hello(1, [AREA1, tlv(143, b'\x00\x01' + sub(1, bytes(8)) + bytes([9, 200]))]))   # sub-TLV longer than TLV
madd(hello(1, [AREA1, tlv(143, b'\x00\x01' + sub(4, bytes(10)))]))   # short MCID
madd(hello(1, [AREA1, tlv(143, b'\x00\x01' + sub(5, bytes(10)))]))   # short digest
madd(hello(1, [AREA1, tlv(143, b'\x00\x01' + sub(6, bytes(8)))]))    # short BVID tuple
madd(hello(1, [AREA1, tlv(99, bytes(40))])[:-20])          # truncated PDU (reported length stays)
write_pcap(os.path.join(out, 'isis-hello-coverage-malformed.pcap'), mal)
print(len(frames), len(mal))
