#!/usr/bin/env python3
# Generates test/captures/mip_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic Mobile IP (RFC 5944, UDP 434) captures.  Usage: mkmip.py <outdir>
Writes mip-coverage.pcap (valid frames) and mip-coverage-malformed.pcap."""
import struct
import sys
import os

def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def eth(payload, et=0x0800):
    return bytes([2,0,0,0,0,2, 2,0,0,0,0,1]) + struct.pack('!H', et) + payload

def ipv4(payload, proto=17, src=(192,0,2,1), dst=(192,0,2,2)):
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0,
                    bytes(src), bytes(dst))
    return h[:10] + struct.pack('!H', csum(h)) + h[12:] + payload

def udp(payload, sport, dport):
    return struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload

def write_pcap(fn, frames):
    with open(fn, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)

HOA = bytes([10, 0, 0, 5]); HA = bytes([10, 0, 0, 1]); COA = bytes([192, 0, 2, 77])
IDENT = struct.pack('!II', 0xe8000000, 0x80000000)   # NTP time

def req(flags=0x80, life=1800, ident=IDENT): return struct.pack('!BBH', 1, flags, life) + HOA + HA + COA + ident
def rep(code=0, life=1800, ident=IDENT): return struct.pack('!BBH', 3, code, life) + HOA + HA + ident
def rev(flags=0xc000, rid=77): return struct.pack('!BBH', 7, 0, flags) + HOA + HA + COA + struct.pack('!I', rid)
def rack(flags=0x8000, rid=77): return struct.pack('!BBH', 15, 0, flags) + HOA + struct.pack('!I', rid)

def ext(t, data): return bytes([t, len(data)]) + data            # 1 octet length
def ext4(t, sub, data): return struct.pack('!BBH', t, sub, len(data)) + data   # 2 octet length
SPI = struct.pack('!I', 0x100)

frames = []; bad = []
def F(m, sport=40000, dport=434): frames.append(eth(ipv4(udp(m, sport, dport))))

# messages
for fl in (0xff, 0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01, 0x00):
    F(req(fl))
codes = (0, 1, 64, 65, 67, 70, 88, 96, 128, 131, 133, 142, 149, 150, 192, 200)
for c in codes: F(rep(c))
F(rev(0xc000)); F(rev(0x4000)); F(rev(0x0000)); F(rack(0x8000)); F(rack(0x0000))
# extensions after a Registration Request / Reply
MH = ext(32, SPI + bytes(range(16)))
F(req() + MH)
F(req() + ext(33, SPI + bytes(8)) + ext(34, SPI + bytes(8)))
F(rep() + ext(131, b'mn@example.org') + MH)
F(req() + ext4(36, 1, SPI + bytes(range(20))))                       # generalized auth
F(req() + ext4(36, 3, SPI + bytes(range(8))) + ext(34, SPI + bytes(4)))
F(rep() + ext(137, struct.pack('!HI', 0x8000, 1700000000)))          # revocation support
F(rep() + ext(137, struct.pack('!HI', 0x0000, 0)))
F(rep() + ext(139, b'\x01' + HA) + ext(139, b'\x02' + HA))           # dynamic HA
F(rep() + ext(145, b'\x01' + b'registration ok') + ext(145, b'\x02' + b'fa text'))
F(req() + ext(144, bytes([0, 0, 0xc0, 4, 0, 0])) + ext(144, bytes([0, 0, 0x00, 47, 0, 0])))   # UDP tunnel req
F(rep() + ext(44, struct.pack('!BBHH', 0, 0, 0x8000, 30)) + ext(44, struct.pack('!BBHH', 0, 64, 0, 0)))
F(rep() + ext4(47, 1, b'\x01') + ext4(47, 1, b'\x02') + ext4(47, 0, b'\x00'))   # PMIPv4 non-skippable
F(req() + ext(147, b'\x01' + b'iface-id') + ext(147, b'\x02\x01' + bytes([2,0,0,0,0,9]))
        + ext(147, b'\x02\x03' + b'35-209900') + ext(147, b'\x03\x01' + b'310150123456789')
        + ext(147, b'\x03\x00' + b'zz') + ext(147, b'\x04\x05') + ext(147, b'\x00'))
F(req() + ext(148, b'\x00\x18' + HOA) + ext(148, b'\x01\x00\x18\x00' + HOA)
        + ext(148, b'\x02\x03\x10\x00' + HOA))                        # mobile network ext
# critical vendor extensions: CVSE 38 (2 octet length), old CVSE 37
F(req() + ext4(38, 0, struct.pack('!II', 12951, 0) [:4] + struct.pack('!H', 2) + b'keydata'))
F(req() + struct.pack('!BBH', 38, 0, 6 + 4) + struct.pack('!IH', 5535, 0x0401) + struct.pack('!I', 0x1001)
        + ext(132, b'challenge'))
F(req() + struct.pack('!BBH', 38, 0, 6 + 3) + struct.pack('!IH', 4491, 0x0102) + b'abc' + ext(129, b'\0\0'))
F(req() + struct.pack('!BBH', 38, 0, 6 + 2) + struct.pack('!IH', 5535, 0x0101) + b'\0\0')
# old CVSE (37): the length is one octet but the dissector reads it as a 2 octet length
F(req() + bytes([37, 8]) + b'\0' + struct.pack('!H', 8) + struct.pack('!IH', 4491, 0x0102) + b'ab')
# normal vendor extensions 134 / 133 with the 3GPP2 and a generic vendor
F(rep() + ext(134, b'\0\0' + struct.pack('!IHH', 5535, 16, 1)))                            # PPP link indicator
F(rep() + ext(134, b'\0\0' + struct.pack('!IH', 5535, 17) + bytes([1, 0x11, 4]) + bytes([8,8,8,8]) + bytes([0x12, 4]) + bytes([8,8,4,4])))
F(rep() + ext(134, b'\0\0' + struct.pack('!IHH', 4491, 7, 0x1234)) + ext(133, b'\0\0' + struct.pack('!IHH', 4491, 8, 0x4321)))
# generic and unknown extensions
F(req() + ext(132, b'\x00' * 12) + ext(129, b'\x01\x02') + ext(130, b'') + ext(200, b'xyz') + ext(255, b'\x01'))
# Types without a message dissector parse as extension lists: handoff, regional, fast binding...
for t in (16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 255):
    F(bytes([t, 6]) + bytes(range(1, 7)))
# NAT traversal tunnel data: IPv4 / UDP / MIP type 4 / IPv4 / UDP
inner_udp = ipv4(udp(b'hello', 5000, 5001), 17, (172,16,0,1), (172,16,0,2))
F(struct.pack('!BBH', 4, 4, 0) + inner_udp)
_ic = struct.pack('!BBHHH', 0, 0, 0, 1, 1)
inner_icmp = ipv4(struct.pack('!BBHHH', 0, 0, csum(_ic), 1, 1), 1, (172,16,0,1), (172,16,0,2))
F(struct.pack('!BBH', 4, 4, 0) + inner_icmp)
F(struct.pack('!BBH', 4, 47, 0) + inner_udp)                  # next header GRE (still an IP header)
F(struct.pack('!BBH', 4, 55, 0) + inner_udp)
# nested: tunnel data carrying a registration request that carries tunnel data
mid = ipv4(udp(struct.pack('!BBH', 4, 4, 0) + inner_udp, 434, 434), 17, (172,16,1,1), (172,16,1,2))
F(struct.pack('!BBH', 4, 4, 0) + mid)
# a Registration Request from a mobile node on another port
F(req() + MH, sport=434, dport=434)
F(rep(), sport=434, dport=40000)

# ---- malformed -----------------------------------------------------------
def B(m, sport=40000, dport=434): bad.append(eth(ipv4(udp(m, sport, dport))))
# reproducer of the NAT-T recursion: N levels of IPv4/UDP434/MIP type 4
def natt(n):
    pkt = struct.pack('!BBH', 4, 4, 0) + b'\x45'
    for i in range(n):
        pkt = ipv4(udp(struct.pack('!BBH', 4, 4, 0) + pkt if i else pkt, 434, 434))
    return pkt
for n in (4, 5, 6, 40):
    bad.append(eth(natt(n)))
bad.append(eth(natt(700)))
B(struct.pack('!BBH', 4, 4, 0))                   # tunnel data without payload
B(struct.pack('!BBH', 4, 4, 0) + b'\x45\0')       # truncated IP
# truncated messages
B(req()[:10]); B(rep()[:6]); B(rev()[:12]); B(rack()[:6]); B(b'\x01'); B(b'\x04')
# extensions running past the end or too short
B(req() + bytes([32, 40]) + bytes(8))
B(req() + bytes([32, 2]) + bytes(2))               # auth shorter than its SPI
B(req() + bytes([36, 1]))                          # general auth, truncated header
B(req() + bytes([137, 6, 0, 0]))
B(req() + bytes([148, 3, 9, 0, 0]))                # MNE unknown sub-type
B(req() + bytes([134, 4, 0, 0, 0, 0]))             # NVSE shorter than six octets
B(req() + bytes([134, 8]) + bytes(8))              # NVSE, unknown vendor, short
B(rep() + ext(134, b'\0\0' + struct.pack('!IH', 5535, 17) + b'\x01'))   # DNS truncated
B(req() + struct.pack('!BBH', 38, 0, 3) + bytes(3))
B(req() + bytes([37, 3, 0, 0, 0]))
B(rep() + ext(134, b'\0\0' + struct.pack('!IH', 5535, 99) + b'\0\0'))      # unknown 3GPP2 type
B(req() + bytes([44, 3, 0, 0, 0]))
B(req() + bytes([139, 2, 1, 2]))
B(req() + bytes([147, 3, 2, 1, 0]))
B(req() + bytes([147, 3, 3, 1, 0]))
B(req() + bytes([147, 1, 1]))
B(req() + bytes([145, 0]))
B(req() + bytes([131, 20]) + b'abc')
B(req() + bytes([144, 6, 0, 0, 0]))
B(req() + bytes([47]) + b'\x01\x00\xff')
B(bytes([20, 200]) + bytes(4))                     # type without a dissector, bad extension length

out = sys.argv[1] if len(sys.argv) > 1 else '.'
os.makedirs(out, exist_ok=True)
write_pcap(os.path.join(out, 'mip-coverage.pcap'), frames)
write_pcap(os.path.join(out, 'mip-coverage-malformed.pcap'), bad)
print(len(frames), len(bad))
