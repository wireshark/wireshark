#!/usr/bin/env python3
# Generates test/captures/bier_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the BIER (Bit Index Explicit
Replication, RFC 8296) dissector (packet-bier.c).

All packets are built from scratch with struct; no captured traffic is
used. Each frame is Ethernet (02:00:00:00:00:01 -> 01:00:5e:00:00:01)
carrying MPLS (ethertype 0x8847) whose post-stack first nibble is 5, so
MPLS hands the payload to BIER (mpls.pfn 5). Inner payloads are UDP to the
discard port between documentation addresses.

Usage: mkbier.py <output directory>

Writes:
  bier-coverage.pcap            every BitString length, every next protocol
                                (MPLS down/upstream, Ethernet, IPv4, OAM,
                                IPv6, VXLAN, NVGRE, Geneve, reserved and
                                unknown values), headers that BIER rejects,
                                MPLS/BIER nesting, and (last frame) the
                                MPLS<->BIER loop that stops with the
                                "bier.too_deep" warning
  bier-coverage-malformed.pcap  truncated inner payloads (exceptions)
"""

import struct
import sys

SRC4 = (192, 0, 2, 1)
DST4 = (233, 252, 0, 1)
SRC6 = bytes.fromhex('20010db8000000000000000000000001')
DST6 = bytes.fromhex('ff0e0000000000000000000000000001')
ETH_DST = bytes.fromhex('01005e000001')
ETH_SRC = bytes.fromhex('020000000001')
IN_DST = bytes.fromhex('020000000aaa')
IN_SRC = bytes.fromhex('020000000bbb')


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


def ipv4(proto, payload, ident=1, src=SRC4, dst=DST4):
    h = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0, 64, proto, 0,
                    bytes(src), bytes(dst))
    return h[:10] + struct.pack('>H', csum(h)) + h[12:] + payload


def udp4(data, sport=40000, dport=9, src=SRC4, dst=DST4, ident=1):
    u = struct.pack('>HHHH', sport, dport, 8 + len(data), 0) + data
    c = csum(struct.pack('>4s4sBBH', bytes(src), bytes(dst), 0, 17, len(u)) + u) or 0xffff
    return ipv4(17, u[:6] + struct.pack('>H', c) + u[8:], ident, src, dst)


def udp6(data, sport=40000, dport=9):
    u = struct.pack('>HHHH', sport, dport, 8 + len(data), 0) + data
    pseudo = struct.pack('>16s16sIxxxB', SRC6, DST6, len(u), 17)
    c = csum(pseudo + u) or 0xffff
    u = u[:6] + struct.pack('>H', c) + u[8:]
    return struct.pack('>IHBB16s16s', 0x60000000, len(u), 17, 64, SRC6, DST6) + u


def eth(payload, ethertype=0x0800, dst=IN_DST, src=IN_SRC):
    return dst + src + struct.pack('>H', ethertype) + payload


def mpls(label, payload, bos=1, tc=0, ttl=64):
    return struct.pack('>I', (label << 12) | (tc << 9) | (bos << 8) | ttl) + payload


def bier(proto, payload, bsl=1, ver=0, entropy=0x12345, oam=0, rsv=0, dscp=0,
         bfir=1, bitstring=None, nibble=5):
    n = 1 << (bsl + 2) if 1 <= bsl <= 7 else 8
    if bitstring is None:
        bitstring = bytes(n - 1) + b'\x01'
    w0 = (nibble << 28) | (ver << 24) | (bsl << 20) | entropy
    w1 = (oam << 30) | (rsv << 28) | (dscp << 22) | (proto & 0x3f) << 16 | bfir
    return struct.pack('>II', w0, w1) + bitstring + payload


def frame(inner, labels=(100,)):
    stack = inner
    for i, lab in enumerate(reversed(labels)):
        stack = mpls(lab, stack, bos=1 if i == 0 else 0)
    return ETH_DST + ETH_SRC + b'\x88\x47' + stack


def write(path, pkts):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, p in enumerate(pkts):
            if isinstance(p, tuple):
                p, orig = p
            else:
                orig = len(p)
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), orig) + p)


def data(i):
    return b'BIER coverage %03d' % i


def main(out):
    pk = []
    # 1-7: every BitString length (64 .. 4096 bits) carrying IPv4/UDP,
    # with different BFIR-ids, entropy and bit patterns
    for bsl in range(1, 8):
        n = 1 << (bsl + 2)
        bits = bytes((bsl * 17 + k) & 0xff for k in range(n))
        pk.append(frame(bier(4, udp4(data(bsl), ident=bsl), bsl=bsl, bfir=bsl * 100,
                             entropy=0x10000 + bsl, bitstring=bits)))
    # 8: MPLS downstream-assigned label carrying IPv4
    pk.append(frame(bier(1, mpls(300, udp4(data(8), ident=8)))))
    # 9: MPLS upstream-assigned label carrying IPv6
    pk.append(frame(bier(2, mpls(301, udp6(data(9))), bsl=2)))
    # 10: Ethernet frame (IPv4 inside)
    pk.append(frame(bier(3, eth(udp4(data(10), ident=10)), bsl=3)))
    # 11: IPv4 with non-zero version, OAM, Rsv, DSCP and an all-ones header
    pk.append(frame(bier(4, udp4(data(11), ident=11), ver=3, entropy=0xfffff, oam=3,
                         rsv=3, dscp=0x3f, bfir=0xffff)))
    # 12: OAM packet (no dissector registered -> data)
    pk.append(frame(bier(5, bytes.fromhex('1001000000000001') + b'BIER-OAM')))
    # 13: IPv6
    pk.append(frame(bier(6, udp6(data(13)), bsl=4)))
    # 14: VXLAN without IP/UDP (VNI 4660) carrying Ethernet/IPv4
    pk.append(frame(bier(7, struct.pack('>II', 0x08000000, 4660 << 8) +
                         eth(udp4(data(14), ident=14)))))
    # 15: NVGRE (GRE with key, protocol 0x6558) carrying Ethernet/IPv4
    pk.append(frame(bier(8, struct.pack('>HHI', 0x2000, 0x6558, (5000 << 8) | 7) +
                         eth(udp4(data(15), ident=15)))))
    # 16: Geneve without IP/UDP (VNI 7777) carrying Ethernet/IPv4
    pk.append(frame(bier(9, struct.pack('>BBHI', 0, 0, 0x6558, 7777 << 8) +
                         eth(udp4(data(16), ident=16)))))
    # 17-19: Reserved (0), unknown (10), Reserved (63): data
    for i, p in ((17, 0), (18, 10), (19, 63)):
        pk.append(frame(bier(p, data(i))))
    # 20: two-label stack, then BIER -> MPLS -> BIER -> IPv4 (nesting)
    pk.append(frame(bier(1, mpls(400, bier(4, udp4(data(20), ident=20), bsl=2, bfir=20))),
                    labels=(16, 200)))
    # 21-25: headers BIER rejects (MPLS then uses its heuristics / data):
    # 21: shorter than 16 octets
    pk.append(frame(bytes.fromhex('5010000000040001') + b'\x00\x01\x02\x03'))
    # 22: BitString length 0
    pk.append(frame(bier(4, b'\x00' * 16, bsl=0)))
    # 23: BitString length 8 (reserved)
    pk.append(frame(bier(4, b'\x00' * 16, bsl=8)))
    # 24: BitString length 15
    pk.append(frame(bier(4, b'\x00' * 16, bsl=15)))
    # 25: BSL 7 (512 octets) but only 100 octets follow
    pk.append(frame(bytes.fromhex('5070000000040001') + bytes(100)))
    # 26: only one octet of the BIER header captured (snapshot length),
    # 40 octets on the wire
    f = frame(bier(4, b'\x00' * 24))
    pk.append((f[:19], len(f)))
    # 27: MPLS label 500 carrying IPv4/UDP directly; with
    # "-d mpls.label==500,bier" BIER is tried first and rejects the
    # first nibble 4, then the first nibble logic dissects IPv4
    pk.append(frame(udp4(data(27), ident=27), labels=(500,)))
    # 28: the reproducer of bier_mpls_loop.py, shortened from
    # 3000 to 500 levels of MPLS (label 100, S=1) + BIER (BSL 1, next
    # protocol MPLS): stops with bier.too_deep before the layer limit
    level = struct.pack('>I', (100 << 12) | (1 << 8) | 64) + \
        bytes([0x50, 0x10, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01]) + b'\x00' * 7 + b'\x01'
    pk.append(b'\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x88\x47' +
              level * 500 + b'\x00' * 16)
    write(out + '/bier-coverage.pcap', pk)

    bad = []
    # 1: IPv4 payload cut short
    bad.append(frame(bier(4, udp4(data(1))[:12])))
    # 2: IPv6 payload cut short
    bad.append(frame(bier(6, udp6(data(2))[:20])))
    # 3: MPLS label cut short after BIER
    bad.append(frame(bier(1, b'\x00\x12')))
    # 4: VXLAN header cut short
    bad.append(frame(bier(7, b'\x08\x00\x00')))
    # 5: Geneve header cut short
    bad.append(frame(bier(9, b'\x00\x00\x65')))
    # 6: GRE header cut short
    bad.append(frame(bier(8, b'\x20')))
    write(out + '/bier-coverage-malformed.pcap', bad)


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')
