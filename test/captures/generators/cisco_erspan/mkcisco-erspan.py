#!/usr/bin/env python3
# Generates test/captures/cisco_erspan_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the Cisco ERSPAN dissector
(packet-cisco-erspan.c).

ERSPAN runs over GRE with protocol type 0x88BE (Type I without the GRE
sequence number, Type II with it) or 0x22EB (Type III). The header
version decides the layout; Type III has an optional 8 octet platform
specific sub-header. The mirrored frame is an Ethernet frame without FCS
(or, for Type III frame types other than Ethernet, data). Linux cooked
captures of an ipgre interface hand ERSPAN the payload without the GRE
flags, which is taken as Type I. Every packet is built from scratch with
struct; no captured traffic is used. Each mirrored frame is a single
Ethernet/IPv4/UDP datagram to the discard port; tunnels are never nested
(deep nesting reaches the generic layer limit, see README).

Usage: mkcisco-erspan.py <output directory>

Writes:
  cisco-erspan-coverage.pcapng            Type I, II and III, every field
                                          value range, every platform ID,
                                          unknown versions, Linux cooked
                                          ipgre frames
  cisco-erspan-coverage-malformed.pcapng  headers cut short
"""

import os
import struct
import sys

SRC = (192, 0, 2, 1)
DST = (198, 51, 100, 2)


def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


def ipv4(proto, payload, src=SRC, dst=DST, ident=1):
    hdr = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0,
                      64, proto, 0, bytes(src), bytes(dst))
    return hdr[:10] + struct.pack('>H', csum(hdr)) + hdr[12:] + payload


def udp(sport, dport, data, src, dst):
    hdr = struct.pack('>HHHH', sport, dport, 8 + len(data), 0)
    pseudo = struct.pack('>4s4sBBH', bytes(src), bytes(dst), 0, 17, 8 + len(data))
    c = csum(pseudo + hdr + data) or 0xffff
    return hdr[:6] + struct.pack('>H', c) + data


def eth(etype, payload, dst='020000000002', src='020000000001'):
    return bytes.fromhex(dst) + bytes.fromhex(src) + struct.pack('>H', etype) + payload


def mirrored(n, vlan=None):
    """The mirrored frame: Ethernet, IPv4, UDP to the discard port."""
    a, b = (10, 0, 0, 1), (10, 0, 0, 2)
    ip = ipv4(17, udp(40000 + n, 9, b'erspan-%d' % n, a, b), a, b, ident=n)
    if vlan is not None:
        return eth(0x8100, struct.pack('>HH', vlan, 0x0800) + ip, '020000000012', '020000000011')
    return eth(0x0800, ip, '020000000012', '020000000011')


def gre(proto, payload, seq=None):
    if seq is None:
        return struct.pack('>HH', 0x0000, proto) + payload
    return struct.pack('>HHI', 0x1000, proto, seq) + payload


def outer(payload, n, vlan=None):
    ip = ipv4(47, payload, ident=n)
    if vlan is not None:
        return eth(0x8100, struct.pack('>HH', vlan, 0x0800) + ip)
    return eth(0x0800, ip)


def type2(vlan=0, cos=0, encap=0, t=0, spanid=0, reserved=0, index=0, ver=1):
    return struct.pack('>HHI', (ver << 12) | vlan,
                       (cos << 13) | (encap << 11) | (t << 10) | spanid,
                       (reserved << 20) | index)


def type3(vlan=0, cos=0, bso=0, t=0, spanid=0, ts=0, sgt=0, p=1, ft=0, hw=0,
          d=0, gra=0, sub=None, ver=2):
    h = struct.pack('>HHIHH', (ver << 12) | vlan,
                    (cos << 13) | (bso << 11) | (t << 10) | spanid, ts, sgt,
                    (p << 15) | (ft << 10) | (hw << 4) | (d << 3) | (gra << 1)
                    | (1 if sub is not None else 0))
    return h + (sub or b'')


def sub(platid, w1, w2):
    return struct.pack('>II', (platid << 26) | w1, w2)


def sll_ipgre(proto, payload):
    """Linux cooked capture header of an ipgre interface (ARPHRD_IPGRE)."""
    return struct.pack('>HHH8sH', 0, 778, 4, bytes(SRC) + bytes(4), proto) + payload


def pcapng_block(btype, body):
    body += b'\0' * ((-len(body)) % 4)
    n = 12 + len(body)
    return struct.pack('<II', btype, n) + body + struct.pack('<I', n)


def write_pcapng(path, frames):
    """frames: (interface, data); interface 0 is Ethernet, 1 Linux cooked."""
    with open(path, 'wb') as f:
        f.write(pcapng_block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1)))
        f.write(pcapng_block(1, struct.pack('<HHI', 1, 0, 262144)))
        f.write(pcapng_block(1, struct.pack('<HHI', 113, 0, 262144)))
        for i, (ifc, p) in enumerate(frames):
            ts = (1700000000 + i) * 1000000
            f.write(pcapng_block(6, struct.pack('<IIIII', ifc, ts >> 32, ts & 0xffffffff,
                                                len(p), len(p)) + p))


def main_frames():
    F = []

    def add(payload, vlan=None):
        n = len(F) + 1
        F.append((0, outer(payload, n, vlan)))

    # 1: Type I (0x88BE without the GRE sequence number)
    add(gre(0x88BE, mirrored(1)))
    # 2-5: Type II, encapsulation 0-3; 3 truncated; 5 keeps the VLAN tag
    add(gre(0x88BE, type2(vlan=100, cos=5, encap=0, spanid=1, index=12345) + mirrored(2), seq=1))
    add(gre(0x88BE, type2(vlan=200, cos=0, encap=1, t=1, spanid=2, index=1) + mirrored(3), seq=2))
    add(gre(0x88BE, type2(vlan=300, cos=7, encap=2, spanid=1023, index=0xfffff) + mirrored(4), seq=3))
    add(gre(0x88BE, type2(vlan=400, encap=3, spanid=3, reserved=0xfff) + mirrored(5, vlan=400), seq=4))
    # 6: Type II in an 802.1Q tagged outer frame (VLAN 77 is kept)
    add(gre(0x88BE, type2(vlan=4095, encap=0, spanid=4) + mirrored(6), seq=5), vlan=77)
    # 7-10: Type III without a sub-header, BSO 0-3, granularity 0-3,
    #       ingress/egress, truncated
    add(gre(0x22EB, type3(vlan=10, cos=1, bso=0, spanid=10, ts=1000, sgt=0x1234, hw=1, d=0, gra=0) + mirrored(7)))
    add(gre(0x22EB, type3(vlan=11, cos=2, bso=1, t=1, spanid=11, ts=2000, sgt=2, hw=63, d=1, gra=1) + mirrored(8)))
    add(gre(0x22EB, type3(vlan=12, cos=3, bso=2, spanid=12, ts=0xffffffff, sgt=0xffff, d=0, gra=2) + mirrored(9)))
    add(gre(0x22EB, type3(vlan=4095, cos=7, bso=3, spanid=1023, ts=0, p=0, d=1, gra=3) + mirrored(10)))
    # 11-20: Type III with a platform specific sub-header: platform IDs
    #        1, 3, 4, 5, 6, 7, 0 (alias of 7), 2, 8 and 63 (reserved)
    add(gre(0x22EB, type3(vlan=20, spanid=20, ts=1, gra=3, sub=sub(1, (0x5 << 12) | 0x123, 0xabcdef01)) + mirrored(11)))
    add(gre(0x22EB, type3(vlan=21, spanid=21, ts=2, gra=2, sub=sub(3, (0x7 << 14) | 0x3fff, 0x0000ffff)) + mirrored(12)))
    add(gre(0x22EB, type3(vlan=22, spanid=22, ts=3, sub=sub(4, (0xff << 14) | 0x1234, 0xffffffff)) + mirrored(13)))
    add(gre(0x22EB, type3(vlan=23, spanid=23, ts=4, sub=sub(5, (0x3ff << 16) | 0x8001, 1700000000)) + mirrored(14)))
    add(gre(0x22EB, type3(vlan=24, spanid=24, ts=5, sub=sub(6, (0x001 << 16) | 0x0002, 1700000001)) + mirrored(15)))
    add(gre(0x22EB, type3(vlan=25, spanid=25, ts=6, gra=2, sub=sub(7, (0x3f << 20) | 0xfffff, 0x00000001)) + mirrored(16)))
    add(gre(0x22EB, type3(vlan=26, spanid=26, ts=7, gra=2, sub=sub(0, 0x00042, 0x00000002)) + mirrored(17)))
    add(gre(0x22EB, type3(vlan=27, spanid=27, ts=8, sub=sub(2, 0x1234567, 0x89abcdef)) + mirrored(18)))
    add(gre(0x22EB, type3(vlan=28, spanid=28, ts=9, sub=sub(8, 0, 0)) + mirrored(19)))
    add(gre(0x22EB, type3(vlan=29, spanid=29, ts=10, sub=sub(63, 0x3ffffff, 0xffffffff)) + mirrored(20)))
    # 21-23: Type III frame types other than Ethernet go to data: IP (2),
    #        1 and 31 (unnamed)
    a, b = (10, 0, 0, 3), (10, 0, 0, 4)
    ippdu = ipv4(17, udp(40021, 9, b'ip-frame', a, b), a, b, ident=21)
    add(gre(0x22EB, type3(vlan=30, spanid=30, ft=2, p=0) + ippdu))
    add(gre(0x22EB, type3(vlan=31, spanid=31, ft=1, p=0) + b'\x01\x02\x03\x04'))
    add(gre(0x22EB, type3(vlan=32, spanid=32, ft=31, p=0, sub=sub(1, 1, 1)) + b'\x05\x06\x07\x08'))
    # 24: a Type III header in 0x88BE with the sequence number
    add(gre(0x88BE, type3(vlan=40, spanid=40, ts=40) + mirrored(24), seq=6))
    # 25: a Type II header in 0x22EB
    add(gre(0x22EB, type2(vlan=41, spanid=41, index=41) + mirrored(25)))
    # 26-27: unknown versions 0 (0x22EB) and 15 (0x88BE): only the
    #        version is shown, with a warning
    add(gre(0x22EB, struct.pack('>H', 0x0000) + bytes(10)))
    add(gre(0x88BE, struct.pack('>H', 0xf123) + bytes(10), seq=7))
    # 28-29: Linux cooked capture of an ipgre interface: the GRE flags
    #        are not handed to ERSPAN, so 0x88BE is Type I; 0x22EB has a
    #        header
    F.append((1, sll_ipgre(0x88BE, mirrored(28))))
    F.append((1, sll_ipgre(0x22EB, type3(vlan=50, spanid=50, ts=50, sub=sub(5, 7, 8)) + mirrored(29))))
    return F


def malformed_frames():
    F = []

    def add(payload):
        F.append((0, outer(payload, len(F) + 1)))

    # 1: one octet of an ERSPAN header
    add(gre(0x22EB, b'\x20'))
    # 2: a Type II header cut short
    add(gre(0x88BE, type2(vlan=1, spanid=1)[:6], seq=1))
    # 3: a Type III header cut short
    add(gre(0x22EB, type3(vlan=1, spanid=1)[:9]))
    # 4: a Type III sub-header cut short
    add(gre(0x22EB, type3(vlan=1, spanid=1, sub=sub(5, 1, 2))[:16]))
    # 5: a reserved platform ID sub-header cut short
    add(gre(0x22EB, type3(vlan=1, spanid=1, sub=sub(9, 1, 2))[:14]))
    # 6: Type II header, mirrored frame cut short
    add(gre(0x88BE, type2(vlan=1, spanid=1) + mirrored(7)[:10], seq=2))
    # 7: Linux cooked ipgre, 0x22EB with a header cut short
    F.append((1, sll_ipgre(0x22EB, type3(vlan=1)[:5])))
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcapng(os.path.join(out, 'cisco-erspan-coverage.pcapng'), main_frames())
    write_pcapng(os.path.join(out, 'cisco-erspan-coverage-malformed.pcapng'), malformed_frames())


if __name__ == '__main__':
    main()
