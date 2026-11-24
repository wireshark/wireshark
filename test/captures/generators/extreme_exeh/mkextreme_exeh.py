#!/usr/bin/env python3
# Generates test/captures/extreme_exeh_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures for the EXEH (EXos internal Extra Header)
dissector (packet-extreme-exeh.c).

EXEH is carried in Ethernet frames with ethertype 0xE555, registered by
default. A 38 octet header (module and port numbers, direction 7 for
incoming or 0xff for outgoing, frame source, VLAN, an ethertype and a
word that is the length for ethertype 0x8100) is followed by a complete
Ethernet frame without FCS, which is handed to eth_withoutfcs. Every
packet is built with struct; nothing comes from a real network.

Usage: mkextreme_exeh.py <output directory>
  extreme-exeh-coverage.pcap            both directions, every frame
                                        source, 0x8100 length checks
  extreme-exeh-coverage-malformed.pcap  headers cut short
"""
import os
import struct
import sys

A = bytes.fromhex('02000000000a')
B = bytes.fromhex('02000000000b')
C = bytes.fromhex('02000000000c')
D = bytes.fromhex('02000000000d')


def pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)


def ipv4(payload=b'x' * 8):
    h = struct.pack('>BBHHHBBH', 0x45, 0, 20 + len(payload), 7, 0x4000, 64, 253, 0) + \
        bytes([10, 0, 0, 1, 10, 0, 0, 2])
    s = sum(struct.unpack('>10H', h))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return h[:10] + struct.pack('>H', (~s) & 0xffff) + h[12:] + payload


def inner(etype=0x0800, payload=None, dst=D, src=C):
    if payload is None:
        payload = ipv4()
    return dst + src + struct.pack('>H', etype) + payload


def exeh(direction=0x07, m1=1, p1=2, m2=1, p2=2, fsrc=0, vlan=0, etype=0x0800,
         eword=0, frame=None, unk0=0, flags17=0, unk10=bytes(7), unk18=bytes(4),
         unk22=0, unk28=0, unk32=0):
    if frame is None:
        frame = inner()
    h = struct.pack('>HHHHH', unk0, m1, p1, m2, p2) + unk10 + bytes([flags17]) + \
        unk18 + struct.pack('>HHHHHHHHH', unk22, fsrc, vlan, unk28, direction, unk32,
                             etype, eword, 0)[0:0]
    h += struct.pack('>HHHHHHHH', unk22, fsrc, vlan, unk28, direction, unk32, etype, eword)
    assert len(h) == 38, len(h)
    return h + frame


def eth(payload, dst=B, src=A, etype=0xE555):
    return dst + src + struct.pack('>H', etype) + payload


main = [
    # 1: incoming, ports equal, frame source N/A, IPv4 frame
    eth(exeh()),
    # 2: outgoing from the CPU; module2 and port2 zero are not compared
    eth(exeh(direction=0xff, m1=3, p1=4, m2=0, p2=0, fsrc=0x0000)),
    # 3: outgoing from Broadcom hardware, with the Add VLAN ID word
    eth(exeh(direction=0xff, m1=1, p1=9, m2=0, p2=0, fsrc=0x4248, unk22=0x000f,
             flags17=0x02, vlan=100)),
    # 4: outgoing, other flag bits, unknown words non-zero
    eth(exeh(direction=0xff, unk0=0x1234, unk10=bytes(range(7)), flags17=0xfd,
             unk18=b'\xde\xad\xbe\xef', unk22=0, unk28=0xaaaa, unk32=0xbbbb, m2=1, p2=2)),
    # 5: incoming with a VLAN tag as the EXEH ethertype 0x8100 with matching
    #    length: eword = bytes from 0x8100 to the end of the frame
    None,
    # 6: etype 0x8100 with a wrong length
    eth(exeh(etype=0x8100, eword=7, frame=inner(0x8100, struct.pack('>HH', 100, 0x0800) + ipv4()))),
    # 7: etype 0x8100 with right length computed below
    None,
    # 8: other ethertype (etypedata shown)
    eth(exeh(etype=0x86dd, eword=0x1234)),
    # 9: inner frame is an ARP-like data ethertype
    eth(exeh(frame=inner(0x88b5, b'experimental ethertype data'))),
    # 10: incoming but frame source and ports warnings (all three expert infos)
    eth(exeh(direction=0x07, m1=1, p1=2, m2=3, p2=4, fsrc=0x4248)),
    # 11: outgoing, unknown frame source magic, module2 non-zero and unequal
    eth(exeh(direction=0xff, m1=1, p1=2, m2=5, p2=6, fsrc=0x1111)),
    # 12: direction neither 7 nor 255 (handled as outgoing)
    eth(exeh(direction=0x0001, m1=1, p1=2, m2=0, p2=0, fsrc=0)),
    # 13: EXEH nested in EXEH
    eth(exeh(frame=inner(0xE555, exeh()))),
]
# 5: VLAN tagged inner frame with the matching length (4 bytes at offset 34,
# the tag contents; the length counts from the 0x8100 octets to the end)
tagged = inner(0x8100, struct.pack('>HH', 100, 0x0800) + ipv4())
main[4] = eth(exeh(etype=0x8100, eword=4 + len(tagged), frame=tagged, vlan=200))
# 7: length equal to the bytes remaining at the ethertype (includes the 4 octets
# of etype and length word plus the inner frame)
main[6] = eth(exeh(etype=0x8100, eword=4 + len(tagged), frame=tagged))

# EXEH nested 600 times, each level an Ethernet frame (the reproducer of
# "Ethertype: Limit the nesting of encapsulated payloads")
deep = inner(0x88b5, b'bottom of the nesting')
for _ in range(600):
    deep = inner(0xE555, exeh(frame=deep))
main.append(deep)

malformed = [
    # inner frame too short for Ethernet (header cut), and no inner frame
    eth(exeh(frame=b'\x01\x02\x03')),
    eth(exeh(frame=b'')),
    # header cut at each interesting point
    eth(exeh()[:30]),            # direction at offset 30 cannot be read
    eth(exeh()[:2]),
    eth(exeh()[:10]),
    eth(exeh()[:25]),
    eth(exeh()[:35]),            # etype cut
    eth(exeh()[:37]),
    eth(b''),
]

if __name__ == '__main__':
    out = sys.argv[1]
    pcap(os.path.join(out, 'extreme-exeh-coverage.pcap'), main)
    pcap(os.path.join(out, 'extreme-exeh-coverage-malformed.pcap'), malformed)
