#!/usr/bin/env python3
# Generates test/captures/auto_rp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the Cisco Auto-RP dissector
(packet-auto_rp.c).

All packets are built from scratch with struct; no captured traffic is
used. Candidate RPs (10.1.0.x) send RP announcements to 224.0.1.39 and a
mapping agent (10.1.0.100) sends RP mappings to 224.0.1.40, all on UDP
port 496.

Usage: mkauto_rp.py <output directory>

Writes:
  auto_rp-coverage.pcap            every packet type, PIM version, group
                                   sign, singular/plural forms, unknown
                                   version and type, trailing data
  auto_rp-coverage-malformed.pcap  truncated packets (exceptions)
"""

import struct
import sys

PORT = 496
ANNOUNCE = (224, 0, 1, 39)
DISCOVERY = (224, 0, 1, 40)
MAPPER = (10, 1, 0, 100)


def ip_checksum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


class Pcap:
    def __init__(self):
        self.frames = []

    def udp(self, src, dst, payload, sport=PORT, dport=PORT):
        udp = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
        pseudo = struct.pack('>4s4sBBH', bytes(src), bytes(dst), 0, 17, len(udp))
        cs = ip_checksum(pseudo + udp) or 0xffff
        udp = udp[:6] + struct.pack('>H', cs) + udp[8:]
        ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0xc0, 20 + len(udp), len(self.frames) & 0xffff,
                         0, 16, 17, 0, bytes(src), bytes(dst))
        ip = ip[:10] + struct.pack('>H', ip_checksum(ip)) + ip[12:]
        # IPv4 multicast MAC for the destination group
        dmac = b'\x01\x00\x5e' + bytes([dst[1] & 0x7f, dst[2], dst[3]])
        self.frames.append(dmac + b'\x02\x00\x00\x00\x01' + bytes([src[3]]) + b'\x08\x00' + ip + udp)

    def write(self, path):
        out = [struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)]
        t = 1700000000
        for i, f in enumerate(self.frames):
            out.append(struct.pack('<IIII', t + i, 0, len(f), len(f)) + f)
        with open(path, 'wb') as fh:
            fh.write(b''.join(out))


def group(addr, mask, sign=0):
    return struct.pack('>BB4s', sign, mask, bytes(addr))


def rp_map(addr, pimver, groups):
    return struct.pack('>4sBB', bytes(addr), pimver, len(groups)) + b''.join(groups)


def auto_rp(ver_type, holdtime, maps, rp_count=None, reserved=0, trailing=b''):
    if rp_count is None:
        rp_count = len(maps)
    return struct.pack('>BBHI', ver_type, rp_count, holdtime, reserved) + b''.join(maps) + trailing


def main_capture():
    c = Pcap()
    # 1: RP announcement, one RP (PIMv2), one positive group, holdtime 181
    c.udp((10, 1, 0, 1), ANNOUNCE, auto_rp(0x11, 181, [
        rp_map((10, 1, 0, 1), 2, [group((224, 0, 0, 0), 4)])]))
    # 2: announcement, dual version RP, a negative and a positive group, holdtime 1
    c.udp((10, 1, 0, 2), ANNOUNCE, auto_rp(0x11, 1, [
        rp_map((10, 1, 0, 2), 3, [group((239, 0, 0, 0), 8, 1), group((224, 0, 0, 0), 4)])]))
    # 3: announcement, PIMv1 RP, no groups, holdtime 0 (forever)
    c.udp((10, 1, 0, 3), ANNOUNCE, auto_rp(0x11, 0, [rp_map((10, 1, 0, 3), 1, [])]))
    # 4: RP mapping, three RPs (version unknown, v1, v2), groups 3/0/1
    c.udp(MAPPER, DISCOVERY, auto_rp(0x12, 181, [
        rp_map((10, 1, 0, 1), 0, [group((224, 0, 0, 0), 4), group((239, 1, 0, 0), 16, 1),
                                  group((232, 0, 0, 0), 8)]),
        rp_map((10, 1, 0, 3), 1, []),
        rp_map((10, 1, 0, 2), 2, [group((239, 255, 255, 250), 32)])]))
    # 5: RP mapping with no RPs, holdtime 65535
    c.udp(MAPPER, DISCOVERY, auto_rp(0x12, 65535, []))
    # 6: unknown packet type 3
    c.udp(MAPPER, DISCOVERY, auto_rp(0x13, 60, [rp_map((10, 1, 0, 4), 2, [group((225, 0, 0, 0), 8)])]))
    # 7: unknown version 2, packet type 0, reserved field set
    c.udp(MAPPER, DISCOVERY, auto_rp(0x20, 60, [rp_map((10, 1, 0, 5), 2, [group((226, 0, 0, 0), 8)])],
                                     reserved=0xdeadbeef))
    # 8: reserved bits set in the PIM version and sign octets (masked off)
    c.udp((10, 1, 0, 6), ANNOUNCE, auto_rp(0x11, 120, [
        rp_map((10, 1, 0, 6), 0xfe, [group((227, 0, 0, 0), 8, 0xfe), group((228, 0, 0, 0), 8, 0xff)])]))
    # 9: RP mapping followed by trailing data
    c.udp(MAPPER, DISCOVERY, auto_rp(0x12, 181, [
        rp_map((10, 1, 0, 1), 2, [group((224, 0, 0, 0), 4)])], trailing=b'\xca\xfe\xba\xbe\x00'))
    # 10: announcement whose RP count is 0 but carries data (all of it trailing)
    c.udp((10, 1, 0, 7), ANNOUNCE, auto_rp(0x11, 30, [rp_map((10, 1, 0, 7), 2, [group((229, 0, 0, 0), 8)])],
                                           rp_count=0))
    # 11: a large mapping, 16 RPs with 8 groups each
    maps = [rp_map((10, 1, 1, i), 2 if i % 2 else 3,
                   [group((224 + j, i, 0, 0), 16, j & 1) for j in range(8)]) for i in range(16)]
    c.udp(MAPPER, DISCOVERY, auto_rp(0x12, 181, maps))
    return c


def malformed_capture():
    c = Pcap()
    # 1: one octet, the RP count is missing
    c.udp(MAPPER, DISCOVERY, b'\x12')
    # 2: header cut in the holdtime
    c.udp(MAPPER, DISCOVERY, b'\x12\x01\x00')
    # 3: 255 RPs, 255 groups each, truncated (ayiya_nested.py)
    c.udp(MAPPER, DISCOVERY, bytes([0x12, 255, 0, 10, 0, 0, 0, 0]) + bytes([10, 0, 0, 1, 2, 255])
          + b'\x00\x08\xe0\x00\x00\x00' * 3)
    # 4: map header cut before the group count
    c.udp(MAPPER, DISCOVERY, auto_rp(0x12, 10, [], rp_count=1) + b'\x0a\x01\x00\x01\x02')
    # 5: a group cut in its prefix (the map subtree length fits)
    c.udp(MAPPER, DISCOVERY, auto_rp(0x11, 10, [rp_map((10, 1, 0, 1), 2, [group((224, 0, 0, 0), 4)])])[:-2])
    return c


if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    main_capture().write(out + '/auto_rp-coverage.pcap')
    malformed_capture().write(out + '/auto_rp-coverage-malformed.pcap')
