#!/usr/bin/env python3
# Generates test/captures/dvmrp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the DVMRP dissector
(packet-dvmrp.c).

DVMRP is carried in IGMP (IP protocol 2) as IGMP type 0x13, which the
IGMP dissector hands to DVMRP through the "igmp.type" table by default.
A v3 message has an 8 octet header (type, code, checksum, reserved,
capabilities, minor version 0xff, major version 3); without the
"strict_v3" preference every message of 8 octets or more is taken as v3,
so v1 messages (4 octet header and commands) are only decoded as v1
when they are shorter than 8 octets, or with strict_v3 set. The v1
messages longer than 8 octets here use codes 3 and 4, which decode as
v3 "Ask Neighbors"/"Neighbors" (no body parsing) by default and as the
v1 commands with strict_v3. Every packet is built from scratch with
struct; no captured traffic is used.

Usage: mkdvmrp.py <output directory>

Writes:
  dvmrp-coverage.pcap            every v3 code (Probe, Report with every
                                 netmask form and the default route,
                                 Neighbors 2 with every flag, Prune,
                                 Graft and Graft ACK with and without
                                 netmask, unknown code), short v1
                                 messages and long v1 messages with
                                 every command
  dvmrp-coverage-malformed.pcap  bad checksum, truncated Report, Prune
                                 and v1 commands
"""

import os
import struct
import sys

from pcaplib import eth, ipv4, cksum, ip4, write_pcap  # noqa: E402

ROUTER_A = '192.0.2.1'
ROUTER_B = '192.0.2.2'
ALL_DVMRP = '224.0.0.4'


def igmp_frame(msg, src=ROUTER_A, dst=ALL_DVMRP, good_cksum=True):
    """Fill in the IGMP checksum (octets 2-3) and wrap in IPv4/Ethernet."""
    if good_cksum:
        msg = msg[:2] + b'\0\0' + msg[4:]
        msg = msg[:2] + struct.pack('>H', cksum(msg)) + msg[4:]
    a = ip4(dst)
    if a[0] >= 224:
        dmac = bytes([0x01, 0x00, 0x5e, a[1] & 0x7f, a[2], a[3]])
    else:
        dmac = bytes.fromhex('020000000002')
    smac = bytes.fromhex('020000000001') if src == ROUTER_A else bytes.fromhex('020000000002')
    return eth(ipv4(msg, 2, src, dst, ttl=1 if a[0] >= 224 else 64), 0x0800, smac, dmac)


def v3(code, body=b'', caps=0, reserved=0, minor=0xff, major=3):
    return struct.pack('>BBHBBBB', 0x13, code, 0, reserved, caps, minor, major) + body


def v1(code, cmds=b''):
    return struct.pack('>BBH', 0x13, code, 0) + cmds


def route(mask3, pairs):
    """mask3: the three low mask octets as sent (m1, m2, m3); pairs: list
    of (source octets, metric); the last pair gets the 0x80 bit."""
    out = bytes(mask3)
    for i, (src, metric) in enumerate(pairs):
        out += bytes(src)
        if i == len(pairs) - 1:
            metric |= 0x80
        out += bytes([metric])
    return out


def main_frames():
    F = []
    # 1: Probe with every capability bit, a generation ID and two neighbors
    F.append(igmp_frame(v3(1, struct.pack('>I', 0x11223344) + ip4(ROUTER_B) + ip4('192.0.2.3'),
                           caps=0x3f)))
    # 2: Probe without capabilities and without neighbors, from router B
    F.append(igmp_frame(v3(1, struct.pack('>I', 0x55667788), caps=0x00), src=ROUTER_B))
    # 3: Report: a /16 route with two sources, a /24 with one, a /32 with
    #    one, a /8 (mask octets 0) with the default route and a source
    rep = route([0xff, 0x00, 0x00], [([10, 1], 1), ([10, 2], 2)])
    rep += route([0xff, 0xff, 0x00], [([192, 0, 2], 3)])
    rep += route([0xff, 0xff, 0xff], [([198, 51, 100, 7], 4)])
    rep += route([0x00, 0x00, 0x00], [([0], 5), ([11], 32)])
    F.append(igmp_frame(v3(2, rep)))
    # 4: Ask Neighbors (obsolete), 5: Neighbors (obsolete, data not parsed)
    F.append(igmp_frame(v3(3), dst=ROUTER_B))
    F.append(igmp_frame(v3(4, ip4(ROUTER_A) + b'\x01\x01\x00\x01' + ip4(ROUTER_B)),
                        src=ROUTER_B, dst=ROUTER_A))
    # 6: Ask Neighbors 2
    F.append(igmp_frame(v3(5), dst=ROUTER_B))
    # 7: Neighbors 2 with capabilities: three local interfaces, every flag,
    #    neighbor counts 2, 0 and 3 (the third cut short by the end)
    n2 = ip4('192.0.2.2') + bytes([1, 1, 0x01 | 0x02, 2]) + ip4('192.0.2.1') + ip4('192.0.2.5')
    n2 += ip4('198.51.100.1') + bytes([2, 16, 0x10 | 0x20, 0])
    n2 += ip4('203.0.113.1') + bytes([3, 32, 0x40 | 0x80, 3]) + ip4('203.0.113.2') + ip4('203.0.113.3')
    F.append(igmp_frame(v3(6, n2, caps=0x15), src=ROUTER_B, dst=ROUTER_A))
    # 8: Prune with source netmask, 9: without
    F.append(igmp_frame(v3(7, ip4('198.51.100.7') + ip4('233.252.0.1') + struct.pack('>I', 7200)
                           + ip4('255.255.255.0')), dst=ROUTER_B))
    F.append(igmp_frame(v3(7, ip4('198.51.100.8') + ip4('233.252.0.2') + struct.pack('>I', 60)),
                        dst=ROUTER_B))
    # 10: Graft with netmask, 11: without
    F.append(igmp_frame(v3(8, ip4('198.51.100.7') + ip4('233.252.0.1') + ip4('255.255.255.0')),
                        src=ROUTER_B, dst=ROUTER_A))
    F.append(igmp_frame(v3(8, ip4('198.51.100.8') + ip4('233.252.0.2')),
                        src=ROUTER_B, dst=ROUTER_A))
    # 12: Graft ACK with netmask, 13: without
    F.append(igmp_frame(v3(9, ip4('198.51.100.7') + ip4('233.252.0.1') + ip4('255.255.255.0')),
                        dst=ROUTER_B))
    F.append(igmp_frame(v3(9, ip4('198.51.100.8') + ip4('233.252.0.2')), dst=ROUTER_B))
    # 14: unknown v3 code 0x0a
    F.append(igmp_frame(v3(0x0a, b'\x00\x00\x00\x00')))
    # 15: v3 header with an other version (minor 0, major 3): v3 by default
    #     (strict_v3 off), Ask Neighbors 2 has no body
    F.append(igmp_frame(v3(5, minor=0, major=3), dst=ROUTER_B))
    # 16-21: v1 messages shorter than 8 octets, decoded as v1 by default
    F.append(igmp_frame(v1(1)))                                   # Response, no commands
    F.append(igmp_frame(v1(2, b'\x00\x00')))                      # Request, NULL
    F.append(igmp_frame(v1(1, b'\x02\x02')))                      # AFI IPv4
    F.append(igmp_frame(v1(1, b'\x04\x05')))                      # Metric 5
    F.append(igmp_frame(v1(1, b'\x06\x10')))                      # Infinity 16
    F.append(igmp_frame(v1(0x0b, b'\x05\x03\x0b')))               # unknown code, Flags0, unknown cmd
    # 22-23: long v1 messages (codes 3 and 4), v3 Ask Neighbors/Neighbors
    #        by default, v1 commands with strict_v3
    cmds = b'\x00\x00'                                   # NULL
    cmds += b'\x02\x02' + b'\x02\x07'                    # AFI IPv4, AFI unknown
    cmds += b'\x03\x01' + ip4('255.255.255.0')           # Subnetmask
    cmds += b'\x03\x00'                                  # Subnetmask, none
    cmds += b'\x04\x03' + b'\x05\x03' + b'\x06\x20'      # Metric, Flags0, Infinity
    cmds += b'\x07\x02' + ip4('198.51.100.0') + ip4('203.0.113.0')   # DA
    cmds += b'\x08\x01' + ip4('192.0.2.0')               # RDA
    cmds += b'\x09\x02' + ip4('233.252.0.1') + struct.pack('>I', 600) \
        + ip4('233.252.0.2') + struct.pack('>I', 1200)  # NMR
    cmds += b'\x0a\x01' + ip4('233.252.0.3')             # NMR cancel
    cmds += b'\x0c'                                      # unknown command
    F.append(igmp_frame(v1(3, cmds)))
    F.append(igmp_frame(v1(4, b'\x0a\x02' + ip4('233.252.0.1') + ip4('233.252.0.2'))))
    # 24: Report with unusual mask octets (only the second, only the third
    #     nonzero), so each source octet is read on its own
    rep = route([0x00, 0xff, 0x00], [([10, 3], 6)])
    rep += route([0x00, 0x00, 0xff], [([10, 4], 7)])
    F.append(igmp_frame(v3(2, rep), src=ROUTER_B))
    # 25: minor version 0xff with major version 2: v3 Ask Neighbors 2 by
    #     default; with strict_v3 v1 NULL, unknown and AFI commands
    F.append(igmp_frame(v3(5, b'\x02', minor=0xff, major=2), dst=ROUTER_B))
    return F


def malformed_frames():
    F = []
    # 1: Probe with a bad checksum
    m = v3(1, struct.pack('>I', 1), caps=0x3f)
    m = m[:2] + b'\x12\x34' + m[4:]
    F.append(igmp_frame(m, good_cksum=False))
    # 2: Report cut short in a source/metric pair
    F.append(igmp_frame(v3(2, route([0xff, 0xff, 0], [([10, 1, 2], 1)])[:-2])))
    # 3: Prune without the lifetime
    F.append(igmp_frame(v3(7, ip4('198.51.100.7') + ip4('233.252.0.1'))))
    # 4: Graft without the group, 5: Graft ACK without the group
    F.append(igmp_frame(v3(8, ip4('198.51.100.7'))))
    F.append(igmp_frame(v3(9, ip4('198.51.100.7'))))
    # 6: Probe without the generation ID
    F.append(igmp_frame(v3(1, b'\x01\x02')))
    # 7: v1 Destination Address with a count beyond the data
    #    (v1 with strict_v3; by default v3 Report on the same bytes)
    F.append(igmp_frame(v1(3, b'\x07\x05' + ip4('198.51.100.0'))))
    # 8: v1 Subnetmask cut short, NMR cut short, NMR cancel cut short
    F.append(igmp_frame(v1(3, b'\x03\x01\x01\x02')))
    F.append(igmp_frame(v1(4, b'\x09\x01' + ip4('233.252.0.1') + b'\x00')))
    F.append(igmp_frame(v1(4, b'\x0a\x03' + ip4('233.252.0.1'))))
    # 11: v1 AFI without its value (5 octets)
    F.append(igmp_frame(v1(1, b'\x02')))
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'dvmrp-coverage.pcap'), main_frames())
    write_pcap(os.path.join(out, 'dvmrp-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()
