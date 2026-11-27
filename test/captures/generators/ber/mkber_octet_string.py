#!/usr/bin/env python3
# BER constructed OCTET STRINGs in SNMP, nested and cut short
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""SNMP messages (UDP port 161) with constructed OCTET STRINGs, for
"BER: Reassemble constructed OCTET STRINGs in a per-packet composite tvb":

 1. SNMPv3 whose ScopedPDU has two top level constructed OCTET STRINGs,
    contextEngineID "AA"+"BB" and contextName "CC"+"DD". The strings of a
    frame used to share one reassembly id, so with -2 both showed the
    last one's data.
 2. SNMPv3 whose contextEngineID is a constructed OCTET STRING cut short
    after its first segment, with a consistent outer length. The segments
    used to stay in the reassembly table.
 3. A valid SNMPv3 message with contextEngineID "CC"+"DD", from the same
    addresses as frame 2. It used to show the segments of frame 2 too.
 4. SNMPv1 whose community is a constructed OCTET STRING nested 40 deep,
    each level holding the inner string and one more segment. Every level
    used to keep a copy of the whole content for the life of the capture.
 5. The same nested 40 deep, with an inner segment of 2000 octets.
 6. SNMPv1 whose community is nested 600 deep (past the BER nesting
    limit).

Usage: mkber_octet_string.py [<output directory>]

Writes ber-octet-string.pcap. Every packet is built here; nothing comes
from a real network.
"""

import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))

from capgen import eth, ipv4, udp, write_pcap  # noqa: E402


def tlv(t, v):
    n = len(v)
    if n < 0x80:
        ln = bytes([n])
    else:
        b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
        ln = bytes([0x80 | len(b)]) + b
    return bytes([t]) + ln + v


def cons_os(*segs):
    return tlv(0x24, b''.join(tlv(0x04, s) for s in segs))


USM = tlv(0x30, tlv(0x04, b'') + tlv(0x02, b'\0') + tlv(0x02, b'\0') +
          tlv(0x04, b'') + tlv(0x04, b'') + tlv(0x04, b''))
GLOB = tlv(0x30, tlv(0x02, b'\x01') + tlv(0x02, b'\x05\xdc') +
           tlv(0x04, b'\x00') + tlv(0x02, b'\x03'))
PDU = tlv(0xA0, tlv(0x02, b'\x01') + tlv(0x02, b'\0') + tlv(0x02, b'\0') + tlv(0x30, b''))


def v3(scoped):
    return tlv(0x30, tlv(0x02, b'\x03') + GLOB + tlv(0x04, USM) + scoped)


def nested(depth, payload):
    s = tlv(0x04, payload)
    for _ in range(depth):
        s = tlv(0x24, s + b'\x04\x01\x00')
    return s


def v1(community):
    return tlv(0x30, b'\x02\x01\x00' + community)


def frame(payload, i):
    src, dst = '192.0.2.1', '192.0.2.2'
    return eth(ipv4(udp(payload, 40000, 161, src=src, dst=dst), 17, src=src, dst=dst, ident=i + 1),
               0x0800)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    two = v3(tlv(0x30, cons_os(b'AA', b'BB') + cons_os(b'CC', b'DD') + PDU))
    full = v3(tlv(0x30, cons_os(b'AA', b'BB') + tlv(0x04, b'ctx') + PDU))
    cut = full[:full.index(b'\x24\x08') + 6]
    cut = cut[:1] + bytes([len(cut) - 2]) + cut[2:]       # the outer length matches
    good = v3(tlv(0x30, cons_os(b'CC', b'DD') + tlv(0x04, b'ctx') + PDU))
    payloads = [two, cut, good,
                v1(nested(40, b'A' * 20)), v1(nested(40, b'B' * 2000)), v1(nested(600, b'C'))]
    write_pcap(os.path.join(out, 'ber-octet-string.pcap'),
               [frame(p, i) for i, p in enumerate(payloads)])


if __name__ == '__main__':
    main()
