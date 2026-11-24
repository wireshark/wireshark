#!/usr/bin/env python3
# Generates test/captures/slowprotocols_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures for the 802.3 Slow Protocols dissector
(packet-slowprotocols.c): ethertype 0x8809, destination 01:80:c2:00:00:02.

Usage: mkslowprotocols.py <output directory>

Writes:
  slowprotocols-coverage.pcap            every registered subtype (LACP,
                                         Marker, OAM, OSSP) and unknown
                                         subtypes, with and without
                                         padding after the PDU
  slowprotocols-coverage-malformed.pcap  frames cut short
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import struct
from pcaplib import eth, MAC_A, pcap

SLOW_DST = bytes.fromhex('0180c2000002')


def slow(payload, pad=0):
    return eth(payload + b'\0' * pad, 0x8809, MAC_A, SLOW_DST)


def lacp_info(tlv, system=b'\x02\0\0\0\0\x01', key=1, prio=0x8000, port=1,
              state=0x3d):
    return struct.pack('!BB', tlv, 20) + struct.pack('!H6sHHHB', prio, system, key,
                                                  0x8000, port, state) + b'\0\0\0'


def lacp(state=0x3d, pstate=0x3d):
    p = struct.pack('!BB', 1, 1)                       # subtype, version
    p += lacp_info(1, state=state)                     # actor
    p += lacp_info(2, system=b'\x02\0\0\0\0\x02', key=2, port=2, state=pstate)
    p += struct.pack('!BBH', 3, 16, 1500) + b'\0' * 12  # collector
    p += struct.pack('!BB', 0, 0) + b'\0' * 50          # terminator, reserved
    return p


def marker(code):
    p = struct.pack('!BB', 2, 1)
    p += struct.pack('!BBHI6sH', code, 16, 1, 0x1000, b'\x02\0\0\0\0\x01', 0)
    p += struct.pack('!BB', 0, 0) + b'\0' * 90
    return p


def oam(flags, code, body):
    return struct.pack('!BHB', 3, flags, code) + body


def main(out):
    fr = []
    fr.append(slow(lacp(), 0))
    fr.append(slow(lacp(0x01, 0xff), 0))
    fr.append(slow(marker(1)))
    fr.append(slow(marker(2)))
    # OAM information PDU with a local information TLV, a variable request
    info = struct.pack('!BBBHBBH3s4s', 1, 16, 1, 3, 0x03, 0x1f, 1500, b'\x00\x80\xc2', b'\0\0\0\1') + b'\0\0'
    fr.append(slow(oam(0x0052, 0, info)))
    fr.append(slow(oam(0x0000, 1, b'\x00\x01\x00\x00')))                 # event notification, end TLV
    fr.append(slow(oam(0x0000, 2, b'\x07\x00\x01\x00')))                 # variable request
    fr.append(slow(oam(0x0000, 3, b'\x07\x00\x01\x01\x05\x00'), 20))    # variable response, padded
    fr.append(slow(oam(0x0000, 4, b'\x01')))                              # loopback control
    fr.append(slow(oam(0x0000, 5, b'\x00\x80\xc2\x01\x02')))            # organization specific
    # Organization specific slow protocol (subtype 0x0a): no dissector
    fr.append(slow(struct.pack('!B', 0x0a) + bytes.fromhex('00 80 c2 01') + b'\x11\x22\x33'))
    # unknown subtypes: 0, 4, 9, 0x0b and 0xff
    for st in (0, 4, 9, 0x0b, 0xff):
        fr.append(slow(struct.pack('!B', st) + bytes(range(st & 0xf, (st & 0xf) + 10))))
    # a frame with Ethernet padding past the PDU: the PDU is shortened to
    # its dissected length (set_actual_length)
    fr.append(slow(marker(1), 0) + b'\0' * 8)
    pcap(os.path.join(out, 'slowprotocols-coverage.pcap'), fr)
    print('%d frames' % len(fr))
    m = [slow(b'\x01'), slow(b'\x01\x01\x01\x14'), slow(b'\x02\x01\x01'),
         slow(b'\x03\x00'), slow(b'')]
    # frame cut short: only the subtype byte on the wire
    pcap(os.path.join(out, 'slowprotocols-coverage-malformed.pcap'), m)


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')
