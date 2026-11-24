#!/usr/bin/env python3
# Generates test/captures/openthread_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the OpenThread coverage captures: mkopenthread.py <outdir>.
OpenThread is only reachable through Decode As of a UDP port, so the main
capture carries the frames as Exported PDU ("openthread"). Each PDU is the
channel octet, an IEEE 802.15.4 frame without FCS and two phoney CRC octets."""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import struct
from wslib import pcapng, exported_pdu, gz

def ot(channel, wpan):
    return exported_pdu('openthread', bytes([channel]) + wpan + b'\x00\x00')

def ip6(payload, nh=58, src=1, dst=2):
    return (struct.pack('!IHBB', 0x60000000, len(payload), nh, 64)
            + bytes([0xfe, 0x80] + [0] * 13 + [src]) + bytes([0xfe, 0x80] + [0] * 13 + [dst]) + payload)

def data(seq, payload, panid=0xface, dst=0x0001, src=0x0002):
    return struct.pack('<HBHHH', 0x8841, seq, panid, dst, src) + payload

def frames():
    f = []
    echo = bytes([128, 0, 0, 0, 0, 1, 0, 1]) + b'ping'
    f.append(ot(11, data(1, b'\x41' + ip6(echo))))             # uncompressed IPv6 over 6LoWPAN
    f.append(ot(15, data(2, b'\x41' + ip6(bytes([129, 0, 0, 0, 0, 1, 0, 1]) + b'ping'), dst=2, src=1)))
    f.append(ot(20, struct.pack('<HBHHBBBB', 0x8000, 3, 0xface, 0x0001, 0xff, 0xcf, 0, 0)
                    + bytes([3, 0x91]) + b'OpenThreadNet\0\0\0' + bytes(range(8))))  # Thread beacon
    f.append(ot(26, struct.pack('<HB', 0x0002, 4)))             # acknowledgement
    f.append(ot(12, struct.pack('<HBHH8sB', 0xc863, 5, 0xface, 0x0001, bytes(range(8)), 4)))  # data request
    f.append(ot(13, data(6, b'\x7a\x33\x3a' + b'\x00' * 12)))   # 6LoWPAN IPHC
    f.append(ot(14, data(7, b'')))                                # empty data payload
    f.append(ot(25, struct.pack('<HBHHH', 0x8841, 8, 0xface, 0xffff, 0x0002) + b'\xc0\x00\x00'))
    return f

def main(out):
    fr = frames()
    pcapng(os.path.join(out, 'openthread-coverage.pcapng'), [(1, d) if i == 1 else (i, d) for i, d in fr])
    gz(os.path.join(out, 'openthread-coverage.pcapng'))
    # malformed: only the channel octet, or less than 3 octets
    bad = [exported_pdu('openthread', b'\x0b'), exported_pdu('openthread', b'\x0b\x00'),
           exported_pdu('openthread', b'\x0b\x41\x88'), exported_pdu('openthread', bytes([11]) + data(9, b'\x41') + b'\x00')]
    pcapng(os.path.join(out, 'openthread-coverage-malformed.pcapng'), bad)

if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')
