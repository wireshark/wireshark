#!/usr/bin/env python3
# Generates test/captures/cisco_oui_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate a synthetic capture for the Cisco OUI registration
(packet-cisco-oui.c).

packet-cisco-oui.c has no dissector: it registers the LLC SNAP OUI
00:00:0c, the "llc.cisco_pid" field and dissector table with the PID
names. This capture has an IEEE 802.3 frame with LLC/SNAP for every
named Cisco PID (with a valid payload for the protocols that have a
dissector), and for a PID that has no name. Every packet is built from
scratch with struct; no captured traffic is used.

Usage: mkcisco-oui.py <output directory>

Writes:
  cisco-oui-coverage.pcap  one frame per Cisco PID
"""

import os
import struct
import sys

SRC_MAC = bytes.fromhex('020000000001')
DST_MAC = bytes.fromhex('01000ccccccc')
PVST_MAC = bytes.fromhex('01000ccccccd')
CGMP_MAC = bytes.fromhex('0100000ccddd')


def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    while s >> 16:
        s = (s >> 16) + (s & 0xffff)
    return ~s & 0xffff


def frame(pid, payload, dst=DST_MAC):
    llc = bytes([0xaa, 0xaa, 0x03, 0, 0, 0x0c]) + struct.pack('>H', pid) + payload
    return dst + SRC_MAC + struct.pack('>H', len(llc)) + llc


BRIDGE = struct.pack('>H', 0x8001) + bytes.fromhex('020000000001')


def stp_config():
    """IEEE 802.1D configuration BPDU (35 octets)."""
    return (struct.pack('>HBBB', 0, 0, 0, 0) + BRIDGE + struct.pack('>I', 0)
            + BRIDGE + struct.pack('>HHHHH', 0x8001, 0, 20 * 256, 2 * 256, 15 * 256))


def pvst():
    # A configuration BPDU, padding to offset 36 and the Originating VLAN TLV
    return stp_config() + b'\x00' + struct.pack('>HHH', 0, 2, 10)


def pagp():
    p = (bytes([1, 0x05]) + bytes.fromhex('020000000001') + bytes([1, 128])
         + struct.pack('>III', 10101, 1, 5001)
         + bytes.fromhex('020000000002') + bytes([1, 128])
         + struct.pack('>III', 10102, 1, 5002)
         + struct.pack('>H', 1))
    tlvs = [struct.pack('>HH', 1, 4 + 8) + b'switch-1',
            struct.pack('>HH', 2, 4 + 7) + b'Gi1/0/1']
    return p + struct.pack('>H', len(tlvs)) + b''.join(tlvs)


def udld():
    tlvs = (struct.pack('>HH', 1, 4 + 11) + b'FOC1234X5YZ'
            + struct.pack('>HH', 2, 4 + 7) + b'Gi1/0/1'
            + struct.pack('>HH', 4, 5) + b'\x07'
            + struct.pack('>HH', 5, 5) + b'\x05')
    return bytes([0x21, 0x00]) + struct.pack('>H', 0) + tlvs


def mcp():
    return (struct.pack('>BBI', 1, 4, 1) + struct.pack('>BBI', 2, 4, 101)
            + struct.pack('>BBIII', 3, 12, 1, 2, 0x0a000001)
            + struct.pack('>BBI', 4, 4, 0x1a000001)
            + struct.pack('>BBI', 5, 4, 1700000000)
            + struct.pack('>BBI', 6, 4, 1)
            + struct.pack('>BB', 7, 20) + bytes(range(20))
            + struct.pack('>BB', 8, 0))


def cdp():
    body = struct.pack('>HH', 1, 4 + 8) + b'switch-1'
    pdu = struct.pack('>BBH', 2, 180, 0) + body
    return pdu[:2] + struct.pack('>H', csum(pdu)) + pdu[4:]


def cgmp():
    return (bytes([0x10, 0, 0, 1]) + bytes.fromhex('01005e010101')
            + bytes.fromhex('020000000011'))


def vtp():
    domain = b'vtp-domain'
    return (bytes([1, 1, 0, len(domain)]) + domain.ljust(32, b'\0')
            + struct.pack('>I', 3) + bytes([192, 0, 2, 1])
            + b'260101120000' + bytes(16))


def dtp():
    return (b'\x01' + struct.pack('>HH', 1, 4 + 11) + b'vtp-domain\0'
            + struct.pack('>HH', 2, 5) + b'\x03'
            + struct.pack('>HH', 3, 5) + b'\xa5'
            + struct.pack('>HH', 4, 10) + bytes.fromhex('020000000001'))


def main_frames():
    return [
        frame(0x0102, b'drip-payload'),            # 1: DRIP (no dissector)
        frame(0x0104, pagp()),                     # 2: PAgP
        frame(0x0105, b'mls-hello'),               # 3: MLS Hello (no dissector)
        frame(0x0108, stp_config()),               # 4: RLQ request (STP)
        frame(0x0109, stp_config()),               # 5: RLQ response (STP)
        frame(0x010b, pvst(), PVST_MAC),           # 6: PVST+
        frame(0x010c, stp_config()),               # 7: VLAN Bridge (STP)
        frame(0x0111, udld()),                     # 8: UDLD
        frame(0x0139, mcp()),                      # 9: MCP
        frame(0x2000, cdp()),                      # 10: CDP
        frame(0x2001, cgmp(), CGMP_MAC),           # 11: CGMP
        frame(0x2003, vtp()),                      # 12: VTP
        frame(0x2004, dtp()),                      # 13: DTP
        frame(0x200a, b'uplink-fast'),             # 14: STP Uplink Fast (no dissector)
        frame(0x7777, b'unknown-pid'),             # 15: a PID with no name
    ]


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, p in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
            f.write(p)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'cisco-oui-coverage.pcap'), main_frames())


if __name__ == '__main__':
    main()
