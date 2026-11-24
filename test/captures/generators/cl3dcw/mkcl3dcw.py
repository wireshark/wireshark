#!/usr/bin/env python3
# Generates test/captures/cl3dcw_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the CableLabs Dual-Channel
Wi-Fi dissector (packet-cl3dcw.c).

Dual-Channel Wi-Fi control messages are CL3 subprotocol 0x00DC: Ethernet
with EtherType 0xB4E3, a 4 octet CL3 version 1 header, then a one octet
message type and a type specific body (lists of data channel MAC
addresses, SSIDs, or MAC address and SSID bonds). Every frame is built
from scratch with struct; no captured traffic is used.

Usage: mkcl3dcw.py <output directory>

Writes:
  cl3dcw-coverage.pcap            every message type, lists of one and
                                  more entries, SSIDs of length 0 to 32
  cl3dcw-coverage-malformed.pcap  empty lists, SSIDs longer than 32
                                  octets, an unknown type, truncated
                                  messages
"""

import os
import struct
import sys

STA = bytes.fromhex('020000000001')
AP = bytes.fromhex('020000000002')
DC = [bytes.fromhex('0200000000a%d' % i) for i in range(1, 6)]


def eth(payload, src=STA, dst=AP):
    return dst + src + struct.pack('>H', 0xB4E3) + payload


def dcw(mtype, body=b'', to_ap=True):
    """A Dual-Channel Wi-Fi message in a CL3 version 1 frame."""
    p = b'\x11\x00' + struct.pack('>H', 0x00DC) + bytes([mtype]) + body
    return eth(p) if to_ap else eth(p, AP, STA)


def macs(*m):
    return bytes([len(m)]) + b''.join(m)


def ssids(*s):
    return bytes([len(s)]) + b''.join(bytes([len(x)]) + x for x in s)


def bonds(*b):
    return bytes([len(b)]) + b''.join(m + bytes([len(s)]) + s for m, s in b)


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)) + fr)


SSID32 = b'dual-channel-wifi-data-ssid-0032'
assert len(SSID32) == 32


def main_capture(out):
    frames = [
        # 1-2: Station Join with one and with three data channel MACs
        dcw(0x01, macs(DC[0])),
        dcw(0x01, macs(DC[0], DC[1], DC[2])),
        # 3-4: AP Accept Station with one SSID, and with SSIDs of 0, 32
        #      octets and one with a non-ASCII octet
        dcw(0x21, ssids(b'dcw-data'), False),
        dcw(0x21, ssids(b'', SSID32, b'caf\xe9'), False),
        # 5-6: Station Ack with one bond, and with three (SSIDs of 0 and
        #      32 octets among them)
        dcw(0x11, bonds((DC[0], b'dcw-data'))),
        dcw(0x11, bonds((DC[1], b''), (DC[2], SSID32), (DC[3], b'x'))),
        # 7: Station Nack with two MACs
        dcw(0x12, macs(DC[3], DC[4])),
        # 8: AP Reject Station with one MAC
        dcw(0x22, macs(DC[4]), False),
        # 9: Station Unjoin with two MACs
        dcw(0x02, macs(DC[0], DC[1])),
        # 10: AP Ack Disconnect, 11: AP Quit (no body)
        dcw(0x41, b'', False),
        dcw(0x99, b'', False),
        # 12: Station Join followed by octets past the message (in the
        #     CL3 payload, not part of the DCW message)
        dcw(0x01, macs(DC[2]) + b'\xde\xad\xbe\xef'),
    ]
    write_pcap(os.path.join(out, 'cl3dcw-coverage.pcap'), frames)


def malformed_capture(out):
    long_ssid = b'S' * 33
    frames = [
        # 1-6: every list with a count of 0 (No data-channels provided)
        dcw(0x01, macs()),
        dcw(0x02, macs()),
        dcw(0x11, bonds()),
        dcw(0x12, macs()),
        dcw(0x21, ssids(), False),
        dcw(0x22, macs(), False),
        # 7-8: an SSID of 33 octets in a bond and in an SSID list
        dcw(0x11, bonds((DC[0], long_ssid))),
        dcw(0x21, ssids(long_ssid), False),
        # 9-10: unknown message types
        dcw(0x00, b'abc'),
        dcw(0xFF),
        # 11: Station Join counting 5 MACs with only 2 present
        dcw(0x01, b'\x05' + DC[0] + DC[1]),
        # 12: Station Ack bond cut in the MAC, 13: SSID length past the end
        dcw(0x11, b'\x01' + DC[0][:3]),
        dcw(0x11, b'\x01' + DC[0] + b'\x20abc'),
        # 14: AP Accept Station with an SSID length past the end
        dcw(0x21, b'\x02\x03abc\x40', False),
        # 15: a message type only, without the count octet
        dcw(0x12),
        # 16: an empty DCW message (CL3 header only)
        eth(b'\x11\x00\x00\xdc'),
    ]
    write_pcap(os.path.join(out, 'cl3dcw-coverage-malformed.pcap'), frames)


if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    main_capture(out)
    malformed_capture(out)
