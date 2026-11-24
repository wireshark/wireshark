#!/usr/bin/env python3
# Generates test/captures/cl3_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the CableLabs Layer-3
Protocol dissector (packet-cl3.c).

CL3 runs directly over Ethernet with EtherType 0xB4E3. The first octet
holds the version (high nibble) and the header length in 32 bit words
(low nibble); version 1 adds a reserved octet and a 16 bit subprotocol
ID (0x00DC is Dual-Channel Wi-Fi, packet-cl3dcw.c). Every frame is built
from scratch with struct; no captured traffic is used.

Usage: mkcl3.py <output directory>

Writes:
  cl3-coverage.pcap            version 1 with the Dual-Channel Wi-Fi
                               subprotocol, an unknown subprotocol, an
                               empty payload and Ethernet padding
  cl3-coverage-malformed.pcap  bad header lengths, unknown versions,
                               truncated headers
"""

import os
import struct
import sys

STA = bytes.fromhex('020000000001')
AP = bytes.fromhex('020000000002')


def eth(payload, src=STA, dst=AP, pad=False):
    f = dst + src + struct.pack('>H', 0xB4E3) + payload
    if pad and len(f) < 60:
        f += b'\0' * (60 - len(f))
    return f


def cl3(subproto, payload, version=1, hwords=1, rsvd=0):
    return bytes([(version << 4) | hwords, rsvd]) + struct.pack('>H', subproto) + payload


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)) + fr)


def main_capture(out):
    frames = [
        # 1: Dual-Channel Wi-Fi Station Join with two data channel MACs
        eth(cl3(0x00DC, b'\x01\x02' + bytes.fromhex('0200000000a1') + bytes.fromhex('0200000000a2'))),
        # 2: Dual-Channel Wi-Fi AP Accept Station with one SSID
        eth(cl3(0x00DC, b'\x21\x01\x07dcw-5gh'), AP, STA),
        # 3: Dual-Channel Wi-Fi AP Quit (no body), padded to 60 octets; the
        #    padding is part of the CL3 payload
        eth(cl3(0x00DC, b'\x99'), AP, STA, pad=True),
        # 4: an unknown subprotocol: the payload is shown as bytes
        eth(cl3(0x1234, b'unknown subprotocol payload')),
        # 5: subprotocol 0xFFFF and a reserved octet that is not zero, no payload
        eth(cl3(0xFFFF, b'', rsvd=0xA5)),
    ]
    write_pcap(os.path.join(out, 'cl3-coverage.pcap'), frames)


def malformed_capture(out):
    frames = [
        # 1: version 1 with a header length of 2 words (Bad Header Length)
        eth(cl3(0x00DC, b'\0\0\0\0\x41', hwords=2)),
        # 2: version 1 with a header length of 0 (Bad Header Length twice)
        eth(cl3(0x00DC, b'\x41', hwords=0)),
        # 3: header length of 15 words, past the end of the frame
        eth(cl3(0x1234, b'xyz', hwords=15)),
        # 4: version 2 (Unknown protocol version)
        eth(cl3(0x00DC, b'\x41', version=2)),
        # 5: version 0 with header length 0
        eth(cl3(0, b'', version=0, hwords=0)),
        # 6: one octet only; 7: three octets (subprotocol cut short)
        eth(b'\x11'),
        eth(b'\x11\x00\x00'),
    ]
    write_pcap(os.path.join(out, 'cl3-coverage-malformed.pcap'), frames)


if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    main_capture(out)
    malformed_capture(out)
