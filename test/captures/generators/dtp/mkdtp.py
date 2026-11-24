#!/usr/bin/env python3
# Generates test/captures/dtp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the DTP dissector
(packet-dtp.c, Cisco Dynamic Trunking Protocol).

DTP runs over IEEE 802.3 + LLC/SNAP with the Cisco OUI and PID 0x2004,
sent to 01:00:0c:cc:cc:cc. The body is a version octet and TLVs with a
16 bit type and a 16 bit length that includes the 4 octet header. Every
packet is built from scratch with struct; no captured traffic is used.

Usage: mkdtp.py <output directory>

Writes:
  dtp-coverage.pcap            every known TLV, every value of the
                               trunk status and trunk type fields,
                               unknown TLVs (the reproducer of the fix)
  dtp-coverage-malformed.pcap  short or wrong TLV lengths, truncation
"""

import os
import struct
import sys

DST = bytes.fromhex('01000ccccccc')
SRC = bytes.fromhex('020000000001')


def pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)


def dtp_frame(body, version=1, src=SRC):
    payload = b'\xaa\xaa\x03\x00\x00\x0c' + struct.pack('!H', 0x2004)
    payload += bytes([version]) + body
    return DST + src + struct.pack('!H', len(payload)) + payload


def tlv(t, v, length=None):
    return struct.pack('!HH', t, len(v) + 4 if length is None else length) + v


def domain(name):
    return tlv(1, name + b'\0')


def status(v):
    return tlv(2, bytes([v]))


def ttype(v):
    return tlv(3, bytes([v]))


def sender(n):
    return tlv(4, bytes([0x02, 0, 0, 0, 0, n]))


def main_frames():
    f = []
    # 1-4: a typical negotiation: Domain, Trunk Status, Trunk Type, Sender ID
    f.append(dtp_frame(domain(b'LAB') + status(0x03) + ttype(0xa5) + sender(1)))
    f.append(dtp_frame(domain(b'LAB') + status(0x04) + ttype(0x40) + sender(2),
                       src=bytes.fromhex('020000000002')))
    f.append(dtp_frame(domain(b'LAB') + status(0x81) + ttype(0xa5) + sender(1)))
    f.append(dtp_frame(domain(b'LAB') + status(0x83) + ttype(0x42) + sender(2),
                       src=bytes.fromhex('020000000002')))
    # 5: every administrative status, unknown values too
    f.append(dtp_frame(status(0x01) + status(0x02) + status(0x00) + status(0x87)))
    # 6: every operating/administrative trunk type, unknown values too
    f.append(dtp_frame(ttype(0x20) + ttype(0x21) + ttype(0x45) + ttype(0x07) + ttype(0x60)))
    # 7: empty domain name, version 2
    f.append(dtp_frame(domain(b'') + sender(3), version=2))
    # 8: domain name of the maximum 32 characters
    f.append(dtp_frame(domain(b'D' * 32) + sender(4)))
    # 9-11: the reproducer of "DTP: Show unknown TLV data as bytes and
    # dispatch on the 16-bit type" (dtp_unknown_tlv_ether.py)
    f.append(dtp_frame(tlv(5, b'\x12\x34') + tlv(2, b'\x81') + tlv(4, bytes.fromhex('020000000001'))))
    f.append(dtp_frame(tlv(6, b'A' * 12)))
    f.append(dtp_frame(tlv(0x0104, bytes.fromhex('020000000009'))))
    # 12: types whose low octet is a known type, and a 6 octet unknown TLV
    f.append(dtp_frame(tlv(0x0101, b'XY\0') + tlv(0x0202, b'\x81') + tlv(0x0303, b'\xa5')
                       + tlv(0xff00, bytes(6)) + status(0x81)))
    return f


def malformed_frames():
    f = []
    f.append(dtp_frame(status(0x81) + b'\x00\x02'))          # 2 octets left
    f.append(dtp_frame(tlv(1, b'', 4) + status(0x81)))       # length 4
    f.append(dtp_frame(tlv(2, b'', 2)))                       # length 2
    f.append(dtp_frame(domain(b'E' * 33)))                    # domain too long
    f.append(dtp_frame(tlv(2, b'\x81\x00')))                  # status length 2
    f.append(dtp_frame(tlv(3, b'\xa5\x00')))                  # type length 2
    f.append(dtp_frame(tlv(4, bytes(5))))                     # sender length 5
    f.append(dtp_frame(tlv(4, bytes(6), 40)))                 # past the end
    f.append(dtp_frame(tlv(7, b'abc', 30)))                   # unknown, past the end
    f.append(dtp_frame(b''))                                  # version only
    f.append(DST + SRC + struct.pack('!H', 8) + b'\xaa\xaa\x03\x00\x00\x0c\x20\x04')
    return f


if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcap(os.path.join(out, 'dtp-coverage.pcap'), main_frames())
    pcap(os.path.join(out, 'dtp-coverage-malformed.pcap'), malformed_frames())
