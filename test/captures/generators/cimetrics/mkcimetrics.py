#!/usr/bin/env python3
# Generates test/captures/cimetrics_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the Cimetrics MS/TP
dissector (packet-cimetrics.c, filter name "cimetrics").

The Cimetrics U+4 device sends BACnet MS/TP frames inside IEEE 802.3
frames with LLC/SNAP, OUI 00:10:90 (Cimetrics) and PID 0x0001. The
payload is a 16 bit delta time (little endian), an 8 bit value and the
MS/TP frame without the 55 FF preamble (frame type, destination,
source, length, header CRC, data, data CRC), which packet-mstp.c
dissects. Every packet is built from scratch with struct; no captured
traffic is used.

Usage: mkcimetrics.py <output directory>
Writes:
  cimetrics-coverage.pcap            every MS/TP frame type with and
                                     without data, BACnet NPDUs, a
                                     proprietary frame with vendor ID
  cimetrics-coverage-malformed.pcap  frames cut short, a bad length
"""
import os
import struct
import sys

MAC_A = bytes.fromhex('020000000001')
MAC_B = bytes.fromhex('020000000002')


def crc8_header(data):
    """MS/TP header CRC (BACnet standard, Annex G)."""
    crc = 0xff
    for b in data:
        c = crc ^ b
        c = c ^ (c << 1) ^ (c << 2) ^ (c << 3) ^ (c << 4) ^ (c << 5) ^ (c << 6) ^ (c << 7)
        crc = (c & 0xfe) ^ ((c >> 8) & 1)
    return ~crc & 0xff


def crc16_data(data):
    """MS/TP data CRC: CRC-16 CCITT, reflected, init and xorout 0xFFFF,
    sent low octet first."""
    crc = 0xffff
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0x8408 if crc & 1 else crc >> 1
    return struct.pack('<H', ~crc & 0xffff)


def mstp(ftype, dst, src, data=b'', length=None):
    if length is None:
        length = len(data)
    hdr = struct.pack('>BBBH', ftype, dst, src, length)
    out = hdr + bytes([crc8_header(hdr)])
    if data:
        out += data + crc16_data(data)
    return out


def cimetrics(frame, timer=0, value=0):
    return struct.pack('<HB', timer, value) + frame


def llc_frame(payload, pid=0x0001):
    llc = bytes.fromhex('aaaa03') + bytes.fromhex('001090') + struct.pack('>H', pid) + payload
    return MAC_B + MAC_A + struct.pack('>H', len(llc)) + llc


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, p in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
            f.write(p)


# BACnet NPDU (version 1, no addresses) with an unconfirmed Who-Is
NPDU_WHO_IS = bytes.fromhex('0100' '1008')
# BACnet NPDU (expecting reply) with a confirmed ReadProperty of
# device,1 present-value (invoke ID 1)
NPDU_READ_PROPERTY = bytes.fromhex('0104' '0005010c' '0c02000001' '1955')
# BACnet NPDU with an I-Am of device,1
NPDU_I_AM = bytes.fromhex('0100' '1000' 'c402000001' '220400' '9100' '2105')


def main_frames():
    F = []
    # 1: Token 5 -> 10, delta time 0
    F.append(llc_frame(cimetrics(mstp(0x00, 10, 5), timer=0, value=0)))
    # 2: Poll For Master 10 -> 11
    F.append(llc_frame(cimetrics(mstp(0x01, 11, 10), timer=12, value=1)))
    # 3: Reply To Poll For Master 11 -> 10
    F.append(llc_frame(cimetrics(mstp(0x02, 10, 11), timer=3, value=2)))
    # 4: Test_Request with data, 5: Test_Response with data
    F.append(llc_frame(cimetrics(mstp(0x03, 11, 10, b'test-data'), timer=250, value=3)))
    F.append(llc_frame(cimetrics(mstp(0x04, 10, 11, b'test-data'), timer=2, value=4)))
    # 6: BACnet Data Expecting Reply (ReadProperty)
    F.append(llc_frame(cimetrics(mstp(0x05, 11, 10, NPDU_READ_PROPERTY), timer=1000, value=5)))
    # 7: Reply Postponed
    F.append(llc_frame(cimetrics(mstp(0x07, 10, 11), timer=5, value=6)))
    # 8: BACnet Data Not Expecting Reply, broadcast Who-Is
    F.append(llc_frame(cimetrics(mstp(0x06, 255, 10, NPDU_WHO_IS), timer=65535, value=255)))
    # 9: BACnet Data Not Expecting Reply, I-Am
    F.append(llc_frame(cimetrics(mstp(0x06, 255, 11, NPDU_I_AM), timer=40, value=7)))
    # 10: an unassigned frame type (0x30)
    F.append(llc_frame(cimetrics(mstp(0x30, 10, 11), timer=1, value=8)))
    # 11: a proprietary frame (type 0x80) with vendor ID 0x0123 and data
    F.append(llc_frame(cimetrics(mstp(0x80, 10, 127, struct.pack('>H', 0x0123) + b'vendor'),
                                 timer=7, value=9)))
    return F


def malformed_frames():
    F = []
    # 1: only the delta time
    F.append(llc_frame(cimetrics(b'')[:2]))
    # 2: MS/TP header cut short
    F.append(llc_frame(cimetrics(mstp(0x00, 10, 5)[:3])))
    # 3: data length past the end of the frame
    F.append(llc_frame(cimetrics(mstp(0x03, 11, 10, b'abc', length=40)[:9])))
    # 4: a bad header CRC
    F.append(llc_frame(cimetrics(mstp(0x00, 10, 5)[:5] + b'\x00')))
    # 5: a bad data CRC
    F.append(llc_frame(cimetrics(mstp(0x03, 11, 10, b'test')[:-2] + b'\x00\x00')))
    # 6: a proprietary frame with a length too short for the vendor ID
    F.append(llc_frame(cimetrics(mstp(0x81, 10, 11, b'\x01'))))
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'cimetrics-coverage.pcap'), main_frames())
    write_pcap(os.path.join(out, 'cimetrics-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()
