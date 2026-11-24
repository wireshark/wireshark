#!/usr/bin/env python3
# Generates test/captures/j1939_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the J1939 dissector
(packet-j1939.c, SAE J1939 on CAN with 29 bit identifiers).

J1939 is reached only through the "can.subdissector" Decode As table
(-d can.subdissector,j1939); it needs the struct can_info that the CAN
dissectors pass. Every packet is built from scratch with struct; no
captured traffic is used.

Usage: mkj1939.py <output directory>

Writes pcapng files with two interfaces:
  0  LINKTYPE_CAN_SOCKETCAN (227)       J1939 frames
  1  LINKTYPE_WIRESHARK_UPPER_PDU (252) an Exported PDU naming "j1939"
                                        (no CAN information: rejected)

  j1939-coverage.pcapng            frames with every kind of source and
                                    destination address, PDU1 and PDU2
                                    formats, priorities, data pages, many
                                    named PGNs, RTR and CAN FD frames, a
                                    zero length frame, standard
                                    identifiers (not J1939) and an Exported
                                    PDU naming "j1939"
  j1939-coverage-malformed.pcapng  (no frame is malformed for this
                                    dissector: it only displays the bytes;
                                    the file holds the frames that reach
                                    the error paths of the CAN layer)
"""

import os
import struct
import sys

T0 = 1700000000
CAN_EFF_FLAG = 0x80000000
CAN_RTR_FLAG = 0x40000000
CAN_ERR_FLAG = 0x20000000


def pad4(b):
    return b + b'\0' * ((4 - len(b) % 4) % 4)


def shb():
    body = struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1)
    tot = 12 + len(body)
    return struct.pack('<II', 0x0A0D0D0A, tot) + body + struct.pack('<I', tot)


def idb(linktype):
    body = struct.pack('<HHI', linktype, 0, 0)
    tot = 12 + len(body)
    return struct.pack('<II', 1, tot) + body + struct.pack('<I', tot)


def epb(ifid, ts, data):
    t = int(ts * 1000000)
    body = (struct.pack('<IIIII', ifid, t >> 32, t & 0xffffffff, len(data), len(data))
            + pad4(data))
    tot = 12 + len(body)
    return struct.pack('<II', 6, tot) + body + struct.pack('<I', tot)


def write(path, frames):
    with open(path, 'wb') as f:
        f.write(shb() + idb(227) + idb(252))
        for i, (ifid, data) in enumerate(frames):
            f.write(epb(ifid, T0 + i * 0.001, data))


def can(can_id, data, fd=False):
    """SocketCAN record (big endian ID). The data length is the DLC;
    classic frames are padded to 8 octets."""
    if fd:
        return (0, struct.pack('>IBBBB', can_id, len(data), 0x04, 0, 0) + data)
    return (0, struct.pack('>IBBBB', can_id, len(data), 0, 0, 0) + data.ljust(8, b'\xff'))


def j(pri, pf, ps, sa, dp=0, edp=0):
    """29 bit identifier: priority, EDP, DP, PDU format, PDU specific, source."""
    return CAN_EFF_FLAG | (pri << 26) | (edp << 25) | (dp << 24) | (pf << 16) | (ps << 8) | sa


def pgn_id(pri, pgn, sa, ps=0xff):
    """Identifier for a PGN (for PDU1 formats the destination goes into PS)."""
    pf = (pgn >> 8) & 0xff
    if pf < 240:
        return j(pri, pf, ps, sa, dp=(pgn >> 16) & 1, edp=(pgn >> 17) & 1)
    return j(pri, pf, pgn & 0xff, sa, dp=(pgn >> 16) & 1, edp=(pgn >> 17) & 1)


PGNS = (59392, 59904, 60160, 60416, 60928, 65240, 65341, 126208, 126464, 126992, 126993,
        126996, 126998, 127233, 127237, 127245, 127250, 127251, 127252, 127257, 127258,
        127488, 127489, 127493, 127497, 127501, 127503, 127505, 127506, 127507, 127508,
        127509, 127510, 127511, 127512, 127513, 127514, 127744, 127750, 128000, 128259,
        128267, 128275, 128520, 128776, 128777, 128778, 129025, 129026, 129027, 129028,
        129029, 129033, 129038, 129039, 129040, 129041, 129044, 129045, 129283, 129284,
        129285, 129291, 129301, 129302, 129538, 129539, 129540, 129541, 129542, 129545,
        129546, 129547, 129549, 129550, 129792, 129793, 129794, 129795, 129796, 129797,
        129798, 129799, 129800, 129801, 129802, 129803, 129804, 129805, 129806, 129807,
        129808, 129809, 129810, 130052, 130053, 130054, 130060, 130064, 130065, 130066,
        130067, 130068, 130069, 130070, 130071, 130072, 130073, 130074, 130306, 130310,
        130311, 130312, 130313, 130314, 130315, 130316, 130320, 130321, 130322, 130323,
        130324, 130576, 130577, 130578, 130823, 130824, 130840, 130847)


def build_main():
    fr = []
    data = bytes([1, 2, 3, 4, 5, 6, 7, 8])
    # Not J1939: standard identifier
    fr.append(can(0x123, data[:4]))
    # Source addresses: named (0-89), reserved, arbitrary (128-247), named (248-255)
    for sa in (0, 3, 11, 38, 89, 90, 127, 128, 200, 247, 248, 249, 251, 252, 253, 254, 255):
        fr.append(can(pgn_id(6, 61444, sa), data))              # Electronic Engine Controller 1
    # Destination specific (PDU1) messages from and to various addresses
    for sa, da in ((0, 255), (3, 11), (128, 0), (11, 248), (250, 254)):
        fr.append(can(pgn_id(3, 59904, sa, da), bytes([0x00, 0xee, 0x00])))
    # Priorities 0 to 7
    for pri in range(8):
        fr.append(can(pgn_id(pri, 65262, 0x00), data))
    # Data page 0 and 1, EDP 0 and 1
    fr.append(can(j(6, 240, 4, 0x10, dp=0), data))
    fr.append(can(j(6, 240, 4, 0x10, dp=1), data))
    fr.append(can(j(6, 240, 4, 0x10, edp=1), data))
    fr.append(can(j(6, 234, 0x20, 0x10, dp=1, edp=1), data))
    # Named PGNs from the table
    for pgn in PGNS:
        fr.append(can(pgn_id(6, pgn, 0x20), data))
    # PGNs without a name
    for pgn in (0, 61444, 65535, 0x3ff00, 0x3ffff, 60672):
        fr.append(can(pgn_id(6, pgn, 0x21), data))
    # Remote transmission request, no payload; zero length data; short data
    fr.append(can(CAN_RTR_FLAG | pgn_id(6, 59904, 0x22, 0x00), b''))
    fr.append(can(pgn_id(6, 65262, 0x23), b''))
    fr.append(can(pgn_id(6, 65262, 0x23), b'\x01'))
    # CAN FD with 64 bytes
    fr.append(can(pgn_id(6, 130820, 0x24), bytes(range(64)), fd=True))
    fr.append(can(pgn_id(6, 65262, 0x24), bytes(range(12)), fd=True))
    # An Exported PDU naming "j1939": no CAN information
    n = b'j1939\0\0\0'
    fr.append((1, struct.pack('>HH', 12, len(n)) + n + struct.pack('>HH', 0, 0) + bytes([1, 2, 3, 4])))
    return fr


def build_malformed():
    fr = []
    # An error frame is not for J1939; neither is a standard identifier
    fr.append(can(CAN_ERR_FLAG | 0x00000004, bytes([0, 0, 0, 0x80, 0, 0, 0, 0])))
    fr.append(can(0x7ff, data=bytes([1, 2, 3, 4, 5, 6, 7, 8])))
    # A frame with a data length code of 0 and a truncated record
    fr.append((0, struct.pack('>IBBBB', pgn_id(6, 65262, 0x23), 8, 0, 0, 0) + bytes([1, 2, 3])))
    return fr


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    os.makedirs(out, exist_ok=True)
    m = build_main()
    write(os.path.join(out, 'j1939-coverage.pcapng'), m)
    write(os.path.join(out, 'j1939-coverage-malformed.pcapng'), build_malformed())
    print('main frames: %d' % len(m))


if __name__ == '__main__':
    main()
