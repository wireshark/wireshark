#!/usr/bin/env python3
# Generates test/captures/nmea2000_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the NMEA 2000 dissector
(packet-nmea2000.c): PGN 65341 (Simnet autopilot angle), and the fast
packet PGNs 127237 (heading/track control) and 126996 (product
information) with reassembly.

NMEA 2000 is reached through J1939 (j1939.pgn table) on CAN with 29 bit
identifiers; J1939 itself is reached only through the Decode As table
can.subdissector, so tshark needs -d can.subdissector,j1939. The generic
"nmea2000" handle is reached through an Exported PDU. Every packet is
built from scratch with struct.

Usage: mknmea2000.py <output directory>

  nmea2000-coverage.pcapng            valid frames
  nmea2000-coverage-malformed.pcapng  truncated frames, duplicate and
                                      out-of-order fragments, fragments
                                      that never complete
"""
import os
import struct
import sys

T0 = 1700000000
CAN_EFF_FLAG = 0x80000000


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


def can(can_id, data, dlc=None):
    """SocketCAN record: classic frames are padded to 8 octets."""
    return (0, struct.pack('>IBBBB', can_id, len(data) if dlc is None else dlc, 0, 0, 0)
            + data.ljust(8, b'\xff'))


def pgn_id(pri, pgn, sa, ps=0xff):
    pf = (pgn >> 8) & 0xff
    dp = (pgn >> 16) & 1
    edp = (pgn >> 17) & 1
    if pf < 240:
        return CAN_EFF_FLAG | (pri << 26) | (edp << 25) | (dp << 24) | (pf << 16) | (ps << 8) | sa
    return CAN_EFF_FLAG | (pri << 26) | (edp << 25) | (dp << 24) | (pf << 16) | ((pgn & 0xff) << 8) | sa


def simnet(man, ind, mode, angle, res2=0, r16=0xffff, r8=0xff):
    v = man | (res2 << 11) | (ind << 13)
    return struct.pack('<HHBBH', v, r16, mode, r8, angle)


def fixed(s, n=32):
    return s.encode().ljust(n, b'\0')[:n]


def product_info():
    """134 octets of PGN 126996."""
    return (struct.pack('<HH', 2100, 4711) + fixed('Model X1') + fixed('1.2.3')
            + fixed('rev A') + fixed('SN-0001') + bytes([1, 3]))


def heading_track():
    """21 octets of PGN 127237."""
    return bytes(range(0x30, 0x30 + 21))


def fast(pgn, sa, seq, payload, nbytes=None, pri=6, order=None, skip=(), dup=()):
    """Frames of a fast packet. The first frame carries the frame counter
    0 and the total length; later frames 7 octets each."""
    total = len(payload) if nbytes is None else nbytes
    chunks = [payload[:6]]
    rest = payload[6:]
    while rest:
        chunks.append(rest[:7])
        rest = rest[7:]
    out = []
    idx = list(range(len(chunks))) if order is None else order
    for i in idx:
        if i in skip:
            continue
        if i == 0:
            d = bytes([(seq << 5) | 0, total]) + chunks[0]
        else:
            d = bytes([(seq << 5) | i]) + chunks[i]
        out.append(can(pgn_id(pri, pgn, sa), d, dlc=8))
        if i in dup:
            out.append(can(pgn_id(pri, pgn, sa), d, dlc=8))
    return out


def exported_pdu(name, payload):
    n = name.encode() + b'\0'
    return (1, struct.pack('>HH', 12, len(n)) + pad4(n) + struct.pack('>HH', 0, 0) + payload)


def interleave(*lists):
    out = []
    for i in range(max(len(x) for x in lists)):
        for x in lists:
            if i < len(x):
                out.append(x[i])
    return out


def build_main():
    fr = []
    # PGN 65341 Simnet autopilot angle: manufacturers (named and not),
    # industry codes 0-5 and one unnamed, modes (named and not), angles
    for man, ind, mode, ang in ((1857, 4, 2, 0), (137, 4, 3, 15708), (140, 5, 10, 31416), (135, 1, 11, 62831),
                                (69, 0, 2, 100), (2047, 2, 3, 1), (116, 3, 10, 2), (144, 6, 11, 3),
                                (88, 7, 99, 65535), (0, 0, 0, 0), (85, 4, 2, 1000), (154, 4, 252, 5000)):
        fr.append(can(pgn_id(6, 65341, 0x10 + len(fr)), simnet(man, ind, mode, ang, res2=len(fr) & 3)))
    # Heading/track control, 21 octets in four frames, several sources
    # and sequence counters
    for sa, seq in ((0x20, 0), (0x21, 1), (0x22, 7), (0x20, 2)):
        fr += fast(127237, sa, seq, heading_track(), 21)
    # Product information, 134 octets in 20 frames, certification levels
    # and load equivalency
    pi = product_info()
    fr += fast(126996, 0x30, 0, pi, 134)
    fr += fast(126996, 0x31, 5, pi[:-2] + bytes([0, 0]), 134)
    fr += fast(126996, 0x32, 3, pi[:-2] + bytes([2, 255]), 134)
    # The reproducer of "NMEA2000: Use the real PGN in the fast-packet
    # fragment id": fragments of 126996 and 127237 from one source with
    # the same sequence counter, interleaved. Both reassemble separately.
    fr += interleave(fast(126996, 0x40, 4, pi, 134), fast(127237, 0x40, 4, heading_track(), 21))
    # Fragments of two sources interleaved
    fr += interleave(fast(126996, 0x41, 6, pi, 134), fast(126996, 0x42, 6, pi, 134))
    # A second message with the same source and sequence after the first completed
    fr += fast(127237, 0x40, 4, heading_track(), 21)
    # Exported PDU naming the generic "nmea2000" dissector
    fr.append(exported_pdu('nmea2000', bytes([1, 2, 3, 4, 5, 6, 7, 8])))
    fr.append(exported_pdu('nmea2000', b''))
    return fr


def build_malformed():
    fr = []
    hd = heading_track()
    pi = product_info()
    # Truncated frames: no data at all, one octet, a short Simnet frame
    fr.append(can(pgn_id(6, 126996, 0x50), b'', dlc=0))
    fr.append(can(pgn_id(6, 127237, 0x50), b'\x20', dlc=1))
    fr.append(can(pgn_id(6, 127237, 0x50), b'\x00', dlc=1))
    fr.append(can(pgn_id(6, 65341, 0x50), b'\x41\x9a', dlc=2))
    fr.append(can(pgn_id(6, 65341, 0x50), b'', dlc=0))
    # Missing fragment: never completes
    fr += fast(127237, 0x51, 1, hd, 21, skip=(2,))
    fr += fast(126996, 0x51, 1, pi, 134, skip=(10,))
    # Duplicate fragments
    fr += fast(127237, 0x52, 2, hd, 21, dup=(1, 3))
    # Out of order fragments
    fr += fast(127237, 0x53, 3, hd, 21, order=(0, 2, 1, 3))
    fr += fast(126996, 0x53, 3, pi, 134, order=[0] + list(range(19, 0, -1)))
    # First frame only; and a continuation without a first frame
    fr += fast(126996, 0x54, 2, pi, 134, order=(0,))
    fr += fast(126996, 0x55, 2, pi, 134, order=(5, 6))
    # Frame counter beyond the last fragment, then the last fragment
    fr.append(can(pgn_id(6, 127237, 0x56), bytes([0x20 | 9]) + b'1234567'))
    fr.append(can(pgn_id(6, 127237, 0x56), bytes([0x20 | 31]) + b'1234567'))
    # Same message sent again with different data (overlap with conflicts)
    fr += fast(127237, 0x57, 6, hd, 21)
    fr += fast(127237, 0x57, 6, bytes(reversed(hd)), 21)
    return fr


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    os.makedirs(out, exist_ok=True)
    write(os.path.join(out, 'nmea2000-coverage.pcapng'), build_main())
    write(os.path.join(out, 'nmea2000-coverage-malformed.pcapng'), build_malformed())


main()
