#!/usr/bin/env python3
# Generates test/captures/busmirroring_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the BusMirroring dissector
(packet-busmirroring.c).

AUTOSAR Bus Mirroring protocol over UDP port 30511. Every packet is built
from scratch with struct; no captured traffic is used.

Usage: mkbusmirroring.py <output directory>

Writes:
  busmirroring-coverage.pcap            CAN, LIN and FlexRay data items with
                                        and without network state, frame ID
                                        and payload; several items per
                                        packet; the protocol warnings (invalid
                                        IDs, PIDs, lengths, network types and
                                        the nanoseconds reproducer)
  busmirroring-coverage-malformed.pcap  data items cut at every field, a data
                                        length past the end, a short header
"""

import os
import struct
import sys

PORT = 30511
SRC = (192, 0, 2, 1)
DST = (192, 0, 2, 2)

CAN, LIN, FLEXRAY, ETHERNET = 1, 2, 3, 4
NS, FID, PL = 0x80, 0x40, 0x20


def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


def udp_frame(data, sport=PORT, dport=PORT, ident=1):
    udp = struct.pack('>HHHH', sport, dport, 8 + len(data), 0)
    pseudo = struct.pack('>4s4sBBH', bytes(SRC), bytes(DST), 0, 17, 8 + len(data))
    c = csum(pseudo + udp + data) or 0xffff
    udp = udp[:6] + struct.pack('>H', c) + data
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), ident, 0, 64, 17, 0,
                     bytes(SRC), bytes(DST))
    ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
    return bytes.fromhex('020000000002020000000001') + b'\x08\x00' + ip + udp


def header(seq, items, sec=1700000000, ns=123456789, version=1, data_length=None):
    if data_length is None:
        data_length = len(items)
    return (struct.pack('>BB', version, seq) + struct.pack('>Q', sec)[2:]
            + struct.pack('>IH', ns, data_length) + items)


def item(ts, flags, netid, state=None, frame_id=b'', payload=None):
    d = struct.pack('>HBB', ts, flags, netid)
    if state is not None:
        d += bytes([state])
    d += frame_id
    if payload is not None:
        d += bytes([len(payload)]) + payload
    return d


def can_id(ident, extended=False, fd=False):
    return struct.pack('>I', (0x80000000 if extended else 0) | (0x40000000 if fd else 0) | ident)


def fr_id(slot, cycle, ch_a=True, ch_b=False, valid=True):
    v = (0x8000 if ch_b else 0) | (0x4000 if ch_a else 0) | (0x0800 if valid else 0) | slot
    return struct.pack('>HB', v, cycle)


def lin_pid(frame_id):
    """The protected identifier: frame ID plus its two parity bits."""
    b = [(frame_id >> i) & 1 for i in range(6)]
    p0 = b[0] ^ b[1] ^ b[2] ^ b[4]
    p1 = 1 ^ (b[1] ^ b[3] ^ b[4] ^ b[5])
    return frame_id | (p0 << 6) | (p1 << 7)


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, p in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
            f.write(p)


def main_frames():
    F = []
    seq = [0]

    def pkt(items, **kw):
        seq[0] += 1
        F.append(udp_frame(header(seq[0], items, **kw), ident=seq[0]))

    # 1: CAN items: no optional field, network state only, standard frame
    # ID only, payload only, and all three (CAN 2.0, 8 octets)
    pkt(item(100, CAN, 1)
        + item(101, CAN | NS, 1, state=0x40 | 0x03)
        + item(102, CAN | FID, 1, frame_id=can_id(0x123))
        + item(103, CAN | PL, 1, payload=b'\x01\x02\x03')
        + item(104, CAN | NS | FID | PL, 1, state=0xf5, frame_id=can_id(0x7ff),
               payload=bytes(range(8))))
    # 2: CAN extended ID, CAN FD with 12 and 64 octets, CAN FD with 8, an
    # empty CAN payload
    pkt(item(200, CAN | FID | PL, 2, frame_id=can_id(0x1abcdef, extended=True),
             payload=b'\xaa' * 4)
        + item(201, CAN | NS | FID | PL, 2, state=0x40,
               frame_id=can_id(0x100, fd=True), payload=bytes(range(12)))
        + item(202, CAN | FID | PL, 2, frame_id=can_id(0x1fffffff, extended=True, fd=True),
               payload=bytes(range(64)))
        + item(203, CAN | FID | PL, 2, frame_id=can_id(0x10, fd=True), payload=b'\x55' * 8)
        + item(204, CAN | FID | PL, 2, frame_id=can_id(0x11), payload=b''))
    # 3: LIN items: no optional field, network state, valid PID, payload,
    # all three
    pkt(item(300, LIN, 3)
        + item(301, LIN | NS, 3, state=0x40 | 0x0f)
        + item(302, LIN | FID, 3, frame_id=bytes([lin_pid(0x12)]))
        + item(303, LIN | PL, 3, payload=b'\x10\x20')
        + item(304, LIN | NS | FID | PL, 3, state=0x80 | 0x05,
               frame_id=bytes([lin_pid(0x3c)]), payload=bytes(range(8))))
    # 4: FlexRay items: no optional field, network state, frame ID (both
    # channels, slot valid), payload, all three (FlexRay payloads may be
    # longer than 8 octets)
    pkt(item(400, FLEXRAY, 4)
        + item(401, FLEXRAY | NS, 4, state=0x40 | 0x3f)
        + item(402, FLEXRAY | FID, 4, frame_id=fr_id(0x7ff, 63, ch_a=True, ch_b=True))
        + item(403, FLEXRAY | PL, 4, payload=bytes(range(32)))
        + item(404, FLEXRAY | NS | FID | PL, 4, state=0x20,
               frame_id=fr_id(17, 5, ch_a=False, ch_b=True, valid=False),
               payload=bytes(range(254))))
    # 5: mixed CAN, LIN and FlexRay in one packet, other header values
    pkt(item(0, CAN | NS | FID | PL, 10, state=0x40, frame_id=can_id(0x55), payload=b'\x01')
        + item(65535, LIN | NS | FID | PL, 11, state=0x40, frame_id=bytes([lin_pid(1)]),
               payload=b'\x02')
        + item(1, FLEXRAY | NS | FID | PL, 12, state=0x40, frame_id=fr_id(1, 0), payload=b'\x03'),
        sec=0, ns=0, version=2)
    # 6: a header with no data items
    pkt(b'', sec=0x0000ffffffff, ns=999999999)
    # 7-12: protocol warnings (the item is complete)
    # 7: standard CAN ID above 0x7FF
    pkt(item(700, CAN | FID, 1, frame_id=can_id(0x800)))
    # 8: LIN PID with wrong parity bits
    pkt(item(800, LIN | FID, 3, frame_id=b'\x12'))
    # 9: CAN 2.0 payload of 9, CAN FD payload of 13, LIN payload of 9
    pkt(item(900, CAN | PL, 1, payload=bytes(9))
        + item(901, CAN | FID | PL, 1, frame_id=can_id(0x1, fd=True), payload=bytes(13))
        + item(902, LIN | PL, 3, payload=bytes(9)))
    # 10: invalid network types (0 and Ethernet), with network state, a
    # frame ID flag (no frame ID is read) and a payload
    pkt(item(1000, 0, 5)
        + item(1001, ETHERNET | NS | FID | PL, 6, state=0xc0, payload=b'\xee\xee'))
    # 11: the reproducer busmirroring_bad_nsecs.py: seconds
    # 0xFFFFFFFFFFFF and nanoseconds 0xFFFFFFFF; one CAN item
    F.append(udp_frame(bytes([1, 7]) + b'\xff' * 6 + b'\xff\xff\xff\xff' + struct.pack('>H', 6)
                       + struct.pack('>H', 1) + bytes([0xe1, 0x01, 0x40, 0x80, 0, 1, 0x23,
                                                       0x01, 0xaa]), ident=11))
    # 12: nanoseconds of exactly one second
    seq[0] = 11
    pkt(item(1200, CAN, 1), ns=1000000000)
    return F


def malformed_frames():
    F = []
    hdr = lambda items, dl=None: udp_frame(header(1, items, data_length=dl))
    # 1: header shorter than 14 octets (not dissected)
    F.append(udp_frame(b'\x01\x02\x03'))
    # 2: data length past the end of the packet, items complete
    F.append(hdr(item(1, CAN, 1), dl=500))
    # 3-5: item cut after 1 octet, after the timestamp, after the flags
    F.append(hdr(b'\x00'))
    F.append(hdr(b'\x00\x01'))
    F.append(hdr(b'\x00\x01\x41'))
    # 6: network state missing
    F.append(hdr(struct.pack('>HBB', 1, CAN | NS, 1)))
    # 7-9: CAN, LIN, FlexRay frame ID missing or cut
    F.append(hdr(struct.pack('>HBB', 1, CAN | FID, 1) + b'\x00\x00'))
    F.append(hdr(struct.pack('>HBB', 1, LIN | FID, 1)))
    F.append(hdr(struct.pack('>HBB', 1, FLEXRAY | FID, 1) + b'\x00'))
    # 10: payload length missing
    F.append(hdr(struct.pack('>HBB', 1, CAN | PL, 1)))
    # 11: payload shorter than its length
    F.append(hdr(struct.pack('>HBB', 1, LIN | PL, 1) + b'\x08\x01\x02'))
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'busmirroring-coverage.pcap'), main_frames())
    write_pcap(os.path.join(out, 'busmirroring-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()
