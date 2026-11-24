#!/usr/bin/env python3
# Generates test/captures/isobus_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the ISOBUS dissector
(packet-isobus.c, ISO 11783 on CAN with 29 bit identifiers).

ISOBUS is reached only through the "can.subdissector" Decode As table
(-d can.subdissector,isobus); it needs the struct can_info that the CAN
dissectors pass. Every packet is built from scratch with struct; no
captured traffic is used.

Usage: mkisobus.py <output directory>

Writes pcapng files with two interfaces:
  0  LINKTYPE_CAN_SOCKETCAN (227)       ISOBUS frames
  1  LINKTYPE_WIRESHARK_UPPER_PDU (252) an Exported PDU naming "isobus"
                                        (no CAN information: rejected)

  isobus-coverage.pcapng            address claims, requests,
                                    acknowledgements, time/date, the
                                    transport protocol (BAM, RTS/CTS/EOMA,
                                    abort, data), the extended transport
                                    protocol, proprietary and unknown
                                    PGNs, and the reproducer of the fix
                                    (an RTS flood on one address pair)
  isobus-coverage-malformed.pcapng  frames shorter than their message
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


def pgn3(pgn):
    return struct.pack('<I', pgn)[:3]


def name(idn, manuf, ecu, finst, func, vs, vsi, ig, aac=1):
    v = (idn & 0x1fffff) | (manuf & 0x7ff) << 21 | (ecu & 7) << 32 | (finst & 31) << 35 \
        | (func & 0xff) << 40 | (vs & 0x7f) << 49 | (vsi & 15) << 56 | (ig & 7) << 60 | (aac & 1) << 63
    return struct.pack('<Q', v)


def tp_transfer(src, dst, pgn, data, bam=False, cts=True):
    """Frames of one transport protocol transfer. BAM is broadcast; RTS/CTS
    is connection managed (RTS from src, CTS and EOMA from dst)."""
    n = (len(data) + 6) // 7
    fr = []
    if bam:
        fr.append(can(j(7, 236, 255, src), bytes([32]) + struct.pack('<H', len(data)) + bytes([n, 0xff]) + pgn3(pgn)))
    else:
        fr.append(can(j(7, 236, dst, src), bytes([16]) + struct.pack('<H', len(data)) + bytes([n, 0xff]) + pgn3(pgn)))
        if cts:
            fr.append(can(j(7, 236, src, dst), bytes([17, n, 1, 0xff, 0xff]) + pgn3(pgn)))
    for i in range(n):
        chunk = data[7 * i:7 * i + 7]
        fr.append(can(j(7, 235, 255 if bam else dst, src), bytes([i + 1]) + chunk.ljust(7, b'\xff')))
    if not bam and cts:
        fr.append(can(j(7, 236, src, dst), bytes([19]) + struct.pack('<H', len(data)) + bytes([n, 0xff]) + pgn3(pgn)))
    return fr


def etp_transfer(src, dst, pgn, size, packets):
    fr = [can(j(7, 200, dst, src), bytes([20]) + struct.pack('<I', size) + pgn3(pgn)),
          can(j(7, 200, src, dst), bytes([21, 16, 1, 0, 0]) + pgn3(pgn)),
          can(j(7, 200, src, dst), bytes([22, 16, 1, 0, 0]) + pgn3(pgn))]
    for i in range(packets):
        fr.append(can(j(7, 199, dst, src), bytes([i + 1]) + bytes([0x40 + i] * 7)))
    fr.append(can(j(7, 200, src, dst), bytes([23]) + struct.pack('<I', size) + pgn3(pgn)))
    return fr


def build_main():
    fr = []
    # Not ISOBUS: a standard (11 bit) identifier, an RTR frame
    fr.append(can(0x123, bytes([1, 2, 3, 4])))
    fr.append(can(CAN_EFF_FLAG | CAN_RTR_FLAG | 0x1cee00fe, b''))
    # Address claims: arbitrary address capable, a global function of the
    # industry group, an industry group specific function, vehicle systems
    fr.append(can(j(6, 238, 255, 0x80), name(0x12345, 55, 0, 0, 0x1a, 0x01, 0, 2)))
    fr.append(can(j(6, 238, 255, 0x26), name(0x00001, 1, 1, 2, 0x00, 0, 0, 0, aac=0)))
    fr.append(can(j(6, 238, 255, 0x27), name(0x1fffff, 0x7ff, 7, 31, 0x81, 0, 0, 0)))
    fr.append(can(j(6, 238, 255, 0x28), name(7, 100, 0, 0, 0x90, 0x7f, 15, 7)))
    fr.append(can(j(6, 238, 255, 254), name(9, 3, 0, 0, 0x02, 0, 0, 1)))     # cannot claim an address
    fr.append(can(j(6, 238, 255, 255), name(9, 3, 0, 0, 0x02, 0, 0, 1)))     # claims the global address
    # Requests: a known PGN, address claim, an unknown PGN; destination specific and global
    fr.append(can(j(6, 234, 0x26, 0x80), pgn3(60928)))
    fr.append(can(j(6, 234, 255, 0x80), pgn3(0)))
    fr.append(can(j(6, 234, 255, 0x80), pgn3(256)))
    fr.append(can(j(6, 234, 255, 0x80), pgn3(0x3ffff)))
    # Acknowledgement (PGN 59392): every control byte group, reserved bytes
    # set to 0xff
    fr.append(can(j(6, 232, 255, 0x26), bytes([0, 0xff, 0xff, 0xff, 0x80]) + pgn3(60928)))          # ACK
    fr.append(can(j(6, 232, 255, 0x26), bytes([1, 0x01, 0xff, 0xff, 0x80]) + pgn3(60928)))          # NACK, group function value
    fr.append(can(j(6, 232, 255, 0x26), bytes([2, 0x02, 0xff, 0xff, 0x80]) + pgn3(65254)))
    fr.append(can(j(6, 232, 255, 0x26), bytes([3, 0x03, 0xff, 0xff, 0x80]) + pgn3(65254)))
    fr.append(can(j(6, 232, 255, 0x26), bytes([128, 0x10, 0xff, 0xff, 0x80]) + pgn3(256)))          # one byte identifier
    fr.append(can(j(6, 232, 255, 0x26), bytes([129, 0x10, 0xff, 0xff, 0x80]) + pgn3(256)))
    fr.append(can(j(6, 232, 255, 0x26), bytes([130, 0x10, 0xff, 0xff, 0x80]) + pgn3(256)))
    fr.append(can(j(6, 232, 255, 0x26), bytes([131, 0x10, 0xff, 0xff, 0x80]) + pgn3(256)))
    fr.append(can(j(6, 232, 255, 0x26), bytes([144, 0x10, 0xff, 0xff, 0x80]) + pgn3(256)))          # two byte identifier
    fr.append(can(j(6, 232, 255, 0x26), bytes([145, 0x10, 0xff, 0xff, 0x80]) + pgn3(256)))
    fr.append(can(j(6, 232, 255, 0x26), bytes([146, 0x10, 0xff, 0xff, 0x80]) + pgn3(256)))
    fr.append(can(j(6, 232, 255, 0x26), bytes([147, 0x10, 0xff, 0xff, 0x80]) + pgn3(256)))
    fr.append(can(j(6, 232, 255, 0x26), bytes([160, 0x10, 0x11, 0x12, 0x80]) + pgn3(256)))          # three byte identifier
    fr.append(can(j(6, 232, 255, 0x26), bytes([161, 0x10, 0x11, 0x12, 0x80]) + pgn3(256)))
    fr.append(can(j(6, 232, 255, 0x26), bytes([162, 0x10, 0x11, 0x12, 0x80]) + pgn3(256)))
    fr.append(can(j(6, 232, 255, 0x26), bytes([163, 0x10, 0x11, 0x12, 0x80]) + pgn3(256)))
    fr.append(can(j(6, 232, 255, 0x26), bytes([100, 0xff, 0xff, 0xff, 0x80]) + pgn3(256)))          # unknown control byte
    # Time/date (PGN 65254): seconds, minutes, hours, month, day, year, UTC offsets
    fr.append(can(j(6, 254, 0xe6, 0x26), bytes([120, 30, 12, 6, 80, 38, 125, 127])))          # UTC+2, no minutes
    fr.append(can(j(6, 254, 0xe6, 0x26), bytes([0, 0, 0, 1, 4, 0, 130, 125])))                # minutes offset 5
    # Other PGNs: proprietary A / B, a known PF without a decoder, unknown data page 1
    fr.append(can(j(6, 239, 0x26, 0x80), bytes([1, 2, 3, 4, 5, 6, 7, 8])))
    fr.append(can(j(6, 255, 0x12, 0x80), bytes([1, 2, 3, 4, 5, 6, 7, 8])))
    fr.append(can(j(6, 239, 0x26, 0x80, dp=1), bytes([1, 2, 3, 4, 5, 6, 7, 8])))
    fr.append(can(j(6, 100, 0x26, 0x80, dp=1), bytes([1, 2, 3, 4, 5, 6, 7, 8])))
    fr.append(can(j(6, 170, 0x26, 0x80), bytes([1, 2, 3, 4, 5, 6, 7, 8])))
    fr.append(can(j(6, 171, 0x80, 0x26), bytes([1, 2, 3, 4, 5, 6, 7, 8])))
    fr.append(can(j(6, 147, 255, 0x80), bytes([1, 2, 3, 4, 5, 6, 7, 8])))
    fr.append(can(j(6, 254, 0xf0, 0x80, edp=1), bytes([1, 2, 3, 4, 5, 6, 7, 8])))
    fr.append(can(j(6, 0xfe, 0xca, 0x26), bytes([1, 2, 3, 4, 5, 6, 7, 8])))
    # VT frames are decoded by the ISOBUS VT dissector (PDU formats 230, 231)
    fr.append(can(j(7, 230, 255, 0x26), bytes([0xfe, 0x80, 0x00, 0x01, 0x10, 0x02, 0, 0])))
    fr.append(can(j(5, 231, 0x26, 0x80), bytes([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff])))
    # Transport protocol: BAM, RTS/CTS/EOMA, a one packet transfer, a
    # transfer for unknown PGN 0xFF00, a message for ECU to VT (PGN 0xE700)
    fr += tp_transfer(0x80, 255, 0xfe6a, bytes(range(30)), bam=True)
    fr += tp_transfer(0x80, 0x26, 0xff00, bytes(range(20, 40)))
    fr += tp_transfer(0x26, 0x80, 0xff00, bytes(range(5)))
    fr += tp_transfer(0x80, 0x26, 0xe700, bytes([0x12, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09]))
    # Both directions between one address pair at the same time (RTS from
    # both nodes): each connection managed on its own pair
    # Connection abort with reasons from the table, unknown reason, unknown control byte
    for reason in (1, 2, 3, 4, 5, 6, 7, 8, 9, 250, 251, 0):
        fr.append(can(j(7, 236, 0x80, 0x26), bytes([255, reason, 0xff, 0xff, 0xff]) + pgn3(0xff00)))
    fr.append(can(j(7, 236, 0x80, 0x26), bytes([200, 0, 0, 0, 0, 0, 0, 0])))
    # TP.DT from a node without a connection management message
    fr.append(can(j(7, 235, 0x99, 0x98), bytes([1, 1, 2, 3, 4, 5, 6, 7])))
    # Extended transport protocol: connection management with every control
    # byte, the abort reasons, data transfer packets
    fr += etp_transfer(0x80, 0x26, 0xff00, 14, 2)
    fr.append(can(j(7, 200, 0x80, 0x26), bytes([255, 3, 0xff, 0xff, 0xff]) + pgn3(0xff00)))
    fr.append(can(j(7, 200, 0x80, 0x26), bytes([255, 200, 0xff, 0xff, 0xff]) + pgn3(0xff00)))
    fr.append(can(j(7, 200, 0x80, 0x26), bytes([99, 1, 2, 3, 4, 5, 6, 7])))
    # Reproducer, RTS flood on one address pair: every RTS appends an entry
    # to the per address pair list and every TP packet walked it (quadratic)
    flood = bytes([16]) + struct.pack('<H', 9) + bytes([2, 0xff]) + pgn3(0xe700)
    for i in range(300):
        fr.append(can(j(6, 236, 0x26, 0x80), flood))
    fr.append(can(j(6, 235, 0x26, 0x80), bytes([1, 0, 1, 2, 3, 4, 5, 6])))
    fr.append(can(j(6, 235, 0x26, 0x80), bytes([2, 7, 8, 0xff, 0xff, 0xff, 0xff, 0xff])))
    # An Exported PDU naming "isobus": no CAN information
    n = b'isobus\0\0'
    fr.append((1, struct.pack('>HH', 12, len(n)) + n + struct.pack('>HH', 0, 0) + bytes([1, 2, 3, 4])))
    return fr


def build_malformed():
    fr = []
    # Frames shorter than their message
    for pf, ps, data in ((234, 0x26, b'\x01\x02'), (236, 0x26, b''), (236, 0x26, b'\x10\x09\x00'),
                         (236, 0x26, b'\x11\x01'), (236, 0x26, b'\x13\x09'), (236, 0x26, b'\xff\x01'),
                         (236, 255, b'\x20\x09'), (238, 255, b'\x01\x02\x03'),
                         (232, 255, b'\x00\xff'), (232, 255, b'\xa0\x10\x11'),
                         (200, 0x26, b'\x14\x01\x02'), (200, 0x26, b'\x15\x01'), (200, 0x26, b'\x16\x01'),
                         (200, 0x26, b'\x17\x01'), (200, 0x26, b'\xff\x01'), (200, 0x26, b''),
                         (199, 0x26, b''), (235, 0x26, b''), (254, 0xe6, b'\x01\x02')):
        fr.append((0, struct.pack('>IBBBB', j(6, pf, ps, 0x80), len(data), 0, 0, 0) + data))
    # Acknowledgement with a reserved field that is not 0xff
    fr.append(can(j(6, 232, 255, 0x26), bytes([0, 1, 0x12, 0x34, 0x80]) + pgn3(60928)))
    fr.append(can(j(6, 232, 255, 0x26), bytes([128, 1, 0x12, 0x34, 0x80]) + pgn3(60928)))
    fr.append(can(j(6, 232, 255, 0x26), bytes([144, 1, 0x12, 0x34, 0x80]) + pgn3(60928)))
    return fr


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    os.makedirs(out, exist_ok=True)
    m = build_main()
    write(os.path.join(out, 'isobus-coverage.pcapng'), m)
    write(os.path.join(out, 'isobus-coverage-malformed.pcapng'), build_malformed())
    print('main frames: %d' % len(m))


if __name__ == '__main__':
    main()
