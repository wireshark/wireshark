#!/usr/bin/env python3
# Generates test/captures/caneth_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the CAN-ETH (Controller
Area Network over Ethernet) dissector (packet-caneth.c).

CAN-ETH runs on UDP port 11898 (registered by default) and, with the
caneth_udp heuristic (disabled by default, --enable-heuristic
caneth_udp), on any UDP port. A PDU is the magic "ISO11898", version 1,
a frame count (at most 16) and that many 15 octet CAN frames (32 bit
little endian identifier, DLC, 8 data octets, extended flag, RTR flag),
optionally followed by reserved option octets. The heuristic splits a
datagram into PDUs of 10 + 15 * count octets. Every packet is built from
scratch with struct; no captured traffic is used.

Usage: mkcaneth.py <output directory>

Writes:
  caneth-coverage.pcap            PDUs with 0 to 16 frames, standard,
                                  extended and RTR frames, every DLC,
                                  options, datagrams the dissector
                                  rejects, several PDUs in one datagram
                                  for the heuristic (the fixed reproducer)
  caneth-coverage-malformed.pcap  frame counts past the end, DLCs past
                                  the frame, a magic cut short
"""

import os
import struct
import sys

SRC = (192, 0, 2, 1)
DST = (192, 0, 2, 2)
PORT = 11898


def pcap(path, frames, linktype=1):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, p in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
            f.write(p)


def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


def ipv4(proto, payload, ident=1):
    hdr = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0,
                      64, proto, 0, bytes(SRC), bytes(DST))
    return hdr[:10] + struct.pack('>H', csum(hdr)) + hdr[12:] + payload


def udp(sport, dport, data):
    hdr = struct.pack('>HHHH', sport, dport, 8 + len(data), 0)
    pseudo = struct.pack('>4s4sBBH', bytes(SRC), bytes(DST), 0, 17, 8 + len(data))
    c = csum(pseudo + hdr + data) or 0xffff
    return hdr[:6] + struct.pack('>H', c) + data


def frame(data, sport=PORT, dport=PORT, ident=1):
    return (bytes.fromhex('020000000002020000000001') + b'\x08\x00'
            + ipv4(17, udp(sport, dport, data), ident=ident))


def can(canid, data=b'', ext=0, rtr=0, dlc=None, fill=0x00):
    """One 15 octet CAN-ETH CAN frame."""
    if dlc is None:
        dlc = len(data)
    return (struct.pack('<IB', canid, dlc) + data.ljust(8, bytes([fill]))[:8]
            + bytes([ext, rtr]))


def pdu(frames, count=None, version=1, magic=b'ISO11898', options=b''):
    if count is None:
        count = len(frames)
    return magic + bytes([version, count]) + b''.join(frames) + options


def main_frames():
    f = []
    # 1: one standard frame, DLC 8 (the padding field then shows only
    #    the two flag octets)
    f.append(frame(pdu([can(0x123, bytes(range(1, 9)))])))
    # 2: three frames: standard DLC 2 (6 octets padding), extended ID
    #    0x1abcdef DLC 4, RTR with DLC 0
    f.append(frame(pdu([can(0x321, b'\x11\x22'),
                        can(0x1abcdef, b'\xa1\xa2\xa3\xa4', ext=1),
                        can(0x7ff, rtr=1)])))
    # 3: sixteen frames (the version 1 limit), DLC 0-8 and 8 again,
    #    extended and RTR mixed, non-zero padding
    fr = []
    for i in range(16):
        dlc = min(i, 8)
        fr.append(can(0x100 + i if i % 3 else 0x18000000 + i,
                      bytes(range(0x30 + i, 0x30 + i + dlc)),
                      ext=0 if i % 3 else 1, rtr=1 if i == 15 else 0, fill=0xcc))
    f.append(frame(pdu(fr)))
    # 4: no frames
    f.append(frame(pdu([])))
    # 5: one frame and four option octets (reserved)
    f.append(frame(pdu([can(0x55, b'\x55')], options=b'\x01\x02\x03\x04')))
    # 6: extended frame with the flags as 0xff (any non-zero value) and
    #    the identifier's upper bits set (masked off)
    f.append(frame(pdu([can(0xffffffff, b'\xee' * 3, ext=0xff, rtr=0xff)])))
    # 7: standard frame with an identifier above 0x7ff (masked to 11 bits)
    f.append(frame(pdu([can(0x0000f800 | 0x2aa, b'\x2a')])))
    # 8-11: datagrams on port 11898 the dissector rejects (shown as
    #    data): 9 octets, a wrong magic, version 2, 17 frames
    f.append(frame(b'ISO11898\x01'))
    f.append(frame(pdu([can(1, b'\x01')], magic=b'ISO11899')))
    f.append(frame(pdu([can(1, b'\x01')], version=2)))
    f.append(frame(pdu([can(1, b'\x01')] * 17)))
    # 12: the reproducer (caneth_heur_len.py): two PDUs of
    #    one frame each in one datagram on ports 40000/40001; the
    #    caneth_udp heuristic splits them (the first used to swallow the
    #    datagram)
    rep = lambda i: (b'ISO11898' + bytes([1, 1]) + struct.pack('<IB', 0x100 + i, 2)
                     + b'\x11\x22' + b'\0' * 6 + b'\x00\x00')
    f.append(frame(rep(1) + rep(2), 40000, 40001))
    # 13: three PDUs in one datagram (0, 2 and 1 frames) on another port
    f.append(frame(pdu([]) + pdu([can(0x10, b'\x10'), can(0x11, b'\x11\x11', ext=1)])
                   + pdu([can(0x12, b'')]), 40002, 40003))
    # 14: one PDU followed by six octets that are not a PDU: the
    #    heuristic dissects the PDU and stops
    f.append(frame(pdu([can(0x20, b'\x20\x21')]) + b'\x00\x01\x02\x03\x04\x05',
                   40004, 40005))
    # 15: a datagram on another port that is not CAN-ETH (heuristic
    #    rejects it)
    f.append(frame(b'not CAN-ETH payload', 40006, 40007))
    return f


def malformed_frames():
    f = []
    # 1: three frames announced, one present
    f.append(frame(pdu([can(0x1, b'\x01')], count=3)))
    # 2: DLC 15 (data past the 15 octet frame)
    f.append(frame(pdu([can(0x2, b'\x02' * 8, dlc=15)])))
    # 3: DLC 255
    f.append(frame(pdu([can(0x3, b'\x03' * 8, dlc=255)])))
    # 4: DLC 9 and 10: the data runs into the flag octets, no exception
    #    and no expert info
    f.append(frame(pdu([can(0x4, b'\x04' * 8, dlc=9), can(0x5, b'\x05' * 8, dlc=10)])))
    # 5: heuristic: two frames announced, one present
    f.append(frame(pdu([can(0x6, b'\x06')], count=2), 40000, 40001))
    # 6: heuristic: a PDU followed by "ISO11898" with no version octet
    f.append(frame(pdu([can(0x7, b'\x07')]) + b'ISO11898', 40000, 40001))
    # 7: heuristic: a PDU with a DLC of 12
    f.append(frame(pdu([can(0x8, b'\x08' * 8, dlc=12)]), 40000, 40001))
    return f


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcap(os.path.join(out, 'caneth-coverage.pcap'), main_frames())
    pcap(os.path.join(out, 'caneth-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()
