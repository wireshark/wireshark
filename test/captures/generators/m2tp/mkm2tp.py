#!/usr/bin/env python3
# Generates test/captures/m2tp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Write the synthetic M2TP coverage captures.

Usage: mkm2tp.py <outdir>

M2TP (MTP2 Tunnelling Protocol, an s-link draft) over SCTP port 9908 and
PPID 99. Every message class/type, every parameter, parameters with
padding and an unknown parameter, and MTP2 signal units (FISU, LSSU, MSU)
in the Protocol Data parameter. Nothing comes from a real network.
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct

from sslib import Sctp, write_pcap, mtp3_sltm  # noqa: E402

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'
PORT, PPID = 9908, 99


def param(tag, value=b''):
    p = struct.pack('!HH', tag, 4 + len(value)) + value
    return p + b'\0' * ((-len(p)) % 4)


def msg(cls, typ, params=b'', ver=1, length=None):
    if length is None:
        length = 8 + len(params)
    return struct.pack('!BBBBI', ver, 0, cls, typ, length) + params


def u32(v):
    return struct.pack('!I', v)


def iface(v=1):
    return param(1, u32(v))


def mtp2(kind, i=0):
    """MTP2 signal units without CRC: BSN, FSN, LI."""
    if kind == 'fisu':
        return bytes([0x80 | i, 0x80 | (i + 1), 0])
    if kind == 'lssu1':
        return bytes([i, i + 1, 1, 0x04])
    if kind == 'lssu2':
        return bytes([i, i + 1, 2, 0x01, 0x00])
    pl = mtp3_sltm(2, 1, i, b'M2TP')
    return bytes([i, i + 1, len(pl)]) + pl


def main():
    s = Sctp(PORT, PPID, cport=9908)
    frames, ranges = [], []

    def add(payload, rev=False):
        frames.append(s.frame(payload, rev))

    def mark(name, start):
        ranges.append((name, start + 1, len(frames)))

    st = len(frames)
    # management: ERR with every error code, info and diagnostic
    for code in range(0, 11):
        add(msg(0, 0, param(12, u32(code)) + param(7, b'\x01\x02\x03\x04\x05')), code % 2 == 1)
    add(msg(0, 0, param(12, u32(7)) + param(4, b'protocol error') + param(7, b'')), True)
    add(msg(0, 0, param(4, b'')))
    add(msg(0, 5))          # unknown management type, no parameters
    mark('ERR with every error code, diagnostic and info', st)

    st = len(frames)
    # SG state maintenance: every message with parameters
    add(msg(3, 1, iface(1) + param(3, u32(1)) + param(2, u32(1)) + param(4, b'asp up')))
    add(msg(3, 4, iface(1) + param(3, u32(2)) + param(2, u32(2))), True)
    add(msg(3, 3, param(9, b'heartbeat-12345')))
    add(msg(3, 6, param(9, b'heartbeat-12345')), True)
    add(msg(3, 3, param(9, b'')))
    add(msg(3, 2, param(10, u32(1)) + iface(7)))
    add(msg(3, 5, param(10, u32(2)) + iface(7)), True)
    add(msg(3, 2, param(10, u32(99))))
    add(msg(3, 1, param(3, u32(3)) + param(2, u32(9))))
    add(msg(3, 1, param(3, u32(7)) + param(2, u32(0))))
    add(msg(3, 9))          # unknown SGSM type
    add(msg(3, 1, param(0x7777, b'\x01\x02\x03\x04\x05\x06')))     # unknown parameter, padded
    add(msg(3, 1, param(0x7778, b'')))                              # unknown, empty
    add(msg(3, 1, param(4, b'abc') + param(4, b'abcde') + param(4, b'abcdef') + param(4, b'abcdefg')))
    mark('ASP Up/Down/Beat and their acks, reason, interface, user and mode values', st)

    st = len(frames)
    # data messages with MTP2 signal units, padded and not
    for i in range(4):
        add(msg(255, 1, iface(i + 1) + param(13, mtp2('fisu', i))), i % 2 == 1)
    for i in range(4):
        add(msg(255, 1, param(13, mtp2('lssu1', i))), i % 2 == 1)
    for i in range(3):
        add(msg(255, 1, iface(5) + param(13, mtp2('lssu2', i))), i % 2 == 1)
    for i in range(5):
        add(msg(255, 1, iface(6) + param(13, mtp2('msu', i))), i % 2 == 1)
    add(msg(255, 2, param(13, mtp2('fisu'))))          # unknown data type
    add(msg(1, 1, iface(1)))                            # unknown class
    mark('DATA with FISU, LSSU and MSU in Protocol Data (padded and not)', st)
    write_pcap(os.path.join(OUT, 'm2tp-coverage.pcap'), frames)

    # malformed capture: truncated messages, parameter lengths outside the message
    mal = []
    s2 = Sctp(PORT, PPID, cport=9908)
    good = msg(255, 1, iface(1) + param(13, mtp2('msu', 1)))
    for n in (3, 8, 10, 14, 17, 21, len(good) - 3):
        mal.append(s2.frame(good[:n]))
    mal.append(s2.frame(msg(3, 1, struct.pack('!HH', 3, 2))))                # parameter length < 4
    mal.append(s2.frame(msg(3, 1, struct.pack('!HH', 3, 200) + b'\0' * 4)))   # parameter too long
    mal.append(s2.frame(msg(3, 1, struct.pack('!HH', 1, 6) + b'\0\0\0\0'), True))  # short interface id
    mal.append(s2.frame(msg(255, 1, struct.pack('!HH', 13, 4))))             # empty protocol data
    mal.append(s2.frame(msg(0, 0, struct.pack('!HH', 4, 3))))                # info length < header
    mal.append(s2.frame(msg(0, 0, struct.pack('!HH', 12, 6) + b'\0\0\0\0')))  # error code cut short
    write_pcap(os.path.join(OUT, 'm2tp-coverage-malformed.pcap'), mal)
    for r in ranges:
        print(r)
    print(len(frames), len(mal))


if __name__ == '__main__':
    main()
