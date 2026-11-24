#!/usr/bin/env python3
# Generates test/captures/bist_itch_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the BIST ITCH dissector
(packet-bist-itch.c).

BIST ITCH has no port and no heuristic: it is reached only with Decode As
on the payload of MoldUDP64 or MoldUDP. Every packet is built from scratch
with struct; no captured traffic is used. A feed source (192.0.2.1) sends
MoldUDP64 datagrams to UDP port 30064 and MoldUDP datagrams to UDP port
30010 of 239.0.0.1.

Usage: mkbist_itch.py <output directory>

Writes:
  bist_itch-coverage.pcap            every message type at full length,
                                     the optional tails of Add Order and
                                     Order Book Directory, trailing bytes,
                                     unknown types (with and without a
                                     body), several messages per datagram,
                                     MoldUDP64 and MoldUDP
  bist_itch-coverage-malformed.pcap  every known type cut short or bare,
                                     and an empty message

Dissect with
  -d udp.port==30064,moldudp64 -d udp.port==30010,moldudp
  -d moldudp64.payload,bist_itch -d moldudp.payload,bist_itch
"""

import os
import struct
import sys

SRC = (192, 0, 2, 1)
DST = (239, 0, 0, 1)
PORT64 = 30064
PORT = 30010


def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


class Pcap:
    def __init__(self):
        self.frames = []

    def udp(self, dport, data, sport=40000):
        hdr = struct.pack('>HHHH', sport, dport, 8 + len(data), 0)
        pseudo = struct.pack('>4s4sBBH', bytes(SRC), bytes(DST), 0, 17, 8 + len(data))
        c = csum(pseudo + hdr + data) or 0xffff
        l4 = hdr[:6] + struct.pack('>H', c) + data
        ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(l4), len(self.frames) + 1,
                         0x4000, 64, 17, 0, bytes(SRC), bytes(DST))
        ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
        eth = bytes.fromhex('01005e000001') + bytes.fromhex('020000000001') + b'\x08\x00'
        self.frames.append(eth + ip + l4)

    def write(self, path):
        out = [struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)]
        t = 1700000000
        for i, f in enumerate(self.frames):
            out.append(struct.pack('<IIII', t + i, 0, len(f), len(f)) + f)
        with open(path, 'wb') as fh:
            fh.write(b''.join(out))


class Feed:
    """MoldUDP64 and MoldUDP sessions with running sequence numbers."""
    def __init__(self, cap):
        self.cap = cap
        self.seq64 = 1
        self.seq = 1

    def mold64(self, *msgs, count=None):
        body = b''.join(struct.pack('>H', len(m)) + m for m in msgs)
        n = len(msgs) if count is None else count
        self.cap.udp(PORT64, b'BISTITCH01' + struct.pack('>QH', self.seq64, n) + body)
        self.seq64 += len(msgs)

    def mold(self, *msgs):
        body = b''.join(struct.pack('<H', len(m)) + m for m in msgs)
        self.cap.udp(PORT, b'BISTITCH02' + struct.pack('<IH', self.seq, len(msgs)) + body)
        self.seq += len(msgs)


def a(s, n):
    """ASCII field, space padded."""
    s = s.encode()
    assert len(s) <= n
    return s + b' ' * (n - len(s))


# Message builders. Each returns the full-length message.

def add_order(ns=1000, oid=123456789, ob=70616, side=b'B', rank_seq=11, qty=500,
              price=1234500, attrs=0x0102, lot=1, rank_time=1700000000123456789):
    return (b'A' + struct.pack('>IQI', ns, oid, ob) + side + struct.pack('>I', rank_seq) +
            struct.pack('>QIHB', qty, price, attrs, lot) + struct.pack('>Q', rank_time))


def equilibrium(ns=1001, ob=70616):
    return b'Z' + struct.pack('>IIQQIIIQQ', ns, ob, 1000, 1200, 1234500, 1234000,
                              1235000, 300, 400)


def combo_leg(ns=1002):
    return b'M' + struct.pack('>III', ns, 80001, 70616) + b'S' + struct.pack('>I', 2)


def executed(ns=1003, oid=123456789):
    return (b'E' + struct.pack('>IQI', ns, oid, 70616) + b'B' +
            struct.pack('>QQI', 200, 99000001, 5) + b'\0' * 7 + b'\0' * 7)


def second(sec=36000):
    return b'T' + struct.pack('>I', sec)


def trade(ns=1004):
    return (b'P' + struct.pack('>IQI', ns, 99000002, 6) + b'S' +
            struct.pack('>QII', 150, 70616, 1234600) + b'\0' * 14 + b'Y' + b'N')


def executed_price(ns=1005, oid=123456790):
    return (b'C' + struct.pack('>IQI', ns, oid, 70616) + b'S' +
            struct.pack('>QQI', 100, 99000003, 7) + b'\0' * 14 +
            struct.pack('>I', 1234700) + b'Y' + b'N')


def delete(ns=1006, oid=123456789):
    return b'D' + struct.pack('>IQI', ns, oid, 70616) + b'B'


def system_event(ns=1007, code=b'O'):
    return b'S' + struct.pack('>I', ns) + code


def directory(ns=1008, rank_type=True):
    m = (b'R' + struct.pack('>II', ns, 70616) + a('GARAN.E', 32) +
         a('TURKIYE GARANTI BANKASI', 32) + a('TRAGARAN91N1', 12) + b'\x01' + a('TRY', 3) +
         struct.pack('>HHIIIQB', 3, 0, 1, 100, 1000000, 1, 0) +
         struct.pack('>IIIHB', 0, 0, 20261231, 0, 0))
    if rank_type:
        m += b'\x01'
    return m


def flush(ns=1009):
    return b'Y' + struct.pack('>II', ns, 70616)


def short_sell(ns=1010):
    return b'V' + struct.pack('>II', ns, 70616) + b'\x01'


def ob_state(ns=1011):
    return b'O' + struct.pack('>II', ns, 70616) + a('P_SUREKLI_ISLEM', 20)


def tick_size(ns=1012):
    return b'L' + struct.pack('>IIQII', ns, 70616, 100, 0, 999900)


SIZES = {'A': 45, 'Z': 53, 'M': 18, 'E': 52, 'T': 5, 'P': 50, 'C': 58, 'D': 18,
         'S': 6, 'R': 130, 'Y': 9, 'V': 10, 'O': 29, 'L': 25}


def all_types():
    return [add_order(), equilibrium(), combo_leg(), executed(), second(), trade(),
            executed_price(), delete(), system_event(), directory(), flush(),
            short_sell(), ob_state(), tick_size()]


def main_capture(path):
    cap = Pcap()
    f = Feed(cap)
    msgs = all_types()
    for m in msgs:
        assert len(m) == SIZES[chr(m[0])], (chr(m[0]), len(m))
    # 1: start of messages and a Second message in one datagram
    f.mold64(system_event(ns=1, code=b'O'), second(36000))
    # 2-15: one message of each type per datagram
    for m in msgs:
        f.mold64(m)
    # 16-21: Add Order with the optional tails present in part
    # (18: up to the side, 20: part of the ranking sequence, 22: with the
    # ranking sequence, 30: part of quantity/price, 37: without the ranking
    # time, 40: part of the ranking time)
    full = add_order(oid=223456789, side=b'S', qty=750, price=1235000)
    for n in (18, 20, 22, 30, 37, 40):
        f.mold64(full[:n])
    f.mold64(full + b'\xee\xee')            # 22: trailing bytes
    # 23-24: Order Book Directory without the ranking type, with trailing bytes
    f.mold64(directory(rank_type=False))
    f.mold64(directory() + b'\xee\xee')
    # 25: Second with trailing bytes
    f.mold64(second(36001) + b'\xee')
    # 26: the bare unknown type of bist_itch_alltypes.py ('Q')
    f.mold64(b'Q')
    # 27: unknown type with a body
    f.mold64(b'Q' + bytes(range(0x41, 0x4a)))
    # 28: every type in one MoldUDP64 datagram
    f.mold64(*msgs)
    # 29: MoldUDP (little endian) with Add Order, Executed, Delete
    f.mold(add_order(oid=323456789), executed(oid=323456789), delete(oid=323456789))
    # 30: end of messages
    f.mold64(system_event(ns=2, code=b'C'))
    cap.write(path)


def malformed_capture(path):
    cap = Pcap()
    f = Feed(cap)
    # 1-14: every type cut in half (Add Order inside the order ID, since
    # half of it ends at an optional field), 15-28: every type bare (type
    # octet only)
    for m in all_types():
        f.mold64(m[:10] if m[:1] == b'A' else m[:len(m) // 2])
    for m in all_types():
        f.mold64(m[:1])
    # 29: an empty message
    f.mold64(b'')
    cap.write(path)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    main_capture(os.path.join(out, 'bist_itch-coverage.pcap'))
    malformed_capture(os.path.join(out, 'bist_itch-coverage-malformed.pcap'))


if __name__ == '__main__':
    main()
