#!/usr/bin/env python3
# Generates test/captures/wimaxmacphy_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the WiMAX MAC-PHY (wimaxmacphy plugin) coverage captures.

Usage: mkwimaxmacphy.py <outdir> [-v]

The dissector has no port or heuristic; it is reached with Decode As
(udp.port).  Frames are Ethernet/IPv4/UDP to port 5000.  Writes
wimaxmacphy-coverage.pcap and wimaxmacphy-coverage-malformed.pcap.
"""
import os
import random
import struct
import sys

random.seed(41)


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def frame(payload, sport=5000, dport=5000):
    udp = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0,
                     bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2]))
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    return b'\x02\0\0\0\0\x02' + b'\x02\0\0\0\0\x01' + b'\x08\x00' + ip + udp


def write_pcap(fn, frames):
    with open(fn, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)) + fr)


def rnd(n):
    return bytes(random.getrandbits(8) for _ in range(n))


def u8(*a):
    return bytes(x & 0xff for x in a)


def u16(x):
    return struct.pack('!H', x & 0xffff)


def u32(x):
    return struct.pack('!I', x & 0xffffffff)


# ---- downlink descriptors ------------------------------------------------
def dl_sub_burst(t):
    b = u8(t, rnd(1)[0], 3, 4) + u16(40 + t) + rnd(2) + rnd(1) + u8(random.randrange(16)) \
        + u16(0x1234) + u16(0x0102) + u8(0x40 | 2, 3) + u32(1000 + t)
    if t in (0x61, 0x64):
        b += rnd(4)
    return b


def dl_burst(t, ext, subs):
    b = u8(t, ext, 7, 0x12) + u32(512) + u8(2, 3, 1, 2)
    if t == 0x40:
        b += u16(18) + rnd(2)
    elif t == 0x41:
        b += u8(4, 5) + u16(0x55)
        if ext == 1:
            b += u8(2, 3) + rnd(2)
        elif ext == 2:
            b += u8(1, 2) + rnd(2)
    elif t == 0x43:
        b += u8(4, 6) + rnd(2)
    b += u8(len(subs)) + rnd(3)
    return b + b''.join(dl_sub_burst(s) for s in subs)


def dl_zone(t, bursts):
    b = u8(t, 1, 0, 12, 1, 0, 7, 3, 1) + rnd(3)
    if t == 0x21:
        b += u8(1, 2, 1, 3)
    elif t == 0x22:
        b += u8(1, 1) + rnd(2)
    b += u8(len(bursts)) + rnd(3)
    return b + b''.join(dl_burst(*x) for x in bursts)


def dl_subframe(zones, frameno=5):
    b = u8(1, frameno, 0, 2) + rnd(4) + u8(len(zones)) + rnd(3)
    return b + b''.join(dl_zone(*z) for z in zones)


# ---- uplink descriptors --------------------------------------------------
def ul_sub_burst(t):
    b = u8(t, 3) + u16(0x1010 + t) + u16(0x20) + rnd(2)
    if t == 0x68:
        b += u8(1, 3) + rnd(2)
    elif t == 0x69:
        b += u8(0xa5) + u16(0x1234) + u8(0x3c)
    elif t == 0x6a:
        b += u32(0x5a5a5a5a)
    elif t == 0x6b:
        b += u8(1, 2, 3, 1, 4, 5) + u16(0xbeef) + u8(2, 1, 0)
    else:
        b += u8(1, 2) + u16(30) + u32(777) + u8(1, 0x0b) + rnd(2)
        if t in (0x61, 0x64):
            b += u8(3, 4, 1, 2)
    return b


UL_BURST_LEN = {0x40: 4, 0x41: 4, 0x42: 8, 0x43: 8, 0x44: 4, 0x45: 8, 0x46: 4}


def ul_burst(t, ext, subs):
    b = u8(t, ext, 9, 0x23) + u32(640) + u8(1, 2, 0, 1) + u16(0x77) + u16(0x88)
    if t in UL_BURST_LEN:
        b += rnd(UL_BURST_LEN[t])
    elif t == 0x47:
        b += u16(64) + rnd(2)
        if ext in (1, 2):
            b += rnd(4)
    b += u8(len(subs)) + rnd(3)
    return b + b''.join(ul_sub_burst(s) for s in subs)


def ul_zone(t, bursts):
    b = u8(t, 1, 0, 12, 1, 0, 7, 1)
    if t == 0x22:
        b += u8(1, 2, 1, 0)
    b += u8(len(bursts)) + rnd(3)
    return b + b''.join(ul_burst(*x) for x in bursts)


def ul_subframe(zones, frameno=6):
    b = u8(2, frameno, 0, 2) + u32(123456) + u8(len(zones)) + rnd(3)
    return b + b''.join(ul_zone(*z) for z in zones)


DL_ALL = [(0x21, [(0x40, 0, [0x60]), (0x41, 0, [0x61, 0x64, 0x60]), (0x41, 1, [0x61]),
                  (0x41, 2, [0x64]), (0x41, 3, []), (0x43, 0, [0x60]), (0x45, 0, [0x61])]),
          (0x22, [(0x41, 1, [0x61])]),
          (0x20, [(0x41, 0, [0x60])])]
UL_ALL = [(0x20, [(0x40, 0, [0x60]), (0x41, 0, [0x68]), (0x42, 0, [0x69]), (0x43, 0, [0x6a]),
                  (0x44, 0, [0x6b]), (0x45, 0, [0x61]), (0x46, 0, [0x64]),
                  (0x47, 0, [0x60, 0x61, 0x64]), (0x47, 1, [0x68, 0x69]),
                  (0x47, 2, [0x6a, 0x6b]), (0x47, 3, []), (0x4f, 0, [0x70])]),
          (0x22, [(0x47, 1, [0x61])]),
          (0x23, [(0x47, 0, [0x60])])]


def msg(mtype, body, entity=1, seg=0):
    return u8((entity & 0xf) | ((seg & 3) << 4), mtype) + body


def build():
    fr, ranges = [], []

    def add(label, pkts):
        s = len(fr) + 1
        fr.extend(frame(p, sport=5000 + len(fr) % 7) for p in pkts)
        ranges.append((label, s, len(fr)))

    # TXSTART.request: all DL burst/sub-burst types, and variants
    dl = dl_subframe(DL_ALL)
    add('PHY-TXSTART.request, all downlink zone/burst/sub-burst types, descriptor of the fix (padding after the zone count)',
        [msg(1, u16(len(dl)) + dl, entity=1),
         msg(1, u16(len(dl_subframe([]))) + dl_subframe([]), entity=2, seg=1),
         msg(1, u16(len(dl) + 6) + dl + rnd(6), entity=3, seg=2)])   # longer TXVECTOR
    ul = ul_subframe(UL_ALL)
    add('PHY-RXSTART.request, all uplink zone/burst/sub-burst types',
        [msg(7, u16(len(ul)) + ul), msg(7, u16(len(ul_subframe([]))) + ul_subframe([]), seg=3),
         msg(7, u16(len(ul) + 5) + ul + rnd(5))])
    add('simple primitives: TXSTART confirmation/indication, TXSDU request/confirmation, TXEND, RXSTART confirmation/indication',
        [msg(2, rnd(2)), msg(3, rnd(6)), msg(4, u16(0x5a5a) + rnd(40)),
         msg(4, u16(0x1234)), msg(5, rnd(6)), msg(6, rnd(6)),
         msg(8, rnd(2)), msg(9, rnd(2))])
    def rxsdu(itype, extra=b''):
        return msg(10, u16(7) + u32(0x80000010 if itype == 0 else 5) + u8(40, 30, 0, 5, 0x21)
                   + u8((itype << 4) | 0x04 | 1) + u16(3) + u32(1) + u32(2) + extra)

    add('PHY-RXSDU.indication: data burst, HARQ ACK, fast feedback and other indication types',
        [rxsdu(0, rnd(60)), rxsdu(1, u16(0x66) + u8(0x1f, 0xf0)), rxsdu(2, u16(0x66) + rnd(1) + u8(0x5a) + rnd(3) + u8(0)),
         rxsdu(3), rxsdu(0)])
    add('PHY-RXEND.indication with one and three SSs, PHY-RXCDMA.indication',
        [msg(11, rnd(4) + u16(1)), msg(11, rnd(4) + u16(1) + u16(2) + u16(3)),
         msg(15, rnd(22))])
    add('unknown message types (0, 12-14, 16, 255), minimal packet',
        [msg(0, rnd(5)), msg(12, rnd(3)), msg(13, b''), msg(14, rnd(9)), msg(16, rnd(2)), msg(255, rnd(4)),
         msg(11, rnd(4) + u16(9), entity=15)])
    return fr, ranges


def build_malformed():
    fr = []
    dl = dl_subframe(DL_ALL)
    ul = ul_subframe(UL_ALL)
    fr.append(frame(b'\x01'))                      # shorter than the header: not accepted
    fr.append(frame(b''))
    fr.append(frame(msg(1, u16(len(dl)) + dl[:30])))  # truncated downlink descriptor
    fr.append(frame(msg(7, u16(len(ul)) + ul[:50])))
    fr.append(frame(msg(1, u16(len(dl)) + dl[:-1])))
    fr.append(frame(msg(1, u16(5))))  # no descriptor at all
    fr.append(frame(msg(1, u16(300) + u8(1, 2, 0, 2) + rnd(4) + u8(255) + rnd(3))))  # 255 zones, no data
    fr.append(frame(msg(7, u16(300) + u8(1, 2, 0, 2) + rnd(4) + u8(255) + rnd(3))))
    fr.append(frame(msg(10, rnd(10))))  # short RXSDU
    fr.append(frame(msg(10, u16(7) + u32(5) + rnd(4) + u8(40, 30, 0, 5, 1, 1) + u16(3) + u32(1) + u32(2) + rnd(2))))
    fr.append(frame(msg(11, rnd(4))))  # RXEND without an SS (do loop reads past)
    fr.append(frame(msg(15, rnd(10))))
    fr.append(frame(msg(2, b'')))
    fr.append(frame(msg(4, rnd(3))))
    fr.append(frame(msg(2, rnd(2) + rnd(7))))  # extra bytes after a primitive
    fr.append(frame(msg(1, u16(len(dl)) + dl + rnd(3))))  # TXVECTOR shorter than the data
    # 200 zones x 3 bursts: long but valid
    z = [(0x20, [(0x41, 0, [0x60])])] * 20
    d = dl_subframe(z)
    fr.append(frame(msg(1, u16(len(d)) + d)))
    return fr


if __name__ == '__main__':
    out = sys.argv[1]
    frames, ranges = build()
    write_pcap(os.path.join(out, 'wimaxmacphy-coverage.pcap'), frames)
    write_pcap(os.path.join(out, 'wimaxmacphy-coverage-malformed.pcap'), build_malformed())
    if '-v' in sys.argv:
        for l, a, b in ranges:
            print('%d-%d: %s' % (a, b, l))
        print('total', len(frames))
