#!/usr/bin/env python3
# Generates test/captures/tetra_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic TETRA coverage captures.

Usage: mktetra.py <outdir>            write the captures
       mktetra.py <outdir> --candidates   write all candidate frames
                                          (used by pick.py to choose
                                          the frames of the main capture)

The PDU contents are pseudo random bits from a fixed seed: the TETRA
MAC and NAS PDUs are PER encoded (bit packed), and random bits decode
as a valid, varied PDU tree in most cases. pick.py runs tshark on the
candidates and keeps those that decode without malformed packets or
error expert infos and that add a new field or enumerated value to the
tree. The kept candidate numbers are in SELECTED below, so this script
always writes the same capture.
"""
import random
import struct
import sys

NCAND = 200000
CHUNK = 25000

# Candidate numbers kept by pick.py (see above).
SELECTED = [0, 1, 2, 4, 5, 6, 7, 8, 9, 11, 12, 13, 14, 16, 17, 18, 19, 20, 21, 22, 24, 25, 26, 27, 28, 29, 31, 36, 38, 39, 41, 42, 43, 45, 47, 48, 49, 50, 51, 52, 55, 56, 57, 59, 60, 61, 62, 64, 65, 67, 71, 73, 74, 75, 76, 77, 78, 79, 80, 83, 86, 87, 88, 91, 94, 96, 99, 102, 105, 107, 110, 111, 112, 113, 116, 117, 119, 122, 124, 125, 126, 127, 129, 130, 131, 133, 135, 136, 138, 139, 140, 141, 143, 144, 145, 148, 149, 150, 152, 153, 155, 156, 160, 163, 170, 171, 172, 174, 175, 176, 179, 180, 181, 184, 190, 191, 194, 195, 197, 198, 203, 206, 211, 212, 213, 217, 218, 221, 223, 229, 230, 234, 240, 248, 250, 251, 255, 257, 259, 260, 265, 266, 268, 270, 271, 272, 278, 287, 288, 289, 290, 292, 300, 301, 308, 313, 323, 328, 329, 330, 339, 345, 354, 355, 360, 361, 367, 369, 370, 372, 374, 375, 379, 380, 381, 384, 391, 400, 402, 413, 415, 419, 423, 425, 426, 428, 436, 437, 438, 440, 444, 448, 449, 450, 451, 458, 470, 471, 473, 476, 480, 481, 482, 488, 490, 491, 493, 496, 499, 502, 508, 513, 514, 519, 521, 522, 523, 526, 530, 532, 535, 539, 544, 548, 554, 557, 565, 569, 579, 580, 584, 592, 594, 598, 601, 603, 606, 608, 609, 611, 614, 616, 620, 624, 626, 632, 633, 634, 641, 642, 646, 652, 659, 664, 685, 689, 693, 697, 699, 703, 711, 712, 715, 725, 733, 739, 740, 756, 765, 772, 787, 788, 793, 796, 798, 813, 816, 824, 834, 835, 836, 839, 856, 864, 866, 870, 886, 901, 907, 909, 912, 921, 939, 946, 947, 960, 961, 969, 975, 976, 983, 989, 998, 1011, 1029, 1045, 1049, 1056, 1058, 1073, 1087, 1107, 1116, 1119, 1128, 1131, 1135, 1153, 1163, 1164, 1165, 1175, 1182, 1200, 1204, 1222, 1232, 1243, 1258, 1261, 1283, 1306, 1321, 1325, 1329, 1338, 1367, 1376, 1409, 1416, 1426, 1430, 1437, 1461, 1482, 1483, 1502, 1507, 1521, 1524, 1561, 1587, 1609, 1611, 1625, 1637, 1644, 1652, 1670, 1692, 1716, 1718, 1735, 1744, 1750, 1765, 1768, 1772, 1778, 1783, 1787, 1849, 1851, 1853, 1870, 1879, 1953, 1997, 2012, 2023, 2058, 2062, 2098, 2111, 2151, 2170, 2225, 2232, 2287, 2290, 2316, 2320, 2342, 2364, 2430, 2442, 2472, 2548, 2566, 2629, 2723, 2739, 2820, 2830, 2871, 2933, 2962, 3002, 3017, 3036, 3037, 3102, 3210, 3257, 3426, 3444, 3477, 3531, 3541, 3590, 3734, 3739, 3743, 3812, 3857, 3975, 4010, 4053, 4220, 4424, 4425, 4516, 4537, 4542, 4560, 4661, 4765, 4778, 4893, 4917, 4923, 4968, 5054, 5067, 5088, 5175, 5961, 5978, 5980, 6128, 6231, 6257, 6341, 6364, 6584, 6585, 6769, 6775, 7161, 7315, 7354, 7399, 7588, 7669, 7796, 8128, 8398, 8448, 8484, 8702, 8768, 8777, 9419, 9825, 9972, 10049, 10071, 10205, 10348, 10447, 10546, 10660, 10681, 10773, 11026, 11096, 11109, 11542, 11947, 12116, 12267, 12491, 12764, 12768, 12888, 13903, 13930, 13984, 14132, 14266, 14424, 14502, 14646, 14689, 14809, 14980, 15142, 15595, 15676, 16262, 16328, 16391, 16409, 16515, 16620, 16821, 17777, 17982, 18413, 18884, 18945, 19079, 19465, 20263, 20362, 21364, 22961, 24129, 24583, 24936, 25051, 25748, 26003, 26060, 26584, 26795, 26915, 26987, 27216, 27264, 27657, 29887, 30383, 30951, 33143, 33545, 35229, 35787, 35856, 36367, 37419, 37677, 37933, 39588, 40554, 41378, 44392, 45824, 46113, 46560, 49476, 50041, 50270, 50348, 50982, 52298, 53183, 54874, 55915, 56726, 57216, 58499, 58986, 59531, 59582, 59644, 60350, 61353, 62272, 64578, 66142, 66288, 66530, 68109, 70917, 71752, 71805, 72525, 73266, 73269, 73455, 75361, 76459, 77794, 78195, 79361, 79745, 80223, 80903, 82120, 84208, 84345, 89257, 94571, 95716, 95949, 96000, 96534, 100082, 101428, 102776, 103459, 103827, 104883, 105504, 105680, 106466, 106515, 106640, 109189, 110166, 115296, 116368, 118914, 118937, 120614, 120997, 122303, 123194, 124797, 126050, 126176, 127189, 132702, 137330, 137984, 138561, 140072, 143646, 151836, 184695, 187960, 190637]
# Candidates that decode with errors; they go to the malformed capture.
REJECTED = [3, 30, 32, 34, 53, 68, 121, 157, 231, 261, 291, 305, 397, 406, 420, 424, 553, 590, 610, 617, 662, 669, 670, 672, 767, 904, 930, 1100, 1141, 1151, 1156, 1177, 1203, 1252, 1274, 1323, 1340, 1369, 1400, 1404, 1464, 1489, 1536, 1541, 1547, 1578, 1598, 1632, 1669, 1676, 1682, 1704, 1708, 1790, 1890, 1897, 1954, 1981, 1993, 2075]

# bit lengths of the PDUs per logical channel type (packet-tetra.c)
RXLEN = {1: 14, 2: 268, 3: 124, 5: 60, 6: 124, 7: 274, 8: 137, 9: 144,
         10: 288, 11: 124, 15: 92}
TXLEN = {1: 14, 2: 268, 3: 124, 5: 60, 6: 124, 7: 274, 8: 137, 9: 144,
         10: 288, 11: 124}
# GSMTAP TETRA sub types 0..8 map to these logical channels (0 = none)
GSMTAP_CHANS = {1: 5, 2: 1, 3: 15, 4: 3, 5: 2, 6: 6, 7: 11, 8: 7}


def nbytes(bits):
    return (bits + 7) // 8


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


class Cap:
    def __init__(self, path):
        self.f = open(path, 'wb')
        self.f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        self.n = 0

    def udp(self, dport, payload, sport=40000):
        self.n += 1
        udp = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), self.n, 0, 64, 17,
                         0, bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2]))
        ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
        eth = bytes.fromhex('020000000002020000000001') + b'\x08\x00' + ip + udp
        self.f.write(struct.pack('<IIII', self.n, 0, len(eth), len(eth)) + eth)

    def close(self):
        self.f.close()


def rb(r, n):
    return bytes(r.getrandbits(8) for _ in range(n))


def tetra_frame(typ, carrier, timer, regs, pdus, ind_len=None):
    """UNITDATA-REQ (1, 128) or -IND (2, 127) frame; regs is the TxR or
    RvSteR register value."""
    b = struct.pack('<BBI', typ, carrier, timer)
    if typ in (2, 127):
        # the length word precedes RvSteR
        b += struct.pack('<I', ind_len if ind_len is not None else sum(map(len, pdus)))
    b += struct.pack('<I', regs)
    return b + b''.join(pdus)


def req_regs(types):
    """TxR for 1-3 channels."""
    n = len(types)
    if n == 1:
        return 0 | (types[0] << 2)
    if n == 2:
        return 1 | (types[0] << 6) | (types[1] << 10)
    return 2 | (types[0] << 2) | (types[1] << 6) | (types[2] << 10)


def ind_regs(types, crc=0):
    v = len(types)
    for i, t in enumerate(types):
        v |= t << ((i + 1) * 4)
    return v | (crc << 2)


def timer_value(r):
    # the slot number is bits 11-14; 4 and 8 are remapped to 3 and 4
    slot = r.choice([0, 1, 2, 4, 8, 3, 5])
    return (r.getrandbits(32) & ~0x7800) | (slot << 11)


def candidate(i):
    """Return (kind, payload, dport)."""
    r = random.Random(i * 7919 + 13)
    k = r.random()
    if k < 0.35:      # GSMTAP TETRA (UDP 4729, downlink)
        sub = r.choice(list(GSMTAP_CHANS))
        lch = GSMTAP_CHANS[sub]
        hdr = struct.pack('!BBBBHbbIBBBB', 2, 4, 5, r.getrandbits(3), 0, -60, 10,
                          r.getrandbits(32), sub, 0, 0, 0)
        return 'gsmtap', hdr + rb(r, nbytes(RXLEN[lch])), 4729
    if k < 0.65:      # UNITDATA-REQ
        n = r.choice([1, 1, 1, 2, 3])
        types = [r.choice(list(TXLEN)) for _ in range(n)]
        pdus = [rb(r, nbytes(TXLEN[t])) for t in types]
        typ = r.choice([1, 1, 128])
        return 'req', tetra_frame(typ, r.randrange(256), timer_value(r),
                                  req_regs(types) | (r.getrandbits(18) << 14),
                                  pdus), 7074
    # UNITDATA-IND
    n = r.choice([1, 1, 1, 2, 3])
    types = [r.choice(list(RXLEN)) for _ in range(n)]
    pdus = []
    for t in types:
        pdus.append(rb(r, nbytes(RXLEN[t])))
    typ = r.choice([2, 2, 127])
    return 'ind', tetra_frame(typ, r.randrange(256), timer_value(r),
                              ind_regs(types, r.getrandbits(1)) | (r.getrandbits(16) << 16), pdus), 7074


def write_main(path, nums):
    c = Cap(path)
    for i in nums:
        kind, payload, dport = candidate(i)
        c.udp(dport, payload)
    # carrier numbers, timer and unknown types without a PDU
    r = random.Random(4242)
    for typ in (3, 3, 9, 200):
        c.udp(7074, struct.pack('<BBI', typ, 7, timer_value(r)) + rb(r, 8))
    # GSMTAP frames whose TETRA channel is not decoded: none (0) and
    # the burst type
    hdr = struct.pack('!BBBBHbbIBBBB', 2, 4, 5, 0, 0, -60, 10, 1, 0, 0, 0, 0)
    c.udp(4729, hdr + rb(r, 20))
    c.close()
    return c.n


def write_malformed(path, rejected):
    c = Cap(path)
    r = random.Random(777)
    # candidates that did not decode cleanly (PER errors, truncation)
    for i in rejected:
        kind, payload, dport = candidate(i)
        c.udp(dport, payload)
    # frames too short for the header
    for n in (1, 2, 5, 9):
        c.udp(7074, bytes([1, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])[:n])
    # UNITDATA-REQ with the channel count field 3 (4 channels): warning
    c.udp(7074, tetra_frame(1, 1, 0, 3 | (5 << 2) | (6 << 6) | (1 << 10), [rb(r, 8), rb(r, 16), rb(r, 2)]))
    # UNITDATA-REQ with a channel type that has no length (SCH/HU = 15,
    # TCH/2.4 = 9 is fine) and unknown types
    c.udp(7074, tetra_frame(1, 1, 0, req_regs([15]), [rb(r, 4)]))
    c.udp(7074, tetra_frame(1, 1, 0, req_regs([4]), [rb(r, 4)]))
    c.udp(7074, tetra_frame(1, 1, 0, req_regs([0, 12]), [rb(r, 4)]))
    # IND with unknown types (no PDU bytes), and every channel truncated
    c.udp(7074, tetra_frame(2, 1, 0, ind_regs([4, 12, 13]), [rb(r, 3)]))
    for t, ln in ((1, 1), (2, 10), (3, 5), (5, 3), (6, 5), (7, 20), (11, 6), (15, 4)):
        c.udp(7074, tetra_frame(2, 1, 0, ind_regs([t]), [rb(r, ln)]))
        c.udp(7074, tetra_frame(1, 1, 0, req_regs([t]), [rb(r, ln)]))
    # GSMTAP with empty and short TETRA payloads, and the maximum channel
    for sub in range(1, 9):
        hdr = struct.pack('!BBBBHbbIBBBB', 2, 4, 5, 0, 0, -60, 10, 1, sub, 0, 0, 0)
        c.udp(4729, hdr)
        c.udp(4729, hdr + rb(r, 1))
        c.udp(4729, hdr + rb(r, 3))
    hdr = struct.pack('!BBBBHbbIBBBB', 2, 4, 5, 0, 0, -60, 10, 1, 9, 0, 0, 0)
    c.udp(4729, hdr + rb(r, 20))
    c.close()
    return c.n


if __name__ == '__main__':
    out = sys.argv[1]
    if len(sys.argv) > 2 and sys.argv[2] == '--candidates':
        first = int(sys.argv[3])
        c = Cap(out + '/candidates.pcap')
        for i in range(first, min(first + CHUNK, NCAND)):
            kind, payload, dport = candidate(i)
            c.udp(dport, payload)
        c.close()
        sys.exit(0)
    print('main', write_main(out + '/tetra-coverage.pcap', SELECTED))
    print('malformed', write_malformed(out + '/tetra-coverage-malformed.pcap', REJECTED))
