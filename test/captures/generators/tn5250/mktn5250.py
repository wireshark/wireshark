#!/usr/bin/env python3
# Generates test/captures/tn5250_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic TN5250 coverage captures.

Usage: mktn5250.py <outdir> [--cand]

Writes tn5250-coverage.pcap (valid data only) and
tn5250-coverage-malformed.pcap.  With --cand it writes cand.pcap with
every candidate record (used by select5250.py to choose the KEEP table
below; not part of the deliverables).

All packets are built with struct.  Records for which no hand-built
layout exists are drawn from a PRNG seeded by the (kind, key, trial)
triple, and only the triples that decode cleanly (select5250.py) are
kept in KEEP.
"""
import os
import random
import struct
import sys

CLI = bytes.fromhex('020000000001'); SRV = bytes.fromhex('020000000002')
CIP = bytes([10, 0, 0, 1]); SIP = bytes([10, 0, 0, 2])

IAC, DONT, DO, WONT, WILL, SB, SE, EOR_CMD = 255, 254, 253, 252, 251, 250, 240, 239
OPT_BINARY, OPT_TTYPE, OPT_EOR, OPT_TN3270E = 0, 24, 25, 40


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


class Conn:
    def __init__(self, cport, sport=23, t0=1700000000):
        self.cport, self.sport = cport, sport
        self.cseq, self.sseq = 1000, 5000
        self.pkts = []
        self.t = t0 + cport

    def _pkt(self, from_cli, payload):
        if from_cli:
            src, dst, sp, dp, seq, ack = CIP, SIP, self.cport, self.sport, self.cseq, self.sseq
            self.cseq += len(payload)
            smac, dmac = CLI, SRV
        else:
            src, dst, sp, dp, seq, ack = SIP, CIP, self.sport, self.cport, self.sseq, self.cseq
            self.sseq += len(payload)
            smac, dmac = SRV, CLI
        tcp = struct.pack('!HHIIBBHHH', sp, dp, seq, ack, 0x50, 0x18, 65535, 0, 0) + payload
        ph = src + dst + struct.pack('!BBH', 0, 6, len(tcp))
        tcp = tcp[:16] + struct.pack('!H', csum(ph + tcp)) + tcp[18:]
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0, src, dst)
        ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
        self.pkts.append((self.t, dmac + smac + b'\x08\x00' + ip + tcp))
        self.t += 1

    def cli(self, p): self._pkt(True, p)
    def srv(self, p): self._pkt(False, p)


def sb(opt, data):
    return bytes([IAC, SB, opt]) + data + bytes([IAC, SE])


def telnet_start(c, ttype):
    """Telnet negotiation of a TN3270 session (TERMINAL-TYPE, EOR, BINARY)."""
    c.srv(bytes([IAC, DO, OPT_TTYPE]))
    c.cli(bytes([IAC, WILL, OPT_TTYPE]))
    c.srv(sb(OPT_TTYPE, b'\x01'))
    c.cli(sb(OPT_TTYPE, b'\x00' + ttype))
    c.srv(bytes([IAC, DO, OPT_EOR, IAC, WILL, OPT_EOR]))
    c.cli(bytes([IAC, WILL, OPT_EOR, IAC, DO, OPT_EOR]))
    c.srv(bytes([IAC, DO, OPT_BINARY, IAC, WILL, OPT_BINARY]))
    c.cli(bytes([IAC, WILL, OPT_BINARY, IAC, DO, OPT_BINARY]))


def write_pcap(fn, pkts):
    with open(fn, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for (t, p) in pkts:
            f.write(struct.pack('<IIII', t, 0, len(p), len(p)))
            f.write(p)


import re


def rec(data, ff_pairs=False):
    # telnet hands the data with any escaped IAC still doubled to TN5250,
    # so a record must not contain a lone 0xFF; an escaped pair (FF FF)
    # is read by tn5250_add_hf_items as one value
    if ff_pairs:
        assert all(len(m) % 2 == 0 for m in re.findall(b'\xff+', data)), 'single 0xFF'
    else:
        assert b'\xff' not in data
    return data + bytes([IAC, EOR_CMD])


def H(h):
    return bytes.fromhex(h.replace(' ', ''))


def eb(text):
    return text.encode('cp037')


def gds(body, flags=0, b8=0, op=3, length=None):
    """GDS header (10 octets) and body."""
    if length is None:
        length = 10 + len(body)
    return struct.pack('!HHHBBBB', length, 0x12A0, 0, 4, flags, b8, op) + body


ESC = b'\x04'

# ------------------------------------------------------------ candidates
CMDS = [0x40, 0x20, 0x50, 0x42, 0x52, 0x82, 0x62, 0x64, 0x66, 0x68, 0x6A, 0x6C, 0x72, 0x83, 0x02, 0x03,
        0x12, 0x13, 0x23, 0x16, 0x22, 0x21]
ORDERS = [0x13, 0x14, 0x11, 0x02, 0x03, 0x01, 0x10, 0x12, 0x1D, 0x15]
WDSF = [0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x58, 0x59, 0x5B, 0x5F, 0x60, 0x61, 0x99]
WSF = [0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3F, 0x70, 0x72, 0x99]
WSSF = [0x66, 0x67, 0x68, 0x6A, 0x71, 0x99]
AIDS = [0xBD, 0xF1, 0xF3, 0xF4, 0xF5, 0xD9, 0xDA, 0xF6, 0xF8, 0x3F, 0x50, 0x6C, 0x6E, 0x6B] + \
    list(range(0x31, 0x3D)) + list(range(0xB1, 0xBD)) + [0x88]
# (kind, key) of every candidate group
GROUPS = ([('cmd', c) for c in CMDS] + [('wtd', c) for c in ORDERS] + [('wdsf', c) for c in WDSF] +
          [('wsf', c) for c in WSF] + [('wssf', c) for c in WSSF] + [('in', a) for a in AIDS] +
          [('wec', 0)])

# Extra heads (prefixes) per group: the header of a structured field or
# order with the layout that the dissector reads, followed by the seeded
# fill.  The first (empty) prefix of every group is implicit.
_R = lambda n, k=1: bytes((k * 37 + i * 11 + 3) % 200 + 1 for i in range(n))
_CWB = H('0d 01') + _R(11)
_CWT = H('09 10') + _R(4, 2) + eb('abc')
PREFIX = {
    ('wdsf', 0x51): [_R(5, 3) + x for x in (_CWB, _CWT, _CWB + _CWT, _CWT + _CWB, H('05 10') + _R(4, 5), H('0d 01'))],
    ('wdsf', 0x50): [_R(24, 4) + x for x in (H('10 10 01'), H('0f 10 02'), H('0c 10 00'), H('0b 10 41'), H('09 09'),
                     H('13 01'), H('06 02'), H('0b 03'), H('13 01') + H('06 02') + H('0b 03'), H('03 10 00'))],
    ('wdsf', 0x53): [_R(11, 6) + x for x in (H('0b 03'), H('0b 03 0b 03'), H('0a 09'))],
    ('wdsf', 0x60): [_R(7, 7) + x for x in (H('0a 00'), H('0a 04'), H('0a 07'), H('0a 03 0a 05'), H('0a 09'))],
    ('wdsf', 0x54): [H('01 02') + _R(4, 8), H('01 02')],
    ('wdsf', 0x55): [H('00 00') + _R(8, 9), H('00 00') + _R(4, 9), H('00 00')],
    ('wdsf', 0x52): [H('00 00')], ('wdsf', 0x58): [H('00 00')], ('wdsf', 0x5B): [H('00 00')],
    ('cmd', 0x13): [H('00 06'), H('00 04 11 05 0a'), H('00 02'), H('00 03 13 05 0a'), H('00 06 14 01 01')],
    ('wtd', 0x10): [H('40 08 00 04'), H('40 08 00 09'), H('40 08 00 00')],
    ('wtd', 0x03): [H('40 08 05 0a 03'), H('40 08 05 0a 01'), H('40 08 05 0a 05'), H('40 08 05 0a 02')],
    ('wsf', 0x36): [_R(8, 10) + bytes([n]) for n in (11, 15, 25, 40, 5)],
    ('in', 0x88): [_R(1)],
    ('cmd', 0x03): [H('06 00 01 01 18 50'), H('09 00 01 01 18 50'), H('0c 80 01 01 18 50')],
    ('wtd', 0x1D): [H('40 08') + H('40 20') + f + H('20 0005') for f in
                    (H('8101'), H('8101 8200 8501'), H('8101 8200 8501 8601 B140 8001 8801 8901 8A01 8401'), H('B1A0 8000'))] +
                   [H('40 08') + H('40 20') + H('8101') + H('01 0005'), H('40 08') + H('00 20') + H('20 0005'),
                    H('40 08') + H('00 00 21 0005')],
    ('wssf', 0x67): [_R(6, 12) + H('0003') + eb('abc'), _R(6, 13) + H('0000'), _R(6, 14) + H('0002') + eb('ab')],
    ('wssf', 0x71): [_R(2, 15) + x for x in (H('03 01 41'), H('03 02 41'), H('03 01 41 03 02 42'), H('03 02 41 03 01 42'),
                     H('03 09 41'))],
    ('wssf', 0x66): [_R(16, 16)],
    ('wssf', 0x6A): [H('41') + _R(3, 17)],
    ('wsf', 0x3B): [_R(3, 18) + x for x in (H('04 80 01 02'), H('06 40 01 02 03 04'), H('04 80 01 02 06 40 01 02 03 04'),
                    H('06 40 01 02 03 04 04 80 01 02'), H('03 99 01'), H('03 99 01 04 80 01 02'), H('20 99'))],
    ('wsf', 0x30): [_R(1, 19) + x for x in (H('01 41'), H('04 41 42 43 04 44 45 46'), H('02 41 02 42'), H('00 00'))],
    ('wsf', 0x31): [_R(1, 20) + x for x in (H('01 41 42'), H('05 41 42 43 44'), H('00 41 42'))],
    ('wsf', 0x39): [_R(1, 21) + x for x in (H('01 41 42'), H('05 41 42 43 44'), H('00 41 42'))],
    ('wsf', 0x35): [_R(4, 22) + H('01 02 03 04 05')],
    ('wsf', 0x3A): [_R(1, 23) + H('01') + eb('1234') + H('02') + eb('5678'), _R(1, 23)],
}


def cand_record(kind, key, trial):
    """Returns (direction, record data (GDS header and body))."""
    pre = [b''] + PREFIX.get((kind, key), [])
    p, v = divmod(trial, 256)
    r = random.Random('%s:%d:%d' % (kind, key, trial))
    L = v % 64
    fill = bytes(r.randrange(255) for _ in range(L))
    fill = pre[p] + fill
    if kind == 'cmd':
        return 'o', gds(ESC + bytes([key]) + fill)
    if kind == 'wec':
        return 'o', gds(ESC + b'\x21' + fill)
    if kind == 'wtd':
        return 'o', gds(ESC + b'\x11' + fill[:2].ljust(2, b'\x40') + bytes([key]) + fill[2:])
    if kind in ('wdsf', 'wsf', 'wssf'):
        n = 4 + len(fill)
        sfd = struct.pack('!H', n) + b'\xd9' + bytes([key]) + fill
        if kind == 'wdsf':
            return 'o', gds(ESC + b'\x11\x40\x08' + b'\x15' + sfd)
        return 'o', gds(ESC + (b'\xf3' if kind == 'wsf' else b'\xf4') + sfd)
    if kind == 'in':
        return 'i', gds(bytes([r.randrange(1, 24), r.randrange(1, 80), key]) + fill)
    raise ValueError(kind)


def ntrials(kind, key):
    return 256 * (1 + len(PREFIX.get((kind, key), [])))


KEEP = {
    ('cmd', 0x2): [0],
    ('cmd', 0x3): [6, 113, 256, 515, 774],
    ('cmd', 0x12): [0],
    ('cmd', 0x13): [324, 656, 721, 768, 867, 804, 1415],
    ('cmd', 0x16): [2],
    ('cmd', 0x20): [1],
    ('cmd', 0x21): [2, 33, 63],
    ('cmd', 0x22): [2],
    ('cmd', 0x23): [3],
    ('cmd', 0x40): [0],
    ('cmd', 0x42): [2],
    ('cmd', 0x50): [0],
    ('cmd', 0x52): [2],
    ('cmd', 0x62): [0],
    ('cmd', 0x64): [0],
    ('cmd', 0x66): [0],
    ('cmd', 0x68): [0],
    ('cmd', 0x6A): [0],
    ('cmd', 0x6C): [0],
    ('cmd', 0x72): [0],
    ('cmd', 0x82): [2],
    ('cmd', 0x83): [0],
    ('in', 0x31): [0, 32, 63],
    ('in', 0x32): [0, 32, 63],
    ('in', 0x33): [0, 32, 63],
    ('in', 0x34): [0, 96, 63],
    ('in', 0x35): [0, 32, 63],
    ('in', 0x36): [0, 32, 63],
    ('in', 0x37): [0, 32, 63],
    ('in', 0x38): [0, 32, 63],
    ('in', 0x39): [0, 32, 63],
    ('in', 0x3A): [0, 32, 63],
    ('in', 0x3B): [0, 32, 63],
    ('in', 0x3C): [0, 32, 63],
    ('in', 0x3F): [0, 32, 63],
    ('in', 0x50): [0, 32, 63],
    ('in', 0x6B): [0, 32, 63],
    ('in', 0x6C): [0, 32, 63],
    ('in', 0x6E): [0, 32, 63],
    ('in', 0x88): [58, 62, 63, 313, 317, 319],
    ('in', 0xB1): [0, 32, 63],
    ('in', 0xB2): [0, 32, 63],
    ('in', 0xB3): [0, 32, 63],
    ('in', 0xB4): [0, 32, 63],
    ('in', 0xB5): [0, 32, 63],
    ('in', 0xB6): [0, 32, 63],
    ('in', 0xB7): [0, 32, 63],
    ('in', 0xB8): [0, 32, 63],
    ('in', 0xB9): [0, 32, 63],
    ('in', 0xBA): [0, 32, 63],
    ('in', 0xBB): [0, 32, 63],
    ('in', 0xBC): [0, 32, 63],
    ('in', 0xBD): [0, 32, 63],
    ('in', 0xD9): [0, 32, 63],
    ('in', 0xDA): [0, 32, 63],
    ('in', 0xF1): [0, 32, 63],
    ('in', 0xF3): [0, 32, 63],
    ('in', 0xF4): [0, 32, 63],
    ('in', 0xF5): [0, 32, 63],
    ('in', 0xF6): [0, 32, 127],
    ('in', 0xF8): [0, 32, 63],
    ('wdsf', 0x50): [0, 24, 48, 269, 293, 317, 524, 548, 572, 777, 938, 825, 1032, 1056, 1080, 1287, 1311, 1335, 1553, 1577, 1796, 1820, 1844, 2057, 2081, 2105, 2317, 2341, 2365, 2567, 2591, 2615],
    ('wdsf', 0x51): [0, 33, 63, 256, 291, 511, 512, 547, 572, 768, 803, 828, 1024, 1121, 1084, 1280, 1315, 1340, 1547, 1572, 1597],
    ('wdsf', 0x52): [0, 32, 63, 256, 288, 319],
    ('wdsf', 0x53): [0, 33, 55, 265, 287, 309, 519, 552, 574, 777, 799, 821],
    ('wdsf', 0x54): [0, 32, 63, 256, 288, 319, 512, 544, 575],
    ('wdsf', 0x55): [0, 30, 62, 256, 288, 316, 512, 544, 572, 768, 800, 828],
    ('wdsf', 0x58): [0, 32, 63, 256, 288, 319],
    ('wdsf', 0x59): [0, 33, 63],
    ('wdsf', 0x5B): [0, 32, 63, 256, 288, 319],
    ('wdsf', 0x5F): [0, 33, 63],
    ('wdsf', 0x60): [0, 102, 127, 264, 292, 316, 520, 544, 569, 776, 999, 828, 1030, 1065, 1086, 1285, 1387, 1341],
    ('wdsf', 0x61): [0, 30, 60],
    ('wdsf', 0x99): [0, 32, 63],
    ('wec', 0x0): [2, 33, 63],
    ('wsf', 0x30): [1, 141, 244, 256, 768, 1005, 1022, 1024],
    ('wsf', 0x31): [1, 48, 58, 256, 513, 653, 633, 768],
    ('wsf', 0x32): [4],
    ('wsf', 0x33): [10],
    ('wsf', 0x34): [10],
    ('wsf', 0x35): [4, 34, 59, 256, 286, 316],
    ('wsf', 0x36): [266, 526, 792, 1063, 1290],
    ('wsf', 0x37): [5],
    ('wsf', 0x38): [0, 32, 63],
    ('wsf', 0x39): [1, 218, 179, 256, 513, 515, 766, 768],
    ('wsf', 0x3A): [1, 31, 61, 256, 286, 316, 512, 542, 572],
    ('wsf', 0x3B): [3, 77, 256, 336, 367, 512, 585, 768, 921, 1024, 1220, 1815],
    ('wsf', 0x3F): [0, 32, 63],
    ('wsf', 0x70): [1],
    ('wsf', 0x72): [2],
    ('wsf', 0x99): [0, 32, 63],
    ('wssf', 0x66): [0, 39, 63, 256, 288, 319],
    ('wssf', 0x67): [0, 256, 288, 319, 512, 544, 575, 768, 800, 831],
    ('wssf', 0x68): [0, 30, 60],
    ('wssf', 0x6A): [0, 32, 63, 256, 288, 319],
    ('wssf', 0x71): [0, 100, 63, 256, 355, 319, 512, 614, 574, 768, 933, 831, 1024, 1058, 1151, 1281, 1380, 1343],
    ('wssf', 0x99): [0, 32, 63],
    ('wtd', 0x1): [10, 46, 53],
    ('wtd', 0x2): [4, 32, 127],
    ('wtd', 0x3): [258, 279, 355, 512, 671, 698, 772, 785, 1008, 1025, 1102, 1106],
    ('wtd', 0x10): [258, 278, 373, 519, 657, 688, 768, 977, 992],
    ('wtd', 0x11): [4, 33, 191],
    ('wtd', 0x12): [3, 96, 187],
    ('wtd', 0x13): [4, 31, 126],
    ('wtd', 0x14): [4, 158, 189],
    ('wtd', 0x1D): [5, 33, 255, 256, 282, 447, 512, 542, 639, 768, 795, 959, 1024, 1117, 1086, 1280, 1306, 1407, 1536, 1692, 1791, 1792, 1950, 1983],
}


def make_cand(outdir):
    c = Conn(51000)
    telnet_start(c, b'IBM-3179-2')
    index = []
    for kind, key in GROUPS:
        for trial in range(ntrials(kind, key)):
            d, data = cand_record(kind, key, trial)
            (c.srv if d == 'o' else c.cli)(rec(data, True))
            index.append((len(c.pkts), kind, key, trial))
    write_pcap(os.path.join(outdir, 'cand.pcap'), c.pkts)
    with open(os.path.join(outdir, 'cand.idx'), 'w') as f:
        for e in index:
            f.write('%d %s %d %d\n' % e)


TTYPES = [b'IBM-5555-C01', b'IBM-5555-B01', b'IBM-3477-FC', b'IBM-3477-FG', b'IBM-3180-2', b'IBM-3179-2',
          b'IBM-3196-A1', b'IBM-5292-2', b'IBM-5291-1', b'IBM-5251-11']


def ttype_only(c, name):
    c.srv(bytes([IAC, DO, OPT_TTYPE]))
    c.cli(bytes([IAC, WILL, OPT_TTYPE]))
    c.srv(sb(OPT_TTYPE, b'\x01'))
    c.cli(sb(OPT_TTYPE, b'\x00' + name))


def wtd(orders, ccc=b'\x40\x08'):
    return ESC + b'\x11' + ccc + orders


def sba(r, c):
    return b'\x11' + bytes([r, c])


def hand_frames():
    """Hand built server to client records (header flags, byte 8, op, body)."""
    out = []
    out.append(gds(ESC + b'\x40', op=2))                                   # Clear Unit
    out.append(gds(ESC + b'\x20\x00'))                                     # Clear Unit Alternate
    out.append(gds(ESC + b'\x50'))                                         # Clear Format Table
    out.append(gds(wtd(sba(1, 1) + eb('Sign On') + sba(3, 10) + eb('User'))))
    out.append(gds(wtd(b'\x13\x05\x0a')))                                  # Insert Cursor
    out.append(gds(wtd(b'\x14\x05\x0a' + eb('mc'))))                       # Move Cursor
    out.append(gds(wtd(b'\x02\x05\x0a' + eb('-'))))                        # Repeat to Address
    out.append(gds(wtd(b'\x10\x00\x03' + eb('abc'))))                      # Transparent Data
    out.append(gds(wtd(b'\x12\x01\x20')))                                  # Write Extended Attribute
    out.append(gds(wtd(b'\x12\x03\xf1')))
    out.append(gds(wtd(b'\x12\x05\x01')))
    # header variants: flags, byte 8 with the HLP bit (adds an error code item), operation codes
    for flags in (0x00, 0x80, 0x40, 0x20, 0x10, 0x08, 0xF8):
        out.append(gds(wtd(sba(2, 2) + eb('hdr')), flags=flags, b8=0x00))
    for b8 in (0x02, 0x03):
        out.append(gds(wtd(sba(2, 2) + eb('hdr')), b8=b8))
    for op in (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13):
        out.append(gds(wtd(sba(2, 2) + eb('op')), op=op))
    # Restore Screen with nested commands (at most 4 nested Restore Screens)
    for depth in range(0, 4):
        out.append(gds(ESC + b'\x12' + (ESC + b'\x12') * depth + ESC + b'\x40'))
    out.append(gds(ESC + b'\x12' + ESC + b'\x40' + ESC + b'\x50'))
    # reproducer of the offsets fix: Pass-Through and True Transparency Write with correct lengths
    data = b'\xc8\xc5\xd3\xd3\xd6\x40\xe6\xd6\xd9\xd3'
    out.append(gds(ESC + b'\xf3' + struct.pack('!HBB', 4 + len(data), 0xD9, 0x3F) + data))
    out.append(gds(ESC + b'\xf4' + struct.pack('!HBB', 4 + 2 + 1 + len(data), 0xD9, 0x6A) + b'\x00\x00' + b'\x00' + data))
    # structured fields whose length field is shorter than the fixed part
    for t, body in ((0x54, H('01 02')), (0x55, H('00 00')), (0x3F, b''), (0x6A, b'')):
        if t in (0x54, 0x55):
            out.append(gds(wtd(b'\x15' + struct.pack('!HBB', 5, 0xD9, t) + body)))
        elif t == 0x3F:
            out.append(gds(ESC + b'\xf3' + struct.pack('!HBB', 3, 0xD9, t)))
        else:
            out.append(gds(ESC + b'\xf4' + struct.pack('!HBB', 4, 0xD9, t) + b'\x00'))
    # unknown command codes (warning)
    for cmd in (0x00, 0x99, 0x44):
        out.append(gds(ESC + bytes([cmd])))
    # ESC FF FF: an escaped 0xFF in the WCC and in a field
    out.append(gds(ESC + b'\x11' + b'\xff\xff\x08' + sba(3, 3) + eb('ff'), ), )
    return out


def inbound_hand():
    out = []
    for aid in AIDS:
        if aid == 0x88:
            continue
        out.append(gds(bytes([5, 7, aid]) + eb('input'), flags=0))
    out.append(gds(bytes([5, 7, 0xF1])))
    out.append(gds(bytes([5, 7, 0xF1]) + b'\x11\x06\x07' + eb('x')))
    out.append(gds(H('00 05'), flags=0x01))                                   # error code
    out.append(gds(H('08 11 02 00'), flags=0x80))                            # negative responses
    out.append(gds(H('10 03 01 00'), flags=0x80))
    out.append(gds(H('10 05 01 00'), flags=0x80))
    out.append(gds(H('10 05 02 00'), flags=0x80))
    out.append(gds(H('00 00 00 01'), flags=0x80))
    # a non-AID inbound record that carries a command (ESC) and one that does not
    out.append(gds(ESC + b'\x40\x00'))
    out.append(gds(ESC + b'\x40' + eb('extra')))
    out.append(gds(eb('plain field data')))
    out.append(gds(H('05 07 ff ff') + eb('pass'), ))                         # AID FF: pass-through response
    return out


def build_main():
    pk = []
    bad = []
    c = Conn(50001)
    telnet_start(c, b'IBM-3179-2')
    for d in hand_frames():
        c.srv(rec(d, True))
    for d in inbound_hand():
        c.cli(rec(d, True))
    for (kind, key), trials in sorted(KEEP.items()):
        for trial in trials:
            d, data = cand_record(kind, key, trial)
            (c.srv if d == 'o' else c.cli)(rec(data, True))
    # records split over several TCP segments (Telnet reassembles them):
    # the first segments carry no IAC at all
    scr = gds(wtd(sba(1, 1) + eb('split record that goes over segments ') * 3))
    for cut in ((20,), (15, 40, 70)):
        pos = 0
        for k in cut:
            c.srv(scr[pos:k])
            pos = k
        c.srv(rec(scr[pos:]))
    inp = gds(bytes([5, 7, 0xF1]) + eb('split input record ') * 2)
    c.cli(inp[:15])
    c.cli(rec(inp[15:]))
    # two records in one segment
    c.srv(rec(gds(ESC + b'\x40')) + rec(gds(ESC + b'\x50')))
    pk += c.pkts
    for n, t in enumerate(TTYPES):
        c = Conn(50010 + n)
        ttype_only(c, t)
        c.srv(rec(gds(ESC + b'\x40'), True))
        c.srv(rec(gds(wtd(sba(1, 1) + eb('screen'))), True))
        c.cli(rec(gds(bytes([1, 1, 0xF1]) + eb('x')), True))
        pk += c.pkts

    # ---------------------------------------------------- malformed capture
    c = Conn(50100)
    ttype_only(c, b'IBM-3179-2')
    # Restore Screen nested past the limit of 4 (the reproducer of the
    # nesting fix has 600 levels)
    for depth in (4, 5, 8, 50, 600):
        c.srv(rec(gds(ESC + b'\x12' + (ESC + b'\x12') * depth + ESC + b'\x40'), True))
    # inbound record whose first command is a Restore Screen chain
    c.cli(rec(gds(b'\x00\x00\x00' + (ESC + b'\x12') * 8 + ESC + b'\x40'), True))
    # Define Fake DP Command Key Function with an unknown minor structure
    c.srv(rec(gds(ESC + b'\xf3' + struct.pack('!HBB', 4 + 3 + 3, 0xD9, 0x3B) + _R(3, 18) + H('03 99 01')), True))
    # one truncated record per group (last octet missing)
    for (kind, key), trials in sorted(KEEP.items()):
        d, data = cand_record(kind, key, trials[-1])
        (c.srv if d == 'o' else c.cli)(rec(data[:-1], True))
    # short records
    for body in (b'', b'\x04', b'\x04\x11', b'\x04\x11\x40', b'\x04\x11\x40\x08\x11\x05',
                 b'\x04\x11\x40\x08\x10\x00\x20' + eb('ab'), b'\x04\x13\x00\x20',
                 b'\x04\xf3\x00\x20\xd9\x3f', b'\x04\xf4\x00\x20\xd9\x67' + b'\x01' * 8):
        c.srv(rec(gds(body), True))
    c.cli(rec(gds(b'\x05'), True))
    c.cli(rec(gds(b'\x05\x07'), True))
    c.cli(rec(gds(b'\x01\x01\xf1\x11\x05'), True))
    c.cli(rec(gds(b'\x00', flags=0x01), True))
    c.cli(rec(gds(b'\x00\x00', flags=0x80), True))
    c.srv(rec(H('00 0a 12 a0'), True))                                       # header cut short
    bad += c.pkts
    return pk, bad


def exported_pdu_pcapng(fn, names, payload=b'\x04\x40'):
    """Exported PDU file (link type 252) whose frames name the TN5250
    dissector: it needs a conversation made by Telnet and does nothing."""
    def block(t, body):
        body += b'\0' * (-len(body) % 4)
        return struct.pack('<II', t, len(body) + 12) + body + struct.pack('<I', len(body) + 12)
    out = block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    out += block(1, struct.pack('<HHI', 252, 0, 65535))
    for n, name in enumerate(names):
        nb = name.encode()
        tlv = struct.pack('!HH', 12, len(nb)) + nb + b'\0' * (-len(nb) % 4) + struct.pack('!HH', 0, 0)
        d = tlv + payload
        out += block(6, struct.pack('<IIIII', 0, 1000 + n, 0, len(d), len(d)) + d)
    open(fn, 'wb').write(out)


if __name__ == '__main__':
    outdir = sys.argv[1]
    if '--cand' in sys.argv:
        make_cand(outdir)
        sys.exit(0)
    main, bad = build_main()
    write_pcap(os.path.join(outdir, 'tn5250-coverage.pcap'), main)
    write_pcap(os.path.join(outdir, 'tn5250-coverage-malformed.pcap'), bad)
    exported_pdu_pcapng(os.path.join(outdir, 'tn5250-coverage-exppdu.pcapng'), ['tn5250'])
    print(len(main), len(bad))
