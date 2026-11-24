#!/usr/bin/env python3
# Generates test/captures/tn3270_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic TN3270 / TN3270E coverage captures.

Usage: mktn3270.py <outdir> [--cand]

Writes tn3270-coverage.pcap (valid data only) and
tn3270-coverage-malformed.pcap.  With --cand it writes cand.pcap with
every candidate structured field body (used by select3270.py to choose
the KEEP table below; not part of the deliverables).

All packets are built with struct.  Structured field bodies for which
no hand-built layout exists are drawn from a PRNG seeded by the
(direction, structured field id, trial) triple, and only the triples
that decode cleanly (select3270.py) are kept in KEEP.
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


def rec(data, ff_pairs=False):
    # telnet hands the data with any escaped IAC still doubled to TN3270,
    # so a record must not contain 0xFF at all
    if ff_pairs:
        import re
        assert all(len(m) % 2 == 0 for m in re.findall(b'\xff+', data)), 'single 0xFF'
    else:
        assert b'\xff' not in data
    return data + bytes([IAC, EOR_CMD])


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


# ---------------------------------------------------------------- tables
IB = [0x0F22, 0x0FB1, 0x0F80, 0x1031, 0x0FC1, 0x8184, 0x8199, 0x819F, 0x8185, 0x8186, 0x81AB, 0x8198,
      0x81A2, 0x8191, 0x81A0, 0x8195, 0x8197, 0x81B5, 0x818C, 0x818A, 0x8190, 0x8194, 0x81B4, 0x81B6,
      0x8187, 0x819E, 0x8182, 0x81A6, 0x81AA, 0x81B2, 0x818B, 0x81FF, 0x818F, 0x81A7, 0x818E, 0x81B3,
      0x81B1, 0x819C, 0x8188, 0x81A1, 0x8192, 0x81B0, 0x81A9, 0x8196, 0x8180, 0x8183, 0x81A8, 0x8181,
      0x819A]
OB = [0x0E, 0x0F85, 0x0C, 0x0D, 0x03, 0x0F05, 0x0F24, 0x0F07, 0x06, 0x0F0A, 0x0F71, 0x40, 0x4B, 0x4C,
      0x0F08, 0x09, 0x0FC1, 0x01, 0x1030, 0x00, 0x1033, 0x41, 0x0F04, 0x4A, 0x1032, 0x0F01, 0x0F84, 0x0B]
OBIB = [0x0F21, 0x0F02, 0x0F11, 0x0F0F, 0x0F10, 0x0F1F, 0x1034, 0x0F83]


def sfid(i):
    return bytes([i]) if i < 0x100 else struct.pack('!H', i)


def sf(i, body):
    return struct.pack('!H', 2 + len(sfid(i)) + len(body)) + sfid(i) + body


def H(h):
    return bytes.fromhex(h.replace(' ', ''))


def _eb(t):
    return t.encode('cp037')


_LFS = lambda op: bytes([0, 0, op]) + _eb('LOCALNAM') + _eb('GRP001') + _eb('FORMATNAME000001')
_TXT = _eb('abc') + b'\x11\x40\x40' + _eb('de')
_SDP_EX = [H('06 01 41 42 43'), H('04 02 41 42'), H('22 03') + _eb('FAILFORMAT000001') + _eb('FORMATNAME000002'),
           H('0c 04 0001 0002 0003 00000004'), H('14 05') + _eb('GROUPNAME0000001') + H('0007')]
_HDR_OEM = H('00 01') + _eb('DEVNAME ') + _eb('USER    ')
_HDR_IBM = H('00 01 0102 0304 05')
_SD11 = lambda t: bytes([0x0B, t]) + bytes(range(1, 10))

# Prefixes (header and self-defining parameters) that the seeded fill
# is appended to.  The first (empty) prefix of every id is implicit.
PREFIX = {
    ('o', 0x0F24): [_LFS(op) for op in (1, 2, 3, 4, 5, 6)],
    ('o', 0x06): [H('80 41 c1 08 09 00'), H('80 41 c1 08 03 01'), H('80 41 c1 08 0a 00'), H('80 41 c1 08 00 00'),
                  H('00 41 c1 08')],
    ('o', 0x0F71): [H('01 02 c3 00 00 01 0010 0020 0004'), H('01 02 c3 00 00 01 0010 0020 0000')],
    ('o', 0x40): [H('00 f7 c1 0102'), H('00 01 c3') + _TXT, H('00 05 c2') + _TXT, H('00 0d c1') + _TXT,
                  H('00 0f c1'), H('00 f1 c1') + _TXT, H('00 7e c1') + _TXT, H('00 6f c2'), H('00 f5 c1') + _TXT,
                  H('00 03'), H('00 f1')],
    ('o', 0x01): [H('00 02'), H('00 03 80 80 81 85 86'), H('00 03 00'), H('00 6e'), H('00 f2'), H('00 f6'),
                  H('ff ff 03 40 80 81')],
    ('o', 0x03): [H('80'), H('00')],
    ('o', 0x0F08): [H('00 0000') + x for x in (H('06 01 41 42 43 44'), H('03 04 41'), H('04 05 41 42'),
                    H('06 01 41 42 43 44 03 04 41'), H('03 04 41 04 05 41 42'),
                    H('06 01 41 42 43 44 03 04 41 04 05 41 42'), H('0a 09'))],
    ('o', 0x0F84): [H('00 00 03 01 41'), H('00 00 03 01 41 03 01 42'), H('00 00 05 05')],
    ('o', 0x09): [H('00 02 41'), H('00 00'), H('00 01'), H('00 02')],
    ('i', 0x0F22): [H('00 00 00') + b''.join(_SDP_EX[i] for i in c) for c in
                    ([0], [1], [2], [3], [4], [0, 1], [2, 3, 4], [1, 4], [0, 1, 2, 3, 4])],
    ('i', 0x8184): [H('f0 0001 04 07 02 41 42 43 4445'), H('00 0001 04 07 02 41 42 43 4445'), H('00 0001 04 07 09 41 42 43 4445')],
    ('i', 0x8185): [bytes([f1, f2]) + bytes(7) for f1 in (0x08, 0x04, 0x02, 0x0E, 0x1E, 0x80) for f2 in (0x00, 0x10)],
    ('i', 0x8186): [H('00 02 f1 f2 f2 f3 04 02 00 f4'), H('00 01 ff ff ff ff 04 02 00 f4'), H('01 00 04 02 f1 f2'),
                    H('00 02 f1 ff ff 41 f2'), H('00 01 41 ff ff')],
    ('i', 0x818F): [_HDR_OEM + x for x in (H('04 01 4142'), H('06 02 4142 4344'), H('04 03 4142'),
                    H('04 01 4142 06 02 4142 4344 04 03 4142'), H('04 09 41 42'), H('05 09 41'))],
    ('i', 0x8191): [H('00') + x for x in (H('03 01 41'), H('03 02 42'), H('03 01 41 03 02 42'), H('03 02 41 03 01 42 03 01 43'),
                                       H('03 09 41'), H('05 01 41'))],
    ('i', 0x8195): [H('00 01 0002 0003 04 05') + x for x in (H('05 02 41 42 43'), H('04 01 41 42 43'), H('05 03 41 4243'),
                    H('05 02 41 42 43 04 01 41 42 43 05 03 41 4243 00'), H('04 01 4142 04 01 4142 04 01 4142 00'),
                    H('06 09 41 42 43 44'))],
    ('i', 0x8197): [H('0001 0002 0003') + x for x in (H('00'), H('01 11 2233'), H('02 11 2233 12 4455'),
                    H('01 11 2233 04 01 41 42'), H('00 04 01 41 42'))],
    ('i', 0x8194): [H('00 01 0002 0003') + x for x in (H('04 01 41 42 0005'), H('04 02 41 42'))],
    ('i', 0x8187): [H('02 f1 f2 f2 f4'), H('01 ff ff ff ff'), H('02 41 ff ff 42 43'), H('00')],
    ('i', 0x819E): [_HDR_IBM + x for x in (H('04 02 41 42'), H('04 01 41 42 00'), H('05 03 41 42 43 00'),
                    H('04 02 41 42 04 01 41 42 05 03 41 42 43 00'), H('04 09 41 42'))],
    ('i', 0x81A6): [H('00 00') + b''.join(_SD11(t) for t in c) for c in
                    ([1], [2], [3], [1, 2], [2, 3], [1, 2, 3], [3, 1, 2], [9])] + [H('00 00 0b 01 0000')],
    ('i', 0x818E): [x for x in (H('03 01 41'), H('02 03'), H('03 01 41 02 03'), H('02 03 03 01 41'), H('02 03 02 03'),
                    H('03 01 41 03 01 42'), H('02 07'))],
    ('i', 0x819C): [H('0001 01 01') + x for x in (H('04 01 41 42'), H('04 02 41 42'))],
    ('i', 0x81A9): [H('0000') + x for x in (H('03 01 41'), H('03 02 41'))],
    ('i', 0x8196): [x for x in (H('0b 01 05 00000100 00000200 00010002'), H('0b 01 05 00000100 00000200'),
                    H('0b 01 05 00000100 00000200 0001'), H('0b 02 05 00000100'))],
    ('i', 0x8181): [H('00 80 0050 0018 01 00000001 00000001 01 01 0780') + H('01 01 50 18'),
                    H('00 00 0050 0018 01 00000001 00000001 01 01 0780')],
    ('i', 0x81A1): [_eb('DEV1') + H('00000001') + H('00'), _eb('DEV1') + H('00000001') + H('05') + _eb('RPQ1'),
                    _eb('DEV1') + H('00000001') + H('01'), _eb('DEV1') + H('00000001') + H('00')],
    ('i', 0x81AB): [H('0001 0002 0003 0004 0005 01 02'), ],
}


def cand_body(direction, i, trial):
    pre = [b''] + PREFIX.get((direction, i), [])
    p, v = divmod(trial, 96)
    r = random.Random('%s:%d:%d' % (direction, i, trial))
    n = v % 48
    return pre[p] + bytes(r.randrange(255) for _ in range(n))


def ntrials(direction, i):
    return 96 * (1 + len(PREFIX.get((direction, i), [])))



# Filled in by select3270.py: {(direction, sfid): [trial, ...]}
KEEP = {
    ('i', 0xF02): [4],
    ('i', 0xF0F): [3, 25, 47],
    ('i', 0xF10): [3, 25, 47],
    ('i', 0xF11): [3, 25, 47],
    ('i', 0xF1F): [3, 25, 47],
    ('i', 0xF21): [2, 25, 47],
    ('i', 0xF22): [5, 26, 47, 96, 120, 143, 192, 216, 239, 288, 312, 335, 384, 408, 431, 480, 504, 527, 576, 600, 623, 672, 696, 719, 768, 792, 815, 864, 888, 911],
    ('i', 0xF80): [4, 26, 47],
    ('i', 0xF83): [2],
    ('i', 0xFB1): [18, 33, 47],
    ('i', 0xFC1): [3, 25, 47],
    ('i', 0x1031): [39, 43, 47],
    ('i', 0x1034): [1, 24, 47],
    ('i', 0x8180): [0, 24, 47],
    ('i', 0x8181): [19, 34, 47, 96, 120, 143, 192, 216, 239],
    ('i', 0x8182): [0, 24, 47],
    ('i', 0x8183): [65, 77, 42],
    ('i', 0x8184): [6, 27, 47, 96, 120, 143, 192, 216, 239, 288, 312, 335],
    ('i', 0x8185): [9, 78, 93, 96, 121, 141, 192, 213, 234, 288, 313, 333, 384, 405, 426, 480, 501, 522, 576, 603, 621, 672, 694, 716, 768, 794, 807, 864, 886, 908, 960, 986, 999, 1056, 1080, 1101, 1152, 1177, 1197],
    ('i', 0x8186): [60, 65, 20, 96, 120, 143, 192, 216, 239, 288, 312, 335, 386, 409, 431, 482, 505, 527],
    ('i', 0x8187): [18, 87, 40, 96, 120, 143, 192, 216, 239, 288, 312, 335, 384, 408, 431],
    ('i', 0x8188): [0, 24, 47],
    ('i', 0x818A): [0, 1],
    ('i', 0x818B): [3, 25, 47],
    ('i', 0x818C): [6, 27, 47],
    ('i', 0x818E): [2, 25, 47, 96, 120, 143, 192, 216, 239, 288, 312, 335, 384, 408, 431, 480, 504, 527, 576, 600, 623, 672, 696, 719],
    ('i', 0x818F): [19, 33, 47, 96, 120, 143, 192, 216, 239, 288, 312, 335, 384, 408, 431, 480, 504, 527, 576, 600, 623],
    ('i', 0x8190): [0],
    ('i', 0x8191): [2, 25, 47, 96, 120, 143, 192, 216, 239, 288, 312, 335, 384, 408, 431, 480, 504, 527, 576, 600, 623],
    ('i', 0x8192): [1, 24, 47],
    ('i', 0x8194): [8, 28, 47, 96, 120, 143, 192, 216, 239],
    ('i', 0x8195): [10, 29, 47, 96, 120, 143, 193, 216, 239, 289, 312, 335, 384, 408, 431, 480, 504, 527, 576, 600, 623],
    ('i', 0x8196): [2, 25, 47, 96, 120, 143, 192, 216, 239, 288, 312, 335, 384, 408, 431],
    ('i', 0x8197): [18, 39, 91, 98, 121, 143, 194, 217, 239, 290, 313, 335, 384, 408, 431, 480, 504, 527],
    ('i', 0x8198): [2, 25, 47],
    ('i', 0x8199): [2, 25, 47],
    ('i', 0x819A): [4, 26, 47],
    ('i', 0x819C): [6, 27, 47, 96, 120, 143, 192, 216, 239],
    ('i', 0x819E): [9, 28, 47, 96, 120, 143, 193, 216, 239, 288, 312, 335, 384, 408, 431, 480, 504, 527],
    ('i', 0x819F): [2, 25, 47],
    ('i', 0x81A0): [0, 24, 47],
    ('i', 0x81A1): [29, 37, 94, 96, 120, 143, 192, 216, 239, 288, 312, 335, 384, 408, 431],
    ('i', 0x81A2): [1, 24, 47],
    ('i', 0x81A6): [3, 25, 47, 97, 120, 143, 193, 216, 239, 289, 312, 335, 385, 408, 431, 481, 504, 527, 576, 600, 623, 672, 696, 719, 768, 792, 815, 872, 892, 911],
    ('i', 0x81A7): [5, 26, 47],
    ('i', 0x81A8): [19, 82, 93],
    ('i', 0x81A9): [4, 26, 47, 96, 120, 143, 192, 216, 239],
    ('i', 0x81AA): [7, 27, 47],
    ('i', 0x81AB): [9, 28, 47, 96, 120, 143],
    ('i', 0x81B0): [0, 24, 47],
    ('i', 0x81B1): [0, 24, 47],
    ('i', 0x81B2): [0, 24, 47],
    ('i', 0x81B3): [0],
    ('i', 0x81B4): [0, 24, 47],
    ('i', 0x81B5): [0, 24, 47],
    ('i', 0x81B6): [0, 24, 47],
    ('o', 0x0): [1],
    ('o', 0x1): [2, 96, 192, 216, 239, 288, 312, 335, 384, 480, 576, 625, 672, 696, 719],
    ('o', 0x3): [1, 96, 192],
    ('o', 0x6): [4, 29, 47, 105, 124, 143, 195, 217, 239, 297, 316, 335, 384, 408, 431, 480],
    ('o', 0x9): [2, 96, 97, 192, 288, 384, 385],
    ('o', 0xB): [5],
    ('o', 0xC): [27, 37, 47],
    ('o', 0xD): [1],
    ('o', 0xE): [1],
    ('o', 0x40): [2, 25, 47, 96, 120, 143, 192, 196, 205, 288, 341, 302, 384, 387, 442, 480, 484, 543, 576, 580, 645, 672, 725, 683, 768, 821, 796, 864, 920, 929, 960, 984, 1007, 1056, 1059, 1117],
    ('o', 0x41): [1, 24, 47],
    ('o', 0x4A): [1, 24, 47],
    ('o', 0x4B): [3, 25, 47],
    ('o', 0x4C): [5, 26, 47],
    ('o', 0xF01): [6, 27, 47],
    ('o', 0xF02): [4],
    ('o', 0xF04): [2],
    ('o', 0xF05): [0, 24, 47],
    ('o', 0xF07): [0, 24, 47],
    ('o', 0xF08): [5, 26, 47, 96, 120, 143, 192, 216, 239, 288, 312, 335, 384, 408, 431, 480, 504, 527, 576, 600, 623, 672, 696, 719],
    ('o', 0xF0A): [27, 37, 47],
    ('o', 0xF0F): [3, 25, 47],
    ('o', 0xF10): [3, 25, 47],
    ('o', 0xF11): [3, 25, 47],
    ('o', 0xF1F): [3, 25, 47],
    ('o', 0xF21): [2, 25, 47],
    ('o', 0xF24): [33, 40, 47, 96, 120, 143, 192, 216, 239, 288, 312, 335, 384, 408, 431, 480, 504, 527, 576, 600, 623],
    ('o', 0xF71): [100, 122, 143, 192, 216, 239],
    ('o', 0xF83): [2],
    ('o', 0xF84): [4, 26, 47, 96, 120, 143, 192, 216, 239, 288, 312, 335],
    ('o', 0xF85): [3, 4],
    ('o', 0xFC1): [3, 25, 47],
    ('o', 0x1030): [1, 50],
    ('o', 0x1032): [3, 4],
    ('o', 0x1033): [5, 26, 47],
    ('o', 0x1034): [1, 24, 47],
}


def sf_frame(direction, i, body):
    if direction == 'o':
        return ('srv', rec(b'\xf3' + sf(i, body), True))
    return ('cli', rec(b'\x88' + sf(i, body), True))


def make_cand(outdir):
    c = Conn(51000)
    telnet_start(c, b'IBM-3278-2')
    index = []
    for direction, ids in (('o', OB + OBIB), ('i', IB + OBIB)):
        for i in ids:
            if 0xFF in sfid(i):
                continue
            for trial in range(ntrials(direction, i)):
                who, data = sf_frame(direction, i, cand_body(direction, i, trial))
                getattr(c, who)(data)
                index.append((len(c.pkts), direction, i, trial))
    write_pcap(os.path.join(outdir, 'cand.pcap'), c.pkts)
    with open(os.path.join(outdir, 'cand.idx'), 'w') as f:
        for e in index:
            f.write('%d %s %d %d\n' % e)


def eb(text):
    return text.encode('cp037')


# --------------------------------------------------------- 3270 data stream
def wcc_byte(reset=0, p1=0, p2=0, start=0, alarm=0, kbd=0, mdt=0):
    return bytes([(reset << 6) | (p1 << 5) | (p2 << 4) | (start << 3) | (alarm << 2) | (kbd << 1) | mdt])


def sba(row, col, cols=80):
    a = row * cols + col
    if a & 0xFF == 0xFF:        # 0xFF cannot be sent (telnet IAC)
        a -= 1
    return b'\x11' + struct.pack('!H', a)


def sba12(row, col, cols=80, second=False):
    a = row * cols + col
    hi, lo = (a >> 6) & 0x3F, a & 0x3F
    base = 0xC0 if second else 0x40
    return b'\x11' + bytes([base | hi, 0x40 | lo])


def sf_order(attr):
    return b'\x1d' + bytes([attr])


def sfe(pairs):
    return b'\x29' + bytes([len(pairs)]) + b''.join(bytes(p) for p in pairs)


def mf(pairs):
    return b'\x2c' + bytes([len(pairs)]) + b''.join(bytes(p) for p in pairs)


def sa(t, v):
    return b'\x28' + bytes([t, v])


def ra(a1, a2, ch):
    return b'\x3c' + bytes([a1, a2, ch])


def eua(a1, a2):
    return b'\x12' + bytes([a1, a2])


IC = b'\x13'
PT = b'\x05'


def ge(c):
    return b'\x08' + bytes([c])


ATTR_TYPES = [(0x00, [0x00, 0xF1, 0xC8]), (0xC0, [0x20, 0x60, 0x08, 0x2C, 0xC1, 0xF0]),
              (0xC1, [0x00, 0x01, 0x02, 0x04, 0x07]), (0xC2, [0x00, 0x01, 0x02, 0x04, 0x08, 0x0F]),
              (0x41, [0x00, 0xF0, 0xF1, 0xF2, 0xF4, 0xF3]), (0x42, [0x00, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8]),
              (0x43, [0x00, 0x40, 0xEF, 0xF0, 0xF7, 0xF8, 0xFE]), (0x45, [0xF1, 0xF2, 0xF6, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE]),
              (0x46, [0x00, 0xF0, 0xF1, 0xFE])]


def screen_login():
    d = wcc_byte(reset=1, kbd=1)
    d += sba(0, 0) + sf_order(0x60) + eb('Welcome to the test host') + sf_order(0x20)
    d += sba(2, 0) + sf_order(0x60) + eb('Userid  ===>') + sf_order(0x40) + IC + eb('        ')
    d += sba(3, 0) + sf_order(0x60) + eb('Password ===>') + sf_order(0x4C) + eb('        ')
    d += sf_order(0x60)
    return d


def orders_frames():
    """Frames of server to client write commands with every order."""
    out = []
    out.append(bytes([0xF5]) + screen_login())
    # all WCC bit combinations
    for w in (0x00, 0xC3, 0x3C, 0xFE, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80):
        out.append(bytes([0x01, w]) + sba(5, 5) + eb('WCC %02X' % w))
    # address formats
    out.append(b'\x01\xc2' + sba(0, 0) + eb('a') + sba(23, 79) + eb('b') + sba12(10, 10) + eb('c') +
               sba12(11, 11, second=True) + eb('d') + b'\x11\x80\x00' + eb('e') + b'\x11\x3f\x7f' + eb('f'))
    # field attribute orders
    for fa in (0x20, 0x60, 0x08, 0x0C, 0x1C, 0x2C, 0x7C, 0xC1, 0xF0, 0x4D, 0x41, 0x61):
        out.append(b'\x01\xc2' + sba(6, 6) + sf_order(fa) + eb('field'))
    # start field extended and modify field: every attribute type and value
    for (t, vals) in ATTR_TYPES:
        for v in vals:
            out.append(b'\x01\xc2' + sba(7, 0) + sfe([(t, v)]) + eb('x') + mf([(t, v)]) + eb('y') + sa(t, v) + eb('z'))
    out.append(b'\x01\xc2' + sba(8, 0) + sfe([(0xC0, 0x60), (0x41, 0xF1), (0x42, 0xF2), (0x45, 0xF4), (0xC2, 0x0F),
                                              (0x43, 0xF1), (0x46, 0xF0), (0xC1, 0x07), (0x00, 0x00)]) + eb('many'))
    out.append(b'\x01\xc2' + sfe([]) + mf([]) + eb('empty'))
    # repeat to address, erase unprotected to address
    out.append(b'\x01\xc2' + sba(9, 0) + ra(0x01, 0x40, 0x40) + eb('after') + ra(0x02, 0x03, 0xC1))
    out.append(b'\x01\xc2' + ra(0x01, 0x08, 0x00) + b'\x00\xc1' + ge(0x40))
    out.append(b'\x01\xc2' + ra(0x05, 0x01, 0x08) + b'\x40')
    out.append(b'\x01\xc2' + sba(10, 0) + eua(0x05, 0x40) + eb('eua') + eua(0x06, 0x08) + b'\x40')
    out.append(b'\x01\xc2' + sba(10, 0) + eua(0x05, 0x40) + ge(0xC1) + eb('ge'))
    # insert cursor, program tab, graphic escape
    out.append(b'\x01\xc2' + sba(11, 0) + IC + PT + eb('tab') + PT + ge(0xAA))
    # NUL bytes treated as data, high data bytes
    out.append(b'\x01\xc2' + sba(12, 0) + b'\x00\x00' + eb('nul') + b'\x00')
    # bogus order codes (warning)
    out.append(b'\x01\xc2' + sba(13, 0) + b'\x30' + eb('bogus'))
    out.append(b'\x01\xc2' + b'\x01' + eb('o1') + b'\x3f')
    # erase all unprotected, no orders
    for cmd in (0x0F, 0x6F, 0x05, 0x0D, 0x7E, 0xF5, 0xF1, 0x01):
        out.append(bytes([cmd, 0x42]))
    # read commands
    for cmd in (0x02, 0x06, 0x0E, 0xF2, 0xF6, 0x6E):
        out.append(bytes([cmd]))
    # unknown command codes (warning)
    for cmd in (0x03, 0xF7, 0x00, 0x44):
        out.append(bytes([cmd]))
    return out


AIDS = [0x60, 0xE8, 0x61, 0x7F, 0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0x7A, 0x7B, 0x7C,
        0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0x4A, 0x4B, 0x4C, 0x6D, 0x6A, 0x6B, 0x6C, 0x7D,
        0x7E, 0x6E, 0x6B, 0x6D, 0xE6, 0xE7]


def aid_frames():
    out = []
    for a in sorted(set(AIDS)):
        out.append(bytes([a]) + b'\x40\x5a' + sba(2, 12) + eb('USER01') + sba(3, 13) + eb('PASS'))
    for a in (0x6C, 0x6E, 0x6D, 0x6B):   # these four may be sent alone
        out.append(bytes([a]))
    for a in (0x00, 0x01, 0x30, 0xE0, 0xFA):                  # unknown AID
        out.append(bytes([a]))
    out.append(b'\x7d' + b'\x40\x40' + sba(1, 1) + eb('data') + sf_order(0x20) + eb('x') + IC)
    out.append(b'\x7d' + b'\x00\x00' + sba12(1, 1) + b'\x00' + eb('y'))
    return out


def tn3270e_negotiate(c, devtype=b'IBM-3278-2', lu=b'LU01'):
    c.srv(bytes([IAC, DO, OPT_TN3270E]))
    c.cli(bytes([IAC, WILL, OPT_TN3270E]))
    c.srv(sb(OPT_TN3270E, b'\x08\x02'))                                  # SEND DEVICE-TYPE
    c.cli(sb(OPT_TN3270E, b'\x02\x07' + devtype + b'\x01' + lu))          # DEVICE-TYPE REQUEST type CONNECT lu
    c.srv(sb(OPT_TN3270E, b'\x02\x04' + devtype + b'\x01' + lu))          # DEVICE-TYPE IS type CONNECT lu
    c.cli(sb(OPT_TN3270E, b'\x03\x07\x00\x02\x04'))                      # FUNCTIONS REQUEST BIND-IMAGE RESPONSES SYSREQ
    c.srv(sb(OPT_TN3270E, b'\x03\x04\x00\x02\x04'))                      # FUNCTIONS IS


def tn3270e_hdr(dtype, req=0, resp=0, seq=1, extra=b''):
    return bytes([dtype, req, resp]) + struct.pack('!H', seq) + extra


def ttype_only(c, name):
    c.srv(bytes([IAC, DO, OPT_TTYPE]))
    c.cli(bytes([IAC, WILL, OPT_TTYPE]))
    c.srv(sb(OPT_TTYPE, b'\x01'))
    c.cli(sb(OPT_TTYPE, b'\x00' + name))


def sf_frames_extra():
    """Hand-built structured field frames: NULs between fields, unknown
    ids, several fields in one record, the escaped partition id."""
    out = []
    # (direction, bytes after the command/AID)
    erase = H('00 04 03 00')
    out.append(('o', H('00 00') + erase))            # two NULs, then Erase/Reset
    out.append(('o', erase + H('00 00 00') + erase))
    out.append(('i', H('00 00') + sf(0x0F22, H('00 00 00') + _SDP_EX[1])))
    out.append(('o', H('00 05 50 41 42')))           # unknown one-byte id
    out.append(('o', H('00 06 0f 99 41 42')))        # unknown 0F xx id
    out.append(('o', H('00 06 10 77 41 42')))        # unknown 10 xx id
    out.append(('i', H('00 06 81 70 41 42')))        # unknown 81 xx id
    out.append(('i', H('00 05 60 41 42')))
    # several structured fields in one record
    out.append(('o', sf(0x0E, H('00')) + sf(0x03, H('80')) + sf(0x0B, H('00 0001 0002')) + sf(0x0D, H('00'))))
    out.append(('i', sf(0x0F22, H('00 00 00') + _SDP_EX[1]) + sf(0x8180, H('00 01 41')) + sf(0x81B3, b'')))
    # Query Reply (Null) 0x81FF: the 0xFF of the id is an escaped IAC pair
    out.append(('i', H('00 05 81 ff ff')))
    # read partition with the partition id 0xFF (escaped on the wire)
    out.append(('o', sf(0x01, H('ff ff 03 40 80 81'))))
    out.append(('o', sf(0x01, H('ff ff 02'))))
    # the DIA reproducer of "TN3270: Fix Query Reply and structured field offsets"
    out.append(('i', sf(0x8197, struct.pack('!HHH', 0, 0x100, 0x100) + b'\x01' + b'\x11' + struct.pack('!H', 0x2233) + b'\x04\x01\x44\x55')))
    # DDM and IBM auxiliary device with a parameter right after the header
    out.append(('i', sf(0x8195, H('00 01 0002 0003 04 05') + H('06 02 41 42 43 44'))))
    out.append(('i', sf(0x819E, H('00 01 0102 0304 05') + H('06 02 41 42 43 44'))))
    # RPQ names with an empty name list (rpql == 0) and one name
    out.append(('i', sf(0x81A1, _eb('DEV1') + H('00000001') + H('00'))))
    out.append(('i', sf(0x81A1, _eb('DEV1') + H('00000001') + H('05') + _eb('RPQ1'))))
    return out


def models_frames(c, cols, rows):
    out = []
    c.srv(rec(bytes([0xF5, 0xC3]) + sba(0, 0, cols) + sf_order(0x60) + eb('Alt screen') + sba(rows - 1, cols - 1, cols)))
    c.srv(rec(bytes([0x7E, 0xC3]) + sba(rows - 1, cols - 1, cols) + eb('EWA')))
    c.srv(rec(b'\xf3' + sf(0x03, H('80'))))                               # Erase/Reset, alternate size
    c.srv(rec(bytes([0xF1, 0xC3]) + sba(rows - 1, 0, cols) + eb('after erase/reset')))
    c.srv(rec(b'\xf3' + sf(0x03, H('00'))))                               # default size
    c.srv(rec(bytes([0xF1, 0xC3]) + sba(23, 79, 80) + eb('default size')))
    c.cli(rec(bytes([0x7D]) + sba(1, 2, cols) + eb('INPUT')))


TTYPES = [b'IBM-3278-2-E', b'IBM-3278-3', b'IBM-3278-4', b'IBM-3278-5', b'IBM-3277-2', b'IBM-3279-3',
          b'IBM-3279-4', b'IBM-3279-2-E', b'IBM-3279-2', b'IBM-3279-4-E']
DIM = {2: (80, 24), 3: (80, 32), 4: (80, 43), 5: (132, 27)}


def build_main():
    """Returns (main packets, malformed packets)."""
    pk = []
    bad = []

    # ---- connection 1: 3278-2 over plain TN3270
    c = Conn(50001)
    telnet_start(c, b'IBM-3278-2')
    for d in orders_frames():
        c.srv(rec(d))
    for d in aid_frames():
        c.cli(rec(d))
    # structured fields whose body decodes cleanly from the seeded fill
    for (direction, i), trials in sorted(KEEP.items()):
        for trial in trials:
            who, data = sf_frame(direction, i, cand_body(direction, i, trial))
            getattr(c, who)(data)
    for direction, data in sf_frames_extra():
        if direction == 'o':
            c.srv(rec(b'\xf3' + data, True))
        else:
            c.cli(rec(b'\x88' + data, True))
    # records split over several TCP segments (Telnet reassembles them):
    # the first segments carry no IAC at all
    scr = bytes([0xF5, 0xC3]) + screen_login() * 3
    for cut in ((40,), (30, 90, 150)):
        pos = 0
        for k in cut:
            c.srv(scr[pos:k])
            pos = k
        c.srv(rec(scr[pos:]))
    inp = b'\x7d\x40\x5a' + sba(2, 12) + eb('SPLIT INPUT') * 4
    c.cli(inp[:20])
    c.cli(rec(inp[20:]))
    # two records in one segment
    c.srv(rec(bytes([0x01, 0xC3]) + eb('one')) + rec(bytes([0x01, 0xC3]) + eb('two')))
    pk += c.pkts

    # ---- one connection for every terminal type that TN3270 accepts
    for n, t in enumerate(TTYPES):
        c = Conn(50010 + n)
        ttype_only(c, t)
        cols, rows = DIM[int(t[9:10])]
        models_frames(c, cols, rows)
        pk += c.pkts

    # ---- TN3270-REGIME option
    c = Conn(50030)
    c.srv(bytes([IAC, DO, 29]))
    c.cli(bytes([IAC, WILL, 29]))
    c.cli(sb(29, b'\x01NORMAL'))
    c.srv(sb(29, b'\x00NORMAL'))
    c.srv(sb(29, b'\x07'))
    c.cli(rec(bytes([0x7D]) + sba(2, 2) + eb('REGIME')))
    c.srv(rec(bytes([0x01, 0xC3]) + sba(1, 1) + eb('regime data')))
    pk += c.pkts

    # ---- TN3270E: negotiation, then every header data type
    for cport, devtype in ((50040, b'IBM-3278-2'), (50041, b'IBM-3279-4')):
        c = Conn(cport)
        tn3270e_negotiate(c, devtype)
        c.srv(rec(tn3270e_hdr(0, 0, 0, 1) + bytes([0xF5, 0xC3]) + sba(0, 0) + sf_order(0x60) + eb('TN3270E screen')))
        c.cli(rec(tn3270e_hdr(0, 0, 1, 1) + b'\x7d' + sba(1, 1) + eb('answer')))
        c.srv(rec(tn3270e_hdr(0, 1, 2, 2) + b'\x01\xc3' + eb('x')))
        c.srv(rec(tn3270e_hdr(0, 2, 0, 3) + b'\xf3' + sf(0x03, H('80'))))
        c.srv(rec(tn3270e_hdr(0, 0, 0, 4)))                                  # header only
        c.srv(rec(tn3270e_hdr(1, 0, 0, 5) + b'\x01\x02\x03'))             # SCS data
        c.cli(rec(tn3270e_hdr(1, 0, 1, 5) + b'\x01\x02\x03'))
        c.cli(rec(tn3270e_hdr(2, 0, 0, 5, b'\x00')))                         # RESPONSE positive
        c.cli(rec(tn3270e_hdr(2, 0, 1, 6, b'\x02')))                         # RESPONSE negative
        c.srv(rec(tn3270e_hdr(3, 0, 0, 7, eb('bind image'))))                # BIND-IMAGE
        c.srv(rec(tn3270e_hdr(4, 0, 0, 8, b'\x01')))                        # UNBIND
        c.srv(rec(tn3270e_hdr(5, 0, 0, 9, eb('nvt data'))))                  # NVT data
        c.cli(rec(tn3270e_hdr(6, 0, 0, 10, b'\x04')))                       # REQUEST
        c.srv(rec(tn3270e_hdr(7, 0, 0, 11, eb('sscp lu'))))                  # SSCP-LU data
        c.srv(rec(tn3270e_hdr(0x20, 0, 0, 12)))                              # unknown data type
        c.srv(rec(tn3270e_hdr(0, 0, 0, 13) + b'\x44'))                      # unknown command code
        pk += c.pkts
    # rejected TN3270E negotiation, then fallback
    c = Conn(50042)
    c.srv(bytes([IAC, DO, OPT_TN3270E]))
    c.cli(bytes([IAC, WILL, OPT_TN3270E]))
    c.cli(sb(OPT_TN3270E, b'\x02\x07IBM-3278-2'))
    c.srv(sb(OPT_TN3270E, b'\x02\x06\x05\x03'))                           # REJECT REASON INV-DEVICE-NAME
    c.srv(sb(OPT_TN3270E, b'\x02\x06\x05'))
    c.cli(sb(OPT_TN3270E, b'\x00\x01\x01'))                               # ASSOCIATE
    pk += c.pkts

    # ---------------------------------------------------- malformed capture
    c = Conn(50100)
    ttype_only(c, b'IBM-3278-5')
    # truncated structured fields: one frame per structured field id
    for (direction, i), trials in sorted(KEEP.items()):
        who, data = sf_frame(direction, i, cand_body(direction, i, trials[-1]))
        data = data[:-3] + data[-2:]            # drop the last body byte, keep the length
        getattr(c, who)(data)
    # truncated orders
    for tail in (b'\x11\x40', b'\x1d', b'\x29\x02\xc0\x20', b'\x28\xc0', b'\x3c\x00\x10', b'\x12\x01',
                 b'\x2c\x03\x41\xf1', b'\x08'):
        c.srv(rec(b'\x01\xc2' + tail))
    for tail in (b'\x40', b'\x40\x40\x11', b'\x40\x5a\x1d'):
        c.cli(rec(b'\x7d' + tail))
    c.cli(rec(b'\x7d'))                         # ENTER without cursor address
    c.cli(rec(b'\x88\x00'))                    # structured field without a length
    c.cli(rec(b'\x88\x00\x20\x81\x84'))        # length beyond the record
    c.srv(rec(b'\xf3\x00\x20\x0e\x00'))
    # Outbound Text Header with a 0xFFFF header length (reproducer of the hdr_length fix)
    c.srv(rec(b'\xf3' + sf(0x0F71, H('01 02 c3 00 00 01 0010 0020 ff ff 41 42'), ), True))
    # Query Reply DIA that claims more file servers than it holds
    c.cli(rec(b'\x88' + sf(0x8197, H('0001 0002 0003 09 11 2233')), True))
    # TN3270E header cut short
    bad += c.pkts
    c = Conn(50101)
    tn3270e_negotiate(c)
    c.srv(rec(b'\x00'))
    c.srv(rec(b'\x00\x00\x00'))
    c.srv(rec(b'\x05\x00\x00\x00'))
    bad += c.pkts
    return pk, bad


def exported_pdu_pcapng(fn, names, payload=b'\x01\xc3\x40'):
    """Exported PDU file (link type 252) whose frames name the TN3270
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
    write_pcap(os.path.join(outdir, 'tn3270-coverage.pcap'), main)
    write_pcap(os.path.join(outdir, 'tn3270-coverage-malformed.pcap'), bad)
    exported_pdu_pcapng(os.path.join(outdir, 'tn3270-coverage-exppdu.pcapng'), ['tn3270'])
    print(len(main), len(bad))
