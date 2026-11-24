#!/usr/bin/env python3
# Generates test/captures/zbee-zcl_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Coverage capture generator for packet-zbee-zcl.c (ZigBee Cluster Library
# core: profile-wide commands, data types, arrays/sets/bags, FCF variants).
# Synthetic frames, built with struct only: 802.15.4 (linktype 230, no FCS)
# -> ZigBee NWK -> APS -> ZCL, reached through the default zbee_nwk
# heuristic; the addresses are made up.
#   usage: mkzbee-zcl.py <outdir>
# writes zbee-zcl-coverage.pcap, zbee-zcl-coverage-malformed.pcap and
# zbee-zcl_coverage.pcap.gz
import struct
import sys
import os
import gzip

GEN = 0xfc00        # cluster no dissector knows: generic attribute data decoding
LOCK = 0x0101       # registered cluster (Door Lock), with its own attribute ids
MFR = 0x1002        # a manufacturer code (ZCL manufacturer specific frames)

# data type -> sample value
TYPES = [
    (0x00, b''), (0x08, b'\xa5'), (0x09, b'\xa5\x5a'), (0x0a, b'\x01\x02\x03'),
    (0x0b, b'\x01\x02\x03\x04'), (0x0c, bytes(range(1, 6))), (0x0d, bytes(range(1, 7))),
    (0x0e, bytes(range(1, 8))), (0x0f, bytes(range(1, 9))),
    (0x10, b'\x01'), (0x10, b'\x00'), (0x10, b'\xff'),
    (0x18, b'\x81'), (0x19, b'\x01\x80'), (0x1a, bytes(range(1, 4))), (0x1b, bytes(range(1, 5))),
    (0x1c, bytes(range(1, 6))), (0x1d, bytes(range(1, 7))), (0x1e, bytes(range(1, 8))), (0x1f, bytes(range(1, 9))),
    (0x20, b'\x7f'), (0x21, b'\x34\x12'), (0x22, b'\x56\x34\x12'), (0x23, b'\x78\x56\x34\x12'),
    (0x24, bytes(range(1, 6))), (0x25, bytes(range(1, 7))), (0x26, bytes(range(1, 8))), (0x27, bytes(range(1, 9))),
    (0x28, b'\xfe'), (0x29, b'\xfe\xff'), (0x2a, b'\xfe\xff\xff'), (0x2b, b'\xfe\xff\xff\xff'),
    (0x2c, b'\xfe' + b'\xff' * 4), (0x2d, b'\xfe' + b'\xff' * 5), (0x2e, b'\xfe' + b'\xff' * 6), (0x2f, b'\xfe' + b'\xff' * 7),
    (0x30, b'\x02'), (0x31, b'\x03\x00'),
    (0x38, b'\x00\x3c'), (0x39, struct.pack('<f', 1.5)), (0x3a, struct.pack('<d', -2.25)),
    (0x41, b'\x04\xde\xad\xbe\xef'), (0x41, b'\x00'), (0x41, b'\xff'),
    (0x42, b'\x05hello'), (0x42, b'\x00'), (0x42, b'\xff'),
    (0x43, b'\x03\x00\x01\x02\x03'), (0x43, b'\x00\x00'), (0x43, b'\xff\xff'),
    (0x44, b'\x05\x00world'), (0x44, b'\x00\x00'), (0x44, b'\xff\xff'),
    (0x4c, b''),
    (0xe0, bytes([13, 45, 59, 99])), (0xe1, bytes([124, 12, 31, 7])), (0xe1, bytes([124, 1, 1, 9])),
    (0xe2, struct.pack('<I', 0x2a0c4e00)), (0xe8, b'\x06\x00'), (0xe9, b'\x01\x00'),
    (0xea, b'\x01\x02\x03\x04'), (0xf0, bytes(range(1, 9))), (0xf1, bytes(range(1, 17))),
    (0xff, b''), (0x01, b''), (0x60, b''),
]
ANALOG = [t for t, _ in TYPES if (t & 0xf0) == 0x20 or (t & 0xf8) == 0x38 or (t & 0xf8) == 0xe0]

def zcl_frame(seq, cluster, zcl, profile=0x0104):
    mac = struct.pack('<HBHHH', 0x8841, seq & 0xff, 0x1234, 0x0000, 0x0001)
    nwk = struct.pack('<HHHBB', 0x0008, 0x0000, 0x0001, 0x1e, seq & 0xff)
    aps = struct.pack('<BBHHBB', 0x00, 0x01, cluster, profile, 0x01, seq & 0xff)
    return mac + nwk + aps + zcl

def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 230))
        for i, p in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)) + p)

# FCF: frame type bits 0-1, manufacturer specific 0x04, direction (server to
# client) 0x08, disable default response 0x10
TOSRV, TOCLI = 0x00, 0x08

def array(kind, elem_type, n, body):
    return bytes([kind]) + bytes([elem_type]) + struct.pack('<H', n) + body

def nested(depth, leaf_type=0x20, leaf=b'\x07', kind=0x48):
    """ARRAY of ARRAY ... (depth levels) holding one 8-bit value"""
    body = bytes([leaf_type]) + struct.pack('<H', 1) + leaf   # innermost: elements
    for _ in range(depth - 1):
        body = bytes([kind]) + struct.pack('<H', 1) + body
    return bytes([kind]) + body

def build():
    fr, bad = [], []
    def add(lst, cid, fcf, cmd, payload=b'', mfr=None, profile=0x0104):
        zcl = bytes([fcf | (0x04 if mfr is not None else 0)])
        if mfr is not None:
            zcl += struct.pack('<H', mfr)
        zcl += bytes([len(lst) & 0xff, cmd]) + payload
        lst.append(zcl_frame(len(lst) + 1, cid, zcl, profile))
    A = lambda attr, t, v: struct.pack('<HB', attr, t) + v
    # ---- Read Attributes (0x00), Read Attributes Response (0x01) ----------
    for cid in (GEN, LOCK):
        for d in (TOSRV, TOCLI):
            add(fr, cid, d, 0x00, struct.pack('<HHH', 0x0000, 0x0001, 0xfffd))
    for d in (TOSRV, TOCLI):
        for i, (t, v) in enumerate(TYPES):
            add(fr, GEN, d, 0x01, struct.pack('<HB', i, 0) + bytes([t]) + v)
        # failures and successes mixed in one frame
        add(fr, GEN, d, 0x01, struct.pack('<HB', 0, 0x86) + struct.pack('<HB', 1, 0) + bytes([0x20, 5]) + struct.pack('<HB', 2, 0x88) + struct.pack('<HB', 3, 0) + bytes([0x21, 1, 2]))
        # Door Lock attributes: Lock State, Lock Type, Actuator Enabled
        for lock in ((0, 0x30, b'\x01'), (1, 0x30, b'\x02'), (2, 0x10, b'\x01')):
            add(fr, LOCK, d, 0x01, struct.pack('<HB', lock[0], 0) + bytes([lock[1]]) + lock[2])
        add(fr, LOCK, d, 0x01, struct.pack('<HB', 0, 0x86) + struct.pack('<HB', 1, 0) + bytes([0x30, 2]) + struct.pack('<HB', 2, 0x88))
    # all the data types in one Read Attributes Response, up to the subtree limit
    one = b''.join(struct.pack('<HB', i, 0) + bytes([t]) + v for i, (t, v) in enumerate(TYPES))
    add(fr, GEN, TOCLI, 0x01, one)
    # ---- Report Attributes (0x0a), also with manufacturer code ---------------
    for i, (t, v) in enumerate(TYPES):
        add(fr, GEN, TOCLI, 0x0a, A(i, t, v))
    add(fr, GEN, TOSRV, 0x0a, A(1, 0x20, b'\x01') + A(2, 0x42, b'\x03abc') + A(3, 0x21, b'\x01\x02'))
    add(fr, GEN, TOCLI, 0x0a, A(1, 0x20, b'\x01') + A(2, 0x42, b'\x03abc'), mfr=MFR)
    add(fr, LOCK, TOCLI, 0x0a, A(0x0000, 0x30, b'\x01') + A(0x0001, 0x30, b'\x00'))
    add(fr, LOCK, TOCLI, 0x0a, A(0x0000, 0x30, b'\x01'), mfr=MFR)
    # more attribute records than the (64) attribute subtrees
    add(fr, GEN, TOCLI, 0x0a, b''.join(A(i, 0x20, bytes([i])) for i in range(70)))
    # ---- Write Attributes (0x02), Undivided (0x03), No Response (0x05) ---------
    for cmd in (0x02, 0x03, 0x05):
        for d in (TOSRV, TOCLI):
            add(fr, GEN, d, cmd, A(0x0010, 0x42, b'\x03abc') + A(0x0011, 0x21, b'\x10\x00'))
            add(fr, LOCK, d, cmd, A(0x0000, 0x30, b'\x01'))
    add(fr, GEN, TOSRV, 0x02, A(0x0010, 0x42, b'\x03abc'), mfr=MFR)
    # ---- Write Attributes Response (0x04) --------------------------------------
    for d in (TOSRV, TOCLI):
        add(fr, GEN, d, 0x04, b'\x00')
        add(fr, GEN, d, 0x04, bytes([0x88]) + struct.pack('<H', 0x0010) + bytes([0x87]) + struct.pack('<H', 0x0011) + b'\x00')
        add(fr, LOCK, d, 0x04, bytes([0x88]) + struct.pack('<H', 0x0000))
    # ---- Configure Reporting (0x06) ---------------------------------------------
    for d in (TOSRV, TOCLI):
        for t, v in TYPES:
            if t in (0x41, 0x42, 0x43, 0x44, 0x48, 0x4c, 0x50, 0x51):
                continue
            rec = b'\x00' + struct.pack('<HBHH', 0x0021, t, 5, 600)
            if t in ANALOG:
                rec += v
            add(fr, GEN, d, 0x06, rec)
        add(fr, GEN, d, 0x06, b'\x01' + struct.pack('<HH', 0x0021, 1800))
        add(fr, GEN, d, 0x06, b'\x00' + struct.pack('<HBHH', 0x0021, 0x20, 5, 600) + b'\x02' + b'\x01' + struct.pack('<HH', 0x0022, 1800))
        add(fr, LOCK, d, 0x06, b'\x00' + struct.pack('<HBHH', 0x0000, 0x30, 1, 60))
        add(fr, LOCK, d, 0x06, b'\x01' + struct.pack('<HH', 0x0000, 30))
    # ---- Configure Reporting Response (0x07) ------------------------------------
    for d in (TOSRV, TOCLI):
        add(fr, GEN, d, 0x07, b'\x00')
        add(fr, GEN, d, 0x07, bytes([0x8c, 0]) + struct.pack('<H', 0x0021) + bytes([0x86, 1]) + struct.pack('<H', 0x0022))
        add(fr, LOCK, d, 0x07, bytes([0x8c, 0]) + struct.pack('<H', 0x0000) + bytes([0x8c, 1]) + struct.pack('<H', 0x0001))
    add(bad, GEN, TOSRV, 0x07, b'\x86')          # short, non-success (warning)
    # ---- Read Reporting Configuration (0x08) and Response (0x09) ---------------
    for d in (TOSRV, TOCLI):
        add(fr, GEN, d, 0x08, b'\x00' + struct.pack('<H', 0x0021) + b'\x01' + struct.pack('<H', 0x0022))
        add(fr, LOCK, d, 0x08, b'\x00' + struct.pack('<H', 0x0000) + b'\x01' + struct.pack('<H', 0x0001))
        for t, v in TYPES:
            if t in (0x41, 0x42, 0x43, 0x44, 0x48, 0x4c, 0x50, 0x51):
                continue
            rec = b'\x00\x00' + struct.pack('<HBHH', 0x0021, t, 5, 600)
            if t in ANALOG:
                rec += v
            add(fr, GEN, d, 0x09, rec)
        add(fr, GEN, d, 0x09, b'\x00\x01' + struct.pack('<HH', 0x0021, 1800))
        add(fr, GEN, d, 0x09, b'\x86\x00' + struct.pack('<H', 0x0021) + b'\x8c\x01' + struct.pack('<H', 0x0022))
        add(fr, LOCK, d, 0x09, b'\x00\x00' + struct.pack('<HBHH', 0x0000, 0x30, 1, 60) + b'\x00\x01' + struct.pack('<HH', 0x0001, 10))
    # ---- Default Response (0x0b) ---------------------------------------------------
    for d in (TOSRV, TOCLI):
        add(fr, GEN, d | 0x10, 0x0b, bytes([0x00, 0x00]))
        add(fr, LOCK, d | 0x10, 0x0b, bytes([0x01, 0x81]))
    # ---- Discover Attributes (0x0c), Response (0x0d), Extended (0x15, 0x16) --------
    for d in (TOSRV, TOCLI):
        add(fr, GEN, d, 0x0c, struct.pack('<HB', 0x0000, 16))
        add(fr, LOCK, d, 0x0c, struct.pack('<HB', 0x0000, 16))
        add(fr, GEN, d, 0x15, struct.pack('<HB', 0x0000, 16))
        add(fr, GEN, d, 0x0d, b'\x01' + b''.join(struct.pack('<HB', i, t) for i, t in ((0, 0x20), (1, 0x21), (2, 0x42))))
        add(fr, GEN, d, 0x0d, b'\x00')
        add(fr, LOCK, d, 0x0d, b'\x00' + struct.pack('<HBHB', 0x0000, 0x30, 0x0001, 0x30))
        add(fr, GEN, d, 0x16, b'\x01' + b''.join(struct.pack('<HBB', i, t, a) for i, t, a in ((0, 0x20, 1), (1, 0x21, 3), (2, 0x42, 7))))
        add(fr, LOCK, d, 0x16, b'\x00' + struct.pack('<HBBHBB', 0x0000, 0x30, 1, 0x0001, 0x30, 2))
    # ---- Discover Commands Received (0x11) / Generated (0x13) and responses ----
    for d in (TOSRV, TOCLI):
        add(fr, GEN, d, 0x11, b'\x00\x10')
        add(fr, GEN, d, 0x13, b'\x00\x10')
        add(fr, GEN, d, 0x12, b'\x01\x00\x01\x02\x03')
        add(fr, GEN, d, 0x14, b'\x01\x00\x01\x02\x03')
        add(fr, GEN, d, 0x12, b'\x00')
        add(fr, GEN, d, 0x14, b'\x00')
    # ---- Read / Write Attributes Structured (0x0e, 0x0f, 0x10) -----------------------
    for d in (TOSRV, TOCLI):
        add(fr, GEN, d, 0x0e, struct.pack('<HBHH', 0x0000, 2, 1, 2) + struct.pack('<HB', 0x0001, 0))
        add(fr, LOCK, d, 0x0e, struct.pack('<HBH', 0x0000, 1, 1))
        add(fr, GEN, d, 0x0f, struct.pack('<HBHH', 0x0000, 2, 1, 2) + bytes([0x20, 0x07]))
        add(fr, GEN, d, 0x0f, struct.pack('<HB', 0x0001, 0) + bytes([0x21, 0x34, 0x12]) + struct.pack('<HBH', 0x0002, 1, 3) + bytes([0x42, 2]) + b'ab')
        add(fr, LOCK, d, 0x0f, struct.pack('<HBH', 0x0000, 1, 1) + bytes([0x30, 1]))
        add(fr, GEN, d, 0x10, bytes([0x00]))
        add(fr, GEN, d, 0x10, bytes([0x86]) + struct.pack('<HBH', 0x0001, 1, 5) + bytes([0x8e]) + struct.pack('<HB', 0x0002, 0))
        add(fr, LOCK, d, 0x10, bytes([0x86]) + struct.pack('<HBH', 0x0000, 1, 5))
    # more selectors than the (16) selector subtrees
    add(fr, GEN, TOSRV, 0x0e, b''.join(struct.pack('<HB', i, 0) for i in range(20)))
    # ---- arrays, sets, bags, nesting -------------------------------------------------------
    arr = lambda et, n, body: bytes([0x48, et]) + struct.pack('<H', n) + body
    st = lambda et, n, body: bytes([0x50, et]) + struct.pack('<H', n) + body
    bg = lambda et, n, body: bytes([0x51, et]) + struct.pack('<H', n) + body
    add(fr, GEN, TOCLI, 0x0a, struct.pack('<H', 0x10) + arr(0x20, 3, b'\x01\x02\x03'))
    add(fr, GEN, TOCLI, 0x0a, struct.pack('<H', 0x10)[:2] + arr(0x21, 0, b''))
    add(fr, GEN, TOCLI, 0x0a, struct.pack('<H', 0x10) + arr(0x42, 2, b'\x02ab\x03cde'))
    add(fr, GEN, TOCLI, 0x0a, struct.pack('<H', 0x10) + arr(0x20, 20, bytes(range(20))))            # more elements than subtrees
    add(fr, GEN, TOCLI, 0x0a, struct.pack('<H', 0x10) + arr(0x20, 300, bytes(range(40))))           # count larger than the data
    add(fr, GEN, TOCLI, 0x0a, struct.pack('<H', 0x10) + st(0x21, 3, b'\x01\x00\x02\x00\x03\x00'))
    add(fr, GEN, TOCLI, 0x0a, struct.pack('<H', 0x10) + st(0x20, 20, bytes(range(20))))
    add(fr, GEN, TOCLI, 0x0a, struct.pack('<H', 0x10) + bg(0x30, 2, b'\x01\x02'))
    add(fr, GEN, TOCLI, 0x0a, struct.pack('<H', 0x10) + bg(0x20, 20, bytes(range(20))))
    for lvl in (2, 3):
        add(fr, GEN, TOCLI, 0x0a, struct.pack('<H', 0x10) + nested(lvl))
        add(fr, GEN, TOCLI, 0x0a, struct.pack('<H', 0x10) + nested(lvl, kind=0x50))
        add(fr, GEN, TOCLI, 0x0a, struct.pack('<H', 0x10) + nested(lvl, kind=0x51))
    add(fr, GEN, TOSRV, 0x0a, struct.pack('<H', 0x10) + nested(3))
    add(fr, GEN, TOCLI, 0x01, struct.pack('<HB', 0x10, 0) + nested(3))
    add(fr, GEN, TOSRV, 0x02, struct.pack('<H', 0x10) + nested(3))
    # an array holding sets, bags and arrays of different types
    add(fr, GEN, TOCLI, 0x0a, struct.pack('<H', 0x10) + arr(0x50, 2, bytes([0x20]) + struct.pack('<H', 2) + b'\x01\x02' + bytes([0x21]) + struct.pack('<H', 1) + b'\x01\x00'))
    # exactly the nesting limit (16 levels) is still decoded
    add(fr, GEN, TOCLI, 0x0a, struct.pack('<H', 0x10) + nested(16))
    add(fr, GEN, TOCLI, 0x0a, struct.pack('<H', 0x10) + nested(16, kind=0x50))
    # one level too deep (the expert info of the nesting bound, in this capture on purpose)
    add(fr, GEN, TOCLI, 0x0a, struct.pack('<H', 0x10) + nested(17))
    add(fr, GEN, TOCLI, 0x0a, struct.pack('<H', 0x10) + nested(17, kind=0x50))
    add(fr, GEN, TOCLI, 0x0a, struct.pack('<H', 0x10) + nested(17, kind=0x51))
    add(fr, GEN, TOCLI, 0x01, struct.pack('<HB', 0x10, 0) + nested(18))
    # 20 levels and an array of structures (zero length elements)
    add(bad, GEN, TOCLI, 0x0a, struct.pack('<H', 0x10) + nested(20))
    add(bad, GEN, TOCLI, 0x0a, struct.pack('<H', 0x10) + arr(0x4c, 2, b'\x01\x02'))
    add(bad, GEN, TOCLI, 0x0a, struct.pack('<H', 0x10) + st(0x4c, 2, b'\x01\x02'))
    # the reproducer of the unbounded recursion: 1000 levels deep
    add(bad, GEN, TOCLI, 0x0a, struct.pack('<H', 0x10) + nested(1000))
    # ---- cluster specific commands: no cluster dissector for the cluster / manufacturer code
    for d in (0x01, 0x09):
        add(fr, GEN, d, 0x00, b'\x01\x02')
        add(fr, GEN, d, 0x7f, b'')
        add(fr, LOCK, d, 0x7f, b'\x01')
    add(fr, GEN, 0x01, 0x05, b'\x01\x02', mfr=MFR)
    add(fr, LOCK, 0x09, 0x05, b'\x01', mfr=MFR)
    # unknown profile-wide command ids
    add(fr, GEN, TOSRV, 0x17, b'\x01')
    add(fr, GEN, TOSRV, 0x7f, b'')
    # the same commands for other profiles that hand frames to ZCL
    for prof in (0x0101, 0x0105, 0x0107, 0x0108, 0x0109, 0x010a, 0xc05e, 0xa1e0):
        add(fr, GEN, TOSRV, 0x00, struct.pack('<H', 0x0000), profile=prof)
    # ---- registered clusters whose attribute decoder is called for the reportable change,
    # and the time formats that the core provides to the cluster dissectors ------------------
    TEMP, COLOR, PWRPROF = 0x0402, 0x0300, 0x001a
    for d in (TOSRV, TOCLI):
        add(fr, TEMP, d, 0x06, b'\x00' + struct.pack('<HBHHh', 0x0000, 0x29, 1, 60, 50))
        add(fr, TEMP, d, 0x09, b'\x00\x00' + struct.pack('<HBHHh', 0x0000, 0x29, 1, 60, 50))
    add(fr, COLOR, TOCLI, 0x0a, A(0x0002, 0x21, b'\x0a\x00') + A(0x4004, 0x21, b'\x1e\x00'))
    add(fr, COLOR, TOCLI, 0x01, struct.pack('<HB', 0x0002, 0) + bytes([0x21, 0x0b, 0x00]) + struct.pack('<HB', 0x4004, 0) + bytes([0x21, 0x3c, 0x00]))
    # Power Profile (Energy Phases Schedule Notification): scheduled time in minutes
    add(fr, PWRPROF, 0x01, 0x04, b'\x01\x02\x01\x3c\x00\x02\x78\x00')
    # trailing data after a complete command
    add(fr, GEN, TOSRV, 0x0b, b'\x00\x00\xde\xad')
    return fr, bad

def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    fr, bad = build()
    # malformed capture: the error frames, plus every 9th frame cut short
    cut = [f[:-1] for f in fr[::9]] + [f[:-3] for f in fr[4::13]]
    write_pcap(os.path.join(out, 'zbee-zcl-coverage.pcap'), fr)
    write_pcap(os.path.join(out, 'zbee-zcl-coverage-malformed.pcap'), bad + cut)
    with open(os.path.join(out, 'zbee-zcl-coverage.pcap'), 'rb') as f:
        raw = f.read()
    with gzip.GzipFile(os.path.join(out, 'zbee-zcl_coverage.pcap.gz'), 'wb', mtime=0) as g:
        g.write(raw)
    print(len(fr), len(bad), len(cut))

if __name__ == '__main__':
    main()
