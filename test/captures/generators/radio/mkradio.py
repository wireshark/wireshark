#!/usr/bin/env python3
# Generates test/captures/radio_coverage.pcap.gz, radio_coverage_ampdu.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the wlan_radio coverage captures (synthetic).  Usage: mkradio.py <outdir>

The 802.11 radio information dissector (packet-ieee80211-radio.c) gets its
data from a pseudo header.  A pcap file with DLT 127 (radiotap) is the
way a real capture reaches it, so the frames are radiotap frames with
a TSFT, the PHY fields and a minimal 802.11 frame (null data, RTS, ack,
beacon without vendor IEs).

radio-coverage.pcap            main capture, no malformed frames, identical in one and two passes
radio-coverage-ampdu.pcap      A-MPDU subframes (the first subframe is shown without the aggregate
                               information in a one pass dissection, see README)
radio-coverage-malformed.pcap  frames with more 11be users than slots, U-SIG with
                               unknown bits (static header state, see README)
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
import random
from rtlib import ack, add_fcs, beacon, nulldata, rts, simple, write_pcap

out = sys.argv[1] if len(sys.argv) > 1 else '.'
rng = random.Random(0x11ad)
main, bad, agg = [], [], []
U64 = 0xffffffffffffffff


def rb(n, bias=0.3):
    r = bytearray()
    for _ in range(n):
        x = rng.random()
        r.append(0 if x < bias / 2 else 0xff if x < bias else rng.randrange(256))
    return bytes(r)


tsf = [1000000]
marks = {}


def body(kind=None, fcs=False):
    k = kind or rng.choice(['null', 'qos', 'rts', 'ack', 'beacon', 'null'])
    s = rng.randrange(4096)
    f = {'null': lambda: nulldata(s), 'qos': lambda: nulldata(s, qos=True), 'rts': lambda: rts(rng.choice([0, 44, 314, 0x8001])),
         'ack': ack, 'beacon': lambda: beacon(b'radio', s, s),
         'long': lambda: nulldata(s, qos=True) + bytes(rng.randrange(256) for _ in range(rng.choice([60, 150, 300])))}[k]()
    return add_fcs(f) if fcs else f


def fr(fields, kind=None, t=None, step=None, fcs=False, lst=None, tlv=None, flag=None):
    """a radiotap frame: TSFT (t, or advancing by step), flags (flag) and fields"""
    fl = list(fields)
    if t is None:
        tsf[0] += step if step is not None else rng.randrange(40, 3000)
        t = tsf[0]
    else:
        tsf[0] = t if t != U64 else tsf[0]
    fl.append((0, struct.pack('<Q', t)))
    if flag is not None:
        fl.append((1, bytes([flag])))
    (main if lst is None else lst).append(simple(fl, tlv=tlv) + body(kind, fcs or bool(flag is not None and flag & 0x10)))


def chan(f, fl):
    return (3, struct.pack('<HH', f, fl))


marks['legacy'] = len(main) + 1
# ------------------------------------------------------------ legacy PHYs
RATES_B = (2, 4, 11, 22, 44, 66)
RATES_OFDM = (12, 18, 24, 36, 48, 72, 96, 108)
for rate in RATES_B:
    for fl in (0x00, 0x02, 0x10, 0x12):
        fr([(2, bytes([rate])), chan(2412, 0x00a0)], flag=fl, kind='long' if rate == 4 else None)
    fr([(2, bytes([rate])), chan(2412, 0x0080)])                  # DSSS channel
    fr([(2, bytes([rate])), chan(2412, 0x0480)])                  # dynamic CCK-OFDM at a DSSS rate: 11b
    fr([(2, bytes([rate])), chan(2437, 0x00c0)], flag=0x02)       # pure g channel at a DSSS rate
    fr([(2, bytes([rate]))], flag=0x00)                           # no channel: guess from the rate
    fr([(2, bytes([rate])), chan(2412, 0x0000)])
for rate in RATES_OFDM:
    for freq, fl in ((5180, 0x0140), (5180, 0x0150), (5180, 0x2150), (5180, 0x2140), (2437, 0x00c0), (2437, 0x0480),
                     (2437, 0x00d0), (5180, 0x4140), (5180, 0x8140), (2412, 0x0000), (5805, 0x0000)):
        fr([(2, bytes([rate])), chan(freq, fl)], kind='long' if rate == 24 else None)
    fr([(2, bytes([rate]))])
    fr([(2, bytes([rate])), chan(2417, 0x0000)], flag=0x10)
    fr([(2, bytes([rate])), chan(5180, 0x0100 | 0x0040)], flag=0x00)
fr([(2, bytes([22])), chan(2412, 0x0090)])
fr([(2, bytes([6])), chan(2412, 0x00a0)])                         # rate that is neither DSSS nor OFDM
fr([(2, bytes([0])), chan(2412, 0x00a0)])
fr([(2, bytes([0x80 + 7])), chan(5180, 0x0140)])
fr([chan(2412, 0x0880), (4, bytes([3, 9]))])                       # FHSS with hop set and pattern
fr([chan(2412, 0x0880), (4, bytes([1, 2])), (2, b'\x02')])
fr([chan(2412, 0x0880)])
fr([chan(0, 0x0080), (2, b'\x02')])
# no TSFT
for r in (2, 12, 108):
    main.append(simple([(2, bytes([r])), chan(5180, 0x0140)]) + body())
    main.append(simple([(2, bytes([r])), chan(2412, 0x00a0)]) + body())
# signal and noise
for sig, noi in ((-60, -95), (-30, None), (None, -90), (-128, -128), (127, 0)):
    f = [(2, b'\x0c'), chan(5180, 0x0140)]
    if sig is not None:
        f.append((5, struct.pack('<b', sig)))
    if noi is not None:
        f.append((6, struct.pack('<b', noi)))
    fr(f)
fr([(2, b'\x0c'), (12, b'\x28'), (13, b'\x0a')])
fr([(2, b'\x0c'), (5, b'\xc4'), (12, b'\x28')])
fr([(2, b'\x0c'), (5, b'\xc4'), (6, b'\xa0'), (11, b'\x01'), (10, b'\x14'), (7, b'\x42\x00')])
# tsf going backwards / equal (negative or zero inter frame space)
fr([(2, b'\x0c'), chan(5180, 0x0140)], t=50000)
fr([(2, b'\x0c'), chan(5180, 0x0140)], t=50000)
fr([(2, b'\x0c'), chan(5180, 0x0140)], t=49000)
fr([(2, b'\x0c'), chan(5180, 0x0140)], t=0)
fr([(2, b'\x0c'), chan(5180, 0x0140)], t=1 << 40)
fr([(2, b'\x0c'), chan(5180, 0x0140)], t=(1 << 40) + 60)

marks['11n'] = len(main) + 1
# ------------------------------------------------------------------ 11n
def mcs(known, flags, idx):
    return (19, bytes([known, flags, idx]))

for known in (0x07, 0x47, 0x4f, 0x5f, 0x7f, 0x3f, 0xff, 0x03, 0x05, 0x06, 0x01, 0x02, 0x04, 0x00, 0x27, 0x17, 0x0f, 0x7e):
    for flags in (0x00, 0x04, 0x01, 0x05, 0x08, 0x10, 0x20, 0x40, 0x60, 0x80, 0x1d, 0x7f, 0xff):
        if rng.random() > 0.4:
            continue
        fr([mcs(known, flags, rng.choice([0, 1, 3, 7, 8, 15, 16, 23, 24, 31, 32, 33, 52, 76, 77, 100]))],
           flag=rng.choice([None, 0x00, 0x10]), kind=rng.choice([None, 'long']))
for i in range(78):
    for k in range(2):
        bw = (i + k) % 2
        gi = ((i + k) // 2) % 2
        fr([mcs(0x07, bw | (gi << 2), i), chan(5180 if i % 2 else 2437, 0x0140 if i % 2 else 0x00c0)],
           kind='long' if i % 13 == 0 else None)
for st in range(4):
    for ne in range(4):
        for gf in (0, 1):
            fr([mcs(0x7f, 0x04 | (gf << 3) | (st << 5) | ((ne & 1) << 7), 11)])
            fr([mcs(0xff if ne & 2 else 0x7f, (gf << 3) | (st << 5) | ((ne & 1) << 7) | 0x10, 11)])
for k in range(0, 0x80):
    if k % 5:
        continue
    fr([mcs(k | 0x02 if k & 0x40 == 0 else k | 0x7, rng.randrange(256), rng.randrange(0, 80))])
fr([mcs(0x00, 0, 0)])
fr([mcs(0x07, 0x00, 4), (1, b'\x80')])
fr([mcs(0x03, 0x00, 4), (1, b'\x80')])
fr([mcs(0x03, 0x00, 4), (1, b'\x00')])

# aggregates (A-MPDUs): subframes of one PPDU carry the same TSF (Broadcom),
# or the TSF of the first and then 0 (Intel), or -1 until the last (QCA)
def ampdu(fields_fn, n, pattern, base):
    for i in range(n):
        if pattern == 'same':
            t = base
        elif pattern == 'intel':
            t = base if i == 0 else 0
        elif pattern == 'qca':
            t = U64 if i < n - 1 else base + 600
        else:
            t = base + 100 * i
        fr(fields_fn(i), t=t, kind=rng.choice(['long', 'qos', 'null']), flag=0x10 if i % 3 == 0 else 0x00, lst=agg)
    tsf[0] = base + 3000


for pattern in ('same', 'intel', 'qca', 'none'):
    for n in (2, 3, 5):
        base = tsf[0] + 5000
        ampdu(lambda i: [mcs(0x07, 0x04, 9 + (i % 3)), (5, bytes([0xc0 + i])), chan(5180, 0x0140)], n, pattern, base)
        base = tsf[0] + 5000
        ampdu(lambda i: [mcs(0x07, 0x00 if i % 2 else 0x01, 12 + i), (5, bytes([0xc0]))], n, pattern, base)
    base = tsf[0] + 5000
    ampdu(lambda i: [mcs(0x07 | 0x20, 0x04 | (1 << 5), 3 + i), (20, struct.pack('<IHBB', 77, 0, 0, 0))], 3, pattern, base)

marks['11ac'] = len(main) + 1
# ----------------------------------------------------------------- 11ac
def vht(known, flags, bw, users, coding=0, gid=0, paid=0):
    u = bytes(users) + bytes(4 - len(users))
    return (21, struct.pack('<HBB', known, flags, bw) + u + bytes([coding, gid]) + struct.pack('<H', paid))

for mcs_ in range(12):
    for nss in (1, 2, 3, 4, 5, 8, 9):
        for k in range(2):
            bw = rng.choice([0, 1, 4, 11, 12, 20])
            fr([vht(0x017f, 4 * k, bw, [(mcs_ << 4) | nss]), chan(5180, 0x0140)],
               kind='long' if (mcs_ + nss) % 11 == 0 else None)
for known in (0, 0x0004, 0x0040, 0x0044, 0x0001 | 0x0004 | 0x0040, 0x0002 | 0x0044, 0x0008 | 0x0044, 0x0010 | 0x0044,
              0x0020 | 0x0044, 0x00ff | 0x100, 0x0180 | 0x44, 0x0100 | 0x44, 0xffff):
    for flags in (0x00, 0x01, 0x04, 0x0c, 0x08, 0x1f, 0x3f, 0x02, 0x10, 0x20):
        for users in ([0x11], [0x11, 0x92], [0x11, 0x92, 0x23], [0x11, 0x92, 0x23, 0x84], [0x00], [0xf1, 0xa2], [0xc3, 0x00, 0x14]):
            if rng.random() > 0.15:
                continue
            fr([vht(known, flags, rng.choice([0, 1, 4, 11]), users, rng.randrange(16), rng.randrange(64), rng.randrange(512)),
                chan(5180, 0x0140)], kind=rng.choice([None, None, 'long']))
for pattern in ('same', 'intel', 'qca', 'none'):
    for n in (2, 4):
        base = tsf[0] + 5000
        ampdu(lambda i: [vht(0x007f, 0x04, 4, [(7 << 4) | 2]), (20, struct.pack('<IHBB', 5, 0, 0, 0))], n, pattern, base)
        base = tsf[0] + 5000
        ampdu(lambda i: [vht(0x007f, 0x01, 1, [((3 + i) << 4) | 1]), chan(5180, 0x0140)], n, pattern, base)
        base = tsf[0] + 5000
        ampdu(lambda i: [vht(0x0044, 0x00, 1, [0x11, 0x22]), chan(5180, 0x0140)], n, pattern, base)
    # a switch from 11n to 11ac inside the pattern: no aggregate
    ampdu(lambda i: [mcs(0x07, 0, 5)] if i < 2 else [vht(0x007f, 0x04, 4, [0x72])], 4, pattern, tsf[0] + 7000)

for bw in (26, 27, 31):                                            # bandwidth beyond the rate table
    fr([vht(0x0044, 0x00, bw, [0x11]), chan(5180, 0x0140)])
    fr([vht(0x0044, 0x04, bw, [0x42, 0x31]), chan(5180, 0x0140)], flag=0x10)

marks['11ax'] = len(main) + 1
# ----------------------------------------------------------------- 11ax
for _ in range(60):
    fr([(23, rb(12))], flag=rng.choice([None, 0x00]))
for fmt in range(4):
    for d5 in (0x0000, 0x0001, 0x0102, 0x0213, 0x0d34, 0x0f0f, 0x0707, 0x0022, 0x1234):
        for d3 in (0xffff, 0x0000, 0x5555, 0x00ff, 0xa000):
            if rng.random() > 0.5:
                continue
            d1 = fmt | (rng.choice([0xffff, 0x7ffc, 0x0000, 0x3ff0, 0x4ffc]) & ~3)
            fr([(23, struct.pack('<HHHHHH', d1, rng.choice([0xffff, 0x0000, 0x00ff]), d3, rng.randrange(65536), d5, rng.randrange(65536)))])
# data rate for SU: known gi/bw/mcs/nss with the known bits for data1/data2
for nss in range(1, 9):
    for mcs_ in range(0, 12):
        for gi in range(4):
            for bw in (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 16, 20):
                if rng.random() > 0.12:
                    continue
                d3 = (mcs_ << 8) | 0x0f00 & 0 | 0x0fc0 & 0
                fr([(23, struct.pack('<HHHHHH', 0x3ffc & ~3 | 0, 0xffff, (mcs_ << 8) | 0x0010, ((nss - 1) << 4) | (nss - 1) | 0x0000, bw | (gi << 4) | 0x0000, 0))])
for _ in range(30):
    fr([(24, rb(12))], kind=rng.choice([None, 'qos']))
for _ in range(25):
    fr([(23, rb(12)), (24, rb(12))])
fr([(23, rb(12)), (24, rb(12)), (5, b'\xc3')], tlv=[(26, b'\x01'), (27, struct.pack('<HH', 3, 0x0150))])

marks['psdu'] = len(main) + 1
# --------------------------------------------------------------- zero-length PSDU, L-SIG
for t in (0, 1, 2, 3, 0x7f, 0xff):
    fr([(26, bytes([t]))])
for rl in range(0, 12):
    fr([(27, struct.pack('<HH', rng.choice([3, 1, 2, 0]), (rl * 97 << 4 & 0xfff0) | rng.randrange(16)))], kind='ack')
fr([(26, b'\x00'), (27, struct.pack('<HH', 3, 0x0150))])

marks['11be'] = len(main) + 1
# ------------------------------------------------------- 11be, 11ah, 11ad
def usig(common, val, mask=0xffffffff):
    return (33, struct.pack('<III', common, val, mask))

users = lambda n: b''.join(rb(4) for _ in range(n))
for n in (0, 1, 2, 3, 4):
    for _ in range(14):
        fr([], tlv=[(34, rb(40, 0.45) + users(n))], kind=rng.choice([None, 'long']))
for n in (1, 2, 4):
    for ul_dl in (0, 1):
        for tc in range(4):
            common = (rng.randrange(1 << 32) | 0x7f) & ~4 | (ul_dl << 2)
            common |= (rng.randrange(8) << 3) & 0 | (0x1 << 8)
            for _ in range(2):
                fr([], tlv=[usig(common, (tc << 6) | rng.randrange(64) | (rng.randrange(1 << 24) << 8)),
                            (34, struct.pack('<I', rng.choice([0xffffffff, rng.randrange(1 << 32) | 0x1fff])) + rb(36, 0.5) + users(n))])
# EHT with known gi/nss/mcs (rate), several bandwidths/RU sizes
for gi in range(3):
    for bwv in range(0, 8):
        for mcs_ in (0, 5, 13, 14, 15):
            for nss in (1, 2, 3, 0):
                if rng.random() > 0.2:
                    continue
                known = 0xffffffff
                data0 = (gi << 4) | 0x8
                ui = 0x0000007f | (mcs_ << 20) | (nss << 24)
                fr([], tlv=[usig((bwv << 0) | 0x7ff0 | (1 << 26) | (1 << 3 + 0) & 0, 0), (34, struct.pack('<II', known, data0) + rb(32, 0.2) + struct.pack('<I', ui))])
for sizes in range(0, 34):
    fr([], tlv=[(34, struct.pack('<III', 0xffffffff, rng.randrange(1 << 32), (sizes) | rng.randrange(1 << 24) << 5) + rb(28) + struct.pack('<I', 0xffffffff & ~1))])
for _ in range(25):
    fr([], tlv=[(32, rb(6, 0.5))])
fr([(5, b'\xc5')], tlv=[(32, rb(6)), (34, rb(40))])
# U-SIG / EHT combined, all fields known
for ul_dl in (0, 1):
    for tc in range(4):
        for bwv in (0, 1, 2, 3, 4, 5, 6, 7):
            common = 0x00000fff & ~4 | (ul_dl << 2) | (bwv << 18) | 0x1 << 13
            fr([], tlv=[usig(common, (tc << 6) | rng.randrange(64)), (34, struct.pack('<I', 0xffffffff) + rb(32, 0.1) + struct.pack('<I', 0x0f0f0ff0) + struct.pack('<I', 0x0b0000ff | (rng.randrange(3) << 24)))])
# 11ad: a frequency in the 60 GHz band with an MCS field
for fqz in (57240, 58320, 60480, 62640, 64800):
    fr([chan(fqz, 0x0100), mcs(0x07, 0x04, 3)])
    fr([chan(fqz, 0x0100)])
    fr([chan(fqz, 0x0100), (2, b'\x0c')])
# 6 GHz and S1G channel flags
for freq, fl in ((5955, 0x0100), (6115, 0x0100), (7115, 0x0100), (902, 0x0001 | 0x0100), (916, 0x0002), (868, 0x0004)):
    fr([chan(freq, fl), (2, b'\x0c')])

marks['xchannel'] = len(main) + 1
# ------------------------------------------------------------- xchannel
for xf, fq in ((0x0040 | 0x0100, 5180), (0x0080 | 0x0020, 2412), (0x0140 | 0x20000, 5180), (0x00a0 | 0x10000, 2412), (0x0100 | 0x0040 | 0x40000, 5200)):
    fr([(18, struct.pack('<IHBB', xf, fq, 36, 0)), (19, bytes([0x07, 0x04, 5]))])
    fr([(18, struct.pack('<IHBB', xf, fq, 36, 0)), (2, b'\x0c')])

# ---------------------------------------------------------------- malformed
# 11be with more users than the slots of the pseudo header (a warning "malformed" expert info)
for _ in range(4):
    bad.append(simple([(0, struct.pack('<Q', 5))], tlv=[(34, rb(40) + users(5))]) + body('null'))
    bad.append(simple([(0, struct.pack('<Q', 5))], tlv=[(34, rb(40) + users(9))]) + body('null'))
# U-SIG frames with unknown bits (stale static header arrays, see README)
for ul_dl in (0, 1):
    for tc in range(4):
        for mask in (0, 0x0f0f0f0f, 0xaaaaaaaa, 0x00ffff00, 0x55555555):
            common = rng.randrange(1 << 32) & ~4 | (ul_dl << 2) | 0xf7f
            bad.append(simple([(0, struct.pack('<Q', 5))], tlv=[(33, struct.pack('<III', common, (tc << 6) | rng.randrange(64), mask))]) + body('null'))

# Cisco WIDS (Decode As UDP port): wlan_noqos_radio, no radiotap involved
def cwids(frames):
    d = b''
    for f in frames:
        d += struct.pack('>H', 2) + bytes(6) + b'\x00' + bytes([rng.choice([1, 6, 11, 36])]) + bytes(6)
        d += struct.pack('>HH', len(f), len(f)) + bytes(8) + f
    return d


def udp_eth(payload, sport=1234, dport=2887):
    udp = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0, bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]))
    s = sum(struct.unpack('>10H', ip)); s = (s & 0xffff) + (s >> 16); s = (s & 0xffff) + (s >> 16)
    ip = ip[:10] + struct.pack('>H', ~s & 0xffff) + ip[12:]
    return bytes.fromhex('020000000002020000000001') + b'\x08\x00' + ip + udp

wids = [udp_eth(cwids([nulldata(1), rts(30)])), udp_eth(cwids([beacon(b'wids', 5, 5)])),
        udp_eth(cwids([nulldata(2, qos=True), ack(), nulldata(3)]))]
os.makedirs(out, exist_ok=True)
write_pcap(os.path.join(out, 'radio-coverage-cwids.pcap'), 1, wids)
write_pcap(os.path.join(out, 'radio-coverage.pcap'), 127, main, step=2000)
write_pcap(os.path.join(out, 'radio-coverage-ampdu.pcap'), 127, agg, step=2000)
write_pcap(os.path.join(out, 'radio-coverage-malformed.pcap'), 127, bad)
print(len(main), len(bad), len(agg), marks)
