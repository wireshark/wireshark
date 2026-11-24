#!/usr/bin/env python3
# Generates test/captures/wlancap_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic AVS (wlancap) captures. Usage: mkwlancap.py <outdir> [-v]
# Writes wlancap-coverage.pcap (linktype 163, DLT_IEEE802_11_RADIO_AVS) and
# wlancap-coverage-malformed.pcap. Everything is built with struct.
import struct
import sys
import os

DLT_PRISM = 119
DLT_AVS = 163

def pcap(name, linktype, frames):
    with open(name, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)

# Minimal 802.11 frames: nothing beyond the MAC header (no IEs, no EAPOL,
# nothing protected).
A1 = bytes.fromhex('020000000001')
A2 = bytes.fromhex('020000000002')
A3 = bytes.fromhex('020000000003')
def null_data(seq=1, to_ds=True):
    fc = bytes([0x48, 0x01 if to_ds else 0x02])
    return fc + b'\x00\x00' + A1 + A2 + A3 + struct.pack('<H', seq << 4)
def ack():
    return bytes.fromhex('d4000000') + A1

def avs(version=2, phy=4, chan=6, rate=10, ant=1, prio=0, ssi=2, sig=-40,
        noise=-90, pream=2, enc=1, seq=7, drops=0, mactime=0x1122334455,
        hosttime=0x99aabbccdd, length=None, cookie=None, raddr=A2,
        hop=None):
    if cookie is None:
        cookie = 0x80211000 + version
    if hop is not None:
        chan = (hop[0] << 24) | (hop[1] << 16) | (hop[2] << 8)
    n = 80 if version >= 2 else 64
    if length is None:
        length = n
    h = struct.pack('>IIQQIIIIIIiII', cookie, length, mactime, hosttime,
                    phy, chan, rate, ant, prio, ssi, sig,
                    noise & 0xffffffff, pream)
    h += struct.pack('>I', enc)
    if version >= 2:
        h += struct.pack('>II', seq, drops) + raddr + b'\0\0'
    return h

def build(outdir, verbose=False):
    main = []
    notes = []
    def add(label, hdr, body=None):
        main.append(hdr + (null_data(len(main) + 1) if body is None else body))
        notes.append(label)
    # PHY types 0-9 with DSSS data rates etc.
    for phy in range(0, 10):
        add('phy %d' % phy, avs(phy=phy, chan=1 + phy, rate=10 + phy * 10))
    # version 1 (64 bytes), version 0 (also no sequence fields)
    add('v1 11b dbm', avs(version=1, phy=4, chan=11, rate=20))
    add('v0', avs(version=0, phy=6, chan=36, rate=540))
    # FHSS: hop set/pattern/index
    add('fhss', avs(phy=1, hop=(3, 5, 9), rate=10))
    # channel number / MHz / KHz
    add('chan 6 11g', avs(phy=6, chan=6, rate=540))
    add('chan 36 11a', avs(phy=8, chan=36, rate=540))
    add('chan 0', avs(phy=6, chan=0, rate=540))
    add('chan 255 (no freq)', avs(phy=6, chan=255, rate=540))
    add('2437 MHz', avs(phy=6, chan=2437, rate=540))
    add('5180 MHz', avs(phy=8, chan=5180, rate=540))
    add('9000 MHz (no channel)', avs(phy=6, chan=9000, rate=540))
    add('2412000 KHz', avs(phy=6, chan=2412000, rate=540))
    # data rates: 100 kb/s units (small) and b/s (>= 100000), zero, odd
    add('rate 0', avs(phy=6, rate=0))
    add('rate 55 (5.5 Mb/s)', avs(phy=4, rate=55))
    add('rate 11 (1.1 Mb/s, not a half multiple)', avs(phy=4, rate=11))
    add('rate 1000000 b/s', avs(phy=4, rate=1000000))
    add('rate 5500000 b/s', avs(phy=4, rate=5500000))
    add('rate 100000 b/s', avs(phy=4, rate=100000))
    add('rate 100 (10 kb/s? units of 100 kb/s)', avs(phy=6, rate=100))
    # 11g with DSSS rate becomes 11b; 11g with OFDM rate stays
    add('11g dsss rate', avs(phy=9, rate=20))
    add('11g ofdm rate', avs(phy=9, rate=540))
    # reproducer: rate that overflowed uint32 (50000 * 100000)
    add('rate 50000 (overflow reproducer)', avs(phy=4, rate=50000, chan=6))
    add('rate 42950 (just above 2^32/100000)', avs(phy=4, rate=42950))
    # SSI types 0-3 (+ unknown 7) with noise values
    for ssi in (0, 1, 2, 3, 7):
        add('ssi %d' % ssi, avs(phy=6, ssi=ssi, sig=50 if ssi != 2 else -40,
                                noise=20 if ssi != 2 else -90, rate=540))
        add('ssi %d noise unavailable' % ssi,
            avs(phy=6, ssi=ssi, sig=50 if ssi != 2 else -40,
                noise=0xffffffff, rate=540))
    add('ssi 2 noise 0', avs(phy=6, ssi=2, sig=-50, noise=0, rate=540))
    # preamble: only used for DSSS (11b) frames
    for p in (0, 1, 2, 3):
        add('11b preamble %d' % p, avs(phy=4, pream=p, rate=20))
    add('11g preamble 1 (not 11b)', avs(phy=6, pream=1, rate=540))
    # encodings 0-8
    for e in range(0, 9):
        add('encoding %d' % e, avs(enc=e, phy=6, rate=540))
    add('receiver address / sequence', avs(seq=0xffffffff, drops=12345))
    # higher versions and bad cookie: header skipped, 802.11 follows
    add('v3 (skip)', avs(version=2, cookie=0x80211003))
    add('v9 (skip)', avs(version=2, cookie=0x80211009, length=80))
    # a longer header than we know (v2 with 8 extra bytes of header)
    add('v2 length 88', avs(version=2, length=88) + b'\0' * 8)
    # other 802.11 frame types behind the header: control (ACK) and
    # a frame from the DS
    add('ack', avs(phy=6, rate=540), ack())
    add('null from DS', avs(phy=6, rate=540), null_data(3, False))
    # AVS header followed by a header with FCS-sized trailer data
    add('null + 4 bytes', avs(phy=6, rate=540), null_data(4) + b'\xff' * 4)
    # same header as Prism-carried AVS is in the prism capture
    pcap(os.path.join(outdir, 'wlancap-coverage.pcap'), DLT_AVS, main)

    mal = []
    # header length beyond the packet
    mal.append(avs(version=2, length=200) + null_data())
    # truncated header (shorter than version 2 needs)
    mal.append(avs(version=2)[:50])
    # header length 0 on a skip version (the 802.11 dissector gets the
    # whole packet, including the AVS header)
    mal.append(avs(version=2, cookie=0x80211005, length=0) + null_data())
    # length shorter than the fields
    mal.append(avs(version=2, length=10) + null_data())
    # truncated 802.11 frame
    mal.append(avs(version=2) + b'\x48\x01\x00')
    # header only
    mal.append(avs(version=2))
    # too short even for the cookie and length
    mal.append(struct.pack('>I', 0x80211002))
    pcap(os.path.join(outdir, 'wlancap-coverage-malformed.pcap'), DLT_AVS, mal)
    if verbose:
        for i, n in enumerate(notes, 1):
            print(i, n)
        print('main frames:', len(main), 'malformed frames:', len(mal))

if __name__ == '__main__':
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    build(out, '-v' in sys.argv)
