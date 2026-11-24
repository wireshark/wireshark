#!/usr/bin/env python3
# Generates test/captures/gsm_abis_tfp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic capture for packet-gsm_abis_tfp.c (Abis TRAU Frame Protocol).
Usage: mkgsm_abis_tfp.py <outdir> [-v]
Frames are LAPD (pcap linktype 203) UI frames with SAPI 10 and 11 (TS 48.056
GSM SAPI values; needs lapd.use_gsm_sapi_values:TRUE)."""
import struct
import sys

def write_pcap(path, linktype, pkts):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, p in enumerate(pkts):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
            f.write(p)

def lapd(sapi, tei, payload, cr=0):
    return \
        bytes([(sapi << 2) | (cr << 1), (tei << 1) | 1, 0x03]) + payload

def hdr(atsr, rate, seq, delay, p, s, m, ftype, tail=1):
    v = (atsr << 21) | (rate << 19) | (seq << 14) | (delay << 9) | (p << 7) | (s << 6) | (m << 5) | (ftype << 1) | tail
    return v.to_bytes(3, 'big')

def main():
    out = sys.argv[1]
    verbose = '-v' in sys.argv
    frames = []
    notes = []
    def add(note, sapi, payload, tei=1):
        frames.append(lapd(sapi, tei, payload))
        notes.append((len(frames), note))
    body16 = bytes((i * 7) & 0xff for i in range(40))
    # Slot rates 0..3; 16k (rate 0) frame types 0..15, others 0..15
    for rate in range(4):
        for ft in range(0, 16, 1 if rate == 0 else 3):
            add('rate %d ftype %d' % (rate, ft), 10 if ft & 1 else 11,
                hdr(ft & 7, rate, (ft * 2) & 31, ft + 1, ft & 1, ft & 1, (ft >> 1) & 1, ft) + body16)
    # Reproducer of the fix: slot rate 0, frame type 2 (FR), delay 5, seq 3
    add('reproducer: frame type FR / delay info', 10, hdr(1, 0, 3, 5, 0, 0, 0, 2) + bytes(40))
    # Packing scheme 1, silence, marker
    add('packed scheme 1, S and M', 11, hdr(5, 1, 31, 31, 1, 1, 1, 1) + body16)
    # 8k slot rate (frame bits 160), AMR with rates for all length values
    for ln in (1, 5, 12, 13, 15, 17, 19, 20, 26, 31, 7):
        add('AMR 8k len %d' % ln, 10, hdr(2, 1, ln, 2, 0, 0, 0, 0) + bytes(ln))
    # AMR 16k (frame type 0 | 0x80) with rate
    for ln in (12, 31):
        add('AMR 16k len %d' % ln, 11, hdr(2, 0, ln, 2, 0, 0, 0, 0) + bytes(ln))
    # Tail bit clear: the header continues for further octets
    add('tail bit clear, 2 extension octets', 10, hdr(3, 0, 4, 4, 0, 0, 0, 3, tail=0) + b'\x00\x02\x01' + body16)
    # frame without payload after the header
    add('header only', 11, hdr(0, 3, 0, 0, 0, 0, 0, 15))
    write_pcap(out + '/gsm_abis_tfp-coverage.pcap', 203, frames)
    # Malformed capture: truncated headers, tail bit never set
    bad = [lapd(10, 1, b''), lapd(10, 1, b'\x20'), lapd(11, 1, b'\x20\x00'),
           lapd(10, 1, hdr(1, 0, 1, 1, 0, 0, 0, 1, tail=0)),
           lapd(10, 1, hdr(1, 0, 1, 1, 0, 0, 0, 1, tail=0) + b'\x00\x00\x00'),
           lapd(11, 1, hdr(1, 0, 1, 1, 0, 0, 0, 0) + bytes(5))]
    write_pcap(out + '/gsm_abis_tfp-coverage-malformed.pcap', 203, bad)
    if verbose:
        for n, t in notes:
            print(n, t)
    print(len(frames), 'frames')

main()
