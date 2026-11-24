#!/usr/bin/env python3
# Generates test/captures/sdlc_coverage.syc.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the SDLC coverage captures. Usage: mksdlc.py <outdir>
SDLC frames are reached through a Sniffer (.syc) file, which carries the
direction (DTE->DCE = command) in the frame status byte, or through pcap
link type 268. In pcap/pcapng the SDLC pseudo header is all zero, so every
frame there is a response (frame.c overrides the pcapng direction flag)."""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import struct
from c17lib import pcapng

LT = 268
IN, OUT = 1, 2   # IN = DCE->DTE (response, P2P_DIR_RECV), OUT = DTE->DCE (command, P2P_DIR_SENT)

def syc(path, frames, flags):
    def rec(t, body=b''):
        return struct.pack('<HHH', t, len(body), 0) + body
    out = b'TRSNIFF data    \x1a'
    out += rec(1, struct.pack('<hhhhbBbBbbhh', 4, 0, 0, 0, 4, 7, 1, 1, 0, 0, 0, 0))
    out += rec(7, bytes([0, 0, 0, 0, 0, 0]))   # HEADER2: network subtype 0 = SDLC (5th octet)
    for i, (f, d) in enumerate(zip(frames, flags)):
        t = (i + 1) * 100000
        fs = 0x80 if d == OUT else 0
        hdr = struct.pack('<HHBBhBBhh', t & 0xffff, t >> 16, 0, 0, len(f), fs, 0, 0, 0)
        out += rec(4, hdr + f)
    out += rec(3)
    open(path, 'wb').write(out)

def th_fid2(daf=1, oaf=2, snf=0x0001):
    return struct.pack('>BBBBH', 0x2e, 0x00, daf, oaf, snf)

def sna(rh=b'\x0b\x80\x00', ru=b'\x01\x02\x03'):
    return th_fid2() + rh + ru

def main(outdir):
    fr, fl = [], []
    def add(addr, ctl, payload=b'', d=OUT):
        fr.append(bytes([addr, ctl]) + payload); fl.append(d)
    # I frames, both directions, all N(S)/N(R) corners, P/F set and clear
    for d in (OUT, IN):
        for ns, nr, pf in ((0, 0, 0), (1, 2, 1), (7, 7, 0), (3, 5, 1)):
            add(0xc1, (nr << 5) | (pf << 4) | (ns << 1), sna(), d)
    # I frame with each other FID type and a short/empty SNA payload
    for fid in (0x0e, 0x1e, 0x3e, 0x4e, 0x5e, 0xfe, 0x2e):
        add(0xc1, 0x00, bytes([fid]) + b'\0' * 9 + b'\x0b\x80\x00' + b'\x01\x02\x03' + b'\0' * 30)
    # S frames: RR, RNR, REJ, and the 4th type (SREJ), both directions, P/F
    for d in (OUT, IN):
        for st in (0, 1, 2, 3):
            for nr, pf in ((0, 0), (5, 1)):
                add(0xc1, (nr << 5) | (pf << 4) | (st << 2) | 1, b'', d)
    add(0xc3, 0x01, b'\xaa\xbb', OUT)   # S frame with trailing data
    # U frames: every 5 bit modifier, P/F clear and set, both directions
    for d in (OUT, IN):
        for m in range(32):
            ctl = ((m >> 2) << 5) | ((m & 3) << 2) | 3
            pl = sna() if m == 0 else b''   # UI carries SNA
            add(0xc1, ctl, pl, d)
            add(0xc1, ctl | 0x10, pl, d)
    add(0xc1, 0xbf, b'\x01\x02\x03\x04', OUT)   # XID with data
    add(0xc1, 0x97, b'\x01\x02', IN)            # FRMR with data
    add(0xff, 0x93, b'', OUT)                   # broadcast address SNRM
    add(0x00, 0x73, b'', IN)                    # UA from address 0
    # No direction flag at all (treated as response)
    add(0xc1, 0x10, sna(), None)
    add(0xc1, 0x01, b'', None)
    syc(os.path.join(outdir, 'sdlc-coverage.syc'), fr, fl)
    main_n = len(fr)
    pcapng(os.path.join(outdir, 'sdlc-coverage-linktype.pcapng'), LT, fr[:60], fl[:60])

    # Malformed: truncations and odd lengths
    fr, fl = [], []
    for d in (OUT, IN, None):
        fr.append(b''); fl.append(d)             # no address
        fr.append(b'\xc1'); fl.append(d)         # no control
    fr.append(b'\xc2\x02'); fl.append(OUT)
    fr.append(b'\xc2\x02\x2e'); fl.append(OUT)
    fr.append(b'\xc2\x03'); fl.append(IN)
    for ctl in (0x00, 0x01, 0x03, 0x1f):
        for d in (OUT, IN):
            fr.append(bytes([0xc1, ctl])); fl.append(d)
    big = sna() * 40
    fr.append(b'\xc1\x00' + big); fl.append(OUT)
    fr.append(b'\xc1\x00' + b'\xf0' + b'\xff' * 100); fl.append(IN)
    fr.append(b'\xc1\x00\x2e\x00\x01'); fl.append(OUT)   # TH cut after 5 octets
    fr.append(b'\xc1\x00' + th_fid2() + b'\x0b\x80'); fl.append(OUT)  # RH cut
    fr.append(b'\xc1\x00' + th_fid2()); fl.append(IN)    # no RH
    syc(os.path.join(outdir, 'sdlc-coverage-malformed.syc'), fr, fl)
    pcapng(os.path.join(outdir, 'sdlc-coverage-malformed.pcapng'), LT, fr, [None if d is None else d for d in fl])
    print(main_n, len(fr))

main(sys.argv[1])
