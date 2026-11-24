#!/usr/bin/env python3
# Generates test/captures/ax25_nol3_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Build synthetic AX.25 captures (LINKTYPE_AX25) whose frames carry PID
# 0xF0 (no layer 3) for packet-ax25-nol3.c: plain text, DX cluster
# spots and a few APRS-looking frames for the preference branches (the
# APRS decoding itself is covered by aprs_coverage.pcap.gz).
# Every packet is built with struct; nothing comes from a real network.
# Usage: mkax25_nol3.py <outdir>
import os
import struct
import sys

LINKTYPE_AX25 = 3


def write_pcap(fn, linktype, pkts):
    with open(fn, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, p in enumerate(pkts):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
            f.write(p)


def call(cs, ssid=0, last=False, c=False):
    cs = cs.ljust(6)[:6]
    s = 0x60 | ((ssid & 0xf) << 1) | (0x80 if c else 0) | (1 if last else 0)
    return bytes(ord(ch) << 1 for ch in cs) + bytes([s])


def ax25(info, ctl=0x03, dst='DX', src='N0CLUS', src_ssid=0, resp=False):
    dc, sc = (False, True) if resp else (True, False)
    return call(dst, 0, c=dc) + call(src, src_ssid, last=True, c=sc) + bytes([ctl, 0xF0]) + info


def main(outdir):
    P = []
    M = []
    # 1-3: plain text: a UI frame, an I frame and a UI response
    P.append(ax25(b'Welcome to the N0CLUS node. Type H for help.\r', dst='CQ'))
    P.append(ax25(b'Connected to N0CLUS\r', ctl=0x00, dst='N0USER'))
    P.append(ax25(b'73 de N0USER\r', dst='N0CLUS', src='N0USER', resp=True))
    # 4-8: DX cluster spots ("DX" at the start), UI and I frames
    P.append(ax25(b'DX de K1ABC:     14025.0  W2XYZ        CW 599 strong      1200Z\r\x07\x07'))
    P.append(ax25(b'DX de G4AAA:      7074.0  JA1BBB       FT8 -12 dB         0815Z FN42\r'))
    P.append(ax25(b'DX de VK2CC:     21280.0  ZL1DDD       up 5               2359Z\r', ctl=0x22))
    P.append(ax25(b'DX de N0CALL: 1'))                 # exactly the 15 octets shown in the Info column
    P.append(ax25(b'DX\x01\x02\x7f binary report\xff\xfe'))  # non-printable octets in the report
    # 9-12: text that is not a DX spot: a 'D' without the 'X', lower
    # case, a single octet, and "DX" further on
    P.append(ax25(b'DY de K1ABC: not a spot\r'))
    P.append(ax25(b'dx de k1abc: lower case\r'))
    P.append(ax25(b'X'))
    P.append(ax25(b'Spot: DX de K1ABC 14025.0\r'))
    # 13-16: APRS data type indicators; only a UI frame goes to APRS
    # (with ax25_nol3.showaprs), an I frame with the same text stays text
    P.append(ax25(b'>Status text', dst='APRS'))
    P.append(ax25(b'>Status text in an I frame', ctl=0x00, dst='APRS'))
    P.append(ax25(b'!4903.50N/07201.75W-Test', dst='APRS', resp=True))
    P.append(ax25(b'Hello, not an APRS indicator', dst='APRS'))

    # Malformed capture: paths that throw when a preference is on
    M.append(ax25(b''))                    # empty info field (either preference reads octet 0)
    M.append(ax25(b'D'))                   # showcluster reads octet 1
    M.append(ax25(b'DX'))                  # dissect_dx() shows 15 octets of a 2 octet report
    M.append(ax25(b'DX de K1ABC'))         # 11 octets, still shorter than 15

    write_pcap(os.path.join(outdir, 'ax25_nol3-coverage.pcap'), LINKTYPE_AX25, P)
    write_pcap(os.path.join(outdir, 'ax25_nol3-coverage-malformed.pcap'), LINKTYPE_AX25, M)
    print('ax25_nol3-coverage.pcap: %d frames, ax25_nol3-coverage-malformed.pcap: %d frames' % (len(P), len(M)))


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')
