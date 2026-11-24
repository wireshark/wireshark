#!/usr/bin/env python3
# Generates test/captures/hyperscsi_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic captures for packet-hyperscsi.c (ethertype 0x889a).
Usage: mkhyperscsi.py <outdir>"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













from pylib import eth, H, Pcap, S

def hs(res, tagno, last, fragno, ver, cmd, payload=b''):
    h1 = ((res & 0xf) << 4) | ((tagno >> 5) & 0xf)
    h2 = ((tagno & 0x1f) << 3) | (0x04 if last else 0) | ((fragno >> 8) & 3)
    h3 = fragno & 0xff
    return bytes([h1, h2, h3, ver, cmd]) + payload

def main(out):
    p = Pcap(1)
    cmds = [0x00, 0x01, 0x10, 0x11, 0x12, 0x13, 0x20, 0x21]
    for i, c in enumerate(cmds):
        p.add(eth(S, H, 0x889a, hs(0, 10 + i, True, 0, 1, c, bytes(range(40)))))
    # Replies from the target
    p.add(eth(H, S, 0x889a, hs(0, 10, True, 0, 1, 0x01, bytes(range(40)))))
    # Unknown commands, and the top bit of the command set (masked off)
    p.add(eth(S, H, 0x889a, hs(0, 20, True, 0, 1, 0x30, bytes(40))))
    p.add(eth(S, H, 0x889a, hs(0, 21, True, 0, 1, 0x7f, bytes(40))))
    p.add(eth(S, H, 0x889a, hs(0, 22, True, 0, 1, 0x80 | 0x01, bytes(40))))
    # Fragments: not last, then last, with the maximum tag and fragment numbers
    p.add(eth(S, H, 0x889a, hs(3, 0x1ff, False, 0x3ff, 2, 0x00, bytes(40))))
    p.add(eth(S, H, 0x889a, hs(0xf, 0x1ff, True, 0x155, 2, 0x00, bytes(40))))
    p.add(eth(S, H, 0x889a, hs(1, 0, False, 1, 0, 0x00, bytes(40))))
    # Header with no payload beyond the 5 octets (padded by Ethernet)
    p.add(eth(S, H, 0x889a, hs(0, 1, True, 0, 1, 0x10)))
    p.write(os.path.join(out, 'hyperscsi-coverage.pcap'))

    m = Pcap(1)
    # Truncated below the 5 octets of header and PDU start
    for n in (2, 3, 4):
        m.add(eth(S, H, 0x889a, hs(0, 1, True, 0, 1, 0x00)[:n]))
    m.write(os.path.join(out, 'hyperscsi-coverage-malformed.pcap'))

main(sys.argv[1])
