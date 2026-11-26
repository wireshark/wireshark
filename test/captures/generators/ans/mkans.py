#!/usr/bin/env python3
# Intel ANS probe coverage capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Intel Advanced Network Services (ANS) fault tolerance probes, which are
sent as Ethernet frames of ethertype 0x886d, to the broadcast address or to
the multicast address 01:aa:00:00:00:00.

Usage: mkans.py [<output directory>]

Writes ans-coverage.pcap (probes of several teams, members, revisions and
sequence numbers, with and without the padding) and
ans-coverage-malformed.pcap (probes cut short). Every packet is built here;
nothing comes from a real network.
"""

import os
import struct
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))

from capgen import eth, write_pcap  # noqa: E402

ETHERTYPE_INTEL_ANS = 0x886d
BCAST = 'ff:ff:ff:ff:ff:ff'
MCAST = '01:aa:00:00:00:00'
TEAM_A = bytes.fromhex('020000000a01')
TEAM_B = bytes.fromhex('020000000b02')


def probe(seq, sender, team, app=1, rev=1, pad=18):
    return struct.pack('!HHIH', app, rev, seq, sender) + team + bytes(pad)


def build():
    clean, malformed = [], []
    # Broadcast probes of one team: ascending sequence, three members
    for i in range(6):
        clean.append(eth(probe(100 + i, i % 3, TEAM_A), ETHERTYPE_INTEL_ANS,
                         dst=BCAST, src='02:00:00:00:00:%02x' % (0x10 + i % 3)))
    # Multicast probes of another team, another revision
    for i in range(4):
        clean.append(eth(probe(0x01020300 + i, 7, TEAM_B, rev=2), ETHERTYPE_INTEL_ANS,
                         dst=MCAST, src='02:00:00:00:00:20'))
    # Extreme values and other application and revision IDs
    clean.append(eth(probe(0xffffffff, 0xffff, bytes.fromhex('ffffffffffff'), app=0xffff, rev=0xffff),
                     ETHERTYPE_INTEL_ANS, dst=BCAST, src='02:00:00:00:00:30'))
    clean.append(eth(probe(0, 0, bytes(6), app=0, rev=0), ETHERTYPE_INTEL_ANS, dst=BCAST, src='02:00:00:00:00:31'))
    # Without the padding, with extra padding
    clean.append(eth(probe(500, 1, TEAM_A, pad=0), ETHERTYPE_INTEL_ANS, dst=BCAST, src='02:00:00:00:00:10'))
    clean.append(eth(probe(501, 1, TEAM_A, pad=100), ETHERTYPE_INTEL_ANS, dst=BCAST, src='02:00:00:00:00:10'))
    # Malformed: shorter than the fields it decodes
    full = probe(900, 4, TEAM_B)
    for n in (0, 3, 7, 9, 12, 15):
        malformed.append(eth(full[:n], ETHERTYPE_INTEL_ANS, dst=BCAST, src='02:00:00:00:00:40'))
    # Cut by the capture, not by the sender
    malformed.append((eth(full, ETHERTYPE_INTEL_ANS, dst=BCAST, src='02:00:00:00:00:41')[:20], 14 + len(full)))
    return clean, malformed


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    clean, malformed = build()
    write_pcap(os.path.join(out, 'ans-coverage.pcap'), clean)
    write_pcap(os.path.join(out, 'ans-coverage-malformed.pcap'), malformed)
    print('%d + %d frames' % (len(clean), len(malformed)), file=sys.stderr)


if __name__ == '__main__':
    main()
