#!/usr/bin/env python3
# Generates test/captures/msnip_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the MSNIP coverage captures: mkmsnip.py <outdir> [-v]
MSNIP is carried in IGMP (IP protocol 2) packets of type 0x23-0x25 sent to
224.0.0.22 (the dissector ignores other destinations)."""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from k11lib import csum, eth, ipv4

def ip4(a): return bytes(int(x) for x in a.split('.'))

def igmp(body, good=True):
    """body: the IGMP message with the checksum field (octets 2-3) zero"""
    ck = csum(body)
    if not good:
        ck ^= 0x5a5a
    return body[:2] + struct.pack('!H', ck) + body[4:]

def frame(payload, dst='224.0.0.22', src='192.0.2.1'):
    return eth(ipv4(2, payload, src, dst))

def gm(groups, hold=60, good=True):
    b = struct.pack('!BBHI', 0x23, len(groups), 0, hold)
    for g, m in groups:
        b += ip4(g) + bytes([m]) + b'\0\0\0'
    return igmp(b, good)

def isol(hold=30, genid=7, good=True):
    return igmp(struct.pack('!BBHHH', 0x24, 0, 0, hold, genid), good)

def rmr(recs, good=True):
    b = struct.pack('!BBH', 0x25, len(recs), 0)
    for t, g in recs:
        b += bytes([t]) + b'\0\0\0' + ip4(g)
    return igmp(b, good)

def build():
    main, mal, notes = [], [], []
    def mark(t): notes.append((len(main) + 1, t))
    mark('Multicast Group Map: 0, 1 and 3 groups; Interest Solicitation; Receiver Membership Report with every record type')
    main.append(frame(gm([])))
    main.append(frame(gm([('239.1.1.1', 24)], hold=3600)))
    main.append(frame(gm([('239.1.1.1', 24), ('232.5.5.5', 32), ('224.9.9.9', 4)])))
    main.append(frame(isol()))
    main.append(frame(isol(hold=0xffff, genid=0xffff)))
    main.append(frame(rmr([])))
    main.append(frame(rmr([(1, '239.1.1.1')])))
    main.append(frame(rmr([(2, '239.1.1.1'), (1, '232.5.5.5'), (9, '224.9.9.9')])))
    mark('MSNIP to a destination other than 224.0.0.22: not MSNIP (IGMP unknown)')
    main.append(frame(rmr([(1, '239.1.1.1')]), dst='192.0.2.2'))
    main.append(frame(gm([('239.1.1.1', 24)]), dst='224.0.0.1'))
    mark('IP payload longer than the capture: the checksum is not verified')
    # a GM with no groups, IP header claims 40 octets of payload, the capture has 8
    f = gm([])
    p = ipv4(2, f, '192.0.2.1', '224.0.0.22')
    p = bytearray(p); p[2:4] = struct.pack('!H', 20 + 40); p[10:12] = b'\0\0'; p[10:12] = struct.pack('!H', csum(bytes(p[:20])))
    main.append(('cut', eth(bytes(p)), 14 + 20 + 40))
    # ---- malformed
    mal.append(frame(gm([('239.1.1.1', 24)], good=False)))        # bad checksums
    mal.append(frame(isol(good=False)))
    mal.append(frame(rmr([(1, '239.1.1.1')], good=False)))
    mal.append(frame(gm([('239.1.1.1', 24)])[:-6]))               # group cut
    mal.append(frame(rmr([(1, '239.1.1.1')])[:-3]))
    mal.append(frame(isol()[:-3]))
    mal.append(frame(struct.pack('!BBHI', 0x23, 5, 0, 0)))
    mal.append(frame(struct.pack('!BBH', 0x25, 200, 0) + b'\0' * 16))
    mal.append(frame(b'\x24\x00'))
    return main, mal, notes

def write(fname, frames):
    with open(fname, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, p in enumerate(frames):
            wl = None
            if isinstance(p, tuple): _, p, wl = p
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), wl or len(p)))
            f.write(p)

if __name__ == '__main__':
    out = sys.argv[1]
    main, mal, notes = build()
    write(os.path.join(out, 'msnip-coverage.pcap'), main)
    write(os.path.join(out, 'msnip-coverage-malformed.pcap'), mal)
    if '-v' in sys.argv:
        print('main', len(main), 'malformed', len(mal))
        for n, t in notes: print(n, t)
