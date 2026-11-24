#!/usr/bin/env python3
# Generates test/captures/nsrp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the Juniper NetScreen Redundant Protocol (NSRP) coverage captures
(synthetic, struct only).

Usage: mknsrp.py <outdir> [-v]

Writes, into <outdir>:
  nsrp-coverage.pcap            main capture (Ethernet, ethertype 0x8133)
  nsrp-coverage-malformed.pcap  frames cut inside the header and the message headers
"""
import struct
import sys
import os

OUT = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('-') else '.'
VERBOSE = '-v' in sys.argv


def eth(payload, dst='01:00:5e:00:00:00', src='02:00:00:00:00:01'):
    mac = lambda m: bytes(int(x, 16) for x in m.split(':'))
    return mac(dst) + mac(src) + struct.pack('!H', 0x8133) + payload


def header(mtype, body, ver=1, clust=1, flag=0, haport=3, dst=0x01020304, src=0x05060708, length=None):
    n = 16 + len(body) if length is None else length
    return struct.pack('!BBBBHBBII', ver, mtype, clust, flag, n, haport, 0, dst, src) + body


def ha(msgtype, data=b'', wst=1, hst=2, flag=0, enc=0x10, total=0, ns=1, nr=2, cksum=0xabcd):
    return struct.pack('!BBBBHBBIHHHH', msgtype, wst, hst, flag, 20 + len(data), enc, 0, total or (20 + len(data)),
                       ns, nr, 0, cksum) + data


def mng(msgtype, data=b'', wst=1, hst=2, flag=0, auth=1, prio=100, dummy=0, cksum=0x1234):
    return struct.pack('!BBBBHBBBBH', msgtype, wst, hst, flag, 12 + len(data), auth, 0, prio, dummy, cksum) + data


def dat(msgtype, data=b'', wst=1, hst=2, flag=0, ifnum=1, total=None):
    return struct.pack('!BBBBHBBI', msgtype, wst, hst, flag, 12 + len(data), ifnum, 0,
                       12 + len(data) if total is None else total) + data


RANGES = []


class Cap:
    def __init__(self, name):
        self.name, self.frames = name, []

    def add(self, payload):
        self.frames.append(eth(payload))
        return len(self.frames)

    def group(self, text):
        first = len(self.frames) + 1
        return lambda: RANGES.append((self.name, first, len(self.frames), text))

    def save(self):
        with open(os.path.join(OUT, self.name), 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            for i, fr in enumerate(self.frames):
                f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
                f.write(fr)


def main():
    os.makedirs(OUT, exist_ok=True)
    c = Cap('nsrp-coverage.pcap')
    g = c.group('HA message (header type 0): every message type 0x01-0x15 and an unknown one, flags, encryption flag, data')
    for mt in list(range(1, 0x16)) + [0x16, 0x80, 0xff]:
        c.add(header(0, ha(mt, b'nsrp ha data %d' % mt, flag=(1 << (mt % 8)) & 0xff)))
    c.add(header(0, ha(0x05, b'z', flag=0x80, enc=0xf0, ns=0xffff, nr=0xffff)))
    c.add(header(0, ha(0x0a, b'x' * 100, flag=0x00, enc=0x0f)))
    g()
    g = c.group('MNG message (header type 2): message types, authentication flag, priority, data')
    for mt in (1, 5, 0x0b, 0x15, 0x30):
        c.add(header(2, mng(mt, b'mng data %d' % mt, auth=mt & 1, prio=(mt * 10) & 0xff)))
    c.add(header(2, mng(0x05, b'z', auth=0xff, prio=0xff, dummy=0xff, cksum=0xffff)))
    g()
    g = c.group('DATA message (header type 3): interface numbers, data; header types 1 (HA, no body shown), 4 and 0xff')
    for i, ifn in enumerate((0, 1, 7, 0xff)):
        c.add(header(3, dat(0x01 + i, b'payload data %d' % i, ifnum=ifn)))
    c.add(header(3, dat(0x0a, b'z', ifnum=2)))
    c.add(header(1, b'\0' * 16))
    c.add(header(4, b'\0' * 16))
    c.add(header(0xff, b'\0' * 16, ver=2, clust=255, flag=0xff, haport=255, dst=0xffffffff, src=0))
    c.add(header(3, dat(0x03, b'minimal frame padding!' * 2), ver=0, clust=0, haport=0, dst=0, src=0xffffffff))
    g()
    c.save()

    m = Cap('nsrp-coverage-malformed.pcap')
    g = m.group('frames cut inside the header and in each message header (exceptions)')
    full = {'ha': header(0, ha(5, b'data')), 'mng': header(2, mng(5, b'data')), 'dat': header(3, dat(1, b'data'))}
    for n in (0, 1, 3, 7, 10, 15):
        m.add(full['ha'][:n])
    for n in (16, 18, 23, 25, 28, 31, 33, 35):
        m.add(full['ha'][:n])
    for n in (17, 24, 26, 27, 29):
        m.add(full['mng'][:n])
    for n in (17, 23, 26, 27):
        m.add(full['dat'][:n])
    m.add(header(0, ha(5)))     # no data after the message header: the data item is cut
    m.add(header(2, mng(5)))
    m.add(header(3, dat(1)))
    g()
    m.save()
    if VERBOSE:
        for r in RANGES:
            print(*r)
        print(len(c.frames), len(m.frames))


main()
