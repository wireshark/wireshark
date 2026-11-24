#!/usr/bin/env python3
# Generates test/captures/ns_ha_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the NetScaler HA heartbeat (NS-HA) coverage captures (synthetic,
struct only).

Usage: mkns_ha.py <outdir> [-v]

Writes, into <outdir>:
  ns-ha-coverage.pcap            main capture: Exported PDU frames (link type 252)
                                 naming the "nstrace.ha" dissector
  ns-ha-coverage-malformed.pcap  heartbeats cut short
  ns-ha-udp.pcap                 the same heartbeats over UDP port 3003 (needs
                                 Decode As udp.port 3003): runcov.sh only
"""
import struct
import sys
import os

OUT = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('-') else '.'
VERBOSE = '-v' in sys.argv

SIG = 0x01020304


def hb(version, state=3, master=2, app=0, typ=0, sig=SIG, start=1700000000, release=130, flags=0, inc=7,
       sync=0x10, dr=9):
    """The heartbeat of a given version (unknown versions: header only)."""
    h = struct.pack('<IBBBB', sig, version, app, typ, state)
    if version == 10:
        return h + struct.pack('<III', start, 0, master) + struct.pack('<III', release, flags, inc) + \
            struct.pack('<I', sync) + b'\x55' * 96 + struct.pack('<I', dr)
    if version in (8, 9):
        b = struct.pack('<III', start, 0, master) + struct.pack('<III', inc, sync, flags)
        if version == 9:
            b += b'\x55' * 96 + struct.pack('<I', dr)
        return h + b
    if version in (3, 4):
        return h + struct.pack('<IIII', 1, 2, master, inc)
    return h + b'\xee' * 8


def expdu(data, name=b'nstrace.ha'):
    pad = (-len(name)) % 4
    return struct.pack('!HH', 12, len(name) + pad) + name + b'\0' * pad + struct.pack('!HH', 0, 0) + data


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def udp_frame(payload, sport=3003, dport=3003):
    u = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(u), 1, 0, 64, 17, 0, bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2]))
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    return b'\x02\x00\x00\x00\x00\x02' + b'\x02\x00\x00\x00\x00\x01' + b'\x08\x00' + ip + u


def write_pcap(fname, frames, linktype):
    with open(os.path.join(OUT, fname), 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)


RANGES = []


def main():
    os.makedirs(OUT, exist_ok=True)
    frames = []
    udp = []

    def add(group, items):
        first = len(frames) + 1
        for d in items:
            frames.append(expdu(d))
            udp.append(udp_frame(d))
        RANGES.append(('ns-ha-coverage.pcap', first, len(frames), group))

    add('version 10 (7.0 and later): every node state 0-0xB and an unknown one, every master state 0-4 and an unknown one',
        [hb(10, state=s, master=s % 5) for s in range(0x0c)] + [hb(10, state=0x40, master=9)])
    add('version 10: sync states (enabled, failed, success, disabled, in progress, unknown), app and type values',
        [hb(10, sync=v) for v in (0x00, 0x04, 0x10, 0x40, 0x20, 0x33)] +
        [hb(10, app=1, typ=1), hb(10, app=7, typ=9)])
    add('version 10: every flag (version mismatch, stay primary, INC, propagation disabled, SSL card failure, SSL card absent) alone and together',
        [hb(10, flags=f) for f in (0x8000, 0x4000, 0x1000, 0x2000, 0x100, 0x200, 0xf300, 0xffffffff, 0)])
    add('version 9 (6.1) with interface information and DR incarnation, version 8 (6.0) without',
        [hb(9, flags=0x8000), hb(9, state=1, master=1, flags=0x4300), hb(8, flags=0x2000), hb(8, state=2, master=0, sync=0x40)])
    add('versions 3 and 4 (5.2): master state and incarnation only',
        [hb(3), hb(4, master=4, state=8)])
    add('unknown versions (0, 1, 2, 5, 7, 11, 255): header only', [hb(v, state=v % 12) for v in (0, 1, 2, 5, 7, 11, 255)])
    write_pcap('ns-ha-coverage.pcap', frames, 252)
    write_pcap('ns-ha-udp.pcap', udp, 1)

    mal = []
    first = 1
    for v in (10, 9, 8, 4):
        full = hb(v)
        for n in (0, 3, 6, 8, 10, 14, 18, 22, 30, 38, 100, len(full) - 1):
            if n < len(full):
                mal.append(expdu(full[:n]))
    write_pcap('ns-ha-coverage-malformed.pcap', mal, 252)
    RANGES.append(('ns-ha-coverage-malformed.pcap', 1, len(mal), 'heartbeats of versions 10, 9, 8 and 4 cut short at several offsets'))
    if VERBOSE:
        for r in RANGES:
            print(*r)
        print(len(frames), len(mal), len(udp))


main()
