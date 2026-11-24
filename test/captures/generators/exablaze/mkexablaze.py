#!/usr/bin/env python3
# Generates test/captures/exablaze_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the Exablaze trailer
dissector (packet-exablaze.c).

Exablaze devices append a 16 octet trailer to Ethernet frames: the
original FCS, device and port numbers, a timestamp (32 bit seconds
and a 40 bit binary fraction) and one more octet the dissector ignores; optionally the new FCS follows. The
dissector is a heuristic Ethernet trailer dissector (exablaze_eth,
disabled by default) that accepts a trailer if its seconds field is
within a week of the capture time. Every packet is built from scratch
with struct.

Usage: mkexablaze.py <output directory>

Writes:
  exablaze-coverage.pcap            trailers with and without the FCS, in
                                    the past and future, at the one week
                                    limit, behind padding, over IPv4 and
                                    VLAN, and frames that are not
                                    accepted
  exablaze-coverage-malformed.pcap  frames whose trailer is cut short
                                    by the snap length
"""
import os
import struct
import sys

BASE = 1700000000


def pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, (fr, orig) in enumerate(frames):
            f.write(struct.pack('<IIII', BASE + i, 1000 * i, len(fr), orig))
            f.write(fr)


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def trailer(sec, frac, dev=1, port=2, fcs=0xdeadbeef, new_fcs=None):
    t = struct.pack('>IBBI', fcs, dev, port, sec) + frac.to_bytes(5, 'big') + b'\x00'
    if new_fcs is not None:
        t += struct.pack('>I', new_fcs)
    return t


def udp_frame(tail, vlan=False, payload=b'exablaze'):
    udp = struct.pack('!HHHH', 5000, 5001, 8 + len(payload), 0) + payload
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
                     bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2]))
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    eth = bytes.fromhex('020000000002020000000001')
    if vlan:
        eth += struct.pack('!HHH', 0x8100, 7, 0x0800)
    else:
        eth += struct.pack('!H', 0x0800)
    return eth + ip + udp + tail


def main_frames():
    F = []
    n = [0]

    def add(tail, **kw):
        # the capture time of frame i is BASE + i (frame numbers are 1 based)
        n[0] += 1
        fr = udp_frame(tail, **kw)
        F.append((fr, len(fr)))
        return BASE + n[0] - 1
    half = 0x8000000000
    # 1: plain trailer, 0.5 s
    add(trailer(BASE, half, 1, 2))
    # 2: trailer followed by the new FCS; the first try (no FCS) fails
    add(trailer(BASE + 1, half, 3, 4, new_fcs=0x12345678))
    # 3: one hour in the future, largest fraction, device and port 255
    add(trailer(BASE + 2 + 3600, 0xffffffffff, 255, 255))
    # 4: one day in the past, fraction 0
    add(trailer(BASE + 3 - 86400, 0, 0, 0))
    # 5: padding in front of the trailer
    add(b'\0' * 10 + trailer(BASE + 4, 0x4000000000, 9, 10))
    # 6: exactly a week in the future (accepted)
    add(trailer(BASE + 5 + 604800, 0x2000000000, 11, 12))
    # 7: exactly a week in the past (accepted)
    add(trailer(BASE + 6 - 604800, 0x1000000000, 13, 14))
    # 8: on a VLAN
    add(trailer(BASE + 7, 0x0800000000, 15, 16), vlan=True)
    # 9: with FCS, in the past
    add(trailer(BASE + 8 - 1000, half, 17, 18, new_fcs=0xcafef00d))
    # 10: 18 zero octets after the IP packet: not accepted (time)
    add(b'\0' * 18)
    # 11: a week and a second in the future: not accepted
    add(trailer(BASE + 10 + 604801, half))
    # 12: a week and a second in the past: not accepted
    add(trailer(BASE + 11 - 604801, half))
    # 13: trailer shorter than 16 octets: not accepted
    add(b'\xaa' * 12)
    # 14: no trailer at all
    add(b'')
    # 15: 20 octets not accepted at either offset
    add(b'\x55' * 20)
    # 16: seconds 0 (1970): not accepted
    add(trailer(0, half))
    return F


def malformed_frames():
    F = []
    fr = udp_frame(trailer(BASE, 0x8000000000))
    # captured length cuts the trailer: the heuristic needs all of it
    F.append((fr[:len(fr) - 6], len(fr)))
    fr = udp_frame(trailer(BASE + 1, 0x8000000000, new_fcs=1))
    F.append((fr[:len(fr) - 3], len(fr)))
    fr = udp_frame(trailer(BASE + 2, 0x8000000000))
    F.append((fr[:len(fr) - 1], len(fr)))
    return F


def main():
    out = sys.argv[1]
    pcap(os.path.join(out, 'exablaze-coverage.pcap'), main_frames())
    pcap(os.path.join(out, 'exablaze-coverage-malformed.pcap'), malformed_frames())


main()
