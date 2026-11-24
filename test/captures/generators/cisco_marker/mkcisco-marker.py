#!/usr/bin/env python3
# Generates test/captures/cisco_marker_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the Cisco ERSPAN3 marker
packet dissector (packet-cisco-marker.c).

ERSPAN Type III marker packets are UDP datagrams; the dissector has no
default port and is reached with Decode As (udp.port, "erspan-marker").
The layout: a 20 octet proprietary header, a 2 octet header flag
(little endian), version/type/SSID, granularity/UTC offset, an 8 octet
field holding the 48 bit ASIC timestamp, UTC seconds and microseconds,
a little endian sequence number and reserved word, and an 8 octet tail
whose low 32 bits hold the 0xA5A5A5A5 signature. Every packet is built
from scratch with struct; no captured traffic is used.

Usage: mkcisco-marker.py <output directory>

Writes:
  cisco-marker-coverage.pcap            marker packets with typical,
                                        zero and maximum values, and one
                                        with octets after the tail
  cisco-marker-coverage-malformed.pcap  marker packets cut short
"""

import os
import struct
import sys

SRC = (192, 0, 2, 10)
DST = (198, 51, 100, 20)
SPORT = 50000
PORT = 35000


def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


def ipv4(proto, payload, ident=1):
    hdr = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0,
                      64, proto, 0, bytes(SRC), bytes(DST))
    return hdr[:10] + struct.pack('>H', csum(hdr)) + hdr[12:] + payload


def udp(data):
    hdr = struct.pack('>HHHH', SPORT, PORT, 8 + len(data), 0)
    pseudo = struct.pack('>4s4sBBH', bytes(SRC), bytes(DST), 0, 17, 8 + len(data))
    c = csum(pseudo + hdr + data) or 0xffff
    return hdr[:6] + struct.pack('>H', c) + data


def frame(data, ident):
    return (bytes.fromhex('020000000002') + bytes.fromhex('020000000001')
            + struct.pack('>H', 0x0800) + ipv4(17, udp(data), ident))


def marker(prop=bytes(range(20)), header=1, version=1, mtype=5, ssid=1,
           gra=3, utcoff=37, ts=0x0000123456789abc, sec=1700000000,
           usec=500000, seq=1, reserved=0, tail=0x00000000a5a5a5a5):
    return (prop + struct.pack('<H', header)
            + struct.pack('>HHQII', (mtype << 12) | (version << 8) | ssid,
                          (gra << 8) | utcoff, ts, sec, usec)
            + struct.pack('<II', seq, reserved) + struct.pack('>Q', tail))


def pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)


def main_frames():
    m = [
        # 1-3: a sequence of typical markers
        marker(seq=1),
        marker(seq=2, ts=0x0000123456789abc + 1000000, usec=600000),
        marker(seq=3, ts=0x0000123456789abc + 2000000, usec=700000),
        # 4: header flag clear, every other field zero
        marker(prop=bytes(20), header=0, version=0, mtype=0, ssid=0, gra=0,
               utcoff=0, ts=0, sec=0, usec=0, seq=0, reserved=0, tail=0),
        # 5: every field at its maximum (the timestamp and tail fields have
        #    their unused bits set too, which the masks drop)
        marker(prop=b'\xff' * 20, header=0xffff, version=15, mtype=15,
               ssid=255, gra=255, utcoff=255, ts=0xffffffffffffffff,
               sec=0xffffffff, usec=999999, seq=0xffffffff,
               reserved=0xffffffff, tail=0xffffffffffffffff),
        # 6: octets after the tail
        marker(seq=6) + b'extra',
    ]
    return [frame(d, i + 1) for i, d in enumerate(m)]


def malformed_frames():
    m = marker(seq=9)
    return [frame(m[:n], 100 + n) for n in (10, 21, 30, 50, 57)] + [frame(b'', 99)]


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcap(os.path.join(out, 'cisco-marker-coverage.pcap'), main_frames())
    pcap(os.path.join(out, 'cisco-marker-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()
