#!/usr/bin/env python3
# Generates test/captures/homepna_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures for the HomePNA dissector
(packet-homepna.c, ethertype 0x886C).

The header is a type and a length (one octet each when the first octet
is 127 or less, two octets each otherwise), a version octet, "length - 3"
octets of data, one skipped octet, then a two octet ethertype that is
handed to the ethertype dissector (0 means no next layer).  Every packet
is built from scratch with struct; no captured traffic is used.

Usage: mkhomepna.py <output directory>

Writes:
  homepna-coverage.pcap            every short and long type range, data,
                                   next layer ARP / IPv4 / no next layer /
                                   unknown ethertype, padding trailer
  homepna-coverage-malformed.pcap  control length 0-2 (the fixed bug),
                                   header and ethertype cut short
"""
import struct
import sys

ETYPE = 0x886C


def pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)


def eth(payload, pad=True, dst=1, src=2):
    fr = bytes([2, 0, 0, 0, 0, dst, 2, 0, 0, 0, 0, src]) + struct.pack('>H', ETYPE) + payload
    if pad and len(fr) < 60:
        fr += b'\0' * (60 - len(fr))
    return fr


def arp():
    return struct.pack('>HHBBH', 1, 0x0800, 6, 4, 1) + \
        bytes([2, 0, 0, 0, 0, 2]) + bytes([10, 0, 0, 1]) + bytes(6) + bytes([10, 0, 0, 2])


def ipv4_udp():
    udp = struct.pack('>HHHH', 4000, 4001, 12, 0) + b'abcd'
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
                     bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]))
    return ip + udp


def short(typ, length, ver, data, etype, payload=b'', gap=b'\x00'):
    """length is the control length field; data should be length-3 octets."""
    return bytes([typ, length, ver]) + data + gap + struct.pack('>H', etype) + payload


def long_(typ, length, ver, data, etype, payload=b'', gap=b'\x00'):
    return struct.pack('>HHB', typ, length, ver) + data + gap + struct.pack('>H', etype) + payload


def main(out):
    f = []
    # 1-6: short format types 0..5 and 6 (reserved), data of varying size
    f.append(eth(short(0, 3, 1, b'', 0x0806, arp())))              # 1 non-standard, no data
    f.append(eth(short(1, 7, 1, b'\x11\x22\x33\x44', 0x0806, arp())))  # 2 rate request
    f.append(eth(short(2, 4, 2, b'\xaa', 0x0800, ipv4_udp())))     # 3 link integrity
    f.append(eth(short(3, 11, 1, bytes(range(8)), 0x0806, arp())))  # 4 capabilities
    f.append(eth(short(4, 5, 1, b'\x01\x02', 0x0800, ipv4_udp())))  # 5 LARQ
    f.append(eth(short(5, 6, 1, b'\x01\x02\x03', 0x0806, arp())))   # 6 vendor short
    f.append(eth(short(6, 3, 1, b'', 0x0806, arp())))              # 7 reserved ITU-T
    f.append(eth(short(127, 3, 1, b'', 0x0800, ipv4_udp())))       # 8 highest short type
    # long format (first octet > 127)
    f.append(eth(long_(0x8000, 3, 1, b'', 0x0806, arp())))         # 9 long, ITU-T reserved 32768
    f.append(eth(long_(0x8001, 8, 3, b'\xde\xad\xbe\xef\x00', 0x0800, ipv4_udp())))  # 10 vendor long
    f.append(eth(long_(0x8002, 5, 1, b'\x01\x02', 0x0806, arp())))  # 11 reserved 32770+
    f.append(eth(long_(0xffff, 3, 1, b'', 0x0806, arp())))         # 12 top of last range
    f.append(eth(long_(0x8080, 4, 1, b'\x55', 0x0806, arp())))     # 13 long, 0x8080
    # no next layer: etype 0, with padding left over for the Ethernet trailer
    f.append(eth(short(1, 3, 1, b'', 0), pad=True))                # 14 etype 0, padding
    f.append(eth(short(2, 6, 1, b'\x00\x01\x02', 0), pad=True))    # 15
    # unknown ethertype: payload shown as data
    f.append(eth(short(1, 3, 1, b'', 0x1234, b'\x01\x02\x03\x04\x05')))  # 16
    # a next layer whose data is longer than the ethernet minimum
    f.append(eth(short(4, 3, 1, b'', 0x0800, ipv4_udp() + b'\0' * 40)))  # 17
    # a frame exactly 4 octets: length 3, but no ethertype -> would be malformed; keep out
    # type 0x7f00 in the long form is not reachable; first octet 0x80 is the border
    f.append(eth(long_(0x8000, 9, 1, bytes(6), 0x0806, arp())))    # 18 long with 6 octets data
    pcap(out + '/homepna-coverage.pcap', f)

    m = []
    # the fixed bug: control length smaller than 3 (short and long format)
    for cl in (0, 1, 2):
        m.append(eth(bytes([0x01, cl, 0x01]) + b'\x00\x00' + b'\x08\x00' + b'\0' * 30))
    m.append(eth(bytes([0x80, 0x01, 0x00, 0x00, 0x01]) + b'\0' * 30))
    m.append(eth(struct.pack('>HHB', 0x8001, 2, 1) + b'\0' * 30))
    # shorter than 4 octets: dissector declines
    m.append(eth(b'\x01\x03\x01', pad=False))
    # header fits but the ethertype is past the end (exception)
    m.append(eth(bytes([0x01, 0x20, 0x01]) + b'\0' * 4, pad=False))
    # long format header cut short
    m.append(eth(bytes([0x80, 0x00, 0x00, 0x03]), pad=False))
    # control length 3 and the ethertype cut to one octet
    m.append(eth(bytes([0x01, 0x03, 0x01, 0x00, 0x08]), pad=False))
    pcap(out + '/homepna-coverage-malformed.pcap', m)


if __name__ == '__main__':
    main(sys.argv[1])
