#!/usr/bin/env python3
# Generates test/captures/etag_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures for the E-Tag (IEEE 802.1BR) dissector,
packet-etag.c. E-Tag has ethertype 0x893F, registered by default.
Usage: mketag.py <output directory>
Writes etag-coverage.pcap (clean) and etag-coverage-malformed.pcap."""
import os
import struct
import sys

MACS = bytes.fromhex('020000000002' '020000000001')


def csum(b):
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b + b'\0' * (len(b) % 2)))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ipv4(payload, proto=17):
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0,
                     bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2]))
    return ip[:10] + struct.pack('!H', csum(ip)) + ip[12:] + payload


def udp(payload):
    return struct.pack('!HHHH', 40000, 9, 8 + len(payload), 0) + payload


INNER = ipv4(udp(b'hello'))


def etag(pcp, dei, iecid_base, grp, ecid_base, iecid_ext, ecid_ext, etype, payload, resv=0):
    w1 = (pcp << 13) | (dei << 12) | iecid_base
    w2 = (resv << 14) | (grp << 12) | ecid_base
    return (struct.pack('>HHHBB', 0x893f, w1, w2, iecid_ext, ecid_ext)
            + struct.pack('>H', etype) + payload)


def frame(body):
    return MACS + body


def pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)


def main(out):
    ok = []
    # 1-8: every E-PCP value, with group and DEI varying
    for pcp in range(8):
        ok.append(frame(etag(pcp, pcp & 1, 0x100 + pcp, pcp & 3, 0x200 + pcp,
                             pcp, 0x10 + pcp, 0x0800, INNER)))
    # 9: all bits set, including the reserved bits
    ok.append(frame(etag(7, 1, 0xfff, 3, 0xfff, 0xff, 0xff, 0x0800, INNER, resv=3)))
    # 10: all zero
    ok.append(frame(etag(0, 0, 0, 0, 0, 0, 0, 0x0800, INNER)))
    # 11: nested E-Tags (two levels)
    ok.append(frame(etag(1, 0, 5, 1, 6, 0, 0, 0x893f, etag(2, 0, 7, 2, 8, 1, 1, 0x0800, INNER)[2:])))
    # 12: 802.1Q VLAN inside the E-Tag
    ok.append(frame(etag(0, 0, 1, 0, 2, 0, 0, 0x8100,
                         struct.pack('>HH', 0x0064, 0x0800) + INNER)))
    # 13: unknown payload ethertype
    ok.append(frame(etag(0, 0, 1, 0, 2, 0, 0, 0x1234, b'\xde\xad\xbe\xef' * 4)))
    # 14: trailer after the IPv4 payload
    ok.append(frame(etag(0, 0, 3, 0, 4, 0, 0, 0x0800, INNER + b'\x01\x02\x03\x04\x05\x06')))
    # 15: header only, empty payload for an unknown type
    ok.append(frame(etag(0, 0, 3, 0, 4, 0, 0, 0x88b5, b'')))
    pcap(os.path.join(out, 'etag-coverage.pcap'), ok)

    bad = []
    # 1: truncated TCI (3 octets)
    bad.append(frame(b'\x89\x3f\x12\x34\x56'))
    # 2: TCI complete but ethertype missing
    bad.append(frame(b'\x89\x3f' + bytes.fromhex('123456789abc')))
    # 3: ethertype cut to one octet
    bad.append(frame(b'\x89\x3f' + bytes.fromhex('123456789abc') + b'\x08'))
    # 4: 2000 nested E-Tags (the nesting limit)
    bad.append(frame((b'\x89\x3f' + bytes.fromhex('123456789abc')) * 2000 + b'\x08\x00' + INNER))
    pcap(os.path.join(out, 'etag-coverage-malformed.pcap'), bad)


if __name__ == '__main__':
    main(sys.argv[1])
