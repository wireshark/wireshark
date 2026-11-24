#!/usr/bin/env python3
# Generates test/captures/enc_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the OpenBSD enc(4)
dissector (packet-enc.c).

LINKTYPE_ENC (109) frames start with a 12 octet header: the address
family in the byte order of the host that wrote the file, the SPI in
network byte order and the flags in the writer's byte order. The
dissector decides the byte order from the address family (BSD AF_
values have the upper 16 bits zero) and hands the payload to IPv4
(AF_INET 2) or IPv6 (AF_INET6 24), or to the data dissector.
Every packet is built from scratch with struct; no captured traffic is
used.

Usage: mkenc.py <output directory>

Writes:
  enc-coverage.pcap            IPv4 and IPv6 payloads in both byte
                               orders, every flag, an unknown family
  enc-coverage-malformed.pcap  frames shorter than the header
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct

from pkt import LINKTYPE_ENC, ipv4, ipv6, udp, udp6, write_pcap

AF_INET = 2
AF_INET6 = 24

CONF, AUTH, COMP, AUTH_AH = 0x400, 0x800, 0x1000, 0x2000


def enc(af, spi, flags, payload, little=True):
    e = "<" if little else ">"
    return (struct.pack(e + "I", af) + struct.pack(">I", spi) +
            struct.pack(e + "I", flags) + payload)


def v4(n):
    return ipv4(udp(b"enc test %d" % n, 40000 + n, 40000, "198.51.100.1",
                    "198.51.100.2"), 17, "198.51.100.1", "198.51.100.2",
                ident=n)


def v6(n):
    return ipv6(udp6(b"enc v6 %d" % n, 40000 + n, 40000), 17)


def main_frames():
    F = []
    # 1: IPv4, little endian writer, payload authenticated
    F.append(enc(AF_INET, 0x1000, AUTH, v4(1), True))
    # 2: IPv4, big endian writer, encrypted and authenticated
    F.append(enc(AF_INET, 0x1001, CONF | AUTH, v4(2), False))
    # 3: IPv6, little endian, compressed, header authenticated (AH)
    F.append(enc(AF_INET6, 0x2000, COMP | AUTH_AH, v6(3), True))
    # 4: IPv6, big endian, every defined flag
    F.append(enc(AF_INET6, 0x2001, CONF | AUTH | COMP | AUTH_AH, v6(4),
                 False))
    # 5: no flags
    F.append(enc(AF_INET, 0, 0, v4(5), True))
    # 6: reserved flag bits set
    F.append(enc(AF_INET, 0xffffffff, 0xFFFFC3FF, v4(6), True))
    # 7: unknown address family (AF_UNIX 1): handed to the data dissector
    F.append(enc(1, 0x3000, AUTH, b"\x01\x02\x03\x04payload", True))
    # 8: unknown family 0x1234, big endian
    F.append(enc(0x1234, 0x3001, 0, b"\xaa\xbb\xcc", False))
    # 9: header only, unknown family, no payload
    F.append(enc(1, 0x3002, CONF, b"", True))
    return F


def malformed_frames():
    F = []
    # 1: only the address family
    F.append(struct.pack("<I", AF_INET))
    # 2: address family and SPI, no flags
    F.append(struct.pack("<I", AF_INET) + struct.pack(">I", 0x10))
    # 3: header and a truncated IPv4 header
    F.append(enc(AF_INET, 0x11, AUTH, b"\x45\x00\x00", True))
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "."
    write_pcap(os.path.join(out, "enc-coverage.pcap"), main_frames(),
               LINKTYPE_ENC)
    write_pcap(os.path.join(out, "enc-coverage-malformed.pcap"),
               malformed_frames(), LINKTYPE_ENC)


if __name__ == "__main__":
    main()
