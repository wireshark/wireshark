#!/usr/bin/env python3
# Generates test/captures/e100_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the E100 dissector
(packet-e100.c, Arbor/Netscout E100 encapsulation).

An E100 probe sends the frames it monitors to a collector over UDP,
each behind a 28 octet header: version 1, receive port, sequence
number, probe IP address, monitor packet ID, a seconds/microseconds
timestamp, the captured and the original length. The inner frame is
Ethernet without FCS. E100 has only a heuristic UDP dissector,
"e100_udp", which is disabled by default, so the capture is decoded
with --enable-heuristic e100_udp. The heuristic takes a UDP payload of
28 octets or more with version 1 and a captured length that matches
the rest of the payload. Every packet is built from scratch with
struct; no captured traffic is used.

Usage: mke100.py <output directory>

Writes:
  e100-coverage.pcap            E100 frames carrying inner ARP, ICMP
                                and UDP frames, cut-short inner frames
                                (original length larger than captured),
                                original lengths of 0x7fffffff and
                                0xffffffff (the reproducer of the
                                review), and UDP payloads the heuristic
                                rejects (too short, version 2, length
                                mismatch)
  e100-coverage-malformed.pcap  original length 0, an inner frame too
                                short for Ethernet
"""

import os
import struct
import sys

from pcaplib import eth, eth_ipv4_udp, ipv4, ip4, cksum, write_pcap  # noqa: E402

PROBE = '192.0.2.50'
COLLECTOR = '192.0.2.60'
SPORT, DPORT = 49152, 9100


def e100(inner, port, seq, mon_id, ts, orig=None, cap=None, version=1):
    if cap is None:
        cap = len(inner)
    if orig is None:
        orig = len(inner)
    return struct.pack('>BBH4sIIIII', version, port, seq, ip4(PROBE), mon_id,
                       ts[0], ts[1], cap, orig) + inner


def outer(payload):
    return eth_ipv4_udp(payload, SPORT, DPORT, PROBE, COLLECTOR,
                        bytes.fromhex('020000000050'), bytes.fromhex('020000000060'))


H1 = bytes.fromhex('0200000000a1')
H2 = bytes.fromhex('0200000000a2')


def inner_arp():
    arp = struct.pack('>HHBBH6s4s6s4s', 1, 0x0800, 6, 4, 1, H1, ip4('198.51.100.1'),
                      b'\0' * 6, ip4('198.51.100.2'))
    return eth(arp + b'\0' * 18, 0x0806, H1, b'\xff' * 6)


def inner_icmp(seq, reply=False):
    icmp = struct.pack('>BBHHH', 0 if reply else 8, 0, 0, 0x1234, seq) + b'abcdefghijklmnop'
    icmp = icmp[:2] + struct.pack('>H', cksum(icmp)) + icmp[4:]
    if reply:
        return eth(ipv4(icmp, 1, '198.51.100.2', '198.51.100.1'), 0x0800, H2, H1)
    return eth(ipv4(icmp, 1, '198.51.100.1', '198.51.100.2'), 0x0800, H1, H2)


def inner_udp():
    return eth_ipv4_udp(b'inner datagram', 1234, 5678, '198.51.100.2', '198.51.100.1', H2, H1)


def main_frames():
    F = []
    # 1: inner ARP request on port 1
    F.append(outer(e100(inner_arp(), 1, 1, 1001, (1700000000, 1))))
    # 2-3: inner ICMP echo request and reply, port 2
    F.append(outer(e100(inner_icmp(1), 2, 2, 1002, (1700000000, 250000))))
    F.append(outer(e100(inner_icmp(1, True), 2, 3, 1003, (1700000001, 999999))))
    # 4: inner UDP, port 255, sequence 65535
    F.append(outer(e100(inner_udp(), 255, 65535, 0xffffffff, (1700000002, 0))))
    # 5: the probe captured the 56 octets of an inner UDP frame but the
    #    frame on the wire was 98 octets (an Ethernet trailer not captured)
    F.append(outer(e100(inner_udp(), 3, 4, 1005, (1700000003, 5), orig=98)))
    # 6-7: the reproducer: original lengths 0x7fffffff and 0xffffffff
    F.append(outer(e100(inner_arp(), 1, 5, 1006, (1700000004, 6), orig=0x7fffffff)))
    F.append(outer(e100(inner_arp(), 1, 6, 1007, (1700000004, 7), orig=0xffffffff)))
    # 8: UDP payload shorter than an E100 header (heuristic rejects it)
    F.append(outer(b'\x01' + b'\0' * 26))
    # 9: header version 2 (rejected)
    F.append(outer(e100(inner_arp(), 1, 7, 1008, (1700000005, 0), version=2)))
    # 10: captured length does not match the payload (rejected)
    F.append(outer(e100(inner_arp(), 1, 8, 1009, (1700000005, 1), cap=10)))
    return F


def malformed_frames():
    F = []
    # 1: original length 0 (the inner frame reports 0 octets)
    F.append(outer(e100(inner_arp(), 1, 9, 2001, (1700000010, 0), orig=0)))
    # 2: inner frame of 6 octets (shorter than an Ethernet header)
    F.append(outer(e100(H2, 1, 10, 2002, (1700000010, 1))))
    # 3: header only, no inner frame
    F.append(outer(e100(b'', 1, 11, 2003, (1700000010, 2))))
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'e100-coverage.pcap'), main_frames())
    write_pcap(os.path.join(out, 'e100-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()
