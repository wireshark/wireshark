#!/usr/bin/env python3
# Generates test/captures/igrp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic captures for packet-igrp.c (Cisco IGRP, IP protocol 9).
Usage: mkigrp.py <outdir>"""
import struct
import sys
import os
from pylib import A, eth, H, ipv4, ipv6, Pcap

def entry(net3, delay, bw, mtu, rel, load, hops):
    return bytes(net3) + delay.to_bytes(3, 'big') + bw.to_bytes(3, 'big') + \
        struct.pack('>HBBB', mtu, rel, load, hops)

def igrp(vo, update, asn, nint, nsys, next_, entries, cksum=0x1234):
    return struct.pack('>BBHHHHH', vo, update, asn, nint, nsys, next_, cksum) + b''.join(entries)

def f(payload, src=A, dst='224.0.0.10'):
    return eth('01:00:5e:00:00:0a', H, 0x0800, ipv4(src, dst, 9, payload, ttl=1))

def main(out):
    p = Pcap(1)
    e = entry
    # Request (no entries)
    p.add(f(igrp(0x12, 0, 100, 0, 0, 0, [])))
    # Response with interior routes (network from the source address),
    # system and exterior routes
    p.add(f(igrp(0x11, 1, 100, 2, 1, 1, [
        e((0, 1, 0), 1000, 1544, 1500, 255, 1, 0),
        e((0, 2, 0), 21000, 128, 1500, 250, 10, 1),
        e((10, 0, 0), 8000, 10000, 1500, 200, 100, 3),
        e((172, 16, 0), 9000, 10000, 576, 180, 255, 255)])))
    # Response with only system routes and only exterior routes
    p.add(f(igrp(0x11, 2, 200, 0, 2, 0, [
        e((192, 168, 1), 5000, 100000, 1500, 255, 2, 4),
        e((192, 168, 2), 6000, 100000, 1500, 255, 2, 5)])))
    p.add(f(igrp(0x11, 3, 65535, 0, 0, 1, [
        e((198, 51, 100), 0xffffff, 0xffffff, 65535, 0, 0, 0)]), src='198.51.100.7'))
    # Source address with another first octet for the interior routes
    p.add(f(igrp(0x11, 1, 100, 1, 0, 0, [
        e((0, 9, 9), 100, 100, 1500, 255, 1, 1)]), src='172.16.0.1'))
    # Opcode other than request and response, with version 1
    p.add(f(igrp(0x13, 0, 100, 0, 0, 0, [])))
    # Unknown version (warning expert info)
    p.add(f(igrp(0x21, 0, 100, 0, 0, 0, [])))
    # Over IPv6 (no IPv4 source address, network is 0)
    pay = igrp(0x11, 1, 100, 1, 0, 0, [e((0, 1, 0), 100, 100, 1500, 255, 1, 1)])
    p.add(eth('33:33:00:00:00:0a', H, 0x86dd, ipv6('2001:db8::1', 'ff02::a', 9, pay)))
    p.write(os.path.join(out, 'igrp-coverage.pcap'))

    m = Pcap(1)
    # Fewer than 12 octets
    m.add(f(bytes([0x11, 0, 0, 100, 0, 1, 0, 0])))
    # Claims 3 interior routes, only one present
    m.add(f(igrp(0x11, 1, 100, 3, 0, 0, [e((0, 1, 0), 1, 1, 1500, 1, 1, 1)])))
    # Claims system and exterior routes with no data
    m.add(f(igrp(0x11, 1, 100, 0, 65535, 0, [])))
    m.add(f(igrp(0x11, 1, 100, 0, 0, 4, [])))
    # Last entry cut short
    m.add(f(igrp(0x11, 1, 100, 1, 0, 0, [e((0, 1, 0), 1, 1, 1500, 1, 1, 1)[:9]])))
    m.write(os.path.join(out, 'igrp-coverage-malformed.pcap'))

main(sys.argv[1])
