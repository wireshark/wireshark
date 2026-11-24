#!/usr/bin/env python3
# Generates test/captures/vmlab_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic VMware Lab Manager (ethertype 0x88DE) captures for packet-vmlab.c.

Usage: mkvmlab.py <outdir> [-v]
Writes vmlab-coverage.pcapng (main capture: no malformed packets or error
expert infos) and vmlab-coverage-malformed.pcapng (truncated headers).
Addresses are from 192.0.2.0/24.
"""
import os
import struct
import sys

from pcaplib import arp, eth, ip_ping, ipv4, mac, udp, write_pcapng


def vmlab(flags, pgrp, addr, dst, src, etype, payload, outer_dst=2, outer_src=1):
    hdr = struct.pack('>BBH', flags, pgrp, 0) + mac(addr) + mac(dst) + mac(src) + struct.pack('>H', etype)
    return eth(outer_dst, outer_src, 0x88DE, hdr + payload)


def build_main():
    fr, marks = [], []

    def mark(label):
        marks.append((len(fr) + 1, label))

    def add(d, i=0):
        fr.append((i, d))

    mark('ICMP echo, flags 0 and the More Fragments bit, portgroups 0, 1, 7 and 255')
    add(vmlab(0x00, 0, 21, 22, 21, 0x0800, ip_ping(1, 2, 1)))
    add(vmlab(0x04, 1, 22, 21, 22, 0x0800, ip_ping(2, 1, 2)))
    add(vmlab(0x00, 7, 21, 22, 21, 0x0800, ip_ping(1, 2, 3)))
    add(vmlab(0x04, 255, 22, 21, 22, 0x0800, ip_ping(2, 1, 4)))
    mark('The unknown flag bits (0xF8 and 0x03)')
    add(vmlab(0xf8, 3, 21, 22, 21, 0x0800, ip_ping(1, 2, 5)))
    add(vmlab(0x03, 3, 21, 22, 21, 0x0800, ip_ping(1, 2, 6)))
    add(vmlab(0xff, 3, 21, 22, 21, 0x0800, ip_ping(1, 2, 7)))
    mark('The two addresses differ; ARP, UDP, an unknown ethertype, a VLAN, an 802.3 length')
    add(vmlab(0x00, 2, 23, 22, 21, 0x0806, arp(1, 21, 1, 0, 2)))
    add(vmlab(0x00, 2, 21, 21, 22, 0x0806, arp(2, 22, 2, 21, 1)))
    add(vmlab(0x00, 2, 21, 22, 21, 0x0800, ipv4(17, udp(1000, 2000, b'udp in a vmlab frame'))))
    add(vmlab(0x00, 2, 21, 22, 21, 0x1234, b'unknown ethertype payload'))
    add(vmlab(0x00, 2, 21, 22, 21, 0x8100, struct.pack('>HH', 0x0064, 0x0800) + ip_ping(1, 2, 8)))
    add(vmlab(0x00, 2, 21, 22, 21, 0x0010, b'0123456789abcdef'))
    mark('Broadcast and multicast outer and inner addresses')
    f = eth(2, 1, 0x88DE, struct.pack('>BBH', 0, 9, 0) + b'\xff' * 6 + b'\xff' * 6 + mac(21) + struct.pack('>H', 0x0806) + arp(1, 21, 1, 0, 2))
    add(f)
    return fr, marks


def build_malformed():
    fr, marks = [], []

    def mark(label):
        marks.append((len(fr) + 1, label))

    def add(d, i=0):
        fr.append((i, d))

    mark('Truncated header, and an IPv4 ethertype with no data')
    add(vmlab(0x00, 2, 21, 22, 21, 0x0800, b''))
    add(eth(2, 1, 0x88DE, b''))
    add(eth(2, 1, 0x88DE, b'\x00\x01\x00\x00' + mac(21)))
    add(eth(2, 1, 0x88DE, struct.pack('>BBH', 0, 1, 0) + mac(21) + mac(22) + mac(21)))           # no ethertype
    add(eth(2, 1, 0x88DE, struct.pack('>BBH', 0, 1, 0) + mac(21) + mac(22) + mac(21) + b'\x08'))  # ethertype cut
    return fr, marks


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    verbose = '-v' in sys.argv
    os.makedirs(out, exist_ok=True)
    for name, fn in (('vmlab-coverage', build_main), ('vmlab-coverage-malformed', build_malformed)):
        fr, marks = fn()
        write_pcapng(os.path.join(out, name + '.pcapng'), [1], fr)
        print('%s.pcapng: %d frames' % (name, len(fr)))
        if verbose:
            ends = [m[0] for m in marks[1:]] + [len(fr) + 1]
            for (s, label), e in zip(marks, ends):
                print('  %d-%d %s' % (s, e - 1, label))


if __name__ == '__main__':
    main()
