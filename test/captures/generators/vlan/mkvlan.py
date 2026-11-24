#!/usr/bin/env python3
# Generates test/captures/vlan_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic 802.1Q VLAN captures for packet-vlan.c.

Usage: mkvlan.py <outdir> [-v]
Writes vlan-coverage.pcapng (main capture: no malformed packets or error
expert infos; two Ethernet interfaces) and vlan-coverage-malformed.pcapng
(length past the end, truncated tags, 21 nested tags).
Addresses are from 192.0.2.0/24.
"""
import os
import struct
import sys

from pcaplib import arp, eth, ip_ping, ipv4, mac, udp, write_pcapng

IPX_ETHERTYPE = 0x8137


def tci(pri, dei, vid):
    return (pri << 13) | (dei << 12) | vid


def tag(pri, dei, vid, inner_etype):
    return struct.pack('>HH', tci(pri, dei, vid), inner_etype)


def vlan_frame(pri, dei, vid, etype, payload, outer=0x8100, src=1, dst=2):
    return eth(dst, src, outer, tag(pri, dei, vid, etype) + payload)


def stp_bpdu():
    return struct.pack('>HBBB8sI8sHHHHH', 0, 0, 0, 0, b'\x80\x00\x02\x00\x00\x00\x00\x01', 4,
                       b'\x80\x00\x02\x00\x00\x00\x00\x01', 0x8001, 0, 5120, 512, 3840)


def ipx_packet(data=b'IPX data'):
    hdr = struct.pack('>HHBB4s6sH4s6sH', 0xffff, 30 + len(data), 0, 0,
                      b'\0\0\0\1', mac(9), 0x4000, b'\0\0\0\2', mac(8), 0x4001)
    return hdr + data


def nested(n, payload, vid0=100):
    """Ethernet 0x8100, then n tags; the last one carries the payload."""
    body = b''
    for i in range(n):
        et = 0x8100 if i < n - 1 else 0x0800
        body += tag(i & 7, 0, vid0 + i, et)
    return eth(2, 1, 0x8100, body + payload)


def build_main():
    f0 = []
    marks = []

    def mark(label):
        marks.append((len(f0) + 1, label))

    def add(data, ifid=0):
        f0.append((ifid, data))

    mark('One tag, priority 0-7 with and without the drop eligible bit, VLAN IDs 0, 1, 100 and 4094')
    vids = [1, 100, 4094, 0, 10, 20, 30, 40]
    for pri in range(8):
        add(vlan_frame(pri, pri & 1, vids[pri], 0x0800, ip_ping(1, 2, pri + 1)))
    add(vlan_frame(3, 1, 4094, 0x0800, ip_ping(2, 1, 9)))
    mark('ARP and an unknown ethertype in a VLAN')
    add(vlan_frame(0, 0, 10, 0x0806, arp(1)))
    add(vlan_frame(0, 0, 10, 0x0806, arp(2, 2, 2, 1, 1)))
    add(vlan_frame(0, 0, 10, 0x1234, b'unknown ethertype payload'))
    add(vlan_frame(0, 0, 10, 0x0800, ipv4(17, udp(1000, 2000, b'udp in a vlan'))))
    mark('QinQ: 0x9100 outer tag, then 0x8100; three tags')
    add(vlan_frame(0, 0, 200, 0x8100, tag(1, 0, 10, 0x0800) + ip_ping(1, 2, 20), outer=0x9100))
    add(vlan_frame(5, 1, 300, 0x8100, tag(2, 0, 20, 0x8100) + tag(3, 1, 30, 0x0800) + ip_ping(1, 2, 21), outer=0x9100))
    add(eth(2, 1, 0x9100, tag(0, 0, 7, 0x9100) + tag(0, 0, 8, 0x8100) + tag(0, 0, 9, 0x0800) + ip_ping(1, 2, 22)))
    mark('802.3 length and LLC (STP BPDU) with a trailer, SNAP with a trailer, IPX without LLC')
    llc = b'\x42\x42\x03' + stp_bpdu()
    add(eth(2, 1, 0x8100, struct.pack('>HH', tci(7, 0, 1), len(llc)) + llc + b'\0' * 4))
    snap = b'\xaa\xaa\x03\0\0\0' + struct.pack('>H', 0x0800) + ip_ping(1, 2, 23)
    add(eth(2, 1, 0x8100, struct.pack('>HH', tci(0, 0, 50), len(snap)) + snap + b'\xde\xad\xbe\xef'))
    ipx = ipx_packet()
    add(eth(2, 1, 0x8100, struct.pack('>HH', tci(0, 0, 60), len(ipx)) + ipx))
    add(eth(2, 1, 0x8100, struct.pack('>HH', tci(0, 0, 60), len(llc)) + llc))
    mark('20 nested tags (the limit), and the VLAN ID that stays the first one')
    add(nested(20, ip_ping(1, 2, 30)))
    add(nested(19, ip_ping(1, 2, 31), vid0=500))
    mark('Second interface: the same VLAN IDs, MAC addresses and ping')
    for pri in range(4):
        add(vlan_frame(pri, 0, 10, 0x0800, ip_ping(1, 2, 40 + pri)), 1)
    add(vlan_frame(0, 0, 10, 0x0800, ip_ping(1, 2, 40)), 1)
    add(vlan_frame(0, 0, 0, 0x0800, ip_ping(1, 2, 44)), 1)                              # VLAN ID 0 on the second interface
    add(eth(2, 1, 0x0800, ip_ping(1, 2, 45)), 1)                                          # no tag at all
    return f0, marks


def build_malformed():
    f0 = []
    marks = []

    def mark(label):
        marks.append((len(f0) + 1, label))

    def add(data, ifid=0):
        f0.append((ifid, data))

    mark('21 nested tags: Too many nested VLAN tags (warning)')
    add(nested(21, ip_ping(1, 2, 50)))
    add(nested(25, ip_ping(1, 2, 51)))
    mark('Length field past the end of the payload (802.3 + LLC)')
    llc = b'\x42\x42\x03' + stp_bpdu()
    add(eth(2, 1, 0x8100, struct.pack('>HH', tci(0, 0, 1), len(llc) + 100) + llc))
    add(eth(2, 1, 0x8100, struct.pack('>HH', tci(0, 0, 1), 1500) + b'\xff\xff' + b'\0' * 10))
    mark('Truncated: the tag is cut short, no inner ethertype, length 0 and no LLC')
    add(eth(2, 1, 0x8100, struct.pack('>HH', tci(0, 0, 60), 0)))
    add(eth(2, 1, 0x8100, b'\x00\x0a'))
    add(eth(2, 1, 0x8100, b''))
    add(eth(2, 1, 0x8100, struct.pack('>HH', tci(0, 0, 1), 0x0800) + b'\x45\x00\x00'))
    return f0, marks


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    verbose = '-v' in sys.argv
    os.makedirs(out, exist_ok=True)
    for name, fn in (('vlan-coverage', build_main), ('vlan-coverage-malformed', build_malformed)):
        fr, marks = fn()
        write_pcapng(os.path.join(out, name + '.pcapng'), [1, 1], fr)
        print('%s.pcapng: %d frames' % (name, len(fr)))
        if verbose:
            ends = [m[0] for m in marks[1:]] + [len(fr) + 1]
            for (s, label), e in zip(marks, ends):
                print('  %d-%d %s' % (s, e - 1, label))


if __name__ == '__main__':
    main()
