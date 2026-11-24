#!/usr/bin/env python3
# Generates test/captures/vntag_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic VN-Tag (Cisco, ethertype 0x8926) captures for packet-vntag.c.

Usage: mkvntag.py <outdir> [-v]
Writes vntag-coverage.pcapng (main capture: no malformed packets or error
expert infos) and vntag-coverage-malformed.pcapng (length past the end,
truncated tags). Addresses are from 192.0.2.0/24.
"""
import os
import struct
import sys

from pcaplib import arp, eth, ip_ping, ipv4, mac, udp, write_pcapng


def vntag(dir_=0, ptr=0, dst=0, looped=0, r=0, ver=0, src=0):
    return struct.pack('>I', (dir_ << 31) | (ptr << 30) | (dst << 16) | (looped << 15) | (r << 14) | (ver << 12) | src)


def vn_frame(tagword, etype, payload, srcm=1, dstm=2):
    return eth(dstm, srcm, 0x8926, tagword + struct.pack('>H', etype) + payload)


def stp_bpdu():
    return struct.pack('>HBBB8sI8sHHHHH', 0, 0, 0, 0, b'\x80\x00\x02\x00\x00\x00\x00\x01', 4,
                       b'\x80\x00\x02\x00\x00\x00\x00\x01', 0x8001, 0, 5120, 512, 3840)


def ipx_packet(data=b'IPX data'):
    return struct.pack('>HHBB4s6sH4s6sH', 0xffff, 30 + len(data), 0, 0,
                       b'\0\0\0\1', mac(9), 0x4000, b'\0\0\0\2', mac(8), 0x4001) + data


def build_main():
    fr, marks = [], []

    def mark(label):
        marks.append((len(fr) + 1, label))

    def add(d, i=0):
        fr.append((i, d))

    mark('Every flag and field value: direction, pointer, destination, looped, reserved, version, source')
    add(vn_frame(vntag(0, 0, 5, 0, 0, 0, 3), 0x0800, ip_ping(1, 2, 1)))
    add(vn_frame(vntag(1, 0, 0x3fff, 0, 0, 0, 0xfff), 0x0800, ip_ping(2, 1, 2)))
    add(vn_frame(vntag(0, 1, 1, 1, 0, 0, 1), 0x0800, ip_ping(1, 2, 3)))
    add(vn_frame(vntag(1, 1, 0x2aaa, 1, 1, 3, 0x555), 0x0800, ip_ping(1, 2, 4)))
    add(vn_frame(vntag(0, 0, 0, 0, 1, 2, 0), 0x0800, ip_ping(1, 2, 5)))
    mark('ARP, UDP and an unknown ethertype')
    add(vn_frame(vntag(0, 0, 7, 0, 0, 0, 8), 0x0806, arp(1)))
    add(vn_frame(vntag(1, 0, 8, 0, 0, 0, 7), 0x0806, arp(2, 2, 2, 1, 1)))
    add(vn_frame(vntag(0, 0, 7, 0, 0, 0, 8), 0x0800, ipv4(17, udp(1000, 2000, b'udp in a vn-tag'))))
    add(vn_frame(vntag(0, 0, 7, 0, 0, 0, 8), 0x1234, b'unknown ethertype payload'))
    mark('802.3 length: LLC (STP BPDU) with a trailer, SNAP with a trailer, IPX without LLC')
    llc = b'\x42\x42\x03' + stp_bpdu()
    add(eth(2, 1, 0x8926, vntag(0, 0, 3, 0, 0, 0, 4) + struct.pack('>H', len(llc)) + llc + b'\0' * 4))
    snap = b'\xaa\xaa\x03\0\0\0' + struct.pack('>H', 0x0800) + ip_ping(1, 2, 6)
    add(eth(2, 1, 0x8926, vntag(0, 0, 3, 0, 0, 0, 4) + struct.pack('>H', len(snap)) + snap + b'\xde\xad\xbe\xef'))
    ipx = ipx_packet()
    add(eth(2, 1, 0x8926, vntag(0, 0, 3, 0, 0, 0, 4) + struct.pack('>H', len(ipx)) + ipx))
    mark('VLAN inside the VN-Tag, and a VN-Tag inside a VLAN')
    add(vn_frame(vntag(0, 0, 9, 0, 0, 0, 10), 0x8100, struct.pack('>HH', 0x2064, 0x0800) + ip_ping(1, 2, 7)))
    add(eth(2, 1, 0x8100, struct.pack('>HH', 0x0064, 0x8926) + vntag(1, 0, 11, 0, 0, 0, 12) + struct.pack('>H', 0x0800) + ip_ping(1, 2, 8)))
    mark('VN-Tag inside a VN-Tag')
    add(vn_frame(vntag(0, 0, 1, 0, 0, 0, 2), 0x8926, vntag(0, 0, 3, 0, 0, 0, 4) + struct.pack('>H', 0x0800) + ip_ping(1, 2, 9)))
    return fr, marks


def build_malformed():
    fr, marks = [], []

    def mark(label):
        marks.append((len(fr) + 1, label))

    def add(d, i=0):
        fr.append((i, d))

    mark('Length field past the end of the payload')
    llc = b'\x42\x42\x03' + stp_bpdu()
    add(eth(2, 1, 0x8926, vntag(0, 0, 3, 0, 0, 0, 4) + struct.pack('>H', len(llc) + 100) + llc))
    add(eth(2, 1, 0x8926, vntag(0, 0, 3, 0, 0, 0, 4) + struct.pack('>H', 1500) + b'\xff\xff' + b'\0' * 10))
    mark('Truncated: the tag, the ethertype, length 0 and no LLC, IPv4 without data')
    add(eth(2, 1, 0x8926, vntag(0, 0, 3, 0, 0, 0, 4) + struct.pack('>H', 0)))
    add(vn_frame(vntag(0, 0, 1, 0, 0, 0, 2), 0x0800, b''))
    add(eth(2, 1, 0x8926, b'\x00\x01'))
    add(eth(2, 1, 0x8926, b''))
    add(eth(2, 1, 0x8926, vntag(0, 0, 3, 0, 0, 0, 4)))
    add(eth(2, 1, 0x8926, vntag(0, 0, 3, 0, 0, 0, 4) + b'\x08\x00' + b'\x45\x00\x00'))
    return fr, marks


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    verbose = '-v' in sys.argv
    os.makedirs(out, exist_ok=True)
    for name, fn in (('vntag-coverage', build_main), ('vntag-coverage-malformed', build_malformed)):
        fr, marks = fn()
        write_pcapng(os.path.join(out, name + '.pcapng'), [1], fr)
        print('%s.pcapng: %d frames' % (name, len(fr)))
        if verbose:
            ends = [m[0] for m in marks[1:]] + [len(fr) + 1]
            for (s, label), e in zip(marks, ends):
                print('  %d-%d %s' % (s, e - 1, label))


if __name__ == '__main__':
    main()
