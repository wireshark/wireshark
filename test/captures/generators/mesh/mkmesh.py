#!/usr/bin/env python3
# Generates test/captures/mesh_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures for the Mesh Header dissector
(packet-mesh.c: the 5 octet OLPC mesh header after the Marvell SNAP PID).

The mesh header is reached from LLC/SNAP with OUI 0x005043 (Marvell) in
an information frame (UI or I).  Every packet is built with struct;
nothing comes from a real network.

Usage: mkmesh.py <output directory>
  mesh-coverage.pcap            LLC/SNAP with the Marvell OUI: UI and I
                                frames, IPv4, ARP and an unknown PID,
                                other TTL and sequence values, a mesh
                                header without payload, non-information
                                frames (no mesh header), another OUI
  mesh-coverage-malformed.pcap  mesh header cut short
"""
import os
import struct
import sys

A = bytes.fromhex('020000000001')
B = bytes.fromhex('020000000002')


def pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)


def csum(b):
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ipv4(payload=b'olpc mesh payload'):
    udp = struct.pack('>HHHH', 40000, 40001, 8 + len(payload), 0) + payload
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 7, 0x4000, 64, 17, 0,
                     bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]))
    ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
    return ip + udp


def arp():
    return struct.pack('>HHBBH', 1, 0x0800, 6, 4, 1) + A + bytes([10, 0, 0, 1]) + \
        b'\0' * 6 + bytes([10, 0, 0, 2])


def mesh_hdr(ttl=5, seq=0x1234, b01=b'\x00\x00'):
    return b01 + struct.pack('>BH', ttl, seq)


def llc(ctrl, oui, etype, body, dsap=0xaa, ssap=0xaa):
    payload = struct.pack('>BB', dsap, ssap) + ctrl + oui + struct.pack('>H', etype) + body
    return B + A + struct.pack('>H', len(payload)) + payload


MARVELL = bytes.fromhex('005043')
UI = b'\x03'
# I frame, modulo 128: two octets, N(S)=3, N(R)=5
IFR = struct.pack('>BB', 3 << 1, 5 << 1)


def main():
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    f = []
    # 1-2: UI, mesh header + IPv4 and ARP
    f.append(llc(UI, MARVELL, 0x0800, mesh_hdr() + ipv4()))
    f.append(llc(UI, MARVELL, 0x0806, mesh_hdr(ttl=1, seq=1) + arp()))
    # 3-4: I frame (two octet control field), IPv4 and ARP
    f.append(llc(IFR, MARVELL, 0x0800, mesh_hdr(ttl=64, seq=0x8000) + ipv4(b'information frame')))
    f.append(llc(IFR, MARVELL, 0x0806, mesh_hdr(ttl=0, seq=0) + arp()))
    # 5-6: limits of TTL and sequence number, non-zero first two octets
    f.append(llc(UI, MARVELL, 0x0800, mesh_hdr(ttl=255, seq=0xffff, b01=b'\xff\xff') + ipv4()))
    f.append(llc(UI, MARVELL, 0x0800, mesh_hdr(ttl=128, seq=0x00ff, b01=b'\x12\x34') + ipv4(b'x')))
    # 7: a PID without a dissector: data after the mesh header
    f.append(llc(UI, MARVELL, 0x88b5, mesh_hdr(ttl=9, seq=9) + b'unknown protocol bytes'))
    # 8: a mesh header and nothing after it, with an Ethertype that has no dissector
    f.append(llc(UI, MARVELL, 0x88b6, mesh_hdr(ttl=3, seq=3)))
    # 9-10: Marvell OUI in non-information frames: no mesh header (XID, TEST)
    f.append(llc(b'\xaf', MARVELL, 0x0800, b'\x81\x01\x00'))
    f.append(llc(b'\xe3', MARVELL, 0x0800, b'test data'))
    # 11: another OUI (Cisco, no mesh header)
    f.append(llc(UI, bytes.fromhex('00000c'), 0x0800, ipv4(b'not mesh')))
    # 12: ARP with trailing octets
    f.append(llc(UI, MARVELL, 0x0806, mesh_hdr(ttl=2, seq=2) + arp() + b'\x00' * 18))
    pcap(os.path.join(out, 'mesh-coverage.pcap'), f)

    bad = []
    # mesh header of 4 octets and of 2 octets, of 0 octets
    bad.append(llc(UI, MARVELL, 0x0800, b'\x00\x00\x05\x12'))
    bad.append(llc(UI, MARVELL, 0x0800, b'\x00\x00'))
    bad.append(llc(UI, MARVELL, 0x0800, b''))
    # a mesh header and nothing after it, with an IPv4 PID
    bad.append(llc(UI, MARVELL, 0x0800, mesh_hdr(ttl=3, seq=3)))
    pcap(os.path.join(out, 'mesh-coverage-malformed.pcap'), bad)


main()
