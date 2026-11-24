#!/usr/bin/env python3
# Generates test/captures/telkonet_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures for the Telkonet powerline dissector
(packet-telkonet.c): ethertype 0x88A1, an 8 octet header whose first
octet is the type (0x78 = tunnel, followed by an Ethernet frame without
FCS).

Usage: mktelkonet.py <output directory>

Writes:
  telkonet-coverage.pcap            tunnel frames carrying Ethernet/IP/UDP
                                    (also ARP and a short inner frame),
                                    unknown types
  telkonet-coverage-malformed.pcap  frames shorter than the 8 octet
                                    header or empty, tunnels without or
                                    with a cut inner frame
"""

import struct
import sys
import os

MAC_A = bytes.fromhex('020000000001')
MAC_B = bytes.fromhex('020000000002')


def pcap(path, frames, linktype=1):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def ip4(proto, payload, src='192.0.2.1', dst='192.0.2.2'):
    s = bytes(map(int, src.split('.')))
    d = bytes(map(int, dst.split('.')))
    h = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0, s, d)
    h = h[:10] + struct.pack('>H', csum(h)) + h[12:]
    return h + payload


def eth(payload, ethertype=0x0800, src=MAC_A, dst=MAC_B):
    return dst + src + struct.pack('>H', ethertype) + payload


def udp(sport, dport, payload, rev=False):
    u = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    if rev:
        return eth(ip4(17, u, src='192.0.2.2', dst='192.0.2.1'), src=MAC_B, dst=MAC_A)
    return eth(ip4(17, u))


def tcp(sport, dport, seq, ack, payload, flags=0x18, rev=False):
    t = struct.pack('>HHIIBBHHH', sport, dport, seq, ack, 0x50, flags, 8192, 0, 0) + payload
    if rev:
        return eth(ip4(6, t, src='192.0.2.2', dst='192.0.2.1'), src=MAC_B, dst=MAC_A)
    return eth(ip4(6, t))

ETHERTYPE = 0x88A1


def telk(typ, payload, rest=b'\0\0\0\0\0\0\0', src=MAC_A, dst=MAC_B):
    return eth(bytes([typ]) + rest + payload, ETHERTYPE, src=src, dst=dst)


def main_frames():
    F = []
    inner_udp = udp(1234, 5678, b'telkonet tunnel')
    inner_arp = eth(struct.pack('>HHBBH6s4s6s4s', 1, 0x0800, 6, 4, 1,
                                MAC_A, bytes([192, 0, 2, 1]), bytes(6),
                                bytes([192, 0, 2, 2])), 0x0806)
    # 1: tunnel with an Ethernet/IPv4/UDP frame (no FCS)
    F.append(telk(0x78, inner_udp))
    # 2: tunnel with an ARP request, header bytes not zero
    F.append(telk(0x78, inner_arp, rest=bytes.fromhex('01020304050607')))
    # 3: tunnel with a minimal Ethernet header and no payload
    F.append(telk(0x78, MAC_B + MAC_A + b'\x88\xb5'))
    # 4: unknown type 0x01
    F.append(telk(0x01, b'opaque data'))
    # 5: unknown type 0x00 with no payload (header only)
    F.append(telk(0x00, b''))
    # 6: type 0xff
    F.append(telk(0xff, b'\xde\xad\xbe\xef'))
    return F


def malformed_frames():
    F = []
    # 1: tunnel with only 3 octets of the header
    F.append(eth(bytes([0x78, 0, 0]), ETHERTYPE))
    # 2: no payload at all
    F.append(eth(b'', ETHERTYPE))
    # 3: tunnel with an inner frame cut inside the Ethernet header
    F.append(telk(0x78, MAC_B + b'\0\0\0'))
    # 4: tunnel without any inner frame (header only)
    F.append(telk(0x78, b''))
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcap(os.path.join(out, 'telkonet-coverage.pcap'), main_frames())
    pcap(os.path.join(out, 'telkonet-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()
