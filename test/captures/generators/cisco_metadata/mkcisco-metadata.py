#!/usr/bin/env python3
# Generates test/captures/cisco_metadata_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the Cisco MetaData
dissector (packet-cisco-metadata.c, filter name "cmd").

Cisco MetaData carries a Security Group Tag. On Ethernet (ethertype
0x8909) the header is version, length, options, SGT and the ethertype
of the payload; inside GRE (GRE protocol 0x8909) the payload ethertype
comes first. Every packet is built from scratch with struct; no captured
traffic is used.

Usage: mkcisco-metadata.py <output directory>
Writes:
  cisco-metadata-coverage.pcap            Ethernet and GRE encapsulations
                                          with several payloads, nesting,
                                          a trailer, the GRE item length
                                          reproducer and the nesting limit
  cisco-metadata-coverage-malformed.pcap  truncated headers, the GRE
                                          nesting limit
"""
import os
import struct
import sys

MAC_A = bytes.fromhex('020000000001')
MAC_B = bytes.fromhex('020000000002')
ETH_CMD = 0x8909


def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def eth(etype, payload, dst=MAC_B, src=MAC_A):
    return dst + src + struct.pack('>H', etype) + payload


def ipv4(proto, payload, src=(192, 0, 2, 1), dst=(192, 0, 2, 2), ident=1):
    hdr = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0,
                      64, proto, 0, bytes(src), bytes(dst))
    return hdr[:10] + struct.pack('>H', csum(hdr)) + hdr[12:] + payload


def udp4(sport, dport, data, src=(192, 0, 2, 1), dst=(192, 0, 2, 2)):
    hdr = struct.pack('>HHHH', sport, dport, 8 + len(data), 0)
    pseudo = struct.pack('>4s4sBBH', bytes(src), bytes(dst), 0, 17, 8 + len(data))
    c = csum(pseudo + hdr + data) or 0xffff
    return hdr[:6] + struct.pack('>H', c) + data


def ip_udp(data, ident=1, src=(192, 0, 2, 1), dst=(192, 0, 2, 2)):
    return ipv4(17, udp4(40000 + ident, 9, data, src, dst), src, dst, ident)


def ipv6_udp(data):
    src = bytes.fromhex('20010db8000000000000000000000001')
    dst = bytes.fromhex('20010db8000000000000000000000002')
    hdr = struct.pack('>HHHH', 40001, 9, 8 + len(data), 0)
    pseudo = src + dst + struct.pack('>II', 8 + len(data), 17)
    c = csum(pseudo + hdr + data) or 0xffff
    u = hdr[:6] + struct.pack('>H', c) + data
    return struct.pack('>IHBB', 0x60000000, len(u), 17, 64) + src + dst + u


def arp():
    return struct.pack('>HHBBH6s4s6s4s', 1, 0x0800, 6, 4, 1, MAC_A,
                       bytes((192, 0, 2, 1)), b'\0' * 6, bytes((192, 0, 2, 2)))


def cmd_eth(etype, payload, version=1, length=1, options=0, sgt=10):
    """Ethernet form: version, length, options, SGT, payload ethertype."""
    return struct.pack('>BBHHH', version, length, options, sgt, etype) + payload


def cmd_gre(etype, payload, version=1, length=1, options=0, sgt=10):
    """GRE form: payload ethertype, version, length, options, SGT."""
    return struct.pack('>HBBHH', etype, version, length, options, sgt) + payload


def gre_frame(gre_payload, ident=1):
    gre = struct.pack('>HH', 0, ETH_CMD) + gre_payload
    return eth(0x0800, ipv4(47, gre, ident=ident))


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, p in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
            f.write(p)


# Each Ethernet nesting level adds two layers (cmd, ethertype), each GRE
# level one (cmd, called through the gre.proto table); the default
# gui.max_tree_depth is 500 and the dissector stops when the layer count
# + 16 reaches it. 260 and 490 levels are enough and keep the frames
# small (about 2 and 4 KB).
NEST = 260
NEST_GRE = 490


def main_frames():
    F = []
    # 1: Ethernet, IPv4 UDP payload
    F.append(eth(ETH_CMD, cmd_eth(0x0800, ip_udp(b'cmd-ipv4', 1))))
    # 2: Ethernet, IPv6 UDP payload, other version/options/SGT values
    F.append(eth(ETH_CMD, cmd_eth(0x86dd, ipv6_udp(b'cmd-ipv6'), version=2, length=3,
                                  options=0xffff, sgt=65535)))
    # 3: Ethernet, ARP payload, SGT 0
    F.append(eth(ETH_CMD, cmd_eth(0x0806, arp(), sgt=0)))
    # 4: Ethernet, IPv4 followed by 6 octets of trailer
    F.append(eth(ETH_CMD, cmd_eth(0x0800, ip_udp(b'trailer', 4) + b'\xde\xad\xbe\xef\x00\x01')))
    # 5: Ethernet, CMD in CMD (two SGTs), IPv4 payload
    F.append(eth(ETH_CMD, cmd_eth(ETH_CMD, cmd_eth(0x0800, ip_udp(b'nested', 5), sgt=200),
                                  sgt=100)))
    # 6: Ethernet, 802.1Q VLAN 42 then IPv4
    F.append(eth(ETH_CMD, cmd_eth(0x8100, struct.pack('>HH', 42, 0x0800) + ip_udp(b'vlan', 6))))
    # 7: Ethernet, an ethertype with no dissector (local experimental 0x88b5)
    F.append(eth(ETH_CMD, cmd_eth(0x88b5, b'experimental')))
    # 8: GRE, IPv4 payload (the cmd_gre_len reproducer: inner IPv4 header
    # with no next header, 198.51.100.1 -> .2)
    F.append(gre_frame(cmd_gre(0x0800, ipv4(59, b'', (198, 51, 100, 1), (198, 51, 100, 2), 2),
                               sgt=10), 8))
    # 9: GRE, IPv6 UDP payload
    F.append(gre_frame(cmd_gre(0x86dd, ipv6_udp(b'gre-ipv6'), sgt=300, options=0x8001), 9))
    # 10: GRE, transparent Ethernet bridging, inner Ethernet with IPv4
    F.append(gre_frame(cmd_gre(0x6558, eth(0x0800, ip_udp(b'gre-teb', 10)), sgt=400), 10))
    # 11: GRE, a protocol GRE has no dissector for: data
    F.append(gre_frame(cmd_gre(0x88b5, b'gre-unknown', sgt=500), 11))
    # 12: GRE, CMD in CMD
    F.append(gre_frame(cmd_gre(ETH_CMD, cmd_gre(0x0800, ip_udp(b'gre-nested', 12), sgt=601),
                               sgt=600), 12))
    # 13: Ethernet, CMD nested NEST times (the cmd_recursion reproducer,
    # shortened): stops with cmd.too_deep before the layer limit
    payload = b''.join(cmd_eth(ETH_CMD, b'', sgt=i) for i in range(NEST))
    F.append(eth(ETH_CMD, payload + cmd_eth(0x88b5, b'\0' * 8)))
    return F


def malformed_frames():
    F = []
    # 1: Ethernet, header cut after the SGT (no payload ethertype)
    F.append(eth(ETH_CMD, struct.pack('>BBHH', 1, 1, 0, 10)))
    # 2: Ethernet, only two octets
    F.append(eth(ETH_CMD, b'\x01\x01'))
    # 3: GRE, header cut after the options
    F.append(gre_frame(struct.pack('>HBBH', 0x0800, 1, 1, 0), 3))
    # 4: GRE, IPv4 payload cut short
    F.append(gre_frame(cmd_gre(0x0800, ip_udp(b'cut', 4)[:12]), 4))
    # 5: Ethernet, IPv4 payload cut short
    F.append(eth(ETH_CMD, cmd_eth(0x0800, ip_udp(b'cut', 5)[:12])))
    # 6: GRE, CMD nested NEST_GRE times: stops with cmd.too_deep, but the
    # expert is added with length -1 (packet-cisco-metadata.c:141), which
    # proto_tree_add_expert() now takes as unsigned and answers with a
    # ReportedBoundsError after adding the item: Malformed Packet
    payload = b''.join(cmd_gre(ETH_CMD, b'', sgt=i) for i in range(NEST_GRE))
    F.append(gre_frame(payload + cmd_gre(0x88b5, b'\0' * 8), 6))
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'cisco-metadata-coverage.pcap'), main_frames())
    write_pcap(os.path.join(out, 'cisco-metadata-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()
