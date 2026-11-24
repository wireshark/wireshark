#!/usr/bin/env python3
# Generates test/captures/trill_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Builds trill-coverage.pcap and trill-coverage-malformed.pcap
import struct
import sys
import os
from pcaplib import write, eth, ipv4, udp, csum

def inner_udp(sport=1000, dport=2000, data=b'trill inner frame'):
    return udp(sport, dport, data, src='198.51.100.1', dst='198.51.100.2')

def inner_arp():
    arp = struct.pack('!HHBBH6s4s6s4s', 1, 0x0800, 6, 4, 1, b'\x02\0\0\0\0\x01', bytes([198, 51, 100, 1]),
                      b'\0' * 6, bytes([198, 51, 100, 2]))
    return eth(arp, 0x0806, dst='ff:ff:ff:ff:ff:ff', src='02:00:00:00:00:01')

def trill(inner, ver=0, rsv=0, multi=0, oplen=0, hop=63, egress=0x0002, ingress=0x0001, opts=None):
    """TRILL header: V(2) R(2) M(1) Op-Length(5, units of 4 octets) Hop Count(6),
    egress and ingress nicknames, options, then the inner Ethernet frame."""
    word = (ver << 14) | (rsv << 12) | (multi << 11) | (oplen << 6) | hop
    if opts is None:
        opts = bytes((i * 7) & 0xff for i in range(oplen * 4))
    return struct.pack('!HHH', word, egress, ingress) + opts + inner

def outer(payload, dst='01:80:c2:00:00:40', src='02:aa:bb:cc:dd:01'):
    return eth(payload, 0x22f3, dst=dst, src=src)

def main(out):
    fr = []
    u = inner_udp()
    fr.append(outer(trill(u)))                                   # 1 unicast
    fr.append(outer(trill(inner_arp(), multi=1, egress=0xfff0, hop=10)))   # 2 multi-destination ARP
    # version and reserved values
    for v in (1, 2, 3):
        fr.append(outer(trill(u, ver=v)))                        # 3-5 unallocated versions
    for r in (1, 2, 3):
        fr.append(outer(trill(u, rsv=r)))                        # 6-8 illegal reserved values
    # every option length: 1, 2, 8, 16, 31 words
    for n in (1, 2, 8, 16, 31):
        fr.append(outer(trill(u, oplen=n)))                      # 9-13
    # nicknames: every range
    nick = (0x0000, 0x0001, 0x1234, 0xffbf, 0xffc0, 0xffc1, 0xffc2, 0xfff0, 0xfffe, 0xffff)
    for i, n in enumerate(nick):
        fr.append(outer(trill(u, egress=n, ingress=nick[(i + 3) % len(nick)], multi=i & 1, hop=i)))   # 14-23
    fr.append(outer(trill(u, hop=0)))                            # 24 hop count 0
    fr.append(outer(trill(u, hop=63, multi=1, ver=2, rsv=3, oplen=31)))   # 25 all fields at once
    # TRILL carrying a TRILL frame (a few levels), then a VLAN-tagged inner frame
    lvl = trill(u)
    for i in range(3):
        lvl = trill(eth(lvl, 0x22f3, dst='01:80:c2:00:00:40', src='02:aa:bb:cc:dd:02'), egress=0x0100 + i)
    fr.append(outer(lvl))                                        # 26 three nested levels
    vl = eth(struct.pack('!HH', 0x0064, 0x0800) + ipv4(17, struct.pack('!HHHH', 5, 6, 8, 0)), 0x8100)
    fr.append(outer(trill(vl)))                                  # 27 inner VLAN frame
    fr.append(outer(trill(b'')[:6] + eth(b'\x00' * 4, 0x88b5)))   # 28 inner frame of an unknown ethertype (padding)
    # an inner IPv6 frame, and an inner frame shorter than an Ethernet header after the options
    src6, dst6 = bytes(range(16)), bytes(range(16, 32))
    udp6 = struct.pack('!HHHH', 1, 2, 8, 0)
    ck = csum(src6 + dst6 + struct.pack('!IBBBB', 8, 0, 0, 0, 17) + udp6)
    udp6 = struct.pack('!HHHH', 1, 2, 8, ck or 0xffff)
    v6 = eth(b'\x60\0\0\0' + struct.pack('!HBB', 8, 17, 64) + src6 + dst6 + udp6, 0x86dd)
    fr.append(outer(trill(v6)))                                  # 29
    write(os.path.join(out, 'trill-coverage.pcap'), fr)
    print('main frames', len(fr))

    m = []
    m.append(outer(b'\x00\x3f\x00'))                             # shorter than the fixed header
    m.append(outer(trill(b'', oplen=31)[:30]))                   # options cut short
    m.append(outer(trill(u[:6])))                                # inner Ethernet header cut short
    m.append(outer(trill(u[:30], oplen=2)))                      # inner frame cut in the IP header
    # nested TRILL beyond the dissector depth limit (the review reproducer used 3000 levels)
    lvl = u
    for i in range(int(os.environ.get('TRILL_NEST', '420'))):
        lvl = trill(eth(lvl, 0x22f3), hop=63)
    m.append(outer(lvl))
    write(os.path.join(out, 'trill-coverage-malformed.pcap'), m)

main(sys.argv[1] if len(sys.argv) > 1 else '.')
