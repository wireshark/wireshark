#!/usr/bin/env python3
# Apple IP-over-IEEE 1394 coverage capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Apple IP-over-IEEE 1394 (packet-ap1394.c, link type 138,
WTAP_ENCAP_APPLE_IP_OVER_IEEE1394): a header of destination and source
EUI-64 addresses and an ethertype, followed by the payload the ethertype
selects. Every packet is built with struct; nothing comes from a real
network.

Usage: mkap1394.py [<output directory>]
writes ap1394-coverage.pcap and ap1394-coverage-malformed.pcap
"""
import os
import struct
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))
import capgen  # noqa: E402

LINKTYPE_APPLE_IP_OVER_IEEE1394 = 138

EUI_A = bytes.fromhex('00 11 22 ff fe 33 44 55')
EUI_B = bytes.fromhex('00 11 22 ff fe 66 77 88')
EUI_BCAST = b'\xff' * 8


def frame(etype, payload, dst=EUI_B, src=EUI_A):
    return dst + src + struct.pack('>H', etype) + payload


def icmp_echo(typ, ident, seq):
    body = struct.pack('>BBHHH', typ, 0, 0, ident, seq) + b'ieee1394 ping'
    return body[:2] + struct.pack('>H', capgen.inet_checksum(body)) + body[4:]


def arp1394(op, sha, spa, tha, tpa):
    """ARP with hardware type 24 (IEEE 1394), 16 octet hardware addresses
    (EUI-64, max_rec, spd, 48 bit unicast FIFO offset)."""
    def hw(eui, fifo):
        return eui + struct.pack('>BBHI', 11, 2, 0xffff, fifo)
    return struct.pack('>HHBBH', 24, 0x0800, 16, 4, op) + hw(sha, 0xf0000400) + \
        capgen.ip4(spa) + hw(tha, 0xf0000400 if tha != bytes(8) else 0) + capgen.ip4(tpa)


A4, B4 = '192.0.2.1', '192.0.2.2'
A6, B6 = '2001:db8::1', '2001:db8::2'

frames = []
# 1: IPv4 UDP
frames.append(frame(0x0800, capgen.ipv4(capgen.udp(b'hello over firewire', 40000, 7000, A4, B4),
                                        17, A4, B4)))
# 2, 3: IPv4 ICMP echo request and reply
frames.append(frame(0x0800, capgen.ipv4(icmp_echo(8, 0x1394, 1), 1, A4, B4, ident=2)))
frames.append(frame(0x0800, capgen.ipv4(icmp_echo(0, 0x1394, 1), 1, B4, A4, ident=3),
                    dst=EUI_A, src=EUI_B))
# 4, 5: ARP request and reply
frames.append(frame(0x0806, arp1394(1, EUI_A, A4, bytes(8), B4), dst=EUI_BCAST))
frames.append(frame(0x0806, arp1394(2, EUI_B, B4, EUI_A, A4), dst=EUI_A, src=EUI_B))
# 6: IPv4 TCP data segment
frames.append(frame(0x0800, capgen.ipv4(capgen.tcp(b'hello', 40001, 80, seq=1, ack=1, src=A4, dst=B4), 6, A4, B4, ident=4)))
# 7: IPv6 ICMPv6 echo request
icmp6 = struct.pack('>BBHHH', 128, 0, 0, 0x1394, 1) + b'ieee1394 ping'
icmp6 = icmp6[:2] + struct.pack('>H', capgen.l4_checksum(icmp6, 58, A6, B6)) + icmp6[4:]
frames.append(frame(0x86dd, capgen.ipv6(icmp6, 58, A6, B6)))
# 8: IPv6 UDP to the broadcast EUI-64
frames.append(frame(0x86dd, capgen.ipv6(capgen.udp(b'multicast-ish', 40002, 7001, A6, B6), 17, A6, B6),
                    dst=EUI_BCAST))
# 9: ethertype nobody handles: shown as data
frames.append(frame(0x1234, b'unknown ethertype payload'))
# 10: 802.1Q VLAN tag inside the 1394 encapsulation, carrying IPv4
frames.append(frame(0x8100, struct.pack('>HH', 5, 0x0800) +
                    capgen.ipv4(capgen.udp(b'tagged', 40003, 7002, A4, B4), 17, A4, B4, ident=5)))
# 11: header only with an unknown ethertype
frames.append(frame(0xfffe, b''))
# 12: MPLS unicast
frames.append(frame(0x8847, struct.pack('>I', (100 << 12) | (1 << 8) | 64) +
                    capgen.ipv4(capgen.udp(b'mpls', 40004, 7003, A4, B4), 17, A4, B4, ident=6)))

outdir = sys.argv[1] if len(sys.argv) > 1 else '.'
capgen.write_pcap(os.path.join(outdir, 'ap1394-coverage.pcap'), frames,
                  linktype=LINKTYPE_APPLE_IP_OVER_IEEE1394)
n = len(frames)

# Malformed capture: frames shorter than the 18 octet header
bad = [frame(0x0800, b''),                       # empty IPv4 payload
       EUI_B + EUI_A + b'\x08',                   # ethertype cut after one octet
       EUI_B + EUI_A,                             # no ethertype
       EUI_B + EUI_A[:3],                         # source cut
       EUI_B[:4],                                 # destination cut
       frame(0x0800, capgen.ipv4(b'', 17, A4, B4)[:12]),   # IPv4 header cut short
       frame(0x0806, arp1394(1, EUI_A, A4, bytes(8), B4)[:20])]   # ARP cut short
capgen.write_pcap(os.path.join(outdir, 'ap1394-coverage-malformed.pcap'), bad,
                  linktype=LINKTYPE_APPLE_IP_OVER_IEEE1394)
print('ap1394-coverage.pcap: %d frames' % n)
