#!/usr/bin/env python3
# Generates test/captures/gue_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generate the GUE (Generic UDP Encapsulation) coverage captures.
# Usage: mkgue.py <outdir>.  GUE runs over UDP port 6080 (registered by default).
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
import socket
from common import pcap, ip4, udp, eth, csum

M1 = bytes.fromhex('0200000000a1'); M2 = bytes.fromhex('0200000000a2')


V6A = socket.inet_pton(socket.AF_INET6, '2001:db8::1')
V6B = socket.inet_pton(socket.AF_INET6, '2001:db8::2')
V6C = socket.inet_pton(socket.AF_INET6, '2001:db8::a')
V6D = socket.inet_pton(socket.AF_INET6, '2001:db8::b')


def udp6(src, dst, sp, dp, payload):
    """UDP over IPv6 with the mandatory checksum."""
    h = struct.pack('>HHHH', sp, dp, 8 + len(payload), 0)
    c = csum(src + dst + struct.pack('>IBBBB', len(h) + len(payload), 0, 0, 0, 17) + h + payload) or 0xffff
    return h[:6] + struct.pack('>H', c) + payload


def icmp_echo(data=bytes(12), typ=13):
    b = struct.pack('>BBHHH', typ, 0, 0, 1, 1) + data
    return b[:2] + struct.pack('>H', csum(b)) + b[4:]


def inner_ipv4(proto=17, payload=None, rev=False):
    if payload is None:
        payload = udp(1234, 4321, b'ip payload')
    a, b = ('192.168.1.2', '192.168.1.1') if rev else ('192.168.1.1', '192.168.1.2')
    return ip4(a, b, proto, payload)


def inner_ipv6(nh=17, payload=None):
    if payload is None:
        payload = udp6(V6A, V6B, 1234, 4321, b'v6 payload')
    return struct.pack('>IHBB', 0x60000000, len(payload), nh, 64) + V6A + V6B + payload


def gue0(proto, payload=b'', hlen=0, flags=0, control=False, ext=None, hlen_field=None):
    """Variant 0: 2 bits variant, C bit, 5 bits hlen, proto/ctype, 16 bits flags."""
    ext = bytes(range(1, 1 + 4 * hlen)) if ext is None else ext
    hl = hlen if hlen_field is None else hlen_field
    return struct.pack('>BBH', (0 << 6) | (0x20 if control else 0) | hl, proto, flags) + ext + payload


def pkt(gue, sport=50000, dport=6080, src='10.0.0.1', dst='10.0.0.2'):
    return eth(M2, M1, 0x0800, ip4(src, dst, 17, udp(sport, dport, gue)))


def pkt6(gue, sport=50000, dport=6080):
    u = udp6(V6C, V6D, sport, dport, gue)
    h = struct.pack('>IHBB', 0x60000000, len(u), 17, 64) + V6C + V6D
    return eth(M2, M1, 0x86dd, h + u)


def build():
    fr = []
    A = fr.append
    # variant 0 data messages with the common payloads
    A(pkt(gue0(4, inner_ipv4())))                                   # IPIP
    A(pkt(gue0(41, inner_ipv6())))                                  # IPv6
    A(pkt(gue0(17, udp(1111, 5555, b'udp in gue'))))                # UDP
    A(pkt(gue0(1, icmp_echo())))                                    # ICMP timestamp request (echo is matched with its reply only in the second pass)
    A(pkt(gue0(253, b'experimental protocol payload')))             # nothing claims it: data
    A(pkt(gue0(59, b'')))                                           # no next header, empty payload
    # extension fields (hlen) and flags
    A(pkt(gue0(4, inner_ipv4(), hlen=1)))
    A(pkt(gue0(4, inner_ipv4(), hlen=3, flags=0x8001)))
    A(pkt(gue0(41, inner_ipv6(), hlen=31, flags=0xffff)))
    A(pkt(gue0(4, inner_ipv4(), flags=0x0100)))
    # control messages
    A(pkt(gue0(0, b'control payload', control=True)))               # type 0
    A(pkt(gue0(255, b'experimental control', control=True)))        # type 255 experimental
    A(pkt(gue0(7, b'', control=True, hlen=2)))                      # unassigned type, extension, no payload
    # variant 1: the UDP payload is the IP packet itself
    A(pkt(inner_ipv4()))
    A(pkt(inner_ipv4(1, icmp_echo())))
    A(pkt(inner_ipv6()))
    A(pkt6(inner_ipv4()))                                           # GUE over IPv6 carrying IPv4
    A(pkt6(gue0(41, inner_ipv6())))
    # variant 1 with an IP version that is neither 4 nor 6
    A(pkt(bytes([0x50]) + b'not an ip packet at all'))
    A(pkt(bytes([0x7f]) + b'version 7'))
    # unknown variants 2 and 3
    A(pkt(bytes([0x80, 4, 0, 0]) + inner_ipv4()))
    A(pkt(bytes([0xc0 | 0x20 | 3, 1, 0, 0]) + b'variant three'))
    # variant 0 with fewer than 4 octets is not GUE
    A(pkt(bytes([0x00, 0x04])))
    A(pkt(bytes([0x00])))
    return fr


def build_malformed():
    fr = []
    A = fr.append
    # header length larger than the packet (error expert info)
    A(pkt(gue0(4, inner_ipv4(), hlen_field=31, ext=b'')))
    A(pkt(gue0(4, b'', hlen_field=1, ext=b'\1\2')))
    A(pkt(gue0(0, b'', control=True, hlen_field=20, ext=b'')))
    # truncated captures
    for n in (1, 2, 3, 5, 10):
        p = pkt(gue0(4, inner_ipv4(), hlen=2))
        A((p[:14 + 20 + 8 + n], len(p)))
    p = pkt(inner_ipv4())
    A((p[:14 + 20 + 8 + 10], len(p)))
    p = pkt(gue0(41, inner_ipv6()))
    A((p[:14 + 20 + 8 + 4 + 20], len(p)))
    A(pkt(b''))                                                     # empty UDP payload
    return fr


if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    for name, fr in (('gue-coverage.pcap', build()), ('gue-coverage-malformed.pcap', build_malformed())):
        pcap(os.path.join(out, name), fr)
        print('wrote %d frames to %s' % (len(fr), name))
