#!/usr/bin/env python3
# Generates test/captures/dsr_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the DSR dissector
(packet-dsr.c, Dynamic Source Routing, RFC 4728).

DSR is IP protocol 48. The 4 octet header holds a next header, the F
(flow state) bit and either a reserved field and the length of the
options that follow, or a hop count and a 16 bit flow id. The rest of
the packet goes to the next header. Every packet is built from scratch
with struct; no captured traffic is used.

Usage: mkdsr.py <output directory>

Writes:
  dsr-coverage.pcap            every option and route error type, hop
                               lists, flow state headers, next headers
                               UDP, TCP, DSR and none, IPv6
  dsr-coverage-malformed.pcap  the Next Header recursion reproducer and
                               options past the end of the packet
"""

import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import struct

from pktlib import eth, ip4, ip6, mac, pcap, udp, tcp_seg

A = (192, 0, 2, 1)
B = (192, 0, 2, 2)


def ip(n):
    return bytes((192, 0, 2, n))


def v4(payload, proto=48, ident=1):
    return eth(mac(2), mac(1), 0x0800, ip4(A, B, proto, payload, ident))


def v6(payload):
    s = bytes.fromhex('20010db8000000000000000000000001')
    d = bytes.fromhex('20010db8000000000000000000000002')
    return eth(mac(2), mac(1), 0x86dd, ip6(s, d, 48, payload))


def hdr(nh, opts):
    return struct.pack('!BBH', nh, 0, len(opts)) + opts


def fs_hdr(nh, hops, flow):
    return struct.pack('!BBH', nh, 0x80 | hops, flow)


def opt(t, body):
    return struct.pack('!BB', t, len(body)) + body


def rreq(ident, target, hops=()):
    return opt(1, struct.pack('!H', ident) + ip(target) + b''.join(ip(h) for h in hops))


def rrep(lasthopex, hops):
    return opt(2, bytes([0x80 if lasthopex else 0]) + b''.join(ip(h) for h in hops))


def rerr(etype, salvage, src, dst, extra):
    return opt(3, bytes([etype, salvage & 0x0f]) + ip(src) + ip(dst) + extra)


def ackreq(ident, addr=None):
    return opt(160, struct.pack('!H', ident) + (ip(addr) if addr else b''))


def ack(ident, src, dst):
    return opt(32, struct.pack('!H', ident) + ip(src) + ip(dst))


def srcrt(first, last, salvage, segsleft, hops):
    b = (0x80 if first else 0) | (0x40 if last else 0) | ((salvage >> 2) & 0x03)
    b2 = ((salvage & 0x03) << 6) | (segsleft & 0x3f)
    return opt(96, bytes([b, b2]) + b''.join(ip(h) for h in hops))


def padn(n):
    return opt(0, bytes(n))


PAD1 = b'\xe0'


def timeout(t):
    return opt(128, struct.pack('!H', t))


def destflowid(flow, dst):
    return opt(129, struct.pack('!H', flow) + ip(dst))


def udp_payload(data, sport=5000, dport=9):
    return udp(A, B, sport, dport, data)


def main_frames():
    f = []
    # 1: Route request without a hop list, next header "none" (59)
    f.append(v4(hdr(59, rreq(0x0101, 9))))
    # 2: Route request with a hop list of 3 addresses
    f.append(v4(hdr(59, rreq(0x0102, 9, (3, 4, 5)))))
    # 3: Route reply with the last hop external bit and 3 hops, then UDP
    f.append(v4(hdr(17, rrep(True, (3, 4, 9))) + udp_payload(b'hello dsr')))
    # 4: Route reply without the bit and one hop
    f.append(v4(hdr(59, rrep(False, (9,)))))
    # 5-10: Route errors of every type, an unknown type, salvage counts
    f.append(v4(hdr(59, rerr(1, 0, 3, 1, ip(4)))))
    f.append(v4(hdr(59, rerr(2, 1, 3, 1, b''))))
    f.append(v4(hdr(59, rerr(3, 2, 3, 1, b'\x81'))))
    f.append(v4(hdr(59, rerr(129, 3, 3, 1, ip(9) + struct.pack('!H', 0xbeef)))))
    f.append(v4(hdr(59, rerr(130, 15, 3, 1, ip(9)))))
    f.append(v4(hdr(59, rerr(42, 0, 3, 1, b''))))
    # 11: Ack request without and with an address
    f.append(v4(hdr(59, ackreq(0x0201) + ackreq(0x0202, 3))))
    # 12: Ack
    f.append(v4(hdr(59, ack(0x0202, 2, 3))))
    # 13: Source route with every flag, salvage and segments left, then UDP
    f.append(v4(hdr(17, srcrt(True, True, 9, 3, (3, 4, 5))) + udp_payload(b'routed')))
    # 14: Source route without hops and without flags
    f.append(v4(hdr(59, srcrt(False, False, 0, 0, ()))))
    # 15: Pad1 and PadN between options
    f.append(v4(hdr(59, PAD1 + ackreq(0x0203, 4) + padn(3) + PAD1 + ack(0x0203, 4, 1))))
    # 16: flow state options: timeout and destination/flow id, then TCP
    f.append(v4(hdr(6, timeout(300) + destflowid(0x0042, 9))
                + tcp_seg(A, B, 40000, 80, 1, 1, 0x10, b'')))
    # 17: an unknown option type
    f.append(v4(hdr(59, opt(5, b'') + ackreq(0x0204))))
    # 18: the options of a Route Request, Route Error and Ack Request
    # together (Info column with separators)
    f.append(v4(hdr(59, rreq(0x0103, 9, (3,)) + rerr(1, 0, 3, 1, ip(4)) + ackreq(0x0205, 1))))
    # 19: a DSR header carrying another DSR header (next header 48)
    f.append(v4(hdr(48, ackreq(0x0206)) + hdr(17, ack(0x0206, 2, 1)) + udp_payload(b'x')))
    # 20: flow state header, next header UDP
    f.append(v4(fs_hdr(17, 2, 0xabcd) + udp_payload(b'flow')))
    # 21: the flow state frame of the reproducer
    # (dsr_nexthdr_recursion.py): flow id 0x1234
    f.append(v4(fs_hdr(59, 3, 0x1234)))
    # 22: an options length of 0, an unknown next header (data)
    f.append(v4(hdr(253, b'') + b'opaque'))
    # 23: DSR over IPv6
    f.append(v6(hdr(59, rreq(0x0104, 9, (3, 4)))))
    # 24: fewer than 4 octets: not DSR, shown as data
    f.append(v4(b'\x3b\x00'))
    return f


def malformed_frames():
    f = []
    # 1: the reproducer: 2000 nested DSR headers (next header 48)
    f.append(v4(struct.pack('!BBH', 48, 0, 0) * 2000))
    # 2: options length past the end of the packet
    f.append(v4(struct.pack('!BBH', 59, 0, 40) + rreq(1, 9)))
    # 3: a hop list longer than the packet
    f.append(v4(struct.pack('!BBH', 59, 0, 30) + opt(1, struct.pack('!H', 1) + ip(9) + bytes(4))[:2]
                .replace(b'\x01\x0a', b'\x01\x1a') + struct.pack('!H', 1) + ip(9) + bytes(4)))
    # 4: route error cut short
    f.append(v4(struct.pack('!BBH', 59, 0, 4) + b'\x03\x0e\x01\x00'))
    # 5: flow state header cut short
    f.append(v4(b'\x3b\x83\x12'))
    # 6: source route, timeout, flow id, ack cut short
    for t in (96, 128, 129, 32, 160, 2):
        f.append(v4(struct.pack('!BBH', 59, 0, 3) + bytes([t, 20, 0])))
    return f


if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcap(os.path.join(out, 'dsr-coverage.pcap'), main_frames())
    pcap(os.path.join(out, 'dsr-coverage-malformed.pcap'), malformed_frames())
