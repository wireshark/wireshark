#!/usr/bin/env python3
# AODV coverage capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""AODV messages (epan/dissectors/packet-aodv.c): RREQ, RREP, RERR and RREP-ACK
over IPv4 and IPv6 (RFC 3561), the draft-perkins-manet-aodv6-01 types 16-19,
every flag, several unreachable destinations, every extension type, a
non-AODV first octet, AODV on a second UDP port (for the udp.port pref), and
zero length and short extensions and truncated messages.

Usage: mkaodv.py [<output directory>]

Writes:
  aodv-coverage.pcap            the messages that decode cleanly
  aodv-coverage-malformed.pcap  zero length and short extensions (error
                                expert info), truncated messages

Every packet is built here; nothing comes from a real network. Addresses are
documentation addresses (192.0.2.0/24, 2001:db8::/32) and locally
administered MACs.
"""

import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct

from capgen import eth, ipv4, ipv6, udp, write_pcap  # noqa: E402

AODV = 654
ALT_PORT = 6540   # AODV here only with -o aodv.udp.port:654,6540


def mac(n):
    return bytes([0x02, 0, 0, 0, 0, n])


def a4(n):
    return bytes([192, 0, 2, n])


def a6(n):
    return b'\x20\x01\x0d\xb8' + bytes(11) + bytes([n])


def udp4(src, dst, payload, sport=AODV, dport=AODV):
    s, d = a4(src), a4(dst)
    seg = udp(payload, sport, dport, src=s, dst=d)
    return eth(ipv4(seg, 17, src=s, dst=d, ident=0, flags_frag=0x4000), 0x0800,
               dst=mac(dst), src=mac(src))


def udp6(src, dst, payload, sport=AODV, dport=AODV):
    s, d = a6(src), a6(dst)
    seg = udp(payload, sport, dport, src=s, dst=d)
    return eth(ipv6(seg, 17, src=s, dst=d), 0x86dd, dst=mac(dst), src=mac(src))


# ---------------------------------------------------------------------------
# AODV messages (RFC 3561 section 5, draft-perkins-manet-aodv6-01)

J, R, G, D, U = 0x8000, 0x4000, 0x2000, 0x1000, 0x0800   # RREQ flags
RR, RA = 0x8000, 0x4000                                  # RREP flags
N = 0x8000                                               # RERR flag


def ext(t, data):
    return struct.pack('!BB', t, len(data)) + data


def hello(ms, extra=b''):
    return ext(2, struct.pack('!I', ms) + extra)


def ntp(ts, extra=b''):
    return ext(3, struct.pack('!Q', ts) + extra)


def addr(v6, n):
    return a6(n) if v6 else a4(n)


def rreq(v6, flags, hops, rid, dst, dseq, orig, oseq, exts=b''):
    return (struct.pack('!BHBI', 1, flags, hops, rid) + addr(v6, dst) + struct.pack('!I', dseq)
            + addr(v6, orig) + struct.pack('!I', oseq) + exts)


def rrep(v6, flags, prefix, hops, dst, dseq, orig, life, exts=b''):
    return (struct.pack('!BHB', 2, flags | prefix, hops) + addr(v6, dst) + struct.pack('!I', dseq)
            + addr(v6, orig) + struct.pack('!I', life) + exts)


def rerr(v6, flags, dests, count=None):
    count = len(dests) if count is None else count
    return struct.pack('!BHB', 3, flags, count) + b''.join(
        addr(v6, n) + struct.pack('!I', s) for n, s in dests)


def rrep_ack(t=4):
    return struct.pack('!BB', t, 0)


def d_rreq(flags, hops, rid, dseq, oseq, dst, orig, exts=b''):
    return struct.pack('!BHBIII', 16, flags, hops, rid, dseq, oseq) + a6(dst) + a6(orig) + exts


def d_rrep(flags, prefix, hops, dseq, dst, orig, life, exts=b''):
    return (struct.pack('!BHBI', 17, flags | prefix, hops, dseq) + a6(dst) + a6(orig)
            + struct.pack('!I', life) + exts)


def d_rerr(flags, dests, count=None):
    count = len(dests) if count is None else count
    return struct.pack('!BHB', 18, flags, count) + b''.join(
        struct.pack('!I', s) + a6(n) for n, s in dests)


def build_main():
    f = []
    # ---- RFC 3561 over IPv4 (frames 1-28)
    # RREQ: no flag, each flag alone, all flags (and reserved bits set)
    for i, fl in enumerate((0, J, R, G, D, U, J | R | G | D | U | 0x07ff)):
        f.append(udp4(1, 255, rreq(False, fl, i, 100 + i, 9, 50 + i, 1, 10 + i)))
    # RREQ with each extension type, alone and chained
    f.append(udp4(1, 255, rreq(False, G, 1, 200, 9, 5, 1, 6, hello(1000))))
    f.append(udp4(1, 255, rreq(False, 0, 1, 201, 9, 5, 1, 6, ntp(0x0123456789abcdef))))
    f.append(udp4(1, 255, rreq(False, 0, 1, 202, 9, 5, 1, 6, ext(1, b'\0\0'))))
    f.append(udp4(1, 255, rreq(False, 0, 1, 203, 9, 5, 1, 6, ext(200, b'abc'))))
    f.append(udp4(1, 255, rreq(False, U, 1, 204, 9, 0, 1, 6,
                               hello(500, b'\xee\xee') + ntp(42, b'\xff') + ext(1, b'\0') + ext(7, b'x'))))
    # RREP: no flag, R, A, both; prefix sizes 0, 1, 31
    for fl, pfx in ((0, 0), (RR, 1), (RA, 24), (RR | RA, 0x1f), (0x3f00, 5)):
        f.append(udp4(9, 1, rrep(False, fl, pfx, 2, 9, 77, 1, 3000)))
    f.append(udp4(9, 1, rrep(False, RA, 0, 0, 9, 78, 1, 2000, hello(1000))))     # Hello message
    f.append(udp4(9, 1, rrep(False, 0, 0, 3, 9, 79, 1, 4000, ntp(1) + hello(250))))
    # RERR: N flag or not, 0, 1 and several unreachable destinations
    f.append(udp4(3, 255, rerr(False, 0, [])))
    f.append(udp4(3, 255, rerr(False, N, [(7, 1)])))
    f.append(udp4(3, 255, rerr(False, 0, [(7, 2), (8, 3), (9, 4), (10, 0xffffffff)])))
    f.append(udp4(3, 255, rerr(False, N | 0x7fff, [(n, n) for n in range(20, 40)])))
    # RREP-ACK
    f.append(udp4(1, 9, rrep_ack()))
    f.append(udp4(1, 9, rrep_ack() + b'\0\0'))
    # first octet not an AODV type: not AODV, shown as data
    f.append(udp4(1, 9, b'\x05\x00\x00\x00'))
    f.append(udp4(1, 9, b'\x00'))
    # AODV on a second port (only with the udp.port preference)
    f.append(udp4(1, 255, rreq(False, D, 1, 300, 9, 5, 1, 6), sport=ALT_PORT, dport=ALT_PORT))

    # ---- RFC 3561 over IPv6 (frames 29-44)
    for i, fl in enumerate((0, J, R, G, D, U, J | R | G | D | U)):
        f.append(udp6(1, 2, rreq(True, fl, i, 400 + i, 9, 60 + i, 1, 20 + i)))
    f.append(udp6(1, 2, rreq(True, 0, 1, 410, 9, 5, 1, 6, hello(1000) + ntp(99) + ext(1, b'\0\0') + ext(9, b'zz'))))
    for fl, pfx in ((0, 0), (RR, 64 & 0x1f), (RA | RR, 0x1f)):
        f.append(udp6(9, 1, rrep(True, fl, pfx, 2, 9, 88, 1, 3000)))
    f.append(udp6(9, 1, rrep(True, RA, 0, 0, 9, 89, 1, 2000, hello(1000))))
    f.append(udp6(3, 2, rerr(True, 0, [])))
    f.append(udp6(3, 2, rerr(True, N, [(7, 1)])))
    f.append(udp6(3, 2, rerr(True, 0, [(7, 1), (8, 2), (9, 3)])))
    f.append(udp6(1, 9, rrep_ack()))

    # ---- draft-perkins-manet-aodv6-01 (frames 45-60)
    for i, fl in enumerate((0, J, R, G, D, U, J | R | G | D | U)):
        f.append(udp6(1, 2, d_rreq(fl, i, 500 + i, 70 + i, 30 + i, 9, 1)))
    f.append(udp6(1, 2, d_rreq(0, 1, 510, 5, 6, 9, 1, hello(1000) + ntp(7) + ext(1, b'\0\0') + ext(9, b'zz'))))
    for fl, pfx in ((0, 0), (RR, 64), (RA | RR, 0x7f)):
        f.append(udp6(9, 1, d_rrep(fl, pfx, 2, 99, 9, 1, 3000)))
    f.append(udp6(9, 1, d_rrep(RA, 0, 0, 100, 9, 1, 2000, hello(1000) + ntp(8))))
    f.append(udp6(3, 2, d_rerr(0, [])))
    f.append(udp6(3, 2, d_rerr(N, [(1, 7)])))
    f.append(udp6(3, 2, d_rerr(0, [(1, 7), (2, 8), (3, 9)])))
    f.append(udp6(1, 9, rrep_ack(19)))

    # ---- further cases that decode cleanly (frames 61-69)
    rreq4 = rreq(False, J, 3, 7, 9, 5, 1, 6)
    f.append(udp4(1, 2, rreq4 + bytes([9, 1, 0]) * 470))                   # 470 extensions
    f.append(udp4(1, 2, rrep(False, RA, 0x1f, 2, 9, 5, 1, 300, hello(1000))))
    f.append(udp4(1, 2, rrep_ack()))
    f.append(udp6(1, 2, rreq(True, 0, 3, 7, 9, 5, 1, 6, hello(1000))))
    f.append(udp6(1, 2, rrep(True, 0, 64, 2, 9, 5, 1, 300)))             # prefix octet 64
    f.append(udp6(1, 2, rerr(True, 0, [(7, 1), (7, 1)])))
    f.append(udp6(1, 2, d_rreq(0, 1, 2, 3, 4, 9, 1, bytes([9, 1, 0]) * 100)))
    f.append(udp6(1, 2, d_rrep(0, 0x7f, 1, 2, 9, 1, 9)))
    f.append(udp6(1, 2, rrep_ack(19)))
    return f


def build_malformed():
    f = []
    rreq4 = rreq(False, J, 3, 7, 9, 5, 1, 6)
    # zero length extension, short Timestamp, RERR claiming 255 destinations
    # (v4 and draft v6)
    f.append(udp4(1, 2, rreq4 + hello(1000) + ntp(123) + bytes([1, 0])))
    f.append(udp4(1, 2, rreq4 + bytes([3, 1, 0])))
    f.append(udp4(1, 2, rerr(False, N, [(7, 1)] * 3, count=255)))
    f.append(udp6(1, 2, d_rerr(0, [(7, 1)] * 2, count=255)))
    # short Hello Interval, short Timestamp of 7, both in IPv6
    f.append(udp4(1, 2, rreq4 + ext(2, b'\0\0') + hello(5)))
    f.append(udp6(1, 2, rreq(True, 0, 1, 1, 9, 5, 1, 6, ext(3, bytes(7)) + ext(2, b'\0\0\0'))))
    f.append(udp6(1, 2, d_rrep(0, 0, 1, 2, 9, 1, 9, ext(2, b'\1'))))
    # extension running past the end, a lone type octet
    f.append(udp4(1, 2, rreq4 + bytes([2, 4, 0, 0])))
    f.append(udp4(1, 2, rreq4 + bytes([2])))
    f.append(udp4(1, 2, rrep(False, 0, 0, 1, 9, 5, 1, 300) + bytes([3, 0])))
    # truncated messages of each type
    for p4 in (rreq4, rrep(False, 0, 0, 1, 9, 5, 1, 300), rerr(False, 0, [(7, 1)])):
        f.append(udp4(1, 2, p4[:-3]))
    for p6 in (rreq(True, 0, 1, 1, 9, 5, 1, 6), rrep(True, 0, 0, 1, 9, 5, 1, 300),
               rerr(True, 0, [(7, 1)]), d_rreq(0, 1, 2, 3, 4, 9, 1),
               d_rrep(0, 0, 1, 2, 9, 1, 9), d_rerr(0, [(7, 1)])):
        f.append(udp6(1, 2, p6[:-3]))
    f.append(udp4(1, 2, b'\x01'))
    return f


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'aodv-coverage.pcap'), build_main(), snaplen=65535)
    write_pcap(os.path.join(out, 'aodv-coverage-malformed.pcap'), build_malformed(), snaplen=65535)


if __name__ == '__main__':
    main()
