#!/usr/bin/env python3
# Generates test/captures/ip_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic captures for packet-ip.c.  Usage: mkip.py <outdir> [-v]
Writes ip-coverage.pcap (main) and ip-coverage-malformed.pcap."""
import struct
import sys
import os

ETH = bytes.fromhex('020000000002' '020000000001') + b'\x08\x00'
A = bytes([192, 0, 2, 1])
B = bytes([192, 0, 2, 2])
C = bytes([198, 51, 100, 7])
P1 = bytes([10, 1, 2, 3])        # private
P2 = bytes([172, 16, 5, 6])      # private
L1 = bytes([169, 254, 1, 1])     # link local


def cksum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ip4(payload=b'', proto=253, src=A, dst=B, opts=b'', ttl=64, tos=0,
        ident=1, flags=0, off=0, tot=None, ver=4, ihl=None, bad_sum=False,
        pad=0):
    """flags: 0x4 DF, 0x2... as in the 3 flag bits (RF=4, DF=2, MF=1)."""
    opts = opts + b'\0' * (-len(opts) % 4)
    hl = 20 + len(opts)
    assert hl % 4 == 0 and hl <= 60, hl
    if ihl is None:
        ihl = hl // 4
    if tot is None:
        tot = hl + len(payload)
    fo = ((flags & 7) << 13) | (off & 0x1fff)
    h = struct.pack('!BBHHHBBH4s4s', (ver << 4) | ihl, tos, tot, ident, fo,
                    ttl, proto, 0, src, dst) + opts
    s = cksum(h)
    if bad_sum:
        s ^= 0x1234
    h = h[:10] + struct.pack('!H', s) + h[12:]
    return h + payload + b'\0' * pad


def udp(sp, dp, data=b''):
    return struct.pack('!HHHH', sp, dp, 8 + len(data), 0) + data


def icmp(t, c, rest, data=b''):
    h = struct.pack('!BBH', t, c, 0) + rest + data
    return h[:2] + struct.pack('!H', cksum(h)) + h[4:]


def ipv6(payload=b'', nh=59):
    return struct.pack('!IHBB16s16s', 0x60000000, len(payload), nh, 64,
                       bytes(15) + b'\1', bytes(15) + b'\2') + payload


class Cap:
    def __init__(self):
        self.frames = []
        self.marks = []

    def add(self, pkt, eth=True):
        self.frames.append(ETH + pkt if eth else pkt)

    def mark(self, name):
        self.marks.append((len(self.frames) + 1, name))

    def write(self, path):
        with open(path, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            for i, d in enumerate(self.frames):
                f.write(struct.pack('<IIII', 1700000000 + i, 0, len(d), len(d)))
                f.write(d)


def opt(t, body):
    return bytes([t, len(body) + 2]) + body


def pad4(o):
    return o + b'\0' * (-len(o) % 4)


# --------------------------------------------------------------------------
def main_cap():
    c = Cap()
    D = b'synthetic'
    c.mark('basic')
    c.add(ip4(D))
    c.add(ip4(D, ident=0xabcd, flags=2))                    # DF
    c.add(ip4(D, src=C, dst=A, ttl=128))
    c.add(ip4(udp(1024, 9, D), proto=17))
    c.add(ip4(icmp(8, 0, struct.pack('!HH', 1, 1), D), proto=1))
    c.add(ip4(struct.pack('!HHIIBBHHH', 1024, 80, 1, 0, 0x50, 2, 8192, 0, 0),
              proto=6))
    c.add(ip4(b'', proto=253))                             # zero data
    c.add(ip4(D + b'\0' * 20, proto=253, pad=0))           # payload w/o pad
    c.add(ip4(D, pad=14))                                  # link padding
    c.add(ip4(D, tot=0))                                   # TSO, len 0
    c.add(ip4(D, tos=0x00))
    c.mark('dsfield')
    for dscp in (0, 1, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30, 32, 34,
                 36, 38, 40, 44, 46, 48, 56, 2, 63):
        c.add(ip4(D, tos=dscp << 2 | (dscp & 3)))
    for ecn in (1, 2, 3):
        c.add(ip4(D, tos=ecn))
    c.mark('ttl')
    c.add(ip4(D, ttl=3))                                   # too small
    c.add(ip4(D, ttl=0))
    c.add(ip4(D, dst=bytes([224, 0, 0, 5]), ttl=64))       # LNCB, ttl != 1
    c.add(ip4(D, dst=bytes([224, 0, 0, 5]), ttl=1))
    c.add(ip4(D, dst=bytes([224, 0, 0, 18]), ttl=255))     # VRRP
    c.add(ip4(D, dst=bytes([224, 0, 0, 18]), ttl=1))
    c.add(ip4(D, dst=bytes([224, 0, 0, 102]), ttl=255))    # GLPB
    c.add(ip4(D, dst=bytes([224, 0, 0, 251]), ttl=255))    # mDNS
    c.add(ip4(D, dst=bytes([224, 0, 0, 252]), ttl=7))      # LLMNR any ttl
    igmp = icmp(0x11, 100, bytes([224, 0, 0, 1]))     # same checksum rule
    c.add(ip4(igmp, proto=2, dst=bytes([224, 0, 0, 1]), ttl=1))
    c.add(ip4(igmp, proto=2, dst=bytes([224, 0, 0, 1]), ttl=2))
    pim = icmp(0x20, 0, struct.pack('!HHH', 1, 2, 105))
    c.add(ip4(pim, proto=103, dst=bytes([192, 0, 2, 9]), ttl=1))   # PIM
    ospf = struct.pack('!BBH4s4sHH8s', 2, 1, 44, A, bytes(4), 0, 0, bytes(8)) + \
        struct.pack('!4sHBBI4s4s', bytes([255, 255, 255, 0]), 10, 2, 1, 40, A, bytes(4))
    c.add(ip4(ospf, proto=89, dst=bytes([192, 0, 2, 9]), ttl=1))    # OSPF
    c.add(ip4(D, dst=bytes([239, 1, 1, 1]), ttl=1))        # multicast low ttl
    c.mark('flags')
    c.add(ip4(D, flags=4))                                 # reserved bit
    c.add(ip4(D, flags=1))                                 # MF, first fragment
    c.add(ip4(D, flags=0, off=1))                          # last, orphan
    c.mark('addresses')
    for s, d in ((P1, P2), (P2, P1), (L1, A), (A, L1), (P1, A)):
        c.add(ip4(D, src=s, dst=d, ident=0x50))
    c.mark('options')
    O = {}
    c.add(ip4(D, opts=bytes([1, 1, 1, 0])))                # NOP NOP NOP EOL
    c.add(ip4(D, opts=bytes([1, 1, 1, 1])))                # 4 NOPs
    c.add(ip4(D, opts=bytes([1, 1, 1, 1, 1, 1, 1, 1])))
    c.add(ip4(D, opts=bytes([1, 0, 0, 0])))                # NOP EOL
    # Security: RFC 791 (len 11) and RFC 1108 forms
    c.add(ip4(D, opts=pad4(opt(0x82, struct.pack('!HH2s3s', 0xF135, 0x1234,
                                                 b'AB', b'XYZ')))))
    c.add(ip4(D, opts=pad4(opt(0x82, struct.pack('!HH2s3s', 0x0000, 0, b'AB',
                                                 b'XYZ')))))
    c.add(ip4(D, opts=pad4(opt(0x82, bytes([0x5a])))))
    c.add(ip4(D, opts=pad4(opt(0x82, bytes([0x96, 0x80, 0x01, 0x00])))))
    c.add(ip4(D, opts=pad4(opt(0x82, bytes([0xab, 0x3e])))))
    c.add(ip4(D, opts=pad4(opt(0x82, bytes([0x3d, 0x00])))))
    c.add(ip4(D, opts=pad4(opt(0x82, bytes(9)))))          # len 11 not 791 -> 1108, extraneous
    # extended security
    c.add(ip4(D, opts=pad4(opt(0x85, bytes([1, 2, 3, 4, 5])))))
    c.add(ip4(D, opts=pad4(opt(0x85, bytes([1])))))
    # CIPSO: DOI + tags
    doi = struct.pack('!I', 0x01020304)
    tags = [
        bytes([0, 0, 0]),                                  # padding
        bytes([1, 4, 0, 5]),                               # restrictive, no cats
        bytes([1, 8, 0, 5, 0x80, 0x01, 0x00, 0x20]),       # with cats
        bytes([1, 6, 0, 5, 0, 0]),                         # no bit set
        bytes([2, 4, 0, 6]),
        bytes([2, 10, 0, 6, 0, 1, 0, 2, 0xff, 0xff]),
        bytes([5, 4, 0, 7]),
        bytes([5, 12, 0, 7, 0, 10, 0, 20, 0, 30, 0, 30]),
        bytes([5, 10, 0, 7, 0, 10, 0, 20, 0, 33]),         # odd tail
        bytes([6, 6, 1, 2, 3, 4]),
        bytes([7, 6, 1, 2, 3, 4]),
        bytes([7, 2]),
        bytes([9, 4, 0, 0]),                               # unknown tag
    ]
    for t in tags:
        c.add(ip4(D, opts=pad4(opt(0x86, doi + t))))
    c.add(ip4(D, opts=pad4(opt(0x86, doi + tags[2] + bytes([7, 4, 9, 9])))))
    c.add(ip4(D, opts=pad4(opt(0x86, doi + bytes([0])))))
    # LSR / SSR / RR
    def route(t, ptr, addrs):
        return opt(t, bytes([ptr]) + b''.join(addrs))
    r3 = [bytes([10, 0, 0, i]) for i in (1, 2, 3)]
    for t in (0x83, 0x89):
        c.add(ip4(D, opts=pad4(route(t, 4, r3))))            # next = first
        c.add(ip4(D, opts=pad4(route(t, 8, r3))))            # one recorded
        c.add(ip4(D, opts=pad4(route(t, 12, r3))))           # last = dest
        c.add(ip4(D, opts=pad4(route(t, 16, r3))))           # exhausted
        c.add(ip4(D, opts=pad4(route(t, 255, r3))))
        c.add(ip4(D, opts=pad4(route(t, 4, r3[:1]))))        # dest only
        c.add(ip4(D, opts=pad4(route(t, 3, r3))))            # before address
        c.add(ip4(D, opts=pad4(route(t, 6, r3))))            # middle
    c.add(ip4(D, opts=bytes([0x83, 7, 4, 198, 51, 100, 7, 0])))   # LSR repro
    c.add(ip4(D, opts=bytes([0x83, 4, 4, 0xEE, 0, 0, 0, 0])))     # len 4
    c.add(ip4(D, opts=bytes([0x83, 5, 4, 0xEE, 0xDD, 0, 0, 0])))  # len 5
    c.add(ip4(D, opts=bytes([0x83, 3, 4, 0])))                    # len 3
    c.add(ip4(D, opts=bytes([0x89, 6, 4, 0xEE, 0xDD, 0xCC, 0, 0])[:8]))
    c.add(ip4(D, opts=pad4(route(0x07, 4, [bytes(4)] * 3))))     # RR next
    c.add(ip4(D, opts=pad4(route(0x07, 8, [bytes([10, 0, 0, 9])] + [bytes(4)] * 2))))
    c.add(ip4(D, opts=pad4(route(0x07, 16, [bytes([10, 0, 0, 9])] * 3))))  # full
    c.add(ip4(D, opts=pad4(route(0x07, 255, [bytes([10, 0, 0, 9])] * 3))))
    c.add(ip4(D, opts=pad4(route(0x07, 4, [])) ))
    c.add(ip4(D, opts=pad4(route(0x07, 3, [bytes(4)]))))          # before
    c.add(ip4(D, opts=pad4(route(0x07, 6, [bytes(4)]))))          # middle
    c.add(ip4(D, opts=bytes([0x07, 6, 4, 1, 2, 3, 0, 0])[:8]))    # too long
    # stream id, MTU, traceroute, RA, SDB, QS, DSR
    c.add(ip4(D, opts=opt(0x88, b'\x12\x34')))
    c.add(ip4(D, opts=bytes([0x88, 6, 1, 2, 0, 0, 0, 0])[:8]))
    c.add(ip4(D, opts=opt(11, b'\x05\xdc')))
    c.add(ip4(D, opts=opt(12, b'\x05\xdc')))
    c.add(ip4(D, opts=pad4(opt(0x52, struct.pack('!HHH4s', 7, 3, 4, A)))))
    c.add(ip4(D, opts=opt(0x94, b'\0\0')))
    c.add(ip4(D, opts=opt(0x94, b'\0\1')))
    c.add(ip4(D, opts=pad4(opt(0x95, A + B))))
    c.add(ip4(D, opts=pad4(opt(0x95, A + b'\1\2'))))
    c.add(ip4(D, opts=pad4(opt(0x95, b''))))
    c.add(ip4(D, opts=opt(25, bytes([0x0a, 60]) + struct.pack('!I', 0xfffffffc)[:4]), ttl=64))
    c.add(ip4(D, opts=pad4(opt(25, bytes([0x0a, 60, 1, 2, 3, 0xfc])))))
    c.add(ip4(D, opts=pad4(opt(25, bytes([0x4f, 0, 1, 2, 3, 0xfc])))))
    c.add(ip4(D, opts=pad4(opt(25, bytes([0x80, 0, 1, 2, 3, 0xfc])))))   # unknown func
    c.add(ip4(D, opts=pad4(opt(0x9a, struct.pack('<H4s', 8080, A)))))
    # timestamp
    ts0 = lambda ptr, fl, body: opt(0x44, bytes([ptr, fl]) + body)
    c.add(ip4(D, opts=ts0(5, 0, struct.pack('!II', 100, 0))))
    c.add(ip4(D, opts=ts0(1, 0, struct.pack('!II', 100, 200))))
    c.add(ip4(D, opts=ts0(3, 0, b'\0' * 8)))
    c.add(ip4(D, opts=ts0(6, 0, b'\0' * 8)))
    c.add(ip4(D, opts=ts0(5, 1, A + struct.pack('!I', 1000) + bytes(4) + struct.pack('!I', 5))))
    c.add(ip4(D, opts=ts0(13, 3, A + struct.pack('!I', 1000) + B + struct.pack('!I', 5))))
    c.add(ip4(D, opts=pad4(ts0(5, 0, b'\0' * 3))))                    # too long
    c.add(ip4(D, opts=pad4(ts0(5, 1, b'\0' * 6))))
    c.add(ip4(D, opts=ts0(5, 0x10 | 1, A + struct.pack('!I', 1000) + b'\0' * 4 + struct.pack('!I', 5))))
    # unknown / other-numbered options
    c.add(ip4(D, opts=pad4(opt(0x8b, b'\1\2\3'))))
    c.add(ip4(D, opts=pad4(opt(10, b'\1\2'))))
    c.add(ip4(D, opts=pad4(opt(30, b'\1\2'))))
    c.add(ip4(D, opts=pad4(opt(0x4d, b'\1\2'))))
    c.add(ip4(D, opts=pad4(opt(0x8e, b'\1\2'))))
    # several options in one header + after EOL
    c.add(ip4(D, opts=pad4(opt(0x94, b'\0\0') + opt(11, b'\5\xdc') + bytes([1, 0]))))
    c.add(ip4(D, opts=bytes([0, 0x94, 4, 0, 0, 0, 0, 0])))        # EOL then junk
    # option dissection with maximal option space
    c.add(ip4(D, opts=bytes([1] * 40)))
    c.add(ip4(D, opts=route(0x83, 4, [bytes([10, 0, 0, i]) for i in range(9)]) + b'\0'))
    c.add(ip4(D, opts=pad4(opt(0x82, bytes([0x5a, 0x01, 0x01, 0x00])))))
    c.mark('fragments')
    # ICMP echo of 3000 octets in three fragments, in order
    big = icmp(8, 0, struct.pack('!HH', 7, 1), bytes(i % 251 for i in range(2992)))
    def frags(ident, order, src=A, dst=B, size=1000, proto=1, data=big):
        n = (len(data) + size - 1) // size
        pk = []
        for i in range(n):
            ch = data[i * size:(i + 1) * size]
            pk.append(ip4(ch, proto=proto, src=src, dst=dst, ident=ident,
                          flags=1 if i < n - 1 else 0, off=i * size // 8))
        return [pk[i] for i in order]
    for p in frags(0x1001, (0, 1, 2)):
        c.add(p)
    for p in frags(0x1002, (2, 0, 1), src=P1, dst=P2):       # out of order
        c.add(p)
    for p in frags(0x1003, (0, 2, 1), src=L1, dst=A):
        c.add(p)
    for p in frags(0x1004, (0, 1, 2), data=udp(40000, 40001, bytes(2000)), proto=17, size=800):
        c.add(p)
    for p in frags(0x1005, (1, 0), data=b'x' * 1600, proto=253, size=800):
        c.add(p)
    c.add(frags(0x1006, (0, 1, 2))[0])                       # never completed
    c.add(frags(0x1006, (0, 1, 2))[2])
    c.add(ip4(D + b'1234567', flags=1, off=0, ident=0x1007, proto=253))   # first frag
    c.add(ip4(D, flags=0, off=2, ident=0x1007, proto=253))
    c.add(ip4(D, flags=1, off=0, ident=0x1009, proto=253))   # tiny first frag
    c.add(ip4(D, flags=0, off=1, ident=0x1009, proto=253))   # overlaps (not multiple of 8)
    c.add(ip4(D, flags=3, off=2, ident=0x1008, proto=253))   # DF and MF
    c.mark('icmp_inner')
    inner = ip4(udp(53, 53, b'\0' * 4), proto=17, tot=200, src=B, dst=A)[:28]
    c.add(ip4(icmp(3, 3, bytes(4), inner), proto=1, src=B, dst=A))
    inner2 = ip4(b'', proto=6, tot=1500, src=B, dst=A)[:20] + bytes(8)
    c.add(ip4(icmp(3, 4, struct.pack('!HH', 0, 1400), inner2), proto=1, src=B, dst=A))
    c.add(ip4(icmp(11, 0, bytes(4), inner2), proto=1, src=B, dst=A))
    c.mark('tunnel')
    inn = ip4(D, src=P1, dst=P2)
    c.add(ip4(inn, proto=4))
    c.add(ip4(ipv6(), proto=4))
    c.add(ip4(ip4(ip4(D), proto=4), proto=4))
    c.add(ip4(ipv6(D, 59), proto=41))
    # GTP-U carrying IPv4 / IPv6 (heuristic) and a non-IP payload
    def gtp(p):
        return udp(2152, 2152, struct.pack('!BBHI', 0x30, 255, len(p), 0x1234) + p)
    c.add(ip4(gtp(ip4(D, src=P1, dst=P2)), proto=17))
    c.add(ip4(gtp(ip4(D, src=P1, dst=P2, opts=pad4(opt(0x94, b'\0\0')))), proto=17))
    c.add(ip4(gtp(ipv6(D, 59)), proto=17))
    c.add(ip4(gtp(b'\x90abcdef'), proto=17))                  # not IP
    c.add(ip4(gtp(b'\x45'), proto=17))                          # too short
    c.add(ip4(gtp(ip4(D, src=P1, dst=P2, pad=4)), proto=17))    # tot != length
    c.add(ip4(gtp(ip4(D, src=P1, dst=P2, ihl=5, ver=3)), proto=17))  # version 3
    c.add(ip4(gtp(bytes([0x44, 0, 0, 20]) + bytes(16)), proto=17))   # ihl 4
    c.mark('conv')
    for i in range(6):
        c.add(ip4(D, src=bytes([192, 0, 2, 20 + i % 3]), dst=bytes([192, 0, 2, 30 + i % 2]), ident=0x70 + i))
    # a TCP segment to the STT port: with "try heuristic first" the IP
    # heuristic list (STT) takes it before the TCP handler
    inner_eth = bytes.fromhex('ffffffffffff' '020000000001') + b'\x08\x06' + struct.pack(
        '!HHBBH6s4s6s4s', 1, 0x0800, 6, 4, 1, bytes([2, 0, 0, 0, 0, 1]), A, bytes(6), B)
    stt_hdr = struct.pack('!BBBBHHQH', 0, 0, 0, 0, 0, 0, 0x1234, 0)    # version 0, no flags
    stt_len = len(stt_hdr) + len(inner_eth)
    stt_tcp = struct.pack('!HHIIBBHHH', 1000, 7471, stt_len, 7, 0x50, 0x10, 0, 0, 0)
    c.add(ip4(stt_tcp + stt_hdr + inner_eth, proto=6))
    c.mark('cipso_overflow')
    # reproducers of "IP: Fix short LSR/SSR options and CIPSO tag bounds":
    # a tag one octet past the end of the option (error expert, no exception)
    for t in (1, 2, 5, 6, 7):
        c.add(ip4(D, opts=pad4(opt(0x86, doi + bytes([t, 5, 0, 5])))))
    return c


def malformed_cap():
    c = Cap()
    D = b'synthetic'
    c.add(ip4(D, ver=5))
    c.add(ip4(ipv6(), ver=6))
    c.add(ip4(D, ihl=4))
    c.add(ip4(D, tot=10))
    c.add(ip4(D, tot=300))
    c.add(ip4(D, bad_sum=True))
    c.add(ip4(D, ver=0, ihl=5))
    c.add(ip4(D, ihl=15))                                   # header past the data
    c.add(ip4(D, ihl=6))
    doi = struct.pack('!I', 1)
    for t in (1, 2, 5, 6, 7):
        for tl in (0, 1, 2, 3, 35, 200):
            c.add(ip4(D, opts=pad4(opt(0x86, doi + bytes([t, tl, 0, 5])))))
    c.add(ip4(D, opts=pad4(opt(0x86, doi + bytes([1])))))
    c.add(ip4(D, opts=pad4(opt(0x86, b'\0\0'))))
    c.add(ip4(D, opts=bytes([1, 1, 1, 0x94])))             # length byte past end
    c.add(ip4(D, opts=bytes([1, 1, 0x94, 0])))
    c.add(ip4(D, opts=bytes([0x94, 1, 0, 0])))              # too short length
    c.add(ip4(D, opts=bytes([0x94, 0, 0, 0])))
    c.add(ip4(D, opts=bytes([0x94, 8, 0, 0])))              # past the end
    c.add(ip4(D, opts=bytes([0x8e, 8, 0, 0])))              # unknown, past the end
    c.add(ip4(D, opts=bytes([0x8e, 1, 0, 0])))
    c.add(ip4(D, opts=bytes([0x8e, 0, 0, 0])))
    c.add(ip4(D, opts=bytes([0x94, 5, 0, 0, 0, 0, 0, 0])))     # RA length 5
    c.add(ip4(D, opts=bytes([0x94, 3, 0, 0])))                 # RA length 3
    c.add(ip4(D, opts=bytes([0x88, 3, 0, 0])))                 # SID length 3
    c.add(ip4(D, opts=bytes([0x88, 5, 0, 0, 0, 0, 0, 0])))
    c.add(ip4(D, opts=bytes([11, 3, 0, 0])))
    c.add(ip4(D, opts=bytes([25, 3, 0, 0])))
    c.add(ip4(D, opts=bytes([0x9a, 3, 0, 0])))
    c.add(ip4(D, opts=bytes([0x52, 3, 0, 0])))
    c.add(ip4(D, opts=bytes([0x82, 2, 0, 0])))             # security, empty
    c.add(ip4(D, opts=bytes([0x85, 2, 0, 0])))
    c.add(ip4(D, opts=bytes([0x83, 2, 0, 0])))             # LSR, no pointer
    c.add(ip4(D, opts=bytes([0x07, 2, 0, 0])))
    c.add(ip4(D, opts=bytes([0x44, 3, 0, 0])))             # TS short
    c.add(ip4(D, opts=bytes([0x44, 2, 0, 0])))
    c.add(ip4(D, opts=bytes([0x83, 4, 4, 0xEE, 0, 0, 0, 0])))
    c.add(ip4(D, opts=bytes([0x89, 3, 4, 0])))
    c.add(ip4(D, opts=bytes([0x83, 6, 4, 1, 2, 3, 0, 0])[:8]))
    c.add(ip4(D, opts=bytes([0x82, 3, 0x3d, 0x01])))       # FTI to the end
    c.add(ip4(D, opts=bytes([0x82, 5, 0x3d, 0x01, 0x01, 0x01])[:6] + b'\0\0'))
    c.add(ip4(D, opts=bytes([0x82, 12, 0x3d, 0x01, 0x01, 1, 1, 1, 1, 1, 1, 1, 0, 0])[:12]))
    # bogus ip version through the generic IP handler (IP-in-IP)
    c.add(ip4(bytes([0x50]) + bytes(19), proto=4))
    c.add(ip4(bytes([0x00]), proto=4))
    c.add(ip4(ip4(D, ihl=4), proto=4))
    c.add(ip4(ip4(D, tot=300), proto=4))
    # fragments with a bad checksum, an overlapping fragment, ICMP error
    c.add(ip4(D, flags=1, off=0, ident=0x2000, bad_sum=True))
    c.add(ip4(D, flags=0, off=1, ident=0x2000, bad_sum=True))
    # truncated frames
    full = ETH + ip4(D)
    c.frames.append(full[:14 + 19])
    c.frames.append(full[:14 + 21])
    c.frames.append(ETH + ip4(D, opts=pad4(opt(0x44, bytes([5, 0, 0, 0, 0, 0]))))[:14 + 26])
    c.frames.append(ETH + ip4(D, opts=pad4(opt(0x82, bytes(9))))[:14 + 25])
    return c


def main():
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    m = main_cap()
    m.write(os.path.join(out, 'ip-coverage.pcap'))
    x = malformed_cap()
    x.write(os.path.join(out, 'ip-coverage-malformed.pcap'))
    if '-v' in sys.argv:
        for n, nm in m.marks:
            print(n, nm)
        print('main frames', len(m.frames), 'malformed', len(x.frames))


main()
