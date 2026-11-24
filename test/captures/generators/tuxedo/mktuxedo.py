#!/usr/bin/env python3
# Generates test/captures/tuxedo_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Common helpers: pcap writer and Ethernet / MPLS / IPv4 / UDP builders.
import struct
import sys
import os

MAC_A = bytes.fromhex('020000000001')
MAC_B = bytes.fromhex('020000000002')
IP_A = bytes([192, 0, 2, 1])
IP_B = bytes([192, 0, 2, 2])


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def eth(payload, etype, dst=MAC_B, src=MAC_A):
    return dst + src + struct.pack('>H', etype) + payload


def ipv4(payload, proto=17, src=IP_A, dst=IP_B, ident=1):
    h = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0,
                    64, proto, 0, src, dst)
    h = h[:10] + struct.pack('>H', csum(h)) + h[12:]
    return h + payload


def ipv6(payload, nh=17):
    src = bytes.fromhex('20010db8000000000000000000000001')
    dst = bytes.fromhex('20010db8000000000000000000000002')
    return struct.pack('>IHBB', 0x60000000, len(payload), nh, 64) + src + dst + payload


def udp(payload, sport, dport, src=IP_A, dst=IP_B):
    n = 8 + len(payload)
    pseudo = src + dst + struct.pack('>BBH', 0, 17, n)
    h = struct.pack('>HHHH', sport, dport, n, 0)
    c = csum(pseudo + h + payload) or 0xffff
    return struct.pack('>HHHH', sport, dport, n, c) + payload


def udp_frame(payload, sport, dport, ident=1):
    return eth(ipv4(udp(payload, sport, dport), ident=ident), 0x0800)


def mpls(label, payload, ttl=64, tc=0, bos=1):
    return struct.pack('>I', (label << 12) | (tc << 9) | (bos << 8) | ttl) + payload


def mpls_frame(label, payload, **kw):
    return eth(mpls(label, payload, **kw), 0x8847)


class Pcap:
    def __init__(self, linktype=1):
        self.frames = []
        self.linktype = linktype

    def add(self, data, snap=None):
        # snap: captured length smaller than the original length
        self.frames.append((data, snap))
        return len(self.frames)

    def write(self, path):
        with open(path, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, self.linktype))
            for i, (d, snap) in enumerate(self.frames):
                t = 1700000000 + i
                cap = d if snap is None else d[:snap]
                f.write(struct.pack('<IIII', t, 1000 * i, len(cap), len(d)))
                f.write(cap)
        return len(self.frames)


def tcp(payload, sport, dport, seq=1, ack=1, flags=0x18, src=IP_A, dst=IP_B):
    h = struct.pack('>HHIIBBHHH', sport, dport, seq, ack, 0x50, flags, 65535, 0, 0)
    pseudo = src + dst + struct.pack('>BBH', 0, 6, len(h) + len(payload))
    c = csum(pseudo + h + payload)
    return h[:16] + struct.pack('>H', c) + h[18:] + payload


def tcp_frame(payload, sport, dport, seq=1, ack=1, flags=0x18, down=False, ident=1):
    if down:
        return eth(ipv4(tcp(payload, sport, dport, seq, ack, flags, src=IP_B, dst=IP_A), 6, src=IP_B, dst=IP_A, ident=ident), 0x0800, dst=MAC_A, src=MAC_B)
    return eth(ipv4(tcp(payload, sport, dport, seq, ack, flags), 6, ident=ident), 0x0800)


class Tcp:
    """One TCP connection with consistent sequence numbers (client = IP_A)."""
    def __init__(self, cport, sport, ident=1):
        self.cport, self.sport, self.ident = cport, sport, ident
        self.cseq, self.sseq = 1000, 5000

    def c(self, payload):
        self.ident += 1
        f = tcp_frame(payload, self.cport, self.sport, self.cseq, self.sseq, 0x18, False, self.ident)
        self.cseq += len(payload)
        return f

    def s(self, payload):
        self.ident += 1
        f = tcp_frame(payload, self.sport, self.cport, self.sseq, self.cseq, 0x18, True, self.ident)
        self.sseq += len(payload)
        return f


def raw_eth(dst, src, etype, payload):
    return dst + src + struct.pack('>H', etype) + payload

# ---- tuxedo ----
# BEA Tuxedo over TCP: the heuristic (enabled by default) recognises the
# magic of a segment, then sets the conversation dissector, so later
# segments without the magic are shown as continuations.
MAGIC = 0x91039858
SMAGIC = 0x73903842


def msg(op, extra=b'', magic=MAGIC):
    return struct.pack('>II', magic, op) + extra


def build(out):
    main = Pcap()
    t = Tcp(52000, 55123)
    for op in range(1, 26):                                                 # 1-25 every opcode, alternating direction
        p = msg(op, bytes(range(op)) + b'tuxedo payload')
        main.add(t.s(p) if op % 2 == 0 else t.c(p))
    main.add(t.c(msg(0x99, b'unknown opcode')))                             # 26 unknown opcode 0x99
    main.add(t.s(msg(0, b'')))                                              # 27 opcode 0, exactly 8 octets
    main.add(t.c(b'continuation of a message: no magic'))                   # 28 continuation (conversation already set)
    main.add(t.s(b'abcdefgh'))                                              # 29 8 octets, no magic
    main.add(t.c(b'abc'))                                                   # 30 3 octets: too short, no Info
    t2 = Tcp(52001, 55124)
    main.add(t2.c(msg(1, b'second conversation', magic=SMAGIC)))            # 31 other magic (SMAGIC), new conversation
    main.add(t2.s(msg(2, b'x' * 600, magic=SMAGIC)))                        # 32 reply with a longer body
    main.add(t2.c(b'follow-up without magic'))                              # 33 continuation
    t3 = Tcp(52002, 55125)
    main.add(t3.c(b'no magic at all, so nothing is decoded as TUXEDO'))     # 34 first segment without the magic: plain TCP
    main.write(os.path.join(out, 'tuxedo-coverage.pcap'))
    bad = Pcap()
    t4 = Tcp(52003, 55126)
    bad.add(t4.c(struct.pack('>I', MAGIC)))                                 # 1 four octets: only the magic, not recognised
    bad.add(t4.c(struct.pack('>I', MAGIC) + b'\0\0\0'))                     # 2 seven octets with the magic
    bad.add(t4.c(msg(5)))                                                   # 3 a good message sets the conversation
    bad.add(t4.s(b'\x91\x03\x98'))                                          # 4 three octets in the conversation
    bad.add(t4.c(b''.join([b'x'] * 7)))                                     # 5 seven octets in the conversation
    bad.add(t4.s(msg(2)), snap=14 + 20 + 20 + 6)                            # 6 captured length 6 of 8 (the heuristic needs 8)
    bad.write(os.path.join(out, 'tuxedo-coverage-malformed.pcap'))
    print('main', len(main.frames), 'malformed', len(bad.frames))


if __name__ == '__main__':
    build(sys.argv[1] if len(sys.argv) > 1 else '.')
