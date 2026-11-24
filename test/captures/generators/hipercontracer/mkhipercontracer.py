#!/usr/bin/env python3
# Generates test/captures/hipercontracer_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Writes the HiPerConTracer coverage captures.
Usage: mkhipercontracer.py <outdir> [-v]
All packets are built with struct; addresses are from 192.0.2.0/24 and
2001:db8::/32."""
import struct
import sys
import os

MAC_A = b"\x02\x00\x00\x00\x00\x01"
MAC_B = b"\x02\x00\x00\x00\x00\x02"
IP_A = bytes([192, 0, 2, 1])
IP_B = bytes([192, 0, 2, 2])
IP6_A = bytes.fromhex("20010db8000000000000000000000001")
IP6_B = bytes.fromhex("20010db8000000000000000000000002")
EPOCH_OFFSET_NS = 212803200000000000   # 1976-09-29 to 1970-01-01, in ns


def csum(b):
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def hdr(magic, ttl, rnd, tweak, ts, total=64):
    """HiPerConTracer header: 16 octets, then zeros up to 64 octets, then
    (beyond 64) octets equal to their offset."""
    b = struct.pack("!IBBHQ", magic, ttl, rnd, tweak, ts)
    b += b"\0" * (min(total, 64) - 16)
    for off in range(64, total):
        b += bytes([off & 0xff])
    return b[:total] if total >= 16 else b


def ts_ns(unix_s, ns=0):
    """2.x time stamp: nanoseconds since 1976-09-29."""
    return unix_s * 1000000000 + ns - EPOCH_OFFSET_NS


def ts_us(unix_s, us=0):
    """1.x time stamp: microseconds since 1976-09-29."""
    return (unix_s * 1000000 + us) - EPOCH_OFFSET_NS // 1000


class Cap:
    def __init__(self):
        self.frames = []

    def n(self):
        return len(self.frames) + 1

    def ip4(self, proto, payload, src=IP_A, dst=IP_B, ttl=64):
        iph = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, 0,
                          ttl, proto, 0, src, dst)
        iph = iph[:10] + struct.pack("!H", csum(iph)) + iph[12:]
        self.frames.append(MAC_B + MAC_A + b"\x08\x00" + iph + payload)

    def ip6(self, nxt, payload, src=IP6_A, dst=IP6_B, hlim=64):
        iph = struct.pack("!IHBB16s16s", 0x60000000, len(payload), nxt, hlim, src, dst)
        self.frames.append(MAC_B + MAC_A + b"\x86\xdd" + iph + payload)

    def icmp_echo(self, data, reply=False, ident=0x1234, seq=1):
        m = struct.pack("!BBHHH", 0 if reply else 8, 0, 0, ident, seq) + data
        m = m[:2] + struct.pack("!H", csum(m)) + m[4:]
        if reply:
            self.ip4(1, m, IP_B, IP_A)
        else:
            self.ip4(1, m)

    def icmp6_echo(self, data, reply=False, ident=0x1234, seq=1):
        t = 129 if reply else 128
        src, dst = (IP6_B, IP6_A) if reply else (IP6_A, IP6_B)
        m = struct.pack("!BBHHH", t, 0, 0, ident, seq) + data
        pseudo = src + dst + struct.pack("!IBBBB", len(m), 0, 0, 0, 58)
        m = m[:2] + struct.pack("!H", csum(pseudo + m)) + m[4:]
        self.ip6(58, m, src, dst)

    def udp(self, data, sport=40000, dport=40001, v6=False):
        u = struct.pack("!HHHH", sport, dport, 8 + len(data), 0) + data
        if v6:
            pseudo = IP6_A + IP6_B + struct.pack("!IBBBB", len(u), 0, 0, 0, 17)
            u = u[:6] + struct.pack("!H", csum(pseudo + u) or 0xffff) + u[8:]
            self.ip6(17, u)
        else:
            self.ip4(17, u)

    def tcp(self, data, sport=40000, dport=40001, seq=1000, ack=1, flags=0x18,
            reverse=False):
        src, dst = (IP_B, IP_A) if reverse else (IP_A, IP_B)
        opts = b"\x02\x04\x05\xb4" if flags & 2 else b""
        if reverse:
            sport, dport = dport, sport
        t = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 0x50 + len(opts) * 4,
                        flags, 8192, 0, 0) + opts + data
        pseudo = src + dst + struct.pack("!BBH", 0, 6, len(t))
        t = t[:16] + struct.pack("!H", csum(pseudo + t)) + t[18:]
        self.ip4(6, t, src, dst)

    def write(self, path):
        with open(path, "wb") as f:
            f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            for i, fr in enumerate(self.frames):
                f.write(struct.pack("<IIII", 1000 + i, 0, len(fr), len(fr)))
                f.write(fr)


def main(outdir, verbose):
    c = Cap()
    marks = []

    def mark(name):
        marks.append((c.n(), name))

    T2 = ts_ns(1780000000, 123456789)       # 2.x, nanoseconds
    T1 = ts_us(1780000001, 654321)          # 1.x, microseconds
    M = 0x5ca1ab1e

    mark("ICMP echo request/reply, 2.x time stamp, 64 octets")
    c.icmp_echo(hdr(M, 3, 1, 0xbeef, T2))
    c.icmp_echo(hdr(M, 3, 1, 0xbeef, T2), reply=True)
    mark("ICMP, 1.x (microsecond) time stamp")
    c.icmp_echo(hdr(M, 17, 2, 0x1111, T1), seq=2)
    mark("ICMP, lengths 16, 40, 64, 100")
    for ln in (16, 40, 64, 100):
        c.icmp_echo(hdr(M, 5, 0, 0x2222, T2, ln), seq=3)
    mark("ICMP, reproducer of the padding length: zeros up to 80 octets")
    c.icmp_echo(hdr(M, 6, 3, 0x3333, T2, 80)[:64] + b"\0" * 16, seq=4)
    mark("ICMP, rejected: TTL 0, implausible time stamps, non-zero padding")
    c.icmp_echo(hdr(M, 0, 1, 0, T2), seq=5)
    c.icmp_echo(hdr(M, 4, 1, 0, 0), seq=6)             # 1976
    c.icmp_echo(hdr(M, 4, 1, 0, (1 << 62) + (1 << 61)), seq=7)   # beyond 2099
    c.icmp_echo(hdr(M, 4, 1, 0, T2)[:30] + b"\1" + hdr(M, 4, 1, 0, T2)[31:], seq=8)
    c.icmp_echo(hdr(M, 4, 1, 0, T2)[:63] + b"\1", seq=9)
    c.icmp_echo(b"short", seq=10)
    mark("ICMP, rejected: SASL/Kerberos wrap token look-alike")
    sasl = struct.pack("!IBBHQ", 0x00000091, 5, 4, 0x00ff, 0) + b"\0" * 48
    c.icmp_echo(sasl, seq=11)
    mark("ICMPv6 echo request/reply")
    c.icmp6_echo(hdr(M, 8, 4, 0xcafe, T2))
    c.icmp6_echo(hdr(M, 8, 4, 0xcafe, T2), reply=True)
    c.icmp6_echo(hdr(M, 9, 5, 0xcafe, T1, 100), seq=2)
    mark("UDP and TCP (need the heuristics or Decode As)")
    c.udp(hdr(M, 10, 6, 0x0007, T2))
    c.udp(hdr(M, 10, 6, 0x0008, T2, 100), v6=True)
    c.tcp(b"", seq=999, ack=0, flags=0x02)
    c.tcp(b"", seq=5000, ack=1000, flags=0x12, reverse=True)
    c.tcp(b"", seq=1000, ack=5001, flags=0x10)
    c.tcp(hdr(M, 11, 7, 0x0009, T2), seq=1000, ack=5001)
    c.tcp(hdr(M, 11, 7, 0x000a, T2, 90), seq=1064, ack=5001)
    c.udp(b"\0" * 20)                         # zero TTL: rejected
    mark("end")
    main_n = len(c.frames)
    c.write(os.path.join(outdir, "hipercontracer-coverage.pcap"))

    m = Cap()
    # Not HiPerConTracer, or cut short
    m.icmp_echo(hdr(M, 3, 1, 0xbeef, T2)[:60])           # shorter than 64 octets, zeros only
    m.icmp_echo(hdr(M, 3, 1, 0xbeef, T2, 48)[:47])
    m.icmp_echo(hdr(M, 3, 1, 0xbeef, T2)[:15])
    m.write(os.path.join(outdir, "hipercontracer-coverage-malformed.pcap"))
    if verbose:
        for n, name in marks:
            print(n, name)
        print("main frames", main_n)


if __name__ == "__main__":
    main(sys.argv[1], "-v" in sys.argv)
