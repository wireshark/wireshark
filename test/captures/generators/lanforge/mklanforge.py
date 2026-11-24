#!/usr/bin/env python3
# Generates test/captures/lanforge_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the LANforge dissector
(packet-lanforge.c): the LANforge traffic generator header, found by the
heuristic dissectors on UDP and TCP (any port). Every packet is built
with struct; nothing comes from a real network.

Usage: mklanforge.py <output directory>

Writes:
  lanforge-coverage.pcap            UDP and TCP packets with the 28 octet
                                    header, with and without random data
  lanforge-coverage-malformed.pcap  packets the heuristic rejects (too
                                    short, wrong magic)
"""

import os
import struct
import sys

MAC_A = bytes.fromhex('020000000001')
MAC_B = bytes.fromhex('020000000002')
IP_A = bytes([192, 0, 2, 1])
IP_B = bytes([192, 0, 2, 2])


def pcap(path, frames, linktype=1):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)


def csum(data):
    if len(data) & 1:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def ipv4(proto, payload, src=IP_A, dst=IP_B, ident=1):
    hdr = struct.pack('>BBHHHBBH', 0x45, 0, 20 + len(payload), ident, 0, 64, proto, 0) + src + dst
    hdr = hdr[:10] + struct.pack('>H', csum(hdr)) + hdr[12:]
    return hdr + payload


def l4_sum(proto, src, dst, seg):
    ph = src + dst + struct.pack('>BBH', 0, proto, len(seg))
    return csum(ph + seg)


def udp_frame(sport, dport, payload, to_b=True, ident=1):
    src, dst = (IP_A, IP_B) if to_b else (IP_B, IP_A)
    seg = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    c = l4_sum(17, src, dst, seg) or 0xffff
    seg = seg[:6] + struct.pack('>H', c) + seg[8:]
    macs = (MAC_B, MAC_A) if to_b else (MAC_A, MAC_B)
    return macs[0] + macs[1] + b'\x08\x00' + ipv4(17, seg, src, dst, ident)


def tcp_frame(sport, dport, seq, ack, flags, payload=b'', to_b=True, ident=1):
    src, dst = (IP_A, IP_B) if to_b else (IP_B, IP_A)
    seg = struct.pack('>HHIIBBHHH', sport, dport, seq & 0xffffffff, ack & 0xffffffff,
                      0x50, flags, 8192, 0, 0) + payload
    seg = seg[:16] + struct.pack('>H', l4_sum(6, src, dst, seg)) + seg[18:]
    macs = (MAC_B, MAC_A) if to_b else (MAC_A, MAC_B)
    return macs[0] + macs[1] + b'\x08\x00' + ipv4(6, seg, src, dst, ident)


class TcpFlow:
    """One TCP connection; data() returns frames with correct seq/ack."""

    def __init__(self, cport, sport, isn_c=1000, isn_s=5000):
        self.c, self.s = cport, sport
        self.seq_c, self.seq_s = isn_c, isn_s
        self.n = 0

    def _id(self):
        self.n += 1
        return self.n

    def open(self):
        f = [tcp_frame(self.c, self.s, self.seq_c, 0, 0x02, b'', True, self._id())]
        self.seq_c += 1
        f.append(tcp_frame(self.s, self.c, self.seq_s, self.seq_c, 0x12, b'', False, self._id()))
        self.seq_s += 1
        f.append(tcp_frame(self.c, self.s, self.seq_c, self.seq_s, 0x10, b'', True, self._id()))
        return f

    def data(self, payload, from_client=True):
        if from_client:
            fr = tcp_frame(self.c, self.s, self.seq_c, self.seq_s, 0x18, payload, True, self._id())
            self.seq_c += len(payload)
        else:
            fr = tcp_frame(self.s, self.c, self.seq_s, self.seq_c, 0x18, payload, False, self._id())
            self.seq_s += len(payload)
        return fr

    def close(self):
        f = [tcp_frame(self.c, self.s, self.seq_c, self.seq_s, 0x11, b'', True, self._id())]
        self.seq_c += 1
        f.append(tcp_frame(self.s, self.c, self.seq_s, self.seq_c, 0x11, b'', False, self._id()))
        self.seq_s += 1
        f.append(tcp_frame(self.c, self.s, self.seq_c, self.seq_s, 0x10, b'', True, self._id()))
        return f


MAGIC = 0x1a2b3c4d


def lf(seq, src=1, dst=2, pld_len=0, pattern=0, ts=(1700000000, 123456789),
       data=b'', crc=0xdeadbeef, magic=MAGIC):
    return (struct.pack('>IIHHHBB', crc, magic, src, dst, pld_len & 0xffff,
                        pld_len >> 16, pattern)
            + struct.pack('>III', seq, ts[0], ts[1]) + data)


def main_frames():
    F = []
    n = 0
    # UDP, heuristic on any port: small payload length, no extra data
    F.append(udp_frame(4000, 4001, lf(1, 1, 2, 0), True))
    # UDP with random data after the header and a 3 byte payload length
    F.append(udp_frame(4000, 4001, lf(2, 3, 4, 0x01ffee, 0x5a, data=bytes(range(64))), False))
    # different session ids, patterns and timestamps (zero and large)
    F.append(udp_frame(5555, 6666, lf(0xffffffff, 65535, 65535, 0xffffff, 0xff,
                                      ts=(0, 0), data=b'\xaa' * 20), True))
    F.append(udp_frame(5555, 6666, lf(3, 0, 0, 1472, 1, ts=(2000000000, 999999999),
                                      data=b'\x55' * 100), True))
    # IPv4 fragment-free large frame
    F.append(udp_frame(29990, 29991, lf(4, 10, 20, 1000, 2, data=bytes(i & 255 for i in range(900))), False))
    # TCP, heuristic on any port
    t = TcpFlow(41000, 29999)
    F += t.open()
    F.append(t.data(lf(5, 1, 2, 12, 3, data=b'hello world!'), True))
    F.append(t.data(lf(6, 2, 1, 0, 4), False))
    F += t.close()
    return F


def malformed_frames():
    F = []
    # Rejected by the heuristic: shorter than 28 octets, wrong magic
    F.append(udp_frame(4000, 4001, lf(1)[:27], True))
    F.append(udp_frame(4000, 4001, lf(1, magic=0x1a2b3c4e), True))
    # Exactly 28 octets with the right magic is accepted
    F.append(udp_frame(4000, 4001, lf(9), True))
    t = TcpFlow(41001, 29999)
    F += t.open()
    F.append(t.data(lf(1, magic=0x11111111, data=b'x' * 8), True))
    F.append(t.data(lf(1)[:20], True))
    F += t.close()
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcap(os.path.join(out, 'lanforge-coverage.pcap'), main_frames())
    pcap(os.path.join(out, 'lanforge-coverage-malformed.pcap'), malformed_frames())


main()
