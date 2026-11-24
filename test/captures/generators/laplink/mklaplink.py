#!/usr/bin/env python3
# Generates test/captures/laplink_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the Laplink dissector
(packet-laplink.c): name solicitation and reply over UDP port 1547 and
length-prefixed messages over TCP port 1547. Every packet is built with
struct; nothing comes from a real network.

Usage: mklaplink.py <output directory>

Writes:
  laplink-coverage.pcap            UDP name solicitation/reply, every TCP
                                   ident, an unknown ident, two PDUs in one
                                   segment, PDUs split over segments
  laplink-coverage-malformed.pcap  UDP packets the dissector rejects, a TCP
                                   length past the end of the data
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


def lp_tcp(ident, data=b'', length=None):
    return struct.pack('>IH', ident, len(data) if length is None else length) + data


def lp_udp(ident, name):
    return struct.pack('>I', ident) + name


def main_frames():
    F = []
    # 1-2: UDP name solicitation and reply
    F.append(udp_frame(1547, 1547, lp_udp(0x0f010000, b'LAPTOP-A\0'), True))
    F.append(udp_frame(1547, 1547, lp_udp(0xf0000200, b'DESKTOP-B\0'), False))
    # TCP session
    t = TcpFlow(40000, 1547)
    F += t.open()
    idents = [0xff08c000, 0xff08c200, 0xff0bc000, 0xff0bc200, 0xff10c000,
              0xff10c200, 0xff11c000, 0xff11c200, 0xff13c000, 0xff13c200,
              0xff14c000]
    for i, ident in enumerate(idents):
        F.append(t.data(lp_tcp(ident, bytes(range(i, i + 4 + i))), i % 2 == 0))
    # unknown ident ("TCP TBA"), empty data
    F.append(t.data(lp_tcp(0x12345678, b''), True))
    # two PDUs in one segment
    F.append(t.data(lp_tcp(0xff11c000, b'abc') + lp_tcp(0xff14c000, b'defgh'), False))
    # one PDU split over two segments (reassembly)
    pdu = lp_tcp(0xff11c200, bytes(range(40)))
    F.append(t.data(pdu[:20], True))
    F.append(t.data(pdu[20:], True))
    # PDU header split inside the length field
    pdu = lp_tcp(0xff10c000, b'0123456789')
    F.append(t.data(pdu[:5], False))
    F.append(t.data(pdu[5:], False))
    F += t.close()
    return F


def malformed_frames():
    F = []
    # UDP: unknown ident (not claimed), shorter than 4 bytes
    F.append(udp_frame(1547, 1547, lp_udp(0x11223344, b'X\0'), True))
    F.append(udp_frame(1547, 1547, b'\x0f\x01', True))
    # UDP: name without terminating NUL
    F.append(udp_frame(1547, 1547, lp_udp(0x0f010000, b'NONUL'), True))
    # TCP: length field longer than the data, too short for the header
    t = TcpFlow(40001, 1547)
    F += t.open()
    F.append(t.data(lp_tcp(0xff11c000, b'abc', 100), True))
    F += t.close()
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcap(os.path.join(out, 'laplink-coverage.pcap'), main_frames())
    pcap(os.path.join(out, 'laplink-coverage-malformed.pcap'), malformed_frames())


main()
