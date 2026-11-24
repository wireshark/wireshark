# Helper module for the http2 capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Tiny pcap writer for group g7 reproducers (synthetic addresses only)."""
import struct

CLI = (bytes([192, 0, 2, 1]), 40000)
SRV = (bytes([192, 0, 2, 2]), 80)


def _csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


class TcpFlow:
    def __init__(self, cport=40000, sport=80):
        self.c = (CLI[0], cport)
        self.s = (SRV[0], sport)
        self.seq = {0: 1000, 1: 5000}
        self.pkts = []

    def _pkt(self, d, flags, payload):
        src, dst = (self.c, self.s) if d == 0 else (self.s, self.c)
        seq = self.seq[d]
        ack = self.seq[1 - d] if flags != 0x02 else 0
        tcp = struct.pack('!HHIIBBHHH', src[1], dst[1], seq, ack, 5 << 4,
                          flags, 65535, 0, 0)
        ph = src[0] + dst[0] + struct.pack('!BBH', 0, 6, len(tcp) + len(payload))
        cs = _csum(ph + tcp + payload)
        tcp = tcp[:16] + struct.pack('!H', cs) + tcp[18:]
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp) + len(payload),
                         1, 0, 64, 6, 0, src[0], dst[0])
        ip = ip[:10] + struct.pack('!H', _csum(ip)) + ip[12:]
        mac_c = b'\x02\x00\x00\x00\x00\x01'
        mac_s = b'\x02\x00\x00\x00\x00\x02'
        eth = (mac_s + mac_c if d == 0 else mac_c + mac_s) + b'\x08\x00'
        self.pkts.append(eth + ip + tcp + payload)
        n = len(payload)
        if flags & 0x03:
            n += 1
        self.seq[d] = (seq + n) & 0xffffffff

    def handshake(self):
        self._pkt(0, 0x02, b'')
        self._pkt(1, 0x12, b'')
        self._pkt(0, 0x10, b'')

    def send(self, d, payload):
        self._pkt(d, 0x18, payload)

    def write(self, fn):
        write_pcap(fn, self.pkts)


def write_pcap(fn, pkts, linktype=1):
    with open(fn, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, p in enumerate(pkts):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
            f.write(p)
