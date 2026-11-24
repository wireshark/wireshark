#!/usr/bin/env python3
# Generates test/captures/oicq_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the OICQ dissector
(packet-oicq.c, the OICQ/QQ instant messaging protocol, UDP port 8000).

An OICQ packet is a flag octet (0x02), a 16 bit version, a 16 bit command,
a 16 bit sequence number, a 32 bit OICQ number and variable data. Every
packet is built with struct; the payloads are made-up strings and bytes,
not captured traffic and not encrypted data.

Usage: mkoicq.py <output directory>

Writes:
  oicq-coverage.pcap            every command value, both directions, data
                                of several kinds and sizes, packets that the
                                heuristic rejects (flag or command unknown)
  oicq-coverage-malformed.pcap  packets cut short (exceptions with a tree)
"""
import os
import struct
import sys


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff

MAC_A = bytes.fromhex('020000000001')
MAC_B = bytes.fromhex('020000000002')
IPA = bytes((192, 0, 2, 1))
IPB = bytes((192, 0, 2, 2))

def ip4(proto, payload, src=IPA, dst=IPB, ident=1):
    h = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0, 64, proto, 0, src, dst)
    return h[:10] + struct.pack('>H', csum(h)) + h[12:] + payload

def eth(payload, et=0x0800, src=MAC_A, dst=MAC_B):
    return dst + src + struct.pack('>H', et) + payload

def udp_frame(payload, sport, dport, src=IPA, dst=IPB):
    u = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    ph = src + dst + struct.pack('>BBH', 0, 17, len(u))
    u = u[:6] + struct.pack('>H', csum(ph + u) or 0xffff) + u[8:]
    return eth(ip4(17, u, src, dst))

class Tcp:
    """Minimal TCP flow: handshake, then data segments in both directions."""
    def __init__(self, sport, dport, cseq=1000, sseq=70000):
        self.sport, self.dport = sport, dport
        self.cseq, self.sseq = cseq, sseq
        self.frames = []

    def _seg(self, to_server, payload, flags):
        if to_server:
            src, dst, sp, dp, seq, ack = IPA, IPB, self.sport, self.dport, self.cseq, self.sseq
        else:
            src, dst, sp, dp, seq, ack = IPB, IPA, self.dport, self.sport, self.sseq, self.cseq
        t = struct.pack('>HHIIBBHHH', sp, dp, seq, ack if flags & 0x10 else 0, 0x50, flags, 65535, 0, 0) + payload
        ph = src + dst + struct.pack('>BBH', 0, 6, len(t))
        t = t[:16] + struct.pack('>H', csum(ph + t)) + t[18:]
        mac_s, mac_d = (MAC_A, MAC_B) if to_server else (MAC_B, MAC_A)
        self.frames.append(eth(ip4(6, t, src, dst), src=mac_s, dst=mac_d))
        adv = len(payload) + (1 if flags & 3 else 0)
        if to_server:
            self.cseq += adv
        else:
            self.sseq += adv

    def handshake(self):
        self._seg(True, b'', 0x02)
        self._seg(False, b'', 0x12)
        self._seg(True, b'', 0x10)

    def send(self, to_server, payload):
        self._seg(to_server, payload, 0x18)
        self._seg(not to_server, b'', 0x10)

def write_pcap(path, frames, linktype=1, snap=262144):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, snap, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)


COMMANDS = [0x0001, 0x0002, 0x0004, 0x0005, 0x0006, 0x0009, 0x000a, 0x000b, 0x000d,
            0x0012, 0x0016, 0x0017, 0x0018, 0x001a, 0x001c, 0x001d, 0x0021, 0x0022,
            0x0026, 0x0027, 0x0029, 0x0030, 0x0031, 0x003c, 0x003d, 0x003e, 0x0058,
            0x005c, 0x0062, 0x0065, 0x0067, 0x0080, 0x0081, 0x00b5, 0x03f7]


def oicq(cmd, seq, qq, data=b'', flag=2, ver=0x3b21):
    return struct.pack('>BHHHI', flag, ver, cmd, seq, qq) + data


def main_capture(path):
    frames = []
    for i, cmd in enumerate(COMMANDS):
        client = i % 2 == 0
        data = (b'hello world %d\x03' % i) if i % 3 else (bytes(((i * 7 + k) % 0x7e) + 1 for k in range(20)) + b'\x03')
        pkt = oicq(cmd, i + 1, 10000 + i, data)
        if client:
            frames.append(udp_frame(pkt, 4000 + i, 8000))
        else:
            frames.append(udp_frame(pkt, 8000, 4000 + i))
    # one octet of data, a long message
    frames.append(udp_frame(oicq(0x0002, 101, 12345, b'\x03'), 4100, 8000))
    frames.append(udp_frame(oicq(0x0016, 102, 12345, b'long message ' * 60 + b'\x03'), 4100, 8000))
    # other version, high bit characters in the data
    frames.append(udp_frame(oicq(0x0016, 103, 0xffffffff, bytes(range(1, 255)), ver=0x0000), 4100, 8000))
    # rejected by the heuristic: unknown flag, unknown command (these stay plain UDP)
    frames.append(udp_frame(oicq(0x0002, 104, 1, b'abc', flag=0x03), 4100, 8000))
    frames.append(udp_frame(oicq(0x0003, 105, 1, b'abc'), 4100, 8000))
    frames.append(udp_frame(oicq(0xffff, 106, 1, b'abc'), 4100, 8000))
    write_pcap(path, frames)


def malformed_capture(path):
    frames = []
    pkt = oicq(0x0002, 1, 99, b'abc')
    for cut in (5, 6, 7, 8, 9, 10, 11):             # cut inside the header (command still readable)
        frames.append(udp_frame(pkt[:cut], 4000, 8000))
    frames.append(udp_frame(pkt[:9], 4000, 8000))    # header only, no data: the data item cannot be added
    frames.append(udp_frame(pkt[:3], 4000, 8000))    # too short to read the command
    frames.append(udp_frame(b'\x02', 4000, 8000))
    write_pcap(path, frames)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    os.makedirs(out, exist_ok=True)
    main_capture(os.path.join(out, 'oicq-coverage.pcap'))
    malformed_capture(os.path.join(out, 'oicq-coverage-malformed.pcap'))


if __name__ == '__main__':
    main()
