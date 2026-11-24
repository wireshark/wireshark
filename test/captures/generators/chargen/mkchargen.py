#!/usr/bin/env python3
# Generates test/captures/chargen_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate a synthetic capture that exercises the Character Generator
Protocol dissector (packet-chargen.c, RFC 864).

Chargen runs on UDP and TCP port 19, both registered by default. A UDP
client sends any datagram and the server answers with a datagram of
characters; over TCP the server sends lines of characters until the
client closes. Every packet is built from scratch with struct; no
captured traffic is used.

Usage: mkchargen.py <output directory>

Writes:
  chargen-coverage.pcap   UDP requests (empty and with data) and replies,
                          a TCP connection with handshake, several
                          segments of the rotating 72 character pattern,
                          a segment with octets outside ASCII, and FIN
"""

import os
import struct
import sys

MAC_C = bytes.fromhex('020000000001')
MAC_S = bytes.fromhex('020000000002')
IP_C = bytes([192, 0, 2, 1])
IP_S = bytes([198, 51, 100, 2])
PORT = 19


def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


def ip_frame(src, dst, proto, l4, ident):
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(l4), ident, 0, 64, proto, 0, src, dst)
    ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
    smac, dmac = (MAC_C, MAC_S) if src == IP_C else (MAC_S, MAC_C)
    return dmac + smac + b'\x08\x00' + ip + l4


def udp_frame(sport, dport, payload, src, dst, ident=1):
    udp = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    pseudo = struct.pack('>4s4sBBH', src, dst, 0, 17, len(udp))
    c = csum(pseudo + udp) or 0xffff
    udp = udp[:6] + struct.pack('>H', c) + udp[8:]
    return ip_frame(src, dst, 17, udp, ident)


def tcp_frame(sport, dport, payload, seq, ack, src, dst, flags=0x18, ident=1):
    # SYNs carry an MSS option (a SYN without options looks like a scanner)
    opts = struct.pack('>BBHBBBB', 2, 4, 1460, 4, 2, 1, 1) if flags & 0x02 else b''
    tcp = struct.pack('>HHIIBBHHH', sport, dport, seq, ack, (5 + len(opts) // 4) << 4, flags,
                      65535, 0, 0) + opts
    pseudo = struct.pack('>4s4sBBH', src, dst, 0, 6, len(tcp) + len(payload))
    c = csum(pseudo + tcp + payload)
    tcp = tcp[:16] + struct.pack('>H', c) + tcp[18:]
    return ip_frame(src, dst, 6, tcp + payload, ident)


class Conn:
    """One TCP connection with a three way handshake."""

    def __init__(self, frames, cport):
        self.f = frames
        self.cport = cport
        self.cseq = 1000
        self.sseq = 5000
        self.add(True, b'', 0x02)
        self.add(False, b'', 0x12)
        self.add(True, b'', 0x10)

    def add(self, from_client, data, flags=0x18):
        if from_client:
            fr = tcp_frame(self.cport, PORT, data, self.cseq, self.sseq if flags != 0x02 else 0,
                           IP_C, IP_S, flags, ident=len(self.f) + 1)
            self.cseq += len(data) + (1 if flags & 0x03 else 0)
        else:
            fr = tcp_frame(PORT, self.cport, data, self.sseq, self.cseq, IP_S, IP_C, flags,
                           ident=len(self.f) + 1)
            self.sseq += len(data) + (1 if flags & 0x03 else 0)
        self.f.append(fr)
        return len(self.f)


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, p in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
            f.write(p)


# The RFC 864 pattern: the 95 printable characters, 72 per line, each
# line starting one character later than the previous one.
PRINTABLE = bytes(range(0x20, 0x7f))


def line(n):
    return bytes(PRINTABLE[(n + i) % len(PRINTABLE)] for i in range(72)) + b'\r\n'


def lines(first, count):
    return b''.join(line(first + i) for i in range(count))


def main_frames():
    F = []
    # 1-2: UDP request with a short text and the one line reply
    F.append(udp_frame(50000, PORT, b'hello\n', IP_C, IP_S, ident=1))
    F.append(udp_frame(PORT, 50000, line(0), IP_S, IP_C, ident=2))
    # 3-4: UDP request with an empty payload (UDP does not hand it to
    # Chargen) and a reply of 512 octets
    F.append(udp_frame(50001, PORT, b'', IP_C, IP_S, ident=3))
    F.append(udp_frame(PORT, 50001, lines(1, 7)[:512], IP_S, IP_C, ident=4))
    # 5-7: TCP handshake
    c = Conn(F, 50002)
    # 8-10: server sends one line, then 10 lines, then 19 lines
    c.add(False, line(0))
    c.add(False, lines(1, 10))
    c.add(False, lines(11, 19))
    # 11: a segment with octets outside ASCII and a NUL (the label stops
    # at the NUL)
    c.add(False, b'chargen \x00\x80\xfe\xff end\r\n')
    # 12: client acknowledges
    c.add(True, b'', 0x10)
    # 13-15: FIN
    c.add(True, b'', 0x11)
    c.add(False, b'', 0x11)
    c.add(True, b'', 0x10)
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'chargen-coverage.pcap'), main_frames())


if __name__ == '__main__':
    main()
