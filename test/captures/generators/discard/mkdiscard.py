#!/usr/bin/env python3
# Generates test/captures/discard_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the Discard dissector
(packet-discard.c, RFC 863).

Discard is registered on UDP and TCP port 9. Over UDP the Wake On LAN
dissector is tried first (it is commonly sent to port 9), so the
capture holds both a WOL magic packet and plain discard datagrams.
Every packet is built from scratch with struct; no captured traffic is
used. The frames are also the reproducer frames of
discard_prefs.py (empty, binary, text and truncated
payloads).

Usage: mkdiscard.py <output directory>

Writes:
  discard-coverage.pcap  UDP and TCP discard data (empty, binary, text,
                         256 octets), a WOL magic packet to UDP port 9,
                         IPv4 and IPv6, and a datagram cut short by the
                         capture length (snaplen) that shows
                         [Packet size limited during capture]
"""

import os
import struct
import sys

MAC_A = bytes.fromhex('020000000001')
MAC_B = bytes.fromhex('020000000002')
V4_A = bytes([192, 0, 2, 1])
V4_B = bytes([192, 0, 2, 2])
V6_A = bytes.fromhex('20010db8000000000000000000000001')
V6_B = bytes.fromhex('20010db8000000000000000000000002')


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def eth(payload, ethertype):
    return MAC_B + MAC_A + struct.pack('!H', ethertype) + payload


def ipv4(proto, l4):
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(l4), 1, 0x4000, 64,
                     proto, 0, V4_A, V4_B)
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    return eth(ip + l4, 0x0800)


def udp4(payload, sport, dport):
    ulen = 8 + len(payload)
    udp = struct.pack('!HHHH', sport, dport, ulen, 0) + payload
    pseudo = V4_A + V4_B + struct.pack('!xBH', 17, ulen)
    udp = udp[:6] + struct.pack('!H', csum(pseudo + udp) or 0xffff) + udp[8:]
    return ipv4(17, udp)


def udp6(payload, sport, dport):
    ulen = 8 + len(payload)
    udp = struct.pack('!HHHH', sport, dport, ulen, 0) + payload
    pseudo = V6_A + V6_B + struct.pack('!IxxxB', ulen, 17)
    udp = udp[:6] + struct.pack('!H', csum(pseudo + udp) or 0xffff) + udp[8:]
    ip = struct.pack('!IHBB', 0x60000000, ulen, 17, 64) + V6_A + V6_B
    return eth(ip + udp, 0x86dd)


class Tcp:
    """One TCP connection from A:sport to B:9 over IPv4."""
    def __init__(self, sport, dport=9):
        self.sport, self.dport = sport, dport
        self.seq, self.ack = 1000, 5000

    def seg(self, payload, flags, to_server=True):
        if to_server:
            sp, dp, seq, ack, src, dst = (self.sport, self.dport, self.seq,
                                          self.ack, V4_A, V4_B)
        else:
            sp, dp, seq, ack, src, dst = (self.dport, self.sport, self.ack,
                                          self.seq, V4_B, V4_A)
        tcp = struct.pack('!HHIIBBHHH', sp, dp, seq, ack if flags & 0x10 else 0,
                          5 << 4, flags, 65535, 0, 0) + payload
        pseudo = src + dst + struct.pack('!xBH', 6, len(tcp))
        tcp = tcp[:16] + struct.pack('!H', csum(pseudo + tcp)) + tcp[18:]
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), 1, 0x4000,
                         64, 6, 0, src, dst)
        ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
        ip += tcp
        if not to_server:
            fr = MAC_A + MAC_B + b'\x08\x00' + ip
        else:
            fr = eth(ip, 0x0800)
        adv = len(payload) + (1 if flags & 0x03 else 0)
        if to_server:
            self.seq += adv
        else:
            self.ack += adv
        return fr


BINARY = b'\x00\xff\x80hello\x00world'
TEXT = b'The quick brown fox jumps over the lazy dog'


def frames():
    out = []            # (frame, caplen or None)
    # 1-4: UDP over IPv6 and IPv4: empty, binary, text, 256 octets
    out.append((udp6(b'', 40000, 9), None))
    out.append((udp6(BINARY, 40000, 9), None))
    out.append((udp4(TEXT, 40002, 9), None))
    out.append((udp4(bytes(range(256)), 40002, 9), None))
    # 5: Wake On LAN magic packet to UDP port 9 (WOL is tried first)
    out.append((udp4(b'\xff' * 6 + bytes.fromhex('020000000099') * 16, 40003, 9), None))
    # 6-8: TCP to port 9 (no handshake, so there are no TCP expert
    # infos): binary, text, 256 octets
    t = Tcp(40001)
    out.append((t.seg(BINARY, 0x18), None))
    out.append((t.seg(TEXT, 0x18), None))
    out.append((t.seg(bytes(range(256)), 0x18), None))
    # 9: UDP datagram of 200 octets captured with only 100 octets
    out.append((udp6(b'A' * 200, 40000, 9), 100))
    return out


def pcap(path, recs):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, (fr, cap) in enumerate(recs):
            c = len(fr) if cap is None else cap
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, c, len(fr)))
            f.write(fr[:c])


def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcap(os.path.join(outdir, 'discard-coverage.pcap'), frames())


if __name__ == '__main__':
    main()
