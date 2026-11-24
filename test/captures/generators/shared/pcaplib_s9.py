# Shared helper module for the capture generators in test/captures/generators
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
import struct


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ip4(s):
    return bytes(map(int, s.split('.')))


ETH_C = b'\x02\x00\x00\x00\x00\x01'
ETH_S = b'\x02\x00\x00\x00\x00\x02'


def tcp_pkt(src, dst, sport, dport, seq, ack, payload, flags=0x18, ipid=1):
    opts = b'\x02\x04\x05\xb4' if flags & 2 else b''   # MSS on SYN (no scanner warning)
    tcp = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts
    ph = ip4(src) + ip4(dst) + struct.pack('!BBH', 0, 6, len(tcp) + len(payload))
    c = csum(ph + tcp + payload)
    tcp = tcp[:16] + struct.pack('!H', c) + tcp[18:]
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp) + len(payload), ipid, 0, 64, 6, 0,
                     ip4(src), ip4(dst))
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    eth = (ETH_S + ETH_C if sport < 1024 or sport == 21001 or sport == 1883 else ETH_C + ETH_S) + b'\x08\x00'
    return eth + ip + tcp + payload


def udp_pkt(src, dst, sport, dport, payload, ipid=1):
    udp = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), ipid, 0, 64, 17, 0, ip4(src), ip4(dst))
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    eth = ETH_S + ETH_C + b'\x08\x00'
    return eth + ip + udp


class Stream:
    """One TCP connection; tracks sequence numbers."""
    def __init__(self, client, cport, server, sport, cseq=1000, sseq=5000):
        self.c, self.cp, self.s, self.sp = client, cport, server, sport
        self.cseq, self.sseq = cseq, sseq
        self.pkts = []

    def hs(self):
        self.pkts.append(tcp_pkt(self.c, self.s, self.cp, self.sp, self.cseq, 0, b'', 0x02))
        self.cseq += 1
        self.pkts.append(tcp_pkt(self.s, self.c, self.sp, self.cp, self.sseq, self.cseq, b'', 0x12))
        self.sseq += 1
        self.pkts.append(tcp_pkt(self.c, self.s, self.cp, self.sp, self.cseq, self.sseq, b'', 0x10))

    def send(self, data):
        self.pkts.append(tcp_pkt(self.c, self.s, self.cp, self.sp, self.cseq, self.sseq, data))
        self.cseq += len(data)

    def recv(self, data):
        self.pkts.append(tcp_pkt(self.s, self.c, self.sp, self.cp, self.sseq, self.cseq, data))
        self.sseq += len(data)


def write_pcap(path, pkts, linktype=1):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, p in enumerate(pkts):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
            f.write(p)
