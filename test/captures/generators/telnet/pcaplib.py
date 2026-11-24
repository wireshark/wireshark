# Helper module for the telnet capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Helper for group s14 generators: Ethernet/IPv4/TCP or UDP pcap writer.
import struct

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def ip4(src, dst, proto, payload):
    hdr = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0,
                      bytes(src), bytes(dst))
    hdr = hdr[:10] + struct.pack('!H', csum(hdr)) + hdr[12:]
    return hdr + payload

def eth(payload, etype=0x0800, src=1, dst=2):
    return bytes([2, 0, 0, 0, 0, dst, 2, 0, 0, 0, 0, src]) + struct.pack('!H', etype) + payload

SRC = [192, 0, 2, 1]
DST = [192, 0, 2, 2]

def tcp_pkt(sport, dport, seq, payload, src=SRC, dst=DST, flags=0x18):
    t = struct.pack('!HHIIBBHHH', sport, dport, seq, 1, 0x50, flags, 65535, 0, 0)
    return eth(ip4(src, dst, 6, t + payload))

def udp_pkt(sport, dport, payload, src=SRC, dst=DST):
    u = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0)
    return eth(ip4(src, dst, 17, u + payload))

def write_pcap(name, pkts, linktype=1):
    with open(name, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, p in enumerate(pkts):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
            f.write(p)

class TcpFlow:
    """Simple one-direction-at-a-time TCP flow with correct sequence numbers."""
    def __init__(self, cport, sport, src=SRC, dst=DST):
        self.c, self.s, self.src, self.dst = cport, sport, src, dst
        self.cseq, self.sseq = 1000, 5000
    def c2s(self, data):
        p = tcp_pkt(self.c, self.s, self.cseq, data, self.src, self.dst)
        self.cseq += len(data)
        return p
    def s2c(self, data):
        p = tcp_pkt(self.s, self.c, self.sseq, data, self.dst, self.src)
        self.sseq += len(data)
        return p

def exported_pdu(dissector_name, payload):
    # EXP_PDU_TAG_DISSECTOR_NAME (12), end of options (0)
    n = dissector_name.encode()
    pad = (-len(n)) % 4
    tags = struct.pack('!HH', 12, len(n)) + n + b'\0' * pad + struct.pack('!HH', 0, 0)
    return tags + payload
