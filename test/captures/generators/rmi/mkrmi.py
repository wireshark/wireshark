#!/usr/bin/env python3
# Generates test/captures/rmi_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
import struct
import sys
import os

def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff

def ip4(a): return bytes(int(x) for x in a.split('.'))

def ip_pkt(proto, l4, src, dst, ident=1, ttl=64):
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(l4), ident, 0, ttl, proto, 0, ip4(src), ip4(dst))
    return ip[:10] + struct.pack('>H', csum(ip)) + ip[12:] + l4

ETH = b'\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01'
def eth_wrap(ippkt, etype=0x0800, rev=False):
    mac = ETH[6:] + ETH[:6] if rev else ETH
    return mac + struct.pack('>H', etype) + ippkt

def udp_frame(payload, sport, dport, src='192.0.2.1', dst='192.0.2.2'):
    udp = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    return eth_wrap(ip_pkt(17, udp, src, dst))

class Tcp:
    '''A TCP connection that tracks sequence numbers.'''
    def __init__(self, a, ap, b, bp):
        self.a, self.ap, self.b, self.bp = a, ap, b, bp
        self.seq = {0: 1000, 1: 5000}
    def seg(self, payload, d=0, flags=0x18, advance=True):
        if d == 0: s, sp, t, tp = self.a, self.ap, self.b, self.bp
        else: s, sp, t, tp = self.b, self.bp, self.a, self.ap
        seq, ack = self.seq[d], self.seq[1 - d]
        tcp = struct.pack('>HHIIBBHHH', sp, tp, seq, ack, 0x50, flags, 8192, 0, 0) + payload
        if advance:
            self.seq[d] += len(payload) + (1 if flags & 3 else 0)
        return eth_wrap(ip_pkt(6, tcp, s, t))
    def handshake(self):
        return [self.seg(b'', 0, 0x02), self.seg(b'', 1, 0x12), self.seg(b'', 0, 0x10)]

def write_pcap(name, frames, linktype=1):
    with open(name, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1000 + i, 0, len(fr), len(fr)))
            f.write(fr)

def ser(extra=b''):
    return struct.pack('>HH', 0xaced, 5) + extra

def main():
    out = sys.argv[1]; verbose = '-v' in sys.argv
    A, B = '192.0.2.10', '192.0.2.20'
    f = []
    c = Tcp(A, 40000, B, 1099)
    f += c.handshake()
    # output stream header: StreamProtocol, SingleOp, Multiplex, unknown
    f.append(c.seg(b'JRMI' + struct.pack('>HB', 2, 0x4b), 0))
    # protocol ack with endpoint identifier
    f.append(c.seg(b'\x4e' + struct.pack('>H', 10) + b'192.0.2.20' + struct.pack('>I', 40000), 1))
    # endpoint identifier of the client then a Call with serialization data
    f.append(c.seg(struct.pack('>H', 10) + b'192.0.2.10' + struct.pack('>I', 0), 0))
    f.append(c.seg(b'\x50' + ser(b'\x77\x0f' + bytes(15) + b'\x73\x72\x00\x04Test'), 0))
    # return data
    f.append(c.seg(b'\x51' + ser(b'\x77\x01\x01\x78'), 1))
    # ping and ping ack, dgc ack with a unique identifier
    f.append(c.seg(b'\x52', 0))
    f.append(c.seg(b'\x53', 1))
    f.append(c.seg(b'\x54' + bytes(range(14)), 0))
    # not supported
    f.append(c.seg(b'\x4f', 1))
    # further connections: other protocols, ack with an empty hostname
    for proto, ver in ((0x4c, 2), (0x4d, 2), (0x99, 7)):
        c2 = Tcp(A, 40010 + proto, B, 1099)
        f.append(c2.seg(b'JRMI' + struct.pack('>HB', ver, proto), 0))
    f.append(c2.seg(b'\x4e' + struct.pack('>H', 0) + struct.pack('>I', 1099), 1))
    # a bare serialization stream (starts with 0xaced), a continuation (unknown token)
    f.append(c2.seg(ser(b'\x73\x71\x00\x7e\x00\x00'), 0))
    f.append(c2.seg(b'\x01\x02\x03 continuation data', 0))
    # one and two byte segments: only the first octet is checked
    f.append(c2.seg(b'\x4e' + b'\x00\x01a' + struct.pack('>I', 7), 1))
    f.append(c2.seg(b'\xac', 0))
    # a line feed within the data: the type is derived from the first line only
    f.append(c2.seg(b'JRMI\x00\x02\x4b\nrest of the data', 0))
    write_pcap(os.path.join(out, 'rmi-coverage.pcap'), f)
    mal = []
    c3 = Tcp(A, 41000, B, 1099)
    mal.append(c3.seg(b'JRMI\x00', 0))               # output stream header cut short (type needs 4 bytes: ok)
    mal.append(c3.seg(b'JRMI\x00\x02', 0))           # protocol octet missing
    mal.append(c3.seg(b'\x4e', 1))                    # ack without endpoint id
    mal.append(c3.seg(b'\x4e\x00\x20abc', 1))        # hostname length past the end
    mal.append(c3.seg(b'\x4e\x00\x03abc\x00', 1))    # port missing
    mal.append(c3.seg(b'\x50', 0))                    # call without serialization data
    mal.append(c3.seg(b'\x50\xac\xed', 0))            # serialization header cut short
    mal.append(c3.seg(b'\x51\xac', 1))
    mal.append(c3.seg(b'\xac\xed\x00', 0))            # serialization stream, version cut
    mal.append(c3.seg(b'\x54', 0))                    # dgc ack, no id
    write_pcap(os.path.join(out, 'rmi-coverage-malformed.pcap'), mal)
    if verbose: print('main', len(f), 'malformed', len(mal))

main()
