#!/usr/bin/env python3
# Generates test/captures/ncs_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# NCS (packet-ncs.c) synthetic capture generator. Python struct only; all addresses are made up.
import struct
import sys
import os
import gzip

def _csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def ipv4(src, dst, proto, payload, ident=1):
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0, 64, proto, 0,
                     bytes(src), bytes(dst))
    ip = ip[:10] + struct.pack('!H', _csum(ip)) + ip[12:]
    return ip + payload

def eth(payload, src=2, dst=1, etype=0x0800):
    return bytes([2, 0, 0, 0, 0, dst]) + bytes([2, 0, 0, 0, 0, src]) + struct.pack('!H', etype) + payload

def udp(src, dst, sport, dport, payload, srcmac=2, dstmac=1):
    u = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    return eth(ipv4(src, dst, 17, u), srcmac, dstmac)

def tcp(src, dst, sport, dport, seq, ack, payload, flags=0x18, srcmac=2, dstmac=1):
    opts = b'\x02\x04\x05\xb4' if flags & 0x02 else b''   # MSS on SYN and SYN-ACK
    t = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts + payload
    return eth(ipv4(src, dst, 6, t), srcmac, dstmac)

A = [10, 0, 0, 1]
B = [10, 0, 0, 2]

class Stream:
    '''One TCP connection: A (client, MAC 2) to B (server, MAC 1).'''
    def __init__(self, frames, cport, sport, handshake=True):
        self.f = frames
        self.cp, self.sp = cport, sport
        self.cs, self.ss = 1000, 5000
        if handshake:
            frames.append(tcp(A, B, cport, sport, self.cs, 0, b'', 0x02))
            frames.append(tcp(B, A, sport, cport, self.ss, self.cs + 1, b'', 0x12, 1, 2))
            self.cs += 1; self.ss += 1
            frames.append(tcp(A, B, cport, sport, self.cs, self.ss, b'', 0x10))
    def c(self, data):
        self.f.append(tcp(A, B, self.cp, self.sp, self.cs, self.ss, data, 0x18))
        self.cs += len(data)
    def s(self, data):
        self.f.append(tcp(B, A, self.sp, self.cp, self.ss, self.cs, data, 0x18, 1, 2))
        self.ss += len(data)

def write_pcap(name, frames, linktype=1):
    with open(name, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, fr in enumerate(frames):
            t = 1700000000 + i // 1000
            f.write(struct.pack('<IIII', t, (i % 1000) * 1000, len(fr), len(fr)))
            f.write(fr)

def gz(name):
    with open(name, 'rb') as f, gzip.GzipFile(name + '.gz', 'wb', mtime=0) as g:
        g.write(f.read())
# ---- Novell Cluster Services heartbeat: IP protocol 224 (IPv4) or next
# header 224 (IPv6). Payload: 4 bytes (not decoded), panning id, incarnation.
def ipv6(src, dst, nxt, payload):
    return struct.pack('!IHBB', 0x60000000, len(payload), nxt, 64) + src + dst + payload

def hb(pan, inc, head=0, extra=b''):
    return struct.pack('!III', head, pan, inc) + extra

def ip4frame(payload, src=A, dst=B, mac=(2, 1), ident=1):
    return eth(ipv4(src, dst, 224, payload, ident), mac[0], mac[1])

def ip6frame(payload, mac=(2, 1)):
    s = bytes.fromhex('fd000000000000000000000000000001')
    d = bytes.fromhex('fd000000000000000000000000000002')
    return eth(ipv6(s, d, 224, payload), mac[0], mac[1], 0x86dd)

main = []
main.append(ip4frame(hb(0x00000001, 0x00000001)))
main.append(ip4frame(hb(0x00000002, 0x00000001), A, [10, 0, 0, 3], ident=2))
main.append(ip4frame(hb(0x00000001, 0x00000002), ident=3))
main.append(ip4frame(hb(0xdeadbeef, 0xffffffff, 0x01020304), ident=4))
main.append(ip4frame(hb(0, 0), ident=5))
# heartbeat to the multicast group 239.1.2.3 and a broadcast
main.append(eth(ipv4(A, [239, 1, 2, 3], 224, hb(0x11, 0x22), 6), 2, 1))
main.append(eth(ipv4(A, [255, 255, 255, 255], 224, hb(0x33, 0x44), 7), 2, 1))
# longer payload: bytes after the incarnation are not decoded
main.append(ip4frame(hb(0x55, 0x66, 0, b'extra data after the heartbeat' * 4), ident=8))
main.append(ip6frame(hb(0x00000007, 0x00000009)))
main.append(ip6frame(hb(0x0a0b0c0d, 0x01020304, 0, b'ipv6 extra')))

frames = []
# malformed: payload shorter than the 12 bytes the dissector reads
frames.append(ip4frame(hb(1, 2)[:11], ident=20))
frames.append(ip4frame(hb(1, 2)[:8], ident=21))
frames.append(ip4frame(hb(1, 2)[:5], ident=22))
frames.append(ip4frame(b'', ident=23))
frames.append(ip6frame(hb(1, 2)[:9]))

if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'ncs-coverage.pcap'), main)
    gz(os.path.join(out, 'ncs-coverage.pcap'))
    os.rename(os.path.join(out, 'ncs-coverage.pcap.gz'), os.path.join(out, 'ncs_coverage.pcap.gz'))
    write_pcap(os.path.join(out, 'ncs-coverage-malformed.pcap'), frames)
