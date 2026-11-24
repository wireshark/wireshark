#!/usr/bin/env python3
# Generates test/captures/romon_coverage.pcap.gz
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

# ---- pcapng ----
def _blk(btype, body):
    pad = (-len(body)) % 4
    n = 12 + len(body) + pad
    return struct.pack('<II', btype, n) + body + b'\0' * pad + struct.pack('<I', n)

def write_pcapng(name, ifaces, frames):
    '''ifaces: list of linktypes; frames: list of (iface index, data).'''
    out = _blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    for lt in ifaces:
        out += _blk(1, struct.pack('<HHI', lt, 0, 262144))
    for i, (ifc, d) in enumerate(frames):
        ts = 1000 * 1000000 + i * 100000
        out += _blk(6, struct.pack('<IIIII', ifc, ts >> 32, ts & 0xffffffff, len(d), len(d)) + d)
    with open(name, 'wb') as f:
        f.write(out)

def exp_pdu(dissector, payload):
    '''Exported PDU (linktype 252) carrying the named dissector.'''
    n = dissector.encode()
    tag = struct.pack('>HH', 12, (len(n) + 3) // 4 * 4) + n + b'\0' * ((-len(n)) % 4)
    return tag + struct.pack('>HH', 0, 0) + payload

def main():
    out = sys.argv[1]; verbose = '-v' in sys.argv
    f = []
    def add(payload, src=b'\x02\x00\x00\x00\x00\x01', dst=b'\x02\x00\x00\x00\x00\x02'):
        f.append(dst + src + struct.pack('>H', 0x88bf) + payload)
    # RoMON (Mikrotik Router Management Overlay Network) has no public
    # specification; the dissector only marks the payload. Different sizes,
    # a broadcast destination and a minimal frame.
    add(bytes(range(46)))
    add(b'\x01\x02\x03\x04' + bytes(60))
    add(b'\x00' * 46, dst=b'\xff' * 6)
    add(b'\x80' + bytes(range(1, 200)))
    add(b'\x00' * 46, src=b'\x02\x00\x00\x00\x00\x03', dst=b'\x01\x80\xc2\x00\x00\x00')
    write_pcap(os.path.join(out, 'romon-coverage.pcap'), f)
    # one frame whose Ethernet payload is empty (padded to the minimum length by
    # the sender, here left empty): RoMON still shows a (zero length) item
    write_pcap(os.path.join(out, 'romon-coverage-malformed.pcap'), [f[0][:14], f[0][:15]])
    if verbose: print('main', len(f), 'malformed 2')

main()
