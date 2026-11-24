#!/usr/bin/env python3
# Generates test/captures/roq_coverage.pcapng.gz
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

def qvarint(v):
    if v < 0x40: return struct.pack('>B', v)
    if v < 0x4000: return struct.pack('>H', 0x4000 | v)
    if v < 0x40000000: return struct.pack('>I', 0x80000000 | v)
    return struct.pack('>Q', 0xC000000000000000 | v)

def rtp(pt=96, seq=1, ts=1000, ssrc=0x11223344, marker=0, payload=b'\x00' * 20):
    return struct.pack('>BBHII', 0x80, (marker << 7) | pt, seq, ts, ssrc) + payload

def rtcp_sr(ssrc=0x11223344):
    return struct.pack('>BBHIIIIII', 0x80, 200, 6, ssrc, 0xe0000000, 0, 1000, 10, 2000)

def rtcp_rr(ssrc=0x11223344):
    return struct.pack('>BBHI', 0x80, 201, 1, ssrc)

def main():
    out = sys.argv[1]; verbose = '-v' in sys.argv
    f = []
    def dg(payload): f.append((0, exp_pdu('roq.datagram', payload)))
    # QUIC DATAGRAM frames: flow identifier (varint), then one RTP or RTCP packet.
    # RoQ over QUIC is only reached after QUIC packet protection is removed; an
    # Exported PDU names the datagram dissector (see README)
    for v in (0, 5, 63, 64, 16383, 16384, 2 ** 30 - 1, 2 ** 30, 2 ** 62 - 1):
        dg(qvarint(v) + rtp(seq=v & 0xffff))
    dg(qvarint(1) + rtp(pt=0, marker=1))        # marker set, payload type 0 (RTP)
    dg(qvarint(2) + rtp(pt=33))                  # MP2T
    dg(qvarint(3) + rtcp_sr())                   # RTCP Sender Report (packet type 200)
    dg(qvarint(3) + rtcp_rr())                   # RTCP Receiver Report (201)
    dg(qvarint(4) + struct.pack('>BBHI', 0x80, 192, 1, 0x11223344))   # lowest RTCP packet type
    dg(qvarint(4) + struct.pack('>BBHI', 0x80, 223, 1, 0x11223344))   # highest RTCP packet type
    dg(qvarint(4) + struct.pack('>BB', 0x80, 191) + b'\0' * 10)  # not RTCP: RTP with PT 63
    dg(qvarint(4) + struct.pack('>BB', 0x80, 224) + b'\0' * 10)  # not RTCP
    # Datagram dissector is also reachable as stream dissector name without QUIC data
    f.append((0, exp_pdu('roq', b'\x00' + rtp())))
    write_pcapng(os.path.join(out, 'roq-coverage.pcapng'), [252], f)
    mal = []
    def mdg(payload): mal.append((0, exp_pdu('roq.datagram', payload)))
    mdg(qvarint(6) + b'\x80')                    # a single octet after the flow id
    mdg(qvarint(6))                              # flow id only, no RTP or RTCP packet
    mdg(b'')                                     # no flow identifier
    mdg(b'\x40')                                 # 2 octet varint, 1 present
    mdg(b'\x80\x00\x01')                         # 4 octet varint, 3 present
    mdg(b'\xc0' + b'\x00' * 6)                   # 8 octet varint, 7 present
    write_pcapng(os.path.join(out, 'roq-coverage-malformed.pcapng'), [252], mal)
    if verbose: print('main', len(f), 'malformed', len(mal))

main()
