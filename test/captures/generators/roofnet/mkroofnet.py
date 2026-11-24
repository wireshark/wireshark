#!/usr/bin/env python3
# Generates test/captures/roofnet_coverage.pcap.gz
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

def a(s): return ip4(s)

def udp_ip(sport=1234, dport=5678, payload=b'roofnet payload', src='10.0.0.1', dst='10.0.0.2'):
    udp = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    return ip_pkt(17, udp, src, dst)

def roofnet(typ, flags, payload=b'', nlinks=None, links=(), datalen=None, ttl=64, nxt=0, seq=7,
            qdst='10.0.0.9', ver=1, skip=b'\0' * 4):
    '''Header (20 octets), links, the 4 octets the dissector skips, payload.
    links: list of (src, fwd, rev, seq, age) and the final destination address.'''
    if nlinks is None: nlinks = len(links)
    if datalen is None: datalen = len(payload)
    hdr = struct.pack('>BBBBHHHH4sI', ver, typ, nlinks, nxt, ttl, 0, flags, datalen, a(qdst), seq)
    body = b''
    for (s, fw, rv, sq, ag) in links:
        body += a(s) + struct.pack('>IIII', fw, rv, sq, ag)
    if links:
        body += b'\0' * 4   # the destination of the last link
    return hdr + body + (skip if not links else b'') + payload

def eth(etype, payload, src=b'\x02\x00\x00\x00\x00\x01', dst=b'\x02\x00\x00\x00\x00\x02'):
    return dst + src + struct.pack('>H', etype) + payload

LINKS = [('10.0.0.1', 100, 90, 5, 1), ('10.0.0.2', 80, 70, 6, 2), ('10.0.0.3', 60, 50, 7, 3)]

def main():
    out = sys.argv[1]; verbose = '-v' in sys.argv
    f = []
    # 1: Query without links and without data: the data offset is past the end of the
    #    frame (reported length remaining < 0): the reproducer of the unsigned fix
    f.append(eth(0x0641, roofnet(1, 0, b'', skip=b'')))
    # 2: Query with three links, no data
    f.append(eth(0x0641, roofnet(1, 0, links=LINKS)))
    # 3: Reply with the update flag and two links
    f.append(eth(0x0641, roofnet(2, 0x0002, links=LINKS[:2], nxt=1)))
    # 4: Data with an IPv4 payload
    f.append(eth(0x0643, roofnet(4, 0, udp_ip(), links=LINKS[:1])))
    # 5: Data without links, IPv4 payload
    f.append(eth(0x0644, roofnet(4, 0, udp_ip(dport=5300))))
    # 6: Gateway message with the error flag and some reserved flag bits
    f.append(eth(0x0645, roofnet(8, 0x0001 | 0x0004 | 0x8000, links=LINKS)))
    # 7: layer 2 flag: Ethernet frame (padded with 2 octets) carrying IPv4
    inner = b'\0\0' + eth(0x0800, udp_ip(dport=7000))
    f.append(eth(0x0641, roofnet(4, 0x0200, inner, links=LINKS[:1])))
    # 8: layer 2, nested twice: Ethernet -> Roofnet -> Ethernet -> Roofnet -> Ethernet -> IPv4
    inner2 = b'\0\0' + eth(0x0641, roofnet(4, 0x0200, b'\0\0' + eth(0x0800, udp_ip(dport=7001))))
    f.append(eth(0x0641, roofnet(4, 0x0200, inner2)))
    # 9: unknown message type, update and layer 2 flags with no payload
    f.append(eth(0x0641, roofnet(0x10, 0x0202, links=LINKS[:1])))
    # 10: ten links, the largest accepted number
    ten = [('10.0.1.%d' % i, i, i + 1, i + 2, i + 3) for i in range(10)]
    f.append(eth(0x0643, roofnet(2, 0, links=ten)))
    # 11: three links announced but only one present: the link loop stops
    short = roofnet(1, 0, links=LINKS[:1], nlinks=3)
    f.append(eth(0x0641, short[:20 + 24]))
    # 12: data length larger than the data present
    f.append(eth(0x0643, roofnet(4, 0, udp_ip(), datalen=200)))
    write_pcap(os.path.join(out, 'roofnet-coverage.pcap'), f)
    mal = []
    # too many links (11)
    mal.append(eth(0x0641, roofnet(1, 0, links=[('10.0.2.%d' % i, 1, 2, 3, 4) for i in range(11)])))
    mal.append(eth(0x0641, roofnet(1, 0, nlinks=255)))
    # more payload than the data length says
    mal.append(eth(0x0643, roofnet(4, 0, udp_ip(), datalen=10)))
    mal.append(eth(0x0641, roofnet(4, 0x0200, b'\0\0' + eth(0x0800, udp_ip()), datalen=5)))
    # more than 64 KiB of payload after a small data length: the remaining length
    # does not fit in 16 bits; before the unsigned fix it was truncated
    mal.append(eth(0x0643, roofnet(4, 0, udp_ip()[:20] + bytes(65536 + 10), datalen=20)))
    # header cut short
    mal.append(eth(0x0641, roofnet(1, 0, links=LINKS)[:12]))
    mal.append(eth(0x0641, b'\x01'))
    # IP payload cut short
    mal.append(eth(0x0643, roofnet(4, 0, udp_ip()[:12], datalen=12)))
    write_pcap(os.path.join(out, 'roofnet-coverage-malformed.pcap'), mal)
    if verbose: print('main', len(f), 'malformed', len(mal))

main()
