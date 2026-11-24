#!/usr/bin/env python3
# Generates test/captures/vxlan_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic coverage captures for packet-vxlan.c (VXLAN on UDP 4789 and
8472, VXLAN-GPE on UDP 4790).
    mkvxlan.py <outdir>
Writes vxlan-coverage.pcap and vxlan-coverage-malformed.pcap
"""
import struct
import socket
import sys
import os

def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b)//2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

MAC_C = b'\x02\0\0\0\0\x01'
MAC_S = b'\x02\0\0\0\0\x02'
CLI = '192.0.2.1'
SRV = '192.0.2.2'

def ipv4(proto, payload, src, dst, ident=1, frag=0):
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, frag, 64, proto, 0,
                    socket.inet_aton(src), socket.inet_aton(dst))
    return h[:10] + struct.pack('!H', csum(h)) + h[12:] + payload

def eth_ip(ip, from_client):
    d, s = (MAC_S, MAC_C) if from_client else (MAC_C, MAC_S)
    return d + s + b'\x08\x00' + ip

def udp(sp, dp, payload, from_client=True):
    src, dst = (CLI, SRV) if from_client else (SRV, CLI)
    u = struct.pack('!HHHH', sp, dp, 8 + len(payload), 0) + payload
    return eth_ip(ipv4(17, u, src, dst), from_client)

class Tcp:
    """One TCP connection, client port cp to server port sp."""
    def __init__(self, cp, sp):
        self.cp, self.sp = cp, sp
        self.cseq, self.sseq = 1000, 5000
    def seg(self, payload, from_client=True, flags=0x18):
        if from_client:
            sport, dport, seq, ack = self.cp, self.sp, self.cseq, self.sseq
            self.cseq += len(payload) + (1 if flags & 3 else 0)
        else:
            sport, dport, seq, ack = self.sp, self.cp, self.sseq, self.cseq
            self.sseq += len(payload) + (1 if flags & 3 else 0)
        src, dst = (CLI, SRV) if from_client else (SRV, CLI)
        t = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0) + payload
        ph = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack('!BBH', 0, 6, len(t))
        t = t[:16] + struct.pack('!H', csum(ph + t)) + t[18:]
        return eth_ip(ipv4(6, t, src, dst), from_client)
    def handshake(self):
        return [self.seg(b'', True, 0x02), self.seg(b'', False, 0x12), self.seg(b'', True, 0x10)]
    def close(self):
        return [self.seg(b'', False, 0x11), self.seg(b'', True, 0x11), self.seg(b'', False, 0x10)]

def write_pcap(path, frames, linktype=1):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, (i * 1000) % 1000000, len(fr), len(fr)))
            f.write(fr)

def inner_udp_ip(sp=1024, dp=9, data=b'inner payload'):
    return ipv4(17, struct.pack('!HHHH', sp, dp, 8 + len(data), 0) + data, '198.51.100.1', '198.51.100.2')

def inner_udp_ip6(data=b'inner v6 payload'):
    src = socket.inet_pton(socket.AF_INET6, '2001:db8::1')
    dst = socket.inet_pton(socket.AF_INET6, '2001:db8::2')
    u = struct.pack('!HHHH', 1024, 9, 8 + len(data), 0) + data
    ck = csum(src + dst + struct.pack('!IBBBB', len(u), 0, 0, 0, 17) + u) or 0xffff
    u = u[:6] + struct.pack('!H', ck) + u[8:]
    return struct.pack('!IHBB16s16s', 0x60000000, len(u), 17, 64, src, dst) + u

def inner_eth(ip=None, etype=0x0800):
    return b'\x02\0\0\0\x01\x01' + b'\x02\0\0\0\x01\x02' + struct.pack('!H', etype) + (ip if ip is not None else inner_udp_ip())

def vxlan(flags, gbp, vni, reserved, payload):
    """RFC 7348 / GBP header: flags (16 bits), group policy id, VNI, reserved"""
    return struct.pack('!HH', flags, gbp) + struct.pack('!I', (vni << 8) | reserved) + payload

def gpe(flags, nproto, vni, reserved, payload, res16=0):
    return struct.pack('!BHB', flags, res16, nproto) + struct.pack('!I', (vni << 8) | reserved) + payload

def nsh(payload, nproto=3):
    # base header: version 0, no O/U, TTL 63, length 6 words, MD type 1, next protocol
    base = struct.pack('!HBB', (63 << 6) | 6, 1, nproto)
    sp = struct.pack('!I', (0x123456 << 8) | 254)
    ctx = struct.pack('!IIII', 1, 2, 3, 4)
    return base + sp + ctx + payload

def mpls(payload):
    return struct.pack('!I', (100 << 12) | (1 << 8) | 64) + payload

def v(payload, dport=4789, sport=49152, from_client=True):
    return udp(sport, dport, payload, from_client)

def main(outdir):
    f = []
    # --- VXLAN (RFC 7348): I flag, VNI, inner Ethernet
    f.append(v(vxlan(0x0800, 0, 5000, 0, inner_eth())))
    # other port (Linux default 8472), the reply direction
    f.append(v(vxlan(0x0800, 0, 5000, 0, inner_eth()), dport=8472, from_client=False))
    # flags: no I flag; G (GBP extension) with a group policy id; D (don't learn); A (policy applied)
    f.append(v(vxlan(0x0000, 0, 0, 0, inner_eth())))
    f.append(v(vxlan(0x8800, 4660, 0xffffff, 0, inner_eth())))
    f.append(v(vxlan(0x0840, 7, 1, 0, inner_eth())))
    f.append(v(vxlan(0x0848, 65535, 16777215, 0, inner_eth())))
    f.append(v(vxlan(0x8848, 0, 42, 0, inner_eth())))
    # reserved flag bits and a reserved octet that is not zero (expert warning)
    f.append(v(vxlan(0x7fb7 | 0x0800, 1, 77, 0x5a, inner_eth())))
    # inner payloads: ARP and an ethernet frame of another type and IPv6
    arp = struct.pack('!HHBBH6s4s6s4s', 1, 0x0800, 6, 4, 1, b'\x02\0\0\0\x01\x01', bytes([198, 51, 100, 1]),
                      b'\0' * 6, bytes([198, 51, 100, 2]))
    f.append(v(vxlan(0x0800, 0, 9, 0, inner_eth(arp, 0x0806))))
    f.append(v(vxlan(0x0800, 0, 9, 0, inner_eth(inner_udp_ip6(), 0x86dd))))
    # --- VXLAN-GPE (UDP 4790): every next protocol
    f.append(v(gpe(0x0c, 1, 100, 0, inner_udp_ip()), dport=4790))      # P and I bits, IPv4
    f.append(v(gpe(0x0c, 2, 101, 0, inner_udp_ip6()), dport=4790))     # IPv6
    f.append(v(gpe(0x0c, 3, 102, 0, inner_eth()), dport=4790))         # Ethernet
    f.append(v(gpe(0x0c, 4, 103, 0, nsh(inner_eth())), dport=4790))    # NSH
    f.append(v(gpe(0x0c, 5, 104, 0, mpls(inner_udp_ip())), dport=4790))  # MPLS
    f.append(v(gpe(0x0d, 3, 105, 0, inner_eth()), dport=4790))         # with the OAM bit
    f.append(v(gpe(0x04, 3, 0, 0, inner_eth()), dport=4790))           # no instance bit
    f.append(v(gpe(0x1c, 3, 106, 0, inner_eth()), dport=4790))         # version 1
    # next protocol not registered: shown as data; and no P bit
    f.append(v(gpe(0x0c, 0x7f, 107, 0, b'unknown next protocol data'), dport=4790))
    f.append(v(gpe(0x08, 0, 108, 0, b'no next protocol bit'), dport=4790))
    # reserved bits, reserved 16 bit and reserved octet (expert warning)
    f.append(v(gpe(0xc2 | 0x0c, 3, 109, 0x33, inner_eth(), res16=0x1234), dport=4790))
    # a tunnel inside a tunnel: the payload of the inner Ethernet frame is VXLAN again
    inner = inner_udp_ip(49153, 4789, vxlan(0x0800, 0, 6000, 0, inner_eth()))
    f.append(v(vxlan(0x0800, 0, 5001, 0, inner_eth(inner))))
    write_pcap(os.path.join(outdir, 'vxlan-coverage.pcap'), f)

    m = []
    # header only: no inner Ethernet frame
    m.append(v(vxlan(0x0800, 0, 1, 0, b'')))
    m.append(v(gpe(0x0c, 3, 1, 0, b''), dport=4790))
    m.append(v(gpe(0x0c, 1, 1, 0, b''), dport=4790))
    # a truncated header: the VNI is cut off
    m.append(v(vxlan(0x0800, 0, 1, 0, b'')[:6]))
    m.append(v(gpe(0x0c, 3, 1, 0, b'')[:3], dport=4790))
    # truncated inner frames
    m.append(v(vxlan(0x0800, 0, 1, 0, inner_eth()[:10])))
    m.append(v(vxlan(0x0800, 0, 1, 0, inner_eth()[:20])))
    m.append(v(gpe(0x0c, 4, 1, 0, nsh(inner_eth())[:10]), dport=4790))
    m.append(v(gpe(0x0c, 5, 1, 0, mpls(b'')[:2]), dport=4790))
    # nested VXLAN, 14 levels deep (the layer limit stops the recursion)
    pay = inner_eth()
    for i in range(14):
        pay = inner_eth(inner_udp_ip(49153, 4789, vxlan(0x0800, 0, 7000 + i, 0, pay)))
    m.append(v(vxlan(0x0800, 0, 5002, 0, pay)))
    write_pcap(os.path.join(outdir, 'vxlan-coverage-malformed.pcap'), m)

main(sys.argv[1] if len(sys.argv) > 1 else '.')
