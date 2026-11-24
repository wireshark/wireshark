# Shared helper module for the capture generators in test/captures/generators
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
import struct

def pcap(fname, pkts, linktype=1):
    with open(fname, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, p in enumerate(pkts):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
            f.write(p)

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def ipv4(proto, payload, src='192.0.2.1', dst='192.0.2.2'):
    s = bytes(int(x) for x in src.split('.'))
    d = bytes(int(x) for x in dst.split('.'))
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0, s, d)
    h = h[:10] + struct.pack('!H', csum(h)) + h[12:]
    return h + payload

def eth(payload, etype=0x0800):
    return b'\x02\x00\x00\x00\x00\x02' + b'\x02\x00\x00\x00\x00\x01' + struct.pack('!H', etype) + payload

def tcp(sport, dport, payload, seq=1, ack=1, flags=0x18, src='192.0.2.1', dst='192.0.2.2'):
    h = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0)
    return eth(ipv4(6, h + payload, src, dst))

def udp(sport, dport, payload, src='192.0.2.1', dst='192.0.2.2'):
    h = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0)
    return eth(ipv4(17, h + payload, src, dst))

def exported_pdu(name, payload, extra=b''):
    n = name.encode()
    pad = (4 - len(n) % 4) % 4
    t = struct.pack('!HH', 12, len(n) + pad) + n + b'\0' * pad
    return t + extra + struct.pack('!HH', 0, 0) + payload

def exp_port_tags(sport, dport):
    return (struct.pack('!HHI', 24, 4, 2) + struct.pack('!HHI', 25, 4, sport) +
            struct.pack('!HHI', 26, 4, dport))

class Conn:
    """TCP connection with sequence numbers; send() returns frames."""
    def __init__(self, cport, sport, src='192.0.2.1', dst='192.0.2.2', isn_c=1000, isn_s=5000):
        self.cport, self.sport, self.src, self.dst = cport, sport, src, dst
        self.c, self.s = isn_c, isn_s
    def syn(self):
        out = [tcp(self.cport, self.sport, b'', self.c, 0, 0x02, self.src, self.dst)]
        self.c += 1
        out.append(tcp(self.sport, self.cport, b'', self.s, self.c, 0x12, self.dst, self.src))
        self.s += 1
        out.append(tcp(self.cport, self.sport, b'', self.c, self.s, 0x10, self.src, self.dst))
        return out
    def cs(self, data):
        f = tcp(self.cport, self.sport, data, self.c, self.s, 0x18, self.src, self.dst)
        self.c += len(data); return f
    def sc(self, data):
        f = tcp(self.sport, self.cport, data, self.s, self.c, 0x18, self.dst, self.src)
        self.s += len(data); return f

def pcapng_write(fname, groups, base=1700000000):
    """groups: list of (linktype, [frames]); one interface per group, frames written
    group by group (frame numbers follow this order)."""
    def blk(t, body):
        pad = (4 - len(body) % 4) % 4
        L = 12 + len(body) + pad
        return struct.pack('<II', t, L) + body + b'\0' * pad + struct.pack('<I', L)
    out = blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    for lt, _ in groups:
        out += blk(1, struct.pack('<HHI', lt, 0, 262144))
    ts = 0
    for i, (lt, frames) in enumerate(groups):
        for p in frames:
            t = (base + ts) * 1000000
            ts += 1
            out += blk(6, struct.pack('<IIIII', i, t >> 32, t & 0xffffffff, len(p), len(p)) + p)
    open(fname, 'wb').write(out)
