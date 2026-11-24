# Shared helper module for the capture generators in test/captures/generators
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
import struct
import sys
import os
import gzip

def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def ipv4(proto, payload, src='192.0.2.1', dst='192.0.2.2', ident=1, flags_frag=0, ttl=None):
    s = bytes(int(x) for x in src.split('.'))
    d = bytes(int(x) for x in dst.split('.'))
    hdr = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident & 0xffff,
                      flags_frag, (ttl if ttl is not None else (255 if dst.startswith('224.0.0.') else 64)), proto, 0, s, d)
    hdr = hdr[:10] + struct.pack('!H', csum(hdr)) + hdr[12:]
    return hdr + payload

def eth(payload, src=1, dst=2):
    return (bytes([2, 0, 0, 0, 0, dst]) + bytes([2, 0, 0, 0, 0, src]) +
            b'\x08\x00' + payload)

def udp(sport, dport, payload, **kw):
    u = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    return eth(ipv4(17, u, **kw))

def tcp(sport, dport, seq, payload, ack=1, flags=0x18, opts=b'', **kw):
    t = struct.pack('!HHIIBBHHH', sport, dport, seq & 0xffffffff, ack,
                    (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts + payload
    return eth(ipv4(6, t, **kw))

class Conn:
    """A TCP connection with sequence tracking; frames collected in .out list."""
    def __init__(self, out, cport, sport, caddr='192.0.2.1', saddr='192.0.2.2',
                 cisn=1000, sisn=5000, handshake=True):
        self.out = out; self.cport = cport; self.sport = sport
        self.c = caddr; self.s = saddr
        self.cseq = cisn; self.sseq = sisn
        if handshake:
            out.append(tcp(cport, sport, self.cseq, b'', ack=0, flags=0x02, opts=b'\x02\x04\x05\xb4', src=self.c, dst=self.s))
            self.cseq += 1
            out.append(tcp(sport, cport, self.sseq, b'', ack=self.cseq, flags=0x12, opts=b'\x02\x04\x05\xb4', src=self.s, dst=self.c))
            self.sseq += 1
            out.append(tcp(cport, sport, self.cseq, b'', ack=self.sseq, flags=0x10, src=self.c, dst=self.s))
    def send(self, data, psh=True):
        self.out.append(tcp(self.cport, self.sport, self.cseq, data, ack=self.sseq,
                            flags=0x18 if psh else 0x10, src=self.c, dst=self.s))
        self.cseq += len(data)
    def recv(self, data, psh=True):
        self.out.append(tcp(self.sport, self.cport, self.sseq, data, ack=self.cseq,
                            flags=0x18 if psh else 0x10, src=self.s, dst=self.c))
        self.sseq += len(data)
    def csegs(self, data, n):
        """client data split into segments of n octets"""
        for i in range(0, len(data), n):
            self.send(data[i:i+n], psh=(i + n >= len(data)))
    def ssegs(self, data, n):
        for i in range(0, len(data), n):
            self.recv(data[i:i+n], psh=(i + n >= len(data)))
    def fin(self):
        self.out.append(tcp(self.cport, self.sport, self.cseq, b'', ack=self.sseq, flags=0x11, src=self.c, dst=self.s))
        self.cseq += 1
        self.out.append(tcp(self.sport, self.cport, self.sseq, b'', ack=self.cseq, flags=0x11, src=self.s, dst=self.c))
        self.sseq += 1
        self.out.append(tcp(self.cport, self.sport, self.cseq, b'', ack=self.sseq, flags=0x10, src=self.c, dst=self.s))

def write_pcap(name, frames):
    with open(name, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i // 1000, (i % 1000) * 1000,
                                len(fr), len(fr)))
            f.write(fr)

def gz(name):
    with open(name, 'rb') as f:
        d = f.read()
    with open(name + '.gz', 'wb') as o:
        o.write(gzip.compress(d, 9, mtime=0))

def eth6(payload, src=1, dst=2):
    return (bytes([2, 0, 0, 0, 0, dst]) + bytes([2, 0, 0, 0, 0, src]) +
            b'\x86\xdd' + payload)

def _a6(a):
    import socket
    return socket.inet_pton(socket.AF_INET6, a)

def udp6(sport, dport, payload, src='2001:db8::1', dst='2001:db8::2'):
    ulen = 8 + len(payload)
    u = struct.pack('!HHHH', sport, dport, ulen, 0) + payload
    ph = _a6(src) + _a6(dst) + struct.pack('!IBBBB', ulen, 0, 0, 0, 17)
    c = csum(ph + u) or 0xffff
    u = u[:6] + struct.pack('!H', c) + u[8:]
    return eth6(struct.pack('!IHBB', 6 << 28, ulen, 17, 64) + _a6(src) + _a6(dst) + u)
