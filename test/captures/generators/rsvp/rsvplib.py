# Helper module for the rsvp capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Helpers for mkrsvp.py: RSVP messages, objects and the IP/UDP/Ethernet
# framing. Everything is built with struct.
import struct

def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def a4(s): return bytes(int(x) for x in s.split('.'))
def a6(s):
    import socket
    return socket.inet_pton(socket.AF_INET6, s)

def pad4(b): return b + b'\0' * (-len(b) % 4)

def obj(cls, ct, body=b'', length=None):
    """RSVP object: length, class, c-type"""
    body = bytes(body)
    return struct.pack('!HBB', 4 + len(body) if length is None else length, cls, ct) + body

def msg(mtype, objs, ttl=64, flags=1, cksum='ok', length=None, version=1):
    body = b''.join(objs)
    ln = 8 + len(body) if length is None else length
    hdr = struct.pack('!BBHBBH', (version << 4) | flags, mtype, 0, ttl, 0, ln)
    m = hdr + body
    if cksum == 'ok':
        m = m[:2] + struct.pack('!H', csum(m)) + m[4:]
    elif cksum == 'bad':
        m = m[:2] + b'\xde\xad' + m[4:]
    return m  # cksum == 'zero' leaves 0

def ip4pkt(payload, proto=46, src='192.0.2.1', dst='192.0.2.2', ttl=64, ident=1, ds=0xc0):
    h = struct.pack('!BBHHHBBH4s4s', 0x45, ds, 20 + len(payload), ident, 0, ttl, proto, 0, a4(src), a4(dst))
    return h[:10] + struct.pack('!H', csum(h)) + h[12:] + payload

def udp(payload, sport=3455, dport=3455, src='192.0.2.1', dst='192.0.2.2'):
    ln = 8 + len(payload)
    pseudo = struct.pack('!4s4sBBH', a4(src), a4(dst), 0, 17, ln)
    u = struct.pack('!HHHH', sport, dport, ln, 0) + payload
    c = csum(pseudo + u) or 0xffff
    return u[:6] + struct.pack('!H', c) + u[8:]

def ip6pkt(payload, nh=46, src='2001:db8::1', dst='2001:db8::2'):
    return struct.pack('!IHBB16s16s', 0x60000000, len(payload), nh, 64, a6(src), a6(dst)) + payload

ETH4 = b'\x02\0\0\0\0\x02\x02\0\0\0\0\x01\x08\x00'
ETH6 = b'\x02\0\0\0\0\x02\x02\0\0\0\0\x01\x86\xdd'

class Cap:
    def __init__(self):
        self.frames = []     # (bytes, label)
    def add(self, rsvp, label='', kind='ip', src='192.0.2.1', dst='192.0.2.2', proto=46, **kw):
        if kind == 'ip':
            f = ETH4 + ip4pkt(rsvp, proto=proto, src=src, dst=dst, **kw)
        elif kind == 'udp':
            f = ETH4 + ip4pkt(udp(rsvp, src=src, dst=dst), proto=17, src=src, dst=dst)
        elif kind == 'ip6':
            f = ETH6 + ip6pkt(rsvp, nh=proto)
        elif kind == 'raw':
            f = rsvp
        self.frames.append((f, label))
        return len(self.frames)
    def write(self, path):
        with open(path, 'wb') as fh:
            fh.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
            for i, (p, _) in enumerate(self.frames):
                fh.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
                fh.write(p)
