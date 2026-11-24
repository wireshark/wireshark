# Shared helper module for the capture generators in test/captures/generators
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Small packet building helpers (Ethernet / IPv4 / TCP / UDP / pcap), struct only.
import struct

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def ip4(a):
    return bytes(int(x) for x in a.split('.'))

def eth(payload, src=1, dst=2, etype=0x0800):
    return (b'\x02\x00\x00\x00\x00' + bytes([dst]) + b'\x02\x00\x00\x00\x00' + bytes([src])
            + struct.pack('!H', etype) + payload)

def ipv4(proto, src, dst, payload, ident=1, ttl=64):
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0, ttl, proto, 0,
                    ip4(src), ip4(dst))
    h = h[:10] + struct.pack('!H', csum(h)) + h[12:]
    return h + payload

def udp(sport, dport, payload):
    return struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload

def tcp(sport, dport, seq, ack, flags, payload=b'', win=65535):
    return struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 5 << 4, flags, win, 0, 0) + payload

def udp_frame(sport, dport, payload, src='192.0.2.1', dst='192.0.2.2', ident=1):
    return eth(ipv4(17, src, dst, udp(sport, dport, payload), ident))

class Cap:
    def __init__(self, linktype=1):
        self.linktype = linktype
        self.frames = []
    def add(self, data, orig=None):
        self.frames.append((data, orig if orig is not None else len(data)))
        return len(self.frames)
    def write(self, name):
        with open(name, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, self.linktype))
            for i, (d, o) in enumerate(self.frames):
                f.write(struct.pack('<IIII', 1700000000 + i, 0, len(d), o))
                f.write(d)

class Tcp:
    '''One TCP connection; tracks sequence numbers.'''
    ident = 100
    def __init__(self, cap, sport, dport, cip='192.0.2.1', sip='192.0.2.2'):
        self.cap, self.sport, self.dport, self.cip, self.sip = cap, sport, dport, cip, sip
        self.cseq, self.sseq = 1000, 5000
    def _send(self, from_client, flags, payload=b'', trunc=None):
        Tcp.ident += 1
        if from_client:
            t = tcp(self.sport, self.dport, self.cseq, self.sseq if flags & 0x10 else 0, flags, payload)
            f = eth(ipv4(6, self.cip, self.sip, t, Tcp.ident), 1, 2)
            self.cseq += len(payload) + (1 if flags & 3 else 0)
        else:
            t = tcp(self.dport, self.sport, self.sseq, self.cseq, flags, payload)
            f = eth(ipv4(6, self.sip, self.cip, t, Tcp.ident), 2, 1)
            self.sseq += len(payload) + (1 if flags & 3 else 0)
        if trunc is not None:
            return self.cap.add(f[:len(f) - trunc], len(f))
        return self.cap.add(f)
    def handshake(self):
        self._send(True, 0x02); self._send(False, 0x12); self._send(True, 0x10)
    def c(self, payload, trunc=None):
        return self._send(True, 0x18, payload, trunc)
    def s(self, payload, trunc=None):
        return self._send(False, 0x18, payload, trunc)
    def fin(self):
        self._send(True, 0x11); self._send(False, 0x11); self._send(True, 0x10)
