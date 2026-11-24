# Helper module for the spray capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
import struct

class Cap:
    """Collects frames; write() produces a pcap."""
    def __init__(self, linktype=1):
        self.linktype = linktype
        self.frames = []
        self.marks = []
    def mark(self, text):
        self.marks.append((len(self.frames) + 1, text))
    def add(self, fr):
        self.frames.append(fr)
        return len(self.frames)
    def write(self, path):
        with open(path, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, self.linktype))
            for i, fr in enumerate(self.frames):
                f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
                f.write(fr)

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def ipv4(proto, payload, src='192.0.2.1', dst='192.0.2.2'):
    sa = bytes(int(x) for x in src.split('.'))
    da = bytes(int(x) for x in dst.split('.'))
    h = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0, sa, da)
    h = h[:10] + struct.pack('>H', csum(h)) + h[12:]
    return h + payload

def eth(payload, etype=0x0800, dst=b'\x02\x00\x00\x00\x00\x02', src=b'\x02\x00\x00\x00\x00\x01'):
    return dst + src + struct.pack('>H', etype) + payload

def udp(sport, dport, payload, src='192.0.2.1', dst='192.0.2.2'):
    u = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    return eth(ipv4(17, u, src, dst))

def tcpseg(sport, dport, seq, payload, src='192.0.2.1', dst='192.0.2.2', flags=0x18, ack=1):
    t = struct.pack('>HHIIBBHHH', sport, dport, seq, ack, 0x50, flags, 65535, 0, 0) + payload
    return eth(ipv4(6, t, src, dst))

class Tcp:
    """One direction-aware TCP stream (no handshake) writing into a Cap."""
    def __init__(self, cap, cport, sport, c='192.0.2.1', s='192.0.2.2'):
        self.cap = cap; self.cport = cport; self.sport = sport; self.c = c; self.s = s
        self.cseq = 1000; self.sseq = 5000
    def c2s(self, payload):
        self.cap.add(tcpseg(self.cport, self.sport, self.cseq, payload, self.c, self.s, ack=self.sseq))
        self.cseq += len(payload)
    def s2c(self, payload):
        self.cap.add(tcpseg(self.sport, self.cport, self.sseq, payload, self.s, self.c, ack=self.cseq))
        self.sseq += len(payload)

def epdu(proto, payload):
    name = proto.encode()
    pad = (4 - len(name) % 4) % 4
    return struct.pack('>HH', 12, len(name) + pad) + name + b'\0' * pad + struct.pack('>HH', 0, 0) + payload

def pcapng(path, linktype, frames, flags=None, snaplen=65535):
    """frames: list of bytes; flags: optional list of epb_flags values (None = no option)."""
    def blk(t, body):
        body += b'\0' * ((4 - len(body) % 4) % 4)
        tl = 12 + len(body)
        return struct.pack('<II', t, tl) + body + struct.pack('<I', tl)
    out = blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    out += blk(1, struct.pack('<HHI', linktype, 0, snaplen))
    for i, fr in enumerate(frames):
        ts = (1700000000 + i) * 1000000
        opts = b''
        if flags and flags[i] is not None:
            opts = struct.pack('<HHI', 2, 4, flags[i]) + struct.pack('<HH', 0, 0)
        pad = b'\0' * ((4 - len(fr) % 4) % 4)
        out += blk(6, struct.pack('<IIIII', 0, ts >> 32, ts & 0xffffffff, len(fr), len(fr)) + fr + pad + opts)
    open(path, 'wb').write(out)

def ipv6(nh, payload, src='2001:db8::1', dst='2001:db8::2', hlim=64):
    import socket
    return struct.pack('>IHBB', 0x60000000, len(payload), nh, hlim) + socket.inet_pton(socket.AF_INET6, src) + socket.inet_pton(socket.AF_INET6, dst) + payload

def udp6(sport, dport, payload, src='2001:db8::1', dst='2001:db8::2'):
    u = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    return eth(ipv6(17, u, src, dst), 0x86dd)

def exppdu(name, payload):
    """Exported PDU (DLT 252) record naming a dissector."""
    n = name.encode()
    pad = (4 - len(n) % 4) % 4
    return struct.pack('>HH', 12, len(n) + pad) + n + b'\0' * pad + struct.pack('>HH', 0, 0) + payload

def xstr(s):
    """XDR string/opaque with padding."""
    if isinstance(s, str):
        s = s.encode()
    return struct.pack('>I', len(s)) + s + b'\0' * ((4 - len(s) % 4) % 4)

def rpc_call(xid, prog, vers, proc, args=b'', cred=(0, b''), verf=(0, b'')):
    return struct.pack('>IIIIII', xid, 0, 2, prog, vers, proc) + struct.pack('>I', cred[0]) + xstr(cred[1]) + struct.pack('>I', verf[0]) + xstr(verf[1]) + args

def rpc_reply(xid, results=b'', accept=0, verf=(0, b'')):
    return struct.pack('>III', xid, 1, 0) + struct.pack('>I', verf[0]) + xstr(verf[1]) + struct.pack('>I', accept) + results
