# Helper module for the wireguard capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Small helpers shared by the generators: pcap writer, Ethernet/IP/UDP/TCP."""
import struct
import socket
import zlib

def pcap(path, frames, linktype=1, snaplen=262144):
    out = struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, snaplen, linktype)
    t = 0
    for f in frames:
        out += struct.pack('<IIII', 1700000000 + t // 100, (t % 100) * 10000, len(f), len(f)) + f
        t += 1
    open(path, 'wb').write(out)

def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def eth(payload, etype, dst='02:00:00:00:00:02', src='02:00:00:00:00:01'):
    m = lambda s: bytes(int(x, 16) for x in s.split(':'))
    return m(dst) + m(src) + struct.pack('!H', etype) + payload

_ipid = [1]
def ip4(payload, proto, src='192.0.2.1', dst='192.0.2.2'):
    _ipid[0] += 1
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), _ipid[0] & 0xffff, 0, 64, proto, 0,
                    socket.inet_aton(src), socket.inet_aton(dst))
    h = h[:10] + struct.pack('!H', csum(h)) + h[12:]
    return h + payload

def udp(payload, sport, dport):
    return struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload

def udp_frame(payload, sport, dport, src='192.0.2.1', dst='192.0.2.2'):
    return eth(ip4(udp(payload, sport, dport), 17, src, dst), 0x0800)

class Tcp:
    """One TCP connection with simple sequence tracking."""
    def __init__(self, sport, dport, src='192.0.2.1', dst='192.0.2.2'):
        self.sp, self.dp, self.src, self.dst = sport, dport, src, dst
        self.cseq, self.sseq = 1000, 5000
    def _seg(self, c2s, flags, data=b''):
        if c2s:
            sp, dp, s, a, ip_s, ip_d = self.sp, self.dp, self.cseq, self.sseq, self.src, self.dst
        else:
            sp, dp, s, a, ip_s, ip_d = self.dp, self.sp, self.sseq, self.cseq, self.dst, self.src
        opt = b''
        if flags & 0x02:
            a = 0 if not flags & 0x10 else a
            opt = struct.pack('!BBH', 2, 4, 1460)
        h = struct.pack('!HHIIBBHHH', sp, dp, s, a, ((20 + len(opt)) // 4) << 4, flags, 65535, 0, 0) + opt
        ps = socket.inet_aton(ip_s) + socket.inet_aton(ip_d) + struct.pack('!BBH', 0, 6, len(h) + len(data))
        ck = csum(ps + h + data)
        h = h[:16] + struct.pack('!H', ck) + h[18:]
        return eth(ip4(h + data, 6, ip_s, ip_d), 0x0800,
                   *(('02:00:00:00:00:02', '02:00:00:00:00:01') if c2s else ('02:00:00:00:00:01', '02:00:00:00:00:02')))
    def handshake(self):
        f = [self._seg(True, 0x02)]; self.cseq += 1
        f.append(self._seg(False, 0x12)); self.sseq += 1
        f.append(self._seg(True, 0x10))
        return f
    def send(self, data, c2s=True, mss=1400):
        out = []
        for i in range(0, max(len(data), 1), mss):
            ch = data[i:i + mss]
            out.append(self._seg(c2s, 0x18, ch))
            if c2s: self.cseq += len(ch)
            else: self.sseq += len(ch)
        out.append(self._seg(not c2s, 0x10))
        return out
    def fin(self):
        f = [self._seg(True, 0x11)]; self.cseq += 1
        f.append(self._seg(False, 0x11)); self.sseq += 1
        f.append(self._seg(True, 0x10))
        return f

def pcapng(path, frames, dsb=None, linktype=1):
    """frames: list of bytes (one interface). dsb: bytes of a WireGuard (WGKL)
    or other Decryption Secrets Block payload as (secrets_type, data)."""
    def blk(t, body):
        body += b'\0' * ((4 - len(body) % 4) % 4)
        n = 12 + len(body)
        return struct.pack('<II', t, n) + body + struct.pack('<I', n)
    out = blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    out += blk(1, struct.pack('<HHI', linktype, 0, 0))
    if dsb:
        out += blk(0x0A, struct.pack('<II', dsb[0], len(dsb[1])) + dsb[1])
    for i, f in enumerate(frames):
        ts = 1700000000_000000 + i * 10000
        out += blk(6, struct.pack('<IIIII', 0, ts >> 32, ts & 0xffffffff, len(f), len(f)) + f)
    open(path, 'wb').write(out)

def ip6(payload, nxt, src='2001:db8::1', dst='2001:db8::2'):
    h = struct.pack('!IHBB', 0x60000000, len(payload), nxt, 64)
    return h + socket.inet_pton(socket.AF_INET6, src) + socket.inet_pton(socket.AF_INET6, dst) + payload

def udp6_frame(payload, sport, dport, src='2001:db8::1', dst='2001:db8::2'):
    u = udp(payload, sport, dport)
    ps = socket.inet_pton(socket.AF_INET6, src) + socket.inet_pton(socket.AF_INET6, dst) + struct.pack('!IBBBB', len(u), 0, 0, 0, 17)
    ck = csum(ps + u) or 0xffff
    u = u[:6] + struct.pack('!H', ck) + u[8:]
    return eth(ip6(u, 17, src, dst), 0x86dd)
