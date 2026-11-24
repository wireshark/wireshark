# Shared helper module for the capture generators in test/captures/generators
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Helpers shared by the group u9 generators (UA3G, UA, UAUDP, UASIP, UCI, UCP).
# Everything is synthetic: addresses are from 192.0.2.0/24 and 198.51.100.0/24.
import struct


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ip4(src, dst, proto, payload, ident=1):
    hdr = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0, 64, proto, 0,
                      bytes(src), bytes(dst))
    hdr = hdr[:10] + struct.pack('!H', csum(hdr)) + hdr[12:]
    return hdr + payload


def eth(payload, et=0x0800, src='020000000001', dst='020000000002'):
    return bytes.fromhex(dst) + bytes.fromhex(src) + struct.pack('!H', et) + payload


def udp(src, dst, sport, dport, data):
    u = struct.pack('!HHHH', sport, dport, 8 + len(data), 0) + data
    return eth(ip4(src, dst, 17, u))


class Tcp:
    '''One TCP connection; sequence numbers are tracked per direction.'''

    def __init__(self, a, b, pa, pb):
        self.a, self.b, self.pa, self.pb = a, b, pa, pb
        self.seq = {0: 1000, 1: 5000}

    def seg(self, d, data, flags=0x18):
        s, dd = (self.a, self.b) if d == 0 else (self.b, self.a)
        sp, dp = (self.pa, self.pb) if d == 0 else (self.pb, self.pa)
        seq = self.seq[d]
        ack = self.seq[1 - d]
        if not flags & 0x10:
            ack = 0
        opts = b'\x02\x04\x05\xb4' if flags & 0x02 else b''     # MSS on SYN and SYN/ACK
        t = struct.pack('!HHIIBBHHH', sp, dp, seq, ack, (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts + data
        ph = bytes(s) + bytes(dd) + struct.pack('!BBH', 0, 6, len(t))
        t = t[:16] + struct.pack('!H', csum(ph + t)) + t[18:]
        self.seq[d] += len(data) + (1 if flags & 0x03 else 0)
        return eth(ip4(s, dd, 6, t), src='020000000001' if d == 0 else '020000000002',
                   dst='020000000002' if d == 0 else '020000000001')

    def handshake(self):
        return [self.seg(0, b'', 0x02), self.seg(1, b'', 0x12), self.seg(0, b'', 0x10)]

    def close(self):
        return [self.seg(0, b'', 0x11), self.seg(1, b'', 0x11), self.seg(0, b'', 0x10)]


def epdu(name, data, ipv4=None, ports=None):
    '''Exported PDU frame: dissector name tag and optionally IPv4 src/dst,
    UDP ports.'''
    n = name.encode()
    pad = n + b'\0' * ((4 - len(n) % 4) % 4)
    tags = struct.pack('!HH', 12, len(pad)) + pad     # the length includes the padding
    if ipv4:
        tags += struct.pack('!HH4s', 20, 4, bytes(ipv4[0]))
        tags += struct.pack('!HH4s', 21, 4, bytes(ipv4[1]))
    if ports:
        tags += struct.pack('!HHI', 24, 4, 3)           # port type UDP (EXP_PDU_PT_UDP = 3)
        tags += struct.pack('!HHI', 25, 4, ports[0])   # src port
        tags += struct.pack('!HHI', 26, 4, ports[1])   # dst port
    return tags + struct.pack('!HH', 0, 0) + data


class Pcap:
    '''Classic pcap writer; frames get one second steps.'''

    def __init__(self, linktype=1):
        self.linktype = linktype
        self.frames = []

    def add(self, fr, t=None):
        self.frames.append(fr)
        return len(self.frames)

    def extend(self, frs):
        for f in frs:
            self.add(f)

    def __len__(self):
        return len(self.frames)

    def write(self, fname):
        with open(fname, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, self.linktype))
            for i, fr in enumerate(self.frames):
                f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
                f.write(fr)


def _opt(code, data):
    pad = (4 - len(data) % 4) % 4
    return struct.pack('<HH', code, len(data)) + data + b'\0' * pad


def _blk(btype, body):
    total = 12 + len(body)
    return struct.pack('<II', btype, total) + body + struct.pack('<I', total)


class Pcapng:
    '''pcapng writer with several interfaces (linktype list).'''

    def __init__(self, linktypes):
        self.linktypes = linktypes
        self.frames = []   # (iface, data)

    def add(self, fr, iface=0):
        self.frames.append((iface, fr))
        return len(self.frames)

    def __len__(self):
        return len(self.frames)

    def write(self, fname):
        out = _blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
        for lt in self.linktypes:
            out += _blk(1, struct.pack('<HHI', lt, 0, 262144))
        for i, (iface, fr) in enumerate(self.frames):
            ts = (1700000000 + i) * 1000000
            pad = b'\0' * ((4 - len(fr) % 4) % 4)
            out += _blk(6, struct.pack('<IIIII', iface, ts >> 32, ts & 0xffffffff, len(fr), len(fr)) + fr + pad)
        with open(fname, 'wb') as f:
            f.write(out)


def udp6(src, dst, sport, dport, data):
    '''UDP over IPv6 (src and dst are 16 byte addresses), with checksum.'''
    u = struct.pack('!HHHH', sport, dport, 8 + len(data), 0) + data
    ph = bytes(src) + bytes(dst) + struct.pack('!IBBBB', len(u), 0, 0, 0, 17)
    c = csum(ph + u) or 0xFFFF
    u = u[:6] + struct.pack('!H', c) + u[8:]
    ip = struct.pack('!IHBB', 0x60000000, len(u), 17, 64) + bytes(src) + bytes(dst)
    return eth(ip + u, et=0x86DD)
