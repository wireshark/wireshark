# Helper module for the icap capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Packet writing helpers (Ethernet, IPv4/IPv6, TCP, UDP, SCTP; pcap output).
Synthetic addresses only (192.0.2.0/24, 198.51.100.0/24, 2001:db8::/32)."""
import socket
import struct
import zlib

CIP = '192.0.2.1'
SIP = '192.0.2.2'
CIP6 = '2001:db8::1'
SIP6 = '2001:db8::2'

clock = [1700000000 * 1000000]


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def ip6(s):
    return socket.inet_pton(socket.AF_INET6, s)


def ip4(s):
    return bytes(map(int, s.split('.')))


class Cap:
    """Frames of interface 0 (Ethernet) or 1 (Exported PDU, pcapng only)."""

    def __init__(self, linktype=1):
        self.frames = []
        self.linktype = linktype

    def add(self, data, snap=None, dt=1000, ifc=0):
        clock[0] += dt
        self.frames.append((clock[0], data, snap, ifc))
        return len(self.frames)

    def n(self):
        return len(self.frames)

    def exported_pdu(self, proto_name, payload, dt=1000):
        name = proto_name.encode()
        pad = (4 - len(name) % 4) % 4
        tags = struct.pack('!HH', 12, len(name) + pad) + name + b'\0' * pad + struct.pack('!HH', 0, 0)
        return self.add(tags + payload, dt=dt, ifc=1)

    def write(self, fn):
        if fn.endswith('.pcapng'):
            return self.write_ng(fn)
        with open(fn, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, self.linktype))
            for ts, d, snap, _ in self.frames:
                cap = d if snap is None else d[:snap]
                f.write(struct.pack('<IIII', ts // 1000000, ts % 1000000, len(cap), len(d)) + cap)

    def write_ng(self, fn):
        def block(btype, body):
            body += b'\0' * (-len(body) % 4)
            ln = 12 + len(body)
            return struct.pack('<II', btype, ln) + body + struct.pack('<I', ln)
        out = block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
        out += block(1, struct.pack('<HHI', 1, 0, 262144))
        out += block(1, struct.pack('<HHI', 252, 0, 262144))
        for ts, d, snap, ifc in self.frames:
            cap = d if snap is None else d[:snap]
            out += block(6, struct.pack('<IIIII', ifc, ts >> 32, ts & 0xffffffff, len(cap), len(d)) + cap)
        with open(fn, 'wb') as f:
            f.write(out)


def eth_ip(proto, src, dst, payload, v6, d=0, ident=1):
    if v6:
        ip = struct.pack('!IHBB16s16s', 0x60000000, len(payload), proto, 64, src, dst)
        eth = bytes([2, 0, 0, 0, 0, 2 - d]) + bytes([2, 0, 0, 0, 0, 1 + d]) + b'\x86\xdd'
    else:
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0, 64, proto, 0, src, dst)
        ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
        eth = bytes([2, 0, 0, 0, 0, 2 - d]) + bytes([2, 0, 0, 0, 0, 1 + d]) + b'\x08\x00'
    return eth + ip + payload


class Flow:
    """One TCP connection; c() is client to server, s() server to client."""

    def __init__(self, cap, cport, sport, cip=CIP, sip=SIP, v6=False):
        self.cap = cap
        self.v6 = v6
        if v6:
            cip, sip = (cip, sip) if ':' in cip else (CIP6, SIP6)
            self.ep = {0: [ip6(cip), cport, 1000], 1: [ip6(sip), sport, 5000]}
        else:
            self.ep = {0: [ip4(cip), cport, 1000], 1: [ip4(sip), sport, 5000]}

    def seg(self, d, payload, dt=1000, snap=None, flags=0x18, seq=None):
        a, b = self.ep[d], self.ep[1 - d]
        sq = a[2] if seq is None else seq
        if flags & 2:
            tcp = struct.pack('!HHIIBBHHH', a[1], b[1], sq, b[2] if flags & 0x10 else 0, 7 << 4, flags, 65535, 0, 0) \
                + b'\x02\x04\x05\xb4\x04\x02\x01\x01'
        else:
            tcp = struct.pack('!HHIIBBHHH', a[1], b[1], sq, b[2], 5 << 4, flags, 65535, 0, 0)
        if seq is None:
            a[2] = (a[2] + len(payload) + (1 if flags & 0x03 else 0)) & 0xffffffff
        return self.cap.add(eth_ip(6, a[0], b[0], tcp + payload, self.v6, d), snap=snap, dt=dt)

    def open(self):
        self.seg(0, b'', flags=0x02)
        self.seg(1, b'', flags=0x12)
        self.seg(0, b'', flags=0x10)

    def fin(self, d=1):
        self.seg(d, b'', flags=0x11)
        self.seg(1 - d, b'', flags=0x10)

    def c(self, data, **kw):
        return self.seg(0, data if isinstance(data, bytes) else data.encode(), **kw)

    def s(self, data, **kw):
        return self.seg(1, data if isinstance(data, bytes) else data.encode(), **kw)

    def ack(self, d):
        self.seg(d, b'', flags=0x10)


def udp(cap, sport, dport, payload, v6=False, cip=CIP, sip=SIP, d=0, dt=1000):
    a = (ip4(cip), sport) if not v6 else (ip6(CIP6), sport)
    b = (ip4(sip), dport) if not v6 else (ip6(SIP6), dport)
    if d:
        a, b = b, a
    u = struct.pack('!HHHH', a[1], b[1], 8 + len(payload), 0) + payload
    if v6:
        ph = a[0] + b[0] + struct.pack('!IBBBB', len(u), 0, 0, 0, 17)
        u = u[:6] + struct.pack('!H', csum(ph + u) or 0xffff) + u[8:]
    return cap.add(eth_ip(17, a[0], b[0], u, v6, d), dt=dt)


def crc32c(data):
    crc = 0xffffffff
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82f63b78 if crc & 1 else 0)
    return crc ^ 0xffffffff


def sctp_data(cap, sport, dport, tsn, ppid, payload, begin_end=3, sid=0, ssn=0, tag=0x11111111, dt=1000, d=0):
    ln = 16 + len(payload)
    chunk = struct.pack('!BBHIHHI', 0, begin_end, ln, tsn, sid, ssn, ppid) + payload
    chunk += b'\0' * (-len(chunk) % 4)
    hdr = struct.pack('!HHII', sport, dport, tag, 0)
    pkt = hdr + chunk
    pkt = pkt[:8] + struct.pack('<I', crc32c(pkt)) + pkt[12:]
    a, b = ip4(CIP), ip4(SIP)
    if d:
        a, b = b, a
    return cap.add(eth_ip(132, a, b, pkt, False, d), dt=dt)


# ---- compression helpers (no libraries beyond zlib)
def gzip_bytes(data):
    c = zlib.compressobj(6, zlib.DEFLATED, 31)
    return c.compress(data) + c.flush()


def deflate_bytes(data):
    c = zlib.compressobj(6, zlib.DEFLATED, 15)
    return c.compress(data) + c.flush()


def brotli_stored(data):
    """Brotli stream with one uncompressed meta-block."""
    assert 0 < len(data) <= 65536
    bits = 0 | (0 << 1) | (0 << 2) | ((len(data) - 1) << 4) | (1 << 20)
    return struct.pack('<I', bits)[:3] + data + b'\x03'


def zstd_raw(data):
    """Zstandard frame with one raw block (single segment, 1 byte size)."""
    assert len(data) < 256
    return b'\x28\xb5\x2f\xfd' + bytes([0x20, len(data)]) + \
        struct.pack('<I', 1 | (len(data) << 3))[:3] + data


def xpress_literal(data):
    """[MS-WUSP] Xpress block of Plain LZ77 literals."""
    assert 0 < len(data) < 32
    comp = struct.pack('<I', 1 << (31 - len(data))) + data
    return struct.pack('<II', len(data), len(comp)) + comp
