# Shared helper module for the capture generators in test/captures/generators
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Shared helpers: pcap/pcapng writers, Ethernet/IPv4/UDP/TCP builders, Exported PDU."""
import struct
import gzip

LT_ETH = 1
LT_EXPPDU = 252


def pcapng(path, frames):
    """frames: list of (interface, bytes). Interface 0 is Ethernet,
    interface 1 Exported PDU. Timestamps advance 10 ms per frame."""
    def block(btype, body):
        pad = (4 - len(body) % 4) % 4
        body += b'\0' * pad
        ln = 12 + len(body)
        return struct.pack('<II', btype, ln) + body + struct.pack('<I', ln)

    out = block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    out += block(1, struct.pack('<HHI', LT_ETH, 0, 262144))
    out += block(1, struct.pack('<HHI', LT_EXPPDU, 0, 262144))
    t0 = 1700000000 * 1000000
    for i, (ifc, data) in enumerate(frames):
        ts = t0 + i * 10000
        out += block(6, struct.pack('<IIIII', ifc, ts >> 32, ts & 0xffffffff,
                                    len(data), len(data)) + data)
    with open(path, 'wb') as f:
        f.write(out)


# ------------------------------------------------------------ IP/UDP/TCP

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ip4(s):
    return bytes(int(x) for x in s.split('.'))


def mac(addr):
    a = ip4(addr)
    if a[0] == 224:
        return bytes([0x01, 0x00, 0x5e, a[1] & 0x7f, a[2], a[3]])
    return bytes([2, 0]) + a


IDENT = [0]


def ipv4(proto, payload, src, dst):
    IDENT[0] += 1
    hdr = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), IDENT[0] & 0xffff,
                      0x4000, 64, proto, 0, ip4(src), ip4(dst))
    hdr = hdr[:10] + struct.pack('!H', csum(hdr)) + hdr[12:]
    return mac(dst) + mac(src) + b'\x08\x00' + hdr + payload


def udp(payload, src, sport, dst, dport):
    u = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    ph = ip4(src) + ip4(dst) + struct.pack('!BBH', 0, 17, len(u))
    c = csum(ph + u) or 0xffff
    u = u[:6] + struct.pack('!H', c) + u[8:]
    return (0, ipv4(17, u, src, dst))


class TCP:
    """A TCP connection; c2s()/s2c() return frames carrying data."""

    def __init__(self, cli, cport, srv, sport):
        self.cli, self.cport, self.srv, self.sport = cli, cport, srv, sport
        self.cseq, self.sseq = 1000, 5000

    def seg(self, payload, to_server, flags=0x18, seq=None):
        if to_server:
            src, sp, dst, dp = self.cli, self.cport, self.srv, self.sport
            s, a = self.cseq, self.sseq
        else:
            src, sp, dst, dp = self.srv, self.sport, self.cli, self.cport
            s, a = self.sseq, self.cseq
        if seq is not None:
            s = seq
        opts = b''
        if flags & 0x02:
            opts = b'\x02\x04\x05\xb4'           # MSS
            if not flags & 0x10:
                a = 0
        t = struct.pack('!HHIIBBHHH', sp, dp, s & 0xffffffff, a & 0xffffffff,
                        (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts + payload
        ph = ip4(src) + ip4(dst) + struct.pack('!BBH', 0, 6, len(t))
        t = t[:16] + struct.pack('!H', csum(ph + t)) + t[18:]
        return (0, ipv4(6, t, src, dst))

    def handshake(self):
        f = [self.seg(b'', True, 0x02)]
        self.cseq += 1
        f.append(self.seg(b'', False, 0x12))
        self.sseq += 1
        f.append(self.seg(b'', True, 0x10))
        return f

    def c2s(self, payload):
        f = self.seg(payload, True)
        self.cseq += len(payload)
        return f

    def s2c(self, payload):
        f = self.seg(payload, False)
        self.sseq += len(payload)
        return f


def exported_pdu(proto_name, payload):
    name = proto_name.encode()
    pad = (4 - len(name) % 4) % 4
    tags = struct.pack('!HH', 12, len(name) + pad) + name + b'\0' * pad
    tags += struct.pack('!HH', 0, 0)
    return (1, tags + payload)


# --------------------------------------------------------- DOF encodings


def pcap(path, frames, linktype=1):
    """Classic pcap with Ethernet frames; frames are (ifc, bytes) or bytes."""
    out = struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype)
    for i, fr in enumerate(frames):
        data = fr[1] if isinstance(fr, tuple) else fr
        out += struct.pack('<IIII', 1700000000 + i // 100, (i % 100) * 10000,
                           len(data), len(data)) + data
    with open(path, 'wb') as f:
        f.write(out)


def gz(path):
    with open(path, 'rb') as f:
        d = f.read()
    with gzip.GzipFile(path + '.gz', 'wb', mtime=0) as f:
        f.write(d)
