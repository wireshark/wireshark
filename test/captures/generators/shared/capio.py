# Shared helper module for the capture generators in test/captures/generators
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Capture writer helpers (pcapng with an Ethernet and an Exported PDU interface),
Ethernet/IPv4/SCTP/UDP builders.  Synthetic addresses only (192.0.2.0/24)."""
import struct


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def crc32c(data):
    crc = 0xffffffff
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
    return (~crc) & 0xffffffff


ETH_UP = b'\x02\x00\x00\x00\x00\x02' + b'\x02\x00\x00\x00\x00\x01' + b'\x08\x00'
ETH_DN = b'\x02\x00\x00\x00\x00\x01' + b'\x02\x00\x00\x00\x00\x02' + b'\x08\x00'


def ipv4(payload, src, dst, proto):
    s = bytes(map(int, src.split('.')))
    d = bytes(map(int, dst.split('.')))
    h = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0, s, d)
    h = h[:10] + struct.pack('>H', csum(h)) + h[12:]
    return h + payload


class Sctp:
    """One SCTP association (DATA chunks only), client = 192.0.2.1, server = 192.0.2.2."""
    def __init__(self, cport, sport, client='192.0.2.1', server='192.0.2.2', vt_up=0x01020304, vt_dn=0x05060708):
        self.cport, self.sport, self.client, self.server = cport, sport, client, server
        self.vt = (vt_up, vt_dn)
        self.tsn = [1, 1]
        self.ssn = [0, 0]

    def data(self, payload, up=True, ppid=0, flags=3, stream=0, ssn=None, tsn=None):
        k = 0 if up else 1
        if tsn is None:
            tsn = self.tsn[k]
            self.tsn[k] += 1
        if ssn is None:
            ssn = self.ssn[k]
            if flags & 1:
                self.ssn[k] += 1
        pad = (-len(payload)) % 4
        chunk = struct.pack('>BBHIHHI', 0, flags, 16 + len(payload), tsn, stream, ssn, ppid) + payload + b'\0' * pad
        sp, dp = (self.cport, self.sport) if up else (self.sport, self.cport)
        hdr = struct.pack('>HHII', sp, dp, self.vt[k], 0)
        c = crc32c(hdr + chunk)
        hdr = struct.pack('>HHI', sp, dp, self.vt[k]) + struct.pack('<I', c)
        sctp = hdr + chunk
        s, d = (self.client, self.server) if up else (self.server, self.client)
        return (ETH_UP if up else ETH_DN) + ipv4(sctp, s, d, 132)


def udp(payload, sport, dport, up=True, src='192.0.2.1', dst='192.0.2.2'):
    u = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    s, d = (src, dst) if up else (dst, src)
    return (ETH_UP if up else ETH_DN) + ipv4(u, s, d, 17)


def tlv(t, v):
    return struct.pack('>HH', t, len(v)) + v


def exported(dissector, payload):
    return tlv(12, dissector.encode()) + tlv(0, b'') + payload


def _blk(t, body):
    pad = (-len(body)) % 4
    n = 12 + len(body) + pad
    return struct.pack('<II', t, n) + body + b'\0' * pad + struct.pack('<I', n)


class Cap:
    """Frames: (interface, bytes).  Interface 0 = Ethernet, 1 = Exported PDU."""
    def __init__(self):
        self.fr = []

    def eth(self, data):
        self.fr.append((0, data))

    def epdu(self, name, payload):
        self.fr.append((1, exported(name, payload)))

    def write(self, path, t0=1700000000):
        out = _blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
        for lt in (1, 252):
            out += _blk(1, struct.pack('<HHI', lt, 0, 65535))
        for i, (ifc, d) in enumerate(self.fr):
            ts = (t0 + i) * 1000000
            out += _blk(6, struct.pack('<IIIII', ifc, ts >> 32, ts & 0xffffffff, len(d), len(d)) + d)
        open(path, 'wb').write(out)

    def write_pcap(self, path, linktype=1, t0=1700000000):
        with open(path, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
            for i, (ifc, d) in enumerate(self.fr):
                f.write(struct.pack('<IIII', t0 + i, 0, len(d), len(d)) + d)


class Tcp:
    """One TCP connection, client = 192.0.2.1 -> server = 192.0.2.2.  syn() gives the handshake frames."""
    def __init__(self, cport, sport, client='192.0.2.1', server='192.0.2.2'):
        self.cport, self.sport, self.client, self.server = cport, sport, client, server
        self.seq = [1000, 5000]
        self.ack = [0, 0]

    def seg(self, payload, up=True, flags=0x18):
        k = 0 if up else 1
        sp, dp = (self.cport, self.sport) if up else (self.sport, self.cport)
        s, d = (self.client, self.server) if up else (self.server, self.client)
        ackn = self.seq[1 - k] if flags & 0x10 else 0
        hdr = struct.pack('>HHIIBBHHH', sp, dp, self.seq[k], ackn, 5 << 4, flags, 65535, 0, 0)
        pseudo = bytes(map(int, s.split('.'))) + bytes(map(int, d.split('.'))) + struct.pack('>BBH', 0, 6, 20 + len(payload))
        c = csum(pseudo + hdr + payload)
        hdr = hdr[:16] + struct.pack('>H', c) + hdr[18:]
        self.seq[k] += len(payload) + (1 if flags & 0x03 else 0)
        return (ETH_UP if up else ETH_DN) + ipv4(hdr + payload, s, d, 6)

    def syn(self):
        return [self.seg(b'', True, 0x02), self.seg(b'', False, 0x12), self.seg(b'', True, 0x10)]
