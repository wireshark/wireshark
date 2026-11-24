# Helper module for the dxl capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Small helpers to build synthetic link, IP, UDP, TCP and SCTP frames
and write them as classic pcap files. Everything is built with struct."""

import struct
import zlib

MAC_A = bytes.fromhex('020000000001')
MAC_B = bytes.fromhex('020000000002')


def write_pcap(path, frames, linktype=1, snaplen=262144):
    """frames: list of bytes, or (bytes, linktype ignored) tuples."""
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, snaplen, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)


def eth(payload, ethertype, src=MAC_A, dst=MAC_B):
    return dst + src + struct.pack('>H', ethertype) + payload


def cksum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ip4(addr):
    return bytes(map(int, addr.split('.')))


def ipv4(payload, proto, src='192.0.2.1', dst='192.0.2.2', ttl=64, ident=1,
         options=b''):
    ihl = 5 + len(options) // 4
    hdr = struct.pack('>BBHHHBBH4s4s', 0x40 | ihl, 0, 4 * ihl + len(payload),
                      ident, 0, ttl, proto, 0, ip4(src), ip4(dst)) + options
    hdr = hdr[:10] + struct.pack('>H', cksum(hdr)) + hdr[12:]
    return hdr + payload


def udp(payload, sport, dport, src='192.0.2.1', dst='192.0.2.2'):
    ln = 8 + len(payload)
    ph = ip4(src) + ip4(dst) + struct.pack('>BBH', 0, 17, ln)
    u = struct.pack('>HHHH', sport, dport, ln, 0) + payload
    c = cksum(ph + u) or 0xffff
    return u[:6] + struct.pack('>H', c) + u[8:]


def tcp(payload, sport, dport, seq, ack=1, flags=0x18, src='192.0.2.1',
        dst='192.0.2.2', options=b''):
    t = struct.pack('>HHIIBBHHH', sport, dport, seq, ack,
                    (5 + len(options) // 4) << 4, flags, 65535, 0, 0) + options + payload
    ph = ip4(src) + ip4(dst) + struct.pack('>BBH', 0, 6, len(t))
    c = cksum(ph + t)
    return t[:16] + struct.pack('>H', c) + t[18:]


def eth_ipv4_udp(payload, sport, dport, src='192.0.2.1', dst='192.0.2.2',
                 smac=MAC_A, dmac=MAC_B):
    return eth(ipv4(udp(payload, sport, dport, src, dst), 17, src, dst),
               0x0800, smac, dmac)


class TcpFlow:
    """Both directions of one TCP connection, with sequence numbers."""

    def __init__(self, sport, dport, src='192.0.2.1', dst='192.0.2.2'):
        self.a = (src, sport)
        self.b = (dst, dport)
        self.seq = {0: 1000, 1: 5000}

    def handshake(self):
        f = []
        (s, sp), (d, dp) = self.a, self.b
        mss = b'\x02\x04\x05\xb4\x04\x02\x01\x01'
        f.append(eth(ipv4(tcp(b'', sp, dp, self.seq[0] - 1, 0, 0x02, s, d, mss), 6, s, d), 0x0800))
        f.append(eth(ipv4(tcp(b'', dp, sp, self.seq[1] - 1, self.seq[0], 0x12, d, s, mss), 6, d, s),
                     0x0800, MAC_B, MAC_A))
        f.append(eth(ipv4(tcp(b'', sp, dp, self.seq[0], self.seq[1], 0x10, s, d), 6, s, d), 0x0800))
        return f

    def send(self, payload, reverse=False):
        i = 1 if reverse else 0
        (s, sp), (d, dp) = (self.b, self.a) if reverse else (self.a, self.b)
        seg = tcp(payload, sp, dp, self.seq[i], self.seq[1 - i], 0x18, s, d)
        self.seq[i] += len(payload)
        smac, dmac = (MAC_B, MAC_A) if reverse else (MAC_A, MAC_B)
        return eth(ipv4(seg, 6, s, d), 0x0800, smac, dmac)


def crc32c(data):
    crc = 0xffffffff
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
    return crc ^ 0xffffffff


def sctp_data(payload, ppid, sport, dport, tsn, stream=0, ssn=0, vtag=1,
              src='192.0.2.1', dst='192.0.2.2', smac=MAC_A, dmac=MAC_B):
    ln = 16 + len(payload)
    chunk = struct.pack('>BBHIHHI', 0, 3, ln, tsn, stream, ssn, ppid) + payload
    chunk += b'\0' * ((4 - ln % 4) % 4)
    hdr = struct.pack('>HHII', sport, dport, vtag, 0)
    c = crc32c(hdr + chunk)
    pkt = hdr[:8] + struct.pack('<I', c) + chunk
    return eth(ipv4(pkt, 132, src, dst), 0x0800, smac, dmac)


def write_pcapng(path, linktypes, frames, snaplen=262144):
    """linktypes: list of link types, one interface each; frames: list of
    (interface index, bytes)."""
    def block(btype, body):
        body += b'\0' * ((4 - len(body) % 4) % 4)
        ln = 12 + len(body)
        return struct.pack('<II', btype, ln) + body + struct.pack('<I', ln)
    with open(path, 'wb') as f:
        f.write(block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1)))
        for lt in linktypes:
            f.write(block(1, struct.pack('<HHI', lt, 0, snaplen)))
        for i, (ifc, fr) in enumerate(frames):
            ts = (1700000000 + i) * 1000000 + 1000 * i
            f.write(block(6, struct.pack('<IIIII', ifc, ts >> 32, ts & 0xffffffff,
                                         len(fr), len(fr)) + fr))
