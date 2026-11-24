#!/usr/bin/env python3
# Generates test/captures/gnutella_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the Gnutella dissector
(packet-gnutella.c).  Everything is built with struct; nothing comes from
a real network.  Usage: mkgnutella.py <output directory>

Writes:
  gnutella-coverage.pcap            Ping, Pong, Push, Query, QueryHit and
                                    unknown descriptors on TCP port 6346,
                                    several PDUs in one segment, a PDU split
                                    over segments, a transfer stream.
  gnutella-coverage-malformed.pcap  cut-short payloads
"""
import os
import sys
import struct
import socket

def pcap(path, frames, linktype=1):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, fr in enumerate(frames):
            orig = len(fr)
            if isinstance(fr, tuple):      # (captured bytes, original length)
                fr, orig = fr
            f.write(struct.pack('<IIII', 1700000000 + i // 1000, 1000 * (i % 1000), len(fr), orig))
            f.write(fr)

def _blk(t, body):
    pad = (-len(body)) % 4
    n = 12 + len(body) + pad
    return struct.pack('<II', t, n) + body + b'\0' * pad + struct.pack('<I', n)

def pcapng(path, idbs, frames):
    """idbs: list of linktypes; frames: list of (idb index, bytes)"""
    out = _blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    for lt in idbs:
        out += _blk(1, struct.pack('<HHI', lt, 0, 65535))
    for i, (ifc, fr) in enumerate(frames):
        ts = (1700000000 + i) * 1000000
        out += _blk(6, struct.pack('<IIIII', ifc, ts >> 32, ts & 0xffffffff, len(fr), len(fr)) + fr)
    open(path, 'wb').write(out)

def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def ip4(src, dst, proto, payload, ident=1):
    h = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0, 64, proto, 0,
                    socket.inet_aton(src), socket.inet_aton(dst))
    h = h[:10] + struct.pack('>H', csum(h)) + h[12:]
    return h + payload

def udp(sp, dp, payload):
    return struct.pack('>HHHH', sp, dp, 8 + len(payload), 0) + payload

def eth(dst, src, et, payload):
    return dst + src + struct.pack('>H', et) + payload

def tcpseg(src, dst, sp, dp, seq, ack, flags, payload=b'', ident=1, win=65535):
    """Ethernet/IPv4/TCP segment with correct checksums."""
    opts = b'\x02\x04\x05\xb4' if flags & 0x02 else b''
    if flags == 0x02:
        ack = 0
    h = struct.pack('>HHIIBBHHH', sp, dp, seq, ack, (5 + len(opts) // 4) << 4, flags, win, 0, 0)
    h = h[:20] + opts
    ps = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack('>BBH', 0, 6, len(h) + len(payload))
    c = csum(ps + h + payload)
    h = h[:16] + struct.pack('>H', c) + h[18:]
    return eth(bytes.fromhex('020000000002'), bytes.fromhex('020000000001'), 0x0800,
               ip4(src, dst, 6, h + payload, ident))

class Flow:
    """One TCP connection; client = 10.0.0.1, server = 10.0.0.2."""
    def __init__(self, cport, sport, frames, cip='10.0.0.1', sip='10.0.0.2', cseq=1000, sseq=5000):
        self.c, self.s, self.cp, self.sp, self.f = cip, sip, cport, sport, frames
        self.cseq, self.sseq = cseq, sseq
    def _send(self, from_client, flags, data=b''):
        if from_client:
            fr = tcpseg(self.c, self.s, self.cp, self.sp, self.cseq, self.sseq, flags, data)
            self.cseq += len(data) + (1 if flags & 3 else 0)
        else:
            fr = tcpseg(self.s, self.c, self.sp, self.cp, self.sseq, self.cseq, flags, data)
            self.sseq += len(data) + (1 if flags & 3 else 0)
        self.f.append(fr)
    def open(self):
        self._send(True, 0x02)
        self._send(False, 0x12)
        self._send(True, 0x10)
    def c2s(self, data): self._send(True, 0x18, data)
    def s2c(self, data): self._send(False, 0x18, data)
    def ack_c(self): self._send(True, 0x10)
    def ack_s(self): self._send(False, 0x10)
    def fin_s(self, data=b''): self._send(False, 0x19, data)
    def fin_c(self): self._send(True, 0x11)
    def close(self):
        self.fin_s(); self.fin_c(); self.ack_s()


def hdr(desc, size, ttl=7, hops=0, gid=None):
    gid = gid if gid is not None else bytes((i * 7 + desc) & 0xff for i in range(16))
    return gid + struct.pack('<BBBI', desc, ttl, hops, size)

def pdu(desc, payload, **kw):
    return hdr(desc, len(payload), **kw) + payload

def ping(): return pdu(0x00, b'')
def pong(port, ip, files, kb):
    return pdu(0x01, struct.pack('<H', port) + bytes(ip) + struct.pack('<II', files, kb))
def push(sid, idx, ip, port):
    return pdu(0x40, sid + struct.pack('<I', idx) + bytes(ip) + struct.pack('<H', port))
def query(speed, text):
    return pdu(0x80, struct.pack('<H', speed) + text)
def hit(idx, size, name, extra=b''):
    return struct.pack('<II', idx, size) + name + b'\0' + extra + b'\0'
def queryhit(port, ip, speed, hits, trailer=b'', sid=b'S' * 16, count=None):
    body = struct.pack('<BH', len(hits) if count is None else count, port) + bytes(ip) + struct.pack('<I', speed)
    body += b''.join(hits) + trailer + sid
    return pdu(0x81, body)

def build(path_main, path_bad):
    f = []
    A, B = '10.0.0.1', '10.0.0.2'
    # connection 1: handshake (transfer stream), then descriptors
    c = Flow(40000, 6346, f, A, B)
    c.open()
    c.c2s(b'GNUTELLA CONNECT/0.6\r\nUser-Agent: Test\r\n\r\n')           # stream
    c.s2c(b'GNUTELLA/0.6 200 OK\r\nUser-Agent: Test\r\n\r\n')            # stream
    c.c2s(ping())
    c.s2c(pong(6346, (192, 0, 2, 7), 120, 4096))
    c.c2s(query(0, b'free music\0'))
    c.c2s(query(56, b''))                                                 # "Missing data for Query Search"
    c.c2s(query(128, b'x' * 298))                                         # size 300: reproducer for the 32-bit length
    c.s2c(queryhit(6346, (192, 0, 2, 7), 1000,
                   [hit(1, 4096, b'song.mp3', b'urn:sha1:ABC'), hit(2, 12345, b'other file.ogg')]))
    c.s2c(queryhit(6347, (192, 0, 2, 8), 56, [hit(7, 1, b'a.txt')], trailer=b'VENDOR\x02\x00\x01\x00'))
    c.s2c(queryhit(6348, (192, 0, 2, 9), 56, []))
    c.c2s(push(b'P' * 16, 3, (192, 0, 2, 10), 6346))
    c.c2s(pdu(0x02, b'unknown'))                                          # unknown descriptor
    c.c2s(pdu(0x7f, b'', ttl=1, hops=6))
    # several PDUs in one segment
    c.c2s(ping() + pong(1, (1, 2, 3, 4), 0, 0) + push(b'Q' * 16, 0, (5, 6, 7, 8), 65535))
    # one PDU split over two segments (reassembly)
    q = query(10, b'split search string\0')
    c.c2s(q[:30]); c.c2s(q[30:])
    # split inside the header
    p = pong(9, (9, 9, 9, 9), 5, 6)
    c.s2c(p[:10]); c.s2c(p[10:])
    # largest accepted size (4096), then a size above it (transfer stream)
    c.c2s(pdu(0x80, struct.pack('<H', 1) + b'y' * 4093 + b'\0'))
    c.c2s(hdr(0x81, 4097) + b'z' * 40)
    c.close()
    # connection 2: a PDU whose header is split before the length field is complete
    d = Flow(40001, 6346, f, A, B)
    d.open()
    pp = ping()
    d.c2s(pp[:5]); d.c2s(pp[5:])
    d.s2c(hdr(0x81, 4097)[:19])                                          # fewer than 23 bytes, reassembled
    d.s2c(hdr(0x81, 4097)[19:] + b'w' * 8)
    d.close()
    pcap(path_main, f)

    g = []
    c = Flow(40002, 6346, g, A, B)
    c.open()
    c.c2s(pdu(0x80, b'\x05'))                                    # Query: speed field cut short
    c.c2s(pdu(0x01, b'\x01\x02\x03\x04'))                          # Pong cut short
    c.c2s(pdu(0x40, b'P' * 10))                                   # Push cut short
    c.c2s(pdu(0x81, struct.pack('<BH', 3, 6346) + bytes((1, 2, 3, 4)) + struct.pack('<I', 5)
              + struct.pack('<II', 1, 2) + b'unterminated name'))   # QueryHit: count 3, names not terminated
    c.c2s(pdu(0x81, struct.pack('<BH', 1, 6346) + bytes((1, 2, 3, 4)) + struct.pack('<I', 5)))   # QueryHit: no hit, no servent ID
    c.c2s(pdu(0x81, b'\x02'))                                     # QueryHit: header cut short
    # a second PDU in a segment with a size above the limit: the length is
    # clamped to 4096 for reassembly, then the payload is cut short
    c.c2s(ping() + hdr(0x80, 5000) + struct.pack('<H', 1) + b'q' * 4094)
    c.close()
    pcap(path_bad, g)

if __name__ == '__main__':
    out = sys.argv[1]
    build(os.path.join(out, 'gnutella-coverage.pcap'), os.path.join(out, 'gnutella-coverage-malformed.pcap'))
