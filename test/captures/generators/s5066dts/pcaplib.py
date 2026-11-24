# Helper module for the s5066dts capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
import struct
import zlib

class Pcap:
    def __init__(self, linktype=1):
        self.linktype = linktype
        self.frames = []
    def add(self, data, ts=None):
        self.frames.append(bytes(data))
    def write(self, path):
        with open(path, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, self.linktype))
            for i, d in enumerate(self.frames):
                f.write(struct.pack('<IIII', 1700000000 + i, 0, len(d), len(d)))
                f.write(d)

def mac(n): return bytes([2, 0, 0, 0, 0, n])
def ip4(a): return bytes(int(x) for x in a.split('.'))

def csum(b):
    if len(b) & 1: b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b)//2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def eth(payload, etype=0x0800, src=1, dst=2):
    return mac(dst) + mac(src) + struct.pack('>H', etype) + payload

_ipid = [0]
def ipv4(payload, proto, src='10.0.0.1', dst='10.0.0.2', flags_frag=0, ident=None):
    _ipid[0] += 1
    if ident is None: ident = _ipid[0]
    h = struct.pack('>BBHHHBBH', 0x45, 0, 20 + len(payload), ident, flags_frag, 64, proto, 0) + ip4(src) + ip4(dst)
    h = h[:10] + struct.pack('>H', csum(h)) + h[12:]
    return h + payload

def udp(payload, sport, dport):
    return struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload

def tcp(payload, sport, dport, seq, ack=0, flags=0x18, win=65535):
    if flags & 2:
        return struct.pack('>HHIIBBHHH', sport, dport, seq & 0xffffffff, (ack if flags & 0x10 else 0) & 0xffffffff, 6 << 4, flags, win, 0, 0) + b'\x02\x04\x05\xb4' + payload
    return struct.pack('>HHIIBBHHH', sport, dport, seq & 0xffffffff, ack & 0xffffffff, 5 << 4, flags, win, 0, 0) + payload

def udp_frame(payload, sport, dport, src='10.0.0.1', dst='10.0.0.2', sm=1, dm=2):
    return eth(ipv4(udp(payload, sport, dport), 17, src, dst), 0x0800, sm, dm)

class TcpStream:
    """Client c (10.0.0.1:cport) <-> server s (10.0.0.2:sport) with seq tracking."""
    def __init__(self, pcap, cport, sport, caddr='10.0.0.1', saddr='10.0.0.2', handshake=True):
        self.p = pcap; self.cp = cport; self.sp = sport
        self.ca = caddr; self.sa = saddr
        self.cseq = 1000; self.sseq = 5000
        if handshake:
            self._raw(True, b'', 0x02)
            self.cseq += 1
            self._raw(False, b'', 0x12)
            self.sseq += 1
            self._raw(True, b'', 0x10)
    def _raw(self, c, data, flags):
        if c:
            seg = tcp(data, self.cp, self.sp, self.cseq, self.sseq, flags)
            self.p.add(eth(ipv4(seg, 6, self.ca, self.sa), 0x0800, 1, 2))
        else:
            seg = tcp(data, self.sp, self.cp, self.sseq, self.cseq, flags)
            self.p.add(eth(ipv4(seg, 6, self.sa, self.ca), 0x0800, 2, 1))
    def c(self, data):
        self._raw(True, data, 0x18); self.cseq += len(data)
    def s(self, data):
        self._raw(False, data, 0x18); self.sseq += len(data)
    def fin(self):
        self._raw(True, b'', 0x11); self.cseq += 1
        self._raw(False, b'', 0x11); self.sseq += 1


class PcapNg:
    """pcapng writer; add(data, lt) with one IDB per link type."""
    def __init__(self):
        self.frames = []
    def add(self, data, lt=1):
        self.frames.append((lt, bytes(data)))
    def write(self, path):
        def blk(t, body):
            body += b'\0' * ((4 - len(body) % 4) % 4)
            return struct.pack('<II', t, len(body) + 12) + body + struct.pack('<I', len(body) + 12)
        out = blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
        lts = []
        for lt, _ in self.frames:
            if lt not in lts: lts.append(lt)
        for lt in lts:
            out += blk(1, struct.pack('<HHI', lt, 0, 262144))
        t = 1700000000 * 1000000
        for lt, fr in self.frames:
            t += 1000
            out += blk(6, struct.pack('<IIIII', lts.index(lt), t >> 32, t & 0xffffffff, len(fr), len(fr)) + fr)
        open(path, 'wb').write(out)
