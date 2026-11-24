#!/usr/bin/env python3
# Generates test/captures/openflow_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Common helpers: classic pcap writer with simple TCP streams (Ethernet/IPv4/TCP).
import struct
import sys
import os

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

class Pcap:
    """pcapng writer: interface 0 is Ethernet, interface 1 is Exported PDU."""
    def __init__(self):
        self.frames = []
        self.ipid = 1
    def raw(self, frame, iface=0):
        self.frames.append((iface, frame))
    def epdu(self, name, data):
        """A frame holding data for the dissector called name (Exported PDU)."""
        nm = name.encode()
        tag = struct.pack('!HH', 12, (len(nm) + 3) // 4 * 4) + nm + b'\0' * (-len(nm) % 4)
        self.raw(tag + struct.pack('!HH', 0, 0) + data, 1)
    @staticmethod
    def _blk(t, body):
        body += b'\0' * (-len(body) % 4)
        return struct.pack('<II', t, len(body) + 12) + body + struct.pack('<I', len(body) + 12)
    def write(self, fn):
        out = self._blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
        out += self._blk(1, struct.pack('<HHI', 1, 0, 0))
        out += self._blk(1, struct.pack('<HHI', 252, 0, 0))
        for i, (ifc, f) in enumerate(self.frames):
            out += self._blk(6, struct.pack('<IIIII', ifc, 0, 1000 * i, len(f), len(f)) + f)
        open(fn, 'wb').write(out)

class Flow:
    """One TCP connection; the 'switch' is the client, the controller listens."""
    def __init__(self, pcap, sport=40000, dport=6653, handshake=True):
        self.p = pcap
        self.sport, self.dport = sport, dport
        self.cseq, self.sseq = 1000, 5000
        if handshake:
            self._tcp(True, b'', 0x02)
            self.cseq += 1
            self._tcp(False, b'', 0x12)
            self.sseq += 1
            self._tcp(True, b'', 0x10)
    def _tcp(self, from_switch, data, flags=0x18):
        if from_switch:
            sp, dp, seq, ack = self.sport, self.dport, self.cseq, self.sseq
            src, dst = bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2])
            esrc, edst = '020000000001', '020000000002'
        else:
            sp, dp, seq, ack = self.dport, self.sport, self.sseq, self.cseq
            src, dst = bytes([192, 0, 2, 2]), bytes([192, 0, 2, 1])
            esrc, edst = '020000000002', '020000000001'
        opt = b''
        if flags & 0x02:
            ack = 0 if flags == 0x02 else ack
            opt = struct.pack('!BBHBBBB', 2, 4, 1460, 4, 2, 1, 1)
        tcp = struct.pack('!HHIIBBHHH', sp, dp, seq, ack, ((20 + len(opt)) // 4) << 4, flags, 65535, 0, 0) + opt + data
        ln = len(tcp)
        pseudo = src + dst + struct.pack('!BBH', 0, 6, ln)
        c = csum(pseudo + tcp)
        tcp = tcp[:16] + struct.pack('!H', c) + tcp[18:]
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + ln, self.p.ipid, 0, 64, 6, 0, src, dst)
        self.p.ipid += 1
        ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
        self.p.raw(bytes.fromhex(edst + esrc + '0800') + ip + tcp)
    def send(self, from_switch, *pdus, split=None):
        """Send PDUs in one segment; with split=[n,...] cut the stream at these offsets."""
        data = b''.join(pdus)
        cuts = [0] + list(split or []) + [len(data)]
        for a, b in zip(cuts, cuts[1:]):
            self._tcp(from_switch, data[a:b])
            if from_switch:
                self.cseq += b - a
            else:
                self.sseq += b - a

def eth_ip_udp(payload=b'abcdefgh', sport=1234, dport=5678):
    udp = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 7, 0, 64, 17, 0,
                     bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]))
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    return bytes.fromhex('0a0000000002' '0a0000000001' '0800') + ip + udp

def hdr(ver, typ, body=b'', xid=1, length=None):
    return struct.pack('!BBHI', ver, typ, 8 + len(body) if length is None else length, xid) + body

def pad(n):
    return b'\0' * n

def pad8(b):
    return b + b'\0' * (-len(b) % 8)

def s(name, n):
    return name.encode().ljust(n, b'\0')[:n]

def mac(i):
    return bytes([2, 0, 0, 0, 0, i & 0xff])

def hello(ver):
    if ver == 1:
        return hdr(1, 0, b'', xid=1)
    # version bitmap element: versions 1.0, 1.3, 1.4, 1.5
    bm = struct.pack('!HHI', 1, 8, (1 << 1) | (1 << 4) | (1 << 5) | (1 << 6))
    return hdr(ver, 0, bm + pad(0), xid=1)

def echo(ver, data=b'ping', typ=2, xid=2):
    return hdr(ver, typ, data, xid=xid)

def build():
    pc = Pcap()
    # TCP 6653: one connection per version, then all four in one stream
    for ver, sp in ((1, 40001), (4, 40004), (5, 40005), (6, 40006)):
        f = Flow(pc, sport=sp)
        f.send(True, hello(ver))
        f.send(False, hello(ver))
        f.send(False, echo(ver))
        f.send(True, echo(ver, typ=3))
        f.send(True, hdr(ver, 5, xid=3), hdr(ver, 18 if ver == 1 else 20, xid=3))
    # versions OpenFlow dissects but does not decode: 1.1, 1.2 and nonsense
    f = Flow(pc, sport=40010)
    for ver in (2, 3, 0, 7, 0x84):
        f.send(True, hdr(ver, 0, b'', xid=9))
    # several versions in one stream and in one segment, split messages
    f = Flow(pc, sport=40011)
    f.send(True, echo(1), echo(4), echo(5), echo(6))
    f.send(False, echo(6, b'x' * 40), split=[5])
    f.send(False, echo(4, b'y' * 60), echo(5, b'z' * 10), split=[3, 70])
    f.send(True, echo(1, b'a'), echo(2, b'b'), echo(3, b'c'))
    # legacy ports are found by the heuristic (first packet to 6633/6634)
    f = Flow(pc, sport=40012, dport=6633)
    f.send(True, hello(4))
    f.send(False, hello(4))
    f.send(True, echo(4))
    f.send(False, echo(4, typ=3))
    f = Flow(pc, sport=40013, dport=6634)
    f.send(True, hello(1))
    f.send(False, hello(1))
    f.send(True, echo(1, b'hi'))
    f = Flow(pc, sport=40014, dport=6633)
    f.send(True, hello(6))
    f.send(True, hello(5))
    # a port that is not OpenFlow: not claimed by the heuristic
    f = Flow(pc, sport=40015, dport=9999)
    f.send(True, hello(4))
    f.send(True, echo(1))
    # Exported PDU to the openflow dissector itself
    pc.epdu('openflow', echo(4, b'epdu'))
    pc.epdu('openflow', echo(1) + echo(5, b'two'))
    pc.epdu('openflow', hdr(2, 0))
    pc.write(os.path.join(OUT, 'openflow-coverage.pcapng'))

def build_mal():
    pc = Pcap()
    f = Flow(pc, sport=41000)
    f.send(True, hdr(4, 2, b'ab', length=6))      # length below the header
    f.send(True, hdr(4, 2, b'', length=0))
    f.send(True, hdr(1, 2, b'', length=7))
    f.send(True, b'\x04\x02\x00')                 # fragment of a header, never completed
    f = Flow(pc, sport=41001)
    f.send(True, b'\x04\x02\xff\xff' + pad(4))     # a 64 KiB PDU that never completes
    f = Flow(pc, sport=41002, dport=6633)
    f.send(True, hdr(1, 2, b'abcdefgh', length=40))
    pc.write(os.path.join(OUT, 'openflow-coverage-malformed.pcapng'))

if __name__ == '__main__':
    OUT = sys.argv[1] if len(sys.argv) > 1 else '.'
    build()
    build_mal()
