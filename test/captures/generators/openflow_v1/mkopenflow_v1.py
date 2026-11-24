#!/usr/bin/env python3
# Generates test/captures/openflow_v1_coverage.pcapng.gz
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

def ofp_match(wild=0x3fffff, in_port=1, ethsrc=None, ethdst=None, vlan=0xffff, pcp=0, dltype=0x0800,
              tos=0, proto=17, nwsrc=0x0a000001, nwdst=0x0a000002, tpsrc=1234, tpdst=5678):
    return (struct.pack('!IH', wild, in_port) + (ethsrc or mac(1)) + (ethdst or mac(2)) +
            struct.pack('!HBxHBB2xIIHH', vlan, pcp, dltype, tos, proto, nwsrc, nwdst, tpsrc, tpdst))

def phy_port(n, cfg=0, state=0, curr=0x0fff):
    return (struct.pack('!H', n) + mac(n) + s('eth%d' % n, 16) +
            struct.pack('!IIIIII', cfg, state, curr, 0x0fff, 0x0fff, 0x0fff))

def action_out(port=1, maxlen=128):
    return struct.pack('!HHHH', 0, 8, port, maxlen)

def action_other(typ=1, ln=8):
    return struct.pack('!HH', typ, ln) + pad(ln - 4)

V = 1
def m(typ, body=b'', **kw):
    return hdr(V, typ, body, **kw)

def build():
    pc = Pcap()
    f = Flow(pc)
    # Handshake and the immutable messages
    f.send(True, m(0, xid=1))
    f.send(False, m(0, xid=1))
    f.send(False, m(2, b'ping', xid=2), m(3, b'ping', xid=2))
    f.send(True, m(1, struct.pack('!HH', 1, 1) + b'bad'), m(4, b'\0\0\0\x01vendor'))
    f.send(False, m(5, xid=3))
    caps = 0x7f
    acts = 0xfff
    feat = (struct.pack('!Q', 0x0001020304050607) + struct.pack('!IB3xII', 256, 2, caps, acts) +
            phy_port(1, cfg=0x7f, state=1, curr=0x7ff) + phy_port(2, curr=0x0fff))
    f.send(True, m(6, feat, xid=3))
    # no ports
    f.send(True, m(6, feat[:24], xid=3))
    # partial port (length 32 + 48 + 10)
    f.send(True, m(6, feat[:24] + phy_port(3) + b'0123456789'))
    f.send(False, m(7, xid=4))
    f.send(True, m(8, struct.pack('!HH', 0, 128), xid=4))
    f.send(False, m(9, struct.pack('!HH', 1, 0xffff), xid=5))
    # packet in
    pkt = eth_ip_udp()
    for reason in (0, 1, 2):
        f.send(True, m(10, struct.pack('!IHHBx', 0xffffffff if reason == 0 else 77, len(pkt), 3, reason) + pkt))
    # flow removed
    for reason in (0, 1, 2):
        f.send(True, m(11, ofp_match() + struct.pack('!QHBxIIH2xQQ', 0x1122334455667788, 100, reason, 10, 500, 30, 1000, 64000)))
    f.send(True, m(12, struct.pack('!B7x', 0) + phy_port(1)))
    f.send(True, m(12, b''))        # no body, length 8: no expert info
    # packet out
    f.send(False, m(13, struct.pack('!IHH', 0xffffffff, 0xfffd, 8) + action_out(2) + pkt))
    f.send(False, m(13, struct.pack('!IHH', 5, 1, 8) + action_out(0xfffb, 0)))
    f.send(False, m(13, struct.pack('!IHH', 5, 1, 8) + action_other(1, 8)))
    # flow mod
    for cmd in range(5):
        f.send(False, m(14, ofp_match() + struct.pack('!QHHHHIHH', 0xdead0000 + cmd, cmd, 10, 20, 100, 0xffffffff, 0xffff, 1) + action_out(3)))
    f.send(False, m(14, ofp_match(wild=0, in_port=7, vlan=100, pcp=3, dltype=0x0806, tos=0x2c, proto=1) +
                    struct.pack('!QHHHHIHH', 1, 0, 0, 0, 1, 1, 2, 0) + action_other(5, 16)))
    f.send(False, m(15, struct.pack('!H', 1) + mac(1) + struct.pack('!IIII4x', 0, 0, 0, 0)))   # port mod: default
    # stats requests
    f.send(False, m(16, struct.pack('!HH', 0, 0)))
    f.send(False, m(16, struct.pack('!HH', 1, 0) + ofp_match() + struct.pack('!BxH', 0xff, 0xffff)))
    for t in (2, 3, 4, 5, 0xffff):
        f.send(False, m(16, struct.pack('!HH', t, 0) + pad(8)))
    # stats replies
    f.send(True, m(17, struct.pack('!HH', 0, 0)))         # length 12: no body
    f.send(True, m(17, struct.pack('!HH', 0, 0) + s('mfr', 256) + s('hw', 256) + s('sw', 256) + s('1234', 32) + s('dp', 256)))
    f.send(True, m(17, struct.pack('!HH', 1, 1) + pad(88)))
    f.send(True, m(17, struct.pack('!HH', 3, 0) + pad(64)))
    f.send(True, m(17, struct.pack('!HH', 0, 0)[:4]))
    # remaining unknown types
    f.send(False, m(18), m(19))
    f.send(False, m(20, struct.pack('!H2x', 1)))
    f.send(True, m(21, struct.pack('!H2x', 1)))
    # message split over two segments, and two messages in one segment
    f.send(True, m(10, struct.pack('!IHHBx', 9, len(pkt), 3, 0) + pkt), split=[10])
    f.send(False, m(2, b'a'), m(3, b'b'), m(2, b'cdef'))
    # Exported PDU: the fixed features reply length wrap. The header length
    # (20) is shorter than the data that follows it
    pc.epdu('openflow_v1', m(6, feat[:16 + 8], length=20) + pad(80))
    pc.epdu('openflow_v1', m(6, feat, length=8 + 24 + 48))
    pc.epdu('openflow_v1', m(10, struct.pack('!IHHBx', 5, len(pkt), 3, 0) + pkt))
    pc.write(os.path.join(OUT, 'openflow_v1-coverage.pcapng'))

def build_mal():
    pc = Pcap()
    f = Flow(pc)
    # reproducer of the fixed length wrap: features reply shorter than 32 bytes
    f.send(True, m(6, struct.pack('!Q', 1) + pad(4)))
    f.send(True, m(6, struct.pack('!Q', 1) + pad(12), length=20))
    f.send(True, m(6, struct.pack('!Q', 1) + pad(12)))
    # truncated bodies
    f.send(True, m(10, b'\0\0'))
    f.send(True, m(11, pad(10)))
    f.send(True, m(13, struct.pack('!IHH', 5, 1, 8)))
    f.send(True, m(14, pad(10)))
    f.send(True, m(16, b'\0'))
    f.send(True, m(17, b'\0\0'))
    f.send(True, m(8, b'\0'))
    # unknown action in packet out whose length goes backwards
    f.send(True, m(13, struct.pack('!IHH', 5, 1, 8) + struct.pack('!HH', 1, 0) + pad(8)))
    f.send(True, m(13, struct.pack('!IHH', 0xffffffff, 1, 8) + struct.pack('!HH', 1, 2) + pad(8)))
    f.send(True, m(12, pad(2)))
    # short header lengths (tcp_dissect_pdus rejects them)
    f.send(True, hdr(1, 5, b'', length=4))
    pc.write(os.path.join(OUT, 'openflow_v1-coverage-malformed.pcapng'))

if __name__ == '__main__':
    OUT = sys.argv[1] if len(sys.argv) > 1 else '.'
    build()
    build_mal()
