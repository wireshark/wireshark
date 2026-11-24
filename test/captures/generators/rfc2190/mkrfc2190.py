#!/usr/bin/env python3
# Generates test/captures/rfc2190_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generator of the RFC 2190 (H.263 RTP payload header) coverage captures
(packet-rfc2190.c).

Usage: mkrfc2190.py [-v] [outdir]   (writes rfc2190-coverage.pcapng and
rfc2190-coverage-malformed.pcapng, built with struct only).

RFC 2190 is reached by default through RTP payload type 34 (a SIP INVITE
whose SDP puts the static payload type on a UDP port opens the RTP
conversation) and through IAX2 video frames with the H.263 codec. The main
capture has two interfaces (Ethernet and Exported PDU, link type 252); the
Exported PDU frames name the registered dissector "rfc2190" and are the
reproducers of the fixed header length. Nothing comes from a real network.
"""
# ---- classic pcap / pcapng writers and Ethernet/IPv4/UDP helpers ----
import struct
import sys
import os

def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

class Cap:
    """Frames of one or more interfaces; written as pcap (one link type) or pcapng."""
    def __init__(self, linktype=1, snaplen=262144):
        self.links = [linktype]; self.snap = snaplen
        self.frames = []; self.ts = 1700000000.0; self.ipid = 1
    def iface(self, linktype):
        self.links.append(linktype); return len(self.links) - 1
    def raw(self, data, iface=0):
        self.frames.append((self.ts, bytes(data), iface)); self.ts += 0.01
        return len(self.frames)
    def ip(self, src, dst, proto, payload):
        self.ipid += 1
        h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), self.ipid, 0, 64, proto, 0,
                        bytes(map(int, src.split('.'))), bytes(map(int, dst.split('.'))))
        h = h[:10] + struct.pack('!H', csum(h)) + h[12:]
        return h + payload
    def eth(self, ipkt, s=b'\x02\0\0\0\0\x01', d=b'\x02\0\0\0\0\x02', et=0x0800):
        return d + s + struct.pack('!H', et) + ipkt
    def udp(self, src, dst, sp, dp, payload, iface=0):
        u = struct.pack('!HHHH', sp, dp, 8 + len(payload), 0) + payload
        return self.raw(self.eth(self.ip(src, dst, 17, u)), iface)
    def write(self, path):
        if len(self.links) == 1:
            with open(path, 'wb') as f:
                f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, self.snap, self.links[0]))
                for ts, d, _ in self.frames:
                    f.write(struct.pack('<IIII', int(ts), int((ts % 1) * 1e6), len(d), len(d)) + d)
        else:
            def blk(t, body):
                body += b'\0' * ((-len(body)) % 4)
                return struct.pack('<II', t, len(body) + 12) + body + struct.pack('<I', len(body) + 12)
            out = blk(0x0a0d0d0a, struct.pack('<IHHq', 0x1a2b3c4d, 1, 0, -1))
            for lt in self.links:
                out += blk(1, struct.pack('<HHI', lt, 0, self.snap))
            for ts, d, i in self.frames:
                t = int(ts * 1e6)
                out += blk(6, struct.pack('<IIIII', i, t >> 32, t & 0xffffffff, len(d), len(d)) + d)
            open(path, 'wb').write(out)

A, B = '192.0.2.10', '192.0.2.20'

def sip(body, call='c11call'):
    h = ('INVITE sip:bob@192.0.2.20 SIP/2.0\r\nVia: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK%s\r\n'
         'From: <sip:alice@192.0.2.10>;tag=1\r\nTo: <sip:bob@192.0.2.20>\r\nCall-ID: %s\r\nCSeq: 1 INVITE\r\n'
         'Contact: <sip:alice@192.0.2.10>\r\nContent-Type: application/sdp\r\nContent-Length: %d\r\n\r\n'
         % (call, call, len(body)))
    return h.encode() + body

def sdp(port, pt, rtpmap=None, media='video'):
    s = ('v=0\r\no=- 1 1 IN IP4 192.0.2.10\r\ns=-\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\n'
         'm=%s %d RTP/AVP %d\r\n' % (media, port, pt))
    if rtpmap:
        s += 'a=rtpmap:%d %s\r\n' % (pt, rtpmap)
    return s.encode()

_seq = [100]
def rtp(payload, pt, marker=0):
    _seq[0] += 1
    return struct.pack('!BBHII', 0x80, (marker << 7) | pt, _seq[0], _seq[0] * 3000, 0x1234) + payload

def exp_pdu(name, payload):
    """Exported PDU (link type 252) naming a registered dissector (tags padded to 4)."""
    n = name.encode(); pad = (-len(n)) % 4
    return struct.pack('!HH', 12, len(n) + pad) + n + b'\0' * pad + struct.pack('!HH', 0, 0) + payload

# ---- RFC 2190 headers ----
def hdr_a(f=0, p=0, sbit=0, ebit=0, src=2, i=0, u=0, s=0, a=0, r=0, dbq=0, trb=0, tr=7):
    """Mode A (F=0): 4 octets. r is the 4 reserved bits (1 bit in octet 2, 3 bits in octet 3)."""
    return bytes([(f << 7) | (p << 6) | (sbit << 3) | ebit,
                  (src << 5) | (i << 4) | (u << 3) | (s << 2) | (a << 1) | ((r >> 3) & 1),
                  ((r & 7) << 5) | (dbq << 3) | trb, tr])

def hdr_b(sbit=0, ebit=0, src=2, quant=10, gobn=3, mba=100, r=0, i=0, u=0, s=0, a=0,
          hmv1=0, vmv1=0, hmv2=0, vmv2=0):
    """Mode B (F=1, P=0): 8 octets."""
    return bytes([0x80 | (sbit << 3) | ebit, (src << 5) | quant,
                  (gobn << 3) | ((mba >> 6) & 7), ((mba & 0x3f) << 2) | r,
                  (i << 7) | (u << 6) | (s << 5) | (a << 4) | ((hmv1 >> 3) & 0xf),
                  ((hmv1 & 7) << 5) | ((vmv1 >> 2) & 0x1f),
                  ((vmv1 & 3) << 6) | ((hmv2 >> 1) & 0x3f),
                  ((hmv2 & 1) << 7) | vmv2])

def hdr_c(rr=0, dbq=0, trb=0, tr=9, **kw):
    """Mode C (F=1, P=1): 12 octets (mode B header with P set + 4 octets)."""
    b = bytearray(hdr_b(**kw)); b[0] |= 0x40
    return bytes(b) + bytes([(rr >> 11) & 0xff, (rr >> 3) & 0xff, ((rr & 7) << 5) | (dbq << 3) | trb, tr])

# a small H.263 picture: picture start code, TR, PTYPE (CIF), PQUANT
PSC = bytes([0x00, 0x00, 0x80, 0x02, 0x0a, 0x20, 0x00, 0x00])
GBSC = bytes([0x00, 0x00, 0x85, 0x40, 0x00])


# ---- main ----
def build(outdir, verbose=False):
    c = Cap(1)
    ex = c.iface(252)
    marks = []
    def mark(n): marks.append((len(c.frames) + 1, n))
    def send(payload, mk=0):
        c.udp(A, B, 5006, 5006, rtp(payload, 34, mk))
    mark('SIP INVITE with SDP: static payload type 34 (H.263) on UDP 5006')
    c.udp(A, B, 5060, 5060, sip(sdp(5006, 34, 'H263/90000'), call='c11rfc2190'))
    mark('mode A (F=0, P=0): SBIT/EBIT, source formats 1-7, I/U/S/A flags, DBQ, TRB, TR, reserved bits')
    send(hdr_a() + bytes(range(1, 21)))
    for src in range(1, 8):
        send(hdr_a(src=src, i=src & 1, tr=src * 30) + bytes([0x11, 0x22, 0x33, 0x44]))
    send(hdr_a(sbit=7, ebit=7, u=1, s=1, a=1, r=0xf, dbq=3, trb=7, tr=255) + bytes([0xaa] * 8))
    send(hdr_a(sbit=3, ebit=5, i=1, dbq=1, trb=2, tr=0) + bytes([0xaa] * 8))
    mark('mode A (F=0, P=1: header length 4), with a picture start code')
    send(hdr_a(p=1, tr=1) + PSC)
    send(hdr_a(p=1, sbit=1, ebit=1, u=1) + bytes([0x55] * 6))
    mark('mode A with an H.263 picture (PSC) and a GOB (GBSC)')
    send(hdr_a(tr=1, i=1) + PSC)
    send(hdr_a(tr=2) + GBSC)
    mark('mode B (F=1, P=0): QUANT, GOBN, MBA, motion vectors, flags, reserved bits')
    send(hdr_b() + bytes(range(1, 21)))
    send(hdr_b(sbit=1, ebit=2, src=3, quant=31, gobn=31, mba=511, r=3, i=1, u=1, s=1, a=1,
               hmv1=127, vmv1=127, hmv2=127, vmv2=127) + bytes([0x77] * 6))
    send(hdr_b(sbit=7, ebit=7, src=7, quant=1, gobn=1, mba=1, hmv1=1, vmv1=2, hmv2=3, vmv2=4) + bytes([0x77] * 6))
    send(hdr_b(src=1, quant=0, gobn=0, mba=0) + PSC)
    mark('mode C (F=1, P=1): PB-frames fields DBQ, TRB, TR and reserved bits')
    send(hdr_c() + bytes(range(1, 21)))
    send(hdr_c(rr=0x7ffff, dbq=3, trb=7, tr=250, sbit=2, ebit=5, src=5, quant=31, gobn=17, mba=300,
               i=1, u=1, s=1, a=1, hmv1=64, vmv1=65, hmv2=66, vmv2=67) + bytes([0x99] * 6))
    send(hdr_c(src=1) + PSC)
    mark('header followed by a single octet / by nothing')
    send(hdr_a() + b'\x01')
    send(hdr_a())
    send(hdr_b())
    send(hdr_c())
    mark('IAX2 video frames with the H.263 codec (UDP 4569, subclass 0x93)')
    def iax2_video(src, dst, ts, oseq, iseq, csub, payload):
        return struct.pack('!HHIBBBB', 0x8000 | src, dst, ts, oseq, iseq, 3, csub) + payload
    c.udp(A, B, 4569, 4569, iax2_video(0x1234, 1, 100, 1, 0, 0x80 | 19, hdr_a() + PSC))
    c.udp(A, B, 4569, 4569, iax2_video(0x1234, 1, 140, 2, 0, 0x80 | 19 | 0x40, hdr_b() + GBSC))
    mark('Exported PDU "rfc2190": the reproducers of the fixed header length (mode C and mode B followed by a PSC)')
    modeC = hdr_c(src=2) + PSC + b'\0' * 8
    modeB = hdr_b(src=2) + PSC + b'\0' * 8
    c.raw(exp_pdu('rfc2190', modeC), ex)
    c.raw(exp_pdu('rfc2190', modeB), ex)
    c.raw(exp_pdu('rfc2190', hdr_a(p=1) + PSC + b'\0' * 8), ex)
    c.write(os.path.join(outdir, 'rfc2190-coverage.pcapng'))
    n = len(c.frames)
    # malformed: header cut inside the bit fields / data missing
    m = Cap(1); mex = m.iface(252)
    m.udp(A, B, 5060, 5060, sip(sdp(5006, 34, 'H263/90000'), call='c11rfc2190'))
    for h in (hdr_a(), hdr_b(), hdr_c()):
        for cut in (1, 2, 3, 5, 9, 11):
            if cut < len(h):
                m.udp(A, B, 5006, 5006, rtp(h[:cut], 34))
    m.udp(A, B, 5006, 5006, rtp(b'', 34))
    for h in (hdr_a(), hdr_b(), hdr_c()):
        m.raw(exp_pdu('rfc2190', h[:len(h) - 1]), mex)
        m.raw(exp_pdu('rfc2190', h[:2]), mex)
    m.write(os.path.join(outdir, 'rfc2190-coverage-malformed.pcapng'))
    if verbose:
        for i, (f, nme) in enumerate(marks):
            e = marks[i + 1][0] - 1 if i + 1 < len(marks) else n
            print('%4d-%-4d %s' % (f, e, nme))
        print('main %d frames, malformed %d frames' % (n, len(m.frames)))

if __name__ == '__main__':
    build(sys.argv[1] if len(sys.argv) > 1 and sys.argv[1] != '-v' else '.', '-v' in sys.argv)
