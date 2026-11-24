#!/usr/bin/env python3
# Generates test/captures/mpeg1_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Builds the MPEG1 (RFC 2250 video payload) coverage captures. Usage: mkmpeg1.py <outdir> [-v]
import struct
import sys
import os

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def ip4(a):
    return bytes(int(x) for x in a.split('.'))

ETH = b'\x02\x00\x00\x00\x00\x02' + b'\x02\x00\x00\x00\x00\x01'

def ethip(proto, payload, src, dst, ident=1):
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0, 64, proto, 0, ip4(src), ip4(dst))
    ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
    return ETH + b'\x08\x00' + ip + payload

def udp(payload, sport, dport, src='192.0.2.1', dst='192.0.2.2'):
    u = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    return ethip(17, u, src, dst)

def tcp(payload, sport, dport, seq, ack, flags=0x18, src='192.0.2.1', dst='192.0.2.2'):
    t = struct.pack('>HHIIBBHHH', sport, dport, seq & 0xffffffff, ack & 0xffffffff, 0x50, flags, 65535, 0, 0) + payload
    pseudo = ip4(src) + ip4(dst) + struct.pack('>BBH', 0, 6, len(t))
    c = csum(pseudo + t)
    t = t[:16] + struct.pack('>H', c) + t[18:]
    return ethip(6, t, src, dst)

def exp_pdu(name, payload, extra=b''):
    n = name.encode()
    pad = (4 - len(n) % 4) % 4
    return struct.pack('>HH', 12, len(n) + pad) + n + b'\0' * pad + extra + struct.pack('>HH', 0, 0) + payload

def rtp(pt, seq, ts, payload, ssrc=0x11223344, marker=0):
    return struct.pack('>BBHII', 0x80, (marker << 7) | pt, seq & 0xffff, ts & 0xffffffff, ssrc) + payload

class Cap:
    """pcapng writer with interface 0 = Ethernet, 1 = Exported PDU (252)."""
    def __init__(self):
        self.frames = []
    def eth(self, data, note=None):
        self.frames.append((1, data)); return len(self.frames)
    def epdu(self, name, payload, extra=b''):
        self.frames.append((252, exp_pdu(name, payload, extra))); return len(self.frames)
    def write(self, fname):
        def blk(t, body):
            body += b'\0' * ((4 - len(body) % 4) % 4)
            return struct.pack('<II', t, len(body) + 12) + body + struct.pack('<I', len(body) + 12)
        out = blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
        out += blk(1, struct.pack('<HHI', 1, 0, 0))
        out += blk(1, struct.pack('<HHI', 252, 0, 0))
        for i, (lt, d) in enumerate(self.frames):
            out += blk(6, struct.pack('<IIIII', 0 if lt == 1 else 1, 0, 1000 + i, len(d), len(d)) + d)
        open(fname, 'wb').write(out)

def pcap(fname, linktype, pkts):
    with open(fname, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, p in enumerate(pkts):
            f.write(struct.pack('<IIII', 1000 + i, 0, len(p), len(p)) + p)

def main(out, verbose):
    sip = ('INVITE sip:bob@192.0.2.2 SIP/2.0\r\nVia: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1\r\n'
           'From: <sip:alice@192.0.2.1>;tag=1\r\nTo: <sip:bob@192.0.2.2>\r\nCall-ID: mpeg1@192.0.2.1\r\n'
           'CSeq: 1 INVITE\r\nContact: <sip:alice@192.0.2.1>\r\nContent-Type: application/sdp\r\n')
    sdp = ('v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=mpeg1\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\n'
           'm=video 5004 RTP/AVP 32\r\na=rtpmap:32 MPV/90000\r\n')
    sip += 'Content-Length: %d\r\n\r\n' % len(sdp) + sdp
    cap = Cap()
    cap.eth(udp(sip.encode(), 5060, 5060))
    first_rtp = len(cap.frames) + 1
    seq = 100
    # Header byte 0-1: MBZ(5) T(1) TR(10); byte 2: AN N S B E P(3); byte 3: FBV BFC(3) FFV FFC(3)
    cases = []
    # every picture type, every flag alone and together, T and TR extremes
    for p in range(8):
        cases.append((0x00, 0x01 + p, (0x80 >> 0) * 0 | p, 0x00))
    for bit in (0x80, 0x40, 0x20, 0x10, 0x08):
        cases.append((0x04, 0x05, bit | 1, 0x00))
    cases.append((0x04, 0x05, 0xff, 0xff))
    cases.append((0xfb, 0xff, 0x00, 0x00))   # MBZ set, TR 0x3ff
    cases.append((0x00, 0x00, 0x00, 0x00))
    cases.append((0x00, 0x2a, 0xa1, 0x7f))   # reproducer: AN=1 S=1 P=I
    for fbv in (0x80, 0x70, 0x08, 0x07):
        cases.append((0x00, 0x01, 0x21, fbv))
    for i, (b0, b1, b2, b3) in enumerate(cases):
        pl = bytes([b0, b1, b2, b3]) + bytes(range(i, i + 12))
        cap.eth(udp(rtp(32, seq, 90000 * i, pl), 5004, 5004)); seq += 1
    # larger slice payload with a marker bit
    cap.eth(udp(rtp(32, seq, 2, bytes([0, 2, 0x31, 0]) + bytes(200), marker=1), 5004, 5004)); seq += 1
    last_rtp = len(cap.frames)
    # Exported PDU entry
    ep = len(cap.frames) + 1
    cap.epdu('mpeg1', bytes([0x04, 0x05, 0xa1, 0x00]) + b'\0' * 8)
    cap.epdu('mpeg1', bytes([0x00, 0x01, 0x21, 0xf7]) + b'\xaa' * 4)
    cap.write(os.path.join(out, 'mpeg1-coverage.pcapng'))
    # malformed: truncated headers
    m = Cap()
    m.eth(udp(sip.encode(), 5060, 5060))
    for n in (0, 1, 2, 3, 4):
        m.epdu('mpeg1', bytes([0x04, 0x05, 0xa1, 0x00])[:n])
        m.eth(udp(rtp(32, 1 + n, 1, bytes([0x04, 0x05, 0xa1, 0x00])[:n]), 5004, 5004))
    m.write(os.path.join(out, 'mpeg1-coverage-malformed.pcapng'))
    if verbose:
        print('frames: 1 SIP; %d-%d RTP; %d-%d Exported PDU' % (first_rtp, last_rtp, ep, len(cap.frames)))

if __name__ == '__main__':
    main(sys.argv[1], '-v' in sys.argv)
