#!/usr/bin/env python3
# Generates test/captures/evs_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the EVS dissector
(packet-evs.c).

EVS (Enhanced Voice Services, 3GPP TS 26.445 Annex A) payloads are
carried in RTP. A SIP INVITE with SDP (a=rtpmap EVS/16000) makes
Wireshark decode the RTP streams as EVS; one stream has a=fmtp hf-only=1
(Header-Full format only, the sizes of the compact format are not
interpreted). Both framing modes are exercised: Compact (by payload
size) and Header-Full (CMR and ToC octets). Every packet is built from
scratch with struct.

Usage: mkevs.py <output directory>

Writes:
  evs-coverage.pcap            compact format of every payload size and
                               every bit layout, header-full with every
                               CMR type, both ToC modes, F bit chains,
                               RTP padding that changes the size, hf-only
  evs-coverage-malformed.pcap  header-full payloads cut short
"""
import os
import struct
import sys

# ---- packet helpers ----

def pcap(path, frames, linktype=1):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def udp4(sport, dport, payload, src=(192, 0, 2, 1), dst=(192, 0, 2, 10)):
    udp = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
                     bytes(src), bytes(dst))
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    return bytes.fromhex('020000000002020000000001') + b'\x08\x00' + ip + udp

def sip_invite(medias, cid=1):
    """medias: list of (port, pt, rtpmap or None, fmtp or None)."""
    sdp = 'v=0\r\no=- 1 1 IN IP4 192.0.2.10\r\ns=-\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\n'
    for port, pt, rtpmap, fmtp in medias:
        sdp += 'm=audio %d RTP/AVP %d\r\n' % (port, pt)
        if rtpmap:
            sdp += 'a=rtpmap:%d %s\r\n' % (pt, rtpmap)
        if fmtp:
            sdp += 'a=fmtp:%d %s\r\n' % (pt, fmtp)
    body = sdp.encode()
    hdr = ('INVITE sip:bob@192.0.2.10 SIP/2.0\r\n'
           'Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK776\r\n'
           'From: <sip:alice@192.0.2.1>;tag=1\r\nTo: <sip:bob@192.0.2.10>\r\n'
           'Call-ID: cov%d@192.0.2.1\r\nCSeq: 1 INVITE\r\n'
           'Contact: <sip:alice@192.0.2.1>\r\nMax-Forwards: 70\r\n'
           'Content-Type: application/sdp\r\nContent-Length: %d\r\n\r\n' % (cid, len(body)))
    return udp4(5060, 5060, hdr.encode() + body)

class Rtp:
    def __init__(self, port, pt, ssrc=0x11223344):
        self.port, self.pt, self.ssrc = port, pt, ssrc
        self.seq, self.ts = 100, 1000
    def pkt(self, payload, pad=0, marker=False):
        b0 = 0x80 | (0x20 if pad else 0)
        if pad:
            payload = payload + b'\0' * (pad - 1) + bytes([pad])
        h = struct.pack('!BBHII', b0, self.pt | (0x80 if marker else 0), self.seq, self.ts, self.ssrc)
        self.seq += 1
        self.ts += 160
        return udp4(30000 + self.port % 1000, self.port, h + payload)
# ---- end of helpers ----

# payload sizes (octets) of the compact format
COMPACT = [6, 7, 17, 18, 20, 23, 24, 32, 33, 36, 40, 41, 46, 50, 58, 60, 61, 80,
           120, 160, 240, 320]


def fill(n, first):
    """n octets starting with the octet 'first'."""
    return bytes([first]) + bytes((0x5a + 3 * i) & 0xff for i in range(1, n))


def compact_frames(r):
    F = []
    for n in COMPACT:
        if n == 7:
            F.append(r.pkt(fill(7, 0x00)))   # d(0) = 0: EVS Primary 2.8
            F.append(r.pkt(fill(7, 0x40)))   # d(0) = 0, PPP/NELP (bit 0 = 0, bandwidth)
            # d(0) = 1 is an AMR-WB IO SID, but the dissector does not treat
            # it as compact: CMR octet, one ToC octet (F = 0), 5 octets
            F.append(r.pkt(bytes([0x80, 0x29]) + fill(5, 0x31)))
            F.append(r.pkt(bytes([0xe0, 0x2a]) + fill(5, 0x32)))
        elif n == 6:
            F.append(r.pkt(fill(6, 0x00)))   # LP-CNG: type flag 0
            F.append(r.pkt(fill(6, 0x80)))   # FD-CNG
            F.append(r.pkt(fill(6, 0x40)))
            F.append(r.pkt(fill(6, 0xe0)))
        elif n == 61:
            for b in (0x00, 0x08, 0x18, 0x10):   # CELP / MDCT, HQ / TCX
                F.append(r.pkt(fill(61, b)))
        elif n == 80:
            for b in (0x00, 0x80, 0xc0, 0xe0, 0xa0):
                F.append(r.pkt(fill(80, b)))
        elif n == 160:
            for b in (0x00, 0x80, 0xa0, 0xc0, 0xe0):
                F.append(r.pkt(fill(160, b)))
        else:
            F.append(r.pkt(fill(n, 0x00)))
            F.append(r.pkt(fill(n, 0xf5)))
    return F


def hf_cmr(t, d):
    return bytes([0x80 | (t << 4) | d])


def toc(f, mode, q, rate):
    return bytes([(f << 6) | (mode << 5) | (q << 4) | rate])


def hf_frames(r):
    F = []
    # CMR + one ToC + data for each CMR type and sample D values
    for t in range(8):
        for d in (0, 5, 15):
            F.append(r.pkt(hf_cmr(t, d) + toc(0, 0, 0, 4) + fill(33, 0x11)))
    # ToC without CMR: mode 0, every rate value
    for rate in range(16):
        F.append(r.pkt(toc(0, 0, 0, rate) + fill(5 + rate, 0x22)))
    # ToC mode 1 (AMR-WB IO), Q bit 0 and 1, every rate value
    for rate in range(16):
        F.append(r.pkt(toc(0, 1, rate & 1, rate) + fill(17, 0x33)))
    # several frames in a packet (F bit chain)
    F.append(r.pkt(toc(1, 0, 0, 3) + toc(0, 0, 0, 3) + fill(20, 0x44)))
    F.append(r.pkt(hf_cmr(1, 2) + toc(1, 1, 1, 2) + toc(1, 0, 0, 1) + toc(0, 1, 0, 8) + fill(30, 0x55)))
    # ToC only, no speech data
    F.append(r.pkt(toc(0, 0, 0, 0xf)))
    F.append(r.pkt(hf_cmr(7, 15) + toc(0, 1, 0, 0xe)))
    # header-full packet of a size that is also a compact size
    # (decoded as compact unless hf-only)
    F.append(r.pkt(toc(0, 0, 0, 4) + fill(32, 0x66)))   # 33 octets
    return F


def main_frames():
    F = []
    F.append(sip_invite([(21000, 96, 'EVS/16000', None),
                         (21002, 97, 'EVS/16000', 'hf-only=1'),
                         (21004, 98, 'EVS/16000', 'hf-only=0')]))
    r = Rtp(21000, 96)
    F += compact_frames(r)
    F += hf_frames(r)
    # RTP padding (the padding length the dissector adds excludes the count octet): 5 octets + 1 = 6 (48 bits, SID 2.4 compact)
    F.append(r.pkt(fill(5, 0x00), pad=2))
    F.append(r.pkt(fill(16, 0x00), pad=3))   # 18 octets: EVS Primary 7.2
    F.append(r.pkt(toc(0, 0, 0, 1) + fill(3, 0x77), pad=4))
    # hf-only=1 in the SDP: the same sizes are Header-Full
    r = Rtp(21002, 97)
    for n in (6, 7, 17, 33, 61):
        F.append(r.pkt(toc(0, 0, 0, 4) + fill(n - 1, 0x01)))
    F.append(r.pkt(hf_cmr(0, 1) + toc(1, 1, 0, 2) + toc(0, 1, 0, 2) + fill(32, 0x88)))
    # hf-only=0 explicitly
    r = Rtp(21004, 98)
    F.append(r.pkt(fill(33, 0x00)))
    return F


def malformed_frames():
    F = []
    F.append(sip_invite([(21000, 96, 'EVS/16000', None)]))
    r = Rtp(21000, 96)
    F.append(r.pkt(fill(7, 0x80)))                      # a 56 bit AMR-WB IO SID: not compact, ToC runs off the end
    F.append(r.pkt(fill(7, 0xe0)))
    F.append(r.pkt(hf_cmr(1, 1)))                       # CMR only, no ToC
    F.append(r.pkt(toc(1, 0, 0, 3)))                    # F bit set, no next ToC
    F.append(r.pkt(toc(1, 0, 0, 3) + toc(1, 0, 0, 3)))
    F.append(r.pkt(b'\x00'))                            # 1 octet ToC
    return F


def main():
    out = sys.argv[1]
    pcap(os.path.join(out, 'evs-coverage.pcap'), main_frames())
    pcap(os.path.join(out, 'evs-coverage-malformed.pcap'), malformed_frames())


main()
