#!/usr/bin/env python3
# Generates test/captures/evrc_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the EVRC dissector
(packet-evrc.c).

EVRC payloads (RFC 3558 header format for EVRC, EVRC-B, EVRC-WB, EVRC-NW
and EVRC-NW2K, and the legacy draft-ietf-avt-evrc-07 format on static
payload type 60) are carried in RTP. A SIP INVITE with SDP media lines
(a=rtpmap EVRC, EVRCB, EVRCWB, EVRCNW, EVRCNW2K) makes Wireshark decode
the RTP streams on ports 20000-20008 as the variants. The legacy format
is registered only for payload type 60 and only with the preference
evrc.legacy_pt_60, so its frames (port 20010) are plain RTP at default
preferences. Every packet is built from scratch with struct.

Usage: mkevrc.py <output directory>

Writes:
  evrc-coverage.pcap            SIP/SDP and RTP packets of every variant:
                                every frame type, 1 to 32 frames per
                                packet, odd and even ToC, every mode
                                request, the legacy ToC with the reduced
                                rate bit
  evrc-coverage-malformed.pcap  truncated ToC / data, empty payloads
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

SIZES = {1: 2, 2: 5, 3: 10, 4: 22}


def data(n, seed):
    return bytes((seed + 7 * i) & 0xff for i in range(n))


def rfc(first, mode, types, count=None, trunc_data=None, trunc_toc=None):
    """RFC 3558 payload: first octet (reserved/interleave), mode+count
    octet, packed ToC, then speech data of the sizes the ToC gives."""
    if count is None:
        count = len(types) - 1
    p = bytes([first, (mode << 5) | count])
    toc = b''
    for i in range(0, len(types), 2):
        hi = types[i]
        lo = types[i + 1] if i + 1 < len(types) else 0
        toc += bytes([(hi << 4) | lo])
    if trunc_toc is not None:
        toc = toc[:trunc_toc]
    p += toc
    body = b''.join(data(SIZES.get(t, 0), 0x10 * k) for k, t in enumerate(types))
    if trunc_data is not None:
        body = body[:trunc_data]
    return p + body


def legacy(first, tocs, datalens=None):
    p = bytes([first]) + bytes(tocs)
    if datalens is None:
        datalens = []
        for t in tocs:
            datalens.append(SIZES.get(t & 0x3f, 0))
    return p + b''.join(data(n, 0x20 + k) for k, n in enumerate(datalens))


def variant_frames(r, first, nw2k=False):
    F = []
    # first octet: reserved/enc cap bits (high), interleave length (0x38),
    # index (0x07)
    F.append(r.pkt(rfc(first, 0, [4])))                       # full rate
    F.append(r.pkt(rfc(first | 0x09, 1, [3, 1])))             # two frames
    F.append(r.pkt(rfc(first | 0x12, 2, [4, 0, 5])))          # odd count
    F.append(r.pkt(rfc(first | 0x1b, 3, [2, 1, 3, 4])))       # 1/4 rate
    F.append(r.pkt(rfc(first, 4, [1])))                       # 1/8 rate
    F.append(r.pkt(rfc(first, 5, [0])))                       # blank
    F.append(r.pkt(rfc(first, 6, [5, 5])))                    # erasures
    F.append(r.pkt(rfc(first | 0x3f, 7, [6, 7, 15, 3])))      # types not defined
    F.append(r.pkt(rfc(first, 0, [1] * 32)))                  # 32 frames
    F.append(r.pkt(rfc(first, 0, [3, 4], trunc_data=15)))     # data truncated
    return F


def main_frames():
    F = []
    F.append(sip_invite([(20000, 96, 'EVRC/8000', None),
                         (20002, 97, 'EVRCB/8000', None),
                         (20004, 98, 'EVRCWB/16000', None),
                         (20006, 99, 'EVRCNW/16000', None)]))
    # (SDP handling allows 4 media descriptions per message)
    F.append(sip_invite([(20008, 100, 'EVRCNW2K/16000', None),
                         (20010, 60, None, None)], cid=2))
    r = Rtp(20000, 96)
    F += variant_frames(r, 0x40)
    r = Rtp(20002, 97)
    F += variant_frames(r, 0x40)
    r = Rtp(20004, 98)
    F += variant_frames(r, 0x80)
    r = Rtp(20006, 99)
    F += variant_frames(r, 0xc0)
    r = Rtp(20008, 100)
    # NW2K: bit 0x80 reserved, bit 0x40 encoding capability
    F += variant_frames(r, 0x40)
    F.append(r.pkt(rfc(0x80, 7, [4, 3])))
    F.append(r.pkt(rfc(0xc0, 2, [4])))
    # every mode request value of the variants
    for port, pt in ((20000, 96), (20002, 97), (20004, 98), (20006, 99), (20008, 100)):
        rr = Rtp(port, pt, 0x2000 + port)
        for m in range(8):
            F.append(rr.pkt(rfc(0x00, m, [1, 0])))
    # legacy format, payload type 60
    r = Rtp(20010, 60)
    F.append(r.pkt(legacy(0x00, [0x04])))                       # full rate
    F.append(r.pkt(legacy(0x1b, [0x83, 0x01])))                 # 1/2, 1/8
    F.append(r.pkt(legacy(0x0a, [0xc3, 0xc4, 0xc1, 0x0e])))     # reduced rate bit
    F.append(r.pkt(legacy(0x00, [0xc4, 0xce, 0x82, 0x02])))           # reduced rate, erasure, 1/4
    F.append(r.pkt(legacy(0x00, [0x84] * 32)))                  # 32 entries, more follow
    F.append(r.pkt(legacy(0x00, [0x80 | k for k in (0, 1, 3, 4, 14, 7)] + [0x00])))
    F.append(r.pkt(legacy(0x00, [0x04], [10])))                 # data short
    F.append(r.pkt(bytes([0x00])))                              # header only
    return F


def malformed_frames():
    F = []
    F.append(sip_invite([(20000, 96, 'EVRC/8000', None), (20010, 60, None, None)]))
    r = Rtp(20000, 96)
    F.append(r.pkt(bytes([0x00])))                  # missing mode/count octet
    F.append(r.pkt(rfc(0, 0, [1, 1, 1, 1], trunc_toc=1)))   # ToC cut short
    F.append(r.pkt(rfc(0, 0, [1, 1, 1, 1], trunc_toc=0)))   # no ToC
    r = Rtp(20010, 60)
    F.append(r.pkt(b'\x00' * 0))                    # empty payload
    F.append(r.pkt(bytes([0x00, 0x84])))            # more entries promised
    return F


def main():
    out = sys.argv[1]
    pcap(os.path.join(out, 'evrc-coverage.pcap'), main_frames())
    pcap(os.path.join(out, 'evrc-coverage-malformed.pcap'), malformed_frames())


main()
