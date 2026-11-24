#!/usr/bin/env python3
# Generates test/captures/opus_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the Opus coverage captures: mkopus.py <outdir>.
Opus is reached the way a call reaches it: a SIP INVITE with SDP names
"opus/48000/2" for payload type 96, and the RTP stream that follows is
dissected as Opus. Includes the reproducers of "Opus: Read the second VBR
size byte correctly, widen frame sizes"."""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import struct
from wslib import pcap, pcapng, udp, exported_pdu, gz

CLI, SRV = '192.0.2.1', '192.0.2.2'
SSRC = 0x11223344

def sdp(port):
    return ('v=0\r\no=- 1 1 IN IP4 %s\r\ns=-\r\nc=IN IP4 %s\r\nt=0 0\r\n'
            'm=audio %d RTP/AVP 96\r\na=rtpmap:96 opus/48000/2\r\n'
            'a=fmtp:96 minptime=10;useinbandfec=1\r\n' % (CLI, CLI, port)).encode()

def sip(method, body, cseq):
    hdr = ('%s sip:bob@example.com SIP/2.0\r\nVia: SIP/2.0/UDP %s:5060;branch=z9hG4bK1\r\n'
           'From: <sip:alice@example.com>;tag=1\r\nTo: <sip:bob@example.com>\r\n'
           'Call-ID: opus-1@example.com\r\nCSeq: %d %s\r\nContent-Type: application/sdp\r\n'
           'Content-Length: %d\r\n\r\n' % (method, CLI, cseq, method, len(body)))
    return hdr.encode() + body

def sip_ok(body):
    hdr = ('SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP %s:5060;branch=z9hG4bK1\r\n'
           'From: <sip:alice@example.com>;tag=1\r\nTo: <sip:bob@example.com>;tag=2\r\n'
           'Call-ID: opus-1@example.com\r\nCSeq: 1 INVITE\r\nContent-Type: application/sdp\r\n'
           'Content-Length: %d\r\n\r\n' % (CLI, len(body)))
    return hdr.encode() + body

class Rtp:
    def __init__(self, sport=40000, dport=40002, ssrc=SSRC, pt=96):
        self.seq, self.ts, self.sport, self.dport, self.ssrc, self.pt = 100, 1000, sport, dport, ssrc, pt
    def pkt(self, payload):
        self.seq += 1
        self.ts += 960
        r = struct.pack('!BBHII', 0x80, self.pt, self.seq, self.ts, self.ssrc) + payload
        return udp(r, CLI, self.sport, SRV, self.dport)

def toc(config, stereo, code):
    return bytes([(config << 3) | (stereo << 2) | code])

def vbr_size(n):
    """Opus size field: one byte below 252, otherwise two bytes."""
    if n < 252:
        return bytes([n])
    b0 = 252 + (n & 3)
    return bytes([b0, (n - b0) // 4])

def pad_len(n):
    """Padding length bytes for n additional padding octets (RFC 6716)."""
    out = b''
    while n > 254:
        out += b'\xff'
        n -= 254
    return out + bytes([n])

def payloads():
    p = []
    # code 0 for the SILK, hybrid and CELT configs, mono and stereo
    for cfg in range(32):
        p.append(toc(cfg, cfg & 1, 0) + bytes([cfg]) * (10 + cfg))
    p.append(toc(31, 1, 0))                                   # DTX: no frame data
    p.append(toc(31, 0, 0) + b'\x77' * 1275)                  # largest frame
    # code 1, two CBR frames
    p.append(toc(1, 0, 1) + b'\x11' * 20)
    p.append(toc(19, 1, 1) + b'')
    # code 2, two VBR frames: one and two byte size fields
    p.append(toc(5, 0, 2) + vbr_size(10) + b'\x22' * 10 + b'\x23' * 7)
    p.append(toc(5, 0, 2) + vbr_size(251) + b'\x22' * 251 + b'\x23' * 3)
    p.append(toc(5, 0, 2) + vbr_size(252) + b'\x22' * 252 + b'\x23' * 3)
    p.append(toc(5, 0, 2) + vbr_size(700) + b'\x22' * 700 + b'\x23')
    p.append(toc(5, 0, 2) + vbr_size(2) + b'\x22' * 2 + b'\x23' * 1300)   # the last frame is not size checked
    # code 3 CBR, different frame counts and configs
    p.append(toc(1, 0, 3) + bytes([0x03]) + b'\x33' * 30)                  # 3 x 10, silk 20 ms
    p.append(toc(3, 0, 3) + bytes([0x02]) + b'\x33' * 40)                  # silk 60 ms x 2
    p.append(toc(13, 1, 3) + bytes([0x06]) + b'\x34' * 60)                 # hybrid 20 ms x 6
    p.append(toc(12, 1, 3) + bytes([0x0c]) + b'\x34' * 48)                 # hybrid 10 ms x 12 = 120 ms
    p.append(toc(16, 0, 3) + bytes([0x30]) + b'\x35' * 96)                 # celt 2.5 ms x 48
    p.append(toc(31, 0, 3) + bytes([0x01]) + b'\x36' * 11)                 # one frame
    # code 3 CBR with padding
    p.append(toc(1, 0, 3) + bytes([0x42]) + pad_len(5) + b'\x37' * 20 + bytes(5))
    p.append(toc(1, 0, 3) + bytes([0x42]) + pad_len(600) + b'\x37' * 20 + bytes(600))
    p.append(toc(1, 0, 3) + bytes([0x42]) + pad_len(3) + b'\x37' * 20 + b'\x00\x01\x00')   # non-zero padding
    p.append(toc(1, 0, 3) + bytes([0x42]) + pad_len(0) + b'\x37' * 20)
    # code 3 VBR
    p.append(toc(1, 0, 3) + bytes([0x83]) + vbr_size(5) + vbr_size(6) + b'\x38' * 5 + b'\x39' * 6 + b'\x3a' * 4)
    # S3 reproducer: size field 252,1 -> 256 octets; the old code read 252 twice (1260)
    p.append(bytes([0xfb, 0x82, 252, 1]) + b'\x22' * 256 + b'\x33' * 20)
    p.append(toc(1, 0, 3) + bytes([0x83]) + vbr_size(400) + vbr_size(300) + b'\x38' * 400 + b'\x39' * 300 + b'\x3a' * 8)
    p.append(toc(1, 0, 3) + bytes([0xc3]) + pad_len(4) + vbr_size(5) + vbr_size(6)
             + b'\x38' * 5 + b'\x39' * 6 + b'\x3a' * 2 + bytes(4))
    return p

def malformed():
    b = []
    # R1: empty packet, one-byte VBR size over the packet
    b.append(b'')
    b.append(toc(5, 0, 2) + bytes([200]) + b'\x01' * 5)
    b.append(toc(5, 0, 2) + bytes([253]))                                   # size field needs a second octet
    b.append(toc(5, 0, 2) + vbr_size(700) + b'\x22' * 700)              # empty last frame: the frame item is out of bounds
    # R3: code 1 with an odd length
    b.append(toc(1, 0, 1) + b'\x11' * 7)
    # R4: code 2 without data
    b.append(toc(5, 0, 2))
    # R5: frame count 0 and too many frames (60 ms x 10 > 5760 samples)
    b.append(toc(3, 0, 3) + bytes([0x00]) + b'\x33' * 4)
    b.append(toc(3, 0, 3) + bytes([0x0a]) + b'\x33' * 40)
    # R6: code 3 without the frame count octet; CBR not divisible
    b.append(toc(1, 0, 3))
    b.append(toc(1, 0, 3) + bytes([0x03]) + b'\x33' * 31)
    b.append(toc(1, 0, 3) + bytes([0x42]) + pad_len(30) + b'\x33' * 4)      # padding larger than the packet: negative CBR
    # R7: padding length octets run out, VBR sizes run out, VBR frames exceed the packet
    b.append(toc(1, 0, 3) + bytes([0x43]) + b'\xff\xff')
    b.append(toc(1, 0, 3) + bytes([0x84]))
    b.append(toc(1, 0, 3) + bytes([0x83]) + vbr_size(3) + vbr_size(4) + b'\x38' * 5)
    b.append(toc(1, 0, 3) + bytes([0x83]) + vbr_size(3) + bytes([9]) + b'\x38' * 3)
    # R2: frames over 1275 octets
    b.append(toc(31, 0, 0) + b'\x77' * 1276)
    b.append(toc(1, 0, 3) + bytes([0x82]) + vbr_size(5) + b'\x22' * 5 + b'\x23' * 1300)
    b.append(toc(1, 0, 3) + bytes([0x02]) + b'\x33' * 2800)
    b.append(toc(1, 0, 1) + b'\x33' * 2800)
    # S2 reproducer (a 40000 octet packet): R2 error, dissector must not throw
    b.append(bytes([0xf8]) + b'\x11' * 39999)
    return b

def main(out):
    fr = []
    fr.append(udp(sip('INVITE', sdp(40000), 1), CLI, 5060, SRV, 5060))
    fr.append(udp(sip_ok(sdp(40002)), SRV, 5060, CLI, 5060))
    r1 = Rtp(40000, 40002)
    r2 = Rtp(40002, 40000, ssrc=0x55667788)
    for i, pl in enumerate(payloads()):
        fr.append((r1 if i % 3 else r2).pkt(pl))
    pcap(os.path.join(out, 'opus-coverage.pcap'), fr)
    gz(os.path.join(out, 'opus-coverage.pcap'))
    # malformed capture: same SIP/SDP set-up, then the bad payloads
    mf = fr[:2]
    r = Rtp(40000, 40002)
    for pl in malformed():
        mf.append(r.pkt(pl))
    mf.append(exported_pdu('opus', b''))        # no TOC octet: R1 (reached only without a tree)
    mf.append(exported_pdu('opus', b'\xf8' + b'\x11' * 20))
    pcapng(os.path.join(out, 'opus-coverage-malformed.pcapng'), mf)

if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')
