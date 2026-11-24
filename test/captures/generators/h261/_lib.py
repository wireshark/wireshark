# Helper module for the h261 capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
import struct
import time

def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b)//2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

class Pcap:
    def __init__(self, linktype=1):
        self.frames = []; self.linktype = linktype
        self.seq = {}; self.ipid = 1; self.ts = 1700000000.0
    def raw(self, data):
        self.frames.append((self.ts, bytes(data))); self.ts += 0.01
    def ip(self, src, dst, proto, payload):
        self.ipid += 1
        h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20+len(payload), self.ipid, 0, 64, proto, 0,
                        bytes(map(int, src.split('.'))), bytes(map(int, dst.split('.'))))
        h = h[:10] + struct.pack('!H', csum(h)) + h[12:]
        return h + payload
    def eth(self, ipkt, s=b'\x02\0\0\0\0\x01', d=b'\x02\0\0\0\0\x02', et=0x0800):
        return d + s + struct.pack('!H', et) + ipkt
    def udp(self, src, dst, sp, dp, payload, ts=None):
        u = struct.pack('!HHHH', sp, dp, 8+len(payload), 0) + payload
        self.raw(self.eth(self.ip(src, dst, 17, u)))
    def tcp(self, src, dst, sp, dp, payload, flags=0x18, seq=None):
        k = (src, dst, sp, dp)
        if seq is None: seq = self.seq.get(k, 1000 + (sp * 7919 + dp) % 100000)
        self.seq[k] = seq + len(payload) + (1 if flags & 3 else 0)
        ack = self.seq.get((dst, src, dp, sp), 0)
        t = struct.pack('!HHIIBBHHH', sp, dp, seq, ack, 0x50, flags, 65535, 0, 0) + payload
        self.raw(self.eth(self.ip(src, dst, 6, t)))
    def write(self, path):
        with open(path, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, self.linktype))
            for ts, d in self.frames:
                f.write(struct.pack('<IIII', int(ts), int((ts % 1)*1e6), len(d), len(d)) + d)

# ---- helpers shared by the SIP/SDP + RTP based generators ----
A, B = '192.0.2.10', '192.0.2.20'

def sip(body, call='c23h26x'):
    h = ('INVITE sip:bob@192.0.2.20 SIP/2.0\r\nVia: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK%s\r\n'
         'From: <sip:alice@192.0.2.10>;tag=1\r\nTo: <sip:bob@192.0.2.20>\r\nCall-ID: %s\r\nCSeq: 1 INVITE\r\n'
         'Contact: <sip:alice@192.0.2.10>\r\nContent-Type: application/sdp\r\nContent-Length: %d\r\n\r\n'
         % (call, call, len(body)))
    return h.encode() + body

def sdp(port, pt, rtpmap=None, fmtp=None, media='video'):
    s = ('v=0\r\no=- 1 1 IN IP4 192.0.2.10\r\ns=-\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\n'
         'm=%s %d RTP/AVP %d\r\n' % (media, port, pt))
    if rtpmap:
        s += 'a=rtpmap:%d %s\r\n' % (pt, rtpmap)
    if fmtp:
        s += 'a=fmtp:%d %s\r\n' % (pt, fmtp)
    return s.encode()

_seq = [100]
def rtp(payload, pt, marker=0):
    _seq[0] += 1
    return struct.pack('!BBHII', 0x80, (marker << 7) | pt, _seq[0], _seq[0] * 3000, 0x1234) + payload
