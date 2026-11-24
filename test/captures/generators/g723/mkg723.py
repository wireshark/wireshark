#!/usr/bin/env python3
# Generates test/captures/g723_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Write g723-coverage.pcap: SIP/SDP call setup for RTP payload type 4
(G.723.1) followed by RTP packets carrying every frame type.
Usage: mkg723.py <outdir>"""
import os
import struct
import sys

A = bytes([192, 0, 2, 1])
B = bytes([192, 0, 2, 2])
MA = bytes.fromhex('020000000001')
MB = bytes.fromhex('020000000002')


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def udp(src, dst, sp, dp, payload, ident):
    u = struct.pack('!HHHH', sp, dp, 8 + len(payload), 0) + payload
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(u), ident, 0, 64, 17, 0, src, dst)
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    smac, dmac = (MA, MB) if src == A else (MB, MA)
    return dmac + smac + b'\x08\x00' + ip + u


def rtp(seq, ts, payload, pt=4, marker=0, ssrc=0x11223344):
    return struct.pack('!BBHII', 0x80, (marker << 7) | pt, seq, ts, ssrc) + payload


def sdp(addr, port, pt=4):
    return ('v=0\r\no=alice 1 1 IN IP4 %s\r\ns=-\r\nc=IN IP4 %s\r\nt=0 0\r\n'
            'm=audio %d RTP/AVP %d\r\na=rtpmap:%d G723/8000\r\na=fmtp:%d annexa=no\r\n'
            % (addr, addr, port, pt, pt, pt)).encode()


def sip(first, extra, body=b''):
    h = first + '\r\n' + 'Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1\r\n' \
        'From: <sip:alice@example.com>;tag=1\r\nTo: <sip:bob@example.com>\r\n' \
        'Call-ID: g723call@192.0.2.1\r\nCSeq: 1 INVITE\r\n' + extra
    if body:
        h += 'Content-Type: application/sdp\r\n'
    h += 'Content-Length: %d\r\n\r\n' % len(body)
    return h.encode() + body


pk = []
n = [0]


def add(src, dst, sp, dp, payload):
    n[0] += 1
    pk.append(udp(src, dst, sp, dp, payload, n[0]))


add(A, B, 5060, 5060, sip('INVITE sip:bob@example.com SIP/2.0', 'Contact: <sip:alice@192.0.2.1>\r\n',
                          sdp('192.0.2.1', 20000)))
add(B, A, 5060, 5060, sip('SIP/2.0 200 OK', 'Contact: <sip:bob@192.0.2.2>\r\n', sdp('192.0.2.2', 30000)))

# Frame types of RFC 3551: 24 octets (high rate, bits 00), 20 (low rate, 01),
# 4 (SID, 10) and a reserved frame (11)
frames = []
for i in range(4):
    frames.append(bytes([(i * 8 + 5) << 2 | 0]) + bytes((i + j) & 0xff for j in range(23)))
for i in range(3):
    frames.append(bytes([(i * 9 + 17) << 2 | 1]) + bytes((3 * i + j) & 0xff for j in range(19)))
frames.append(bytes([0x3f << 2 | 2]) + b'\x01\x02\x03')
frames.append(bytes([0x01 << 2 | 2]) + b'\x04\x05\x06')
frames.append(bytes([0x2a << 2 | 3]) + b'\x07\x08\x09')
frames.append(bytes([0x00]))                 # one octet: high rate, no more data
frames.append(bytes([0xfd]))                 # one octet: reserved, LPC 3f
seq = 100
for i, f in enumerate(frames):
    # both directions, each uses its own port
    add(A, B, 20000, 30000, rtp(seq + i, 160 * i, f, marker=1 if i == 0 else 0))
    if i % 3 == 0:
        add(B, A, 30000, 20000, rtp(seq + i, 160 * i, f[::-1] if len(f) > 1 else f, ssrc=0x55667788))
# A second call that offers PT 4 but with a different port pair
add(A, B, 5060, 5060, sip('INVITE sip:carol@example.com SIP/2.0', '', sdp('192.0.2.1', 20002)))
add(B, A, 5060, 5060, sip('SIP/2.0 200 OK', '', sdp('192.0.2.2', 30002)))
for i in range(3):
    add(A, B, 20002, 30002, rtp(i, 160 * i, frames[i]))

out = sys.argv[1]
os.makedirs(out, exist_ok=True)


def write(fn, recs):
    with open(os.path.join(out, fn), 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, r in enumerate(recs):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(r), len(r)) + r)


write('g723-coverage.pcap', pk)

# Malformed: truncated captures cannot be reached because the dissector
# reads one octet at most; an RTP packet with an empty payload is
# dissected by RTP only.
mal = [udp(A, B, 5060, 5060, sip('INVITE sip:bob@example.com SIP/2.0', 'Contact: <sip:alice@192.0.2.1>\r\n',
                                 sdp('192.0.2.1', 20010)), 1),
       udp(A, B, 20010, 30010, rtp(1, 0, b''), 2),
       udp(A, B, 20010, 30010, rtp(2, 160, b'\x00' * 24), 3)]
write('g723-coverage-malformed.pcap', mal)
