#!/usr/bin/env python3
# Generates test/captures/rtp_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the RTP dissector
(packet-rtp.c: RTP, SRTP, RFC 2198 redundant audio, RFC 4571 framing,
PacketCable CCC, RFC 5285 header extensions, stream tracking).

Everything is built with struct; nothing comes from a real network.  RTP is
reached the way a real capture reaches it: a SIP INVITE / 200 OK (and a
re-INVITE) carries SDP that announces the RTP streams, and the RTP packets
that follow are dissected by the conversations that SDP created.

Usage: mkrtp.py <output directory>

Writes:
  rtp-coverage.pcapng            main capture (interface 0 Ethernet, interface 1
                                 Exported PDU for the Bluetooth A2DP / VDP and
                                 direct dissector calls)
  rtp-coverage-malformed.pcapng  bad padding, truncated packets, short packets
  rtp-coverage-extra.pcapng      streams that need preferences or Decode As:
                                 RFC 4571 over TCP, PacketCable CCC, a stream
                                 with no SDP (RTP heuristic), RTP version 0
                                 variants, Exported PDU calls by name
"""
# ---- common helpers (pcap/pcapng writers, Ethernet/IP/UDP/TCP, SIP/SDP, RTP) ----
import os
import struct
import sys

MAC_A = bytes.fromhex('020000000a01')
MAC_B = bytes.fromhex('020000000a02')
IP_A = bytes([10, 0, 0, 1])
IP_B = bytes([10, 0, 0, 2])
T0 = 1700000000


def ip_csum(h):
    s = sum(struct.unpack('>%dH' % (len(h) // 2), h))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ipv4(proto, src, dst, payload, ident=1):
    h = struct.pack('>BBHHHBBH', 0x45, 0, 20 + len(payload), ident, 0, 64, proto, 0) + src + dst
    h = h[:10] + struct.pack('>H', ip_csum(h)) + h[12:]
    return h + payload


def udp_frame(sport, dport, payload, a_to_b=True, src=None, dst=None):
    if src is None:
        src, dst = (IP_A, IP_B) if a_to_b else (IP_B, IP_A)
    macs = (MAC_B + MAC_A) if a_to_b else (MAC_A + MAC_B)
    u = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    return macs + b'\x08\x00' + ipv4(17, src, dst, u)


def tcp_frame(sport, dport, seq, ack, flags, payload=b'', a_to_b=True):
    src, dst = (IP_A, IP_B) if a_to_b else (IP_B, IP_A)
    macs = (MAC_B + MAC_A) if a_to_b else (MAC_A + MAC_B)
    t = struct.pack('>HHIIBBHHH', sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0) + payload
    return macs + b'\x08\x00' + ipv4(6, src, dst, t)


def pcap(path, frames, linktype=1):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, fr in enumerate(frames):
            t = i * 0.01
            if isinstance(fr, tuple):
                fr, t = fr
            f.write(struct.pack('<IIII', T0 + int(t), int((t % 1) * 1000000), len(fr), len(fr)))
            f.write(fr)


def _blk(t, body):
    pad = (-len(body)) % 4
    n = 12 + len(body) + pad
    return struct.pack('<II', t, n) + body + b'\0' * pad + struct.pack('<I', n)


def pcapng(path, frames, linktypes=(1,)):
    """frames: list of (interface index, bytes)."""
    out = _blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    for lt in linktypes:
        out += _blk(1, struct.pack('<HHI', lt, 0, 262144))
    for i, (ifc, fr) in enumerate(frames):
        ts = T0 * 1000000 + i * 10000
        if isinstance(fr, tuple):
            fr, t = fr
            ts = T0 * 1000000 + int(t * 1000000)
        out += _blk(6, struct.pack('<IIIII', ifc, ts >> 32, ts & 0xffffffff, len(fr), len(fr)) + fr)
    with open(path, 'wb') as f:
        f.write(out)


def tlv(t, v):
    return struct.pack('>HH', t, len(v)) + v


def exp_pdu(dissector, payload, bluetooth=False):
    hdr = tlv(12, dissector.encode() + b'\0' * ((-len(dissector)) % 4))
    if bluetooth:
        hdr += tlv(20, IP_A) + tlv(21, IP_B)
        hdr += tlv(24, struct.pack('>I', 15))
        hdr += tlv(25, struct.pack('>I', 1)) + tlv(26, struct.pack('>I', 1))
    return hdr + struct.pack('>HH', 0, 0) + payload


def sdp(addr, media, session='s7', origin_id=1, session_attrs=()):
    """media: list of (kind, port, proto, fmts, [attribute lines])."""
    s = 'v=0\r\no=- %d 1 IN IP4 %s\r\ns=%s\r\nc=IN IP4 %s\r\nt=0 0\r\n' % (origin_id, addr, session, addr)
    for a in session_attrs:
        s += 'a=%s\r\n' % a
    for kind, port, proto, fmts, attrs in media:
        s += 'm=%s %d %s %s\r\n' % (kind, port, proto, ' '.join(str(x) for x in fmts))
        for a in attrs:
            s += 'a=%s\r\n' % a
    return s.encode()


def sip_invite(call_id, body, frm='alice', to='bob', cseq=1, host_a='10.0.0.1', host_b='10.0.0.2'):
    h = ('INVITE sip:%s@%s SIP/2.0\r\nVia: SIP/2.0/UDP %s:5060;branch=z9hG4bK%s\r\n'
         'From: <sip:%s@%s>;tag=a1\r\nTo: <sip:%s@%s>\r\nCall-ID: %s\r\nCSeq: %d INVITE\r\n'
         'Contact: <sip:%s@%s>\r\nContent-Type: application/sdp\r\nContent-Length: %d\r\n\r\n'
         % (to, host_b, host_a, call_id, frm, host_a, to, host_b, call_id, cseq, frm, host_a, len(body)))
    return h.encode() + body


def sip_ok(call_id, body, frm='alice', to='bob', cseq=1, host_a='10.0.0.1', host_b='10.0.0.2'):
    h = ('SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP %s:5060;branch=z9hG4bK%s\r\n'
         'From: <sip:%s@%s>;tag=a1\r\nTo: <sip:%s@%s>;tag=b1\r\nCall-ID: %s\r\nCSeq: %d INVITE\r\n'
         'Contact: <sip:%s@%s>\r\nContent-Type: application/sdp\r\nContent-Length: %d\r\n\r\n'
         % (host_a, call_id, frm, host_a, to, host_b, call_id, cseq, to, host_b, len(body)))
    return h.encode() + body


def rtp(pt, seq, ts, ssrc, payload=b'', marker=False, csrc=(), ext=None, pad=0, version=2):
    """ext: (profile, bytes) with len(bytes) a multiple of 4."""
    o1 = (version << 6) | (0x20 if pad else 0) | (0x10 if ext is not None else 0) | len(csrc)
    o2 = (0x80 if marker else 0) | pt
    b = struct.pack('>BBHII', o1, o2, seq & 0xffff, ts & 0xffffffff, ssrc)
    for c in csrc:
        b += struct.pack('>I', c)
    if ext is not None:
        b += struct.pack('>HH', ext[0], len(ext[1]) // 4) + ext[1]
    b += payload
    if pad:
        b += b'\0' * (pad - 1) + bytes([pad])
    return b



PA, PB = 20000, 30000      # first RTP port of A (10.0.0.1) and of B (10.0.0.2)


def crc32c(data):
    crc = 0xffffffff
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82f63b78 if crc & 1 else 0)
    return crc ^ 0xffffffff


def red_hdr(pt, ts_off, blen, more=True):
    if more:
        return bytes([0x80 | pt]) + struct.pack('>I', (ts_off << 10) | blen)[1:]
    return bytes([pt])


def ext_one_byte(items, pad_to=None):
    """RFC 5285 one-byte header extension elements (id, data)."""
    b = b''
    for i, d in items:
        if i == 'pad':
            b += b'\0' * d
        elif i == 15:
            b += bytes([0xf0]) + d
        else:
            b += bytes([(i << 4) | (len(d) - 1)]) + d
    b += b'\0' * ((-len(b)) % 4)
    return (0xBEDE, b)


def ext_two_byte(items, app=0):
    b = b''
    for i, d in items:
        if i == 'pad':
            b += b'\0' * d
        else:
            b += bytes([i, len(d)]) + d
    b += b'\0' * ((-len(b)) % 4)
    return (0x1000 | app, b)


class Stream:
    """Sequence numbers and timestamps for one direction of one stream."""
    def __init__(self, ssrc, seq=1000, ts=16000):
        self.ssrc, self.seq, self.ts = ssrc, seq, ts

    def pkt(self, pt, payload=b'', step=160, **kw):
        p = rtp(pt, self.seq, self.ts, self.ssrc, payload, **kw)
        self.seq = (self.seq + 1) & 0xffff
        self.ts = (self.ts + step) & 0xffffffff
        return p


def eth_frame(ethertype, payload, a_to_b=True):
    macs = (MAC_B + MAC_A) if a_to_b else (MAC_A + MAC_B)
    return macs + struct.pack('>H', ethertype) + payload


def ces(seq, rtp_pkt, l=0, r=0, m=0, frg=0, length=0, ecid=1, res=0x102):
    '''CESoETH: ECID word, control word, then the (optional) RTP header and TDM data.'''
    cw = struct.pack('>BBH', (l << 3) | (r << 2) | m, (frg << 6) | length, seq)
    return struct.pack('>I', (ecid << 12) | res) + cw + rtp_pkt


def ple(seq, rtp_pkt, l=0, r=0, frg=0, length=0, rsv=0):
    '''PLE (RFC 9801) over IP protocol 147: control word then an RTP header.'''
    cw = struct.pack('>I', (l << 27) | (r << 26) | (rsv << 24) | (frg << 22) | (length << 16) | seq)
    return cw + rtp_pkt


def main(outdir):
    F = []

    def add(fr, ifc=0):
        F.append((ifc, fr))

    def a2b(i, p):
        add(udp_frame(PA + 2 * i, PB + 2 * i, p))

    def b2a(i, p):
        add(udp_frame(PB + 2 * i, PA + 2 * i, p, a_to_b=False))

    AMR_FMTP = 'fmtp:96 mode-set=0,2,4,7;octet-align=1'
    EVS_FMTP = 'fmtp:97 br=9.6-24.4;bw=nb-wb'

    def media(base, ports_ip):
        """The media lines of the offer (base=PA) and of the answer (base=PB)."""
        key = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'    # a dummy 30 octet value, not a real key
        return [
            # 0: G.711, comfort noise, telephone-event, RFC 2198 redundancy
            ('audio', base, 'RTP/AVP', [0, 8, 18, 13, 101, 99],
             ['rtpmap:0 PCMU/8000', 'rtpmap:8 PCMA/8000', 'rtpmap:18 G729/8000', 'rtpmap:13 CN/8000',
              'rtpmap:101 telephone-event/8000', 'rtpmap:99 red/8000', 'fmtp:99 0/0']),
            # 1: AMR, EVS, a dynamic type with no decoder, and one with no rtpmap
            ('audio', base + 2, 'RTP/AVP', [96, 97, 98, 100, 105],
             ['rtpmap:96 AMR/8000', AMR_FMTP, 'rtpmap:97 EVS/16000', EVS_FMTP,
              'rtpmap:98 opus/48000/2', 'rtpmap:100 AMR-WB/16000/1', 'fmtp:100 octet-align=1',
              'fmtp:105 profile=x;level=1']),
            # 2: SRTP with an MKI
            ('audio', base + 4, 'RTP/SAVP', [0, 101],
             ['rtpmap:0 PCMU/8000', 'rtpmap:101 telephone-event/8000',
              'crypto:1 AES_CM_128_HMAC_SHA1_80 inline:%s|2^20|1:4' % key]),
            # 3: SRTP with a short tag and no MKI
            ('audio', base + 6, 'RTP/SAVP', [8],
             ['rtpmap:8 PCMA/8000', 'crypto:1 AES_CM_128_HMAC_SHA1_32 inline:%s' % key]),
            # 4: video: H.264, MPEG-4, and the static video payload types
            ('video', base + 8, 'RTP/AVP', [96, 97, 31, 26, 32, 34],
             ['rtpmap:96 H264/90000', 'rtpmap:97 MP4V-ES/90000']),
            # 5: V.150.1 modem relay
            ('audio', base + 10, 'RTP/AVP', [98, 100], ['rtpmap:98 v150fw/8000', 'rtpmap:100 CLEARMODE/8000']),
            # 6: a stream that is replaced by the re-INVITE
            ('audio', base + 12, 'RTP/AVP', [0, 96], ['rtpmap:0 PCMU/8000', 'rtpmap:96 AMR/8000', 'fmtp:96 octet-align=1']),
            # 7: stream for header extensions and sequence arithmetic
            ('audio', base + 14, 'RTP/AVP', [0, 8], ['rtpmap:0 PCMU/8000', 'rtpmap:8 PCMA/8000']),
        ]

    # SDP keeps at most four media descriptions per message: two calls
    off = sdp('10.0.0.1', media(PA, None)[:4])
    ans = sdp('10.0.0.2', media(PB, None)[:4])
    add(udp_frame(5060, 5060, sip_invite('rtp1', off)))
    add(udp_frame(5060, 5060, sip_ok('rtp1', ans), a_to_b=False))
    off = sdp('10.0.0.1', media(PA, None)[4:], origin_id=3)
    ans = sdp('10.0.0.2', media(PB, None)[4:], origin_id=3)
    add(udp_frame(5060, 5060, sip_invite('rtp2', off, frm='carol')))
    add(udp_frame(5060, 5060, sip_ok('rtp2', ans, frm='carol'), a_to_b=False))

    sa = {i: Stream(0xa0000000 + i) for i in range(8)}
    sb = {i: Stream(0xb0000000 + i, 5000, 90000) for i in range(8)}
    g711 = bytes((i * 7) & 0xff for i in range(160))

    # ---- stream 0: plain RTP, header fields -------------------------------
    a2b(0, sa[0].pkt(0, g711, marker=True))
    b2a(0, sb[0].pkt(0, g711))
    a2b(0, sa[0].pkt(8, g711))
    a2b(0, sa[0].pkt(18, b'\x11' * 20, step=160))
    a2b(0, sa[0].pkt(13, b'\x20', step=160))                    # comfort noise
    a2b(0, sa[0].pkt(0, g711, csrc=(0x01020304,)))
    a2b(0, sa[0].pkt(0, g711, csrc=(0x01020304, 0x05060708, 0x090a0b0c)))
    a2b(0, sa[0].pkt(0, g711, pad=4))                           # padding
    a2b(0, sa[0].pkt(0, g711, pad=1))                           # padding of just the count
    a2b(0, sa[0].pkt(0, b'', pad=4))                            # padding only
    a2b(0, sa[0].pkt(3, b'\x55' * 33))                          # GSM
    a2b(0, sa[0].pkt(9, b'\x55' * 80))                          # G.722
    a2b(0, sa[0].pkt(120, b'\x01\x02\x03'))                     # dynamic, not announced: RTPType-120
    a2b(0, sa[0].pkt(0, b''))                                   # no payload at all
    # telephone-event and unannounced rtp.pt 100 (default range 100-101)
    a2b(0, sa[0].pkt(101, struct.pack('>BBH', 5, 10, 160), marker=True))
    a2b(0, sa[0].pkt(100, struct.pack('>BBH', 6, 0x8a, 960)))
    # RTCP in the RTP port (RFC 5761): marker + payload type 72-76 = RTCP SR
    sr = struct.pack('>BBHIQIII', 0x80, 200, 6, 0xa0000000, 0xe0f0a0b000000000, 160, 10, 1600)
    a2b(0, sr)
    # ---- stream 0: RFC 2198 redundant audio -------------------------------
    p = red_hdr(0, 160, 160) + red_hdr(0, 0, 0, False) + g711 + g711
    a2b(0, sa[0].pkt(99, p))
    p = red_hdr(0, 320, 160) + red_hdr(8, 160, 160) + red_hdr(101, 0, 0, False) + g711 + g711 + \
        struct.pack('>BBH', 3, 10, 480)
    a2b(0, sa[0].pkt(99, p, marker=True))
    p = red_hdr(0, 0, 0, False) + g711                          # a single block
    b2a(0, sb[0].pkt(99, p))
    p = red_hdr(105, 160, 4) + red_hdr(0, 0, 0, False) + b'\xde\xad\xbe\xef' + g711     # unknown PT 105
    a2b(0, sa[0].pkt(99, p))
    # a block that is again RED: the nested block is shown as data with a warning
    p = red_hdr(0, 160, 20) + red_hdr(99, 0, 0, False) + g711[:20] + \
        red_hdr(0, 160, 10) + red_hdr(99, 0, 0, False) + g711[:10] + \
        bytes([99]) * 3 + b'\x00' * 4
    a2b(0, sa[0].pkt(99, p))

    # ---- stream 1: AMR, EVS, other dynamic types --------------------------
    AMRWB = b'\xf0\x04' + b'\x11' * 16 + b'\xa0'
    amr = b'\xf0' + b'\x3c' + bytes(range(31))                  # CMR 15, FT 7 (12.2 kbit/s), Q=1
    a2b(1, sa[1].pkt(96, amr))
    b2a(1, sb[1].pkt(96, amr, marker=True))
    a2b(1, sa[1].pkt(97, b'\x00' + bytes(24)))                  # EVS
    a2b(1, sa[1].pkt(98, b'\xfc\xff\xfe'))                      # opus: no dissector
    a2b(1, sa[1].pkt(100, AMRWB ))  # AMR-WB
    a2b(1, sa[1].pkt(105, b'\x01\x02'))                         # dynamic type with no rtpmap
    # AMR inside RED, with and without the redundancy
    p = red_hdr(96, 160, len(amr)) + red_hdr(96, 0, 0, False) + amr + amr
    a2b(1, sa[1].pkt(99, p))

    # ---- stream 2, 3: SRTP: only the framing is shown ---------------------
    blob = bytes((i * 13 + 5) & 0xff for i in range(80))        # opaque filler, not real ciphertext
    a2b(2, sa[2].pkt(0, blob + b'\x00\x00\x00\x01' + b'\x77' * 10))
    b2a(2, sb[2].pkt(0, blob + b'\x00\x00\x00\x01' + b'\x77' * 10, marker=True))
    a2b(2, sa[2].pkt(101, blob[:20] + b'\x00\x00\x00\x01' + b'\x77' * 10, ext=ext_one_byte([(1, b'\x05')])))
    a2b(3, sa[3].pkt(8, blob + b'\x66' * 4))
    a2b(3, sa[3].pkt(8, blob + b'\x66' * 4, pad=2))

    # ---- stream 4: video, static video payload types ----------------------
    a2b(4, sa[4].pkt(96, b'\x09\xf0', step=3000))
    a2b(4, sa[4].pkt(96, b'\x09\x30', step=0, marker=True))
    a2b(4, sa[4].pkt(97, bytes(40), step=3000))
    a2b(4, sa[4].pkt(31, b'\x00\x00\x00\x00' + bytes(20), step=3000))           # H.261
    a2b(4, sa[4].pkt(26, b'\x00\x00\x00\x00\x00\x40\x30\x30' + bytes(20), step=3000))   # JPEG
    a2b(4, sa[4].pkt(32, b'\x00\x00\x00\x00' + bytes(20), step=3000))           # MPEG video
    a2b(4, sa[4].pkt(34, b'\x00\x00\x00\x00' + bytes(20), step=3000))           # H.263

    # ---- stream 5: V.150.1 ---------------------------------------------------
    a2b(5, sa[5].pkt(98, b'\x00\x01\x02\x03' + bytes(8)))

    # H.223 over a CLEARMODE stream: a MUX-PDU (3 octet header, closing flag
    # E14D) split over RTP packets asks RTP to reassemble (bit-swapped data)
    def bs(b):
        return bytes(int('{:08b}'.format(x)[::-1], 2) for x in b)
    a2b(5, sa[5].pkt(100, bs(b'\x00\x00\x00')))
    a2b(5, sa[5].pkt(100, bs(b'\xe1\x4d')))
    a2b(5, sa[5].pkt(100, bs(b'\x00\x00')))
    a2b(5, sa[5].pkt(100, bs(b'\x00')))
    a2b(5, sa[5].pkt(100, bs(b'\xe1\x4d')))
    a2b(5, sa[5].pkt(100, bs(b'\x00\x00\x00\xe1\x4d')))         # a whole PDU in one packet
    a2b(5, sa[5].pkt(100, bs(b'\x00\x00\x00\xe1\x4d\x00\x00\x00')))   # a whole PDU and the start of another
    a2b(5, sa[5].pkt(100, bs(b'\xe1\x4d')))
    # a retransmitted first fragment: the same sequence number again, so the
    # fragment is "never reassembled"
    dup = rtp(100, sa[5].seq, sa[5].ts, sa[5].ssrc, bs(b'\x00\x00\x00'))
    sa[5].seq += 1
    a2b(5, dup)
    a2b(5, dup)

    # ---- stream 7: header extensions and sequence number arithmetic ------
    s7 = sa[7]
    a2b(7, s7.pkt(0, g711, ext=ext_one_byte([(1, b'\xaa'), ('pad', 2), (2, b'\xbb\xcc\xdd'), (3, bytes(16))])))
    a2b(7, s7.pkt(0, g711, ext=ext_one_byte([(1, b'\xaa'), (15, b'\x00\x00')])))        # id 15 ends it
    a2b(7, s7.pkt(0, g711, ext=ext_one_byte([('pad', 4)])))                              # padding only
    a2b(7, s7.pkt(0, g711, ext=ext_two_byte([(1, b'\x01\x02'), (2, b''), ('pad', 1), (3, b'\x09')], app=5)))
    a2b(7, s7.pkt(0, g711, ext=ext_two_byte([(4, b'\xff' * 8)])))
    a2b(7, s7.pkt(0, g711, ext=ext_two_byte([('pad', 8)])))
    a2b(7, s7.pkt(0, g711, ext=(0x4321, struct.pack('>II', 0x11223344, 0x55667788))))   # other profile
    a2b(7, s7.pkt(0, g711, ext=(0x4321, b'')))                                          # zero length
    # ED-137 header extensions (ED-137: 0x0067, ED-137A/B/C: 0x0167) are covered
    # by the rtp-ed137 capture; one of each here shows that RTP hands them on
    a2b(7, s7.pkt(8, g711, ext=(0x0067, struct.pack('>I', 0xf0400000))))
    a2b(7, s7.pkt(8, g711, ext=(0x0167, struct.pack('>HH', 0x7001, 0x1100))))
    # sequence number and timestamp wrap, and an out-of-order packet over the wrap
    w = Stream(0xc0000007, seq=65533, ts=0xfffffe00)
    for _ in range(5):
        a2b(7, w.pkt(0, g711[:20], step=160))
    a2b(7, rtp(0, 65535, 0xffffff60, 0xc0000007, g711[:20]))   # backwards over the wrap
    a2b(7, rtp(0, 3, 0x00000400, 0xc0000007, g711[:20]))
    a2b(7, rtp(0, 5, 0x20000, 0xc0000007, g711[:20]))          # small jump
    a2b(7, rtp(0, 0x9000, 0x90000000, 0xc0000007, g711[:20]))  # a large forward jump
    a2b(7, rtp(0, 0x2000, 0x10000000, 0xc0000007, g711[:20]))  # and back
    # a second SSRC on the same stream
    a2b(7, rtp(0, 1, 160, 0xc0000008, g711[:20]))
    # truncated capture: only part of the payload was captured
    cut = udp_frame(PA, PB, rtp(0, 50, 0, 0xc0000009, g711))
    # (frames with a capture length shorter than the frame are made below)

    # ---- version 0 / 1 / 3 packets (RFC 7983 demultiplexing by default) ------
    stun = struct.pack('>HHI', 1, 0, 0x2112A442) + b'\x01' * 12
    a2b(0, b'\x40\x01' + struct.pack('>H', 4) + b'\x01\x02\x03\x04')    # TURN ChannelData, number 0x4001
    zr = b'\x10\x00' + struct.pack('>HI', 1, 0x5a525450) + struct.pack('>I', 0xa0000000)
    zr += b'\x50\x5a' + struct.pack('>H', 6) + b'Ping    ' + b'1.10' + bytes(8)
    zr = zr[:12] + zr[12:]
    # (the ZRTP packet is completed with its CRC below)
    zr = zr + struct.pack('<I', crc32c(zr))
    a2b(0, zr)
    dtls = b'\x14\xfe\xfd' + b'\x00\x00' + b'\x00' * 5 + b'\x01' + b'\x00\x01\x01'
    a2b(0, dtls)
    a2b(0, b'\x05' + bytes(15))                                  # version 0, none of the above
    a2b(0, b'\x55' + bytes(15))                                  # version 1, not a channel
    a2b(0, b'\xc0' + bytes(15))                                  # version 3
    a2b(0, b'\xff\x10' + struct.pack('>HHI', 1, 0, 0x2112A442)[0:0] + bytes(14))   # MS-TURN
    # TURN ChannelData carrying an RTP packet (its payload is shown as RTP)
    inner = sa[0].pkt(0, g711[:40])
    a2b(0, b'\x40\x01' + struct.pack('>H', len(inner)) + inner)

    # ---- RTP from Exported PDUs: Bluetooth A2DP and VDP, rtp by name --------
    sbc = b'\x03' + b'\x9c\x71\x10\x76' + bytes(20)
    ssrc_bt = 0x0b000001
    for i in range(3):
        add(exp_pdu('bta2dp', rtp(96, 10 + i, 1000 + 128 * i, ssrc_bt, sbc, marker=(i == 0)), bluetooth=True), 1)
    add(exp_pdu('bta2dp', rtp(96, 20, 5000, ssrc_bt, b''), bluetooth=True), 1)             # the reproducer
    add(exp_pdu('btvdp', rtp(96, 30, 9000, ssrc_bt + 1, sbc), bluetooth=True), 1)
    add(exp_pdu('btvdp', rtp(96, 31, 9000, ssrc_bt + 1, b''), bluetooth=True), 1)
    add(exp_pdu('rtp', rtp(0, 1, 160, 0x0c000001, g711[:40])), 1)
    add(exp_pdu('rtp', rtp(0, 2, 320, 0x0c000001, g711[:40])), 1)
    add(exp_pdu('rtp.rfc2198', red_hdr(0, 160, 20) + red_hdr(8, 0, 0, False) + g711[:20] + g711[:20]), 1)
    # the nested-RED reproducer: each level costs one octet
    add(exp_pdu('rtp', rtp(99, 3, 480, 0x0c000001, bytes([99]) * 8 + b'\x00' * 4)), 1)

    # PacketCable CCC (Exported PDU by name): RTP follows the 12 octet CCC header
    ccc = struct.pack('>IQ', 7, 0xe0f0a0b000000000)
    add(exp_pdu('pkt_ccc', ccc + rtp(0, 7, 160, 0x0e000002, g711[:40])), 1)

    # a padded A2DP packet (the payload offset skips the SBC header octet)
    add(exp_pdu('bta2dp', rtp(96, 21, 6000, ssrc_bt, sbc, pad=2), bluetooth=True), 1)

    # CESoETH (ethertype 0x88d8, RTP header found by the heuristic) and PLE
    # (IP protocol 147): both use the RTP header without an RTP packet
    tdm = bytes(range(32))
    add(eth_frame(0x88d8, ces(100, rtp(0, 100, 800, 0x1c000001, tdm))))
    add(eth_frame(0x88d8, ces(101, rtp(0, 101, 1600, 0x1c000001, tdm), l=1, m=1), a_to_b=False))
    add(eth_frame(0x88d8, ces(102, rtp(0, 102, 2400, 0x1c000001, tdm), r=1, frg=1)))
    add(eth_frame(0x88d8, ces(103, rtp(0, 103, 3200, 0x1c000001, tdm[:14]) + bytes(12), length=30, frg=2, m=2)))
    add(eth_frame(0x88d8, ces(104, tdm, frg=3)))                                    # no RTP header
    add(eth_frame(0x88d8, ces(105, rtp(0, 105, 4000, 0x1c000001, tdm), l=1, m=3)))
    for sq, rs, l, r in ((200, 200, 0, 0), (201, 0x1201, 1, 0), (202, 202, 0, 1)):
        add(eth_frame(0x0800, ipv4(147, IP_A, IP_B, ple(sq, rtp(8, rs, 800 * sq, 0x1d000001, tdm), l=l, r=r))))

    # ---- a re-INVITE that changes stream 6 --------------------------------
    for _ in range(2):
        a2b(6, sa[6].pkt(96, amr))
    off2 = sdp('10.0.0.1', [('audio', PA + 12, 'RTP/AVP', [96, 97], ['rtpmap:96 AMR-WB/16000', 'fmtp:96 octet-align=1', 'rtpmap:97 EVS/16000'])],
               origin_id=2)
    ans2 = sdp('10.0.0.2', [('audio', PB + 12, 'RTP/AVP', [96, 97], ['rtpmap:96 AMR-WB/16000', 'fmtp:96 octet-align=1', 'rtpmap:97 EVS/16000'])],
               origin_id=2)
    add(udp_frame(5060, 5060, sip_invite('rtp2', off2, cseq=2, frm='carol')))
    add(udp_frame(5060, 5060, sip_ok('rtp2', ans2, cseq=2, frm='carol'), a_to_b=False))
    for _ in range(2):
        a2b(6, sa[6].pkt(96, AMRWB))
    b2a(6, sb[6].pkt(97, b'\x00' + bytes(24)))
    # the same SDP once more: no change of stream, setup info is not duplicated
    add(udp_frame(5060, 5060, sip_invite('rtp2', off2, cseq=3, frm='carol')))
    add(udp_frame(5060, 5060, sip_ok('rtp2', ans2, cseq=3, frm='carol'), a_to_b=False))
    a2b(6, sa[6].pkt(96, AMRWB))

    # the file's frames: write the main capture
    pcapng(os.path.join(outdir, 'rtp-coverage.pcapng'), F, linktypes=(1, 252))

    # ---- malformed capture -------------------------------------------------
    M = [F[0], F[1]]
    g = Stream(0xa0000100)

    def m(p, i=0):
        M.append((0, udp_frame(PA + 2 * i, PB + 2 * i, p)))
    m(g.pkt(0, g711[:10]))
    # padding bit with a count of 0 (illegal) and a count larger than the payload
    q = bytearray(rtp(0, 2, 160, 0xa0000100, g711[:10]))
    q[0] |= 0x20
    m(bytes(q) + b'\x00')
    q = bytearray(rtp(0, 3, 320, 0xa0000100, g711[:10]))
    q[0] |= 0x20
    m(bytes(q) + b'\xff')
    # packets shorter than the fixed header, a CSRC list or extension that runs off the end
    m(rtp(0, 4, 480, 0xa0000100, b'')[:11])
    m(rtp(0, 5, 640, 0xa0000100, b'')[:2])
    m(rtp(0, 6, 800, 0xa0000100, b'', csrc=(1, 2, 3))[:20])
    m(rtp(0, 7, 960, 0xa0000100, b'', ext=(0xBEDE, bytes(8)))[:16])
    m(rtp(0, 8, 1120, 0xa0000100, b'', ext=(0xBEDE, bytes(8)))[:21])
    # an extension whose length is longer than the packet
    m(rtp(0, 9, 1280, 0xa0000100, b'')[:12] + b'')
    q = bytearray(rtp(0, 10, 1440, 0xa0000100, g711[:8], ext=(0xBEDE, bytes(8))))
    q[14:16] = struct.pack('>H', 100)
    m(bytes(q))
    # one-byte extension elements that overrun, two-byte elements that overrun
    m(rtp(0, 11, 1600, 0xa0000100, g711[:8], ext=(0xBEDE, b'\x1f\x01\x02\x03')))
    m(rtp(0, 12, 1760, 0xa0000100, g711[:8], ext=(0x1000, b'\x01\x7f\x02\x03')))
    # RED: header runs off the end, block longer than the packet, empty
    m(rtp(99, 13, 1920, 0xa0000100, b'\x80\x00'))
    m(rtp(99, 14, 2080, 0xa0000100, red_hdr(0, 160, 900) + red_hdr(0, 0, 0, False) + g711[:20]))
    m(rtp(99, 15, 2240, 0xa0000100, b''))
    m(rtp(99, 16, 2400, 0xa0000100, red_hdr(101, 160, 2) + red_hdr(101, 0, 0, False) + b'\x01\x02\x03'))
    # SRTP stream with a payload shorter than the MKI and tag
    m(rtp(0, 17, 2560, 0xa0000200, b'\x01\x02\x03'), i=2)
    m(struct.pack('>HHI', 1, 0, 0x2112A442) + b'\x01' * 12)       # STUN through version 0
    m(rtp(101, 18, 2720, 0xa0000100, b'\x01', pad=4))                           # padded payload that throws (event too short)
    m(rtp(101, 19, 2880, 0xa0000100, b'\x01'))
    # padding bit with a truncated capture is made with caplen below
    frames_m = M
    pcapng(os.path.join(outdir, 'rtp-coverage-malformed.pcapng'), M, linktypes=(1, 252))
    # truncated captures need a capture length shorter than the frame length
    _trunc(os.path.join(outdir, 'rtp-coverage-malformed.pcapng'), M, cut)

    # ---- extra capture ----------------------------------------------------------------
    X = []
    ssrc_x = 0x0d000001
    # RFC 4571 over TCP port 40000: several PDUs in a segment, a PDU split in two, empty PDU
    tcpseq = 1

    def tcp(payload, a_to_b=True):
        nonlocal tcpseq
        X.append((0, tcp_frame(40001, 40000, tcpseq, 1, 0x18, payload, a_to_b=a_to_b)))
        tcpseq += len(payload)
    st = Stream(ssrc_x)
    pkts = [st.pkt(0, g711) for _ in range(6)]
    framed = [struct.pack('>H', len(p)) + p for p in pkts]
    tcp(framed[0])
    tcp(framed[1] + framed[2])
    tcp(framed[3][:50])
    tcp(framed[3][50:] + b'\x00\x00')
    tcp(framed[4] + framed[5][:30])
    tcp(framed[5][30:])
    tcp(struct.pack('>H', 12 + 4) + st.pkt(101, b'\x05\x8a\x03\xc0'))
    # PacketCable CCC over UDP 6000 (Decode As): 12 octet CCC header then RTP
    for i in range(3):
        X.append((0, udp_frame(6000, 6000, ccc + rtp(0, 100 + i, 160 * i, 0x0e000001, g711[:40]))))
    # a stream with no SDP: only the heuristic (rtp_udp) or Decode As finds it
    h = Stream(0x0f000001)
    for i in range(4):
        X.append((0, udp_frame(7000, 7002, h.pkt(0, g711[:40]))))
    X.append((0, udp_frame(7000, 7002, h.pkt(99, red_hdr(0, 160, 20) + red_hdr(0, 0, 0, False) + g711[:20] + g711[:20]))))
    X.append((0, udp_frame(7000, 7002, h.pkt(101, struct.pack('>BBH', 1, 10, 160)))))
    X.append((0, udp_frame(7000, 7002, h.pkt(0, g711[:40], pad=3))))
    X.append((0, udp_frame(7000, 7002, h.pkt(0, g711[:40], ext=ext_one_byte([(1, b'\x01')])))))
    X.append((0, udp_frame(7000, 7002, sr)))
    X.append((0, udp_frame(7000, 7002, h.pkt(0, g711[:40], ext=(0x0067, b'\x00\x00\x00\x00')))))
    # version 0 packets for the version0_type preference: STUN, classic STUN, T.38, SPRT, ZRTP
    X.append((0, udp_frame(7004, 7006, stun)))
    X.append((0, udp_frame(7004, 7006, b'\x00\x01\x00\x00' + b'\x02' * 16)))
    X.append((0, udp_frame(7004, 7006, b'\x00\x10\x00\x00' + b'ZRTP' + bytes(8))))
    X.append((0, udp_frame(7004, 7006, b'\x00\x01\x00\x00\x00\x00\x00\x00')))
    # RTP over Exported PDU by name: no stream info at all, with AMR through the PT table
    X.append((1, exp_pdu('rtp.rfc2198', b'\x00' + b'\xf0\x3c' + b'\x55' * 31)))        # uninitialised-info reproducer
    X.append((1, exp_pdu('rtp.rfc2198', b'\x00' + b'\x00' * 160)))
    X.append((1, exp_pdu('rtp.rfc2198', b'\x80\x00\x00\x01\x00\x00\x01\x02')))
    X.append((1, exp_pdu('pkt_ccc', ccc + rtp(0, 7, 160, 0x0e000002, g711[:40]))))
    # the heuristic: payload types 72-76, an extension flag with a truncated header,
    # padding counts of 0 and larger than the packet
    for q in (rtp(72, 90, 0, 0x0f000002, g711[:20]),
              bytes([0x90, 0, 0, 91, 0, 0, 0, 0, 0, 0, 0, 1, 0xbe]),
              rtp(0, 92, 0, 0x0f000002, g711[:10], pad=0)[:12] + b'\x00',
              bytes([0xa0]) + rtp(0, 93, 0, 0x0f000002, g711[:10])[1:] + b'\x00',
              bytes([0xa0]) + rtp(0, 94, 0, 0x0f000002, g711[:10])[1:] + b'\xff',
              rtp(0, 95, 0, 0x0f000002, b''),
              b'\x80'):
        X.append((0, udp_frame(7000, 7002, q)))
    q = bytearray(rtp(0, 96, 0, 0x0f000002, b'', ext=(0xBEDE, b'')))
    q[14:16] = struct.pack('>H', 100)
    X.append((0, udp_frame(7000, 7002, bytes(q))))                       # extension longer than the packet
    # one octet in the first RTP port: too short for any heuristic
    X.append((0, udp_frame(7000, 7002, b'\x80')))
    # an RTPproxy reply: its relay address is set up with rtp_add_address()
    X.append((0, udp_frame(40000, 22222, b'cx1 U call1 192.0.2.1 5004 f t\n')))
    X.append((0, udp_frame(22222, 40000, b'cx1 35000 192.0.2.50\n', a_to_b=False)))
    X.append((0, udp_frame(6000, 35000, rtp(0, 1, 160, 0x0f000003, g711[:20]), src=IP_A, dst=bytes([192, 0, 2, 50]))))
    # CESoETH with an RTP header that the heuristic does not accept (CSRC and extension),
    # which the "rtp_header" preference makes it decode; a PLE with a bad RTP version
    ext = (0xBEDE, b'\x10\xaa\x00\x00')
    X.append((0, eth_frame(0x88d8, ces(300, rtp(0, 300, 0, 0x1c000002, tdm, csrc=(1, 2), ext=ext)))))
    X.append((0, eth_frame(0x88d8, ces(301, bytes([0x40]) + rtp(0, 301, 0, 0x1c000002, tdm)[1:]))))
    X.append((0, eth_frame(0x88d8, ces(302, rtp(0, 302, 0, 0x1c000002, tdm), length=45))))
    X.append((0, eth_frame(0x88d8, ces(303, rtp(0, 303, 0, 0x1c000002, tdm), res=0x103))))
    X.append((0, eth_frame(0x0800, ipv4(147, IP_A, IP_B, ple(300, bytes([0x40]) + rtp(0, 300, 0, 0x1d000002, tdm)[1:])))))
    X.append((0, eth_frame(0x0800, ipv4(147, IP_A, IP_B, ple(301, rtp(0, 301, 0, 0x1d000002, tdm), frg=1, length=2, rsv=1)))))
    pcapng(os.path.join(outdir, 'rtp-coverage-extra.pcapng'), X, linktypes=(1, 252))


def _trunc(path, M, cut):
    """Append frames with a capture length shorter than the frame length."""
    out = b''
    # an RTP packet with the padding bit set whose last octet was not captured
    q = bytearray(cut[14 + 20 + 8:])
    q[0] |= 0x20
    fr = bytearray(cut[:14 + 20 + 8]) + q
    caplen = len(fr) - 20
    ts = (T0 + 5000) * 1000000
    blk = struct.pack('<IIIII', 0, ts >> 32, ts & 0xffffffff, caplen, len(fr)) + bytes(fr[:caplen])
    out += _blk(6, blk)
    # a truncated frame without padding: info_all_data_present is false
    fr2 = cut
    caplen = len(fr2) - 60
    blk = struct.pack('<IIIII', 0, ts >> 32, (ts + 1) & 0xffffffff, caplen, len(fr2)) + fr2[:caplen]
    out += _blk(6, blk)
    with open(path, 'ab') as f:
        f.write(out)


if __name__ == '__main__':
    main(sys.argv[1])
