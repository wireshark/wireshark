#!/usr/bin/env python3
# Generates test/captures/rtp_ed137_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the RTP ED-137 dissector
(packet-rtp-ed137.c: the EUROCAE ED-137 / ED-137A / ED-137B / ED-137C RTP
header extensions used for air traffic control radio and telephony).

Everything is built with struct; nothing comes from a real network.  A SIP
INVITE with SDP (only the offer, so that a single RTP conversation covers both
directions, which the RMM / MAM transaction tracking needs) announces the RTP
stream; the RTP packets carry the extension in the RTP header.  RTP profile
0x0067 selects ED-137 (one 32 bit word per feature), 0x0167 selects ED-137A/B/C
(a 16 bit header followed by type/length coded features).

Usage: mkrtp_ed137.py <output directory>

Writes:
  rtp-ed137-coverage.pcap            main capture
  rtp-ed137-coverage-malformed.pcap  RSSI indexes out of range (error expert
                                     info), an RMM that gets no response,
                                     short extensions
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

class Stream:
    """Sequence numbers and timestamps for one direction of one stream."""
    def __init__(self, ssrc, seq=1000, ts=16000):
        self.ssrc, self.seq, self.ts = ssrc, seq, ts

    def pkt(self, pt, payload=b'', step=160, **kw):
        p = rtp(pt, self.seq, self.ts, self.ssrc, payload, **kw)
        self.seq = (self.seq + 1) & 0xffff
        self.ts = (self.ts + step) & 0xffffffff
        return p




PA, PB = 22000, 32000
PTT_TYPES = (0, 1, 2, 3, 4, 5, 6, 7)


def ed137_word(ptt=0, squ=0, ptt_id=0, sct=0, ext=False, ft=0, ftlen=0, value=0, vf=0):
    w = (ptt << 29) | (squ << 28) | (ptt_id << 24) | (sct << 23)
    if ext:
        w |= 0x00400000 | (ft << 18) | (ftlen << 14) | (value << 1)
    w |= vf
    return struct.pack('>I', w)


def feat(ft, value):
    """ED-137A additional feature: one octet type/length, then the value."""
    return bytes([(ft << 4) | len(value)]) + value


def ed137a(ptt=0, squ=0, ptt_id=0, pm=0, ptts=0, sct=0, feats=()):
    w = (ptt << 13) | (squ << 12) | (ptt_id << 8) | (pm << 7) | (ptts << 6) | (sct << 5)
    body = b''.join(feats)
    if feats:
        w |= 1
    b = struct.pack('>H', w) + body
    return b + b'\0' * ((-len(b)) % 4)


def sqi(qidx, ml):
    return feat(1, bytes([(qidx << 3) | ml]))


def tdly(mode, value):
    return feat(2, bytes([(mode << 7) | value]))


def rrc_single(bits):
    return feat(3, bytes([bits]))


def rrc_paired(bits, sq, sqi1, sqi2):
    return feat(3, bytes([bits, sq, sqi1, sqi2]))[:0] + bytes([(3 << 4) | 4, bits, sq, sqi1, sqi2])


def rmm(tq, t1):
    return feat(4, struct.pack('>I', (tq << 23) | t1)[1:])


def mam(tqg, t1, nmr, t2, tsd, tj1, tid, ts2=None):
    v = struct.pack('>I', (tqg << 23) | t1)[1:] + struct.pack('>I', (nmr << 23) | t2)[1:] + \
        struct.pack('>HHH', tsd, tj1, tid)
    if ts2 is not None:
        return bytes([(4 << 4) | 14]) + v + struct.pack('>H', ts2)
    return bytes([(4 << 4) | 12]) + v


def main(outdir):
    F = []
    t = [0.0]
    st_a = Stream(0xed000001, 100, 8000)
    st_b = Stream(0xed000002, 500, 64000)
    g711 = bytes((i * 3) & 0xff for i in range(160))

    off = sdp('10.0.0.1', [('audio', PA, 'RTP/AVP', [8, 0], ['rtpmap:8 PCMA/8000', 'rtpmap:0 PCMU/8000', 'ptime:20'])])
    F.append(udp_frame(5060, 5060, sip_invite('ed1', off)))

    def a2b(ext, dt=0.02, pt=8, marker=False):
        t[0] += dt
        F.append((udp_frame(PA, PB, st_a.pkt(pt, g711, ext=ext, marker=marker)), t[0]))

    def b2a(ext, dt=0.02, pt=8):
        t[0] += dt
        F.append((udp_frame(PB, PA, st_b.pkt(pt, g711, ext=ext), a_to_b=False), t[0]))

    # ---- ED-137 (profile 0x0067): one word per feature ------------------------
    a2b((0x0067, ed137_word()))                                                     # no PTT, not extended
    for ptt in PTT_TYPES:
        a2b((0x0067, ed137_word(ptt=ptt, ptt_id=ptt + 1, sct=ptt & 1)), marker=(ptt == 1))
    b2a((0x0067, ed137_word(squ=1, vf=1)))                                          # SQU only
    a2b((0x0067, ed137_word(ptt=1, squ=1, ptt_id=5)))                              # PTT and SQU
    b2a((0x0067, ed137_word(ptt=1, squ=1, ext=True, ft=1, ftlen=1, value=(10 << 5) | 0)))     # BSS, RSSI index 10
    b2a((0x0067, ed137_word(ext=True, ft=1, ftlen=1, value=(100 << 5) | 0)))                   # BSS, index above the RSSI max
    b2a((0x0067, ed137_word(ext=True, ft=1, ftlen=1, value=(20 << 5) | (2 << 1))))             # BSS with another method
    b2a((0x0067, ed137_word(squ=1, ext=True, ft=2, ftlen=1, value=(25 << 7))))                 # CLIMAX offset
    b2a((0x0067, ed137_word(ext=True, ft=3, ftlen=1, value=0x123)))                            # other feature
    a2b((0x0067, ed137_word(ptt=2) + ed137_word(ext=True, ft=1, ftlen=1, value=(5 << 5)) +
         ed137_word(ext=True, ft=2, ftlen=1, value=(9 << 7)) + ed137_word(ext=True, ft=9, ftlen=2, value=7)))   # several

    # ---- ED-137A/B/C (profile 0x0167) --------------------------------------------
    a2b((0x0167, ed137a()))                                                          # no PTT, no features
    for ptt in PTT_TYPES:
        a2b((0x0167, ed137a(ptt=ptt, ptt_id=ptt, pm=ptt & 1, ptts=(ptt >> 1) & 1, sct=ptt & 1)))
    b2a((0x0167, ed137a(squ=1)))
    a2b((0x0167, ed137a(ptt=1, squ=1)))
    a2b((0x0167, ed137a(feats=[sqi(10, 0)])))                                        # RSSI index
    a2b((0x0167, ed137a(feats=[sqi(0, 0)])))                                         # SQI N/A
    a2b((0x0167, ed137a(feats=[sqi(20, 3)])))                                        # QIDX with a method
    a2b((0x0167, ed137a(feats=[tdly(0, 40)])))                                       # CLIMAX delay, relative
    a2b((0x0167, ed137a(feats=[tdly(1, 100)])))                                      # absolute
    a2b((0x0167, ed137a(feats=[sqi(7, 0), tdly(0, 5)])))                             # two features
    a2b((0x0167, ed137a(ptt=1, feats=[rrc_single(0xa5)])))                          # RRC single
    a2b((0x0167, ed137a(feats=[rrc_paired(0x5a, 0xf0, (10 << 3) | 0, (3 << 3) | 2)])))         # RRC paired
    a2b((0x0167, ed137a(feats=[rrc_paired(0x00, 0x00, (0 << 3) | 0, (15 << 3) | 0)])))
    a2b((0x0167, ed137a(feats=[feat(5, b'\x01\x02')])))                              # a feature nobody decodes
    a2b((0x0167, ed137a(feats=[feat(7, b'')])))                                      # zero length feature
    a2b((0x0167, ed137a(feats=[feat(1, b'')])))                                      # sqi key with another length
    # climax delay-difference measurement: RMM requests from the VCS (A), MAM responses from the GRS (B)
    a2b((0x0167, ed137a(feats=[rmm(1, 0x001000)])), dt=0.5)
    b2a((0x0167, ed137a(feats=[mam(1, 0x001000, 0, 0x001010, 0x0010, 0x0002, 0x0003)])), dt=0.02)     # B: 12 octets, synchronised
    a2b((0x0167, ed137a(feats=[rmm(0, 0x002000)])), dt=0.5)
    b2a((0x0167, ed137a(feats=[mam(0, 0x002000, 1, 0x002040, 0x0100, 0x0005, 0x0007)])), dt=0.02)     # B: relative, NMR
    a2b((0x0167, ed137a(feats=[rmm(1, 0x7ffff0)])), dt=0.5)
    b2a((0x0167, ed137a(feats=[mam(1, 0x7ffff0, 0, 0x000010, 0x0010, 0x0002, 0x0003, ts2=0x0009)])), dt=0.02)   # C: 14 octets, T2 < T1 wrap
    a2b((0x0167, ed137a(feats=[rmm(0, 0x003000)])), dt=0.5)
    b2a((0x0167, ed137a(feats=[mam(0, 0x003000, 1, 0x003100, 0x0200, 0x0005, 0x0007, ts2=0x0001)])), dt=0.02)
    b2a((0x0167, ed137a(feats=[mam(0, 0x00dead, 0, 0x00dfff, 0x0200, 0x0005, 0x0007)])), dt=0.02)    # a MAM that no RMM asked for
    # other RTP payload types and plain RTP in the same stream
    a2b(None, pt=0)
    a2b((0x0167, ed137a(ptt=1)), pt=0, marker=True)
    # the same MAM again (a response that was already seen), and a 12 octet MAM whose T2 is below T1 (wrap)
    b2a((0x0167, ed137a(feats=[mam(1, 0x001000, 0, 0x001010, 0x0010, 0x0002, 0x0003)])), dt=0.02)
    a2b((0x0167, ed137a(feats=[rmm(1, 0x7ffe00)])), dt=0.5)
    b2a((0x0167, ed137a(feats=[mam(1, 0x7ffe00, 0, 0x000100, 0x0010, 0x0002, 0x0003)])), dt=0.02)
    pcap(os.path.join(outdir, 'rtp-ed137-coverage.pcap'), F)

    # ---- malformed ---------------------------------------------------------------------
    F = F[:1]
    t[0] = 0.0
    a2b((0x0167, ed137a(feats=[sqi(20, 0)])))                                       # RSSI index out of range (error)
    a2b((0x0167, ed137a(feats=[rrc_paired(0x00, 0x00, (20 << 3) | 0, (30 << 3) | 0)])))   # both RRC SQIs out of range
    a2b((0x0167, ed137a(feats=[rmm(1, 0x005000)])), dt=0.5)                           # an RMM nobody answers
    a2b((0x0167, ed137a(feats=[rmm(1, 0x005000)])), dt=0.5)                           # the same again
    a2b((0x0167, struct.pack('>H', 1) + b'\x00\x00'))                                 # extension flag, zero features
    a2b((0x0167, b'\xf1\x00\x00\x00'))                                                # feature type 15 of length 1 with nothing
    a2b((0x0167, struct.pack('>H', 1) + bytes([0x4c]) + bytes(5)))                 # MAM cut short
    a2b((0x0167, struct.pack('>H', 1) + bytes([0x43, 0x01])))                      # RMM cut short
    a2b((0x0167, struct.pack('>H', 1) + bytes([0x11])))                            # SQI without its value
    a2b((0x0167, struct.pack('>H', 1) + bytes([0x31, 0x00, 0x00, 0x00])[:3]))
    a2b((0x0167, b'\x00\x00' + b'\x00\x00'))
    a2b((0x0067, b'\x00\x00\x00\x00'))
    # an extension whose length runs past the end of the packet
    q = bytearray(st_a.pkt(8, g711[:8], ext=(0x0167, ed137a(feats=[sqi(5, 0)]))))
    q[14:16] = struct.pack('>H', 20)
    t[0] += 0.02
    F.append((udp_frame(PA, PB, bytes(q)), t[0]))
    q = bytearray(st_a.pkt(8, g711[:8], ext=(0x0067, ed137_word(ptt=1))))
    q[14:16] = struct.pack('>H', 20)
    t[0] += 0.02
    F.append((udp_frame(PA, PB, bytes(q)), t[0]))
    pcap(os.path.join(outdir, 'rtp-ed137-coverage-malformed.pcap'), F)


if __name__ == '__main__':
    main(sys.argv[1])
