#!/usr/bin/env python3
# Generates test/captures/rtp_events_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the RTP Events dissector
(packet-rtp-events.c, RFC 2833 / RFC 4733 telephone events and Cisco NSE).

Everything is built with struct; nothing comes from a real network.  RTP
Events is reached the way a real capture reaches it: a SIP INVITE / 200 OK
with SDP announces the RTP streams ("telephone-event" and "X-NSE" in
a=rtpmap, plus a stream with no rtpmap for payload type 101, which is in
the default rtp.pt range 100-101), and the RTP packets that follow carry
the 4 octet event payload.

Usage: mkrtp_events.py <output directory>

Writes:
  rtp-events-coverage.pcap            SIP + SDP, voice, every event ID 0-255
                                      (as telephone-event), begin / continue /
                                      end packets with volume and the reserved
                                      bit, Cisco NSE events
  rtp-events-coverage-malformed.pcap  event payloads cut short (1, 2, 3 octets)
  rtp-events-coverage-expdu.pcap      an Exported PDU naming "rtpevent" (no
                                      RTP packet, so no stream setup frame)
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
            f.write(struct.pack('<IIII', T0 + i // 100, (i % 100) * 10000, len(fr), len(fr)))
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
        ts = (T0 + i // 100) * 1000000 + (i % 100) * 10000
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


def sdp(addr, media, session='s7', origin_id=1):
    """media: list of (kind, port, proto, fmts, [attribute lines])."""
    s = 'v=0\r\no=- %d 1 IN IP4 %s\r\ns=%s\r\nc=IN IP4 %s\r\nt=0 0\r\n' % (origin_id, addr, session, addr)
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


A_PORT, B_PORT = 20000, 30000


def event(ev, end=False, res=False, vol=10, dur=160):
    return struct.pack('>BBH', ev, (0x80 if end else 0) | (0x40 if res else 0) | (vol & 0x3f), dur)


def main(outdir):
    frames = []
    off = sdp('10.0.0.1', [
        ('audio', A_PORT, 'RTP/AVP', [0, 101], ['rtpmap:0 PCMU/8000', 'rtpmap:101 telephone-event/8000',
                                                'fmtp:101 0-16']),
        ('audio', A_PORT + 2, 'RTP/AVP', [0, 101], ['rtpmap:0 PCMU/8000']),      # 101 only via rtp.pt
        ('audio', A_PORT + 4, 'RTP/AVP', [102, 100], ['rtpmap:102 telephone-event/16000',
                                                      'rtpmap:100 X-NSE/8000', 'fmtp:100 192-203']),
    ])
    ans = sdp('10.0.0.2', [
        ('audio', B_PORT, 'RTP/AVP', [0, 101], ['rtpmap:0 PCMU/8000', 'rtpmap:101 telephone-event/8000']),
        ('audio', B_PORT + 2, 'RTP/AVP', [0, 101], ['rtpmap:0 PCMU/8000']),
        ('audio', B_PORT + 4, 'RTP/AVP', [102, 100], ['rtpmap:102 telephone-event/16000',
                                                      'rtpmap:100 X-NSE/8000']),
    ])
    frames.append(udp_frame(5060, 5060, sip_invite('ev1', off)))
    frames.append(udp_frame(5060, 5060, sip_ok('ev1', ans), a_to_b=False))

    ssrc_a, ssrc_b = 0x11110001, 0x22220002
    seq = 100
    ts = 1000
    # voice then a DTMF digit: begin (marker), continuation, three end packets
    frames.append(udp_frame(A_PORT, B_PORT, rtp(0, seq, ts, ssrc_a, b'\xd5' * 160)))
    seq += 1
    ts += 160
    for end, dur, mk in [(False, 160, True), (False, 320, False), (False, 480, False),
                         (True, 640, False), (True, 640, False), (True, 640, False)]:
        frames.append(udp_frame(A_PORT, B_PORT, rtp(101, seq, ts, ssrc_a, event(5, end, False, 10, dur), marker=mk)))
        seq += 1
    # the answerer sends a '#' with the reserved bit and volume 63
    frames.append(udp_frame(B_PORT, A_PORT, rtp(101, 7, 5000, ssrc_b, event(11, True, True, 63, 800), marker=True),
                            a_to_b=False))
    # every event ID once (payload type 101 on the stream with an rtpmap)
    for ev in range(256):
        frames.append(udp_frame(A_PORT, B_PORT, rtp(101, seq, ts, ssrc_a, event(ev, ev % 3 == 0, False, ev % 64, ev * 7))))
        seq += 1
        ts += 160
    # the same without an rtpmap for 101: found through the rtp.pt range 100-101
    for ev in (0, 9, 16, 32, 255):
        frames.append(udp_frame(A_PORT + 2, B_PORT + 2, rtp(101, seq, ts, ssrc_a, event(ev, True, False, 0, 80))))
        seq += 1
        ts += 160
    # the other direction, payload type 102 (16 kHz telephone-event)
    for ev in (1, 2, 3):
        frames.append(udp_frame(B_PORT + 4, A_PORT + 4, rtp(102, seq, ts, ssrc_b, event(ev, ev == 3, False, 20, 320 * ev)),
                                a_to_b=False))
        seq += 1
    # Cisco NSE events (X-NSE, payload type 100, which is in the default range)
    for ev in (192, 193, 194, 199, 200, 201, 202, 203, 204):
        frames.append(udp_frame(A_PORT + 4, B_PORT + 4, rtp(100, seq, ts, ssrc_a, event(ev, False, False, 0, 0))))
        seq += 1
        ts += 160
    pcap(os.path.join(outdir, 'rtp-events-coverage.pcap'), frames)

    # malformed: payloads shorter than the 4 octet event
    mal = [frames[0], frames[1]]
    for n in (1, 2, 3):
        mal.append(udp_frame(A_PORT, B_PORT, rtp(101, 900 + n, 90000, ssrc_a, event(5)[:n])))
    pcap(os.path.join(outdir, 'rtp-events-coverage-malformed.pcap'), mal)

    # the dissector called directly by name from an Exported PDU capture:
    # there is no RTP conversation, so no setup frame
    pcap(os.path.join(outdir, 'rtp-events-coverage-expdu.pcap'),
         [exp_pdu('rtpevent', event(1, True, False, 5, 400))], linktype=252)


if __name__ == '__main__':
    main(sys.argv[1])
