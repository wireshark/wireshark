#!/usr/bin/env python3
# Generates test/captures/rtpproxy_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the RTPproxy dissector
(packet-rtpproxy.c: the RTPproxy command protocol and the rtpengine "ng"
bencode variant, over UDP and TCP port 22222).

Everything is built with struct; nothing comes from a real network.  A SIP
proxy (10.0.0.1) sends commands to the RTPproxy (10.0.0.2, port 22222,
the registered default, so no Decode As is needed) and gets replies.  The
replies to Update / Lookup commands carry the relay address, which sets up an
RTP and an RTCP conversation (by default, "establish_conversation"), so RTP
and RTCP packets to that address are included too.

Usage: mkrtpproxy.py <output directory>

Writes:
  rtpproxy-coverage.pcapng            main capture: every command, replies,
                                      sub-commands, ng bencode, TCP, RTP/RTCP
  rtpproxy-coverage-malformed.pcapng  bad addresses, short or odd commands
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




CLIENT, SERVER = 40000, 22222


def udp6_frame(sport, dport, payload):
    src = bytes.fromhex('20010db8000000000000000000000001')
    dst = bytes.fromhex('20010db8000000000000000000000002')
    u = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    pseudo = src + dst + struct.pack('>IBBBB', len(u), 0, 0, 0, 17)
    data = pseudo + u + (b'\0' if len(u) % 2 else b'')
    total = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    csum = (~total) & 0xffff or 0xffff
    u = u[:6] + struct.pack('>H', csum) + u[8:]
    ip = struct.pack('>IHBB', 0x60000000, len(u), 17, 64) + src + dst
    return MAC_B + MAC_A + b'\x86\xdd' + ip + u


def main(outdir):
    F = []
    t = [0.0]

    def req(text, dt=0.01, port=CLIENT):
        t[0] += dt
        F.append((0, (udp_frame(port, SERVER, text if isinstance(text, bytes) else text.encode()), t[0])))

    def rep(text, dt=0.01, port=CLIENT):
        t[0] += dt
        F.append((0, (udp_frame(SERVER, port, text if isinstance(text, bytes) else text.encode(), a_to_b=False), t[0])))

    # ---- handshake and versions ------------------------------------------
    req('c1 V\n')
    rep('c1 1\n')
    req('c2 VF 20150330\n')
    rep('c2 1\n')
    req('c3 VF 99999999\n')
    rep('c3 0\n')
    req('c4 VF 20260306\n')
    rep('c4 20260306\n')
    # ---- Update: every modifier, an IPv6 and a label form -------------------
    req('c5 Uc0,8,101,z20d101u1l10.0.0.9r192.0.2.5w call1@host 192.0.2.1 5004 from1;1 to1;1 unix:/var/run/notify.sock tag-n\n')
    rep('c5 35000 192.0.2.50\n')
    req('c6 Ul[2001:db8::1]r[2001:db8::2]Ae6 call2 2001:db8::5 5006 from2 to2 [2001:db8::7]:9000 tag-n\n')
    rep('c6 35002 2001:db8::50\n')
    req('c7 Ul{lbl1}ec0 call3 192.0.2.3 5008 from3;2 to3 tcp:%%CC_SELF%%:9999 tag-n\n')
    rep('c7 35004 192.0.2.51\n')
    req('c8 UiIsu call4 192.0.2.4 5010 from4 to4 9999 tag-n\n')                # port-only notify
    rep('c8 35006\n')
    req('c9 Uu call5 192.0.2.5 5012 ;1 to5 /tmp/notify-sock tag-n\n')       # empty from tag, path notify
    rep('c9 35008 192.0.2.52\n')
    req('c10 U call6 192.0.2.6 5014 from6 to6 10.9.8.7:5000 tag-n\n')       # IPv4:port notify
    rep('c10 35010 192.0.2.53\n')
    req('c11 U call7 192.0.2.7 5016 from7 to7 [2001:db8::9]:5001 tag-n\n')   # IPv6 notify
    rep('c11 35012 2001:db8::51\n')
    req('c12 U call8 192.0.2.8 5018 from8 to8 tcp:%%CC_SELF%%:6000 tag-n\n')
    rep('c12 35014 192.0.2.54\n')
    req('c13 U\n')                                                          # nothing after the command
    req('c14 U call9 192.0.2.9 5020 from9\n')                               # a single tag
    req('c15 U call10\n')
    # a request with a cookie that a later Q reuses (the two-pass reproducer)
    req('dup1 D call11 tag1\n')
    req('dup1 Q call11 tag1 tag2\n')
    rep('dup1 5 7\n')
    # the IP-and-port fix: the Info column shows IP:port
    req('abc123 U callid1 192.0.2.10 5004 tag1\n')
    rep('abc123 35016 192.0.2.55\n')
    # ---- Lookup ------------------------------------------------------------
    req('c20 Lc0,8 call1@host 192.0.2.60 5004 to1;1 from1;1\n')
    rep('c20 35018 192.0.2.56\n')
    req('c21 L call1@host 2001:db8::60 5004 to1 from1\n')
    rep('c21 35020 2001:db8::56\n')
    # ---- Information, delete, playback, recording, copy -------------------
    req('c22 I\n')
    rep('c22 sessions created: 3\nactive sessions: 1\n')
    req('c23 Ib\n')
    rep('c23 sessions created: 3 active sessions: 1\n')
    req('c24 D call1@host from1;1 to1;1\n')
    rep('c24 0\n')
    req('c25 Pc0,8 call1@host /tmp/moh.wav 0 from1;1 to1;1\n')
    rep('c25 0\n')
    req('c26 S call1@host from1 to1\n')
    rep('c26 0\n')
    req('c27 R call1@host from1 to1\n')
    rep('c27 0\n')
    req('c28 N call1@host from1 to1\n')
    rep('c28 0\n')
    req('c29 Cs call1@host /tmp/copy.wav from1;1 to1;1\n')
    rep('c29 0\n')
    req('c30 X\n')
    rep('c30 0\n')
    # ---- Query: named and positional counters, bad values -------------------
    req('c31 Q call1@host from1;1 to1;1 ttl npkts_ina nrelayed rtpa_jlast foo\n')
    rep('c31 30 120 118 0.250 7\n')
    req('c32 Q call1@host from1 to1\n')
    rep('c32 ttl=25 npkts_ina=10 =5 nrelayed=9 extra\n')
    req('c33 Q call1@host from1 to1 ttl npkts_ina\n')
    rep('c33 abc -1\n')
    req('c34 Q call1@host from1 to1 ttl\n')
    rep('c34 E50\n')
    req('c35 Q call1@host from1 to1 rtpa_nsent rtpa_javg longest_ipi\n')
    rep('c35 100 1.5 3\n')
    # ---- statistics -------------------------------------------------------------
    req('c36 Gv ttl npkts_ina  \n')
    rep('c36 0\n')
    req('c37 G\n')
    # ---- error replies ----------------------------------------------------------
    req('c38 U call12 192.0.2.12 5022 from12 to12\n')
    rep('c38 E7\n')
    req('c39 D call12 from12\n')
    rep('c39 E999\n')
    # ---- sub-commands (&&) --------------------------------------------------------
    req('c40 U call13 192.0.2.13 5024 from13 to13 && Qttl && D call13 from13\n')
    rep('c40 35022 192.0.2.57 && 5 && 0\n')
    req('c41 L call13 192.0.2.14 5026 to13 from13 &&\n')                       # dangling separator
    req('c42 U call14 192.0.2.15 5028 from14 to14 &&   && S x\n')
    rep('c42 35024 192.0.2.58 &&\n')
    # ---- no reply in time: expert info ----------------------------------------------
    req('c43 U call15 192.0.2.16 5030 from15 to15\n', dt=0.5)
    rep('c43 35026 192.0.2.59\n', dt=2.5)
    # ---- not RTPproxy ------------------------------------------------------------------
    req(b'\x01\x02\x03 not rtpproxy')
    req(b'nospace')
    req('c44 \n')
    # ---- rtpengine ng (bencode) ----------------------------------------------------------
    sdp_o = sdp('10.0.0.1', [('audio', 5004, 'RTP/AVP', [0], ['rtpmap:0 PCMU/8000'])]).decode()
    sdp_a = sdp('192.0.2.80', [('audio', 35100, 'RTP/AVP', [0], ['rtpmap:0 PCMU/8000'])]).decode()

    def b(s):
        return b'%d:%s' % (len(s), s.encode())
    ng = b'd' + b('command') + b('offer') + b('call-id') + b('ng-call-1') + b('sdp') + b(sdp_o) + \
        b('flags') + b'l' + b('trust-address') + b('SDES-off') + b'e' + b('from-tag') + b('ft1') + \
        b('x') + b'd' + b('n') + b'i42e' + b'ee'
    req(b'c50 ' + ng)
    rep(b'c50 d' + b('result') + b('ok') + b('sdp') + b(sdp_a) + b'e')
    req(b'c51 d' + b('command') + b('answer') + b('sdp') + b(sdp_o) + b'e')     # no call-id: remembered
    rep(b'c51 d' + b('result') + b('ok') + b'e')
    req(b'c52 d' + b('command') + b('ping') + b'e')
    rep(b'c52 d' + b('result') + b('pong') + b'e')
    req(b'c53 d' + b('command') + b('delete') + b('call-id') + b('ng-call-1') + b'e')
    rep(b'c53 d' + b('foo') + b'i5ee')                                                 # reply with no result
    req(b'c54 d' + b('command') + b('query') + b('call-id') + b('ng-call-2') + b'e')
    rep(b'c54 d' + b('result') + b('error') + b('error-reason') + b('Unknown call-id') + b'e')
    # ---- RTP and RTCP to the addresses the replies announced -------------------------------
    st = Stream(0x5a000001)
    for i in range(3):
        t[0] += 0.02
        F.append((0, (udp_frame(35000, 6000, st.pkt(0, bytes(range(40))), src=bytes([192, 0, 2, 50]), dst=bytes([10, 0, 0, 1]), a_to_b=False), t[0])))
    t[0] += 0.02
    sr = struct.pack('>BBHIQIII', 0x80, 200, 6, 0x5a000001, 0xe0f0a0b000000000, 160, 3, 120)
    F.append((0, (udp_frame(35001, 6001, sr, src=bytes([192, 0, 2, 50]), dst=bytes([10, 0, 0, 1]), a_to_b=False), t[0])))
    for i in range(2):
        t[0] += 0.02
        F.append((0, (udp_frame(6002, 35008, st.pkt(8, bytes(range(40))), src=bytes([10, 0, 0, 1]), dst=bytes([192, 0, 2, 52])), t[0])))

    # ---- TCP: with and without the terminating line feed ------------------------------------
    seq = [1, 1]

    def tcp(payload, c2s=True):
        t[0] += 0.01
        if c2s:
            F.append((0, (tcp_frame(41000, SERVER, seq[0], seq[1], 0x18, payload), t[0])))
            seq[0] += len(payload)
        else:
            F.append((0, (tcp_frame(SERVER, 41000, seq[1], seq[0], 0x18, payload, a_to_b=False), t[0])))
            seq[1] += len(payload)
    tcp(b'c60 V\n')
    tcp(b'c60 1\n', False)
    tcp(b'c61 U call20 192.0.2.20 5040 from20 to20')
    tcp(b'c61 35030 192.0.2.60', False)
    tcp(b'c62 I\n')
    tcp(b'c62 sessions created: 1\n', False)
    # ---- shorter forms of the commands, odd framing (appended at the end) -------------------
    req('d1 U call30 192.0.2.30\n')                       # IP only
    req('d2 U call30 192.0.2.30 5050\n')                  # no tags
    req('d3 U call30 192.0.2.30 5050 from30 \n')          # first tag, then white space
    req('d4 U call30 192.0.2.30 5050 from30 to30 \n')     # both tags, then white space
    req('d5 Cs call30 /tmp/c.wav\n')                      # copy target only
    req('d6 P call30 /tmp/m.wav\n')                       # file name only
    req('d7 P call30 /tmp/m.wav 8\n')                     # file name and codec only
    req('d8 Q call30 from30 to30 rtpa_jlast\n')
    rep('d8 abc\n')                                       # a double that is not a number
    req('d9 L call30 192.0.2.31 5052 to30 from30 &&  \n')  # separator, then only white space
    req('d10 Zfoo call30\n')                              # unknown command letter
    req('d13 U call&30 192.0.2.33 5056 from30 to30\n')    # an & that is not a sub-command separator
    req('d14 U call30 192.0.2.34 5058 from30 to&\n')      # ends in an &
    req('d11 V\n\x00\x00')                               # trailing NUL padding
    t[0] += 0.01
    F.append((0, (udp6_frame(40000, SERVER, b'd12 U call31 192.0.2.32 5054 from31 to31 9001 tag-n\n'), t[0])))   # notify without IP over IPv6
    pcapng(os.path.join(outdir, 'rtpproxy-coverage.pcapng'), F)

    # ---- malformed / odd ---------------------------------------------------------------------
    F = []
    t[0] = 0.0
    req('m1 Ur999.1.1.1 call1 192.0.2.1 5004 f t\n')
    req('m2 Ul[2001:zz::1] call1 192.0.2.1 5004 f t\n')
    req('m3 Ul{abc call1 192.0.2.1 5004 f t\n')
    req('m4 Ul{} call1 192.0.2.1 5004 f t\n')
    req('m5 Ul call1 192.0.2.1 5004 f t\n')
    req('m6 U call1 999.1.1.1 5004 f t\n')
    req('m7 U call1 2001:zz::1 5004 f t\n')
    req('m8 U call1 192.0.2.1 5004 f t 999.1.1.1:5000 tag\n')
    req('m9 U call1 192.0.2.1 5004 f t zz::1:5000 tag\n')
    req('m10 U call1 192.0.2.1 5004 f t tcp: tag\n')
    req('m11 U call1 192.0.2.1 5004 f t unix:\n')
    req('m12 Uz call1 192.0.2.1 5004 f t\n')
    req('m13 Ud call1 192.0.2.1 5004 f t\n')
    req('m14 Pc call1\n')
    req('m15 Cs\n')
    req('m16 Q call1 f t ttl\n')
    rep('m16 5\n')
    rep('m17 35000 999.1.1.1\n')
    rep('m18 35000 2001:zz::1\n')
    rep('m19 35000 192.0.2.1 and more\n')
    req(b'm20 d3:foo99999:x')                                           # string longer than the packet
    req(b'm20b d9:abc')
    req(b'm20f d3:foo5')                                                # a length with no colon
    req(b'm20g d3:foox')                                                # not a bencode element
    req(b'm20c d3:fooe')                                                # a terminator where a value should be
    req(b'm20d d3:fooi5ei7ei8ee')                                       # a key that is not a string
    req('m20e Ul[1:2:3:4:5:6:7:8:9] call1 192.0.2.1 5004 f t\n')       # IPv6 that does not parse
    req(b'm21 d7:command5:offe')
    req(b'm22 d3:foo' + b'l' * 30 + b'e' * 30 + b'e')                  # nested too deep
    req(b'm23 d3:fooi5')
    req(b'm24 d7:command99999999999:x')
    req(b'm25 d7:commandl3:foo3:bare')
    req(b'm26 d7:command5:offer3:sdp0:e')
    req(b'm27 d4:sdp 1:ae')
    req(b'm28 d3:abc')
    req(b'm29 d3:abc3:xyze')
    req(b'm30 di1ei2ee')
    req(b'm31 d3:sdp3:abce')
    req(b'm32 V')
    req('m33 VF 2015')
    req('m34 I')
    req('m35 U call1 192.0.2.1 5004 f t && && &&\n')
    req('m36 U call1 192.0.2.1 5004 f t &&&& x\n')
    req('m37 G ' + 'x ' * 40 + '\n')
    pcapng(os.path.join(outdir, 'rtpproxy-coverage-malformed.pcapng'), F)


if __name__ == '__main__':
    main(sys.argv[1])
