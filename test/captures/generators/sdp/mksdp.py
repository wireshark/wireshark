#!/usr/bin/env python3
# Generates test/captures/sdp_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generates the sdp coverage captures: mksdp.py <outdir>
# Everything is built with struct; nothing comes from a real network.
import sys
import struct

# ---- packet builders (all addresses are documentation addresses) ----
def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

MAC_A = b'\x02\0\0\0\0\x01'
MAC_B = b'\x02\0\0\0\0\x02'

def ip4(src, dst, proto, payload, ident=1):
    h = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0, 64,
                    proto, 0, bytes(src), bytes(dst))
    h = h[:10] + struct.pack('>H', csum(h)) + h[12:]
    return h + payload

def eth(src_mac, dst_mac, payload, etype=0x0800):
    return dst_mac + src_mac + struct.pack('>H', etype) + payload

def udp(src, dst, sport, dport, payload, ident=1):
    u = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    return eth(MAC_A if src[3] & 1 else MAC_B, MAC_B if src[3] & 1 else MAC_A,
               ip4(src, dst, 17, u, ident))

class Tcp:
    '''One TCP connection; seq numbers tracked per direction.'''
    def __init__(self, a, b, pa, pb):
        self.a, self.b, self.pa, self.pb = a, b, pa, pb
        self.sa, self.sb = 1000, 5000
        self.ident = 100
    def seg(self, fwd, payload=b'', flags=0x18):
        if fwd:
            s, d, sp, dp, seq, ack = self.a, self.b, self.pa, self.pb, self.sa, self.sb
        else:
            s, d, sp, dp, seq, ack = self.b, self.a, self.pb, self.pa, self.sb, self.sa
        if flags & 0x10 == 0:
            ack = 0
        opts = b''
        if flags & 2:
            opts = struct.pack('>BBH', 2, 4, 1460)
        t = struct.pack('>HHIIBBHHH', sp, dp, seq, ack, (5 + len(opts) // 4) << 4,
                        flags, 65535, 0, 0) + opts
        t += payload
        ph = bytes(s) + bytes(d) + struct.pack('>BBH', 0, 6, len(t))
        c = csum(ph + t)
        t = t[:16] + struct.pack('>H', c) + t[18:]
        adv = len(payload) + (1 if flags & 3 else 0)
        if fwd:
            self.sa += adv
        else:
            self.sb += adv
        self.ident += 1
        return eth(MAC_A if fwd else MAC_B, MAC_B if fwd else MAC_A,
                   ip4(s, d, 6, t, self.ident))
    def handshake(self):
        return [self.seg(True, b'', 0x02), self.seg(False, b'', 0x12),
                self.seg(True, b'', 0x10)]
    def close(self):
        return [self.seg(True, b'', 0x11), self.seg(False, b'', 0x11),
                self.seg(True, b'', 0x10)]

def exp_pdu(name, payload):
    n = name.encode()
    pad = (4 - len(n) % 4) % 4
    tags = struct.pack('>HH', 12, len(n) + pad) + n + b'\0' * pad
    tags += struct.pack('>HH', 0, 0)
    return tags + payload

class Cap:
    """pcapng writer; packets are (linktype, data). Linktype 1 = Ethernet,
    252 = Exported PDU."""
    def __init__(self):
        self.pkts = []
        self.t = 1700000000
    def add(self, p, linktype=1):
        self.pkts.append((linktype, p))
        return len(self.pkts)
    @staticmethod
    def blk(btype, body):
        body += b'\0' * ((4 - len(body) % 4) % 4)
        n = 12 + len(body)
        return struct.pack('<II', btype, n) + body + struct.pack('<I', n)
    def write(self, path):
        out = self.blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
        lts = []
        for lt, _ in self.pkts:
            if lt not in lts:
                lts.append(lt)
        for lt in lts:
            out += self.blk(1, struct.pack('<HHI', lt, 0, 262144))
        for i, (lt, p) in enumerate(self.pkts):
            ts = (self.t + i) * 1000000 + i * 1000
            out += self.blk(6, struct.pack('<IIIII', lts.index(lt), ts >> 32,
                                           ts & 0xffffffff, len(p), len(p)) + p)
        with open(path, 'wb') as f:
            f.write(out)

A = [192, 0, 2, 1]
B = [192, 0, 2, 2]
MC = [224, 2, 127, 254]
CRLF = b'\r\n'

def sdp_text(lines):
    return b''.join(l.encode() + CRLF for l in lines)

# ---- SIP carrier ----
def sip(first, cid, cseq, method, body=b'', ctype=b'application/sdp', frm=A, to=B,
        extra=b'', tag2=True):
    h = first.encode() + CRLF
    h += b'Via: SIP/2.0/UDP %d.%d.%d.%d:5060;branch=z9hG4bK%s' % (tuple(frm) + (cid.encode(),)) + CRLF
    h += b'From: <sip:a@192.0.2.1>;tag=a%s' % cid.encode() + CRLF
    h += b'To: <sip:b@192.0.2.2>' + (b';tag=b%s' % cid.encode() if tag2 else b'') + CRLF
    h += b'Call-ID: %s@192.0.2.1' % cid.encode() + CRLF
    h += b'CSeq: %d %s' % (cseq, method.encode()) + CRLF
    h += b'Contact: <sip:a@192.0.2.1:5060>' + CRLF + extra
    if body:
        h += b'Content-Type: ' + ctype + CRLF
    h += b'Content-Length: %d' % len(body) + CRLF + CRLF
    return h + body

def invite(cap, cid, body, cseq=1, method='INVITE', ack=False):
    return cap.add(udp(A, B, 5060, 5060, sip('%s sip:b@192.0.2.2 SIP/2.0' % method, cid, cseq, method, body,
                                             tag2=(method != 'INVITE'))))

def ok(cap, cid, body, cseq=1, method='INVITE', code='200 OK'):
    return cap.add(udp(B, A, 5060, 5060, sip('SIP/2.0 ' + code, cid, cseq, method, body, frm=B)))

def rtp(pt, seq, ssrc=0x1234, ts=None, payload=b'\0' * 20, marker=0):
    return struct.pack('>BBHII', 0x80, (marker << 7) | pt, seq, ts if ts is not None else seq * 160, ssrc) + payload

def media_pkt(cap, src, dst, sport, dport, data):
    cap.add(udp(src, dst, sport, dport, data))

B64_SPS = 'Z0IACpZTBYmI'
B64_PPS = 'aMljiA=='
B64_VPS = 'QAEMAf//AWAAAAMAkAAAAwAAAwBdlZgJ'
B64_SPS265 = 'QgEBAWAAAAMAkAAAAwAAAwBdoAKAgC0WWVmkkyvAQEAAAAMAQAAABkI='
B64_PPS265 = 'RAHAcYDbQA=='
KEYA = 'WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz'   # made-up 30 octets, base64
KEYB = 'QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo1QUJD'
# MIKEY with header, timestamp and RAND payloads only (no key data)
MIKEY = 'AQAFgAoLDA0BAAARIjNEAAAAAAsA6POhsgAAAAAAEAABAgMEBQYHCAkKCwwNDg8='

SESSION = [
    'v=0',
    'o=alice 2890844526 2890842807 IN IP4 192.0.2.1',
    's=Kitchen sink',
    'i=Session information',
    'u=http://www.example.com/seminars/sdp.pdf',
    'e=j.doe@example.com (Jane Doe)',
    'p=+1 617 555-6011',
    'c=IN IP4 224.2.17.12/127/3',
    'b=CT:128',
    'b=AS:64',
    'b=TIAS:64000',
    'b=RR:800',
    't=2873397496 2873404696',
    'r=7d 1h 0 25h',
    'r=604800 3600 0',
    'z=2882844526 -1h 2898848070 0',
    'k=clear:made-up-key',
    'a=ipbcp:1 Request',
    'a=key-mgmt:mikey ' + MIKEY,
    'a=recvonly',
    'a=group:BUNDLE audio video',
    'a=ice-lite',
    'a=ice-ufrag:abcd',
    'a=ptime:20',
]

def build(outdir):
    cap = Cap()
    frames = {}
    def mark(name):
        frames[name] = len(cap.pkts)

    # ===== Call 1: SIP offer/answer carrying the kitchen sink =====
    offer1 = sdp_text([l for l in SESSION if not l.startswith('a=key-mgmt')] + [
        'm=audio 5004/2 RTP/AVP 0 8 18 96 101 9',
        'i=Audio title',
        'c=IN IP4 192.0.2.1',
        'b=AS:80',
        'a=rtpmap:96 opus/48000/2',
        'a=rtpmap:101 telephone-event/8000',
        'a=rtpmap:9 G722/8000',
        'a=rtpmap:0 PCMU/8000',
        'a=fmtp:101 0-16',
        'a=fmtp:96 minptime=10;useinbandfec=1',
        'a=fmtp:18 annexb=no',
        'a=sendrecv',
        'a=rtcp:5105',
        'm=video 5006 RTP/AVP 97 98 99 100 102 103',
        'c=IN IP6 2001:db8::1',
        'a=rtpmap:97 H264/90000',
        'a=fmtp:97 profile-level-id=42e01f;packetization-mode=1;sprop-parameter-sets=%s,%s' % (B64_SPS, B64_PPS),
        'a=rtpmap:98 H265/90000',
        'a=fmtp:98 sprop-vps=%s;sprop-sps=%s;sprop-pps=%s' % (B64_VPS, B64_SPS265, B64_PPS265),
        'a=rtpmap:99 MP4V-ES/90000',
        'a=fmtp:99 profile-level-id=1',
        'a=rtpmap:100 H263-2000/90000',
        'a=fmtp:100 profile=0;level=10',
        'a=rtpmap:102 H263-1998/90000',
        'a=fmtp:102 profile=3;level=45',
        'a=rtpmap:103 H264-SVC/90000',
        'a=fmtp:103 packetization-mode=2;profile-level-id=53001f',
        'a=rtcp-mux',
        'a=sendrecv',
        'm=message 7394 msrp/tcp *',
        'c=IN IP4 192.0.2.1',
        'a=path:msrp://192.0.2.1:7394/abc123;tcp',
        'a=accept-types:text/plain',
        'm=image 5008 udptl t38',
        'a=T38FaxVersion:0',
    ])
    answer1 = sdp_text([
        'v=0', 'o=bob 2890844527 2890842808 IN IP4 192.0.2.2', 's=-',
        'c=IN IP4 192.0.2.2', 't=0 0',
        'm=audio 6004 RTP/AVP 0 96 101',
        'a=rtpmap:96 opus/48000/2',
        'a=rtpmap:101 telephone-event/8000',
        'a=fmtp:101 0-15',
        'm=video 0 RTP/AVP 97',
        'm=message 7396 msrp/tcp *',
        'a=path:msrp://192.0.2.2:7396/def456;tcp',
        'm=image 6008 udptl t38',
    ])
    invite(cap, 'c1', offer1)
    # retransmission of the INVITE before any response (a resend does not count)
    invite(cap, 'c1', offer1)
    ok(cap, 'c1', b'', code='100 Trying')
    ok(cap, 'c1', answer1)
    # retransmission of the final response
    ok(cap, 'c1', answer1)
    mark('call1_answer')
    cap.add(udp(A, B, 5060, 5060, sip('ACK sip:b@192.0.2.2 SIP/2.0', 'c1', 1, 'ACK')))
    # media on the negotiated ports (RTP, RTCP)
    media_pkt(cap, A, B, 5004, 6004, rtp(96, 1, payload=b'\x78' * 30))
    media_pkt(cap, B, A, 6004, 5004, rtp(0, 1, ssrc=0x4321, payload=b'\xff' * 160))
    media_pkt(cap, A, B, 5004, 6004, rtp(101, 2, payload=b'\x01\x0a\x00\xa0'))
    media_pkt(cap, A, B, 5005, 6005, struct.pack('>BBHI', 0x80, 201, 1, 0x1234) )
    mark('call1_media')
    # in-dialog re-offer (UPDATE): a new offer for the same call
    invite(cap, 'c1', sdp_text([
        'v=0', 'o=alice 2890844526 2890842808 IN IP4 192.0.2.1', 's=-',
        'c=IN IP4 192.0.2.1', 't=0 0', 'm=audio 5004 RTP/AVP 0 96',
        'a=rtpmap:96 opus/48000/2', 'a=sendonly']), cseq=2, method='UPDATE')
    ok(cap, 'c1', sdp_text([
        'v=0', 'o=bob 2890844527 2890842809 IN IP4 192.0.2.2', 's=-',
        'c=IN IP4 192.0.2.2', 't=0 0', 'm=audio 6004 RTP/AVP 0',
        'a=recvonly']), cseq=2, method='UPDATE')

    # ===== Call 2: video offer rejected with a 488 that carries SDP =====
    invite(cap, 'c2', sdp_text([
        'v=0', 'o=- 1 1 IN IP4 192.0.2.1', 's=-', 'c=IN IP4 192.0.2.1', 't=0 0',
        'm=video 5020 RTP/AVPF 96', 'a=rtpmap:96 H264/90000',
        'a=fmtp:96 profile-level-id=64001f;packetization-mode=0']))
    ok(cap, 'c2', sdp_text([
        'v=0', 'o=- 1 1 IN IP4 192.0.2.2', 's=-', 'c=IN IP4 192.0.2.2', 't=0 0',
        'm=video 0 RTP/AVPF 96']), code='488 Not Acceptable Here')
    mark('call2_reject')

    # ===== Call 3: SRTP crypto offer and answer (made-up keys) =====
    offer3 = sdp_text([
        'v=0', 'o=- 3 3 IN IP4 192.0.2.1', 's=-', 'c=IN IP4 192.0.2.1', 't=0 0',
        'm=audio 5030 RTP/SAVP 0 8',
        'a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:%s|2^20|1:4' % KEYA,
        'a=crypto:2 AES_CM_128_HMAC_SHA1_32 inline:%s|2^31' % KEYB,
        'a=crypto:3 F8_128_HMAC_SHA1_80 inline:%s|1048576|7:12' % KEYA,
        'a=crypto:4 UNKNOWN_SUITE inline:%s' % KEYB,
        'a=crypto:5 AES_CM_128_HMAC_SHA1_80 inline:%s;inline:%s|2^20' % (KEYA, KEYB),
        'a=crypto:7 AES_CM_128_HMAC_SHA1_80 inline:%s|99:5' % KEYA,
        'a=crypto:8 AES_CM_128_HMAC_SHA1_80 other:%s' % KEYA,
        'm=video 5032 UDP/TLS/RTP/SAVPF 96',
        'a=rtpmap:96 VP8/90000',
        'a=rtcp-mux:1',
        'a=fingerprint:sha-256 00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF',
        'a=setup:actpass',
        'a=candidate:1 1 UDP 2130706431 192.0.2.1 5032 typ host',
        'a=candidate:2 1 TCP 1694498815 198.51.100.7 9 typ srflx raddr 192.0.2.1 rport 5032',
        'a=candidate:3 1 UDP 1677729535 198.51.100.8 5033 typ prflx',
        'a=candidate:4 1 UDP 100 203.0.113.9 3478 typ relay',
        'a=candidate:5 1 UDP 100 203.0.113.9 3478 typ other',
        'a=candidate:6 1 UDP 100 203.0.113.9 3478 no-typ',
    ])
    invite(cap, 'c3', offer3)
    ok(cap, 'c3', sdp_text([
        'v=0', 'o=- 3 3 IN IP4 192.0.2.2', 's=-', 'c=IN IP4 192.0.2.2', 't=0 0',
        'm=audio 6030 RTP/SAVP 0',
        'a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:%s|2^20|1:4' % KEYB,
        'm=video 6032 UDP/TLS/RTP/SAVPF 96', 'a=rtpmap:96 VP8/90000']))
    mark('call3_srtp')

    # ===== Call 4: V.150 SPRT, BFCP, T.38 without RTP, MSRP forms =====
    invite(cap, 'c4', sdp_text([
        'v=0', 'o=- 4 4 IN IP4 192.0.2.1', 's=-', 'c=IN IP4 192.0.2.1', 't=0 0',
        'm=audio 5040 RTP/AVP 0 120',
        'a=rtpmap:120 v150fw/8000',
        'm=audio 0 UDPSPRT 120',
        'a=sprtmap:120 v150fw/8000',
        'm=audio 5042 udpsprt 120',
        'm=application 5044 UDP/BFCP *',
        'a=floorctrl:c-s',
        'm=message 7400 msrp/tcp *',
        'a=path:msrp://192.0.2.1/session;tcp',
    ]))
    ok(cap, 'c4', sdp_text([
        'v=0', 'o=- 4 4 IN IP4 192.0.2.2', 's=-', 'c=IN IP4 192.0.2.2', 't=0 0',
        'm=audio 6040 RTP/AVP 0',
        'm=audio 0 UDPSPRT 120',
        'm=audio 6042 udpsprt 120',
        'm=application 6044 UDP/BFCP *',
        'm=message 7402 msrp/tcp *',
        'a=path:msrp://192.0.2.2:7402;tcp',
    ]))
    invite(cap, 'c5', sdp_text([
        'v=0', 'o=- 5 5 IN IP4 192.0.2.1', 's=-', 'c=IN IP4 192.0.2.1', 't=0 0',
        'm=image 5050 UDPTL t38',
        'a=T38FaxVersion:0', 'a=T38MaxBitRate:14400',
        'm=message 7410 msrp/tcp *',
        'a=path:msrp://not-an-ip:7410/abc;tcp',
        'm=message 7411 msrp/tcp *',
        'a=path:msrp://192.0.2.1:badport/abc;tcp',
        'm=message 7412 msrp/tcp *',
        'a=path:msrp://192.0.2.1:7412',
    ]))
    ok(cap, 'c5', sdp_text([
        'v=0', 'o=- 5 5 IN IP4 192.0.2.2', 's=-', 'c=IN IP6 2001:db8::2', 't=0 0',
        'm=image 6050 udptl t38', 'a=T38FaxVersion:0']))

    # ===== Call 6: bundle, more media descriptions than the limit, many
    # payload types, session level rtpmap/fmtp/crypto/control =====
    pts = ' '.join(str(p) for p in list(range(0, 8)) + list(range(96, 116)))
    invite(cap, 'c6', sdp_text([
        'v=0', 'o=- 6 6 IN IP4 192.0.2.1', 's=-', 'c=IN IP4 192.0.2.1', 't=0 0',
        'a=rtpmap:111 opus/48000/2',
        'a=fmtp:111 useinbandfec=1',
        'a=control:rtsp://192.0.2.1/session6',
        'm=audio 5160 RTP/AVP ' + pts,
        'm=video 5160 RTP/AVP 96',
        'a=rtpmap:96 VP8/90000',
        'a=mid:video',
        'm=audio 5162 RTP/AVP 0',
        'a=rtcp:5170 IN IP4 192.0.2.1',
        'm=audio 5164 RTP/AVP 8',
        'm=audio 5166 RTP/AVP 18',
        'm=video 5168 RTP/AVP 31',
        'm=text 5170 RTP/AVP 98',
        'a=rtpmap:98 t140/1000',
    ]))
    ok(cap, 'c6', sdp_text([
        'v=0', 'o=- 6 6 IN IP4 192.0.2.2', 's=-', 'c=IN IP4 192.0.2.2', 't=0 0',
        'm=audio 6160 RTP/AVP 0', 'm=video 6160 RTP/AVP 96', 'a=rtpmap:96 VP8/90000',
        'm=audio 6162 RTP/AVP 0', 'm=audio 6164 RTP/AVP 8']))

    # ===== The reproducers of the fixes in this batch =====
    # same a=control: URI in two m= sections of an SDP (use after free)
    def ctl_sdp(p0, p1, ctl):
        s = ['v=0', 'o=- 1 1 IN IP4 192.0.2.1', 's=-', 'c=IN IP4 192.0.2.1', 't=0 0',
             'm=audio %d RTP/AVP 96' % p0, 'a=rtpmap:96 opus/48000/2']
        if ctl:
            s.append('a=control:rtsp://192.0.2.1/x')
        s += ['m=video %d RTP/AVP 97' % p1, 'a=rtpmap:97 H264/90000']
        if ctl:
            s.append('a=control:rtsp://192.0.2.1/x')
        return sdp_text(s)
    invite(cap, 'c7', ctl_sdp(5080, 5082, True))
    ok(cap, 'c7', ctl_sdp(6080, 6082, False))
    mark('repro_dfree')
    cap.add(exp_pdu('sdp', ctl_sdp(5084, 5086, True)), 252)
    mark('repro_uaf')

    # ===== Exported PDU "sdp": SDP without an offer/answer exchange =====
    cap.add(exp_pdu('sdp', sdp_text(SESSION + [
        'm=audio 5090 RTP/AVP 0 96', 'a=rtpmap:96 AMR/8000/1', 'a=fmtp:96 mode-set=0,2,4,7',
        'a=ed137type:Radio', 'a=ed137txrxmode:TxRx', 'a=ed137fid:123.450',
        'a=type:Radio', 'a=txrxmode:TxRx', 'a=fid:123.450',
        'a=sendonly',
        'm=video 5091 RTP/AVP 99', 'a=rtpmap:99 MP4V-ES/90000',
        'a=fmtp:99 profile-level-id=1',
        'm=audio 5092 RTP/AVP 8', 'a=type:Radio', 'a=rtcp:5093', 'a=rtcp:abc',
        'm=audio 5094 RTP/AVP 8', 'a=rtcp-mux', 'a=rtcp-mux:1',
    ])), 252)
    mark('exp_ed137')
    # tokens: fmtp with string formats, unknown fmtp mime types, h248item,
    # session-level attributes before any m=
    cap.add(exp_pdu('sdp', sdp_text([
        'v=0', 'o=- 2 2 IN IP4 192.0.2.1', 's=-', 'c=IN IP4 192.0.2.1', 't=0 0',
        'a=rtpmap:96 opus/48000/2', 'a=fmtp:96 stereo=1', 'a=fmtp:96 stereo=1;sprop-stereo=1',
        'a=crypto:9 AES_CM_128_HMAC_SHA1_80 inline:%s' % KEYA,
        'a=ipbcp:2.0 Request', 'a=ipbcp:1 Bearer',
        'a=key-mgmt:unknownproto ' + MIKEY, 'a=custom:value',
        'm=application 9 UDP/TLS/RTP/SAVP ipdc-kmm', 'a=fmtp:ipdc-kmm xyz=1',
        'm=application 9 RTP/AVP mcptt', 'a=fmtp:mcptt mc_queueing',
        'm=application 9 RTP/AVP mcvideo', 'a=fmtp:mcvideo x',
        'm=application 9 RTP/AVP mcdata', 'a=fmtp:mcdata x',
        'm=application 9 RTP/AVP tbcp', 'a=fmtp:tbcp x',
        'm=audio 5100 RTP/AVP 0',
        'a=h248item:h324ext/h223lcparm=08',
        'a=h248item:other/item=01',
        'a=h248item:h324ext/other=08',
        'a=h248item:h324ext/h223lcparm',
        'a=h248item:h324ext/h223lcparm=zz',
        'a=key-mgmt:mikey ' + MIKEY,
        'a=fmtp:96 0',
        'a=fmtp:0 a=b',
        'a=rtpmap:96 opus/48000',
        'a=rtpmap:97 opus/48000/1',
        'a=rtpmap:0 PCMU/8000',
        'a=rtpmap:9 G722/8000/1',
        'a=rtpmap:8 PCMA/8000/2/extra',
    ])), 252)
    mark('exp_misc')
    # IPv6 connection, port counts, "c=" at media level only, k= prompt
    cap.add(exp_pdu('sdp', sdp_text([
        'v=0', 'o=- 3 3 IN IP6 2001:db8::1', 's=-', 'i=info', 't=0 0', 'k=base64:YWJj',
        'k=uri:http://x.example/key', 'k=prompt',
        'b=X-YZ:128',
        'm=audio 5110/2 RTP/AVP 0', 'c=IN IP6 ff15::101/3', 'c=IN IP4 192.0.2.5/127', 'i=title',
        'm=video 5112 RTP/AVP 31', 'c=IN IP4 192.0.2.5',
        'm=audio 5114 RTP/AVP 0',
        'c=IN IP4 bogus',
        'c=IN IP6 bogus',
        'c=IN IP9 192.0.2.5',
        'm=audio 5116 FOO/BAR 0 1 2',
        'z=1 2 3 4 5 6',
        'x=unknown line type',
    ])), 252)
    mark('exp_misc2')
    # the first crypto line of an SDP sets the algorithms: other suites first
    for suite, extra in (('AES_CM_128_HMAC_SHA1_32', '|2^20|1:4'), ('F8_128_HMAC_SHA1_80', '|2^20|1:4'),
                         ('AES_CM_128_HMAC_SHA1_80', '')):
        cap.add(exp_pdu('sdp', sdp_text(['v=0', 'o=- 5 5 IN IP4 192.0.2.1', 's=-', 'c=IN IP4 192.0.2.1', 't=0 0',
            'm=audio 5105 RTP/SAVP 0', 'a=crypto:1 %s inline:%s%s' % (suite, KEYA, extra)])), 252)
    mark('exp_crypto')
    # a trailing blank line, then more data after the SDP
    cap.add(exp_pdu('sdp', sdp_text(['v=0', 'o=- 4 4 IN IP4 192.0.2.1', 's=-', 't=0 0', '', 'trailing=data', 'a=x'])), 252)

    # ===== SIP header combinations around SDP (multipart not used) =====
    # SIP with Content-Type that carries parameters and upper case
    invite(cap, 'c8', sdp_text(['v=0', 'o=- 8 8 IN IP4 192.0.2.1', 's=-', 'c=IN IP4 192.0.2.1', 't=0 0',
                                'm=audio 5120 RTP/AVP 0']), method='INVITE')
    cap.add(udp(B, A, 5060, 5060, sip('SIP/2.0 183 Session Progress', 'c8', 1, 'INVITE',
        sdp_text(['v=0', 'o=- 8 8 IN IP4 192.0.2.2', 's=-', 'c=IN IP4 192.0.2.2', 't=0 0', 'm=audio 6120 RTP/AVP 0']),
        ctype=b'APPLICATION/SDP; charset=utf-8', frm=B)))
    ok(cap, 'c8', sdp_text(['v=0', 'o=- 8 8 IN IP4 192.0.2.2', 's=-', 'c=IN IP4 192.0.2.2', 't=0 0', 'm=audio 6120 RTP/AVP 0']))
    # a different final response with SDP after the answer: the offer is already answered
    ok(cap, 'c8', sdp_text(['v=0', 'o=- 8 8 IN IP4 192.0.2.2', 's=-', 'c=IN IP4 192.0.2.2', 't=0 0', 'm=audio 6122 RTP/AVP 0']),
       code='487 Request Terminated')

    # ===== RTSP: DESCRIBE reply with SDP (a=control) and SETUP =====
    t = Tcp(A, B, 40100, 554)
    for p in t.handshake():
        cap.add(p)
    req = (b'DESCRIBE rtsp://192.0.2.2/stream RTSP/1.0\r\nCSeq: 1\r\nAccept: application/sdp\r\n\r\n')
    cap.add(t.seg(True, req))
    body = sdp_text([
        'v=0', 'o=- 9 9 IN IP4 192.0.2.2', 's=Stream', 'c=IN IP4 0.0.0.0', 't=0 0',
        'a=control:*',
        'm=video 0 RTP/AVP 96', 'a=rtpmap:96 H264/90000',
        'a=fmtp:96 packetization-mode=1;profile-level-id=42e01f',
        'a=control:trackID=1',
        'm=audio 0 RTP/AVP 97', 'a=rtpmap:97 MPEG4-GENERIC/44100/2',
        'a=control:rtsp://192.0.2.2/stream/trackID=2',
        'm=audio 0 RTP/AVP 0', 'a=control:TrackID=3',
    ])
    rep = (b'RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Base: rtsp://192.0.2.2/stream/\r\n'
           b'Content-Type: application/sdp\r\nContent-Length: %d\r\n\r\n' % len(body)) + body
    cap.add(t.seg(False, rep))
    mark('rtsp_describe')
    for i, u in enumerate(['rtsp://192.0.2.2/stream/trackID=1', 'rtsp://192.0.2.2/stream/trackID=2']):
        req = (b'SETUP %s RTSP/1.0\r\nCSeq: %d\r\nTransport: RTP/AVP;unicast;client_port=%d-%d\r\n\r\n'
               % (u.encode(), 2 + i * 2, 41000 + i * 4, 41001 + i * 4))
        cap.add(t.seg(True, req))
        rep = (b'RTSP/1.0 200 OK\r\nCSeq: %d\r\nSession: 12345678\r\n'
               b'Transport: RTP/AVP;unicast;client_port=%d-%d;server_port=%d-%d\r\n\r\n'
               % (2 + i * 2, 41000 + i * 4, 41001 + i * 4, 6970 + i * 2, 6971 + i * 2))
        cap.add(t.seg(False, rep))
    mark('rtsp_setup')
    media_pkt(cap, B, A, 6970, 41000, rtp(96, 1, payload=b'\x09\x10'))
    for p in t.close():
        cap.add(p)

    # ===== HTTP carrying application/sdp, SAP, MGCP =====
    t = Tcp(A, B, 40200, 80)
    for p in t.handshake():
        cap.add(p)
    cap.add(t.seg(True, b'GET /call.sdp HTTP/1.1\r\nHost: 192.0.2.2\r\n\r\n'))
    body = sdp_text(['v=0', 'o=- 10 10 IN IP4 192.0.2.2', 's=-', 'c=IN IP4 192.0.2.2', 't=0 0',
                     'm=audio 5130 RTP/AVP 0', 'a=control:http://192.0.2.2/audio'])
    cap.add(t.seg(False, b'HTTP/1.1 200 OK\r\nContent-Type: application/sdp\r\nContent-Length: %d\r\n\r\n' % len(body) + body))
    mark('http_sdp')
    for p in t.close():
        cap.add(p)
    sdpb = sdp_text(['v=0', 'o=- 11 11 IN IP4 192.0.2.1', 's=SAP session', 'c=IN IP4 224.2.17.12/127',
                     't=0 0', 'm=audio 5140 RTP/AVP 0'])
    sap = struct.pack('>BBH4s', 0x20, 0, 0x1234, bytes(A)) + b'application/sdp\0' + sdpb
    cap.add(udp(A, MC, 9875, 9875, sap))
    mark('sap')
    cap.add(udp(A, B, 2727, 2427,
        b'CRCX 1201 aaln/1@gw.example.net MGCP 1.0\r\nC: A3C47F21456789F0\r\nL: p:10, a:PCMU\r\nM: recvonly\r\n\r\n' +
        sdp_text(['v=0', 'c=IN IP4 192.0.2.1', 'm=audio 5150 RTP/AVP 0'])))
    cap.add(udp(B, A, 2427, 2727,
        b'200 1201 OK\r\nI: FDE234C8\r\n\r\n' +
        sdp_text(['v=0', 'c=IN IP4 192.0.2.2', 'm=audio 6150 RTP/AVP 0'])))
    mark('mgcp')
    media_pkt(cap, A, B, 5150, 6150, rtp(0, 1, payload=b'\xff' * 80))
    cap.add(udp(A, B, 2727, 2427,
        b'CRCX 1202 aaln/2@gw.example.net MGCP 1.0\r\nC: A3C47F21456789F1\r\nL: p:10, a:PCMU\r\nM: recvonly\r\nX-Osmux: ON\r\n\r\n' +
        sdp_text(['v=0', 'c=IN IP4 192.0.2.1', 'm=audio 5152 RTP/AVP 0'])))
    cap.add(udp(B, A, 2427, 2727,
        b'200 1202 OK\r\nI: FDE234C9\r\nX-Osmux: ON\r\n\r\n' +
        sdp_text(['v=0', 'c=IN IP4 192.0.2.2', 'm=audio 6152 RTP/AVP 0'])))
    mark('mgcp_osmux')
    # H.248 (text encoding, UDP 2944) with SDP in the Local and Remote descriptors
    mg = (b'MEGACO/1 [192.0.2.1]:2944\r\nTransaction = 10 {\r\n Context = 5 {\r\n  Add = RTP/1 {\r\n'
          b'   Media {\r\n    LocalControl {Mode = SendReceive},\r\n    Local {\r\n'
          + sdp_text(['v=0', 'c=IN IP4 192.0.2.1', 'm=audio 5200 RTP/AVP 0']) +
          b'    },\r\n    Remote {\r\n'
          + sdp_text(['v=0', 'c=IN IP4 192.0.2.2', 'm=audio 6200 RTP/AVP 0']) +
          b'    }\r\n   }\r\n  }\r\n }\r\n}\r\n')
    cap.add(udp(A, B, 2944, 2944, mg))
    mark('megaco')

    cap.write(outdir + '/sdp-coverage.pcapng')
    with open(outdir + '/frames.txt', 'w') as f:
        for k, v in frames.items():
            f.write('%s %d\n' % (k, v))

    # ===== malformed capture: paths that only malformed SDP reaches =====
    # Every bad line gets an SDP of its own: a line shorter than 2
    # octets or a token error ends or aborts the rest of the dissection.
    cap = Cap()
    def xp(lines, raw=None):
        cap.add(exp_pdu('sdp', raw if raw is not None else sdp_text(lines)), 252)
    SESS = ['v=0', 's=-']
    MED = ['v=0', 'c=IN IP4 192.0.2.1', 'm=audio 5004 RTP/AVP 96', 'a=rtpmap:96 opus/48000/2']
    VID = ['v=0', 'c=IN IP4 192.0.2.1', 'm=video 5004 RTP/AVP 96 97 98 99 100']
    def one(ctx, lines):
        for l in lines:
            xp(ctx + [l])
    one(SESS, ['garbage without equal sign', 'o=', 'c=', 'b=', 'b=AS', 't=', 'r=', 'r=1', 'z=', 'k=', 'k=nocolon',
               'a=', 'a=:', 'a=x:', 'a=ipbcp:', 'a=ipbcp: ', 'a=ipbcp:x', 'a=ipbcp:1 ', 'a=key-mgmt:',
               'o=a ', 'o=a 1 ', 'o=a 1 2 ', 'o=a 1 2 IN ', 'o=a 1 2 IN IP4 ', 'o=a', 'o=a 1', 'o=a 1 2', 'o=a 1 2 IN',
               'o=a 1 2 IN IP4', 'o=a  1', 'c=IN ', 'c=IN IP4 ', 'c=IN IP4 192.0.2.1/', 'c=IN IP4 192.0.2.1//2',
               'c=IN', 'c=IN IP4', 'b=CT', 'b=CT:', 't=1 ', 't=1', 'r=7d ', 'r=7d', 'r=7d 1h', 'r=7d 1h ', 'r=7d  1h 0',
               'z=1 ', 'z=1 2 3', 'z=1 2 3 ', 'z=1 ', 'z= ', 'z=1  2', 'i=', 'u=', 'e=', 'p=',
               'm=', 'm=audio', 'm=audio ', 'm=audio 5004', 'm=audio 5004 ', 'm=audio  5004  RTP/AVP  0  8',
               'm=audio 70000 RTP/AVP 0', 'm=audio 5004/ RTP/AVP 0', 'm=audio 5004/2', 'm=audio 5004/2 ',
               'm=audio abc RTP/AVP 0', 'm=audio -1 RTP/AVP 0', 'm=audio a/2 RTP/AVP 0', 'm=audio 70000/2 RTP/AVP 0',
               'm=audio 5118 RTP/AVP', 'm=audio 5118 RTP/AVP ', 'm=audio 5118 RTP/AVP  0',
               'm=audio 5004/', 'm=audio 5004/2 ', 'a=key-mgmt: ', 'a=key-mgmt:  ', 'a=rtcp-mux:', 'a=ipbcp:  ',
               'm', 'v', '=', 'ab'])
    one(MED, ['a=rtpmap:', 'a=rtpmap:96', 'a=rtpmap:96 ', 'a=rtpmap:96 opus', 'a=rtpmap:96 opus/', 'a=rtpmap:96 opus/abc',
              'a=rtpmap:96 opus/48000/x', 'a=rtpmap:999 opus/48000', 'a=rtpmap:x opus/48000', 'a=rtpmap:96 x',
              'a=fmtp:', 'a=fmtp:96', 'a=fmtp:999 x=1', 'a=fmtp:abc x=1', 'a=fmtp:96 ', 'a=fmtp:96 =',
              'a=fmtp:96 x=1;;y=2;', 'a=fmtp: 96 x=1', 'a=control:', 'a=rtcp:', 'a=type:', 'a=path:',
              'a=crypto:', 'a=crypto:x', 'a=crypto:abc AES_CM_128_HMAC_SHA1_80 inline:' + KEYA,
              'a=crypto:99999999999 AES_CM_128_HMAC_SHA1_80 inline:' + KEYA,
              'a=crypto:1', 'a=crypto:1 ', 'a=crypto:1 AES_CM_128_HMAC_SHA1_80', 'a=crypto:1 AES_CM_128_HMAC_SHA1_80 ',
              'a=crypto:1 AES_CM_128_HMAC_SHA1_80 noColon',
              'a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:%s|2^20|1:abc' % KEYA,
              'a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:%s|2^20|1:99999999999' % KEYA,
              'a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:%s|2^20|1:' % KEYA,
              'a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:%s|2^20|1:4 KDR=1 UNENCRYPTED_SRTP' % KEYA,
              'a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:AAAA|2^20|1:4',
              'a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:%s|' % KEYA,
              'a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:%s|2^20|' % KEYA,
              'a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:%s|2^20|1' % KEYA,
              'a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:%s|5' % KEYA,
              'a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:',
              'a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:%s|||' % KEYA,
              'a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:%s;' % KEYA,
              'a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:%s;noColon' % KEYA,
              'a=candidate:', 'a=candidate:7 1 UDP', 'a=candidate:1', 'a=candidate:1 1', 'a=candidate:1 1 UDP 1',
              'a=candidate:1 1 UDP 1 192.0.2.1', 'a=candidate:1 1 UDP 1 192.0.2.1 5000',
              'a=candidate:1 1 UDP 1 192.0.2.1 5000 typ', 'a=candidate:1 1 UDP 1 192.0.2.1 5000 typ ',
              'a=key-mgmt:mikey', 'a=key-mgmt:mikey !!!!', 'a=key-mgmt:mikey AA==', 'a=key-mgmt:mikey ' + MIKEY[:20],
              'a=key-mgmt:', 'a=key-mgmt:x ',
              'a=h248item:h324ext/h223lcparm=0', 'a=h248item:h324ext/h223lcparm=ffffffff',
              'a=h248item:h324ext/h223lcparm=0000', 'a=h248item:h324ext/h223lcparm=zz', 'a=h248item:h324ext/h223lcparm',
              'a=h248item:h324ext/h223lcparm=',
              'a=rtpmap:96 opus/48000/2/3', 'a=rtpmap:96  opus/48000', 'a=sendrecv:'])
    LONGCFG = '000001B001000001B58913000001000000012000C48D8800F50A04169463000001B24C61766335332E33352E30'
    for pt, mime, fm in ((96, 'H264/90000', ['profile-level-id=zz', 'profile-level-id=42e0', 'profile-level-id=42e01f00',
                                            'packetization-mode=x', 'sprop-parameter-sets=', 'sprop-parameter-sets=!!!!,@@@@',
                                            'sprop-parameter-sets=AA==,AA==', 'sprop-parameter-sets=%s,' % B64_SPS,
                                            'sprop-parameter-sets=%s,AA==' % B64_SPS, 'x']),
                         (97, 'H265/90000', ['sprop-vps=!!!', 'sprop-sps=AA==', 'sprop-pps=', 'sprop-vps=AA==']),
                         (98, 'MP4V-ES/90000', ['profile-level-id=abc', 'config=zz', 'config=0001', 'config=', 'config=' + LONGCFG,
                                                'profile-level-id=1']),
                         (99, 'H263-2000/90000', ['profile=x', 'level=999', 'profile=2;level=20']),
                         (100, 'H263-1998/90000', ['level=20', 'profile=9'])):
        for f in fm:
            xp(VID + ['a=rtpmap:%d %s' % (pt, mime), 'a=fmtp:%d %s' % (pt, f)])
    xp(['v=0', 'c=IN IP4 192.0.2.1', 'm=message 7000 msrp/tcp *', 'a=path:msrp://'])
    for p in ('a=path:msrp://192.0.2.1', 'a=path:msrp://:', 'a=path:msrp://192.0.2.1:99999/x;tcp', 'a=path:msrp://192.0.2.1:/x'):
        xp(['v=0', 'c=IN IP4 192.0.2.1', 'm=message 7000 msrp/tcp *', p])
    xp([], raw=b'v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nm=audio 5004 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000')
    xp([], raw=b'v=0\no=- 1 1 IN IP4 192.0.2.1\ns=-\nc=IN IP4 192.0.2.1\nm=audio 5004 RTP/AVP 0\n')
    xp([], raw=b'v=0\r\n\x00\x01binary\xff\xfe\r\nm=\xff\xfe 5004 RTP/AVP 0\r\n')
    # long lines and many media sections
    xp(['v=0', 'c=IN IP4 192.0.2.1'] + ['m=audio %d RTP/AVP 0' % (5000 + 2 * i) for i in range(12)] +
       ['a=rtpmap:96 ' + 'x' * 2000 + '/8000'])
    # SIP SDP with a line without '=' and an empty line (transport setup skips them)
    invite(cap, 'm3', sdp_text(['v=0', 'o=- 1 1 IN IP4 192.0.2.1', 'no equal sign here', 's=-', 'c=IN IP4 192.0.2.1',
                                't=0 0', 'm=audio 5004 RTP/AVP 0', '', 'a=sendrecv']))
    # the reproducer of the exception in setup_sdp_transport(): a malformed
    # MIKEY line in a SIP INVITE; one pass and two passes must agree
    invite(cap, 'm1', sdp_text(['v=0', 'o=- 1 1 IN IP4 192.0.2.1', 's=-', 'c=IN IP4 192.0.2.1', 't=0 0',
        'a=key-mgmt:mikey AQAFgM0XflABAAAAAAAAAAAAAAsAyO5n', 'm=audio 5004 RTP/AVP 0']))
    # answer with a malformed MIKEY line, a bad rtpmap and a long attribute
    ok(cap, 'm1', sdp_text(['v=0', 'o=- 1 1 IN IP4 192.0.2.2', 's=-', 'c=IN IP4 192.0.2.2', 't=0 0',
        'm=audio 6004 RTP/AVP 0', 'a=key-mgmt:mikey AQAF', 'a=rtpmap:0 PCMU/8000']))
    # sdp in SIP 200 OK to an unknown request; ANSWER without OFFER
    ok(cap, 'm2', sdp_text(['v=0', 'o=- 2 2 IN IP4 192.0.2.2', 's=-', 'c=IN IP4 192.0.2.2', 't=0 0',
        'm=audio 6104 RTP/AVP 0']))
    cap.write(outdir + '/sdp-coverage-malformed.pcapng')

if __name__ == '__main__':
    build(sys.argv[1])
