#!/usr/bin/env python3
# Generates test/captures/sip_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generates the sip coverage captures: mksip.py <outdir>
# Everything is built with struct; nothing comes from a real network.
import sys
import struct
import zlib

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
C3 = [192, 0, 2, 3]
CRLF = b'\r\n'

def crc32c(data):
    crc = 0xffffffff
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
    return crc ^ 0xffffffff

def sctp_data(src, dst, sport, dport, payload, tsn=1, ppid=3):
    chunk_len = 16 + len(payload)
    chunk = struct.pack('>BBHIHHI', 0, 3, chunk_len, tsn, 0, tsn - 1, ppid) + payload
    chunk += b'\0' * ((4 - len(chunk) % 4) % 4)
    hdr = struct.pack('>HHII', sport, dport, 0x11223344, 0)
    crc = crc32c(hdr + chunk)
    hdr = hdr[:8] + struct.pack('<I', crc)
    return eth(MAC_A, MAC_B, ip4(src, dst, 132, hdr + chunk))

def sctp_init(src, dst, sport, dport, ack=False):
    if not ack:
        body = struct.pack('>IIHHI', 0xaaaa0001, 65535, 4, 4, 1000)
        chunk = struct.pack('>BBH', 1, 0, 4 + len(body)) + body
        vtag = 0
    else:
        body = struct.pack('>IIHHI', 0xbbbb0001, 65535, 4, 4, 5000)
        chunk = struct.pack('>BBH', 2, 0, 4 + len(body)) + body
        vtag = 0xaaaa0001
    hdr = struct.pack('>HHII', sport, dport, vtag, 0)
    crc = crc32c(hdr + chunk)
    hdr = hdr[:8] + struct.pack('<I', crc)
    return eth(MAC_A, MAC_B, ip4(src, dst, 132, hdr + chunk))

def hdrs(cid, cseq, method, frm=A, to=B, to_tag=None, via_proto='UDP', extra=(), branch=None, mf=70, clen=None):
    h = [b'Via: SIP/2.0/%s %d.%d.%d.%d:5060;branch=z9hG4bK%s;rport' % ((via_proto.encode(),) + tuple(frm) + ((branch or cid).encode(),)),
         b'Max-Forwards: %d' % mf,
         b'From: "Alice" <sip:alice@192.0.2.1>;tag=a%s' % cid.encode(),
         b'To: <sip:bob@192.0.2.2>' + (b';tag=b%s' % cid.encode() if to_tag else b''),
         b'Call-ID: %s@192.0.2.1' % cid.encode(),
         b'CSeq: %d %s' % (cseq, method.encode())]
    h += [x if isinstance(x, bytes) else x.encode() for x in extra]
    return h

def msg(first, cid, cseq, method, extra=(), body=b'', ctype=None, to_tag=False, clen=True, **kw):
    h = [first.encode() if isinstance(first, str) else first] + hdrs(cid, cseq, method, to_tag=to_tag, extra=extra, **kw)
    if ctype:
        h.append(b'Content-Type: ' + (ctype if isinstance(ctype, bytes) else ctype.encode()))
    if clen:
        h.append(b'Content-Length: %d' % len(body))
    return CRLF.join(h) + CRLF + CRLF + body

def req(method, cid, cseq=1, uri='sip:bob@192.0.2.2', extra=(), body=b'', ctype=None, to_tag=False, **kw):
    return msg('%s %s SIP/2.0' % (method, uri), cid, cseq, method, extra, body, ctype, to_tag, **kw)

def resp(code, reason, cid, cseq, method, extra=(), body=b'', ctype=None, to_tag=True, **kw):
    kw.setdefault('frm', B)
    return msg('SIP/2.0 %d %s' % (code, reason), cid, cseq, method, extra, body, ctype, to_tag, **kw)

def U(cap, data, fwd=True, sport=5060, dport=5060):
    if fwd:
        return cap.add(udp(A, B, sport, dport, data))
    return cap.add(udp(B, A, dport, sport, data))

B64_SPS = 'Z0IACpZTBYmI'
HEX32 = b'0123456789abcdef0123456789abcdef'
HEX32B = b'fedcba9876543210fedcba9876543210'
SDP = (b'v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\n'
       b'm=audio 5004 RTP/AVP 0 8\r\na=rtpmap:0 PCMU/8000\r\n')
SDP_ANS = SDP.replace(b'192.0.2.1', b'192.0.2.2').replace(b'5004', b'6004')

# a header of every kind known to the dissector
ALLHDRS = [
    'Accept: application/sdp, application/3gpp-ims+xml;q=0.5',
    'Accept-Contact: *;+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel";require;explicit',
    'Accept-Encoding: gzip', 'Accept-Language: en', 'Accept-Resource-Priority: dsn.flash,dsn.immediate',
    'Additional-Identity: <sip:alt@example.com>', 'Alert-Info: <http://www.example.com/sounds/moo.wav>',
    'Allow: INVITE, ACK, CANCEL, OPTIONS, BYE', 'Allow-Events: presence, message-summary',
    'Answer-Mode: Manual;require', 'Attestation-Info: A',
    'Authentication-Info: nextnonce="47364c23432d2e131a5fb210812c", qop=auth, rspauth="6629fae49393a05397450978507c4ef1", cnonce="0a4f113b", nc=00000001',
    'Call-Info: <sip:alice@192.0.2.1>;purpose=icon', 'Cellular-Network-Info: 3GPP-UTRAN-FDD; utran-cell-id-3gpp=2343200000',
    'Content-Disposition: session;handling=required', 'Content-Language: en', 'Date: Sat, 13 Nov 2010 23:29:00 GMT',
    'Error-Info: <sip:not-in-service-recording@example.com>', 'Event: presence',
    'Feature-Caps: *;+g.3gpp.srvcc-alerting;+g.3gpp.atcf="<sip:atcf@example.com>"', 'Flow-Timer: 120',
    'Geolocation: <cid:target123@atlanta.example.com>;inserted-by="sip:alice@example.com";used-for-routing',
    'Geolocation-Error: 100 "Cannot Process Location"', 'Geolocation-Routing: yes',
    'History-Info: <sip:bob@example.com?Reason=SIP;cause=302>;index=1,<sip:carol@example.com>;index=1.1',
    'Identity: "made-up-signature"', 'Identity-Info: <https://example.com/cert>;alg=rsa-sha1',
    'Info-Package: dtmf', 'In-Reply-To: 70710@saturn.bell-tel.com', 'Join: 12345@host;to-tag=1;from-tag=2',
    'Max-Breadth: 60', 'MIME-Version: 1.0', 'Min-Expires: 60', 'Min-SE: 90', 'Organization: Example Inc',
    'Origination-Id: abc', 'P-Access-Network-Info: 3GPP-E-UTRAN-FDD; utran-cell-id-3gpp=234150999999999; network-provided',
    'P-Answer-State: Confirmed', 'P-Asserted-Identity: "Bob" <sip:bob@example.com>, <tel:+358-555-1234567>',
    'P-Asserted-Service: urn:urn-7:3gpp-service.ims.icsi.mmtel',
    'P-Associated-URI: <sip:user1@example.com>;param=1, <sip:user2@example.com>',
    'P-Called-Party-ID: <sip:bob@example.com>', 'P-Charge-Info: <sip:alice@example.com>',
    'P-Charging-Function-Addresses: ccf=192.0.2.5;ecf=192.0.2.6;ccf="[2001:db8::1]"',
    'P-Charging-Vector: icid-value="AyretyU0dm+6O2IrT5tAFrbHLso=023551024"; icid-generated-at=192.0.2.1; orig-ioi=home1.net',
    'P-DCS-Trace-Party-ID: <sip:alice@example.com>', 'P-DCS-OSPS: BLV', 'P-DCS-Billing-Info: 0123456789abc',
    'P-DCS-LAES: laes=192.0.2.1:5000', 'P-DCS-Redirect: <sip:x@example.com>;count=1', 'P-Early-Media: supported',
    'P-Media-Authorization: 0123abcd', 'P-Preferred-Identity: <sip:alice@example.com>',
    'P-Preferred-Service: urn:urn-7:3gpp-service.ims.icsi.mmtel', 'P-Profile-Key: <sip:chatroom-!.*!@example.com>',
    'P-Refused-URI-List: <sip:x@example.com>', 'P-Served-User: <sip:alice@example.com>;sescase=orig;regstate=reg',
    'P-User-Database: <aaa://host.example.com>', 'P-Visited-Network-ID: "Visited network number 1"',
    'Path: <sip:p1.example.com;lr>', 'Permission-Missing: sip:carol@example.com', 'Policy-Contact: <sip:x@y>',
    'Policy-ID: x', 'Priority: urgent', 'Priority-Share: x', 'Priv-Answer-Mode: Auto', 'Privacy: id;critical',
    'Proxy-Authenticate: Digest realm="atlanta.com", domain="sip:ss1.carrier.com", qop="auth", nonce="f84f1cec41e6cbe5aea9c8e88d359", opaque="", stale=FALSE, algorithm=MD5',
    'Proxy-Authorization: Digest username="Alice", realm="atlanta.com", nonce="c60f3082ee1212b402a21831ae", response="245f23415f11432b3434341c022", uri="sip:bob@192.0.2.2"',
    'Proxy-Require: sec-agree', 'RAck: 776656 1 INVITE', 'Reason: SIP ;cause=200 ;text="Call completed elsewhere"',
    'Reason: Q.850;cause=16;text="Terminated"', 'Reason: X.1;cause=3', 'Reason-Phrase: x',
    'Record-Route: <sip:p2.example.com;lr>,<sip:p1.example.com;lr>', 'Recv-Info: x', 'Refer-Sub: false',
    'Refer-To: <sip:dave@example.com?Replaces=12345%40host%3Bto-tag%3D1%3Bfrom-tag%3D2>',
    'Referred-By: <sip:alice@example.com>', 'Reject-Contact: *;+sip.mobility="fixed"', 'Relayed-Charge: x',
    'Replaces: 12345@host;to-tag=1;from-tag=2', 'Reply-To: Bob <sip:bob@example.com>',
    'Request-Disposition: proxy, recurse', 'Require: 100rel', 'Resource-Priority: wps.0', 'Resource-Share: x',
    'Response-Source: x', 'Restoration-Info: x', 'Route: <sip:server10.biloxi.com;lr>, <sip:bigbox3.site3.atlanta.com;lr>',
    'RSeq: 988789',
    'Security-Client: ipsec-3gpp; alg=hmac-sha-1-96; spi-c=98765432; spi-s=87654321; port-c=8642; port-s=7531, tls',
    'Security-Server: ipsec-3gpp; q=0.1; alg=hmac-sha-1-96; prot=esp; mod=trans; ealg=aes-cbc; spi-c=1111; spi-s=2222; port-c=5062; port-s=5064',
    'Security-Verify: ipsec-3gpp; alg=hmac-md5-96; ealg=des-ede3-cbc; spi-c=1; spi-s=2; port-c=3; port-s=4',
    'Server: Example/1.0', 'Service-Interact-Info: x', 'Service-Route: <sip:orig@scscf.example.com;lr>',
    'Session-Expires: 1800;refresher=uac', 'Session-ID: ' + HEX32.decode() + ';remote=' + HEX32B.decode() + ';logme',
    'SIP-ETag: abc', 'SIP-If-Match: abc', 'Subject: Project X', 'Subscription-State: active;expires=3600',
    'Supported: timer, 100rel', 'Suppress-If-Match: x', 'Target-Dialog: 12345@host;remote-tag=1;local-tag=2',
    'Timestamp: 54', 'Trigger-Consent: sip:x@example.com;target-uri="sip:alice@example.com"',
    'Unsupported: foo', 'User-Agent: Example UA', 'Warning: 370 devnull "Choose a bigger pipe"',
    'WWW-Authenticate: Digest realm="biloxi.com", qop="auth,auth-int", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", opaque="5ccc069c403ebaf9f0171e9517f40e41"',
    'Diversion: <sip:alice@example.com>;reason=unconditional', 'User-to-User: 00;encoding=hex',
    # compact forms
    'a: *;+sip.instance="<urn:uuid:00000000-0000-1000-8000-AABBCCDDEEFF>"', 'u: presence', 'o: refer',
    'y: "sig"', 'n: <https://example.com/cert>', 'r: <sip:dave@example.com>', 'b: <sip:alice@example.com>',
    'j: *', 'd: proxy', 'x: 90', 's: subject', 'k: timer', 'X-Custom-Header: some value',
    # unusual layout: header with a continuation line, a lowercase name, a name with spaces before the colon
    'subject: folded', ' value', 'Organization : spaced',
]

def build(outdir):
    cap = Cap()
    frames = {}
    def mark(name):
        frames[name] = len(cap.pkts)

    # ===== 1. REGISTER with bindings, authentication challenge =====
    U(cap, req('REGISTER', 'r1', 1, uri='sip:example.com',
               extra=['Contact: <sip:alice@192.0.2.1:5060>;expires=3600;+sip.instance="<urn:uuid:f81d4fae>";q=0.7, "Alice" <sip:alice@192.0.2.9>;expires=0, <sip:alice@192.0.2.8>',
                      'Expires: 3600', 'Supported: path, gruu', 'Allow: INVITE, ACK, BYE']))
    U(cap, (resp(401, 'Unauthorized', 'r1', 1, 'REGISTER',
           extra=['WWW-Authenticate: Digest realm="example.com", nonce="84f1c1ae6cbe5ua9c8e88d359", opaque="", algorithm=MD5, qop="auth", stale=false, domain="sip:example.com"'])),
      fwd=False)
    U(cap, req('REGISTER', 'r1', 2, uri='sip:example.com', to_tag=True,
               extra=['Contact: <sip:alice@192.0.2.1:5060>;expires=3600',
                      'Authorization: Digest username="alice", realm="example.com", nonce="84f1c1ae6cbe5ua9c8e88d359", uri="sip:example.com", response="d3b07384d113edec49eaa6238ad5ff00", algorithm=MD5, cnonce="0a4f113b", opaque="", qop=auth, nc=00000001',
                      'Expires: 3600']))
    U(cap, resp(200, 'OK', 'r1', 2, 'REGISTER',
                extra=['Contact: <sip:alice@192.0.2.1:5060>;expires=3600, <sip:alice@192.0.2.7>;expires=0', 'Date: Sat, 13 Nov 2010 23:29:00 GMT',
                       'Authentication-Info: nextnonce="47364c23432d2e131a5fb210812c"']), fwd=False)
    # remove all bindings; fetch bindings; one binding that expires
    U(cap, req('REGISTER', 'r2', 1, uri='sip:example.com', extra=['Contact: *', 'Expires: 0']))
    U(cap, resp(200, 'OK', 'r2', 1, 'REGISTER'), fwd=False)
    U(cap, req('REGISTER', 'r3', 1, uri='sip:example.com'))
    U(cap, resp(200, 'OK', 'r3', 1, 'REGISTER', extra=['Contact: <sip:alice@192.0.2.1>;expires=100']), fwd=False)
    U(cap, req('REGISTER', 'r4', 1, uri='sip:example.com', extra=['Contact: <sip:alice@192.0.2.1>;expires=0']))
    U(cap, resp(200, 'OK', 'r4', 1, 'REGISTER', extra=['Contact: <sip:alice@192.0.2.1>;expires=0, <sip:b@192.0.2.2>;expires=60']), fwd=False)
    U(cap, req('REGISTER', 'r5', 1, uri='sip:example.com', extra=['Contact: <sip:alice@192.0.2.1>', 'Expires: 0']))
    U(cap, req('REGISTER', 'r7', 1, uri='sip:example.com', extra=['Contact: <sip:alice@192.0.2.1>, <sip:alice@192.0.2.2>;expires=60', 'Expires: 0']))
    U(cap, resp(200, 'OK', 'r7', 1, 'REGISTER', extra=['Contact: <sip:alice@192.0.2.2>;expires=60, <sip:alice@192.0.2.1>', 'Expires: 0']), fwd=False)
    U(cap, req('REGISTER', 'r6', 1, uri='sip:example.com', extra=['Contact: "Al, ice" <sip:a@192.0.2.1>;x="a;b,c";expires=5;foo']))
    mark('register')

    # ===== 2. INVITE with every header, 100/180/183/200, ACK, BYE =====
    U(cap, req('INVITE', 'i1', 1, uri='sip:bob@192.0.2.2;transport=udp?subject=x', extra=ALLHDRS,
               body=SDP, ctype='application/sdp'))
    mark('invite_allhdrs')
    U(cap, resp(100, 'Trying', 'i1', 1, 'INVITE', to_tag=False), fwd=False)
    U(cap, resp(180, 'Ringing', 'i1', 1, 'INVITE', extra=['Contact: <sip:bob@192.0.2.2>', 'Require: 100rel', 'RSeq: 1']), fwd=False)
    U(cap, resp(183, 'Session Progress', 'i1', 1, 'INVITE', extra=['P-Early-Media: sendrecv'], body=SDP_ANS, ctype='application/sdp'), fwd=False)
    U(cap, req('PRACK', 'i1', 2, to_tag=True, extra=['RAck: 1 1 INVITE']))
    U(cap, resp(200, 'OK', 'i1', 2, 'PRACK'), fwd=False)
    U(cap, resp(200, 'OK', 'i1', 1, 'INVITE', extra=['Contact: <sip:bob@192.0.2.2>', 'Record-Route: <sip:p1.example.com;lr>'],
                body=SDP_ANS, ctype='application/sdp'), fwd=False)
    U(cap, req('ACK', 'i1', 1, to_tag=True))
    U(cap, req('BYE', 'i1', 3, to_tag=True, extra=['Reason: SIP;cause=200;text="Call completed elsewhere"']))
    U(cap, resp(200, 'OK', 'i1', 3, 'BYE'), fwd=False)
    # responses of every class and some unusual ones
    for n, (code, reason, extra) in enumerate([
            (302, 'Moved Temporarily', ['Contact: <sip:bob@192.0.2.50>;q=0.5, <sip:bob@192.0.2.51>;q=0.1']),
            (401, 'Unauthorized', ['WWW-Authenticate: Digest realm="r", nonce="n"']),
            (407, 'Proxy Authentication Required', ['Proxy-Authenticate: Digest realm="r", nonce="n"']),
            (480, 'Temporarily Unavailable', ['Retry-After: 120']),
            (486, 'Busy Here', ['Retry-After: 60;duration=30']),
            (487, 'Request Terminated', []),
            (500, 'Server Internal Error', ['Retry-After: 5 (I am overloaded)']),
            (503, 'Service Unavailable', ['Retry-After: 10']),
            (600, 'Busy Everywhere', []), (603, 'Decline', ['Warning: 399 example.com "x"']),
            (199, 'Early Dialog Terminated', []), (299, 'Unknown Success', []), (420, 'Bad Extension', ['Unsupported: foo']),
            (421, 'Extension Required', ['Require: foo']), (422, 'Session Interval Too Small', ['Min-SE: 90']),
            (423, 'Interval Too Brief', ['Min-Expires: 600']), (489, 'Bad Event', ['Allow-Events: presence']),
            (494, 'Security Agreement Required', ['Security-Server: tls']),
        ]):
        cid = 'x%d' % n
        U(cap, req('INVITE', cid, 1, extra=['Contact: <sip:alice@192.0.2.1>']))
        U(cap, resp(code, reason, cid, 1, 'INVITE', extra=extra), fwd=False)
        U(cap, req('ACK', cid, 1, to_tag=True)) if code >= 300 else None
    mark('responses')

    # ===== 3. every method and unknown ones =====
    methods = ['CANCEL', 'DO', 'INFO', 'MESSAGE', 'NOTIFY', 'OPTIONS', 'QAUTH', 'REFER', 'SPRACK', 'SUBSCRIBE',
               'UPDATE', 'PUBLISH', 'FOOBAR']
    for n, m in enumerate(methods):
        cid = 'm%d' % n
        extra = []
        body = b''; ct = None
        if m == 'INFO':
            extra = ['Info-Package: dtmf']; body = b'Signal=1\r\nDuration=160\r\n'; ct = 'application/dtmf-relay'
        elif m == 'MESSAGE':
            body = b'Hello, world'; ct = 'text/plain;charset=utf-8'
        elif m == 'NOTIFY':
            extra = ['Event: refer', 'Subscription-State: terminated;reason=noresource']
            body = b'SIP/2.0 200 OK\r\n'; ct = 'message/sipfrag;version=2.0'
        elif m == 'REFER':
            extra = ['Refer-To: <sip:carol@192.0.2.3>', 'Referred-By: <sip:alice@192.0.2.1>']
        elif m == 'SUBSCRIBE':
            extra = ['Event: presence', 'Expires: 600', 'Accept: application/pidf+xml']
        elif m == 'PUBLISH':
            extra = ['Event: presence', 'SIP-If-Match: abc']
            body = (b'<?xml version="1.0" encoding="UTF-8"?>\r\n<presence xmlns="urn:ietf:params:xml:ns:pidf" entity="sip:alice@192.0.2.1">'
                    b'<tuple id="t1"><status><basic>open</basic></status></tuple></presence>\r\n')
            ct = 'application/pidf+xml'
        elif m == 'UPDATE':
            extra = ['Session-Expires: 1800;refresher=uas', 'Min-SE: 90']
        elif m == 'OPTIONS':
            extra = ['Accept: application/sdp', 'Contact: <sip:alice@192.0.2.1>']
        elif m == 'SPRACK':
            extra = ['RAck: 5 5 INVITE']
        U(cap, req(m, cid, 1 + n, to_tag=(m in ('UPDATE', 'INFO', 'REFER', 'NOTIFY')), extra=extra, body=body, ctype=ct))
        U(cap, resp(200, 'OK', cid, 1 + n, m), fwd=False)
    mark('methods')

    # ===== 4. bodies: multipart, gzip, nested message/sip, other types =====
    mp = (b'--boundary1\r\nContent-Type: application/sdp\r\n\r\n' + SDP +
          b'\r\n--boundary1\r\nContent-Type: application/isup;version=itu-t92+\r\nContent-Disposition: signal;handling=optional\r\n\r\n\x01\x00\x20\x00\x0a\x00\x02\x00\x04\x03\x10\x21\x43'
          b'\r\n--boundary1\r\nContent-Type: text/plain\r\n\r\nplain part\r\n--boundary1--\r\n')
    U(cap, req('INVITE', 'b1', 1, body=mp, ctype='multipart/mixed;boundary=boundary1', extra=['MIME-Version: 1.0']))
    U(cap, req('MESSAGE', 'b2', 1, body=zlib.compress(b'compressed text body'), ctype='text/plain',
               extra=['Content-Encoding: deflate']))
    U(cap, req('MESSAGE', 'b2g', 1, body=b'not compressed at all', ctype='text/plain',
               extra=['Content-Encoding: gzip']))
    inner = req('OPTIONS', 'n3', 1, extra=['Accept: application/sdp'])
    mid = req('OPTIONS', 'n2', 1, body=inner, ctype='message/sip')
    U(cap, req('MESSAGE', 'n1', 1, body=mid, ctype='message/sip'))
    mark('nested3')
    U(cap, req('MESSAGE', 'b2m', 1, body=b'--b\r\nContent-Type: text/plain\r\n\r\nx\r\n--b--\r\n', ctype='multipart/x-unknown;boundary=b'))
    U(cap, req('MESSAGE', 'b3', 1, body=b'\x01\x02\x03binary', ctype='application/octet-stream'))
    U(cap, req('MESSAGE', 'b4', 1, body=b'unknown content type body', ctype='application/x-nonexistent'))
    U(cap, req('MESSAGE', 'b5', 1, body=b'no content type, body only'))
    U(cap, req('MESSAGE', 'b5b', 1, body=b'Content-Length smaller than the body, extra octets follow', ctype='text/plain',
               clen=False, extra=['Content-Length: 10']))
    U(cap, req('MESSAGE', 'b6', 1, body=b'<doc/>', ctype='application/xml;charset=utf-8'))
    U(cap, req('MESSAGE', 'b7', 1, body=b'l=xyz', ctype='application/vnd.3gpp.sms'))
    U(cap, req('MESSAGE', 'b8', 1, body=b'<?xml version="1.0"?><ims-3gpp version="1"><alternative-service><type>emergency</type></alternative-service></ims-3gpp>',
               ctype='application/3gpp-ims+xml'))
    U(cap, req('MESSAGE', 'b9', 1, body=b'<?xml version="1.0"?><resource-lists xmlns="urn:ietf:params:xml:ns:resource-lists"/>',
               ctype='application/resource-lists+xml'))
    mark('bodies')

    # ===== 5. Header details: URIs, Via, Contact, Reason, Route =====
    uris = [
        'sip:bob@192.0.2.2', 'sips:bob@example.com:5061', 'sip:bob:secret@192.0.2.2:5060;transport=tcp;lr?h=v',
        'sip:[2001:db8::2]:5060', 'sip:bob@[2001:db8::2]', 'sip:example.com', 'tel:+358501234567',
        'tel:+358501234567;phone-context=example.com', 'sip:+358501234567@example.com;user=phone',
        'sip:bob@example.com;maddr=192.0.2.9;ttl=5', 'sip:%62ob@example.com', 'urn:service:sos',
        'sip:bob@example.com:5060', 'sip:192.0.2.2:5060;lr',
    ]
    for n, u in enumerate(uris):
        U(cap, req('OPTIONS', 'u%d' % n, 1, uri=u, extra=[
            'Contact: <%s>;expires=10' % u, 'Route: <%s>, <sip:p@192.0.2.9;lr>' % u,
            'To: "Bob %d" <%s>;tag=t%d' % (n, u, n), 'P-Called-Party-ID: %s' % u]))
    # name-addr and addr-spec forms in From/To/Contact
    U(cap, (b'OPTIONS sip:bob@192.0.2.2 SIP/2.0\r\nVia: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bKf1\r\n'
            b'From: Alice <sip:alice@192.0.2.1>;tag=1\r\nTo: sip:bob@192.0.2.2;tag=2\r\nCall-ID: f1@192.0.2.1\r\nCSeq: 1 OPTIONS\r\n'
            b'Contact: sip:alice@192.0.2.1;expires=5, "Quoted \\"Name\\"" <sip:alice@192.0.2.1>;q=1, Alice <tel:+123>\r\n'
            b'P-Asserted-Identity: sip:alice@192.0.2.1, <tel:+1234>\r\nP-Preferred-Identity: tel:+1234\r\n'
            b'History-Info: <sip:a@b>;index=1\r\nPermission-Missing: <sip:z@y>;x=1\r\nContent-Length: 0\r\n\r\n'))
    for n, v in enumerate([
            'SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bKv1;received=192.0.2.9;rport=5062;maddr=224.0.1.1;ttl=3;comp=sigcomp;sigcomp-id=urn:uuid:abc',
            'SIP/2.0/TCP [2001:db8::1]:5060;branch=z9hG4bKv2;oc=5;oc-validity=500;oc-seq=1234.5;oc-algo=loss;be-route=sip:be@example.com',
            'SIP/2.0/TLS example.com;branch=z9hG4bKv3;rport', 'SIP / 2.0 / UDP host : 5060 ; branch=z9hG4bKv4 ;foo',
            'SIP/2.0/SCTP 192.0.2.1:5060,SIP/2.0/UDP 192.0.2.2:5060;branch=z9hG4bKv5',
            'SIP/2.0/WS 192.0.2.1:abc;branch=z9hG4bKv6', 'SIP/2.0/UDP/extra 192.0.2.1:5060;branch=z9hG4bKv7',
            'SIP/2.0/UDP /extra 192.0.2.1:5060;branch=z9hG4bKv8',
            'SIP/2.0/UDP a:5060;branch=z9hG4bKq, SIP/2.0/UDP b:5060;branch=z9hG4bKr']):
        U(cap, (b'OPTIONS sip:bob@192.0.2.2 SIP/2.0\r\nVia: ' + v.encode() + b'\r\nFrom: <sip:a@b>;tag=1\r\nTo: <sip:b@c>\r\n'
                b'Call-ID: v%d@192.0.2.1\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n' % n))
    mark('uris')
    # session id forms (the second is the reproducer of the leak, fixed)
    for n, v in enumerate([HEX32 + b';remote=' + HEX32B, HEX32 + b';remote=' + HEX32B + b';logme',
                           HEX32 + b';remote=' + HEX32B + b';foo=bar;logme', HEX32 + b';foo=bar',
                           HEX32 + b';remote', b'0' * 32 + b';remote=' + HEX32B, HEX32 + b';remote=' + b'0' * 32,
                           HEX32]):
        U(cap, (b'OPTIONS sip:bob@192.0.2.2 SIP/2.0\r\nVia: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bKs%d\r\nFrom: <sip:a@b>;tag=1\r\n'
                b'To: <sip:b@c>\r\nCall-ID: s%d@192.0.2.1\r\nCSeq: 1 OPTIONS\r\nSession-ID: ' % (n, n) + v +
                b'\r\nContent-Length: 0\r\n\r\n'))
    mark('sessionid')
    # Reason with each protocol; Security headers; P-Access-Network-Info variants
    for n, h in enumerate([
            'Reason: SIP;cause=486;text="Busy"', 'Reason: Q.850;cause=17', 'Reason: Other;cause=1;text="x"',
            'P-Access-Network-Info: IEEE-802.11a; i-wlan-node-id=00112233445566; network-provided',
            'P-Access-Network-Info: 3GPP-UTRAN-TDD; utran-cell-id-3gpp=2341500000000001; local-time-zone="UTC+01:00"',
            'P-Access-Network-Info: 3GPP-E-UTRAN-FDD; utran-cell-id-3gpp="234150999999999"',
            'P-Access-Network-Info: IEEE-802.11a',
            'P-Access-Network-Info: ADSL; dsl-location="a1"; operator-specific-GI="x"; ci-3gpp2=abc',
            'P-Charging-Vector: icid-value=1234;icid-gen-addr="[2001:db8::1]";term-ioi=home2.net;ggsn=192.0.2.9;gcid=1;auth-token=x',
            'Feature-Caps: *;+g.3gpp.icsi-ref="urn%3Aurn-7";+g.3gpp.trf="sip:trf@x"', 'P-Charging-Function-Addresses: ccf=a;ccf=b',
            'Security-Client: digest', 'Security-Client: ipsec-3gpp;alg=x;spi-c=1234',
            'History-Info: <sip:a@b>;index=1', 'History-Info: <sip:a@b>;index=1,<sip:c@d>;index=1.1,<sip:e@f>',
            'Accept-Contact: *;explicit', 'Via: SIP/2.0/UDP a:5060;branch=z9hG4bKx;rport=5060',
            'P-Associated-URI: <sip:a@b>', 'P-Associated-URI: <sip:a@b>;x=1;service-priority=5',
            'Trigger-Consent: sip:x@y', 'Trigger-Consent: sip:x@y;target-uri="sip:a@b";foo;target-uri="sip:c@d"',
            'Service-Route: <sip:a@b;lr>', 'Path: <sip:a@b;lr>, <sip:c@d;lr>', 'Record-Route: <sip:a@b;lr>',
            'Authorization: Digest username="u", realm="r", nonce="n", uri="sip:x", response="abc", algorithm=AKAv1-MD5, auts="abc", ik="x", ck="y"',
            'Authorization: Basic dXNlcjpwYXNz', 'Authorization: Digest', 'Authorization: Digest username=u,realm="r\\"q",nonce=n',
            ]):
        U(cap, (b'OPTIONS sip:bob@192.0.2.2 SIP/2.0\r\nVia: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bKh%d\r\nFrom: <sip:a@b>;tag=1\r\n'
                b'To: <sip:b@c>\r\nCall-ID: h%d@192.0.2.1\r\nCSeq: 1 OPTIONS\r\n' % (n, n) + h.encode() + b'\r\nContent-Length: 0\r\n\r\n'))
    mark('headers2')

    # ===== 6. Retransmission, request/response matching =====
    for n in range(2):
        U(cap, req('OPTIONS', 'rt1', 1, extra=['Contact: <sip:alice@192.0.2.1>']))
    U(cap, resp(200, 'OK', 'rt1', 1, 'OPTIONS'), fwd=False)
    U(cap, resp(200, 'OK', 'rt1', 1, 'OPTIONS'), fwd=False)
    U(cap, req('OPTIONS', 'rt1', 1, extra=['Contact: <sip:alice@192.0.2.1>']), sport=5070)
    # CANCEL / 487 / ACK sequence; a response without request; a request after the transaction
    U(cap, req('INVITE', 'cc1', 1)); U(cap, req('CANCEL', 'cc1', 1)); U(cap, resp(200, 'OK', 'cc1', 1, 'CANCEL'), fwd=False)
    U(cap, resp(487, 'Request Terminated', 'cc1', 1, 'INVITE'), fwd=False); U(cap, req('ACK', 'cc1', 1, to_tag=True))
    U(cap, resp(200, 'OK', 'orphan', 7, 'OPTIONS'), fwd=False)
    U(cap, req('OPTIONS', 'late', 1)); U(cap, resp(100, 'Trying', 'late', 1, 'OPTIONS'), fwd=False)
    U(cap, resp(200, 'OK', 'late', 1, 'OPTIONS'), fwd=False); U(cap, req('OPTIONS', 'late', 2))
    # an INVITE with SDP that is retransmitted, then rejected with SDP in the 488
    U(cap, req('INVITE', 'sd1', 1, body=SDP, ctype='application/sdp'))
    U(cap, req('INVITE', 'sd1', 1, body=SDP, ctype='application/sdp'))
    U(cap, resp(488, 'Not Acceptable Here', 'sd1', 1, 'INVITE', body=SDP_ANS, ctype='application/sdp'), fwd=False)
    U(cap, req('ACK', 'sd1', 1, to_tag=True))
    mark('matching')

    # ===== 7. TCP: segments, several messages per segment, reassembly =====
    t = Tcp(A, B, 40001, 5060)
    for p in t.handshake():
        cap.add(p)
    m1 = req('INVITE', 'tc1', 1, body=SDP, ctype='application/sdp', via_proto='TCP', extra=['Contact: <sip:alice@192.0.2.1;transport=tcp>'])
    half = m1.index(b'\r\n\r\n') + 4 + 10
    cap.add(t.seg(True, m1[:40]))           # headers split over segments
    cap.add(t.seg(True, m1[40:half]))       # body split too
    cap.add(t.seg(True, m1[half:]))
    mark('tcp_split')
    cap.add(t.seg(False, resp(200, 'OK', 'tc1', 1, 'INVITE', body=SDP_ANS, ctype='application/sdp', via_proto='TCP')))
    two = (req('ACK', 'tc1', 1, to_tag=True, via_proto='TCP') + req('OPTIONS', 'tc2', 1, via_proto='TCP'))
    cap.add(t.seg(True, two))
    mark('tcp_two')
    cap.add(t.seg(False, resp(200, 'OK', 'tc2', 1, 'OPTIONS', via_proto='TCP')))
    # keep-alive CRLF CRLF and a message without Content-Length
    cap.add(t.seg(True, b'\r\n\r\n'))
    cap.add(t.seg(True, (b'OPTIONS sip:bob@192.0.2.2 SIP/2.0\r\nVia: SIP/2.0/TCP 192.0.2.1:5060;branch=z9hG4bKnc\r\nFrom: <sip:a@b>;tag=1\r\nTo: <sip:b@c>\r\n'
                         b'Call-ID: nc@192.0.2.1\r\nCSeq: 1 OPTIONS\r\n\r\n')))
    # headers not finished: the next segment completes them
    cap.add(t.seg(True, b'OPTIONS sip:bob@192.0.2.2 SIP/2.0\r\nVia: SIP/2.0/TCP 192.0.2.1:5060;branch=z9hG4bKhh\r\nFrom: <sip:a@b>;tag=1\r\n'))
    cap.add(t.seg(True, b'To: <sip:b@c>\r\nCall-ID: hh@192.0.2.1\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n'))
    for p in t.close():
        cap.add(p)
    # one non-printable octet; a start line without line end; SigComp
    t = Tcp(A, B, 40004, 5060)
    for p in t.handshake():
        cap.add(p)
    cap.add(t.seg(True, b'\0'))
    cap.add(t.seg(True, b'\xf8\x00\x00' + b'\x01' * 8))
    for p in t.close():
        cap.add(p)
    t = Tcp(A, B, 40005, 5060)
    for p in t.handshake():
        cap.add(p)
    ms = req('OPTIONS', 'ts1', 1, via_proto='TCP')
    cap.add(t.seg(True, ms[:20]))
    cap.add(t.seg(True, ms[20:]))
    # a message and the start of the next one without a line end, and one with incomplete headers
    m2 = req('OPTIONS', 'ts2', 1, via_proto='TCP')
    cap.add(t.seg(True, ms + m2[:15]))
    cap.add(t.seg(True, m2[15:]))
    cap.add(t.seg(True, ms + m2[:90]))
    cap.add(t.seg(True, m2[90:]))
    for p in t.close():
        cap.add(p)
    # non-default TCP port: the heuristic finds SIP; a stream that continues a message
    t = Tcp(A, B, 40002, 5070)
    for p in t.handshake():
        cap.add(p)
    cap.add(t.seg(True, req('OPTIONS', 'th1', 1, via_proto='TCP')))
    cap.add(t.seg(False, resp(200, 'OK', 'th1', 1, 'OPTIONS', via_proto='TCP')))
    cap.add(t.seg(True, req('OPTIONS', 'th2', 1, via_proto='TCP') + b'X' * 50))   # a continuation
    cap.add(t.seg(True, req('OPTIONS', 'th3', 1, via_proto='TCP') + b'\r\nZZZ'))   # empty line: not SIP
    m4 = req('OPTIONS', 'th4', 1, via_proto='TCP')
    cap.add(t.seg(True, req('OPTIONS', 'th5', 1, via_proto='TCP') + m4[:100]))      # headers not complete
    cap.add(t.seg(True, m4[100:]))
    cap.add(t.seg(True, b'X' * 50))        # not SIP
    for p in t.close():
        cap.add(p)
    mark('tcp')

    # ===== 8. other transports: heuristic UDP, SCTP, Exported PDU, WebSocket, TURN =====
    U(cap, req('OPTIONS', 'hu1', 1), sport=5070, dport=5070)
    U(cap, resp(200, 'OK', 'hu1', 1, 'OPTIONS'), fwd=False, sport=5070, dport=5070)
    U(cap, b'not a sip message at all, just text', sport=5070, dport=5070)
    cap.add(sctp_init(A, B, 5060, 5060))
    cap.add(sctp_init(B, A, 5060, 5060, ack=True))
    cap.add(sctp_data(A, B, 5060, 5060, req('OPTIONS', 'sc1', 1, via_proto='SCTP'), ppid=0))
    cap.add(sctp_data(A, B, 5098, 5098, req('OPTIONS', 'sc2', 1, via_proto='SCTP'), tsn=2, ppid=0))
    mark('sctp')
    # SigComp: the first octet has the five high bits set
    U(cap, b'\xf8\x00\x00' + b'\x01' * 8)
    # an ICMP port unreachable that holds the whole datagram it answers
    sipm = req('OPTIONS', 'ic1', 1)
    inner = ip4(A, B, 17, struct.pack('>HHHH', 5060, 5060, 8 + len(sipm), 0) + sipm, 77)
    icmp = struct.pack('>BBHI', 3, 3, 0, 0) + inner
    icmp = icmp[:2] + struct.pack('>H', csum(icmp)) + icmp[4:]
    cap.add(eth(MAC_B, MAC_A, ip4(B, A, 1, icmp, 78)))
    mark('icmp')
    cap.add(exp_pdu('sip', req('OPTIONS', 'e1', 1)), 252)
    cap.add(exp_pdu('sip.tcp', req('OPTIONS', 'e2', 1, via_proto='TCP')), 252)
    mark('exported')
    # TURN ChannelData carrying SIP
    sipm = req('OPTIONS', 'tu1', 1)
    U(cap, struct.pack('>HH', 0x4001, len(sipm)) + sipm + b'\0' * ((4 - len(sipm) % 4) % 4), sport=40010, dport=3478)
    # WebSocket (RFC 7118): HTTP upgrade, then a text frame in each direction
    t = Tcp(A, B, 40003, 8080)
    for p in t.handshake():
        cap.add(p)
    cap.add(t.seg(True, b'GET / HTTP/1.1\r\nHost: 192.0.2.2\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n'
                        b'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Protocol: sip\r\nSec-WebSocket-Version: 13\r\n\r\n'))
    cap.add(t.seg(False, b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n'
                         b'Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\nSec-WebSocket-Protocol: sip\r\n\r\n'))
    ws = req('OPTIONS', 'ws1', 1, via_proto='WS')
    cap.add(t.seg(True, bytes([0x81, 0x80 | 126]) + struct.pack('>H', len(ws)) + b'\0\0\0\0' + ws))
    ws = resp(200, 'OK', 'ws1', 1, 'OPTIONS', via_proto='WS')
    cap.add(t.seg(False, bytes([0x81, 126]) + struct.pack('>H', len(ws)) + ws))
    for p in t.close():
        cap.add(p)
    mark('websocket')

    # ===== 9. reproducers of the fixes =====
    # Session-ID leak (the layout of the report, "remote" + spaces + "=")
    U(cap, (b'OPTIONS sip:bob@192.0.2.2 SIP/2.0\r\nVia: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1\r\nCall-ID: leak1@192.0.2.1\r\nCSeq: 1 OPTIONS\r\n'
            b'Session-ID: ' + HEX32 + b';remote' + b' ' * 27 + b'=' + HEX32 + b';lo\r\nContent-Length: 0\r\n\r\n'))
    mark('repro_sessionid')
    # ;remote=<uuid> is decoded as remote_uuid; the logme parameter after it
    U(cap, (b'OPTIONS sip:bob@192.0.2.2 SIP/2.0\r\nVia: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK2\r\nCall-ID: remote1@192.0.2.1\r\nCSeq: 1 OPTIONS\r\n'
            b'Session-ID: ' + HEX32 + b';remote=' + HEX32 + b'\r\n\r\n'))
    mark('repro_remote')
    # SIP in SIP (message/sip) nested to the limit and beyond (the limit is 4)
    def nest(n):
        body = req('OPTIONS', 'nn%d' % n, 1)
        for k in range(n - 1, 0, -1):
            body = req('OPTIONS', 'nn%d' % k, 1, body=body, ctype='message/sip')
        return body
    U(cap, nest(4))
    mark('repro_nest4')

    cap.write(outdir + '/sip-coverage.pcapng')
    with open(outdir + '/frames.txt', 'w') as f:
        for k, v in frames.items():
            f.write('%s %d\n' % (k, v))

    # ===== malformed capture =====
    cap = Cap()
    def X(data, **kw):
        U(cap, data, **kw)
    # nesting beyond the limit; with a gzip body it expands to many levels
    X(nest(8))
    hdr = b'OPTIONS sip:b@192.0.2.2 SIP/2.0\r\nContent-Type: message/sip\r\n\r\n'
    inner = hdr * 30 + b'OPTIONS sip:b@192.0.2.2 SIP/2.0\r\n\r\n'
    X(b'OPTIONS sip:b@192.0.2.2 SIP/2.0\r\nContent-Type: message/sip\r\nContent-Encoding: gzip\r\n\r\n' + zlib.compress(inner, 9))
    # two SIP messages in one TCP segment: results shared (two-pass differences, not fixed)
    t = Tcp(A, B, 40010, 5060)
    for p in t.handshake():
        cap.add(p)
    cap.add(t.seg(True, req('INVITE', 'two1', 1, via_proto='TCP') + req('INVITE', 'two2', 1, via_proto='TCP')))
    cap.add(t.seg(False, resp(200, 'OK', 'two1', 1, 'INVITE', via_proto='TCP') + resp(200, 'OK', 'two2', 1, 'INVITE', via_proto='TCP')))
    for p in t.close():
        cap.add(p)
    base = lambda extra, first=b'OPTIONS sip:bob@192.0.2.2 SIP/2.0': (first + b'\r\nVia: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bKm\r\nFrom: <sip:a@b>;tag=1\r\nTo: <sip:b@c>\r\nCall-ID: m@192.0.2.1\r\nCSeq: 1 OPTIONS\r\n' + extra)
    # the reproducer of the leak as reported: the last header has no line end
    X(b'OPTIONS sip:bob@192.0.2.2 SIP/2.0\r\nVia: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1\r\nCall-ID: leak1@192.0.2.1\r\nCSeq: 1 OPTIONS\r\n'
      b'Session-ID: ' + HEX32 + b';remote' + b' ' * 27 + b'=' + HEX32 + b';lo')
    X(b'OPTIONS sip:bob@192.0.2.2 SIP/2.0\r\nVia: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1\r\nCall-ID: leak2@192.0.2.1\r\nCSeq: 1 OPTIONS\r\n'
      b'Session-ID: ' + HEX32 + b';remote=' + HEX32 + b';lo')
    bad = [
        b'P-Charging-Vector: icid-value=1;flag\r\n\r\n', b'P-Charging-Vector: icid-value=1;icid-gen-addr=x;y\r\n\r\n',
        b'Session-ID: ' + HEX32 + b';remote=' + HEX32 + b'; \r\n\r\n', b'Session-ID: ' + HEX32 + b';remote=' + HEX32 + b';\t\r\n\r\n',
        b'Via: SIP/2.0/UDP host;oc=abc\r\n\r\n', b'Via: SIP/2.0/UDP host;oc-seq=\r\n\r\n',
        b'Trigger-Consent: sip:x@y;target-uri="sip:a@b";x\r\n\r\n',
        b'P-Access-Network-Info: 3GPP-UTRAN-FDD\r\n\r\n',
        b'Session-ID: ' + HEX32B[:0] + b';remote=' + HEX32B + b'\r\n\r\n', b'Security-Client: ipsec-3gpp;alg=x;spi-c=abc\r\n\r\n',
        b'Content-Length: abc\r\n\r\n', b'Content-Length: 99999999999\r\n\r\nbody', b'Content-Length: 500\r\n\r\nshort body',
        b'Retry-After: abc\r\n\r\n', b'Expires: x\r\n\r\n', b'Max-Forwards: x\r\n\r\n', b'RSeq: x\r\n\r\n',
        b'NoColonHere\r\n\r\n', b'X-Header: value without end', b'Reason: SIP\r\n\r\n', b'Reason: SIP;cause=abc;text="x\r\n\r\n',
        b'Reason: SIP;cause=1;text=x\r\n\r\n', b'Reason: ;\r\n\r\n', b'Reason:\r\n\r\n',
        b'Security-Client: ipsec-3gpp;spi-c=abc\r\n\r\n', b'Security-Client: ipsec-3gpp;noequals\r\n\r\n', b'Security-Client: \r\n\r\n',
        b'Session-ID: \r\n\r\n', b'Session-ID: ;remote=' + HEX32 + b'\r\n\r\n', b'Session-ID: zzzz\r\n\r\n',
        b'Session-ID: ' + HEX32 + b';remote=' + HEX32 + b';\r\n\r\n', b'Session-ID: ' + HEX32 + b';remote=' + HEX32 + b';logme;;x\r\n\r\n',
        b'Session-ID: ' + HEX32 + b';remote=' + HEX32 + b';l',
        b'Via: SIP/2.0/UDP host:99999;branch=x\r\n\r\n', b'Via: SIP/2.0/UDP host:\r\n\r\n', b'Via: SIP/2.0/UDP\r\n\r\n', b'Via: x\r\n\r\n',
        b'Via: SIP/2.0/UDP [2001:db8::1\r\n\r\n', b'Via: SIP/2.0/UDP host;\r\n\r\n', b'Via: SIP/2.0/UDP host;branch\r\n\r\n',
        b'Via: SIP/2.0/UDP host;branch=\r\n\r\n', b'Via: SIP/2.0/UDP host;oc-seq=\r\n\r\n', b'Via: SIP/2.0/UDP host;oc\r\n\r\n',
        b'Via: \r\n\r\n', b'Via:\r\n\r\n',
        b'Contact: <sip:a@b\r\n\r\n', b'Contact: sip:\r\n\r\n', b'Contact: <>\r\n\r\n', b'Contact: <sip:a@b>;expires=abc\r\n\r\n',
        b'Contact: <sip:a@b>;x="unterminated\r\n\r\n', b'Contact: ,\r\n\r\n', b'Contact:\r\n\r\n', b'Contact: <sip:a@b>,\r\n\r\n',
        b'To: \r\n\r\n', b'To: <sip:a@b\r\n\r\n', b'To: <sip:a@b>;tag=\r\n\r\n', b'From: <\r\n\r\n', b'From: sip:\r\n\r\n',
        b'To: <tel:\r\n\r\n', b'To: tel:+1;\r\n\r\n', b'To: <sip:[::1>\r\n\r\n', b'To: <sip:a@[::1\r\n\r\n', b'To: <sip:a@b:>\r\n\r\n',
        b'To: sip:a@b:5060;\r\n\r\n', b'To: "unterminated <sip:a@b>\r\n\r\n', b'To: <sip:a@b>;tag=x;tag=y\r\n\r\n',
        b'P-Asserted-Identity: <sip:\r\n\r\n', b'P-Asserted-Identity:\r\n\r\n',
        b'History-Info: ,,\r\n\r\n', b'History-Info:\r\n\r\n', b'P-Charging-Function-Addresses: ccf=\r\n\r\n',
        b'P-Charging-Function-Addresses: ;\r\n\r\n', b'P-Charging-Function-Addresses:\r\n\r\n',
        b'P-Access-Network-Info: \r\n\r\n', b'P-Access-Network-Info: x;\r\n\r\n', b'P-Access-Network-Info: x;a\r\n\r\n',
        b'P-Access-Network-Info: x;utran-cell-id-3gpp=\r\n\r\n', b'P-Charging-Vector: icid-value\r\n\r\n',
        b'P-Charging-Vector: ;\r\n\r\n', b'P-Charging-Vector: a=;\r\n\r\n', b'Feature-Caps: \r\n\r\n', b'Feature-Caps: *;\r\n\r\n',
        b'Feature-Caps: *;a\r\n\r\n',
        b'Route: <\r\n\r\n', b'Route: ,\r\n\r\n', b'Route:\r\n\r\n', b'Route: <sip:a@b>,<sip:c', b'Route: sip:a@b;lr;foo\r\n\r\n',
        b'Accept-Contact: ;\r\n\r\n',
        b'Authorization: Digest username\r\n\r\n', b'Authorization: Digest username="unterminated\r\n\r\n',
        b'Authorization: Digest =\r\n\r\n', b'Authorization: Digest a=\r\n\r\n', b'Authorization: Digest ,,\r\n\r\n',
        b'Authorization:\r\n\r\n', b'Authorization: Digest nc=1,qop=auth,cnonce=x,response=y\r\n\r\n',
        b'Trigger-Consent: sip:x@y;target-uri="unterminated\r\n\r\n', b'Trigger-Consent: \r\n\r\n',
        b'Content-Type: text/plain;\r\n\r\nbody', b'Content-Type: \r\n\r\nbody', b'Content-Type: ;\r\n\r\nbody',
        b'Content-Encoding: gzip\r\nContent-Length: 5\r\n\r\nxxxxx', b'Content-Encoding: deflate\r\n\r\nnot deflate data',
        b'CSeq: abc\r\n\r\n', b'CSeq: 1\r\n\r\n', b'CSeq: 1 \r\n\r\n', b'CSeq: 1 ' + b'M' * 100 + b'\r\n\r\n',
        b'CSeq:\r\n\r\n', b'RAck: 1\r\n\r\n', b'RAck: 1 2\r\n\r\n', b'RAck: x y z\r\n\r\n', b'RAck:\r\n\r\n',
        b'Call-ID:\r\n\r\n', b'Call-ID: ' + b'c' * 300 + b'\r\n\r\n',
        b'Expires:\r\n\r\n', b'Retry-After:\r\n\r\n', b'Refer-To:\r\n\r\n', b'Join:\r\n\r\n',
        b'\r\n', b'',
    ]
    for b in bad:
        X(base(b) if b else base(b'')[:-0 or None])
    # a message without a Call-ID, without CSeq, with an unknown method and status lines of odd shape
    X(b'OPTIONS sip:bob@192.0.2.2 SIP/2.0\r\nVia: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bKnc\r\nContent-Length: 0\r\n\r\n')
    X(b'SIP/2.0 200\r\nVia: SIP/2.0/UDP 192.0.2.1\r\nCall-ID: s@h\r\nCSeq: 1 OPTIONS\r\n\r\n')
    X(b'SIP/2.0 2000 OK\r\nCall-ID: s2@h\r\nCSeq: 1 OPTIONS\r\n\r\n')
    X(b'SIP/2.0 abc OK\r\nCall-ID: s3@h\r\nCSeq: 1 OPTIONS\r\n\r\n')
    X(b'SIP/9.9 200 OK\r\nCall-ID: s4@h\r\nCSeq: 1 OPTIONS\r\n\r\n')
    X(b'OPTIONS sip:bob@192.0.2.2 SIP/9.9\r\nCall-ID: s5@h\r\nCSeq: 1 OPTIONS\r\n\r\n')
    X(b'OPTIONS sip:bob@192.0.2.2\r\nCall-ID: s6@h\r\nCSeq: 1 OPTIONS\r\n\r\n')
    X(b'options sip:bob@192.0.2.2 SIP/2.0\r\nCall-ID: s7@h\r\nCSeq: 1 OPTIONS\r\n\r\n')
    X(b'OPTIONS \r\nCall-ID: s8@h\r\n\r\n')
    for rl in (b'OPTIONS ab SIP/2.0', b'OPTIONS sipbob SIP/2.0', b'OPTIONS sipbob SIP/2.0:x', b'OPTIONS sip:b@h SIP/2.0:', b'OPTIONS sip:a SIP/2.0 extra',
               b'OPTIONS a:b', b'FOO sip:a SIP/2.0'):
        X(rl + b'\r\nCall-ID: rl@h\r\nCSeq: 1 OPTIONS\r\n\r\n')
    X(b'\xf8\x00\x00' + b'\x01' * 8)
    X(b'SIP/2.0 ')
    X(b'OPTIONS sip:bob@192.0.2.2 SIP/2.0\r\n')
    X(b'OPTIONS sip:bob@192.0.2.2 SIP/2.0')
    X(b'This is a continuation line of nothing\r\n', sport=5070, dport=5060)
    X(b'\x01\x02\x03 binary garbage', sport=5060, dport=5060)
    X(b'OPTIONS sip:b\x00ob@192.0.2.2 SIP/2.0\r\nCall-ID: nul@h\r\nCSeq: 1 OPTIONS\r\n\r\n')
    X(b'   \r\n')
    # an extremely long header, many Via headers, deep folded header
    X(base(b'X-Long: ' + b'a' * 6000 + b'\r\n\r\n'))
    X(base(b''.join(b'Via: SIP/2.0/UDP 192.0.2.1:%d;branch=z9hG4bK%d\r\n' % (5060 + i, i) for i in range(200)) + b'\r\n'))
    X(base(b'Subject: a\r\n' + b' b\r\n' * 300 + b'\r\n'))
    # truncated TCP message: Content-Length larger than the stream delivers
    t = Tcp(A, B, 40011, 5060)
    for p in t.handshake():
        cap.add(p)
    cap.add(t.seg(True, req('MESSAGE', 'tr1', 1, body=b'x' * 10, ctype='text/plain', via_proto='TCP', clen=False,
                            extra=['Content-Length: 1000'])))
    cap.add(t.seg(True, b'y' * 20))
    for p in t.close():
        cap.add(p)
    # SDP bodies that cannot be applied: no media, missing lines
    X(req('INVITE', 'sd1', 1, body=b'v=0\r\ngarbage\r\n', ctype='application/sdp'))
    X(resp(200, 'OK', 'sd1', 1, 'INVITE', body=b'v=0\r\nm=audio 0 RTP/AVP 0\r\n', ctype='application/sdp'), fwd=False)
    cap.add(exp_pdu('sip', base(b'Content-Length: 0\r\n\r\n')), 252)
    cap.add(exp_pdu('sip', b'OPTIONS'), 252)
    cap.add(exp_pdu('sip', b''), 252)
    cap.write(outdir + '/sip-coverage-malformed.pcapng')

if __name__ == '__main__':
    build(sys.argv[1])
