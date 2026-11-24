#!/usr/bin/env python3
# Generates test/captures/multipart_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the MIME multipart coverage captures. Usage: mkmultipart.py <outdir>
multipart-coverage.pcap            main capture: HTTP (TCP 80) and SIP (UDP 5060)
                                   messages with multipart bodies
multipart-coverage-malformed.pcap  missing parameters, truncated bodies, odd headers
Everything is synthetic."""
import struct
import sys
import os
import zlib
import base64

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'

def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

C = [192, 0, 2, 1]; S = [192, 0, 2, 2]

def eth(src):
    return (bytes.fromhex('020000000002020000000001') if src == C else
            bytes.fromhex('020000000001020000000002')) + b'\x08\x00'

def ip_hdr(src, dst, proto, n, ident=1):
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + n, ident, 0, 64, proto, 0, bytes(src), bytes(dst))
    return ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]

def tcp(src, dst, sport, dport, seqn, ack, flags, payload):
    opts = b'\x02\x04\x05\xb4' if flags & 2 else b''
    t = struct.pack('>HHIIBBHHH', sport, dport, seqn, ack, (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts + payload
    ph = bytes(src) + bytes(dst) + struct.pack('>BBH', 0, 6, len(t))
    t = t[:16] + struct.pack('>H', csum(ph + t)) + t[18:]
    return eth(src) + ip_hdr(src, dst, 6, len(t)) + t

def udp(src, dst, sport, dport, payload):
    u = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    return eth(src) + ip_hdr(src, dst, 17, len(u)) + u

class Pcap:
    def __init__(self): self.pkts = []
    def add(self, p): self.pkts.append(p)
    def write(self, name):
        with open(os.path.join(OUT, name), 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
            for i, p in enumerate(self.pkts):
                f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
                f.write(p)

class Conn:
    """One TCP connection with HTTP request/response pairs."""
    def __init__(self, pc, sport):
        self.pc, self.sport = pc, sport
        self.c, self.s = 5000, 90000
        pc.add(tcp(C, S, sport, 80, self.c, 0, 0x02, b''))
        pc.add(tcp(S, C, 80, sport, self.s, self.c + 1, 0x12, b''))
        self.c += 1; self.s += 1
        pc.add(tcp(C, S, sport, 80, self.c, self.s, 0x10, b''))
    def request(self, data):
        self.pc.add(tcp(C, S, self.sport, 80, self.c, self.s, 0x18, data)); self.c += len(data)
    def response(self, data):
        self.pc.add(tcp(S, C, 80, self.sport, self.s, self.c, 0x18, data)); self.s += len(data)
    def ack_c(self):
        self.pc.add(tcp(C, S, self.sport, 80, self.c, self.s, 0x10, b''))

def get(path, extra=''):
    return ('GET %s HTTP/1.1\r\nHost: mp.example\r\n%s\r\n' % (path, extra)).encode()
def post(path, ctype, body):
    return ('POST %s HTTP/1.1\r\nHost: mp.example\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\n'
            % (path, ctype, len(body))).encode() + body
def resp(ctype, body, extra=''):
    return ('HTTP/1.1 200 OK\r\nContent-Type: %s\r\n%sContent-Length: %d\r\n\r\n'
            % (ctype, extra, len(body))).encode() + body

def part(headers, body, b, first=False):
    h = ''.join(x + '\r\n' for x in headers)
    return None

def mp(b, parts, preamble=b'', trailer=b'', last=b'--', pad=b''):
    """parts: list of (list of header lines, body bytes)."""
    out = preamble
    for i, (hdrs, body) in enumerate(parts):
        out += b''
        out += (b'\r\n' if (i > 0 or preamble) else b'') + b'--' + b + pad + b'\r\n'
        out += b''.join(h.encode() + b'\r\n' for h in hdrs) + b'\r\n' + body
    out += b'\r\n--' + b + last + b'\r\n' + trailer
    return out

def png_chunk(t, d):
    return struct.pack('>I', len(d)) + t + d + struct.pack('>I', zlib.crc32(t + d) & 0xffffffff)
PNG = (b'\x89PNG\r\n\x1a\n' + png_chunk(b'IHDR', struct.pack('>IIBBBBB', 1, 1, 8, 2, 0, 0, 0))
       + png_chunk(b'IDAT', zlib.compress(b'\x00\x00\x00\x00')) + png_chunk(b'IEND', b''))
CMS = bytes.fromhex('3023' '0609' '2a864886f70d010702' 'a016' '3014' '020101' '3100' '300b' '0609' '2a864886f70d010701' '3100')

def main():
    pc = Pcap()
    cn = Conn(pc, 40000)
    # ---- 1. multipart/mixed: preamble, headers of every kind, trailer
    body = mp(b'frontier', [
        (['Content-Type: text/plain; charset=us-ascii', 'Content-Description: first part',
          'Content-Language: en', 'Content-Id: <p1@mp.example>', 'Content-Transfer-Encoding: 7bit',
          'Content-Length: 12', 'Content-Disposition: inline; filename="a.txt"'], b'Hello World\n'),
        (['c: text/html', 'l: 24', 'X-Custom-Header: some value', 'Content-Type-Fold: a',
          'Content-Disposition: attachment;', ' filename="b.html"'], b'<html><b>x</b></html>\n'),
        (['Content-Type: application/octet-stream', 'Content-Transfer-Encoding: binary'], bytes(range(32))),
        (['Content-Type: text/plain'], b'last part'),
    ], preamble=b'This is a multi-part message in MIME format.\r\n', trailer=b'epilogue text\r\n')
    cn.request(get('/mixed')); cn.response(resp('multipart/mixed; boundary=frontier', body))
    # ---- 2. quoted boundary with parameters, folded Content-Type, transport padding after the boundary
    body = mp(b'simple boundary', [
        (['Content-Type: text/plain; charset="utf-8"; format=flowed'], b'quoted boundary'),
        (['Content-Type: text/plain',  'Content-Encoding: identity'], b'second'),
    ], pad=b'  ')
    cn.request(get('/quoted')); cn.response(resp('multipart/mixed; charset=x; boundary="simple boundary"; foo=bar', body))
    # ---- 3. multipart/form-data upload (request), file as octet-stream, plain field
    body = mp(b'----WebKitFormBoundary7MA4YWxk', [
        (['Content-Disposition: form-data; name="field1"'], b'value1'),
        (['Content-Disposition: form-data; name="file"; filename="data.bin"',
          'Content-Type: application/octet-stream'], bytes(range(64))),
        (['Content-Disposition: form-data; name="doc"; filename="n.xml"', 'Content-Type: application/xml'],
         b'<?xml version="1.0"?><a><b>1</b></a>'),
    ])
    cn.request(post('/upload', 'multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxk', body))
    cn.response(resp('text/plain', b'ok'))
    # ---- 4. multipart/related with an image and html, multipart/alternative, multipart/report
    body = mp(b'rel', [(['Content-Type: text/html', 'Content-Id: <root>'], b'<img src="cid:img">'),
                       (['Content-Type: image/png', 'Content-Id: <img>', 'Content-Transfer-Encoding: binary'], PNG)])
    cn.request(get('/related')); cn.response(resp('multipart/related; type="text/html"; boundary=rel', body))
    body = mp(b'alt', [(['Content-Type: text/plain'], b'plain'), (['Content-Type: text/html'], b'<p>html</p>')])
    cn.request(get('/alt')); cn.response(resp('multipart/alternative; boundary=alt', body))
    body = mp(b'rep', [(['Content-Type: text/plain'], b'report text'),
                       (['Content-Type: message/delivery-status'], b'Reporting-MTA: dns; mx.example\r\n')])
    cn.request(get('/report')); cn.response(resp('multipart/report; report-type=delivery-status; boundary=rep', body))
    # ---- 5. multipart/signed with a base64 signature part, and an unknown multipart subtype
    body = mp(b'sig', [(['Content-Type: text/plain'], b'signed text'),
                       (['Content-Type: application/pkcs7-signature; name=smime.p7s'], CMS)])
    cn.request(get('/signed')); cn.response(resp('multipart/signed; protocol="application/pkcs7-signature"; micalg=sha1; boundary=sig', body))
    body = mp(b'x', [(['Content-Type: image/png'], PNG), (['Content-Type: text/plain'], b'frame 2')])
    cn.request(get('/replace')); cn.response(resp('multipart/x-mixed-replace; boundary=x', body))
    # ---- 6. gzip and deflate encoded parts (uncompress_data is on by default)
    co = zlib.compressobj(9, zlib.DEFLATED, 31); gz = co.compress(b'hello world ' * 20) + co.flush()
    co = zlib.compressobj(9, zlib.DEFLATED, 15); df = co.compress(b'deflated text ' * 10) + co.flush()
    body = mp(b'gz', [(['Content-Type: text/plain', 'Content-Encoding: gzip'], gz),
                      (['Content-Type: text/plain', 'Content-Encoding: deflate'], df),
                      (['Content-Type: text/plain', 'Content-Encoding: x-gzip'], b'not really gzip')])
    cn.request(get('/gzip')); cn.response(resp('multipart/mixed; boundary=gz', body))
    # ---- 7. base64 transfer encoding, base64 + gzip (the fixed gunzip length; needs
    # mime_multipart.remove_base64_encoding), unknown body type
    co = zlib.compressobj(9, zlib.DEFLATED, 31); gz2 = co.compress(b'hello world ' * 20) + co.flush()
    body = mp(b'b64', [(['Content-Type: text/plain', 'Content-Transfer-Encoding: base64'], base64.b64encode(b'plain text in base64 ' * 3)),
                       (['Content-Type: text/plain', 'Content-Transfer-Encoding: base64', 'Content-Encoding: gzip'], base64.b64encode(gz2)),
                       (['Content-Type: application/x-unknown-type', 'Content-Disposition: attachment; filename=x.bin'], b'\x01\x02\x03'),
                       (['Content-Type: text/plain; name=named.txt', 'Content-Transfer-Encoding: BASE64'], base64.b64encode(b'named')),
                       (['Content-Type: text/plain', 'Content-Transfer-Encoding: quoted-printable'], b'a=3Db')])
    cn.request(get('/b64')); cn.response(resp('multipart/mixed; boundary=b64', body))
    # ---- 8. encrypted (MS-WSMV), first part of another type than the protocol: not processed
    body = mp(b'Encrypted Boundary', [(['Content-Type: text/plain'], b'first'), (['Content-Type: application/octet-stream'], b'second')])
    cn.request(post('/wsman', 'multipart/encrypted; protocol="application/HTTP-SPNEGO-session-encrypted"; boundary="Encrypted Boundary"', body))
    cn.response(resp('text/plain', b'ok'))
    # ---- 9. last boundary without the CRLF in front, no CRLF before the first boundary
    body = (b'--nb\r\nContent-Type: text/plain\r\n\r\nno crlf before the close delimiter--nb--\r\n')
    cn.request(get('/nocrlf')); cn.response(resp('multipart/mixed; boundary=nb', body))
    body = (b'--nh\r\nContent-Type: text/plain\r\n\r\nbody\r\n--nh\r\nX-Only: header\r\n--nh--')
    cn.request(get('/nohdr')); cn.response(resp('multipart/mixed; boundary=nh', body))
    # headers without the blank line before the next boundary, no CRLF after the last header
    body = (b'--nl\r\nContent-Type: text/plain\r\nContent-Description: d\r\n--nl\r\nContent-Type: text/plain\r\n\r\nx\r\n--nl--')
    cn.request(get('/nolast')); cn.response(resp('multipart/mixed; boundary=nl', body))
    # first line is not a header: whole part is the body; unprintable header name
    body = mp(b'nb2', [([], b'just text, no header lines here'), (['Bad\x01Name: x'], b'body2'), (['no colon here'], b'body3')])
    cn.request(get('/noheader')); cn.response(resp('multipart/mixed; boundary=nb2', body))
    # bare LF and bare CR line ends, folding with LF, quoted pair and an unterminated quote in a header
    body = (b'--lf\nContent-Type: text/plain;\n charset=us-ascii\nContent-Description: lf only\n\nlf body\n--lf\n'
            b'Content-Type: text/plain\nContent-Disposition: attachment; filename="a\\"b.txt"\n\nsecond\n--lf\n'
            b'Content-Type: text/plain\nContent-Disposition: attachment; filename="open\n\nthird\n--lf--\n')
    cn.request(get('/lf')); cn.response(resp('multipart/mixed; boundary=lf', body))
    body = (b'--cr\r\nContent-Type: text/plain;\r charset=us-ascii\r\n\r\ncr fold\r\n--cr\r\n'
            b'Content-Type: text/plain\rContent-Description: stop\r\n\r\ncr stop\r\n--cr--\r\n')
    cn.request(get('/cr')); cn.response(resp('multipart/mixed; boundary=cr', body))
    body = mp(b'qp', [(['Content-Type: text/plain', 'Content-Disposition: attachment; filename="a\\"b.txt"'], b'quoted pair'),
                      (['Content-Type: text/plain', 'Content-Disposition: attachment; filename="open'], b'unterminated quote'),
                      (['Content-Type: text/plain', 'Content-Disposition: attachment; filename="back\\'], b'ends in backslash')])
    cn.request(get('/qp')); cn.response(resp('multipart/mixed; boundary=qp', body))
    # the first boundary is the closing one; a header that runs into the closing delimiter
    cn.request(get('/closed')); cn.response(resp('multipart/mixed; boundary=lb', b'--lb--\r\n'))
    body = b'--ho\r\nContent-Type: text/plain--ho--\r\n'
    cn.request(get('/hdrend')); cn.response(resp('multipart/mixed; boundary=ho', body))
    # ---- 10. nested multipart: three levels (full decode) and 20 levels (nesting limit)
    def nest(levels, ctype_inner):
        inner = b'leaf text'
        for i in range(levels, 0, -1):
            b = ('n%02d' % i).encode()
            inner = mp(b, [(['Content-Type: ' + (ctype_inner if i == levels else 'multipart/mixed; boundary=n%02d' % (i + 1))], inner)])
        return inner
    cn.request(get('/nest3')); cn.response(resp('multipart/mixed; boundary=n01', nest(3, 'text/plain')))
    cn.request(get('/nest20')); cn.response(resp('multipart/mixed; boundary=n01', nest(20, 'text/plain')))
    cn.ack_c()
    # ---- 11. SIP message with a multipart/mixed body (SDP and an ISUP body), UDP 5060
    sdp = b'v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\nm=audio 4000 RTP/AVP 0\r\n'
    b2 = mp(b'unique-boundary-1', [(['Content-Type: application/sdp'], sdp),
                                  (['Content-Type: application/isup; version=itu-t92+', 'Content-Disposition: signal; handling=optional'], bytes([0x01, 0x00, 0x60, 0x01, 0x0a, 0x00, 0x02, 0x00, 0x04, 0x01, 0x10, 0x21, 0x43]))])
    sip = ('INVITE sip:b@192.0.2.2 SIP/2.0\r\nVia: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK77\r\nFrom: <sip:a@192.0.2.1>;tag=1\r\n'
           'To: <sip:b@192.0.2.2>\r\nCall-ID: mp1\r\nCSeq: 1 INVITE\r\nMIME-Version: 1.0\r\n'
           'Content-Type: multipart/mixed;boundary=unique-boundary-1\r\nContent-Length: %d\r\n\r\n' % len(b2)).encode() + b2
    pc.add(udp(C, S, 5060, 5060, sip))
    pc.write('multipart-coverage.pcap')

    # ---------------------------------------------------------------- malformed
    pm = Pcap()
    cm = Conn(pm, 41000)
    # no boundary parameter, no parameters at all
    cm.request(get('/noboundary')); cm.response(resp('multipart/mixed; charset=x', b'--x\r\n\r\nbody\r\n--x--'))
    cm.request(get('/valueless')); cm.response(resp('multipart/mixed; foo', b'--x\r\n\r\nbody\r\n--x--'))
    cm.request(get('/noparam')); cm.response(resp('multipart/mixed', b'--x\r\n\r\nbody\r\n--x--'))
    # encrypted without protocol parameter
    cm.request(get('/noproto')); cm.response(resp('multipart/encrypted; boundary=zz; foo', b'--zz\r\n\r\nbody\r\n--zz--'))
    # boundary never found, too short to hold one, last part without a closing boundary
    cm.request(get('/noeol')); cm.response(resp('multipart/mixed; boundary=qq', b'there is no line end in here at all and no boundary either'))
    cm.request(get('/noclose')); cm.response(resp('multipart/mixed; boundary=uu', b'--uu\r\nContent-Type: text/plain\r\n\r\nbody\r\nmore\r\nlines\r\n'))
    cm.request(get('/noboundaryline')); cm.response(resp('multipart/mixed; boundary=qq', b'there is no delimiter in here at all\r\n'))
    cm.request(get('/short')); cm.response(resp('multipart/mixed; boundary=qqqqqqqq', b'--qq'))
    cm.request(get('/unterminated')); cm.response(resp('multipart/mixed; boundary=uu', b'--uu\r\nContent-Type: text/plain\r\n\r\nno closing delimiter'))
    cm.request(get('/boundaryonly')); cm.response(resp('multipart/mixed; boundary=bo', b'--bo'))
    cm.request(get('/boundarycr')); cm.response(resp('multipart/mixed; boundary=bo', b'--bo\r'))
    cm.request(get('/preamblenoeol')); cm.response(resp('multipart/mixed; boundary=bo', b'pre\r\n--bo'))
    # ---- 8. encrypted (MS-WSMV): protocol parameter, a first part with the protocol type
    # and an octet-stream second part (placeholder token, nothing is decrypted)
    body = mp(b'Encrypted Boundary', [
        (['Content-Type: application/HTTP-SPNEGO-session-encrypted', 'OriginalContent: type="application/soap+xml;charset=UTF-8";Length=40'], b''),
        (['Content-Type: application/octet-stream'], struct.pack('<I', 16) + b'\x00' * 24)])
    cm.request(post('/wsman', 'multipart/encrypted;protocol="application/HTTP-SPNEGO-session-encrypted";boundary="Encrypted Boundary"', body))
    cm.response(resp('text/plain', b'ok'))
    body = mp(b'Encrypted Boundary', [
        (['Content-Type: application/HTTP-SPNEGO-session-encrypted', 'OriginalContent: application/soap+xml; foo'], b''),
        (['Content-Type: application/octet-stream'], b'\x04\x00\x00\x00abcd')])
    cm.request(post('/wsman', 'multipart/encrypted; protocol="application/HTTP-SPNEGO-session-encrypted"; boundary="Encrypted Boundary"', body))
    cm.response(resp('text/plain', b'ok'))
    body = mp(b'E', [(['Content-Type: application/HTTP-SPNEGO-session-encrypted'], b''),
                     (['Content-Type: application/octet-stream'], struct.pack('<I', 44) + bytes.fromhex('050406ff0000000000000001') + b'\x00' * 32)])
    cm.request(post('/wsman', 'multipart/encrypted; protocol="application/HTTP-SPNEGO-session-encrypted"; boundary=E', body)); cm.response(resp('text/plain', b'ok'))
    # encrypted: part 0 matches, part 1 has a token longer than the data; token only
    body = mp(b'E', [(['Content-Type: application/HTTP-SPNEGO-session-encrypted'], b''),
                     (['Content-Type: application/octet-stream'], b'\x01\x02')])
    cm.request(post('/wsman', 'multipart/encrypted; protocol="application/HTTP-SPNEGO-session-encrypted"; boundary=E', body)); cm.response(resp('text/plain', b'ok'))
    body = mp(b'E', [(['Content-Type: application/HTTP-SPNEGO-session-encrypted'], b''),
                     (['Content-Type: application/octet-stream'], b'')])
    cm.request(post('/wsman', 'multipart/encrypted; protocol="application/HTTP-SPNEGO-session-encrypted"; boundary=E', body)); cm.response(resp('text/plain', b'ok'))
    # part 0 of an encrypted message is raw data
    body = mp(b'E', [(['Content-Type: application/octet-stream'], b'xx'), (['Content-Type: application/octet-stream'], b'yy')])
    cm.request(post('/wsman', 'multipart/encrypted; protocol="application/HTTP-SPNEGO-session-encrypted"; boundary=E', body)); cm.response(resp('text/plain', b'ok'))
    # corrupt gzip and deflate bodies
    body = mp(b'cg', [(['Content-Type: text/plain', 'Content-Encoding: gzip'], b'\x1f\x8b\x08\x00broken'),
                      (['Content-Type: text/plain', 'Content-Encoding: deflate'], b'\xff\xff')])
    cm.request(get('/badgzip')); cm.response(resp('multipart/mixed; boundary=cg', body))
    # invalid base64 with the preference on
    body = mp(b'bb', [(['Content-Type: text/plain', 'Content-Transfer-Encoding: base64'], b'!!!not base64!!!')])
    cm.request(get('/badb64')); cm.response(resp('multipart/mixed; boundary=bb', body))
    # header folded across the end of the body, headers with only a colon
    body = (b'--hh\r\nContent-Type: text/plain\r\n ; charset=x\r\n\r\nbody\r\n--hh\r\n:\r\n\r\nx\r\n--hh\r\n\r\n--hh--')
    cm.request(get('/hdr')); cm.response(resp('multipart/mixed; boundary=hh', body))
    cm.ack_c()
    pm.write('multipart-coverage-malformed.pcap')

main()
