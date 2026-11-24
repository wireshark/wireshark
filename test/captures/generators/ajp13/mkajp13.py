#!/usr/bin/env python3
# AJP13 coverage capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""AJP13 (packet-ajp13.c): a web server (10.0.0.1) talks AJP13 to a servlet
container (10.0.0.2) on TCP port 8009.

Usage: mkajp13.py [<output directory>]

Writes:
  ajp13-coverage.pcap            every message type, method, coded and
                                 named header, request attribute, request
                                 and response bodies (reassembled, gzip,
                                 deflate, br, zstd), and a request with a
                                 very large query_string
  ajp13-coverage-malformed.pcap  paths that end in an exception or an
                                 error expert info

Port 8009 is claimed by nvme-tcp by default, so dissect with
-d tcp.port==8009,ajp13.

Every packet is built here (zlib and gzip from the standard library make the
compressed bodies); nothing comes from a real network.
"""

import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import gzip
import struct
import zlib

from capgen import eth, ipv4, tcp, write_pcap  # noqa: E402

AJP_PORT = 8009
WEB = (10, 0, 0, 1)        # web server (AJP client)
CONTAINER = (10, 0, 0, 2)  # servlet container (AJP server)
SYN_OPTIONS = bytes.fromhex('0204ffd704020101')  # MSS, SACK permitted


class Pcap:
    def __init__(self):
        self.frames = []

    def tcp(self, sport, dport, seq, ack, flags, payload=b'', src=WEB, dst=CONTAINER):
        seg = tcp(payload, sport, dport, seq=seq, ack=ack, flags=flags,
                  options=SYN_OPTIONS if flags & 0x02 else b'', src=bytes(src), dst=bytes(dst))
        ip = ipv4(seg, 6, src=bytes(src), dst=bytes(dst), ident=len(self.frames) & 0xffff,
                  flags_frag=0x4000)
        self.frames.append(eth(ip, 0x0800, dst='02:00:00:00:00:02', src='02:00:00:00:00:01'))

    def write(self, path):
        write_pcap(path, self.frames, ts=lambda i: (1700000000 + i // 100, (i % 100) * 10000))


class TcpStream:
    """A TCP connection from the web server to the container, with correct
    sequence numbers. handshake=False starts it in the middle, as if the
    capture had been started late."""
    def __init__(self, cap, cport, handshake=True):
        self.cap, self.cport = cap, cport
        self.cseq, self.sseq = 1000 + cport, 5000 + cport
        if handshake:
            cap.tcp(cport, AJP_PORT, self.cseq, 0, 0x02)
            cap.tcp(AJP_PORT, cport, self.sseq, self.cseq + 1, 0x12, src=CONTAINER, dst=WEB)
            self.cseq += 1
            self.sseq += 1
            cap.tcp(cport, AJP_PORT, self.cseq, self.sseq, 0x10)

    def web(self, *datas):
        """Send each argument as one TCP segment from the web server."""
        for data in datas:
            self.cap.tcp(self.cport, AJP_PORT, self.cseq, self.sseq, 0x18, data)
            self.cseq += len(data)

    def container(self, *datas):
        for data in datas:
            self.cap.tcp(AJP_PORT, self.cport, self.sseq, self.cseq, 0x18, data,
                         src=CONTAINER, dst=WEB)
            self.sseq += len(data)

    def close(self):
        self.cap.tcp(self.cport, AJP_PORT, self.cseq, self.sseq, 0x11)
        self.cseq += 1
        self.cap.tcp(AJP_PORT, self.cport, self.sseq, self.cseq, 0x11, src=CONTAINER, dst=WEB)
        self.sseq += 1
        self.cap.tcp(self.cport, AJP_PORT, self.cseq, self.sseq, 0x10)


def split(data, *cuts):
    """Split data at the given offsets, for PDUs spread over segments."""
    out, last = [], 0
    for c in cuts:
        out.append(data[last:c])
        last = c
    return out + [data[last:]]


# ---------------------------------------------------------------------------
# AJP13 encoding


def u8(v):
    return struct.pack('>B', v)


def u16(v):
    return struct.pack('>H', v)


def s(v):
    """AJP string: length, bytes, trailing null. None is the null string
    (length 0xFFFF, nothing follows)."""
    if v is None:
        return b'\xff\xff'
    if isinstance(v, str):
        v = v.encode()
    return u16(len(v)) + v + b'\0'


def req(body):
    """A packet from the web server to the container."""
    return b'\x12\x34' + u16(len(body)) + body


def rsp(body):
    """A packet from the container to the web server."""
    return b'AB' + u16(len(body)) + body


# FORWARD_REQUEST, CPING
FORWARD_REQUEST, SEND_BODY_CHUNK, SEND_HEADERS, END_RESPONSE = 2, 3, 4, 5
GET_BODY_CHUNK, SHUTDOWN, CPONG, CPING = 6, 7, 9, 10

# coded request headers (0xA0nn)
ACCEPT, ACCEPT_CHARSET, ACCEPT_ENCODING, ACCEPT_LANGUAGE = 1, 2, 3, 4
AUTHORIZATION, CONNECTION, CONTENT_TYPE, CONTENT_LENGTH = 5, 6, 7, 8
COOKIE, COOKIE2, HOST, PRAGMA, REFERER, USER_AGENT = 9, 10, 11, 12, 13, 14

# coded response headers (0xA0nn)
R_CONTENT_TYPE, R_CONTENT_LANGUAGE, R_CONTENT_LENGTH, R_DATE = 1, 2, 3, 4
R_LAST_MODIFIED, R_LOCATION, R_SET_COOKIE, R_SET_COOKIE2 = 5, 6, 7, 8
R_SERVLET_ENGINE, R_STATUS, R_WWW_AUTHENTICATE = 9, 10, 11


def headers(hdrs):
    """A header count and the headers: (int, value) is a coded header,
    (str or None, value) a named one."""
    out = u16(len(hdrs))
    for name, value in hdrs:
        if isinstance(name, int):
            out += b'\xa0' + u8(name) + s(value)
        else:
            out += s(name) + s(value)
    return out


def forward(method, uri, hdrs=(), attrs=b'\xff', ver='HTTP/1.1', raddr='192.0.2.10',
            rhost='client.example.net', srv='www.example.com', port=80, ssl=0,
            code=FORWARD_REQUEST):
    return req(u8(code) + u8(method) + s(ver) + s(uri) + s(raddr) + s(rhost) + s(srv)
               + u16(port) + u8(ssl) + headers(list(hdrs)) + attrs)


def attr(aid, value):
    return u8(aid) + s(value)


def body(data):
    """A request body packet: no type code, just the length of the data."""
    return req(u16(len(data)) + data)


def send_headers(status, msg, hdrs=()):
    return rsp(u8(SEND_HEADERS) + u16(status) + s(msg) + headers(list(hdrs)))


def body_chunk(data, length=None):
    return rsp(u8(SEND_BODY_CHUNK) + u16(len(data) if length is None else length) + data + b'\0')


def end_response(reuse=1):
    return rsp(u8(END_RESPONSE) + u8(reuse))


def get_body_chunk(n=8186):
    return rsp(u8(GET_BODY_CHUNK) + u16(n))


# ---------------------------------------------------------------------------
# Compressed bodies the dissector uncompresses

def brotli_stored(data):
    """A brotli stream holding data in one uncompressed meta-block."""
    assert 0 < len(data) <= 0x10000
    bits = []

    def put(v, n):
        bits.extend((v >> i) & 1 for i in range(n))

    put(0, 1)               # WBITS = 16
    put(0, 1)               # ISLAST = 0
    put(0, 2)               # MNIBBLES = 4
    put(len(data) - 1, 16)  # MLEN - 1
    put(1, 1)               # ISUNCOMPRESSED
    bits.extend([0] * (-len(bits) % 8))
    head = bytes(sum(b << i for i, b in enumerate(bits[j:j + 8])) for j in range(0, len(bits), 8))
    return head + data + b'\x03'  # ISLAST = 1, ISLASTEMPTY = 1


def zstd_raw(data):
    """A zstd frame holding data in one raw block."""
    assert len(data) < 256
    return (b'\x28\xb5\x2f\xfd' + b'\x20' + u8(len(data))        # single segment, 1 octet size
            + struct.pack('<I', 1 | (len(data) << 3))[:3] + data)  # last block, raw


def raw_deflate(data):
    c = zlib.compressobj(9, zlib.DEFLATED, -15)
    return c.compress(data) + c.flush()


HTML = (b'<!DOCTYPE html>\n<html><head><title>AJP13 test</title></head>\n'
        b'<body><p>Served by a synthetic servlet container.</p></body></html>\n')
TEXT = b'The quick brown fox jumps over the lazy servlet. ' * 8


# ---------------------------------------------------------------------------
# The clean capture

def every_header_and_attribute(cap):
    """One request with every coded request header and every request
    attribute, and a response with every coded response header."""
    c = TcpStream(cap, 40001)
    long_name = 'X-Long-' + 'L' * 3100   # first octet of the length >= 12
    hdrs = [
        (ACCEPT, 'text/html,application/xhtml+xml'),
        (ACCEPT_CHARSET, 'utf-8'),
        (ACCEPT_ENCODING, 'gzip, deflate, br, zstd'),
        (ACCEPT_LANGUAGE, 'en-US,en;q=0.5'),
        (AUTHORIZATION, 'Basic dXNlcjpwYXNz'),
        (CONNECTION, 'keep-alive'),
        (CONTENT_TYPE, 'text/plain'),
        (CONTENT_LENGTH, '0'),
        (COOKIE, 'JSESSIONID=0123456789ABCDEF'),
        (COOKIE2, '$Version="1"'),
        (HOST, 'www.example.com'),
        (PRAGMA, 'no-cache'),
        (REFERER, 'http://www.example.com/'),
        (USER_AGENT, 'synthetic/1.0'),
        (0x0F, 'coded header code past the table'),
        (0x00, 'coded header code 0'),
        ('X-Forwarded-For', '192.0.2.10'),
        (long_name, 'long header name'),
        (None, 'null header name'),
        ('X-Null-Value', None),
    ]
    attrs = (attr(0x01, '/app') + attr(0x02, '/servlet') + attr(0x03, 'alice')
             + attr(0x04, 'BASIC') + attr(0x05, 'q=all&x=1') + attr(0x06, 'node1')
             + attr(0x07, '-----BEGIN CERTIFICATE-----MIIB-----END CERTIFICATE-----')
             + attr(0x08, 'ECDHE-RSA-AES128-GCM-SHA256') + attr(0x09, '0011223344556677')
             + u8(0x0A) + s('AJP_REMOTE_PORT') + s('54321')       # req_attribute
             + u8(0x0B) + u16(128)                                # ssl_key_size
             + attr(0x0C, 'sharedsecret') + attr(0x0D, 'PROPFIND')
             + attr(0x0E, 'attribute code past the table') + attr(0x00, None)
             + b'\xff')
    c.web(forward(2, '/app/servlet/index.html', hdrs, attrs, ssl=1, rhost=None, port=443))
    rhdrs = [
        (R_CONTENT_TYPE, 'Text/HTML; charset=UTF-8'),
        (R_CONTENT_LANGUAGE, 'en'),
        (R_CONTENT_LENGTH, str(len(HTML))),
        (R_DATE, 'Tue, 14 Nov 2023 22:13:20 GMT'),
        (R_LAST_MODIFIED, 'Tue, 14 Nov 2023 22:00:00 GMT'),
        (R_LOCATION, 'http://www.example.com/app/'),
        (R_SET_COOKIE, 'JSESSIONID=0123456789ABCDEF; Path=/app'),
        (R_SET_COOKIE2, 'a=b; Version=1'),
        (R_SERVLET_ENGINE, 'Synthetic/1.0'),
        (R_STATUS, '200'),
        (R_WWW_AUTHENTICATE, 'Basic realm="app"'),
        (0x0C, 'coded header code past the table'),
        ('X-Powered-By', 'Servlet/4.0'),
        (long_name, 'long header name'),
        (None, 'null header name'),
    ]
    # Several PDUs in one segment
    c.container(send_headers(200, 'OK', rhdrs) + body_chunk(HTML) + end_response(1))

    # Every method, and one code that is not a method
    for m in list(range(1, 22)) + [99]:
        c.web(forward(m, '/app/m%d' % m, [(HOST, 'www.example.com')]))
        c.container(send_headers(204, 'No Content') + end_response(1))
    c.close()


def post_with_content_length(cap):
    """A request body with Content-Length: the first body packet follows
    the request, the others answer GET_BODY_CHUNK. The response body is
    gzip compressed and spread over three chunks and four segments."""
    c = TcpStream(cap, 40002)
    form = b'name=alice&city=springfield&x=1'  # 31 octets
    hdrs = [(CONTENT_TYPE, 'Application/X-WWW-Form-Urlencoded; charset=UTF-8'),
            (CONTENT_LENGTH, str(len(form))), (HOST, 'forms.example.com'),
            ('Content-Encoding', 'identity')]
    fr = forward(4, '/app/form', hdrs, attr(0x05, 'a=1&b=2') + b'\xff')
    c.web(*split(fr, 3, 40))                       # one PDU over three segments
    c.web(body(form[:11]))
    c.container(get_body_chunk())
    c.web(body(form[11:22]))
    c.container(get_body_chunk())
    c.web(body(form[22:]))                         # Content-Length reached
    gz = gzip.compress(TEXT, mtime=0)
    third = len(gz) // 3
    chunks = [body_chunk(gz[:third]), body_chunk(gz[third:2 * third]), body_chunk(gz[2 * third:])]
    c.container(send_headers(200, 'OK', [(R_CONTENT_TYPE, 'text/plain'),
                                         ('Content-Encoding', 'gzip')]) + chunks[0])
    c.container(*split(chunks[1], 2))              # split inside the header
    c.container(chunks[2] + end_response(0))
    c.close()


def chunked_and_encodings(cap):
    """Request bodies without Content-Length (they end with an empty body
    packet) and every Content-Encoding the dissector knows."""
    c = TcpStream(cap, 40003)
    # deflate request body, ended by an empty packet (12 34 00 00)
    js = b'{"items":[' + b','.join(b'{"id":%d}' % i for i in range(20)) + b']}'
    dfl = zlib.compress(js)
    c.web(forward(5, '/api/items.json', [(CONTENT_TYPE, 'application/json'),
                                         ('Content-Encoding', 'deflate'),
                                         ('Transfer-Encoding', 'chunked')]))
    c.container(get_body_chunk())
    c.web(body(dfl[:20]))
    c.container(get_body_chunk())
    c.web(body(dfl[20:]))
    c.container(get_body_chunk())
    c.web(b'\x12\x34\x00\x00')
    c.container(send_headers(201, 'Created', [(R_CONTENT_TYPE, 'application/json'),
                                              ('content-encoding', 'x-gzip')])
                + body_chunk(gzip.compress(js, mtime=0)) + end_response(1))

    # x-deflate (raw deflate) request body, ended by a body packet of length 0
    c.web(forward(5, '/api/raw', [(CONTENT_TYPE, 'text/plain'),
                                  ('Content-Encoding', 'x-deflate')]))
    c.container(get_body_chunk())
    c.web(body(raw_deflate(TEXT)))
    c.container(get_body_chunk())
    c.web(req(u16(0)))
    c.container(send_headers(200, 'OK', [(R_CONTENT_TYPE, 'text/plain'),
                                         ('Content-Encoding', 'br')])
                + body_chunk(brotli_stored(TEXT)) + end_response(1))

    # Responses in the other encodings
    for path, enc, data in (('/z.txt', 'zstd', zstd_raw(TEXT[:200])),
                            ('/d.txt', 'Deflate', zlib.compress(TEXT)),
                            ('/c.txt', 'compress', TEXT),
                            ('/bad.txt', 'gzip', b'this is not gzip data')):
        c.web(forward(2, '/static' + path, [(HOST, 'static.example.com')]))
        c.container(send_headers(200, 'OK', [(R_CONTENT_TYPE, 'text/plain'),
                                             ('Content-Encoding', enc)]),
                    body_chunk(data), end_response(1))
    # A request body that ends before the container reads all of it:
    # END_RESPONSE stops the body
    c.web(forward(4, '/app/upload', [(CONTENT_LENGTH, '100'), (CONTENT_TYPE, 'text/plain')]))
    c.web(body(b'first part of the upload'))
    c.container(send_headers(413, 'Payload Too Large') + end_response(0))
    c.close()


def odd_messages(cap):
    """A capture started in the middle of a response, CPING/CPONG, message
    codes that are not defined and data that is not AJP13."""
    c = TcpStream(cap, 40004, handshake=False)
    c.container(body_chunk(b'tail of a response whose headers were not captured'))
    c.container(end_response(1))
    # A request body asked for by GET_BODY_CHUNK, of a request not captured
    c.container(get_body_chunk(100))
    c.web(body(b'body of a request that was not captured'))
    # Response without a request
    c.container(send_headers(200, 'OK', [(R_CONTENT_TYPE, 'text/plain')]),
                body_chunk(b'orphan response body'),
                body_chunk(b''),                                # empty chunk
                body_chunk(b'short', length=1000),              # longer than the data
                end_response(1))
    # CPING / CPONG
    c.web(req(u8(CPING)))
    c.container(rsp(u8(CPONG)))
    c.web(req(u8(CPING)) + req(u8(CPING)))
    c.container(rsp(u8(CPONG)) + rsp(u8(CPONG)))
    # Message codes the container does not send, and one that is undefined
    c.container(rsp(u8(SHUTDOWN) + b'\0\x04stop'))
    c.container(rsp(u8(0x0B) + b'\0\x05undefined'))
    # A request with a code that is not FORWARD_REQUEST, laid out like
    # one, with a body that therefore belongs to no request
    c.web(forward(2, '/not-forwarded', [(CONTENT_LENGTH, '4')], code=8))
    c.web(body(b'abcd'))
    c.container(end_response(1))
    # Attributes that end with the packet, without the 0xFF terminator
    c.web(forward(2, '/no-terminator', [], attr(0x06, 'node2')))
    c.container(send_headers(304, 'Not Modified') + end_response(1))
    # Neither magic
    c.web(b'\x56\x78' + u16(4) + b'junk')
    c.close()


def large_query_string(cap):
    """A 31000 octet URI and 11000
    null query_string attributes, which used to keep a copy of the URI per
    attribute (about 1.4 GB). The URI ends in "/big" so the exported file
    name shows whether the query string was appended once."""
    c = TcpStream(cap, 40005)
    uri = b'/' + b'\x01' * 30995 + b'/big'
    assert len(uri) == 31000
    attrs = b'\x05\xff\xff' * 11000 + b'\xff'
    c.web(req(u8(2) + u8(2) + s(b'') + s(uri) + s(b'') + s(b'') + s(b'')
              + u16(0) + u8(0) + u16(0) + attrs))
    c.container(send_headers(200, 'OK', [(R_CONTENT_TYPE, 'text/plain')])
                + body_chunk(b'big response\n') + end_response(1))
    c.close()


# ---------------------------------------------------------------------------
# Paths that end in an exception or an error expert info

def malformed_packets(cap):
    c = TcpStream(cap, 40101)
    # Content-Length that is not a number: error expert info
    c.web(forward(2, '/bad-length', [(CONTENT_LENGTH, 'abc')]))
    c.container(send_headers(400, 'Bad Request') + end_response(1))
    # SHUTDOWN from the web server is dissected as a FORWARD_REQUEST and
    # runs out of data reading the method
    c.web(req(u8(SHUTDOWN)))
    # A request body packet whose length is larger than the packet
    c.web(forward(4, '/short-body', [(CONTENT_LENGTH, '50')]))
    c.web(req(u16(50) + b'only ten..'))
    c.container(end_response(1))
    # Truncated FORWARD_REQUEST: the URI length points past the PDU
    c.web(req(u8(2) + u8(2) + s('HTTP/1.1') + u16(500) + b'/x'))
    # Truncated SEND_HEADERS: two headers announced, one present
    c.container(rsp(u8(SEND_HEADERS) + u16(200) + s('OK') + u16(2) + b'\xa0\x01' + s('text/plain')))
    # A response that is too short for the data offset
    c.container(rsp(u8(0x0C)))
    c.close()


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    cap = Pcap()
    for gen in (every_header_and_attribute, post_with_content_length, chunked_and_encodings,
                odd_messages, large_query_string):
        gen(cap)
    cap.write(os.path.join(out, 'ajp13-coverage.pcap'))
    bad = Pcap()
    malformed_packets(bad)
    bad.write(os.path.join(out, 'ajp13-coverage-malformed.pcap'))


if __name__ == '__main__':
    main()
