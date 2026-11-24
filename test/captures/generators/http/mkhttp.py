#!/usr/bin/env python3
# Generates test/captures/http_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Write the HTTP coverage captures (Ethernet, TCP, UDP/SSDP, SCTP).

http-coverage.pcap            requests and responses of many sessions
http-coverage-malformed.pcap  paths that need malformed input (error expert
                              infos, failed decompression, snap length cuts)

Usage: mkhttp.py <outdir> [-v]    (-v prints the frame ranges)
"""
import base64
import os
import struct
import sys
import zlib

from wslib import (  # noqa
    brotli_stored, Cap, deflate_bytes, Flow, gzip_bytes, sctp_data, udp, xpress_literal, zstd_raw,
)

VERBOSE = '-v' in sys.argv
sections = {}


def mark(cap, name):
    sections.setdefault(id(cap), []).append((cap.n() + 1, name))


def b64(b):
    return base64.b64encode(b).decode()


def b64u(b):
    return base64.urlsafe_b64encode(b).decode().rstrip('=')


def msg(first, headers=(), body=b'', cl=True):
    """Build an HTTP message. headers: list of (name, value) or raw strings."""
    out = first.encode() + b'\r\n'
    for h in headers:
        out += (h if isinstance(h, str) else '%s: %s' % h).encode('latin-1') + b'\r\n'
    if cl and body is not None and not any(
            (h if isinstance(h, str) else h[0]).lower() in ('content-length', 'transfer-encoding')
            for h in headers) and body != b'':
        out += b'Content-Length: %d\r\n' % len(body)
    return out + b'\r\n' + (body if isinstance(body, bytes) else body.encode())


def req(method, uri, headers=(), body=b'', host='www.example.com', ver='HTTP/1.1', cl=True):
    hs = list(headers)
    if host and not any((h if isinstance(h, str) else h[0]).lower() == 'host' for h in hs):
        hs.insert(0, ('Host', host))
    if body != b'' and method in ('GET', 'HEAD'):
        pass
    return msg('%s %s %s' % (method, uri, ver), hs, body, cl)


def resp(code, reason='OK', headers=(), body=b'', ver='HTTP/1.1', cl=True):
    return msg('%s %s %s' % (ver, code, reason), headers, body, cl)


def chunked(parts, trailer=b'', ext=None):
    out = b''
    for i, p in enumerate(parts):
        e = (';' + ext).encode() if ext else b''
        out += b'%x%s\r\n' % (len(p), e) + p + b'\r\n'
    return out + b'0\r\n' + trailer + b'\r\n'


def exch(f, request, response, dt=2000, dt2=30000):
    f.c(request, dt=dt)
    f.s(response, dt=dt2)


def new_flow(cap, cport, sport=80, **kw):
    f = Flow(cap, cport, sport, **kw)
    f.open()
    return f


HTML = b'<html><head><title>Test</title></head><body><p>Hello, world!</p></body></html>\r\n'
JSON = b'{"name": "example", "values": [1, 2, 3], "nested": {"ok": true}}'
XML = b'<?xml version="1.0"?><root><item id="1">one</item><item id="2">two</item></root>'
GIF = bytes.fromhex('47494638396101000100800000000000ffffff21f90401000000002c00000000010001000002024401003b')

METHODS = ['GET', 'PUT', 'COPY', 'HEAD', 'LOCK', 'MOVE', 'POLL', 'POST', 'BCOPY', 'BMOVE', 'MKCOL',
           'TRACE', 'PATCH', 'LABEL', 'MERGE', 'QUERY', 'DELETE', 'SEARCH', 'UNLOCK', 'REPORT',
           'UPDATE', 'BDELETE', 'CONNECT_NOT', 'OPTIONS', 'CHECKIN', 'PROPFIND', 'CHECKOUT',
           'CCM_POST', 'BPROPFIND', 'PROPPATCH', 'BPROPPATCH', 'UNCHECKOUT', 'MKACTIVITY',
           'MKWORKSPACE', 'RPC_CONNECT', 'RPC_IN_DATA', 'RPC_OUT_DATA', 'VERSION-CONTROL',
           'BASELINE-CONTROL']

STATUS = [100, 101, 102, 103, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 226, 299, 300, 301,
          302, 303, 304, 305, 307, 308, 399, 400, 401, 402, 403, 404, 405, 406, 407, 408, 409, 410,
          411, 412, 413, 414, 415, 416, 417, 418, 421, 422, 423, 424, 425, 426, 428, 429, 431, 451,
          499, 500, 501, 502, 503, 504, 505, 506, 507, 508, 510, 511, 599]


def dns_query(name='www.example.org', qtype=1, ident=0):
    q = b''.join(bytes([len(p)]) + p.encode() for p in name.split('.')) + b'\0'
    return struct.pack('!HHHHHH', ident, 0x0100, 1, 0, 0, 0) + q + struct.pack('!HH', qtype, 1)


def dns_response(name='www.example.org', ident=0):
    q = b''.join(bytes([len(p)]) + p.encode() for p in name.split('.')) + b'\0'
    return (struct.pack('!HHHHHH', ident, 0x8180, 1, 1, 0, 0) + q + struct.pack('!HH', 1, 1) +
            b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 300, 4) + bytes([192, 0, 2, 80]))


def png():
    def chunk(t, d):
        return struct.pack('!I', len(d)) + t + d + struct.pack('!I', zlib.crc32(t + d))
    return (b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('!IIBBBBB', 1, 1, 8, 6, 0, 0, 0)) +
            chunk(b'IDAT', zlib.compress(b'\x00\xff\x00\x00\xff')) + chunk(b'IEND', b''))


def build_main(cap):
    # ---- 1. methods, status codes, basic headers (port 80, IPv4)
    mark(cap, 'methods and basic headers')
    f = new_flow(cap, 41000)
    exch(f, req('GET', '/index.html', [
        ('User-Agent', 'Mozilla/5.0 (X11; Linux x86_64) TestAgent/1.0'),
        ('Accept', 'text/html,application/xhtml+xml'), ('Accept-Language', 'en-US,en;q=0.5'),
        ('Accept-Encoding', 'gzip, deflate'), ('Connection', 'keep-alive'),
        ('Cookie', 'sid=0123456789; theme=dark;lang=en; ;empty='),
        ('Cache-Control', 'max-age=0'), ('X-Forwarded-For', '203.0.113.9'),
        ('Referer', 'http://www.example.com/start.html'), ('Accept-Query', 'application/json'),
        ('X-Request-Id', 'abc-123'), ('X-Custom', 'custom value'),
        ('Mixed-CASE-Header', 'value'), ('Empty-Header', ''), 'X-Name: Zo\xeb']),
        resp(200, 'OK', [('Date', 'Mon, 01 Jan 2024 00:00:00 GMT'), ('Server', 'TestServer/1.0'),
                         ('Last-Modified', 'Sun, 31 Dec 2023 23:00:00 GMT'),
                         ('Set-Cookie', 'sid=abc; Path=/; HttpOnly'),
                         ('Cache-Control', 'public'), ('Connection', 'keep-alive'),
                         ('Content-Type', 'text/html; charset=UTF-8'),
                         ('X-Request-Id', 'abc-123')], HTML))
    for m in METHODS:
        if m == 'CONNECT_NOT':
            continue
        body = b'x=1&y=2' if m in ('POST', 'PUT', 'PATCH', 'QUERY') else b''
        hs = [('Content-Type', 'application/x-www-form-urlencoded')] if body else []
        if m in ('HEAD',):
            exch(f, req(m, '/head', hs, body),
                 resp(200, 'OK', [('Content-Length', '1234'), ('Content-Type', 'text/html')], cl=False))
        else:
            exch(f, req(m, '/m/' + m.lower(), hs, body),
                 resp(200, 'OK', [('Content-Type', 'text/plain')], b'done ' + m.encode()))
    # unusable Content-Length values on requests: no body is assumed
    for v in ('-5', 'abc', '1 2', '5 ', '99999999999999999999', ''):
        exch(f, req('GET', '/cl/' + (v.strip() or 'empty').replace(' ', '_'), [('Content-Length', v)]),
             resp(200, 'OK', [('Content-Length', '0')]))
    # NOTIFY, SUBSCRIBE, UNSUBSCRIBE (GENA, notification type) and M- prefix (RFC 2774)
    exch(f, req('NOTIFY', '/event', [('NT', 'upnp:event'), ('NTS', 'upnp:propchange')]),
         resp(200, 'OK', [('Content-Length', '0')]))
    exch(f, req('SUBSCRIBE', '/event', [('CALLBACK', '<http://192.0.2.1:5000/>'), ('NT', 'upnp:event')]),
         resp(200, 'OK', [('SID', 'uuid:1234'), ('Content-Length', '0')]))
    exch(f, req('UNSUBSCRIBE', '/event', [('SID', 'uuid:1234')]),
         resp(200, 'OK', [('Content-Length', '0')]))
    exch(f, req('M-POST', '/mandatory', [('Man', '"http://www.example.com/ext"; ns=01')]),
         resp(200, 'OK', [('Content-Length', '0')]))
    exch(f, req('M-SEARCH', '*', [('ST', 'ssdp:all'), ('MAN', '"ssdp:discover"'), ('MX', '1')]),
         resp(200, 'OK', [('Content-Length', '0')]))
    # status codes: 8 request/response pairs pipelined per segment
    mark(cap, 'status codes')
    for i in range(0, len(STATUS), 8):
        chunk = STATUS[i:i + 8]
        f.c(b''.join(req('GET', '/s/%d' % c) for c in chunk), dt=2000)
        for c in chunk:
            f.s(resp(c, 'Reason %d' % c, [('Content-Length', '0')]) if c not in (204, 304, 100, 101, 102, 103, 199)
                else resp(c, 'Reason %d' % c, cl=False), dt=20000)
    # status line variants: empty reason, ICY, HTTP/1.0, HTTP/2.0-like, 9xx code in the stats
    exch(f, req('GET', '/s/noreason'), resp(200, '', [('Content-Length', '2')], b'ok'))
    exch(f, req('GET', '/s/v10', ver='HTTP/1.0'), resp(200, 'OK', [('Content-Length', '3')], b'ok\n', ver='HTTP/1.0'))
    exch(f, req('GET', '/s/600'), resp(600, 'Beyond', [('Content-Length', '0')]))
    exch(f, req('GET', '/s/099'), resp('099', 'Below', [('Content-Length', '0')]))
    f.fin()
    return f



def build_targets(cap):
    mark(cap, 'request targets, path and query parts, DoH')
    f = new_flow(cap, 41002)
    for uri in ['/', '/a/b/c.html', '/path;param=1/seg;x/y', '/q?x=1&y=2;z=3&empty=&flag', '/?', '/p?a=b#frag',
                'http://proxy.example.net/abs/path?q=1', '*', '/a%20b/c%2Fd?e=f%26g', '/semi;colon', '/one?a=1;b=2',
                '/path/with/many/segments/in/it/' + '/'.join('s%d' % i for i in range(20))]:
        exch(f, req('GET', uri), resp(200, 'OK', [('Content-Length', '0')]))
    # absolute URI request: full_uri is the URI itself; CONNECT-like full uri
    exch(f, req('OPTIONS', '*', host='www.example.com'), resp(200, 'OK', [('Allow', 'GET, HEAD'), ('Content-Length', '0')]))
    # DNS over HTTPS (RFC 8484): GET with a base64url query of at least 30 bytes, and shorter / invalid ones
    q = dns_query('www.example.org', ident=1)
    r = dns_response('www.example.org', ident=1)
    dt = ('Content-Type', 'application/dns-message')
    exch(f, req('GET', '/dns-query?dns=' + b64u(q), [('Accept', 'application/dns-message')], host='dns.example.net'),
         resp(200, 'OK', [dt], r))
    q2 = dns_query('a-rather-long-name.subdomain.example.org', 28, ident=2)
    exch(f, req('GET', '/dns-query?x=1&dns=' + b64u(q2) + '&y=2', host='dns.example.net'),
         resp(200, 'OK', [dt], dns_response('a-rather-long-name.subdomain.example.org', ident=2)))
    exch(f, req('GET', '/dns-query?dns=AAABAAAB', host='dns.example.net'), resp(200, 'OK', [('Content-Length', '0')]))
    q4 = dns_query('trailing.example.org', ident=4)
    exch(f, req('GET', '/dns-query?dns=' + b64u(q4) + 'A', host='dns.example.net'),
         resp(200, 'OK', [dt], dns_response('trailing.example.org', ident=4)))
    # DoH POST with a DNS message body
    exch(f, req('POST', '/dns-query', [dt, ('Accept', 'application/dns-message')], dns_query('post.example.org', ident=3),
                host='dns.example.net'),
         resp(200, 'OK', [dt], dns_response('post.example.org', ident=3)))
    f.fin()


def build_chunked(cap):
    mark(cap, 'chunked bodies, transfer codings, content length cases')
    f = new_flow(cap, 41003)
    ct = ('Content-Type', 'text/plain')
    exch(f, req('GET', '/c1'), resp(200, 'OK', [ct, ('Transfer-Encoding', 'chunked')], cl=False,
                                    body=chunked([b'Hello, ', b'chunked ', b'world'])))
    exch(f, req('GET', '/c2'), resp(200, 'OK', [ct, ('Transfer-Encoding', 'chunked')], cl=False,
                                    body=chunked([b'with trailer'], trailer=b'X-Trailer: yes\r\nX-Other: 1\r\n')))
    exch(f, req('GET', '/c3'), resp(200, 'OK', [ct, ('Transfer-Encoding', 'chunked')], cl=False,
                                    body=chunked([b'ext one', b'ext two'], ext='name=value')))
    exch(f, req('GET', '/c4'), resp(200, 'OK', [ct, ('Transfer-Encoding', 'chunked')], cl=False, body=chunked([])))
    # chunked request (POST)
    exch(f, req('POST', '/c6', [('Content-Type', 'text/plain'), ('Transfer-Encoding', 'chunked')], cl=False,
                body=chunked([b'a=1&', b'b=2'])), resp(200, 'OK', [('Content-Length', '0')]))
    # a response chunked body split into three TCP segments (reassembly)
    f.c(req('GET', '/c7'), dt=2000)
    body = chunked([b'A' * 300, b'B' * 300, b'C' * 100])
    hdr = resp(200, 'OK', [ct, ('Transfer-Encoding', 'chunked')], cl=False)
    f.s(hdr + body[:200], dt=20000)
    f.s(body[200:500], dt=10000)
    f.s(body[500:], dt=10000)
    # chunk size line split between segments
    f.c(req('GET', '/c8'), dt=2000)
    body = chunked([b'x' * 20, b'y' * 20])
    f.s(hdr + body[:3], dt=20000)
    f.s(body[3:], dt=10000)
    # transfer codings
    for te in ('chunked,, ', 'chunked'):
        data = gzip_bytes(b'transfer coded body')
        exch(f, req('GET', '/te/' + te.replace(' ', '').replace(',', '_')),
             resp(200, 'OK', [ct, ('Transfer-Encoding', te)], cl=False, body=chunked([data])))
    # Content-Length variants
    exch(f, req('POST', '/cl1', [('Content-Length', '4')], b'abcd'), resp(200, 'OK', [('Content-Length', '3')], b'ok\n'))
    # body split in two segments (reassembly by Content-Length)
    None
    big = b''.join(bytes([65 + i % 26]) for i in range(2500))
    h = req('POST', '/cl2', [('Content-Type', 'application/octet-stream')], big)
    f.c(h[:700], dt=2000)
    f.c(h[700:1500], dt=2000)
    f.c(h[1500:], dt=2000)
    f.s(resp(200, 'OK', [('Content-Length', '0')]), dt=20000)
    # a request header split between two segments
    h = req('GET', '/cl3', [('User-Agent', 'split-header-agent')])
    f.c(h[:20], dt=2000)
    f.c(h[20:], dt=2000)
    f.s(resp(200, 'OK', [('Content-Length', '0')]), dt=20000)
    # request line only partly there, no CRLF at all in the first segment
    f.c(b'GET /cl4', dt=2000)
    f.c(b' HTTP/1.1\r\nHost: x\r\n\r\n', dt=1000)
    f.s(resp(200, 'OK', [('Content-Length', '0')]), dt=20000)
    # body extends over three response segments
    big = bytes(range(256)) * 12
    h = resp(200, 'OK', [('Content-Type', 'application/octet-stream')], big)
    f.c(req('GET', '/cl5'), dt=2000)
    f.s(h[:1000], dt=20000)
    f.s(h[1000:2000], dt=1000)
    f.s(h[2000:], dt=1000)
    f.fin()

    # a Content-Length smaller than the data in the segment followed by more
    # HTTP in the same segment (pipelined, excess)
    f = new_flow(cap, 41004)
    f.c(req('GET', '/p1') + req('GET', '/p2') + req('POST', '/p3', body=b'xyz'), dt=2000)
    f.s(resp(200, 'OK', [('Content-Length', '1')], b'1'), dt=20000)
    f.s(resp(200, 'OK', [('Content-Length', '1')], b'2'), dt=2000)
    f.s(resp(404, 'Not Found', [('Content-Length', '1')], b'3'), dt=2000)
    f.fin()


def build_bodies(cap):
    mark(cap, 'content encodings and media types')
    f = new_flow(cap, 41005)
    plain = b'The quick brown fox jumps over the lazy dog. ' * 4
    for enc, data in (('gzip', gzip_bytes(plain)), ('deflate', deflate_bytes(plain)), ('x-gzip', gzip_bytes(plain)),
                      ('x-deflate', deflate_bytes(plain)), ('GZIP', gzip_bytes(plain)),
                      ('br', brotli_stored(plain)), ('zstd', zstd_raw(plain[:100])),
                      ('xpress', xpress_literal(plain[:30])),
                      ('identity', plain)):
        exch(f, req('GET', '/enc/' + enc, [('Accept-Encoding', enc)]),
             resp(200, 'OK', [('Content-Type', 'text/plain'), ('Content-Encoding', enc)], data))
    # gzip + chunked
    exch(f, req('GET', '/enc/chunked'), resp(200, 'OK', [('Content-Type', 'text/html'), ('Content-Encoding', 'gzip'),
                                                         ('Transfer-Encoding', 'chunked')], cl=False,
                                           body=chunked([gzip_bytes(HTML)[:20], gzip_bytes(HTML)[20:]])))
    # empty gzip body is not decompressed
    exch(f, req('GET', '/enc/empty'), resp(200, 'OK', [('Content-Encoding', 'gzip'), ('Content-Length', '0')]))
    # Content-Type media types
    for ctype, body in (('text/html', HTML), ('text/html; charset=UTF-8', HTML), ('TEXT/HTML ; CHARSET=utf-8', HTML),
                        ('application/json', JSON), ('application/json;charset=utf-8', JSON),
                        ('text/xml', XML), ('application/xml', XML), ('image/png', png()), ('image/gif', GIF),
                        ('application/octet-stream', bytes(range(40))), ('text/plain', b'plain text'),
                        ('application/x-www-form-urlencoded', b'a=1&b=%41%42&c=hello+world'),
                        ('application/x-unknown-type', b'some unknown payload'),
                        ('multipart/unknown; boundary=XX', b'--XX\r\nContent-Type: text/plain\r\n\r\nfirst\r\n--XX--\r\n'),
                        ('message/http', b'GET /inner HTTP/1.1\r\nHost: inner.example.com\r\n\r\n'),
                        ('text/css', b'body { color: red; }'), ('application/javascript', b'var a = 1;'),
                        ('text/html;', HTML), ('text/html;  ', HTML)):
        exch(f, req('GET', '/ct/' + ctype.split(';')[0].replace('/', '_')),
             resp(200, 'OK', [('Content-Type', ctype)], body))
    # multipart/form-data upload request
    bd = (b'--B0undary\r\nContent-Disposition: form-data; name="field1"\r\n\r\nvalue1\r\n'
          b'--B0undary\r\nContent-Disposition: form-data; name="file"; filename="a.txt"\r\nContent-Type: text/plain\r\n\r\n'
          b'file contents\r\n--B0undary--\r\n')
    exch(f, req('POST', '/upload', [('Content-Type', 'multipart/form-data; boundary=B0undary')], bd),
         resp(200, 'OK', [('Content-Length', '0')]))
    exch(f, req('POST', '/json', [('Content-Type', 'application/json')], JSON),
         resp(200, 'OK', [('Content-Type', 'application/json')], JSON))
    exch(f, req('POST', '/form', [('Content-Type', 'application/x-www-form-urlencoded')], b'user=test&q=a%20b'),
         resp(200, 'OK', [('Content-Type', 'text/html')], HTML))
    # body without Content-Type: data
    exch(f, req('PUT', '/nct', body=b'raw body without type'), resp(200, 'OK', [('Content-Length', '0')]))
    f.fin()


def tls_hello(server=False):
    """Plain TLS handshake messages (no key material is used)."""
    ext = struct.pack('!HH', 0, 0)
    if not server:
        body = struct.pack('!H', 0x0303) + bytes(range(32)) + b'\0' + struct.pack('!H', 4) + \
            struct.pack('!HH', 0x009c, 0x00ff) + b'\x01\0' + struct.pack('!H', len(ext)) + ext
        hs = b'\x01' + struct.pack('!I', len(body))[1:] + body
    else:
        body = struct.pack('!H', 0x0303) + bytes(range(32, 64)) + b'\0' + struct.pack('!HB', 0x009c, 0) + \
            struct.pack('!H', len(ext)) + ext
        hs = b'\x02' + struct.pack('!I', len(body))[1:] + body
    return b'\x16\x03\x03' + struct.pack('!H', len(hs)) + hs


def build_ranges(cap):
    mark(cap, 'Range requests and Content-Range responses')
    f = new_flow(cap, 41010)
    host = 'files.example.com'
    # three outstanding range requests, answered out of order and with a lost response
    f.c(req('GET', '/big.bin', [('Range', 'bytes=100-199')], host=host), dt=2000)
    f.c(req('GET', '/big.bin', [('Range', 'bytes=200-299')], host=host), dt=2000)
    f.c(req('GET', '/big.bin', [('Range', 'bytes=-500')], host=host), dt=2000)
    f.c(req('GET', '/big.bin', [('Range', 'bytes=0-')], host=host), dt=2000)
    f.c(req('GET', '/big.bin', [('Range', 'bytes 5-9')], host=host), dt=2000)
    f.c(req('GET', '/big.bin', [('Range', 'bytes=-')], host=host), dt=2000)
    f.s(resp(206, 'Partial Content', [('Content-Range', 'bytes 200-299/1000'), ('Content-Type', 'application/octet-stream')],
             bytes(100)), dt=20000)
    f.s(resp(206, 'Partial Content', [('Content-Range', 'bytes 100-199/1000'), ('Content-Type', 'application/octet-stream')],
             bytes(100)), dt=20000)
    f.s(resp(206, 'Partial Content', [('Content-Range', 'bytes 500-999/1000'), ('Content-Type', 'application/octet-stream')],
             bytes(500)), dt=20000)
    f.s(resp(206, 'Partial Content', [('Content-Range', 'bytes */1000'), ('Content-Length', '0')]), dt=20000)
    f.s(resp(206, 'Partial Content', [('Content-Range', 'bytes0-9/1000'), ('Content-Length', '0')]), dt=20000)
    f.s(resp(206, 'Partial Content', [('Content-Range', 'bytes 0-9/1000'), ('Content-Length', '0')]), dt=20000)
    f.s(resp(416, 'Range Not Satisfiable', [('Content-Range', 'bytes */1000'), ('Content-Length', '0')]), dt=20000)
    # a request with a range and without a response before the next request
    exch(f, req('GET', '/other.bin', [('Range', 'bytes=7-')], host=host),
         resp(206, 'Partial Content', [('Content-Range', 'bytes 7-9/10'), ('Content-Length', '3')], b'abc'))
    # a plain request/response pair after the ranges
    exch(f, req('GET', '/plain', host=host), resp(200, 'OK', [('Content-Length', '2')], b'ok'))
    f.fin()


def build_proxy(cap):
    mark(cap, 'CONNECT proxying, SSTP, nested tunnels')
    # CONNECT to a TLS port: the tunnel carries plain TLS handshake messages
    f = new_flow(cap, 41020, 3128)
    exch(f, req('CONNECT', 'secure.example.com:443', [('Proxy-Connection', 'keep-alive')], host='secure.example.com:443'),
         resp(200, 'Connection established', [('Proxy-agent', 'TestProxy/1.0')], cl=False))
    f.c(tls_hello(False), dt=5000)
    f.s(tls_hello(True), dt=20000)
    f.fin()
    # a 407 first, then the successful CONNECT, with HTTP inside the tunnel
    f = new_flow(cap, 41021, 3128)
    exch(f, req('CONNECT', 'inner.example.com:80', host='inner.example.com:80'),
         resp(407, 'Proxy Authentication Required', [('Proxy-Authenticate', 'Basic realm="proxy"'), ('Content-Length', '0')]))
    exch(f, req('CONNECT', 'inner.example.com:80', [('Proxy-Authorization', 'Basic ' + b64(b'user:placeholder'))],
                host='inner.example.com:80'),
         resp(200, 'Connection established', cl=False))
    exch(f, req('GET', '/inside/tunnel', host='inner.example.com'),
         resp(200, 'OK', [('Content-Type', 'text/plain'), ('Content-Length', '6')], b'inner\n'))
    exch(f, req('GET', '/inside/tunnel2', host='inner.example.com'),
         resp(200, 'OK', [('Content-Length', '0')]))
    f.fin()
    # CONNECT to a port that is not known: data; and one without a port
    f = new_flow(cap, 41022, 3128)
    exch(f, req('CONNECT', 'unknown.example.com:9999', host='unknown.example.com:9999'),
         resp(200, 'OK', cl=False))
    f.c(b'\x00\x01\x02\x03 opaque data', dt=5000)
    f.s(b'\x04\x05\x06 reply', dt=5000)
    f.fin()
    f = new_flow(cap, 41023, 3128)
    exch(f, req('CONNECT', 'noport.example.com', host='noport.example.com'), resp(200, 'OK', cl=False))
    f.c(b'\x00opaque', dt=5000)
    f.fin()
    # nested CONNECT: the tunnel carries HTTP with another CONNECT
    f = new_flow(cap, 41024, 3128)
    exch(f, req('CONNECT', 'outer.example.com:80', host='outer.example.com:80'), resp(200, 'OK', cl=False))
    exch(f, req('CONNECT', 'next.example.com:8080', host='next.example.com:8080'), resp(200, 'OK', cl=False))
    f.c(b'\x00data in the nested tunnel', dt=5000)
    f.s(b'\x00reply in the nested tunnel', dt=5000)
    f.fin()
    # CONNECT whose 200 response has a body length (ignored) and a 3xx failure
    f = new_flow(cap, 41025, 3128)
    exch(f, req('CONNECT', 'gone.example.com:443', host='gone.example.com:443'),
         resp(403, 'Forbidden', [('Content-Length', '0')]))
    f.fin()

    # SSTP: SSTP_DUPLEX_POST, the 200 response and an SSTP Call Connect Request
    f = new_flow(cap, 41026, 8080)
    exch(f, req('SSTP_DUPLEX_POST', '/sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/',
                [('SSTPCORRELATIONID', '{00000000-0000-0000-0000-000000000000}'),
                 ('Content-Length', '18446744073709551615')], host='vpn.example.com'),
         resp(200, 'OK', [('Content-Length', '18446744073709551615'), ('Server', 'Microsoft-HTTPAPI/2.0')], cl=False))
    sstp = struct.pack('!BBH', 0x10, 1, 14) + struct.pack('!HH', 1, 1) + struct.pack('!BBHH', 0, 1, 6, 1)
    f.c(sstp, dt=5000)
    f.fin()


def ws_frame(opcode, payload, mask=None, fin=True):
    b0 = (0x80 if fin else 0) | opcode
    n = len(payload)
    if n < 126:
        h = bytes([b0, (0x80 if mask else 0) | n])
    else:
        h = bytes([b0, (0x80 if mask else 0) | 126]) + struct.pack('!H', n)
    if mask:
        return h + mask + bytes(c ^ mask[i % 4] for i, c in enumerate(payload))
    return h + payload


def build_upgrade(cap):
    mark(cap, 'Upgrade: WebSocket, h2c, TLS and unknown protocols')
    # WebSocket (RFC 6455 example nonce and accept value)
    f = new_flow(cap, 41030, 8080)
    exch(f, req('GET', '/chat', [('Upgrade', 'websocket'), ('Connection', 'Upgrade'),
                                 ('Sec-WebSocket-Key', 'dGhlIHNhbXBsZSBub25jZQ=='),
                                 ('Sec-WebSocket-Version', '13'), ('Sec-WebSocket-Protocol', 'chat, superchat'),
                                 ('Sec-WebSocket-Extensions', 'permessage-deflate; client_max_window_bits'),
                                 ('Origin', 'http://www.example.com')], host='ws.example.com'),
         resp(101, 'Switching Protocols', [('Upgrade', 'websocket'), ('Connection', 'Upgrade'),
                                           ('Sec-WebSocket-Accept', 's3pPLMBiTxaQ9kYGzzhZRbK+xOo='),
                                           ('Sec-WebSocket-Protocol', 'chat')], cl=False))
    f.c(ws_frame(1, b'hello server', mask=b'abcd'), dt=5000)
    f.s(ws_frame(1, b'hello client'), dt=5000)
    f.c(ws_frame(9, b'ping', mask=b'wxyz'), dt=5000)
    f.s(ws_frame(10, b'ping'), dt=5000)
    f.c(ws_frame(2, bytes(range(20)), mask=b'\x01\x02\x03\x04'), dt=5000)
    f.s(ws_frame(8, struct.pack('!H', 1000) + b'bye'), dt=5000)
    f.fin()
    # h2c upgrade with the HTTP2-Settings header; settings 3 = 100 and 4 = 65535
    settings = struct.pack('!HI', 3, 100) + struct.pack('!HI', 4, 65535) + struct.pack('!HI', 2, 0)
    f = new_flow(cap, 41031, 80)
    exch(f, req('GET', '/h2c', [('Connection', 'Upgrade, HTTP2-Settings'), ('Upgrade', 'h2c'),
                                ('HTTP2-Settings', b64u(settings))]),
         resp(101, 'Switching Protocols', [('Connection', 'Upgrade'), ('Upgrade', 'h2c')], cl=False))
    f.c(b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n' + struct.pack('!BHBBI', 0, 0, 4, 0, 0)[0:0] +
        b'\x00\x00\x00\x04\x00\x00\x00\x00\x00', dt=5000)
    f.s(b'\x00\x00\x06\x04\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x64', dt=5000)
    f.fin()
    # TLS upgrade (RFC 2817) and an upgrade to a protocol nobody knows
    f = new_flow(cap, 41033, 80)
    exch(f, req('OPTIONS', '*', [('Upgrade', 'TLS/1.0'), ('Connection', 'Upgrade')]),
         resp(101, 'Switching Protocols', [('Upgrade', 'TLS/1.0, HTTP/1.1'), ('Connection', 'Upgrade')], cl=False))
    f.c(tls_hello(False), dt=5000)
    f.s(tls_hello(True), dt=5000)
    f.fin()
    f = new_flow(cap, 41034, 80)
    exch(f, req('GET', '/up', [('Upgrade', 'x-custom-proto'), ('Connection', 'Upgrade')]),
         resp(101, 'Switching Protocols', [('Upgrade', 'X-Custom-Proto'), ('Connection', 'Upgrade')], cl=False))
    f.c(b'\x00\x01 custom protocol data', dt=5000)
    f.s(b'\x00\x02 custom reply', dt=5000)
    f.fin()

    # HTTP/2 prior knowledge on an HTTP port: the client preface is recognised and the stream is HTTP/2
    f = new_flow(cap, 41036, 8080)
    f.c(b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n' + b'\x00\x00\x06\x04\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x64', dt=2000)
    f.s(b'\x00\x00\x00\x04\x00\x00\x00\x00\x00', dt=2000)
    f.c(b'\x00\x00\x00\x04\x01\x00\x00\x00\x00', dt=2000)
    f.s(b'\x00\x00\x00\x04\x01\x00\x00\x00\x00', dt=2000)
    f.fin()
    # 101 response followed in the same segment by a part of an HTTP/2 frame (reassembly asked for by h2)
    f = new_flow(cap, 41037, 80)
    f.c(req('GET', '/h2c-partial', [('Connection', 'Upgrade, HTTP2-Settings'), ('Upgrade', 'h2c'),
                                    ('HTTP2-Settings', b64u(struct.pack('!HI', 3, 100)))]), dt=2000)
    f.s(resp(101, 'Switching Protocols', [('Connection', 'Upgrade'), ('Upgrade', 'h2c')], cl=False) +
        b'\x00\x00\x0c\x04\x00\x00\x00\x00\x00\x00\x03\x00\x00', dt=20000)
    f.s(b'\x00\x64\x00\x04\x00\x00\xff\xff', dt=2000)
    f.fin()
    # an Upgrade header that the server does not accept: a normal response follows
    f = new_flow(cap, 41035, 80)
    exch(f, req('GET', '/noup', [('Upgrade', 'websocket'), ('Connection', 'Upgrade')]),
         resp(200, 'OK', [('Content-Length', '2')], b'ok'))
    exch(f, req('GET', '/after'), resp(200, 'OK', [('Content-Length', '2')], b'ok'))
    f.fin()


def build_alt(cap):
    mark(cap, 'other transports: heuristic port, IPv6, SCTP, SSDP')
    # port 8888 is not an HTTP port: the TCP heuristic finds the HTTP request line
    f = new_flow(cap, 41040, 8888)
    exch(f, req('GET', '/heur'), resp(200, 'OK', [('Content-Type', 'text/plain'), ('Content-Length', '5')], b'heur\n'))
    exch(f, req('POST', '/heur2', body=b'abc'), resp(201, 'Created', [('Content-Length', '0')]))
    f.fin()
    # a flow that starts with a response (no request seen)
    f = new_flow(cap, 41041, 8889)
    f.s(resp(200, 'OK', [('Content-Length', '4')], b'lone'), dt=5000)
    f.fin()
    # IPv6
    f = new_flow(cap, 41042, 80, v6=True)
    exch(f, req('GET', '/v6', host='[2001:db8::2]'), resp(200, 'OK', [('Content-Type', 'text/html')], HTML))
    f.fin()
    # SSDP over UDP 1900 (IPv4 and IPv6)
    udp(cap, 50000, 1900, req('M-SEARCH', '*', [('ST', 'ssdp:all'), ('MAN', '"ssdp:discover"'), ('MX', '2')],
                              host='239.255.255.250:1900'), sip='239.255.255.250')
    udp(cap, 1900, 50000, resp(200, 'OK', [('CACHE-CONTROL', 'max-age=1800'), ('ST', 'upnp:rootdevice'),
                                           ('LOCATION', 'http://192.0.2.2:5000/desc.xml'),
                                           ('SERVER', 'Linux UPnP/1.0 Test/1.0'), ('USN', 'uuid:0000::upnp:rootdevice')]),
        d=1)
    udp(cap, 50001, 1900, req('NOTIFY', '*', [('NT', 'upnp:rootdevice'), ('NTS', 'ssdp:alive'),
                                              ('LOCATION', 'http://192.0.2.2:5000/desc.xml')], host='239.255.255.250:1900'))
    udp(cap, 50002, 1900, req('M-SEARCH', '*', [('ST', 'ssdp:all')], host='[ff02::c]:1900'), v6=True)
    # SSDP with a body and a text line that is not HTTP
    udp(cap, 50003, 1900, req('NOTIFY', '*', [('NT', 'upnp:rootdevice')], b'ignored body', host='239.255.255.250:1900'))
    # HTTP over SCTP (port 80)
    sctp_data(cap, 40001, 80, 1, 0, req('GET', '/sctp'))
    sctp_data(cap, 80, 40001, 1, 0, resp(200, 'OK', [('Content-Type', 'text/plain'), ('Content-Length', '5')], b'sctp\n'), d=1)


def grpc_msg(payload=b'\x0a\x05hello', flag=0):
    return struct.pack('!BI', flag, len(payload)) + payload


def build_stream(cap):
    mark(cap, 'chunked streaming (gRPC-Web) in streaming chunk mode')
    f = new_flow(cap, 41050, 8080)
    h = req('POST', '/pkg.Service/Method', [('Content-Type', 'application/grpc-web'), ('X-Grpc-Web', '1'),
                                          ('Content-Encoding', 'identity'), ('Upgrade', 'h2c'),
                                          ('Transfer-Encoding', 'chunked')], cl=False, host='grpc.example.com')
    m1, m2, m3 = grpc_msg(b'\x0a\x03one'), grpc_msg(b'\x0a\x03two'), grpc_msg(b'\x0a\x0bthree-three')
    c = lambda d: b'%x\r\n' % len(d) + d + b'\r\n'
    f.c(h + c(m1), dt=2000)
    f.c(c(m2), dt=2000)
    part = c(m3)
    f.c(part[:9], dt=2000)
    f.c(part[9:] + b'0\r\n\r\n', dt=2000)
    rh = resp(200, 'OK', [('Content-Type', 'application/grpc-web+proto'), ('Transfer-Encoding', 'chunked')], cl=False)
    trailer = grpc_msg(b'grpc-status: 0\r\ngrpc-message: OK\r\n', flag=0x80)
    f.s(rh + c(grpc_msg(b'\x0a\x05reply')), dt=20000)
    f.s(c(trailer) + b'0\r\n\r\n', dt=5000)
    # a second message on the same connection: still streaming mode
    f.c(h + c(m1) + c(m2) + b'0\r\n\r\n', dt=2000)
    f.s(rh + c(grpc_msg(b'\x0a\x05again')) + c(trailer) + b'0\r\n\r\n', dt=20000)
    # a non-streaming request in between
    exch(f, req('GET', '/plain', host='grpc.example.com'), resp(200, 'OK', [('Content-Length', '2')], b'ok'))
    f.fin()
    # grpc-web-text with base64 bodies
    f = new_flow(cap, 41051, 8080)
    exch(f, req('POST', '/pkg.Service/Text', [('Content-Type', 'application/grpc-web-text'),
                                             ('Transfer-Encoding', 'chunked')], cl=False,
                body=chunked([b64(m1).encode()])),
         resp(200, 'OK', [('Content-Type', 'application/grpc-web-text+proto'), ('Transfer-Encoding', 'chunked')], cl=False,
              body=chunked([b64(grpc_msg(b'\x0a\x02ok')).encode()])))
    f.fin()


def build_seq(cap):
    mark(cap, 'redirect and referer sequences (http_seq statistics)')
    f = new_flow(cap, 41060)
    R = lambda code, loc: resp(code, 'Redirect', [('Location', loc), ('Content-Length', '0')])
    step = [
        ('/start', None, R(302, '/next')),
        ('/next', 'http://seq.example.com/start', R(301, 'http://other.example.org/landing')),
        ('/page?x=1', 'http://seq.example.com/next', R(302, '?y=2')),
        ('/page?y=2', 'http://seq.example.com/page?x=1', R(302, 'rel/path.html')),
        ('/dir/page.html', 'http://seq.example.com/page?y=2', R(302, '//cdn.example.net/asset.js')),
        ('/dir/other.html', 'http://seq.example.com/dir/page.html', R(302, '')),
        ('/dir/last.html', 'http://seq.example.com/dir/other.html', R(302, '/abs/only')),
        ('/loop', 'http://seq.example.com/loop', R(302, '/loop')),
        ('/self', 'http://seq.example.com/self', resp(200, 'OK', [('Content-Length', '0')])),
        ('/other-ref', 'http://seq.example.com/start', resp(200, 'OK', [('Content-Length', '0')])),
    ]
    for uri, ref, response in step:
        hs = [('Referer', ref)] if ref else []
        exch(f, req('GET', uri, hs, host='seq.example.com'), response)
    # chain of referers deeper than the 64 levels the statistics follow
    prev = 'http://seq.example.com/start'
    for i in range(70):
        uri = '/chain/%d' % i
        exch(f, req('GET', uri, [('Referer', prev)], host='seq.example.com'), resp(200, 'OK', [('Content-Length', '0')]),
             dt2=1000)
        prev = 'http://seq.example.com' + uri
    # redirect with an absolute-URI request that has no path, and a relative Location
    exch(f, req('GET', 'http://nopath.example.com', host='nopath.example.com'), R(302, '/x'))
    exch(f, req('GET', '/ftp', host='seq.example.com'), R(302, 'ftp://ftp.example.com/file'))
    f.fin()


def build_auth(cap):
    mark(cap, 'authorization headers (placeholder values)')
    f = new_flow(cap, 41070)
    ntlm1 = (b'NTLMSSP\0' + struct.pack('<II', 1, 0x00088207) + struct.pack('<HHI', 0, 0, 0) * 2 +
             struct.pack('<Q', 0))
    ntlm2 = (b'NTLMSSP\0' + struct.pack('<IHHII', 2, 0, 0, 40, 0x00088207) + bytes(8) + bytes(8) +
             struct.pack('<HHI', 0, 0, 40))
    cases = [
        ('Authorization', 'Basic ' + b64(b'user:placeholder')),
        ('Authorization', 'Basic ' + b64(b'nocolon')),
        ('Proxy-Authorization', 'Basic ' + b64(b'proxyuser:placeholder')),
        ('Authorization', 'Digest username="user", realm="test", nonce="0000000000000000", uri="/", '
                          'response="00000000000000000000000000000000", opaque="0000"'),
        ('Authorization', 'Digest'),
        ('Authorization', 'NTLM ' + b64(ntlm1)),
        ('Authorization', 'Negotiate ' + b64(ntlm1)),
        ('Authorization', 'Bearer placeholder-token'),
        ('Authorization', 'CitrixAGBasic username="%s"; domain="%s"; password="%s"; AGESessionId="%s"' % (
            b64(b'user'), b64(b'DOMAIN'), b64(b'placeholder'), b64(b'session1'))),
        ('Authorization', 'CitrixAGBasic username=""; domain=""; password=""; AGESessionId=""'),
        ('Authorization', 'CitrixAGBasic username="%s"; domain="%s"' % (b64(b'only'), b64(b'DOM'))),
        ('Authorization', 'CitrixAGBasic username="unterminated'),
        ('Authorization', 'CitrixAGBasic '),
        ('Authorization', 'Kerberos'),
    ]
    for name, value in cases:
        exch(f, req('GET', '/auth', [(name, value)], host='auth.example.com'), resp(200, 'OK', [('Content-Length', '0')]))
    for name, value in (('WWW-Authenticate', 'Basic realm="test"'), ('WWW-Authenticate', 'NTLM ' + b64(ntlm2)),
                        ('WWW-Authenticate', 'Negotiate ' + b64(ntlm2)), ('WWW-Authenticate', 'Negotiate'),
                        ('Proxy-Authenticate', 'Digest realm="test", nonce="0000"'),
                        ('WWW-Authenticate', 'Kerberos')):
        exch(f, req('GET', '/auth2', host='auth.example.com'),
             resp(401, 'Unauthorized', [(name, value), ('Content-Length', '0')]))
    f.fin()


def build_warn(cap):
    mark(cap, 'WARN: expert infos (warnings), repro frames of the streaming and pipeline fixes')
    f = new_flow(cap, 41080)
    ct = ('Content-Type', 'text/plain')
    # Transfer-Encoding and Content-Length together
    exch(f, req('POST', '/w1', [('Content-Length', '3'), ('Transfer-Encoding', 'chunked')], cl=False, body=chunked([b'abc'])),
         resp(200, 'OK', [('Transfer-Encoding', 'chunked'), ('Content-Length', '3')], cl=False, body=chunked([b'xyz'])))
    # excess data after a body, in the same segment
    exch(f, req('GET', '/w4'), resp(200, 'OK', [('Content-Length', '3')], b'abcTRAILING GARBAGE WITHOUT HTTP\r\n'))
    # bad header names, trailing whitespace before the colon, NUL in a value
    exch(f, req('GET', '/w5', ['Bad Header: value', 'Content-Length : 0', '(brackets): x', 'X-Nul: ab\x00cd',
                               'Tab\tName: v', 'X-Good: ok']),
         resp(200, 'OK', ['X-Resp NUL: a\x00b', 'Bad Resp Header: 1', 'Content-Length: 0']))
    exch(f, req('GET', '/w5b', [(': empty name'), 'Na\x00me: nul in name', 'User-Agent: nul\x00in value', 'Host: h\x00ost',
                                'Content-Type: text/plain\x00']),
         resp(200, 'OK', [('Content-Length', '0')]))
    # request target with spaces and a tab
    exch(f, req('GET', '/path with spaces', ), resp(200, 'OK', [('Content-Length', '0')]))
    exch(f, req('GET', '/tab\tin\tpath'), resp(200, 'OK', [('Content-Length', '0')]))
    exch(f, req('GET', ''), resp(200, 'OK', [('Content-Length', '0')]))
    # invalid status codes
    for line in ('HTTP/1.1 2000 Too long', 'HTTP/1.1 abc Not a number', 'HTTP/1.1 20 Short', 'HTTP/1.1 2x0 Mixed',
                 'HTTP/1.1', 'HTTP/1.1 ', 'HTTP/1.1  200 two spaces', 'HTTP/1.1 200'):
        exch(f, req('GET', '/w6'), line.encode() + b'\r\nContent-Length: 0\r\n\r\n')
    # a body type that its dissector refuses
    exch(f, req('GET', '/w7'), resp(200, 'OK', [('Content-Type', 'application/json')], b'this is not json at all'))
    exch(f, req('GET', '/w8'), resp(200, 'OK', [('Content-Type', 'image/png')], b'not a png'))
    exch(f, req('GET', '/w9'), resp(200, 'OK', [('Content-Type', 'text/xml')], b'not xml'))
    # content encodings that fail or are not supported
    exch(f, req('GET', '/w10'), resp(200, 'OK', [ct, ('Content-Encoding', 'compress')], b'\x1f\x9d\x90abc'))
    exch(f, req('GET', '/w11'), resp(200, 'OK', [ct, ('Content-Encoding', 'gzip')], b'this is not gzip data'))
    exch(f, req('GET', '/w12'), resp(200, 'OK', [ct, ('Content-Encoding', 'snappy')], b'\x05\x10hello'))
    exch(f, req('GET', '/w13'), resp(200, 'OK', [ct, ('Content-Encoding', 'xpress')], b'\x00\x00'))
    exch(f, req('GET', '/w14'), resp(200, 'OK', [ct, ('Content-Encoding', 'xpress')],
                                     struct.pack('<II', 10, 0) + b'0123456789'))
    exch(f, req('GET', '/w15'), resp(200, 'OK', [ct, ('Content-Encoding', 'xpress')],
                                     struct.pack('<II', 10, 100000) + b'0123456789'))
    exch(f, req('GET', '/w16'), resp(200, 'OK', [ct, ('Content-Encoding', 'xpress')],
                                     struct.pack('<II', 10, 60) + b'0123456789'))
    exch(f, req('GET', '/w17'), resp(200, 'OK', [ct, ('Content-Encoding', 'br')], b'not brotli'))
    exch(f, req('GET', '/w18'), resp(200, 'OK', [ct, ('Content-Encoding', 'zstd')], b'not zstd data'))
    exch(f, req('GET', '/w19'), resp(200, 'OK', [ct, ('Content-Encoding', 'unknown-coding')], b'data'))
    # two xpress blocks: the second one fails after the first one worked
    blk = xpress_literal(b'first block')
    exch(f, req('GET', '/w20'), resp(200, 'OK', [ct, ('Content-Encoding', 'xpress')],
                                     blk + struct.pack('<II', 10, 3) + b'\x00\x00\x00'))
    f.fin()
    # plain HTTP on the TLS port
    f = new_flow(cap, 41081, 443)
    exch(f, req('GET', '/tls-port'), resp(200, 'OK', [('Content-Length', '2')], b'ok'))
    f.fin()
    # reproducers of "HTTP: Do not assert on Content-Length in streaming chunk mode"
    mark(cap, 'WARN: reproducers of the streaming chunk mode fix')
    # Content-Length together with chunked and a streaming content type
    f = new_flow(cap, 41082, 80)
    f.c(b"POST /svc/M HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n"
        b"Content-Type: application/grpc-web\r\nContent-Length: 5\r\n\r\n"
        b"5\r\n\x00\x00\x00\x00\x00\r\n0\r\n\r\n")
    f.fin()
    # two requests in one segment, the second one in streaming mode (both orders)
    plain = b"POST /a HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\nhi"
    stream = (b"POST /svc/M HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n"
              b"Content-Type: application/grpc-web\r\n\r\n"
              b"5\r\n\x00\x00\x00\x00\x00\r\n0\r\n\r\n")
    for port, payload in ((41083, plain + stream), (41084, stream + plain)):
        f = new_flow(cap, port, 80)
        f.c(payload)
        f.fin()
    # pipelined responses in one segment (the request of each is only known on the later passes)
    mark(cap, 'WARN: pipelined responses in one segment')
    f = new_flow(cap, 41085)
    f.c(req('GET', '/pl1') + req('GET', '/pl2'), dt=2000)
    f.s(resp(200, 'OK', [('Content-Length', '0')]) + resp(200, 'OK', [('Content-Length', '2')], b'hi'), dt=20000)
    f.fin()


def build_misc(cap):
    mark(cap, 'media types handled by other dissectors, ranges of ports, continuation data')
    f = new_flow(cap, 41090, 631)
    exch(f, req('POST', '/ipp/print', [('Content-Type', 'application/ipp')], b'\x01\x01\x00\x0b\x00\x00\x00\x01\x03',
                host='printer.example.com:631'),
         resp(200, 'OK', [('Content-Type', 'application/ipp')], b'\x01\x01\x00\x00\x00\x00\x00\x01\x03'))
    f.fin()
    # a request with an unknown method is not HTTP: nothing is dissected as HTTP
    f = new_flow(cap, 41091, 80)
    f.c(b'FROB / HTTP/1.1\r\nHost: x\r\n\r\n', dt=2000)
    f.s(b'garbage reply\r\n', dt=2000)
    f.fin()
    # JSON and XML found by the heuristic subdissectors only with preferences; here by Content-Type
    f = new_flow(cap, 41092, 80)
    exch(f, req('POST', '/rpc', [('Content-Type', 'application/json-rpc')],
                b'{"jsonrpc": "2.0", "method": "ping", "id": 1}'),
         resp(200, 'OK', [('Content-Type', 'application/json-rpc')], b'{"jsonrpc": "2.0", "result": "pong", "id": 1}'))
    f.fin()

    # a request after the gap flow: the conversation knows HTTP and the continuation has excess data
    f = new_flow(cap, 41094, 80)
    exch(f, req('GET', '/gap2'), resp(200, 'OK', [('Content-Length', '3')], b'abc'))
    f.ep[1][2] += 2000
    f.s(b'\x00\x01\x02 binary after a gap', dt=1000)
    f.c(req('GET', '/gap3'), dt=1000)
    f.s(resp(200, 'OK', [('Content-Length', '2')], b'ok'), dt=1000)
    f.fin()
    # Content-Type message/http without a final line ending
    f = new_flow(cap, 41095, 80)
    exch(f, req('GET', '/mh'), resp(200, 'OK', [('Content-Type', 'message/http')], b'HTTP/1.1 200 OK\r\nX-Inner: 1\r\n\r\nbody without end'))
    f.fin()
    # data on an unregistered port that the HTTP heuristic rejects
    f = new_flow(cap, 41096, 8890)
    f.c(b'hello world\r\n', dt=2000)
    f.s(b'12345678\r\n', dt=2000)
    f.c(b'no line ending at all', dt=2000)
    f.s(b'\x00\x01 binary', dt=2000)
    f.fin()


def build_malformed(cap):
    mark(cap, 'malformed: leading CRLF, bad CONNECT ports, nested CONNECT to the same target')
    f = new_flow(cap, 42000)
    exch(f, b'\r\n' + req('GET', '/leading-crlf'), resp(200, 'OK', [('Content-Length', '0')]))
    exch(f, b'\r\n' + req('GET', '/leading-crlf2'), resp(200, 'OK', [('Content-Length', '0')]))
    f.c(b'\r\n\r\n', dt=1000)
    f.fin()
    for i, tgt in enumerate(('badport.example.com:abc', 'bigport.example.com:99999999999', 'neg.example.com:-1')):
        f = new_flow(cap, 42001 + i, 3128)
        exch(f, req('CONNECT', tgt, host=tgt), resp(200, 'OK', cl=False))
        f.c(b'\x00tunnel data', dt=1000)
        f.s(b'\x00tunnel reply', dt=1000)
        f.fin()
    # a CONNECT inside the tunnel to the same target: the guard in http_payload_subdissector looks
    # up another conversation than the one decode_tcp_ports uses and the dissection recurses
    f = new_flow(cap, 42010, 3128)
    exch(f, req('CONNECT', 'outer.example.com:80', host='outer.example.com:80'), resp(200, 'OK', cl=False))
    exch(f, req('CONNECT', 'outer.example.com:80', host='outer.example.com:80'), resp(200, 'OK', cl=False))
    f.c(b'\x00data in the nested tunnel', dt=1000)
    f.s(b'\x00reply in the nested tunnel', dt=1000)
    f.fin()
    mark(cap, 'malformed: HTTP2-Settings, Kerberos and Negotiate placeholders')
    settings = struct.pack('!HI', 3, 100) + struct.pack('!HI', 4, 65535)
    f = new_flow(cap, 42020)
    exch(f, req('GET', '/h2c-short', [('Connection', 'Upgrade, HTTP2-Settings'), ('Upgrade', 'h2c'),
                                      ('HTTP2-Settings', b64u(settings[:4]))]),
         resp(200, 'OK', [('Content-Length', '0')]))
    exch(f, req('GET', '/h2c-empty', [('HTTP2-Settings', '')]), resp(200, 'OK', [('Content-Length', '0')]))
    # Kerberos / Negotiate tokens that are constant placeholder bytes, not real tickets
    ph = b64(bytes(24))
    for name, value in (('Authorization', 'Kerberos ' + ph), ('Authorization', 'Negotiate ' + ph),
                        ('Authorization', 'NTLM ' + ph), ('Authorization', 'Kerberos ')):
        exch(f, req('GET', '/krb', [(name, value)], host='auth.example.com'), resp(200, 'OK', [('Content-Length', '0')]))
    for name, value in (('WWW-Authenticate', 'Kerberos ' + ph), ('WWW-Authenticate', 'Negotiate ' + ph),
                        ('WWW-Authenticate', 'NTLM ' + ph)):
        exch(f, req('GET', '/krb2', host='auth.example.com'), resp(401, 'Unauthorized', [(name, value), ('Content-Length', '0')]))
    f.fin()
    mark(cap, 'malformed: cut by the snap length and incomplete messages')
    f = new_flow(cap, 42030)
    big = bytes(range(256)) * 4
    h = req('POST', '/cut1', [('Content-Type', 'application/octet-stream')], big)
    f.c(h, snap=200, dt=1000)                                    # body cut by the snap length
    f.s(resp(200, 'OK', [('Content-Type', 'text/plain'), ('Content-Length', '40')], b'x' * 40), snap=90, dt=1000)
    f.c(req('POST', '/cut2', [('Transfer-Encoding', 'chunked')], cl=False, body=chunked([b'y' * 100, b'z' * 100])),
        snap=130, dt=1000)
    f.s(resp(200, 'OK', [('Transfer-Encoding', 'chunked'), ('Content-Type', 'text/plain')], cl=False,
             body=chunked([b'y' * 100, b'z' * 100])), snap=150, dt=1000)
    f.c(req('GET', '/cut3', [('User-Agent', 'x' * 100)]), snap=60, dt=1000)      # header line cut
    f.s(resp(200, 'OK', [('Content-Encoding', 'gzip'), ('Content-Length', '60')], gzip_bytes(b'q' * 100)[:60]), snap=110,
        dt=1000)
    f.c(req('GET', '/cut4', [('Referer', 'http://x/' + 'r' * 80)]), snap=30, dt=1000)  # request line cut
    f.fin()
    mark(cap, 'malformed: incomplete headers and bodies at the end of the stream')
    f = new_flow(cap, 42031)
    f.c(b'GET /noend HTTP/1.1\r\nHost: x', dt=1000)
    f.c(b'\r\nX-Late: 1', dt=1000, flags=0x19)
    f.ack(1)
    f = new_flow(cap, 42032)
    f.c(b'GET /noend2 HTTP/1.1\r\nHost: x\r\nlonely line without a colon', dt=1000, flags=0x19)
    f.ack(1)
    f = new_flow(cap, 42033)
    f.c(req('GET', '/chunk-short'), dt=1000)
    f.s(resp(200, 'OK', [('Content-Type', 'text/plain'), ('Transfer-Encoding', 'chunked')], cl=False,
             body=b'100\r\n' + b'a' * 20), dt=1000, flags=0x19)    # chunk larger than the data, FIN on the segment
    f.ack(0)
    f = new_flow(cap, 42034)
    f.c(req('GET', '/chunk-bad'), dt=1000)
    f.s(resp(200, 'OK', [('Transfer-Encoding', 'chunked')], cl=False, body=b'zz\r\nnot hex\r\n0\r\n\r\n'), dt=1000)
    f.s(resp(200, 'OK', [('Transfer-Encoding', 'chunked')], cl=False, body=b'\r\n'), dt=1000)
    f.fin()
    f = new_flow(cap, 42035)
    f.c(req('GET', '/lone-lf'), dt=1000)
    f.s(b'HTTP/1.1 200 OK\nContent-Length: 2\n\nok', dt=1000)      # bare LF line ends
    f.c(b'GET /half HTTP/1.1\r\nHost: x\r\n\r\nGET / HTT', dt=1000)
    f.fin()
    mark(cap, 'malformed: request lines, methods and odd Content-Range values')
    f = new_flow(cap, 42036)
    for line in (b'GET /', b'GET', b'GET  ', b'GET /x HTTP/1.1 trailing words', b'HTTP/1.1 200', b'HTTP/1.1', b'ICY', b'ICY 200',
                 b'M-GET / HTTP/1.1', b'get / HTTP/1.1', b'PROPFIND', b'VERSION-CONTROL /x HTTP/1.1',
                 b'BASELINE-CONTROL', b'SSTP_DUPLEX_POST /x HTTP/1.1', b'MKWORKSPACE /w HTTP/1.1'):
        f.c(line + b'\r\nHost: x\r\n\r\n', dt=1000)
        f.s(b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n', dt=1000)
    f.fin()
    f = new_flow(cap, 42037)
    f.c(req('GET', '/r1', [('Range', 'bytes=99999999999999999999-')]), dt=1000)
    f.c(req('GET', '/r2', [('Range', 'bytes=abc-')]), dt=1000)
    f.s(resp(206, 'Partial', [('Content-Range', 'bytes 99999999999999999999-1/2'), ('Content-Length', '0')]), dt=1000)
    f.s(resp(206, 'Partial', [('Content-Range', 'bytes -5/10'), ('Content-Length', '0')]), dt=1000)
    f.s(resp(206, 'Partial', [('Content-Range', 'bytes 0--/10'), ('Content-Length', '0')]), dt=1000)
    f.s(resp(206, 'Partial', [('Content-Range', ' '), ('Content-Length', '0')]), dt=1000)
    f.fin()
    f = new_flow(cap, 42038)
    f.c(b'\x00\x01\x02 not http at all' * 20, dt=1000)
    f.s(b'\xff' * 50, dt=1000)
    f.fin()


def build_expdu(cap):
    mark(cap, 'Exported PDU entry points of the HTTP dissectors')
    for name in ('http', 'http-over-tcp', 'http-over-tls', 'http-over-sctp'):
        cap.exported_pdu(name, req('GET', '/expdu/' + name, host='expdu.example.com'))
        cap.exported_pdu(name, resp(200, 'OK', [('Content-Type', 'text/plain'), ('Content-Length', '5')], b'expdu'))


def build_tail(cap):
    # frames from here on decode differently in one pass and with -2 (TCP
    # reassembly up to the FIN of a message without a length)
    mark(cap, 'TAIL: messages that run to the end of the stream')
    # TCP stream with a gap: the response body continues in segments that are not reassembled
    f = new_flow(cap, 41093, 80)
    f.c(req('GET', '/gap1'), dt=2000)
    h = resp(200, 'OK', [('Content-Type', 'application/octet-stream'), ('Content-Length', '4000')], bytes(range(256)) * 15 + b'')
    f.s(h[:600], dt=20000)
    f.ep[1][2] += 1500          # segments that were not captured
    f.s(bytes(range(256)) * 2, dt=1000)                       # binary continuation
    f.ep[1][2] += 700
    f.s(b'text continuation of the body, printable\r\n', dt=1000)
    f.ep[1][2] += 300
    f.s(b'more text without a line ending', dt=1000)
    f.fin()
    # ICY response without length: the body runs to the end of the stream
    f = new_flow(cap, 41100)
    exch(f, req('GET', '/s/icy'), b'ICY 200 OK\r\nicy-name: Test Radio\r\nContent-Type: audio/mpeg\r\n\r\n')
    f.s(b'\x80\x01\x02\x03' + bytes(60), dt=50000)
    f.fin()
    # Transfer-Encoding values that are not (only) chunked: one connection each
    gz = gzip_bytes(b'transfer coded body')
    port = 41101
    for te, body in (('x-gzip', gz), ('identity', b'identity coded'), ('compress', b'\x1f\x9d\x90abc'), ('deflate', deflate_bytes(b'x' * 40)),
                     ('x-compress', b'\x1f\x9d\x90abc'), ('gzip, deflate', gz), ('gzip, chunked', chunked([gz])),
                     ('chunked, gzip', chunked([gz])), ('foo, chunked', chunked([b'unk'])),
                     ('gzip, deflate, chunked', chunked([b'two codings'])), ('Chunked', chunked([b'upper case coding name'])),
                     ('GZIP,Chunked', chunked([gz]))):
        f = new_flow(cap, port)
        port += 1
        exch(f, req('GET', '/te/' + te.replace(' ', '').replace(',', '_')),
             resp(200, 'OK', [('Content-Type', 'text/plain'), ('Transfer-Encoding', te)], cl=False, body=body))
        f.fin()
    # no length: data segments follow the headers (text, then binary); the FIN is on the last data segment
    f = new_flow(cap, 41120)
    exch(f, req('GET', '/s/stream'), resp(200, 'OK', [('Content-Type', 'text/plain')], cl=False, body=b'first part\r\n'))
    f.s(b'second part, printable text\r\n', dt=10000)
    f.s(b'\x00\x01\x02 binary part', dt=10000)
    f.s(b'last part', dt=10000, flags=0x19)
    f.ack(0)
    # a response without length to a request: the next request is a continuation of the stream
    f = new_flow(cap, 41121)
    exch(f, req('GET', '/s/nolen1'), resp(200, 'OK', [('Content-Type', 'application/octet-stream')], cl=False, body=bytes(range(100))))
    f.s(bytes(range(100, 200)), dt=1000)
    f.fin()
    # content encoded body without a length
    f = new_flow(cap, 41122)
    exch(f, req('GET', '/s/gz'), resp(200, 'OK', [('Content-Type', 'text/plain'), ('Content-Encoding', 'gzip')],
                                      cl=False, body=gzip_bytes(b'gzip body that runs to the end of the stream')))
    f.fin()


def build_all():
    main = Cap()
    build_main(main)
    build_targets(main)
    build_chunked(main)
    build_bodies(main)
    build_ranges(main)
    build_proxy(main)
    build_upgrade(main)
    build_alt(main)
    build_stream(main)
    build_seq(main)
    build_auth(main)
    build_misc(main)
    build_expdu(main)
    build_warn(main)
    build_tail(main)
    return main


if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('-') else '.'
    main = build_all()
    main.write(os.path.join(out, 'http-coverage.pcapng'))
    mal = Cap()
    build_malformed(mal)
    mal.write(os.path.join(out, 'http-coverage-malformed.pcapng'))
    if VERBOSE:
        for cap, title in ((main, 'main'), (mal, 'malformed')):
            sec = sections[id(cap)]
            print(title)
            for i, (n, name) in enumerate(sec):
                end = sec[i + 1][0] - 1 if i + 1 < len(sec) else cap.n()
                print('  %d-%d %s' % (n, end, name))
            print('  ', cap.n(), 'frames')
