#!/usr/bin/env python3
# Generates test/captures/icap_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Write the ICAP coverage captures (Ethernet, IPv4/IPv6, TCP port 1344).

icap-coverage.pcapng           ICAP OPTIONS, REQMOD and RESPMOD exchanges
icap-coverage-malformed.pcapng cut and odd messages (coverage number only)

Usage: mkicap.py <outdir> [-v]
"""
import os
import sys

from wslib import Cap, Flow  # noqa

sections = {}


def mark(cap, name):
    sections.setdefault(id(cap), []).append((cap.n() + 1, name))


def icap(first, headers=(), body=b''):
    out = first.encode() + b'\r\n'
    for h in headers:
        out += (h if isinstance(h, str) else '%s: %s' % h).encode() + b'\r\n'
    return out + b'\r\n' + body


def chunk(*parts, ieof=False):
    out = b''.join(b'%x\r\n' % len(p) + p + b'\r\n' for p in parts)
    return out + (b'0; ieof\r\n\r\n' if ieof else b'0\r\n\r\n')


HREQ = (b'GET /origin/file.html HTTP/1.1\r\nHost: www.example.com\r\nAccept: */*\r\n'
        b'User-Agent: TestAgent/1.0\r\n\r\n')
HRES = (b'HTTP/1.1 200 OK\r\nDate: Mon, 01 Jan 2024 00:00:00 GMT\r\nServer: TestServer/1.0\r\n'
        b'Content-Type: text/html\r\nTransfer-Encoding: chunked\r\n\r\n')
HTML = b'<html><body>Hello, ICAP</body></html>'
URL = 'icap://icap.example.net/'
ENC = lambda s: ('Encapsulated', s)


def exch(f, a, b, dt=2000):
    f.c(a, dt=dt)
    f.s(b, dt=20000)


def build_main(cap):
    mark(cap, 'OPTIONS exchanges')
    f = Flow(cap, 43000, 1344)
    f.open()
    exch(f, icap('OPTIONS ' + URL + 'reqmod ICAP/1.0', [('Host', 'icap.example.net'), ('User-Agent', 'IcapClient/1.0')]),
         icap('ICAP/1.0 200 OK', [('Date', 'Mon, 01 Jan 2024 00:00:00 GMT'), ('Methods', 'REQMOD'),
                                  ('Service', 'Test ICAP Server 1.0'), ('ISTag', '"TEST-1"'), ('Max-Connections', '100'),
                                  ('Options-TTL', '3600'), ('Allow', '204'), ('Preview', '1024'),
                                  ('Transfer-Complete', 'html'), ENC('null-body=0')]))
    exch(f, icap('OPTIONS ' + URL + 'respmod ICAP/1.0', [('Host', 'icap.example.net')]),
         icap('ICAP/1.0 200 OK', [('Methods', 'RESPMOD'), ('ISTag', '"TEST-2"'), ENC('null-body=0')]))
    exch(f, icap('OPTIONS ' + URL + 'missing ICAP/1.0', [('Host', 'icap.example.net')]),
         icap('ICAP/1.0 404 ICAP Service not found', [('ISTag', '"TEST-1"'), ENC('null-body=0')]))

    mark(cap, 'REQMOD')
    exch(f, icap('REQMOD ' + URL + 'reqmod ICAP/1.0',
                 [('Host', 'icap.example.net'), ('Allow', '204'), ENC('req-hdr=0, null-body=%d' % len(HREQ))], HREQ),
         icap('ICAP/1.0 204 No Content', [('ISTag', '"TEST-1"'), ENC('null-body=0')]))
    modreq = (b'GET /origin/other.html HTTP/1.1\r\nHost: www.example.com\r\nX-Modified: yes\r\n\r\n')
    exch(f, icap('REQMOD ' + URL + 'reqmod ICAP/1.0',
                 [('Host', 'icap.example.net'), ENC('req-hdr=0, null-body=%d' % len(HREQ))], HREQ),
         icap('ICAP/1.0 200 OK', [('ISTag', '"TEST-1"'), ENC('req-hdr=0, null-body=%d' % len(modreq))], modreq))
    post = (b'POST /upload HTTP/1.1\r\nHost: www.example.com\r\nContent-Type: application/x-www-form-urlencoded\r\n'
            b'Transfer-Encoding: chunked\r\n\r\n')
    exch(f, icap('REQMOD ' + URL + 'reqmod ICAP/1.0',
                 [('Host', 'icap.example.net'), ENC('req-hdr=0, req-body=%d' % len(post))],
                 post + chunk(b'a=1&b=2')),
         icap('ICAP/1.0 200 OK', [('ISTag', '"TEST-1"'), ENC('req-hdr=0, req-body=%d' % len(post))],
              post + chunk(b'a=1&b=3')))
    # a REQMOD that returns an HTTP error response
    err = b'HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\nContent-Length: %d\r\n\r\n' % len(HTML)
    exch(f, icap('REQMOD ' + URL + 'reqmod ICAP/1.0',
                 [('Host', 'icap.example.net'), ENC('req-hdr=0, null-body=%d' % len(HREQ))], HREQ),
         icap('ICAP/1.0 200 OK', [('ISTag', '"TEST-1"'), ENC('res-hdr=0, res-body=%d' % len(err))], err + chunk(HTML)))

    mark(cap, 'RESPMOD, preview and continuation')
    off = len(HREQ)
    exch(f, icap('RESPMOD ' + URL + 'respmod ICAP/1.0',
                 [('Host', 'icap.example.net'), ('Allow', '204'),
                  ENC('req-hdr=0, res-hdr=%d, res-body=%d' % (off, off + len(HRES)))],
                 HREQ + HRES + chunk(HTML)),
         icap('ICAP/1.0 200 OK', [('ISTag', '"TEST-1"'), ENC('res-hdr=0, res-body=%d' % len(HRES))], HRES + chunk(HTML)))
    # preview: the client sends a partial body, the server asks for the rest (100 Continue)
    f.c(icap('RESPMOD ' + URL + 'respmod ICAP/1.0',
             [('Host', 'icap.example.net'), ('Preview', '10'), ('Allow', '204'),
              ENC('req-hdr=0, res-hdr=%d, res-body=%d' % (off, off + len(HRES)))],
             HREQ + HRES + chunk(HTML[:10])[:-5] + b'0\r\n\r\n'), dt=2000)
    f.s(icap('ICAP/1.0 100 Continue'), dt=20000)
    f.c(chunk(HTML[10:], ieof=True), dt=2000)             # data without an ICAP start line
    f.c(b'second part of the body, printable text\r\n', dt=2000)
    f.c(bytes(range(32)), dt=2000)                       # binary continuation
    f.s(icap('ICAP/1.0 204 No modifications needed', [('ISTag', '"TEST-1"'), ENC('null-body=0')]), dt=20000)
    # a preview with ieof and zero length
    exch(f, icap('RESPMOD ' + URL + 'respmod ICAP/1.0',
                 [('Host', 'icap.example.net'), ('Preview', '0'),
                  ENC('res-hdr=0, res-body=%d' % len(HRES))], HRES + b'0; ieof\r\n\r\n'),
         icap('ICAP/1.0 204 No modifications needed', [('ISTag', '"TEST-1"'), ENC('null-body=0')]))
    f.fin()

    mark(cap, 'error responses, odd headers and other lines')
    f = Flow(cap, 43001, 1344)
    f.open()
    for code, text in ((400, 'Bad request'), (500, 'Server error'), (501, 'Method not implemented'),
                       (503, 'Service overloaded'), (505, 'ICAP version not supported by server')):
        exch(f, icap('REQMOD ' + URL + 'reqmod ICAP/1.0', [('Host', 'icap.example.net'), ENC('null-body=0')]),
             icap('ICAP/1.%d %d %s' % (code % 2, code, text), [('ISTag', '"TEST-1"'), ENC('null-body=0')]))
    # header lines that are not valid tokens end the header block; header with a space in the name
    f.c(icap('REQMOD ' + URL + 'x ICAP/1.0', ['Host: h', 'X Bad Name: v', '(not a header)', 'tail: x']), dt=2000)
    f.s(icap('ICAP/1.0 200 OK', ['Header-With-Separators/x: v', 'Odd"Header: v', 'a@b: v', 'k=v: x', '{x}: y', '[x]: y',
                                 'a,b: v', 'a;b: v', 'a<b: v', 'a>b: v', 'q?: v', 'a\\b: v', 'tab\there: v', ':no-name', 'ISTag: "x"']),
        dt=20000)
    # a line with a non printable character first, a line without a colon, and text after
    f.c(icap('REQMOD ' + URL + 'x ICAP/1.0', ['Host: h', 'Bad\x01Char: v', 'after: x'], b'trailing body bytes'), dt=2000)
    f.s(icap('ICAP/1.0 200 OK', ['no colon in this line', 'ISTag: "y"'], b'\x00\x01 binary'), dt=20000)
    # a request line that is only partly ICAP
    f.c(b'REQMOD', dt=2000)                  # too short to be a request
    f.c(b'OPTIONS', dt=2000)
    f.c(b'ICAP', dt=2000)
    f.c(b'RESPMOD ', dt=2000)
    f.c(b'\r\n', dt=2000)
    f.c(b'', dt=2000)
    f.s(b'ICAP/1.0 200 OK', dt=2000)
    f.fin()

    mark(cap, 'IPv6 and a second client')
    f = Flow(cap, 43002, 1344, v6=True)
    f.open()
    exch(f, icap('REQMOD icap://[2001:db8::2]/reqmod ICAP/1.0', [('Host', '[2001:db8::2]'), ENC('req-hdr=0, null-body=%d' % len(HREQ))], HREQ),
         icap('ICAP/1.0 204 No Content', [('ISTag', '"TEST-1"'), ENC('null-body=0')]))
    f.fin()
    # encapsulated HTTP that the HTTP dissector does not recognise
    f = Flow(cap, 43003, 1344)
    f.open()
    exch(f, icap('REQMOD ' + URL + 'x ICAP/1.0', [('Host', 'icap.example.net'), ENC('opt-body=0')], b'\x00\x01\x02 opaque encapsulated data'),
         icap('ICAP/1.0 200 OK', [('ISTag', '"TEST-1"'), ENC('opt-body=0')], bytes(20)))
    f.fin()


def build_malformed(cap):
    mark(cap, 'malformed: cut messages')
    f = Flow(cap, 44000, 1344)
    f.open()
    f.c(icap('REQMOD ' + URL + 'x ICAP/1.0', [('Host', 'h'), ENC('req-hdr=0, null-body=%d' % len(HREQ))], HREQ), snap=70, dt=1000)
    f.s(icap('ICAP/1.0 200 OK', [('ISTag', '"TEST-1"'), ENC('res-hdr=0, res-body=%d' % len(HRES))], HRES + chunk(HTML)), snap=90, dt=1000)
    f.c(icap('REQMOD ' + URL + 'x ICAP/1.0', [('Host', 'h')], b'GET / HTTP/1.1\r\nHost: x\r\n\r\n'), snap=60, dt=1000)
    f.c(b'REQMOD icap://x/y ICAP/1.0\r\nHost: h\r\nEncapsulated: req-hdr=0, req-body=5\r\n\r\nGET / HTTP/1.1\r\nHost', dt=1000)
    f.s(b'ICAP/1.0 200 OK\r\nISTag', dt=1000)
    f.s(b'ICAP/1.0 200 OK\r\n\r\n\r\n\r\nHTTP/1.1 200 OK\r\n\r\n', dt=1000)
    f.fin()


if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('-') else '.'
    main = Cap()
    build_main(main)
    main.write(os.path.join(out, 'icap-coverage.pcapng'))
    mal = Cap()
    build_malformed(mal)
    mal.write(os.path.join(out, 'icap-coverage-malformed.pcapng'))
    if '-v' in sys.argv:
        for cap, title in ((main, 'main'), (mal, 'malformed')):
            sec = sections[id(cap)]
            print(title)
            for i, (n, name) in enumerate(sec):
                end = sec[i + 1][0] - 1 if i + 1 < len(sec) else cap.n()
                print('  %d-%d %s' % (n, end, name))
            print('  ', cap.n(), 'frames')
