#!/usr/bin/env python3
# Generates test/captures/http-urlencoded_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Write the URL Encoded Form Data coverage captures.

The dissector is a media type handler for application/x-www-form-urlencoded;
the bodies travel in HTTP over TCP port 80, in multipart parts and in Exported
PDUs (dissector name urlencoded-form).

http-urlencoded-coverage.pcapng            valid and odd but decodable bodies
http-urlencoded-coverage-malformed.pcapng  bodies that raise exceptions

Usage: mkurlencoded.py <outdir> [-v]
"""
import os
import sys

from wslib import Cap, Flow  # noqa

sections = {}


def mark(cap, name):
    sections.setdefault(id(cap), []).append((cap.n() + 1, name))


CT = 'application/x-www-form-urlencoded'


def post(uri, body, ctype=CT, extra=()):
    h = 'POST %s HTTP/1.1\r\nHost: forms.example.com\r\nContent-Type: %s\r\n' % (uri, ctype)
    for e in extra:
        h += e + '\r\n'
    return h.encode() + b'Content-Length: %d\r\n\r\n' % len(body) + body


def ok(body=b'', ctype=None):
    h = 'HTTP/1.1 200 OK\r\n'
    if ctype:
        h += 'Content-Type: %s\r\n' % ctype
    return h.encode() + b'Content-Length: %d\r\n\r\n' % len(body) + body


BODIES = [
    b'user=test&password=placeholder&submit=Login',
    b'a=1',
    b'name=John+Smith&city=New+York&note=a+b+c',
    b'k%41%42=v%43%44&%65%66=%67%68',
    b'q=%E3%81%82%E3%81%84&caf%C3%A9=cr%C3%A8me',                # UTF-8 multi-byte
    b'bad=%FF%FE%FD&overlong=%C0%AF&cut=%E3%81',                  # invalid UTF-8
    b'flag&other&third=3',                                        # keys without value
    b'=novalue-key&=&empty=&',                                    # empty key, empty value, trailing &
    b'&&a=1&&b=2&&',                                              # empty items
    b'eq=a=b=c&more=x%3Dy',                                       # '=' inside the value
    b'nul=%00%01%02&ctl=%0D%0A%09',
    b'plus+key+=plus+value+&%2B=%2B',
    b'x' * 300 + b'=' + b'y' * 300,
    b'&'.join(b'item%d=value%d' % (i, i) for i in range(40)),
    b'lower=%e3%81%82&upper=%E3%81%82&mixed=%aB',
    b'only-key-no-equals',
    b'%',                                                         # not enough characters: see malformed
]


def build_main(cap):
    mark(cap, 'request and response bodies in HTTP')
    f = Flow(cap, 45000, 80)
    f.open()
    for i, b in enumerate(BODIES[:-1]):
        f.c(post('/form/%d' % i, b), dt=2000)
        f.s(ok(b'ok'), dt=20000)
    f.c(post('/charset', b'a=1&b=2', CT + '; charset=UTF-8'), dt=2000)
    f.s(ok(b'c=3&d=4', CT + '; charset=ISO-8859-1'), dt=20000)
    f.c(post('/upper', b'a=1', 'Application/X-WWW-Form-Urlencoded'), dt=2000)
    f.s(ok(b'e=5', CT), dt=20000)
    f.fin()
    mark(cap, 'multipart parts and Exported PDU')
    f = Flow(cap, 45001, 80)
    f.open()
    mp = (b'--BND\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nm1=1&m2=2\r\n'
          b'--BND\r\nContent-Type: text/plain\r\n\r\nplain\r\n--BND--\r\n')
    f.c(post('/mp', mp, 'multipart/mixed; boundary=BND'), dt=2000)
    f.s(ok(b'ok'), dt=20000)
    f.fin()
    # no media type information: the dissector is called by name
    for b in (b'p=1&q=2', b'', b'solo'):
        cap.exported_pdu('urlencoded-form', b)
    # a body split over TCP segments (reassembled by HTTP)
    f = Flow(cap, 45002, 80)
    f.open()
    h = post('/split', b'part1=aaaa&part2=bbbb&part3=cccc')
    f.c(h[:-20], dt=2000)
    f.c(h[-20:], dt=2000)
    f.s(ok(b'ok'), dt=20000)
    f.fin()


def build_malformed(cap):
    mark(cap, 'malformed: percent sequences that are cut or not hex')
    f = Flow(cap, 46000, 80)
    f.open()
    for i, b in enumerate((b'%', b'a=%', b'a=%4', b'a=b&c=%4', b'%4', b'k%=v', b'a=%zz', b'%zz=1', b'a=%4z', b'a=1&%',
                           b'a=%41%4')):
        f.c(post('/bad/%d' % i, b), dt=2000)
        f.s(ok(b'ok'), dt=20000)
    f.c(post('/cut', b'a=1&b=2&c=%41', extra=()), snap=130, dt=1000)
    f.fin()


if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('-') else '.'
    main = Cap()
    build_main(main)
    main.write(os.path.join(out, 'http-urlencoded-coverage.pcapng'))
    mal = Cap()
    build_malformed(mal)
    mal.write(os.path.join(out, 'http-urlencoded-coverage-malformed.pcapng'))
    if '-v' in sys.argv:
        for cap, title in ((main, 'main'), (mal, 'malformed')):
            sec = sections[id(cap)]
            print(title)
            for i, (n, name) in enumerate(sec):
                end = sec[i + 1][0] - 1 if i + 1 < len(sec) else cap.n()
                print('  %d-%d %s' % (n, end, name))
            print('  ', cap.n(), 'frames')
