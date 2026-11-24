#!/usr/bin/env python3
# Generates test/captures/bhttp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the Binary HTTP dissector
(packet-bhttp.c, RFC 9292).

All packets are built from scratch with struct; no captured traffic is
used. Binary HTTP is reached the default way: as the body of an HTTP/1.1
message with "Content-Type: message/bhttp" on TCP port 80 (the
"media_type" table), e.g. between an Oblivious HTTP relay (192.0.2.1)
and a gateway (198.51.100.1). Each HTTP message uses its own TCP
connection so HTTP does not pair requests and responses (that would add
"Response in" links only in the second pass).

Usage: mkbhttp.py <output directory>

Writes:
  bhttp-coverage.pcap            known- and indeterminate-length requests
                                 and responses, informational responses,
                                 trailers, padding, content chunks, all
                                 varint sizes, an unknown framing indicator
  bhttp-coverage-malformed.pcap  lengths longer than the message (each
                                 length the dissector checks), including a
                                 small version of the 32-bit length
                                 reproducer (all-0xff field section)
"""

import struct
import sys

CLIENT = (192, 0, 2, 1)
SERVER = (198, 51, 100, 1)


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def ipv4(src, dst, proto, payload, ident=1):
    h = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0, 64, proto, 0,
                    bytes(src), bytes(dst))
    return h[:10] + struct.pack('>H', csum(h)) + h[12:] + payload


def tcp4(src, dst, sport, dport, seq, ack, flags, payload):
    t = struct.pack('>HHIIBBHHH', sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0) + payload
    c = csum(struct.pack('>4s4sBBH', bytes(src), bytes(dst), 0, 6, len(t)) + t)
    return t[:16] + struct.pack('>H', c) + t[18:]


def eth(src_mac, dst_mac, ip):
    return dst_mac + src_mac + b'\x08\x00' + ip


MAC_C = bytes.fromhex('020000000001')
MAC_S = bytes.fromhex('020000000002')


def vi(v, size=None):
    """QUIC variable-length integer, optionally with a forced size."""
    if size is None:
        size = 1 if v < 0x40 else 2 if v < 0x4000 else 4 if v < 0x40000000 else 8
    code = {1: 0, 2: 1, 4: 2, 8: 3}[size]
    assert v < (1 << (8 * size - 2))
    return ((code << (8 * size - 2)) | v).to_bytes(size, 'big')


def vs(s, size=None):
    """Length-prefixed string."""
    if isinstance(s, str):
        s = s.encode()
    return vi(len(s), size) + s


def fields(lines):
    return b''.join(vs(n) + vs(v) for n, v in lines)


def kfs(lines, size=None):
    """Known-length field section."""
    body = fields(lines)
    return vi(len(body), size) + body


def ifs(lines):
    """Indeterminate-length field section (terminated by a zero)."""
    return fields(lines) + vi(0)


def kcontent(data, size=None):
    return vi(len(data), size) + data


def icontent(chunks):
    return b''.join(vs(c) for c in chunks) + vi(0)


def control(method, scheme, authority, path):
    return vs(method) + vs(scheme) + vs(authority) + vs(path)


# ---------------------------------------------------------------- HTTP/TCP

class Writer:
    def __init__(self):
        self.frames = []
        self.port = 40000

    def segments(self, src, dst, sport, dport, data, split=None):
        smac, dmac = (MAC_C, MAC_S) if src == CLIENT else (MAC_S, MAC_C)
        parts = [data] if split is None else [data[:split], data[split:]]
        seq = 1
        for p in parts:
            ip = ipv4(src, dst, 6, tcp4(src, dst, sport, dport, seq, 1, 0x18, p),
                      ident=len(self.frames) + 1)
            self.frames.append(eth(smac, dmac, ip))
            seq += len(p)

    def request(self, body, split=None):
        self.port += 1
        http = (b'POST /gateway HTTP/1.1\r\nHost: gateway.example\r\n'
                b'Content-Type: message/bhttp\r\nContent-Length: %d\r\n\r\n' % len(body)) + body
        self.segments(CLIENT, SERVER, self.port, 80, http, split)

    def response(self, body, split=None):
        self.port += 1
        http = (b'HTTP/1.1 200 OK\r\nContent-Type: message/bhttp\r\n'
                b'Content-Length: %d\r\n\r\n' % len(body)) + body
        self.segments(SERVER, CLIENT, 80, self.port, http, split)

    def write(self, path):
        with open(path, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
            for i, fr in enumerate(self.frames):
                f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)) + fr)


KREQ, KRESP, IREQ, IRESP = vi(0), vi(1), vi(2), vi(3)

HDRS = [('user-agent', 'curl/8.0'), ('accept', '*/*')]


def main_capture():
    w = Writer()
    # 1: known-length GET, header section, ends there (no content)
    w.request(KREQ + control('GET', 'https', 'www.example.com', '/index.html') + kfs(HDRS))
    # 2: POST with headers, content, trailers
    w.request(KREQ + control('POST', 'https', 'api.example.com', '/v1/upload')
              + kfs([('content-type', 'text/plain')]) + kcontent(b'hello, world')
              + kfs([('x-checksum', 'abc123')]))
    # 3: same with 16 octets of padding after the trailers
    w.request(KREQ + control('PUT', 'https', 'api.example.com', '/v1/item/7')
              + kfs(HDRS) + kcontent(b'{"id":7}') + kfs([('x-trailer', '1')]) + bytes(16))
    # 4: control data only
    w.request(KREQ + control('DELETE', 'https', 'api.example.com', '/v1/item/7'))
    # 5: empty header section, empty content, empty trailers
    w.request(KREQ + control('OPTIONS', 'https', 'api.example.com', '*')
              + kfs([]) + kcontent(b'') + kfs([]))
    # 6: 2, 4 and 8 octet varints: long path, 300 octet content,
    #    lengths written in longer forms than needed
    path = '/' + 'p' * 99
    w.request(vi(0, 2) + vs('GET', 2) + vs('https', 4) + vs('www.example.com', 8) + vs(path)
              + kfs([('x-long', 'v' * 70)], size=4) + kcontent(bytes(range(256)) + b'x' * 44)
              + kfs([('x-end', 'yes')], size=8))
    # 7: final response status only
    w.response(KRESP + vi(200))
    # 8: 103 Early Hints, then 200 with headers, content and trailers
    w.response(KRESP + vi(103) + kfs([('link', '</style.css>; rel=preload')])
               + vi(200) + kfs([('content-type', 'text/html')]) + kcontent(b'<html></html>')
               + kfs([('server-timing', 'db;dur=53')]))
    # 9: only an informational response (status, then the message ends)
    w.response(KRESP + vi(100))
    # 10: 102 with headers, then 204 with headers only
    w.response(KRESP + vi(102) + kfs([('x-progress', '50')]) + vi(204) + kfs([('date', 'today')]))
    # 11: 100, then a status outside 100-599 stops the response
    w.response(KRESP + vi(100) + kfs([]) + vi(600) + b'tail')
    # 12: a status below 100 stops at once
    w.response(KRESP + vi(50))
    # 13: 100 with headers, then a varint cut short ends the response
    w.response(KRESP + vi(100) + kfs([('x-a', 'b')]) + b'\x40')
    # 14: indeterminate-length GET with headers only
    w.request(IREQ + control('GET', 'https', 'www.example.com', '/') + ifs(HDRS))
    # 15: indeterminate POST, headers, two content chunks, trailers, padding
    w.request(IREQ + control('POST', 'https', 'api.example.com', '/stream')
              + ifs([('content-type', 'application/octet-stream'), ('x-id', '42')])
              + icontent([b'first chunk', b'second chunk of data'])
              + ifs([('x-checksum', 'deadbeef')]) + bytes(8))
    # 16: headers, one chunk, empty trailers (end of message)
    w.request(IREQ + control('PATCH', 'https', 'api.example.com', '/x')
              + ifs([('x-a', '1')]) + icontent([b'z' * 100]) + vi(0))
    # 17: control data only
    w.request(IREQ + control('HEAD', 'https', 'www.example.com', '/'))
    # 18: header section without its terminator (message ends)
    w.request(IREQ + control('GET', 'https', 'www.example.com', '/t') + fields(HDRS))
    # 19: content chunk without its terminator (message ends)
    w.request(IREQ + control('POST', 'https', 'www.example.com', '/t')
              + ifs([('x-a', '1')]) + vs(b'partial'))
    # 20: indeterminate 103, then 200 with headers, chunks, trailers
    w.response(IRESP + vi(103) + ifs([('link', '</a.js>; rel=preload')])
               + vi(200) + ifs([('content-type', 'text/plain')])
               + icontent([b'part one ', b'part two']) + ifs([('etag', '"xyz"')]))
    # 21: final response status only
    w.response(IRESP + vi(404))
    # 22: 100 only, then the message ends
    w.response(IRESP + vi(100))
    # 23: 100 with headers, then status 700 stops the response
    w.response(IRESP + vi(100) + ifs([('x-a', 'b')]) + vi(700))
    # 24: 100 with headers, then a varint cut short ends the response
    w.response(IRESP + vi(101) + ifs([('upgrade', 'h2c')]) + b'\x80\x00')
    # 25: 500 with headers, content, end of message, and a 2 octet status
    w.response(IRESP + vi(500, 2) + ifs([('retry-after', '120')])
               + icontent([b'internal error']) + vi(0))
    # 26: unknown framing indicator
    w.request(vi(4) + b'\x01\x02\x03')
    # 27-28: known-length request split over two TCP segments (HTTP
    #        reassembles it before Binary HTTP sees it)
    w.request(KREQ + control('POST', 'https', 'upload.example.com', '/big')
              + kfs(HDRS) + kcontent(bytes((i * 7) & 0xff for i in range(2000)))
              + kfs([('x-done', '1')]), split=600)
    # 29: indeterminate status below 100 stops at once
    w.response(IRESP + vi(42))
    # 30: indeterminate 200, empty content (a zero chunk length; the
    #     dissector takes the next zero, the empty trailer section, as
    #     the content terminator)
    w.response(IRESP + vi(200) + ifs([('a', 'b')]) + vi(0) + vi(0))
    # 31-32: known- and indeterminate-length responses with padding
    #        after the trailers (not shown by the dissector)
    w.response(KRESP + vi(200) + kfs([('a', 'b')]) + kcontent(b'ok') + kfs([]) + bytes(12))
    w.response(IRESP + vi(200) + ifs([('a', 'b')]) + icontent([b'ok']) + vi(0) + bytes(12))
    return w


def malformed_capture():
    w = Writer()
    ff = b'\xff' * 300
    # 1: small version of the 32-bit length reproducer
    #    (bhttp_neg1_quadratic_http.py): empty control data,
    #    a field section length of 1048576, then 300 octets of 0xff
    w.request(bytes([0, 0, 0, 0, 0]) + bytes([0x80, 0x10, 0x00, 0x00]) + ff)
    # 2: the same with a field section length that fits, but all-0xff
    #    field lines (name length 2^62-1)
    w.request(bytes([0, 0, 0, 0, 0]) + vi(300, 2) + ff)
    # 3-6: method, scheme, authority, path longer than the message
    w.request(KREQ + vi(1000) + b'GET')
    w.request(KREQ + vs('GET') + vi(1000) + b'https')
    w.request(KREQ + vs('GET') + vs('https') + vi(1000) + b'x')
    w.request(KREQ + vs('GET') + vs('https') + vs('x') + b'\xff' * 8)
    # 7: known field section: value length too long
    w.request(KREQ + control('GET', 'https', 'x', '/') + vi(5) + vs('a') + vi(1000) + b'b')
    # 8: known content length too long
    w.response(KRESP + vi(200) + kfs([]) + vi(5000) + b'short')
    # 9: indeterminate field section: all 0xff
    w.request(IREQ + control('GET', 'https', 'x', '/') + ff)
    # 10: indeterminate field section: value length too long
    w.response(IRESP + vi(200) + vs('a') + vi(999) + b'b')
    # 11: indeterminate content chunk too long
    w.response(IRESP + vi(200) + ifs([('a', 'b')]) + vi(4000) + b'data')
    # 12: control data cut in a varint
    w.request(KREQ + vs('GET') + b'\x40')
    return w


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    main_capture().write(out + '/bhttp-coverage.pcap')
    malformed_capture().write(out + '/bhttp-coverage-malformed.pcap')


if __name__ == '__main__':
    main()
