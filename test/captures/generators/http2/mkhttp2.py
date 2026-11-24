#!/usr/bin/env python3
# Generates test/captures/http2_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate http2-coverage.pcap and http2-coverage-malformed.pcap.

Synthetic HTTP/2 over TCP (addresses 192.0.2.x).  No TLS, no compression
tricks: header blocks are plain HPACK literals/indexed entries.
usage: mkhttp2.py <outdir>
"""
import struct
import sys
import os
from g7lib import TcpFlow, write_pcap

MAGIC = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'

def frame(ftype, flags, sid, payload=b'', length=None):
    if length is None:
        length = len(payload)
    return struct.pack('!I', length)[1:] + bytes([ftype, flags]) + struct.pack('!I', sid) + payload

DATA, HEADERS, PRIORITY, RST, SETTINGS, PUSH, PING, GOAWAY, WUPD, CONT = range(10)
ALTSVC, ORIGIN, PRIUPD = 10, 12, 16
END_STREAM, ACK, END_HEADERS, PADDED, PRIO = 1, 1, 4, 8, 0x20

def lit(name, value):
    return b'\x00' + bytes([len(name)]) + name + bytes([len(value)]) + value

REQ = b'\x82\x86\x84\x41\x0bexample.org' + lit(b'user-agent', b'cov')
RESP = b'\x88' + lit(b'content-type', b'text/plain')
CONNECT_HB = (lit(b':method', b'CONNECT') + lit(b':protocol', b'h2c') +
              lit(b':scheme', b'http') + lit(b':authority', b'x') + lit(b':path', b'/'))

def setting(i, v):
    return struct.pack('!HI', i, v)

def settings(*items, flags=0):
    return frame(SETTINGS, flags, 0, b''.join(setting(i, v) for i, v in items))

def wupd(sid, inc):
    return frame(WUPD, 0, sid, struct.pack('!I', inc))

def conn(cport, sport):
    f = TcpFlow(cport=cport, sport=sport)
    f.handshake()
    return f

def build_main():
    caps = []

    # --- 1: TCP heuristic (magic), every frame type, both directions
    f = conn(41001, 50080)
    f.send(0, MAGIC + settings((1, 4096), (2, 0), (3, 100), (4, 65535), (5, 16384),
                                (6, 8192), (8, 1), (9, 1), (0x10, 1), (0x77, 5)))
    f.send(1, settings((3, 128), (4, 100000)) + frame(SETTINGS, ACK, 0))
    f.send(0, frame(SETTINGS, ACK, 0) + wupd(0, 1000))
    f.send(0, frame(HEADERS, END_HEADERS | END_STREAM, 1, REQ))
    f.send(1, frame(HEADERS, END_HEADERS, 1, RESP))
    f.send(1, frame(DATA, 0, 1, b'hello ') + frame(DATA, END_STREAM, 1, b'world'))
    f.send(0, wupd(1, 500) + wupd(0, 500))
    # padded HEADERS with priority, split in HEADERS + CONTINUATION
    pl = bytes([3]) + struct.pack('!IB', 0x80000001, 15) + REQ[:6] + b'\0\0\0'
    f.send(0, frame(HEADERS, PADDED | PRIO | END_STREAM, 3, pl))
    f.send(0, frame(CONT, PADDED | END_HEADERS, 3, bytes([2]) + REQ[6:] + b'\0\0'))
    f.send(0, frame(CONT, END_HEADERS, 3, REQ[6:]))
    f.send(0, frame(HEADERS, PRIO | END_HEADERS, 5, struct.pack('!IB', 3, 200) + REQ))
    f.send(0, frame(PRIORITY, 0, 5, struct.pack('!IB', 0x80000003, 0)))
    f.send(1, frame(PUSH, END_HEADERS, 5, struct.pack('!I', 2) + REQ))
    f.send(1, frame(PUSH, PADDED | END_HEADERS, 5, bytes([2]) + struct.pack('!I', 4) + REQ + b'\0\0'))
    f.send(1, frame(PUSH, PADDED, 5, bytes([0]) + struct.pack('!I', 6) + REQ))
    f.send(1, frame(DATA, PADDED, 5, bytes([4]) + b'padded' + b'\0' * 4))
    f.send(1, frame(DATA, PADDED | END_STREAM, 5, bytes([0]) + b'nopad'))
    f.send(0, frame(RST, 0, 5, struct.pack('!I', 8)))
    f.send(0, frame(PING, 0, 0, b'12345678'))
    f.send(1, frame(PING, ACK, 0, b'12345678'))
    f.send(1, frame(ALTSVC, 0, 0, struct.pack('!H', 11) + b'example.org' + b'h3=":443"'))
    f.send(1, frame(ALTSVC, 0, 1, struct.pack('!H', 0) + b'h3=":8443"'))
    f.send(1, frame(ALTSVC, 0, 1, struct.pack('!H', 3) + b'a.b'))
    f.send(1, frame(ORIGIN, 0, 0, b''.join(struct.pack('!H', len(o)) + o for o in
                (b'https://a.example', b'https://b.example:8443'))))
    f.send(0, frame(PRIUPD, 0, 0, struct.pack('!I', 3) + b'u=2, i'))
    f.send(0, frame(PRIUPD, 0, 0, struct.pack('!I', 5)))
    f.send(0, frame(11, 0, 0, b'\x01\x02\x03') + frame(13, 0, 7, b'\x00') + frame(0xee, 0xff, 9, b'xx'))
    f.send(1, frame(GOAWAY, 0, 0, struct.pack('!II', 5, 0)))
    f.send(1, frame(GOAWAY, 0, 0, struct.pack('!II', 0x80000005, 2) + b'debug data'))
    # a frame split over two TCP segments, and two frames in one segment
    ping = frame(PING, 0, 0, b'abcdefgh')
    f.send(0, ping[:5]); f.send(0, ping[5:])
    f.send(0, frame(DATA, 0, 7, b'x' * 40)[:20]); f.send(0, frame(DATA, 0, 7, b'x' * 40)[20:])
    caps.append(f.pkts)

    # --- 2: window size accounting and warnings
    f = conn(41002, 50081)
    f.send(0, MAGIC + settings())
    f.send(1, settings((4, 0x80000000)) + settings((4, 100)) + settings((4, 100)))
    f.send(0, wupd(0, 0x7fffffff))
    f.send(0, wupd(0, 0x7fffffff))
    f.send(0, wupd(0, 0))
    f.send(0, wupd(3, 10))
    f.send(1, frame(DATA, 0, 1, b'a' * 100))
    f.send(0, frame(DATA, 0, 1, b'b' * 100) * 2)
    f.send(0, frame(DATA, 0, 0, b'c' * 10))
    for _ in range(5):
        f.send(1, frame(DATA, 0, 3, b'd' * 16000))
    caps.append(f.pkts)

    # --- 3: HTTP port heuristic (port 80), request + magic on an HTTP port
    f = conn(41003, 80)
    f.send(0, MAGIC + settings((3, 10)))
    f.send(1, settings())
    f.send(0, frame(PING, 0, 0, b'\0' * 8))
    caps.append(f.pkts)

    # --- 4: HTTP/1.1 Upgrade: h2c with an HTTP2-Settings header
    f = conn(41004, 80)
    f.send(0, b'GET / HTTP/1.1\r\nHost: example.org\r\nConnection: Upgrade, HTTP2-Settings\r\n'
              b'Upgrade: h2c\r\nHTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA\r\n\r\n')
    f.send(1, b'HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n')
    f.send(1, settings((3, 100)))
    f.send(0, MAGIC + settings() + frame(SETTINGS, ACK, 0))
    f.send(1, frame(HEADERS, END_HEADERS, 1, RESP) + frame(DATA, END_STREAM, 1, b'upgraded'))
    caps.append(f.pkts)

    # --- 5: reproducer: extended CONNECT with :protocol h2c, DATA frames
    # nested on stream 1 (fixed by "HTTP2: Prevent unbounded tunnel recursion";
    # only reachable with nghttp2, plain DATA frames in this build)
    N = 7270
    f = conn(41005, 50082)
    f.send(0, MAGIC + frame(SETTINGS, 0, 0) + frame(HEADERS, END_HEADERS, 1, CONNECT_HB))
    f.send(0, b''.join(frame(DATA, 0, 1, length=9 * (N - 1 - i)) for i in range(N)))
    caps.append(f.pkts)

    # --- 6: tunnel via extended CONNECT with a few real nested frames, and
    # a 2nd stream with a non-HTTP protocol name
    f = conn(41006, 50083)
    hb = (lit(b':method', b'CONNECT') + lit(b':protocol', b'websocket') + lit(b':scheme', b'http') +
          lit(b':authority', b'x') + lit(b':path', b'/ws'))
    f.send(0, MAGIC + settings((8, 1)) + frame(HEADERS, END_HEADERS, 1, hb))
    f.send(1, settings((8, 1)) + frame(HEADERS, END_HEADERS, 1, RESP))
    f.send(0, frame(DATA, 0, 1, b'\x81\x05hello'))
    f.send(1, frame(DATA, END_STREAM, 1, b'\x81\x05world'))
    caps.append(f.pkts)

    # --- 7: connection window exceeded by the server's DATA (warning)
    f = conn(41007, 50084)
    f.send(0, MAGIC + settings())
    f.send(1, settings())
    for _ in range(5):
        f.send(1, frame(DATA, 0, 1, b'e' * 16000))
    caps.append(f.pkts)

    # --- 8: not HTTP/2: heuristics reject (TCP port, plain HTTP request)
    f = conn(41008, 50085)
    f.send(0, b'hello, this is not http2 at all\r\n')
    caps.append(f.pkts)
    f = conn(41009, 80)
    f.send(0, b'GET /x HTTP/1.1\r\nHost: example.org\r\n\r\n')
    f.send(1, b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok')
    caps.append(f.pkts)

    return [p for c in caps for p in c]

def build_malformed():
    caps = []
    def one(frames, port):
        f = conn(42000 + port % 1000, port)
        f.send(0, MAGIC + settings())
        for d, fr in frames:
            f.send(d, fr)
        caps.append(f.pkts)
    one([(0, frame(PING, 0, 0, b'1234'))], 50100)                      # short PING
    one([(0, frame(HEADERS, PADDED, 1, bytes([200]) + b'abc'))], 50101)  # padding > length
    one([(0, frame(PUSH, PADDED, 1, bytes([200]) + struct.pack('!I', 2) + b'a'))], 50102)
    one([(0, frame(CONT, PADDED, 1, bytes([50]) + b'abc'))], 50103)
    one([(1, frame(ALTSVC, 0, 0, struct.pack('!H', 500) + b'abc'))], 50104)
    one([(1, frame(ORIGIN, 0, 0, struct.pack('!H', 500) + b'abc'))], 50105)
    one([(0, frame(PRIUPD, 0, 0, b'\x00'))], 50106)
    one([(0, frame(RST, 0, 1, b'\x00\x00'))], 50107)
    one([(1, frame(GOAWAY, 0, 0, b'\x00\x00\x00'))], 50108)
    one([(0, frame(PRIORITY, 0, 1, b'\x00\x00'))], 50109)
    one([(0, frame(WUPD, 0, 1, b'\x00'))], 50110)
    one([(0, frame(SETTINGS, 0, 0, b'\x00\x03\x00'))], 50111)
    one([(0, frame(DATA, PADDED, 1, b''))], 50112)
    one([(0, frame(HEADERS, PRIO, 1, b'\x00\x00'))], 50113)
    one([(0, frame(DATA, 0, 1, b'abc', length=100))], 50114)          # truncated frame
    # the same state in a one connection ends with an unknown type of length 0
    one([(0, frame(99, 0, 0, b''))], 50115)
    return [p for c in caps for p in c]

if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    m = build_main()
    write_pcap(os.path.join(out, 'http2-coverage.pcap'), m)
    b = build_malformed()
    write_pcap(os.path.join(out, 'http2-coverage-malformed.pcap'), b)
    print(len(m), len(b))
