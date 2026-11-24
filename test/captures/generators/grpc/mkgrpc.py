#!/usr/bin/env python3
# Generates test/captures/grpc_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the GRPC coverage captures. Usage: mkgrpc.py <outdir>
gRPC over HTTP/2 (cleartext, prior knowledge: found by the HTTP/2 TCP
heuristic) and gRPC-Web over HTTP/1.1."""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
import zlib
import gzip
import base64
from common import Flow, pcap, tcpseg

# ------------------------------------------------------------ HTTP/2
PREFACE = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'

def h2frame(t, flags, sid, payload=b''):
    return struct.pack('>I', len(payload))[1:] + bytes([t, flags]) + struct.pack('>I', sid) + payload

def hp(name, value):
    """HPACK literal header field without indexing, new name, no Huffman"""
    return b'\x00' + bytes([len(name)]) + name + bytes([len(value)]) + value

def req_headers(path, ctype, enc=None, extra=()):
    h = hp(b':method', b'POST') + hp(b':scheme', b'http') + hp(b':path', path) + hp(b':authority', b'server.example')
    h += hp(b'content-type', ctype) + hp(b'te', b'trailers')
    if enc: h += hp(b'grpc-encoding', enc)
    for n, v in extra: h += hp(n, v)
    return h

def resp_headers(ctype, enc=None):
    h = hp(b':status', b'200') + hp(b'content-type', ctype)
    if enc: h += hp(b'grpc-encoding', enc)
    return h

def trailers(status=b'0', msg=None):
    h = hp(b'grpc-status', status)
    if msg: h += hp(b'grpc-message', msg)
    return h

def msg(payload, compressed=0):
    return bytes([compressed]) + struct.pack('>I', len(payload)) + payload

def pb_str(field, s): return bytes([(field << 3) | 2, len(s)]) + s
def pb_varint(field, v): return bytes([(field << 3) | 0, v])

REQ = pb_str(1, b'world') + pb_varint(2, 7)
REP = pb_str(1, b'Hello world')
LONG = pb_str(1, b'x' * 100) + pb_str(2, b'y' * 100)

class H2:
    """one cleartext HTTP/2 connection"""
    def __init__(self, frames, cport, sport=50051):
        self.fl = Flow(cport, sport, frames)
        self.fl.open()
        self.first = True
    def c(self, *frs):
        data = b''.join(frs)
        if self.first:
            data = PREFACE + h2frame(4, 0, 0) + data
            self.first = False
        self.fl.c2s(data)
    def s(self, *frs): self.fl.s2c(b''.join(frs))
    def settings(self):
        self.fl.s2c(h2frame(4, 0, 0) + h2frame(4, 1, 0))
        self.fl.c2s(h2frame(4, 1, 0))

def http1(frames, cport, requests, sport=80):
    fl = Flow(cport, sport, frames)
    fl.open()
    for rq, rs in requests:
        if rq is not None:
            fl.c2s(rq)
        for seg in (rs if isinstance(rs, list) else [rs]):
            fl.s2c(seg)
    return fl

def http_req(path, ctype, body, extra=b''):
    return (b'POST ' + path + b' HTTP/1.1\r\nHost: server.example\r\nContent-Type: ' + ctype + b'\r\n' + extra +
            b'Content-Length: %d\r\n\r\n' % len(body) + body)

def http_resp(ctype, body, extra=b''):
    return (b'HTTP/1.1 200 OK\r\nContent-Type: ' + ctype + b'\r\n' + extra +
            b'Content-Length: %d\r\n\r\n' % len(body) + body)

def main(outdir):
    F, H, marks = [], [], []
    def mark(s): marks.append((len(F) + 1, s))

    PATH = b'/helloworld.Greeter/SayHello'
    # --------------------------------------------------------------- gRPC-Web over HTTP/1.1
    mark('gRPC-Web over HTTP/1.1: data and trailer frames, compression, grpc-web+proto, text (base64)')
    trailer = b'grpc-status: 0\r\ngrpc-message: OK\r\n'
    body_rep = msg(REP) + bytes([0x80]) + struct.pack('>I', len(trailer)) + trailer
    http1(F, 41002, [
        (http_req(PATH, b'application/grpc-web', msg(REQ)), http_resp(b'application/grpc-web', body_rep)),
        (http_req(PATH, b'application/grpc-web+proto', msg(REQ)), http_resp(b'application/grpc-web+proto', body_rep)),
        (http_req(PATH, b'application/grpc-web', msg(gzip.compress(LONG), 1), b'grpc-encoding: gzip\r\n'),
         http_resp(b'application/grpc-web', msg(gzip.compress(REP), 1) + bytes([0x80]) + struct.pack('>I', len(trailer)) + trailer, b'grpc-encoding: gzip\r\n')),
        (http_req(PATH, b'application/grpc-web', msg(b'not gzip', 1), b'grpc-encoding: gzip\r\n'),
         http_resp(b'application/grpc-web', bytes([0x80]) + struct.pack('>I', len(trailer)) + trailer)),
        (http_req(PATH, b'application/grpc-web', msg(REQ, 1)), http_resp(b'application/grpc-web', msg(REP))),
        (http_req(PATH, b'application/grpc-web', msg(b'')), http_resp(b'application/grpc-web', msg(b''))),
    ])
    http1(F, 41003, [
        (http_req(PATH, b'application/grpc-web-text', base64.b64encode(msg(REQ))),
         http_resp(b'application/grpc-web-text', base64.b64encode(body_rep))),
        (http_req(PATH, b'application/grpc-web-text+proto', base64.b64encode(msg(REQ) + msg(REQ))),
         http_resp(b'application/grpc-web-text+proto', base64.b64encode(msg(REP)))),
    ])

    # --------------------------------------------------------------- gRPC over HTTP/2
    # The streams have no HEADERS frames (HPACK needs nghttp2): the headers come from the
    # http2_fake_headers UAT, see UAT in this file.
    c = H2(H, 41001)
    streams = [
        # id, path, content-type, encoding, request body, response body
        (1, PATH, b'application/grpc', None, msg(REQ), msg(REP)),
        (3, PATH, b'application/grpc', b'gzip', msg(gzip.compress(LONG), 1), msg(gzip.compress(REP), 1)),
        (5, PATH, b'application/grpc+proto', b'deflate', msg(zlib.compress(LONG), 1), msg(zlib.compress(REP), 1)),
        (7, b'/json.Service/Call', b'application/grpc+json', None, msg(b'{"name": "world", "n": 7}'), msg(b'{"greeting": "Hello world"}\n')),
        (9, b'/json.Service/Detect', b'application/grpc', None, msg(b'{"detected": true}'), msg(b'{"detected": true}\r\n')),
        (11, PATH, b'application/grpc', None, msg(REQ) + msg(b'') + msg(pb_str(1, b'second')) + msg(REQ[:3]), msg(REP) + msg(REP)),
        (13, PATH, b'application/grpc', None, msg(gzip.compress(REQ), 1), msg(REP)),          # compressed, no grpc-encoding
        (15, PATH, b'application/grpc', b'identity', msg(REQ, 1), msg(REP)),
        (17, PATH, b'application/grpc', b'snappy', msg(REQ, 1), msg(REP)),
        (19, b'/other.pkg.Service/Method', b'application/grpc', None, msg(REQ), msg(REP)),
    ]
    for sid, path, ct, enc, rq, rs in streams:
        c.c(h2frame(0, 1, sid, rq))
        if sid == 1:
            c.settings()
        c.s(h2frame(0, 1, sid, rs))
    uat = []
    for sid, path, ct, enc, rq, rs in streams:
        uat.append(('50051', str(sid), 'IN', ':path', path.decode()))
        uat.append(('50051', str(sid), 'IN', 'content-type', ct.decode()))
        uat.append(('50051', str(sid), 'OUT', 'content-type', ct.decode()))
        if enc:
            uat.append(('50051', str(sid), 'IN', 'grpc-encoding', enc.decode()))
            uat.append(('50051', str(sid), 'OUT', 'grpc-encoding', enc.decode()))

    mark('gRPC (application/grpc) over HTTP/1.1: unary, gzip, deflate, JSON, several messages, compression without or with an unknown encoding')
    trailer2 = b'grpc-status: 0\r\n'
    http1(F, 41004, [
        (http_req(PATH, b'application/grpc', msg(REQ)), http_resp(b'application/grpc', msg(REP))),
        (http_req(PATH, b'application/grpc+proto', msg(REQ)), http_resp(b'application/grpc+proto', msg(REP))),
        (http_req(PATH, b'application/grpc', msg(gzip.compress(LONG), 1), b'grpc-encoding: gzip\r\n'),
         http_resp(b'application/grpc', msg(gzip.compress(REP), 1), b'grpc-encoding: gzip\r\n')),
        (http_req(PATH, b'application/grpc', msg(zlib.compress(LONG), 1), b'grpc-encoding: deflate\r\n'),
         http_resp(b'application/grpc', msg(zlib.compress(REP), 1), b'grpc-encoding: deflate\r\n')),
        (http_req(b'/json.Service/Call', b'application/grpc+json', msg(b'{"name": "world", "n": 7}')),
         http_resp(b'application/grpc+json', msg(b'{"greeting": "Hello world"}\n'))),
        (http_req(b'/json.Service/Detect', b'application/grpc', msg(b'{"detected": true}')),
         http_resp(b'application/grpc', msg(b'{"detected": true}\r\n'))),
        (http_req(b'/json.Service/Detect', b'application/grpc', msg(b'{"detected": "newline"}\n')),
         http_resp(b'application/grpc', msg(b'{"detected": "newline"}\n'))),
        (http_req(PATH, b'application/grpc', msg(REQ) + msg(b'') + msg(pb_str(1, b'second'))),
         http_resp(b'application/grpc', msg(REP) + msg(REP))),
        (http_req(PATH, b'application/grpc', msg(gzip.compress(REQ), 1)), http_resp(b'application/grpc', msg(REP))),
        (http_req(PATH, b'application/grpc', msg(REQ, 1), b'grpc-encoding: identity\r\n'), http_resp(b'application/grpc', msg(REP))),
        (http_req(PATH, b'application/grpc', msg(REQ, 1), b'grpc-encoding: snappy\r\n'), http_resp(b'application/grpc', msg(REP))),
        (http_req(b'/other.pkg.Service/Method', b'application/grpc', msg(REQ)), http_resp(b'application/grpc', msg(REP))),
    ])
    mark('a response without the request in the capture, a gRPC body in a multipart part')
    http1(F, 41006, [(None, http_resp(b'application/grpc', msg(REP))), (None, http_resp(b'application/grpc-web', msg(REP)))])
    part = b'--xx\r\nContent-Type: application/grpc\r\n\r\n' + msg(REQ) + b'\r\n--xx--\r\n'
    http1(F, 41007, [(http_req(PATH, b'multipart/mixed; boundary=xx', part), http_resp(b'multipart/mixed; boundary=xx', part))])
    mark('streaming responses (chunked): a message split over chunks, a message header split over chunks')
    def chunked(chunks):
        return b''.join(b'%x\r\n' % len(c) + c + b'\r\n' for c in chunks) + b'0\r\n\r\n'
    def http_resp_chunked(ctype, chunks):
        # one TCP segment per chunk: the first has the headers, the last the terminating chunk
        hdr = b'HTTP/1.1 200 OK\r\nContent-Type: ' + ctype + b'\r\nTransfer-Encoding: chunked\r\n\r\n'
        segs = [b'%x\r\n' % len(c) + c + b'\r\n' for c in chunks]
        segs[0] = hdr + segs[0]
        segs[-1] += b'0\r\n\r\n'
        return segs
    full = msg(REP) + msg(REP)
    http1(F, 41005, [
        (http_req(PATH, b'application/grpc', msg(REQ)), http_resp_chunked(b'application/grpc', [full[:3], full[3:12], full[12:]])),
        (http_req(PATH, b'application/grpc-web', msg(REQ)), http_resp_chunked(b'application/grpc-web', [full[:2], full[2:7], full[7:] + bytes([0x80]) + struct.pack('>I', len(trailer2)) + trailer2])),
        (http_req(PATH, b'application/grpc-web-text', base64.b64encode(msg(REQ))), http_resp_chunked(b'application/grpc-web-text', [base64.b64encode(full)[:8], base64.b64encode(full)[8:]])),
    ])

    mark('reproducers of the length overflow: message lengths 0xFFFFFFFF, 0xFFFFFFFB and 0xFFFFFFFC (warning "Malformed message data", no exception)')
    for i, mlen in enumerate((0xFFFFFFFF, 0xFFFFFFFB, 0xFFFFFFFC)):
        body = b'\x00' + struct.pack('>I', mlen) + b'\x08\x01\x10\x02\x18\x03'
        http1(F, 41010 + i, [(http_req(PATH, b'application/grpc-web', body), http_resp(b'application/grpc-web', msg(REP)))])

    # --------------------------------------------------------------- malformed
    M = []
    # the reproducer of the length overflow: message length 0xFFFFFFFF, 0xFFFFFFFB, 0xFFFFFFFC
    for i, mlen in enumerate((0xFFFFFFFF, 0xFFFFFFFB, 0xFFFFFFFC)):
        body = b'\x00' + struct.pack('>I', mlen) + b'\x08\x01\x10\x02\x18\x03'
        M.append(tcpseg('10.0.0.1', '10.0.0.2', 42000 + i, 80, 1000, 1, 0x18, http_req(PATH, b'application/grpc-web', body)))
    # truncated header, message longer than the body
    for i, body in enumerate((b'\x00\x00\x00', b'\x00\x00\x00\x00\x10abc', msg(REQ) + b'\x00\x00')):
        M.append(tcpseg('10.0.0.1', '10.0.0.2', 42010 + i, 80, 1000, 1, 0x18, http_req(PATH, b'application/grpc-web', body)))
    # HTTP/2 (fake headers, streams 21-29): truncated and invalid messages
    c = H2(H, 42020)
    c.c(h2frame(0, 1, 21, msg(REQ)[:-3]))
    c.c(h2frame(0, 1, 23, b'\x00\x00\x00'))
    c.c(h2frame(0, 1, 25, b'\x00' + struct.pack('>I', 0xFFFFFFFF) + b'abc'))
    c.c(h2frame(0, 1, 27, msg(b'not gzip data', 1)))
    c.c(h2frame(0, 1, 29, msg(gzip.compress(REQ)[:12], 1)))
    for sid in (21, 23, 25):
        uat.append(('50051', str(sid), 'IN', ':path', PATH.decode()))
    for sid in (21, 23, 25, 27, 29):
        uat.append(('50051', str(sid), 'IN', 'content-type', 'application/grpc'))
    for sid in (27, 29):
        uat.append(('50051', str(sid), 'IN', ':path', PATH.decode()))
        uat.append(('50051', str(sid), 'IN', 'grpc-encoding', 'gzip'))
    # grpc-web-text with invalid base64
    http1(M, 42030, [(http_req(PATH, b'application/grpc-web-text', b'!!!!not base64!!!!'), http_resp(b'application/grpc-web-text', b'====')),
                     (http_req(PATH, b'application/grpc-web-text', base64.b64encode(b'\x00\x00\x00\x00\x09abc')), http_resp(b'application/grpc-web-text', b''))])
    # gRPC-Web trailers with a truncated header
    http1(M, 42040, [(http_req(PATH, b'application/grpc-web', bytes([0x80, 0, 0])), http_resp(b'application/grpc-web', bytes([0x80, 0, 0, 0, 200]) + b'abc'))])

    with open(outdir + '/http2_fake_headers.txt', 'w') as f:
        # one -o uat:http2_fake_headers: argument per line (server port, stream, direction, name, value, override, enable)
        for u in uat:
            f.write('uat:http2_fake_headers:"%s","%s","%s","%s","%s","FALSE","TRUE"\n' % u)
    pcap(outdir + '/grpc-coverage.pcap', F)
    pcap(outdir + '/grpc-coverage-h2.pcap', H)
    pcap(outdir + '/grpc-coverage-malformed.pcap', M)
    for n, s in marks:
        print(n, s)
    print(len(F), 'frames;', len(M), 'malformed')

main(sys.argv[1])
