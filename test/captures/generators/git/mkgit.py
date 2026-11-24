#!/usr/bin/env python3
# Generates test/captures/git_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic captures for packet-git.c.  Usage: mkgit.py <outdir> [-v]"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import util as u

def pkt(data, upper=False):
    if isinstance(data, str):
        data = data.encode()
    h = b'%04x' % (len(data) + 4)
    return h.upper() if upper else h

def pl(data, upper=False):
    if isinstance(data, str):
        data = data.encode()
    return pkt(data, upper) + data

FLUSH = b'0000'; DELIM = b'0001'; RESPEND = b'0002'

def http_resp(ctype, body, extra=b''):
    return (b'HTTP/1.1 200 OK\r\nContent-Type: ' + ctype + b'\r\n' + extra +
            b'Content-Length: %d\r\n\r\n' % len(body)) + body

def http_post(path, ctype, body):
    return (b'POST ' + path + b' HTTP/1.1\r\nHost: git.example.test\r\n'
            b'Content-Type: ' + ctype + b'\r\nContent-Length: %d\r\n\r\n' % len(body)) + body

ADV = b'application/x-git-upload-pack-advertisement'
REQ = b'application/x-git-upload-pack-request'
RES = b'application/x-git-upload-pack-result'
OID1 = b'a' * 40
OID2 = b'0123456789abcdef' * 2 + b'01234567'

def main_frames():
    out = []
    # --- git:// protocol v2 session (TCP 9418)
    c = u.Conn(out, 40000, 9418)
    c.send(pl(b'git-upload-pack /project.git\0host=git.example.test\0\0version=2\0'))
    c.recv(pl(b'version 2\n') + pl(b'agent=git/2.40.0\n') + pl(b'ls-refs=unborn\n') +
           pl(b'fetch=shallow wait-for-done\n') + pl(b'server-option\n') +
           pl(b'object-format=sha1\n') + FLUSH)
    c.send(pl(b'command=ls-refs\n') + pl(b'agent=git/2.40.0\n') + DELIM +
           pl(b'peel\n') + pl(b'symrefs\n') + pl(b'ref-prefix refs/heads/\n') + FLUSH)
    c.recv(pl(OID1 + b' HEAD symref-target:refs/heads/main\n') +
           pl(OID1 + b' refs/heads/main\n') + FLUSH)
    c.send(pl(b'command=fetch\n') + DELIM + pl(b'thin-pack\n') + pl(b'no-progress\n') +
           pl(b'ofs-delta\n') + pl(b'want ' + OID1 + b'\n') + pl(b'done\n') + FLUSH)
    # response: packfile section with sideband, response-end
    c.recv(pl(b'packfile\n') + pl(b'\x02Enumerating objects: 3, done.\n') +
           pl(b'\x01PACK\0\0\0\x02\0\0\0\x03abcdefgh') +
           pl(b'\x03fatal: demo error\n') + pl(b'\x01' + b'\x00' * 20) + FLUSH + RESPEND)
    # empty pkt-line, "version" with exact boundaries, first byte 0 and 4
    c.send(b'0004' + pl(b'version 1') + pl(b'version ') + pl(b'version 1\n') +
           pl(b'\x00zero') + pl(b'\x04four') + pl(b'\x01') + FLUSH)
    # uppercase hex digits
    c.send(pl(b'x' * 300, upper=True))
    # a pkt-line split over three TCP segments (reassembly)
    big = pl(b'\x01' + bytes(range(256)) * 3)
    c.ssegs(big + FLUSH, 300)
    # several pkt-lines in one segment followed by one that starts in the next
    two = pl(b'one\n') + pl(b'two\n')
    nxt = pl(b'three three three three\n')
    c.send(two + nxt[:10], psh=False)
    c.send(nxt[10:] + FLUSH)
    # the length field itself split over segments
    p4 = pl(b'split length\n')
    c.send(p4[:2], psh=False)
    c.send(p4[2:])
    c.fin()
    # --- git:// protocol v1 session on a second connection
    c = u.Conn(out, 40001, 9418, caddr='192.0.2.5')
    c.send(pl(b'git-upload-pack /old.git\0host=git.example.test\0'))
    c.recv(pl(b'version 1\n') + pl(OID2 + b' HEAD\0multi_ack thin-pack side-band side-band-64k ofs-delta\n') +
           pl(OID2 + b' refs/heads/master\n') + FLUSH)
    c.send(pl(b'want ' + OID2 + b' multi_ack side-band-64k\n') + FLUSH + pl(b'done\n'))
    c.recv(pl(b'NAK\n') + pl(b'\x01PACK-data') + pl(b'\x02Counting objects\n') + FLUSH)
    c.fin()
    # --- smart HTTP, one connection per exchange
    # advertisement
    h = u.Conn(out, 41000, 80)
    h.send(b'GET /project.git/info/refs?service=git-upload-pack HTTP/1.1\r\nHost: git.example.test\r\n\r\n')
    body = (pl(b'# service=git-upload-pack\n') + FLUSH + pl(b'version 2\n') + pl(b'agent=git/2.40.0\n') +
            pl(b'ls-refs\n') + FLUSH)
    h.recv(http_resp(ADV, body))
    # request
    body = pl(b'command=ls-refs\n') + DELIM + pl(b'peel\n') + FLUSH
    h.send(http_post(b'/project.git/git-upload-pack', REQ, body))
    # result with sideband data, empty pkt-line (reproducer of the fix),
    # delimiter, response end
    body = (b'0004' + pl(b'\x01data1') + pl(b'\x02progress\n') + pl(b'\x03error\n') + DELIM +
            b'0004' + pl(b'\x01\x01') + pl(b'plain text') + FLUSH + RESPEND)
    h.recv(http_resp(RES, body))
    # the reproducer from the review: empty pkt-line followed by a sideband byte 1..3
    body = b'0004' + b'0009\x01abcd' + b'0000'
    h.recv(http_resp(RES, body))
    # result carried in a segmented body (HTTP reassembly)
    body = pl(b'\x01' + bytes(range(256)) * 2) + pl(b'\x02done\n') + FLUSH
    resp = http_resp(RES, body)
    h.ssegs(resp, 400)
    # lone empty pkt-line as a whole body
    h.recv(http_resp(RES, b'0004'))
    h.fin()
    # a HTTP/1.0 style server reply with a charset parameter on the type
    h = u.Conn(out, 41001, 80, caddr='192.0.2.6')
    h.send(http_post(b'/project.git/git-upload-pack', REQ + b'; charset=utf-8',
                     pl(b'want ' + OID1 + b'\n') + FLUSH))
    h.recv(http_resp(RES, pl(b'NAK\n') + pl(b'\x01PACK') + FLUSH))
    h.fin()
    return out

def mal_frames():
    out = []
    # git:// with unrecognised special pkt-len 0003 and a non-hex length
    c = u.Conn(out, 42000, 9418)
    c.send(b'0003')
    c.send(b'zzzz' + b'garbage')
    c.send(pl(b'ok\n') + b'0003' + FLUSH)
    # HTTP bodies with trouble part-way through
    h = u.Conn(out, 42001, 80)
    h.recv(http_resp(RES, pl(b'\x01data') + b'0003' + FLUSH))
    h.recv(http_resp(RES, pl(b'\x01data') + b'zz!!' + b'more'))
    h.recv(http_resp(RES, pl(b'a') + b'00ff' + b'short'))     # pkt-line longer than the body
    h.recv(http_resp(ADV, b'00'))                              # shorter than a length
    h.recv(http_resp(ADV, b'0004' + b'0000' + b'0001' + b'0002' + b'0003'))
    # pkt-line cut in the git:// stream: length but data never arrives, then FIN
    c = u.Conn(out, 42002, 9418)
    c.send(b'0100' + b'abc')
    c.fin()
    return out

if __name__ == '__main__':
    o = sys.argv[1]
    os.makedirs(o, exist_ok=True)
    m = main_frames()
    u.write_pcap(os.path.join(o, 'git-coverage.pcap'), m)
    u.gz(os.path.join(o, 'git-coverage.pcap'))
    mm = mal_frames()
    u.write_pcap(os.path.join(o, 'git-coverage-malformed.pcap'), mm)
    if '-v' in sys.argv:
        print(len(m), len(mm))
