#!/usr/bin/env python3
# Generates test/captures/resp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic RESP (REdis Serialization Protocol) captures.
# Usage: mkresp.py <outdir> [-v]    (-v prints the frame ranges)
# Writes resp-coverage.pcap and resp-coverage-malformed.pcap
import struct
import sys
import os

CLI = bytes([192, 0, 2, 10]); SRV = bytes([192, 0, 2, 20])
ETH = b'\x02\x00\x00\x00\x00\x02' + b'\x02\x00\x00\x00\x00\x01' + b'\x08\x00'

def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

class Cap:
    def __init__(self): self.frames = []; self.ipid = 1
    def tcp(self, sport, dport, seq, ack, flags, payload, src, dst, snap=None):
        tcp = struct.pack('!HHIIBBHHH', sport, dport, seq & 0xffffffff, ack & 0xffffffff,
                          5 << 4, flags, 65535, 0, 0)
        ph = src + dst + struct.pack('!BBH', 0, 6, len(tcp) + len(payload))
        tcp = tcp[:16] + struct.pack('!H', csum(ph + tcp + payload)) + tcp[18:]
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp) + len(payload),
                         self.ipid, 0, 64, 6, 0, src, dst)
        self.ipid += 1
        ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
        pkt = ETH + ip + tcp + payload
        self.frames.append((pkt, snap))
    def write(self, path):
        with open(path, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            for i, (p, snap) in enumerate(self.frames):
                c = p if snap is None else p[:snap]
                f.write(struct.pack('<IIII', 1 + i // 4, 250000 * (i % 4), len(c), len(p)) + c)

class Conn:
    '''One TCP connection client -> server port 6379.'''
    def __init__(self, cap, cport, handshake=True):
        self.cap = cap; self.cport = cport; self.cseq = 1000; self.sseq = 5000
        if handshake:
            cap.tcp(cport, 6379, self.cseq, 0, 0x02, b'', CLI, SRV); self.cseq += 1
            cap.tcp(6379, cport, self.sseq, self.cseq, 0x12, b'', SRV, CLI); self.sseq += 1
            cap.tcp(cport, 6379, self.cseq, self.sseq, 0x10, b'', CLI, SRV)
    def req(self, *datas, snap=None):
        for d in datas:
            self.cap.tcp(self.cport, 6379, self.cseq, self.sseq, 0x18, d, CLI, SRV, snap)
            self.cseq += len(d)
    def rsp(self, *datas):
        for d in datas:
            self.cap.tcp(6379, self.cport, self.sseq, self.cseq, 0x18, d, SRV, CLI)
            self.sseq += len(d)

def bulk(b): return b'$%d\r\n%s\r\n' % (len(b), b)
def cmd(*args): return b'*%d\r\n' % len(args) + b''.join(bulk(a) for a in args)
def vb(enc, val): v = enc + b':' + val; return b'=%d\r\n%s\r\n' % (len(v), v)

def build():
    mark = []          # (name, first frame, last frame)
    cap = Cap()
    def sect(name, fn):
        a = len(cap.frames) + 1; fn(); mark.append((name, a, len(cap.frames)))
    port = [40000]
    def conn(**kw):
        port[0] += 1; return Conn(cap, port[0], **kw)

    # ---- RESP2 commands and replies
    def resp2():
        c = conn()
        c.req(cmd(b'SET', b'key', b'value')); c.rsp(b'+OK\r\n')
        c.req(cmd(b'GET', b'key')); c.rsp(bulk(b'value'))
        c.req(cmd(b'INCR', b'counter')); c.rsp(b':1000\r\n')
        c.req(cmd(b'GET', b'missing')); c.rsp(b'$-1\r\n')
        c.req(cmd(b'GET', b'empty')); c.rsp(b'$0\r\n\r\n')
        c.req(cmd(b'LRANGE', b'l', b'0', b'-1'))
        c.rsp(b'*3\r\n' + bulk(b'a') + b':2\r\n' + b'*2\r\n+x\r\n-ERR inner\r\n')
        c.req(cmd(b'BLPOP', b'nolist', b'1')); c.rsp(b'*-1\r\n')
        c.req(cmd(b'SMEMBERS', b'none')); c.rsp(b'*0\r\n')
        c.req(cmd(b'BAD')); c.rsp(b'-ERR unknown command\r\n')
        # pipelined: three commands in one segment, three replies in one
        c.req(cmd(b'PING') + cmd(b'ECHO', b'hi') + cmd(b'DEL', b'a', b'b'))
        c.rsp(b'+PONG\r\n' + bulk(b'hi') + b':2\r\n')
        # a one-character string, an empty element, and a long string
        c.req(cmd(b'SET', b'x', b'y')); c.rsp(b'+OK\r\n')
        c.req(cmd(b'SET', b'e', b'')); c.rsp(b'+OK\r\n')
        c.req(cmd(b'SET', b'long', b'L' * 150)); c.rsp(b'+OK\r\n')
        c.req(cmd(b'GET', b'long')); c.rsp(bulk(b'L' * 150))
        # binary (non ASCII) data
        c.req(cmd(b'SET', b'bin', b'\x01\xff\xfe\x80')); c.rsp(b'+OK\r\n')
        c.req(cmd(b'GET', b'bin')); c.rsp(bulk(b'\x80\x81'))
        # strings that look like JSON
        c.req(cmd(b'JSON.SET', b'doc', b'$', b'{"a":[1,2,{"b":null}],"c":"d"}'))
        c.rsp(b'+OK\r\n')
        c.req(cmd(b'RPUSH', b'l', b'[1,2,3]', b'{ not json}', b'{open', b'[x', b'{'))
        c.rsp(b':5\r\n')
        c.req(cmd(b'GET', b'doc')); c.rsp(bulk(b'{"a":1}'))
        # an unknown type byte, a bare CRLF, an inline command
        c.rsp(b'?what\r\n')
        c.rsp(b'\r\n')
        c.req(b'PING\r\n')
    sect('RESP2 commands and replies', resp2)

    # ---- reassembly
    def reasm():
        c = conn()
        full = cmd(b'SET', b'k', b'v' * 300)
        c.req(full[:20], full[20:60], full[60:])                # split in the bulk string
        c.rsp(b'+OK\r\n')
        c.req(b'*3\r\n')                                         # only the array header
        c.req(cmd(b'MSET', b'a', b'1')[4:])                      # (rest of the elements)
        c.rsp(b'+OK\r\n')
        c.req(b'*2\r\n$3\r\nGE', b'T\r\n$1\r\nk\r\n')            # split inside a line
        c.rsp(b'$3\r\nv', b'al\r\n')                            # bulk string split
        c.rsp(b'*2\r\n$1\r\na\r\n', b'$1\r\nb\r\n')              # split between elements
        c.rsp(b'*2\r\n*1\r\n', b':1\r\n:2\r\n')                  # nested array split
        c.rsp(b'%2\r\n+a\r\n', b':1\r\n+b\r\n:2\r\n')            # map split between entries
        c.rsp(b'%2\r\n+a\r\n:1\r\n+b', b'\r\n:2\r\n')            # map split inside an entry line
        c.rsp(b'%1\r\n', b'+a\r\n:1\r\n')                        # map header only
        c.rsp(b'%1\r\n$5\r\nhel', b'lo\r\n:1\r\n')                 # map key split
        c.rsp(b'%1\r\n+a\r\n$5\r\nhel', b'lo\r\n')                 # map value split
        c.rsp(b'=15\r\ntxt:Som', b'e string\r\n')                # verbatim split
        c.rsp(b'*1\r\n=15\r\ntxt:Som', b'e string\r\n')
        c.rsp(b'*1\r\n', b'$300\r\n' + b'x' * 300 + b'\r\n')
        c.rsp(b'+OK', b'\r\n')
        c.rsp(b'$10\r\n01234', b'56789\r\n')                    # a result then the next reply
        c.rsp(b'+AFTER\r\n')
    sect('Reassembly over TCP segments', reasm)

    # ---- RESP3
    def resp3():
        c = conn()
        c.req(cmd(b'HELLO', b'3'))
        c.rsp(b'%3\r\n+server\r\n+redis\r\n+version\r\n+7.2.0\r\n+proto\r\n:3\r\n')
        c.req(cmd(b'GET', b'k')); c.rsp(b'_\r\n')
        c.rsp(b'#t\r\n#f\r\n')                                   # booleans
        c.rsp(b',3.14159\r\n,-2\r\n,inf\r\n,-inf\r\n,nan\r\n,1.5e3\r\n')
        c.rsp(b'(3492890328409238509324850943850943825024385\r\n(-12\r\n(+7\r\n')
        c.rsp(b'(1\r\n')
        c.rsp(vb(b'txt', b'Some string'))
        c.rsp(vb(b'mkd', b'# Heading'))
        c.rsp(vb(b'txt', b''))                                   # empty value
        c.rsp(b'=3\r\ntxt\r\n')                                  # shorter than "xxx:"
        c.rsp(b'=0\r\n\r\n')
        c.rsp(vb(b'txt', b'\xe2\x82\xac'))                       # non ASCII value
        c.rsp(vb(b'txt', b'z' * 200))
        c.rsp(b'!21\r\nSYNTAX invalid syntax\r\n')
        c.rsp(b'!0\r\n\r\n')
        c.rsp(b'!-1\r\n')
        c.rsp(b'!4\r\n\xff\xfe\xfd\xfc\r\n')
        c.rsp(b'~3\r\n+a\r\n+b\r\n:3\r\n')
        c.rsp(b'~0\r\n~-1\r\n')
        c.rsp(b'>3\r\n+message\r\n+chan\r\n+payload\r\n')
        c.rsp(b'>0\r\n')
        c.rsp(b'%2\r\n+first\r\n:1\r\n+second\r\n%1\r\n+nested\r\n~2\r\n:1\r\n:2\r\n')
        c.rsp(b'|1\r\n+key-popularity\r\n%2\r\n$1\r\na\r\n,0.1923\r\n$1\r\nb\r\n,0.0012\r\n')
        c.rsp(b'|0\r\n%0\r\n')
        c.rsp(b'*3\r\n:1\r\n:2\r\n:3\r\n')
        c.req(cmd(b'SMEMBERS', b's'))
        # RESP3 types in requests (depth 1 verbatim, bulk string with JSON)
        c.req(b'*3\r\n' + vb(b'txt', b'{"v":[1,2]}') + vb(b'txt', b'[1]') + vb(b'txt', b'x' * 120))
        c.req(b'*1\r\n' + b'=4\r\ntxt:\r\n')
        c.req(b'*2\r\n' + b'=3\r\ntxt\r\n' + b'!5\r\nERROR\r\n')
        c.req(b'~2\r\n' + bulk(b'a') + bulk(b'b'))
        c.req(b'>1\r\n' + bulk(b'{"x":1}'))
        c.req(b'%1\r\n' + bulk(b'k') + bulk(b'[1,2]'))
    sect('RESP3 types', resp3)

    # ---- recursion limit
    def deep():
        c = conn()
        c.rsp(b'*1\r\n' * 33 + b':1\r\n')
        c.rsp(b'%1\r\n+k\r\n' * 33 + b':1\r\n')
        c.rsp(b'*1\r\n' * 5 + b':1\r\n')
    sect('Nesting past the recursion limit', deep)

    # ---- reproducers of the fixed bugs
    def repro():
        c = conn(handshake=False)
        payload = b'*1\r\n$1000000000\r\n{abc'
        c.req(payload + b'}' * 100)
        cap.frames[-1] = (cap.frames[-1][0], len(cap.frames[-1][0]) - 100)
        c = conn(handshake=False)
        c.req(b'*1\r\n' + vb(b'txt', b'{"a":1}'))
        c = conn(handshake=False)
        c.req(b'*1\r\n' + vb(b'txt', b'[1]'))
        c.req(b'*1\r\n=2\r\ntx\r\n')
    sect('Reproducers (RESP: Fix an out-of-bounds read in the JSON detection)', repro)
    return cap, mark

def build_malformed():
    cap = Cap(); port = [41000]
    def conn(**kw):
        port[0] += 1; return Conn(cap, port[0], **kw)
    def trunc(data, cut):
        c = conn(handshake=False); c.req(data)
        if cut:
            cap.frames[-1] = (cap.frames[-1][0], len(cap.frames[-1][0]) - cut)
    trunc(b'*2\r\n$3\r\nGET\r\n$5\r\nhello\r\n', 5)
    trunc(b'*2\r\n$3\r\nGET\r\n$5\r\nhello\r\n', 2)
    trunc(b'*1\r\n=15\r\ntxt:Some string\r\n', 6)
    trunc(b'*1\r\n=15\r\ntxt:{ab}xxxxxx\r\n', 12)
    trunc(b'*1\r\n=15\r\ntxt:\r\n', 3)
    trunc(b'*1\r\n=5\r\nxy\r\n', 3)
    trunc(b'*1\r\n$20\r\n{12345}\r\n', 10)
    trunc(b'*1\r\n$20\r\n[12345]\r\n', 10)
    trunc(b'*3\r\n:1\r\n:2\r\n', 0)
    trunc(b'%2\r\n+a\r\n:1\r\n', 0)
    trunc(b'*5\r\n', 0)
    trunc(b'%5\r\n', 0)
    trunc(b'*1\r\n!10\r\nabc\r\n', 4)
    trunc(b'*1\r\n$2147483647\r\n{x\r\n', 0)
    trunc(b'*1\r\n=2147483647\r\ntxt:{x\r\n', 0)
    trunc(b'*1\r\n=4\r\n{}}}\r\n', 0)
    # malformed lengths and values (all complete, nothing is cut)
    for d in (b'*-5\r\n', b'$-7\r\n', b'$-99999999999999999999\r\n', b'=-1\r\n', b'!-3\r\n',
              b'%-2\r\n', b'|-1\r\n', b'_x\r\n', b'#x\r\n', b'(x12\r\n', b'(12x3\r\n',
              b'(\r\n', b'~-4\r\n', b'>-1\r\n'):
        c = conn(handshake=False); c.rsp(d)
    # a declared length of about 2^31 and more: the clamped length wants more data
    for d in (b'$99999999999999\r\nabc', b'=2147483647\r\ntxt:{ab', b'!3000000000\r\nabc'):
        c = conn(handshake=False); c.rsp(d)
    return cap

if __name__ == '__main__':
    out = sys.argv[1]
    cap, mark = build()
    cap.write(os.path.join(out, 'resp-coverage.pcap'))
    build_malformed().write(os.path.join(out, 'resp-coverage-malformed.pcap'))
    if '-v' in sys.argv:
        for n, a, b in mark: print('%4d-%4d  %s' % (a, b, n))
        print(len(cap.frames), 'frames')
