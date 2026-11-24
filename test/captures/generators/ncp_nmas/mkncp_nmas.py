#!/usr/bin/env python3
# Generates test/captures/ncp_nmas_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# NMAS (packet-ncp-nmas.c) synthetic capture generator. Python struct only; all addresses are made up.
import struct
import sys
import os
import gzip

def _csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def ipv4(src, dst, proto, payload, ident=1):
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0, 64, proto, 0,
                     bytes(src), bytes(dst))
    ip = ip[:10] + struct.pack('!H', _csum(ip)) + ip[12:]
    return ip + payload

def eth(payload, src=2, dst=1, etype=0x0800):
    return bytes([2, 0, 0, 0, 0, dst]) + bytes([2, 0, 0, 0, 0, src]) + struct.pack('!H', etype) + payload

def udp(src, dst, sport, dport, payload, srcmac=2, dstmac=1):
    u = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    return eth(ipv4(src, dst, 17, u), srcmac, dstmac)

def tcp(src, dst, sport, dport, seq, ack, payload, flags=0x18, srcmac=2, dstmac=1):
    opts = b'\x02\x04\x05\xb4' if flags & 0x02 else b''   # MSS on SYN and SYN-ACK
    t = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts + payload
    return eth(ipv4(src, dst, 6, t), srcmac, dstmac)

A = [10, 0, 0, 1]
B = [10, 0, 0, 2]

class Stream:
    '''One TCP connection: A (client, MAC 2) to B (server, MAC 1).'''
    def __init__(self, frames, cport, sport, handshake=True):
        self.f = frames
        self.cp, self.sp = cport, sport
        self.cs, self.ss = 1000, 5000
        if handshake:
            frames.append(tcp(A, B, cport, sport, self.cs, 0, b'', 0x02))
            frames.append(tcp(B, A, sport, cport, self.ss, self.cs + 1, b'', 0x12, 1, 2))
            self.cs += 1; self.ss += 1
            frames.append(tcp(A, B, cport, sport, self.cs, self.ss, b'', 0x10))
    def c(self, data):
        self.f.append(tcp(A, B, self.cp, self.sp, self.cs, self.ss, data, 0x18))
        self.cs += len(data)
    def s(self, data):
        self.f.append(tcp(B, A, self.sp, self.cp, self.ss, self.cs, data, 0x18, 1, 2))
        self.ss += len(data)

def write_pcap(name, frames, linktype=1):
    with open(name, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, fr in enumerate(frames):
            t = 1700000000 + i // 1000
            f.write(struct.pack('<IIII', t, (i % 1000) * 1000, len(fr), len(fr)))
            f.write(fr)

def gz(name):
    with open(name, 'rb') as f, gzip.GzipFile(name + '.gz', 'wb', mtime=0) as g:
        g.write(f.read())

IPX_NCP_SOCKET = 0x0451
CONN, TASK = 5, 1

def nhdr(typ, seq, conn=CONN, task=TASK):
    return struct.pack('!HBBBB', typ, seq, conn & 0xff, task, conn >> 8)

def nrep(seq, data=b'', code=0, status=0, conn=CONN, task=TASK):
    return nhdr(0x3333, seq, conn, task) + bytes([code, status]) + data

frames = []
def u(payload, sport=1024, dport=524, to_server=True):
    if to_server:
        frames.append(udp(A, B, sport, dport, payload))
    else:
        frames.append(udp(B, A, dport, sport, payload, 1, 2))

# ---- NMAS: NCP function 0x5e. Request: header, func, subfunc, body.
# subfunc 1 ping, 2 fragment (handle 0xffffffff: a complete message with a
# sub verb), 3 abort. The reply is matched to the request by the NCP
# dissector (connection and sequence) and uses the sub verb that the request
# stored.
NONE = 0xffffffff

def req(seq, subfunc, body=b''):
    return nhdr(0x2222, seq) + bytes([0x5e, subfunc]) + body

def frag(seq, subverb, body=b'', length=None, handle=NONE, ctx=bytes(12)):
    if length is None:
        length = 16 + 4 + len(body)
    return req(seq, 2, struct.pack('<III', handle, 64, length) + ctx + struct.pack('<I', subverb) + body)

def rep(seq, body=b'', **k):
    return nrep(seq, body, **k)

def frep(seq, rc=0, body=b'', length=None, handle=NONE):
    if length is None:
        length = 8 + len(body)
    return rep(seq, struct.pack('<III', length, handle, rc) + body)

state = {'seq': 0}
def pair(request, reply):
    state['seq'] += 1
    s = state['seq']
    u(request(s))
    if reply is not None:
        u(reply(s), to_server=False)

def lstr(s, nul=True):
    '''Length-prefixed string: little endian length, optional NUL.'''
    if isinstance(s, str):
        s = s.encode()
    if nul:
        s += b'\0'
    return struct.pack('<I', len(s)) + s

def bstr(s):
    s = s.encode() if isinstance(s, str) else s
    return struct.pack('>I', len(s)) + s

ERR_NOT_FOUND = 0xFFFFF99A
ERR_LOGIN_FAILED = 0xFFFFF996
ERR_BAD_SYNTAX = 0xFFFFF9A0

# --- ping and abort (an unknown subfunction has no NCP definition and is not NMAS)
pair(lambda s: req(s, 1, struct.pack('<II', 2, 0)), lambda s: rep(s, struct.pack('<II', 0, 3)))
pair(lambda s: req(s, 1, struct.pack('<II', 1, 0x80)), lambda s: rep(s))          # reply too short to decode
pair(lambda s: req(s, 3), lambda s: rep(s, struct.pack('<I', 0)))
pair(lambda s: req(s, 3), lambda s: rep(s))

# --- fragment with a handle (a continuation, no sub verb)
pair(lambda s: req(s, 2, struct.pack('<I', 0x1234) + bytes(20)),
     lambda s: rep(s, struct.pack('<II', 16, 0x1234) + bytes(8)))

# --- fragmented ping (sub verb 0)
pair(lambda s: frag(s, 0, struct.pack('<II', 2, 0)),
     lambda s: frep(s, 0, struct.pack('>I', 0xcafe0001)))
pair(lambda s: frag(s, 0, struct.pack('<II', 2, 0)), lambda s: frep(s, 0))         # nothing after the return code

# --- client put data (2): opaque data; reply with the queue sizes
pair(lambda s: frag(s, 2, bytes(range(32))),
     lambda s: frep(s, 0, struct.pack('<II', 1500, 0)))

# --- client get data (4) and credentials (6)
pair(lambda s: frag(s, 4), lambda s: frep(s, 0, b'get data reply payload'))
pair(lambda s: frag(s, 6),
     lambda s: frep(s, 0, struct.pack('<III', 1, 2, 3) + b'enc credential bytes'))

# --- login store management (8): every login store verb and an unknown one
for v in (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 99):
    pair(lambda s, v=v: frag(s, 8, struct.pack('<I', 4096) + bytes([v, 0, 0, 0]) + b'login store payload'),
         lambda s: frep(s, 0, b'encrypted data of a login store message'))

# --- writable object check (10): strings with NULs, a non-printable byte,
# an empty string; the reply carries the version
pair(lambda s: frag(s, 10, bytes(12) + lstr('ACME_TREE') + lstr('cn=admin.o=acme')),
     lambda s: frep(s, 0, struct.pack('<I', 0x201)))
pair(lambda s: frag(s, 10, bytes(12) + lstr(b'tr\x01ee', False) + lstr(b'')),
     lambda s: frep(s, 0, struct.pack('<I', 0x201)))
pair(lambda s: frag(s, 10, bytes(12) + lstr(b'', False) + lstr('user', False)),
     lambda s: frep(s, 0, struct.pack('<I', 0x201)))

# --- message handler (1242): the message verb (echo, start session, client
# write, client read, end session, unknown) in the request and the reply
def mh(verb, body=b'', ver=0x00010000, sess=0x11223344):
    return bytes(4) + struct.pack('>II', ver, sess) + bytes(3) + bytes([verb]) + body

echo = b'echo this data'
pair(lambda s: frag(s, 1242, mh(1, bstr(echo))),
     lambda s: rep(s, struct.pack('<III', 8 + 4 + len(echo), NONE, 0) + bstr(echo)))
# start session: attributes user (1), tree (2), clearance (4), login sequence (11);
# the string lengths are subtracted from the message length
def attrs(items):
    return b''.join(struct.pack('>I', a) + bstr(v) for a, v in items)
A4 = [(1, 'admin'), (2, 'TREE'), (4, 'clr'), (11, 'seq')]
body = attrs(A4)
pair(lambda s: frag(s, 1242, mh(3, struct.pack('>I', 4 + len(body)) + body)),
     lambda s: frep(s, 0, struct.pack('>I', 0xdeadbeef)))
# the length ends the loop while data follows
body = attrs([(1, 'ab'), (2, 'cd')])
pair(lambda s: frag(s, 1242, mh(3, struct.pack('>I', 4 + 4) + body + b'tail-bytes')),
     lambda s: frep(s, 0, struct.pack('>I', 0xdeadbeef)))
# length 4: no attributes
pair(lambda s: frag(s, 1242, mh(3, struct.pack('>I', 4))),
     lambda s: frep(s, 0, struct.pack('>I', 1)))
# an unknown attribute type is skipped, the loop goes on with the next four bytes
body = struct.pack('>I', 99) + attrs([(1, 'x')])
pair(lambda s: frag(s, 1242, mh(3, struct.pack('>I', 4 + 1 + 1) + body)),
     lambda s: frep(s, 0, struct.pack('>I', 1)))
pair(lambda s: frag(s, 1242, mh(5, b'client write payload bytes')), lambda s: frep(s, 0, b'ok'))
pair(lambda s: frag(s, 1242, mh(7)), lambda s: frep(s, 0, bytes(8)))             # client read; reply: unknown payload error
pair(lambda s: frag(s, 1242, mh(7)), lambda s: frep(s, 0, struct.pack('>I', ERR_LOGIN_FAILED)))
pair(lambda s: frag(s, 1242, mh(7)), lambda s: frep(s, 0, struct.pack('>I', 0xFFFFF963)))
pair(lambda s: frag(s, 1242, mh(9)), lambda s: frep(s, 0, bytes(4)))
pair(lambda s: frag(s, 1242, mh(2, b'unknown message verb')), lambda s: frep(s, 0, b'data'))
pair(lambda s: frag(s, 1242, mh(5, b'x')), lambda s: frep(s, 0, b'data'))
pair(lambda s: frag(s, 1242, mh(5, b'x')), lambda s: frep(s, 0))

# --- sub verb that is no known verb
pair(lambda s: frag(s, 12, b'unknown sub verb'), lambda s: frep(s, 0, b'unknown'))
# --- a fragment of an NMAS message (handle is not -1): reply too
pair(lambda s: frag(s, 2, bytes(8), handle=7), lambda s: frep(s, 0, handle=7))

# --- error return codes: known, unknown, success
for sv in (0, 2, 4, 6, 8, 1242):
    pair(lambda s, sv=sv: frag(s, sv, struct.pack('<I', 4096) + bytes([1, 0, 0, 0]) if sv == 8 else (mh(1, bstr(b'x')) if sv == 1242 else struct.pack('<II', 2, 0) if sv == 0 else b'')),
         lambda s: frep(s, ERR_NOT_FOUND, b'ignored data'))
pair(lambda s: frag(s, 4), lambda s: frep(s, ERR_BAD_SYNTAX))
pair(lambda s: frag(s, 4), lambda s: frep(s, 0x12345678, b'data'))

main = frames
frames = []

# ---- malformed
state['seq'] = 100
# request cut inside the header
u(req(101, 2, struct.pack('<I', NONE) + bytes(10)))
# writable object check: string longer than the label limit (the item runs past the packet)
pair(lambda s: frag(s, 10, bytes(12) + struct.pack('<I', 5000) + b'A' * 40), lambda s: frep(s, 0, struct.pack('<I', 1)))
# writable object check: second string missing
pair(lambda s: frag(s, 10, bytes(12) + lstr('tree')), None)
# message handler echo: length longer than the data
pair(lambda s: frag(s, 1242, mh(1, struct.pack('>I', 500) + b'short')), None)
# start session with a string that runs past the packet
pair(lambda s: frag(s, 1242, mh(3, struct.pack('>I', 100) + struct.pack('>II', 1, 200) + b'abc')), None)
# start session with a length smaller than the strings (the count wraps)
pair(lambda s: frag(s, 1242, mh(3, struct.pack('>I', 2) + attrs([(1, 'ab'), (2, 'cd')]))), None)
# replies cut short
pair(lambda s: frag(s, 6), lambda s: rep(s, struct.pack('<II', 40, NONE)))
pair(lambda s: frag(s, 6), lambda s: frep(s, 0, struct.pack('<III', 1, 2, 3), length=8 + 3))
pair(lambda s: frag(s, 1242, mh(1, bstr(b'x'))), lambda s: frep(s, 0, struct.pack('>I', 900) + b'tiny'))
pair(lambda s: frag(s, 1242, mh(3, struct.pack('>I', 4))), lambda s: frep(s, 0, b'\0\0'))
pair(lambda s: frag(s, 2, b'x'), lambda s: frep(s, 0, b'x', length=3))
pair(lambda s: frag(s, 4), lambda s: frep(s, 0, b'data', length=2))

if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'ncp-nmas-coverage.pcap'), main)
    gz(os.path.join(out, 'ncp-nmas-coverage.pcap'))
    os.rename(os.path.join(out, 'ncp-nmas-coverage.pcap.gz'), os.path.join(out, 'ncp_nmas_coverage.pcap.gz'))
    write_pcap(os.path.join(out, 'ncp-nmas-coverage-malformed.pcap'), frames)
