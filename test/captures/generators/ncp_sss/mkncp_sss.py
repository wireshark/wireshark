#!/usr/bin/env python3
# Generates test/captures/ncp_sss_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# SecretStore (packet-ncp-sss.c) synthetic capture generator. Python struct only; all addresses are made up.
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

# ---- SecretStore (NSSS): NCP function 0x5c. Request: header, func, subfunc, body.
# subfunc 1 ping, 2 fragment (handle 0xffffffff: a complete message with a
# verb), 3 abort. The NCP dissector matches the reply to the request
# (connection and sequence); the reply uses the verb the request stored.
NONE = 0xffffffff

def req(seq, subfunc, body=b''):
    return nhdr(0x2222, seq) + bytes([0x5c, subfunc]) + body

def msg(seq, verb, flags, ctx, body=b'', handle=NONE, length=None):
    '''Complete message: handle, buffer size, length, blank context, verb,
    flags (big endian), context (big endian), then the verb's body.'''
    if length is None:
        length = 16 + 4 + len(body)
    return req(seq, 2, struct.pack('<III', handle, 4096, length) + bytes(12) + struct.pack('<I', verb)
               + struct.pack('>II', flags, ctx) + body)

def rep(seq, body=b'', **k):
    return nrep(seq, body, **k)

def mrep(seq, rc=0, body=b'', handle=NONE, length=None):
    '''Reply: length, handle, 4 bytes, return code, data.'''
    if length is None:
        length = 4 + 4 + 4 + len(body)
    return rep(seq, struct.pack('<III', length, handle, 0) + struct.pack('<I', rc) + body)

state = {'seq': 0}
def pair(request, reply):
    state['seq'] += 1
    s = state['seq']
    u(request(s))
    if reply is not None:
        u(reply(s), to_server=False)

def lstr(s, nul=True):
    if isinstance(s, str):
        s = s.encode()
    if nul:
        s += b'\0'
    return struct.pack('<I', len(s)) + s

ERR_NOT_FOUND = 0xFFFFFCE0
ERR_NICI = 0xFFFFFCDF
ERR_UNKNOWN = 0x7654321

# --- ping and abort
pair(lambda s: req(s, 1, struct.pack('<II', 1, 0)), lambda s: rep(s, struct.pack('<II', 0x10, 0x20)))
pair(lambda s: req(s, 1, struct.pack('<II', 1, 0)), lambda s: rep(s))              # reply too short to decode
pair(lambda s: req(s, 3), lambda s: rep(s, struct.pack('<I', 0)))
pair(lambda s: req(s, 3), lambda s: rep(s))

# --- fragments (handle is not -1): with and without data; replies
pair(lambda s: req(s, 2, struct.pack('<I', 0x55) + bytes(24)),
     lambda s: rep(s, struct.pack('<III', 40, 0x55, 0) + b'fragment data of the reply'))
pair(lambda s: req(s, 2, struct.pack('<I', 0x55) + bytes(4)), lambda s: rep(s, struct.pack('<II', 8, 0x55) + bytes(4)))
# handle -1, short message: reply with a length of at most 4 and no data
pair(lambda s: req(s, 2, struct.pack('<I', 0x55) + bytes(8)), lambda s: rep(s, struct.pack('<III', 4, NONE, 0)))

# --- every verb. Query server (0): user; read app secrets (1): secret, a
# length and bytes, user; write app secrets (2): secret, encrypted data;
# add (3), remove (4): secret and user; remove store (5); enumerate (6):
# secret, user; unlock (7): encrypted credential; set master password (8),
# get service information (9), unknown (16, 255)
FLAGS = 0x00000001
def v0(s): return msg(s, 0, 0x10, 0x1234, bytes(4) + lstr('cn=alice.o=acme'))
def v1(s): return msg(s, 1, 0x3, 0x1234, lstr('app-secret-id') + lstr(b'xx', False) + lstr('cn=alice.o=acme'))
def v2(s): return msg(s, 2, 0x11, 0x1234, bytes(4) + lstr('app-secret-id') + lstr(b'encrypted secret value'))
def v34(v): return lambda s: msg(s, v, 0x3, 0x1234, lstr('another-id') + lstr('cn=bob.o=acme'))
def v6(s): return msg(s, 6, 0x0, 0x1234, lstr('list-id') + lstr('cn=bob.o=acme'))
def v7(s): return msg(s, 7, 0x20, 0x1234, lstr(b'credential bytes', False))
OKDATA = b'encrypted reply data of the secret store'
pair(v0, lambda s: mrep(s, 0, OKDATA))
pair(v1, lambda s: mrep(s, 0, OKDATA))
pair(v2, lambda s: mrep(s, 0, OKDATA))
pair(v34(3), lambda s: mrep(s, 0, OKDATA))
pair(v34(4), lambda s: mrep(s, 0, OKDATA))
pair(lambda s: msg(s, 5, 0x1, 0x1234), lambda s: mrep(s, 0))
# verb 6 reply: the number of items, then the secret ids ending in '*'
items = b'id-one*id-two*id-three*' + bytes(8)
pair(v6, lambda s: mrep(s, 0, bytes(4) + struct.pack('<I', 3) + bytes(4) + items))
pair(v6, lambda s: mrep(s, 0, bytes(4) + struct.pack('<I', 3) + bytes(4) + b'ab*' + bytes(3)))  # stops at the end of the data
pair(v6, lambda s: mrep(s, 0, bytes(4) + struct.pack('<I', 0) + bytes(4) + bytes(12)))              # no items
pair(v7, lambda s: mrep(s, 0, OKDATA))
pair(lambda s: msg(s, 8, 0x1, 0x1234, bytes(8)), lambda s: mrep(s, 0, OKDATA))
pair(lambda s: msg(s, 9, 0x0, 0x1234, bytes(8)), lambda s: mrep(s, 0, OKDATA))
pair(lambda s: msg(s, 16, 0x0, 0x1234, bytes(8)), lambda s: mrep(s, 0, OKDATA))     # unknown verb
pair(lambda s: msg(s, 255, 0x0, 0x1234, bytes(8)), lambda s: mrep(s, 0))             # verb "Fragment"
pair(lambda s: msg(s, 7, 0x0, 0x1234, lstr(b'cred', False)), lambda s: mrep(s, 0))  # success, no data

# --- strings: empty, non-printable, NUL padded; read secrets without a user;
# write secrets without data; secrets with a long length value
pair(lambda s: msg(s, 0, 0x0, 1, bytes(4) + lstr(b'')), lambda s: mrep(s, 0, OKDATA))
pair(lambda s: msg(s, 0, 0x0, 1, bytes(4) + lstr(b'u\x01s\x7fer\0\0', False)), lambda s: mrep(s, 0, OKDATA))
pair(lambda s: msg(s, 1, 0x0, 1, lstr('only-secret') + lstr(b'', False)), lambda s: mrep(s, 0))
pair(lambda s: msg(s, 2, 0x0, 1, bytes(4) + lstr('only-secret')), lambda s: mrep(s, 0))
pair(lambda s: msg(s, 2, 0x0, 1, bytes(4) + lstr('s') + struct.pack('<I', 100) + b'short data'), lambda s: mrep(s, 0))
pair(lambda s: msg(s, 0, 0x0, 1, bytes(4) + lstr(b'', False) + bytes(8)), lambda s: mrep(s, 0, OKDATA))   # empty user, data follows
pair(lambda s: msg(s, 3, 0x0, 1, lstr(b'', False) + lstr('cn=carol.o=acme')), lambda s: mrep(s, 0))   # empty secret id
pair(lambda s: msg(s, 3, 0x0, 1, lstr('only-id')), lambda s: mrep(s, 0))
pair(lambda s: msg(s, 6, 0x0, 1, lstr('only-id')), lambda s: mrep(s, 0))
pair(lambda s: msg(s, 4, 0x0, 1, lstr('only-id')), lambda s: mrep(s, 0))

# --- flags: every bit set, none, and a few single bits
pair(lambda s: msg(s, 5, 0xffffffff, 0x1), lambda s: mrep(s, 0))
pair(lambda s: msg(s, 5, 0x0, 0x2), lambda s: mrep(s, 0))
for fl in (0x00000100, 0x00008000, 0x80000000):
    pair(lambda s, fl=fl: msg(s, 5, fl, 0x2), lambda s: mrep(s, 0))

# --- error return codes: known and unknown (an unknown code is shown as success)
for rc in (ERR_NOT_FOUND, ERR_NICI, 0xFFFFFCD0):
    pair(lambda s: msg(s, 1, 0x0, 1, lstr('s') + lstr(b'', False)), lambda s: mrep(s, rc, b'not decoded'))
pair(lambda s: msg(s, 1, 0x0, 1, lstr('s') + lstr(b'', False)), lambda s: mrep(s, ERR_UNKNOWN, OKDATA))

main = frames
frames = []

# ---- malformed
state['seq'] = 100
# a message cut inside the header
u(req(101, 2, struct.pack('<III', NONE, 4096, 20) + bytes(10)))
# a string whose length is larger than the packet: the item runs past the end
pair(lambda s: msg(s, 0, 0x0, 1, bytes(4) + struct.pack('<I', 5000) + b'x' * 30), None)
pair(lambda s: msg(s, 1, 0x0, 1, struct.pack('<I', 3000) + b'y' * 30), None)
# verb 7 with a credential length that is larger than the data
pair(lambda s: msg(s, 7, 0x0, 1, struct.pack('<I', 900) + b'cred'), None)
# verb 6 reply whose string length is zero (delimiter first)
pair(lambda s: msg(s, 6, 0x0, 1, lstr('a') + lstr('b')),
     lambda s: mrep(s, 0, bytes(4) + struct.pack('<I', 2) + bytes(4) + b'*' + b'zzzzzzzz' + bytes(16)))
# verb 6 reply with a string length larger than the data
pair(lambda s: msg(s, 6, 0x0, 1, lstr('a') + lstr('b')),
     lambda s: mrep(s, 0, bytes(4) + struct.pack('<I', 2) + bytes(4) + struct.pack('<I', 9000) + bytes(20)))
# verb 6 reply with an item that has no delimiter: the string length is read from the data
pair(lambda s: msg(s, 6, 0x0, 1, lstr('a') + lstr('b')),
     lambda s: mrep(s, 0, bytes(4) + struct.pack('<I', 1) + bytes(4) + b'x' * 60 + bytes(4)))
# replies cut short
pair(lambda s: msg(s, 1, 0x0, 1, lstr('s') + lstr(b'', False)), lambda s: rep(s, struct.pack('<II', 40, NONE)))
pair(lambda s: msg(s, 1, 0x0, 1, lstr('s') + lstr(b'', False)), lambda s: rep(s, struct.pack('<III', 40, NONE, 0)))

if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'ncp-sss-coverage.pcap'), main)
    gz(os.path.join(out, 'ncp-sss-coverage.pcap'))
    os.rename(os.path.join(out, 'ncp-sss-coverage.pcap.gz'), os.path.join(out, 'ncp_sss_coverage.pcap.gz'))
    write_pcap(os.path.join(out, 'ncp-sss-coverage-malformed.pcap'), frames)
