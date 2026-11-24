#!/usr/bin/env python3
# Generates test/captures/icep_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the synthetic ICEP (Ice protocol) coverage captures: TCP and UDP,
found by the ICEP heuristic dissectors on port 10000.
Usage: mkicep.py <outdir>"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from c9lib import pcap, Flow, udp_frame

def istr(s):
    if isinstance(s, str):
        s = s.encode()
    if len(s) < 255:
        return bytes([len(s)]) + s
    return b'\xff' + struct.pack('<I', len(s)) + s

def seq(n):                       # size of a sequence/dictionary
    return bytes([n]) if n < 255 else b'\xff' + struct.pack('<I', n)

def params(data=b'', size=None):
    return struct.pack('<IBB', 6 + len(data) if size is None else size, 1, 1) + data

def hdr(mtype, body, comp=0, size=None, magic=b'IceP', pm=1, pn=0, em=1, en=0):
    return magic + bytes([pm, pn, em, en, mtype, comp]) + struct.pack('<i', 14 + len(body) if size is None else size) + body

def ident(name='Hello', cat='', facet=(), op='sayHello', mode=0, ctx=(), prm=None):
    out = istr(name) + istr(cat) + seq(len(facet)) + b''.join(istr(f) for f in facet)
    out += istr(op) + bytes([mode]) + seq(len(ctx)) + b''.join(istr(k) + istr(v) for k, v in ctx)
    return out + (params() if prm is None else prm)

def request(reqid=1, **kw):
    return hdr(0, struct.pack('<I', reqid) + ident(**kw))

def batch(items, count=None):
    return hdr(1, struct.pack('<I', len(items) if count is None else count) + b''.join(ident(**k) for k in items))

def reply(reqid, status, data=b'', size=None):
    return hdr(2, struct.pack('<IB', reqid, status) + data, size=size)

frames = []
C, S = '10.0.0.1', '10.0.0.2'

def conn(cport, fn):
    f = Flow(cport, 10000, frames, cip=C, sip=S)
    f.open()
    fn(f)
    f.close()

def tcp_main(f):
    f.s2c(hdr(3, b''))                                           # validate connection
    f.c2s(request(0))                                            # oneway
    f.s2c(reply(1, 0))
    f.c2s(request(2, name='Printer', cat='Devices', facet=('admin',), op='print', mode=1,
                  ctx=(('user', 'alice'), ('lang', 'en')), prm=params(b'\x01\x02\x03\x04')))
    f.s2c(reply(2, 0, b'\x00\x01\x02\x03\x04'))
    f.c2s(request(3, name='', cat='', op='x', mode=2))            # empty strings, idempotent
    f.s2c(reply(3, 1, b'user exception'))
    f.c2s(request(4, name='N' * 300, cat='C' * 256, op='op', ctx=(('k', 'v' * 260),)))   # 255 + 4 byte sizes
    for st in (2, 3, 4, 5, 6, 7, 8):
        f.s2c(reply(10 + st, st))
    f.c2s(batch([dict(name='A', op='a'), dict(name='B', cat='c', op='b', mode=1, facet=('f',)),
                 dict(name='C', op='c', ctx=(('x', 'y'),), prm=params(b'abcd'))]))
    f.c2s(hdr(1, struct.pack('<I', 0)))                          # empty batch
    f.c2s(hdr(9, b'\x00\x00', comp=1))                           # unknown message type
    f.c2s(request(5, op='compressed') [:9] + bytes([2]) + request(5, op='compressed')[10:])  # compression status 2
    f.c2s(hdr(0, struct.pack('<I', 6) + ident(op='cmp1'), comp=1))
    # two messages in one segment
    f.c2s(request(7, op='first') + request(8, op='second'))
    # one message over two segments (TCP reassembly)
    m = request(9, name='Reassembled', op='split', ctx=(('a', 'b'),), prm=params(bytes(range(40))))
    f.c2s(m[:30]); f.s2c(b'')
    f.c2s(m[30:])
    # a header split after 5 octets
    m = reply(9, 0, b'xyz')
    f.s2c(m[:5]); f.s2c(m[5:])
    f.s2c(hdr(4, b''))                                           # close connection

conn(41000, tcp_main)


# UDP datagrams
def udp(p, sp=41100, dp=10000, src=C, dst=S):
    frames.append(udp_frame(src, dst, sp, dp, p, len(frames) + 1))
udp(request(1, op='udp'))
udp(reply(1, 0, b'ok'), sp=10000, dp=41100, src=S, dst=C)
udp(batch([dict(op='u1'), dict(op='u2')]))
udp(hdr(3, b''))
udp(b'NotIcePxxxxxxxxxxxxxxxxx')                                  # not ICEP
pcap(os.path.join(sys.argv[1], 'icep-coverage.pcap'), frames)

# ---------- malformed capture ----------
frames = []
N12 = istr('n' * 12)                  # a 13 octet name keeps the "too short header" check quiet
RID = struct.pack('<I', 1)
def req(tail):
    return hdr(0, RID + tail)
def tcp_bad(f):
    f.c2s(request(1, name='x' * 600))                              # string too long (> 512)
    f.c2s(req(b'\xc8' + b'a' * 12))                                # name: missing or truncated string
    f.c2s(req(N12 + b'\xc8' + b'a' * 5))                           # category truncated
    f.c2s(req(N12 + istr('') ))                                    # facet missing
    f.c2s(req(N12 + istr('') + b'\x01\xff\x01\x02'))              # facet string: second field of Size missing
    f.c2s(req(N12 + istr('') + b'\x01\x00'))                       # facet with an empty string element (ok)
    f.c2s(request(1, facet=('a', 'b')))                            # facet with two elements
    f.c2s(req(N12 + istr('') + b'\x00' + b'\xc8' + b'a'))          # operation truncated
    f.c2s(req(N12 + istr('') + b'\x00' + istr('op')))               # mode missing
    f.c2s(req(N12 + istr('') + b'\x00' + istr('op') + b'\x00'))    # context missing
    f.c2s(request(1, ctx=[(str(i), 'v') for i in range(70)]))      # context too long
    f.c2s(req(N12 + istr('') + b'\x00' + istr('op') + b'\x00\xff\x01'))   # context: second field of Size missing
    f.c2s(req(N12 + istr('') + b'\x00' + istr('op') + b'\x00\xff' + struct.pack('<I', 2) + istr('k') + istr('v') + istr('k2') + istr('v2') + params()))  # context with 255 size form (ok)
    f.c2s(req(N12 + istr('') + b'\x00' + istr('op') + b'\x00\x01\xc8kk'))   # context key truncated
    f.c2s(req(N12 + istr('') + b'\x00' + istr('op') + b'\x00\x01\x01k\xc8vv')) # context value truncated
    f.c2s(req(N12 + istr('') + b'\x00' + istr('op') + b'\x00\x00\x01\x02'))   # params missing
    f.c2s(request(1, prm=params(size=3)))                          # params size too small
    f.c2s(request(1, prm=params(b'ab', size=100)))                 # encapsulated data missing
    f.c2s(hdr(0, b'\x01\x00'))                                     # request id cut short
    f.c2s(hdr(0, b'\x01\x00\x00\x00' + b'\x01n'))                  # common header too short
    f.c2s(batch([dict(op='x')] * 3, count=100))                    # too many batch requests
    f.c2s(hdr(1, b'\x01\x00'))                                     # batch counter missing
    f.c2s(batch([dict(op='x'), dict(op='y', facet=('a', 'b'))]))   # batch: second request bad
    f.c2s(hdr(1, struct.pack('<I', 1) + N12 + b'\xc8' + b'a' * 5))  # batch: category truncated
    f.c2s(hdr(1, struct.pack('<I', 1) + N12 + istr('') + b'\x00' + b'\xc8' + b'a' * 3))   # batch: operation truncated
    f.c2s(reply(1, 0, b'x', size=100))                             # reply data missing
    f.c2s(hdr(0, b'', size=-5))                                    # negative size
    f.c2s(hdr(0, b'', size=0x7fffffff)[:20])                       # very large size, cut
def tcp_neg(f):
    f.c2s(hdr(0, b'', size=-1))
conn(42001, tcp_neg)
conn(42002, lambda f: f.c2s(hdr(2, b'\x01\x00')))            # reply header too short
conn(42000, tcp_bad)
def udp_bad():
    udp(request(1, name='x' * 600))
    udp(reply(1, 0, b'x', size=100))
    udp(hdr(0, b'', size=-5))
    udp(batch([dict(op='x')] * 3, count=100))
    udp(request(1, prm=params(size=3)))
    udp(request(1, facet=('a', 'b')))
    udp(hdr(0, struct.pack('<I', 1) + b'\x05ab'))
    udp(b'IceP\x01\x00\x01\x00\x00\x00\x0e')                       # header cut short
udp_bad()
# garbage on a port that Decode As hands to the ICEP TCP dissector (runcov.sh)
conn(43000, lambda f: f.c2s(b'This is not ICEP at all, just text.'))
pcap(os.path.join(sys.argv[1], 'icep-coverage-malformed.pcap'), frames)
