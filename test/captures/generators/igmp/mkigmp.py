#!/usr/bin/env python3
# Generates test/captures/igmp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the synthetic IGMP coverage captures (IP protocol 2).
Usage: mkigmp.py <outdir>"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
import socket
from c9lib import pcap, csum, ip4, eth

frames = []
GRP = '224.1.2.3'
def a(ip): return socket.inet_aton(ip)

def fix(msg, length=None, good=True):
    """Put the Internet checksum into octets 2-3 (over `length` octets)."""
    n = len(msg) if length is None else length
    m = msg[:2] + b'\0\0' + msg[4:]
    c = csum(m[:n])
    if not good:
        c ^= 0x1234
    return m[:2] + struct.pack('>H', c) + m[4:]

def send(msg, dst='224.0.0.22', src='192.0.2.1', ttl=1, mf=False, trunc=None, frag=0):
    ip = ip4(src, dst, 2, msg, len(frames) + 1)
    if mf or frag:
        ip = ip[:6] + struct.pack('>H', (0x2000 if mf else 0) | frag) + ip[8:10] + b'\0\0' + ip[12:]
        ip = ip[:10] + struct.pack('>H', csum(ip[:20])) + ip[12:]
    dmac = bytes([1, 0, 0x5e]) + a(dst)[1:] if dst.startswith('224') else bytes.fromhex('020000000002')
    dmac = dmac[:3] + bytes([dmac[3] & 0x7f]) + dmac[4:]
    fr = eth(dmac, bytes.fromhex('020000000001'), 0x0800, ip)
    frames.append((fr[:trunc], len(fr)) if trunc else fr)

# ---------- version 0 (RFC 988), types 0-15, 20 octet messages ----------
def v0(t, code, ident=0x01020304, grp=GRP, key=b'ACCESSKY'):
    return fix(struct.pack('>BBHI', t, code, 0, ident) + a(grp) + key, 20)
send(v0(1, 0), dst='224.0.0.1')          # create group request, public
send(v0(1, 1))                           # private
send(v0(2, 0))                           # create group reply: granted
send(v0(2, 3))                           # reply code (invalid group)
send(v0(2, 7))                           # reply pending
send(v0(3, 0))                           # join request (odd type, no code)
send(v0(4, 1))
send(v0(5, 0)); send(v0(6, 2)); send(v0(7, 0)); send(v0(8, 4))
send(v0(0, 0)); send(v0(15, 0))
# ---------- version 1 and 2 ----------
send(fix(struct.pack('>BBH', 0x11, 0, 0) + a('0.0.0.0'), 8), dst='224.0.0.1')              # v1 general query
send(fix(struct.pack('>BBH', 0x12, 0, 0) + a(GRP), 8), dst=GRP)                             # v1 report
send(fix(struct.pack('>BBH', 0x11, 100, 0) + a('0.0.0.0'), 8), dst='224.0.0.1')            # v2 general query
send(fix(struct.pack('>BBH', 0x11, 20, 0) + a(GRP), 8), dst=GRP)                            # v2 group specific query
send(fix(struct.pack('>BBH', 0x16, 0, 0) + a(GRP), 8), dst=GRP)                             # v2 report
send(fix(struct.pack('>BBH', 0x16, 0, 0) + a('0.0.0.0'), 8), dst=GRP)                       # report for 0.0.0.0
send(fix(struct.pack('>BBH', 0x17, 0, 0) + a(GRP), 8), dst='224.0.0.2')                     # leave
send(fix(struct.pack('>BBH', 0x17, 0, 0) + a('0.0.0.0'), 8), dst='224.0.0.2')
# ---------- version 3 queries (12 octets or more) ----------
def q3(maxresp, grp='0.0.0.0', s=0, qrv=2, qqic=125, srcs=()):
    return fix(struct.pack('>BBH', 0x11, maxresp, 0) + a(grp) + bytes([(s << 3) | qrv, qqic])
               + struct.pack('>H', len(srcs)) + b''.join(a(x) for x in srcs))
send(q3(100), dst='224.0.0.1')                              # general, plain max resp
send(q3(0x8a), dst='224.0.0.1')                             # exponent/mantissa form
send(q3(0xff, qrv=7, s=1), dst='224.0.0.1')
send(q3(100, grp=GRP), dst=GRP)                             # group specific
send(q3(100, grp=GRP, srcs=('192.0.2.7',)), dst=GRP)       # one source
send(q3(100, grp=GRP, srcs=('192.0.2.7', '192.0.2.8', '192.0.2.9')), dst=GRP)
# ---------- version 3 reports ----------
def rec(rtype, grp, srcs=(), aux=b''):
    return (struct.pack('>BBH', rtype, len(aux) // 4, len(srcs)) + a(grp)
            + b''.join(a(x) for x in srcs) + aux)
def rep3(*recs):
    return fix(struct.pack('>BBHHH', 0x22, 0, 0, 0, len(recs)) + b''.join(recs))
send(rep3())                                                # no records: general query note
for rt in range(1, 7):                                      # every record type, no sources
    send(rep3(rec(rt, GRP)))
for rt in range(1, 7):                                      # one source
    send(rep3(rec(rt, GRP, ('192.0.2.7',))))
for rt in range(1, 7):                                      # several sources
    send(rep3(rec(rt, GRP, ('192.0.2.7', '192.0.2.8'))))
send(rep3(rec(9, GRP)))                                     # unknown record type
send(rep3(rec(9, GRP, ('192.0.2.7',))))
send(rep3(rec(1, GRP, ('192.0.2.7',), aux=b'AUX1AUX2'), rec(2, '224.4.5.6'), rec(5, '224.7.8.9', ('192.0.2.1', '192.0.2.2'))))   # aux data, several records
# ---------- multicast traceroute ----------
def mt(t, hops=32, grp=GRP, blocks=0, extra=b''):
    hdr = struct.pack('>BBH', t, hops, 0) + a(grp) + a('192.0.2.50') + a('192.0.2.60') + a('192.0.2.70') + bytes([64]) + b'\x01\x02\x03'
    body = b''
    for i in range(blocks):
        body += (struct.pack('>I', 1000 + i) + a('10.0.%d.1' % i) + a('10.0.%d.2' % i) + a('10.0.%d.3' % i)
                 + struct.pack('>III', 10 + i, 20 + i, 30 + i) + bytes([[1, 2, 3, 4, 5, 6, 7, 8, 99][i % 9], 1 + i, 0x80 | 24, [0, 1, 2, 3, 4, 5, 6, 7, 8, 0x81, 99][i % 11]]))
    return fix(hdr + body + extra)
send(mt(0x1f), dst='224.0.0.2')                             # query (24 octets)
send(mt(0x1f, blocks=2), dst='192.0.2.1')                   # request with blocks
send(mt(0x1e), dst='192.0.2.70')                            # response, no blocks
send(mt(0x1e, blocks=1), dst='192.0.2.70')
send(mt(0x1e, blocks=11), dst='192.0.2.70')                 # every protocol and forwarding code
send(mt(0x1e, blocks=2, extra=b'tail'), dst='192.0.2.70')   # trailing octets after the blocks
# ---------- unknown types, truncated capture, fragmented datagram ----------
send(fix(b'\x77\x00\x00\x00' + b'unknown data'))
send(fix(b'\x77\x00\x00\x00'))
send(fix(struct.pack('>BBH', 0x16, 0, 0) + a(GRP), 8), dst=GRP, trunc=14 + 20 + 6)        # snaplen cut: checksum not verified
send(fix(struct.pack('>BBH', 0x16, 0, 0) + a(GRP), 8), dst=GRP, mf=True)                  # IP fragment: checksum not verified
send(rep3(rec(1, GRP, ('192.0.2.7',))), trunc=14 + 20 + 16)
pcap(os.path.join(sys.argv[1], 'igmp-coverage.pcap'), frames)

# ---------- malformed capture ----------
frames = []
send(fix(struct.pack('>BBH', 0x16, 0, 0) + a(GRP), 8, good=False), dst=GRP)               # bad checksums
send(q3(100, grp=GRP, srcs=('192.0.2.7',)).replace(q3(100, grp=GRP, srcs=('192.0.2.7',))[:4], b'\x11\x64\xff\xff', 1), dst=GRP)
send(v0(1, 0)[:2] + b'\x00\x00' + v0(1, 0)[4:], dst='224.0.0.1')
send(fix(mt(0x1f, blocks=1), good=False), dst='224.0.0.2')
send(fix(rep3(rec(1, GRP, ('192.0.2.7',))), good=False))
send(b'\x16')                                               # one octet
send(b'\x16\x00\x00')                                       # v2 cut short
send(b'\x12\x00\x00\x00\xe0')                               # v1 cut short
send(b'\x22\x00\x00\x00\x00')                               # v3 report cut short
send(fix(struct.pack('>BBHHH', 0x22, 0, 0, 0, 3) + rec(1, GRP)))   # three records announced, one there
send(fix(struct.pack('>BBHHH', 0x22, 0, 0, 0, 1) + struct.pack('>BBH', 1, 5, 2) + a(GRP) + a('192.0.2.1'))) # sources and aux data past the end
send(b'\x11\x64\x00\x00' + a(GRP) + b'\x02\x7d\x00\x05' + a('192.0.2.1'))                   # v3 query: five sources, one there
send(b'\x1e\x20\x00\x00' + a(GRP) + b'\x00' * 8)            # traceroute cut short
send(b'\x03\x00\x00')                                       # v0 cut short
send(b'')
pcap(os.path.join(sys.argv[1], 'igmp-coverage-malformed.pcap'), frames)
