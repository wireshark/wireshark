#!/usr/bin/env python3
# Generates test/captures/xtp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures for the XTP dissector (packet-xtp.c).

XTP (Xpress Transport Protocol 4.0) is IP protocol 36. The 32 octet
header holds the key, the command (24 bit options, 3 bit version, 5 bit
packet format), the data length, a 16 bit checksum, sort, sync and
sequence number; the segment that follows depends on the format: DATA
(with an optional BTAG), CNTL, FIRST (address segment and traffic
specifier), ECNTL (spans), TCNTL (traffic control segment and traffic
specifier), JOIN (obsolete), JCNTL and DIAG. Everything is big endian.

Usage: mkxtp.py <outdir>
Writes xtp-coverage.pcap and xtp-coverage-malformed.pcap.
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from util import ipv4, eth, csum, write_pcap

DATA, CNTL, FIRST, ECNTL, TCNTL, JOIN, JCNTL, DIAG = 0, 1, 2, 3, 5, 6, 7, 8
NOCHECK, EDGE, NOERR, MULTI, RES, SORT, NOFLOW, FASTNAK, SREQ, DREQ, RCLOSE, WCLOSE, EOM, END, BTAG = (
    0x400000, 0x200000, 0x100000, 0x080000, 0x040000, 0x020000, 0x010000, 0x008000, 0x004000, 0x002000,
    0x001000, 0x000800, 0x000400, 0x000200, 0x000100)

def xtp(pformat, seg=b'', options=0, ver=1, key=0x8123456789abcdef, sort=0, sync=0, seq=1, dlen=None,
        good=True, nocheck_len=None):
    cmd = (options << 8) | (ver << 5) | pformat
    dl = len(seg) if dlen is None else dlen
    h = struct.pack('>QIIHHIQ', key, cmd, dl, 0, sort, sync, seq)
    clen = 32 if (options & NOCHECK) else 32 + len(seg)
    c = csum((h + seg)[:clen])
    if not good:
        c ^= 0x5555
    return h[:16] + struct.pack('>H', c) + h[18:] + seg

def aseg_ip(dh=0x0a000001, sh=0x0a000002, dp=1000, sp=2000, alen=16, adom=0):
    return struct.pack('>HBBIIHH', alen, adom, 1, dh, sh, dp, sp)

def aseg_null(addr=0x01020304, alen=8, adom=0):
    return struct.pack('>HBBI', alen, adom, 0, addr)

def tspec0(none=0x1234, tlen=8, service=1):
    return struct.pack('>HBBI', tlen, service, 0, none)

def tspec1(tlen=24, service=4, vals=(1500, 100000, 4000, 200000, 8000)):
    return struct.pack('>HBBI', tlen, service, 1, vals[0]) + struct.pack('>IIII', *vals[1:])

def cntl(rseq=100, alloc=2000, echo=0x11223344):
    return struct.pack('>QQI', rseq, alloc, echo)

def tcntl_seg(rseq=100, alloc=2000, echo=0x11223344, rsvd=7, xkey=0x8000000000000042):
    return struct.pack('>QQIIQ', rseq, alloc, echo, rsvd, xkey)

def ecntl(spans, nspan=None, rseq=100, alloc=2000, echo=5):
    body = b''.join(struct.pack('>QQ', l, r) for l, r in spans)
    return struct.pack('>QQII', rseq, alloc, echo, len(spans) if nspan is None else nspan) + body

def ip(x, src='192.0.2.1', dst='192.0.2.2', **kw):
    return eth(ipv4(36, x, src=src, dst=dst, **kw))

main, mal = [], []
A = lambda *a, **k: main.append(ip(xtp(*a, **k)))
M = lambda *a, **k: mal.append(ip(xtp(*a, **k)))

# DATA: no options, with BTAG, with options of every kind
A(DATA, b'data segment payload', seq=1)
A(DATA, struct.pack('>Q', 0x1122334455667788) + b'btag data', options=BTAG, seq=2)
A(DATA, b'', seq=3)
A(DATA, b'x' * 300, options=EOM | END, seq=4, sort=7, sync=0x80000000)
for i, opt in enumerate((NOCHECK, EDGE, NOERR, MULTI, RES, SORT, NOFLOW, FASTNAK, SREQ, DREQ, RCLOSE, WCLOSE, EOM, END, BTAG)):
    A(DATA, struct.pack('>Q', i) + b'option %d' % i, options=opt, seq=10 + i, key=i)
A(DATA, struct.pack('>Q', 1) + b'all options', options=0x7fffff, seq=30)
A(DATA, b'nocheck data not covered by the checksum', options=NOCHECK, seq=31)
# CNTL: the common control segment
A(CNTL, cntl(), seq=40, options=SREQ | DREQ)
A(CNTL, cntl(rseq=0xffffffffffffffff, alloc=0xfffffffffffffffe, echo=0xffffffff), seq=41, options=EOM)
# FIRST: IP address segment and both traffic specifiers; null address (the traffic
# specifier is read after 16 octets); unsupported formats; address formats >= 128
A(FIRST, aseg_ip() + tspec0(), seq=50, options=SORT | NOFLOW)
A(FIRST, aseg_ip(dp=65535, sp=0) + tspec1(), seq=51)
A(FIRST, aseg_null() + b'\x00' * 8 + tspec0(), seq=52)
A(FIRST, struct.pack('>HBBIIII', 16, 0, 200, 1, 2, 3, 4) + tspec0(), seq=53)
A(FIRST, aseg_ip() + tspec0(service=0), seq=54)
for svc in range(2, 7):
    A(FIRST, aseg_ip() + tspec1(service=svc), seq=54 + svc)
# a service value and a traffic format of zero with a different 'none' value, domain other than 0
A(FIRST, aseg_ip(adom=7) + tspec0(none=0, service=0x7f), seq=62)
# ECNTL: spans
A(ECNTL, ecntl([(10, 20)]), seq=70)
A(ECNTL, ecntl([(10, 20), (30, 40), (0xffffffffffff0000, 0xffffffffffffffff)]), seq=71)
A(ECNTL, ecntl([]), seq=72)
A(ECNTL, ecntl([(i * 10, i * 10 + 5) for i in range(40)]), seq=73)
# TCNTL and JCNTL: traffic control segment, with traffic specifier (and address segment)
A(TCNTL, tcntl_seg() + tspec0(), seq=80)
A(TCNTL, tcntl_seg(rseq=1, alloc=2, echo=3, rsvd=4, xkey=5) + tspec1(), seq=81)
A(JCNTL, tcntl_seg() + aseg_ip() + tspec0(), seq=82)
A(JCNTL, tcntl_seg() + aseg_ip() + tspec1(), seq=83)
# JOIN (obsolete, nothing shown), unknown packet formats
A(JOIN, b'obsolete', seq=90)
for pf in (4, 9, 15, 31):
    A(pf, b'unknown format', seq=91 + pf)
# DIAG: every code and value, a message, no message
for code in range(0, 9):
    A(DIAG, struct.pack('>II', code, (code * 2) % 15) + (b'diagnostic message %d' % code if code % 2 else b''), seq=100 + code)
A(DIAG, struct.pack('>II', 4, 99) + b'', seq=110)
# bad checksum (an expert info) is in the malformed capture; a checksum over data when
# the segment is empty; various keys and key return bit
A(CNTL, cntl(), seq=111, key=0x0000000000000001)
A(CNTL, cntl(), seq=112, key=0xffffffffffffffff)
# IPv4 header options? no: one frame from another address pair
main.append(ip(xtp(DATA, b'other hosts', seq=120), src='198.51.100.7', dst='198.51.100.8'))
# Info string options: each of the 16 option bits through the command options (also bit 0x01..0x80 of the low half)
for i in range(8):
    A(CNTL, cntl(), options=(1 << (16 + i)), seq=130 + i)
for i in range(8):
    A(CNTL, cntl(), options=(1 << i), seq=140 + i)

# ---------------------------------------------------------------------------
# Malformed: version, length, checksum, short segments, spans
M(CNTL, cntl(), ver=0, seq=200)
M(CNTL, cntl(), ver=2, seq=201)
M(CNTL, cntl(), ver=7, seq=202)
M(CNTL, cntl(), dlen=5, seq=203)
M(CNTL, cntl(), dlen=0xffffffff, seq=204, options=NOCHECK)
M(CNTL, cntl(), dlen=0xffffffff, seq=205)
M(DATA, b'abc', good=False, seq=206)
M(DATA, b'abc', good=False, seq=207, options=NOCHECK)
M(CNTL, cntl() + b'\x00', seq=208)
M(CNTL, cntl()[:12], seq=209)
M(CNTL, b'', seq=210)
# FIRST: segments shorter than the minimum, bogus lengths
M(FIRST, b'\x00\x10\x00', seq=211)
M(FIRST, aseg_ip()[:12], seq=212)
M(FIRST, aseg_ip(alen=200) + tspec0(), seq=213)
M(FIRST, aseg_ip(alen=8) + tspec0(), seq=214)
M(FIRST, aseg_null(alen=16) + b'\x00' * 8, seq=215)
M(FIRST, aseg_null(alen=0xffff), seq=216)
M(FIRST, struct.pack('>HBBI', 8, 0, 2, 0) + b'\x00' * 12 + tspec0(), seq=217)       # aformat 2: unsupported
M(FIRST, struct.pack('>HBBI', 8, 0, 127, 0) + b'\x00' * 12 + tspec0(), seq=218)
M(FIRST, aseg_ip(), seq=219)                                                       # no traffic specifier
M(FIRST, aseg_ip() + b'\x00\x08\x01', seq=220)
M(FIRST, aseg_ip() + tspec0(tlen=200), seq=221)
M(FIRST, aseg_ip() + tspec0(tlen=24), seq=222)
M(FIRST, aseg_ip() + tspec1(tlen=8), seq=223)
M(FIRST, aseg_ip() + struct.pack('>HBBI', 8, 1, 7, 0), seq=224)                    # unsupported tformat
M(FIRST, aseg_ip() + struct.pack('>HBBIII', 24, 1, 1, 0, 0, 0), seq=225)           # tspec1 cut: tlen 24, 12 octets
M(FIRST, aseg_ip() + struct.pack('>HBBIII', 24, 1, 1, 0, 0, 0), seq=226)
# ECNTL: nspan wrong, too short, too many (cap), overflow of 16 * nspan
M(ECNTL, ecntl([(1, 2)], nspan=2), seq=230)
M(ECNTL, ecntl([(1, 2)], nspan=0), seq=231)
M(ECNTL, ecntl([], nspan=1), seq=232)
M(ECNTL, ecntl([])[:20], seq=233)
M(ECNTL, ecntl([], nspan=0x10000000), seq=234)
M(ECNTL, ecntl([], nspan=0x20000001), seq=235)
M(ECNTL, ecntl([], nspan=0xffffffff), seq=236)
# TCNTL / JCNTL: short control segments, short traffic specifiers
M(TCNTL, tcntl_seg()[:31], seq=240)
M(TCNTL, b'', seq=241)
M(TCNTL, tcntl_seg(), seq=242)
M(TCNTL, tcntl_seg() + tspec0()[:7], seq=243)
M(JCNTL, tcntl_seg()[:20], seq=244)
M(JCNTL, tcntl_seg(), seq=245)
M(JCNTL, tcntl_seg() + aseg_ip()[:7], seq=246)
M(JCNTL, tcntl_seg() + aseg_ip(), seq=247)
M(JCNTL, tcntl_seg() + aseg_ip(alen=3) + tspec0(), seq=248)
# DIAG shorter than 8
M(DIAG, b'\x00\x00\x00\x01', seq=250)
M(DIAG, b'', seq=251)
# DATA with BTAG shorter than 8 octets
M(DATA, b'\x01\x02\x03', options=BTAG, seq=252)
M(DATA, b'', options=BTAG, seq=253)
# header shorter than 32 octets (not XTP)
mal.append(ip(xtp(DATA, b'abc')[:31]))
mal.append(ip(b'\x00' * 10))

# an ECNTL with more than 10000 spans, as an IP datagram of 160 KB sent in fragments
big = xtp(ECNTL, ecntl([(i, i + 1) for i in range(10001)]), seq=300)
frag = []
off = 0
n = 0
while off < len(big):
    chunk = big[off:off + 64000]
    last = off + len(chunk) >= len(big)
    flags_frag = (0 if last else 0x2000) | (off // 8)
    frag.append(eth(ipv4(36, chunk, src='192.0.2.1', dst='192.0.2.2', ident=7, flags_frag=flags_frag)))
    off += len(chunk)
mal.extend(frag)
# fragments of a small packet, the first only (not reassembled with ip.defragment off)
small = xtp(CNTL, cntl(), seq=301)
mal.append(eth(ipv4(36, small[:24], src='192.0.2.1', dst='192.0.2.2', ident=9, flags_frag=0x2000)))
mal.append(eth(ipv4(36, small[24:], src='192.0.2.1', dst='192.0.2.2', ident=9, flags_frag=24 // 8)))

out = sys.argv[1]
write_pcap(os.path.join(out, 'xtp-coverage.pcap'), main)
write_pcap(os.path.join(out, 'xtp-coverage-malformed.pcap'), mal)
print(len(main), len(mal))
