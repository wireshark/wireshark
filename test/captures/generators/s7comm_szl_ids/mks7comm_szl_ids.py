#!/usr/bin/env python3
# Generates test/captures/s7comm_szl_ids_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic captures for the SZL (system status list) decoders of S7COMM
(packet-s7comm_szl_ids.c): mks7comm_szl_ids.py <outdir> [-v]
Writes s7comm_szl_ids-coverage.pcap and s7comm_szl_ids-coverage-malformed.pcap.
The SZL decoders are reached through S7COMM userdata function group 4, subfunction 1
(Read SZL) over TPKT/COTP on TCP port 102."""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from s7lib import cotp_cc, cotp_cr, dt, Flow, pcap, ts8, ud

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'
VERBOSE = '-v' in sys.argv
main, mal, ranges = [], [], []
_cur = [None, 0]

def sec(name, frames):
    if _cur[0]:
        ranges.append((_cur[0], _cur[1] + 1, len(frames)))
    _cur[0], _cur[1] = name, len(frames)

class Conn:
    port = 51000
    def __init__(self, frames):
        Conn.port += 1
        self.fl = Flow(Conn.port, frames)
        self.fl.open()
        self.fl.c2s(cotp_cr(1)); self.fl.s2c(cotp_cc(1, 2))
        self.ref = 0
    def req(self, pdu, eot=True): self.fl.c2s(dt(pdu, eot))
    def rsp(self, pdu, eot=True): self.fl.s2c(dt(pdu, eot))

def text(n, seed=0):
    """printable filler (the text fields of the SZL records)"""
    return bytes(0x30 + ((seed + i) % 42) for i in range(n))

def szl_req(id, idx):
    return ud(1, 4, 0x01, payload=struct.pack('>HH', id, idx))

def szl_rsp(id, idx, items, ll=None, cnt=None, **kw):
    """response with the given list items (all of the same length)"""
    if ll is None:
        ll = len(items[0]) if items else 0
    if cnt is None:
        cnt = len(items)
    return ud(2, 4, 0x01, ext=True, payload=struct.pack('>HHHH', id, idx, ll, cnt) + b''.join(items), **kw)

def le(*v):
    return b''.join(struct.pack('<H', x) for x in v)

# =====================================================================
F = main
c = Conn(F)

# ---- requests ------------------------------------------------------------------
sec('Read SZL requests: SZL IDs and indexes with a description', F)
IDX = {
    0x0111: [1, 6, 7, 0x81, 0x1234], 0x0112: [0, 0x100, 0x200, 0x300, 0x400, 0x500], 0x0113: [1, 2, 3, 4, 5, 6, 7],
    0x0114: list(range(1, 10)) + [0xa], 0x0115: [0x800, 0xa00, 0xb00, 0xc00, 0xe00, 0xf00], 0x0116: [0, 10, 20, 30, 40, 80, 90, 100, 120, 130],
    0x0118: [1, 2, 3, 0xff, 4], 0x0119: [1, 2, 0x16, 0x80, 0x84, 0xec, 0xed, 0xee], 0x0121: [0, 0x0a0a, 0x1414, 0x1e23, 0x2828, 0x5050, 0x5a, 0x64, 0x7878, 0x7777],
    0x0222: [0, 10, 20, 30, 40, 50, 60, 72, 80, 90, 100, 120, 121], 0x0524: [0x5000, 0x5010, 0x5020, 0x5030, 0x4520, 0x4521],
    0x0131: [1, 2, 3, 4, 5, 6, 7, 8, 9, 0x10, 0x11, 0x12], 0x0132: [1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0x10, 0x11, 0x12],
    0x0174: [1, 0x10, 0x80, 0xec, 0xff], 0x011c: [1, 2, 3, 4, 5, 7, 8, 9, 0xa, 0xb, 0xc], 0x031c: [1, 0xb, 0xd],
    0x0077: [0x1000, 0x2000], 0x0078: [0x1000, 0x2000],
}
for sid, idxs in IDX.items():
    for ix in idxs:
        c.req(szl_req(sid, ix))
sec('Read SZL requests: partial lists, other IDs', F)
PARTIAL = [0x0000, 0x0011, 0x0012, 0x0013, 0x0014, 0x0015, 0x0016, 0x0017, 0x0018, 0x0019, 0x001c, 0x0021, 0x0022, 0x0023, 0x0024,
           0x0025, 0x0031, 0x0032, 0x0033, 0x0037, 0x0071, 0x0074, 0x0075, 0x0076, 0x0077, 0x0078, 0x0081, 0x0082, 0x0090, 0x0091,
           0x0092, 0x0094, 0x0095, 0x0096, 0x00a0, 0x00b1, 0x00b2, 0x00b3, 0x00b4, 0x00ff]
for p in PARTIAL:
    c.req(szl_req(p, 0))
for sid in (0x0f00, 0x0100, 0x0200, 0x0300, 0x0f11, 0x4c91, 0x4d91, 0x0c96, 0x1000, 0x8000, 0xf0ff):
    c.req(szl_req(sid, 0))

# ---- responses ----------------------------------------------------------------------
sec('Read SZL responses: partial list overview (0x0000), module identification and characteristics', F)
c.rsp(szl_rsp(0x0000, 0, [struct.pack('>H', x) for x in (0x0011, 0x0012, 0x0013, 0x0f00, 0x0111)]))
c.rsp(szl_rsp(0x0000, 1, [struct.pack('>H', 0x0111)]))
c.rsp(szl_rsp(0x0012, 0, [struct.pack('>H', 0x0000), struct.pack('>H', 0x0100), struct.pack('>H', 0x0101)]))
c.rsp(szl_rsp(0x0112, 0, [struct.pack('>H', 0x0300)]))
c.rsp(szl_rsp(0x0013, 0, [struct.pack('>HHIHHHHHHHHH', 1, 1, 0x100000, 1, 2, 3, 4, 5, 6, 7, 8, 9)[:36].ljust(36, b'\0') for _ in range(2)]))
c.rsp(szl_rsp(0x0113, 0, [text(36, 3)]))
c.rsp(szl_rsp(0x0113, 1, [text(36, 3)]))             # index 1 is not decoded
for sid in (0x0014, 0x0114):
    c.rsp(szl_rsp(sid, 1, [text(8, 1), text(8, 2)]))
for sid in (0x0015, 0x0115):
    c.rsp(szl_rsp(sid, 0x800, [text(10, 1), text(10, 4)]))
for sid in (0x0011, 0x0111):
    c.rsp(szl_rsp(sid, 1, [text(28, 5), text(28, 9)]))
c.rsp(szl_rsp(0x0222, 0, [text(28, 5), text(28, 9)]))
c.rsp(szl_rsp(0x0222, 0x1e, [text(28, 1)]))

sec('Read SZL responses: diagnostic buffer (0x00a0 and others), identification (0x001c)', F)
for sid in (0x00a0, 0x01a0, 0x04a0, 0x05a0, 0x06a0, 0x07a0, 0x08a0, 0x09a0, 0x0aa0, 0x0ba0, 0x0ca0, 0x0da0, 0x0ea0):
    c.rsp(szl_rsp(sid, 0, [struct.pack('>HBBHHI', ev, 0x16, 1, 0x0102, 0x0304, 0x05060708) + ts8() for ev in (0x8032, 0x113a, 0x0123)]))
def sz1c(sid, ix, body):
    return szl_rsp(sid, ix & 0xf, [struct.pack('>H', ix) + body])
for sid in (0x001c, 0x011c, 0x021c, 0x031c):
    for ix in (1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0x101, 0x1b):
        c.rsp(sz1c(sid, ix, text(32, ix)))

sec('Read SZL responses: communication data (0x0131, 0x0132)', F)
for sid, idxs in ((0x0131, (1, 2, 3, 4, 5, 6, 7, 8, 9, 0x10, 0x0a)), (0x0132, (1, 2, 4, 5, 6, 8, 0xb, 0xc, 3, 9))):
    for ix in idxs:
        n = 40
        # the first two bytes of each record repeat the index
        c.rsp(szl_rsp(sid, ix, [struct.pack('>H', ix) + text(n - 2, ix), struct.pack('>H', ix) + bytes(range(n - 2))]))

sec('Read SZL responses: LEDs, DNN nodes, station and module status', F)
for sid in (0x0019, 0x0119, 0x0074, 0x0174):
    c.rsp(szl_rsp(sid, 0, [struct.pack('>HBB', 0x0201, 1, 0), struct.pack('>HBB', 0x1302, 0, 1)]))
c.rsp(szl_rsp(0x0076, 0, [le(5, 0x1234)]))
# DNN relations (0x0077)
c.rsp(szl_rsp(0x0077, 0x1000, [le(1, 2, 0x11, 0x12, 3, 0x21, 0x22, 0x23, 1, 0x31, 2, 0x41, 0x42)]))
c.rsp(szl_rsp(0x0077, 0x1000, [le(1, 0, 0, 0, 0)]))
def geo(): return le(1, 2, 3, 4, 5)
def cdiag(chet, tl1, echet, tl2, n=0):
    return le(n, 0x0101, 0x0002, 0) + struct.pack('<I', 0x12345678) + le(chet, tl1, echet, tl2) + le(1, 2, 3, 4)
def dnn(ncd, tlvs=None, version=5, cds=None):
    b = le(version)
    if version != 5:
        return b + text(50)
    b += geo() + text(32, 1) + text(32, 8) + le(3)
    b += le(ncd)
    for k in range(ncd):
        b += (cds[k] if cds else cdiag(0, 0, 0, 0, k))
    b += struct.pack('<I', 0x0f0f0f0f) + le(0x00ff, 0) + struct.pack('<I', 0x03) + le(1, 2, 0x0fff, 1, 2, 3, 4)
    b += struct.pack('>H', 0x002a) + text(20, 2) + text(32, 3) + text(22, 4) + text(32, 5)
    if tlvs is not None:
        b += bytes([len(tlvs), 0])
        for t, d in tlvs:
            b += bytes([t, len(d)]) + d
    return b
c.rsp(szl_rsp(0x0078, 0x1000, [dnn(0)]))
c.rsp(szl_rsp(0x0078, 0x1000, [dnn(1, cds=[cdiag(1, 8, 0, 0)])]))
c.rsp(szl_rsp(0x0078, 0x1000, [dnn(3, cds=[cdiag(0, 0, 0, 0), cdiag(0xffff, 8, 7, 8), cdiag(0x1234, 0, 0x55, 8)])]))
c.rsp(szl_rsp(0x0078, 0x1000, [dnn(2, cds=[cdiag(2, 8, 0, 0), cdiag(0x777, 8, 0, 8)])]))
c.rsp(szl_rsp(0x0078, 0x1000, [dnn(1, tlvs=[(1, le(0x0100)), (2, b'\x01\x02\x03'), (1, le(0x0203)), (9, b'')])]))
c.rsp(szl_rsp(0x0078, 0x1000, [dnn(0, tlvs=[])]))
c.rsp(szl_rsp(0x0078, 0x1000, [dnn(0, version=4)]))
c.rsp(szl_rsp(0x0078, 0x1000, [dnn(0), dnn(0, tlvs=[(1, le(1))])], ll=len(dnn(0))))
for sid in (0x0091, 0x0191, 0x0291, 0x0391, 0x0491, 0x0591, 0x0991, 0x0a91, 0x0c91, 0x4c91, 0x0d91, 0x0e91, 0x4d91):
    c.rsp(szl_rsp(sid, 0, [text(16, 1), text(16, 7)]))
for sid in (0x0092, 0x0192, 0x0292, 0x0392, 0x0492, 0x0592, 0x0692, 0x4092, 0x4292, 0x4692, 0x0a92):
    c.rsp(szl_rsp(sid, 0, [bytes([0x15, 0x80, 0x00, 0xff, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x81])]))
def st94(first, bits=()):
    b = bytearray(256)
    b[0] = first
    for i in bits:
        b[i // 8] |= 1 << (i % 8)
    return struct.pack('>H', 0) + bytes(b)
for sid in (0x0094, 0x0194, 0x0294, 0x0694, 0x0794, 0x0394):
    c.rsp(szl_rsp(sid, 0, [st94(0x01, (1, 2, 9, 100, 2047))]))
c.rsp(szl_rsp(0x0094, 0, [st94(0x00, (1, 9))]))
for sid in (0x0696, 0x0c96):
    c.rsp(szl_rsp(sid, 0, [text(48, 1)]))
for sid in (0x0124, 0x0424):
    c.rsp(szl_rsp(sid, 0, [struct.pack('>HBB', 0x4302, 0x01, 0xd5) + bytes(4) + bytes([1, 2, 3, 4]) + ts8(), text(20, 2)]))
c.rsp(szl_rsp(0x0424, 1, [text(20)]))
c.rsp(szl_rsp(0x0f11, 0, [text(12, 1), text(12, 2)]))            # not decoded: raw list
c.rsp(szl_rsp(0x0017, 0, [text(6, 1)]))

sec('Read SZL responses: list headers, fragments and errors', F)
c.rsp(szl_rsp(0x0076, 0, [le(5, 0x1234)] * 3, cnt=0xffff))        # count larger than the data
c.rsp(szl_rsp(0x0076, 0, [le(5, 0x1234)] * 2, cnt=5))
c.rsp(szl_rsp(0x0076, 0, [], ll=0, cnt=4))                        # no list items
c.rsp(szl_rsp(0x0076, 0, [le(1, 2)], ll=4, cnt=0))
c.rsp(ud(2, 4, 0x01, ext=True, payload=struct.pack('>HHHH', 0x0111, 1, 28, 0)))   # header only
c.rsp(ud(2, 4, 0x01, ext=True, payload=b'', ret=0x0a, tsize=0, dlen=0))
c.rsp(ud(2, 4, 0x01, ext=True, payload=b'\x00\x00', ret=0x0a, tsize=0x09, dlen=2))
c.rsp(ud(2, 4, 0x01, ext=True, payload=b'\x00\x00', ret=0x03, tsize=0x09, dlen=2))
# a response in two fragments (data unit reference 7); the first holds the header and one record
rec = [text(28, 1), text(28, 2), text(28, 3)]
hdr = struct.pack('>HHHH', 0x0111, 1, 28, 3)
c.rsp(ud(2, 4, 0x01, ext=True, seq=30, dur=7, last=1, payload=hdr + rec[0]))
c.rsp(ud(2, 4, 0x01, ext=True, seq=30, dur=7, last=0, payload=rec[1] + rec[2]))
# diagnostic buffer in three fragments
dbuf = [struct.pack('>HBBHHI', 0x8032 + k, 0x16, 1, 0x0102, 0x0304, 0x05060708) + ts8(24, 11, 5, 12, k, 0) for k in range(6)]
hdr = struct.pack('>HHHH', 0x00a0, 0, 20, 6)
c.rsp(ud(2, 4, 0x01, ext=True, seq=31, dur=8, last=1, payload=hdr + dbuf[0] + dbuf[1]))
c.rsp(ud(2, 4, 0x01, ext=True, seq=31, dur=8, last=1, payload=dbuf[2] + dbuf[3]))
c.rsp(ud(2, 4, 0x01, ext=True, seq=31, dur=8, last=0, payload=dbuf[4] + dbuf[5]))
sec(None, F)

# =====================================================================
# malformed capture: records shorter than the decoder reads, bad headers
# =====================================================================
M = mal
m = Conn(M)
sec('malformed', M)
for sid, idx, n in [(0x0000, 0, 1), (0x0013, 0, 20), (0x0014, 1, 4), (0x0015, 1, 6), (0x0011, 1, 20), (0x0222, 0, 10), (0x00a0, 0, 10),
                    (0x001c, 1, 10), (0x0131, 1, 20), (0x0132, 1, 20), (0x0019, 0, 2), (0x0076, 0, 2), (0x0077, 0x1000, 6),
                    (0x0078, 0x1000, 20), (0x0091, 0, 8), (0x0092, 0, 8), (0x0094, 0, 100), (0x0696, 0, 20), (0x0424, 0, 10)]:
    m.rsp(ud(2, 4, 0x01, ext=True, payload=struct.pack('>HHHH', sid, idx, n, 1) + text(n, 1)))
m.rsp(szl_rsp(0x0078, 0x1000, [dnn(3, cds=[cdiag(0, 0, 0, 0)] * 3)[:260]]))
m.rsp(szl_rsp(0x0078, 0x1000, [dnn(1, tlvs=[(1, le(1)), (1, b'\x01\x02\x03\x04')])]))
m.rsp(szl_rsp(0x0078, 0x1000, [dnn(1, tlvs=[(1, b'\x01')])]))
m.rsp(szl_rsp(0x0078, 0x1000, [dnn(0, tlvs=[(5, bytes(200))])[:-50]]))
m.rsp(szl_rsp(0x0077, 0x1000, [le(1, 100, 1, 2)]))
m.rsp(szl_rsp(0x0077, 0x1000, [le(1, 0, 100, 1, 2)]))
m.rsp(ud(2, 4, 0x01, ext=True, payload=struct.pack('>HH', 0x0111, 1)))
m.rsp(ud(2, 4, 0x01, ext=True, payload=struct.pack('>HHH', 0x0111, 1, 28)))
m.req(ud(1, 4, 0x01, payload=struct.pack('>H', 0x0111)))
m.req(ud(1, 4, 0x01, payload=b'\x01'))
sec(None, M)

pcap(os.path.join(OUT, 's7comm_szl_ids-coverage.pcap'), main)
pcap(os.path.join(OUT, 's7comm_szl_ids-coverage-malformed.pcap'), mal)
if VERBOSE:
    for n, a, b in ranges:
        print('%d-%d %s' % (a, b, n))
    print('main', len(main), 'malformed', len(mal))
