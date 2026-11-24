#!/usr/bin/env python3
# Generates test/captures/lbmpdm_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the LBMPDM coverage captures.  Usage: mklbmpdm.py <outdir>

lbmpdm-coverage.pcap            main capture (default preferences)
lbmpdm-coverage-malformed.pcap  malformed messages and the reproducers
lbmpdm-coverage-lbmc.pcap       PDM carried in LBMC over LBT-RM (needs
                                -o lbmc.dissect_lbmpdm:TRUE, runcov.sh only)
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from common import pcap, Flow, udp, ip4, eth

BE, LE = '>', '<'
# field types
(T_BOOLEAN, T_INT8, T_UINT8, T_INT16, T_UINT16, T_INT32, T_UINT32, T_INT64, T_UINT64,
 T_FLOAT, T_DOUBLE, T_DECIMAL, T_TIMESTAMP, T_FIX_STRING, T_STRING, T_FIX_UNICODE,
 T_UNICODE, T_BLOB, T_MESSAGE) = range(19)
ARR = 19
EOM = 0xff


def pdm(e, first, segs, def_id=100, vmaj=1, vmin=0, length=None):
    body = b''.join(segs)
    magic = b'\xa7\x1c\xca\xfe' if e == BE else b'\xfe\xca\x1c\xa7'
    if length is None:
        length = 16 + len(body)
    return magic + struct.pack(e + 'BBBBII', 0x10, first, vmaj, vmin, def_id, length) + body


def seg(e, nxt, data, length=None, flags=0):
    if length is None:
        length = len(data)
    return struct.pack(e + 'BBHI', nxt, flags, 0, length) + data


class F:
    def __init__(self, id, typ, length, fsl=0, narr=0, req=0, fixed=1, name=None, iname=None):
        self.id, self.typ, self.len, self.fsl, self.narr = id, typ, length, fsl, narr
        self.req, self.fixed = req, fixed
        self.name = name if name is not None else 'f%d' % id
        self.iname = iname if iname is not None else id


def defn_seg(e, nxt, def_id, fields, names, vmaj=1, vmin=0, fixed_len=0):
    body = struct.pack(e + 'iiBBBBII', def_id, len(fields), 0 if names else 1, 1, vmaj, vmin, fixed_len, 0)
    for f in fields:
        info = struct.pack(e + 'IIIIBBi', f.id, f.len, f.fsl, f.narr, f.req, f.fixed, f.iname)
        if names:
            nm = f.name.encode() + b'\0' if f.name else b''
            rest = info + struct.pack(e + 'i', len(nm)) + nm + struct.pack(e + 'H', f.typ)
            body += struct.pack(e + 'I', len(rest)) + rest
        else:
            body += info + struct.pack(e + 'iH', 0, f.typ)
    return seg(e, nxt, body)


def ofs_seg(e, nxt, entries):
    return seg(e, nxt, b''.join(struct.pack(e + 'II', i, o) for i, o in entries))


# ---- the big definition ----
FIXED_TYPES = [(T_BOOLEAN, 1), (T_INT8, 1), (T_UINT8, 1), (T_INT16, 2), (T_UINT16, 2),
               (T_INT32, 4), (T_UINT32, 4), (T_INT64, 8), (T_UINT64, 8), (T_FLOAT, 4),
               (T_DOUBLE, 8), (T_DECIMAL, 9), (T_TIMESTAMP, 8)]


def big_fields():
    fl = []
    for t, n in FIXED_TYPES:
        fl.append(F(t, t, n, req=1))                       # ids 0..12 fixed required
    fl.append(F(13, T_FIX_STRING, 10, fsl=10, req=1))
    fl.append(F(14, T_FIX_UNICODE, 8, fsl=8, req=1))
    fl.append(F(15, T_UINT16 + ARR, 6, narr=3, req=1))
    fl.append(F(16, T_BLOB, 4, req=1))
    for t, n in FIXED_TYPES:                                # fixed optional arrays, 2 elements
        fl.append(F(20 + t, t + ARR, 2 * n, narr=2))
    fl.append(F(33, T_FIX_STRING + ARR, 10, fsl=5, narr=2))
    fl.append(F(35, T_FIX_UNICODE + ARR, 8, fsl=4, narr=2))
    for t in (T_STRING, T_UNICODE, T_BLOB, T_MESSAGE):      # variable singles
        fl.append(F(40 + t, t, 0, fixed=0))
        fl.append(F(70 + t, t + ARR, 0, narr=2, fixed=0))   # variable arrays
    fl.append(F(100, T_UINT32, 0, fixed=0))                 # variable length UINT32
    fl.append(F(101, T_INT32, 4))                           # optional fixed
    fl.append(F(102, 99, 0, fixed=0))                       # unknown type -> BLOB
    fl.append(F(103, T_BLOB, 3))                            # optional fixed blob
    fl.append(F(104, T_INT16, 2))                           # defined, never in a table
    fl.append(F(106, T_INT8, 1))                            # offset beyond the segment
    return fl


def dec(e, ex, m):
    return struct.pack(e + 'bq', ex, m)


def vstr(e, b):
    return struct.pack(e + 'I', len(b)) + b


def big_data(e, decimal=(-2, 12345), arr_dec=((3, 5), (-1, -77))):
    """Returns (data segment payload, offset table entries)."""
    d = b''
    d += b'\x01' + struct.pack(e + 'b', -5) + b'\xfe' + struct.pack(e + 'hH', -300, 60000)
    d += struct.pack(e + 'iI', -70000, 4000000000) + struct.pack(e + 'qQ', -(2 ** 40), 2 ** 63 + 5)
    d += struct.pack(e + 'f', 1.5) + struct.pack(e + 'd', -2.25)
    d += dec(e, *decimal) + struct.pack(e + 'II', 1700000000, 123456)
    d += b'fixedstr\0\0' + 'AB'.encode('utf-16-be' if e == BE else 'utf-16-le') * 2
    d += struct.pack(e + 'HHH', 1, 2, 3) + b'\xde\xad\xbe\xef'
    ents = []

    def add(i, b):
        nonlocal d
        ents.append((i, len(d)))
        d += b
    add(20 + T_BOOLEAN, b'\x01\x00')
    add(20 + T_INT8, struct.pack(e + 'bb', -1, 2))
    add(20 + T_UINT8, b'\x01\xff')
    add(20 + T_INT16, struct.pack(e + 'hh', -1, 2))
    add(20 + T_UINT16, struct.pack(e + 'HH', 1, 65535))
    add(20 + T_INT32, struct.pack(e + 'ii', -1, 2))
    add(20 + T_UINT32, struct.pack(e + 'II', 1, 2 ** 32 - 1))
    add(20 + T_INT64, struct.pack(e + 'qq', -1, 2))
    add(20 + T_UINT64, struct.pack(e + 'QQ', 1, 2 ** 64 - 1))
    add(20 + T_FLOAT, struct.pack(e + 'ff', 0.5, -8.0))
    add(20 + T_DOUBLE, struct.pack(e + 'dd', 0.25, 1e100))
    add(20 + T_DECIMAL, dec(e, *arr_dec[0]) + dec(e, *arr_dec[1]))
    add(20 + T_TIMESTAMP, struct.pack(e + 'IIII', 1, 2, 3, 4))
    add(33, b'abcdwxyz\0\0')
    add(35, b'\0A\0B\0C\0D' if e == BE else b'A\0B\0C\0D\0')
    add(40 + T_STRING, vstr(e, b'hello world'))
    add(40 + T_UNICODE, vstr(e, 'héllo'.encode('utf-16-be' if e == BE else 'utf-16-le')))
    add(40 + T_BLOB, vstr(e, b'\x00\x01\x02\x03\x04'))
    add(40 + T_MESSAGE, vstr(e, b'\x10\x20\x30'))
    for t, vals in ((T_STRING, (b'one', b'two2')), (T_UNICODE, (b'\0a', b'\0b\0c')),
                    (T_BLOB, (b'\x01', b'\x02\x03')), (T_MESSAGE, (b'\x09', b'\x08\x07'))):
        inner = b''.join(vstr(e, v) for v in vals)
        add(70 + t, struct.pack(e + 'I', len(inner)) + inner)
    add(100, vstr(e, struct.pack(e + 'I', 0xcafe)))
    add(101, struct.pack(e + 'i', -12345))
    add(102, vstr(e, b'\xaa\xbb'))
    add(103, b'xyz')
    ents.append((105, 0))             # an id the definition does not know
    ents.append((106, 0x00ffff00))    # offset outside the data segment
    return d, ents


def big_msg(e, names, decimal=(-2, 12345), arr_dec=((3, 5), (-1, -77)), def_id=100, vmin=0,
            with_defn=False):
    d, ents = big_data(e, decimal, arr_dec)
    segs = []
    first = 1
    if with_defn:
        first = 2
        segs.append(defn_seg(e, 1, def_id, big_fields(), names, vmin=vmin))
    segs.append(ofs_seg(e, 0, ents))
    segs.append(seg(e, EOM, d))
    return pdm(e, first, segs, def_id=def_id, vmin=vmin)


def small_fields():
    return [F(0, T_INT32, 4, req=1), F(1, T_FIX_STRING, 6, fsl=6, req=1), F(5, T_STRING, 0, fixed=0)]


def small_msg(e, names, def_id, vmaj=1, vmin=0, with_defn=True, text=b'small'):
    d = struct.pack(e + 'i', 77) + b'abcdef'
    ents = [(5, len(d))]
    d += vstr(e, text)
    segs = []
    first = 1
    if with_defn:
        first = 2
        segs.append(defn_seg(e, 1, def_id, small_fields(), names, vmaj=vmaj, vmin=vmin, fixed_len=10))
    segs.append(ofs_seg(e, 0, ents))
    segs.append(seg(e, EOM, d))
    return pdm(e, first, segs, def_id=def_id, vmaj=vmaj, vmin=vmin)


def build_main():
    fr = []
    # ---- stream 1: big endian, integer field names, TCP 14371 ----
    f1 = Flow(50001, 14371, fr)
    f1.open()
    defn_only = pdm(BE, 2, [defn_seg(BE, EOM, 100, big_fields(), False, fixed_len=64)])
    f1.s2c(defn_only)                                   # definition
    f1.s2c(defn_only)                                   # the definition again
    f1.s2c(big_msg(BE, False))                          # data, decimal -2 -> 123.45
    for dv in ((0, -2 ** 63), (0, 2 ** 63 - 1), (3, 77), (3, -77), (1, 10 ** 18), (2, 9 * 10 ** 17),
               (19, 5), (-19, 5), (-64, 12345), (-128, 7), (127, 7), (18, 12), (-18, -123456789012345), (0, 0), (-1, -5)):
        f1.s2c(big_msg(BE, False, decimal=dv, arr_dec=((19, 1), (-20, 1)) if dv[0] == 19 else ((3, 5), (-1, -77))))
    # all in one message: definition, offset table and data of a small definition v1.1
    f1.s2c(small_msg(BE, False, 7, vmin=1))
    # same definition with another id and a data message after it
    f1.s2c(small_msg(BE, False, 7, vmin=1, with_defn=False, text=b'again'))
    # data for a definition that was never seen: shown as plain data
    f1.s2c(small_msg(BE, False, 9999, with_defn=False))
    # data segment without an offset table
    f1.s2c(pdm(BE, 0, [seg(BE, EOM, b'\x00' * 12)], def_id=100))
    # data segment followed by a segment of an unknown type
    f1.s2c(pdm(BE, 0, [seg(BE, 0x07, b'abcd'), seg(BE, EOM, b'\x01\x02\x03')], def_id=100))
    # message with no segment at all
    f1.s2c(pdm(BE, EOM, []))
    # message with an empty offset table
    f1.s2c(pdm(BE, 1, [ofs_seg(BE, 0, []), seg(BE, EOM, struct.pack('>i', 77) + b'abcdef')], def_id=7, vmin=1))
    f1.s2c(pdm(BE, 1, [ofs_seg(BE, 0, []), seg(BE, EOM, b'xx')], def_id=555))
    # message whose first segment is of an unknown type (flags set, ignorable)
    f1.s2c(pdm(BE, 0, [seg(BE, EOM, b'ig', flags=0x80)], def_id=100))
    # two messages in one TCP segment
    m1 = small_msg(BE, False, 7, vmin=1, with_defn=False, text=b'first')
    m2 = small_msg(BE, False, 7, vmin=1, with_defn=False, text=b'second')
    f1.s2c(m1 + m2)
    # one message in two TCP segments
    m3 = small_msg(BE, False, 7, vmin=1, with_defn=False, text=b'split across two segments')
    f1.s2c(m3[:23])
    f1.s2c(m3[23:])
    # a message in three segments (the first must hold a whole header for the heuristic)
    m4 = small_msg(BE, False, 7, vmin=1, with_defn=False, text=b'three')
    f1.s2c(m4[:17])
    f1.s2c(m4[17:20])
    f1.s2c(m4[20:])
    f1.ack_c()
    f1.close()

    # ---- stream 2: little endian, string field names, TCP 14372 ----
    f2 = Flow(50002, 14372, fr, cip='10.0.0.3', sip='10.0.0.4')
    f2.open()
    f2.c2s(pdm(LE, 2, [defn_seg(LE, EOM, 100, big_fields(), True, fixed_len=64)]))
    f2.c2s(big_msg(LE, True))
    f2.c2s(big_msg(LE, True, decimal=(5, -4242), arr_dec=((0, 1), (-5, 100000))))
    f2.c2s(small_msg(LE, True, 8, vmaj=2, vmin=3))
    f2.c2s(small_msg(LE, True, 8, vmaj=2, vmin=3, with_defn=False, text=b'little'))
    # definition and data for an unnamed field (string names, name length 0)
    nm0 = [F(0, T_UINT16, 2, req=1, name=''), F(1, T_BLOB, 0, fixed=0, name='blob')]
    d = struct.pack('<H', 513)
    ents = [(1, len(d))]
    d += vstr(LE, b'bl')
    f2.c2s(pdm(LE, 2, [defn_seg(LE, 1, 11, nm0, True), ofs_seg(LE, 0, ents), seg(LE, EOM, d)], def_id=11))
    # the same data message over two PDUs split mid-segment-header
    m5 = small_msg(LE, True, 8, vmaj=2, vmin=3, with_defn=False, text=b'little two')
    f2.c2s(m5[:19])
    f2.c2s(m5[19:])
    f2.s2c(small_msg(LE, True, 8, vmaj=2, vmin=3, with_defn=False, text=b'reply'))
    f2.close()
    return fr


def build_malformed():
    fr = []
    f = Flow(50011, 14371, fr)
    f.open()
    # reproducers of "LBMPDM: Fix crashes and hangs on malformed messages"
    # decimal exponent -64 (SIGFPE), -128
    for ex in (-64, -128, 127):
        fld = [F(0, T_DECIMAL, 9, req=1)]
        d = struct.pack('>bq', ex, 12345)
        f.c2s(pdm(BE, 2, [defn_seg(BE, 1, 20, fld, False), ofs_seg(BE, 0, [(0, 0)]), seg(BE, EOM, d)], def_id=20))
    # offset table entry with a huge id: 0x7ffffffe, 0x10000, 0x10001
    for i in (0x7ffffffe, 0x10000, 0x10001, 0x7fffffff):
        f.c2s(pdm(BE, 1, [seg(BE, EOM, struct.pack('>II', i, 0))]))
    # segment length of 0xfffffff8 (seglen 0, loop never advanced), 0xfffffff7
    f.c2s(pdm(BE, 2, [seg(BE, 2, struct.pack('>iiBBBBII', 7, 0, 1, 1, 1, 0, 0, 0), length=0xfffffff8)]))
    f.c2s(pdm(BE, 0, [seg(BE, 0, b'abcd', length=0xffffffff)]))
    # segment longer than the message, and than the packet
    f.c2s(pdm(BE, 0, [seg(BE, EOM, b'abcd', length=100)]))
    f.c2s(pdm(BE, 0, [seg(BE, EOM, b'abcd')], length=16 + 8 + 2))
    # message length shorter than the header
    f.c2s(pdm(BE, 0, [], length=5))
    f.c2s(pdm(BE, 0, [seg(BE, EOM, b'abcd')], length=0))
    # array of zero size elements, 2^32 - 1 of them (CPU hang)
    fld = [F(0, T_BLOB + ARR, 0, narr=0xffffffff, req=1)]
    f.c2s(pdm(BE, 2, [defn_seg(BE, 1, 21, fld, False), ofs_seg(BE, 0, [(5, 0)]), seg(BE, EOM, b'\0' * 8)], def_id=21))
    # definition with string names, num_fields 0xffffffff, def_len 0xfffffffc
    body = struct.pack('>iiBBBBII', 22, -1, 0, 1, 1, 0, 0, 0)
    body += struct.pack('>IIIIIBBiiH', 0xfffffffc, 0, 0, 0, 0, 1, 1, 0, 0, 2)
    f.c2s(pdm(BE, 2, [seg(BE, EOM, body)], def_id=22))
    # string-named definition with too short and too long def_len
    for dl in (3, 27, 5000):
        body = struct.pack('>iiBBBBII', 23, 1, 0, 1, 1, 0, 0, 0)
        body += struct.pack('>IIIIIBBiiH', dl, 0, 0, 0, 0, 1, 1, 0, 0, 2)
        f.c2s(pdm(BE, 2, [seg(BE, EOM, body)], def_id=23))
    # integer-named definition cut short (no room for the field info)
    body = struct.pack('>iiBBBBII', 24, 1, 1, 1, 1, 0, 0, 0) + b'\0' * 10
    f.c2s(pdm(BE, 2, [seg(BE, EOM, body)], def_id=24))
    # array whose elements have zero size, a few of them
    fld = [F(0, T_BLOB + ARR, 0, narr=3, req=1)]
    f.c2s(pdm(BE, 2, [defn_seg(BE, 1, 25, fld, False), ofs_seg(BE, 0, [(5, 0)]), seg(BE, EOM, b'\0' * 8)], def_id=25))
    # fixed required fields that do not fit in the data segment (bounds exception)
    f.c2s(small_msg(BE, False, 7, vmin=1))
    f.c2s(pdm(BE, 1, [ofs_seg(BE, 0, []), seg(BE, EOM, b'xx')], def_id=7, vmin=1))
    # offset table entry with a negative offset (throws ReportedBoundsError)
    f.c2s(pdm(BE, 1, [seg(BE, EOM, struct.pack('>II', 1, 0xffffff00))]))
    f.c2s(pdm(BE, 1, [seg(BE, EOM, struct.pack('>II', 0xffffff00, 1))]))
    # wrong length for the value of a field (FLOAT with 3 bytes)
    fld = [F(0, T_FLOAT, 3, req=1)]
    f.c2s(pdm(BE, 2, [defn_seg(BE, 1, 26, fld, False), ofs_seg(BE, 0, [(0, 0)]), seg(BE, EOM, b'\0' * 8)], def_id=26))
    # a data field that runs past the end of the data
    fld = [F(0, T_UINT32, 4, req=1), F(1, T_STRING, 0, fixed=0)]
    f.c2s(pdm(BE, 2, [defn_seg(BE, 1, 27, fld, False), ofs_seg(BE, 0, [(1, 4)]),
                      seg(BE, EOM, struct.pack('>II', 1, 1000) + b'abc')], def_id=27))
    # variable array whose total length prefix is cut
    f.c2s(pdm(BE, 0, [seg(BE, EOM, b'ab')], length=16 + 8 + 100))
    # bad magic and bad next header in a connection the heuristic has already claimed
    f.c2s(b'\xa7\x1c\xca\xff' + b'\0' * 20)
    f.c2s(b'\xa7\x1c\xca\xfe' + struct.pack('>BBBBII', 0x10, 5, 1, 0, 1, 16))
    f.close()
    # Headers the heuristic refuses, each in a new connection: after the heuristic has
    # claimed a connection, a bad header goes to get_lbmpdm_tcp_pdu_length() instead
    for cport, data in ((50012, b'\xa7\x1c\xca\xff' + b'\0' * 20),
                        (50013, b'\xa7\x1c\xca\xfe' + struct.pack('>BBBBII', 0x10, 5, 1, 0, 1, 16)),
                        (50014, b'\xfe\xca\x1c\xa7' + struct.pack('<BBBBII', 0x10, 0, 1, 0, 1, 0x80000000) + b'\0' * 8)):
        f = Flow(cport, 14371, fr)
        f.open()
        f.c2s(data)
        f.close()
    return fr


def build_lbmc():
    """LBMC data message carrying PDM over LBT-RM (UDP, multicast)."""
    fr = []
    sess = 0x11223344

    def lbtrm(lbmc, sqn):
        hdr = struct.pack('!BBHI', 0x00, 0x00, 14390, sess)
        data = struct.pack('!IIBBH', sqn, 0, 0, 0, 0)
        return hdr + data + lbmc

    def lbmc_msg(payload, sqn, tidx=1):
        return struct.pack('!BBHII', 0x00, 0x00, 12 + len(payload), tidx, sqn) + payload

    def frame(payload):
        u = udp(14390, 14400, payload)
        return eth(b'\x01\x00\x5e\x0a\x0a\x0a', b'\x02\x00\x00\x00\x00\x01', 0x0800,
                   ip4('10.0.0.1', '224.10.10.10', 17, u))
    msgs = [pdm(BE, 2, [defn_seg(BE, EOM, 100, big_fields(), False)]),
            big_msg(BE, False),
            small_msg(BE, False, 7, vmin=1),
            small_msg(LE, True, 8, vmaj=2, vmin=3)]
    # shorter than a PDM header; a message length smaller than the header (8 and 0)
    msgs += [pdm(BE, 0, [], length=16)[:10], pdm(BE, 0, [seg(BE, EOM, b'abcd')], length=8),
             pdm(LE, 0, [seg(LE, EOM, b'abcd')], length=0)]
    for i, m in enumerate(msgs):
        fr.append(frame(lbtrm(lbmc_msg(m, i + 1), i + 1)))
    return fr


if __name__ == '__main__':
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    pcap(os.path.join(out, 'lbmpdm-coverage.pcap'), build_main())
    pcap(os.path.join(out, 'lbmpdm-coverage-malformed.pcap'), build_malformed())
    pcap(os.path.join(out, 'lbmpdm-coverage-lbmc.pcap'), build_lbmc())
