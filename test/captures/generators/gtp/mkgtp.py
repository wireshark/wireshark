#!/usr/bin/env python3
# Generates test/captures/gtp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the GTP coverage captures.  Usage: mkgtp.py <outdir>

GTP is reached by UDP port 3386 (GTPv0 and GTP', dissector gtpprime), 2123
(GTPv0/v1 control) and 2152 (GTPv1 user plane), all registered by default.
The message and IE tables are read from packet-gtp.c (parse_gtp.py) so every
message type of GTPv0 and GTPv1 is generated with every IE the table lists,
with valid content for each IE.  No keys or ciphertext are produced: the
authentication and key fields are fixed filler bytes.
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import socket
import struct
from common import pcap, ip4, udp, eth, csum, tcpseg
import parse_gtp as P

D = P.DEF
M1 = bytes.fromhex('0200000000a1'); M2 = bytes.fromhex('0200000000a2')
PLMN = bytes.fromhex('13f014')
V4 = bytes([192, 0, 2, 10])
V6 = socket.inet_pton(socket.AF_INET6, '2001:db8::1')


def u16(x): return struct.pack('>H', x)
def u32(x): return struct.pack('>I', x)


def tv(code, content):
    return bytes([code]) + content


def tlv(code, content):
    return bytes([code]) + u16(len(content)) + content


def apn(*labels):
    return b''.join(bytes([len(l)]) + l.encode() for l in labels)


def qos_umts(n, over=None, tc=1):
    """UMTS QoS profile content of n octets (byte 0 is the allocation/retention priority)."""
    base = [0x02, 0x23, 0x7a, 0x44, tc << 5 | 0x13, 0x56, 0x2a, 0x40, 0x33, 0x4b, 0x30, 0x7d, 0x0b,
            0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20]
    b = bytearray(base[:n])
    for k, v in (over or {}).items():
        if k < n:
            b[k] = v
    return bytes(b)


def mm_ctx(mode, count, ver, container=True, netcap=b'\xe5\x40\x00', drx=b'\x09\x23'):
    """MM context.  mode = security mode (0..3)."""
    body = bytes([0x07 if mode != 1 else 0x03])            # CKSN/KSI
    cipher = 1
    body += bytes([(mode << 6) | (count << 3) | cipher])
    trip = b''.join(bytes([0x10 + i] * 16 + [0x20 + i] * 4 + [0x30 + i] * 8) for i in range(count))
    quint = b''.join(bytes([0x40 + i] * 16) + bytes([4]) + bytes([0x50 + i] * 4) + bytes([0x60 + i] * 16)
                     + bytes([0x70 + i] * 16) + bytes([6]) + bytes([0x80 + i] * 6) for i in range(count))
    if mode == 1:
        body += bytes([0xa1] * 8) + trip
    elif mode == 0 or mode == 2:
        body += bytes([0xb1] * 16) + bytes([0xb2] * 16) + u16(len(quint)) + quint
    else:
        body += bytes([0xa1] * 8) + u16(len(quint)) + quint
    body += drx + bytes([len(netcap)]) + netcap
    if container:
        c = bytes([0x23, 5, 0xf4, 0x11, 0x22, 0x33, 0x44])  # IEI 0x23 mobile identity (TMSI)
        body += u16(len(c)) + c
    else:
        body += u16(0)
    return body


def pdp_ctx(ver, ea=False, v6=False, apnname='internet.example', gc=4, gu=16, ptype=None, ea_type=None):
    b = bytearray()
    b.append((0x80 if ea else 0) | 0x40 | 0x20 | 0x10 | 5)   # EA, VPLMN, ASI, ORDER, NSAPI
    b.append(0x03)                                             # SAPI
    if ver == 0:
        for q in range(3):
            b += bytes([0x12, 0x34 + q, 0x0d])
    else:
        for q in (4, 13, 21):
            b.append(q); b += qos_umts(q)
    b += u16(1) + u16(2) + bytes([3, 4])                       # SN down/up, send/receive N-PDU
    if ver == 0:
        b += u16(0x1234)
    else:
        b += u32(0x1000) + u32(0x2000) + bytes([7])
    pt = ptype if ptype is not None else (0x57 if v6 else 0x21)
    addr = V6 if pt == 0x57 else (V4 if pt == 0x21 else b'\x09\x09')
    b += bytes([0xf1, pt, len(addr)]) + addr
    b += bytes([gc]) + (V4 if gc == 4 else V6 if gc == 16 else bytes(gc))
    if ver == 1:
        b += bytes([gu]) + (V4 if gu == 4 else V6 if gu == 16 else bytes(gu))
    a = apn(*apnname.split('.'))
    b += bytes([len(a)]) + a
    b += bytes([0x05, 0x00])                                   # transaction id
    if ea:
        et = ea_type if ea_type is not None else 0x21
        ad = V4 if et == 0x21 else V6 if et == 0x57 else b'\x09\x09'
        b += bytes([et, len(ad)]) + ad
    return bytes(b)


def pco():
    # configuration protocol 0 (PPP): LCP, IPCP with DNS request, then container IDs
    return bytes([0x80, 0xc0, 0x21, 0x04, 0x01, 0x01, 0x00, 0x04,
                  0x80, 0x21, 0x10, 0x01, 0x01, 0x00, 0x10, 0x81, 0x06, 0, 0, 0, 0, 0x83, 0x06, 0, 0, 0, 0,
                  0x00, 0x0a, 0x00, 0x00, 0x03, 0x00])


def tft():
    # create new TFT, 1 packet filter, one IPv4 remote address + mask component
    return bytes([0x21, 0x01, 0x10, 0x09, 0x10, 192, 0, 2, 0, 255, 255, 255, 0])


def msisdn(n=b'\x91\x19\x32\x54\x76\x98\xf0'):
    return n


def ie_samples(ver):
    """code -> list of complete IEs (type byte included).  The first is used in the
    messages, the others in the IE variant messages."""
    S = {}

    def add(code, *contents, kind=None):
        k = kind or ('tv' if code < 0x80 else 'tlv')
        S.setdefault(code, [])
        for c in contents:
            S[code].append(tv(code, c) if k == 'tv' else tlv(code, c))

    add(0x01, b'\x80', b'\x00', b'\xff', b'\x40', b'\xc0')                   # cause
    add(0x02, bytes.fromhex('13400121436587f9'), bytes.fromhex('62022143658709f1'))
    add(0x03, PLMN + u16(0x1234) + b'\x05')
    add(0x04, u32(0xcafe0001))
    add(0x05, u32(0xdeadbeef))
    add(0x06, bytes([0x12, 0x34, 0x0d]))
    add(0x08, b'\x01', b'\x00')
    add(0x09, bytes(range(28)))
    add(0x0b, b'\x03', b'\x07')
    add(0x0c, b'\x01\x02\x03')
    add(0x0d, b'\x01', b'\x00')
    add(0x0e, b'\x0a')
    add(0x0f, b'\xfc', b'\xfd', b'\xfe', b'\xff')
    if ver == 0:
        add(0x10, u16(0x1111)); add(0x11, u16(0x2222)); add(0x12, b'\x05' + u16(0x3333))
        add(0x13, b'\x00', b'\x01', b'\x02', b'\x03')
    else:
        add(0x10, u32(0x11110000)); add(0x11, u32(0x22220000)); add(0x12, b'\x05' + u32(0x33330000))
        add(0x13, b'\x01', b'\x00')
    add(0x14, b'\x05', b'\x0f')
    add(0x15, b'\x01', b'\x41', b'\x51', b'\x61', b'\x71', b'\x81')
    add(0x16, b'\x05' + u16(1) + u16(2) + u16(3) + u16(4))
    add(0x17, b'\x03')
    add(0x18, b'\x53')
    add(0x19, b'\x05\x09')
    add(0x1a, u16(0x0800), u16(0xf000))
    add(0x1b, u16(0x0102))
    add(0x1c, u16(0x0304))
    add(0x1d, b'\x00', b'\x01', b'\x02', b'\x03')
    add(0x7e, b'\x00', b'\x01')
    add(0x7f, u32(0x12345678))
    # end user address
    add(0x80, bytes([0xf1, 0x21]) + V4, bytes([0x00, 0x01]), bytes([0xf1, 0x02]), bytes([0xf1, 0x57]) + V6,
        bytes([0xf1, 0x8d]) + V4, bytes([0xf1, 0x8d]) + V6, bytes([0xf1, 0x8d]) + V4 + V6,
        bytes([0xf1, 0x8d]) + b'\x01\x02\x03', bytes([0xf1, 0x21]), b'', b'\xf1')
    # MM context
    if ver == 0:
        add(0x81, mm_ctx(1, 2, 0), mm_ctx(1, 0, 0, container=False), mm_ctx(1, 1, 0, netcap=b''), b'')
    else:
        add(0x81, mm_ctx(1, 2, 1), mm_ctx(0, 2, 1), mm_ctx(2, 1, 1), mm_ctx(3, 1, 1),
            mm_ctx(0, 0, 1, container=False), mm_ctx(1, 1, 1, netcap=b''), b'')
        c = mm_ctx(1, 1, 1, container=False)[:-2] + u16(3) + b'\x99\x01\x02'
        S[0x81].append(tlv(0x81, c))
    add(0x82, pdp_ctx(ver), pdp_ctx(ver, ea=True), pdp_ctx(ver, ea=True, ea_type=0x57), pdp_ctx(ver, v6=True), pdp_ctx(ver, gc=16, gu=4),
        pdp_ctx(ver, ptype=0x01, gc=3, gu=3), pdp_ctx(ver, ea=True, ea_type=0x01, ptype=0x01), pdp_ctx(ver, ea=True, ea_type=0x01, ptype=0x57, gc=16))
    add(0x83, apn('internet', 'example', 'com'), apn('a'), b'', b'\x04abcd\x00', b'\x02ab\x07toolong')
    add(0x84, pco())
    add(0x85, V4, V6, b'\x00' + V4, b'\x00' + V6, b'\x01\x02\x03')
    add(0x86, msisdn(), b'')
    ext4 = lambda v: {13: v, 14: v, 15: v, 16: v}
    ext8 = lambda v: {13: v, 14: v, 15: v, 16: v, 17: v, 18: v, 19: v, 20: v}
    add(0x87, qos_umts(12), qos_umts(4), qos_umts(13),
        qos_umts(12, {5: 0, 6: 0, 7: 255, 10: 0, 11: 255}),
        qos_umts(12, {5: 0xa0, 6: 0x50, 7: 0x90, 10: 0x50, 11: 0x90}),
        qos_umts(12, {6: 0xf0, 7: 0x7f, 10: 0xf0, 11: 0x7f}),
        qos_umts(12, {6: 0x20, 7: 0x20, 10: 0x20, 11: 0x20}),
        qos_umts(12, tc=2), qos_umts(12, tc=3), qos_umts(12, tc=4), qos_umts(12, tc=0),
        qos_umts(15, ext4(0)), qos_umts(15, ext4(0x20)), qos_umts(15, ext4(0x60)), qos_umts(15, ext4(0xc0)), qos_umts(15, ext4(0xff)),
        qos_umts(17, ext4(0)), qos_umts(17, ext4(0x20)), qos_umts(17, ext4(0x60)), qos_umts(17, ext4(0xc0)), qos_umts(17, ext4(0xff)),
        qos_umts(19, ext8(0)), qos_umts(19, ext8(0x20)), qos_umts(19, ext8(0x50)), qos_umts(19, ext8(0xb0)), qos_umts(19, ext8(0xf0)), qos_umts(19, ext8(0xff)),
        qos_umts(21, ext8(0)), qos_umts(21, ext8(0x20)), qos_umts(21, ext8(0x50)), qos_umts(21, ext8(0xb0)), qos_umts(21, ext8(0xf0)), qos_umts(21, ext8(0xff)))
    add(0x88, bytes(range(16)) + bytes([4]) + bytes([1, 2, 3, 4]) + bytes(range(16)) + bytes(range(16))
        + bytes([6]) + bytes(range(6)))
    add(0x89, tft())
    add(0x8a, PLMN + u16(0x1234) + b'\x05' + u16(0x0102), PLMN + u16(0x1234) + b'\x05' + u16(0x0102) + u16(0x0304),
        b'\x00' + PLMN + u16(0x1234) + b'\x05' + u16(0x0102), b'')
    add(0x8b, bytes.fromhex('000002aabb00'), bytes.fromhex('0002aabb'), b'')
    add(0x8c, b'\x05' + u32(0x1234) + V4, b'\x05' + u32(0x1234) + V6, b'\x05', b'\x05' + u32(0x1234) + bytes(12))
    S[0x8d] = [bytes([0x8d, 3, 0x40, 0x81, 0xc0]), bytes([0x8d, 0])]
    add(0x8e, b'\x01\x02\x03\x04')
    add(0x8f, b'\x01\x02\x03\x04\x05\x06')
    add(0x90, b'\xee\x01')
    add(0x91, b'\x01\x02')
    add(0x92, b'\x05' + u32(0x1234) + V4, b'\x05', b'\x05' + u32(0x1234) + V6)
    add(0x93, msisdn())
    add(0x94, b'\xff', b'\x00', b'\x01')
    add(0x95, b'\x01', b'\x01\x02')
    add(0x96, b'\x03')
    add(0x97, b'\x01', b'\x02', b'\x03', b'\x04', b'\x05', b'\x01\x02')
    add(0x98, b'\x00' + PLMN + u16(0x1234) + u16(0x5678), b'\x01' + PLMN + u16(0x1234) + u16(0x5678),
        b'\x02' + PLMN + u16(0x1234) + b'\x05', b'\x09' + PLMN + u16(0x1234) + b'\x05')
    add(0x99, b'\x0a\x01', b'\x8a\x02')
    add(0x9a, bytes.fromhex('1334010203040506f7'))
    add(0x9b, bytes.fromhex('3100'))
    add(0x9c, b'\x05' + u32(0x1234) + b'\x85' + bytes([0xf1, 0x21, 4]) + V4 + bytes([4]) + V4
        + bytes([len(apn('mbms', 'example'))]) + apn('mbms', 'example') + b'\x01\x00',
        b'\x05' + u32(0x1234) + b'\x05' + bytes([0xf1, 0x57, 16]) + V6 + bytes([16]) + V6 + bytes([3]) + b'abc' + b'\x01\x00',
        b'\x05' + u32(0x1234) + b'\x05' + bytes([0xf1, 0x01, 2, 9, 9]) + bytes([3]) + b'abc' + bytes([0]) + b'\x01\x00')
    add(0x9d, bytes.fromhex('f5') + b'\x01\x02\x03' + PLMN + b'\x07', bytes.fromhex('d5') + b'\x01\x02\x03' + PLMN,
        bytes.fromhex('e5') + b'\x01\x02\x03' + b'\x07', bytes.fromhex('c5') + b'\x01\x02\x03')
    add(0x9e, bytes(8), bytes(9), bytes(10))
    add(0x9f, b'\x80')
    add(0xa0, b'\x01' + u16(0x1234) + u16(0x5678), b'\x00' + u16(0x1234))
    add(0xa1, b'\x00')
    add(0xa2, PLMN + u16(0x1234) + b'\x05\x06\x07', PLMN + u16(0x1234) + b'\x05\x06\x07' + bytes(4))
    add(0xa3, b'\x05')
    add(0xa4, PLMN)
    add(0xa5, b'\x05')
    add(0xa6, b'\x01', b'\x00', b'\x03')
    add(0xa7, b'\x85', b'\x05')
    add(0xa8, bytes([0x01, 0x02, 0x03]), bytes([0x00, 0x00, 0x00]), bytes([0xff, 0xff, 0xff]))
    add(0xa9, PLMN + u16(0x1234) + b'\x05\x06\x07', PLMN + u16(0x1234) + bytes(9))
    add(0xaa, b'\x05')
    add(0xab, b'\x05', b'\x00')
    add(0xac, b'\x01\x02\x03\x04')
    add(0xad, b'\x13\x82\x00\x00', b'')
    add(0xae, PLMN + u16(0x1234) + b'\x05' + u16(0x0102) + b'\x00' + PLMN + u16(0x4321) + b'\x06' + u16(0x0304),
        PLMN + u16(0x1234) + b'\x05' + u16(0x0102) + b'\x01' + PLMN + u16(0x4321) + b'\x06' + u16(0x0304),
        PLMN + u16(0x1234) + b'\x05' + u16(0x0102) + b'\x02' + PLMN + u16(0x4321) + b'\x06' + u16(0x0304))
    add(0xaf, u16(1) + u16(2) + u16(3) + bytes(2), u16(1) + u16(2) + u16(3))
    add(0xb0, b'\x05')
    add(0xb1, b'\x01\x02\x03\x04', b'')
    add(0xb2, b'\x00', b'\x01', b'\x02')
    add(0xb3, b'\x02\x05\x06', b'\x00', b'\x0c')
    add(0xb4, b'\x01\x02\x03\x04\x05')
    add(0xb5, b'\x01', b'\x00')
    add(0xb6, b'\x01', b'\x01\x02')
    add(0xb7, b'\x05')
    add(0xb8, b'\x01', b'\x02')
    add(0xb9, u16(0x1234))
    add(0xba, b'\x01\x02\x03\x04')
    add(0xbb, b'\x01', b'\x00')
    add(0xbc, b'\x01', b'\x00')
    add(0xbd, u16(0x1234))
    add(0xbe, apn('gw', 'example', 'com'), apn('a'))
    add(0xbf, b'\x15', b'\x95')
    add(0xc0, b'\x05\x15', b'\x05\x95')
    add(0xc1, b'\xff', b'\x00', b'\x00\x01')
    add(0xc2, PLMN + u32(0x1234) + b'\x03' + b'\x01', PLMN + u32(0x1234) + b'\x01\x00', PLMN + u32(0x1234) + b'\x00' + b'\x00')
    add(0xc3, b'\x07', b'\x00')
    add(0xc4, b'\x01\x02\x03\x04', b'\x00\x00\x00\x01')
    add(0xc5, b'\x01', b'\x00', b'\x01\x02')
    add(0xc6, u32(1000) + u32(2000))
    add(0xc7, b'\xe0\xe0\xe0\xe0', b'\x00\x00\x00\x00')
    add(0xc8, u32(1000) + u32(2000), u32(1000) + u32(2000) + u32(3000) + u32(4000), u32(1000) + u32(2000) + u32(3000) + u32(4000) + b'\x01')
    add(0xc9, b'\x05' + u32(1000) + u32(2000))
    add(0xca, b'\x65', b'\x25')
    add(0xcb, b'\x01', b'\x00')
    add(0xcc, b'\x05\x01')
    add(0xcd, b'\x01', b'\x00')
    add(0xce, u32(1000) + u32(2000))
    add(0xcf, b'\x03\x00\x00\x00\x00\x00', b'\x00\x00\x00')
    add(0xd0, b'\x01', b'\x00')
    add(0xd1, bytes([0x91, 0x19, 0x32]))
    add(0xd2, bytes([0x91, 0x19, 0x32, 0x54, 0x76, 0x98, 0xf0]))
    add(0xd3, bytes.fromhex('0f0040'), bytes.fromhex('0f'))
    add(0xd4, b'\x00' + PLMN + b'\x01\x02\x03' + u16(0x1234), b'\x01' + PLMN + u32(0x01020304) + u16(0x1234), b'\x02' + PLMN + bytes(4))
    add(0xd5, b'\x15', b'\x05')
    add(0xd6, u32(0x01020304))
    add(0xd7, b'\x05' + b'lhn.example', b'\x05')
    add(0xd8, b'\x01', b'\x00', b'\x01\x02')
    add(0xd9, u32(0x12345678), u32(0x12345678) + b'\x01')
    add(0xda, b'\x07', b'\x00', b'\x00\x01')
    add(0xdb, b'\x0cnode.example\x0drealm.example', b'\x02ab\x00')
    add(0xdc, b'\x03', b'\x00', b'\x00\x01')
    add(0xdd, bytes([len(apn('scef', 'example'))]) + apn('scef', 'example') + b'\x05' + u16(5) + b'scef1',
        bytes([len(apn('s'))]) + apn('s') + b'\x05' + u16(5) + b'scef1' + b'\x01')
    add(0xde, b'\x05', b'\x05\x06')
    add(0xdf, u16(0x1234), u16(0x1234) + b'\x01')
    add(0xe0, b'\x01', b'\x00', b'\x01\x02')
    # charging
    add(0xf9, u16(1) + u16(2), b'', u16(1))
    add(0xfa, u16(3) + u16(4), b'')
    add(0xfb, V4, V6, b'\x01\x02')
    add(0xfe, V4, V6, b'\x01\x02')
    add(0xff, u16(0x1234) + b'private data', u16(0x1234), b'\x01', b'')
    return S


def build_ies(ver):
    """Flatten ie_samples; cached for both versions."""
    return ie_samples(ver)


def ies_for(codes, ver, k=0, pick=None):
    S = build_ies(ver)
    out = b''
    for c in codes:
        alts = S.get(c)
        kk = (pick or {}).get(c, k)
        if not alts:
            out += tlv(c, bytes(4)) if c >= 0x80 else tv(c, b'\x00')
        else:
            out += alts[min(kk, len(alts) - 1)]
    return out


# ---------------------------------------------------------------------------
# headers and transport

def v0_header(msg, payload, seq=1, flow=0x10, tid=bytes.fromhex('1334010203040506'), nsapi=5, snn=0):
    return struct.pack('>BBHHHB3s8s', 0x1e | snn, msg, len(payload), seq, flow, nsapi, b'\xff\xff\xff', tid) + payload


def v1_header(msg, payload, teid=0x1000, seq=1, flags=0x32, npdu=0, ext=b'', short=False):
    """short: no sequence/npdu/next-ext octets (flags & 7 == 0)"""
    if short:
        return struct.pack('>BBHI', flags & ~7, msg, len(payload), teid) + payload
    opt = struct.pack('>HB', seq, npdu) + (ext if ext else b'\x00')
    return struct.pack('>BBHI', flags, msg, len(payload) + len(opt), teid) + opt + payload


def prime_header(msg, payload, ver=0, seq=1, short=False):
    if ver == 0 and not short:
        return struct.pack('>BBHH', 0x0e, msg, len(payload), seq) + bytes(14) + payload
    flags = (ver << 5) | 0x0e | (1 if ver == 0 else 0)
    return struct.pack('>BBHH', flags, msg, len(payload), seq) + payload


def pkt(payload, sport, dport, src='10.0.0.1', dst='10.0.0.2', vlan=None):
    ip = ip4(src, dst, 17, udp(sport, dport, payload))
    if vlan:
        return eth(M2, M1, 0x8100, struct.pack('>HH', vlan, 0x0800) + ip)
    return eth(M2, M1, 0x0800, ip)


def udp6(src, dst, sp, dp, payload):
    h = struct.pack('>HHHH', sp, dp, 8 + len(payload), 0)
    c = csum(src + dst + struct.pack('>IBBBB', len(h) + len(payload), 0, 0, 0, 17) + h + payload) or 0xffff
    return h[:6] + struct.pack('>H', c) + payload


def pkt6(payload, sport, dport):
    a = socket.inet_pton(socket.AF_INET6, '2001:db8::a'); b = socket.inet_pton(socket.AF_INET6, '2001:db8::b')
    u = udp6(a, b, sport, dport, payload)
    return eth(M2, M1, 0x86dd, struct.pack('>IHBB', 0x60000000, len(u), 17, 64) + a + b + u)


def inner_ip(payload=b'inner'):
    return ip4('172.16.0.1', '172.16.0.2', 17, udp(5000, 5001, payload))


def inner_ip6():
    a = socket.inet_pton(socket.AF_INET6, 'fd00::1'); b = socket.inet_pton(socket.AF_INET6, 'fd00::2')
    u = udp6(a, b, 5000, 5001, b'inner6')
    return struct.pack('>IHBB', 0x60000000, len(u), 17, 64) + a + b + u


def inner_eth():
    return eth(M2, M1, 0x0800, inner_ip())


MSG = {}
for n, v in D.items():
    if n.startswith('GTP_MSG_'):
        MSG[n] = v


def message_ies(table, name):
    for mn, fl in table:
        if mn == name:
            return [D[f] for f, p, a in fl]
    return None


def gtp_u(msg, payload=b'', teid=0x1000, flags=0x30, seq=None, npdu=0, chain=()):
    """GTP-U header.  chain: list of (ext header type, content bytes)."""
    opt = b''
    f = flags
    if chain:
        f |= 0x04
    if seq is not None:
        f |= 0x02
    if chain or seq is not None or (f & 1):
        nxt = chain[0][0] if chain else 0
        opt = struct.pack('>HBB', seq or 0, npdu, nxt)
        body = b''
        for k, (t, c) in enumerate(chain):
            nt = chain[k + 1][0] if k + 1 < len(chain) else 0
            n = (len(c) + 2 + 3) // 4
            c = c + bytes(n * 4 - 2 - len(c))
            body += bytes([n]) + c + bytes([nt])
        opt += body
    return struct.pack('>BBHI', f, msg, len(opt) + len(payload), teid) + opt + payload


def pdu_session(kind, **kw):
    """PDU session container content (without the extension header length and next type)."""
    if kind == 'dl':
        qmp, snp, msnp, ppp = kw.get('qmp', 0), kw.get('snp', 0), kw.get('msnp', 0), kw.get('ppp', 0)
        b = bytes([(0 << 4) | (qmp << 3) | (snp << 2) | (msnp << 1), (ppp << 7) | 0x40 | 9])
        if ppp:
            b += bytes([0x80])
        if qmp:
            b += bytes(range(1, 9))
        if snp:
            b += b'\x00\x00\x07'
        if msnp:
            b += b'\x00\x00\x00\x09'
        return b
    qmp, dld, uld, snp, n3, newie = (kw.get(k, 0) for k in ('qmp', 'dld', 'uld', 'snp', 'n3', 'newie'))
    b = bytes([(1 << 4) | (qmp << 3) | (dld << 2) | (uld << 1) | snp, (n3 << 7) | (newie << 6) | 5])
    if qmp:
        b += bytes(range(1, 25))
    if dld:
        b += u32(100)
    if uld:
        b += u32(200)
    if snp:
        b += b'\x00\x00\x08'
    if n3:
        b += u32(300)
    if newie:
        b += bytes([kw.get('f5', 0)])
        if kw.get('f5', 0) & 1:
            b += bytes([0x01])
    return b


def nrup(kind, **kw):
    if kind == 'dl':
        disc, flush, rep = kw.get('disc', 0), kw.get('flush', 0), kw.get('rep', 0)
        b = bytes([(0 << 4) | (disc << 2) | (flush << 1) | 1, (rep << 3) | 0x04 | 0x02 | 0x01]) + b'\x00\x00\x2a'
        if flush:
            b += b'\x00\x00\x10'
        if disc:
            b += bytes([2]) + b'\x00\x00\x11\x05' + b'\x00\x00\x12\x06'
        if rep:
            b += b'\x00\x00\x13'
        return b
    if kind == 'status':
        htx, hdel, lost, rate, hretx, hdretx, cause = (kw.get(k, 0) for k in ('htx', 'hdel', 'lost', 'rate', 'hretx', 'hdretx', 'cause'))
        b = bytes([0x10 | (htx << 3) | (hdel << 2) | 0x02 | lost, (rate << 3) | (hretx << 2) | (hdretx << 1) | cause]) + u32(1000)
        if rate:
            b += u32(5000)
        if lost:
            b += bytes([2]) + b'\x00\x00\x01\x00\x00\x03' + b'\x00\x00\x05\x00\x00\x07'
        if hdel:
            b += b'\x00\x00\x21'
        if htx:
            b += b'\x00\x00\x22'
        if cause:
            b += b'\x01'
        if hdretx:
            b += b'\x00\x00\x23'
        if hretx:
            b += b'\x00\x00\x24'
        return b
    dup, ai, uld, dld = (kw.get(k, 0) for k in ('dup', 'ai', 'uld', 'dld'))
    b = bytes([0x20 | (dup << 3) | (ai << 2) | (uld << 1) | dld, kw.get('sugg', 1)])
    if ai:
        b += bytes([2, 1, 3, 1, 2, 3, 2, 4]) + bytes(4)
    if uld:
        b += u32(11)
    if dld:
        b += u32(22)
    return b


def data_record(fmt, app_rel, ver, records, rel_ext=None, nrec=None):
    b = bytes([nrec if nrec is not None else len(records), fmt, app_rel, ver])
    if rel_ext is not None:
        b += bytes([rel_ext])
    for r in records:
        b += u16(len(r)) + r
    return b


def tr_comm_set():
    return tv(0x7e, b'\x01')


def build():
    fr = []
    A = fr.append
    marks = []

    def mark(name):
        marks.append((len(fr) + 1, name))
    gprs = P.table('gprs_mess_items')
    umts = P.table('umts_mess_items')

    # ---- GTPv0 (every message type with every IE of its table)
    seq = 1
    for mn, fl in gprs:
        m = D[mn]
        codes = [D[f] for f, p, a in fl]
        port = 2123 if seq % 7 == 0 else 3386
        A(pkt(v0_header(m, ies_for(codes, 0), seq=seq), port, port))
        seq += 1
    mark('GTPv1 messages')
    # ---- GTPv1 control plane
    for mn, fl in umts:
        m = D[mn]
        codes = [D[f] for f, p, a in fl]
        pick = {0x8b: 1, 0xad: 1} if mn == 'GTP_MSG_FORW_RELOC_RESP' else {}
        A(pkt(v1_header(m, ies_for(codes, 1, pick=pick), seq=seq, teid=0x1000 + seq), 2123, 2123))
        seq += 1
        if any(a != 'NULL' for f, p, a in fl):
            # the GSN addresses with an alternate decoder (ETSI order check): every address format
            for kk in (1, 2, 3):
                A(pkt(v1_header(m, ies_for(codes, 1, pick={0x85: kk}), seq=seq, teid=0x1000 + seq), 2123, 2123))
                seq += 1

    mark('IE variants')
    # ---- GTPv0 / GTPv1 IE variants (alternate contents of each IE)
    BAD = bad_variants()
    for ver in (0, 1):
        S = build_ies(ver)
        maxk = max(len(v) for v in S.values())
        for carrier, tag in ((0x12, 'ul'), (0x13, 'dl')):
            for k in range(0, maxk):
                parts = []
                for code in sorted(S):
                    if len(S[code]) <= k or (ver, code, k) in BAD:
                        continue
                    if code in (0x8b, 0xad, 0xa1):
                        # transparent containers depend on the direction of the message
                        continue
                    if code == 0x9e:
                        parts.append(S[0xb2][min(k, len(S[0xb2]) - 1)])
                    parts.append(S[code][k])
                if carrier == 0x13 and k > 1 or not parts or (carrier == 0x12 and k == 0 and False):
                    continue
                for g in range(0, len(parts), 12):
                    body = b''.join(parts[g:g + 12])
                    if ver == 0:
                        A(pkt(v0_header(carrier, body, seq=seq), 3386, 3386))
                    else:
                        A(pkt(v1_header(carrier, body, seq=seq, teid=0x2000 + seq), 2123, 2123))
                    seq += 1
        # containers
        for carrier, alt in ((0x12, 0), (0x13, 1)):
            body = ies_for([0x8b, 0xad], ver, k=0, pick={0x8b: alt, 0xad: alt})
            if ver == 1:
                A(pkt(v1_header(carrier, body, seq=seq), 2123, 2123))
            else:
                A(pkt(v0_header(carrier, body, seq=seq), 3386, 3386))
            seq += 1

    mark('request/response pairs')
    # ---- request / response pairs: session tracking, response matching
    def pair(ver, rq, rs, rq_ies, rs_ies, sq, teid, a='10.0.0.1', b='10.0.0.2', rq_pick=None, rs_pick=None, c1=None, c2=None):
        if ver == 0:
            A(pkt(v0_header(rq, rq_ies, seq=sq), 3386, 3386, a, b))
            A(pkt(v0_header(rs, rs_ies, seq=sq), 3386, 3386, b, a))
        else:
            A(pkt(v1_header(rq, rq_ies, seq=sq, teid=teid), 2123, 2123, a, b))
            A(pkt(v1_header(rs, rs_ies, seq=sq, teid=teid), 2123, 2123, b, a))

    def acc(cause):
        return tv(0x01, bytes([cause]))
    S1 = build_ies(1)
    imsi_a = tv(0x02, bytes.fromhex('13400121436587f9')); imsi_b = tv(0x02, bytes.fromhex('13400121436587f8'))
    pair(1, 0x01, 0x02, b'', tv(0x0e, b'\x01'), 3100, 0)

    def gsn(ip):
        return tlv(0x85, socket.inet_aton(ip))

    def session(sgsn, ggsn, t, seq, vlan=None, accept=True, ue=imsi_a, with_err=True):
        """Create / update / error indication / delete between an SGSN and a GGSN; t = (data1, cp1, data2, cp2) TEIDs."""
        d1, c1, d2, c2 = t

        def send(src, dst, msg, ies, teid, sq):
            A(pkt(v1_header(msg, ies, seq=sq, teid=teid), 2123, 2123, src, dst, vlan))
        send(sgsn, ggsn, 0x10, ue + tv(0x10, u32(d1)) + tv(0x11, u32(c1)) + tv(0x14, b'\x05') + tlv(0x80, bytes([0xf1, 0x21]) + V4)
             + gsn(sgsn) + gsn(sgsn), 0, seq)
        send(ggsn, sgsn, 0x11, tv(0x01, bytes([128 if accept else 192])) + tv(0x10, u32(d2)) + tv(0x11, u32(c2)) + gsn(ggsn) + gsn(ggsn),
             c1, seq)
        send(sgsn, ggsn, 0x12, tv(0x10, u32(d1)) + tv(0x14, b'\x05') + gsn(sgsn) + gsn(sgsn), c2, seq + 1)
        send(ggsn, sgsn, 0x13, tv(0x01, bytes([129])) + tv(0x10, u32(d2)) + gsn(ggsn), c1, seq + 1)
        if with_err:
            send(sgsn, ggsn, 0x1a, tv(0x10, u32(d2)) + gsn(ggsn), 0, seq + 2)
            send(ggsn, sgsn, 0x1a, tv(0x10, u32(d1)) + gsn(sgsn), 0, seq + 3)
            send(ggsn, sgsn, 0x1a, tv(0x10, u32(0xdead)) + gsn(sgsn), 0, seq + 4)            # unknown TEID
        send(sgsn, ggsn, 0x14, tv(0x13, b'\x01') + tv(0x14, b'\x05'), c2, seq + 5)
        send(ggsn, sgsn, 0x15, tv(0x01, bytes([128])), c1, seq + 5)
    gsn1 = gsn('10.0.0.1'); gsn2 = gsn('10.0.0.2')
    session('10.0.0.1', '10.0.0.2', (0xa1, 0xa2, 0xa3, 0xa4), 3200)
    session('10.0.0.3', '10.0.0.4', (0xb1, 0xb2, 0xb3, 0xb4), 3210, accept=False, ue=imsi_b)
    session('10.0.0.1', '10.0.0.2', (0xa1, 0xa2, 0xa3, 0xa4), 3220, vlan=10)           # same addresses and TEIDs in another VLAN
    session('10.0.0.1', '10.0.0.2', (0xa1, 0xa2, 0xa3, 0xa4), 3230, vlan=20, ue=imsi_b)
    session('10.0.0.1', '10.0.0.2', (0xa1, 0xa2, 0xa3, 0xa4), 3240, ue=imsi_b, with_err=False)  # the same TEIDs again (replaces the session)
    pair(1, 0x30, 0x31, tv(0x03, PLMN + u16(0x1234) + b'\x05') + tv(0x05, u32(1)), acc(128) + imsi_a, 3300, 0)
    pair(1, 0x32, 0x33, imsi_a + tv(0x03, PLMN + u16(0x1234) + b'\x05') + tv(0x11, u32(5)) + gsn1,
         acc(128) + imsi_a + tv(0x11, u32(6)), 3301, 0)
    pair(1, 0x35, 0x36, imsi_a + tv(0x11, u32(7)), acc(128) + tv(0x11, u32(8)) + tv(0x12, b'\x05' + u32(9)), 3302, 0)
    A(pkt(v1_header(0x80, tlv(0xff, u16(0x0102) + b'x') + ies_for([0x8b, 0xad], 1, pick={0x8b: 0, 0xad: 0}), seq=3303, teid=0), 2123, 2123))          # MS info change notification request
    A(pkt(v1_header(0x81, acc(128) + tlv(0xff, u16(0x0102)), seq=3303, teid=0), 2123, 2123, '10.0.0.2', '10.0.0.1'))
    # a request without a response and a response without a request
    A(pkt(v1_header(0x01, b'', seq=3400), 2123, 2123))
    A(pkt(v1_header(0x02, tv(0x0e, b'\x01'), seq=3401), 2123, 2123, '10.0.0.2', '10.0.0.1'))
    # v0 pairs
    pair(0, 0x01, 0x02, b'', tv(0x0e, b'\x01'), 3500, 0)
    pair(0, 0x10, 0x11, imsi_a + tv(0x0f, b'\xfc') + tv(0x10, u16(1)) + tv(0x11, u16(2)) + tlv(0x80, bytes([0xf1, 0x21]) + V4) + tlv(0x83, apn('a', 'b')) + gsn1 + gsn2,
         acc(128) + tv(0x10, u16(3)) + tv(0x11, u16(4)) + tlv(0x80, bytes([0xf1, 0x21]) + V4) + gsn2 + gsn1, 3501, 0)

    mark('GTP prime')
    # ---- GTP' (charging, port 3386): v0 with the 20 octet and 6 octet header, v1, v2
    gsn_addr = lambda a: bytes([0x80, 4]) + a
    sgsn_pdp = (bytes([0x80, 1, 0x12]) + bytes([0x83, 8]) + bytes.fromhex('13400121436587f9')
                + bytes([0xa5, 6]) + gsn_addr(bytes([192, 0, 2, 1])) + bytes([0x8a, 1, 1])
                + bytes([0xab, 6]) + gsn_addr(bytes([192, 0, 2, 2])) + bytes([0x90, 9]) + bytes.fromhex('260101000000') + b'\x2b\x10\x00'
                + bytes([0x91, 1, 10]) + bytes([0x93, 1, 0]) + bytes([0x9c, 2, 8, 0]))
    BER_SGSN = bytes([0xb4, len(sgsn_pdp)]) + sgsn_pdp
    pseq = 1
    for ver, short in ((0, False), (0, True), (1, False), (2, False)):
        nodeaddr = tlv(0xfe, V4)
        pm = [
            (0x01, b''),
            (0x02, tv(0x0e, b'\x01')),
            (0x04, nodeaddr),
            (0x05, b''),
            (0x06, acc(128) + nodeaddr),
            (0x07, acc(128)),
            (0xf0, tr_comm_set() + tlv(0xfc, data_record(1, 0x16, 0x05, [BER_SGSN])) + tlv(0xf9, u16(1) + u16(2)) + tlv(0xfa, u16(3)) + tlv(0xff, u16(0x0f0f) + b'x')),
            (0xf1, acc(128) + tlv(0xfd, u16(pseq) + u16(pseq + 1))),
        ]
        for m, body in pm:
            hdr = prime_header(m, body, ver=ver, seq=pseq, short=short)
            A(pkt(hdr, 3386, 3386, '10.7.0.1', '10.7.0.2'))
            pseq += 1
    # data record formats: BER release > 6, release 0 with extension, PER, XER, proprietary
    for fmt, rel, ver, recs, ext in ((1, 0x17, 0x05, [BER_SGSN, BER_SGSN], None), (1, 0x10, 0x05, [BER_SGSN], 0x10),
                                      (1, 0x10, 0x05, [BER_SGSN], 0x0a), (2, 0x16, 0x05, [b'\x00\x01'], None),
                                      (3, 0x16, 0x68, [b'\x00\x01'], None), (4, 0x1f, 0x05, [b'<a/>'], None),
                                      (5, 0, 0, [], None), (9, 0, 0, [], None)):
        if fmt >= 5:
            dr = bytes([0, fmt]) + b'proprietary record'
        else:
            dr = data_record(fmt, rel, ver, recs, rel_ext=ext)
        A(pkt(prime_header(0xf0, tr_comm_set() + tlv(0xfc, dr), ver=0, seq=pseq), 3386, 3386, '10.7.0.1', '10.7.0.2'))
        pseq += 1
    A(pkt(prime_header(0xf0, tr_comm_set() + tlv(0xfc, b''), ver=0, seq=pseq), 3386, 3386, '10.7.0.1', '10.7.0.2')); pseq += 1
    A(pkt(prime_header(0xf1, acc(128) + tlv(0xfd, u16(pseq - 5)), ver=0, seq=pseq), 3386, 3386, '10.7.0.1', '10.7.0.2')); pseq += 1
    A(pkt(prime_header(0x06, acc(128) + tlv(0xfe, bytes(5)) , ver=1, seq=pseq), 3386, 3386, '10.7.0.1', '10.7.0.2')); pseq += 1
    A(pkt(prime_header(0x04, tlv(0xfb, V6), ver=1, seq=pseq), 3386, 3386, '10.7.0.1', '10.7.0.2')); pseq += 1
    A(pkt(prime_header(0x04, tlv(0xfb, V4) + tlv(0xfb, bytes(3)), ver=1, seq=pseq), 3386, 3386, '10.7.0.1', '10.7.0.2')); pseq += 1
    # GTP' over IPv6
    A(pkt6(prime_header(0x04, nodeaddr, ver=1, seq=pseq), 3386, 3386)); pseq += 1

    mark('GTP-U')
    # ---- GTP-U (port 2152)
    ip4p = inner_ip(); ip6p = inner_ip6(); ethp = inner_eth()
    A(pkt(gtp_u(0x01, b'', teid=0, seq=7), 2152, 2152))
    A(pkt(gtp_u(0x02, tv(0x0e, b'\x00'), teid=0, seq=7), 2152, 2152, '10.0.0.2', '10.0.0.1'))
    A(pkt(gtp_u(0x1a, tv(0x10, u32(0x1234)) + tlv(0x85, V4), teid=0, seq=8), 2152, 2152))
    A(pkt(gtp_u(0x1f, S1[0x8d][0], teid=0, seq=9), 2152, 2152))
    A(pkt(gtp_u(0xfe, b'', teid=0x1111), 2152, 2152))
    for flags, seq_, npdu_, ch in ((0x30, None, 0, ()), (0x32, 100, 0, ()), (0x31, None, 5, ()), (0x34, None, 0, ((0xc0, u16(0x1234)),)),
                                  (0x36, 101, 3, ((0xc0, u16(0x0234)),)), (0x37, 102, 4, ())):
        A(pkt(gtp_u(0xff, ip4p, teid=0x3000 + flags, flags=flags & ~6, seq=seq_, npdu=npdu_, chain=ch) if flags != 0x31 else
              struct.pack('>BBHI', 0x31, 0xff, len(ip4p) + 4, 0x3031) + struct.pack('>HBB', 0, 5, 0) + ip4p, 2152, 2152))
    A(pkt(gtp_u(0xff, ip6p, teid=0x3100), 2152, 2152))
    A(pkt6(gtp_u(0xff, ip4p, teid=0x3101), 2152, 2152))
    A(pkt(gtp_u(0xff, ethp, teid=0x3102), 2152, 2152))
    A(pkt(gtp_u(0xff, eth(M2, M1, 0x8100, struct.pack('>HH', 5, 0x0800) + inner_ip()), teid=0x3103), 2152, 2152))
    A(pkt(gtp_u(0xff, eth(M2, M1, 0x88a8, struct.pack('>HH', 5, 0x8100) + struct.pack('>HH', 6, 0x0806) + bytes(28)), teid=0x3104), 2152, 2152))
    A(pkt(gtp_u(0xff, eth(M2, M1, 0x8864, bytes([0x11, 0, 0, 1]) + u16(len(ip4p) + 2) + b'\x00\x21' + ip4p), teid=0x3105), 2152, 2152))
    A(pkt(gtp_u(0xff, eth(M2, M1, 0x8863, bytes([0x11, 0x09, 0, 0, 0, 0])), teid=0x3105), 2152, 2152))
    A(pkt(gtp_u(0xff, eth(M2, M1, 0x86dd, ip6p), teid=0x3106), 2152, 2152))
    A(pkt(gtp_u(0xff, b'\x01\x02\x03', teid=0x3107), 2152, 2152))                       # nothing claims it
    A(pkt(gtp_u(0xff, b'\x00' * 20, teid=0x3108), 2152, 2152))
    A(pkt(gtp_u(0xff, eth(M2, M1, 0x0800, b''), teid=0x3109)[:0] + gtp_u(0xff, bytes(10), teid=0x3109), 2152, 2152))  # shorter than an Ethernet header
    A(pkt(gtp_u(0xff, eth(M2, M1, 0x8100, struct.pack('>H', 5)), teid=0x310a), 2152, 2152))
    A(pkt(gtp_u(0xff, eth(M2, M1, 0x88a8, struct.pack('>H', 5)), teid=0x310b), 2152, 2152))
    A(pkt(gtp_u(0xff, eth(M2, M1, 0x88a8, struct.pack('>HH', 5, 0x0800) + bytes(10)), teid=0x310c), 2152, 2152))
    mark('extension headers')
    # extension headers
    def ext(chain, payload=ip4p, teid=0x4000, **kw):
        A(pkt(gtp_u(0xff, payload, teid=teid, flags=0x34, seq=None, chain=chain), 2152, 2152))
    ext(((0x40, u16(2152)),))
    ext(((0x81, b'ran container 1'),))
    ext(((0x03, b'\x00\x00\x07\x00\x00\x00'),))
    ext(((0x82, b'\x00\x00\x07\x00\x00\x00'),))
    ext(((0x83, b'xw ran container'),))
    ext(((0x20, b'\x01\x00'),))                              # no dissector: service class indicator
    ext(((0x01, b'\x00\x00'), (0x02, b'\x00\x00')))
    ext(((0xc1, b'\x00\x00'), (0xc2, b'\x00\x00')))
    ext(((0xc0, u16(0x0123)), (0x40, u16(5)), (0x81, b'abcdef')))
    for kw in ({}, {'qmp': 1}, {'snp': 1}, {'msnp': 1}, {'ppp': 1}, {'qmp': 1, 'snp': 1, 'msnp': 1, 'ppp': 1}):
        ext(((0x85, pdu_session('dl', **kw)),))
    for kw in ({}, {'qmp': 1}, {'dld': 1}, {'uld': 1}, {'snp': 1}, {'n3': 1}, {'newie': 1}, {'newie': 1, 'f5': 1},
               {'qmp': 1, 'dld': 1, 'uld': 1, 'snp': 1, 'n3': 1, 'newie': 1, 'f5': 1}):
        ext(((0x85, pdu_session('ul', **kw)),))
    for kw in ({}, {'disc': 1}, {'flush': 1}, {'rep': 1}, {'disc': 1, 'flush': 1, 'rep': 1}):
        ext(((0x84, nrup('dl', **kw)),))
    for kw in ({}, {'htx': 1}, {'hdel': 1}, {'lost': 1}, {'rate': 1}, {'hretx': 1}, {'hdretx': 1}, {'cause': 1},
               {'htx': 1, 'hdel': 1, 'lost': 1, 'rate': 1, 'hretx': 1, 'hdretx': 1, 'cause': 1}):
        ext(((0x84, nrup('status', **kw)),))
    for kw in ({}, {'dup': 1}, {'ai': 1}, {'uld': 1}, {'dld': 1}, {'dup': 1, 'ai': 1, 'uld': 1, 'dld': 1}):
        ext(((0x84, nrup('assist', **kw)),))
    ext(((0x84, bytes([0x30, 0, 0, 0])),))                   # unknown NR-U PDU type

    mark('PDCP T-PDUs, TCP')
    # ---- T-PDUs for the PDCP-LTE / PDCP-NR table entries of the runcov configuration (10.0.0.2 any TEID, 10.0.0.9 TEID 77)
    pdcp = b'\x80\x01' + ip4p
    A(pkt(gtp_u(0xff, pdcp, teid=0x5001), 2152, 2152))
    A(pkt(gtp_u(0xff, pdcp, teid=77), 2152, 2152, '10.0.0.1', '10.0.0.9'))
    A(pkt(gtp_u(0xff, b'\x00\x01\x02\x03' + bytes(20), teid=78), 2152, 2152, '10.0.0.1', '10.0.0.9'))
    A(pkt6(gtp_u(0xff, pdcp, teid=0x5002), 2152, 2152))
    # GTP over TCP (dissected only with the "Dissect GTP over TCP" preference)
    echo = v1_header(0x01, b'', seq=900)
    A(tcpseg('10.0.0.1', '10.0.0.2', 40100, 2123, 1000, 0, 0x18, echo))
    A(tcpseg('10.0.0.1', '10.0.0.2', 40101, 3386, 1000, 0, 0x18, prime_header(0x01, b'', ver=1, seq=901)))
    A(tcpseg('10.0.0.1', '10.0.0.2', 40102, 2152, 1000, 0, 0x18, gtp_u(0xff, ip4p, teid=0x6000)))

    mark('rejected packets, GTPv2, warnings')
    # ---- not GTP (rejected: version above 2, unknown message type, too short), GTPv2-C
    A(pkt(bytes([0x70, 0x01, 0x00, 0x00]) + bytes(8), 2123, 2123))
    A(pkt(bytes([0x70, 0x01, 0x00, 0x00]) + bytes(8), 3386, 3386))
    A(pkt(v0_header(0x08, b'', seq=912), 3386, 3386))
    A(pkt(v1_header(0x08, b'', seq=910), 2123, 2123))
    A(pkt(bytes([0x32]), 2123, 2123))
    A(pkt(bytes([0x40, 0x01, 0x00, 0x04, 0x00, 0x00, 0x01, 0x00]), 2123, 2123))     # GTPv2-C echo request
    # warning level extension header problems
    ext(((0x40, b'\x08'),))                                  # UDP port extension header with the wrong length
    ext(((0x82, b'\x00\x00\x07'),))                          # long PDCP PDU number with the wrong length
    ext(((0xc0, u16(0x8123)),))                              # PDCP PDU number with the high bit set (note)
    ext(((0xc0, u16(1) + b'\x00\x00'),))                     # wrong length
    ext(((0x85, bytes([0x20, 0, 0, 0])),))                   # unknown PDU session container type
    A(pkt(v1_header(0x12, tv(0x40, b'\x01\x02'), seq=911), 2123, 2123))     # IE type that does not exist

    mark('reproducers')
    # ---- reproducers of the bugs fixed on the branch
    # GTPv1-C over IPv6 (a NULL conversation with session tracking + deinterlacing)
    rq = tv(0x02, bytes.fromhex('13400121436587f9')) + tv(0x10, u32(0x01020304)) + tlv(0x85, V4)
    A(pkt6(v1_header(0x10, rq, seq=950, teid=0), 2123, 2123))
    # GSN address of 5 and of 17 octets as the last IE of the message (read as IPv6 / IPv4 before the fix)
    A(pkt(v1_header(0x10, tv(0x02, bytes.fromhex('13400121436587f9')) + tlv(0x85, b'\x00' + V4), seq=951, teid=0), 2123, 2123))
    A(pkt(v1_header(0x10, tv(0x02, bytes.fromhex('13400121436587f9')) + tlv(0x85, b'\x00' + V6), seq=952, teid=0), 2123, 2123))
    # GTP' Data Record Transfer Request: the IEs after the Data Record Packet IE
    A(pkt(prime_header(0xf0, tv(0x7e, b'\x01') + tlv(0xfc, data_record(1, 0x16, 0x05, [BER_SGSN])) + tlv(0xf9, u16(0x1111) + u16(0x2222)) + tlv(0xff, b'\x00\x01A'), ver=2, seq=953), 3386, 3386, '10.7.0.1', '10.7.0.2'))
    # MBMS Service Area with two codes (length 5)
    A(pkt(v1_header(0x60, tlv(0xa0, b'\x01' + u16(0x1234) + u16(0x5678)) + tlv(0xff, b'\x00\x01A'), seq=954, teid=0x11), 2123, 2123))

    mark('RADIUS')
    # ---- RADIUS access request with the 3GPP QoS profile and selection mode attributes
    rad_id = [0]

    def radius(attrs):
        rad_id[0] += 1
        ident = rad_id[0]
        body = b''.join(bytes([t, len(v) + 2]) + v for t, v in attrs)
        return struct.pack('>BBH', 1, ident, 20 + len(body)) + bytes(range(16)) + body

    def vsa(vtype, val):
        return (26, u32(10415) + bytes([vtype, len(val) + 2]) + val)
    pr = lambda n: ''.join(['%02x' % x for x in (0x0b, 0x0a, 0x2b, 0x23, 0x56, 0x2a, 0x40, 0x33, 0x4b, 0x30, 0x7d, 0x0b, 0x12, 0x14, 0x20, 0x22, 0x24, 0x26, 0x28, 0x2a)[:n]]).encode()
    A(pkt(radius([vsa(5, b'99-' + pr(3))]), 40000, 1812))
    A(pkt(radius([vsa(5, b'99-' + pr(11))]), 40001, 1812))
    A(pkt(radius([vsa(5, b'99-' + pr(13))]), 40002, 1812))
    A(pkt(radius([vsa(5, b'99-' + pr(16))]), 40003, 1812))
    A(pkt(radius([vsa(5, b'99-' + pr(20))]), 40004, 1812))
    A(pkt(radius([vsa(5, b'99' + pr(11))]), 40005, 1812))
    A(pkt(radius([vsa(5, b'08-' + b'0501' + b'0000000001' * 4)]), 40006, 1812))
    A(pkt(radius([vsa(5, b'08-' + b'0505' + b'0000000100000002')]), 40007, 1812))
    A(pkt(radius([vsa(12, b'0'), vsa(12, b'1'), vsa(12, b'2'), vsa(12, b'5')]), 40005, 1812))
    for n, name in marks:
        print('  frame %d: %s' % (n, name))
    return fr


def bad_variants():
    """(version, IE, alternative) combinations that are malformed: they go to the malformed capture."""
    return {(v, 0x95, 1) for v in (0, 1)} | {(v, 0x97, 5) for v in (0, 1)} | {(v, 0x80, k) for v in (0, 1) for k in (5, 7)}


def build_malformed():
    fr = []
    A = fr.append
    seq = 9000
    for (ver, code, k) in sorted(bad_variants()):
        ie = build_ies(ver)[code][k]
        if ver == 0:
            A(pkt(v0_header(0x12, ie, seq=seq), 3386, 3386))
        else:
            A(pkt(v1_header(0x12, ie, seq=seq), 2123, 2123))
        seq += 1
    ip4p = inner_ip()
    # header length field larger / smaller than the packet, v0 and v1
    echo0 = v0_header(0x02, tv(0x0e, b'\x01'), seq=1)
    A(pkt(echo0[:2] + u16(60) + echo0[4:], 3386, 3386))
    A(pkt(echo0 + b'trailing', 3386, 3386))
    echo1 = v1_header(0x02, tv(0x0e, b'\x01'), seq=2)
    A(pkt(echo1[:2] + u16(60) + echo1[4:], 2123, 2123))
    A(pkt(echo1 + b'trailing', 2123, 2123))
    # extension header with length zero and one that runs past the end of the packet
    hdr = gtp_u(0xff, b'', teid=1, flags=0x34, chain=((0x40, b'\x00\x00'),))
    A(pkt(hdr[:11] + bytes([0xc0, 0x00, 0x00, 0x00, 0x00]) + ip4p, 2152, 2152))
    A(pkt(hdr[:11] + bytes([0xc0, 20, 0x00, 0x05, 0x00]), 2152, 2152))
    # GTP-U truncated at every length of a message with extension headers
    full = gtp_u(0xff, ip4p, teid=3, flags=0x34, chain=((0xc0, u16(1)), (0x85, pdu_session('dl', qmp=1, snp=1))))
    for n in range(1, 40):
        A(pkt(full[:n], 2152, 2152))
    # control messages cut at several positions of a message with many IEs
    m1 = v1_header(0x10, ies_for([0x02, 0x03, 0x10, 0x11, 0x14, 0x80, 0x83, 0x87, 0x85, 0x86], 1), seq=7)
    for n in list(range(9, len(m1), 11)) + [len(m1) - 1]:
        A(pkt(m1[:n], 2123, 2123))
    m0 = v0_header(0x10, ies_for([0x02, 0x0f, 0x10, 0x11, 0x80, 0x83, 0x85, 0x86, 0x81, 0x82], 0), seq=7)
    for n in list(range(21, len(m0), 13)) + [len(m0) - 1]:
        A(pkt(m0[:n], 3386, 3386))
    # TLV IEs whose length field runs past the end of the message
    for ver in (0, 1):
        S = build_ies(ver)
        for code in sorted(S):
            if code >= 0x80:
                ie = S[code][0]
                body = bytes([code]) + u16(len(ie) + 40) + ie[3:]
                if ver:
                    A(pkt(v1_header(0x12, body, seq=8), 2123, 2123))
                else:
                    A(pkt(v0_header(0x12, body, seq=8), 3386, 3386))
    return fr


if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    for name, fr in (('gtp-coverage.pcap', build()), ('gtp-coverage-malformed.pcap', build_malformed())):
        pcap(os.path.join(out, name), fr)
        print('wrote %d frames to %s' % (len(fr), name))
