#!/usr/bin/env python3
# Generates test/captures/geonw_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generate the GeoNetworking coverage captures. Usage: mkgeonw.py <outdir>
#
# gelf-style two interface pcapng: interface 0 = Ethernet (ethertype 0x8947),
# interface 1 = Exported PDU naming "gnw.comm" / "gnw.sec" (the dissectors
# that start after the basic header; nothing else calls them).
#
# The security header (ETSI TS 103 097 V1.1.1 = "version 1", V1.2.1 =
# "version 2") is built as STRUCTURE only: every key, signature, digest and
# encrypted-key field is a constant placeholder pattern. Nothing is signed,
# verified, encrypted or derived from a key.
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from common import pcapng, pcap

GN_ETHERTYPE = 0x8947
ETH_DST = bytes.fromhex('ffffffffffff')
def ethhdr(src_last=1):
    return ETH_DST + bytes.fromhex('0200000000') + bytes([src_last]) + struct.pack('>H', GN_ETHERTYPE)

def addr(manual=0, stype=5, cc=240, mid=b'\x02\x00\x00\x00\x00\x01'):
    return bytes([(manual << 7) | (stype << 2) | ((cc >> 8) & 3), cc & 0xff]) + mid

def lpv(a, tst, lat=500000000, lon=100000000, pai=1, speed=1500, heading=900):
    return a + struct.pack('>IiiHH', tst, lat, lon, (pai << 15) | speed, heading)

def spv(a, tst, lat=500000000, lon=100000000):       # short position vector (destination)
    return a + struct.pack('>Iii', tst, lat, lon)

def bh(ver=0, nh=1, lt=0x50, rhl=1, rsv=0):
    return bytes([(ver << 4) | nh, rsv, lt, rhl])

def ch(nh, ht, pl, tc=0x02, flags=0x80, mhl=1, rsv1=0, rsv2=0):
    return bytes([(nh << 4) | rsv1, ht, tc, flags]) + struct.pack('>H', pl) + bytes([mhl, rsv2])

def btpa(dst, src, payload=b''): return struct.pack('>HH', dst, src) + payload
def btpb(dst, info, payload=b''): return struct.pack('>HH', dst, info) + payload

A1 = addr(0, 5, 240, bytes.fromhex('020000000011'))      # passenger car, country 240
A2 = addr(1, 15, 262, bytes.fromhex('020000000022'))     # manual, RSU, 262
A3 = addr(0, 6, 999, bytes.fromhex('020000000033'))      # bus
A4 = addr(0, 20, 724, bytes.fromhex('020000000044'))     # unlisted station type
A5 = addr(0, 0, 0, bytes.fromhex('020000000055'))

# ---- extended headers (ETSI EN 302 636-4-1)
def beacon(a, tst, **kw): return lpv(a, tst, **kw)
def guc(sn, a, tst, dest, dtst=1000, dlat=500100000, dlon=100100000, rsv=0, **kw):
    return struct.pack('>HH', sn, rsv) + lpv(a, tst, **kw) + spv(dest, dtst, dlat, dlon)
def gxc(sn, a, tst, lat, lon, da, db, ang, rsv=0, **kw):
    return struct.pack('>HH', sn, 0) + lpv(a, tst, **kw) + struct.pack('>iiHHHH', lat, lon, da, db, ang, rsv)
def shb(a, tst, rsv=0, **kw): return lpv(a, tst, **kw) + struct.pack('>I', rsv)
def tsb(sn, a, tst, **kw): return struct.pack('>HH', sn, 0) + lpv(a, tst, **kw)
def lsreq(sn, a, tst, target, **kw): return struct.pack('>HH', sn, 0) + lpv(a, tst, **kw) + target
def lsrep(sn, a, tst, dest, **kw): return struct.pack('>HH', sn, 0) + lpv(a, tst, **kw) + spv(dest, 2000)

def gn(bhdr, htype, ext, payload=b'', nh=2, pl=None, **chkw):
    """basic header + common header + extended header + payload"""
    return bhdr + ch(nh, htype, len(payload) if pl is None else pl, **chkw) + ext + payload

def frame(b, src=1):
    return ethhdr(src) + b

# ---- security (structure only)
def vlen(n):
    for k in range(1, 9):
        if n < (1 << (7 * k)):
            val = n | (0)
            # k octets: (k-1) leading one bits, a zero bit, then 8k-k bits of value
            prefix = ((1 << (k - 1)) - 1) << (9 - k)      # leading ones in the first octet
            full = (prefix << (8 * (k - 1))) | n
            return full.to_bytes(k, 'big')
    raise ValueError(n)
intx = vlen
def vec(b): return vlen(len(b)) + b

X32 = bytes(range(0x40, 0x60))     # placeholder 32 octet values
Y32 = bytes(range(0x60, 0x80))
S32 = bytes(range(0x80, 0xa0))
H8 = bytes(range(0xb0, 0xb8))

def eccpoint(t=0, extra=b''):
    if t == 4: return bytes([4]) + X32 + Y32
    if t in (0, 2, 3): return bytes([t]) + X32
    return bytes([t]) + X32 + vec(extra)           # unknown type: opaque follows x
def publickey(algo=0, t=0):
    if algo == 0: return bytes([0]) + eccpoint(t)
    if algo == 1: return bytes([1, 0]) + eccpoint(t)    # symmetric algorithm aes_128_ccm + point
    return bytes([algo]) + vec(b'otherkey')
def signature(algo=0, t=0):
    if algo == 0: return bytes([0]) + eccpoint(t) + S32
    return bytes([algo]) + vec(b'othersig')
def region(rt, version=2):
    if rt == 0: return bytes([0])
    if rt == 1: return bytes([1]) + struct.pack('>iiH', 500000000, 100000000, 5000)
    if rt == 2: return bytes([2]) + struct.pack('>iiii', 500000000, 100000000, 500100000, 100100000)
    if rt == 3: return bytes([3]) + vec(struct.pack('>iiiiii', 1, 2, 3, 4, 5, 6))
    if rt == 4: return bytes([4, 0]) + struct.pack('>H', 276) + intx(5)
    return bytes([rt]) + vec(b'region')
def validity(t, r=0):
    if t == 0: return bytes([0]) + struct.pack('>I', 600000000)
    if t == 1: return bytes([1]) + struct.pack('>II', 500000000, 600000000)
    if t == 2: return bytes([2]) + struct.pack('>I', 500000000) + struct.pack('>H', (2 << 13) | 3)
    if t == 3: return bytes([3]) + region(r)
    return bytes([t]) + vec(b'validity')
def subj_attr(t, v=2):
    if t in (0, 1): return bytes([t]) + publickey(0 if t == 0 else 1)
    if t == 2: return bytes([2, 0xa5])
    if t == 3: return bytes([3]) + eccpoint(2)
    if t == 32: return bytes([32]) + vec(intx(36) + intx(37) + intx(0x1234))
    if t == 33: return bytes([33]) + vec(intx(140) + vec(b'\x01\x00') + intx(141) + vec(b'\x01\x02\x03'))
    if t == 34: return bytes([34]) + vec(intx(36) + b'\x05' + intx(37) + b'\x06')
    if t == 35: return bytes([35]) + vec(intx(36) + b'\x05' + vec(b'\x01\x02') + intx(37) + b'\x00' + vec(b''))
    return bytes([t]) + vec(b'attr')
def subj_info(t=1, body=b'subject'): return bytes([t]) + vec(body)

def certificate(version=2, signer=None, attrs=(), vals=(), sinfo=None, sig=None):
    signer = signer if signer is not None else signer_info(1)
    sinfo = subj_info(1) if sinfo is None else sinfo
    c = bytes([version])
    c += vec(signer) if version == 1 else signer
    c += sinfo
    c += vec(b''.join(attrs)) + vec(b''.join(vals))
    c += signature(0) if sig is None else sig
    return c
def signer_info(t, version=2, cert=None):
    if t == 0: return bytes([0])
    if t == 1: return bytes([1]) + H8
    if t == 2: return bytes([2]) + (cert if cert is not None else certificate(version))
    if t == 3: return bytes([3]) + vec((cert if cert is not None else certificate(version)) * 2)
    if t == 4: return bytes([4, 7]) + H8
    return bytes([t]) + vec(b'signer')

def hdr_field(t, version, body): return bytes([t]) + body
def secured(version, hdr_fields, payload_fields, trailers, profile=0x10):
    out = bytes([version])
    if version == 1:
        out += bytes([profile])
    out += vec(b''.join(hdr_fields))
    if version == 1:
        out += vec(b''.join(payload_fields))
    else:
        out += payload_fields[0]
    out += vec(b''.join(trailers))
    return out
def payload_field(t, data=b''):
    if t == 3: return bytes([3])
    return bytes([t]) + vec(data)
def sig_trailer(algo=0, t=0): return bytes([1]) + signature(algo, t)

T64 = struct.pack('>Q', 700000000000000)
def std_hdr(version, extra=()):
    h = [bytes([0]) + T64]                                # generation_time
    if version == 1: h.append(bytes([5]) + struct.pack('>H', 2))      # message_type (v1: 2 octets)
    else: h.append(bytes([5]) + intx(36))                             # ITS-AID (CAM)
    h.append(bytes([128]) + signer_info(1))                           # signer info digest
    return h + list(extra)

_sec_tst = [20000]
def inner_shb(tst=None, a=A1):
    if tst is None:
        _sec_tst[0] += 10
        tst = _sec_tst[0]
    p = btpb(2999, 0, b'secured payload')
    return ch(2, 0x50, len(p)) + shb(a, tst) + p

def inner_pkt(ht, a=A1):
    _sec_tst[0] += 10
    t = _sec_tst[0]
    p = btpb(2999, 0, b'inner')
    if ht == 0x10: return ch(0, 0x10, 0) + beacon(a, t)
    if ht == 0x20: return ch(2, 0x20, len(p)) + guc(1, a, t, A2) + p
    if ht in (0x30, 0x31, 0x40, 0x42): return ch(2, ht, len(p)) + gxc(2, a, t, 500000000, 100000000, 100, 0, 0) + p
    if ht == 0x51: return ch(2, 0x51, len(p)) + tsb(3, a, t) + p
    if ht == 0x60: return ch(0, 0x60, 0) + lsreq(4, a, t, A2)
    if ht == 0x61: return ch(0, 0x61, 0) + lsrep(5, a, t, A2)
    return ch(2, ht, 0) + bytes(40)                                    # unknown header type

def sec_frame(version, payload_type=0, hdr=None, trailers=None, inner=None, rhl=1, nh=2):
    inner = inner_shb() if inner is None else inner
    hdr = std_hdr(version) if hdr is None else hdr
    trailers = [sig_trailer()] if trailers is None else trailers
    pf = [payload_field(payload_type, inner)]
    return bh(0, 2, rhl=rhl) + secured(version, hdr, pf, trailers)

def build():
    _t = [100]
    def T():
        _t[0] += 100
        return _t[0]
    F = []                       # (ifc, frame)
    def E(b, src=1): F.append((0, frame(b, src)))
    def X(name, b):
        n = name.encode(); pad = (4 - len(n) % 4) % 4
        F.append((1, struct.pack('>HH', 12, len(n) + pad) + n + b'\0' * pad + struct.pack('>HH', 0, 0) + b))

    # ============ basic/common header: beacon, SHB, TSB and BTP
    E(gn(bh(0, 1, rhl=1), 0x10, beacon(A1, T()), nh=0))                          # 1 beacon
    p = btpb(2999, 0x0102, b'btp-b payload ' * 2)
    E(gn(bh(0, 1, rhl=1), 0x50, shb(A1, T()), p, nh=2))                          # SHB with BTP-B
    p = btpa(3000, 3001, b'btp-a payload')
    E(gn(bh(0, 1, rhl=1), 0x50, shb(A1, T()), p, nh=1))                          # SHB with BTP-A, src > dst? (dst 3000 < src 3001)
    p = btpa(3500, 3001, b'btp-a payload 2')
    E(gn(bh(0, 1, rhl=1), 0x50, shb(A1, T()), p, nh=1))                          # dst > src
    p = struct.pack('>IHBB', 0x60000000, 8, 59, 64) + bytes(16) + bytes(16)
    p = struct.pack('>IHBB', 0x60000000, 0, 59, 64) + bytes.fromhex('fe800000000000000200000000000001') + bytes.fromhex('fe800000000000000200000000000002')
    E(gn(bh(0, 1, rhl=1), 0x50, shb(A1, T()), p, nh=3))                          # IPv6 payload
    E(gn(bh(0, 1, rhl=1), 0x50, shb(A1, T()), b'unknown next header', nh=4))     # unknown NH: data
    E(gn(bh(0, 1, rhl=1), 0x50, shb(A1, T()), b'next header 0', nh=0))
    E(gn(bh(0, 1, rhl=1), 0x50, shb(A1, T()), b'', nh=2))                        # no payload
    E(gn(bh(0, 1, rhl=1), 0x50, shb(A1, T(), rsv=0x20300140), btpb(2999, 0, b'dcc'), nh=2))     # DCC-MCO in the SHB reserved field
    # TSB (multi-hop)
    E(gn(bh(0, 1, rhl=10), 0x51, tsb(1, A2, 1000), btpb(2999, 0, b'tsb'), nh=2, mhl=10))
    # basic header variants
    E(gn(bh(0, 1, lt=0x01, rhl=1), 0x50, shb(A2, 1100), btpb(2999, 0, b'x')))                 # life time base 1s
    E(gn(bh(0, 1, lt=0x6e, rhl=1), 0x50, shb(A2, 1200), btpb(2999, 0, b'x')))                 # 10 s / 100 s
    E(gn(bh(0, 1, lt=0xff, rhl=1), 0x50, shb(A2, 1300), btpb(2999, 0, b'x')))
    E(gn(bh(0, 1, rhl=3, rsv=0x33), 0x51, tsb(2, A2, 1400), btpb(2999, 0, b'x'), mhl=3))     # reserved BH byte, RHL<5
    E(gn(bh(0, 1, rhl=5), 0x50, shb(A2, 1500), btpb(2999, 0, b'x')))                          # SHB with RHL 5 (!= 1)
    E(gn(bh(0, 1, rhl=2), 0x10, beacon(A2, 1600), nh=0))                                      # beacon with RHL 2
    E(gn(bh(0, 1, rhl=8), 0x51, tsb(3, A2, 1700), btpb(2999, 0, b'x'), mhl=4))                # MHL < RHL
    E(gn(bh(1, 1, rhl=1), 0x50, shb(A3, 1800), btpb(2999, 0, b'v1')))                         # version 1
    E(gn(bh(0, 0, rhl=1), 0x50, shb(A3, 2000), btpb(2999, 0, b'nh0')))                        # basic header NH = ANY (no common header)
    # common header variations
    E(gn(bh(0, 1, rhl=1), 0x50, shb(A3, 2100), btpb(2999, 0, b'x'), tc=0xff, flags=0xff, rsv1=3, rsv2=9))   # reserved bits
    E(gn(bh(0, 1, rhl=1), 0x50, shb(A3, 2200), btpb(2999, 0, b'x'), tc=0x00, flags=0x00))
    # payload length bogus: larger than the data
    # payload length zero but data present (trailing data after the header)
    E(gn(bh(0, 1, rhl=1), 0x50, shb(A3, 2400), btpb(2999, 0, b'x'), pl=0))
    # payload length shorter than the data present
    E(gn(bh(0, 1, rhl=1), 0x50, shb(A3, 2500), btpb(2999, 0, b'0123456789'), pl=6))
    # beacon and LS with payload length set
    E(gn(bh(0, 1, rhl=1), 0x10, beacon(A3, 2600), b'', pl=4, nh=0))
    # positions and country codes
    E(gn(bh(0, 1, rhl=1), 0x50, shb(A4, 2800, lat=-500000000, lon=-100000000, heading=0), btpb(2999, 0, b'south-west')))
    E(gn(bh(0, 1, rhl=1), 0x50, shb(A5, 2900, lat=-900000000, lon=-1800000000, pai=0, speed=0x7fff), btpb(2999, 0, b'min')))
    E(gn(bh(0, 1, rhl=1), 0x50, shb(A5, 3000, lat=-2**31, lon=2**31 - 1), btpb(2999, 0, b'extreme')))    # reproducers of the fixed lat/lon overflow
    E(gn(bh(0, 1, rhl=1), 0x50, shb(A5, 3100, lat=500000000, lon=1000000000), btpb(2999, 0, b'fix')))   # 50 N, 100 E (geonw_latlon_overflow.py)

    # ============ unicast / anycast / broadcast
    E(gn(bh(0, 1, rhl=10), 0x20, guc(10, A1, T(), A2), btpb(2999, 0, b'guc'), mhl=10))
    for ht in (0x30, 0x31, 0x32, 0x40, 0x41, 0x42):
        hst = ht & 0x0f
        E(gn(bh(0, 1, rhl=10), ht, gxc(20 + ht, A1, T(), 500000000, 100000000, 1000, 0 if hst == 0 else 500, 0 if hst == 0 else 90), btpb(2999, 0, b'gxc'), mhl=10))
    E(gn(bh(0, 1, rhl=10), 0x40, gxc(40, A1, T(), 950000000, 1850000000, 1000, 5, 7, rsv=3), btpb(2999, 0, b'gbc nz'), mhl=10))   # circle with b/angle nonzero, reserved, out of range
    E(gn(bh(0, 1, rhl=10), 0x41, gxc(41, A1, T(), -950000000, -1850000000, 1000, 500, 400), btpb(2999, 0, b'gbc rect'), mhl=10))   # angle > 360
    # unknown header types: stops after the common header
    for ht in (0x00, 0x07, 0x62, 0x70, 0xf3, 0x43, 0x33):
        E(gn(bh(0, 1, rhl=10), ht, bytes(36), b'', mhl=10, pl=0))
    # location service
    E(gn(bh(0, 1, rhl=10), 0x60, lsreq(50, A3, 5000, A4), b'', mhl=10, nh=0))                    # LS request: matched below
    E(gn(bh(0, 1, rhl=10), 0x61, lsrep(51, A4, 5100, A3), b'', mhl=10, nh=0), src=4)             # LS reply
    E(gn(bh(0, 1, rhl=10), 0x61, lsrep(52, A4, 5110, A3), b'', mhl=10, nh=0), src=4)             # second reply: already answered
    E(gn(bh(0, 1, rhl=10), 0x60, lsreq(53, A1, T(), A5), b'', mhl=10, nh=0))                    # LS request without reply
    E(gn(bh(0, 1, rhl=10), 0x61, lsrep(54, addr(0, 9, 9, bytes(6)), 5300, addr(0, 9, 9, bytes([1]*6))), b'', mhl=10, nh=0))     # reply without request
    E(gn(bh(0, 1, rhl=10), 0x60, lsreq(55, A2, 5400, A5), b'payload', mhl=10, nh=0, pl=7))       # LS with payload length: reserved warning

    # ============ duplicate packet detection (per source address, ETSI EN 302 636-4-1 annex A)
    SA = addr(0, 5, 100, bytes.fromhex('0200000000a1'))
    for tst in (1000, 2000, 2000, 1500, 3000, 0x7ffffff0, 0xf0000000, 0x10, 0x10):
        E(gn(bh(0, 1, rhl=1), 0x50, shb(SA, tst), btpb(2999, 0, b'dup'), mhl=1))                  # SHB without sequence numbers
    SB = addr(0, 6, 100, bytes.fromhex('0200000000b1'))
    for sn, tst in ((1, 10), (2, 20), (2, 20), (3, 20), (1, 20), (0xffff, 20), (5, 30), (4, 25), (8, 0x7ffffff0), (9, 0xf0000000), (10, 5), (0xfff0, 7), (3, 7), (3, 7)):
        E(gn(bh(0, 1, rhl=10), 0x51, tsb(sn, SB, tst), btpb(2999, 0, b'dup'), mhl=10))            # TSB with sequence numbers
    SC = addr(0, 7, 100, bytes.fromhex('0200000000c1'))
    E(gn(bh(0, 1, rhl=1), 0x50, shb(SC, 100), btpb(2999, 0, b'first no sn')))                   # SN absent first, then present
    E(gn(bh(0, 1, rhl=10), 0x51, tsb(9, SC, 200), btpb(2999, 0, b'sn'), mhl=10))
    E(gn(bh(0, 1, rhl=1), 0x50, shb(SC, 150), btpb(2999, 0, b'older shb')))                      # SN absent after SN present
    SD = addr(0, 8, 100, bytes.fromhex('0200000000d1'))
    for _ in range(2):                                                                            # identical SHB twice (geonw_dup_2pass.py)
        E(gn(bh(0, 1, rhl=1), 0x50, shb(SD, 12345), b'', nh=0))
    E(gn(bh(1, 1, rhl=1), 0x50, shb(SD, 12345), b'', nh=0))                                      # version 1: no analysis
    E(gn(bh(1, 1, rhl=1), 0x50, shb(SD, 12345), b'', nh=0))

    # ============ BTP ports and payloads
    for dst, src in ((4000, 4001), (4001, 4000)):
        E(gn(bh(0, 1, rhl=1), 0x50, shb(A1, T()), btpa(dst, src, b'port test'), nh=1))
    for dst in (2999, 4001):
        E(gn(bh(0, 1, rhl=1), 0x50, shb(A1, T()), btpb(dst, 0x1234, b'port test'), nh=2))

    # ============ secured packets, version 1
    E((sec_frame(1)))                                                                         # basic secured packet (signer digest)
    for ht in (0x10, 0x20, 0x30, 0x31, 0x40, 0x42, 0x51, 0x60, 0x61, 0x77):
        E((sec_frame(1 if ht & 1 else 2, inner=inner_pkt(ht))))                                # all inner header types
    E((sec_frame(1, payload_type=1)))                                                         # signed payload
    E((sec_frame(1, payload_type=3, inner=b'')))                                              # signed_external: no payload data
    E((sec_frame(1, payload_type=2, inner=b'opaque encrypted payload bytes')))               # encrypted (opaque)
    E((sec_frame(1, payload_type=4, inner=b'opaque')))
    E((sec_frame(1, payload_type=9, inner=b'opaque')))                                        # unknown payload type
    # every header field type
    hf = std_hdr(1, [
        bytes([1]) + T64 + b'\x07',                                                                # generation time with confidence
        bytes([2]) + struct.pack('>I', 800000000),                                                 # expiration
        bytes([3]) + struct.pack('>iih', 500000000, 100000000, -4096),                             # generation location, unknown elevation
        bytes([4]) + vec(b'abcdef'),                                                               # request unrecognized certificate (HashedId3 x2)
        bytes([99]) + vec(b'unknown'),                                                             # unknown header field
    ])
    E((sec_frame(1, hdr=hf)))
    # signer info types
    for t in (0, 2, 3, 4, 5):
        h = [bytes([0]) + T64, bytes([5]) + struct.pack('>H', 2), bytes([128]) + signer_info(t, 1)]
        E((sec_frame(1, hdr=h)))
    # trailers: unknown trailer type, ECIES-style algorithms
    E((sec_frame(1, trailers=[bytes([77]) + vec(b'trailer')])))
    E((sec_frame(1, trailers=[sig_trailer(0, 4)])))                                           # uncompressed point
    E((sec_frame(1, trailers=[sig_trailer(0, 2)])))
    E((sec_frame(1, trailers=[sig_trailer(5)])))                                              # unknown signature algorithm
    E((sec_frame(1, trailers=[sig_trailer(0, 9)])))                                           # unknown ecc point type (opaque follows)
    # certificates with every subject attribute and validity restriction, version 1
    attrs = [subj_attr(t, 1) for t in (0, 1, 2, 3, 32, 33, 34, 35, 99)] + [bytes([0]) + publickey(7)]
    vals = [validity(0), validity(1), validity(2), validity(3, 0), validity(3, 1), validity(3, 2), validity(3, 3), validity(3, 4), validity(3, 9), validity(7)]
    cert1 = certificate(1, signer=signer_info(1), attrs=attrs, vals=vals, sinfo=subj_info(2, b'CN=test'))
    h = [bytes([0]) + T64, bytes([5]) + struct.pack('>H', 2), bytes([128]) + signer_info(2, 1, cert1)]
    E((sec_frame(1, hdr=h)))
    h = [bytes([0]) + T64, bytes([5]) + struct.pack('>H', 2), bytes([128]) + signer_info(3, 1, cert1)]
    E((sec_frame(1, hdr=h)))
    # encryption related structures: placeholders only
    h = std_hdr(1, [bytes([130]) + bytes([0]) + bytes(12),                                         # encryption parameters (nonce)
                    bytes([130]) + bytes([5]) + vec(b'otherenc'),
                    bytes([129]) + vec(H8 + bytes([1]) + eccpoint(0) + bytes(16) + bytes(20)),     # recipient info (ECIES, v1: 20 octet tag)
                    bytes([129]) + vec(H8 + bytes([6]) + vec(b'otherkey'))])
    E((sec_frame(1, hdr=h)))

    # ============ secured packets, version 2
    E((sec_frame(2)))
    E((sec_frame(2, payload_type=1)))
    E((sec_frame(2, payload_type=3, inner=b'')))
    E((sec_frame(2, payload_type=2, inner=b'opaque encrypted payload bytes')))
    E((sec_frame(2, payload_type=7, inner=b'unknown')))
    hf = std_hdr(2, [
        bytes([1]) + T64 + b'\x07', bytes([2]) + struct.pack('>I', 800000000),
        bytes([3]) + struct.pack('>iih', 500000000, 100000000, 300),
        bytes([4]) + vec(b'abc'), bytes([99]) + vec(b'unknown'),
    ])
    E((sec_frame(2, hdr=hf)))
    for t in (0, 2, 3, 4, 5):
        h = [bytes([0]) + T64, bytes([5]) + intx(36), bytes([128]) + signer_info(t, 2)]
        E((sec_frame(2, hdr=h)))
    attrs2 = [subj_attr(t, 2) for t in (0, 1, 2, 3, 32, 33, 99)]
    cert2 = certificate(2, signer=signer_info(1), attrs=attrs2, vals=vals, sinfo=subj_info(1, b'CN=v2'))
    h = [bytes([0]) + T64, bytes([5]) + intx(36), bytes([128]) + signer_info(2, 2, cert2)]
    E((sec_frame(2, hdr=h)))
    h = [bytes([0]) + T64, bytes([5]) + intx(36), bytes([128]) + signer_info(3, 2, cert2)]
    E((sec_frame(2, hdr=h)))
    # a certificate whose signer info is itself a certificate (nesting, depth limited)
    nested = certificate(2, signer=signer_info(2, 2, certificate(2)), attrs=[subj_attr(2)], vals=[validity(0)])
    h = [bytes([0]) + T64, bytes([5]) + intx(36), bytes([128]) + signer_info(2, 2, nested)]
    E((sec_frame(2, hdr=h)))
    # IntX of several lengths: 1 to 4 octets, application ids with names, and the lengths that overflow 32 bits
    for appid in (0, 36, 37, 0x7f, 0x80, 0x1234, 0x3fff, 0x4000, 0x1fffff, 0x200000, 0xfffffff):
        h = [bytes([0]) + T64, bytes([5]) + intx(appid), bytes([128]) + signer_info(1)]
        E((sec_frame(2, hdr=h)))
    # encryption related structures: placeholders only
    h = std_hdr(2, [bytes([130]) + bytes([0]) + bytes(12),
                    bytes([129]) + vec(H8 + bytes([1]) + eccpoint(0) + bytes(16) + bytes(16))])
    E((sec_frame(2, hdr=h)))
    # version 0 and 4: unknown, only the version is shown
    E((bh(0, 2) + bytes([0]) + b'\0' * 20))
    E((bh(0, 2) + bytes([4]) + b'\0' * 20))
    # IEEE 1609.2 (version 3): an unsigned Ieee1609Dot2Data holding the GeoNetworking payload
    inner = inner_shb()
    d = bytes([3, 0x80]) + vec(inner)
    E((bh(0, 2) + d))
    # ... and signedData with psid 36 (digest signer, dummy signature, placeholder values)
    inner = inner_shb()
    tbs = bytes([0x40]) + bytes([3, 0x80]) + vec(inner) + bytes([0x40, 1, 36]) + T64
    sd = bytes([3, 0x81, 0]) + bytes([0x40]) + bytes([3, 0x80]) + vec(inner) + bytes([0x40, 1, 36]) + T64
    sd += bytes([0x80]) + H8 + bytes([0x80, 0x80]) + X32 + S32
    E((bh(0, 2) + sd))

    # ============ Exported PDU: the dissectors that start after the basic header
    X('gnw.comm', ch(2, 0x50, 6) + shb(A1, 900000) + btpb(2999, 0, b'comm'))
    X('gnw.comm', ch(2, 0x10, 0) + beacon(A1, 900010))
    X('gnw.comm', ch(2, 0x20, 6) + guc(70, A1, 900020, A2) + btpb(2999, 0, b'uc'))
    X('gnw.sec', secured(2, std_hdr(2), [payload_field(0, inner_shb(900100))], [sig_trailer()]))
    X('gnw.sec', secured(1, std_hdr(1), [payload_field(0, inner_shb(900200))], [sig_trailer()]))
    return F

def build_mal():
    T = lambda: 1
    F = []
    def E(b, src=1): F.append(frame(b, src))
    global _sec_tst
    # error severity expert infos (bogus version, bogus length, country code > 999)
    E(gn(bh(2, 1, rhl=1), 0x50, shb(A3, 1900), btpb(2999, 0, b'v2')))                         # bogus version 2
    E(gn(bh(0, 1, rhl=1), 0x50, shb(A3, 2300), btpb(2999, 0, b'x'), pl=500))
    E(gn(bh(0, 1, rhl=1), 0x50, shb(addr(0, 5, 1000, A3[2:]), 2700, lat=950000000, lon=1850000000, heading=3700), btpb(2999, 0, b'oor')))
    E(gn(bh(0, 1, rhl=10), 0x20, guc(11, A1, T(), addr(0, 1, 1010, A2[2:]), dlat=-950000000, dlon=1850000000, rsv=7), btpb(2999, 0, b'guc2'), mhl=10))
    # IntX longer than 32 bits, subject info > 255 octets, ssp > 31 octets (all error expert infos)
    h = [bytes([0]) + T64, bytes([5]) + bytes([0xf0, 0, 0, 0, 0]), bytes([128]) + signer_info(1)]     # 5 octet IntX (geonw_intx_assert.py)
    E((sec_frame(2, hdr=h)))
    h = [bytes([0]) + T64, bytes([5]) + b'\xff' * 10, bytes([128]) + signer_info(1)]                # 10 octet IntX: "at most 7 bits" error is in the malformed capture only
    # local region of 5 octets in a validity restriction (geonw_intx_localregion.py)
    vr = bytes([3, 4, 0]) + struct.pack('>H', 1) + bytes([0xf0, 0, 0, 0, 0])
    c = bytes([2]) + signer_info(1) + subj_info(1, b'') + vec(b'') + vec(vr) + signature(0)
    h = [bytes([0]) + T64, bytes([5]) + intx(36), bytes([128]) + signer_info(2, 2, c)]
    E((sec_frame(2, hdr=h)))
    # subject info longer than 255 octets, ssp longer than 31 octets
    big = subj_info(1, b'S' * 300)
    h = [bytes([0]) + T64, bytes([5]) + intx(36), bytes([128]) + signer_info(2, 2, certificate(2, sinfo=big))]
    E((sec_frame(2, hdr=h)))
    sspbig = [bytes([33]) + vec(intx(36) + vec(b'x' * 40))]
    h = [bytes([0]) + T64, bytes([5]) + intx(36), bytes([128]) + signer_info(2, 2, certificate(2, attrs=sspbig))]
    E((sec_frame(2, hdr=h)))
    # LS request to an address with country code > 999; ssp longer than 31 in the priority list; lists that
    # overrun their length; v1 payload list shorter than its payload field; var length of 2 GiB or more
    E(gn(bh(0, 1, rhl=10), 0x60, lsreq(55, A2, 5400, addr(0, 9, 1005, bytes(6))), b'', mhl=10, nh=0))
    a = bytes([35]) + vec(intx(36) + b'\x05' + vec(b'x' * 40))
    h = [bytes([0]) + T64, bytes([5]) + intx(36), bytes([128]) + signer_info(2, 2, certificate(2, attrs=[a]))]
    E(sec_frame(2, hdr=h))
    for t in (32, 33, 34, 35):
        a = bytes([t]) + vlen(2) + intx(36) + bytes([0x80, 0x80])
        h = [bytes([0]) + T64, bytes([5]) + intx(36), bytes([128]) + signer_info(2, 2, certificate(2, attrs=[a]))]
        E(sec_frame(2, hdr=h))
    pl = bytes([0]) + vec(b'x' * 20)
    E(bh(0, 2) + bytes([1, 0x10]) + vec(b''.join(std_hdr(1))) + vlen(2) + pl + vec(b''))
    def dec(bs):
        v = bs[0]; i = 1; mask = 0x80
        while mask and (v & mask):
            v = (((v & ~mask) << 8) + bs[i]) & 0xffffffff; i += 1; mask = (mask << 7) & 0xffffffff
        return v, i
    big = None
    for b1 in range(0, 256, 5):
        for b4 in (0, 1):
            cand = bytes([0xf0, b1, 0x80, 0x00, b4])
            v, n = dec(cand)
            if v >= 0x80000000 and n == 5:
                big = cand; break
        if big: break
    if big is None:
        for b0 in range(0xf0, 0x100):
            for b1 in range(256):
                cand = bytes([b0, b1, 0x80, 0x00, 0x00])
                v, n = dec(cand)
                if v >= 0x80000000 and n == 5: big = cand; break
            if big: break
    E(bh(0, 2) + bytes([2]) + vec(b''.join(std_hdr(2))) + bytes([0]) + big + b'\x00' * 8)
    # truncated headers: basic header, common header, extended header, payload
    E(b'\x01\x00')                                               # less than a basic header
    E(bh(0, 1) + b'\x00')                                         # truncated common header
    E(bh(0, 1) + ch(2, 0x50, 4)[:6])
    E(bh(0, 1) + ch(2, 0x50, 4) + b'\0' * 10)                    # truncated SHB
    E(bh(0, 1) + ch(2, 0x20, 4) + guc(1, A1, T(), A2)[:40])         # truncated GUC
    E(bh(0, 1) + ch(2, 0x60, 0) + lsreq(1, A1, 1, A2)[:30])       # truncated LS request
    E(bh(0, 1) + ch(2, 0x61, 0) + lsrep(1, A1, 1, A2)[:44])       # truncated LS reply
    E(bh(0, 1) + ch(2, 0x40, 0) + gxc(1, A1, T(), 1, 1, 1, 1, 1)[:40])
    E(bh(0, 1) + ch(2, 0x50, 12) + shb(A1, T()) + b'\x00\x00')      # BTP shorter than its header
    E(bh(0, 1) + ch(1, 0x50, 2) + shb(A1, T()) + b'\x00\x00')
    E(bh(0, 1) + ch(3, 0x50, 6) + shb(A1, T()) + b'short!')         # IPv6 payload too short
    for dst in (2001, 2002):
        E(gn(bh(0, 1, rhl=1), 0x50, shb(A1, 100 + dst), btpb(dst, 0x1234, b'\x02\x63\x00\x00\x00\x01'), nh=2))
    # security: lengths that go past the end
    s = bh(0, 2)
    E(s + bytes([2]))                                             # version only
    E(s + bytes([2, 0x20]) + b'\x00' * 4)                         # header length past the end
    E(s + bytes([2, 0x05]) + bytes([5]) + bytes([0xf0, 0, 0, 0, 0]) + b'\0' * 4)            # IntX of 5 octets in the message type, truncated
    E(s + bytes([2, 11]) + bytes([5]) + b'\xff' * 10 + b'\0' * 8)                         # 10 octet IntX (geonw_intx_assert.py): "at most 7 bits" and too big
    vr = bytes([3, 4, 0]) + struct.pack('>H', 1) + bytes([0xf0, 0, 0, 0, 0])
    c = bytes([2]) + signer_info(1) + subj_info(1, b'') + vec(b'') + vec(vr) + signature(0)
    h = [bytes([0]) + T64, bytes([5]) + intx(36), bytes([128]) + signer_info(2, 2, c)]
    E(sec_frame(2, hdr=h))
    E(s + bytes([2, 0x03, 4, 0xff, 0xff]) )                       # request_unrecognized_certificate with a bogus length
    E(s + secured(2, [bytes([4]) + vec(b'abcd')], [payload_field(3)], [])[:-1])               # certificate request not a multiple of 3
    E(s + secured(2, std_hdr(2), [payload_field(0, b'x' * 10)][:1], [])[:-4])
    E(s + secured(1, std_hdr(1), [payload_field(0, b'x')], [sig_trailer()]) + b'')            # payload that is not GeoNetworking
    E(s + bytes([2]) + vec(b'') + bytes([0]) + bytes([0xc0, 0xff, 0xff]) + b'\x00' * 8)     # payload length of 2 MiB
    E(s + bytes([2]) + vec(b'') + bytes([0]) + bytes([0xe0, 0xff, 0xff, 0xff]) + b'\x00' * 8)   # var length with more than 3 octets
    E(s + bytes([1, 16, 0xff, 0xff]) + b'\0' * 4)
    # all-ones var lengths in IntX
    for n in (3, 5, 8):
        E(s + bytes([2, n + 1, 5]) + b'\xff' * n)
    # deeply nested certificate chain: depth limit
    c = certificate(2)
    for _ in range(80):
        c = certificate(2, signer=signer_info(2, 2, c))
    h = [bytes([0]) + T64, bytes([5]) + intx(36), bytes([128]) + signer_info(2, 2, c)]
    E(sec_frame(2, hdr=h))
    # a v1 certificate whose subject attribute list is longer than its length (bogus)
    attrs = [bytes([32]) + vec(intx(36) + intx(37))]
    c = bytes([1]) + vec(signer_info(1)) + subj_info(1) + vlen(3) + attrs[0][:5] + vec(b'') + signature(0)
    h = [bytes([0]) + T64, bytes([5]) + struct.pack('>H', 2), bytes([128]) + bytes([2]) + c]
    E(sec_frame(1, hdr=h))
    # its_aid_list longer than declared
    for t in (32, 33, 34, 35):
        a = bytes([t]) + vlen(3) + intx(36) + intx(37) + b'\x01\x02\x03\x04\x05\x06'
        c = certificate(2, attrs=[a])
        h = [bytes([0]) + T64, bytes([5]) + intx(36), bytes([128]) + signer_info(2, 2, c)]
        E(sec_frame(2, hdr=h))
    # polygon region with a length that is not a multiple of 8
    vr = bytes([3, 3]) + vlen(7) + b'\x01' * 16
    c = certificate(2, vals=[vr])
    h = [bytes([0]) + T64, bytes([5]) + intx(36), bytes([128]) + signer_info(2, 2, c)]
    E(sec_frame(2, hdr=h))
    # BTP-B length too short, truncated 1609.2
    E(bh(0, 2) + bytes([3, 0x80, 0x20]) + b'x')
    return F

if __name__ == '__main__':
    out = sys.argv[1]
    pcapng(os.path.join(out, 'geonw-coverage.pcapng'), [1, 252], build())
    pcap(os.path.join(out, 'geonw-coverage-malformed.pcap'), build_mal(), linktype=1)
