#!/usr/bin/env python3
# Generates test/captures/isis_lsp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generates isis-lsp-coverage.pcap (clean) and isis-lsp-coverage-malformed.pcap
# for packet-isis-lsp.c (L1 and L2 link state PDUs and the TLVs they carry).
import sys
import os
from isislib import (
    area, auth_clear, auth_crypto, auth_md5, f32, ip6, lsp, lsp_with_checksum, sid, struct, tlv,
    write_pcap,
)

out = sys.argv[1] if len(sys.argv) > 1 else '.'
P = struct.pack
A1 = tlv(1, area(b'\x49\x00\x01'))

def sub(t, v):
    assert len(v) <= 255
    return bytes([t, len(v)]) + bytes(v)

def isn(nbr, metric, subs=b'', nsys=6, pn=0):
    return sid(nbr, nsys) + bytes([pn]) + P('>I', metric)[1:] + bytes([len(subs)]) + subs

def v4(*a):
    return bytes(a)

# ---- sub-TLVs of the extended IS reachability TLVs (22, 222) ----
def adj_sid(flags, weight, sli, lan=None):
    return bytes([flags, weight]) + (sid(9) if lan else b'') + sli

SPB_NAME = None
IS_SUB_LIST = [
    sub(3, P('>I', 0x80000005)),                       # administrative groups
    sub(4, P('>II', 17, 18)),                          # link local/remote identifiers
    sub(6, v4(10, 0, 0, 1)), sub(8, v4(10, 0, 0, 2)),
    sub(9, f32(125000000.0)), sub(10, f32(12500000.0)),
    sub(11, b''.join(f32(1000000.0 * i) for i in range(8))),
    sub(12, ip6('2001:db8::1')), sub(13, ip6('2001:db8::2')),
    sub(14, P('>II', 0x1, 0x80000000)),                # extended administrative groups
    sub(15, bytes([1, 10, 2, 20])),                    # link MSD
    sub(17, b'\x01' + P('>I', 5)[1:]),                 # generic metric
    sub(18, P('>I', 100)[1:]),                         # TE default metric
    sub(22, b'\x01\x00\x00\x00' + b''.join(f32(1000000.0 * (i + 1)) for i in range(8))),   # bandwidth constraints (8 CTs)
    sub(29, P('>I', 77)[1:] + b'\x02' + P('>H', 0x8001)),    # SPB link metric
    sub(33, b'\x80' + P('>I', 150)[1:]),
    sub(34, b'\x80' + P('>I', 100)[1:] + b'\x00' + P('>I', 200)[1:]),
    sub(35, b'\x00' + P('>I', 300)[1:]),
    sub(36, b'\x80' + P('>I', 1000)[1:]),              # link loss
    sub(37, f32(1000.0)), sub(38, f32(2000.0)), sub(39, f32(3000.0)),
    sub(99, b'\xde\xad\xbe\xef'),                      # unknown sub-TLV
]
IS_SUBS_ALL = b''.join(IS_SUB_LIST)
SUB_BW1 = sub(22, b'\x01\x00\x00\x00' + f32(1000.0))             # one constraint only
SUB_BW_NONE = sub(22, b'\x01\x00\x00\x00')
ADJ_SIDS = (
    sub(31, adj_sid(0x30, 1, P('>I', 0x00012345)[1:])) +           # 3 octet label, V and L set
    sub(31, adj_sid(0x00, 2, P('>I', 77))) +                       # 4 octet index
    sub(31, adj_sid(0x20, 3, ip6('2001:db8::7'))) +                # 16 octet IPv6 SID, V set
    sub(31, adj_sid(0x30, 4, ip6('2001:db8::8'))) +                # globally unique
    sub(32, adj_sid(0x30, 1, P('>I', 0x00012345)[1:], lan=True)) +
    sub(32, adj_sid(0x00, 2, P('>I', 5), lan=True)) +
    sub(32, adj_sid(0x20, 3, ip6('2001:db8::9'), lan=True)) +
    sub(31, adj_sid(0x00, 5, b'\x01\x02'))                         # SLI of another size: ignored
)
SRV6_STRUCT = sub(1, bytes([32, 16, 16, 0]))
SRV6_ENDX = sub(43, b'\xe0' + bytes([0, 5]) + P('>H', 0x0040) + ip6('2001:db8:1::1') + bytes([len(SRV6_STRUCT) + 4]) + SRV6_STRUCT + sub(99, b'ab'))
SRV6_LAN_ENDX = sub(44, sid(7) + b'\xe0' + bytes([0, 5]) + P('>H', 0x0041) + ip6('2001:db8:1::2') + bytes([len(SRV6_STRUCT) + 4]) + SRV6_STRUCT + sub(99, b'ab'))
SRV6_ENDX_NOSUB = sub(43, b'\x00' + bytes([0, 5]) + P('>H', 0x0040) + ip6('2001:db8:1::3') + b'\x00')
def appspec(sabm, udabm, subs=b'', legacy=False):
    return bytes([(0x80 if legacy else 0) | len(sabm), len(udabm)]) + sabm + udabm + subs
LINK_ATTR_SUBTLV = sub(16, appspec(b'\xe0\x80', b'\x01\x02', sub(18, P('>I', 5)[1:]) + sub(99, b'x')))
LINK_ATTR_NOSUB = sub(16, appspec(b'\x80', b'', legacy=True))
LINK_ATTR_UDABM = sub(16, appspec(b'', b'\x01\x02'))
LINK_ATTR_NONE = sub(16, appspec(b'', b''))

def pack22(subs, first=2, code=22, mt=None):
    """Pack a list of sub-TLVs into TLVs 22 (or 222), one neighbour each, at most 255 octets."""
    res, cur, n = [], b'', first
    for x in subs + [None]:
        if x is None or len(cur) + len(x) > 230:
            if cur:
                body = isn(n, 10 + n, cur)
                res.append(tlv(code, (P('>H', mt) if mt is not None else b'') + body))
                n += 1
            cur = b''
        if x is not None:
            cur += x
    return res

# ---- reachability sub-TLVs (135, 235, 236, 237) ----
def prefix4(metric, plen, addr, up=False, subs=None):
    nb = (plen + 7) // 8
    c = plen | (0x80 if up else 0) | (0x40 if subs is not None else 0)
    r = P('>I', metric) + bytes([c]) + bytes(addr[:nb])
    if subs is not None:
        r += bytes([len(subs)]) + subs
    return r

def prefix6(metric, plen, addr, flags=0, subs=None):
    nb = (plen + 7) // 8
    c = flags | (0x20 if subs is not None else 0)
    r = P('>I', metric) + bytes([c, plen]) + addr[:nb]
    if subs is not None:
        r += bytes([len(subs)]) + subs
    return r

BIER_SUB = sub(32, bytes([1, 0, 1]) + P('>H', 5) + sub(1, bytes([3, 0x40, 0x01, 0x00])) + sub(2, b'ab'))
PFX_SUBS = (sub(1, P('>I', 1) + P('>I', 2)) + sub(2, P('>Q', 3)) +
            sub(3, bytes([0x0c, 0]) + P('>I', 0x12345)[1:]) +           # label SID: V and L flags
            sub(3, bytes([0x00, 1]) + P('>I', 100)) +                   # index SID
            sub(4, b'\xe0') +                                           # prefix attribute flags
            sub(6, b'\x80' + P('>I', 5)) +                              # flex algo prefix metric
            BIER_SUB + sub(99, b'zz'))
PFX_BAD_SUBS = (sub(3, bytes([0xe0, 1]) + P('>I', 100)[1:]) +   # label SID without V and L (bad flags)
                sub(3, bytes([0x04, 1]) + P('>I', 100)) +       # index SID with a flag set
                sub(3, bytes([0x00, 1]) + b'\x01\x02') +        # unknown SID format
                sub(4, b'\xe0\x00') + sub(6, b'\x80') +                 # wrong lengths
                sub(32, b'\x01\x02') +                                  # BIER sub-TLV too short
                sub(32, bytes([1, 0, 1]) + P('>H', 5) + b'\x01') +      # BIER sub-sub-TLV truncated
                sub(32, bytes([1, 0, 1]) + P('>H', 5) + sub(1, b'\x01\x02')))   # MPLS encap of wrong length
EXT_IP = tlv(135, prefix4(10, 24, v4(192, 0, 2, 0)) + prefix4(20, 32, v4(198, 51, 100, 1), up=True) +
             prefix4(30, 0, b'') + prefix4(40, 12, v4(10, 16, 0, 0), subs=PFX_SUBS) +
             prefix4(50, 20, v4(172, 16, 0, 0), subs=b''))
EXT_IP_BAD = tlv(135, prefix4(10, 24, v4(192, 0, 2, 0), subs=PFX_BAD_SUBS))
IPV6_REACH = tlv(236, prefix6(10, 64, ip6('2001:db8:1::')) + prefix6(20, 128, ip6('2001:db8::1'), flags=0xc0) +
                 prefix6(30, 0, b'', flags=0x1f) + prefix6(40, 48, ip6('2001:db8:2::'), flags=0x40, subs=PFX_SUBS) +
                 prefix6(50, 56, ip6('2001:db8:3::'), subs=b''))
MT_IP = tlv(235, P('>H', 2) + prefix4(10, 24, v4(192, 0, 2, 0), subs=sub(1, P('>I', 7))))
MT_IP6 = tlv(237, P('>H', 2) + prefix6(10, 64, ip6('2001:db8:5::'), subs=sub(1, P('>I', 7))))
MT_IS = tlv(222, P('>H', 2) + isn(2, 10, sub(3, P('>I', 5))))

def ip_old(metric, up, addr, mask, ext=False):
    return bytes([metric | (0x80 if up else 0), 0x80, 0x80, 0x80]) + bytes(addr) + bytes(mask)

IP_REACH = tlv(128, ip_old(20, False, (10, 0, 0, 0), (255, 0, 255, 0)) + ip_old(10, False, (192, 0, 2, 0), (255, 255, 255, 0)) +
               ip_old(0x40, True, (198, 51, 100, 0), (255, 255, 0, 0)))      # discontiguous mask first (found_mask is never reset)
IP_REACH_X = tlv(130, ip_old(10, False, (203, 0, 113, 0), (255, 255, 255, 0)) + bytes([5, 0, 0, 0x01]) + bytes(8))
def eis(metric, nbr, nsys=6, pn=1):
    return bytes([metric, 0x80, 0x80, 0x80]) + sid(nbr, nsys) + bytes([pn])
IS_REACH_L1 = tlv(2, b'\x01' + eis(10, 5) + eis(0x40, 6) + eis(0xff, 7))
IS_REACH_L2 = tlv(2, b'\x00' + eis(10, 5) + eis(20, 6, pn=0))
ES_REACH = tlv(3, eis(0, 0x30)[:-1] + eis(5, 0x31)[:-1])

# ---- router capability (242) ----
def cap(subs, rid=v4(10, 0, 0, 1), flags=0x03):
    return tlv(242, rid + bytes([flags]) + subs)
SR_SID4 = sub(1, P('>I', 16000))
SR_SID3 = sub(1, P('>I', 16000)[1:])
FAD_BASE = bytes([128, 0, 0, 100])
def fad(*subs, num=128):
    return sub(26, bytes([num, 0, 0, 100]) + b''.join(subs))
FAD_SUBS = (sub(1, P('>I', 5)) + sub(2, P('>II', 1, 2)) + sub(3, P('>I', 9)) + sub(4, b'\x80') +
            sub(5, P('>II', 7, 8)) + sub(6, f32(1000000.0)) + sub(7, P('>I', 5000)[1:]) +
            sub(8, b'\x80' + f32(1e9) + f32(1e6)) + sub(99, b'\x01\x02'))
CAP_SUBS = (sub(1, b'\xf8') + sub(2, b'\xc0' + P('>I', 1000)[1:] + SR_SID4) + sub(2, b'\x00' + P('>I', 1000)[1:] + SR_SID3) +
            sub(2, b'\x00' + P('>I', 1000)[1:] + sub(7, b'\x01')) + sub(2, b'\x00' + P('>I', 1000)[1:] + sub(1, b'\x01\x02\x03\x04\x05')) +
            sub(12, ip6('2001:db8::11')) + sub(13, b'\x01') + sub(13, b'\x01' + P('>I', 0xa0000000)) +
            sub(6, b'\x00' + P('>HH', 7, 0x8000) + b'\x00' + P('>HH', 8, 0x8001)) +
            sub(7, P('>HHH', 2, 3, 4)) + sub(8, P('>H', 1) + P('>HH', 0x8000, 0x8001)) +
            sub(9, P('>H', 1) + P('>HH', 0x8000, 0x8001)) +
            sub(10, P('>HHHI', 0x1000, 1, 100, 5) + sid(1) + sid(2)) + sub(10, P('>HHHI', 0x1000, 1, 100, 5)) +
            sub(14, P('>H', 100) + P('>HH', 101, 102)) + sub(19, bytes([0, 1, 2])) +
            sub(22, b'\x00' + P('>I', 100)[1:] + sub(1, P('>I', 5000)[1:]) + P('>I', 100)[1:] + sub(7, b'\x01')) +
            sub(23, bytes([1, 10, 2, 20])) + sub(25, P('>H', 0x8000)) + sub(200, b'\x00'))
def split_subs(b):
    r = []
    while b:
        r.append(b[:2 + b[1]])
        b = b[2 + b[1]:]
    return r
def caps(b, per=200):
    res, cur = [], b''
    for x in split_subs(b) + [None]:
        if x is None or len(cur) + len(x) > per:
            if cur:
                res.append(cap(cur))
            cur = b''
        if x is not None:
            cur += x
    return res
FAD = fad(FAD_SUBS)

# ---- misc TLVs ----
def clvs_grp():
    mac = lambda n: b'\x01\x00\x5e\x00\x00' + bytes([n])
    return (sub(1, P('>HHB', 1, 100, 2) + b'\x01' + mac(1) + mac(2) + b'\x00' + mac(3)) +
            sub(2, P('>HHB', 1, 100, 2) + b'\x01' + v4(239, 1, 1, 1) + v4(10, 0, 0, 1) + b'\x00' + v4(239, 1, 1, 2)) +
            sub(3, P('>HHB', 1, 100, 2) + b'\x01' + ip6('ff02::1') + ip6('2001:db8::1') + b'\x00' + ip6('ff02::2')) +
            sub(9, b'\x01\x02\x03'))
TLV_GRP = tlv(142, clvs_grp())
SPB_INST = sub(1, bytes(range(8)) + P('>I', 100) + P('>H', 0x8000) + P('>I', 0x800123) + b'\x02' +
               (b'\xe0' + P('>I', 0x01) + P('>I', 0x100001)[1:]) * 2)
SPB_INST0 = sub(1, bytes(8) + P('>I', 100) + P('>H', 0x8000) + P('>I', 0) + b'\x00')
SPB_OALG = sub(2, P('>I', 1) + b'\x01\x02')
SPBM_SVC = sub(3, sid(1) + P('>H', 100) + b'\xc0' + P('>I', 1000)[1:] + b'\x60' + P('>I', 1001)[1:])
SPBV_MAC = sub(4, P('>H', 0x8064) + b'\xc0' + sid(2) + b'\x40' + sid(3))
MT_CAP = tlv(144, P('>H', 0x8000) + SPB_INST + SPB_OALG + SPBM_SVC + SPBV_MAC + SPB_INST0 +
             sub(6, b'\x00' + P('>HH', 7, 0x8000)) + sub(100, b'x'))
MT_CAP_SMALL = tlv(144, P('>H', 0x0002))
SID_BIND = lambda plen, pfx, subs, flags=0xff: tlv(149, bytes([flags, 3]) + P('>H', 10) + bytes([plen]) + pfx + subs)
SL_SUBS = (sub(1, P('>I', 5000)[1:]) + sub(1, P('>I', 70000)) + sub(3, bytes([0x3f, 1]) + P('>I', 5000)[1:]) +
           sub(3, bytes([0x00, 1]) + P('>I', 5000)))
SL_BAD = sub(1, b'\x01\x02') + sub(3, bytes([0, 1]) + b'\x01\x02')
MT_SUP = tlv(229, P('>HHH', 0, 0x8002, 0x4003))
PURGE1 = tlv(13, b'\x01' + sid(5))
PURGE2 = tlv(13, b'\x02' + sid(5) + sid(6))
MACRI = tlv(147, P('>H', 0x8000) + b'\x64' + P('>H', 100) + sid(1) + sid(2) + sid(3) + sid(4))
MACRI1 = tlv(147, P('>H', 0x8000) + b'\x64' + P('>H', 100))
def locator(bits, loc, subs=b'', metric=10, alg=0):
    return P('>I', metric) + bytes([0x80, alg, bits]) + loc[:(bits + 7) // 8] + bytes([len(subs)]) + subs
ENDSID = sub(5, b'\x00' + P('>H', 0x0020) + ip6('2001:db8:1::') + bytes([len(SRV6_STRUCT) + 4]) + SRV6_STRUCT + sub(99, b'ab'))
SRV6_LOC = tlv(27, P('>H', 0) + locator(48, ip6('2001:db8:1::'), sub(4, b'\xe0') + ENDSID) + locator(64, ip6('2001:db8:2::'), alg=128) +
               locator(128, ip6('2001:db8:3::1'), sub(5, b'\x00' + P('>H', 0x0020) + ip6('2001:db8:1::') + b'\x00') + sub(99, b'x')))
AVAYA_SUBS = sub(1, P('>I', 7)) + sub(135, P('>I', 10) + v4(192, 0, 2, 0) + v4(255, 255, 255, 0)) + \
    sub(236, P('>I', 10) + P('>H', 64) + ip6('2001:db8::')) + sub(99, b'zz')
def avaya(subs):
    return tlv(184, bytes(4) + bytes(7) + b'\x00\x00\x01' + bytes([len(subs)]) + subs)

frames = []
add = frames.append

# LSP header variants
add(lsp(1, [A1, tlv(137, b'router-1')], flags=0x03))                                       # 1
add(lsp(2, [A1, tlv(137, b'router-2')], flags=0x1b, seq=0x7fffffff))                       # 2 P, ATT bits, overload, IS type
add(lsp_with_checksum(lsp(1, [A1, tlv(137, b'router-3')], cksum=0xabcd)))                  # 3 good checksum
add(lsp_with_checksum(lsp(2, [A1, tlv(137, b'router-4')], cksum=0xabcd)))                  # 4
add(lsp(1, [A1], life=0, cksum=0x1234))                                                    # 5 purge: checksum ignored
add(lsp(2, [A1], flags=0x6f))                                                              # 6 other flag bits
add(lsp(1, [A1, tlv(137, b'id1')], idlen=1))                                               # 7
add(lsp(2, [A1, tlv(137, b'id8')], idlen=8))                                               # 8
add(lsp(1, [A1, tlv(137, b'id0')], idlen=255))                                             # 9
add((lsp(1, [A1, tlv(137, b'eth')]), 'eth'))                                               # 10
add(lsp(1, [A1, tlv(137, b'x' * 10), PURGE1]))                                             # 11 purge originator ID (L1)
# neighbours and reachability
add(lsp(1, [A1, IS_REACH_L1, ES_REACH, IP_REACH, IP_REACH_X]))                             # 12
add(lsp(2, [A1, IS_REACH_L2, IP_REACH, IP_REACH_X, tlv(4, sid(9)),
            tlv(5, b'\x80\x40\x80\x80' + bytes([8]) + bytes.fromhex('49000101') + bytes([8]) +
                bytes.fromhex('49000202') + b'\x03' + b'\x49\x10')]))                      # 13 partition DIS, prefix neighbours
add(lsp(1, [A1, tlv(14, P('>H', 1492))]))                                                  # 14 buffer size
add(lsp(2, [A1, tlv(14, P('>H', 1492))]))                                                  # 15
add(lsp(1, [A1] + pack22(IS_SUB_LIST)))                                                    # 16 every IS reachability sub-TLV
add(lsp(2, [A1] + pack22([SUB_BW1, SUB_BW_NONE, LINK_ATTR_SUBTLV, LINK_ATTR_NOSUB, LINK_ATTR_UDABM, LINK_ATTR_NONE], first=20)))   # 17
add(lsp(1, [A1] + pack22([ADJ_SIDS, SRV6_ENDX, SRV6_LAN_ENDX, SRV6_ENDX_NOSUB], first=30)))   # 18
add(lsp(2, [A1] + pack22([ADJ_SIDS, SRV6_ENDX], first=40, code=222, mt=2)))                  # 19 MT IS reachability
add(lsp(1, [A1, MT_IS, EXT_IP, IPV6_REACH, MT_IP, MT_IP6]))                                 # 20
add(lsp(2, [A1, EXT_IP, IPV6_REACH, MT_IP, MT_IP6, MT_SUP]))                                # 21
add(lsp(1, [A1] + caps(CAP_SUBS)))                                                         # 22 router capability sub-TLVs
add(lsp(2, [A1] + caps(CAP_SUBS)))                                                     # 23
add(lsp(1, [A1, cap(FAD)]))                                                                # 24 flexible algorithm definition
add(lsp(2, [A1, cap(sub(26, FAD_BASE) + sub(26, bytes([129, 1, 1, 50]) + sub(5, P('>I', 7)) + sub(4, b'\x00')))]))   # 25
add(lsp(1, [A1, cap(b'')]))                                                                # 26 no sub-TLVs
# SRLG and application specific SRLG
add(lsp(1, [A1, tlv(138, sid(1) + b'\x00\x01' + v4(192, 0, 2, 1) + v4(192, 0, 2, 2) + P('>II', 10, 20))]))   # 27
add(lsp(2, [A1, tlv(138, sid(1) + b'\x00\x00' + v4(192, 0, 2, 1) + v4(192, 0, 2, 2))]))    # 28 no values
def appsrlg(sabm, udabm, subs, values, legacy=False):
    return tlv(238, sid(1) + b'\x00' + bytes([(0x80 if legacy else 0) | len(sabm), len(udabm)]) + sabm + udabm +
               bytes([len(subs)]) + subs + values)
add(lsp(1, [A1, appsrlg(b'\xe0\x80', b'\x01\x02', sub(4, P('>II', 5, 6)) + sub(99, b'x'), P('>II', 11, 12), legacy=True)]))   # 29
add(lsp(2, [A1, appsrlg(b'', b'', b'', P('>I', 11))]))                                      # 30 no bit masks, no sub-TLVs
add(lsp(1, [A1, tlv(140, ip6('2001:db8::1')), tlv(232, ip6('fe80::1')), tlv(134, v4(10, 0, 0, 1))]))   # 31
# multi topology capability and SID/label binding
add(lsp(1, [A1, MT_CAP, MT_CAP_SMALL]))                                                    # 32
add(lsp(2, [A1, MT_CAP]))                                                                  # 33
add(lsp(1, [A1, SID_BIND(32, v4(192, 0, 2, 1), SL_SUBS)]))                                 # 34 IPv4 FEC
add(lsp(2, [A1, SID_BIND(128, ip6('2001:db8::1'), sub(1, P('>I', 5000)[1:]) + sub(3, bytes([0x3f, 1]) + P('>I', 5000)[1:]))]))  # 35 IPv6 FEC
add(lsp(1, [A1, tlv(149, b''), tlv(137, b'after-empty')]))                                  # 36 empty SID/label binding
# group addresses and MAC reachability (L1 only in the table)
add(lsp(1, [A1, TLV_GRP, MACRI, MACRI1]))                                                  # 37
add(lsp(1, [A1, tlv(142, sub(1, P('>HHB', 1, 100, 0)))]))                                  # 38 no group records
# SRv6 locators
add(lsp(1, [A1, SRV6_LOC]))                                                                # 39
add(lsp(2, [A1, SRV6_LOC, PURGE2]))                                                        # 40
# Avaya
add(lsp(1, [A1, avaya(AVAYA_SUBS), tlv(185, b'\x01\x02'), tlv(186, b'\x01\x02')]))         # 41
# Reproducers of the fixes on the branch (isis_smallfixes.py), the ones that decode without errors
add(lsp(1, [tlv(147, b'\x00\x01' + b'\x00' + b'\x00\x0a' + sid(0x11) + sid(0x22) + sid(0x33)), tlv(137, b'r1')]))   # 42 MAC 3+ (fix)
add(lsp(1, [tlv(138, sid(1) + b'\x00\x01' + v4(192, 0, 2, 1) + v4(192, 0, 2, 2) + b'\xaa\xbb'), tlv(137, b'router-one-hostname')]))   # 43 SRLG length 18 (fix)
add(lsp(1, [tlv(242, v4(192, 0, 2, 1) + b'\x00' + sub(26, b'\x80\x00\x00\x80' + sub(5, P('>I', 7)) + sub(4, b'\x80') + sub(7, b'\x00\x00\x10')))]))   # 44 Flex-Algo exclude SRLG (fix)
add(lsp(2, [tlv(5, b'\x0a\x80\x80\x80' + b'\x08' + bytes.fromhex('49000101') + b'\x08' + bytes.fromhex('49000202'))]))   # 45 prefix neighbours (fix)
add(lsp(1, [tlv(149, b'\x00\x00\x00\x01' + bytes([32]) + v4(192, 0, 2, 0) + sub(1, b'\x00\x00\x10') + sub(1, b'\x00\x00\x11'))]))   # 46 two sub-TLVs, each at its own offset (fix)
add(lsp(1, [avaya(sub(1, P('>I', 7))), tlv(137, b'router-6'), tlv(137, b'router-6b')]))   # 47 Avaya IPVPN with a sub-TLV that fits (fix)

# shared TLVs in LSPs (see the isis-clv directory), authentication and unknown TLVs
add(lsp(1, [A1, tlv(7, P('>H', 5) + P('>HH', 1, 2)), tlv(129, bytes([0xcc, 0x8e])), tlv(132, v4(192, 0, 2, 1) + v4(192, 0, 2, 2)),
            tlv(232, ip6('fe80::1')), tlv(134, v4(10, 0, 0, 1)), tlv(229, P('>HH', 0, 0x8002)), tlv(133, b'ippass'),
            auth_clear(b'pass'), tlv(250, b'x')]))                                         # 48
add(lsp(2, [A1, tlv(7, P('>H', 5) + P('>HH', 1, 2)), tlv(129, bytes([0xcc])), tlv(132, v4(192, 0, 2, 1)),
            tlv(232, ip6('fe80::1')), tlv(134, v4(10, 0, 0, 1)), tlv(229, P('>HH', 0, 0x8002)), tlv(133, b'ippass'),
            auth_md5(), tlv(140, ip6('2001:db8::2'))]))                                    # 49
add(lsp(1, [A1, auth_crypto(1, bytes(range(20)))]))                                        # 50
add(lsp(2, [A1, tlv(10, b'\x03\x00'), tlv(137, b'router-key')]))                           # 51 CRYPTO_AUTH Key ID too short (clv fix, warning)
add(lsp(1, [A1, tlv(10, b'\x99\x01')]))                                                    # 52 unknown authentication type
add(lsp(2, [A1, tlv(2, b'\x00'), IS_REACH_L2[:0] + tlv(2, b'\x00' + eis(10, 5))]))         # 53 L2 IS neighbours, no entries / one
add(lsp(1, [A1, tlv(22, isn(2, 10)), tlv(222, P('>H', 3) + isn(2, 10))]))                  # 54 IS neighbours without sub-TLVs
write_pcap(os.path.join(out, 'isis-lsp-coverage.pcap'), frames)

# ---------------- malformed capture ----------------
mal = []
madd = mal.append
def L1(*t, **k): return lsp(1, list(t), **k)
def L2(*t, **k): return lsp(2, list(t), **k)
# header and PDU length problems
for hl in (9, 11, 16, 12 + 6 + 2 + 4 - 1, 12 + 6 + 2 + 4 + 2 - 1, 12 + 6 + 2 + 4 + 2):
    madd(L1(A1, hdrlen=hl))
madd(L1(A1, pdulen=10))
madd(L1(A1, pdulen=900))
madd(L2(A1, pdulen=900, cksum=0x1234))
madd(L1(A1, hdrlen=8))
madd(L1(A1, hdrlen=10))
madd(L1(A1, cksum=0x1234))                                             # bad checksum
madd(lsp_with_checksum(L1(A1, tlv(137, b'x'), cksum=0xabcd)).replace(b'\x01x', b'\x01y'))   # checksum no longer matches
madd((lsp_with_checksum(L1(A1, tlv(8, bytes(40)), cksum=0xabcd)), 'snap:20'))   # checksum cannot be verified
# TLV length problems
PAD = tlv(8, bytes(40))
madd(L1(tlv(128, bytes(5))))
madd(L1(tlv(130, bytes(13))))
madd(L1(tlv(235, b'\x00')))
madd(L1(tlv(237, b'\x00')))
madd(L1(tlv(222, b'\x00')))
madd(L2(tlv(4, bytes(3))))
madd(L2(tlv(4, bytes(10))))
madd(L2(tlv(5, b'\x80\x80')))
madd(L2(tlv(5, b'\x80\x80\x80\x80' + b'\x08')))
madd(L2(tlv(5, b'\x80\x80\x80\x80' + b'\x40\x49')))
madd(L1(tlv(14, b'\x01')))
madd(L1(tlv(138, bytes(10))))
madd(L1(tlv(238, bytes(5))))
madd(L1(appsrlg(b'\xff' * 9, b'', b'', b'')))                         # SABM length 9
madd(L1(tlv(238, sid(1) + b'\x00' + bytes([0x03, 0x00]) + b'\x01')))   # SABM longer than the TLV
madd(L1(tlv(238, sid(1) + b'\x00' + bytes([0x00, 0x09]) + b'\x01' * 12)))   # UDABM length 9
madd(L1(tlv(238, sid(1) + b'\x00' + bytes([0x00, 0x03]) + b'\x01')))   # UDABM longer than the TLV
madd(L1(tlv(238, sid(1) + b'\x00' + bytes([0x00, 0x00]) + b'\x20')))   # sub-TLV length too large
madd(L1(tlv(147, bytes(7))))                                           # MAC reachability, wrong length
madd(L1(tlv(13, bytes(3))))                                            # purge originator ID
madd(L1(tlv(13, b'\x05' + bytes(12))))
madd(L1(tlv(13, b'\x02' + bytes(8))))
madd(L1(tlv(27, bytes(5))))
madd(L1(tlv(184, bytes(10)), PAD))
madd(L1(avaya(b'\x01'), PAD))
madd(L1(tlv(184, bytes(4) + bytes(7) + b'\x00\x00\x01' + b'\x05' + sub(1, P('>I', 7))), PAD))   # sub-TLV bytes disagree with the length
madd(L1(avaya(sub(1, b'\x01\x02')), PAD))
madd(L1(avaya(bytes([7, 4, 0xee])), tlv(137, b'router-6'), tlv(137, b'router-6b')))   # the sub-TLV is longer than the TLV (fix)
madd(L1(avaya(sub(135, b'\x01\x02')), PAD))
madd(L1(avaya(sub(236, b'\x01\x02')), PAD))
# IS reachability, SPB sub-TLVs in the MT capability TLV and SID/label binding
madd(L1(tlv(2, b'\x01' + bytes(5))))
madd(L1(tlv(3, bytes(5))))
madd(L1(tlv(22, isn(2, 10, sub(29, b'\x01\x02')))))
madd(L1(tlv(144, P('>H', 0) + sub(1, bytes(10)))))                    # short SPB instance
madd(L1(tlv(144, P('>H', 0) + sub(1, bytes(8) + P('>I', 100) + P('>H', 0x8000) + P('>I', 0) + b'\x02' + bytes(8)))))   # trees do not match
madd(L1(tlv(144, P('>H', 0) + sub(1, bytes(8) + P('>I', 100) + P('>H', 0x8000) + P('>I', 0) + b'\x00' + bytes(3)))))
madd(L1(tlv(144, P('>H', 0) + sub(3, bytes(5)))))                     # short service identifier
madd(L1(tlv(144, P('>H', 0) + sub(3, sid(1) + P('>H', 100) + b'\x00\x01'))))   # short ISID
madd(L1(tlv(144, P('>H', 0) + sub(4, b'\x01'))))                      # short SPBV MAC
madd(L1(tlv(144, P('>H', 0) + sub(4, P('>H', 5) + b'\x00\x01\x02'))))   # short MAC entry
madd(L1(tlv(144, P('>H', 0) + bytes([9, 200]) + b'\x01')))            # sub-TLV longer than the TLV
madd(L1(tlv(242, v4(1, 2, 3, 4) + b'\x00' + bytes([9, 200]) + b'\x01')))
madd(L1(SID_BIND(24, b'\x01\x02\x03', b'')))                          # unknown prefix length
madd(L1(SID_BIND(32, v4(1, 2, 3, 4), sub(1, b'\x01\x02') + sub(3, bytes([0, 1]) + b'\x01\x02') + sub(77, b'\x01') + sub(31, b'\x01\x02'))))
# prefix reachability sub-TLV problems
madd(L1(EXT_IP_BAD))
madd(L1(tlv(135, prefix4(10, 24, v4(192, 0, 2, 0), subs=sub(3, bytes([0x0c, 0]) + P('>I', 0x12345)[1:])) [:4] + b'\x7f')))   # prefix length 63 bits
madd(L1(tlv(236, P('>I', 10) + b'\x00' + bytes([200]) + bytes(16))))   # IPv6 prefix length 200
madd(L1(tlv(236, prefix6(10, 64, ip6('2001:db8:1::'), subs=PFX_BAD_SUBS))))
madd(L1(tlv(236, prefix6(10, 64, ip6('2001:db8:1::'), subs=sub(3, bytes([0xe0, 1]) + P('>I', 100)[1:])))))
# IS reachability sub-TLVs with bad flags (adjacency SIDs), SRv6 problems
madd(L1(*pack22([sub(31, adj_sid(0x00, 1, P('>I', 0x00012345)[1:])), sub(31, adj_sid(0x30, 1, P('>I', 77))), sub(31, adj_sid(0x00, 1, ip6('2001:db8::7')))])))
madd(L1(*pack22([sub(43, b'\x00' + bytes([0, 5]) + P('>H', 0x0040) + ip6('2001:db8:1::3') + bytes([9]) + bytes([1, 9]) + bytes(7))])))     # sub-sub-TLV too long
madd(L1(*pack22([sub(43, b'\x00' + bytes([0, 5]) + P('>H', 0x0040) + ip6('2001:db8:1::3') + bytes([6]) + bytes([1, 2]) + bytes(2) + b'\x00\x00')])))   # SID structure of wrong length
madd(L1(*pack22([sub(44, sid(7) + b'\x00' + bytes([0, 5]) + P('>H', 0x0040) + ip6('2001:db8:1::3') + bytes([9]) + bytes([1, 9]) + bytes(7))])))
# SRv6 locators
madd(L1(tlv(27, P('>H', 0) + P('>I', 10) + b'\x00\x00\x00' + bytes(4))))                # locator size 0
madd(L1(tlv(27, P('>H', 0) + P('>I', 10) + b'\x00\x00\x80' + ip6('2001:db8::1')[:8])))  # locator longer than the TLV
madd(L1(tlv(27, P('>H', 0) + P('>I', 10) + b'\x00\x00\x08\x20\x40')))                   # short locator entry
madd(L1(tlv(27, P('>H', 0) + locator(64, ip6('2001:db8:2::'), sub(4, b'\xe0')) + b'\x01\x02')))   # second entry too short
madd(L1(tlv(27, P('>H', 0) + P('>I', 10) + b'\x00\x00\x40' + ip6('2001:db8:2::')[:8] + bytes([5]) + bytes([4, 9]) + bytes(3))))   # sub-TLV longer than the sub-TLV list
madd(L1(tlv(27, P('>H', 0) + locator(64, ip6('2001:db8:2::'), sub(5, bytes(10))))))      # End SID too short
madd(L1(tlv(27, P('>H', 0) + locator(64, ip6('2001:db8:2::'), sub(5, b'\x00' + P('>H', 0x0020) + ip6('2001:db8:1::') + bytes([50]))))))
madd(L1(tlv(27, P('>H', 0) + locator(64, ip6('2001:db8:2::'), sub(5, b'\x00' + P('>H', 0x0020) + ip6('2001:db8:1::') + bytes([4]) + bytes([1, 9, 0, 0])))))) # sub-sub-TLV longer than left
madd(L1(tlv(27, P('>H', 0) + locator(64, ip6('2001:db8:2::'), sub(5, b'\x00' + P('>H', 0x0020) + ip6('2001:db8:1::') + bytes([6]) + bytes([1, 2, 0, 0, 0, 0]))))))   # structure of wrong length
# group addresses with short sub-TLVs, and a PSNP-like truncated PDU
madd(L1(tlv(142, sub(1, b'\x01\x02\x03') + sub(1, bytes(30)))))
madd(L1(tlv(142, sub(2, b'\x01\x02\x03') + sub(3, b'\x01'))))
madd(L1(A1, tlv(137, b'router'))[:-6])                                 # truncated PDU
# capability sub-TLV problems: truncated nickname and the checksum TLV
madd(L1(tlv(12, b'\x00')))
write_pcap(os.path.join(out, 'isis-lsp-coverage-malformed.pcap'), mal)
print(len(frames), len(mal))
