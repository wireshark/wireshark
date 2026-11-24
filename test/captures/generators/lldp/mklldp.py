#!/usr/bin/env python3
# Generates test/captures/lldp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the LLDP coverage captures: mklldp.py <outdir> [-v]

lldp-coverage.pcap            main capture (no malformed frames)
lldp-coverage-malformed.pcap  wrong lengths, truncated TLVs, error paths
"""
import struct
import sys
import os
from pylib import eth, mac, Pcap

SRC = '02:00:00:00:00:01'
NEAREST = '01:80:c2:00:00:0e'
MAC6 = mac(SRC)

OUI_DCBX = '001b21'
OUI_8021 = '0080c2'
OUI_8023 = '00120f'
OUI_MED = '0012bb'
OUI_PN = '000ecf'
OUI_CISCO = '000142'
OUI_QBG = '001b3f'
OUI_AVX = '00040d'
OUI_AVX2 = 'd88466'
OUI_HYTEC = '30b216'
OUI_AVAYA = '00400d'
OUI_IANA = '00005e'
OUI_ONOS = 'a42305'
OUI_ODVA = '00216c'


def tlv(t, data=b''):
    return struct.pack('>H', (t << 9) | len(data)) + data


def tlv_len(t, l, data=b''):
    """TLV with a length field that differs from the data"""
    return struct.pack('>H', (t << 9) | l) + data


def org(oui, sub, data=b''):
    return tlv(127, bytes.fromhex(oui) + bytes((sub,)) + data)


def chassis(sub=4, data=MAC6):
    return tlv(1, bytes((sub,)) + data)


def port(sub=7, data=b'port-1'):
    return tlv(2, bytes((sub,)) + data)


def ttl(v=120):
    return tlv(3, struct.pack('>H', v))


END = tlv(0)
HDR = chassis() + port() + ttl()


def pdu(*tlvs, hdr=HDR, end=True, dst=NEAREST, etype=0x88cc):
    return eth(dst, SRC, etype, hdr + b''.join(tlvs) + (END if end else b''))


def mgmt(addr_sub=1, addr=bytes((192, 0, 2, 1)), if_sub=2, if_no=7, oid=b''):
    return tlv(8, bytes((1 + len(addr), addr_sub)) + addr + bytes((if_sub,)) + struct.pack('>I', if_no)
               + bytes((len(oid),)) + oid)


def pg_body(w=0x80):
    # PG TLV body of the IEEE 802.1Qaz ETS TLVs: 4 octets of priority nibbles, 8 bandwidth octets
    return bytes.fromhex('01234567') + bytes((10, 10, 10, 10, 20, 20, 10, 10))


def ets_tables():
    return bytes.fromhex('01234567') + bytes((10, 10, 10, 10, 20, 20, 10, 10)) + bytes((0, 0, 1, 1, 2, 2, 255, 255))


def dcbx_sub(t, body):
    return tlv(t, body)


def mk_dcbx():
    frames = []
    ctrl = dcbx_sub(1, bytes((1, 1)) + struct.pack('>II', 5, 4))
    pg = dcbx_sub(2, bytes((1, 1, 0xC0, 0)) + bytes.fromhex('01234567') + bytes((10, 10, 10, 10, 20, 20, 10, 10, 8)))
    pfc = dcbx_sub(3, bytes((1, 1, 0xA0, 0)) + bytes((0xF0, 4)))
    apps = dcbx_sub(4, bytes((1, 1, 0x80, 0)) + struct.pack('>H', 0x8906) + bytes.fromhex('001b21') [:3] + bytes((0x08,))
                    + struct.pack('>H', 3260) + bytes.fromhex('000000') + bytes((0x20,)))
    lld = dcbx_sub(6, bytes((1, 1, 0x80, 0, 1)))
    frames.append(pdu(org(OUI_DCBX, 2, ctrl + pg + pfc + apps)))          # CEE
    frames.append(pdu(org(OUI_DCBX, 1, ctrl + lld)))                      # CIN
    frames.append(pdu(org(OUI_DCBX, 3, b'')))                            # unknown protocol type, no sub TLV
    return frames


def mk_8021():
    f = []
    f.append(pdu(org(OUI_8021, 1, struct.pack('>H', 100))))                      # port VLAN id
    f.append(pdu(org(OUI_8021, 2, bytes((0x03,)) + struct.pack('>H', 200))))     # PPVID supported+enabled
    f.append(pdu(org(OUI_8021, 3, struct.pack('>HB', 300, 5) + b'vlan3')))
    f.append(pdu(org(OUI_8021, 3, struct.pack('>HB', 301, 0))))                  # empty VLAN name
    f.append(pdu(org(OUI_8021, 4, bytes((4,)) + bytes.fromhex('88cc0000'))))     # protocol identity
    f.append(pdu(org(OUI_8021, 4, bytes((0,)))))                                 # length 0
    f.append(pdu(org(OUI_8021, 7, bytes((0x03,)) + struct.pack('>I', 17))))      # link aggregation
    f.append(pdu(org(OUI_8021, 8, bytes((0xA5, 0x5A)))))                         # congestion notification
    f.append(pdu(org(OUI_8021, 9, bytes((0xC3,)) + ets_tables())))               # ETS configuration, 3 TCs
    f.append(pdu(org(OUI_8021, 9, bytes((0x80,)) + ets_tables())))               # 0 = 8 traffic classes
    f.append(pdu(org(OUI_8021, 10, bytes((0,)) + ets_tables())))                 # ETS recommendation
    f.append(pdu(org(OUI_8021, 11, bytes((0xC8, 0x18)))))                         # PFC configuration
    f.append(pdu(org(OUI_8021, 12, bytes((0,)) + bytes((0x35,)) + struct.pack('>H', 3260)
                     + bytes((0xA0,)) + struct.pack('>H', 0x8906))))             # application priority, two entries
    f.append(pdu(org(OUI_8021, 12, bytes((0,)))))                                # application priority, none
    f.append(pdu(org(OUI_8021, 0x0d, b'unknown subtype')))                       # unknown 802.1 subtype (no case)
    return f


def mk_8023():
    f = []
    f.append(pdu(org(OUI_8023, 1, bytes((0x03,)) + struct.pack('>HH', 0x6C01, 0x0010))))   # MAC/PHY
    f.append(pdu(org(OUI_8023, 1, bytes((0x01,)) + struct.pack('>HH', 0x8000, 0x001E))))
    # MDI power support: short (4), with DLL classification (9), with 802.3bt extension (26)
    f.append(pdu(org(OUI_8023, 2, bytes((0xE7, 0x01, 0x03)))))
    for tsrc in (0x00, 0x40, 0x80, 0xC0, 0x30, 0x70, 0xB0, 0xF0, 0x10, 0x50):
        f.append(pdu(org(OUI_8023, 2, bytes((0xE7, 0x01, 0x03, tsrc | 0x08)) + struct.pack('>HH', 150, 130))))
    bt = (struct.pack('>HHHH', 100, 110, 120, 130) + struct.pack('>H', 0xA5C3) + bytes((0x90,))
          + struct.pack('>H', 600) + bytes((0x0E,)) + bytes((0x01, 0x02, 0x03)))
    f.append(pdu(org(OUI_8023, 2, bytes((0xE7, 0x01, 0x03, 0x68)) + struct.pack('>HH', 150, 130) + bt)))
    f.append(pdu(org(OUI_8023, 3, bytes((0x03,)) + struct.pack('>I', 9))))          # deprecated link aggregation (warning)
    f.append(pdu(org(OUI_8023, 4, struct.pack('>H', 1522))))
    f.append(pdu(org(OUI_8023, 5, struct.pack('>HHHHH', 10, 20, 30, 40, 50))))       # EEE
    f.append(pdu(org(OUI_8023, 7, struct.pack('>H', 0x8F2A))))                      # frame preemption
    f.append(pdu(org(OUI_8023, 6, b'')))                                            # unknown subtype
    return f


def loc_coord(lat_res, lat, lon_res, lon, atype, ares, alt, datum, ver=1):
    la = (lat_res << 34) | (lat & ((1 << 34) - 1))
    lo = (lon_res << 34) | (lon & ((1 << 34) - 1))
    al = (atype << 34) | (ares << 30) | (alt & ((1 << 30) - 1))
    return (la.to_bytes(5, 'big') + lo.to_bytes(5, 'big') + al.to_bytes(5, 'big')
            + bytes(((ver << 6) | datum,)))


def neg34(v):
    return (-v) & ((1 << 34) - 1)


def mk_med():
    f = []
    f.append(pdu(org(OUI_MED, 1, struct.pack('>HB', 0x003F, 3))))                    # capabilities, endpoint class III
    f.append(pdu(org(OUI_MED, 2, bytes((1,)) + bytes.fromhex('c0e0a1'))))            # network policy
    f.append(pdu(org(OUI_MED, 2, bytes((6,)) + bytes.fromhex('2a0020'))))
    # location: coordinates, civic address (several types), ECS ELIN, unknown format
    one = 1 << 25                                   # one degree in 34-bit fixed point (25 fractional bits)
    for args in ((20, 37 * one + one // 3, 20, neg34(122 * one + one // 2), 1, 15, 0x000021B3, 2),     # north/west, altitude in meters
                 (34, neg34(33 * one + one // 7), 34, 151 * one, 2, 30, (-300) & 0x3FFFFFFF, 1),       # south/east, altitude in floors, negative altitude
                 (0, 95 * one, 40, 181 * one, 0, 0, 5, 3),                                          # latitude > 90, longitude > 180, warnings
                 (1, 10 * one, 2, neg34(190 * one), 1, 31, 0x3FFFFFFF, 0),                           # west beyond 180
                 (35, 89 * one, 63, 179 * one, 1, 25, 1000, 2)):
        f.append(pdu(org(OUI_MED, 3, bytes((1,)) + loc_coord(*args))))
    civic = bytes((2,)) + b'US'
    civic_items = bytes((1, 2)) + b'CA' + bytes((3, 8)) + b'San Jose' + bytes((6, 0))
    # LCI length covers what, country, items
    body = bytes((2,)) + b'US' + civic_items
    f.append(pdu(org(OUI_MED, 3, bytes((2, len(body))) + body)))
    f.append(pdu(org(OUI_MED, 3, bytes((3,)) + b'+14085551234')))                      # ECS ELIN
    f.append(pdu(org(OUI_MED, 3, bytes((3,)))))                                       # ECS ELIN without data
    f.append(pdu(org(OUI_MED, 3, bytes((9,)) + b'xyz')))                              # unknown format
    f.append(pdu(org(OUI_MED, 4, bytes((0x41,)) + struct.pack('>H', 150))))          # extended power, PD, source 0
    f.append(pdu(org(OUI_MED, 4, bytes((0x01,)) + struct.pack('>H', 150))))          # PSE
    f.append(pdu(org(OUI_MED, 4, bytes((0xC1,)) + struct.pack('>H', 150))))          # reserved type
    for sub, txt in ((5, b'hw rev 1'), (6, b'fw 1.2'), (7, b'sw 3.4'), (8, b'SN123'), (9, b'Acme'), (10, b'M1'), (11, b'asset-9')):
        f.append(pdu(org(OUI_MED, sub, txt)))
    f.append(pdu(org(OUI_MED, 12, b'unknown')))                                      # unknown MED subtype
    return f


def mk_pn():
    f = []
    f.append(pdu(org(OUI_PN, 1, struct.pack('>IIIII', 100, 200, 300, 400, 500))))     # delay
    f.append(pdu(org(OUI_PN, 1, struct.pack('>IIIII', 0, 0, 0, 0, 0))))               # all unknown
    f.append(pdu(org(OUI_PN, 2, struct.pack('>HH', 0x0001, 0x8010))))
    f.append(pdu(org(OUI_PN, 4, bytes(range(16)) + struct.pack('>H', 2))))
    f.append(pdu(org(OUI_PN, 5, MAC6)))
    per = struct.pack('>I', 0x80000000 | 31250)
    f.append(pdu(org(OUI_PN, 6, MAC6 + bytes(16) + bytes(range(16)) + per + struct.pack('>I', 1000) + struct.pack('>I', 0x80000000 | 2000) + struct.pack('>I', 3000))))
    f.append(pdu(org(OUI_PN, 8, struct.pack('>HHH', 1, 2, 3))))
    f.append(pdu(org(OUI_PN, 9, bytes(range(16)))))
    f.append(pdu(org(OUI_PN, 10, bytes((5, 1)) + bytes((10, 0, 0, 1)))))
    f.append(pdu(org(OUI_PN, 11, bytes(range(16)))))
    f.append(pdu(org(OUI_PN, 12, bytes(range(16)))))
    f.append(pdu(org(OUI_PN, 13, struct.pack('>H', 3) + bytes(range(16)) + bytes(range(8)))))
    pn5 = org(OUI_PN, 5, MAC6)
    f.append(pdu(pn5, hdr=chassis(7, b'station-1') + port(7, b'port-001') + ttl()))              # PROFINET column info: NoS from the chassis ID
    f.append(pdu(pn5, hdr=chassis() + port(7, b'port-002.nos-name') + ttl()))                  # port ID with the name of station
    f.append(pdu(pn5, hdr=chassis() + port(3, MAC6) + ttl()))                                  # NoS from the chassis MAC, no port ID
    f.append(pdu(pn5, hdr=chassis(1, b'comp') + port(1, b'alias') + ttl()))                     # neither is locally assigned
    f.append(pdu(org(OUI_PN, 7, b'unknown')))
    f.append(pdu(org(OUI_PN, 3, b'alias')))
    return f


def mk_cisco():
    f = []
    f.append(pdu(org(OUI_CISCO, 1, bytes((0x0F,)))))                          # UPOE
    f.append(pdu(org(OUI_CISCO, 0xc9, bytes((1,)))))
    f.append(pdu(org(OUI_CISCO, 0xca, bytes((3,)))))
    f.append(pdu(org(OUI_CISCO, 0xcb, struct.pack('>I', 101))))
    f.append(pdu(org(OUI_CISCO, 0xcc, bytes((2,)))))
    f.append(pdu(org(OUI_CISCO, 0xcd, struct.pack('>H', 1))))
    f.append(pdu(org(OUI_CISCO, 0xce, b'fabric1')))
    apic = bytes((1,)) + bytes((10, 0, 0, 1)) + b'0123456789abcdef0123456789abcdef0123'
    apic2 = bytes((2,)) + bytes((10, 0, 0, 2)) + b'fedcba9876543210fedcba9876543210fedc'
    f.append(pdu(org(OUI_CISCO, 0xcf, apic + apic2)))
    f.append(pdu(org(OUI_CISCO, 0xcf, apic + b'ab')))                          # trailing bytes after the entry
    f.append(pdu(org(OUI_CISCO, 0xd0, bytes((10, 0, 0, 5)))))
    f.append(pdu(org(OUI_CISCO, 0xd1, bytes((1,)))))
    f.append(pdu(org(OUI_CISCO, 0xd2, b'n9000-12.0')))
    f.append(pdu(org(OUI_CISCO, 0xd3, struct.pack('>H', 3967))))
    f.append(pdu(org(OUI_CISCO, 0xd4, b'FDO12345')))
    f.append(pdu(org(OUI_CISCO, 0xd6, b'N9K-C9336')))
    f.append(pdu(org(OUI_CISCO, 0xd7, b'leaf101')))
    f.append(pdu(org(OUI_CISCO, 0xd8, struct.pack('>H', 2))))
    f.append(pdu(org(OUI_CISCO, 0xd9, b'\x01\x02\x03\x04')))
    f.append(pdu(org(OUI_CISCO, 0xda, bytes((1,)))))
    f.append(pdu(org(OUI_CISCO, 0xdb, struct.pack('>H', 1))))
    f.append(pdu(org(OUI_CISCO, 0xc9, bytes((1, 2, 3)))))                      # trailing bytes after a fixed field
    f.append(pdu(org(OUI_CISCO, 0x77, b'unknown cisco subtype')))
    f.append(pdu(org(OUI_CISCO, 0x77, b'')))                                   # unknown, no data
    return f


def mk_qbg():
    f = []
    f.append(pdu(org(OUI_QBG, 0, struct.pack('>HHHH', 0x0A00 | 0x0B, 0x0B0A, 100, 90) + bytes((0x15,)))))
    f.append(pdu(org(OUI_QBG, 1, b'cdcp')))
    return f


def mk_avaya():
    f = []
    f.append(pdu(org(OUI_AVX, 11, bytes(32) + bytes.fromhex('0a40f0') + bytes((0,)) + bytes(range(10)))))
    f.append(pdu(org(OUI_AVX, 12, bytes(32) + struct.pack('>H', 0x1064) + bytes.fromhex('000100') + struct.pack('>H', 0x2065) + bytes.fromhex('000200'))))
    f.append(pdu(org(OUI_AVX, 12, bytes(32))))                                 # assignment without entries
    f.append(pdu(org(OUI_AVX, 13, b'unknown')))
    f.append(pdu(org(OUI_AVX2, 4, bytes((1, 2)) + struct.pack('>HH', 4000, 4001) + bytes((6,)) + bytes(range(6)))))
    f.append(pdu(org(OUI_AVX2, 4, bytes((1, 0, 0)))))
    f.append(pdu(org(OUI_AVX2, 5, b'unknown')))
    f.append(pdu(org(OUI_AVAYA, 1, bytes(7))))
    f.append(pdu(org(OUI_AVAYA, 3, bytes((10, 0, 0, 3)))))
    f.append(pdu(org(OUI_AVAYA, 4, bytes((10, 0, 0, 4, 255, 255, 255, 0, 10, 0, 0, 1)))))
    f.append(pdu(org(OUI_AVAYA, 5, bytes((10, 0, 0, 5)))))
    f.append(pdu(org(OUI_AVAYA, 6, bytes((10, 0, 0, 6)))))
    f.append(pdu(org(OUI_AVAYA, 7, bytes((1,)))))
    f.append(pdu(org(OUI_AVAYA, 8, b'unknown')))
    return f


def hy(group, ident, data=b''):
    return bytes(((group << 5) | ident,)) + data


def mk_hytec():
    f = []
    T, R = 1, 2
    f.append(pdu(org(OUI_HYTEC, T, hy(1, 1, b'ACME SFP-1G rev A'))))
    f.append(pdu(org(OUI_HYTEC, T, hy(1, 9, b'x'))))                              # unknown identifier
    for ident in (1, 2, 3):
        f.append(pdu(org(OUI_HYTEC, T, hy(2, ident, struct.pack('>I', 10000)))))
    f.append(pdu(org(OUI_HYTEC, T, hy(2, 9, b'x'))))
    for ident, val in ((1, 123), (2, -234), (3, 0x0A80), (3, -0x0A80), (4, 0x0140), (4, -0x0141)):
        f.append(pdu(org(OUI_HYTEC, T, hy(3, ident, struct.pack('>i', val)))))
    f.append(pdu(org(OUI_HYTEC, T, hy(3, 9, b'x'))))
    f.append(pdu(org(OUI_HYTEC, T, hy(4, 1, b'x'))))                              # unknown group
    mac2 = bytes.fromhex('020000000002')
    f.append(pdu(org(OUI_HYTEC, R, hy(1, 1, MAC6 + mac2 + bytes((8,))))))
    f.append(pdu(org(OUI_HYTEC, R, hy(1, 2, MAC6 + mac2 + bytes((2,))))))
    f.append(pdu(org(OUI_HYTEC, R, hy(1, 3, b'switch-a'))))
    f.append(pdu(org(OUI_HYTEC, R, hy(1, 4, b'port-3'))))
    f.append(pdu(org(OUI_HYTEC, R, hy(1, 5, bytes((192, 0, 2, 7))))))
    f.append(pdu(org(OUI_HYTEC, R, hy(1, 6, bytes((1,))))))
    f.append(pdu(org(OUI_HYTEC, R, hy(1, 7, bytes(range(16))))))
    f.append(pdu(org(OUI_HYTEC, R, hy(1, 8, b'port-4'))))
    f.append(pdu(org(OUI_HYTEC, R, hy(1, 9, struct.pack('>I', 77)))))
    f.append(pdu(org(OUI_HYTEC, R, hy(1, 10, b'x'))))                             # unknown identifier
    f.append(pdu(org(OUI_HYTEC, R, hy(3, 1, b'x'))))                              # unknown group
    f.append(pdu(org(OUI_HYTEC, 3, hy(1, 1, b'x'))))                              # unknown subtype
    return f


def mk_misc():
    f = []
    f.append(pdu(org(OUI_IANA, 1, b'https://mud.example.net/dev.json')))
    f.append(pdu(org(OUI_IANA, 1, b'')))                                         # MUD URL, empty
    f.append(pdu(org(OUI_IANA, 2, b'unknown iana')))
    f.append(pdu(org(OUI_IANA, 3, struct.pack('>I', 1))))                         # same value as the ONOS TTL subtype: length 4 is fine
    # ONOS: Ethertype 0x88cc and the ONOS Ethertype 0x8942
    f.append(pdu(org(OUI_ONOS, 1, b'of:0000000000000001')))
    f.append(pdu(org(OUI_ONOS, 2, b'7')))
    f.append(pdu(org(OUI_ONOS, 3, struct.pack('>I', 1700000000))))
    f.append(pdu(org(OUI_ONOS, 4, b'unknown onos')))
    f.append(pdu(org(OUI_ONOS, 1, b'of:0000000000000002'), hdr=chassis(7, b'of:2') + port(5, b'3') + ttl(120), etype=0x8942))
    f.append(pdu(org(OUI_ODVA, 1, bytes(range(1, 21)))))                          # CIP (handled in packet-enip.c)
    f.append(pdu(org('123456', 9, b'unknown oui data')))                          # default OUI handler
    f.append(pdu(org('123456', 9, b'')))                                          # no data after the subtype
    return f


def main(out, verbose=False):
    p = Pcap()
    marks = []

    def mark(name):
        marks.append((len(p.frames) + 1, name))

    def add(d, orig=None):
        p.add(d, orig)

    def addall(lst):
        for d in lst:
            add(d)

    # ---- mandatory TLVs
    mark('Chassis ID subtypes 1-7 and a reserved one; network address IPv4, IPv6 and another family')
    for sub, data in ((1, b'chassis-comp'), (2, b'eth0-alias'), (3, bytes((1, 2, 3, 4))), (6, b'eth0'), (7, b'locally-assigned-1'),
                      (0, b'reserved'), (9, b'reserved9')):
        add(pdu(hdr=chassis(sub, data) + port() + ttl()))
    add(pdu(hdr=chassis(4, MAC6) + port() + ttl()))
    add(pdu(hdr=chassis(5, bytes((1,)) + bytes((192, 0, 2, 1))) + port() + ttl()))
    add(pdu(hdr=chassis(5, bytes((2,)) + bytes(range(1, 17))) + port() + ttl()))
    add(pdu(hdr=chassis(5, bytes((6,)) + bytes(range(1, 9))) + port() + ttl()))
    mark('Port ID subtypes 1-7 and a reserved one; MAC, network address IPv4, IPv6 and another family')
    for sub, data in ((1, b'port-alias'), (2, bytes((1, 2))), (5, b'Gi1/0/1'), (6, b'circuit-7'), (7, b'port-001.nos-name'),
                      (7, b'port-002'), (0, b'zero'), (9, b'nine')):
        add(pdu(hdr=chassis() + port(sub, data) + ttl()))
    add(pdu(hdr=chassis() + port(3, MAC6) + ttl()))
    add(pdu(hdr=chassis() + port(4, bytes((1,)) + bytes((192, 0, 2, 9))) + ttl()))
    add(pdu(hdr=chassis() + port(4, bytes((2,)) + bytes(range(1, 17))) + ttl()))
    add(pdu(hdr=chassis() + port(4, bytes((6,)) + bytes(range(1, 9))) + ttl()))
    mark('Time To Live: normal, shutdown (TTL 0, with and without End of LLDPDU), a TLV with length 4 (fixed)')
    add(pdu())
    add(pdu(hdr=chassis() + port() + ttl(0)))
    add(pdu(hdr=chassis() + port() + ttl(0), end=False))
    add(pdu(hdr=chassis() + port() + tlv(3, b'\x00\x78\x00\x00'), end=False) + tlv(5, b'abc') + END)   # reproducer 1
    # ---- optional TLVs
    mark('Optional TLVs: port description, system name and description, capabilities (every bit), management addresses')
    add(pdu(tlv(4, b'uplink to core'), tlv(5, b'switch-1'), tlv(6, b'Acme Switch OS 1.0 (long description)')))
    add(pdu(tlv(4, b''), tlv(5, b''), tlv(6, b'')))
    for caps, en in ((0x0001, 0x0001), (0x0004, 0x0004), (0x0014, 0x0004), (0x01FF, 0x0100), (0x0FFF, 0x0A5A), (0xFFFF, 0xFFFF), (0, 0)):
        add(pdu(tlv(7, struct.pack('>HH', caps, en))))
    add(pdu(mgmt(1, bytes((192, 0, 2, 1)), 2, 7)))
    add(pdu(mgmt(2, bytes(range(1, 17)), 3, 1, bytes((1, 3, 6, 1)))))
    add(pdu(mgmt(6, bytes((1, 2, 3, 4, 5, 6)), 1, 0)))                               # other address family, hex
    add(pdu(mgmt(1, bytes((192, 0, 2, 2)), 2, 8, bytes((1, 3, 6, 1, 4, 1, 99)))))
    # ---- organizationally specific TLVs
    mark('DCBX (CEE and CIN control, priority groups, PFC, application and logical link down TLVs)')
    addall(mk_dcbx())
    mark('IEEE 802.1 TLVs (VLAN, PPVID, VLAN name, protocol identity, link aggregation, 802.1Qau, 802.1Qaz)')
    addall(mk_8021())
    mark('IEEE 802.3 TLVs (MAC/PHY, power via MDI with 802.3bt, aggregation, frame size, EEE, preemption)')
    addall(mk_8023())
    mark('LLDP-MED TLVs (capabilities, policy, location, extended power, inventory)')
    addall(mk_med())
    mark('PROFINET TLVs')
    addall(mk_pn())
    mark('Cisco UPOE and ACI TLVs')
    addall(mk_cisco())
    mark('IEEE 802.1Qbg, Extreme/Avaya, Avaya TLVs')
    addall(mk_qbg())
    addall(mk_avaya())
    mark('Hytec transceiver and MAC trace TLVs')
    addall(mk_hytec())
    mark('IANA, ONOS (also on Ethertype 0x8942), ODVA and unknown OUI TLVs')
    addall(mk_misc())
    mark('Unknown TLV types (not consumed unless "assume unrecognized TLV" is set), several TLVs per frame')
    add(pdu(tlv(5, b'sw'), tlv(9, b'unknown tlv type 9'), tlv(5, b'after')))
    add(pdu(tlv(126, b'type 126')))
    # With the preference set, an unknown TLV is only consumed when type and length (as a
    # 16 bit number) do not exceed the bytes left in the frame: a jumbo frame
    add(pdu(tlv(9, b'unknown tlv type 9'), tlv(5, b'after')) + bytes(5000))
    add(pdu(tlv(4, b'desc'), tlv(5, b'sys'), tlv(6, b'sysdesc'), tlv(7, struct.pack('>HH', 0x14, 0x4)), mgmt(),
            org(OUI_8021, 1, struct.pack('>H', 1)), org(OUI_8023, 4, struct.pack('>H', 9000)),
            org(OUI_PN, 5, MAC6), org(OUI_8021, 3, struct.pack('>HB', 10, 4) + b'mgmt')))
    p.write(os.path.join(out, 'lldp-coverage.pcap'))
    if verbose:
        for i, (n, name) in enumerate(marks):
            end = marks[i + 1][0] - 1 if i + 1 < len(marks) else len(p.frames)
            print('%d-%d: %s' % (n, end, name))
        print('total', len(p.frames))

    # ------------------------------------------------------------------ malformed
    m = Pcap()
    M = m.add
    # chassis ID errors
    M(pdu(hdr=tlv(2, b'\x07port') + ttl()))                                        # first TLV is not a chassis ID
    M(pdu(hdr=tlv(1, b'\x04') + port() + ttl()))                                   # MAC chassis ID with wrong length
    M(pdu(hdr=tlv(1, b'\x07') + port() + ttl()))                                   # chassis ID length 1 (subtype only)
    M(pdu(hdr=tlv(1, b'\x04\x01\x02\x03\x04') + port() + ttl()))                   # MAC chassis ID, 4 octets
    M(pdu(hdr=tlv(1, b'\x05\x01\xc0\x00\x02') + port() + ttl()))                   # IPv4 with a bad length
    M(pdu(hdr=tlv(1, b'\x05\x02\xc0\x00\x02\x01') + port() + ttl()))               # IPv6 with a bad length
    M(pdu(hdr=tlv(1, b'\x07' + b'a' * 300) + port() + ttl()))                      # too long
    # port ID errors
    M(pdu(hdr=chassis() + tlv(1, b'\x07x') + ttl()))                               # second TLV is not a port ID
    M(pdu(hdr=chassis() + tlv(2, b'\x03\x01') + ttl()))                            # MAC port ID with a bad length
    M(pdu(hdr=chassis() + tlv(2, b'\x07') + ttl()))                                # port ID length 1 (subtype only)
    M(pdu(hdr=chassis() + tlv(2, b'\x04\x01\xc0\x00') + ttl()))                    # IPv4 with a bad length
    M(pdu(hdr=chassis() + tlv(2, b'\x04\x02\xc0\x00') + ttl()))                    # IPv6 with a bad length
    M(pdu(hdr=chassis() + tlv(2, b'\x07' + b'p' * 300) + ttl()))                   # too long
    # TTL errors
    M(pdu(hdr=chassis() + port() + tlv(4, b'x')))                                  # third TLV is not a TTL
    M(pdu(hdr=chassis() + port() + tlv(3, b'\x00')))                               # TTL of one octet
    M(pdu(tlv(5, b'abc'), hdr=chassis() + port() + ttl(0)))                        # shutdown PDU with an excess TLV
    M(pdu(tlv(4, b'x'), tlv(5, b'y'), hdr=chassis() + port() + ttl(0)))
    # duplicate mandatory TLVs
    M(pdu(chassis(), hdr=HDR))
    M(pdu(port(), hdr=HDR))
    M(pdu(ttl(), hdr=HDR))
    # End of LLDPDU with a length
    M(pdu(tlv(0, b'\x00\x00'), end=False))
    # management address string length 0 (reproducer 2): offset used to go backwards
    mg = b'\x00' + b'\x05' + b'\x02' + b'\x00\x00\x00\x01' + b'\x00'
    M(pdu(tlv(8, mg), tlv(5, b'abc')))
    # truncated mandatory TLVs
    M(eth(NEAREST, SRC, 0x88cc, chassis()[:3]))
    M(eth(NEAREST, SRC, 0x88cc, chassis() + port()[:3]))
    M(eth(NEAREST, SRC, 0x88cc, chassis() + port() + ttl()[:3]))
    M(eth(NEAREST, SRC, 0x88cc, HDR + tlv_len(5, 20, b'abc')))                    # system name longer than the frame
    M(eth(NEAREST, SRC, 0x88cc, HDR + tlv_len(7, 4, b'\x00\x14')))                 # capabilities cut short
    M(eth(NEAREST, SRC, 0x88cc, HDR + tlv_len(8, 12, b'\x05\x01\xc0\x00\x02\x01\x02')))   # management address cut short
    M(eth(NEAREST, SRC, 0x88cc, HDR + tlv(8, b'\x05\x01\xc0\x00\x02\x01\x02\x00\x00\x00\x07\x05')))   # OID longer than the TLV
    # organizationally specific TLVs
    M(pdu(tlv(127, b'\x00\x80\xc2')))                                             # length below 4
    M(pdu(tlv(127, b'\x00\x80')))
    M(pdu(org(OUI_8021, 1, b'\x00')))                                              # port VLAN ID cut short
    M(pdu(org(OUI_8021, 3, struct.pack('>HB', 5, 9) + b'ab')))                     # VLAN name longer than the TLV
    M(pdu(org(OUI_8021, 4, bytes((9,)) + b'ab')))
    M(pdu(org(OUI_8021, 9, bytes((0xC3,)) + ets_tables()[:10])))
    M(pdu(org(OUI_8023, 1, b'\x03\x6c')))
    M(pdu(org(OUI_8023, 2, bytes((0xE7, 0x01)))))                                  # MDI power cut short
    M(pdu(org(OUI_8023, 2, bytes((0xE7, 0x01, 0x03, 0x68, 0, 150)))))
    M(pdu(org(OUI_8023, 4, struct.pack('>HH', 1522, 0))))                           # excess length
    M(pdu(org(OUI_8023, 6, b'x')))
    M(pdu(org(OUI_8023, 7, b'\x8f')))
    # LLDP-MED length errors
    M(pdu(org(OUI_MED, 1, b'\x00')))
    M(pdu(org(OUI_MED, 1, b'\x00\x3f')))                                           # no class
    M(pdu(org(OUI_MED, 2, b'')))
    M(pdu(org(OUI_MED, 2, b'\x01\xc0')))
    M(pdu(org(OUI_MED, 3, b'')))
    M(pdu(org(OUI_MED, 3, bytes((1,)) + bytes(10))))                               # coordinates cut short
    M(pdu(org(OUI_MED, 3, bytes((2,)))))                                           # civic, no length
    M(pdu(org(OUI_MED, 3, bytes((2, 50)) + b'U')))                                 # civic length beyond the TLV
    M(pdu(org(OUI_MED, 3, bytes((2, 0)))))                                         # LCI length 0
    M(pdu(org(OUI_MED, 3, bytes((2, 1, 2)))))                                      # no country
    M(pdu(org(OUI_MED, 3, bytes((2, 3, 2)) + b'U')))                               # LCI length 3: what + 1 country octet
    M(pdu(org(OUI_MED, 3, bytes((2, 4, 2)) + b'US' + bytes((1,)))))                # address type without length
    M(pdu(org(OUI_MED, 3, bytes((2, 7, 2)) + b'US' + bytes((1, 9, 0, 0, 0)))))     # address longer than the LCI
    M(pdu(org(OUI_MED, 3, bytes((2, 9, 2)) + b'US' + bytes((1, 0, 2, 2)) + b'A')))
    # Cisco ACI fixed size fields cut short (fixed)
    M(pdu(org(OUI_CISCO, 0xc9, b'')))
    M(pdu(org(OUI_CISCO, 0xcb, b'\x00\x01')))
    M(pdu(org(OUI_CISCO, 0xd8, b'\x01')))
    # Hytec wrong lengths
    T, R = 1, 2
    M(pdu(org(OUI_HYTEC, T, hy(1, 1, b''))))
    M(pdu(org(OUI_HYTEC, T, hy(1, 1, b'x' * 70))))
    for g, i in ((2, 1), (2, 2), (2, 3), (3, 1), (3, 2), (3, 3), (3, 4)):
        M(pdu(org(OUI_HYTEC, T, hy(g, i, b'xy'))))
    M(pdu(org(OUI_HYTEC, T, hy(2, 1, b''))))
    for i, n in ((1, 5), (2, 5), (5, 3), (6, 2), (7, 4), (9, 2)):
        M(pdu(org(OUI_HYTEC, R, hy(1, i, bytes(n)))))
    for i in (3, 4, 8):
        M(pdu(org(OUI_HYTEC, R, hy(1, i, b''))))
        M(pdu(org(OUI_HYTEC, R, hy(1, i, b'x' * 70))))
    # ONOS and IANA TTL with a wrong length (fixed)
    M(pdu(org(OUI_ONOS, 3, b'\x00\x01')))
    M(pdu(org(OUI_IANA, 3, b'\x00\x01')))
    # DCBX with an unknown sub-TLV (reproducer 3)
    sub_unknown = tlv(5, b'\x00\x00')
    sub_control = tlv(1, b'\x00\x00' + b'\x11\x11\x11\x11' + b'\x22\x22\x22\x22')
    M(pdu(org(OUI_DCBX, 2, sub_unknown + sub_control)))
    M(pdu(org(OUI_DCBX, 2, tlv(1, b'\x01\x01\x00\x00'))))                          # DCBX control cut short
    M(pdu(org(OUI_DCBX, 2, tlv(4, b'\x01\x01\x80\x00\x88'))))                     # DCBX application cut short
    # TLV lengths longer than the frame
    M(eth(NEAREST, SRC, 0x88cc, HDR + tlv_len(127, 40, bytes.fromhex(OUI_8021) + b'\x01\x00')))
    M(eth(NEAREST, SRC, 0x88cc, HDR + tlv_len(4, 200, b'port')))
    m.write(os.path.join(out, 'lldp-coverage-malformed.pcap'))


if __name__ == '__main__':
    main(sys.argv[1], '-v' in sys.argv)
