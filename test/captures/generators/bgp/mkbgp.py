#!/usr/bin/env python3
# Generates test/captures/bgp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the BGP dissector (packet-bgp.c).

BGP over TCP port 179. Every packet is built from scratch with struct;
addresses are from the documentation ranges (192.0.2.0/24, 198.51.100.0/24,
203.0.113.0/24, 2001:db8::/32) and private AS numbers. No captured traffic is
used.

Usage: mkbgp.py <output directory>

Writes:
  bgp-coverage.pcap            the main capture (no malformed packets, no
                               error expert infos; identical with -2)
  bgp-coverage-malformed.pcap  paths only malformed input reaches
  bgp-coverage-index.txt       one line per frame of the main capture
"""

import os
import struct
import sys

# ---------------------------------------------------------------------------
# Link, IP and TCP

def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def ip4(s):
    return bytes(int(x) for x in s.split('.'))


def ip6(s):
    import ipaddress
    return ipaddress.IPv6Address(s).packed


class Stream:
    """One direction of a TCP connection; keeps the sequence number."""
    def __init__(self, src, dst, sport, dport, seq):
        self.src, self.dst, self.sport, self.dport = ip4(src), ip4(dst), sport, dport
        self.seq = seq

    def segment(self, payload):
        tcp = struct.pack('>HHIIBBHHH', self.sport, self.dport, self.seq, 1,
                          0x50, 0x18, 65535, 0, 0)
        ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0xc0, 20 + len(tcp) + len(payload),
                         1, 0x4000, 64, 6, 0, self.src, self.dst)
        ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
        pseudo = self.src + self.dst + struct.pack('>BBH', 0, 6, len(tcp) + len(payload))
        c = csum(pseudo + tcp + payload)
        tcp = tcp[:16] + struct.pack('>H', c) + tcp[18:]
        eth = bytes.fromhex('020000000002') + bytes.fromhex('020000000001') + b'\x08\x00'
        self.seq = (self.seq + len(payload)) & 0xffffffff
        return eth + ip + tcp + payload


def write_pcap(path, frames):
    """frames: list of (frame, captured length or None)"""
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, (fr, caplen) in enumerate(frames):
            cl = len(fr) if caplen is None else caplen
            f.write(struct.pack('<IIII', 1700000000 + i, (i * 1000) % 1000000, cl, len(fr)))
            f.write(fr[:cl])

# ---------------------------------------------------------------------------
# BGP building blocks

MARKER = b'\xff' * 16


def msg(mtype, body, length=None):
    return MARKER + struct.pack('>HB', 19 + len(body) if length is None else length, mtype) + body


def attr(flags, atype, value):
    if len(value) > 255 or flags & 0x10:
        return struct.pack('>BBH', flags | 0x10, atype, len(value)) + value
    return struct.pack('>BBB', flags, atype, len(value)) + value


def update(attrs=b'', nlri=b'', withdrawn=b''):
    body = struct.pack('>H', len(withdrawn)) + withdrawn
    body += struct.pack('>H', len(attrs)) + attrs + nlri
    return msg(2, body)


def mp_reach(afi, safi, nh, nlri, snpa=b'\x00'):
    return attr(0x90, 14, struct.pack('>HBB', afi, safi, len(nh)) + nh + snpa + nlri)


def mp_unreach(afi, safi, nlri):
    return attr(0x90, 15, struct.pack('>HB', afi, safi) + nlri)


def pfx4(plen, addr):
    return bytes([plen]) + ip4(addr)[:(plen + 7) // 8]


def pfx6(plen, addr):
    return bytes([plen]) + ip6(addr)[:(plen + 7) // 8]


def rd0(asn, num):
    return struct.pack('>HHI', 0, asn, num)


def rd1(ip, num):
    return struct.pack('>H4sH', 1, ip4(ip), num)


def rd2(asn, num):
    return struct.pack('>HIH', 2, asn, num)


def label(value, bos=1):
    return struct.pack('>I', (value << 4) | bos)[1:]


def tlv(t, v):
    """BGP-LS TLV: 2 octet type and length."""
    return struct.pack('>HH', t, len(v)) + v


ORIGIN_IGP = attr(0x40, 1, b'\x00')
ORIGIN_EGP = attr(0x40, 1, b'\x01')
ORIGIN_INC = attr(0x40, 1, b'\x02')
NH = ip4('192.0.2.1')
NH6 = ip6('2001:db8::1')
NH_ATTR = attr(0x40, 3, NH)
AFI_IP, AFI_IP6, AFI_L2VPN, AFI_L2VPN_OLD, AFI_LS = 1, 2, 25, 196, 16388


def aspath(segments, asn_len=2, atype=2):
    """segments: list of (segment type, [ASNs])"""
    v = b''
    for st, asns in segments:
        v += bytes([st, len(asns)])
        for a in asns:
            v += struct.pack('>H' if asn_len == 2 else '>I', a)
    return attr(0x40 if atype == 2 else 0xc0, atype, v)


def ext_com(*coms):
    return attr(0xc0, 16, b''.join(coms))


def ec(t, st, rest):
    assert len(rest) == 6
    return bytes([t, st]) + rest

# ---------------------------------------------------------------------------
# Main capture

main = []          # (label, payload, stream)
index = []

C2S = Stream('192.0.2.1', '192.0.2.2', 40000, 179, 1000)
S2C = Stream('192.0.2.2', '192.0.2.1', 179, 40000, 5000)


def add(label_, payload, stream=None):
    main.append((label_, payload, stream or C2S))


def cap(t, v=b''):
    return bytes([t, len(v)]) + v


def param(t, v):
    return bytes([t, len(v)]) + v


def open_msg(params, myas=65001, hold=90, ident='192.0.2.1', optlen=None):
    p = b''.join(params)
    return msg(1, struct.pack('>BHH4sB', 4, myas, hold, ip4(ident),
                              len(p) if optlen is None else optlen) + p)


# --- OPEN ------------------------------------------------------------------
orf_cap = struct.pack('>HBBB', 1, 0, 1, 2) + bytes([0x40, 3, 0x80, 1])
caps1 = [
    cap(1, struct.pack('>HBB', AFI_IP, 0, 1)),
    cap(1, struct.pack('>HBB', AFI_IP6, 0, 1)),
    cap(1, struct.pack('>HBB', AFI_L2VPN, 0, 70)),
    cap(1, struct.pack('>HBB', AFI_LS, 0, 71)),
    cap(2), cap(128), cap(70), cap(72), cap(74), cap(77), cap(0),
    cap(3, orf_cap), cap(130, orf_cap),
    cap(5, struct.pack('>HHH', 1, 1, 2) + struct.pack('>HHH', 1, 128, 2)),
    cap(6),
]
caps2 = [
    cap(7, bytes([0x08]) + struct.pack('>H', 1)),
    cap(8, bytes([0, 1, 1, 2])),
    cap(9, b'\x02'),
    cap(64, struct.pack('>H', 0xc078) + struct.pack('>HBB', 1, 1, 0x80) + struct.pack('>HBB', 2, 1, 0)),
    cap(65, struct.pack('>I', 4200000001)),
    cap(66),
    cap(67, bytes([2, 64, 65, 69])),
    cap(69, struct.pack('>HBB', 1, 1, 3) + struct.pack('>HBB', 2, 1, 1) + struct.pack('>HBB', 25, 70, 2)),
    cap(71, struct.pack('>HBBBH', 1, 1, 0x80, 0, 3600)),
    cap(73, bytes([4]) + b'rtr1' + bytes([11]) + b'example.net'),
    cap(75, bytes([20]) + b'SyntheticBGP 1.0 x86'),
    cap(76, struct.pack('>HBH', 1, 1, 100)),
    cap(131, b'\x00'),
    cap(200, b'\x01\x02\x03'),
]
add('OPEN: every capability, authentication and an AS_TRANS AS',
    open_msg([param(1, b'\x01secret'),
              param(2, b''.join(caps1)),
              param(2, b''.join(caps2))], myas=23456))
add('OPEN: graceful restart in helper mode only, from the peer',
    open_msg([param(2, cap(64, struct.pack('>H', 0x0078)) + cap(65, struct.pack('>I', 65002)))],
             myas=65002, ident='192.0.2.2'), S2C)
# Reproducer bgp_small_fixes.py frame 4: unknown parameter type 3
unk = bytes([3, 4, 2, 2, 0x41, 0x00])
add('OPEN: unknown optional parameter type 3 (reproducer, stepped over)',
    open_msg([unk, param(2, cap(1, struct.pack('>HBB', 1, 0, 1)))]))
# RFC 9072 extended optional parameters length (as the dissector reads it:
# one octet parameter lengths after the extended header)
ext_params = param(2, cap(1, struct.pack('>HBB', 1, 0, 1)) + cap(65, struct.pack('>I', 65001)))
add('OPEN: extended optional parameters length (RFC 9072 header)',
    msg(1, struct.pack('>BHH4sB', 4, 65001, 180, ip4('192.0.2.1'), 255) +
        bytes([255]) + struct.pack('>H', len(ext_params)) + ext_params))
add('KEEPALIVE', msg(4, b''))

# --- NOTIFICATION ----------------------------------------------------------
def notif(major, minor, data=b''):
    return msg(3, bytes([major, minor]) + data)

add('NOTIFICATION: message header error, bad length with data', notif(1, 2, b'\x00\x13'))
add('NOTIFICATION: OPEN error, bad peer AS', notif(2, 2, struct.pack('>H', 65099)))
add('NOTIFICATION: OPEN error, unsupported capability (capability list)',
    notif(2, 7, cap(69, struct.pack('>HBB', 1, 1, 1)) + cap(73, bytes([1]) + b'r' + bytes([0]))))
add('NOTIFICATION: OPEN error, unsupported optional parameter', notif(2, 4))
add('NOTIFICATION: UPDATE error, malformed attribute list', notif(3, 1))
add('NOTIFICATION: hold timer expired', notif(4, 0))
add('NOTIFICATION: finite state machine error', notif(5, 1))
add('NOTIFICATION: cease, administrative shutdown with a communication',
    notif(6, 2, bytes([11]) + b'maintenance'))
add('NOTIFICATION: cease, administrative reset with a communication',
    notif(6, 4, bytes([6]) + b'reboot'))
add('NOTIFICATION: cease, administrative shutdown with other data',
    notif(6, 2, bytes([40]) + b'abc'))
add('NOTIFICATION: cease, hard reset with data', notif(6, 9, b'\x06\x02'))
add('NOTIFICATION: ROUTE-REFRESH error, invalid length', notif(7, 1))
add('NOTIFICATION: send hold timer expired (major code 8, unknown to the dissector)', notif(8, 0))

# --- ROUTE-REFRESH ---------------------------------------------------------
def rr(afi, subtype, safi, orfs=b'', mtype=5):
    return msg(mtype, struct.pack('>HBB', afi, subtype, safi) + orfs)


def orf(when, otype, entries):
    return bytes([when, otype]) + struct.pack('>H', len(entries)) + entries


def orf_prefix(action, match, seq, ge, le, plen, addr):
    return bytes([(action << 6) | (match << 5)]) + struct.pack('>I', seq) + bytes([ge, le]) + pfx4(plen, addr)

add('ROUTE-REFRESH: IPv4 unicast', rr(1, 0, 1))
add('ROUTE-REFRESH: begin of route refresh (subtype 1)', rr(2, 1, 1))
add('ROUTE-REFRESH: end of route refresh (subtype 2)', rr(1, 2, 128))
add('ROUTE-REFRESH: address prefix ORF entries (add/remove/remove-all, permit/deny)',
    rr(1, 0, 1, orf(1, 0x40, orf_prefix(0, 0, 5, 18, 24, 16, '198.51.0.0') +
                              orf_prefix(0, 1, 10, 0, 0, 24, '203.0.113.0') +
                              orf_prefix(1, 0, 5, 18, 24, 16, '198.51.0.0') +
                              bytes([0x80])) +
                orf(2, 0x80, orf_prefix(0, 0, 1, 25, 32, 24, '192.0.2.0'))))
add('ROUTE-REFRESH: CP-ORF and unknown ORF type (warnings)',
    rr(1, 0, 1, orf(1, 0x41, b'\x00\x01\x02\x03') + orf(1, 0x99, b'\xaa\xbb')))
add('ROUTE-REFRESH: Cisco message type 128', rr(1, 0, 1, mtype=0x80))

# --- CAPABILITY message ----------------------------------------------------
def dcap(t, action, v=b''):
    return bytes([t, len(v), action]) + v

add('CAPABILITY: dynamic capability advertisement',
    msg(6, dcap(1, 0, struct.pack('>HBB', 2, 0, 128)) + dcap(2, 1) +
        dcap(69, 0, struct.pack('>HBB', 1, 1, 3))))
add('Unknown message type 7', msg(7, b'\x01\x02\x03\x04'))

# --- UPDATE: basic attributes ----------------------------------------------
communities = attr(0xc0, 8, struct.pack('>IIIIIIIIII',
    (65001 << 16) | 100, 0xFFFFFF01, 0xFFFFFF02, 0xFFFFFF03, 0xFFFFFF04,
    0xFFFF0000, 0xFFFF029A, 0x00000001, 0xFFFF0007, 0xFFFF1234))
add('UPDATE: withdrawn routes, well-known attributes, communities, NLRI',
    update(withdrawn=pfx4(8, '10.0.0.0') + pfx4(25, '192.0.2.128'),
           attrs=ORIGIN_IGP + aspath([(2, [65001, 65002, 23456])]) + NH_ATTR +
           attr(0x80, 4, struct.pack('>I', 100)) + attr(0x40, 5, struct.pack('>I', 200)) +
           attr(0x40, 6, b'') + attr(0xc0, 7, struct.pack('>H4s', 65002, ip4('192.0.2.9'))) +
           communities + attr(0x80, 9, ip4('192.0.2.7')) +
           attr(0x80, 10, ip4('192.0.2.10') + ip4('192.0.2.11')),
           nlri=pfx4(24, '198.51.100.0') + pfx4(25, '203.0.113.128') + pfx4(32, '203.0.113.5') + pfx4(0, '0.0.0.0')))
add('UPDATE: AS_SET/AS_SEQUENCE/confederation segments, AS4_PATH, aggregators',
    update(attrs=ORIGIN_EGP +
           aspath([(3, [65010, 65011]), (4, [65012]), (2, [65001, 23456]), (1, [65020, 65021])]) +
           NH_ATTR + attr(0xc0, 7, struct.pack('>I4s', 4200000002, ip4('192.0.2.9'))) +
           aspath([(2, [4200000001, 65001]), (1, [4200000005])], asn_len=4, atype=17) +
           attr(0xc0, 18, struct.pack('>I4s', 4200000002, ip4('192.0.2.9'))),
           nlri=pfx4(24, '198.51.100.0')))
add('UPDATE: four octet AS_PATH (heuristic), large communities, OTC, D-PATH',
    update(attrs=ORIGIN_INC + aspath([(2, [65001, 4200000001, 65003])], asn_len=4) + NH_ATTR +
           attr(0xc0, 32, struct.pack('>III', 4200000001, 1, 2) + struct.pack('>III', 65001, 3, 4)) +
           attr(0xc0, 35, struct.pack('>I', 65005)) +
           attr(0xc0, 36, bytes([2]) + struct.pack('>IH', 65001, 7) + struct.pack('>IH', 65002, 8) + bytes([70])),
           nlri=pfx4(24, '198.51.100.0')))
add('UPDATE: four octet AS_PATH with two segments (heuristic sees zero high octets)',
    update(attrs=ORIGIN_IGP + aspath([(2, [65001]), (2, [65002, 65003])], asn_len=4) + NH_ATTR,
           nlri=pfx4(24, '198.51.100.0')))
add('UPDATE: four octet AS_PATH whose two octet reading looks valid but has zero high octets',
    update(attrs=ORIGIN_IGP + aspath([(2, [512]), (2, [65002])], asn_len=4) + NH_ATTR,
           nlri=pfx4(24, '198.51.100.0')))
add('UPDATE: NLRI with a path identifier whose first octet reads as a /1 prefix with host bits',
    update(attrs=ORIGIN_IGP + aspath([(2, [65001])]) + NH_ATTR,
           nlri=struct.pack('>I', 0x01050000) + pfx4(24, '198.51.100.0')))
add('UPDATE: NLRI with path identifiers that read as a too long prefix and as a prefix past the end',
    update(attrs=ORIGIN_IGP + aspath([(2, [65001])]) + NH_ATTR,
           nlri=struct.pack('>I', 0x21000001) + pfx4(24, '198.51.100.0')))
add('UPDATE: NLRI with a path identifier that makes the plain reading run past the end',
    update(attrs=ORIGIN_IGP + aspath([(2, [65001])]) + NH_ATTR,
           nlri=struct.pack('>I', 0x08012000) + pfx4(24, '192.0.2.0')))
add('UPDATE: empty AS_PATH, BFD discriminator, AIGP, BGPsec path, unknown attributes',
    update(attrs=ORIGIN_IGP + aspath([]) + NH_ATTR +
           attr(0x80, 38, bytes([1]) + struct.pack('>I', 0x11223344) +
                bytes([1, 4]) + ip4('192.0.2.1') + bytes([1, 16]) + ip6('2001:db8::1') +
                bytes([7, 2, 0xab, 0xcd]) + bytes([9, 0])) +
           attr(0x80, 26, bytes([1]) + struct.pack('>HQ', 11, 1000)) +
           attr(0x80, 33, struct.pack('>H', 14) + struct.pack('>BBI', 1, 0, 65001) + struct.pack('>BBI', 1, 0x80, 65002) +
                struct.pack('>HB', 3 + 22 + 4 + 22 + 2, 1) +
                bytes(range(20)) + struct.pack('>H', 4) + b'SIG1' +
                bytes(range(20, 40)) + struct.pack('>H', 2) + b'S2') +
           attr(0xc0, 241, b'\x01\x02\x03') + attr(0xe0, 30, b'') + attr(0x80, 21, b'\x05\x00\x00\xfd\xe9') +
           attr(0xd0, 128 + 99, b'\xaa' * 4),
           nlri=pfx4(24, '198.51.100.0')))
inner = ORIGIN_IGP + aspath([(2, [65100, 65101])]) + attr(0x40, 5, struct.pack('>I', 50)) + \
    attr(0xc0, 8, struct.pack('>I', (65100 << 16) | 1))
add('UPDATE: ATTR_SET carrying nested path attributes',
    update(attrs=ORIGIN_IGP + aspath([(2, [65001])]) + NH_ATTR +
           attr(0xc0, 128, struct.pack('>I', 65100) + inner) + attr(0xc0, 128, struct.pack('>I', 65100)),
           nlri=pfx4(24, '198.51.100.0')))
add('UPDATE: add-path withdrawn routes and NLRI (path identifiers, heuristic)',
    update(withdrawn=struct.pack('>I', 1) + pfx4(24, '198.51.100.0') + struct.pack('>I', 2) + pfx4(16, '10.1.0.0'),
           attrs=ORIGIN_IGP + aspath([(2, [65001])]) + NH_ATTR,
           nlri=struct.pack('>I', 7) + pfx4(24, '203.0.113.0') + struct.pack('>I', 8) + pfx4(32, '203.0.113.9')))
add('UPDATE: End-of-RIB marker (empty UPDATE)', update())
add('UPDATE: withdrawal only', update(withdrawn=pfx4(24, '198.51.100.0')))
add('UPDATE: SAFI specific attribute (L2TPv3, mGRE, IPsec, L2TPv3 in IPsec)',
    update(attrs=ORIGIN_IGP + aspath([(2, [65001])]) + NH_ATTR +
           attr(0xc0, 19, struct.pack('>HH', 1, 12) + struct.pack('>HBB', 10, 0x80, 4) + struct.pack('>I', 77) + b'COOK' +
                struct.pack('>HH', 1, 8) + struct.pack('>HBB', 10, 0x00, 0) + struct.pack('>I', 78) +
                struct.pack('>HH', 0x8002, 4) + b'\x00\x00\x00\x2f' +
                struct.pack('>HH', 3, 2) + b'\x01\x02' +
                struct.pack('>HH', 5, 6) + struct.pack('>HH', 3, 2) + b'\x01\x02' +
                struct.pack('>HH', 6, 6) + struct.pack('>HH', 2, 2) + b'\x03\x04'),
           nlri=pfx4(24, '198.51.100.0')))

# --- Extended communities (no MP_REACH in the frame: AFI/SAFI unknown) -----
z6 = b'\x00' * 6
coms = [
    ec(0x00, 0x02, struct.pack('>HI', 65001, 100)),           # route target AS2
    ec(0x00, 0x03, struct.pack('>HI', 65001, 200)),           # route origin
    ec(0x40, 0x04, struct.pack('>Hf', 65001, 125000000.0)),   # link bandwidth
    ec(0x40, 0x05, struct.pack('>HI', 65001, 1)),             # non-transitive AS2 other
    ec(0x01, 0x02, ip4('192.0.2.1') + struct.pack('>H', 10)), # route target IPv4
    ec(0x01, 0x07, ip4('192.0.2.2') + struct.pack('>H', 0)),  # OSPF router ID
    ec(0x41, 0x02, ip4('192.0.2.3') + struct.pack('>H', 11)),
    ec(0x02, 0x02, struct.pack('>IH', 4200000001, 12)),       # route target AS4
    ec(0x42, 0x04, struct.pack('>IH', 4200000001, 13)),
    ec(0x03, 0x01, bytes([129, 0x80]) + struct.pack('>I', 500)),   # cost community
    ec(0x03, 0x06, ip4('0.0.0.1') + bytes([5, 1])),                # OSPF route type
    ec(0x03, 0x0c, struct.pack('>IH', 0, 10)),                     # encapsulation MPLS
    ec(0x03, 0x0b, struct.pack('>HI', 0, 100)),                    # color
    ec(0x03, 0x99, z6),
    ec(0x43, 0x01, bytes([2, 0x00]) + struct.pack('>I', 600)),
    ec(0x43, 0x55, z6),
    ec(0x04, 0x00, bytes([0x80, 1, 0, 0, 0x2e, 0])),                # QoS marking
    ec(0x44, 0x00, bytes([0x40, 1, 0, 0, 0x0a, 0])),
    ec(0x05, 0x00, bytes([0xf0, 0x80, 0x40, 0x20, 0x10, 0])),       # CoS capability
    ec(0x06, 0x00, bytes([1, 0]) + struct.pack('>I', 7)),           # EVPN MAC mobility
    ec(0x06, 0x01, bytes([1, 0, 0]) + label(100)),                  # ESI label
    ec(0x06, 0x02, bytes.fromhex('02000000aa01')),                  # ES-import RT
    ec(0x06, 0x03, bytes.fromhex('02000000bb01')),                  # router MAC
    ec(0x06, 0x04, struct.pack('>HHH', 0x001f, 1500, 0)),           # L2 attributes
    ec(0x06, 0x05, bytes([1, 0, 0]) + label(200)),                  # E-tree
    ec(0x06, 0x06, z6),                                             # DF election (raw)
    ec(0x0c, 0x00, struct.pack('>HI', 65001, 1)),                   # MUP
    ec(0x0c, 0x01, ip4('192.0.2.1') + struct.pack('>H', 2)),
    ec(0x0c, 0x02, struct.pack('>IH', 4200000001, 3)),
    ec(0x0c, 0x03, struct.pack('>HI', 65001, 4)),
    ec(0x0c, 0x04, ip4('192.0.2.1') + struct.pack('>H', 5)),
    ec(0x0c, 0x05, struct.pack('>IH', 4200000001, 6)),
    ec(0x0c, 0x09, z6),
    ec(0x80, 0x00, ip4('0.0.0.0') + bytes([1, 0])),                 # OSPF route type
    ec(0x80, 0x01, ip4('192.0.2.5') + b'\x00\x00'),                 # OSPF router ID
    ec(0x80, 0x05, struct.pack('>HI', 65001, 9)),                   # OSPF domain ID
    ec(0x80, 0x06, struct.pack('>Hf', 65001, 1000000.0)),           # flowspec traffic rate
    ec(0x80, 0x07, b'\x00' * 5 + b'\x03'),                          # traffic action
    ec(0x80, 0x08, struct.pack('>HI', 65001, 666)),                 # redirect
    ec(0x80, 0x09, b'\x00' * 5 + b'\x2e'),                          # traffic marking
    ec(0x80, 0x0a, bytes([19, 0xe3]) + struct.pack('>H', 1500) + b'\x00\x00'),  # L2 info
    ec(0x80, 0x0b, struct.pack('>HHH', 100, 200, 3)),               # E-tree
    ec(0x80, 0x84, z6),
    ec(0x81, 0x08, ip4('192.0.2.1') + struct.pack('>H', 7)),        # redirect IPv4
    ec(0x81, 0x04, z6),
    ec(0x82, 0x08, struct.pack('>IH', 4200000001, 8)),              # redirect AS4
    ec(0x82, 0x84, z6),
    ec(0x88, 0x00, struct.pack('>HI', 0x8000, 99)),                 # EIGRP
    ec(0x88, 0x01, struct.pack('>HI', 100, 2560)),
    ec(0x88, 0x02, bytes([255, 3]) + struct.pack('>I', 25600)),
    ec(0x88, 0x03, bytes([0, 10]) + struct.pack('>I', 1500)),
    ec(0x88, 0x04, struct.pack('>H', 200) + ip4('192.0.2.6')),
    ec(0x88, 0x05, struct.pack('>HI', 4, 20)),
    ec(0x88, 0x06, b'\x00\x00' + ip4('192.0.2.7')),
    ec(0x88, 0x07, z6),
    ec(0x08, 0x00, z6),
    ec(0x99, 0x01, z6),
]
add('UPDATE: one extended community of every decoded type and subtype',
    update(attrs=ORIGIN_IGP + aspath([(2, [65001])]) + NH_ATTR + ext_com(*coms[:30]) + ext_com(*coms[30:]),
           nlri=pfx4(24, '198.51.100.0')))

# --- PMSI tunnel attribute (no encapsulation community: MPLS label) -------
def pmsi(flags, ttype, lbl, tid):
    return attr(0xc0, 22, bytes([flags, ttype]) + lbl + tid)

pmsis = [
    ('no tunnel information', pmsi(0, 0, label(0, 0), b'')),
    ('RSVP-TE P2MP LSP', pmsi(1, 1, label(10), struct.pack('>IHH4s', 1, 0, 7, ip4('192.0.2.1')))),
    ('mLDP P2MP, IPv4 root, generic LSP identifier',
     pmsi(0, 2, label(11), bytes([6]) + struct.pack('>HB', 1, 4) + ip4('192.0.2.1') + struct.pack('>H', 7) +
          bytes([1]) + struct.pack('>HI', 4, 99))),
    ('mLDP MP2MP, IPv6 root, extended opaque type',
     pmsi(0, 7, label(12), bytes([8]) + struct.pack('>HB', 2, 16) + ip6('2001:db8::1') + struct.pack('>H', 9) +
          bytes([255]) + struct.pack('>HH', 1, 4) + b'tree')),
    ('PIM-SSM tree', pmsi(0, 3, label(13), ip4('192.0.2.1') + ip4('232.1.1.1'))),
    ('PIM-SM tree', pmsi(0, 4, label(14), ip4('192.0.2.2') + ip4('239.1.1.1'))),
    ('BIDIR-PIM tree', pmsi(0, 5, label(15), ip4('192.0.2.3') + ip4('239.2.2.2'))),
    ('ingress replication IPv4', pmsi(0, 6, label(16), ip4('192.0.2.4'))),
    ('ingress replication IPv6', pmsi(0, 6, label(17), ip6('2001:db8::4'))),
]
for name, p in pmsis:
    add('UPDATE: PMSI tunnel attribute, ' + name,
        update(attrs=ORIGIN_IGP + aspath([(2, [65001])]) + NH_ATTR + p, nlri=pfx4(24, '198.51.100.0')))

# --- Prefix-SID attribute -------------------------------------------------
def psid_tlv(t, v):
    return bytes([t]) + struct.pack('>H', len(v)) + v

srv6_struct = psid_tlv(1, bytes([40, 24, 16, 0, 16, 64]))
srv6_unk_ss = psid_tlv(9, b'\x01\x02')
srv6_info = psid_tlv(1, b'\x00' + ip6('2001:db8:100::') + bytes([0]) + struct.pack('>H', 0x13) + b'\x00' +
                     srv6_struct + srv6_unk_ss)
srv6_unk_s = psid_tlv(7, b'\xaa\xbb')
add('UPDATE: Prefix-SID label index and originator SRGB (reproducer, blocks and next TLV)',
    update(attrs=ORIGIN_IGP + NH_ATTR + attr(0xc0, 40,
           psid_tlv(1, b'\x00\x00\x00' + struct.pack('>I', 42)) +
           psid_tlv(3, b'\x00\x00' + bytes([0, 0x3e, 0x80, 0, 0x1f, 0x40]) + bytes([0x01, 0x86, 0xa0, 0, 0x03, 0xe8])) +
           psid_tlv(1, b'\x00\x00\x00' + struct.pack('>I', 43))),
           nlri=pfx4(24, '198.51.100.0')))
add('UPDATE: Prefix-SID SRv6 L3 and L2 service TLVs (SID information, structure, unknown sub-TLVs)',
    update(attrs=ORIGIN_IGP + NH_ATTR + attr(0xc0, 40,
           psid_tlv(5, b'\x00' + srv6_info + srv6_unk_s) +
           psid_tlv(6, b'\x00' + srv6_info + srv6_unk_s)),
           nlri=pfx4(24, '198.51.100.0')))
add('UPDATE: Prefix-SID unknown TLV type 9 (reproducer, full value length)',
    update(attrs=ORIGIN_IGP + NH_ATTR + attr(0xc0, 40, psid_tlv(9, b'\xde\xad\xbe\xef')),
           nlri=pfx4(24, '198.51.100.0')))

# --- Tunnel encapsulation attribute ---------------------------------------
def stlv(t, v):
    if t < 128:
        return bytes([t, len(v)]) + v
    return bytes([t]) + struct.pack('>H', len(v)) + v


def tun(t, subs):
    v = b''.join(subs)
    return struct.pack('>HH', t, len(v)) + v

tunnels = (
    tun(1, [stlv(1, struct.pack('>I', 0x1234) + b'COOKIE'), stlv(5, struct.pack('>I', 16)), stlv(4, struct.pack('>I', 5))]) +
    tun(2, [stlv(1, struct.pack('>I', 0xabcd)), stlv(2, struct.pack('>H', 0x0800)), stlv(5, struct.pack('>I', 8))]) +
    tun(11, [stlv(1, struct.pack('>I', 0x1111))]) +
    tun(8, [stlv(1, bytes([0xc0]) + label(1000)[:3] + bytes.fromhex('02000000cc01') + b'\x00\x00')]) +
    tun(12, [stlv(1, bytes([0x20, 0, 0]) + struct.pack('>I', 2000 << 8)[:3] + b'\x00')]) +
    tun(9, [stlv(1, bytes([0x80]) + b'\x00\x0b\xb8' + bytes.fromhex('02000000dd01') + b'\x00\x00')]) +
    tun(10, [stlv(1, b''), stlv(5, b''), stlv(6, struct.pack('>IH', 65001, 1) + ip4('192.0.2.1')),
             stlv(8, struct.pack('>H', 6635)), stlv(197, b'\x01\x02\x03')])
)
add('UPDATE: tunnel encapsulation attribute, L2TPv3/GRE/MPLS-in-GRE/VXLAN/VXLAN-GPE/NVGRE/MPLS',
    update(attrs=ORIGIN_IGP + NH_ATTR + attr(0xc0, 23, tunnels), nlri=pfx4(24, '198.51.100.0')))

# SR policy (tunnel type 15) with every sub-TLV and segment type
def seg(t, v):
    return bytes([t, len(v)]) + v

sid16 = ip6('2001:db8:5::1')
beh = struct.pack('>HHBBBB', 0x0030, 0, 32, 16, 16, 0)
mpls_sid = label(16001) + b'\x40'
segments = b''.join([
    seg(1, bytes([0x80, 0]) + label(16001) + b'\x40'),            # A
    seg(13, bytes([0x00, 0]) + sid16),                             # B, 18
    seg(13, bytes([0x10, 0]) + sid16 + beh),                       # B, 26
    seg(3, bytes([0x40, 128]) + ip4('192.0.2.21')),                # C, 6
    seg(3, bytes([0x00, 0]) + ip4('192.0.2.21') + mpls_sid),       # C, 10
    seg(4, bytes([0x00, 0]) + ip6('2001:db8::21')),                # D, 18
    seg(4, bytes([0x00, 0]) + ip6('2001:db8::21') + mpls_sid),     # D, 22
    seg(5, bytes([0, 0]) + struct.pack('>I', 3) + ip4('192.0.2.22')),            # E, 10
    seg(5, bytes([0, 0]) + struct.pack('>I', 3) + ip4('192.0.2.22') + mpls_sid), # E, 14
    seg(6, bytes([0, 0]) + ip4('192.0.2.23') + ip4('192.0.2.24')),               # F, 10
    seg(6, bytes([0, 0]) + ip4('192.0.2.23') + ip4('192.0.2.24') + mpls_sid),    # F, 14
    seg(7, bytes([0, 0]) + struct.pack('>I', 4) + ip6('fe80::1') + struct.pack('>I', 5) + ip6('fe80::2')),             # G, 42
    seg(7, bytes([0, 0]) + struct.pack('>I', 4) + ip6('fe80::1') + struct.pack('>I', 5) + ip6('fe80::2') + mpls_sid),  # G, 46
    seg(8, bytes([0, 0]) + ip6('2001:db8::31') + ip6('2001:db8::32')),             # H, 34
    seg(8, bytes([0, 0]) + ip6('2001:db8::31') + ip6('2001:db8::32') + mpls_sid),  # H, 38
    seg(14, bytes([0, 0]) + ip6('2001:db8::41')),                                  # I, 18
    seg(14, bytes([0, 0]) + ip6('2001:db8::41') + sid16),                          # I, 34
    seg(14, bytes([0x10, 0]) + ip6('2001:db8::41') + sid16 + beh),                 # I, 42
    seg(15, bytes([0, 0]) + struct.pack('>I', 6) + ip6('fe80::3') + struct.pack('>I', 7) + ip6('fe80::4')),                # J, 42
    seg(15, bytes([0, 0]) + struct.pack('>I', 6) + ip6('fe80::3') + struct.pack('>I', 7) + ip6('fe80::4') + sid16),        # J, 58
    seg(15, bytes([0x10, 0]) + struct.pack('>I', 6) + ip6('fe80::3') + struct.pack('>I', 7) + ip6('fe80::4') + sid16 + beh),  # J, 66
    seg(16, bytes([0, 0]) + ip6('2001:db8::51') + ip6('2001:db8::52')),                     # K, 34
    seg(16, bytes([0, 0]) + ip6('2001:db8::51') + ip6('2001:db8::52') + sid16),             # K, 50
    seg(16, bytes([0x10, 0]) + ip6('2001:db8::51') + ip6('2001:db8::52') + sid16 + beh),    # K, 58
    seg(9, bytes([0, 0]) + struct.pack('>I', 10)),                 # weight
    seg(2, b'\x01\x02\x03\x04'),                                   # old type B: raw
    seg(10, b''),                                                  # empty sub-TLV
])
srpolicy = tun(15, [
    stlv(12, bytes([0, 0]) + struct.pack('>I', 100)),               # preference
    stlv(13, bytes([0, 0])),                                        # binding SID, none
    stlv(13, bytes([0x80, 0]) + label(24000) + b'\x00'),            # binding SID, MPLS
    stlv(13, bytes([0x40, 0]) + ip6('2001:db8:b::1')),              # binding SID, SRv6
    stlv(20, bytes([0xa0, 0]) + ip6('2001:db8:b::2')),              # SRv6 binding SID
    stlv(20, bytes([0x20, 0]) + ip6('2001:db8:b::3') + beh),        # with endpoint behavior
    stlv(14, bytes([0, 0, 2])),                                     # ENLP
    stlv(15, bytes([5, 0])),                                        # priority
    stlv(128, b'\x00' + segments),                                  # segment list
    stlv(129, b'\x00' + b'candidate-1'),                            # CP name
    stlv(130, b'\x00' + b'policy-red'),                             # policy name
])
srp_nlri = bytes([96]) + struct.pack('>II', 1, 100) + ip4('192.0.2.30')
add('UPDATE: SR policy SAFI with an SR Policy tunnel (every sub-TLV and segment type)',
    update(attrs=ORIGIN_IGP + mp_reach(AFI_IP, 73, NH, srp_nlri) + attr(0xc0, 23, srpolicy)))
add('UPDATE: IPv6 SR policy SAFI with an IPv6 next hop',
    update(attrs=ORIGIN_IGP + mp_reach(AFI_IP6, 73, NH6, bytes([192]) + struct.pack('>II', 3, 300) + ip6('2001:db8::31')) +
           attr(0xc0, 23, tun(15, [stlv(15, bytes([1, 0]))]))))
add('UPDATE: IPv6 SR policy SAFI with an IPv4 next hop',
    update(attrs=ORIGIN_IGP + mp_reach(AFI_IP6, 73, NH, bytes([192]) + struct.pack('>II', 2, 200) + ip6('2001:db8::30')) +
           attr(0xc0, 23, tun(15, [stlv(12, bytes([0, 0]) + struct.pack('>I', 50))]))))

# --- MP_REACH / MP_UNREACH: IPv4 and IPv6 unicast/multicast ---------------
NH6 = ip6('2001:db8::1')
LL6 = ip6('fe80::1')
add('MP_REACH IPv4 unicast with an IPv6 next hop (RFC 8950)',
    update(attrs=ORIGIN_IGP + aspath([(2, [65001])]) + mp_reach(AFI_IP, 1, NH6, pfx4(24, '198.51.100.0'))))
add('MP_REACH IPv4 multicast with global and link-local IPv6 next hops',
    update(attrs=ORIGIN_IGP + aspath([(2, [65001])]) + mp_reach(AFI_IP, 2, NH6 + LL6, pfx4(24, '232.0.0.0'))))
add('MP_REACH IPv4 unicast+multicast (SAFI 3), IPv4 next hop, two SNPAs',
    update(attrs=ORIGIN_IGP + aspath([(2, [65001])]) +
           mp_reach(AFI_IP, 3, NH, pfx4(24, '198.51.100.0'), snpa=bytes([2, 2, 0xaa, 0xbb, 1, 0xcc]))))
add('MP_REACH IPv4 unicast with path identifiers',
    update(attrs=ORIGIN_IGP + aspath([(2, [65001])]) +
           mp_reach(AFI_IP, 1, NH, struct.pack('>I', 1) + pfx4(24, '198.51.100.0') + struct.pack('>I', 2) + pfx4(24, '198.51.100.0'))))
add('MP_REACH IPv6 unicast, global and link-local next hop',
    update(attrs=ORIGIN_IGP + aspath([(2, [65001])]) +
           mp_reach(AFI_IP6, 1, NH6 + LL6, pfx6(32, '2001:db8::') + pfx6(64, '2001:db8:1:2::') + pfx6(128, '2001:db8::99'))))
add('MP_REACH IPv6 unicast with path identifiers, global next hop',
    update(attrs=ORIGIN_IGP + aspath([(2, [65001])]) +
           mp_reach(AFI_IP6, 1, NH6, struct.pack('>I', 1) + pfx6(48, '2001:db8:1::') + struct.pack('>I', 2) + pfx6(48, '2001:db8:1::'))))
add('MP_REACH IPv6 multicast, second next hop not link-local (warning)',
    update(attrs=ORIGIN_IGP + aspath([(2, [65001])]) + mp_reach(AFI_IP6, 2, NH6 + ip6('2001:db8::2'), pfx6(16, 'ff3e::'))))
add('MP_UNREACH IPv4 unicast',
    update(attrs=mp_unreach(AFI_IP, 1, pfx4(24, '198.51.100.0') + pfx4(16, '10.2.0.0'))))
add('MP_UNREACH IPv6 unicast',
    update(attrs=mp_unreach(AFI_IP6, 1, pfx6(64, '2001:db8:1:2::')) ))
add('MP_UNREACH IPv6 End-of-RIB', update(attrs=mp_unreach(AFI_IP6, 1, b'')))

# --- Labeled unicast ------------------------------------------------------
add('MP_REACH IPv4 labeled unicast (one and two labels)',
    update(attrs=ORIGIN_IGP + aspath([(2, [65001])]) + mp_reach(AFI_IP, 4, NH,
           bytes([24 + 24]) + label(100) + ip4('198.51.100.0')[:3] +
           bytes([48 + 32]) + label(200, 0) + label(201) + ip4('203.0.113.7'))))
add('MP_REACH IPv4 labeled unicast with path identifiers',
    update(attrs=ORIGIN_IGP + aspath([(2, [65001])]) + mp_reach(AFI_IP, 4, NH,
           struct.pack('>I', 1) + bytes([24 + 24]) + label(100) + ip4('198.51.100.0')[:3])))
add('MP_UNREACH IPv4 labeled unicast, withdrawn label 0x800000',
    update(attrs=mp_unreach(AFI_IP, 4, bytes([24 + 24]) + b'\x80\x00\x00' + ip4('198.51.100.0')[:3])))
add('MP_REACH IPv6 labeled unicast',
    update(attrs=ORIGIN_IGP + aspath([(2, [65001])]) + mp_reach(AFI_IP6, 4, NH6,
           bytes([24 + 48]) + label(300) + ip6('2001:db8:3::')[:6])))
add('MP_REACH IPv6 labeled unicast with path identifier',
    update(attrs=ORIGIN_IGP + aspath([(2, [65001])]) + mp_reach(AFI_IP6, 4, NH6,
           struct.pack('>I', 9) + bytes([24 + 48]) + label(300) + ip6('2001:db8:3::')[:6])))

# --- L3VPN ----------------------------------------------------------------
vpn_nh = rd0(0, 0) + NH
add('MP_REACH VPN-IPv4 (RD types 0/1/2, two labels), VPN-IPv4 next hop',
    update(attrs=ORIGIN_IGP + aspath([(2, [65001])]) + mp_reach(AFI_IP, 128, vpn_nh,
           bytes([24 + 64 + 24]) + label(1000) + rd0(65001, 1) + ip4('198.51.100.0')[:3] +
           bytes([24 + 64 + 32]) + label(1001) + rd1('192.0.2.1', 2) + ip4('203.0.113.1') +
           bytes([48 + 64 + 16]) + label(1002, 0) + label(1003) + rd2(4200000001, 3) + ip4('10.3.0.0')[:2]) +
           ext_com(ec(0x00, 0x02, struct.pack('>HI', 65001, 1)))))
add('MP_REACH VPN-IPv4 with an unknown RD type 3',
    update(attrs=ORIGIN_IGP + aspath([(2, [65001])]) + mp_reach(AFI_IP, 128, vpn_nh,
           bytes([24 + 64 + 24]) + label(1000) + struct.pack('>HHI', 3, 1, 1) + ip4('198.51.100.0')[:3])))
add('MP_REACH VPN-IPv4 with path identifiers, VPN-IPv6 next hop with link-local',
    update(attrs=ORIGIN_IGP + aspath([(2, [65001])]) + mp_reach(AFI_IP, 128, rd0(0, 0) + NH6 + rd0(0, 0) + LL6,
           struct.pack('>I', 5) + bytes([24 + 64 + 24]) + label(1000) + rd0(65001, 1) + ip4('198.51.100.0')[:3])))
add('MP_REACH VPN-IPv4 multicast (SAFI 129), VPN-IPv6 next hop, nonzero RD (warning)',
    update(attrs=ORIGIN_IGP + aspath([(2, [65001])]) + mp_reach(AFI_IP, 129, rd0(1, 1) + NH6,
           bytes([24 + 64 + 8]) + label(1000) + rd0(65001, 1) + b'\xe8')))
add('MP_REACH VPN-IPv4 SAFI 130, nonzero RD in VPN-IPv4 next hop (warning)',
    update(attrs=ORIGIN_IGP + aspath([(2, [65001])]) + mp_reach(AFI_IP, 130, rd0(1, 1) + NH,
           bytes([24 + 64 + 8]) + label(1000) + rd0(65001, 1) + b'\x0a')))
add('MP_REACH VPN-IPv6, double VPN-IPv6 next hop with nonzero RDs and a global second address (warnings)',
    update(attrs=ORIGIN_IGP + aspath([(2, [65001])]) + mp_reach(AFI_IP6, 128, rd0(1, 2) + NH6 + rd0(1, 3) + ip6('2001:db8::3'),
           bytes([24 + 64 + 64]) + label(2000) + rd0(65001, 1) + ip6('2001:db8:9:1::')[:8])))
add('MP_REACH VPN-IPv6 with path identifiers, VPN-IPv6 next hop',
    update(attrs=ORIGIN_IGP + aspath([(2, [65001])]) + mp_reach(AFI_IP6, 128, rd0(0, 0) + NH6,
           struct.pack('>I', 3) + bytes([24 + 64 + 64]) + label(2000) + rd0(65001, 1) + ip6('2001:db8:9:1::')[:8])))
add('MP_UNREACH VPN-IPv4 and VPN-IPv6 multicast',
    update(attrs=mp_unreach(AFI_IP, 128, bytes([24 + 64 + 24]) + b'\x80\x00\x00' + rd0(65001, 1) + ip4('198.51.100.0')[:3]) +
           mp_unreach(AFI_IP6, 129, bytes([24 + 64 + 32]) + label(5) + rd0(65001, 1) + ip6('2001:db8::')[:4])))

# --- Other IPv4/IPv6 SAFIs ------------------------------------------------
add('MP_REACH IPv4 encapsulation SAFI (endpoint address)',
    update(attrs=ORIGIN_IGP + mp_reach(AFI_IP, 7, NH, bytes([32]) + ip4('192.0.2.40'))))
add('MP_REACH IPv6 encapsulation SAFI (endpoint address)',
    update(attrs=ORIGIN_IGP + mp_reach(AFI_IP6, 7, NH6, bytes([128]) + ip6('2001:db8::40'))))
add('MP_REACH IPv4 tunnel SAFI',
    update(attrs=ORIGIN_IGP + mp_reach(AFI_IP, 64, NH, bytes([16 + 24]) + struct.pack('>H', 0x55) + ip4('198.51.100.0')[:3])))
add('MP_REACH IPv6 tunnel SAFI',
    update(attrs=ORIGIN_IGP + mp_reach(AFI_IP6, 64, NH6, bytes([16 + 48]) + struct.pack('>H', 0x66) + ip6('2001:db8:4::')[:6])))
add('MP_UNREACH IPv4 MDT SAFI',
    update(attrs=mp_unreach(AFI_IP, 66, bytes([128]) + rd0(65001, 7) + ip4('192.0.2.1') + ip4('239.1.1.1'))))
add('MP_REACH IPv4 route target constraint (wildcard, AS2, IPv4, AS4 (reproducer) route targets)',
    update(attrs=ORIGIN_IGP + mp_reach(AFI_IP, 132, NH,
           bytes([0]) +
           bytes([96]) + struct.pack('>I', 65001) + struct.pack('>HHI', 0x0002, 65001, 100) +
           bytes([96]) + struct.pack('>I', 65001) + struct.pack('>H4sH', 0x0102, ip4('192.0.2.1'), 7) +
           bytes([96]) + struct.pack('>I', 65001) + struct.pack('>HIH', 0x0202, 65536, 7) +
           bytes([64]) + struct.pack('>I', 65001) + struct.pack('>HH', 0x0003, 1))))

# --- Multicast VPN --------------------------------------------------------
def mvpn(rt, body):
    return bytes([rt, len(body)]) + body

spmsi = mvpn(3, rd0(65001, 1) + bytes([32]) + ip4('192.0.2.50') + bytes([32]) + ip4('232.1.1.1') + ip4('192.0.2.1'))
mvpn4 = (mvpn(1, rd0(65001, 1) + ip4('192.0.2.1')) +
         mvpn(2, rd1('192.0.2.1', 1) + struct.pack('>I', 65002)) +
         spmsi +
         mvpn(3, rd2(4200000001, 1) + bytes([0]) + bytes([0]) + ip4('192.0.2.1')) +
         mvpn(4, spmsi + ip4('192.0.2.2')) +
         mvpn(5, rd0(65001, 1) + bytes([32]) + ip4('192.0.2.50') + bytes([32]) + ip4('232.1.1.1')) +
         mvpn(6, rd0(65001, 1) + struct.pack('>I', 65001) + bytes([0]) + bytes([32]) + ip4('239.1.1.1')) +
         mvpn(7, rd0(65001, 1) + struct.pack('>I', 65001) + bytes([32]) + ip4('192.0.2.50') + bytes([32]) + ip4('232.1.1.1')) +
         mvpn(9, rd0(65001, 1)))
add('MP_REACH IPv4 MCAST-VPN, route types 1-7 and an unknown type',
    update(attrs=ORIGIN_IGP + mp_reach(AFI_IP, 5, NH, mvpn4)))
spmsi6 = mvpn(3, rd0(65001, 1) + bytes([128]) + ip6('2001:db8::50') + bytes([128]) + ip6('ff3e::1') + ip6('2001:db8::1'))
mvpn6 = (mvpn(1, rd0(65001, 1) + ip6('2001:db8::1')) + spmsi6 + mvpn(4, spmsi6 + ip6('2001:db8::2')))
add('MP_REACH IPv6 MCAST-VPN, route types 1, 3 and 4',
    update(attrs=ORIGIN_IGP + mp_reach(AFI_IP6, 5, NH6, mvpn6)))

# --- Flow specification ---------------------------------------------------
def fs(*components):
    body = b''.join(components)
    if len(body) < 240:
        return bytes([len(body)]) + body
    return struct.pack('>H', 0xf000 | len(body)) + body


def num(op, value):
    """op: flag bits without the length; value length chosen from the value"""
    for ln, code in ((1, 0), (2, 1), (4, 2), (8, 3)):
        if value < (1 << (8 * ln)):
            break
    return bytes([op | (code << 4)]) + value.to_bytes(ln, 'big')

EOL, AND, LT, GT, EQ = 0x80, 0x40, 0x04, 0x02, 0x01
fs4 = fs(bytes([1]) + pfx4(24, '198.51.100.0'),
         bytes([2]) + pfx4(32, '192.0.2.1'),
         bytes([3]) + num(EQ, 6) + num(EOL | EQ, 17),
         bytes([4]) + num(GT | EQ, 1024) + num(EOL | AND | LT | EQ, 65535),
         bytes([5]) + num(EOL | EQ, 80),
         bytes([6]) + num(EOL | EQ, 53),
         bytes([7]) + num(EOL | EQ, 8),
         bytes([8]) + num(EOL | EQ, 0),
         bytes([9]) + bytes([0x01, 0x02]) + bytes([0x80 | 0x40 | 0x02, 0x3f]),
         bytes([10]) + num(GT, 100000) + num(AND | LT, 1 << 40) + num(EOL | EQ, 1500),
         bytes([11]) + bytes([0x01, 46, 0x81, 10]),
         bytes([12]) + bytes([0x01, 0x01, 0x82, 0x0e]))
add('MP_REACH IPv4 flow specification, every component type (1/2/4/8 octet values), two octet TCP flags last',
    update(attrs=ORIGIN_IGP + mp_reach(AFI_IP, 133, b'', fs4 +
           fs(bytes([1]) + pfx4(24, '203.0.113.0'), bytes([9]) + bytes([0x91, 0x00, 0x12]))) +
           ext_com(ec(0x80, 0x06, struct.pack('>Hf', 65001, 0.0)), ec(0x80, 0x08, struct.pack('>HI', 65001, 666)))))
# Reproducer bgp_small_fixes.py frame 1: four octet value
add('MP_REACH IPv4 flow specification, four octet port value 8080 (reproducer)',
    update(attrs=ORIGIN_IGP + mp_reach(AFI_IP, 133, b'',
           bytes([12, 4, 0xa1]) + struct.pack('>I', 8080) + bytes([5, 0x81, 80]) + bytes([6, 0x81, 53]))))
add('MP_REACH IPv4 flow specification with a two octet NLRI length (>= 240)',
    update(attrs=ORIGIN_IGP + mp_reach(AFI_IP, 133, b'',
           fs(bytes([1]) + pfx4(24, '198.51.100.0'),
              bytes([4]) + b''.join(num(EQ, p) for p in range(1000, 1080)) + num(EOL | EQ, 2000)))))
add('MP_REACH IPv4 VPN flow specification, RD types 0, 1 and 2',
    update(attrs=ORIGIN_IGP + mp_reach(AFI_IP, 134, b'',
           fs(rd0(65001, 1) + bytes([1]) + pfx4(24, '198.51.100.0')) +
           fs(rd1('192.0.2.1', 2) + bytes([5]) + num(EOL | EQ, 443)) +
           fs(rd2(4200000001, 3) + bytes([3]) + num(EOL | EQ, 1)))))
add('MP_REACH IPv6 flow specification (prefix offsets, draft-04 order)',
    update(attrs=ORIGIN_IGP + mp_reach(AFI_IP6, 133, b'',
           fs(bytes([1, 48, 0]) + ip6('2001:db8:1::')[:6],
              bytes([2, 0, 64]) + ip6('2001:db8:2::')[:8],
              bytes([3]) + num(EOL | EQ, 58)))))
add('MP_REACH IPv6 VPN flow specification',
    update(attrs=ORIGIN_IGP + mp_reach(AFI_IP6, 134, b'',
           fs(rd0(65001, 1) + bytes([1, 32, 0]) + ip6('2001:db8::')[:4]))))
add('MP_UNREACH IPv4 flow specification',
    update(attrs=mp_unreach(AFI_IP, 133, fs(bytes([1]) + pfx4(24, '198.51.100.0')))))

# --- L2VPN: VPLS / BGP-AD -------------------------------------------------
vpls = struct.pack('>H', 17) + rd0(65001, 1) + struct.pack('>HHH', 1, 0, 10) + label(800000)
bgpad = struct.pack('>H', 12) + rd0(65001, 2) + ip4('192.0.2.1')
add('MP_REACH L2VPN VPLS (RFC 4761) and BGP-AD (RFC 6074) NLRI',
    update(attrs=ORIGIN_IGP + mp_reach(AFI_L2VPN, 65, NH, vpls + bgpad) +
           ext_com(ec(0x80, 0x0a, bytes([19, 0x02]) + struct.pack('>H', 1500) + b'\x00\x00'))))
add('MP_REACH L2VPN SAFI 128 with an IPv6 next hop',
    update(attrs=ORIGIN_IGP + mp_reach(AFI_L2VPN, 128, NH6, bgpad)))
add('MP_UNREACH old L2VPN AFI 196 VPLS',
    update(attrs=mp_unreach(AFI_L2VPN_OLD, 65, vpls)))

# --- EVPN -----------------------------------------------------------------
def evpn(rt, body):
    return bytes([rt, len(body)]) + body

esis = [
    bytes([0]) + bytes(range(1, 10)),
    bytes([1]) + bytes.fromhex('020000000011') + struct.pack('>H', 1) + b'\x00',
    bytes([2]) + bytes.fromhex('020000000012') + struct.pack('>H', 32768) + b'\x00',
    bytes([3]) + bytes.fromhex('020000000013') + b'\x00\x01\x02' ,
    bytes([4]) + ip4('192.0.2.1') + struct.pack('>I', 9) + b'\x00',
    bytes([5]) + struct.pack('>II', 65001, 10) + b'\x00',
    bytes([255]) + b'\xff' * 9,
]
esis[3] = bytes([3]) + bytes.fromhex('020000000013') + b'\x00\x01' + b'\x00'
MAC = bytes.fromhex('02000000ee01')
ETAG = struct.pack('>I', 100)
RD = rd0(65001, 1)
mc_src4 = bytes([32]) + ip4('192.0.2.50')
mc_grp4 = bytes([32]) + ip4('232.1.1.1')
evpn_routes = [
    ('Ethernet A-D route, ESI type 0', evpn(1, RD + esis[0] + ETAG + label(100))),
    ('MAC/IP route without IP, ESI type 1', evpn(2, RD + esis[1] + ETAG + bytes([48]) + MAC + bytes([0]) + label(101))),
    ('MAC/IP route with IPv4 and two labels, ESI type 2',
     evpn(2, RD + esis[2] + ETAG + bytes([48]) + MAC + bytes([32]) + ip4('192.0.2.60') + label(102) + label(103))),
    ('MAC/IP route with IPv6, ESI type 3',
     evpn(2, RD + esis[3] + ETAG + bytes([48]) + MAC + bytes([128]) + ip6('2001:db8::60') + label(104))),
    ('inclusive multicast route, IPv4', evpn(3, RD + ETAG + bytes([32]) + ip4('192.0.2.1'))),
    ('inclusive multicast route, IPv6', evpn(3, RD + ETAG + bytes([128]) + ip6('2001:db8::1'))),
    ('inclusive multicast route without IP', evpn(3, RD + ETAG + bytes([0]))),
    ('Ethernet segment route, IPv4, ESI type 4', evpn(4, RD + esis[4] + bytes([32]) + ip4('192.0.2.1'))),
    ('Ethernet segment route, IPv6, ESI type 5', evpn(4, RD + esis[5] + bytes([128]) + ip6('2001:db8::1'))),
    ('Ethernet segment route without IP, ESI type 255', evpn(4, RD + esis[6] + bytes([0]))),
    ('IP prefix route, IPv4 (label stack without bottom of stack)',
     evpn(5, RD + esis[0] + ETAG + bytes([24]) + ip4('198.51.100.0') + ip4('192.0.2.1') + label(105, 0))),
    ('IP prefix route, IPv6, withdrawn label',
     evpn(5, RD + esis[0] + ETAG + bytes([64]) + ip6('2001:db8:7::') + ip6('2001:db8::1') + b'\x00\x00\x00')),
    ('selective multicast Ethernet tag route with flags',
     evpn(6, RD + ETAG + mc_src4 + mc_grp4 + bytes([32]) + ip4('192.0.2.1') + bytes([0x0e]))),
    ('selective multicast route, IPv6 originator, no flags',
     evpn(6, RD + ETAG + bytes([0]) + bytes([128]) + ip6('ff3e::1') + bytes([128]) + ip6('2001:db8::1'))),
    ('IGMP join synch route',
     evpn(7, RD + esis[0] + ETAG + mc_src4 + mc_grp4 + bytes([32]) + ip4('192.0.2.1') + bytes([0x02]))),
    ('IGMP leave synch route, maximum response time 100 (reproducer)',
     evpn(8, RD + esis[0] + struct.pack('>I', 0) + b'\x00' + mc_grp4 + bytes([32]) + ip4('192.0.2.9') +
          b'\x00' * 4 + bytes([100]) + b'\x00')),
    ('S-PMSI A-D route', evpn(10, RD + ETAG + mc_src4 + mc_grp4 + bytes([0]))),
]
for name, r in evpn_routes:
    add('MP_REACH EVPN ' + name,
        update(attrs=ORIGIN_IGP + mp_reach(AFI_L2VPN, 70, NH, r) +
               ext_com(ec(0x00, 0x02, struct.pack('>HI', 65001, 0x80000064)))))
add('MP_REACH EVPN with path identifiers (two MAC/IP routes)',
    update(attrs=ORIGIN_IGP + mp_reach(AFI_L2VPN, 70, NH6,
           struct.pack('>I', 1) + evpn_routes[1][1] + struct.pack('>I', 2) + evpn_routes[1][1])))
# VXLAN: the encapsulation community comes before MP_REACH and the PMSI
# attribute (per-frame state is written before it is read)
vxlan_ec = ext_com(ec(0x03, 0x0c, struct.pack('>IH', 0, 8)))
add('MP_REACH EVPN with VXLAN encapsulation: A-D, MAC/IP (one and two VNIs), IP prefix, PMSI with VNI',
    update(attrs=ORIGIN_IGP + vxlan_ec + mp_reach(AFI_L2VPN, 70, NH,
           evpn(1, RD + esis[0] + ETAG + struct.pack('>I', 5000)[1:]) +
           evpn(2, RD + esis[0] + ETAG + bytes([48]) + MAC + bytes([0]) + struct.pack('>I', 5001)[1:]) +
           evpn(2, RD + esis[0] + ETAG + bytes([48]) + MAC + bytes([32]) + ip4('192.0.2.61') +
                struct.pack('>I', 5001)[1:] + struct.pack('>I', 6001)[1:]) +
           evpn(5, RD + esis[0] + ETAG + bytes([24]) + ip4('198.51.100.0') + ip4('192.0.2.1') + struct.pack('>I', 5002)[1:]) +
           evpn(5, RD + esis[0] + ETAG + bytes([64]) + ip6('2001:db8:7::') + ip6('2001:db8::1') + struct.pack('>I', 5003)[1:])) +
           ext_com(ec(0x00, 0x02, struct.pack('>HI', 65001, 5000)), ec(0x06, 0x03, bytes.fromhex('02000000bb01'))) +
           pmsi(0, 6, struct.pack('>I', 5000)[1:], ip4('192.0.2.1'))))
add('MP_REACH EVPN with VXLAN-GPE encapsulation, inclusive multicast route, PMSI with VNI',
    update(attrs=ORIGIN_IGP + ext_com(ec(0x03, 0x0c, struct.pack('>IH', 0, 12))) +
           mp_reach(AFI_L2VPN, 70, NH, evpn(3, RD + ETAG + bytes([32]) + ip4('192.0.2.1'))) +
           pmsi(0, 6, struct.pack('>I', 7000)[1:], ip4('192.0.2.1'))))
add('MP_UNREACH EVPN MAC/IP route',
    update(attrs=mp_unreach(AFI_L2VPN, 70, evpn_routes[2][1])))

# --- BGP-MUP --------------------------------------------------------------
def mup(rt, body, at=1):
    return bytes([at]) + struct.pack('>H', rt) + bytes([len(body)]) + body

t1st = (RD + pfx4(32, '198.51.100.10') + struct.pack('>IB', 0x1000, 9) + bytes([32]) + ip4('192.0.2.70') +
        bytes([32]) + ip4('192.0.2.71') +
        bytes([1, 5]) + struct.pack('>IB', 0x2000, 5) + bytes([2, 4]) + ip4('192.0.2.72') +
        bytes([2, 16]) + ip6('2001:db8::72') + bytes([3, 4]) + ip4('192.0.2.73') +
        bytes([3, 16]) + ip6('2001:db8::73') + bytes([99, 2, 0xab, 0xcd]) + bytes([98, 0]))
mup4 = (mup(1, RD + pfx4(24, '198.51.100.0')) +
        mup(2, RD + ip4('192.0.2.80')) +
        mup(3, t1st) +
        mup(3, RD + pfx4(24, '198.51.100.0') + struct.pack('>IB', 1, 1) + bytes([32]) + ip4('192.0.2.70') + bytes([0])) +
        mup(4, RD + bytes([64]) + ip4('192.0.2.90') + struct.pack('>I', 0x12345678) + bytes([1, 5]) + struct.pack('>IB', 1, 1)) +
        mup(4, RD + bytes([48]) + ip4('192.0.2.91') + b'\x12\x34') +
        mup(4, RD + bytes([24]) + ip4('192.0.2.0')[:3]))
add('MP_REACH IPv4 BGP-MUP, route types 1-4 (type 1 ST TLVs, type 2 ST TEID lengths)',
    update(attrs=ORIGIN_IGP + mp_reach(AFI_IP, 85, NH, mup4) +
           ext_com(ec(0x0c, 0x00, struct.pack('>HI', 65001, 1)))))
mup6 = (mup(1, RD + pfx6(64, '2001:db8:8::')) +
        mup(2, RD + ip6('2001:db8::80')) +
        mup(3, RD + pfx6(128, '2001:db8::10') + struct.pack('>IB', 2, 2) + bytes([128]) + ip6('2001:db8::70') +
            bytes([128]) + ip6('2001:db8::71')) +
        mup(4, RD + bytes([160]) + ip6('2001:db8::90') + struct.pack('>I', 0xabcdef01)) +
        mup(4, RD + bytes([136]) + ip6('2001:db8::91') + b'\x55'))
add('MP_REACH IPv6 BGP-MUP, route types 1-4',
    update(attrs=ORIGIN_IGP + mp_reach(AFI_IP6, 85, NH6, mup6)))
add('MP_REACH IPv4 BGP-MUP with path identifiers',
    update(attrs=ORIGIN_IGP + mp_reach(AFI_IP, 85, NH,
           struct.pack('>I', 1) + mup(2, RD + ip4('192.0.2.80')) + struct.pack('>I', 2) + mup(2, RD + ip4('192.0.2.81')))))
add('MP_REACH IPv4 BGP-MUP, path identifier that reads as an NLRI header',
    update(attrs=ORIGIN_IGP + mp_reach(AFI_IP, 85, NH, struct.pack('>I', 0x0100010e) + mup(2, RD + ip4('192.0.2.82')))))
add('MP_REACH IPv6 BGP-MUP with a path identifier',
    update(attrs=ORIGIN_IGP + mp_reach(AFI_IP6, 85, NH6, struct.pack('>I', 3) + mup(2, RD + ip6('2001:db8::83')))))
add('MP_UNREACH IPv6 BGP-MUP direct segment route',
    update(attrs=mp_unreach(AFI_IP6, 85, mup(2, RD + ip6('2001:db8::80')))))

# --- BGP-LS ---------------------------------------------------------------
def node_desc(t, subs):
    return tlv(t, b''.join(subs))

isis_rid = tlv(515, bytes.fromhex('192000002001'))
ospf_rid = tlv(515, ip4('192.0.2.1'))
local_isis = node_desc(256, [tlv(512, struct.pack('>I', 65001)), tlv(513, struct.pack('>I', 1)),
                             tlv(514, struct.pack('>I', 0)), isis_rid, tlv(516, ip4('192.0.2.1')),
                             tlv(517, struct.pack('>I', 65010))])
local_ospf = node_desc(256, [tlv(512, struct.pack('>I', 65001)), tlv(514, struct.pack('>I', 0)), ospf_rid])
remote_ospf = node_desc(257, [tlv(512, struct.pack('>I', 65001)), tlv(514, struct.pack('>I', 0)), tlv(515, ip4('192.0.2.2'))])
remote_isis = node_desc(257, [tlv(512, struct.pack('>I', 65001)), tlv(515, bytes.fromhex('192000002002')),
                              tlv(600, b'\x01')])   # unknown node descriptor sub-TLV (warning)


def ls_nlri(nt, proto, body, ident=0):
    v = bytes([proto]) + struct.pack('>Q', ident) + body
    return tlv(nt, v)

ls_node_isis = ls_nlri(1, 2, local_isis)
ls_link_ospf = ls_nlri(2, 3, local_ospf + remote_ospf +
                       tlv(258, struct.pack('>II', 1, 2)) + tlv(259, ip4('10.0.0.1')) + tlv(260, ip4('10.0.0.2')) +
                       tlv(261, ip6('2001:db8:a::1')) + tlv(262, ip6('2001:db8:a::2')) + tlv(263, struct.pack('>H', 2)))
ls_link_isis = ls_nlri(2, 1, local_isis + remote_isis + tlv(258, struct.pack('>II', 3, 4)))
ls_pfx4_ospf = ls_nlri(3, 3, local_ospf + tlv(263, struct.pack('>H', 0)) + tlv(264, b'\x01') +
                       tlv(265, pfx4(24, '198.51.100.0')))
ls_pfx6_isis = ls_nlri(4, 2, local_isis + tlv(265, pfx6(64, '2001:db8:1:2::')))
ls_srv6_sid = ls_nlri(6, 4, local_ospf + tlv(263, struct.pack('>H', 2)) + tlv(518, ip6('2001:db8:5::1')))
LS_NH = NH


def ls_attr(*tlvs, atype=29):
    return attr(0x80, atype, b''.join(tlvs))

sr_cap = tlv(1034, bytes([0xc0, 0]) + struct.pack('>I', 8000)[1:] + tlv(1161, label(16000)[:3]) +
             struct.pack('>I', 1000)[1:] + tlv(1161, struct.pack('>I', 20000)))
srlb = tlv(1036, bytes([0, 0]) + struct.pack('>I', 1000)[1:] + tlv(1161, struct.pack('>I', 15000)[1:]) +
           struct.pack('>I', 500)[1:] + tlv(1161, struct.pack('>I', 15500)))
fad = tlv(1039, bytes([128, 1, 0, 100]) +
          tlv(1040, struct.pack('>I', 1)) + tlv(1041, struct.pack('>II', 2, 3)) + tlv(1042, struct.pack('>I', 4)) +
          tlv(1043, struct.pack('>I', 0x80000000)) + tlv(1045, struct.pack('>II', 10, 11)) + tlv(1046, b'\x00\x01') +
          tlv(1045, b''))
node_attrs = ls_attr(
    tlv(263, struct.pack('>HH', 0, 2)), tlv(1024, b'\xf0'), tlv(1025, b'\x01\x02\x03'), tlv(1026, b'router-a'),
    tlv(1027, bytes.fromhex('490001')), tlv(1028, ip4('192.0.2.1')), tlv(1029, ip6('2001:db8::1')),
    sr_cap, tlv(1035, b'\x00\x01\x80'), srlb, tlv(1038, struct.pack('>HH', 0x4000, 0)), fad,
    tlv(266, b'\x01\x0a\x02\x08'), tlv(9999, b'\x00'))
add('MP_REACH BGP-LS node NLRI (IS-IS), node attribute TLVs, SR capabilities, Flex-Algo definition',
    update(attrs=ORIGIN_IGP + mp_reach(AFI_LS, 71, LS_NH, ls_node_isis) + node_attrs))

endx_sub = tlv(1252, bytes([32, 16, 16, 0]))
link_attrs_ospf = ls_attr(
    tlv(258, struct.pack('>II', 1, 2)), tlv(1030, ip4('192.0.2.2')), tlv(1031, ip6('2001:db8::2')),
    tlv(1088, struct.pack('>I', 0x80000005)), tlv(1089, struct.pack('>f', 1.25e9)),
    tlv(1090, struct.pack('>f', 1.0e9)), tlv(1091, struct.pack('>8f', *([1.25e8] * 8))),
    tlv(1092, struct.pack('>I', 10)), tlv(1093, b'\x08\x00'), tlv(1094, b'\xc0'),
    tlv(1095, b'\x0a'), tlv(1095, b'\x00\x0a'), tlv(1095, b'\x00\x00\x0a'),
    tlv(1096, struct.pack('>II', 1, 2)), tlv(1097, b'\xaa\xbb'), tlv(1098, b'link-ab'),
    tlv(1099, bytes([0xf8, 10, 0, 0]) + label(24001)[:3]),
    tlv(1100, b'\x00' * 10),
    tlv(1101, bytes([0xc0, 1, 0, 0]) + struct.pack('>I', 24002)[1:]),
    tlv(1102, bytes([0x80, 1, 0, 0]) + struct.pack('>I', 3)),
    tlv(1103, bytes([0xf0, 1, 0, 0]) + struct.pack('>I', 4)),
    tlv(1106, struct.pack('>HBBBB', 0x39, 0xe0, 0, 10, 0) + ip6('2001:db8:5::39') + endx_sub),
    tlv(1107, struct.pack('>HBBBB', 0x39, 0, 0, 10, 0) + ip4('192.0.2.3') + ip6('2001:db8:5::40') + endx_sub),
    tlv(1122, bytes([4, 4, 0, 0]) + struct.pack('>I', 0xf0000000) + struct.pack('>I', 0x1) +
        tlv(1092, struct.pack('>I', 20)) + tlv(1173, struct.pack('>II', 1, 2))),
    tlv(267, b'\x01\x0a'),
    tlv(1114, bytes([0x80]) + struct.pack('>I', 1000)[1:]),
    tlv(1115, bytes([0x00]) + struct.pack('>I', 900)[1:] + b'\x00' + struct.pack('>I', 1100)[1:]),
    tlv(1116, b'\x00' + struct.pack('>I', 50)[1:]),
    tlv(1117, bytes([0x80]) + struct.pack('>I', 3)[1:]),
    tlv(1118, struct.pack('>f', 1.0e8)), tlv(1119, struct.pack('>f', 2.0e8)), tlv(1120, struct.pack('>f', 3.0e8)),
    tlv(1173, struct.pack('>II', 0x10, 0x20)))
add('MP_REACH BGP-LS link NLRI (OSPFv2), link attribute TLVs (OSPF adjacency SID, SRv6 End.X with sub-TLV)',
    update(attrs=ORIGIN_IGP + mp_reach(AFI_LS, 71, NH6 + LL6, ls_link_ospf) + link_attrs_ospf))
link_attrs_isis = ls_attr(
    tlv(1099, bytes([0xfc, 10, 0, 0]) + struct.pack('>I', 5)),
    tlv(1107, struct.pack('>HBBBB', 0x39, 0, 0, 10, 0) + bytes.fromhex('192000002002') + ip6('2001:db8:5::41') + endx_sub),
    tlv(1092, struct.pack('>I', 30)[1:]),
    tlv(1122, bytes([8, 0, 0, 1]) + struct.pack('>II', 0x40000000, 0) + tlv(1095, b'\x05')))
add('MP_REACH BGP-LS link NLRI without link descriptors',
    update(attrs=ORIGIN_IGP + mp_reach(AFI_LS, 71, LS_NH, ls_nlri(2, 3, local_ospf + remote_ospf))))
add('MP_REACH BGP-LS link NLRI (IS-IS L1), IS-IS adjacency SID, LAN End.X, old TE metric (warnings)',
    update(attrs=ORIGIN_IGP + mp_reach(AFI_LS, 71, LS_NH, ls_link_isis) + link_attrs_isis))
pfx_attrs_ospf = ls_attr(
    tlv(1152, b'\x80'), tlv(1153, struct.pack('>II', 1, 2)), tlv(1154, struct.pack('>QQ', 3, 4)),
    tlv(1155, struct.pack('>I', 20)), tlv(1156, ip4('192.0.2.1')), tlv(1157, b'\x01\x02'),
    tlv(1158, bytes([0x7c, 0, 0, 0]) + label(16005)[:3]), tlv(1159, b'\x00' * 8),
    tlv(1162, bytes([0x80, 0, 0, 0]) + struct.pack('>I', 10)),
    tlv(1170, b'\xe0'), tlv(1171, ip4('192.0.2.1')),
    tlv(1044, bytes([128, 0x80, 0, 0]) + struct.pack('>I', 30)))
add('MP_REACH BGP-LS IPv4 prefix NLRI (OSPFv2), prefix attribute TLVs',
    update(attrs=ORIGIN_IGP + mp_reach(AFI_LS, 71, LS_NH, ls_pfx4_ospf) + pfx_attrs_ospf))
pfx_attrs_isis = ls_attr(
    tlv(1156, ip6('2001:db8::1')), tlv(1158, bytes([0xfc, 0, 0, 0]) + struct.pack('>I', 5)),
    tlv(1170, b'\xf0'), tlv(1171, ip6('2001:db8::1')))
add('MP_REACH BGP-LS IPv6 prefix NLRI (IS-IS L2), IS-IS prefix SID and flags',
    update(attrs=ORIGIN_IGP + mp_reach(AFI_LS, 71, LS_NH, ls_pfx6_isis) + pfx_attrs_isis))
add('MP_REACH BGP-LS SRv6 SID NLRI (direct), SID attribute TLVs, prefix flags of an unknown protocol (warning)',
    update(attrs=ORIGIN_IGP + mp_reach(AFI_LS, 71, LS_NH, ls_srv6_sid) +
           ls_attr(tlv(1250, struct.pack('>HBB', 0x30, 0, 0)), tlv(1252, bytes([32, 16, 16, 0])), tlv(1170, b'\x00'),
                   atype=99)))
# Reproducer bgp_small_fixes.py frame 8: sub-TLV in the last 4 octets
add('UPDATE: BGP-LS Flex-Algo definition with its only sub-TLV in the last 4 octets (reproducer)',
    update(attrs=ORIGIN_IGP + ls_attr(tlv(1039, bytes([128, 0, 0, 100]) + tlv(1045, b'')))))
add('MP_REACH BGP-LS-VPN SAFI 72 node NLRI, VPN-IPv4 next hop',
    update(attrs=ORIGIN_IGP + mp_reach(AFI_LS, 72, rd0(0, 0) + NH, ls_node_isis)))
add('MP_REACH BGP-LS-VPN SAFI 72, VPN-IPv6 next hop',
    update(attrs=ORIGIN_IGP + mp_reach(AFI_LS, 72, rd0(0, 0) + NH6, ls_node_isis)))
add('MP_UNREACH BGP-LS SAFI 128 node NLRI with RD types 0, 1 and 2',
    update(attrs=mp_unreach(AFI_LS, 128,
           tlv(1, rd0(65001, 1) + ls_node_isis[4:]) + tlv(1, rd1('192.0.2.1', 2) + ls_node_isis[4:]) +
           tlv(1, rd2(4200000001, 3) + ls_node_isis[4:]))))

# --- Several messages per TCP segment and reassembly ----------------------
add('KEEPALIVE + UPDATE + KEEPALIVE in one TCP segment',
    msg(4, b'') + update(attrs=ORIGIN_IGP + aspath([(2, [65001])]) + NH_ATTR, nlri=pfx4(24, '198.51.100.0')) + msg(4, b''))
big = update(attrs=ORIGIN_IGP + aspath([(2, [65001, 65002])]) + NH_ATTR,
             nlri=b''.join(pfx4(24, '10.%d.%d.0' % (i // 256, i % 256)) for i in range(1300)))
assert len(big) > 4096
segs = [big[i:i + 1448] for i in range(0, len(big), 1448)]
for n, s in enumerate(segs):
    add('Extended message UPDATE of %d octets (1300 prefixes), TCP segment %d of %d' % (len(big), n + 1, len(segs)), s)
upd = update(attrs=ORIGIN_IGP + aspath([(2, [65001])]) + NH_ATTR, nlri=pfx4(24, '198.51.100.0'))
add('UPDATE split inside its header, TCP segment 1 of 2', upd[:17])
add('UPDATE split inside its header, TCP segment 2 of 2, followed by a KEEPALIVE', upd[17:] + msg(4, b''))

# Separate connection whose first segment starts inside a message
MID = Stream('192.0.2.3', '192.0.2.2', 40001, 179, 77777)
add('Capture started mid-message: continuation bytes, then a KEEPALIVE', b'\x00\x01\xff\xff\x03' * 3 + msg(4, b''), MID)
NOM = Stream('192.0.2.4', '192.0.2.2', 40002, 179, 1)
add('Segment without a BGP marker (not BGP)', b'not a bgp message', NOM)
add('UPDATE whose last attribute is a one segment two octet AS_PATH, MP_REACH first, no NLRI '
    '(was malformed before the heuristic_as2_or_4_from_as_path() fix)',
    update(attrs=ORIGIN_IGP + mp_reach(AFI_IP, 1, NH, pfx4(24, '198.51.100.0')) + aspath([(2, [65001, 65002])])))

# ---------------------------------------------------------------------------
# Malformed capture: paths only malformed input reaches. Every case is a
# message of its own on a connection of its own, so an exception in one
# does not hide the next and TCP does not stitch broken messages together.

bad = []


def bnew(label_, payload, caplen=None):
    port = 41000 + len(bad)
    bad.append((label_, payload, Stream('192.0.2.1', '192.0.2.2', port, 179, 1), caplen))


def bupd(label_, attrs_list, nlri=b'', withdrawn=b''):
    for n, a in enumerate(attrs_list):
        bnew('%s (%d)' % (label_, n + 1), update(attrs=a, nlri=nlri, withdrawn=withdrawn))

# Reproducers bgp_small_fixes.py frames 7, 9 and 10 (error expert infos)
bnew('BGP-LS unknown NLRI type 9 (reproducer, prints the type)',
     update(attrs=ORIGIN_IGP + mp_reach(AFI_LS, 71, NH, struct.pack('>HH', 9, 0))))
bnew('EVPN with path ID, route type 2 with an invalid length (reproducer)',
     update(attrs=ORIGIN_IGP + mp_reach(AFI_L2VPN, 70, NH, struct.pack('>I', 1) + bytes([2, 10]) + b'\x11' * 10)))
bnew('MP_REACH shorter than its next hop (reproducer, expert)',
     update(attrs=attr(0x80, 14, struct.pack('>HBB', 1, 1, 0)) + attr(0x00, 1, b'\x00') + attr(0x40, 3, NH)))
# Message level
bnew('KEEPALIVE followed by a message with an invalid marker in the same segment',
     msg(4, b'') + b'\xfe' + msg(4, b'')[1:])
bnew('KEEPALIVE with a wrong length', msg(4, b'\x00'))
bnew('OPEN of 5000 octets (above 4096)', msg(1, struct.pack('>BHH4sB', 4, 65001, 90, NH, 0) + b'\x00' * (5000 - 29)))
bnew('UPDATE of 5000 octets (above 4096, only invalid with bgp.ext_msg off)',
     update(attrs=ORIGIN_IGP + NH_ATTR, nlri=pfx4(24, '198.51.100.0') * ((5000 - 33) // 4)))
bnew('NOTIFICATION unknown major error 9', notif(9, 1))
bnew('ROUTE-REFRESH community ORF (unregistered)', rr(1, 0, 1, orf(1, 0x02, b'\x01\x02')))
bnew('ROUTE-REFRESH prefix ORF with an invalid action', rr(1, 0, 1, orf(1, 0x40, bytes([0xc0]))))
bnew('ROUTE-REFRESH prefix ORF with an invalid prefix length',
     rr(1, 0, 1, orf(1, 0x40, bytes([0x00]) + struct.pack('>I', 1) + bytes([0, 0, 40, 1, 2, 3, 4, 5]))))
badcaps = [cap(0, b'\x01'), cap(1, b'\x01'), cap(5, b'\x00\x01\x00\x01\x00\x02\x00'), cap(9, b''),
           cap(64, b'\x00\x00\x00'), cap(65, b'\x00'), cap(69, b'\x00'), cap(2, b'\x00'),
           cap(3, b'\x00'), cap(131, b''), cap(7, b''), cap(74, b'\x00')]
bnew('OPEN with every capability length error', open_msg([param(2, b''.join(badcaps))]))
# Path attributes
bupd('UPDATE attribute errors', [
    attr(0x40, 1, b''), attr(0x40, 3, b'\x01'), attr(0x80, 4, b'\x01'), attr(0x40, 5, b''),
    attr(0x40, 6, b'\x01'), attr(0xc0, 7, b'\x01'), attr(0xc0, 18, b'\x00' * 6), attr(0xc0, 8, b'\x01'),
    attr(0x80, 9, b''), attr(0x80, 10, b'\x01'), attr(0xc0, 16, b'\x01'), attr(0xc0, 32, b'\x01'),
    attr(0xc0, 35, b'\x01'), attr(0xc0, 36, b'\x01'),
    attr(0xc0, 36, bytes([2]) + struct.pack('>IH', 1, 1) + struct.pack('>IH', 2, 2)),
    attr(0x80, 38, b'\x01'), attr(0xc0, 128, b'\x01'), attr(0x80, 26, b'\x05'),
    attr(0x40, 2, bytes([2, 3, 0, 1, 0, 2])) + ORIGIN_IGP,
    attr(0x80, 38, bytes([1]) + struct.pack('>I', 1) + bytes([1, 3, 1, 2, 3])),
    attr(0x80, 38, bytes([1]) + struct.pack('>I', 1) + bytes([2, 9, 1])),
    attr(0x80, 38, bytes([1]) + struct.pack('>I', 1) + bytes([7])),
    attr(0xc0, 19, struct.pack('>HH', 1, 9) + struct.pack('>HBB', 1, 0, 3) + b'\x00' * 5),
    attr(0xc0, 19, struct.pack('>HH', 2, 0)),
    attr(0xc0, 40, psid_tlv(1, b'\x00' * 4)), attr(0xc0, 40, psid_tlv(3, b'\x00' * 5)),
    attr(0x80, 33, struct.pack('>H', 5) + b'\x00' * 3 + struct.pack('>HB', 3, 1)),
    pmsi(0, 2, label(1), bytes([6]) + struct.pack('>HB', 1, 4) + ip4('192.0.2.1') + struct.pack('>H', 3) + bytes([0, 0, 0])),
    pmsi(0, 9, label(1), b'\x00' * 4),
    attr(0xc0, 23, tun(10, [stlv(5, struct.pack('>I', 8))])),
])
bnew('UPDATE AIGP with an unknown TLV type (note, malformed group)',
     update(attrs=ORIGIN_IGP + aspath([(2, [65001])]) + NH_ATTR + attr(0x80, 26, bytes([2]) + struct.pack('>H', 3)),
            nlri=pfx4(24, '198.51.100.0')))
bnew('UPDATE attribute longer than the attribute list (NLRI follows)',
     update(attrs=struct.pack('>BBB', 0x40, 1, 10) + b'\x00', nlri=pfx4(24, '198.51.100.0') * 3))
bnew('UPDATE attribute longer than the whole message', update(attrs=struct.pack('>BBB', 0x40, 1, 10) + b'\x00'))
bnew('UPDATE withdrawn route with an invalid prefix length', update(withdrawn=bytes([33, 0, 0, 0, 0xff])))
bnew('UPDATE NLRI with an invalid prefix length', update(attrs=ORIGIN_IGP, nlri=bytes([40, 0, 0, 0, 0xff, 0])))
# Next hop errors
bupd('MP_REACH next hop errors', [
    mp_reach(1, 1, b'\x01\x02\x03', b''), mp_reach(1, 133, NH, b''), mp_reach(2, 133, NH, b''),
    mp_reach(1, 66, NH, b''), mp_reach(2, 66, NH6, b''), mp_reach(25, 1, NH, b''),
    mp_reach(16388, 1, NH, b''), mp_reach(99, 1, NH, b'\x00'), mp_reach(1, 64, NH6, b''),
    mp_reach(1, 128, NH, b''), mp_reach(16388, 72, NH, b''),
])
# decode_prefix_MP errors
bupd('MP_UNREACH NLRI errors', [
    mp_unreach(1, 99, b'\x00'), mp_unreach(2, 99, b'\x00'), mp_unreach(25, 99, b'\x00'),
    mp_unreach(99, 1, b'\x00'),
    mp_unreach(1, 1, bytes([33, 0, 0, 0, 0xff])),
    mp_unreach(2, 1, bytes([129, 0, 0, 0, 0xff])),
    mp_unreach(1, 4, bytes([8, 0x00, 0x08, 0x01])),
    mp_unreach(1, 4, bytes([57]) + label(1) + b'\x00' * 5),
    mp_unreach(2, 4, bytes([8, 0x00, 0x08, 0x01])),
    mp_unreach(2, 4, bytes([153]) + label(1) + b'\x00' * 17),
    mp_unreach(1, 128, bytes([24, 0x00, 0x00, 0x11])),
    mp_unreach(1, 128, bytes([24 + 64 + 33]) + label(1) + b'\x00' * 13),
    mp_unreach(2, 128, bytes([24, 0x00, 0x00, 0x11])),
    mp_unreach(2, 128, bytes([24 + 64 + 129]) + label(1) + b'\x00' * 25),
    mp_unreach(1, 132, bytes([20]) + b'\x00' * 3),
    mp_unreach(1, 132, bytes([96]) + struct.pack('>I', 1) + struct.pack('>HHI', 0x0303, 1, 1)),
    mp_unreach(1, 7, bytes([24, 1, 2, 3])), mp_unreach(2, 7, bytes([64]) + b'\x00' * 8),
    mp_unreach(1, 64, bytes([16, 0, 1])), mp_unreach(1, 64, bytes([16 + 33, 0, 1]) + b'\x00' * 5),
    mp_unreach(2, 64, bytes([8, 0])), mp_unreach(2, 64, bytes([16 + 129, 0, 1]) + b'\x00' * 17),
    mp_unreach(1, 66, bytes([64]) + b'\x00' * 8),
    mp_unreach(1, 5, mvpn(3, rd0(1, 1) + bytes([24]) + b'\x00' * 7)),
    mp_unreach(1, 5, mvpn(3, rd0(1, 1) + bytes([0, 24]) + b'\x00' * 7)),
    mp_unreach(1, 5, mvpn(5, rd0(1, 1) + bytes([24]) + b'\x00' * 3)),
    mp_unreach(1, 5, mvpn(6, rd0(1, 1) + b'\x00\x00\x00\x01' + bytes([24]) + b'\x00' * 3)),
    mp_unreach(2, 5, mvpn(3, rd0(1, 1) + bytes([24]) + b'\x00' * 7)),
    mp_unreach(1, 5, bytes([1, 40]) + b'\x00' * 4),
    mp_unreach(1, 5, mvpn(4, b'\x00\x00')),
    mp_unreach(1, 133, fs(bytes([12]) + bytes([0x91, 0, 1]))),
    mp_unreach(1, 133, fs(bytes([11]) + bytes([0x91, 0, 1]))),
    mp_unreach(1, 133, fs(bytes([13, 0x81, 1]))),
    mp_unreach(2, 133, fs(bytes([13, 0x81, 1]))),
    mp_unreach(1, 133, fs(bytes([1, 33]) + b'\x00' * 5)),
    mp_unreach(2, 133, fs(bytes([1, 129, 0]) + b'\x00' * 17)),
    mp_unreach(2, 133, fs(bytes([2, 0, 200]) + b'\x00' * 17)),
    mp_unreach(1, 134, fs(struct.pack('>HHI', 7, 1, 1) + bytes([3, 0x81, 6]))),
    mp_unreach(25, 133, b'\x05\x03\x81\x06'),
])
bupd('MP_UNREACH EVPN errors', [mp_unreach(25, 70, r) for r in [
    evpn(1, b'\x00' * 10), evpn(2, b'\x00' * 20),
    evpn(2, RD + esis[0] + ETAG + bytes([48]) + MAC + bytes([32]) + b'\x00' * 3),
    evpn(2, RD + esis[0] + ETAG + bytes([48]) + MAC + bytes([128]) + b'\x00' * 3),
    evpn(2, RD + esis[0] + ETAG + bytes([48]) + MAC + bytes([24]) + b'\x00' * 3),
    evpn(3, b'\x00' * 5), evpn(3, RD + ETAG + bytes([32])), evpn(3, RD + ETAG + bytes([128]) + b'\x00' * 3),
    evpn(3, RD + ETAG + bytes([24]) + b'\x00' * 3),
    evpn(4, b'\x00' * 5), evpn(4, RD + esis[0] + bytes([32])), evpn(4, RD + esis[0] + bytes([128]) + b'\x00' * 3),
    evpn(4, RD + esis[0] + bytes([24]) + b'\x00' * 3),
    evpn(5, b'\x00' * 5), evpn(5, RD + esis[0] + ETAG + b'\x18' + b'\x00' * 10),
    evpn(6, b'\x00' * 5), evpn(6, RD + ETAG + bytes([24]) + b'\x00' * 5),
    evpn(1, RD + bytes([9]) + b'\x00' * 9 + ETAG + label(1)),
    evpn(9, RD + b'\x00' * 4)]])
mup_t1 = RD + pfx4(24, '198.51.100.0') + struct.pack('>IB', 1, 1) + bytes([32]) + ip4('192.0.2.1') + bytes([0])
bupd('MP_UNREACH BGP-MUP errors', [mp_unreach(a, 85, r) for a, r in [
    (1, mup(1, RD + bytes([33]) + b'\x00' * 5)), (2, mup(1, RD + bytes([129]) + b'\x00' * 17)),
    (1, mup(3, RD + bytes([33]) + b'\x00' * 5)),
    (1, mup(3, RD + pfx4(24, '198.51.100.0') + struct.pack('>IB', 1, 1) + bytes([24]) + b'\x00' * 4)),
    (1, mup(3, RD + pfx4(24, '198.51.100.0') + struct.pack('>IB', 1, 1) + bytes([32]) + ip4('192.0.2.1') + bytes([24]) + b'\x00' * 3)),
    (1, mup(3, mup_t1 + b'\x01')),
    (1, mup(3, mup_t1 + bytes([1, 9]))),
    (1, mup(3, mup_t1 + bytes([1, 2, 0, 0]))),
    (1, mup(3, mup_t1 + bytes([2, 2, 0, 0]))),
    (1, mup(3, mup_t1 + bytes([3, 2, 0, 0]))),
    (1, mup(3, RD + pfx4(24, '198.51.100.0') + b'\x00' * 8, at=2)),
    (1, mup(4, RD + bytes([72]) + ip4('192.0.2.1') + b'\x00' * 5)),
    (1, mup(4, RD + bytes([40]) + ip4('192.0.2.1') + b'\x00' + b'\x01')),
    (1, mup(9, b'\x00\x01')),
    (2, mup(4, RD + bytes([128 + 8]) + ip6('2001:db8::92') + b'\x66', at=2))]])
lsx = b'\x02' + b'\x00' * 8
bupd('MP_UNREACH BGP-LS NLRI errors', [mp_unreach(AFI_LS, 71, n) for n in [
    tlv(1, b'\x02' + b'\x00' * 5),
    tlv(1, lsx + b'\x01\x00\x00'),
    tlv(1, lsx + node_desc(257, [tlv(512, b'\x00\x00\x00\x01')])),
    tlv(1, lsx + node_desc(256, [tlv(512, b'\x00')])),
    tlv(1, lsx + node_desc(256, [tlv(513, b'\x00')])),
    tlv(1, lsx + node_desc(256, [tlv(514, b'\x00')])),
    tlv(1, lsx + node_desc(256, [tlv(512, b'\x00\x00\x00\x01'), b'\x00\x01'])),
    tlv(2, lsx + local_ospf + b'\x00\x01'),
    tlv(2, lsx + local_ospf + remote_ospf + b'\x00\x01'),
    tlv(2, lsx + local_ospf + remote_ospf + tlv(258, b'\x00')),
    tlv(2, lsx + local_ospf + remote_ospf + tlv(259, b'\x00')),
    tlv(2, lsx + local_ospf + remote_ospf + tlv(260, b'\x00')),
    tlv(2, lsx + local_ospf + remote_ospf + tlv(261, b'\x00')),
    tlv(2, lsx + local_ospf + remote_ospf + tlv(262, b'\x00')),
    tlv(2, lsx + local_ospf + remote_ospf + tlv(263, b'\x00')),
    tlv(2, lsx + local_ospf + remote_ospf + tlv(263, b'\xf0\x00') + tlv(999, b'')),
    tlv(2, lsx + local_ospf + remote_ospf + tlv(258, b'\x00' * 8) + b'\x00'),
    tlv(3, lsx + local_ospf + b'\x00\x01'),
    tlv(3, lsx + local_ospf + tlv(263, b'\x00')),
    tlv(3, lsx + local_ospf + tlv(263, b'\xf0\x00') + tlv(264, b'\x01\x02') + tlv(999, b'')),
    tlv(3, lsx + local_ospf + tlv(265, bytes([33]) + b'\x00' * 5)),
    tlv(3, lsx + local_ospf + tlv(263, b'\x00\x00') + b'\x00'),
    tlv(4, lsx + local_ospf + b'\x00\x01'),
    tlv(4, lsx + local_ospf + tlv(265, bytes([129]) + b'\x00' * 17)),
    tlv(6, lsx + local_ospf + b'\x00\x01'),
    tlv(6, lsx + local_ospf + tlv(263, b'\x00')),
    tlv(6, lsx + local_ospf + tlv(518, b'\x00')),
    tlv(6, lsx + local_ospf + tlv(263, b'\xf0\x00') + tlv(999, b'')),
    tlv(6, lsx + local_ospf + tlv(263, b'\x00\x00') + b'\x00'),
    tlv(1, b''), tlv(2, b''), tlv(3, b''), tlv(4, b''), tlv(6, b''),
    tlv(2, lsx + local_ospf), tlv(3, lsx + local_ospf), tlv(4, lsx + local_ospf), tlv(6, lsx + local_ospf),
]] + [mp_unreach(AFI_LS, 128, tlv(1, b'')), mp_unreach(AFI_LS, 128, tlv(1, b'\x00' * 4)),
      mp_unreach(AFI_LS, 128, tlv(1, struct.pack('>HHI', 3, 0, 0) + ls_node_isis[4:])),
      mp_unreach(AFI_LS, 1, tlv(1, b'\x00'))])
bnew('BGP-LS attribute TLV length errors',
     update(attrs=ls_attr(*[tlv(t, b'\x00') for t in (1028, 1029, 258, 1030, 1031, 1088, 1089, 1090, 1091,
                                                       1093, 1155, 1156, 1101, 1038, 1106, 1107, 1162,
                                                       1171, 1044, 1250, 1252)] +
                          [tlv(1024, b'\x00\x00'), tlv(1094, b'\x00\x00'), tlv(1152, b'\x00\x00'),
                           tlv(1092, b'\x00' * 5), tlv(1095, b'\x00' * 4), tlv(1153, b'\x00' * 5), tlv(1154, b'\x00' * 9),
                           tlv(1096, b'\x00' * 5), tlv(1173, b'\x00' * 5), tlv(263, b'\xf0\x00'),
                           tlv(1024, b'\x0f'), tlv(1093, b'\xc0\x01'), tlv(1094, b'\x3f'), tlv(1152, b'\x7f'),
                           tlv(1122, bytes([3, 0, 0, 0])), tlv(1122, bytes([0, 3, 0, 0])),
                           tlv(1039, bytes([128, 0, 0, 0]) + tlv(1040, b'\x00') + tlv(1043, b'\x00') + tlv(1045, b'\x00'))])))
bnew('BGP-LS LAN End.X SID too short for IS-IS',
     update(attrs=ORIGIN_IGP + mp_reach(AFI_LS, 71, NH, ls_link_isis) + ls_attr(tlv(1107, b'\x00' * 26))))
bnew('BGP-LS LAN End.X SID too short for OSPF',
     update(attrs=ORIGIN_IGP + mp_reach(AFI_LS, 71, NH, ls_link_ospf) + ls_attr(tlv(1107, b'\x00' * 24))))
bnew('MUP NLRI list cut short by the capture length (add-path walk on a truncated frame)',
     update(attrs=ORIGIN_IGP + mp_reach(AFI_IP, 85, NH, struct.pack('>I', 0x0100010e) + mup(2, RD + ip4('192.0.2.80')))),
     caplen=54 + 23 + 7 + 8 + 4 + 2)
bnew('VXLAN EVPN attribute order: NLRI before the encapsulation community (unfixed -2 difference, '
     'bgp_attr_order_state.py)',
     update(attrs=ORIGIN_IGP + mp_reach(AFI_L2VPN, 70, NH, evpn_routes[1][1]) + vxlan_ec))
bnew('AS2 route target before MP_REACH EVPN (unfixed -2 difference)',
     update(attrs=ORIGIN_IGP + ext_com(ec(0x00, 0x02, struct.pack('>HI', 65000, 0x80000064))) +
            mp_reach(AFI_L2VPN, 70, NH, evpn_routes[1][1])))

# ---------------------------------------------------------------------------

def build(items):
    frames = []
    for item in items:
        frames.append((item[2].segment(item[1]), item[3] if len(item) > 3 else None))
    return frames


def main_():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'bgp-coverage.pcap'), build(main))
    write_pcap(os.path.join(out, 'bgp-coverage-malformed.pcap'), build(bad))
    with open(os.path.join(out, 'bgp-coverage-index.txt'), 'w') as f:
        for n, (lab, _p, _s) in enumerate(main, 1):
            f.write('%d\t%s\n' % (n, lab))
        f.write('\nmalformed capture\n')
        for n, (lab, *_rest) in enumerate(bad, 1):
            f.write('%d\t%s\n' % (n, lab))


if __name__ == '__main__':
    main_()
