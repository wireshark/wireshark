#!/usr/bin/env python3
# Generates test/captures/ospf_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the OSPF coverage captures (nothing comes from a real network).

Usage: mkospf.py <outdir>
Writes ospf-coverage.pcap and ospf-coverage-malformed.pcap.
OSPFv2 runs over IPv4 (protocol 89), OSPFv3 over IPv6 (next header 89);
both are reached by default.
"""
import os
import socket
import struct
import sys

# ----------------------------------------------------------------- helpers

def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def ip4(a):
    return socket.inet_aton(a)


def ip6(a):
    return socket.inet_pton(socket.AF_INET6, a)


def pad4(b):
    return b + bytes(-len(b) % 4)


def tlv(t, v, pad=True):
    """Type/length/value with the length of the unpadded value."""
    return struct.pack('!HH', t, len(v)) + (pad4(v) if pad else v)


def flt(x):
    return struct.pack('!f', x)


ETH4 = bytes.fromhex('01005e000005') + bytes.fromhex('020000000001') + b'\x08\x00'
ETH6 = bytes.fromhex('333300000005') + bytes.fromhex('020000000001') + b'\x86\xdd'
SRC4, DST4 = '192.0.2.1', '224.0.0.5'
SRC6, DST6 = 'fe80::1', 'ff02::5'


def frame4(ospf, ident=1, src=SRC4, dst=DST4, ttl=1):
    iph = struct.pack('!BBHHHBBH4s4s', 0x45, 0xc0, 20 + len(ospf), ident, 0, ttl,
                      89, 0, ip4(src), ip4(dst))
    iph = iph[:10] + struct.pack('!H', csum(iph)) + iph[12:]
    return ETH4 + iph + ospf


def frame6(ospf, src=SRC6, dst=DST6):
    iph = struct.pack('!IHBB16s16s', 0x6e000000, len(ospf), 89, 1, ip6(src), ip6(dst))
    return ETH6 + iph + ospf


def ospf2(ptype, body, rid='192.0.2.1', area='0.0.0.0', autype=0, auth=bytes(8),
          fix=True, instance=0, length=None, cksum=None):
    """OSPFv2 packet; the checksum excludes the authentication field."""
    ln = 24 + len(body) if length is None else length
    hdr = struct.pack('!BBH4s4sHBB', 2, ptype, ln, ip4(rid), ip4(area), 0, instance, autype)
    pre = hdr + b''
    if cksum is None:
        c = csum(hdr[:16] + body) if fix else 0
    else:
        c = cksum
    hdr = hdr[:12] + struct.pack('!H', c) + hdr[14:]
    return hdr + auth + body


def ospf3(ptype, body, rid='192.0.2.1', area='0.0.0.0', instance=0, src=SRC6, dst=DST6,
          fix=True, reserved=0, length=None, cksum=None):
    ln = 16 + len(body) if length is None else length
    hdr = struct.pack('!BBH4s4sHBB', 3, ptype, ln, ip4(rid), ip4(area), 0, instance, reserved)
    if cksum is None:
        if fix:
            ph = ip6(src) + ip6(dst) + struct.pack('!II', ln, 89)
            c = csum(ph + hdr + body)
        else:
            c = 0
    else:
        c = cksum
    hdr = hdr[:12] + struct.pack('!H', c) + hdr[14:]
    return hdr + body


# ---- v2 LSAs

def lsa2(ltype, lsid, body=b'', adv='192.0.2.1', opts=0x22, age=1, seq=0x80000001,
         length=None, cks=0x1234):
    ln = 20 + len(body) if length is None else length
    if isinstance(lsid, str):
        lsid = ip4(lsid)
    return struct.pack('!HBB4s4sIHH', age, opts, ltype, lsid, ip4(adv), seq, cks, ln) + body


def opq_id(t, i=0):
    return bytes([t]) + struct.pack('!I', i)[1:]


MINLEN = {1: 24, 2: 28, 3: 28, 4: 28, 5: 36, 7: 36, 9: 20, 10: 20, 11: 20}


def hdr2(t, lsid, **kw):
    return lsa2(t, lsid, bytes(MINLEN[t] - 20), **kw)[:20]


def router_link(lid, data, ltype, metric, tos=()):
    b = ip4(lid) + ip4(data) + struct.pack('!BBH', ltype, len(tos), metric)
    for t, m in tos:
        b += struct.pack('!BBH', t, 0, m)
    return b


def router_lsa2(flags, links, **kw):
    body = struct.pack('!BBH', flags, 0, len(links)) + b''.join(links)
    return lsa2(1, kw.pop('lsid', '192.0.2.1'), body, **kw)


# ---- v3 LSAs

def lsa3(ltype, lsid, body=b'', adv='192.0.2.1', age=1, seq=0x80000001, length=None,
         cks=0x4321):
    ln = 20 + len(body) if length is None else length
    return struct.pack('!HHIIIHH', age, ltype, lsid, struct.unpack('!I', ip4(adv))[0],
                       seq, cks, ln) + body


def prefix_bytes(plen, addr):
    n = (plen + 31) // 32 * 4
    return ip6(addr)[:n] if n <= 16 else b''


def pfx3(plen, popts, addr, third=0):
    return struct.pack('!BBH', plen, popts, third) + prefix_bytes(plen, addr)


def pfx4(plen, popts, addr, third=0):
    return struct.pack('!BBH', plen, popts, third) + ip4(addr)


# ----------------------------------------------------------------- v2 frames

def v2_frames():
    F = []
    # 1 Hello, no neighbors, no auth, all options bits except L (no LLS)
    hello = struct.pack('!4sHBB4s4s4s', ip4('255.255.255.0'), 10, 0xcf, 1, struct.pack('!I', 40),
                        ip4('192.0.2.1'), ip4('192.0.2.2'))
    F.append(frame4(ospf2(1, hello)))
    # 2 Hello with 3 neighbors, MT/E/NP/DC options, simple password
    hello = struct.pack('!4sHBB4s4s4s', ip4('255.255.255.0'), 10, 0x2b, 5, struct.pack('!I', 40),
                        ip4('192.0.2.1'), ip4('192.0.2.2'))
    hello += b''.join(ip4(a) for a in ('192.0.2.2', '192.0.2.3', '192.0.2.4'))
    F.append(frame4(ospf2(1, hello, autype=1, auth=b'secret\0\0', instance=3)))
    # 3 Hello with cryptographic authentication (key id 1, digest of 16 bytes appended)
    digest = bytes(range(0xa0, 0xb0))
    hello = struct.pack('!4sHBB4s4s4s', ip4('255.255.255.0'), 10, 0x02, 1, struct.pack('!I', 40),
                        bytes(4), bytes(4))
    auth = struct.pack('!HBBI', 0, 1, 16, 0x12345678)
    F.append(frame4(ospf2(1, hello, autype=2, auth=auth) + digest))
    # 4 Hello with unknown authentication type 7
    F.append(frame4(ospf2(1, hello, autype=7, auth=bytes(range(8)))))
    # 5 Hello with the LLS bit: extended options TLV and crypto TLV, then LLS id TLV
    hello_l = struct.pack('!4sHBB4s4s4s', ip4('255.255.255.0'), 10, 0x12, 1, struct.pack('!I', 40),
                          ip4('192.0.2.1'), bytes(4))
    tl = tlv(1, struct.pack('!I', 3), False)
    tl += tlv(2, struct.pack('!I', 77) + bytes(range(12)), False)
    tl += tlv(18, bytes([1, 2, 3, 4]), False)
    tl += tlv(99, bytes(4), False)          # unknown TLV, skipped
    lls = struct.pack('!HH', 0xabcd, (4 + len(tl)) // 4) + tl
    F.append(frame4(ospf2(1, hello_l) + lls))
    # 6 DB Description (init, more, master) no LSAs, MT option in LSA header absent
    dbd = struct.pack('!HBBI', 1500, 0x42, 0x07, 0x1000)
    F.append(frame4(ospf2(2, dbd)))
    # 7 DB Description with LSA headers of types 1-5 and 7 and opaque 9/10/11
    hdrs = b''
    for t, i in ((1, '192.0.2.1'), (2, '192.0.2.5'), (3, '10.0.0.0'), (4, '192.0.2.9'),
                 (5, '172.16.0.0'), (7, '172.17.0.0')):
        hdrs += hdr2(t, i, opts=0x22 if t != 7 else 0x28)
    for t in (9, 10, 11):
        hdrs += hdr2(t, opq_id(1, 1))
    # headers keep the LS length of the full header only
    dbd = struct.pack('!HBBI', 1500, 0x42, 0x02, 0x1001) + hdrs
    F.append(frame4(ospf2(2, dbd)))
    # 8 DB Description with the LLS bit set and an LLS block (extended options)
    lls = struct.pack('!HH', 0, 2) + tlv(1, struct.pack('!I', 1), False)
    dbd = struct.pack('!HBBI', 1500, 0x52, 0x01, 0x1002) + hdr2(1, '192.0.2.1')
    F.append(frame4(ospf2(2, dbd) + lls))
    # 9 LS Request: three requests
    req = b''.join(struct.pack('!I4s4s', t, ip4(i), ip4('192.0.2.1'))
                   for t, i in ((1, '192.0.2.1'), (2, '192.0.2.5'), (5, '172.16.0.0')))
    F.append(frame4(ospf2(3, req)))
    # 10 LS Ack with several LSA headers
    ack = hdr2(1, '192.0.2.1') + hdr2(3, '10.0.0.0') + hdr2(5, '172.16.0.0')
    F.append(frame4(ospf2(5, ack)))
    # 11 LS Update: router LSAs and network, summary, ASBR, external, NSSA
    lsas = []
    # Router LSA: flags B,E,V,W,N,S, links: p2p, transit, stub, virtual with TOS metrics
    links = [router_link('192.0.2.2', '192.0.2.1', 1, 10),
             router_link('192.0.2.5', '192.0.2.1', 2, 20, tos=[(0, 5), (4, 30)]),
             router_link('10.1.0.0', '255.255.0.0', 3, 30),
             router_link('192.0.2.7', '192.0.2.1', 4, 40)]
    lsas.append(router_lsa2(0xbf, links))
    # Router LSA with MT option (MT-ID metrics) and the H flag
    lsas.append(router_lsa2(0x81, [router_link('10.2.0.0', '255.255.0.0', 3, 7, tos=[(2, 9)])],
                            lsid='192.0.2.3', adv='192.0.2.3', opts=0x23))
    # Network LSA
    lsas.append(lsa2(2, '192.0.2.5', ip4('255.255.255.0') + ip4('192.0.2.1') + ip4('192.0.2.2')))
    # Summary (3) and ASBR summary (4) with a second TOS metric
    lsas.append(lsa2(3, '10.0.0.0', ip4('255.0.0.0') + struct.pack('!I', 100) +
                     struct.pack('!I', 0x02000064)))
    lsas.append(lsa2(4, '192.0.2.9', ip4('0.0.0.0') + struct.pack('!I', 50)))
    # AS external (E bit, tos 0 and 1) and NSSA external with the P bit
    ext = (ip4('255.255.0.0') + struct.pack('!I', 0x80000014) + ip4('192.0.2.3') + struct.pack('!I', 99) +
           struct.pack('!I', 0x00000014) + ip4('0.0.0.0') + struct.pack('!I', 0))
    lsas.append(lsa2(5, '172.16.0.0', ext))
    lsas.append(lsa2(7, '172.17.0.0', ip4('255.255.0.0') + struct.pack('!I', 0x80000014) +
                     ip4('192.0.2.3') + struct.pack('!I', 99), opts=0x28))
    body = struct.pack('!I', len(lsas)) + b''.join(lsas)
    F.append(frame4(ospf2(4, body)))
    # 12 LS Update with an LSA of header only length (no body) and an unknown LSA type
    # is in the malformed capture; here an empty router LSA and a network LSA with no router
    # is also malformed. Keep this frame to the minimal valid router LSA.
    lsas = [router_lsa2(0, [])]
    F.append(frame4(ospf2(4, struct.pack('!I', 1) + lsas[0])))
    # 13 Unknown OSPF packet type 9 (data)
    F.append(frame4(ospf2(9, bytes(range(8)))))
    # 14a Hello without checksum (0) and an empty LS Request (header only)
    F.append(frame4(ospf2(1, hello, fix=False)))
    F.append(frame4(ospf2(3, b'')))
    # 14 Unknown OSPF version 4 (only the first fields are dissected)
    pkt = bytearray(ospf2(1, hello))
    pkt[0] = 4
    F.append(frame4(bytes(pkt)))
    return F


def v2_opaque_frames():
    F = []
    lsas = []
    # MPLS-TE LSA (type 10, opaque type 1): router address and link with all sub-TLVs
    sub = b''
    sub += tlv(1, bytes([1]))                                           # link type
    sub += tlv(2, ip4('192.0.2.2'))                                     # link id
    sub += tlv(3, ip4('192.0.2.1') + ip4('192.0.2.11'))                 # local addresses
    sub += tlv(4, ip4('192.0.2.2'))                                     # remote
    sub += tlv(5, struct.pack('!I', 77))                                # te metric
    sub += tlv(6, flt(1.25e8))                                          # max bw
    sub += tlv(7, flt(1.0e8))                                           # max reservable
    sub += tlv(8, b''.join(flt(1e7 * (i + 1)) for i in range(8)))       # unreserved
    sub += tlv(9, struct.pack('!I', 0x80000005))                        # color
    sub += tlv(11, struct.pack('!II', 5, 6))                            # local/remote ids
    sub += tlv(14, bytes([0x40, 0, 0, 0]))                              # protection
    sub += tlv(16, struct.pack('!II', 1, 2) + b'')                      # SRLG
    sub += tlv(26, struct.pack('!II', 0xff, 0xff00))                    # ext admin group
    sub += tlv(27, struct.pack('!BBBB', 0x80, 0, 0, 0)[:1] + (1234).to_bytes(3, 'big'))   # delay
    sub += tlv(28, bytes([0x80]) + (10).to_bytes(3, 'big') + bytes([0]) + (20).to_bytes(3, 'big'))
    sub += tlv(29, bytes([0]) + (5).to_bytes(3, 'big'))                 # delay variation
    sub += tlv(32773, ip4('192.0.2.1'))                                 # OIF local node
    sub += tlv(32774, ip4('192.0.2.2'))                                 # OIF remote node
    sub += tlv(32775, bytes([1, 2, 0, 0]) + bytes([5, 0, 0, 3, 7, 0, 0, 1]))   # OIF sonet/sdh
    sub += tlv(55, bytes(8))                                            # unknown sub-TLV
    # bandwidth constraints: model 0, 3 BCs
    sub += tlv(17, bytes([1, 0, 0, 0]) + flt(1e6) + flt(2e6) + flt(3e6))
    # interface switching capability descriptors
    pri = b''.join(flt(1e8) for _ in range(8))
    sub += tlv(15, bytes([1, 1, 0, 0]) + pri + flt(1e6) + struct.pack('!H', 1500) + bytes(2))   # PSC-1
    sub += tlv(15, bytes([100, 1, 0, 0]) + pri + flt(1e6) + bytes([5, 0, 0, 0]))               # TDM
    # LSC with a bitmap sub-sub-TLV (action 4)
    sst = struct.pack('!HHB3s', 1, 16, 3, bytes(3)) + bytes([0x40, 0]) + struct.pack('!H', 12) + \
        bytes([0x20 | 0x04, 0]) + struct.pack('!H', 7) + struct.pack('!I', 0xdeadbeef)
    sub += tlv(15, bytes([150, 1, 0, 0]) + pri + sst)
    # LSC with grid 1 (DWDM), grid 2 (CWDM) and grid 3 (flexi) as WSON
    for g, cs in ((1, 3), (2, 1), (3, 0)):
        sst = struct.pack('!HHB3s', 1, 16, 3, bytes(3)) + bytes([0x40, 0]) + struct.pack('!H', 12) + \
            bytes([(g << 5) | (cs << 1), 0]) + struct.pack('!H', 7) + struct.pack('!I', 0x1)
        sub += tlv(15, bytes([151, 1, 0, 0]) + pri + sst)
    # flexi-grid LSC (152): type at +40, bitmap at +56
    fx = struct.pack('!HHB', 1, 16, 2) + bytes(3) + bytes(4) + struct.pack('!I', 0x50000000) + \
        struct.pack('!H', 32)[0:0]
    fx = struct.pack('!HHB3s4s', 1, 16, 2, bytes(3), bytes(4)) + bytes([0x50, 0, 0, 0])
    fx = fx[:14] + struct.pack('!H', 40) + struct.pack('!II', 0xffff0000, 0x80)
    # 14 bytes: header 4 + pri(1)+pad(3) + 4 reserved + cs/start(4): replace last two bytes
    # of the cs/start word by the effective bit count (they overlap in the dissector)
    sub += tlv(15, bytes([152, 1, 0, 0]) + pri + fx)
    fx32 = fx[:14] + struct.pack('!H', 32) + struct.pack('!I', 0xffff0000)
    sub += tlv(15, bytes([152, 1, 0, 0]) + pri + fx32)
    # an interface switching descriptor with an unlisted capability
    sub += tlv(15, bytes([51, 1, 0, 0]) + pri + bytes(8))
    mpls = tlv(1, ip4('192.0.2.1')) + tlv(2, sub) + tlv(99, bytes(4))
    # TNA information
    tna = tlv(32777, ip4('192.0.2.77'))
    tna += tlv(32776, bytes([32, 0, 0, 0]) + ip4('10.9.9.9'))
    tna += tlv(32778, bytes([128, 0, 0, 0]) + ip6('2001:db8::5'))
    tna += tlv(32779, bytes([8, 0, 0, 0]) + bytes(range(1, 9)))
    mpls += tlv(32768, tna)
    lsas.append(lsa2(10, opq_id(1, 0x0102), mpls, opts=0x20))
    # Grace LSA (type 9): period, reason, restart IP
    grace = tlv(1, struct.pack('!I', 120)) + tlv(2, bytes([1])) + tlv(3, ip4('192.0.2.1'))
    lsas.append(lsa2(9, opq_id(3, 0), grace, opts=0x20))
    # Grace LSA with an unknown TLV only
    lsas.append(lsa2(9, opq_id(3, 1), tlv(77, bytes([1, 2, 3])), opts=0x20))
    # Router information LSA (type 10 opaque type 4)
    ri = tlv(1, struct.pack('!I', 0xf4000000))
    ri += tlv(7, b'router1.example.net')
    ri += tlv(8, bytes([0, 1]))
    sr = struct.pack('!I', 1000)[0:0] + (4000).to_bytes(3, 'big') + bytes([0]) + \
        tlv(1, (16000).to_bytes(3, 'big')) + tlv(1, struct.pack('!I', 17000)) + tlv(1, bytes(2)) + tlv(5, bytes(4))
    ri += tlv(9, sr)
    ri += tlv(14, (1000).to_bytes(3, 'big') + bytes([0]) + tlv(1, (15000).to_bytes(3, 'big')))
    ri += tlv(15, bytes([100, 0, 0, 0]))
    ri += tlv(12, bytes([1, 8, 2, 10]))
    fad = bytes([128, 1, 0, 100])
    fad += tlv(1, struct.pack('!II', 1, 2))
    fad += tlv(2, struct.pack('!I', 3))
    fad += tlv(3, struct.pack('!I', 4))
    fad += tlv(4, struct.pack('!I', 0x80000000))
    fad += tlv(5, struct.pack('!II', 10, 11))
    fad += tlv(10, struct.pack('!I', 5))
    fad += tlv(11, struct.pack('!I', 6))
    fad += tlv(12, struct.pack('!I', 7))
    fad += tlv(77, bytes([1, 2, 3]))
    ri += tlv(16, fad)
    ri += tlv(77, bytes(range(6)))          # unknown TLV
    ri += tlv(10, struct.pack('!II', 1, 2))  # node admin tag, no special code
    lsas.append(lsa2(10, opq_id(4, 0), ri, opts=0x20))
    # Extended prefix LSA (opaque type 7): prefix TLV with prefix SID (3 and 4 octets), flex algo metric
    ep = struct.pack('!BBBB', 3, 24, 0, 0xe0) + ip4('10.1.1.0')
    ep += tlv(2, struct.pack('!BBBB', 0x7c, 0, 0, 1) + (16001).to_bytes(3, 'big'))
    ep += tlv(2, struct.pack('!BBBB', 0x00, 0, 0, 0) + struct.pack('!I', 16002))
    ep += tlv(2, bytes(5))                                              # invalid length
    ep += tlv(3, struct.pack('!BBHI', 128, 0x80, 0, 500))
    ep += tlv(3, bytes(4))                                              # invalid length
    ep += tlv(9, bytes(4))                                              # unknown sub-TLV
    epl = tlv(1, ep)
    epl += tlv(1, struct.pack('!BBBB', 1, 0, 0, 0))                     # prefix length 0
    rng = struct.pack('!BBHBBBB', 24, 0, 5, 0x80, 0, 0, 0) + ip4('10.2.0.0')
    rng += tlv(1, (7000).to_bytes(3, 'big') + bytes([0]))
    epl += tlv(2, rng)
    epl += tlv(2, struct.pack('!BBHBBBB', 0, 0, 1, 0, 0, 0, 0))         # prefix length 0
    epl += tlv(77, bytes(4))
    lsas.append(lsa2(10, opq_id(7, 1), epl, opts=0x20))
    lsas.append(lsa2(11, opq_id(7, 2), tlv(1, ep), opts=0x20))
    # Extended link LSA (opaque type 8)
    el = struct.pack('!BBBB', 1, 0, 0, 0) + ip4('192.0.2.2') + ip4('192.0.2.1')
    el += tlv(2, struct.pack('!BBBB', 0xf8, 0, 0, 10) + (24001).to_bytes(3, 'big'))
    el += tlv(2, struct.pack('!BBBB', 0, 0, 0, 10) + struct.pack('!I', 24002))
    el += tlv(2, bytes(5))
    el += tlv(3, struct.pack('!BBBB', 0x60, 0, 0, 1) + ip4('192.0.2.2') + (24003).to_bytes(3, 'big'))
    el += tlv(3, struct.pack('!BBBB', 0, 0, 0, 1) + ip4('192.0.2.2') + struct.pack('!I', 24004))
    el += tlv(3, bytes(5))
    el += tlv(6, bytes([1, 8, 2, 10]))
    el += tlv(7, b'')
    el += tlv(8, ip4('192.0.2.77'))
    el += tlv(9, struct.pack('!II', 3, 4))
    app = bytes([4, 4, 0, 0]) + bytes([0xe0, 0, 0, 0]) + bytes([1, 2, 3, 4])
    app += tlv(11, struct.pack('!II', 1, 2))
    app += tlv(12, bytes([0x80]) + (33).to_bytes(3, 'big'))
    app += tlv(13, bytes([0x80]) + (3).to_bytes(3, 'big') + bytes([0]) + (9).to_bytes(3, 'big'))
    app += tlv(14, bytes([0]) + (5).to_bytes(3, 'big'))
    app += tlv(19, struct.pack('!I', 0x0f))
    app += tlv(20, struct.pack('!II', 1, 2))
    app += tlv(22, struct.pack('!I', 55))
    app += tlv(77, bytes(4))
    el += tlv(10, app)
    el += tlv(10, bytes([0, 0, 0, 0, 0, 0, 0, 0]))                      # no link attribute sub-TLVs
    el += tlv(77, bytes(4))
    elp = tlv(1, el)
    elp += tlv(1, struct.pack('!BBBB', 3, 0, 0, 0) + ip4('10.0.0.0') + ip4('255.0.0.0'))
    elp += tlv(55, bytes(4))
    lsas.append(lsa2(10, opq_id(8, 1), elp, opts=0x20))
    # Extended inter-area ASBR LSA (opaque type 11)
    eia = ip4('192.0.2.9') + tlv(1, bytes([128, 0, 0, 0]) + struct.pack('!I', 77)) + tlv(2, bytes(4))
    eia = tlv(1, eia) + tlv(77, bytes(4))
    lsas.append(lsa2(11, opq_id(11, 1), eia, opts=0x20))
    # an unknown opaque type (area local, type 200) is in the malformed capture
    F.append(frame4(ospf2(4, struct.pack('!I', len(lsas)) + b''.join(lsas))))
    # one frame per big opaque LSA is not needed; also DB Desc with the opaque headers handled above
    return F


def v2_short_ack():
    return []


# ----------------------------------------------------------------- v3 frames

def v3_frames():
    F = []
    # 1 Hello (v3 options all, DR/BDR, neighbors)
    def hello3(opts, nbrs=(), prio=1):
        return struct.pack('!I', 7) + bytes([prio]) + opts.to_bytes(3, 'big') + struct.pack('!HH', 10, 40) + \
            ip4('192.0.2.1') + ip4('192.0.2.2') + b''.join(ip4(n) for n in nbrs)
    F.append(frame6(ospf3(1, hello3(0x13, ['192.0.2.2', '192.0.2.3']))))
    F.append(frame6(ospf3(1, hello3(0x3f), instance=65)))
    # 3 Hello, address family instance 66 (IPv4 AF) with the AF bit
    F.append(frame6(ospf3(1, hello3(0x113, ['192.0.2.2']), instance=66)))
    # 4 Hello, LLS bit, all the LLS TLVs
    tl = tlv(1, struct.pack('!I', 3), False)
    tl += tlv(3, struct.pack('!HBB', 5, 0xe0, 0), False)
    tl += tlv(4, ip4('192.0.2.2') + ip4('192.0.2.3'), False)
    tl += tlv(7, bytes([1, 0xc0, 0, 0]) + ip4('192.0.2.5') + ip4('192.0.2.6'), False)
    tl += tlv(7, bytes([0, 0x40, 0, 0]) + ip4('192.0.2.5') + ip4('192.0.2.6'), False)
    tl += tlv(8, bytes([128, 0, 0, 0]), False)
    tl += tlv(5, ip4('192.0.2.2') + ip4('192.0.2.3'), False)
    tl += tlv(6, ip4('192.0.2.2'), False)
    tl += tlv(99, bytes(4), False)
    lls = struct.pack('!HH', 0x1111, (4 + len(tl)) // 4) + tl
    F.append(frame6(ospf3(1, hello3(0x213)) + lls))
    # 5 Hello with the AT bit and an authentication trailer of 32 octets
    at = struct.pack('!HHHH', 1, 32, 0, 5) + struct.pack('!Q', 0x1122334455667788) + bytes(range(16))
    F.append(frame6(ospf3(1, hello3(0x413)) + at))
    # 6 Hello with both LLS and AT: LLS first, then trailer
    lls = struct.pack('!HH', 0, 2) + tlv(1, struct.pack('!I', 1), False)
    F.append(frame6(ospf3(1, hello3(0x613)) + lls + at))
    # 7 DB Description v3: options with AT and L bits clear, I/M/MS
    dbd = bytes([0]) + (0x13).to_bytes(3, 'big') + struct.pack('!HBBI', 1500, 0, 0x07, 0x2000)
    F.append(frame6(ospf3(2, dbd)))
    # 8 DB Description with LSA headers (many types)
    hdrs = b''.join(lsa3(t, 0, b'')[:20] for t in (0x2001, 0x2002, 0x2003, 0x2004, 0x4005, 0x2007,
                                                    0x0008, 0x2009, 0xa00b, 0x2012, 0x2021, 0x2022,
                                                    0x2025, 0x2028, 0x2029, 0x4010))
    dbd = bytes([0]) + (0x13).to_bytes(3, 'big') + struct.pack('!HBBI', 1500, 0, 0x02, 0x2001) + hdrs
    F.append(frame6(ospf3(2, dbd)))
    # 9 DB Description with the LLS bit
    dbd = bytes([0]) + (0x213).to_bytes(3, 'big') + struct.pack('!HBBI', 1500, 0, 0x01, 0x2002)
    F.append(frame6(ospf3(2, dbd) + struct.pack('!HH', 0, 2) + tlv(1, struct.pack('!I', 2), False)))
    # 10 DB Description with the AT bit
    dbd = bytes([0]) + (0x413).to_bytes(3, 'big') + struct.pack('!HBBI', 1500, 0, 0x01, 0x2003)
    F.append(frame6(ospf3(2, dbd) + at))
    # 11 LS Request
    req = b''.join(struct.pack('!HHI4s', 0, t, i, ip4('192.0.2.1'))
                   for t, i in ((0x2001, 0), (0x2009, 1), (0x6003, 2)))
    F.append(frame6(ospf3(3, req)))
    # 12 LS Ack
    F.append(frame6(ospf3(5, lsa3(0x2001, 0)[:20] + lsa3(0x2009, 1)[:20])))
    # 13 LS Update with the base LSAs (IPv6 AF)
    F.append(frame6(ospf3(4, ls_update3(base_lsas3(6), 6))))
    # 14 LS Update with the base LSAs (IPv4 AF, instance 70)
    F.append(frame6(ospf3(4, ls_update3(base_lsas3(4), 4), instance=70)))
    # 15 LS Update with the extended LSAs (IPv6 AF)
    F.append(frame6(ospf3(4, ls_update3(ext_lsas3(6), 6))))
    # 16 LS Update with extended LSAs (IPv4 AF)
    F.append(frame6(ospf3(4, ls_update3(ext_lsas3(4), 4), instance=70)))
    # 17 LS Update with Grace, Router information and a router LSA that has flags only
    F.append(frame6(ospf3(4, ls_update3(misc_lsas3(), 6))))
    return F


def ls_update3(lsas, af):
    return struct.pack('!I', len(lsas)) + b''.join(lsas)


def base_lsas3(af):
    P = pfx3 if af == 6 else pfx4
    a1 = '2001:db8:1::' if af == 6 else '10.1.0.0'
    a2 = '2001:db8:2::' if af == 6 else '10.2.0.0'
    L = []
    # Router LSA: flags and options, 2 interfaces
    rbody = bytes([0x0f]) + (0x13).to_bytes(3, 'big')
    rbody += struct.pack('!BBHIII', 1, 0, 10, 5, 6, struct.unpack('!I', ip4('192.0.2.2'))[0])
    rbody += struct.pack('!BBHIII', 2, 0, 20, 7, 8, struct.unpack('!I', ip4('192.0.2.3'))[0])
    L.append(lsa3(0x2001, 0, rbody))
    # Network LSA
    L.append(lsa3(0x2002, 5, bytes([0]) + (0x13).to_bytes(3, 'big') + ip4('192.0.2.1') + ip4('192.0.2.2')))
    # Inter-area prefix
    ip = struct.pack('!I', 77) + b''
    ipfx = bytes([0]) + (77).to_bytes(3, 'big') + P(61 if af == 6 else 21, 0x03, a1)
    L.append(lsa3(0x2003, 1, ipfx))
    # Inter-area router
    L.append(lsa3(0x2004, 2, bytes([0]) + (0x13).to_bytes(3, 'big') + bytes([0]) + (5).to_bytes(3, 'big') + ip4('192.0.2.9')))
    # AS external with forwarding address, tag and referenced link state id
    plen = 64 if af == 6 else 24
    fa = ip6('2001:db8::1') if af == 6 else ip4('10.9.9.9') + bytes(12)
    ext = bytes([0x07]) + (30).to_bytes(3, 'big') + bytes([plen, 0x08]) + struct.pack('!H', 0x2001)
    ext += (prefix_bytes(plen, a2) if af == 6 else ip4(a2)) + fa + struct.pack('!I', 99) + struct.pack('!I', 5)
    L.append(lsa3(0x4005, 7, ext))
    # AS external without optional parts
    ext = bytes([0x00]) + (30).to_bytes(3, 'big') + bytes([plen, 0x08]) + struct.pack('!H', 0)
    ext += (prefix_bytes(plen, a2) if af == 6 else ip4(a2))
    L.append(lsa3(0x4005, 8, ext))
    # NSSA
    L.append(lsa3(0x2007, 1, ext))
    # Link LSA, 2 prefixes
    ll = ip6('fe80::1') if af == 6 else ip4('192.0.2.1') + bytes(12)
    body = bytes([1]) + (0x13).to_bytes(3, 'big') + ll + struct.pack('!I', 2)
    if af == 6:
        body += P(64, 0x01, a1) + P(128, 0x02, a2)
    else:
        body += P(24, 0x01, a1) + P(32, 0x02, a2)
    L.append(lsa3(0x0008, 3, body))
    # Intra-area prefix with 2 prefixes
    body = struct.pack('!HHI4s', 2, 0x2001, 0, ip4('192.0.2.1')) + struct.pack('!4s', ip4('192.0.2.1'))[0:0]
    body = struct.pack('!HHI', 2, 0x2001, 0) + ip4('192.0.2.1')
    body += (P(64, 0x01, a1, 10) + P(48, 0x08, a2, 20)) if af == 6 else (P(24, 0x01, a1, 10) + P(16, 0x08, a2, 20))
    L.append(lsa3(0x2009, 0, body))
    return L


def misc_lsas3():
    L = []
    # Grace LSA (type 11): period and reason and (ignored for v3) IP TLV
    g = tlv(1, struct.pack('!I', 90)) + tlv(2, bytes([2])) + tlv(5, bytes([1, 2, 3]))
    L.append(lsa3(0x000b, 0, g))
    # Router information LSA (type 12 / 0xa00c area scope)
    ri = tlv(1, struct.pack('!I', 0x80000000)) + tlv(7, b'router-v3')
    L.append(lsa3(0x2000 | 12, 0, ri))
    L.append(lsa3(0x2000 | 1, 1, bytes([0, 0, 0, 0x13])))
    return L


def ext_lsas3(af):
    L = []
    plen = 64 if af == 6 else 24
    a1 = '2001:db8:1::' if af == 6 else '10.1.0.0'
    P = pfx3 if af == 6 else pfx4
    pbytes = prefix_bytes(plen, a1) if af == 6 else ip4(a1)
    tlv_ip = struct.pack('!IBB', 10, plen, 0x01) + struct.pack('!H', 0) + pbytes
    # E-Router LSA: router-link TLV and unknown TLV
    rl = struct.pack('!BBHIII', 1, 0, 10, 5, 6, struct.unpack('!I', ip4('192.0.2.2'))[0])
    L.append(lsa3(0x2021, 0, bytes([0x0f]) + (0x13).to_bytes(3, 'big') + tlv(1, rl) + tlv(77, bytes(4))))
    # E-Network LSA: attached routers TLV
    L.append(lsa3(0x2022, 0, bytes([0]) + (0x13).to_bytes(3, 'big') + tlv(2, ip4('192.0.2.1'))))
    # E-AS-External LSA: external prefix TLV
    ep = bytes([0x07]) + (30).to_bytes(3, 'big') + bytes([plen, 0x08, 0, 0]) + pbytes
    L.append(lsa3(0x4025, 0, tlv(5, ep)))
    # E-Link LSA: IPv6 link-local TLV, intra-area prefix TLV
    L.append(lsa3(0x2028, 0, bytes([1]) + (0x13).to_bytes(3, 'big') + tlv(7, ip6('fe80::1')) +
                  tlv(6, tlv_ip)))
    # E-Intra-area-prefix LSA
    L.append(lsa3(0x2029, 0, struct.pack('!HHI', 1, 0x2021, 0) + ip4('192.0.2.1') + tlv(6, tlv_ip)))
    return L


# ----------------------------------------------------------------- pcap

def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, p in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)) + p)


def main_frames():
    return v2_frames() + v2_opaque_frames() + v3_frames()


def malformed_frames():
    F = []
    hello = struct.pack('!4sHBB4s4s4s', ip4('255.255.255.0'), 10, 0x02, 1, struct.pack('!I', 40),
                        bytes(4), bytes(4))
    # reproducers of the fixed bugs: LSA with a too short LS length in LS Ack, LS Update, DB Desc
    F.append(frame4(ospf2(5, lsa2(1, '192.0.2.9', length=0))))
    F.append(frame4(ospf2(4, struct.pack('!I', 0xffffffff) + lsa2(1, '192.0.2.9', length=0))))
    F.append(frame4(ospf2(2, struct.pack('!HBBI', 1500, 0x42, 0x02, 1) + lsa2(1, '192.0.2.9', length=0))))
    # v3 LSA length below the header (fix 4)
    F.append(frame6(ospf3(4, struct.pack('!I', 1) + lsa3(0x2001, 0, length=8))))
    F.append(frame6(ospf3(5, lsa3(0x2001, 0, length=3))))
    # unknown LSA types, short type 2/3/5 LSAs (constraint expert infos)
    F.append(frame4(ospf2(4, struct.pack('!I', 1) + lsa2(6, '192.0.2.9', bytes(8)))))
    F.append(frame4(ospf2(4, struct.pack('!I', 1) + lsa2(2, '192.0.2.5', ip4('255.255.255.0')))))
    F.append(frame4(ospf2(4, struct.pack('!I', 1) + lsa2(3, '10.0.0.0', ip4('255.0.0.0')))))
    F.append(frame4(ospf2(4, struct.pack('!I', 1) + lsa2(5, '10.0.0.0', ip4('255.0.0.0')))))
    F.append(frame4(ospf2(4, struct.pack('!I', 1) + lsa2(10, opq_id(200, 1), bytes(8)))))
    # LSA length below the type minimum, unknown short
    F.append(frame4(ospf2(4, struct.pack('!I', 1) + lsa2(5, '10.0.0.0', bytes(20), length=24))))
    F.append(frame4(ospf2(4, struct.pack('!I', 1) + lsa2(77, '10.0.0.0', bytes(0), length=16))))
    # LSA with a header but no body (length 20) in an LS Update
    F.append(frame4(ospf2(4, struct.pack('!I', 1) + lsa2(1, '10.0.0.0'))))
    # reserved fields not zero (v3), bad checksums
    F.append(frame6(ospf3(1, struct.pack('!I', 7) + bytes([1, 0, 0, 0x13]) + struct.pack('!HH', 10, 40) +
                          bytes(8), reserved=5)))
    F.append(frame6(ospf3(2, bytes([1, 0, 0, 0x13]) + struct.pack('!HBBI', 1500, 1, 1, 1), cksum=0x1111)))
    F.append(frame6(ospf3(3, struct.pack('!HHI4s', 5, 0x2001, 0, ip4('192.0.2.1')))))
    F.append(frame4(ospf2(1, hello, cksum=0x1111)))
    # truncated by snaplen (unverifiable checksum) is covered by making the reported length larger
    F.append(frame4(ospf2(1, hello, length=100)))
    # v3 router LSA, bad prefix length > 128 and reserved fields set
    pl = bytes([0]) + (5).to_bytes(3, 'big') + bytes([200, 0, 0, 1]) + bytes(32)
    F.append(frame6(ospf3(4, struct.pack('!I', 1) + lsa3(0x2003, 1, pl))))
    body = bytes([9]) + (0x13).to_bytes(3, 'big') + struct.pack('!BBHIII', 1, 7, 10, 5, 6, 7)
    F.append(frame6(ospf3(4, struct.pack('!I', 1) + lsa3(0x2001, 0, bytes([0xff, 0, 0, 0x13]) + body[4:]))))
    # v3 link LSA with reserved set, inter area router with reserved
    F.append(frame6(ospf3(4, struct.pack('!I', 1) + lsa3(0x2004, 2, bytes([1, 0, 0, 0x13, 2, 0, 0, 5]) + bytes(4)))))
    F.append(frame6(ospf3(4, struct.pack('!I', 1) + lsa3(0x2003, 1, bytes([1, 0, 0, 5, 64, 0, 7, 7]) + bytes(8)))))
    # v3 unknown LSA type and E-intra-area etc handled in main; E-inter-area-prefix unknown
    F.append(frame6(ospf3(4, struct.pack('!I', 1) + lsa3(0x2023, 1, bytes(8)))))
    # LLS option bit but block missing (v2 and v3); LLS TLV with unknown type
    hello_l = struct.pack('!4sHBB4s4s4s', ip4('255.255.255.0'), 10, 0x12, 1, struct.pack('!I', 40), bytes(4), bytes(4))
    F.append(frame4(ospf2(1, hello_l)))
    # AT with too short a length
    F.append(frame6(ospf3(1, struct.pack('!I', 7) + bytes([1, 0, 4, 0x13]) + struct.pack('!HH', 10, 40) + bytes(8)) +
                    struct.pack('!HH', 1, 8) + bytes(8)))
    # truncated v2 header (6 bytes of header only is cut by the frame)
    F.append(frame4(ospf2(1, hello)[:30]))
    # MPLS: bandwidth constraints with a bad length / too many / none / reserved bytes set
    def mpls_frame(sub, ltype=10):
        link = tlv(2, sub)
        return frame4(ospf2(4, struct.pack('!I', 1) + lsa2(ltype, opq_id(1, 1), link, opts=0x20)))
    F.append(mpls_frame(tlv(17, bytes([1, 0, 0, 0]) + bytes(5), False) + bytes(3)))
    F.append(mpls_frame(tlv(17, bytes([1, 0, 0, 0]) + b''.join(flt(1.0) for _ in range(9)))))
    F.append(mpls_frame(tlv(17, bytes([1, 0, 0, 0]))))
    F.append(mpls_frame(tlv(17, bytes([1, 9, 9, 9]) + flt(1.0))))
    # unidirectional delay with reserved bits
    F.append(mpls_frame(tlv(27, bytes([0x7f]) + (1).to_bytes(3, 'big')) +
                        tlv(28, bytes([0x7f]) + (1).to_bytes(3, 'big') + bytes([9]) + (2).to_bytes(3, 'big')) +
                        tlv(29, bytes([9]) + (1).to_bytes(3, 'big'))))
    # TNA sub-TLV too short and unknown
    tna = tlv(32768, struct.pack('!HH', 32777, 2) + bytes(4))
    F.append(frame4(ospf2(4, struct.pack('!I', 1) + lsa2(10, opq_id(1, 2), tna, opts=0x20))))
    tna = tlv(32768, tlv(5, bytes(4)))
    F.append(frame4(ospf2(4, struct.pack('!I', 1) + lsa2(10, opq_id(1, 3), tna, opts=0x20))))
    # reserved fields of the opaque TLVs
    ri = tlv(9, (10).to_bytes(3, 'big') + bytes([5]) + tlv(1, (1).to_bytes(3, 'big'))) + \
        tlv(15, bytes([1, 1, 1, 1]))
    F.append(frame4(ospf2(4, struct.pack('!I', 1) + lsa2(10, opq_id(4, 1), ri, opts=0x20))))
    ep = tlv(1, struct.pack('!BBBB', 3, 24, 0, 0) + ip4('10.1.1.0') +
             tlv(2, struct.pack('!BBBB', 0, 9, 0, 1) + struct.pack('!I', 16002)) +
             tlv(3, struct.pack('!BBHI', 128, 0x80, 0x0100, 500)[0:4] + bytes([9, 9, 9, 0]) + struct.pack('!I', 5)))
    ep += tlv(2, struct.pack('!BBHBBBB', 24, 0, 5, 0x80, 1, 1, 1) + ip4('10.2.0.0'))
    F.append(frame4(ospf2(4, struct.pack('!I', 1) + lsa2(10, opq_id(7, 3), ep, opts=0x20))))
    el = tlv(1, struct.pack('!BBBB', 1, 1, 1, 1) + ip4('192.0.2.2') + ip4('192.0.2.1') +
             tlv(2, struct.pack('!BBBB', 0xf8, 0, 0, 10) + struct.pack('!I', 24002)) +
             tlv(3, struct.pack('!BBBB', 0x60, 5, 0, 1) + ip4('192.0.2.2') + struct.pack('!I', 24004)) +
             tlv(10, bytes([0, 0, 0, 5, 0, 0, 0, 0]) + tlv(12, bytes([0x7f]) + (33).to_bytes(3, 'big')) +
                 tlv(13, bytes([0x7f]) + (3).to_bytes(3, 'big') + bytes([9]) + (9).to_bytes(3, 'big')) +
                 tlv(14, bytes([9]) + (5).to_bytes(3, 'big'))))
    F.append(frame4(ospf2(4, struct.pack('!I', 1) + lsa2(10, opq_id(8, 2), el, opts=0x20))))
    # extended inter-area ASBR: short TLV, long sub-TLV, wrong FAAM length
    F.append(frame4(ospf2(4, struct.pack('!I', 1) + lsa2(11, opq_id(11, 2), struct.pack('!HH', 1, 2) + bytes(4), opts=0x20))))
    F.append(frame4(ospf2(4, struct.pack('!I', 1) + lsa2(11, opq_id(11, 3), tlv(1, ip4('1.1.1.1') + struct.pack('!HH', 1, 200) + bytes(4)), opts=0x20))))
    F.append(frame4(ospf2(4, struct.pack('!I', 1) + lsa2(11, opq_id(11, 4), tlv(1, ip4('1.1.1.1') + tlv(1, bytes(4))) + bytes(0), opts=0x20))))
    F.append(frame4(ospf2(4, struct.pack('!I', 1) + lsa2(11, opq_id(11, 5), tlv(1, ip4('1.1.1.1') + tlv(1, bytes([1, 9, 9, 9]) + struct.pack('!I', 5))), opts=0x20))))
    # RI with an unknown TLV longer than the LSA, ext prefix etc
    F.append(frame4(ospf2(4, struct.pack('!I', 1) + lsa2(10, opq_id(4, 2), struct.pack('!HH', 77, 200) + bytes(4), opts=0x20))))
    F.append(frame4(ospf2(4, struct.pack('!I', 1) + lsa2(10, opq_id(7, 4), struct.pack('!HH', 77, 200) + bytes(4), opts=0x20))))
    F.append(frame4(ospf2(4, struct.pack('!I', 1) + lsa2(10, opq_id(8, 3), struct.pack('!HH', 77, 200) + bytes(4), opts=0x20))))
    F.append(frame4(ospf2(4, struct.pack('!I', 1) + lsa2(11, opq_id(11, 6), struct.pack('!HH', 77, 200) + bytes(4), opts=0x20))))
    # flex algo prefix metric with reserved bytes set
    ep = tlv(1, struct.pack('!BBBB', 3, 24, 0, 0) + ip4('10.1.1.0') + tlv(3, bytes([128, 0x80, 1, 2, 0, 0, 0, 5])))
    F.append(frame4(ospf2(4, struct.pack('!I', 1) + lsa2(10, opq_id(7, 5), ep, opts=0x20))))
    # v3 network LSA with a reserved byte, link LSA with reserved prefix field
    F.append(frame6(ospf3(4, struct.pack('!I', 1) + lsa3(0x2002, 5, bytes([1, 0, 0, 0x13]) + ip4('192.0.2.1')))))
    ll = bytes([1]) + (0x13).to_bytes(3, 'big') + ip6('fe80::1') + struct.pack('!I', 1)
    F.append(frame6(ospf3(4, struct.pack('!I', 1) + lsa3(0x0008, 3, ll + pfx3(64, 1, '2001:db8:1::', 7)))))
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'ospf-coverage.pcap'), main_frames())
    write_pcap(os.path.join(out, 'ospf-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()
