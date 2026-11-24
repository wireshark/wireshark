#!/usr/bin/env python3
# Generates test/captures/lisp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the LISP control plane
dissector (packet-lisp.c).

LISP control messages use UDP port 4342, which is registered, so no
Decode As is needed. Every packet is built from scratch with struct; no
captured traffic is used. Authentication data fields hold placeholder
bytes only (zeros); no key or MAC is computed.

Usage: mklisp.py <output directory>

Writes:
  lisp-coverage.pcap            every control message type (Map-Request,
                                Map-Reply, Map-Register, Map-Notify,
                                Map-Referral, Info-Request/Reply, ECM) with
                                every address family, every LCAF type and
                                the reproducers of the fixes on the branch
  lisp-coverage-malformed.pcap  unexpected AFIs, truncated records
"""

import os
import struct
import sys

AFI_IP, AFI_IP6, AFI_LCAF, AFI_MAC, AFI_DN = 1, 2, 16387, 6, 17
V4 = bytes([192, 0, 2, 1])
V4B = bytes([198, 51, 100, 7])
V6 = bytes([0x20, 0x01, 0x0d, 0xb8] + [0] * 11 + [1])
V6B = bytes([0x20, 0x01, 0x0d, 0xb8] + [0] * 11 + [9])
MAC = bytes.fromhex('0200c0a80001')
DN = b'eid.example\0'


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ipv4_pkt(proto, l4, src='192.0.2.1', dst='192.0.2.2'):
    sa = bytes(map(int, src.split('.')))
    da = bytes(map(int, dst.split('.')))
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(l4), 0, 0, 64, proto, 0, sa, da)
    return ip[:10] + struct.pack('!H', csum(ip)) + ip[12:] + l4


def ipv6_pkt(proto, l4, src=V6, dst=V6B):
    return struct.pack('!IHBB16s16s', 0x60000000, len(l4), proto, 64, src, dst) + l4


def udp(payload, sport, dport, src=None, dst=None):
    u = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    if src is not None and len(src) == 16:
        ck = csum(src + dst + struct.pack('!IBBBB', len(u), 0, 0, 0, 17) + u) or 0xffff
        u = u[:6] + struct.pack('!H', ck) + u[8:]
    return u


def eth4(ip):
    return bytes.fromhex('020000000002020000000001') + b'\x08\x00' + ip


def eth6(ip):
    return bytes.fromhex('020000000002020000000001') + b'\x86\xdd' + ip


def ctl(payload, sport=4343, dport=4342, v6=False):
    if v6:
        return eth6(ipv6_pkt(17, udp(payload, sport, dport, V6, V6B)))
    return eth4(ipv4_pkt(17, udp(payload, sport, dport)))


def pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)


# ---- addresses -------------------------------------------------------------

def afi_addr(kind):
    """AFI + address for a simple address kind."""
    return {'none': struct.pack('!H', 0),
            'v4': struct.pack('!H', AFI_IP) + V4,
            'v6': struct.pack('!H', AFI_IP6) + V6,
            'mac': struct.pack('!H', AFI_MAC) + MAC,
            'mac2': struct.pack('!H', 1 << 15 | 0) [:0] + struct.pack('!H', 6) + MAC,
            'dn': struct.pack('!H', AFI_DN) + DN}[kind]


def lcaf(t, body, flags=0, rsvd2=0):
    """LCAF after the AFI 16387: header plus body."""
    return struct.pack('!BBBBH', 0, flags, t, rsvd2, len(body)) + body


def lcaf_afi(t, body, **kw):
    return struct.pack('!H', AFI_LCAF) + lcaf(t, body, **kw)


def iid(n, addr):
    return lcaf_afi(2, struct.pack('!I', n) + addr)


def asn(n, addr):
    return lcaf_afi(3, struct.pack('!I', n) + addr)


def geo(addr, lat_n=True, lon_e=True, alt=1200, latdeg=45, mn=30, sc=15, londeg=122, lonmin=10, lonsec=5):
    body = struct.pack('!HBB', (0x8000 if lat_n else 0) | latdeg, mn, sc)
    body += struct.pack('!HBB', (0x8000 if lon_e else 0) | londeg, lonmin, lonsec)
    body += struct.pack('!I', alt) + addr
    return lcaf_afi(5, body)


def nonce_loc(nonce, addr):
    return lcaf_afi(8, b'\x00' + struct.pack('!I', nonce)[1:] + addr)


def mcinfo(i, srcml, grpml, src, grp, flags=0):
    body = struct.pack('!IHBB', i, 0, srcml, grpml) + src + grp
    return lcaf_afi(9, body, rsvd2=flags)


def elp(hops):
    return lcaf_afi(10, b''.join(struct.pack('!H', f) + a for f, a in hops))


def srcdst(sml, dml, src, dst):
    return lcaf_afi(12, struct.pack('!HBB', 0, sml, dml) + src + dst)


def rle(entries):
    return lcaf_afi(13, b''.join(b'\x00\x00\x00' + bytes([lv]) + a for lv, a in entries))


def kv(k, v):
    return lcaf_afi(15, k + v)


def vendor(oui, data):
    return lcaf_afi(255, b'\x00' + oui + data)


def natt(msport, etrport, g, ms, p, rtrs):
    return lcaf_afi(7, struct.pack('!HH', msport, etrport) + g + ms + p + b''.join(rtrs))


def afilist(items):
    return lcaf_afi(1, b''.join(items))


# ---- records ---------------------------------------------------------------

def locator(addr, prio=1, w=100, mp=255, mw=0, flags=0x5):
    return struct.pack('!BBBBH', prio, w, mp, mw, flags) + addr


def mapping(eid, masklen, locs, ttl=1440, act=0, auth=1, inc=0, ver=0, sig=0, res=0, referral=False):
    flags = (act << 13) | (0x1000 if auth else 0) | (0x0800 if inc else 0) | res
    w2 = (sig << 12 if referral else 0) | ver
    return struct.pack('!IBBHH', ttl, len(locs), masklen, flags, w2) + eid + b''.join(locs)


# ---- messages --------------------------------------------------------------

NONCE = bytes.fromhex('1122334455667788')
AUTH = b'\x00' * 20   # placeholder authentication data, no real key


def mreq(src, itrs, recs, flags=0, irc=None, nonce=NONCE, rsvd=0, mapreply=b''):
    irc = len(itrs) - 1 if irc is None else irc
    w = (1 << 20) | flags | rsvd | irc
    return (struct.pack('!I', w)[1:] + bytes([len(recs)]) + nonce + src +
            b''.join(itrs) + b''.join(recs) + mapreply)


def mreq_rec(plen, addr, res=0):
    return bytes([res, plen]) + addr


A_, M_, P_, S_, p_, s_ = 0x080000, 0x040000, 0x020000, 0x010000, 0x008000, 0x004000


def mrep(recs, flags=0, nonce=NONCE, rsvd=0):
    w = (2 << 20) | flags | rsvd
    return struct.pack('!I', w)[1:] + bytes([len(recs)]) + nonce + b''.join(recs)


def mreg(recs, flags=0, nonce=NONCE, keyid=1, auth=AUTH, tail=b'', authlen=None, mtype=3, rsvd=0):
    w = (mtype << 20) | flags | rsvd
    return (struct.pack('!I', w)[1:] + bytes([len(recs)]) + nonce +
            struct.pack('!HH', keyid, len(auth) if authlen is None else authlen) + auth +
            b''.join(recs) + tail)


XTRID = bytes(range(16))
SITEID = bytes(range(0x20, 0x28))


def mnot(recs, flags=0, tail=b'', **kw):
    return mreg(recs, flags=flags, tail=tail, mtype=4, **kw)


def mref(recs, nonce=NONCE, rsvd=0):
    return struct.pack('!I', (6 << 20) | rsvd)[1:] + bytes([len(recs)]) + nonce + b''.join(recs)


def info(reply, prefix_afi, plen, pref, trailer, ttl=1440, auth=AUTH, keyid=1, afi_trailer=None):
    b = struct.pack('!I', (7 << 28) | (0x08000000 if reply else 0))
    b += NONCE + struct.pack('!HH', keyid, len(auth)) + auth
    b += struct.pack('!IBBH', ttl, 0, plen, prefix_afi) + pref + trailer
    return b


def ecm(inner, flags=0):
    return struct.pack('!I', (8 << 28) | flags) + inner


def inner_v4(lisp_msg, dport=4342):
    return ipv4_pkt(17, udp(lisp_msg, 4342, dport), '203.0.113.1', '203.0.113.2')


def inner_v6(lisp_msg, dport=4342):
    return ipv6_pkt(17, udp(lisp_msg, 4342, dport, V6, V6B))


EID4 = struct.pack('!H', AFI_IP) + V4


def build_main():
    F = []
    c = lambda p, **kw: F.append(ctl(p, **kw))
    itr4 = [struct.pack('!H', AFI_IP) + V4B]
    itr6 = [struct.pack('!H', AFI_IP6) + V6B]
    # --- Map-Request ----------------------------------------------------
    rec4 = mreq_rec(32, struct.pack('!H', AFI_IP) + V4)
    c(mreq(afi_addr('v4'), itr4, [rec4]))
    c(mreq(afi_addr('v6'), itr6, [mreq_rec(128, afi_addr('v6'))]), v6=True)
    # all flags (A M P S p s) with the M bit and a Map-Reply record, 2 ITR
    # RLOCs (IPv4 and IPv6), reserved bits set
    mrec = mapping(afi_addr('v4'), 24, [locator(afi_addr('v4')), locator(afi_addr('v6'), flags=0x3)], act=2)
    c(mreq(afi_addr('mac'), [itr4[0], itr6[0]], [rec4, mreq_rec(0, afi_addr('v6'))],
           flags=A_ | M_ | P_ | S_ | p_ | s_, rsvd=0x20, mapreply=mrec))
    c(mreq(afi_addr('none'), itr4, [rec4], flags=P_))                  # not set source EID, probe
    c(mreq(afi_addr('v4'), itr4, [rec4], flags=S_ | s_))
    c(mreq(afi_addr('v4'), itr4, [rec4], flags=p_))
    # source EID as LCAF (Instance ID with an IPv4 address); records: MAC,
    # distinguished name, IPv6 and LCAF prefixes
    c(mreq(iid(5000, afi_addr('v4')), itr4,
           [mreq_rec(48, afi_addr('mac')), mreq_rec(0, afi_addr('dn')), mreq_rec(64, afi_addr('v6')),
            mreq_rec(32, iid(7, afi_addr('v4')))]))
    c(mreq(afi_addr('v4'), itr4, [mreq_rec(32, iid(7, afi_addr('v6')))]))
    c(mreq(afi_addr('v4'), itr4, [mreq_rec(32, iid(7, afi_addr('v4')))]))
    # --- Map-Reply -------------------------------------------------------
    loc4 = locator(afi_addr('v4'))
    loc6 = locator(afi_addr('v6'), prio=2, w=50, flags=0x2)
    c(mrep([mapping(afi_addr('v4'), 24, [loc4, loc6])], flags=0))
    c(mrep([mapping(afi_addr('v6'), 64, [loc4])], flags=0x080000))        # RLOC-probe reply (P bit)
    c(mrep([mapping(afi_addr('mac'), 48, [loc6], act=1, ttl=0xffffffff),
            mapping(afi_addr('dn'), 0, [], act=3, auth=0, ver=0xabc, res=0x0e00),
            mapping(iid(9, afi_addr('v4')), 24, [locator(iid(10, afi_addr('v6')))], act=4)],
           flags=0x040000 | 0x020000))
    c(mrep([mapping(afi_addr('v4'), 24, [loc4], act=5), mapping(afi_addr('v4'), 25, [loc4], act=6),
            mapping(afi_addr('v4'), 26, [loc4], act=7)], rsvd=0x1ffff & 0x00100))
    # --- Map-Reply carrying every LCAF type as the locator ----------------
    lc = []
    lc.append(('null', lcaf_afi(0, b'')))
    lc.append(('afi-list', afilist([afi_addr('v4'), afi_addr('v6'), afi_addr('mac'), afi_addr('dn'),
                                    struct.pack('!H', AFI_LCAF) + lcaf(2, struct.pack('!I', 3) + afi_addr('v4'))])))
    for name, a in (('v4', afi_addr('v4')), ('v6', afi_addr('v6')), ('mac', afi_addr('mac')),
                    ('dn', afi_addr('dn')), ('none', afi_addr('none')),
                    ('lcaf', struct.pack('!H', AFI_LCAF) + lcaf(2, struct.pack('!I', 77) + afi_addr('v4')))):
        lc.append(('iid-' + name, iid(1000 + len(lc), a)))
        lc.append(('asn-' + name, asn(64496 + len(lc), a)))
    for name, a in (('v4', afi_addr('v4')), ('v6', afi_addr('v6')), ('mac', afi_addr('mac')),
                    ('dn', afi_addr('dn')), ('none', afi_addr('none')),
                    ('lcaf', struct.pack('!H', AFI_LCAF) + lcaf(2, struct.pack('!I', 77) + afi_addr('v4')))):
        lc.append(('geo-' + name, geo(a, lat_n=len(lc) % 2 == 0, lon_e=len(lc) % 3 == 0)))
        lc.append(('nonce-' + name, nonce_loc(0xcafe00 + len(lc), a)))
    lc.append(('geo-noalt', geo(afi_addr('v4'), alt=0x7fffffff)))
    lc.append(('geo-bad', geo(afi_addr('v4'), latdeg=95, mn=61, sc=62, londeg=181, lonmin=63, lonsec=64)))
    lc.append(('natt', natt(4342, 4341, afi_addr('v4'), afi_addr('v6'), afi_addr('v4'),
                            [afi_addr('v4'), afi_addr('v6'), afi_addr('v4')])))
    lc.append(('natt-lcaf', natt(4342, 4341, afi_addr('none'), afi_addr('v4'),
                                 struct.pack('!H', AFI_LCAF) + lcaf(2, struct.pack('!I', 5) + afi_addr('v4')),
                                 [afi_addr('v6'), afi_addr('v6')])))
    for sk, gk in (('v4', 'v4'), ('v6', 'v6')):
        pass
    lc.append(('mcinfo', mcinfo(5, 32, 32, afi_addr('v4'), afi_addr('v4'), flags=0x07)))
    lc.append(('mcinfo6', mcinfo(6, 128, 128, afi_addr('v6'), afi_addr('v6'), flags=0x00)))
    lc.append(('mcinfo-lcaf', mcinfo(5, 24, 24, struct.pack('!H', AFI_LCAF) + lcaf(2, struct.pack('!I', 5) + afi_addr('v4')),
                                     struct.pack('!H', AFI_LCAF) + lcaf(3, struct.pack('!I', 5) + afi_addr('v6')), flags=0x02)))
    lc.append(('elp', elp([(0x7, afi_addr('v4')), (0x2, afi_addr('v6')), (0x1, afi_addr('v4')), (0x0, afi_addr('v6')),
                           (0x0, struct.pack('!H', AFI_LCAF) + lcaf(2, struct.pack('!I', 5) + afi_addr('v4')))])))
    for name, a in (('v4', afi_addr('v4')), ('v6', afi_addr('v6')), ('mac', afi_addr('mac')),
                    ('lcaf', struct.pack('!H', AFI_LCAF) + lcaf(2, struct.pack('!I', 77) + afi_addr('v4')))):
        lc.append(('srcdst-' + name, srcdst(24, 32, a, a)))
    lc.append(('rle', rle([(1, afi_addr('v4')), (2, afi_addr('v6')),
                           (3, struct.pack('!H', AFI_LCAF) + lcaf(2, struct.pack('!I', 5) + afi_addr('v4')))])))
    for name, a in (('v4', afi_addr('v4')), ('v6', afi_addr('v6')), ('mac', afi_addr('mac')),
                    ('dn', afi_addr('dn')),
                    ('lcaf', struct.pack('!H', AFI_LCAF) + lcaf(2, struct.pack('!I', 77) + afi_addr('v4')))):
        lc.append(('kv-' + name, kv(a, a)))
    lc.append(('vendor', vendor(b'\x00\x00\x0c', b'vendor-data')))
    # types not decoded: Application Data, Opaque Key, Security Key (a
    # placeholder, no key material), JSON Data Model, unknown type
    for t in (4, 6, 11, 14, 99):
        lc.append(('undecoded-%d' % t, lcaf_afi(t, b'\x01\x02\x03\x04')))
    one = [x for n, x in lc]
    for i in range(0, len(one), 6):
        grp = one[i:i + 6]
        c(mrep([mapping(afi_addr('v4'), 24, [locator(x, flags=0x7) for x in grp])]))
    # --- Map-Register ---------------------------------------------------
    rl = [mapping(afi_addr('v4'), 24, [loc4, loc6])]
    c(mreg(rl, flags=0x080000 | 0x040000 | 0x000001))                    # P S M
    c(mreg(rl, flags=0x020000, tail=XTRID + SITEID))                    # I: xTR-ID, site-ID
    c(mreg(rl + [mapping(afi_addr('v6'), 48, [loc6])], flags=0x010000 | 0x020000, tail=XTRID + SITEID))  # R I
    c(mreg([], keyid=2, auth=b'', rsvd=0x2))
    # --- Map-Notify --------------------------------------------------------
    c(mnot(rl, flags=0))
    c(mnot(rl, flags=0x080000, tail=XTRID + SITEID))                    # I
    c(mnot(rl, flags=0x040000 | 0x080000, tail=XTRID + SITEID + struct.pack('!HH', 3, 20) + AUTH))  # R I
    c(mnot(rl, flags=0x040000, tail=struct.pack('!HH', 3, 0)))
    # --- Map-Referral ----------------------------------------------------
    c(mref([mapping(afi_addr('v4'), 24, [loc4], act=0, referral=True, sig=3, inc=1),
            mapping(afi_addr('v6'), 48, [loc6], act=1, referral=True, auth=0),
            mapping(afi_addr('mac'), 48, [], act=2, referral=True),
            mapping(afi_addr('v4'), 24, [], act=3, referral=True),
            mapping(afi_addr('v4'), 24, [], act=4, referral=True),
            mapping(afi_addr('v4'), 24, [], act=5, referral=True),
            mapping(afi_addr('v4'), 24, [], act=6, referral=True)], rsvd=0x1))
    c(mref([mapping(afi_addr('v4'), 24, [loc4], referral=True)]))
    # --- Info-Request / Info-Reply ------------------------------------------
    c(info(False, AFI_IP, 32, V4, struct.pack('!H', 0)))
    c(info(False, AFI_IP6, 128, V6, struct.pack('!H', 0)))
    nat = natt(4342, 4341, afi_addr('v4'), afi_addr('v6'), afi_addr('v4'), [afi_addr('v4')])
    c(info(True, AFI_IP, 32, V4, nat))
    c(info(True, AFI_IP6, 128, V6, nat))
    # --- Encapsulated Control Messages -------------------------------------
    req = mreq(afi_addr('v4'), itr4, [rec4])
    req6 = mreq(afi_addr('v6'), itr6, [mreq_rec(128, afi_addr('v6'))])
    c(ecm(inner_v4(req)))
    c(ecm(inner_v6(req6), flags=0x04000000))                            # DDT-originated
    c(ecm(inner_v4(req), flags=0x08000000 | 0x04000000))
    c(ecm(b'\x00\x01\x02\x03'))                                         # not IP
    c(ecm(inner_v4(mreq(afi_addr('v4'), itr4, [rec4], flags=S_)), flags=0))
    # --- Reproducers of the fixes on the branch ---------------------------------
    # 1. unknown LCAF type in an AFI List: the depth leaked, 600 entries hit
    #    the dissection depth assertion
    entry = struct.pack('!H', AFI_LCAF) + lcaf(100, b'')
    c(mreq(afilist_src(entry * 520), itr4, [rec4]))
    # 2. nested Instance ID chain (get_addr_str recursion)
    def chain(n, t=2):
        body = struct.pack('!I', 0) + afi_addr('v4')
        a = lcaf(t, body)
        for _ in range(n - 1):
            a = lcaf(t, struct.pack('!IH', 0, AFI_LCAF) + a)
        return struct.pack('!H', AFI_LCAF) + a
    c(mreq(chain(40), itr4, [rec4]))
    c(mreq(chain(12, 3), itr4, [rec4]))                                 # AS Number chain
    # 3. several chains in an AFI list
    lst = b''.join(chain(30) for _ in range(3))
    c(mreq(struct.pack('!H', AFI_LCAF) + lcaf(1, lst), itr4, [rec4]))
    return F


def afilist_src(items):
    return struct.pack('!H', AFI_LCAF) + lcaf(1, items)


E_ = 0x040000


def build_malformed():
    F = []
    c = lambda p, **kw: F.append(ctl(p, **kw))
    itr4 = [struct.pack('!H', AFI_IP) + V4B]
    rec4 = mreq_rec(32, struct.pack('!H', AFI_IP) + V4)
    unk = struct.pack('!H', 99) + b'\x01\x02\x03\x04'
    # unexpected AFIs everywhere
    c(mreq(unk, itr4, [rec4]))                                          # source EID
    c(mreq(afi_addr('v4'), [unk], [rec4]))                              # ITR-RLOC
    c(mreq(afi_addr('v4'), itr4, [mreq_rec(32, unk)]))                  # record prefix
    c(mrep([mapping(unk, 24, [locator(afi_addr('v4'))])]))              # EID prefix
    c(mrep([mapping(afi_addr('v4'), 24, [locator(unk)])]))              # locator
    c(mreg([mapping(unk, 24, [])]))
    c(info(False, 99, 24, b'\x01\x02\x03\x04', struct.pack('!H', 0)))
    c(info(False, AFI_IP, 32, V4, struct.pack('!H', 5)))                # request with a non-zero AFI
    c(info(True, AFI_IP, 32, V4, struct.pack('!H', 1) + V4))            # reply without LCAF
    # unknown AFIs inside LCAFs
    for body_fn in (
        lambda u: afilist_src(afi_addr('v4') + u),
        lambda u: iid(1, u), lambda u: asn(1, u), lambda u: geo(u),
        lambda u: nonce_loc(7, u),
        lambda u: mcinfo(1, 1, 1, u, afi_addr('v4')),
        lambda u: mcinfo(1, 1, 1, afi_addr('v4'), u),
        lambda u: elp([(0, u)]), lambda u: rle([(1, u)]),
        lambda u: srcdst(1, 1, u, afi_addr('v4')),
        lambda u: srcdst(1, 1, afi_addr('v4'), u),
        lambda u: kv(u, afi_addr('v4')), lambda u: kv(afi_addr('v4'), u),
        lambda u: natt(1, 2, u, afi_addr('v4'), afi_addr('v4'), []),
    ):
        u = struct.pack('!H', 99) + b'\x00\x00\x00\x00'
        src = body_fn(u)
        if src[:2] != struct.pack('!H', AFI_LCAF):
            src = struct.pack('!H', AFI_LCAF) + src
        c(mrep([mapping(afi_addr('v4'), 24, [locator(src)])]))
    # bad end of the unexpected AFI inside the AFI list: returns the offset
    c(mrep([mapping(afi_addr('v4'), 24, [locator(afilist_src(unk + afi_addr('v4')))])]))
    # messages cut short
    c(mreq(afi_addr('v4'), itr4, [rec4])[:20])
    c(mrep([mapping(afi_addr('v4'), 24, [locator(afi_addr('v4'))])])[:20])
    c(mreg([mapping(afi_addr('v4'), 24, [])])[:25])
    c(mnot([mapping(afi_addr('v4'), 24, [])], flags=0x040000)[:26])
    c(mref([mapping(afi_addr('v4'), 24, [locator(afi_addr('v4'))], referral=True)])[:16])
    c(info(True, AFI_IP, 32, V4, struct.pack('!H', AFI_LCAF) + b'\x00\x00\x02'))
    c(b'\x10')
    c(b'\x50\x00\x00\x00\x01\x02')                                       # unknown LISP type 5: data
    c(b'\xf0\x00\x00\x00')
    # LCAF with a length that does not match the content
    bad = struct.pack('!H', AFI_LCAF) + struct.pack('!BBBBH', 0, 0, 2, 0, 3) + b'\x00\x00\x00'
    c(mrep([mapping(afi_addr('v4'), 24, [locator(bad)])]))
    # ECM with a truncated inner IPv4 header (exception); the next frame
    # shows the file-scope "encapsulated" flag stuck on
    F.append(ctl(struct.pack('!I', 8 << 28) + bytes([0x45, 0, 0])))
    F.append(ctl(mrep([mapping(afi_addr('v4'), 24, [locator(afi_addr('v4'))])])))
    return F


def main():
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    pcap(os.path.join(out, 'lisp-coverage.pcap'), build_main())
    pcap(os.path.join(out, 'lisp-coverage-malformed.pcap'), build_malformed())


if __name__ == '__main__':
    main()
