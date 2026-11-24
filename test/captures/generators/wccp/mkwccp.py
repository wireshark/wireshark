#!/usr/bin/env python3
# Generates test/captures/wccp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures for the WCCP dissector (packet-wccp.c,
Web Cache Communication Protocol versions 1, 2.0 and 2.01).

WCCP runs over UDP port 2048 (registered by default). Version 1 has the
fixed messages Here I Am (7), I See You (8) and Assign Bucket (9);
version 2 has a header (type, version, length) followed by components
(Security, Service, Router Identity, Web-Cache Identity, Router/Web-Cache
View, Assignment, Query, Capabilities, Alternate Assignment, Assignment
Map, Command Extension, Alternative Assignment Map and the 2.01 Address
Table). With an address table every address is a 32-bit index into it.
Every packet is built with struct from the specification; nothing comes
from a real network. Addresses are from 192.0.2.0/24 and 198.51.100.0/24.

Usage: mkwccp.py <output directory>

Writes:
  wccp-coverage.pcap            main capture (no malformed packets, no
                                error expert infos)
  wccp-coverage-malformed.pcap  paths only malformed input reaches
"""
import os
import socket
import struct
import sys

P = struct.pack

# ------------------------------------------------------------------ pcap


def pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(P('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, d in enumerate(frames):
            f.write(P('<IIII', 1700000000 + i, 0, len(d), len(d)))
            f.write(d)


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def udp_frame(payload, src='192.0.2.1', dst='192.0.2.2', sport=2048,
              dport=2048, ident=[1]):
    udp = P('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    ident[0] += 1
    ip = P('!BBHHHBBH', 0x45, 0, 20 + len(udp), ident[0], 0, 64, 17, 0)
    ip += socket.inet_aton(src) + socket.inet_aton(dst)
    ip = ip[:10] + P('!H', csum(ip)) + ip[12:]
    return (bytes.fromhex('020000000002020000000001') + b'\x08\x00' + ip + udp)


def ip4(s):
    return socket.inet_aton(s)


# ------------------------------------------------- address encoding state

TABLE = None      # list of address strings when an address table is in use


def A(addr):
    """An address field: a raw IPv4 address, or its 32-bit table index."""
    if addr is None:
        return P('>I', 0)
    if TABLE is None:
        return ip4(addr)
    return P('>I', TABLE.index(addr) + 1)


def IDX(n):
    return P('>I', n)


# ------------------------------------------------------------ components

def item(t, data):
    return P('>HH', t, len(data)) + data


def sec(md5=False, opt=None):
    if md5:
        return item(0, P('>I', 1) + bytes(range(16)))
    return item(0, P('>I', 0 if opt is None else opt))


SF_SRC_IP, SF_DST_IP, SF_SRC_PORT, SF_DST_PORT = 1, 2, 4, 8
SF_PORTS, SF_PORTS_SRC, SF_R0 = 0x10, 0x20, 0x40
SF_ALT = 0x100 | 0x200 | 0x400 | 0x800


def svc(stype=0, sid=0, prio=0, proto=0, flags=0, ports=()):
    ports = list(ports) + [0] * (8 - len(ports))
    return item(1, bytes([stype, sid, prio, proto]) + P('>I', flags)
                + P('>8H', *ports))


def rid_element(ip, rid):
    return A(ip) + P('>I', rid)


def rid(ip, r, sendto, recv):
    return item(2, rid_element(ip, r) + A(sendto) + P('>I', len(recv))
                + b''.join(A(x) for x in recv))


def hash_data(pattern=0xa5, weight=10, status=1):
    return bytes((pattern + i * 3) & 0xff for i in range(32)) + P('>HH', weight, status)


def mask_elem(sip=0, dip=0, sp=0, dp=0):
    return P('>IIHH', sip, dip, sp, dp)


def value_elem(sip, dip, sp, dp, wc):
    return A(sip) + A(dip) + P('>HH', sp, dp) + A(wc)


def mv_list(elems):
    """elems: list of (mask element bytes, [value element bytes])"""
    out = P('>I', len(elems))
    for m, vals in elems:
        out += m + P('>I', len(vals)) + b''.join(vals)
    return out


def alt_mv_list(elems):
    """elems: list of (mask element bytes, [(wc ip, [seq numbers])])"""
    out = P('>I', len(elems))
    for m, wcs in elems:
        out += m + P('>I', len(wcs))
        for wc, seqs in wcs:
            out += A(wc) + P('>I', len(seqs)) + b''.join(P('>I', s) for s in seqs)
    return out


WC_HIST, WC_VER = 1, 8


def wc_flags(atype, hist=0, ver=0):
    return hist | (atype << 1) | (ver << 3)


def wc_elem(ip, atype, data=b'', hashrev=0, hist=0, ver=0):
    return A(ip) + P('>HH', hashrev, wc_flags(atype, hist, ver)) + data


def mask_data(elems, weight=5, status=2):
    return mv_list(elems) + P('>HH', weight, status)


def alt_mask_data(elems, weight=5, status=2):
    return alt_mv_list(elems) + P('>HH', weight, status)


def ext_data(atype, payload):
    return P('>HH', atype, len(payload)) + payload


def wcid(ip, atype, data=b'', **kw):
    return item(3, wc_elem(ip, atype, data, **kw))


def rtr_view(change, key_ip, key_chg, routers, wcs):
    return item(4, P('>I', change) + A(key_ip) + P('>I', key_chg)
                + P('>I', len(routers)) + b''.join(A(r) for r in routers)
                + P('>I', len(wcs)) + b''.join(wcs))


def wc_view(change, routers, wcs):
    return item(5, P('>I', change) + P('>I', len(routers))
                + b''.join(rid_element(r, i + 1) for i, r in enumerate(routers))
                + P('>I', len(wcs)) + b''.join(A(w) for w in wcs))


def buckets(wcs, pattern=0):
    out = bytes((i * 7 + pattern) % (len(wcs) if wcs else 1) if (i + pattern) % 5 else
                0xff for i in range(256))
    return out


def hash_buckets(wcs, pattern=0):
    return P('>I', len(wcs)) + b''.join(A(w) for w in wcs) + buckets(wcs, pattern)


def assign_info(key_ip, key_chg, routers, wcs, pattern=0):
    """routers: list of (ip, rid, change)"""
    return (A(key_ip) + P('>I', key_chg) + P('>I', len(routers))
            + b''.join(rid_element(r, i) + P('>I', c) for r, i, c in routers)
            + hash_buckets(wcs, pattern))


def assignment(key_ip, key_chg, routers, wcs, pattern=0):
    return item(6, assign_info(key_ip, key_chg, routers, wcs, pattern))


def query(ip, r, sendto, target):
    return item(7, rid_element(ip, r) + A(sendto) + A(target))


def cap(t, value):
    return P('>HH', t, len(value)) + value


def caps(*elems):
    return item(8, b''.join(elems))


def alt_assign(atype, key_ip, key_chg, routers, body, length=None):
    """routers: list of (ip, rid, change); body depends on the type"""
    inner = (A(key_ip) + P('>I', key_chg) + P('>I', len(routers))
             + b''.join(rid_element(r, i) + P('>I', c) for r, i, c in routers)
             + body)
    return item(13, P('>HH', atype, len(inner) if length is None else length) + inner)


def assign_map(elems):
    return item(14, mv_list(elems))


def cmd_ext(*cmds):
    out = b''
    for t, data in cmds:
        out += P('>HH', t, len(data)) + data
    return item(15, out)


def alt_map(atype, body, length=None):
    return item(16, P('>HH', atype, len(body) if length is None else length) + body)


def addr_table(family, addrs, alen=None):
    if family == 1:
        raw = [ip4(a) for a in addrs]
        alen = 4 if alen is None else alen
    else:
        raw = [socket.inet_pton(socket.AF_INET6, a) for a in addrs]
        alen = 16 if alen is None else alen
    return item(17, P('>HHI', family, alen, len(addrs)) + b''.join(raw))


def msg2(mtype, items, version=0x0200, length=None):
    body = b''.join(items)
    return P('>IHH', mtype, version, len(body) if length is None else length) + body


HIA, ISY, RA, RQ = 10, 11, 12, 13


# ------------------------------------------------------------- version 1

def hash_info(rev=0x2a, pattern=0x0f, flags=0):
    return P('>I', rev) + bytes((pattern + 17 * i) & 0xff for i in range(32)) + P('>I', flags)


def v1_here(recvd=5, rev=1, pattern=0x0f, flags=0):
    return P('>III', 7, 4, 0)[:8] + hash_info(rev, pattern, flags) + P('>I', recvd)


def v1_see(change, recvd, caches):
    out = P('>IIII', 8, 4, change, recvd) + P('>I', len(caches))
    for ip, rev, pat, fl in caches:
        out += ip4(ip) + hash_info(rev, pat, fl)
    return out


def v1_assign(recvd, caches, pattern=0):
    out = P('>III', 9, recvd, len(caches)) + b''.join(ip4(c) for c in caches)
    return out + bytes(0xff if (i + pattern) % 4 == 0 else (i % max(1, len(caches)))
                       for i in range(256))


# ------------------------------------------------------------ the capture

R1, R2, R3 = '192.0.2.1', '192.0.2.2', '192.0.2.3'
C1, C2, C3 = '198.51.100.10', '198.51.100.11', '198.51.100.12'
V6A, V6B = '2001:db8::1', '2001:db8::2'


def build_main():
    global TABLE
    frames = []
    marks = []

    def add(payload, src=R1, dst=R2):
        frames.append(udp_frame(payload, src, dst))

    def mark(name):
        marks.append((name, len(frames) + 1))

    mark('v1')
    add(v1_here())
    add(v1_here(7, 0x1234, 0x00, 0))
    add(v1_here(8, 0x1234, 0xff, 0x00010000))
    add(v1_here(9, 0x1234, 0x55, 0x00010000))
    add(v1_see(1, 2, []))
    add(v1_see(3, 4, [(C1, 1, 0xaa, 0)]))
    add(v1_see(5, 6, [(C1, 1, 0xaa, 0), (C2, 2, 0x0f, 0x10000)]))
    add(v1_assign(7, [C1]))
    add(v1_assign(8, [C1, C2, C3], 1))
    add(v1_assign(9, []))

    mark('v2-basic')
    # Here I Am: security (none, MD5), service, web-cache identity
    # (hash, mask, not present, extended), web-cache view
    wcv = wc_view(7, [R1, R2], [C1, C2, C3])
    ports = (80, 8080, 443, 21, 22, 23, 25, 110)
    secs = [sec(), sec(True)]
    svcs = [
        svc(0, 0, 0, 0),
        svc(1, 51, 10, 6, SF_SRC_IP | SF_DST_IP | SF_DST_PORT | SF_PORTS, ports[:3]),
        svc(1, 52, 20, 17, SF_SRC_PORT | SF_PORTS | SF_PORTS_SRC, ports),
        svc(1, 53, 30, 6, SF_R0 | SF_ALT),
        svc(0, 0, 5, 0, 0),       # warns: priority nonzero (only a warning)
        svc(0, 0, 0, 6, 0),       # warns: protocol nonzero
    ]
    hd = hash_data()
    md = mask_data([(mask_elem(0x1f, 0, 0, 0x30),
                     [value_elem(R1, R2, 80, 8080, C1), value_elem(R2, R1, 25, 0, C2)]),
                    (mask_elem(0, 0x7, 0xff, 0), [])])
    amd = alt_mask_data([(mask_elem(1, 2, 3, 4), [(C1, [1, 2, 3]), (C2, [])]),
                         (mask_elem(5, 6, 7, 8), [])])
    for s in secs:
        for sv in svcs[:2]:
            add(msg2(HIA, [s, sv, wcid(C1, 0, hd), wcv]))
    add(msg2(HIA, [secs[0], svcs[2], wcid(C1, 1, md, hist=1), wcv]))
    add(msg2(HIA, [secs[0], svcs[3], wcid(C2, 0, hd, ver=1), wcv], version=0x0201))
    # not present: the item has length 8; the two data octets are read from the next item
    add(msg2(HIA, [secs[0], svcs[0], wcid(C3, 2, b''), wcv]))
    add(msg2(HIA, [secs[0], svcs[0], wcid(C1, 3, ext_data(0, hd)), wcv]))
    add(msg2(HIA, [secs[0], svcs[0], wcid(C1, 3, ext_data(1, md)), wcv]))
    add(msg2(HIA, [secs[0], svcs[0], wcid(C1, 3, ext_data(2, amd)), wcv]))
    add(msg2(HIA, [secs[0], svcs[0], wcid(C1, 3, ext_data(3, P('>HH', 7, 1))), wcv]))
    add(msg2(HIA, [secs[0], svcs[4], wcid(C1, 0, hd, hashrev=3), wcv]))
    add(msg2(HIA, [secs[0], svcs[5], wcid(C1, 0, hd), wcv]))
    # a web-cache view that lists no routers or caches
    add(msg2(HIA, [secs[0], svcs[0], wcid(C1, 0, hd), wc_view(1, [], [])]))
    # an unknown component type and a capabilities component
    cp = caps(cap(1, P('>I', 3)), cap(2, P('>I', 1)), cap(3, P('>I', 2)),
              cap(4, P('>HH', 0, 100)), cap(4, P('>HH', 500, 100)),
              cap(5, bytes([0, 5, 0, 7])), cap(5, bytes([3, 5, 9, 7])),
              cap(99, b'\x01\x02\x03\x04'))
    add(msg2(HIA, [secs[0], svcs[0], wcid(C1, 0, hd), wcv, cp,
                   item(99, b'unknown')]))
    # capability elements with wrong value lengths (warnings only), and
    # a timer scale with A zero and C not zero
    cpw = caps(cap(1, P('>H', 3)), cap(2, P('>H', 1)), cap(3, P('>H', 1)),
               cap(4, P('>H', 1)), cap(5, P('>H', 1)),
               cap(5, bytes([0, 5, 1, 7])), cap(5, bytes([1, 5, 0, 7])))
    add(msg2(HIA, [secs[0], svcs[0], wcid(C1, 0, hd), wcv, cpw]))
    add(msg2(HIA, [secs[0], svcs[0], wcid(C1, 0, hd), wcv,
                   cmd_ext((1, A(C1)), (2, A(C2)), (7, b'abcd'), (1, b'xyz'))]))

    mark('v2-isy')
    # I See You: router identity, router view with web-cache elements
    rids = [rid(R1, 4, C1, []), rid(R1, 4, C1, [C2]), rid(R2, 9, C1, [C2, C3]),
            rid(R2, 0, C1, [])]       # receive id zero is a warning
    wce = [wc_elem(C1, 0, hd), wc_elem(C2, 1, md), wc_elem(C3, 2, b''),
           wc_elem(C1, 3, ext_data(0, hd))]
    for r in rids:
        add(msg2(ISY, [secs[0], svcs[0], r,
                       rtr_view(1, R1, 2, [R1, R2], wce[:1])]), R2, R1)
    add(msg2(ISY, [secs[1], svcs[1], rids[1], rtr_view(2, R1, 3, [], [])]), R2, R1)
    add(msg2(ISY, [secs[0], svcs[0], rids[1],
                   rtr_view(3, R1, 4, [R1], wce[:2]), cp]), R2, R1)
    add(msg2(ISY, [secs[0], svcs[0], rids[1],
                   rtr_view(3, R1, 4, [R1], [wce[2], wce[3]])]), R2, R1)
    add(msg2(ISY, [secs[0], svcs[0], rids[1], rtr_view(3, R1, 4, [R1], [wce[3]]),
                   cmd_ext((1, A(C1)))]), R2, R1)

    mark('v2-ra-rq')
    routers = [(R1, 3, 11), (R2, 4, 12)]
    wcl = [C1, C2, C3]
    add(msg2(RA, [secs[0], svcs[0], assignment(R1, 5, routers, wcl)]))
    add(msg2(RA, [secs[0], svcs[0], assignment(R1, 5, [], [])]))
    add(msg2(RA, [secs[0], svcs[0], assign_map([(mask_elem(1, 2, 3, 4),
                    [value_elem(R1, R2, 1, 2, C1)])])]))
    add(msg2(RA, [secs[0], svcs[0], assign_map([])]))
    add(msg2(RA, [secs[0], svcs[0], alt_assign(0, R1, 6, routers,
                    P('>I', 3) + b''.join(A(w) for w in wcl) + buckets(wcl))]))
    add(msg2(RA, [secs[0], svcs[0], alt_assign(0, R1, 6, [], P('>I', 0) + buckets([]))]))
    add(msg2(RA, [secs[0], svcs[0], alt_assign(1, R1, 6, routers,
                    mv_list([(mask_elem(1, 2, 3, 4), [value_elem(R1, R2, 1, 2, C1)])]))]))
    add(msg2(RA, [secs[0], svcs[0], alt_assign(2, R1, 6, routers, alt_mv_list(
                    [(mask_elem(9, 8, 7, 6), [(C1, [1]), (C2, [2, 3])])]))]))
    add(msg2(RA, [secs[0], svcs[0], alt_assign(7, R1, 6, routers, b'')]))
    add(msg2(RA, [secs[0], svcs[0], alt_map(0, assign_info(R1, 7, routers, wcl))]))
    add(msg2(RA, [secs[0], svcs[0], alt_map(1, mv_list([(mask_elem(1, 2, 3, 4),
                    [value_elem(R1, R2, 1, 2, C1), value_elem(R1, R2, 3, 4, C2)])]))]))
    add(msg2(RA, [secs[0], svcs[0], alt_map(2, alt_mv_list([(mask_elem(1, 2, 3, 4),
                    [(C3, [5, 6, 7])])]))]))
    add(msg2(RA, [secs[0], svcs[0], alt_map(3, b'')]))
    add(msg2(RA, [secs[0], svcs[0], assignment(R1, 5, routers, wcl),
                  item(99, b'')]))
    add(msg2(RQ, [secs[0], svcs[0], query(R1, 8, R2, C1)]), R1, R2)
    add(msg2(RQ, [secs[1], svcs[2], query(R2, 9, R1, C2)], version=0x0201), R1, R2)

    mark('v2-table')
    # WCCP 2.01 address tables: IPv4 and IPv6, addresses are indexes
    for fam, tab in ((1, [R1, R2, C1, C2, C3]), (2, [V6A, V6B, V6A])):
        TABLE = tab
        t = addr_table(fam, tab)
        a = tab[0]
        b = tab[1]
        c = tab[2]
        wcvt = wc_view(7, [a, b], [c, a])
        hdt = hash_data()
        add(msg2(HIA, [t, secs[0], svcs[0], wcid(c, 0, hdt), wcvt], 0x0201))
        add(msg2(HIA, [secs[0], svcs[0], t, wcid(c, 1, mask_data(
            [(mask_elem(1, 2, 3, 4), [value_elem(a, b, 80, 81, c)])])), wcvt], 0x0201))
        add(msg2(ISY, [secs[0], svcs[0], t, rid(a, 4, b, [c, a]),
                       rtr_view(1, a, 2, [a, b], [wc_elem(c, 0, hdt)])], 0x0201), R2, R1)
        add(msg2(RA, [secs[0], svcs[0], t, assignment(a, 5, [(a, 3, 11)], [b, c])],
                 0x0201))
        add(msg2(RA, [secs[0], t, svcs[0], alt_assign(0, a, 6, [(a, 1, 2)],
                 P('>I', 2) + A(b) + A(c) + buckets([b, c]))], 0x0201))
        add(msg2(RA, [secs[0], svcs[0], t, alt_assign(1, a, 6, [(a, 1, 2)],
                 mv_list([(mask_elem(1, 2, 3, 4), [value_elem(a, b, 1, 2, c)])]))], 0x0201))
        add(msg2(RA, [secs[0], svcs[0], t, alt_assign(2, a, 6, [(a, 1, 2)],
                 alt_mv_list([(mask_elem(1, 2, 3, 4), [(c, [1, 2])])]))], 0x0201))
        add(msg2(RQ, [secs[0], svcs[0], t, query(a, 8, b, c)], 0x0201), R1, R2)
        add(msg2(HIA, [secs[0], svcs[0], t, wcid(c, 0, hdt), wcvt,
                       cmd_ext((1, A(a)))], 0x0201))
        # an index of 0 (undefined address), beyond the table, with a
        # non-zero reserved part
        add(msg2(HIA, [secs[0], svcs[0], t, wcid(None, 0, hdt),
                       wc_view(7, [a], [])], 0x0201))
        TABLE = tab
        add(msg2(HIA, [secs[0], svcs[0], t, item(3, IDX(len(tab) + 5)
                       + P('>HH', 0, wc_flags(2)) ), wc_view(7, [a], [])], 0x0201))
        add(msg2(HIA, [secs[0], svcs[0], t, item(3, IDX(0x00010001)
                       + P('>HH', 0, wc_flags(2))), wc_view(7, [a], [])], 0x0201))
        add(msg2(HIA, [secs[0], svcs[0], t, item(3, IDX(0x00020003)
                       + P('>HH', 0, wc_flags(2))), wc_view(7, [a], [])], 0x0201))
        add(msg2(RA, [secs[0], svcs[0], t, assign_map([(mask_elem(1, 2, 3, 4), [
            value_elem(a, b, 1, 2, None), value_elem(a, b, 3, 4, c),
            A(a) + A(b) + P('>HH', 5, 6) + IDX(0x00030002),
            A(a) + A(b) + P('>HH', 7, 8) + IDX(0x00ff)])])], 0x0201))
    TABLE = None
    t0 = addr_table(1, [])
    add(msg2(HIA, [secs[0], svcs[0], t0, item(3, IDX(1) + P('>HH', 0, wc_flags(2))),
                   wc_view(7, [], [])], 0x0201))
    # the message header length is shorter than the data: the rest is ignored
    add(msg2(HIA, [secs[0], svcs[0], wcid(C1, 0, hd), wcv]) + b'\x00' * 3)
    add(msg2(HIA, [secs[0], svcs[0], wcid(C1, 0, hd), wcv, item(99, b'tail')],
             length=len(secs[0] + svcs[0] + wcid(C1, 0, hd) + wcv)))
    return frames, marks


def sample_items():
    """One valid item of each kind (several for some): (type, data)."""
    global TABLE
    TABLE = None
    hd = hash_data()
    md = mask_data([(mask_elem(1, 2, 3, 4), [value_elem(R1, R2, 1, 2, C1),
                                             value_elem(R2, R1, 3, 4, C2)])])
    amd = alt_mask_data([(mask_elem(1, 2, 3, 4), [(C1, [1, 2]), (C2, [])])])
    routers = [(R1, 3, 11), (R2, 4, 12)]
    wcl = [C1, C2]
    out = []

    def add(it):
        out.append((struct.unpack('>H', it[:2])[0], it[4:]))
    add(sec())
    add(sec(True))
    add(svc(0, 0, 0, 0))
    add(svc(1, 51, 10, 6, SF_PORTS | SF_SRC_PORT, (80, 81)))
    add(rid(R1, 4, C1, []))
    add(rid(R1, 4, C1, [C2, C3]))
    add(wcid(C1, 0, hd))
    add(wcid(C1, 1, md))
    add(wcid(C1, 2, b''))
    add(wcid(C1, 3, ext_data(0, hd)))
    add(wcid(C1, 3, ext_data(1, md)))
    add(wcid(C1, 3, ext_data(2, amd)))
    add(wcid(C1, 3, ext_data(3, P('>HH', 7, 1))))
    add(rtr_view(1, R1, 2, [R1, R2], [wc_elem(C1, 0, hd),
                                     wc_elem(C2, 3, ext_data(3, P('>HH', 7, 1)))]))
    add(wc_view(7, [R1, R2], [C1, C2]))
    add(assignment(R1, 5, routers, wcl))
    add(query(R1, 8, R2, C1))
    add(caps(cap(1, P('>I', 3)), cap(4, P('>HH', 0, 100)), cap(5, bytes([0, 5, 0, 7]))))
    add(alt_assign(0, R1, 6, routers, P('>I', 2) + A(C1) + A(C2) + buckets(wcl)))
    add(alt_assign(1, R1, 6, routers, mv_list([(mask_elem(1, 2, 3, 4),
                                               [value_elem(R1, R2, 1, 2, C1)])])))
    add(alt_assign(2, R1, 6, routers, alt_mv_list([(mask_elem(1, 2, 3, 4), [(C1, [1])])])))
    add(assign_map([(mask_elem(1, 2, 3, 4), [value_elem(R1, R2, 1, 2, C1)])]))
    add(cmd_ext((1, A(C1)), (7, b'abcd')))
    add(alt_map(0, assign_info(R1, 7, routers, wcl)))
    add(alt_map(1, mv_list([(mask_elem(1, 2, 3, 4), [value_elem(R1, R2, 1, 2, C1)])])))
    add(alt_map(2, alt_mv_list([(mask_elem(1, 2, 3, 4), [(C3, [5])])])))
    add(alt_map(3, b''))
    add(addr_table(1, [R1, R2, C1]))
    add(addr_table(2, [V6A, V6B]))
    add(item(99, b'unknown'))
    return out


def build_malformed():
    global TABLE
    frames = []

    def add(payload, src=R1, dst=R2):
        frames.append(udp_frame(payload, src, dst))

    samples = sample_items()
    # 1. every component alone in every message type: the missing and
    # unexpected component errors
    for mt in (HIA, ISY, RQ, RA):
        add(msg2(mt, []))
        for t, data in samples:
            add(msg2(mt, [item(t, data)]))
    # 2. item lengths that are too short or too long, with the data of the
    # item (and zero padding) behind
    seen = set()
    for t, data in samples:
        n = len(data)
        big = n > 300
        lens = set(range(0, 24 if big else n + 5))
        lens |= {n - k for k in range(1, 13)} | {n + 1, n + 4}
        for L in sorted(x for x in lens if x >= 0):
            payload = P('>HH', t, L) + data + b'\0' * 64
            add(msg2(HIA, [payload]))
    # 3. the message length is longer than the packet; unknown types
    add(msg2(HIA, [sec(), svc()], length=500))
    add(P('>I', 99) + b'\0' * 20)
    add(P('>I', 6) + b'\0' * 20)
    add(P('>IHH', 99, 0x0200, 4) + sec())
    # 4. address tables with wrong address lengths, unknown families, more
    # entries than the stored length field can count
    for fam, alen, addrs in ((1, 8, [R1, R2]), (1, 0, [R1]), (2, 4, [V6A]),
                             (2, 32, [V6A])):
        raw = (ip4(R1) if fam == 1 else socket.inet_pton(socket.AF_INET6, V6A))
        body = P('>HHI', fam, alen, 2) + raw * 2
        add(msg2(HIA, [sec(), svc(), item(17, body)]))
    for alen in (0, 1, 3, 4, 5, 8, 12, 17):
        body = P('>HHI', 5, alen, 2) + b'\x11' * 40
        add(msg2(HIA, [sec(), svc(), item(17, body),
                       wcid(None, 2, b''), wc_view(1, [], [])]))
    for fam in (1, 2, 3):
        # table_length 65538 keeps the low 16 bits (2) as the stored length
        addrs = (ip4(R1) if fam == 1 else socket.inet_pton(socket.AF_INET6, V6A)) * 5
        body = P('>HHI', fam, 4 if fam == 1 else 16, 65538) + addrs
        add(msg2(HIA, [sec(), svc(), item(17, body)]))
    # indexes of an unknown address family: the component says family 5
    body = P('>HHI', 5, 4, 2) + ip4(R1) + ip4(R2)
    tbl = item(17, body)
    add(msg2(HIA, [sec(), svc(), tbl, item(3, IDX(1) + P('>HH', 0, wc_flags(2))),
                   item(5, P('>III', 1, 0, 0) + b'')]))
    add(msg2(HIA, [sec(), svc(), tbl, item(3, IDX(1) + P('>HH', 0, wc_flags(1)) +
                   P('>I', 1) + mask_elem() + P('>I', 1) + IDX(1) + IDX(2) +
                   P('>HH', 1, 2) + IDX(1) + P('>HH', 1, 1))]))
    add(msg2(RA, [sec(), svc(), tbl, alt_assign(1, None, 6, [(None, 1, 2)],
                 mv_list([(mask_elem(1, 2, 3, 4), [IDX(1) + IDX(2) + P('>HH', 1, 2) + IDX(1)])]))]))
    # table of length 0, an index that is not 0
    for fam in (1, 2):
        body = P('>HHI', fam, 4 if fam == 1 else 16, 0)
        add(msg2(HIA, [sec(), svc(), item(17, body),
                       item(3, IDX(1) + P('>HH', 0, wc_flags(1)) + P('>I', 1) + mask_elem()
                            + P('>I', 1) + IDX(1) + IDX(0) + P('>HH', 1, 2) + IDX(1)
                            + P('>HH', 1, 1)), item(5, P('>III', 1, 0, 0))]))
    # 5. alternate assignment lengths that do not match
    routers = [(R1, 3, 11)]
    for L in (0, 8, 1000):
        add(msg2(RA, [sec(), svc(), alt_assign(0, R1, 6, routers,
                 P('>I', 1) + A(C1) + buckets([C1]), length=L)]))
        add(msg2(RA, [sec(), svc(), alt_map(0, assign_info(R1, 7, routers, [C1]), length=L)]))
        add(msg2(RA, [sec(), svc(), alt_map(1, mv_list([(mask_elem(1, 2, 3, 4), [])]), length=L)]))
        add(msg2(RA, [sec(), svc(), alt_map(2, alt_mv_list([(mask_elem(1, 2, 3, 4), [])]), length=L)]))
    # extended assignment data with wrong lengths and an unknown type
    md = mask_data([(mask_elem(1, 2, 3, 4), [])])
    hd = hash_data()
    for atype, body in ((0, hd), (1, md), (2, alt_mask_data([(mask_elem(1, 2, 3, 4), [])])),
                        (3, P('>HH', 7, 1)), (9, b'\0' * 4)):
        for dl in (len(body) - 4, len(body) + 1, len(body) + 20, len(body) + 4, 0, 2):
            add(msg2(HIA, [sec(), svc(), item(3, A(C1) + P('>HH', 0, wc_flags(3))
                           + P('>HH', atype, dl) + body), wc_view(1, [], [])]))
    # alternate mask assignment data in an extended element with several lists
    alist = alt_mv_list([(mask_elem(1, 2, 3, 4), [(C1, [1])])])
    for body in (alist, alist + alist + P('>HH', 1, 2), alist[:3], b'',
                 P('>I', 0), P('>I', 0) + P('>H', 3)):
        add(msg2(HIA, [sec(), svc(), item(3, A(C1) + P('>HH', 0, wc_flags(3))
                       + P('>HH', 2, len(body)) + body), wc_view(1, [], [])]))
    # more web caches or routers than the item holds
    for n in (3, 100):
        add(msg2(RA, [sec(), svc(), item(6, A(R1) + P('>I', 5) + P('>I', 0)
                                         + P('>I', n) + A(C1) + A(C2))]))
        add(msg2(RA, [sec(), svc(), alt_assign(0, R1, 6, [], P('>I', n) + A(C1) + A(C2))]))
        add(msg2(RA, [sec(), svc(), alt_assign(0, R1, 6, [], P('>I', n) + A(C1)
                                                 + buckets([C1])[:200])]))
    add(msg2(RA, [sec(), svc(), alt_assign(0, R1, 6, [], P('>I', 100) + b'\x01' * 270)]))
    # 6. short messages of version 1 and 2
    for pkt in (v1_here(), v1_see(1, 2, [(C1, 1, 0xaa, 0)]), v1_assign(3, [C1])):
        for cut in (4, 8, 12, 20, 40, len(pkt) - 1):
            add(pkt[:cut])
    add(P('>I', 10))
    add(P('>IH', 10, 0x200))
    return frames


def main(outdir):
    os.makedirs(outdir, exist_ok=True)
    frames, marks = build_main()
    pcap(os.path.join(outdir, 'wccp-coverage.pcap'), frames)
    print('main frames', len(frames), marks)
    frames = build_malformed()
    pcap(os.path.join(outdir, 'wccp-coverage-malformed.pcap'), frames)
    print('malformed frames', len(frames))


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')
