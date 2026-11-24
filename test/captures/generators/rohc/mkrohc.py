#!/usr/bin/env python3
# Generates test/captures/rohc_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the ROHC coverage captures: mkrohc.py <outdir>.

ROHC is carried two ways: Ethernet with ethertype 0x22F1 (no rohc_info, the
dissector uses its defaults) and PDCP-LTE over UDP (heuristic pdcp_lte_udp,
pdcp-lte.dissect_rohc on) where the framing tags give the profile, mode, CID
size, IP version, RND and UDP checksum flags.  Nothing is encrypted; all
bytes are made up with struct.
"""
import struct
import sys
import os

# ------------------------------------------------------------ pcap / frames


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def write_pcap(name, frames):
    with open(name, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1000 + i, 0, len(fr), len(fr)))
            f.write(fr)


ETH = bytes.fromhex('020000000002020000000001')


def eth_rohc(payload):
    return ETH + struct.pack('>H', 0x22F1) + payload


def udp_frame(payload, sport=40000, dport=40001):
    udp = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
                     bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2]))
    ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
    return ETH + b'\x08\x00' + ip + udp


def ipv4_udp():
    udp = struct.pack('>HHHH', 1, 2, 12, 0) + b'data'
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
                     bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]))
    return ip[:10] + struct.pack('>H', csum(ip)) + ip[12:] + udp


def ipv6_udp():
    src = bytes([0x20, 1, 0xd, 0xb8] + [0] * 11 + [1])
    dst = bytes([0x20, 1, 0xd, 0xb8] + [0] * 11 + [2])
    udp = struct.pack('>HHHH', 1, 2, 12, 0) + b'data'
    ck = csum(src + dst + struct.pack('>IBBBB', len(udp), 0, 0, 0, 17) + udp) or 0xffff
    udp = udp[:6] + struct.pack('>H', ck) + udp[8:]
    return struct.pack('>IHBB', 0x60000000, len(udp), 17, 64) + src + dst + udp


# PDCP-LTE framing: no_header_pdu, user plane, rohc_compression; tags
SIG, USER = 1, 2
R, U, O = 3, 1, 2           # rohc modes (reliable, unidirectional, optimistic)
P_UNC, P_RTP, P_UDP, P_IP, P_TCP = 0, 1, 2, 4, 6


def pdcp(payload, prof, mode=R, ipv=4, large=0, rnd=0, udpck=0, cidinc=0):
    t = bytes([0x02, 12])
    t += bytes([0x07, cidinc])
    t += bytes([0x08, large])
    t += bytes([0x09, mode])
    t += bytes([0x0A, rnd])
    t += bytes([0x0B, udpck])
    t += bytes([0x0C]) + struct.pack('>H', prof)
    t += bytes([0x06]) + struct.pack('>H', ipv)
    return udp_frame(b'pdcp-lte' + bytes([1, USER, 1]) + t + b'\x01' + payload)


def vl(v):
    """Self-describing variable-length value (RFC 3095 4.5.6)."""
    if v < 0x80:
        return bytes([v])
    if v < 0x4000:
        return struct.pack('>H', 0x8000 | v)
    if v < 0x200000:
        return struct.pack('>I', 0xC00000 | v)[1:]
    return struct.pack('>I', 0xE0000000 | v)


PAY = b'\x11\x22\x33\x44\x55\x66\x77\x88\x99'     # trailing payload

# compressed lists: encoding types 0-3, as the dissector reads them
CLIST = {
    '0': bytes([0x00]),
    '0gp': bytes([0x28, 0x07]),
    '0cc': bytes([0x13, 0x81, 0x82, 0xAA]),
    '1': bytes([0x40, 0x05, 0x7F]),
    '1gp': bytes([0x70, 0x01, 0x05, 0xFF, 0xFF]),
    '2': bytes([0x82, 0x05, 0x03]),
    '2gp': bytes([0xA3, 0x01, 0x05, 0x80, 0x03]),
    '3': bytes([0xC0, 0x05, 0x03, 0x04, 0x00]),
    '3gp': bytes([0xF0, 0x01, 0x05, 0x83, 0x03, 0x84, 0x03, 0x00]),
}

# ------------------------------------------------------------ IR / IR-DYN


def static_v4(proto=17):
    return bytes([0x40, proto]) + bytes([192, 0, 2, 1]) + bytes([192, 0, 2, 2])


def static_v6(nxt=17):
    return bytes([0x60, 0x12, 0x34, nxt]) + bytes([0x20, 1, 0xd, 0xb8] + [0] * 11 + [1]) + \
        bytes([0x20, 1, 0xd, 0xb8] + [0] * 11 + [2])


def dyn_v4(rnd=0, nbo=0, df=0, lst='0'):
    return bytes([0x10, 64]) + struct.pack('>H', 0x1234) + \
        bytes([(df << 7) | (rnd << 6) | (nbo << 5)]) + CLIST[lst]


def dyn_udp(ck=0, ipid=None):
    b = struct.pack('>H', ck)
    if ipid is not None:
        b += struct.pack('>H', ipid)
    return b


def dyn_rtp(cc=0, rx=0, mode=R, tss=None, tis=None, lst='0'):
    b = bytes([0x80 | (rx << 4) | cc, 0x80 | 96]) + struct.pack('>H', 100) + \
        struct.pack('>I', 16000) + CLIST[lst]
    if rx:
        b += bytes([0x10 | (mode << 2) | (1 if tss is not None else 0) |
                    (2 if tis is not None else 0)])
        if tss is not None:
            b += vl(tss)
        if tis is not None:
            b += vl(tis)
    return b


def ir(profile, static, dyn=None, cidb=b'', add_cid=0, pad=0):
    d = 1 if dyn is not None else 0
    b = b'\xe0' * pad
    if add_cid:
        b += bytes([0xE0 | add_cid])
    b += bytes([0xFC | d]) + cidb + bytes([profile, 0x5A]) + static
    if dyn is not None:
        b += dyn
    return b


def ir_dyn(profile, dyn, cidb=b'', add_cid=0):
    b = bytes([0xE0 | add_cid]) if add_cid else b''
    return b + bytes([0xF8]) + cidb + bytes([profile, 0x33]) + dyn


def ir_rtp(v6=False, rnd=0, mode=R, ck=0, **kw):
    st = (static_v6() if v6 else static_v4()) + struct.pack('>HH', 5004, 5006) + \
        struct.pack('>I', 0x11223344)
    return st, ((bytes([0x00, 64]) if v6 else dyn_v4(rnd)) if not v6 else b'') + \
        dyn_udp(ck) + dyn_rtp(mode=mode, **kw)


def ir_udp(v6=False, rnd=0, ck=0):
    st = (static_v6() if v6 else static_v4()) + struct.pack('>HH', 5004, 5006)
    return st, (b'' if v6 else dyn_v4(rnd)) + dyn_udp(ck, 0x4321)


# ------------------------------------------------------------ feedback


def fb(data, cid=0, large=None, code=None):
    """Feedback: size in the code field when it fits, else a size octet."""
    body = b''
    if large is not None:
        body += vl(large)
    elif cid:
        body += bytes([0xE0 | cid])
    body += data
    if code is None and len(body) < 8:
        return bytes([0xF0 | len(body)]) + body
    return bytes([0xF0, len(body)]) + body


def fb2(acktype, mode, sn, opts=b''):
    return struct.pack('>H', (acktype << 14) | (mode << 12) | (sn & 0xfff)) + opts


# ------------------------------------------------------------ ext formats


def ext3(c, S=0, RTS=None, TSC=0, I=0, ip=0, rtp=0, inner=0, outer=None,
         tos=0, ttl=0, pr=0, ipx=None, rtpf=0, rpt=0, csrc=None, tss=None, tis=None,
         ip2fields=0, o_i2=0):
    """Extension 3; keeps rnd and mode of the context unchanged."""
    b = bytes([0xC0 | (S << 5) | ((1 if RTS is not None else 0) << 4) | (TSC << 3) |
               (I << 2) | (ip << 1) | rtp])
    if ip:
        fl = inner & ~0x03
        fl |= (c['rnd'] << 1)
        if outer is not None:
            fl |= 1
        b += bytes([fl])
        if outer is not None:
            b += bytes([(outer & ~0x02) | (c['rnd'] << 1)])
    if S:
        b += b'\x55'
    if RTS is not None:
        b += vl(RTS)
    if ip:
        if inner & 0x80:
            b += b'\x10'
        if inner & 0x40:
            b += b'\x40'
        if inner & 0x10:
            b += b'\x11'
        if inner & 0x08:
            b += CLIST[ipx]
    if I:
        b += b'\x12\x34'
    if ip and outer is not None:
        if outer & 0x80:
            b += b'\x10'
        if outer & 0x40:
            b += b'\x40'
        if outer & 0x10:
            b += b'\x06'
        if outer & 0x08:
            b += CLIST[ipx]
        if outer & 0x01:
            b += b'\x23\x45'
    if rtp and c['profile'] == P_RTP:
        b += bytes([(c['mode'] << 6) | (0x20 if rpt else 0) | (0x10 if rtpf & 0x10 else 0) |
                    (0x08 if rtpf & 8 else 0) | (0x04 if csrc else 0) |
                    (0x02 if tss is not None else 0) | (0x01 if tis is not None else 0)])
        if rpt:
            b += bytes([0x80 | 96])
        if csrc:
            b += CLIST[csrc]
        if tss is not None:
            b += vl(tss)
        if tis is not None:
            b += vl(tis)
    return b


def exts(c, t):
    """List of extension byte strings valid for the context."""
    L = [bytes([0x00 | 0x09]), bytes([0x40 | 0x0a, 0x5a]), bytes([0x80 | 0x0b, 0x6b, 0x7c])]
    if c['profile'] == P_RTP:
        L += [ext3(c), ext3(c, S=1), ext3(c, RTS=5), ext3(c, RTS=300), ext3(c, RTS=70000),
              ext3(c, RTS=20000000, TSC=1), ext3(c, S=1, I=1, RTS=1),
              ext3(c, ip=1, inner=0xD0, outer=0xD1, I=1, o_i2=1),
              ext3(c, ip=1, inner=0x28, ipx='1', I=1, outer=0x58, ),
              ext3(c, ip=1, inner=0x08, ipx='0gp'), ext3(c, ip=1, inner=0x08, ipx='2'),
              ext3(c, ip=1, inner=0x08, ipx='3'), ext3(c, ip=1, inner=0x08, ipx='1gp'),
              ext3(c, ip=1, inner=0x08, ipx='2gp'), ext3(c, ip=1, inner=0x08, ipx='3gp'),
              ext3(c, ip=1, inner=0x08, ipx='0cc'),
              ext3(c, rtp=1, rpt=1), ext3(c, rtp=1, csrc='1', tss=7, tis=1000),
              ext3(c, rtp=1, rtpf=0x18, tss=100000), ext3(c, rtp=1, tis=2000000),
              ext3(c, rtp=1, csrc='0cc', rpt=1, tss=3, tis=4, S=1, ip=1, inner=0x40)]
    else:
        L += [ext3(c), ext3(c, S=1), ext3(c, I=1), ext3(c, ip=1, inner=0xD0, outer=0xD1),
              ext3(c, ip=1, inner=0x08, ipx='1')]
    return L


def x_exts(c, t, tag=''):
    """(first octet kind) -> not used; helper kept simple."""
    return exts(c, t)


# ------------------------------------------------------------ compressed packets


def packets(c, mid=b''):
    """Compressed packets (without the add-CID octet) for a context.
    Returns list of (bytes) each followed by payload."""
    P, M = c['profile'], c['mode']
    a = c['ver'] != 4 or c['rnd'] or P == P_UDP
    out = []

    def add(first_part, x=0, t=0xff, exts_=True):
        out.append(first_part + PAY)
        if x and exts_:
            pass
    # type 0
    if P in (P_RTP, P_UDP):
        if M == R:
            out.append(bytes([0x15]) + mid + PAY)                       # R-0
            out.append(bytes([0x55]) + mid + bytes([0xA5]) + PAY)       # R-0-CRC
            out.append(bytes([0x7f]) + mid + bytes([0xFF]) + PAY)
        else:
            out.append(bytes([0x35]) + mid + PAY)                       # UO-0
            out.append(bytes([0x7a]) + mid + PAY)
    def with_ext(head, x_at, t, tail=b''):
        """head already contains the byte with X set at the right place."""
        for e in exts(c, t):
            out.append(head + e + tail + PAY)
    # type 1
    if M == R:
        if a:
            if P == P_UDP:
                out.append(bytes([0x95]) + mid + bytes([0x25]) + PAY)           # R-1 UDP, X=0
                for e in exts(c, 0xff):
                    out.append(bytes([0x95]) + mid + bytes([0xA5]) + e + PAY)   # X=1
            else:
                out.append(bytes([0x95]) + mid + bytes([0x85]) + PAY)           # R-1, M=1 X=0
                out.append(bytes([0x95]) + mid + bytes([0x3F]) + PAY)
                for e in exts(c, 0xff):
                    out.append(bytes([0x95]) + mid + bytes([0x40 | 0x15]) + e + PAY)
        else:
            for t in (0, 1):
                out.append(bytes([0x95]) + mid + bytes([(t << 5) | 0x0B]) + PAY)
                out.append(bytes([0x95]) + mid + bytes([0xC0 | (t << 5) | 0x0B]) + PAY)
                for e in exts(c, t):
                    out.append(bytes([0x95]) + mid + bytes([0x40 | (t << 5) | 0x0B]) + e + PAY)
    else:
        if a:
            if P == P_UDP:
                out.append(bytes([0x95]) + mid + bytes([0x6B]) + PAY)           # UO-1 UDP
            else:
                out.append(bytes([0x95]) + mid + bytes([0x8B]) + PAY)           # UO-1 RTP
                out.append(bytes([0xBF]) + mid + bytes([0x1B]) + PAY)
        else:
            # UO-1-ID (t=0) with and without extension, UO-1-TS (t=1)
            out.append(bytes([0x95]) + mid + bytes([0x6B]) + PAY)
            for e in exts(c, 0):
                out.append(bytes([0x95]) + mid + bytes([0xEB]) + e + PAY)
            out.append(bytes([0xB5]) + mid + bytes([0x8B]) + PAY)
            out.append(bytes([0xBF]) + mid + bytes([0x1B]) + PAY)
    # type 2
    if a:
        if P == P_UDP:
            out.append(bytes([0xC5]) + mid + bytes([0x35]) + PAY)               # X=0
            for e in exts(c, 0xff):
                out.append(bytes([0xC5]) + mid + bytes([0xB5]) + e + PAY)
        else:
            out.append(bytes([0xC9]) + mid + bytes([0x95]) + bytes([0x35]) + PAY)
            out.append(bytes([0xDA]) + mid + bytes([0x55]) + bytes([0x35]) + PAY)
            for e in exts(c, 0xff):
                out.append(bytes([0xC9]) + mid + bytes([0x95]) + bytes([0xB5]) + e + PAY)
    else:
        for t in (0, 1):
            out.append(bytes([0xC5]) + mid + bytes([(t << 7) | 0x15]) + bytes([0x35]) + PAY)
            for e in exts(c, t):
                out.append(bytes([0xC5]) + mid + bytes([(t << 7) | 0x15]) + bytes([0xB5]) + e + PAY)
    return out


# ------------------------------------------------------------ the captures


def build():
    F = []
    S = []

    def sec(name):
        S.append((len(F) + 1, name))

    # --- reproducers of "ROHC: Fix large CID uncompressed profile and field widths"
    sec('fix: large CID, uncompressed profile (PDCP-LTE, cid 0 context from the tags)')
    inner = ipv4_udp()
    F.append(pdcp(inner[:1] + bytes([0x05]) + inner[1:], P_UNC, large=1))
    F.append(pdcp(inner[:1] + bytes([0x85, 0x05]) + inner[1:], P_UNC, large=1))
    sec('fix: 29-bit R-TS in extension 3 into a 32-bit field (Ethernet)')
    st, dy = ir_rtp()
    F.append(eth_rohc(ir(P_RTP, st, dy)))
    F.append(eth_rohc(bytes([0xC0, 0x80, 0x80]) + bytes([0xD0, 0xFF, 0xFF, 0xFF, 0xFF]) + b'payload'))
    # --- Ethernet: IR packets in all forms
    sec('Ethernet IR packets, padding, Add-CID')
    st, dy = ir_rtp(rnd=1, ck=0x1234, rx=1, mode=O, tss=160, tis=20)
    F.append(eth_rohc(ir(P_RTP, st, dy, pad=2) + PAY))
    st, dy = ir_rtp(rx=1, mode=U, lst='1gp', tss=1, tis=2)
    F.append(eth_rohc(ir(P_RTP, st, dy, add_cid=14) + PAY))
    st, dy = ir_rtp(rx=1, mode=R, lst='3', cc=2)
    F.append(eth_rohc(ir(P_RTP, st, dy, add_cid=14) + PAY))
    st, dy = ir_rtp()
    F.append(eth_rohc(ir(P_RTP, st) + PAY))                         # D=0, static only
    F.append(eth_rohc(ir(P_RTP, st, dy) + PAY))                     # replaces the context
    st, dy = ir_rtp(v6=True)
    F.append(eth_rohc(ir(P_RTP, st, dy, add_cid=14) + PAY))
    F.append(eth_rohc(ir(P_RTP, st, None, add_cid=14) + PAY))
    st, dy = ir_udp()
    F.append(eth_rohc(ir(P_UDP, st, dy) + PAY))
    F.append(eth_rohc(ir(P_UDP, st, dy, add_cid=14) + PAY))
    F.append(eth_rohc(ir(P_UDP, st, None, add_cid=14) + PAY))
    st, dy = ir_udp(v6=True, ck=7)
    F.append(eth_rohc(ir(P_UDP, st, None, add_cid=14) + PAY))
    F.append(eth_rohc(ir(P_UDP, st, dy, add_cid=14) + PAY))
    # IP profile: IPv4 / IPv6, protocol UDP and other, with/without dynamic
    F.append(eth_rohc(ir(P_IP, static_v4(1), dyn_v4(), add_cid=14) + PAY))
    F.append(eth_rohc(ir(P_IP, static_v4(1), None, add_cid=14) + PAY))
    F.append(eth_rohc(ir(P_IP, bytes([0xC0]) + static_v4(1)[1:], dyn_v4(1, 1, 1, '2')) + PAY))
    F.append(eth_rohc(ir(P_IP, static_v4(17), dyn_v4(), add_cid=14) + PAY))
    F.append(eth_rohc(ir(P_IP, static_v6(6), dyn_v4(), add_cid=14) + PAY))
    F.append(eth_rohc(ir(P_IP, bytes([0xE0 | 0]) + static_v6(6)[1:], None, add_cid=14) + PAY))
    # UDP profile with a protocol that is not UDP
    F.append(eth_rohc(ir(P_UDP, static_v4(6), None, add_cid=14) + PAY))
    # version errors, unknown profiles
    F.append(eth_rohc(ir(P_UDP, bytes([0x50]) + b'\0' * 12, None, add_cid=14) + PAY))
    F.append(eth_rohc(ir(P_TCP, static_v4(6), None, add_cid=14) + PAY))
    F.append(eth_rohc(ir(3, static_v4(50), None, add_cid=14) + PAY))
    # uncompressed profile: IPv4, IPv6, other payload, empty
    F.append(eth_rohc(ir(P_UNC, b'') + ipv4_udp()))
    F.append(eth_rohc(ir(P_UNC, b'', add_cid=14) + ipv6_udp()))
    F.append(eth_rohc(ir(P_UNC, b'', add_cid=14) + b'\x99\x01\x02\x03'))
    F.append(eth_rohc(ir(P_UNC, b'')))
    # IR-DYN packets
    sec('Ethernet IR-DYN packets')
    st, dy = ir_rtp(rx=1, mode=O, tss=5, tis=6)
    F.append(eth_rohc(ir(P_RTP, st, dy, add_cid=14) + PAY))
    d_rtp = dyn_v4(1) + dyn_udp(0x55) + dyn_rtp(rx=1, mode=U, tis=9, lst='2')
    F.append(eth_rohc(ir_dyn(P_RTP, d_rtp, add_cid=14) + PAY))
    st, dy = ir_udp()
    F.append(eth_rohc(ir(P_UDP, st, dy, add_cid=14) + PAY))
    F.append(eth_rohc(ir_dyn(P_UDP, dyn_v4() + dyn_udp(0, 5), add_cid=14) + PAY))
    F.append(eth_rohc(ir_dyn(P_IP, dyn_v4(), add_cid=14) + PAY))
    F.append(eth_rohc(ir_dyn(P_UNC, b'', add_cid=14) + PAY))
    # Ethernet: feedback, segments
    sec('Ethernet feedback, errors, segments')

    def ctx(profile):
        """(Re)create the context of cid 14 with an IR packet."""
        if profile == P_RTP:
            st, dy = ir_rtp()
            F.append(eth_rohc(ir(P_RTP, st, dy, add_cid=14) + PAY))
        elif profile == P_UDP:
            st, dy = ir_udp()
            F.append(eth_rohc(ir(P_UDP, st, dy, add_cid=14) + PAY))
        elif profile == P_UNC:
            F.append(eth_rohc(ir(P_UNC, b'', add_cid=14) + PAY))
        else:
            F.append(eth_rohc(ir(P_IP, static_v4(1), dyn_v4(), add_cid=14) + PAY))
    ctx(P_RTP)
    F.append(eth_rohc(fb(bytes([0x37]), 14)))                            # type 1: SN
    opts = b''.join([bytes([0x11, 0x2A]), bytes([0x20]), bytes([0x30]), bytes([0x41, 0x81]),
                     bytes([0x51, 0x05]), bytes([0x61, 0x06]), bytes([0x71, 0x07]),
                     bytes([0x91, 0xEE])])
    F.append(eth_rohc(fb(fb2(0, 3, 0x456, opts), 14)))
    F.append(eth_rohc(fb(fb2(1, 2, 0x456, bytes([0x11, 0x2A, 0x20, 0x30])), 14)))
    F.append(eth_rohc(fb(fb2(2, 1, 0x7ff, bytes([0x41, 0x81, 0x51, 0x05, 0x61, 0x06, 0x71, 0x07])), 14)))
    F.append(eth_rohc(fb(fb2(3, 3, 0, bytes([0x71, 0x07])), 14)))
    # size octet form
    F.append(eth_rohc(fb(fb2(0, 2, 3, bytes([0x11, 0x01, 0x20, 0x30, 0x71, 0x04])), 14, code=0)))
    # feedback followed by another packet (start_over): Add-CID + feedback data,
    # then an IR packet
    F.append(eth_rohc(fb(bytes([0x11]), 14) + fb(fb2(0, 3, 2), 14) + bytes([0xEE, 0x15]) + PAY))
    F.append(eth_rohc(fb(bytes([0x11]), 14) + ir(P_UNC, b'', add_cid=14) + PAY))
    ctx(P_UDP)
    F.append(eth_rohc(fb(bytes([0x37]), 0)))                             # cid 0 (RTP, from above)
    F.append(eth_rohc(fb(bytes([0x37]), 14)))
    F.append(eth_rohc(fb(fb2(0, 3, 0x456, bytes([0x11, 0x2A, 0x71, 0x07, 0x91, 0x01])), 14)))
    F.append(eth_rohc(fb(fb2(0, 1, 0x1, bytes([0x20, 0x30, 0x41, 0x80, 0x71, 0x03])), 14)))
    ctx(P_UNC)
    F.append(eth_rohc(fb(bytes([0x00]), 14)))                            # profile 0, octet 0
    F.append(eth_rohc(fb(bytes([0x09]), 14)))                            # invalid octet
    F.append(eth_rohc(fb(fb2(0, 3, 0x123), 14)))                         # type 2, uncompressed
    ctx(P_IP)
    F.append(eth_rohc(fb(bytes([0x09]), 14)))                            # IP profile type 1
    F.append(eth_rohc(fb(fb2(0, 3, 0x123), 14)))                         # type 2, IP profile
    # no context (cid 15 has none yet)
    F.append(eth_rohc(fb(bytes([0x37]), 15)))
    F.append(eth_rohc(fb(fb2(1, 2, 7), 15)))
    # Add-CID followed by feedback is an error packet
    F.append(eth_rohc(bytes([0xE5]) + fb(bytes([0x11])) + PAY))
    # segments
    F.append(eth_rohc(bytes([0xFE]) + PAY))
    F.append(eth_rohc(bytes([0xE2, 0xFF]) + PAY))
    # PDCP-LTE: feedback for a cid that has no context takes the context from
    # the framing (the profile is known); before the Ethernet frames at the
    # end of the capture create a context for cid 15
    sec('PDCP-LTE feedback without a stored context (cid 15)')
    F.append(pdcp(fb(bytes([0x11]), 15), P_RTP, R, 4))
    F.append(pdcp(fb(fb2(0, 2, 5, bytes([0x11, 0x9])), 15), P_RTP, R, 4))
    F.append(pdcp(fb(fb2(0, 2, 5, bytes([0x71, 0x2])), 15), P_UDP, R, 4))
    F.append(pdcp(fb(bytes([0x11]), 15), P_UNC, R, 4))
    F.append(pdcp(fb(fb2(0, 3, 5), 15), P_UNC, R, 4))
    F.append(pdcp(fb(fb2(0, 3, 5), 15), P_TCP, R, 4))
    F.append(pdcp(fb(bytes([0x11]), 15), P_TCP, R, 4))
    F.append(pdcp(fb(bytes([0x11]), large=9), P_UDP, R, 4, 1))

    # --- PDCP-LTE: compressed packets, small CIDs, one context per cid
    sec('PDCP-LTE compressed packets, small CIDs')
    cfgs = [
        (1, dict(profile=P_RTP, mode=R, ver=4, rnd=0)),
        (2, dict(profile=P_RTP, mode=R, ver=4, rnd=1)),
        (3, dict(profile=P_RTP, mode=R, ver=6, rnd=0)),
        (4, dict(profile=P_RTP, mode=U, ver=4, rnd=0)),
        (5, dict(profile=P_RTP, mode=U, ver=4, rnd=1)),
        (6, dict(profile=P_RTP, mode=O, ver=6, rnd=0)),
        (7, dict(profile=P_RTP, mode=O, ver=4, rnd=0)),
        (8, dict(profile=P_UDP, mode=R, ver=4, rnd=0)),
        (9, dict(profile=P_UDP, mode=U, ver=4, rnd=1)),
        (10, dict(profile=P_UDP, mode=O, ver=6, rnd=0)),
    ]
    for cid, c in cfgs:
        c = dict(c, large=0)
        sec('cid %d: profile %d mode %d ip v%d rnd %d' % (cid, c['profile'], c['mode'], c['ver'], c['rnd']))
        ck = 1 if cid in (8, 9, 6) else 0
        for p in packets(c):
            F.append(pdcp(bytes([0xE0 | cid]) + p, c['profile'], c['mode'], c['ver'], 0, c['rnd'], ck))
    # IP profile (no packet formats), unknown profile, uncompressed small CID
    sec('IP profile / unknown profile (no packet formats, extensions not dissected), uncompressed')
    F.append(pdcp(bytes([0xEB, 0x15]) + PAY, P_IP, R, 6, 0, 0, 0))
    F.append(pdcp(bytes([0xEB, 0xC5]) + PAY, P_IP, R, 6, 0, 0, 0))
    cip = dict(profile=P_IP, mode=R, ver=6, rnd=0, large=0)
    for p in packets(cip)[::5]:
        F.append(pdcp(bytes([0xEB]) + p, P_IP, R, 6, 0, 0, 0))
    F.append(pdcp(bytes([0xEB, 0x95, 0x45, 0xB5, 0xC0, 0x01]) + PAY, P_IP, R, 6, 0, 0, 0))
    F.append(pdcp(bytes([0xED]) + ipv4_udp(), P_UNC))
    F.append(pdcp(bytes([0xED]) + ipv6_udp(), P_UNC))
    F.append(pdcp(bytes([0xED]) + b'\x99\x01\x02', P_UNC))
    F.append(pdcp(ipv4_udp(), P_UNC))
    # IR on a cid that has no context while the framing says mode 0 (reserved):
    # the generated configuration shows "not known" as the mode
    sec('IR with reserved mode, then mode 0 contexts')
    st, dy = ir_rtp()
    F.append(pdcp(ir(P_RTP, st, None, add_cid=12) + PAY, P_RTP, 0, 4))
    F.append(pdcp(bytes([0xEC, 0x15]) + PAY, P_RTP, 0, 4))      # packet type 0 in a mode that has none
    sec('PDCP-LTE feedback for a stored context')
    F.append(pdcp(fb(bytes([0x11]), 1), P_RTP, R, 4))
    F.append(pdcp(fb(fb2(0, 1, 5), 1), P_RTP, R, 4))
    F.append(pdcp(fb(fb2(0, 1, 5), 8), P_UDP, R, 4))
    F.append(pdcp(fb(fb2(0, 0, 5), 8), P_UDP, R, 4))
    F.append(pdcp(bytes([0xE8, 0x15]) + PAY, P_UDP, R, 4))      # mode 0: packet type 0 has no format
    # --- large CID: contexts are keyed by cid 0; set them up with IR + feedback
    sec('PDCP-LTE large CID')

    def large_ctx(profile, mode, v6, rnd, cidlen=1):
        cid = [5, 300, 70000, 20000000][cidlen - 1]
        cb = vl(cid)
        if profile == P_RTP:
            st, dy = ir_rtp(v6=v6, rnd=rnd, rx=1, mode=mode)
        else:
            st, dy = ir_udp(v6=v6, rnd=rnd)
        F.append(pdcp(ir(profile, st, dy if not v6 else None, cidb=cb) + PAY, profile, mode, 6 if v6 else 4, 1, rnd))
        F.append(pdcp(fb(fb2(0, mode, 5), large=cid), profile, mode, 4, 1, rnd))
        return cb

    for cidlen, (prof, mode, v6, rnd) in enumerate([
            (P_RTP, R, False, 0), (P_RTP, U, False, 0), (P_RTP, O, False, 1),
            (P_RTP, R, True, 0), (P_UDP, R, False, 0), (P_UDP, U, False, 0)]):
        cl = cidlen % 4 + 1
        cb = large_ctx(prof, mode, v6, rnd, cl)
        c = dict(profile=prof, mode=mode, ver=6 if v6 else 4, rnd=rnd, large=1)
        sec('large cid ctx: profile %d mode %d v6 %s rnd %d' % (prof, mode, v6, rnd))
        for p in packets(c, mid=cb):
            F.append(pdcp(p, prof, mode, c['ver'], 1, rnd))
    # IR / IR-DYN / feedback with large CID, uncompressed profile with large CID
    sec('large CID IR-DYN, IR uncompressed, feedback with several packets')
    st, dy = ir_rtp(rx=1, mode=O)
    F.append(pdcp(ir_dyn(P_RTP, dyn_v4() + dyn_udp(3) + dyn_rtp(), cidb=vl(9)) + PAY, P_RTP, R, 4, 1))
    F.append(pdcp(ir(P_UNC, b'', cidb=vl(300)) + ipv4_udp(), P_UNC, R, 4, 1))
    F.append(pdcp(bytes([0x45]) + vl(300) + ipv4_udp()[1:], P_UNC, R, 4, 1))
    F.append(pdcp(bytes([0x65]) + vl(300) + ipv6_udp()[1:], P_UNC, R, 4, 1))
    F.append(pdcp(bytes([0x99]) + vl(9) + b'\x01\x02\x03', P_UNC, R, 4, 1))
    F.append(pdcp(fb(bytes([0x11]), large=9) + ir(P_UNC, b'', cidb=vl(9)) + ipv4_udp(), P_UNC, R, 4, 1))
    # uncompressed profile, UDP checksum and rnd fields after UO-0 (cid 10, UDP O mode used above)
    sec('Ethernet IR-DYN with no context (IP version 0), packets with defaults, cid 15')
    F.append(eth_rohc(ir_dyn(P_RTP, dyn_udp(0) + dyn_rtp(), add_cid=15) + PAY))
    F.append(eth_rohc(ir_dyn(P_UDP, dyn_udp(0, 4), add_cid=15) + PAY))
    F.append(eth_rohc(bytes([0xEF, 0x15]) + PAY))
    F.append(eth_rohc(bytes([0xEF, 0x85]) + PAY))
    return F, S


def build_malformed():
    F = []
    st, dy = ir_rtp()
    F.append(eth_rohc(ir(P_RTP, st, dy, add_cid=1) + PAY))
    st, dy = ir_udp()
    F.append(eth_rohc(ir(P_UDP, st, dy, add_cid=2) + PAY))
    # CLOCK and JITTER options on a UDP context are errors
    F.append(eth_rohc(fb(fb2(0, 3, 1, bytes([0x51, 0x05])), 2)))
    F.append(eth_rohc(fb(fb2(0, 3, 1, bytes([0x61, 0x05])), 2)))
    # truncated packets: IR, dynamic chain, feedback, extension 3, lists
    full = ir(P_RTP, *ir_rtp(rx=1, mode=U, tss=1, tis=2, lst='3gp'))
    for n in (1, 2, 3, 4, 6, 12, 16, 20, 26, 30, 36, 40, 44, 50, 56, 60):
        F.append(eth_rohc(full[:n]))
    full = ir(P_UDP, *ir_udp(v6=False))
    for n in (3, 5, 8, 12, 14, 16, 20, 24):
        F.append(eth_rohc(full[:n]))
    full = ir(P_UDP, *ir_udp(v6=True), cidb=b'')
    for n in (4, 6, 10, 30, 44, 46):
        F.append(eth_rohc(full[:n]))
    F.append(eth_rohc(ir_dyn(P_RTP, dyn_v4() + dyn_udp(1) + dyn_rtp(rx=1, mode=U, tss=1, tis=2))[:9]))
    F.append(eth_rohc(ir_dyn(P_UDP, dyn_v4() + dyn_udp(1, 1))[:5]))
    F.append(eth_rohc(bytes([0xF8])))
    F.append(eth_rohc(bytes([0xF8, 0x01])))
    F.append(eth_rohc(bytes([0xFC])))
    F.append(eth_rohc(bytes([0xFD])))
    F.append(eth_rohc(bytes([0xF0])))
    F.append(eth_rohc(bytes([0xF3, 0x11])))
    F.append(eth_rohc(bytes([0xF0, 0x05, 0x11])))
    F.append(eth_rohc(bytes([0xE0])))
    F.append(eth_rohc(bytes([0xE0, 0xE0, 0xE0])))
    F.append(eth_rohc(bytes([0xE1])))
    # truncated compressed packets (PDCP-LTE contexts)
    c = dict(profile=P_RTP, mode=R, ver=4, rnd=0, large=0)
    for cid, (profile, mode, ver, rnd, large) in enumerate([
            (P_RTP, R, 4, 0, 0), (P_RTP, U, 4, 0, 0), (P_UDP, R, 4, 0, 0), (P_RTP, O, 6, 0, 0)], 1):
        c = dict(profile=profile, mode=mode, ver=ver, rnd=rnd, large=large)
        for p in packets(c)[::3]:
            for n in (1, 2, 3):
                F.append(pdcp(bytes([0xE0 | cid]) + p[:n], profile, mode, ver, large, rnd))
        for e in exts(c, 0)[3:]:
            for n in (1, 2, 3, 5):
                head = bytes([0xC5, 0x15, 0xB5]) if profile == P_RTP and ver == 4 else bytes([0xC5, 0xB5])
                F.append(pdcp(bytes([0xE0 | cid]) + (head + e)[:len(head) + n], profile, mode, ver, large, rnd))
    # large-CID uncompressed profile with only the first octet, CID cut
    inner = ipv4_udp()
    F.append(pdcp(inner[:1], P_UNC, large=1))
    F.append(pdcp(inner[:1] + b'\x85', P_UNC, large=1))
    F.append(pdcp(inner[:1] + b'\xff', P_UNC, large=1))
    F.append(pdcp(bytes([0x15]), P_RTP, R, 4, 1))
    F.append(pdcp(bytes([0x55, 0x8f]), P_RTP, R, 4, 1))
    F.append(pdcp(bytes([0x95]), P_RTP, R, 4, 1))
    F.append(pdcp(bytes([0xC5, 0xC0]), P_RTP, R, 4, 1))
    return F


if __name__ == '__main__':
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    F, S = build()
    write_pcap(os.path.join(out, 'rohc-coverage.pcap'), F)
    write_pcap(os.path.join(out, 'rohc-coverage-malformed.pcap'), build_malformed())
    with open(os.path.join(out, 'sections.txt'), 'w') as f:
        for n, name in S:
            f.write('%d %s\n' % (n, name))
    print(len(F), 'frames in main capture')
