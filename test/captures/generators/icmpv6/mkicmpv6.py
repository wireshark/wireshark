#!/usr/bin/env python3
# Generates test/captures/icmpv6_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the synthetic ICMPv6 coverage captures.

Usage: mkicmpv6.py <outdir>      (MARKS=1 prints the frame ranges)
Writes icmpv6-coverage.pcap (valid traffic) and
icmpv6-coverage-malformed.pcap.  Every packet is built with struct;
nothing comes from a real network.
"""
import os
import struct
import sys

T0 = 1700006400          # a multiple of 86400: midnight UTC
MAC_A = bytes.fromhex('020000000001')
MAC_B = bytes.fromhex('020000000002')


def a6(s):
    import socket
    return socket.inet_pton(socket.AF_INET6, s)


A = a6('2001:db8::1')
B = a6('2001:db8::2')
C = a6('2001:db8:1::7')
LA = a6('fe80::1')
LB = a6('fe80::2')
ALLNODES = a6('ff02::1')
ALLROUTERS = a6('ff02::2')
MLD2 = a6('ff02::16')
SOLNODE = a6('ff02::1:ff00:2')
GRP = a6('ff1e::1234')


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ip6(payload, nxt=58, src=A, dst=B, hlim=64, tc=0, flow=0, plen=None):
    return struct.pack('!IHBB16s16s', 0x60000000 | (tc << 20) | flow,
                       len(payload) if plen is None else plen, nxt, hlim, src, dst) + payload


def icmp6(t, c, rest, src=A, dst=B, ck=None, plen=None):
    """ICMPv6 message: type, code, everything after the checksum."""
    m = struct.pack('!BBH', t, c, 0) + rest
    if ck is None:
        ph = src + dst + struct.pack('!I3xB', len(m) if plen is None else plen, 58)
        ck = csum(ph + m)
    return m[:2] + struct.pack('!H', ck) + m[4:]


def eth(pl, et=0x86dd, src=MAC_A, dst=MAC_B):
    return dst + src + struct.pack('!H', et) + pl


def udp8(sp=33434, dp=33435, n=0):
    return struct.pack('!HHHH', sp, dp, 8 + n, 0) + b'\0' * n


def orig(nxt=17, l4=None, src=B, dst=C, hlim=60, pad=0):
    if l4 is None:
        l4 = udp8()
    return ip6(l4, nxt=nxt, src=src, dst=dst, hlim=hlim) + b'\0' * pad


def opt(t, body=b'', length=None):
    tot = 2 + len(body)
    pad = (-tot) % 8
    body = body + b'\0' * pad
    return struct.pack('!BB', t, length if length is not None else (2 + len(body)) // 8) + body


def lladdr_mac(m=MAC_A):
    return m


def dnsname(n):
    out = b''
    for lab in n.split('.'):
        out += bytes([len(lab)]) + lab.encode()
    return out + b'\0'


# a fixed DER SubjectPublicKeyInfo with a made-up public key (no secrets)
_ALG = bytes.fromhex('300d06092a864886f70d0101010500')
_KEY = bytes.fromhex('300a0203010001' '0203010001')
_BIT = bytes([0x03, len(_KEY) + 1, 0x00]) + _KEY
SPKI = bytes([0x30, len(_ALG) + len(_BIT)]) + _ALG + _BIT
# DER Name: CN=a
NAME_X501 = bytes.fromhex('300c310a30080603550403' '0c0161')
frames = []
malformed = []
marks = []
tcur = [T0 + 600]


def mark(n):
    marks.append((len(frames) + 1, n))


def add(f, dt=1, lst=None, usec=0, secs=None, caplen=None):
    if secs is None:
        tcur[0] += dt
        secs = tcur[0]
    (frames if lst is None else lst).append((secs, usec, f, caplen))


def msg(t, c, rest, src=A, dst=B, hlim=64, lst=None, ck=None, **kw):
    add(eth(ip6(icmp6(t, c, rest, src, dst, ck=ck), src=src, dst=dst, hlim=hlim)), lst=lst, **kw)


def nd(t, c, rest, src=LA, dst=LB, hlim=255, lst=None, ck=None, **kw):
    msg(t, c, rest, src=src, dst=dst, hlim=hlim, lst=lst, ck=ck, **kw)


def ts_le32(s, us): return struct.pack('<II', s, us)
def ts_be32(s, us): return struct.pack('>II', s, us)
def ts_le64(s, us): return struct.pack('<QQ', s, us)
def ts_be64(s, us): return struct.pack('>QQ', s, us)


def echo(t=128, ident=0x1234, seq=1, data=b'', src=A, dst=B, ck=None, usec=0, dt=1, lst=None, hlim=64):
    msg(t, 0, struct.pack('!HH', ident, seq) + data, src=src, dst=dst, ck=ck, usec=usec, dt=dt, lst=lst, hlim=hlim)


# ---------------------------------------------------------------- options
def o_slla(m=MAC_A, t=1): return opt(t, m)
def o_eui64(t=1): return opt(t, bytes.fromhex('0200000000000001') + b'\0' * 6)
def o_ll_long(t=1): return opt(t, bytes(range(1, 23)))
def o_prefix(plen=64, flags=0xc0, v=2592000, p=604800, prefix=a6('2001:db8:5::')):
    return opt(3, struct.pack('!BBIII16s', plen, flags, v, p, 0, prefix))
def o_mtu(m=1500): return opt(5, struct.pack('!HI', 0, m))
def o_cga(ext=b''):
    params = bytes(16) + a6('2001:db8::')[:8] + b'\x01' + SPKI + ext
    pad = (-(4 + len(params))) % 8
    return opt(11, struct.pack('!BB', pad, 0) + params + b'\0' * pad)
def o_rsa(sig=20):
    return opt(12, b'\0\0' + bytes(range(16)) + b'\xaa' * sig)
def o_ps(sig=20):
    return opt(32, b'\0\0' + bytes(range(16)) + b'\xbb' * sig)
def o_ts(): return opt(13, b'\0' * 6 + struct.pack('!Q', ((T0 + 700) << 16) | 0x8000))
def o_nonce(): return opt(14, b'\x01\x02\x03\x04\x05\x06')
def o_trust(nt, name):
    pad = (-(4 + len(name))) % 8
    return opt(15, struct.pack('!BB', nt, pad) + name + b'\0' * pad)
def o_cert(ct, data):
    pad = (-(4 + len(data))) % 8
    return opt(16, struct.pack('!BB', ct, 0) + data + b'\0' * pad)
def o_routeinfo(plen, pref, life, prefix=b''):
    return opt(24, struct.pack('!BBI', plen, pref << 3, life) + prefix)
def o_rdnss(life, addrs): return opt(25, b'\0\0' + struct.pack('!I', life) + b''.join(addrs))
def o_dnssl(life, names, pad=0):
    b = b''.join(dnsname(n) for n in names)
    b += b'\0' * ((-(8 + len(b))) % 8)
    return opt(31, b'\0\0' + struct.pack('!I', life) + b)
def o_earo(status=0, opaque=0, flags=0x01, tid=7, life=300, rovr=bytes(8)):
    return opt(33, struct.pack('!BBBBH', status, opaque, flags, tid, life) + rovr)
def o_aro(status=0, life=300, eui=bytes(range(8))):
    return opt(33, struct.pack('!BBBBH', status, 0, 0, 0, life) + eui)
def o_6co(ctxlen, flags, life, prefix=b''):
    return opt(34, struct.pack('!BBHH', ctxlen, flags, 0, life) + prefix)
def o_abro(): return opt(35, struct.pack('!HHH16s', 1, 2, 3000, A))
def o_6cio(bits=0x00ff00ff00ff): return opt(36, struct.pack('!Q', bits)[2:])
def o_capport(url=b'https://example.net/captive'):
    return opt(37, url)
def o_pref64(plc, life=300, prefix=bytes(range(1, 13))):
    return opt(38, struct.pack('!H', (life << 3) | plc) + prefix)
def o_pvd(flags, delay, seq, fqdn, ra=b'', inner=b''):
    h = struct.pack('!HH', (flags << 4) | delay, seq) + dnsname(fqdn)
    pad = (-(2 + len(h))) % 8
    return opt(21, h + b'\0' * pad + ra + inner)
def o_dnr(prio=1, life=3600, adn='dns.example.net', addrs=(), svc=b'', adn_only=False, raw=None):
    n = dnsname(adn)
    b = struct.pack('!HIH', prio, life, len(n)) + n
    if not adn_only:
        ab = b''.join(addrs)
        b += struct.pack('!H', len(ab)) + ab + struct.pack('!H', len(svc)) + svc
    return opt(144, b)
def o_lla19(code=1, b=b'\x11\x22\x33\x44\x55'): return opt(19, bytes([code]) + b)
def o_naack(status=1): return opt(20, bytes([1, status]) + bytes(4))
def o_ipa(t=17, code=1, plen=64): return opt(t, struct.pack('!BB4x16s', code, plen, A))
def o_map(): return opt(23, struct.pack('!BBI16s', 0x35, 0x80, 600, A))
def o_hkreq():
    return opt(27, bytes([1, 0x20]) + bytes(range(10)) + b'\0')
def o_hkrep():
    return opt(28, struct.pack('!BBH', 1, 0x10, 900) + bytes(range(8)) + b'\0')
def o_hai(code=1, v=b'\x01\x02\x03'):
    return opt(29, struct.pack('!BB', code, len(v)) + v)
def o_mnid(code=1, v=b'node@example'):
    return opt(30, struct.pack('!BB', code, len(v)) + v)


def pvd_ra():
    return struct.pack('!BBHBBHII', 134, 0, 0, 64, 0x80, 1800, 0, 0)[:16]


# ------------------------------------------------------------------ RPL
def r_opt(t, body=b'', length=None):
    return struct.pack('!BB', t, len(body) if length is None else length) + body


def r_metric(items):
    return r_opt(2, b''.join(items))


def metric(mtype, flags, data):
    return struct.pack('!BHB', mtype, flags, len(data)) + data


def gen_main():
    pay = bytes(range(0x10, 0x30))
    # ---------------------------------------------------------- Echo
    mark('echo with timestamps')
    for n, mk in enumerate((ts_le32, ts_be32, ts_le64, ts_be64)):
        t = tcur[0] + 1
        echo(128, 0x1000 + n, n + 1, mk(t, 250000) + pay, usec=250000)
        echo(129, 0x1000 + n, n + 1, mk(tcur[0], 250000) + pay, src=B, dst=A, usec=260000, dt=0)
    mark('echo payloads and tracking')
    echo(128, 0x1010, 1, ts_le32(T0 - 5 * 86400, 5) + pay)
    echo(129, 0x1010, 1, ts_le32(T0 - 5 * 86400, 5) + pay, src=B, dst=A)
    echo(128, 0x1011, 1, b'')
    echo(129, 0x1011, 1, b'', src=B, dst=A)
    echo(128, 0x1012, 1, b'The quick brown fox jumps over the lazy dog')
    echo(129, 0x1012, 1, b'The quick brown fox jumps over the lazy dog', src=B, dst=A)
    # HiPerConTracer over ICMPv6 (heuristic subdissector)
    hpct = struct.pack('!IBBHQ', 0x00123456, 3, 1, 0x00ff, (T0 - 212803200) * 10**9 + 5) + bytes(48)
    echo(128, 0x1014, 1, hpct)
    echo(129, 0x1014, 1, hpct, src=B, dst=A)
    echo(128, 0x1013, 1, b'abc')
    echo(129, 0x1013, 1, b'abc', src=B, dst=A)
    echo(128, 0x1020, 1, pay)                                   # no reply (-2: no response found)
    echo(129, 0x1021, 1, pay, src=B, dst=A)                     # reply without request
    echo(128, 0x1022, 1, pay)
    echo(129, 0x1022, 1, pay, src=B, dst=A)
    echo(129, 0x1022, 1, pay, src=B, dst=A)                     # duplicate reply
    echo(128, 0x1023, 1, pay, dst=ALLNODES)                     # multicast
    echo(128, 0x1024, 1, pay, ck=0xffff)                        # checksum 0xffff (key 0), bad checksum
    echo(128, 0x1025, 1, pay, ck=0x1234)
    echo(128, 0x1026, 1, bytes(range(256)) * 3)
    echo(129, 0x1026, 1, bytes(range(256)) * 3, src=B, dst=A)
    # fragmented echo request: fragments are reassembled before ICMPv6
    big = icmp6(128, 0, struct.pack('!HH', 0x1030, 1) + bytes(range(200)))
    fh = lambda off, m, nxt=58: struct.pack('!BxHI', nxt, (off << 3) | m, 0x4321)
    add(eth(ip6(fh(0, 1) + big[:104], nxt=44)))
    add(eth(ip6(fh(13, 0) + big[104:], nxt=44)))
    # VLAN, GRE and Teredo
    for vid in (100, 200):
        for t in (128, 129):
            s, d = (A, B) if t == 128 else (B, A)
            add(MAC_B + MAC_A + struct.pack('!HHH', 0x8100, vid, 0x86dd)
                + ip6(icmp6(t, 0, struct.pack('!HH', 0x1040, vid) + pay, s, d), src=s, dst=d))
    for n in range(2):
        for t in (128, 129):
            s, d = (A, B) if t == 128 else (B, A)
            inner = ip6(icmp6(t, 0, struct.pack('!HH', 0x1050, n) + pay, s, d), src=s, dst=d)
            gre = struct.pack('!HH', 0, 0x86dd) + inner
            add(eth(_ip4(gre, 47), et=0x0800))
    teredo = ip6(icmp6(128, 0, struct.pack('!HH', 0x1060, 1) + b'\x01\x02\x03\x04' + pay, A, B), src=A, dst=B)
    add(eth(_ip4(struct.pack('!HHHH', 40000, 3544, 8 + len(teredo), 0) + teredo, 17), et=0x0800))

    # ------------------------------------------------- error messages
    mark('destination unreachable and other errors')
    od = orig()
    for c in range(8):
        msg(1, c, b'\0' * 4 + od)
    msg(1, 99, b'\0' * 4 + od)
    msg(1, 3, b'\0' * 4 + orig(nxt=6, l4=struct.pack('!HHI', 40000, 80, 1), src=B, dst=C))
    inner_echo = icmp6(128, 0, struct.pack('!HH', 0x1070, 1) + pay, B, C)
    msg(1, 0, b'\0' * 4 + orig(nxt=58, l4=inner_echo))
    inner_rep = icmp6(129, 0, struct.pack('!HH', 0x1070, 1) + pay, B, C)
    msg(1, 0, b'\0' * 4 + orig(nxt=58, l4=inner_rep))
    msg(1, 0, b'\0' * 4 + b'\x45\x00' + bytes(30))                  # contained packet is not IPv6
    msg(1, 0, b'\0' * 4 + bytes(10))
    msg(3, 0, b'\0' * 4 + od)
    msg(3, 1, b'\0' * 4 + od)
    msg(3, 7, b'\0' * 4 + od)
    msg(2, 0, struct.pack('!I', 1280) + od)
    for c in range(5):
        msg(4, c, struct.pack('!I', 40) + od)
    # RFC 4884: length in 64-bit words
    odp = orig(pad=128 - 48)
    ext = lambda objs, ver=2: _ext(objs, ver)
    msg(1, 0, bytes([16, 0, 0, 0]) + odp)                            # length without extension
    msg(1, 0, bytes([16, 0, 0, 0]) + odp + ext([_obj(1, 1, struct.pack('>I', (1000 << 12) | 0x100 | 64))]))
    msg(3, 0, bytes([16, 0, 0, 0]) + odp + ext([_obj(2, 0x0f, struct.pack('>I', 9) + struct.pack('>HH', 1, 0) + bytes([10, 1, 1, 1])
                                                    + bytes([5]) + b'eth0' + struct.pack('>I', 1500))]))
    # reproducer of "ICMPv6: Use uint8_t for the original datagram length": length 129 words
    inner = orig(l4=udp8(n=1032 - 48), pad=0)
    assert len(inner) == 1032
    msg(1, 0, bytes([0x81, 0, 0, 0]) + inner + ext([_obj(2, 0, b'\0' * 4)]))
    # error inside an error: the contained datagram is an ICMPv6 error
    nested = icmp6(1, 0, b'\0' * 4 + od, B, C)
    msg(1, 0, b'\0' * 4 + orig(nxt=58, l4=nested))

    # ------------------------------------------------------------ MLD
    mark('MLD')
    mld = lambda t, mrd, grp, src=LA, dst=ALLNODES: msg(t, 0, struct.pack('!HH16s', mrd, 0, grp), src=src, dst=dst, hlim=1)
    mld(130, 10000, bytes(16), dst=ALLNODES)
    mld(130, 1000, GRP, dst=GRP)
    mld(131, 0, GRP, dst=GRP)
    mld(132, 0, GRP, dst=ALLROUTERS)
    q2 = lambda mrc, qqi, srcs, s_flag=0, qrv=2: msg(130, 0, struct.pack('!HH16sBBH', mrc, 0, GRP, (s_flag << 3) | qrv, qqi, len(srcs)) + b''.join(srcs), src=LA, dst=GRP, hlim=1)
    q2(10000, 125, [])
    q2(0x8000 | 0x2123, 130, [A, B], s_flag=1)
    q2(0xf0ff, 0xff, [A], qrv=7)
    rec = lambda rt, aux, srcs, grp=GRP, auxd=b'': struct.pack('!BBH16s', rt, aux, len(srcs), grp) + b''.join(srcs) + auxd
    rep = lambda recs: msg(143, 0, struct.pack('!HH', 0, len(recs)) + b''.join(recs), src=LA, dst=MLD2, hlim=1)
    rep([rec(1, 0, [A, B])])
    rep([rec(2, 0, []), rec(3, 1, [A], auxd=b'\1\2\3\4'), rec(4, 0, [B, C]), rec(5, 0, []), rec(6, 0, [A]), rec(9, 0, [])])
    rep([])

    # ------------------------------------------------ Neighbor Discovery
    mark('neighbor discovery messages and options')
    rs = lambda opts, **kw: nd(133, 0, bytes(4) + b''.join(opts), dst=ALLROUTERS, **kw)
    rs([])
    rs([o_slla()])
    rs([o_eui64(), o_slla(MAC_B, 2)])
    rs([o_ll_long()])
    rs([o_ts(), o_nonce(), o_rsa(), o_cga()], hlim=255)
    ra = lambda opts, flags=0xc8, life=1800, hl=64: nd(134, 0, struct.pack('!BBHII', hl, flags, life, 30000, 1000) + b''.join(opts), dst=ALLNODES)
    ra([])
    ra([o_slla(), o_mtu(), o_prefix()], flags=0x00)
    ra([o_prefix(64, 0x20), o_prefix(48, 0x10), o_prefix(128, 0xff, 0xffffffff, 0xffffffff)], flags=0xff)
    ra([o_routeinfo(0, 0, 3600), o_routeinfo(64, 1, 600, bytes(8)), o_routeinfo(128, 3, 0xffffffff, A)], flags=0x10)
    ra([o_rdnss(3600, [A]), o_rdnss(0xffffffff, [A, B]), o_dnssl(3600, ['example.com', 'sub.example.net']),
        o_dnssl(0xffffffff, ['a.b'])])
    ra([opt(7, struct.pack('!HI', 0, 600000)), opt(8, struct.pack('!HHH', 0, 100, 1800)), o_map(),
        opt(26, bytes([0x80, 0, 0, 0, 0, 0])), o_capport(), o_capport(b'https://example.net/cp.json')])
    ra([o_pref64(0), o_pref64(1), o_pref64(2), o_pref64(3), o_pref64(4), o_pref64(5)])
    ra([o_6co(64, 0x11, 600, bytes(8)), o_6co(0, 0x00, 0), o_6co(128, 0x1f, 600, A), o_abro(), o_6cio(), o_6cio(0xffffffffffff)])
    ra([opt(9, bytes(6) + A + B), opt(10, bytes(6) + C), opt(7, struct.pack('!HI', 0, 5))])
    ra([opt(39, bytes(6)), opt(40, bytes(14)), opt(41, bytes.fromhex('00000000 0e10'.replace(' ', '')) + bytes.fromhex('20010db8000000000000000000000001')), opt(42, bytes(6)), opt(99, bytes(6)), opt(255, bytes(14))])
    ra([o_pvd(0xc00, 3, 7, 'pvd.example.net'), o_pvd(0x200, 1, 8, 'pvd.example.org', ra=pvd_ra(), inner=o_mtu(1280)),
        o_pvd(0x000, 0, 9, 'pvd.a'), o_pvd(0x800, 1, 10, 'x.example.com', inner=o_slla())])
    ra([o_dnr(1, 3600, 'dns.example.net', [A], svc=b'\x00\x01\x00\x06\x02h2\x02h3')])
    ra([o_dnr(1, 0xffffffff, 'dns.example.net', adn_only=True), o_dnr(2, 60, 'doh.example', [A, B], svc=b'')])
    # Neighbor solicitation and advertisement
    ns = lambda tgt, opts, **kw: nd(135, 0, bytes(4) + tgt + b''.join(opts), dst=SOLNODE, **kw)
    ns(A, [])
    ns(A, [o_slla()], src=bytes(16))
    ns(A, [o_aro(0, 300), o_slla()])
    ns(A, [o_earo(0x85, 3, 0x11, 9, 600, bytes(8))], hlim=255)
    ns(A, [o_earo(0x05, 3, 0x0d, 9, 600, bytes(16))])
    ns(A, [o_earo(0, 0, 0x01, 1, 60, bytes(24)), o_earo(0, 0, 0x03, 1, 60, bytes(32))])
    na = lambda fl, tgt, opts, **kw: nd(136, 0, struct.pack('!I', fl << 24) + tgt + b''.join(opts), **kw)
    na(0xe0, A, [o_slla(MAC_A, 2)])
    na(0x00, A, [])
    na(0x00, A, [o_eui64(2)])
    na(0x80, A, [])
    na(0x40, A, [o_aro(1, 300)])
    na(0x20, A, [o_earo(0x41, 0, 0x01, 1, 60, bytes(8)), o_earo(0x02, 0, 0x01, 1, 60, bytes(8))])
    na(0x60, A, [o_aro(3, 0)])
    na(0xa0, A, [o_naack(1), o_ipa(17, 1, 64), o_ipa(18, 2, 128), o_lla19(), o_hai(), o_mnid(),
                 o_hkreq(), o_hkrep(), o_ll_long(2)])
    # Redirect
    rd = lambda opts, **kw: nd(137, 0, bytes(4) + A + B + b''.join(opts), **kw)
    rd([])
    rd([opt(2, MAC_A), opt(4, bytes(6) + ip6(udp8(), nxt=17, src=B, dst=C))])
    rd([opt(4, bytes(6) + b'\x45\0' + bytes(46))])
    rd([opt(4, bytes(6))])
    # Inverse ND, Mobile IPv6 prefix, SEND, FMIPv6
    nd(141, 0, bytes(4) + opt(1, MAC_A) + opt(2, MAC_B) + opt(9, bytes(6) + A) + opt(10, bytes(6) + B))
    nd(142, 0, bytes(4) + opt(2, MAC_B) + opt(10, bytes(6) + A))
    nd(148, 0, struct.pack('!HH', 0x4242, 0xffff) + o_trust(2, b'ca.example.net'))
    nd(149, 0, struct.pack('!HHHH', 0x4242, 2, 1, 0) + o_trust(2, b'ca.example.net') + o_cert(2, b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a'))
    nd(149, 0, struct.pack('!HHHH', 0x4243, 1, 1, 0) + o_trust(1, NAME_X501) + o_trust(7, b'xxxxxxxxxxxx') + o_cga(struct.pack('!HH', 0x0001, 4) + b'abcd')
       + o_cga())
    nd(149, 0, struct.pack('!HHHH', 0x4243, 1, 1, 0) + o_ps() + o_rsa())

    mark('mobility, multicast router, RR, node information')
    msg(144, 0, struct.pack('!HH', 0x1111, 0), dst=a6('2001:db8::fdff:ffff:ffff:fffe'))
    msg(145, 0, struct.pack('!HH', 0x1111, 0) + A + B)
    msg(145, 0, struct.pack('!HH', 0x1111, 0))
    msg(146, 0, struct.pack('!HH', 0x2222, 0))
    msg(147, 0, struct.pack('!HH', 0x2222, 0xc000) + o_prefix() + o_prefix(48, 0xc0))
    msg(147, 0, struct.pack('!HH', 0x2222, 0x0000))
    # Experimental mobility / FMIPv6 (type 150 / 154), subtypes and codes
    for t in (150, 154):
        for st, code in ((2, 0), (2, 1), (3, 0), (3, 1), (3, 5), (4, 0), (4, 1), (4, 2), (5, 0), (5, 1), (5, 7), (9, 0)):
            msg(t, code, bytes([st, 0x00 if st != 4 else 0xc0]) + struct.pack('!H', 0x3333) + o_slla() + o_prefix(), hlim=64)
    msg(154, 0, bytes([4, 0x7f]) + struct.pack('!H', 0x3333))
    # Multicast router advertisement, solicitation, termination
    msg(151, 20, struct.pack('!HH', 125, 2), src=LA, dst=ALLNODES, hlim=1)
    msg(152, 0, b'\0\0', src=LA, dst=ALLROUTERS, hlim=1)
    msg(153, 3, b'\0\0', src=LA, dst=ALLROUTERS, hlim=1)
    # Router renumbering: command with match prefix and use prefix parts, result, sequence reset
    rrh = lambda seq, segn, fl, md: struct.pack('!IBBHI', seq, segn, fl, md, 0)
    mp = lambda op, ordn, ml, mn, mx, pf: struct.pack('!BBBBBBH16s', op, 24, ordn, ml, mn, mx, 0, pf)
    up = lambda ul, kl, fm, raf, v, p, fl, pf: struct.pack('!BBBBIII16s', ul, kl, fm, raf, v, p, fl, pf)
    msg(138, 0, rrh(1, 0, 0xf8, 100))
    msg(138, 0, rrh(2, 1, 0xff, 200) + mp(1, 1, 48, 64, 128, a6('2001:db8:1::')) + up(48, 48, 0xc0, 0xc0, 3600, 1800, 0x40, a6('2001:db8:2::'))
        + up(64, 0, 0x80, 0x00, 0xffffffff, 0xffffffff, 0x20, a6('2001:db8:3::')))
    msg(138, 0, rrh(3, 0, 0x01, 0) + mp(2, 2, 130, 0, 128, a6('2001:db8::')) + up(0, 0, 0, 0, 0, 0, 0, bytes(16)))
    msg(138, 0, rrh(4, 0, 0, 0) + mp(3, 3, 64, 0, 128, a6('2001:db8::')))
    msg(138, 0, rrh(4, 0, 0, 0) + mp(9, 3, 64, 0, 128, a6('2001:db8::')))
    msg(138, 1, rrh(5, 0, 0xc0, 0))
    msg(138, 1, rrh(5, 0, 0xc0, 0) + struct.pack('!HBBI16s', 0xc000, 1, 64, 7, a6('2001:db8:1::'))
        + struct.pack('!HBBI16s', 0x8000, 2, 200, 8, a6('2001:db8:2::')))
    msg(138, 255, rrh(0xffffffff, 0, 0, 0))
    msg(138, 7, rrh(6, 0, 0, 0))
    # Node information: queries and replies
    ni = lambda t, c, qt, fl, nonce, data=b'': msg(t, c, struct.pack('!HH8s', qt, fl, nonce) + data)
    nonce = bytes(range(8))
    ni(139, 0, 0, 0, nonce)
    ni(139, 0, 1, 0, nonce, A)
    ni(139, 1, 2, 0x0007, nonce, dnsname('host.example.com'))
    ni(139, 2, 4, 0x001f, nonce, bytes([192, 0, 2, 9]))
    ni(139, 5, 3, 0xffff, nonce, b'')
    ni(140, 0, 0, 0, nonce)
    ni(140, 0, 0, 0, nonce, b'\1\2\3\4')
    ni(140, 0, 2, 0x0001, nonce, struct.pack('!I', 120) + dnsname('node.example.org') + dnsname('alias.example') + b'\0\0')
    ni(140, 0, 2, 0, nonce, struct.pack('!I', 0))
    ni(140, 0, 3, 0x0014, nonce, struct.pack('!I', 60) + A + struct.pack('!I', 0xffff) + B)
    ni(140, 0, 4, 0, nonce, struct.pack('!II', 60, 0xc0000201) + struct.pack('!II', 10, 0xc0000202))
    ni(140, 1, 1, 0, nonce, b'')
    ni(140, 2, 9, 0, nonce, b'')
    ni(140, 9, 9, 0, nonce, b'')

    mark('RPL')
    # RPL Control Messages (type 155)
    # The argument n selects the key identifier mode n & 3 (in the top two
    # bits) and the security level n.
    sec0 = lambda lvl: struct.pack('!BBBB', 0x80, 1, ((lvl & 3) << 6) | lvl, 0) + struct.pack('!I', 77)
    key = {0: b'\x04', 4: b'\x04', 1: b'', 5: b'', 2: bytes(8) + b'\x04', 6: bytes(8) + b'\x04', 3: bytes(8) + b'\x04', 7: b''}
    sec = lambda lvl: sec0(lvl) + key[lvl]
    rpl = lambda c, body, **kw: msg(155, c, body, src=LA, dst=ALLNODES, hlim=64, **kw)
    metrics = r_metric([
        metric(1, 0x0200 | 0x0010, struct.pack('!H', 0x0003) + bytes([1, 2, 3, 4])),  # NSA with TLV
        metric(1, 0x0000, struct.pack('!H', 0x0001)),
        metric(2, 0x0100, struct.pack('!HH', 0x0922, 0x0801)),
        metric(3, 0x0400, struct.pack('!H', 0x0105)),
        metric(4, 0x0000, struct.pack('!II', 1000, 2000)),
        metric(5, 0x0000, struct.pack('!II', 5, 6)),
        metric(6, 0x0000, bytes([0]) + bytes([0x22, 0x44, 0xc1])),
        metric(7, 0x0000, struct.pack('!HH', 128, 256)),
        metric(8, 0x0200, bytes([0]) + struct.pack('!HH', 0x1241, 0x0201)),
        metric(8, 0x0080, bytes([0]) + struct.pack('!H', 0x0081)),
        metric(8, 0x0000, bytes([0]) + struct.pack('!H', 0x0081)),
    ])
    dag = a6('2001:db8:aa::1')
    opts_all = [
        r_opt(0)[:1], r_opt(1, b'\0\0\0'), metrics,
        r_opt(3, struct.pack('!BBI', 0, 0x18, 600)),
        r_opt(3, struct.pack('!BBI8s', 64, 0x08, 0xffffffff, a6('2001:db8:5::')[:8])),
        r_opt(3, struct.pack('!BBI16s', 128, 0x00, 60, A)),
        r_opt(4, struct.pack('!BBBBHHHBBH', 0x0b, 8, 12, 3, 256, 128, 1, 0, 10, 100)),
        r_opt(5, struct.pack('!BB', 0, 0)),
        r_opt(5, struct.pack('!BB8s', 0, 64, a6('2001:db8:6::')[:8])),
        r_opt(5, struct.pack('!BB16s', 0, 128, A)),
        r_opt(6, struct.pack('!BBBB', 0xc0, 0xe4, 5, 30)),
        r_opt(6, struct.pack('!BBBB16s', 0x80, 0x1b, 5, 30, B)),
        r_opt(7, struct.pack('!BB16sB', 1, 0xe0, dag, 3)),
        r_opt(8, struct.pack('!BBII4s16s', 64, 0xe0, 3600, 1800, bytes(4), a6('2001:db8:7::'))),
        r_opt(9, struct.pack('!I', 0x12345678)),
    ]
    rpl(0, bytes([0x80, 0]) + b''.join(opts_all[:3]))                       # DIS
    rpl(0, bytes([0, 0]) + opts_all[7] + opts_all[13])
    rpl(0x80, sec(0) + bytes([0, 0]) + opts_all[2])      # secure DIS, KIM 0
    rpl(1, struct.pack('!BBHBBBB16s', 1, 3, 256, 0xa9, 5, 0, 0, dag) + b''.join(opts_all[:15]))
    rpl(1, struct.pack('!BBHBBBB16s', 1, 3, 256, 0x40, 5, 0, 0, dag))
    rpl(0x81, sec(1) + struct.pack('!BBHBBBB16s', 1, 3, 256, 0x01, 5, 0, 0, dag))
    rpl(0x81, sec(2) + struct.pack('!BBHBBBB16s', 1, 3, 256, 0x01, 5, 0, 0, dag))
    rpl(0x81, sec(3) + struct.pack('!BBHBBBB16s', 1, 3, 256, 0x01, 5, 0, 0, dag))
    rpl(0x81, sec(7) + struct.pack('!BBHBBBB16s', 1, 3, 256, 0x01, 5, 0, 0, dag))
    rpl(0x81, sec(4) + struct.pack('!BBHBBBB16s', 1, 3, 256, 0x01, 5, 0, 0, dag))
    dao = lambda c, fl, body=b'': rpl(c, struct.pack('!BBBB', 1, fl, 0, 9) + (dag if fl & 0x40 else b'') + body)
    dao(2, 0x80, opts_all[5] + opts_all[10] + opts_all[8])
    dao(2, 0xc0, opts_all[9] + opts_all[11])
    rpl(0x82, sec(6) + struct.pack('!BBBB', 1, 0, 0, 9) + opts_all[9])
    ack = lambda c, fl: rpl(c, struct.pack('!BBBB', 1, fl, 9, 0) + (dag if fl & 0x80 else b''))
    ack(3, 0x00)
    ack(3, 0x80)
    rpl(0x83, sec(5) + struct.pack('!BBBB', 1, 0x80, 9, 0) + dag)
    dco = lambda fl: rpl(7, struct.pack('!BBBB', 1, fl, 0, 9) + (dag if fl & 0x40 else b'') + opts_all[9])
    dco(0x80)
    dco(0xc0)
    rpl(8, struct.pack('!BBBB', 1, 0x80, 9, 0) + dag + opts_all[9])
    rpl(8, struct.pack('!BBBB', 1, 0x00, 9, 0))
    rpl(0x8a, sec(1) + struct.pack('!BBH16sI', 1, 0x80, 0x0102, dag, 5) + opts_all[6])
    rpl(0x8a, sec(0) + struct.pack('!BBH16sI', 1, 0x00, 0x0102, dag, 5))
    # P2P route discovery option in DIO-like messages
    rdo = lambda fl, ltmr, compr, addrs=b'': r_opt(10, struct.pack('!BB16s', fl | compr, ltmr, A) + addrs)
    rpl(1, struct.pack('!BBHBBBB16s', 1, 3, 256, 0x01, 5, 0, 0, dag) + rdo(0x80, 0x45, 4, bytes(12) * 0 + bytes(range(12)) * 2))
    rpl(1, struct.pack('!BBHBBBB16s', 1, 3, 256, 0x01, 5, 0, 0, dag) + rdo(0x40 | 0x80, 0x00, 0, B))
    rpl(1, struct.pack('!BBHBBBB16s', 1, 3, 256, 0x01, 5, 0, 0, dag) + rdo(0x40 | 0x30, 0xc3, 0, B + C))
    rpl(1, struct.pack('!BBHBBBB16s', 1, 3, 256, 0x01, 5, 0, 0, dag) + rdo(0x00, 0x7f, 15, b'\1\2'))
    dro = lambda c, ver, fl, opts=b'': rpl(c, struct.pack('!BBH16s', 1, ver, fl, dag) + opts)
    dro(4, 0, 0xb000, rdo(0x00, 0x05, 0, B))
    dro(4, 3, 0xffff, rdo(0xb0, 0xc5, 0, B))
    dro(0x84, 0, 0x4000, rdo(0x00, 0x05, 0, B))
    rpl(5, struct.pack('!BBH16s', 1, 0, 0xc000, dag))
    rpl(0x85, sec(0) + struct.pack('!BBH16s', 1, 5, 0x3fff, dag))
    rpl(0x45, b'\0' * 8)                                                   # unknown code

    mark('ILNP, 6LoWPAN-ND, MPL, Extended Echo, unknown types')
    msg(156, 0, bytes([2, 0, 0, 0]) + struct.pack('!8sHH', bytes(range(8)), 10, 600) + struct.pack('!8sHH', bytes(range(8, 16)), 20, 0))
    msg(156, 0, bytes([0, 0, 0, 0]))
    for code, sfx in ((0x00, 0), (0x01, 1), (0x02, 2), (0x03, 3), (0x04, 4), (0x15, 5), (0x20, 0xf)):
        rovr = {0: 8, 1: 8, 2: 16, 3: 24, 4: 32, 5: 8, 0xf: 8}[sfx]
        for t in (157, 158):
            msg(t, code, struct.pack('!BBH', 0, 0, 300) + bytes(rovr) + A, src=LA, dst=LB, hlim=64)
    mpl = lambda code, body: msg(159, code, body, src=LA, dst=ALLNODES, hlim=64)
    mpl(0, b'')
    mpl(0, bytes([5, (1 << 2) | 0]) + bytes([0b10100000]))
    mpl(0, bytes([250, (2 << 2) | 1, 0x12, 0x34, 0xff, 0x01]))
    mpl(0, bytes([1, (0 << 2) | 2]) + bytes(range(8)) + bytes([9, (1 << 2) | 3]) + A + bytes([0x80]))
    mpl(0, bytes([3, 0 | 2]) + bytes(range(8)) + bytes([4, 0]))
    # Extended echo (RFC 8335) request and reply with interface identification
    def _ext_echo(t, code, st, objs, ver=2, state=0):
        return msg(t, code, struct.pack('!HBB', 0x4000, st, state) + _ext(objs, ver))
    ioname = _obj(3, 1, b'eth0')
    _ext_echo(160, 0, 1, [ioname], state=0x01)
    _ext_echo(160, 0, 2, [_obj(3, 2, struct.pack('!I', 4))])
    _ext_echo(160, 0, 3, [_obj(3, 3, struct.pack('!HBB', 2, 16, 0) + A)])
    msg(160, 0, struct.pack('!HBB', 0x4000, 4, 0))
    for state in range(7):
        msg(161, state % 5, struct.pack('!HBB', 0x4000, state, (state << 5) | (state & 7)))
    _ext_echo(161, 0, 9, [ioname], state=0x04)
    # Undecoded types
    for t in (5, 100, 101, 127, 162, 200, 255):
        msg(t, 0, b'\0' * 8)

    # --------------- Hop limit warning on a Neighbor Solicitation
    mark('hop limit and checksum')
    ns(A, [], hlim=64)
    ns(A, [], ck=0x4321)


def _ip4(payload, proto, src=bytes([192, 0, 2, 1]), dst=bytes([192, 0, 2, 2])):
    h = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0, src, dst)
    h = h[:10] + struct.pack('>H', csum(h)) + h[12:]
    return h + payload


def _obj(cls, ctype, data=b'', length=None):
    return struct.pack('>HBB', length if length is not None else 4 + len(data), cls, ctype) + data


def _ext(objs, ver=2):
    body = struct.pack('>BBH', ver << 4, 0, 0) + b''.join(objs)
    full = body
    for o in objs:
        if o[2] == 3:
            body = struct.pack('>BBH', ver << 4, 0, 0) + b''.join(objs[:objs.index(o) + 1])
            break
    c = csum(body)
    return full[:2] + struct.pack('>H', c) + full[4:]


def gen_malformed():
    L = malformed
    od = orig()
    # truncated frames
    full = eth(ip6(icmp6(128, 0, struct.pack('!HH', 1, 1) + bytes(40))))
    add(full, lst=L, caplen=len(full) - 10)
    full = eth(ip6(icmp6(1, 0, b'\0' * 4 + od)))
    add(full, lst=L, caplen=14 + 40 + 12)
    full = eth(ip6(icmp6(135, 0, bytes(4) + A + o_slla(), LA, LB), src=LA, dst=LB, hlim=255))
    add(full, lst=L, caplen=len(full) - 6)
    # options: zero length, length running past the message, leftover octets
    nd(135, 0, bytes(4) + A + struct.pack('!BB', 1, 0) + bytes(6), lst=L)
    nd(135, 0, bytes(4) + A + struct.pack('!BB', 1, 9) + bytes(6), lst=L)
    nd(134, 0, struct.pack('!BBHII', 64, 0, 1800, 0, 0) + opt(6, bytes([5]) + bytes(5)), lst=L)         # NBMA: 1 octet left
    nd(136, 0, struct.pack('!I', 0) + A + opt(20, bytes([1, 2]) + A), lst=L)                          # NA ack with address
    nd(134, 0, struct.pack('!BBHII', 64, 0, 1800, 0, 0) + opt(27, bytes([3, 0x20]) + bytes(12)), lst=L)  # HKR padding
    nd(134, 0, struct.pack('!BBHII', 64, 0, 1800, 0, 0) + opt(28, struct.pack('!BBH', 3, 0x10, 9) + bytes(10)), lst=L)
    nd(134, 0, struct.pack('!BBHII', 64, 0, 1800, 0, 0) + opt(24, struct.pack('!BBI', 64, 0, 600) + bytes(32)), lst=L)  # route info length
    nd(134, 0, struct.pack('!BBHII', 64, 0, 1800, 0, 0) + o_pref64(6), lst=L)
    nd(134, 0, struct.pack('!BBHII', 64, 0, 1800, 0, 0) + opt(34, struct.pack('!BBHH', 64, 0x11, 0, 600) + bytes(32)), lst=L)
    nd(135, 0, bytes(4) + A + opt(33, struct.pack('!BBBBH', 0, 0, 1, 1, 60)), lst=L)                  # EARO, ROVR of 0
    nd(135, 0, bytes(4) + A + opt(33, struct.pack('!BBBBH', 0, 0, 1, 1, 60) + bytes(12)), lst=L)       # EARO, ROVR of 12 (len pads)
    # DNR option truncations
    dn = lambda b: nd(134, 0, struct.pack('!BBHII', 64, 0, 1800, 0, 0) + opt(144, b), lst=L)
    dn(struct.pack('!HI', 1, 60))
    dn(struct.pack('!HIH', 1, 60, 40) + b'abcd')
    n = dnsname('dns.example.net')
    dn(struct.pack('!HIH', 1, 60, len(n)) + n + struct.pack('!H', 64) + bytes(8))
    dn(struct.pack('!HIH', 1, 60, len(n)) + n + struct.pack('!H', 0) + bytes(20))
    dn(struct.pack('!HIH', 1, 60, len(n)) + n + struct.pack('!H', 10) + bytes(10))
    dn(struct.pack('!HIH', 1, 60, len(n)) + n + struct.pack('!H', 16) + A + struct.pack('!H', 60) + bytes(4))
    # CGA / trust anchor / certificate with a certificate type 1 that is not a certificate
    nd(148, 0, struct.pack('!HH', 1, 1) + o_cert(1, bytes(30)), lst=L)
    # RPL: invalid option lengths, truncated messages, unknown option
    rpl = lambda c, body: msg(155, c, body, src=LA, dst=ALLNODES, lst=L)
    dag = a6('2001:db8:aa::1')
    dio = struct.pack('!BBHBBBB16s', 1, 3, 256, 0x01, 5, 0, 0, dag)
    rpl(1, dio + r_opt(3, bytes(11)))
    rpl(1, dio + r_opt(5, bytes(5)))
    rpl(1, dio + r_opt(5, bytes(2), length=3)[:0] + r_opt(200, b'\1\2\3'))
    rpl(1, dio + r_opt(2, metric(8, 0x0000, bytes([0]) + struct.pack('!H', 0x0081))[:3] + b'\x20\x00'))
    rpl(1, dio + r_opt(2, metric(99, 0x0000, b'\1\2')))
    rpl(1, dio + r_opt(6, b'\0' * 4) + r_opt(7, b'\1'))
    rpl(1, dio[:12])
    rpl(2, b'\0\0')
    rpl(0x81, b'\x80')
    # P2P DRO with zero-fields that must be zero, reply flag
    rdo = lambda fl, ltmr: r_opt(10, struct.pack('!BB16s', fl, ltmr, A) + B)
    rpl(4, struct.pack('!BBH16s', 1, 1, 0, dag) + rdo(0x80 | 0x30, 0xc0))
    # Router renumbering with MatchLen > 128, result with MatchedLen > 128
    msg(138, 0, struct.pack('!IBBHI', 1, 0, 0, 0, 0) + struct.pack('!BBBBBBH16s', 1, 24, 1, 200, 0, 128, 0, bytes(16)), lst=L)
    msg(138, 1, struct.pack('!IBBHI', 1, 0, 0, 0, 0) + struct.pack('!HBBI16s', 0, 1, 200, 7, bytes(16)), lst=L)
    msg(138, 0, struct.pack('!IBBHI', 1, 0, 0, 0, 0) + bytes(10), lst=L)
    # MPL: non-zero code, short seed id, short buffered messages, trailing octet
    msg(159, 3, bytes(4), lst=L)
    msg(159, 0, bytes([1, (0 << 2) | 3]) + bytes(5), lst=L)
    msg(159, 0, bytes([1, (8 << 2) | 1, 1, 2, 0xff]), lst=L)
    msg(159, 0, bytes([1, 1, 2, 3]) + b'\0', lst=L)
    msg(159, 0, bytes([1]), lst=L)
    # Short messages
    msg(130, 0, bytes(10), lst=L)
    msg(143, 0, struct.pack('!HH', 0, 1) + bytes(12), lst=L)
    msg(143, 0, struct.pack('!HH', 0, 1) + struct.pack('!BBH16s', 1, 0, 3, GRP) + A, lst=L)
    msg(139, 0, bytes(6), lst=L)
    msg(140, 0, struct.pack('!HH8s', 3, 0, bytes(8)) + bytes(10), lst=L)
    msg(156, 0, bytes([5, 0, 0, 0]) + bytes(12), lst=L)
    msg(157, 0, bytes(10), lst=L)
    add(eth(ip6(b'\x80\x00\x00')), lst=L)
    add(eth(ip6(b'\x01\x00\x00\x00\x00\x00')), lst=L)
    # Extended echo with invalid extension
    msg(160, 0, struct.pack('!HBB', 1, 1, 1) + _ext([_obj(3, 1, b'abc', length=2)]), lst=L)
    msg(160, 0, struct.pack('!HBB', 1, 1, 1) + _ext([_obj(3, 1, b'abc', length=100)]), lst=L)
    # Fragment: an unreassembled fragment carrying an ICMPv6 message
    fh = struct.pack('!BxHI', 58, (13 << 3) | 1, 0x77)
    add(eth(ip6(fh + icmp6(128, 0, bytes(8)), nxt=44)), lst=L)


def write(path, fr):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for s, us, p, caplen in fr:
            cl = caplen if caplen is not None else len(p)
            f.write(struct.pack('<IIII', s, us, cl, len(p)) + p[:cl])


if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    gen_main()
    gen_malformed()
    os.makedirs(out, exist_ok=True)
    write(os.path.join(out, 'icmpv6-coverage.pcap'), frames)
    write(os.path.join(out, 'icmpv6-coverage-malformed.pcap'), malformed)
    print(len(frames), len(malformed))
    if os.environ.get('MARKS'):
        print(marks)
