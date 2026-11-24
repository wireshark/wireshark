# Generates test/captures/vrrp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# ---- common helpers (copied into each generator) ----
import struct
import os
import sys
import gzip

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff

def pcap_write(fname, pkts, linktype=1, t0=1700000000):
    with open(fname, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, p in enumerate(pkts):
            olen = None
            if isinstance(p, tuple):
                if len(p) == 3:
                    p, ts, olen = p
                else:
                    p, ts = p
            else:
                ts = t0 + i
            f.write(struct.pack('<IIII', ts, 0, len(p), olen or len(p)))
            f.write(p)

def eth(payload, dst=b'\x02\0\0\0\0\x02', src=b'\x02\0\0\0\0\x01', et=0x0800):
    f = dst + src + struct.pack('!H', et) + payload
    return f + b'\0' * max(0, 60 - len(f))

def ip4(proto, payload, src=(192, 0, 2, 1), dst=(192, 0, 2, 2), ttl=64, ident=1, flags_frag=0, tos=0):
    h = struct.pack('!BBHHHBBH4s4s', 0x45, tos, 20 + len(payload), ident, flags_frag, ttl, proto, 0,
                    bytes(src), bytes(dst))
    h = h[:10] + struct.pack('!H', csum(h)) + h[12:]
    return h + payload

def ip6(nh, payload, src=bytes([0x20, 1, 0xd, 0xb8]) + bytes(11) + b'\1', dst=bytes([0x20, 1, 0xd, 0xb8]) + bytes(11) + b'\2', hlim=64):
    return struct.pack('!IHBB', 0x60000000, len(payload), nh, hlim) + src + dst + payload

def udp(sport, dport, payload, src=(192, 0, 2, 1), dst=(192, 0, 2, 2)):
    u = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    ph = bytes(src) + bytes(dst) + struct.pack('!BBH', 0, 17, len(u))
    c = csum(ph + u) or 0xffff
    return u[:6] + struct.pack('!H', c) + u[8:]

def tcp(sport, dport, seq, ack, flags, payload=b'', src=(192, 0, 2, 1), dst=(192, 0, 2, 2), win=65535):
    t = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 5 << 4, flags, win, 0, 0) + payload
    ph = bytes(src) + bytes(dst) + struct.pack('!BBH', 0, 6, len(t))
    return t[:16] + struct.pack('!H', csum(ph + t)) + t[18:]

def exp_pdu(name, payload):
    n = name.encode()
    pad = (4 - len(n) % 4) % 4
    tags = struct.pack('>HH', 12, len(n) + pad) + n + b'\0' * pad
    tags += struct.pack('>HH', 0, 0)
    return tags + payload

def rtp(pt, seq, ts, ssrc, payload, marker=0):
    return struct.pack('!BBHII', 0x80, (marker << 7) | pt, seq, ts, ssrc) + payload

def gz(path, gzpath):
    with open(path, 'rb') as f:
        d = f.read()
    with open(gzpath, 'wb') as g:
        g.write(gzip.compress(d, 9, mtime=0))

# ---- VRRP over IPv4 and IPv6 (IP protocol 112) ----
MC4 = (224, 0, 0, 18)
MAC4 = b'\x01\x00\x5e\x00\x00\x12'
MAC6 = b'\x33\x33\x00\x00\x00\x12'
S6 = bytes([0xfe, 0x80]) + bytes(13) + b'\x01'
D6 = bytes([0xff, 0x02]) + bytes(13) + b'\x12'

def vrrp(ver, vtype=1, vrid=1, prio=100, addrs=(), auth=0, adver=1, short_int=100, tail=b'',
         v6=False, pseudo=False, bad_cksum=False, src4=(192, 0, 2, 1), ver_nibble=None, rsvd=0):
    n = len(addrs)
    vt = ((ver if ver_nibble is None else ver_nibble) << 4) | vtype
    if ver == 3:
        hdr = struct.pack('!BBBBH', vt, vrid, prio, n, (rsvd << 12) | short_int)
    else:
        hdr = struct.pack('!BBBBBB', vt, vrid, prio, n, auth, adver)
    body = b''.join(bytes(a) for a in addrs) + tail
    pkt = hdr + b'\0\0' + body
    if ver == 3 and (v6 or pseudo):
        if v6:
            src, dst = S6, D6
        else:
            src, dst = bytes(src4), bytes(MC4)
        ph = src + dst + struct.pack('!IBBBB', len(pkt), 0, 0, 0, 112)
        c = csum(ph + pkt)
    else:
        c = csum(pkt)
    if bad_cksum:
        c ^= 0x5a5a
    return pkt[:6] + struct.pack('!H', c) + pkt[8:]

def f4(vr, src=(192, 0, 2, 1), **kw):
    return eth(ip4(112, vr, src=src, dst=MC4, ttl=255), dst=MAC4)

def f6(vr):
    return eth(ip6(112, vr, src=S6, dst=D6, hlim=255), dst=MAC6, et=0x86dd)

A1 = [(192, 0, 2, 100)]
A3 = [(192, 0, 2, 100), (192, 0, 2, 101), (192, 0, 2, 102)]
V6A = [bytes([0x20, 1, 0xd, 0xb8]) + bytes(11) + b'\x64', bytes([0x20, 1, 0xd, 0xb8]) + bytes(11) + b'\x65']

def build(outdir):
    main = []
    # version 2 (RFC 2338/3768): authentication none, simple text, IP auth header, Cisco MD5
    main.append(f4(vrrp(2, prio=100, addrs=A1)))
    main.append(f4(vrrp(2, vrid=2, prio=255, addrs=A3, adver=3)))
    main.append(f4(vrrp(2, vrid=3, prio=0, addrs=A1, auth=1, tail=b'secret\0\0')))
    main.append(f4(vrrp(2, vrid=4, prio=50, addrs=A1, auth=2)))
    main.append(f4(vrrp(2, vrid=5, prio=200, addrs=A1, auth=254, tail=bytes(range(16)))))
    main.append(f4(vrrp(2, vrid=6, prio=100, addrs=[], auth=0)))
    main.append(f4(vrrp(2, vrid=7, prio=100, addrs=A1, auth=254, tail=b'\xaa' * 7)))   # MD5 data too short
    main.append(f4(vrrp(2, vtype=2, vrid=8, prio=100, addrs=A1)))                      # unknown type 2
    main.append(f4(vrrp(2, vrid=9, prio=100, addrs=A1, auth=77)))                      # unknown auth type
    # version 3 over IPv4 (checksum like version 2 by default)
    main.append(f4(vrrp(3, vrid=10, prio=100, addrs=A1, short_int=100)))
    main.append(f4(vrrp(3, vrid=11, prio=255, addrs=A3, short_int=0xfff, rsvd=5)))
    # version 3 over IPv4 with the pseudo header checksum (valid only with the preference off)
    main.append(f4(vrrp(3, vrid=12, prio=90, addrs=A1, pseudo=True)))
    # version 3 over IPv6
    main.append(f6(vrrp(3, vrid=13, prio=100, addrs=V6A[:1], v6=True)))
    main.append(f6(vrrp(3, vrid=14, prio=255, addrs=V6A, v6=True, short_int=200)))
    main.append(f6(vrrp(3, vrid=15, prio=0, addrs=[], v6=True)))
    # version 2 over IPv6 (default branch of the version switch for the addresses)
    main.append(f6(vrrp(2, vrid=16, prio=100, addrs=V6A[:1], v6=True)))
    # unknown versions: 1 and 4 use the version 2 layout and checksum
    main.append(f4(vrrp(2, vrid=17, prio=100, addrs=A1, ver_nibble=1)))
    main.append(f4(vrrp(2, vrid=18, prio=100, addrs=A1, ver_nibble=4)))
    # bad checksums
    main.append(f4(vrrp(2, vrid=19, prio=100, addrs=A1, bad_cksum=True)))
    main.append(f4(vrrp(3, vrid=20, prio=100, addrs=A1, bad_cksum=True)))
    main.append(f6(vrrp(3, vrid=21, prio=100, addrs=V6A[:1], v6=True, bad_cksum=True)))
    # truncated capture: the checksum is not verified
    full = f4(vrrp(2, vrid=22, prio=100, addrs=A3))
    main.append((full[:-12], 1700001000, len(full)))
    # an IPv4 fragmented VRRP datagram (reassembled by IP): the second fragment
    body = vrrp(2, vrid=23, prio=100, addrs=A3 + A3)
    fa, fb = body[:16], body[16:]
    main.append(eth(ip4(112, fa, src=(192, 0, 2, 9), dst=MC4, ttl=255, ident=77, flags_frag=0x2000), dst=MAC4))
    main.append(eth(ip4(112, fb, src=(192, 0, 2, 9), dst=MC4, ttl=255, ident=77, flags_frag=2), dst=MAC4))
    # a second advertisement per router (priority change) for the same VRID
    main.append(f4(vrrp(2, vrid=1, prio=101, addrs=A1)))
    pcap_write(os.path.join(outdir, 'vrrp-coverage.pcap'), main)

    mal = []
    # VRRP shorter than its own header
    mal.append(eth(ip4(112, b'\x21\x01\x64', dst=MC4, ttl=255), dst=MAC4))
    # address count larger than the data
    v = bytearray(vrrp(2, vrid=30, prio=100, addrs=A1))
    v[3] = 30
    mal.append(eth(ip4(112, bytes(v), dst=MC4, ttl=255), dst=MAC4))
    # simple text authentication string cut short
    mal.append(eth(ip4(112, vrrp(2, vrid=31, prio=100, addrs=A1, auth=1, tail=b'abc'), dst=MC4, ttl=255), dst=MAC4))
    # IPv6 address list cut short
    v = bytearray(vrrp(3, vrid=32, prio=100, addrs=V6A[:1], v6=True))
    v[3] = 9
    mal.append(eth(ip6(112, bytes(v), src=S6, dst=D6, hlim=255), dst=MAC6, et=0x86dd))
    pcap_write(os.path.join(outdir, 'vrrp-coverage-malformed.pcap'), mal)
    gz(os.path.join(outdir, 'vrrp-coverage.pcap'), os.path.join(outdir, 'vrrp_coverage.pcap.gz'))

if __name__ == '__main__':
    build(sys.argv[1] if len(sys.argv) > 1 else '.')
