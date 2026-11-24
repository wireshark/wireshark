#!/usr/bin/env python3
# Generates test/captures/ike_coverage.pcap.gz, ike_tcp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generator for the IKE (packet-ike.c) synthetic coverage captures.

Usage: mkike.py <outdir>
Writes <outdir>/ike-coverage.pcap, <outdir>/ike-tcp-coverage.pcap (RFC 8229 stream), <outdir>/ike-coverage-malformed.pcap
and <outdir>/ike-reproducers.pcap (the reproducers of the fixed bugs).

Everything is synthetic.  No key material, ciphertext, integrity values or
signatures are produced: every Encrypted payload, signature, hash,
certificate signature and key exchange value is a constant placeholder
pattern.  Certificates and names are built with a small DER encoder.
"""
import hashlib
import os
import struct
import sys

# ----------------------------------------------------------------------
# pcap / IP / UDP / TCP plumbing
# ----------------------------------------------------------------------

CLIENT4, SERVER4 = bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2])
CLIENT6 = bytes.fromhex('20010db8000000000000000000000001')
SERVER6 = bytes.fromhex('20010db8000000000000000000000002')
MAC_C, MAC_S = bytes.fromhex('020000000001'), bytes.fromhex('020000000002')


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


class Cap:
    def __init__(self):
        self.frames = []
        self.t = 1780272000
        self.ipid = 1
        self.tcp = {}

    def _eth(self, src, dst, v6, l3):
        et = 0x86dd if v6 else 0x0800
        return (MAC_S if dst == SERVER4 or dst == SERVER6 else MAC_C) + \
            (MAC_C if src == CLIENT4 or src == CLIENT6 else MAC_S) + \
            struct.pack('!H', et) + l3

    def _ip(self, src, dst, proto, l4):
        if len(src) == 16:
            hdr = struct.pack('!IHBB', 0x60000000, len(l4), proto, 64) + src + dst
            pseudo = src + dst + struct.pack('!IBBBB', len(l4), 0, 0, 0, proto)
            return hdr, pseudo
        hdr = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(l4), self.ipid, 0,
                          64, proto, 0, src, dst)
        self.ipid += 1
        hdr = hdr[:10] + struct.pack('!H', csum(hdr)) + hdr[12:]
        pseudo = src + dst + struct.pack('!BBH', 0, proto, len(l4))
        return hdr, pseudo

    def add(self, frame):
        self.t += 1
        self.frames.append((self.t, frame))

    def udp(self, payload, sport=500, dport=500, rev=False, v6=False):
        src, dst = (CLIENT6, SERVER6) if v6 else (CLIENT4, SERVER4)
        if rev:
            src, dst = dst, src
            sport, dport = dport, sport
        udp = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
        hdr, pseudo = self._ip(src, dst, 17, udp)
        if v6:
            c = csum(pseudo + udp) or 0xffff
            udp = udp[:6] + struct.pack('!H', c) + udp[8:]
        self.add(self._eth(src, dst, v6, hdr + udp))

    def tcp_seg(self, payload, key, sport, dport, rev=False, flags=0x18, v6=False):
        """One TCP segment of connection key; seq/ack are tracked."""
        st = self.tcp.setdefault(key, {'c': 1000, 's': 5000})
        src, dst = (CLIENT6, SERVER6) if v6 else (CLIENT4, SERVER4)
        me, other = ('s', 'c') if rev else ('c', 's')
        if rev:
            src, dst = dst, src
            sport, dport = dport, sport
        seq, ack = st[me], st[other]
        opt = b'\x02\x04\x05\xb4' if flags & 0x02 else b''
        tcp = struct.pack('!HHIIBBHHH', sport, dport, seq, ack if flags & 0x10 else 0,
                          (5 + len(opt) // 4) << 4, flags, 65535, 0, 0) + opt + payload
        hdr, pseudo = self._ip(src, dst, 6, tcp)
        c = 0
        if not v6:
            c = csum(pseudo + tcp[:16] + b'\0\0' + tcp[18:])
        if v6:
            pseudo = src + dst + struct.pack('!IBBBB', len(tcp), 0, 0, 0, 6)
            c = csum(pseudo + tcp[:16] + b'\0\0' + tcp[18:])
        tcp = tcp[:16] + struct.pack('!H', c) + tcp[18:]
        st[me] += len(payload) + (1 if flags & 0x03 else 0)
        self.add(self._eth(src, dst, v6, hdr + tcp))

    def handshake(self, key, sport, dport, v6=False):
        self.tcp_seg(b'', key, sport, dport, flags=0x02, v6=v6)
        self.tcp_seg(b'', key, sport, dport, rev=True, flags=0x12, v6=v6)
        self.tcp_seg(b'', key, sport, dport, flags=0x10, v6=v6)

    def write(self, path):
        with open(path, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            for t, fr in self.frames:
                f.write(struct.pack('<IIII', t, 0, len(fr), len(fr)) + fr)


# ----------------------------------------------------------------------
# DER encoder (certificates and names; all values are placeholders)
# ----------------------------------------------------------------------

def der(tag, content):
    n = len(content)
    if n < 128:
        l = bytes([n])
    elif n < 256:
        l = bytes([0x81, n])
    else:
        l = bytes([0x82, n >> 8, n & 255])
    return bytes([tag]) + l + content


def oid(s):
    p = [int(x) for x in s.split('.')]
    out = bytes([40 * p[0] + p[1]])
    for v in p[2:]:
        b = [v & 0x7f]
        v >>= 7
        while v:
            b.append(0x80 | (v & 0x7f))
            v >>= 7
        out += bytes(reversed(b))
    return der(0x06, out)


def rdn(o, value):
    return der(0x31, der(0x30, oid(o) + der(0x13, value.encode())))


def dn(cn='gw.example.org', o='Example'):
    return der(0x30, rdn('2.5.4.6', 'XX') + rdn('2.5.4.10', o) + rdn('2.5.4.3', cn))


SIGALG = der(0x30, oid('1.2.840.113549.1.1.11') + der(0x05, b''))


def certificate():
    pub = der(0x30, der(0x02, b'\x00' + bytes(range(1, 65))) + der(0x02, b'\x01\x00\x01'))
    spki = der(0x30, der(0x30, oid('1.2.840.113549.1.1.1') + der(0x05, b'')) +
               der(0x03, b'\x00' + pub))
    tbs = der(0x30,
              der(0xa0, der(0x02, b'\x02')) + der(0x02, b'\x01\x02\x03\x04') + SIGALG +
              dn('ca.example.org') +
              der(0x30, der(0x17, b'200101000000Z') + der(0x17, b'400101000000Z')) +
              dn() + spki)
    return der(0x30, tbs + SIGALG + der(0x03, b'\x00' + bytes([0xa5]) * 64))


# ----------------------------------------------------------------------
# ISAKMP / IKE payload builders
# ----------------------------------------------------------------------

def chain(items, crit=False):
    """items: list of (type, body[, crit]).  Returns (first type, bytes).
    Each generic payload header's next-payload is the next item's type."""
    out = b''
    for i, it in enumerate(items):
        t, body = it[0], it[1]
        c = it[2] if len(it) > 2 else 0
        nxt = items[i + 1][0] if i + 1 < len(items) else 0
        out += struct.pack('!BBH', nxt, c, 4 + len(body)) + body
    return (items[0][0] if items else 0), out


def hdr(first, ver, exch, flags, mid, payload, ispi=b'\x11' * 8, rspi=b'\x22' * 8,
        length=None):
    v = 0x10 if ver == 1 else 0x20
    n = 28 + len(payload) if length is None else length
    return ispi + rspi + struct.pack('!BBBBII', first, v, exch, flags, mid, n) + payload


def msg(items, ver, exch, flags=0, mid=0, **kw):
    first, body = chain(items)
    return hdr(first, ver, exch, flags, mid, body, **kw)


def tv(t, v):
    return struct.pack('!HH', 0x8000 | t, v)


def tlv(t, data):
    return struct.pack('!HH', t, len(data)) + data


def v1_transform(num, tid, attrs=b''):
    return bytes([num, tid, 0, 0]) + attrs


def proposal(num, proto, spi, transforms):
    """Proposal body.  transforms: list of transform bodies."""
    first, tr = chain([(3, t) for t in transforms])
    return bytes([num, proto, len(spi), len(transforms)]) + spi + tr


def sa_v1(doi, sit, props):
    first, body = chain([(2, p) for p in props])
    return struct.pack('!II', doi, sit) + body


def sa_v2(props):
    first, body = chain([(2, p) for p in props])
    return body


def v2_transform(ttype, tid, attrs=b''):
    return bytes([ttype, 0]) + struct.pack('!H', tid) + attrs


def ke_v1(n=128):
    return bytes([0x5a]) * n


def ke_v2(method, n=128):
    return struct.pack('!HH', method, 0) + bytes([0x6b]) * n


def id_v1(idtype, data, proto=0, port=0):
    return bytes([idtype, proto]) + struct.pack('!H', port) + data


def id_v2(idtype, data):
    return bytes([idtype, 0, 0, 0]) + data


def notify_v1(doi, proto, spi, mtype, data=b''):
    return struct.pack('!IBBH', doi, proto, len(spi), mtype) + spi + data


def notify_v2(proto, spi, mtype, data=b''):
    return struct.pack('!BBH', proto, len(spi), mtype) + spi + data


def delete_v1(doi, proto, spis, size=16):
    return struct.pack('!IBBH', doi, proto, size, len(spis)) + b''.join(spis)


def delete_v2(proto, spis, size=4):
    return struct.pack('!BBH', proto, size, len(spis)) + b''.join(spis)


def cfg_v1(ctype, ident, attrs):
    return bytes([ctype, 0]) + struct.pack('!H', ident) + attrs


def cfg_v2(ctype, attrs):
    return bytes([ctype, 0, 0, 0]) + attrs


def ts_v4(proto, sp, ep, sa, ea):
    return struct.pack('!BBHHH4s4s', 7, proto, 16, sp, ep, sa, ea)


def ts_v6(proto, sp, ep, sa, ea):
    return struct.pack('!BBHHH', 8, proto, 40, sp, ep) + sa + ea


def ts_fc():
    return (bytes([9, 0]) + struct.pack('!H', 24) + bytes([0]) + b'\x01\x02\x03' + bytes([0]) +
            b'\x04\x05\x06' + bytes([1, 2, 3, 4]))[:24] + b'\0' * 0


def ts_payload(entries):
    return bytes([len(entries), 0, 0, 0]) + b''.join(entries)


def sha1(*parts):
    return hashlib.sha1(b''.join(parts)).digest()


VID_TABLE = {
    'nat-t': bytes.fromhex('4a131c81070358455c5728f20e95452f'),   # MD5("RFC 3947")
    'dpd': bytes.fromhex('afcad71368a1f1c96b8696fc77570100'),
    'xauth': bytes.fromhex('09002689dfd6b712'),
    'frag': bytes.fromhex('4048b7d56ebce88525e7de7f00d6c2d3'),
    'ms': bytes.fromhex('1e2b516905991c7d7c96fcbfb587e461'),
    'unity': bytes.fromhex('12f5f28c457168a9702d9fe274cc'),
    'cp': bytes.fromhex('f4ed19e0c114eb516faaac0ee37daf2807b4381f'),
    'aruba': b'VIA Auth Profile : ',
    'forti': bytes.fromhex('8299031757a36082c6a621de'),
    'wg': bytes.fromhex('bfc22e9856ba993611c11e48a6d20807a95bedb393026a49e60fac327bb9601b'),
}
SPI16 = bytes(range(0x30, 0x40))


def ts_fc():
    return (bytes([9, 0]) + struct.pack('!H', 16) + b'\0' + b'\x01\x02\x03' + b'\0' +
            b'\x04\x05\x06' + bytes([1, 2, 3, 4]))


# ----------------------------------------------------------------------
# attribute zoos
# ----------------------------------------------------------------------

def ike_attr_zoo():
    """Every IKEv1 Phase 1 attribute class (RFC 2409 Appendix A)."""
    a = b''
    a += tv(1, 7) + tv(2, 2) + tv(3, 1) + tv(4, 14) + tv(5, 1)
    a += tlv(6, bytes([0xc3]) * 16) + tlv(7, b'\x02') + tlv(8, b'\x03')
    a += tlv(9, b'\x04') + tlv(10, b'\x05')
    a += tv(11, 1) + tlv(12, struct.pack('!I', 28800)) + tv(13, 1) + tv(14, 256)
    a += tv(15, 155) + tlv(16, b'\x07\x08') + tv(17, 16) + tv(20, 1)
    a += tv(30, 1)                       # unknown class
    return a


def life_attrs():
    """Life duration of every length 0..9 (RFC 2407 4.5 is variable)."""
    return b''.join(tlv(12, bytes(range(1, n + 1))) for n in range(0, 10))


def ipsec_attr_zoo():
    a = b''
    a += tv(1, 1) + tlv(2, struct.pack('!I', 3600)) + tv(3, 14) + tv(4, 1) + tv(5, 2)
    a += tv(6, 128) + tv(7, 10) + tv(8, 15) + tlv(9, b'\x01\x02') + tv(10, 1) + tv(11, 1)
    a += tv(12, 160) + tlv(13, b'\x01\x02') + tv(14, 1) + tv(15, 1) + tv(40, 1)
    return a


def ipsec_life_attrs():
    return b''.join(tlv(2, bytes(range(1, n + 1))) for n in range(0, 10))


def rohc_attrs():
    return tv(1, 15) + tv(2, 0) + tv(3, 1) + tv(4, 4) + tv(5, 1500) + tlv(2, b'') + tv(9, 1)


# ----------------------------------------------------------------------
# frames
# ----------------------------------------------------------------------

def build_main(cap):
    cert = certificate()
    name_c = dn('ca.example.org')

    # ---------------- IKEv1 main mode (cookies 11../22..) -----------------
    isa = sa_v1(1, 1, [
        proposal(1, 1, b'', [v1_transform(1, 1, ike_attr_zoo()),
                             v1_transform(2, 1, tv(2, 20) + tv(3, 10) + tv(1, 128) + tv(1, 129)
                                          + tv(3, 1) + tv(12, 5)),
                             v1_transform(3, 1, tv(1, 129) + tv(3, 10)),
                             v1_transform(4, 1, tv(1, 5) + tlv(12, b'') + tlv(11, b'')
                                          + tv(11, 2) + life_attrs() + tv(14, 128))]),
        proposal(2, 1, b'', [v1_transform(1, 2, ipsec_attr_zoo())]),
    ])
    vids = [VID_TABLE['nat-t'], VID_TABLE['dpd'], VID_TABLE['xauth'], VID_TABLE['frag'],
            VID_TABLE['ms'] + struct.pack('!I', 3),
            VID_TABLE['unity'] + b'\x01\x02',
            VID_TABLE['cp'] + struct.pack('!5I', 1, 2, 1700000000, 0, 7),
            VID_TABLE['aruba'] + b'sample',
            VID_TABLE['forti'] + struct.pack('!HH', 7, 1234),
            VID_TABLE['wg'] + b'dmVyc2lvbj0xMg==',
            bytes.fromhex('0102030405060708090a0b0c0d0e0f10'),
            VID_TABLE['aruba'][:5], VID_TABLE['cp'][:18]]
    cap.udp(msg([(1, isa)] + [(13, v) for v in vids], 1, 2))
    rsa = sa_v1(1, 1, [proposal(1, 1, b'', [v1_transform(1, 1, tv(1, 7) + tv(2, 2) + tv(3, 1)
                                                         + tv(4, 14) + tv(14, 256))])])
    cap.udp(msg([(1, rsa), (13, VID_TABLE['nat-t']), (13, VID_TABLE['dpd']),
                 (13, VID_TABLE['unity'] + b'\x01\x02')], 1, 2), rev=True)
    cap.udp(msg([(4, ke_v1()), (10, b'\x7e' * 20), (130, sha1(b'nat-d-src')),
                 (130, sha1(b'nat-d-dst')), (20, sha1(b'x'))], 1, 2))
    cap.udp(msg([(4, ke_v1()), (10, b'\x7f' * 20), (7, bytes([1]) + b'\x30\x00'),
                 (7, bytes([4]) + name_c), (7, bytes([4])), (7, bytes([3])),
                 (20, sha1(b'y'))], 1, 2), rev=True)
    # Encrypted flag set but no keys: the payloads stay opaque
    cap.udp(hdr(5, 1, 2, 0x01, 0, bytes([0xa1]) * 48))
    cap.udp(hdr(8, 1, 2, 0x01, 0, bytes([0xa2]) * 40), rev=True)
    cap.udp(hdr(0, 1, 2, 0x01, 0, b''))
    # ID/HASH sent in the clear with an extra payload after next=NONE
    first, body = chain([(5, id_v1(1, CLIENT4)), (8, bytes([0x33]) * 20)])
    cap.udp(hdr(first, 1, 2, 0, 0, body + bytes([0x99]) * 6))

    # ---------------- Identification types ------------------------------
    ids = [
        id_v1(1, CLIENT4, 17, 500), id_v1(2, b'gw.example.org'), id_v1(3, b'user@example.org'),
        id_v1(4, CLIENT4 + bytes([255, 255, 255, 0]), 6, 80),
        id_v1(5, CLIENT6), id_v1(6, CLIENT6 + bytes([255] * 8 + [0] * 8)),
        id_v1(7, CLIENT4 + SERVER4), id_v1(8, CLIENT6 + SERVER6),
        id_v1(9, dn('id.example.org')), id_v1(11, b'key-identifier'),
        id_v1(12, b'\x01\x02\x03'), id_v1(10, b'\x30\x00'),
    ]
    cap.udp(msg([(5, i) for i in ids], 1, 4, ispi=b'\x33' * 8, rspi=b'\x44' * 8))

    # ---------------- aggressive mode ----------------------------------
    ag_sa = sa_v1(1, 4, [proposal(1, 1, b'', [v1_transform(1, 1, tv(1, 7) + tv(2, 2) + tv(3, 3)
                                                           + tv(4, 2))])])
    cap.udp(msg([(1, ag_sa), (4, ke_v1()), (10, b'\x31' * 16), (5, id_v1(2, b'client.example.org')),
                 (13, VID_TABLE['xauth'])], 1, 4, ispi=b'\x55' * 8, rspi=b'\0' * 8))
    cap.udp(msg([(1, ag_sa), (4, ke_v1()), (10, b'\x32' * 16), (5, id_v1(1, SERVER4)),
                 (6, bytes([4]) + cert), (6, bytes([4]) + cert), (9, b'\x51' * 32),
                 (8, b'\x52' * 20), (21, bytes([1, 0, 0, 0]) + CLIENT4),
                 (131, bytes([5, 0, 0, 0]) + CLIENT6), (21, bytes([2, 0, 0, 0]) + b'\x01\x02')],
                1, 4, flags=0, ispi=b'\x55' * 8, rspi=b'\x66' * 8), rev=True)
    # same cookies again from the initiator (Hash/Notify)
    cap.udp(msg([(8, b'\x53' * 20)], 1, 4, ispi=b'\x55' * 8, rspi=b'\x66' * 8))

    # ---------------- quick mode ---------------------------------------
    qm_sa = sa_v1(1, 1, [
        proposal(1, 3, b'\xc0\x01\x02\x03', [v1_transform(1, 12, ipsec_attr_zoo()),
                                             v1_transform(2, 3, ipsec_life_attrs())]),
        proposal(2, 2, b'\xc0\x01\x02\x04', [v1_transform(1, 2, tv(4, 2) + tv(5, 2))]),
        proposal(3, 4, b'\xc0\x01', [v1_transform(1, 3, tv(4, 1))]),
        proposal(4, 5, b'', [v1_transform(1, 9)]),
        proposal(5, 3, b'\xc0\x01\x02\x05', [v1_transform(1, 99, tv(4, 1))]),
    ])
    qm = dict(ispi=b'\x77' * 8, rspi=b'\x88' * 8)
    cap.udp(msg([(8, b'\x61' * 20), (1, qm_sa), (10, b'\x62' * 16), (4, ke_v1(64)),
                 (5, id_v1(4, CLIENT4 + bytes([255, 255, 255, 0]))),
                 (5, id_v1(4, SERVER4 + bytes([255, 255, 0, 0])))],
                1, 32, mid=0x01020304, **qm))
    cap.udp(msg([(8, b'\x63' * 20), (1, qm_sa), (10, b'\x64' * 16)], 1, 32, flags=0x20,
                mid=0x01020304, **qm), rev=True)
    cap.udp(msg([(8, b'\x65' * 20)], 1, 32, mid=0x01020304, **qm))

    # ---------------- informational (notify, delete) -------------------
    inf = dict(ispi=b'\x99' * 8, rspi=b'\xaa' * 8)
    ni = lambda n: (8, bytes([0x70 + n]) * 20)
    cap.udp(msg([ni(0), (11, notify_v1(1, 1, b'\x99' * 8 + b'\xaa' * 8, 24576,
                                       tv(11, 1) + tlv(12, struct.pack('!I', 28800)) + tv(9, 1)
                                       + tlv(12, b'') + life_attrs()))], 1, 5, mid=1, **inf))
    cap.udp(msg([ni(1), (11, notify_v1(1, 3, b'\x01\x02\x03\x04', 24576,
                                       tv(1, 1) + tlv(2, struct.pack('!I', 3600)) + tv(9, 1)
                                       + tlv(2, b'') + ipsec_life_attrs()))], 1, 5, mid=2, **inf))
    cap.udp(msg([ni(2), (11, notify_v1(0, 3, b'\x01\x02\x03\x04', 24576, b'\x00\x01'))],
                1, 5, mid=3, **inf))
    cap.udp(msg([ni(3), (11, notify_v1(1, 1, b'\x99' * 8 + b'\xaa' * 8, 36136,
                                       struct.pack('!I', 4242))),
                 (11, notify_v1(1, 1, b'\x99' * 8 + b'\xaa' * 8, 36137, struct.pack('!I', 4242))),
                 (11, notify_v1(1, 1, b'\x99' * 8 + b'\xaa' * 8, 40501, SERVER4)),
                 (11, notify_v1(1, 1, b'\x99' * 8 + b'\xaa' * 8, 14)),
                 (11, notify_v1(1, 3, b'', 9, b'\x01\x02')),
                 ], 1, 5, mid=4, **inf))
    cap.udp(msg([ni(4), (12, delete_v1(1, 3, [b'\x01\x02\x03\x04', b'\x05\x06\x07\x08'], 4)),
                 (12, delete_v1(1, 1, [b'\x99' * 8 + b'\xaa' * 8])),
                 (12, delete_v1(1, 3, [], 0))], 1, 5, mid=5, **inf))

    # ---------------- transaction exchange (mode config / XAUTH) -------
    attrs_req = b''.join([tlv(1, b''), tlv(3, b''), tlv(7, b''), tlv(14, b''), tv(16520, 0),
                          tlv(16521, b''), tlv(16522, b'')])
    cap.udp(msg([(8, b'\xb1' * 20), (14, cfg_v1(1, 0x1234, attrs_req))], 1, 6, mid=0x2001,
                ispi=b'\xb0' * 8, rspi=b'\xb1' * 8))
    a = b''
    a += tlv(1, CLIENT4 + SERVER4) + tlv(2, bytes([255, 255, 255, 0])) + tlv(3, SERVER4)
    a += tlv(4, SERVER4) + tlv(5, struct.pack('!I', 86400)) + tlv(6, SERVER4)
    a += tlv(7, b'Synthetic VPN 1.0') + tlv(8, CLIENT6 + bytes([64]))
    a += tlv(9, bytes([255] * 8 + [0] * 8)) + tlv(10, SERVER6) + tlv(11, SERVER6)
    a += tlv(12, SERVER6) + tlv(13, CLIENT4 + bytes([255, 255, 255, 0]))
    a += tlv(14, struct.pack('!HHH', 1, 3, 25)) + tlv(15, CLIENT6 + bytes([48]))
    a += tlv(17, b'\x01' * 8 + b'\x02' * 4) + tlv(18, CLIENT6 + bytes([56]))
    a += tlv(20, SERVER4) + tlv(21, SERVER6) + tlv(25, b'example.org')
    a += tlv(1, b'\x01\x02\x03')                 # length not a multiple of 4
    a += tlv(40, b'unknown') + tlv(16, b'\x01')
    cap.udp(msg([(8, b'\xb2' * 20), (14, cfg_v1(2, 0x1234, a))], 1, 6, flags=0x20, mid=0x2001,
                ispi=b'\xb0' * 8, rspi=b'\xb1' * 8), rev=True)
    x = b''
    x += tv(16520, 0) + tlv(16521, b'alice') + tlv(16522, b'PLACEHOLDER') + tlv(16523, b'000000')
    x += tlv(16524, b'Enter credentials') + tlv(16525, b'challenge') + tlv(16526, b'EXAMPLE')
    x += tv(16527, 1) + tlv(16528, b'next-pin') + tlv(16529, b'answer')
    x += tv(21514, 1) + tv(21515, 30) + tlv(21516, b'example.org')
    x += tlv(28672, b'Welcome banner') + tv(28673, 1) + tlv(28674, b'corp.example.org')
    x += tv(28678, 1) + tv(28679, 1)
    cap.udp(msg([(8, b'\xb3' * 20), (14, cfg_v1(3, 0x1235, x))], 1, 6, mid=0x2002,
                ispi=b'\xb0' * 8, rspi=b'\xb1' * 8))
    cap.udp(msg([(8, b'\xb4' * 20), (14, cfg_v1(4, 0x1235, tv(16527, 1)))], 1, 6, flags=0x20,
                mid=0x2002, ispi=b'\xb0' * 8, rspi=b'\xb1' * 8), rev=True)
    cap.udp(msg([(1, ag_sa)], 1, 33, mid=9, ispi=b'\xb5' * 8, rspi=b'\xb6' * 8))
    # DOI other than IPsec/GDOI
    cap.udp(msg([(1, struct.pack('!II', 7, 1) + b'\xee' * 6)], 1, 4, mid=0,
                ispi=b'\xb7' * 8, rspi=b'\xb8' * 8))

    # ---------------- Cisco IKE fragmentation (IKEv1) ------------------
    inner = msg([(1, ag_sa), (4, ke_v1(160)), (10, b'\x31' * 16),
                 (5, id_v1(2, b'client.example.org'))], 1, 4, ispi=b'\xc1' * 8, rspi=b'\xc2' * 8)
    n = len(inner)
    chunks = [inner[:n // 3], inner[n // 3:2 * n // 3], inner[2 * n // 3:]]
    for i, c in enumerate(chunks):
        body = struct.pack('!HBB', 0x1234, i + 1, 1 if i == len(chunks) - 1 else 0) + c
        cap.udp(msg([(132, body)], 1, 4, ispi=b'\xc1' * 8, rspi=b'\xc2' * 8))
    cap.udp(msg([(132, b'\x00\x01\x02')], 1, 4, ispi=b'\xc3' * 8, rspi=b'\xc4' * 8))

    # ---------------- GDOI (RFC 6407) ----------------------------------
    sak = (bytes([16, 0, 0, 0]) + bytes([17, 1]) + struct.pack('!HB', 500, 4) + CLIENT4 +
           bytes([1]) + struct.pack('!HB', 500, 4) + SERVER4 + SPI16 + b'\0\0\0\0' +
           tv(1, 1) + tlv(2, struct.pack('!I', 3600)) + tlv(2, b''))
    sak = sak[:2] + struct.pack('!H', len(sak)) + sak[4:]

    def sat(nxt, proto_id=1, with_attrs=True):
        b = bytes([nxt, 0, 0, 0]) + bytes([proto_id])
        if proto_id in (1, 2):
            b += bytes([1]) + bytes([1]) + struct.pack('!HH', 500, 4) + CLIENT4
            b += bytes([2]) + struct.pack('!HH', 0, 8) + b'dst.test'
            b += bytes([3]) + b'\xde\xad\xbe\xef'
            b += tv(4, 1) + tv(5, 2)
        else:
            b += b'\x01\x02\x03\x04\x05'
        return b[:2] + struct.pack('!H', len(b)) + b[4:]
    sat_chain = sat(16, 1) + sat(0, 2)
    gsa = struct.pack('!II', 2, 0) + struct.pack('!HH', 15, 0) + sak + sat_chain
    gsa2 = struct.pack('!II', 2, 0) + struct.pack('!HH', 16, 0) + sat(0, 1)
    gsa3 = struct.pack('!II', 2, 0) + struct.pack('!HH', 16, 0) + sat(0, 3)
    kd = struct.pack('!HH', 2, 0) + (bytes([1, 0]) + struct.pack('!H', 5 + 4 + 4 + 20)
                                     + bytes([4]) + b'\xaa\xbb\xcc\xdd' + tv(1, 2)
                                     + tlv(2, bytes([0xd4]) * 16)) \
        + (bytes([2, 0]) + struct.pack('!H', 5 + 4) + bytes([0]) + tlv(3, b''))
    g = dict(ispi=b'\xd1' * 8, rspi=b'\xd2' * 8)
    cap.udp(msg([(8, b'\xd3' * 20), (1, gsa), (17, kd), (18, struct.pack('!I', 77)),
                 (19, b'\x01\x02'), (22, b'\x03\x04'), (128, bytes([0xd5]) * 16)],
                1, 32, mid=0x7001, **g))
    cap.udp(msg([(1, gsa2), (18, struct.pack('!I', 78))], 1, 32, mid=0x7002, **g), rev=True)
    cap.udp(msg([(1, gsa3)], 1, 32, mid=0x7003, **g))
    # KEK and TEK payloads directly in the payload chain (they carry their own header)
    cap.udp(msg([(15, sak + sat(0, 1)), (16, sat(0, 2))], 1, 32, mid=0x7004, **g))
    # SA with a short situation
    cap.udp(msg([(1, struct.pack('!II', 1, 0)[:5])], 1, 4, mid=0,
                ispi=b'\xb9' * 8, rspi=b'\xba' * 8))
    cap.udp(msg([(1, struct.pack('!I', 2) + b'\0' * 6)], 1, 4, mid=0,
                ispi=b'\xbb' * 8, rspi=b'\xbc' * 8))
    cap.udp(msg([(8, b'\x01' * 20)], 1, 4, ispi=b'\xbd' * 8, rspi=b'\xbe' * 8))

    # ---------------- IKEv1 over IPv6, TCP and UDP 4500 -----------------
    cap.udp(msg([(8, b'\x91' * 20), (5, id_v1(5, CLIENT6))], 1, 4, ispi=b'\xe1' * 8,
                rspi=b'\xe2' * 8), v6=True)
    cap.udp(b'\xff')                                   # NAT keepalive
    cap.udp(b'\0\0\0\0' + msg([(8, b'\x92' * 20)], 1, 5, ispi=b'\xe3' * 8, rspi=b'\xe4' * 8),
            sport=4500, dport=4500)
    cap.handshake('t500', 40000, 500)
    cap.tcp_seg(msg([(8, b'\x93' * 20)], 1, 5, ispi=b'\xe5' * 8, rspi=b'\xe6' * 8),
                't500', 40000, 500)
    cap.tcp_seg(msg([(8, b'\x94' * 20)], 1, 5, ispi=b'\xe5' * 8, rspi=b'\xe6' * 8),
                't500', 40000, 500, rev=True)

    build_v2(cap, cert, name_c)


def tk_sa_proposals():
    enc = lambda i, kl: v2_transform(1, i, tv(14, kl) if kl else b'')
    p1 = proposal(1, 1, b'', [enc(12, 256), v2_transform(2, 5), v2_transform(3, 12),
                              v2_transform(4, 14), v2_transform(6, 35), v2_transform(7, 36),
                              v2_transform(8, 0), v2_transform(9, 0), v2_transform(10, 0),
                              v2_transform(11, 0), v2_transform(12, 0),
                              v2_transform(13, 1), v2_transform(14, 1),
                              v2_transform(99, 7, tv(14, 128) + tlv(14, b'') + tv(3, 1))])
    p2 = proposal(2, 1, b'', [enc(20, 128), v2_transform(2, 7), v2_transform(4, 31),
                              v2_transform(5, 0)])
    p3 = proposal(3, 3, b'\xca\xfe\xba\xbe', [enc(20, 0), v2_transform(5, 1)])
    p4 = proposal(4, 2, b'\xca\xfe\xba\xbf', [v2_transform(3, 2), v2_transform(5, 1)])
    p5 = proposal(5, 4, b'', [v2_transform(3, 2)])
    p6 = proposal(6, 6, b'', [v2_transform(3, 2)])
    p7 = proposal(7, 77, b'', [v2_transform(3, 2)])
    return [p1, p2, p3, p4, p5, p6, p7]


def build_v2(cap, cert, name_c):
    I, R = 0x08, 0x20
    sp, rp = b'\x11' * 8, b'\x22' * 8
    s0 = b'\0' * 8

    def natd(src_ip, src_port, spi_i, spi_r):
        return sha1(spi_i, spi_r, src_ip, struct.pack('!H', src_port))

    sa = sa_v2(tk_sa_proposals())
    sha_algs = struct.pack('!HHHH', 1, 2, 3, 9)
    # ---- IKE_SA_INIT ---------------------------------------------------
    cap.udp(msg([(33, sa), (34, ke_v2(14)), (40, b'\x41' * 32),
                 (41, notify_v2(0, b'', 16388, natd(CLIENT4, 500, sp, s0))),
                 (41, notify_v2(0, b'', 16389, natd(SERVER4, 500, sp, s0))),
                 (41, notify_v2(0, b'', 16431, sha_algs)),
                 (41, notify_v2(0, b'', 16430)),
                 (41, notify_v2(0, b'', 16406)),
                 (43, VID_TABLE['nat-t']), (43, b'strongSwan 6.0'),
                 (38, bytes([4]) + sha1(b'ca0'))], 2, 34, flags=I, ispi=sp, rspi=s0))
    cap.udp(msg([(33, sa_v2([tk_sa_proposals()[0]])), (34, ke_v2(14)), (40, b'\x42' * 32),
                 (41, notify_v2(0, b'', 16388, b'\xee' * 20)),
                 (41, notify_v2(0, b'', 16389, natd(CLIENT4, 500, sp, rp))),
                 (41, notify_v2(0, b'', 16389, b'\xef' * 20)),
                 (38, bytes([4]) + sha1(b'ca1') + sha1(b'ca2') + sha1(b'ca3')),
                 (41, notify_v2(0, b'', 16388, b'\x01\x02\x03')),
                 (41, notify_v2(0, b'', 16389, b'\x01\x02\x03')),
                 ], 2, 34, flags=R, ispi=sp, rspi=rp), rev=True)
    cap.udp(msg([(41, notify_v2(0, b'', 17, struct.pack('!H', 14)))], 2, 34, flags=R,
                ispi=sp, rspi=s0), rev=True)
    cap.udp(msg([(41, notify_v2(0, b'', 14))], 2, 34, flags=R, ispi=sp, rspi=s0), rev=True)
    # IPv6 NAT detection
    cap.udp(msg([(33, sa_v2([tk_sa_proposals()[0]])), (34, ke_v2(14, 64)), (40, b'\x43' * 24),
                 (41, notify_v2(0, b'', 16388, natd(CLIENT6, 500, b'\x12' * 8, s0))),
                 (41, notify_v2(0, b'', 16389, natd(SERVER6, 500, b'\x12' * 8, s0)))],
                2, 34, flags=I, ispi=b'\x12' * 8, rspi=s0), v6=True)
    # IKE_INTERMEDIATE and the other exchange types without payloads
    cap.udp(msg([(40, b'\x44' * 32)], 2, 43, flags=I, mid=1, ispi=sp, rspi=rp))
    cap.udp(msg([(40, b'\x45' * 32)], 2, 44, flags=R, mid=2, ispi=sp, rspi=rp), rev=True)
    cap.udp(msg([(40, b'\x45' * 32)], 2, 38, flags=I, mid=3, ispi=sp, rspi=rp))

    # ---- IKE_AUTH with the inner payloads in the clear -------------------
    sig_algid = der(0x30, oid('1.2.840.113549.1.1.11') + der(0x05, b''))
    auth_sig = bytes([14, 0, 0, 0, len(sig_algid)]) + sig_algid + bytes([0xa5]) * 48
    tsi = ts_payload([ts_v4(0, 0, 65535, CLIENT4, CLIENT4),
                      ts_v4(6, 80, 80, CLIENT4, SERVER4),
                      ts_v6(17, 0, 65535, CLIENT6, SERVER6), ts_v6(0, 0, 65535, CLIENT6, SERVER6), ts_fc(),
                      bytes([1, 0]) + struct.pack('!H', 8) + b'\xaa' * 4])
    cp_req = cfg_v2(1, tlv(1, b'') + tlv(3, b'') + tlv(8, b'') + tlv(10, b'') + tlv(13, b'')
                    + tlv(7, b'') + tlv(25, b''))
    cp_rep = cfg_v2(2, tlv(1, CLIENT4) + tlv(2, bytes([255, 255, 255, 0])) + tlv(3, SERVER4)
                    + tlv(4, SERVER4) + tlv(5, struct.pack('!I', 1800)) + tlv(6, SERVER4)
                    + tlv(7, b'Synthetic 2.0') + tlv(8, CLIENT6 + bytes([64]))
                    + tlv(10, SERVER6) + tlv(11, SERVER6) + tlv(12, SERVER6)
                    + tlv(13, CLIENT4 + bytes([255, 255, 255, 0]))
                    + tlv(14, struct.pack('!HH', 1, 3)) + tlv(15, CLIENT6 + bytes([48]))
                    + tlv(17, b'\x01' * 8 + b'\x02' * 8) + tlv(18, CLIENT6 + bytes([56]))
                    + tlv(20, SERVER4) + tlv(21, SERVER6) + tlv(25, b'example.org')
                    + tlv(1, b'') + tlv(99, b'xx'))
    au = dict(ispi=sp, rspi=rp)
    cap.udp(msg([(35, id_v2(2, b'client.example.org')), (37, bytes([4]) + cert),
                 (37, bytes([12]) + sha1(b'cert') + b'http://ca.example.org/cert.der'),
                 (37, bytes([1]) + cert), (38, bytes([4]) + sha1(b'a') + sha1(b'b')),
                 (36, id_v2(1, SERVER4)), (39, auth_sig), (47, cp_req),
                 (33, sa_v2([tk_sa_proposals()[2]])), (44, tsi), (45, tsi),
                 (41, notify_v2(3, b'\xca\xfe\xba\xbe', 16387, b'\x12\x34\x02')),
                 (41, notify_v2(0, b'', 16409, struct.pack('!I', 3600) + b'\xf0' * 12)),
                 (41, notify_v2(0, b'', 16413, b'\xf1' * 8))],
                2, 35, flags=I, mid=1, **au))
    cap.udp(msg([(36, id_v2(3, b'user@example.org')), (35, id_v2(5, SERVER6)),
                 (35, id_v2(9, dn('r.example.org'))), (36, id_v2(11, b'key-id')),
                 (35, id_v2(13, b'')), (35, id_v2(12, b'\x01\x02')), (36, id_v2(4, CLIENT4 + SERVER4)),
                 (39, bytes([1, 0, 0, 0]) + b'\xb1' * 32),
                 (39, bytes([14, 0, 0, 0, 0]) + b'\xb2' * 32),
                 (39, bytes([14, 0, 0, 0, 200]) + b'\xb3' * 8),
                 (39, bytes([2, 0, 0, 0]) + b'\xb4' * 32),
                 (47, cp_rep), (45, tsi),
                 (48, bytes([1, 1, 0, 9, 1]) + b'user'),
                 (49, b'\x01\x02\x03\x04'), (50, b'\x05'), (51, b'\x06'), (52, b'\x07'),
                 (54, b'\x08'), (200, b'\x09')],
                2, 35, flags=R, mid=1, **au), rev=True)
    # bad EAP is not a payload error: a short EAP packet
    cap.udp(msg([(48, bytes([3, 1, 0, 4]))], 2, 35, flags=R, mid=2, **au), rev=True)
    # ---- Encrypted payloads (placeholder, no keys) -----------------------
    for i, n in enumerate([0, 2, 3, 4, 5, 24, 64]):
        cap.udp(msg([(46, bytes([0xc5]) * n)], 2, 35, flags=I if i % 2 == 0 else R,
                    mid=10 + i, **au), rev=(i % 2 == 1))
    # critical bit and different next-payload value
    first, body = chain([(46, bytes([0xc6]) * 32, 0x80)])
    cap.udp(hdr(first, 2, 36, I, 20, body, **au))
    # ---- Encrypted Fragment payloads (no keys: header fields only) -------
    for mid in (30, 31):
        for k in (1, 2, 3):
            body = struct.pack('!HH', k, 3) + bytes([0xc7]) * 40
            nxt = 35 if k == 1 else 0
            data = struct.pack('!BBH', nxt, 0, 4 + len(body)) + body
            cap.udp(hdr(53, 2, 35, I, mid, data, **au), rev=(k == 2))
    body = struct.pack('!HH', 1, 1) + bytes([0xc8]) * 24
    cap.udp(hdr(53, 2, 37, I, 32, struct.pack('!BBH', 0, 0, 4 + len(body)) + body, **au))
    # ---- CREATE_CHILD_SA, INFORMATIONAL -----------------------------------
    cap.udp(msg([(41, notify_v2(3, b'\xde\xad\xbe\xef', 16393)), (33, sa_v2([tk_sa_proposals()[2]])),
                 (40, b'\x46' * 32), (34, ke_v2(19, 64)), (44, tsi), (45, tsi)],
                2, 36, flags=I, mid=40, **au))
    cap.udp(msg([(41, notify_v2(0, b'', 9000)), (41, notify_v2(0, b'', 41041, b'\x01\x20')),
                 (42, delete_v2(1, [])), (42, delete_v2(3, [b'\x01\x02\x03\x04', b'\x05\x06\x07\x08'])),
                 (42, delete_v2(3, [], 0))],
                2, 37, flags=R, mid=41, **au), rev=True)
    cap.udp(msg([], 2, 37, flags=I, mid=42, **au))
    # payload types of other IKE versions inside an IKEv2 message: Key Download (v1 numbering,
    # nothing is decoded for IKEv2) and NAT-OA with the IKEv2 ID type names
    cap.udp(msg([(17, b'\x00\x01\x00\x00' + b'\x01' * 8), (21, bytes([1, 0, 0, 0]) + SERVER4),
                 (131, bytes([5, 0, 0, 0]) + SERVER6)], 2, 37, flags=I, mid=45, **au))
    # a header with a version this dissector does not know (3.0)
    cap.udp(msg([(47, cfg_v2(1, tlv(1, b''))), (14, cfg_v1(1, 1, tlv(1, b''))), (41, notify_v2(0, b'', 14))],
                3, 37, flags=I, mid=46, **au))
    # ---- notify payloads -------------------------------------------------
    n2 = lambda t, d=b'', proto=0, spi=b'': (41, notify_v2(proto, spi, t, d))
    redir4 = bytes([1, 4]) + SERVER4 + b'\xa5' * 8
    redir6 = bytes([2, 16]) + SERVER6
    redirn = bytes([3, 11]) + b'gw.test.net' + b'\xa6' * 4
    redirx = bytes([9, 3]) + b'\x01\x02\x03' + b'\xa7' * 2
    notifs = [
        n2(16403, struct.pack('!I', 3725)),
        n2(16407, redir4), n2(16407, redir6), n2(16407, redirn), n2(16407, redirx),
        n2(16408, bytes([1, 4]) + SERVER4), n2(16408, bytes([2, 16]) + SERVER6),
        n2(16408, bytes([5, 2]) + b'\x01\x02'),
        n2(16416, rohc_attrs()), n2(16419, b'\xa8' * 16),
        n2(16422, struct.pack('!III', 1, 2, 3)), n2(16423, b'\xa9' * 4),
        n2(16424, b'\x00\x01\x00\x02'), n2(16431, sha_algs),
        n2(41041, b'\x01\x42'),
        n2(41101, struct.pack('!HB', 9, 0x01) + bytes.fromhex('3412785634129078')),
        n2(41101, struct.pack('!HB', 9, 0x02) + bytes.fromhex('341278563412907856')),
        n2(41101, struct.pack('!HB', 9, 0x03) + b'\x01\x02\x03'),
        n2(41101, struct.pack('!HB', 1, 0x01)), n2(41101, b'\x01'),
        n2(41134, bytes.fromhex('1300') + bytes([8]) + bytes.fromhex('030111f2030411f9')),
        n2(41134),
        n2(61520, struct.pack('!I', 0x12345678)),
        n2(61696, b'VER=1\nFCTVER=7.0.2\nUID=1234abcd\nIP=192.0.2.9\nMAC=02:00:00:00:00:09\n'
                  b'HOST=pc1\nUSER=alice\nOSVER=Linux\nREG_STATUS=1\nEMSSN=FCT00\nEMSID=7\n'
                  b'OTHER=1\nNOEQUALS\ntrailing'),
        n2(16384, b''), n2(40960, b'\x01'), n2(30000),
        n2(1, b'', 3, b'\xde\xad\xbe\xef'),
    ]
    cap.udp(msg(notifs, 2, 37, flags=I, mid=43, **au))
    # ---- SA payload variants ---------------------------------------------
    cap.udp(msg([(33, sa_v2(tk_sa_proposals()))], 2, 36, flags=R, mid=44, **au), rev=True)
    # Version 2.0 header variations: all flag combinations
    for f in (0, I | R, 0x10, 0x10 | I | R, 0x40, 0x80):
        cap.udp(msg([(40, b'\x47' * 16)], 2, 36, flags=f, mid=50, **au))
    # ---- depth reproducer: 300 header-only payloads ------------------------
    for ver, vt in ((1, 13), (2, 43)):
        items = [(vt, b'') for _ in range(300)]
        cap.udp(msg(items, ver, 34 if ver == 2 else 2, flags=I if ver == 2 else 0,
                    ispi=b'\x11' * 8, rspi=b'\0' * 8))
    # ---- IKEv2 over IPv6 + UDP 4500 non-ESP marker ---------------------------
    cap.udp(msg([(35, id_v2(5, CLIENT6)), (39, bytes([2, 0, 0, 0]) + b'\xb5' * 16)], 2, 35,
                flags=I, mid=60, **au), v6=True)
    cap.udp(b'\0\0\0\0' + msg([(40, b'\x48' * 16)], 2, 36, flags=I, mid=61, **au),
            sport=4500, dport=4500)
    cap.udp(b'\0\0\0\0' + msg([(41, notify_v2(0, b'', 16388, natd(SERVER4, 4500, sp, rp)))],
                              2, 37, flags=R, mid=62, **au), sport=4500, dport=4500, rev=True)


def build_tcp4500(cap):
    """RFC 8229 TCP encapsulation, detected by the "IKETCP" prefix."""
    sp, rp = b'\x71' * 8, b'\x72' * 8
    key = 't4500'
    cap.handshake(key, 41000, 4500)
    magic = b'IKETCP'
    cap.tcp_seg(magic, key, 41000, 4500)
    cap.tcp_seg(magic, key, 41000, 4500, rev=True)

    def frame(ike):
        body = b'\0\0\0\0' + ike
        return struct.pack('!H', len(body) + 2) + body
    m1 = msg([(33, sa_v2([tk_sa_proposals()[0]])), (34, ke_v2(14, 64)), (40, b'\x49' * 32)],
             2, 34, flags=0x08, ispi=sp, rspi=b'\0' * 8)
    cap.tcp_seg(frame(m1), key, 41000, 4500)
    m2 = msg([(33, sa_v2([tk_sa_proposals()[0]])), (34, ke_v2(14, 64)), (40, b'\x4a' * 32)],
             2, 34, flags=0x20, ispi=sp, rspi=rp)
    cap.tcp_seg(frame(m2), key, 41000, 4500, rev=True)
    # ESP packet inside the stream (placeholder bytes)
    esp = struct.pack('!II', 0xc0de0001, 1) + bytes([0xe5]) * 32
    cap.tcp_seg(struct.pack('!H', len(esp) + 2) + esp, key, 41000, 4500)
    m3 = msg([(46, bytes([0xc9]) * 24)], 2, 37, flags=0x08, mid=1, ispi=sp, rspi=rp)
    cap.tcp_seg(frame(m3), key, 41000, 4500)


# ----------------------------------------------------------------------
# malformed capture
# ----------------------------------------------------------------------

def build_malformed(cap):
    I, R = 0x08, 0x20
    sp, rp = b'\x81' * 8, b'\x82' * 8
    k = dict(ispi=sp, rspi=rp)
    ag_sa = sa_v1(1, 4, [proposal(1, 1, b'', [v1_transform(1, 1, tv(1, 7))])])

    def pl(nxt, ln, body):
        return struct.pack('!BBH', nxt, 0, ln) + body

    # header problems
    cap.udp(hdr(0, 1, 5, 0, 0, b'', length=20))                       # bogus length
    cap.udp(hdr(8, 1, 5, 0, 0, pl(0, 24, b'\x01' * 20), length=500, **k))  # length too large
    cap.udp(b'\x00')                                                  # 1 byte, not 0xff
    cap.udp(hdr(40, 3, 34, 0, 0, pl(0, 8, b'\x01' * 4), **k))         # unknown version
    cap.udp(hdr(8, 1, 5, 0, 0, pl(0, 3, b'abc'), **k))                # payload length < 4
    cap.udp(hdr(8, 1, 5, 0, 0, pl(0, 200, b'abc'), **k))              # payload length > remaining
    cap.udp(hdr(8, 1, 5, 0, 0, b'\x00\x00', **k))                     # < 4 bytes of payload
    cap.udp(hdr(40, 2, 34, I, 0, pl(0, 3, b'abc'), **k))
    # SA: transform / proposal errors
    prop_bad1 = bytes([1, 1, 0, 2]) + chain([(3, v1_transform(1, 1, tv(1, 7)))])[1]
    cap.udp(msg([(1, struct.pack('!II', 1, 1) + pl(0, 4 + len(prop_bad1), prop_bad1))],
                1, 4, **k))
    prop_long = bytes([1, 1, 0, 1]) + pl(0, 100, b'\x01\x01\x00\x00')
    cap.udp(msg([(1, struct.pack('!II', 1, 1) + pl(0, 4 + len(prop_long), prop_long))], 1, 4, **k))
    cap.udp(msg([(1, struct.pack('!II', 1, 1) + pl(0, 8, bytes([1, 1, 0, 1])) + pl(0, 2, b''))],
                1, 4, **k))
    cap.udp(msg([(33, pl(0, 4 + 4, bytes([1, 1, 0, 1])) + pl(0, 100, b''))], 2, 36, flags=I, **k))
    cap.udp(msg([(33, pl(0, 4 + 4, bytes([1, 1, 0, 1])) + pl(0, 3, b'abc'))], 2, 36, flags=I, **k))
    # sequence payload of the wrong length
    cap.udp(msg([(18, b'\x01\x02')], 1, 32, **k))
    # skf fragment numbering
    for (a, b) in ((0, 3), (4, 3), (1, 0), (0, 0)):
        body = struct.pack('!HH', a, b) + bytes([0xc7]) * 24
        cap.udp(hdr(53, 2, 35, I, 70 + a + b, pl(0, 4 + len(body), body), **k))
    # truncated payload bodies (BoundsError)
    cap.udp(msg([(11, struct.pack('!I', 1) + b'\x03')], 1, 5, **k))
    cap.udp(msg([(41, b'\x00\x00\x40\x13' + b'\x01')], 2, 37, flags=I, **k))      # auth lifetime short
    cap.udp(msg([(41, b'\x00\x00\x40\x17' + b'\x01\xff')], 2, 37, flags=I, **k))  # redirect short
    cap.udp(msg([(12, delete_v1(1, 3, [b'\x01\x02'], 4))], 1, 5, **k))
    cap.udp(msg([(42, delete_v2(3, [b'\x01\x02\x03\x04', b'\x01'], 4))], 2, 37, flags=I, **k))
    cap.udp(msg([(14, cfg_v1(2, 1, tlv(17, b'\x01\x02\x03')))], 1, 6, **k))        # link too short
    cap.udp(msg([(14, cfg_v1(2, 1, tlv(14, b'\x01\x02\x03')))], 1, 6, **k))        # odd length
    cap.udp(msg([(14, cfg_v1(2, 1, tv(16520, 1) + b'\x00'))], 1, 6, **k))
    cap.udp(msg([(44, ts_payload([bytes([7, 0]) + struct.pack('!H', 12) + b'\x01' * 8]))],
                2, 36, flags=I, **k))
    cap.udp(msg([(44, ts_payload([b'\x07\x00\x00\x02']))], 2, 36, flags=I, **k))
    cap.udp(msg([(38, bytes([4]) + b'\x01' * 30)], 2, 35, flags=I, **k))
    cap.udp(msg([(37, bytes([12]) + b'\x01' * 10)], 2, 35, flags=I, **k))
    cap.udp(msg([(37, bytes([4]) + b'\x30\x03\x01')], 2, 35, flags=I, **k))
    cap.udp(msg([(5, id_v1(9, b'\x30\x05\x01'))], 1, 4, **k))
    cap.udp(msg([(5, id_v1(1, b'\x01\x02'))], 1, 4, **k))
    cap.udp(msg([(35, id_v2(5, b'\x01\x02'))], 2, 35, flags=I, **k))
    cap.udp(msg([(21, b'\x01\x00')], 1, 4, **k))
    cap.udp(msg([(13, b'\xf4\xed\x19\xe0\xc1\x14\xeb\x51\x6f\xaa\xac\x0e\xe3\x7d\xaf\x28'
                  b'\x07\xb4\x38\x1f\x01\x02\x03\x04')], 1, 4, **k))
    cap.udp(msg([(13, VID_TABLE['wg'] + b'!!!!')], 1, 4, **k))
    cap.udp(msg([(6, bytes([4]) + b'\x30\x80\x01')], 1, 4, **k))
    cap.udp(msg([(7, bytes([4]) + b'\x30\x80\x01')], 1, 4, **k))
    cap.udp(msg([(39, bytes([14, 0, 0, 0]))], 2, 35, flags=I, **k))
    cap.udp(msg([(17, struct.pack('!HH', 3, 0) + bytes([1, 0, 0, 2]))], 1, 32, **k))
    cap.udp(msg([(17, struct.pack('!HH', 1, 0) + bytes([1, 0]) + struct.pack('!H', 9)
                  + bytes([4, 1, 2]))], 1, 32, **k))
    cap.udp(msg([(16, bytes([0, 0, 0, 3]) + b'\x01\x02\x03\x04')], 1, 32, **k))
    cap.udp(msg([(1, struct.pack('!II', 2, 0) + struct.pack('!HH', 15, 0) + bytes([0, 0, 0, 8])
                  + b'\x01' * 4)], 1, 32, **k))
    cap.udp(msg([(1, struct.pack('!II', 2, 0) + struct.pack('!HH', 16, 0) + bytes([0, 0, 0, 8])
                  + b'\x01' * 4)], 1, 32, **k))
    cap.udp(msg([(41, notify_v2(0, b'', 41101, struct.pack('!HB', 9, 0x01) + b'\x12'))],
                2, 37, flags=I, **k))
    cap.udp(msg([(41, notify_v2(0, b'', 41134, bytes.fromhex('1300') + bytes([40]) + b'\x03'))],
                2, 37, flags=I, **k))
    cap.udp(msg([(41, notify_v2(0, b'', 16422, b'\x01\x02\x03\x04'))], 2, 37, flags=I, **k))
    cap.udp(msg([(41, notify_v2(0, b'', 16416, b'\x80\x01\x00'))], 2, 37, flags=I, **k))
    cap.udp(msg([(11, notify_v1(1, 1, b'', 24576, b'\x80'))], 1, 5, **k))
    cap.udp(msg([(48, b'')], 2, 35, flags=I, **k))
    cap.udp(msg([(34, b'\x00')], 2, 34, flags=I, **k))
    cap.udp(msg([(4, b'')], 1, 4, **k))
    cap.udp(msg([(13, b'')], 1, 4, **k)[:30])        # truncated header
    # TCP: IKETCP framing errors
    cap.handshake('m4500', 41100, 4500)
    cap.tcp_seg(b'IKETCP', 'm4500', 41100, 4500)
    cap.tcp_seg(struct.pack('!H', 200) + b'\0\0\0\0' + b'\x01' * 10, 'm4500', 41100, 4500)
    cap.tcp_seg(struct.pack('!H', 4) + b'\x01\x02', 'm4500', 41100, 4500)
    cap.tcp_seg(struct.pack('!H', 2) + b'\0\0\0\0', 'm4500', 41100, 4500)
    # a TCP stream that starts with something else is not IKETCP
    cap.handshake('x4500', 41200, 4500)
    cap.tcp_seg(b'IKETC', 'x4500', 41200, 4500)


def build_reproducers(cap):
    """Reproducers of "ISAKMP: Fix dissection depth and fragment decryption failure"."""
    # 1. 300 header-only payloads (also in the main capture)
    for ver, vt in ((1, 13), (2, 43)):
        items = [(vt, b'') for _ in range(300)]
        cap.udp(msg(items, ver, 34 if ver == 2 else 2, flags=0x08 if ver == 2 else 0,
                    ispi=b'\x11' * 8, rspi=b'\0' * 8))
    # 2. SKF with no data, decrypted with a NULL cipher / NONE integrity entry in the
    #    IKEv2 decryption table (no key material; see README)
    skf = struct.pack('!BBHHH', 35, 0, 8, 1, 1)
    cap.udp(hdr(53, 2, 35, 0x08, 1, skf, ispi=b'\x11' * 8, rspi=b'\x22' * 8))
    # 3. SK payloads shorter than the 4 octet IV the old code assumed
    for n in (0, 2, 3, 4, 8):
        cap.udp(msg([(46, bytes([0xc5]) * n)], 2, 35, flags=0x08, mid=10 + n,
                    ispi=b'\x13' * 8, rspi=b'\x14' * 8))


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    os.makedirs(out, exist_ok=True)
    cap = Cap()
    build_main(cap)
    cap.write(os.path.join(out, 'ike-coverage.pcap'))
    print('ike-coverage.pcap', len(cap.frames), 'frames')
    cap = Cap()
    build_tcp4500(cap)
    cap.write(os.path.join(out, 'ike-tcp-coverage.pcap'))
    print('ike-tcp-coverage.pcap', len(cap.frames), 'frames')
    cap = Cap()
    build_malformed(cap)
    cap.write(os.path.join(out, 'ike-coverage-malformed.pcap'))
    print('ike-coverage-malformed.pcap', len(cap.frames), 'frames')
    cap = Cap()
    build_reproducers(cap)
    cap.write(os.path.join(out, 'ike-reproducers.pcap'))
    print('ike-reproducers.pcap', len(cap.frames), 'frames')


if __name__ == '__main__':
    main()
