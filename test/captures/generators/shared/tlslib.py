# Shared helper module for the capture generators in test/captures/generators
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Shared helpers for the TLS coverage generators: DER building,
TLS record / handshake / extension builders, a TCP flow wrapper and
pcap / pcapng writers. Everything is built with struct; no keys are
computed and nothing is encrypted (encrypted records are filler)."""

import random
import struct
import zlib

from pktlib import (eth, ip4, ip6, mac, udp, udp_frame, tcp_seg, csum,
                    TcpConn, IP_A, IP_B)

rnd = random.Random(35)


def filler(n):
    return bytes(rnd.randrange(256) for _ in range(n))


# ---------------------------------------------------------------- DER
def der(tag, content=b''):
    n = len(content)
    if n < 0x80:
        ln = bytes([n])
    elif n < 0x100:
        ln = b'\x81' + bytes([n])
    elif n < 0x10000:
        ln = b'\x82' + struct.pack('!H', n)
    else:
        ln = b'\x83' + n.to_bytes(3, 'big')
    return bytes([tag]) + ln + content


def oid(s):
    p = [int(x) for x in s.split('.')]
    b = bytes([p[0] * 40 + p[1]])
    for v in p[2:]:
        enc = [v & 0x7f]
        v >>= 7
        while v:
            enc.append(0x80 | (v & 0x7f))
            v >>= 7
        b += bytes(reversed(enc))
    return der(0x06, b)


def seq(*a):
    return der(0x30, b''.join(a))


def sset(*a):
    return der(0x31, b''.join(a))


def integer(v):
    n = max(1, (v.bit_length() + 8) // 8)
    return der(0x02, v.to_bytes(n, 'big'))


def bitstr(b):
    return der(0x03, b'\x00' + b)


def octstr(b):
    return der(0x04, b)


def utf8(s):
    return der(0x0c, s.encode())


def utctime(s):
    return der(0x17, s.encode())


def name(cn, org=None):
    rdns = []
    if org:
        rdns.append(sset(seq(oid('2.5.4.10'), utf8(org))))
    rdns.append(sset(seq(oid('2.5.4.3'), utf8(cn))))
    return seq(*rdns)


def spki_rsa(bits=512):
    n = int.from_bytes(filler(bits // 8), 'big') | (1 << (bits - 1)) | 1
    return seq(seq(oid('1.2.840.113549.1.1.1'), der(0x05)),
               bitstr(seq(integer(n), integer(65537))))


def sct_extension(scts=None):
    """Certificate Transparency SCT list extension (RFC 6962): the
    extension value is an OCTET STRING that holds the TLS encoded list."""
    one = (b'\x00' + filler(32) + struct.pack('!Q', 1700000000000) + struct.pack('!H', 0) +
           struct.pack('!H', 0x0403) + struct.pack('!H', 70) + filler(70))
    lst = scts or struct.pack('!H', 2 + len(one)) + struct.pack('!H', len(one)) + one
    return seq(oid('1.3.6.1.4.1.11129.2.4.2'), octstr(octstr(lst)))


def cert(cn, issuer='Test CA', san=None, serial=1, sct=False):
    sigalg = seq(oid('1.2.840.113549.1.1.11'), der(0x05))
    exts = b''
    if san or sct:
        items = []
        if san:
            items.append(seq(oid('2.5.29.17'),
                             octstr(seq(*[der(0x82, s.encode()) for s in san]))))
        if sct:
            items.append(sct_extension())
        exts = der(0xa3, seq(*items))
    tbs = seq(der(0xa0, integer(2)), integer(serial), sigalg, name(issuer),
              seq(utctime('200101000000Z'), utctime('400101000000Z')),
              name(cn), spki_rsa(), exts)
    return seq(tbs, sigalg, bitstr(filler(64)))


def ocsp_response(status=0):
    # OCSPResponse with a status only (no responseBytes)
    return seq(der(0x0a, bytes([status])))


# ---------------------------------------------------------------- TLS
def v8(b):
    return bytes([len(b)]) + b


def v16(b):
    return struct.pack('!H', len(b)) + b


def v24(b):
    return len(b).to_bytes(3, 'big') + b


def u16s(*a):
    return b''.join(struct.pack('!H', x) for x in a)


def record(ctype, body, version=0x0303):
    return struct.pack('!BHH', ctype, version, len(body)) + body


def hs(mtype, body, length=None):
    if length is None:
        length = len(body)
    return struct.pack('!B', mtype) + length.to_bytes(3, 'big') + body


def ext(t, data=b''):
    return struct.pack('!HH', t, len(data)) + data


def exts(*e):
    b = b''.join(e)
    return struct.pack('!H', len(b)) + b


def client_hello(version=0x0303, suites=(0xc02f, 0x002f), extensions=None,
                 sid=b'', comp=(0,), random32=None, cookie=None):
    b = struct.pack('!H', version) + (random32 or filler(32)) + v8(sid)
    if cookie is not None:
        b += v8(cookie)
    b += v16(u16s(*suites)) + v8(bytes(comp))
    if extensions is not None:
        b += extensions
    return hs(1, b)


def server_hello(version=0x0303, suite=0xc02f, extensions=None, sid=b'',
                 comp=0, random32=None, tls13=False):
    b = struct.pack('!H', version) + (random32 or filler(32)) + v8(sid)
    b += struct.pack('!H', suite) + bytes([comp])
    if extensions is not None:
        b += extensions
    return hs(2, b)


HRR_RANDOM = bytes.fromhex('cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c')


class Flow:
    """One TCP connection; c() / s() return frames carrying records."""

    def __init__(self, cport, sport=443, a=IP_A, b=IP_B, syn=False):
        self.conn = TcpConn(cport, sport, a, b)
        self.frames = []
        if syn:
            self.frames += self.conn.handshake()

    def c(self, *recs):
        f = self.conn.send(b''.join(recs), False)
        self.frames.append(f)
        return f

    def s(self, *recs):
        f = self.conn.send(b''.join(recs), True)
        self.frames.append(f)
        return f

    def raw(self, data, server=False):
        f = self.conn.send(data, server)
        self.frames.append(f)
        return f

    def fin(self, server=False):
        frm = 1 if server else 0
        f = self.conn._frame(frm, 0x11, b'')
        self.conn.seq[frm] += 1
        self.frames.append(f)
        return f


# ---------------------------------------------------------------- files
def write_pcap(path, frames, linktype=1):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, fr in enumerate(frames):
            fr, orig = fr if isinstance(fr, tuple) else (fr, len(fr))
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, len(fr), orig))
            f.write(fr)


def _blk(t, body):
    pad = (-len(body)) % 4
    n = 12 + len(body) + pad
    return struct.pack('<II', t, n) + body + b'\0' * pad + struct.pack('<I', n)


def write_pcapng(path, frames):
    """frames: (linktype, bytes) tuples; one interface per link type."""
    out = _blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    ifs = {}
    for lt, _ in frames:
        if lt not in ifs:
            ifs[lt] = len(ifs)
            out += _blk(1, struct.pack('<HHI', lt, 0, 262144))
    for i, (lt, fr) in enumerate(frames):
        ts = 1700000000 * 1000000 + i * 1000
        out += _blk(6, struct.pack('<IIIII', ifs[lt], ts >> 32, ts & 0xffffffff,
                                   len(fr), len(fr)) + fr)
    with open(path, 'wb') as f:
        f.write(out)


def exported_pdu(dissector, payload):
    """Exported PDU (link type 252) frame: dissector name tag + data."""
    nm = dissector.encode()
    nm += b'\0' * ((-len(nm)) % 4)
    return struct.pack('!HH', 12, len(nm)) + nm + struct.pack('!HH', 0, 0) + payload
