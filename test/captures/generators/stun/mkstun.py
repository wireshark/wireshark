#!/usr/bin/env python3
# Generates test/captures/stun_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures for the STUN dissector (packet-stun.c).

Usage: mkstun.py <output directory>

Writes:
  stun-coverage.pcapng            STUN/TURN over UDP and TCP on port 3478 and
                                  through the UDP and TCP heuristics: every
                                  method class, every attribute, ChannelData,
                                  RFC 4571 framing, TURN DATA payloads,
                                  transaction tracking, MS-TURN messages
  stun-coverage-versions.pcapng   (only with -o stun.stunversion:...) messages
                                  that need the RFC 3489 or Auto setting
  stun-coverage-malformed.pcapng  short attributes, bad lengths, unknown
                                  attributes, bad fingerprint, nesting past the
                                  limit, PASSWORD-ALGORITHMS corner cases

Every packet is built with struct; addresses are from 192.0.2.0/24,
198.51.100.0/24 and 2001:db8::/32. The MESSAGE-INTEGRITY and password
algorithm values are made-up octets; no key or credential is involved.
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import socket
import struct
import zlib
from pcaplib import exported_pdu, LT_ETH, LT_EXPORTED_PDU, pcapng, TcpConn, udp

COOKIE = 0x2112A442
MSCOOKIE = 0x72C64BC6
REQ, IND, OK, ERR = 0, 1, 2, 3
BINDING, SHARED, ALLOC, REFRESH, SEND, DATA_IND, PERM, CHANBIND = 1, 2, 3, 4, 6, 7, 8, 9
CONNECT, CONNBIND, CONNATT, GOOGPING = 0xa, 0xb, 0xc, 0x80


def mtype(method, cls):
    return ((method & 0xf) | ((cls & 1) << 4) | ((method & 0x70) << 1) | ((cls & 2) << 7)
            | ((method & 0xf80) << 2))


def tid_of(n):
    return struct.pack('>III', 0x01020300 + n, 0x04050600 + n, 0x07080900 + n)


ALLOW_EMPTY = [False]


def stun(mt, attrs, tid, cookie=COOKIE, length=None):
    # A message without attributes makes dissect_stun_message() read the first
    # attribute past the end (frames show Malformed), see the README: only the
    # malformed capture has them.
    if not attrs and not ALLOW_EMPTY[0] and length is None:
        attrs = [attr(0x8022, b'ok')]
    body = b''.join(attrs)
    return struct.pack('>HHI', mt, len(body) if length is None else length, cookie) + tid + body


def attr(t, v, pad=True):
    return struct.pack('>HH', t, len(v)) + v + (b'\0' * ((-len(v)) % 4) if pad else b'')


def addr4(ip, port, family=1):
    return struct.pack('>BBH', 0, family, port) + socket.inet_aton(ip)


def addr6(ip, port):
    return struct.pack('>BBH', 0, 2, port) + socket.inet_pton(socket.AF_INET6, ip)


def xaddr4(ip, port, tid, family=1):
    a = struct.unpack('>I', socket.inet_aton(ip))[0] ^ COOKIE
    return struct.pack('>BBHI', 0, family, port ^ (COOKIE >> 16), a)


def xaddr6(ip, port, tid):
    raw = bytearray(socket.inet_pton(socket.AF_INET6, ip))
    mask = struct.pack('>I', COOKIE) + tid
    x = bytes(a ^ b for a, b in zip(raw, mask))
    return struct.pack('>BBH', 0, 2, port ^ (COOKIE >> 16)) + x


def fingerprint(msg_without_fp, good=True):
    """FINGERPRINT attribute; the message length already counts it."""
    total = len(msg_without_fp) - 20 + 8
    m = msg_without_fp[:2] + struct.pack('>H', total) + msg_without_fp[4:]
    crc = (zlib.crc32(m) & 0xffffffff) ^ 0x5354554e
    if not good:
        crc ^= 1
    return m + struct.pack('>HHI', 0x8028, 4, crc)


def channeldata(ch, data, pad=False):
    d = struct.pack('>HH', ch, len(data)) + data
    return d + (b'\0' * ((-len(d)) % 4) if pad else b'')


MIC = bytes(range(0x40, 0x54))                 # made-up 20 octets, no key
RTCP_SR = bytes.fromhex('80c8000600000001e5a6a2a3000000000000000000000000000000000000000000000000')
SIPMSG = (b'OPTIONS sip:turn@192.0.2.9 SIP/2.0\r\nVia: SIP/2.0/UDP 192.0.2.9;branch=z9hG4bKx\r\n'
          b'From: <sip:a@192.0.2.9>;tag=1\r\nTo: <sip:turn@192.0.2.9>\r\nCall-ID: s@192.0.2.9\r\n'
          b'CSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n')
TFTPRRQ = b'\x00\x01file.txt\x00octet\x00'

C, S = '192.0.2.10', '192.0.2.20'
SRV = '198.51.100.7'


def main(out):
    fr = []
    n = [0]

    def u(payload, sport=40000, dport=3478, src=C, dst=S):
        n[0] += 1
        fr.append(udp(payload, sport, dport, src=src, dst=dst, ident=n[0]))

    def rsp(payload, sport=3478, dport=40000):
        u(payload, sport, dport, S, C)

    t = [0]

    def tid():
        t[0] += 1
        return tid_of(t[0])

    # ------------------------------------------------ Binding with ICE attributes (UDP 3478)
    t1 = tid()
    req = stun(mtype(BINDING, REQ), [attr(6, b'ufrag:peer'), attr(0x24, struct.pack('>I', 1853824767)),
                                      attr(0x802a, bytes(range(8))), attr(0x25, b''),
                                      attr(0x8008 - 0x8008 + 8, MIC)], t1)
    u(fingerprint(req))
    u(fingerprint(req))                                           # retransmission: duplicate request
    rsp(stun(mtype(BINDING, OK), [attr(0x20, xaddr4(C, 40000, t1)), attr(1, addr4(C, 40000)),
                                  attr(0x802b, addr4(S, 3478)), attr(0x802c, addr4(SRV, 3479)),
                                  attr(0x8023, addr4(SRV, 3478)), attr(0x8022, b'turnd 1.0'),
                                  attr(0x8003, b'example.org')], t1))
    rsp(stun(mtype(BINDING, OK), [attr(0x20, xaddr4(C, 40000, t1))], t1))      # duplicate response
    t2 = tid()
    u(stun(mtype(BINDING, REQ), [attr(0x802a, bytes(8)), attr(0x8029, bytes(range(8, 16)))], t2))
    rsp(stun(mtype(BINDING, OK), [attr(0x20, xaddr6('2001:db8::1', 40000, t2)),
                                  attr(1, addr6('2001:db8::1', 40000)),
                                  attr(0x802b, addr6('2001:db8::2', 3478))], t2))
    u(stun(mtype(BINDING, IND), [attr(0x8022, b'ind')], tid()))                # indication, no response
    # an XOR address with an unknown family, then one that is too short
    t3 = tid()
    rsp(stun(mtype(BINDING, OK), [attr(0x20, struct.pack('>BBHI', 0, 7, 1, 2)),
                                  attr(0x20, xaddr4(C, 1, t3)[:4]), attr(1, addr4(C, 2, family=9))], t3))
    # ------------------------------------------------ errors
    t4 = tid()
    u(stun(mtype(BINDING, REQ), [attr(6, b'alice'), attr(0x14, b'example.org'), attr(0x15, b'abcdef0123456789'),
                                 attr(8, MIC)], t4))
    rsp(stun(mtype(BINDING, ERR), [attr(9, struct.pack('>HBB', 0, 4, 1) + b'Unauthorized'),
                                   attr(0x14, b'example.org'), attr(0x15, b'nonce-1234')], t4))
    for code, reason in ((420, b'Unknown Attribute'), (438, b'Stale Nonce'), (487, b'Role Conflict'),
                         (599, b'Custom'), (300, b'Try Alternate'), (400, b'')):
        tx = tid()
        u(stun(mtype(BINDING, REQ), [], tx))
        extra = [attr(0xa, struct.pack('>HHH', 0x0030, 0xc123, 0x7777))] if code == 420 else []
        rsp(stun(mtype(BINDING, ERR), [attr(9, struct.pack('>HBB', 0, code // 100, code % 100) + reason)] + extra, tx))
    # ------------------------------------------------ deprecated RFC 3489 attributes with the cookie
    t5 = tid()
    u(stun(mtype(BINDING, REQ), [attr(3, struct.pack('>I', 6)), attr(3, struct.pack('>I', 4)),
                                 attr(3, struct.pack('>I', 2)), attr(3, struct.pack('>I', 0)),
                                 attr(2, addr4(SRV, 5000)), attr(0x11, addr6('2001:db8::5', 5002)),
                                 attr(7, b'secret??')], t5))
    rsp(stun(mtype(BINDING, OK), [attr(4, addr4(S, 3478)), attr(5, addr4(SRV, 3479)), attr(0xb, addr4(C, 40000)),
                                  attr(0x7, b'pw')], t5))
    # ------------------------------------------------ TURN: Allocate
    ta = tid()
    u(stun(mtype(ALLOC, REQ), [attr(0x19, bytes([17, 0, 0, 0])), attr(0xd, struct.pack('>I', 600)),
                               attr(0x1a, b''), attr(0x18, bytes([0x80, 0, 0, 0])),
                               attr(0x22, bytes(range(8))), attr(0x17, bytes([1, 0, 0, 0])),
                               attr(0x10, struct.pack('>I', 64000)), attr(0x1b, b'token-0123')], ta))
    rsp(stun(mtype(ALLOC, ERR), [attr(9, struct.pack('>HBB', 0, 4, 1) + b'Unauthorized'),
                                 attr(0x14, b'turn.example.org'), attr(0x15, b'n0nce')], ta))
    tb = tid()
    u(stun(mtype(ALLOC, REQ), [attr(0x19, bytes([6, 0, 0, 0])), attr(6, b'alice'),
                               attr(0x14, b'turn.example.org'), attr(0x15, b'n0nce'),
                               attr(0x1c, bytes(32)), attr(0x1e, bytes(range(32))),
                               attr(0x1d, struct.pack('>HH', 2, 0)),
                               attr(0x17, bytes([2, 0, 0, 0]))], tb))
    rsp(stun(mtype(ALLOC, OK), [attr(0x16, xaddr4(SRV, 49152, tb)), attr(0x20, xaddr4(C, 40000, tb)),
                                attr(0xd, struct.pack('>I', 600)), attr(0x10, struct.pack('>I', 1000)),
                                attr(0x16, xaddr6('2001:db8::77', 49153, tb)),
                                attr(0x8000, bytes([2, 0, 0, 0])), attr(0x8001, struct.pack('>HBB', 0, 4, 40) + b'x'),
                                attr(0x8025, struct.pack('>I', 3)), attr(0x2a, struct.pack('>I', 77)),
                                attr(0x1b, b'AT')], tb))
    for m, extra in ((REFRESH, [attr(0xd, struct.pack('>I', 0))]),
                     (PERM, [attr(0x12, xaddr4('203.0.113.9', 5004, tid_of(0))), attr(0x12, xaddr6('2001:db8::9', 5006, tid_of(0)))]),
                     (CHANBIND, [attr(0xc, struct.pack('>HH', 0x4000, 0)), attr(0x12, xaddr4('203.0.113.9', 5004, tid_of(0)))]),
                     (CONNECT, [attr(0x12, xaddr4('203.0.113.9', 5004, tid_of(0)))])):
        tx = tid()
        u(stun(mtype(m, REQ), extra, tx))
        rsp(stun(mtype(m, OK), [attr(0xd, struct.pack('>I', 300))] if m == REFRESH else [], tx))
    # peer addresses with the real transaction id (the XOR of IPv6 uses it)
    tp = tid()
    u(stun(mtype(PERM, REQ), [attr(0x12, xaddr6('2001:db8::99', 7000, tp)), attr(0x12, xaddr4('203.0.113.50', 7001, tp)),
                              attr(0x27, xaddr4('203.0.113.51', 7002, tp)), attr(0x28, xaddr6('2001:db8::51', 7003, tp))], tp))
    rsp(stun(mtype(PERM, OK), [], tp))
    # ------------------------------------------------ TURN Send/Data indications with DATA payloads
    u(stun(mtype(SEND, IND), [attr(0x12, xaddr4('203.0.113.9', 5004, tid_of(0))), attr(0x1a, b''),
                              attr(0x13, RTCP_SR)], tid()))
    rsp(stun(mtype(DATA_IND, IND), [attr(0x12, xaddr4('203.0.113.9', 5004, tid_of(0))), attr(0x13, SIPMSG)], tid()))
    u(stun(mtype(SEND, IND), [attr(0x12, xaddr4('203.0.113.9', 5004, tid_of(0))), attr(0x13, TFTPRRQ)], tid()))
    u(stun(mtype(SEND, IND), [attr(0x12, xaddr4('203.0.113.9', 5004, tid_of(0))), attr(0x13, b'\x99' * 9)], tid()))
    u(stun(mtype(SEND, IND), [attr(0x12, xaddr4('203.0.113.9', 5004, tid_of(0))), attr(0x13, b'')], tid()))
    # STUN carried in a DATA attribute (nested Data indications; dissected only when the
    # "stun_turn" heuristic is enabled): up to eight levels, the limit is four
    inner = b'\0' * 4
    for i in range(8):
        a = attr(0x13, inner)
        inner = stun(mtype(DATA_IND, IND), [a], tid_of(100 + i))
        if i == 7:
            u(inner)
    # ChannelData over UDP: unpadded, padded, a payload that is RTCP
    u(channeldata(0x4000, RTCP_SR))
    u(channeldata(0x4001, bytes(range(11)), pad=True), 40000)
    u(channeldata(0x4002, b'\x01\x02\x03\x04'))
    # ChannelData carrying a STUN message (nested)
    u(channeldata(0x4003, stun(mtype(BINDING, REQ), [attr(0x8022, b'in channel')], tid())))
    u(channeldata(0x4000, b''))
    # ------------------------------------------------ other attributes
    to = tid()
    u(stun(mtype(BINDING, REQ), [attr(0x26, bytes(8)), attr(0x8027, struct.pack('>I', 600)),
                                 attr(0x8004, bytes([3, 1, 0, 0])), attr(0x30, bytes([8, 0, 0, 0])),
                                 attr(0x8000, bytes([1, 0, 0, 0])), attr(0x802e, b'third'),
                                 attr(0x802d, b'\x01'), attr(0x8030, b'ticket!!'), attr(0x8032, b'host.example'),
                                 attr(0x8037, b'app'), attr(0x8039, b'tag'), attr(0xc000, b'cisco'),
                                 attr(0xc001, b'flow'), attr(0xc002, b'net'), attr(0xc058, b'ice'),
                                 attr(0xc059, b'misc'), attr(0xc05a, b'o1'), attr(0xc05b, b'cid'),
                                 attr(0xc05c, b'delta'), attr(0xc05d, b'ack'), attr(0xc060, b'mi32'),
                                 attr(0xff04, b'multi'), attr(0xff05, b'logid'),
                                 attr(0xc057, struct.pack('>HH', 3, 999)), attr(0xc057, struct.pack('>HH', 9, 50)),
                                 attr(0xc057, struct.pack('>HH', 1, 7)), attr(0xc057, struct.pack('>HH', 2, 910)),
                                 ], to))
    u(stun(mtype(GOOGPING, REQ), [], tid()))
    u(stun(mtype(GOOGPING, OK), [], tid()), 40000)
    u(stun(mtype(0x30, REQ), [attr(0x8022, b'method 0x30')], tid()))
    u(stun(mtype(SHARED, REQ), [attr(6, b'name'), attr(7, b'pw')], tid()))
    u(stun(mtype(CONNATT, IND), [attr(0x2a, struct.pack('>I', 9)), attr(0x12, xaddr4('203.0.113.9', 5004, tid_of(0)))], tid()))
    # password algorithms: valid lists with and without parameters and padding
    tw = tid()
    u(stun(mtype(BINDING, ERR), [attr(0x8002, struct.pack('>HH', 1, 4) + b'abcd' + struct.pack('>HH', 2, 0)),
                                 attr(0x1d, struct.pack('>HH', 1, 0)),
                                 attr(0x8002, struct.pack('>HH', 1, 5) + b'abcde\0\0\0' + struct.pack('>HH', 2, 3) + b'xyz\0'),
                                 attr(0x8002, b'')], tw))
    # ------------------------------------------------ MS-TURN messages (also dissected as RFC 5389/8489)
    tm = tid()
    ms = [attr(0xf, struct.pack('>I', MSCOOKIE))]
    u(stun(mtype(ALLOC, REQ), ms + [attr(0x8008, struct.pack('>I', 3)),
                                    attr(0x8070, struct.pack('>I', 2)),
                                    attr(0x8050, bytes(range(20)) + struct.pack('>I', 5)),
                                    attr(0x8055, struct.pack('>HH', 1, 2)),
                                    attr(0x8054, b'AbCd'),
                                    attr(0x8056, struct.pack('>HH', 0, 1)),
                                    attr(0x8057, bytes(range(16))),
                                    attr(0x8058, struct.pack('>IIII', 1, 2, 3, 4)),
                                    attr(0x805d, struct.pack('>III', 0x80000000, 5, 6)),
                                    attr(0x805f, struct.pack('>III', 0x40000000, 5, 6)),
                                    attr(0x805e, struct.pack('>III', 0x10000000, 7, 8)),
                                    attr(0x8060, struct.pack('>III', 0x20000000, 7, 8)),
                                    attr(0x8061, b'dialog-id'), attr(0x8062, b'call-id-1234'),
                                    attr(0x8068, bytes([1, 2, 1, 0])),
                                    attr(0x8095, struct.pack('>Q', 0x1122334455667788)),
                                    attr(0x8006, b'\x00\x01\x02\x03'),
                                    attr(0x8020, xaddr4(C, 40000, tm)), attr(0x8090, addr4(SRV, 4000)),
                                    attr(0x000e, addr4(SRV, 4001)), attr(0x8059, xaddr4(C, 1, tm)),
                                    attr(0x805a, xaddr4(C, 2, tm)), attr(0x805b, xaddr6('2001:db8::7', 3, tm)),
                                    attr(0x805c, xaddr4(C, 4, tm))], tm))
    u(stun(0x0004, ms + [attr(0x13, RTCP_SR)], tid()))                    # MS-TURN Send
    u(stun(0x0115, ms + [attr(0x13, SIPMSG)], tid()))                     # MS-TURN Data indication
    u(stun(0x0004, ms, tid(), length=None))
    # MS-TURN multiplexed ChannelData: session id, then payload
    u(channeldata(0xff10, struct.pack('>Q', 0x1122334455667788) + RTCP_SR))
    u(channeldata(0xff10, b'\x01\x02\x03', pad=True))                     # too short for a session id
    # a request that gets a response from the other side (different tuple, same tid): no match
    u(stun(mtype(BINDING, REQ), [], tid()), 40001, 3478)
    # ------------------------------------------------ STUN on other ports: UDP heuristic
    tq = tid()
    u(stun(mtype(BINDING, REQ), [], tq), 50000, 50001)
    rsp(stun(mtype(BINDING, OK), [attr(0x20, xaddr4(C, 50000, tq))], tq), 50001, 50000)
    u(channeldata(0x4000, RTCP_SR), 50000, 50001)                          # now a known STUN conversation
    # two STUN messages in one datagram (the UDP PDU walker)
    u(stun(mtype(BINDING, REQ), [], tid()) + stun(mtype(BINDING, IND), [], tid()), 40010, 3478)
    # a UDP payload that is not STUN on port 3478 and a heuristic miss elsewhere
    u(b'\x80\x00\x00\x00' + b'\0' * 20, 40011, 3478)                      # reserved channel range
    u(b'\x40\x00\x00\x20' + b'\0' * 8, 40011, 3478)                       # ChannelData length mismatch
    u(b'\x00\x01\x00\x00\x00\x00\x00\x00' + b'\0' * 12, 40011, 3478)      # no magic cookie (classic STUN)
    u(b'\x3f\xff\x00\x00' + struct.pack('>I', COOKIE) + b'\0' * 12, 40011, 3478)   # method above 0x3ff
    u(b'\x00\x01\x00\x20' + struct.pack('>I', COOKIE) + b'\0' * 12, 40011, 3478)   # length past the end
    u(b'\x00\x01\x00', 40011, 3478)                                       # shorter than the minimum header
    u(b'\x00\x01\x00\x00\x21\x12', 40011, 3478)                           # header cut short
    u(channeldata(0x4000, RTCP_SR), 50002, 50003)                         # heuristic never matches ChannelData
    n_udp = len(fr)

    # ------------------------------------------------ TCP 3478
    def tcpconn(sport, dport=3478):
        c = TcpConn(sport, dport, C, S)
        c.handshake()
        return c
    c1 = tcpconn(41000)
    tx = tid()
    c1.send(stun(mtype(BINDING, REQ), [attr(0x8022, b'tcp')], tx))
    c1.send(stun(mtype(BINDING, OK), [attr(0x20, xaddr4(C, 41000, tx))], tx), client=False)
    # RFC 4571 framing (RFC 6544): a two octet length before every message
    m1 = stun(mtype(ALLOC, REQ), [attr(0x19, bytes([6, 0, 0, 0]))], tid())
    c1.send(struct.pack('>H', len(m1)) + m1)
    m2 = stun(mtype(ALLOC, OK), [attr(0x16, xaddr4(SRV, 49152, tid_of(0)))], tid())
    c1.send(struct.pack('>H', len(m2)) + m2, client=False)
    # two messages in one segment, a message in two segments
    m3 = stun(mtype(BINDING, REQ), [], tid())
    m4 = stun(mtype(BINDING, IND), [attr(0x8022, b'two')], tid())
    c1.send(m3 + m4)
    m5 = stun(mtype(BINDING, REQ), [attr(0x8022, b'split across two segments')], tid())
    c1.send(m5[:11])
    c1.send(m5[11:])
    # ChannelData over TCP is padded to four octets
    c1.send(channeldata(0x4000, bytes(range(13)), pad=True))
    c1.send(channeldata(0x4001, RTCP_SR, pad=True), client=False)
    # Send indication with DATA (SIP) over TCP
    c1.send(stun(mtype(SEND, IND), [attr(0x12, xaddr4('203.0.113.9', 5004, tid_of(0))), attr(0x13, SIPMSG)], tid()))
    # ConnectionBind (RFC 6062): the connection becomes raw data afterwards
    c2 = tcpconn(41001)
    tx = tid()
    c2.send(stun(mtype(CONNBIND, REQ), [attr(0x2a, struct.pack('>I', 77))], tx))
    c2.send(stun(mtype(CONNBIND, OK), [], tx), client=False)
    c2.send(b'plain application data after ConnectionBind')
    c2.send(b'\x00\x01\x00\x00' + struct.pack('>I', COOKIE) + b'\0' * 12, client=False)
    # heuristic TCP: STUN on another port, plain and with RFC 4571 framing
    c3 = tcpconn(41002, 50010)
    tx = tid()
    c3.send(stun(mtype(BINDING, REQ), [], tx))
    c3.send(stun(mtype(BINDING, OK), [attr(0x20, xaddr4(C, 41002, tx))], tx), client=False)
    c4 = tcpconn(41003, 50011)
    m6 = stun(mtype(BINDING, REQ), [], tid())
    c4.send(struct.pack('>H', len(m6)) + m6)
    c4.send(struct.pack('>H', len(m6)) + m6, client=False)
    c5 = tcpconn(41004, 50012)                         # not STUN at all
    c5.send(b'GET / HTTP/1.0\r\n\r\n')
    c5.send(channeldata(0x4000, RTCP_SR, pad=True))    # ChannelData is not matched by the heuristic
    for c in (c1, c2, c3, c4, c5):
        pass
    tcp_frames = c1.frames + c2.frames + c3.frames + c4.frames + c5.frames

    frames = fr + tcp_frames
    # an Exported PDU frame naming the STUN UDP dissector
    ep = exported_pdu('stun-udp', stun(mtype(BINDING, REQ), [attr(0x8022, b'exported')], tid()))
    pcapng(os.path.join(out, 'stun-coverage.pcapng'), [(0, f) for f in frames] + [(1, ep)],
           (LT_ETH, LT_EXPORTED_PDU))
    print('main capture: %d frames (1-%d UDP, %d-%d TCP, %d Exported PDU)'
          % (len(frames) + 1, n_udp, n_udp + 1, len(frames), len(frames) + 1))

    # ---------------------------------------------------------------- versions
    v = []
    tv = tid_of(200)
    # RFC 3489 style: attribute lengths that are not multiples of four, no padding
    v.append(udp(stun(mtype(BINDING, REQ), [attr(6, b'alice', pad=False), attr(0x14, b'realm', pad=False),
                                            attr(0x15, b'non', pad=False), attr(0x8022, b'x', pad=False)], tv),
                 40100, 3478, ident=1))
    v.append(udp(stun(mtype(BINDING, REQ), [attr(0x14, b'abcd'), attr(0x15, b'efgh')], tv), 40100, 3478, ident=2))
    # MS-TURN: REALM and NONCE swapped, MAGIC-COOKIE first, unpadded attributes
    v.append(udp(stun(mtype(ALLOC, REQ), [attr(0xf, struct.pack('>I', MSCOOKIE)), attr(0x15, b'ms-realm', pad=False),
                                          attr(0x14, b'ms-nonce12', pad=False), attr(6, b'bob', pad=False)],
                      tid_of(201)), 40101, 3478, ident=3))
    # a message length that is not a multiple of four
    v.append(udp(stun(mtype(BINDING, REQ), [attr(0x8022, b'abc', pad=False)], tid_of(202)), 40102, 3478, ident=4))
    v.append(udp(stun(mtype(BINDING, REQ), [attr(0x8022, b'abcde', pad=False)], tid_of(203)), 40102, 3478, ident=5))
    pcapng(os.path.join(out, 'stun-coverage-versions.pcapng'), [(0, f) for f in v], (LT_ETH,))

    # ---------------------------------------------------------------- malformed
    m = []
    ALLOW_EMPTY[0] = True

    def mu(payload, sport=40200, dport=3478, ident=None):
        m.append(udp(payload, sport, dport, ident=len(m) + 1))
    tid_m = tid_of(300)
    # attributes cut short at every length gate
    for a_t in (0x1, 0x2, 0x4, 0x802b, 0x20, 0x12, 0x8059):
        for ln in (0, 1, 3, 5):
            mu(stun(mtype(BINDING, OK), [attr(a_t, bytes(ln))], tid_m))
    mu(stun(mtype(BINDING, OK), [attr(0x1, struct.pack('>BBH', 0, 1, 80) + b'\x01\x02')], tid_m))     # IPv4 cut
    for a_t in (2, 4, 5, 0xb, 0x11):
        mu(stun(mtype(BINDING, OK), [attr(a_t, struct.pack('>BBH', 0, 1, 80) + b'\x01\x02')], tid_m))
        mu(stun(mtype(BINDING, OK), [attr(a_t, struct.pack('>BBH', 0, 2, 80) + bytes(10))], tid_m))
    mu(stun(mtype(BINDING, OK), [attr(0x1, struct.pack('>BBH', 0, 2, 80) + bytes(10))], tid_m))      # IPv6 cut
    mu(stun(mtype(BINDING, OK), [attr(0x20, struct.pack('>BBH', 0, 2, 80) + bytes(10))], tid_m))
    mu(stun(mtype(BINDING, OK), [attr(0x20, struct.pack('>BBHI', 0, 1, 80, 1))[:12]], tid_m, length=8 + 4 - 0))
    for a_t, ln in ((8, 10), (9, 1), (9, 2), (9, 3), (9, 4), (3, 2), (0x24, 2), (0x8028, 2), (0x8029, 4),
                    (0x19, 0), (0x19, 2), (0xc, 2), (0xd, 2), (0x10, 2), (0x8027, 2), (0x30, 2), (0x18, 0),
                    (0x22, 4), (0x17, 0), (0x17, 2)):
        mu(stun(mtype(BINDING, REQ), [attr(a_t, bytes(ln))], tid_m))
    mu(stun(mtype(BINDING, REQ), [attr(9, struct.pack('>HBB', 0, 4, 1))], tid_m))                     # no reason
    mu(stun(mtype(BINDING, REQ), [attr(0x8000, b'\x01\x00\x00\x00'), attr(0x7777, b'zz')], tid_m))     # unknown attribute
    mu(stun(mtype(BINDING, REQ), [attr(0xa, b'\x00\x30\x00')], tid_m))                                # odd UNKNOWN-ATTRIBUTES
    mu(stun(mtype(BINDING, REQ), [attr(0x8022, b'sw'), attr(0xf, b'ab')], tid_m))                     # MAGIC-COOKIE too short
    # attribute that runs past the end of the message
    mu(stun(mtype(BINDING, REQ), [struct.pack('>HH', 0x8022, 200) + b'abcd'], tid_m))
    mu(stun(mtype(BINDING, REQ), [struct.pack('>HH', 0x7777, 200) + b'abcd'], tid_m))
    # bad fingerprint, fingerprint that is the only attribute
    bad = stun(mtype(BINDING, REQ), [attr(0x8022, b'fp!!')], tid_m)
    mu(fingerprint(bad, good=False))
    # PASSWORD-ALGORITHMS corner cases (the unfixed length check and the fixed ones)
    pa = [struct.pack('>HH', 1, 4) + b'abcd' + struct.pack('>HH', 2, 0),                 # valid
          struct.pack('>HH', 1, 8) + b'abcd',                                           # parameter past the end
          struct.pack('>HH', 1, 3) + b'ab',                                             # parameter longer than data
          b'\x00\x01\x00',                                                              # shorter than a TLV header
          struct.pack('>HH', 1, 1) + b'a\0\0\0' + b'\0\x02',                             # trailing 2 octets
          struct.pack('>HH', 1, 6) + b'abcdef\0\0' ]
    for body in pa:
        mu(stun(mtype(BINDING, REQ), [attr(0x8002, body), attr(0x8022, b'SW-NAME-AFTER-ATTR')], tid_m))
        mu(stun(mtype(BINDING, REQ), [attr(0x1d, body), attr(0x8022, b'SW-NAME-AFTER-ATTR')], tid_m))
    mu(stun(mtype(BINDING, REQ), [attr(0x1d, struct.pack('>HH', 1, 4) + b'abcd' + struct.pack('>HH', 2, 0))], tid_m))
    # a PASSWORD-ALGORITHM(S) attribute whose declared length is not padded to four
    mu(stun(mtype(BINDING, REQ), [attr(0x1d, struct.pack('>HH', 1, 1) + b'a', pad=False) + b'\0\0\0'], tid_m))
    # ChannelData: length that does not fit
    mu(b'\x40\x00\x00\x40' + b'\0' * 8)
    mu(b'\x7f\xff\x00\x00')
    # messages without attributes (the first attribute is read past the end), one response without a request
    for k, mt_ in enumerate((mtype(BINDING, REQ), mtype(BINDING, IND), mtype(BINDING, OK), mtype(ALLOC, REQ),
                            mtype(GOOGPING, REQ))):
        mu(stun(mt_, [], tid_of(310 + k)))
    mu(stun(mtype(BINDING, REQ), [attr(0x8022, b'')], tid_of(320)))                                      # 4 octets of attribute
    mu(stun(mtype(BINDING, REQ), [attr(0x8022, b'abcd')], tid_of(321)))
    mu(stun(mtype(BINDING, OK), [], tid_of(301)))
    # TCP-style 4571 framing inside UDP is not accepted
    mu(struct.pack('>H', 20) + stun(mtype(BINDING, REQ), [], tid_of(302)))
    # nested STUN (enable the stun_turn heuristic): the depth limit and the layer limit
    inner = b'\0' * 4
    for i in range(10):
        inner = stun(mtype(DATA_IND, IND), [attr(0x13, inner)], tid_of(400 + i))
    mu(inner)
    inner = channeldata(0x4000, b'\0' * 4)
    for i in range(6):
        inner = channeldata(0x4000 + i, inner)
    mu(inner)
    pcapng(os.path.join(out, 'stun-coverage-malformed.pcapng'), [(0, f) for f in m], (LT_ETH,))
    print('versions capture: %d frames, malformed capture: %d frames' % (len(v), len(m)))


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')
