#!/usr/bin/env python3
# Generates test/captures/do_irp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the DO-IRP dissector
(packet-do-irp.c, Digital Object Identifier Resolution Protocol, the
Handle System protocol of RFC 3652 and DO-IRP v3.0).

DO-IRP runs over UDP and TCP port 2641 (registered by default). Every
message has a 20 octet envelope (version, flags CP/EC/TC, suggested
version, session ID, request ID, sequence number, message length), a
24 octet header (opcode, response code, operation flags, site info
serial, recursion count, expiration, body length), a body and a
credential. UDP messages longer than 492 octets are sent in fragments,
each with an envelope, and reassembled by request ID and sequence
number; TCP messages go through tcp_dissect_pdus(). Requests and
responses are matched by request ID. Every packet is built from
scratch with struct; signatures, nonces and keys are placeholder octet
strings, not real cryptographic data.

Usage: mkdo_irp.py <output directory>

Writes:
  do-irp-coverage.pcap            every opcode's request and response,
                                  every identifier record type, HS_SITE
                                  with attributes, servers and interfaces,
                                  RSA, DSA and DH public keys, digests,
                                  referrals, error responses, credentials,
                                  encrypted and fragmented messages, TCP
                                  messages sharing and spanning segments,
                                  the clean reproducers of the fixes
  do-irp-coverage-malformed.pcap  lengths beyond the data, unknown digest,
                                  fragments without TC, reassembly errors,
                                  the TCP length wrap, non-DO-IRP data
"""

import os
import socket
import struct
import sys

PORT = 2641
CLIENT = '192.0.2.1'
SERVER = '192.0.2.2'
TC, EC, CP = 0x20, 0x40, 0x80
RD = 0x00800000


def pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s_ = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s_ >> 16:
        s_ = (s_ & 0xffff) + (s_ >> 16)
    return (~s_) & 0xffff


def mac(ip):
    return bytes([2, 0, 0, 0, 0, int(ip.split('.')[-1])])


def ip4(src, dst, proto, payload):
    h = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, 0x4000, 64, proto, 0,
                    socket.inet_aton(src), socket.inet_aton(dst))
    h = h[:10] + struct.pack('>H', csum(h)) + h[12:]
    return mac(dst) + mac(src) + b'\x08\x00' + h + payload


def udp_raw(src, sport, dst, dport, payload):
    u = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    ph = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack('>BBH', 0, 17, len(u))
    c = csum(ph + u) or 0xffff
    return ip4(src, dst, 17, u[:6] + struct.pack('>H', c) + u[8:])


def req(payload, cport=40000):
    return udp_raw(CLIENT, cport, SERVER, PORT, payload)


def rsp(payload, cport=40000):
    return udp_raw(SERVER, PORT, CLIENT, cport, payload)


class Tcp:
    def __init__(self, cport, frames):
        self.cport, self.frames = cport, frames
        self.seq = {True: 1000, False: 5000}
        self.seg(True, 0x02, b'')
        self.seq[True] += 1
        self.seg(False, 0x12, b'')
        self.seq[False] += 1
        self.seg(True, 0x10, b'')

    def seg(self, c2s, flags, payload):
        src, dst = (CLIENT, SERVER) if c2s else (SERVER, CLIENT)
        sport, dport = (self.cport, PORT) if c2s else (PORT, self.cport)
        ack = self.seq[not c2s] if flags & 0x10 else 0
        opts = b'\x02\x04\x05\xb4\x01\x01\x04\x02' if flags & 0x02 else b''
        t = struct.pack('>HHIIBBHHH', sport, dport, self.seq[c2s], ack,
                        (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts + payload
        ph = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack('>BBH', 0, 6, len(t))
        t = t[:16] + struct.pack('>H', csum(ph + t)) + t[18:]
        self.frames.append(ip4(src, dst, 6, t))
        self.seq[c2s] += len(payload)

    def send(self, c2s, payload):
        self.seg(c2s, 0x18, payload)


# --- DO-IRP building blocks ---

def s(text):
    """String: 4 octet length and UTF-8 octets."""
    b = text.encode() if isinstance(text, str) else text
    return struct.pack('>I', len(b)) + b


def d(b):
    """Generic data: 4 octet length and octets."""
    return struct.pack('>I', len(b)) + b


def u32(v):
    return struct.pack('>I', v)


def env(reqid, msglen, seq=0, flags=0, sess=0, major=2, minor=1, sugg=(2, 1)):
    return struct.pack('>BBBBIIII', major, minor, flags | sugg[0], sugg[1], sess, reqid, seq, msglen)


def hdr(opcode, resp, bodylen, opflags=0, sisn=0, rcount=0, exp=0):
    return struct.pack('>IIIHBBII', opcode, resp, opflags, sisn, rcount, 0, exp, bodylen)


def cred_empty():
    return u32(0)


def cred_signed(algo='SHA256withRSA', sig=b'\x5a' * 16, ctype='HS_SIGNED'):
    si = s(algo) + d(sig)
    body = bytes(8) + u32(7) + s(ctype) + u32(len(si)) + si
    return u32(len(body)) + body


def cred_nosig(ctype='HS_MAC'):
    body = bytes(8) + u32(3) + s(ctype) + u32(0)
    return u32(len(body)) + body


def message(opcode, resp, body, cred=None, opflags=0, bodylen=None):
    if cred is None:
        cred = cred_empty()
    return hdr(opcode, resp, len(body) if bodylen is None else bodylen, opflags) + body + cred


def pdu(reqid, inner, **kw):
    return env(reqid, len(inner), **kw) + inner


def pk(ptype, comps, trailer=b''):
    inner = s(ptype) + b'\0\0' + b''.join(d(c) for c in comps) + trailer
    return u32(len(inner)) + inner


def rsa_pk():
    # RSA keys end with 4 unused octets
    return pk('RSA_PUB_KEY', [b'\x01\x00\x01', b'\xc3' * 32], bytes(4))


def dsa_pk():
    return pk('DSA_PUB_KEY', [b'\x11' * 20, b'\x22' * 32, b'\x33' * 32, b'\x44' * 32])


def dh_pk():
    return pk('DH_PUB_KEY', [b'\x55' * 32, b'\x66' * 32, b'\x02'])


def hssite(attrs, servers, version=1, serial=3, primask=0xc0, hashopt=2):
    v = struct.pack('>HBBHBB', version, 2, 10, serial, primask, hashopt) + s('')
    v += u32(len(attrs)) + b''.join(s(k) + s(val) for k, val in attrs)
    v += u32(len(servers))
    for sid, addr, key, ifs in servers:
        v += u32(sid) + addr + key + u32(len(ifs))
        v += b''.join(struct.pack('>BBI', t, p, port) for t, p, port in ifs)
    return u32(len(v)) + v


def record(idx, rtype, value, refs=(), ttl_type=0, ttl=86400, perm=0x0e, ts=1700000000):
    r = u32(idx) + u32(ts) + bytes([ttl_type]) + u32(ttl) + bytes([perm]) + s(rtype) + value
    r += u32(len(refs)) + b''.join(s(x) for x in refs)
    return r


def hsadmin(perm=0x0fff, ident='0.NA/10.1000', index=300):
    v = struct.pack('>H', perm) + s(ident) + u32(index)
    return u32(len(v)) + v


V4ADDR = bytes(12) + socket.inet_aton(SERVER)
V6ADDR = bytes.fromhex('20010db8000000000000000000000002')

SITE = hssite([('desc', 'Primary site'), ('domain', 'example.org')],
              [(1, V4ADDR, rsa_pk(), [(0x02, 0, 2641), (0x01, 1, 2641), (0x03, 2, 8000)]),
               (2, V6ADDR, dsa_pk(), [(0x02, 3, 8443)])])


def all_records():
    """One identifier record of every type the dissector knows."""
    return [
        record(100, 'HS_ADMIN', hsadmin()),
        record(1, 'HS_SITE', SITE, ttl_type=1, ttl=1800000000),
        record(2, 'HS_SITE.PREFIX', hssite([], [])),
        record(3, 'HS_SERV', s('0.NA/10.SERV')),
        record(4, 'HS_SERV.PREFIX', s('0.NA/10.SERV2')),
        record(300, 'HS_PUBKEY', dsa_pk(), perm=0x0f),
        record(301, 'HS_PUBKEY', dh_pk()),
        record(5, 'HS_VLIST', u32(2) + s('10.1000/admins') + s('10.1000/others')),
        record(6, 'HS_NAMESPACE', s('<namespace/>')),
        record(7, 'HS_ALIAS', s('10.1000/alias')),
        record(8, 'HS_CERT', s('eyJhbGciOiJub25lIn0.e30.')),
        record(9, 'HS_SIGNATURE', s('eyJhbGciOiJub25lIn0.e30.')),
        record(10, 'DESC', s('An example object')),
        record(11, 'EMAIL', s('admin@example.org')),
        record(12, 'URL', s('https://example.org/'), refs=('10.1000/1', '10.1000/2')),
        record(13, 'CUSTOM', d(b'\x01\x02\x03\x04')),
        record(14, 'URL', s('')),
    ]


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    f = []

    # 1-2: resolution query with indices and types, and an error response
    f.append(req(pdu(1, message(1, 0, s('10.1000/1') + u32(2) + u32(1) + u32(100) +
                                u32(2) + s('URL') + s('HS_ADMIN'),
                                opflags=0x80000000 | 0x10000000))))
    f.append(rsp(pdu(1, message(1, 100, s('Identifier not found')))))
    # 3-4: resolution query (empty identifier, no indices or types) and a
    # success response with an URL and an EMAIL record
    f.append(req(pdu(2, message(1, 0, s('10.1000/2') + u32(0) + u32(0)))))
    f.append(rsp(pdu(2, message(1, 1, s('10.1000/2') + u32(2) +
                                all_records()[12] + all_records()[11]))))
    # 5-7: responses with a message digest (RD flag): MD5, SHA-1, SHA-256
    for i, (algo, n) in enumerate(((1, 16), (2, 20), (3, 32))):
        body = bytes([algo]) + bytes(range(n)) + s('10.1000/3') + u32(1) + all_records()[10]
        f.append(rsp(pdu(3 + i, message(1, 1, body, opflags=RD))))
    # 8: request with the RD flag (no digest in requests)
    f.append(req(pdu(6, message(1, 0, s('10.1000/6') + u32(0) + u32(0), opflags=RD))))
    # 9-10: service referral with a referral identifier, prefix referral
    # with identifier records instead
    f.append(rsp(pdu(7, message(1, 302, s('0.NA/10.SERV')))))
    f.append(rsp(pdu(8, message(1, 303, s('') + u32(1) + all_records()[3]))))
    # 11-12: challenge (authentication needed) and challenge response
    f.append(rsp(pdu(9, message(1, 402, d(b'\x9e' * 16)))))
    f.append(req(pdu(9, message(200, 0, s('HS_PUBKEY') + s('0.NA/10.1000') + u32(300) +
                                d(b'\xa5' * 20)))))
    # 13-14: verify response request and its response (match)
    f.append(req(pdu(10, message(201, 0, s('0.NA/10.1000') + u32(300) + d(b'\x9e' * 16) +
                                 d(b'\x11' * 20) + d(b'\xa5' * 20)))))
    f.append(rsp(pdu(10, message(201, 1, b'\x01'))))
    # 15-16: get site info request and response with HS_SITE
    f.append(req(pdu(11, message(2, 0, s('')))))
    f.append(rsp(pdu(11, message(2, 1, SITE))))
    # 17-18: list homed prefixes request and response
    f.append(req(pdu(12, message(302, 0, s('')))))
    f.append(rsp(pdu(12, message(302, 1, u32(2) + s('10.1000') + s('10.2000')))))
    # 19-20: create identifier with HS_ADMIN, and its response
    f.append(req(pdu(13, message(100, 0, s('10.1000/new') + u32(1) + all_records()[0],
                                 cred=cred_signed()))))
    f.append(rsp(pdu(13, message(100, 1, s('10.1000/new')))))
    # 21-22: delete identifier, success response without a body
    f.append(req(pdu(14, message(101, 0, s('10.1000/new'), cred=cred_nosig()))))
    f.append(rsp(pdu(14, message(101, 1, b''))))
    # 23-24: add elements and modify elements requests
    f.append(req(pdu(15, message(102, 0, s('10.1000/1') + u32(2) + all_records()[13] +
                                 all_records()[16]))))
    f.append(req(pdu(16, message(104, 0, s('10.1000/1') + u32(1) + all_records()[9]))))
    # 25: remove elements request with indices
    f.append(req(pdu(17, message(103, 0, s('10.1000/1') + u32(3) + u32(1) + u32(2) + u32(3)))))
    # 26-27: list identifiers request and response
    f.append(req(pdu(18, message(105, 0, s('10.1000')))))
    f.append(rsp(pdu(18, message(105, 1, u32(3) + s('10.1000/1') + s('10.1000/2') + s('10.1000/3')))))
    # 28-29: list derived prefixes request and response
    f.append(req(pdu(19, message(106, 0, s('10')))))
    f.append(rsp(pdu(19, message(106, 1, u32(1) + s('10.1000')))))
    # 30-31: home and unhome prefix requests
    f.append(req(pdu(20, message(300, 0, s('0.NA/10.3000')))))
    f.append(req(pdu(21, message(301, 0, s('0.NA/10.3000')))))
    # 32-33: session setup request and response with DH public keys
    f.append(req(pdu(22, message(400, 0, struct.pack('>HI', 4, 3600) + s('0.NA/10.1000') +
                                 u32(300) + dh_pk()))))
    f.append(rsp(pdu(22, message(400, 1, struct.pack('>H', 4) + dh_pk()))))
    # 34: session terminate (unsupported body, shown as data)
    f.append(req(pdu(23, message(401, 0, b'\x00\x01\x02\x03'))))
    # 35-41: error responses of each range, with and without indices
    f.append(rsp(pdu(24, message(102, 2, s('Error') + u32(2) + u32(5) + u32(6)))))
    f.append(rsp(pdu(25, message(102, 201, s('Element already exists') + u32(1) + u32(5)))))
    f.append(rsp(pdu(26, message(1, 301, s('Server not responding')))))
    f.append(rsp(pdu(27, message(100, 400, s('Invalid admin')))))
    f.append(rsp(pdu(28, message(100, 401, s('')))))
    f.append(rsp(pdu(29, message(200, 403, s('Authentication failed')))))
    f.append(rsp(pdu(30, message(400, 505, s('Session message rejected')))))
    # 42-43: unsupported codes: success response to add elements with a
    # body, unknown opcode and response code
    f.append(rsp(pdu(31, message(102, 1, b'\xde\xad'))))
    f.append(req(pdu(32, message(999, 999, b'\xbe\xef'))))
    # 44: version 3 envelope with CP flag and suggested version 3.0,
    # session ID; response code 302 to a non-resolution opcode (unsupported)
    f.append(rsp(pdu(33, message(2, 302, b'\x01'), flags=CP, sess=0x12345678, major=3,
                     minor=0, sugg=(3, 0))))
    # 45: encrypted message (EC flag), not fragmented
    f.append(rsp(pdu(34, b'\xe0' * 40, flags=EC)))
    # 46-47: fragmented resolution response (TC flag), reassembled
    big = message(1, 1, s('10.1000/big') + u32(len(all_records())) + b''.join(all_records()))
    frags = [big[i:i + 492] for i in range(0, len(big), 492)]
    for i, fr in enumerate(frags):
        f.append(rsp(env(35, len(big), seq=i, flags=TC) + fr))
    # encrypted fragmented message of exactly two fragments
    enc = b'\xe1' * 984
    f.append(rsp(env(36, len(enc), seq=0, flags=TC | EC) + enc[:492]))
    f.append(rsp(env(36, len(enc), seq=1, flags=TC | EC) + enc[492:]))
    # small message with TC set: a single fragment, which is never
    # reassembled
    sm = message(2, 0, s(''))
    f.append(req(env(37, len(sm), seq=0, flags=TC) + sm))
    # reproducer do_irp_frag_id16.pcap (A): request IDs 0x00010007 and 7
    # are different messages, so their fragments are not reassembled
    inner = hdr(2, 0, 8) + s(b'ABCD') + b'\0\0\0\0'
    frag0 = inner + b'P' * (492 - len(inner))
    frag1 = b'Q' * (600 - 492)
    f.append(req(env(0x00010007, 600, seq=0, flags=TC) + frag0))
    f.append(req(env(0x00000007, 600, seq=1, flags=TC) + frag1))
    # reproducer do_irp_misc.pcap (UDP): fragments with message length
    # 0xffffffff
    f.append(req(env(31, 0xffffffff, seq=0, flags=TC) + inner + b'P' * 400, cport=40005))
    f.append(req(env(31, 0xffffffff, seq=1, flags=TC) + b'Q' * 400, cport=40005))
    # reproducer do_irp_resp_map.pcap: request, two responses, the request
    # again and a third response; "Response In" is the first response
    rq = pdu(21, message(2, 0, s('x')), )
    rs = pdu(21, message(2, 2, s('err')))
    for p_, c2s in ((rq, True), (rs, False), (rs, False), (rq, True), (rs, False)):
        f.append(req(p_, cport=40006) if c2s else rsp(p_, cport=40006))
    # response with a digest and a body length shorter than the digest
    # (unsupported opcode; nothing is left for the data dissector)
    f.append(rsp(pdu(38, hdr(999, 1, 4, RD) + b'\x01' + bytes(16) + cred_empty())))
    # a message without a credential
    f.append(req(pdu(40, message(2, 0, s(''), cred=b''))))
    # every operation flag set
    f.append(req(pdu(39, message(1, 0, s('10.1000/flags') + u32(0) + u32(0),
                                 opflags=0xfff00000))))

    # --- TCP ---
    c = Tcp(40001, f)
    # resolution query and a large response with every record type
    q = pdu(43, message(1, 0, s('10.1000/big') + u32(0) + u32(0)))
    c.send(True, q)
    c.send(False, pdu(43, big))
    # two queries in one segment
    c.send(True, pdu(41, message(2, 0, s(''))) + pdu(42, message(105, 0, s('10.1000'))))
    # a response split over three segments; the next response starts in
    # the last of them. (Every segment must start with an envelope or be
    # part of a pending reassembly: test_do_irp() rejects others.)
    r = pdu(41, message(2, 1, SITE, cred=cred_signed('SHA1withDSA', b'\x77' * 20)))
    r2 = pdu(42, message(105, 1, u32(1) + s('10.1000/1')))
    c.send(False, r[:30])
    c.send(False, r[30:100])
    c.send(False, r[100:] + r2[:25])
    c.send(False, r2[25:])
    pcap(os.path.join(out, 'do-irp-coverage.pcap'), f)

    # --- malformed ---
    m = []
    # reproducer do_irp_len_wrap.pcap: lengths near 0xffffffff
    m.append(rsp(pdu(1, message(1, 402, u32(0xffffffff) + b'ABCDEFGH', cred=b''))))
    body = struct.pack('>H', 1) + u32(0xfffffffb) + s(b'X') + b'\0\0' + bytes(4)
    m.append(rsp(pdu(2, message(400, 1, body, cred=b''))))
    body = struct.pack('>H', 1) + u32(0xfffffffc) + s(b'X') + b'\0\0' + bytes(4)
    m.append(rsp(pdu(3, message(400, 1, body, cred=b''))))
    m.append(req(pdu(4, message(2, 0, u32(0xfffffffc) + b'abcd', cred=b''))))
    m.append(req(pdu(5, message(2, 0, u32(0xffffffff) + b'abcd', cred=b''))))
    m.append(req(pdu(6, message(999, 0, b'zzzz', cred=b'', bodylen=0xffffffff))))
    m.append(req(pdu(7, message(999, 0, b'zzzz', cred=b'', bodylen=0x7fffffff))))
    # credential and signed info lengths beyond the data
    m.append(req(pdu(8, message(2, 0, s(''), cred=u32(0xfffffff0)))))
    m.append(req(pdu(9, message(2, 0, s(''), cred=u32(30) + bytes(8) + u32(1) + s('X') +
                                u32(0xffffff00) + bytes(5)))))
    # unknown digest algorithm
    m.append(rsp(pdu(10, message(1, 1, b'\x09' + bytes(20), opflags=RD))))
    # fragment without the TC flag (message longer than 492)
    m.append(req(env(11, 600) + frag0))
    m.append(req(env(11, 600, seq=1) + frag1))
    # reproducer do_irp_frag_id16.pcap (B, C): sequence numbers beyond the
    # expected fragment count
    m.append(req(env(9, 600, seq=0x10000, flags=TC) + frag0))
    m.append(req(env(9, 600, seq=0x10001, flags=TC) + frag1))
    m.append(req(env(12, 600, seq=5, flags=TC) + frag1))
    m.append(req(env(12, 600, seq=0, flags=TC) + frag0))
    m.append(req(env(12, 600, seq=1, flags=TC) + frag1))
    # not DO-IRP: version 1, version 4, message length 0, short datagram
    m.append(req(env(13, 8, major=1) + bytes(8)))
    m.append(req(env(14, 8, major=4) + bytes(8)))
    m.append(req(env(15, 0)))
    m.append(req(b'\x02\x01\x00'))
    # truncated records: HS_SITE, HS_ADMIN, identifier record
    m.append(rsp(pdu(16, message(2, 1, SITE[:60]))))
    m.append(rsp(pdu(17, message(1, 1, s('10.1000/1') + u32(1) + all_records()[0][:30]))))
    # header cut short
    m.append(req(env(18, 10) + bytes(10)))
    # reproducer do_irp_misc.pcap / do_irp_tcp_len_wrap.pcap: TCP message
    # length 0xffffffec, which wrapped to 0 with the envelope added
    c = Tcp(40002, m)
    c.send(True, env(1, 0xffffffec) + inner)
    c.send(True, env(2, len(inner)) + inner)
    # TCP: error response whose body length says error indices follow but
    # the message ends
    c = Tcp(40003, m)
    c.send(False, pdu(19, message(1, 2, s('x'), cred=b'', bodylen=20)))
    # TCP: a segment that is not DO-IRP (version 1)
    c = Tcp(40004, m)
    c.send(True, env(20, 8, major=1) + bytes(8))
    pcap(os.path.join(out, 'do-irp-coverage-malformed.pcap'), m)


if __name__ == '__main__':
    main()
