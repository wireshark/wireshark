#!/usr/bin/env python3
# Generates test/captures/coap_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the CoAP dissector
(packet-coap.c).

CoAP (RFC 7252) runs over UDP port 5683 (and DTLS 5684), over TCP port
5683 with a length prefix (RFC 8323), and over WebSockets with the
subprotocol "coap". Every packet is built from scratch with struct; no
captured traffic is used. OSCORE (RFC 8613) messages are encrypted here
with AES-CCM-16-64-128 from the Python "cryptography" module, with the
security contexts written to cfg/oscore_contexts.

Usage: mkcoap.py <output directory>

Writes (pcapng, interface 0 Ethernet, interface 1 Exported PDU):
  coap-coverage.pcapng            every message type and option, the
                                  option delta and length extensions,
                                  request/response tracking and
                                  retransmissions, Block1/Block2/Q-Block
                                  reassembly, OSCORE requests and
                                  responses that decrypt, CoAP over TCP
                                  with every length size and split
                                  messages, CoAP over WebSockets, CoAP
                                  and CoAP-TMF in Exported PDUs, and the
                                  reproducers of the fixed bugs
  coap-coverage-malformed.pcapng  invalid options, bad lengths, broken
                                  OSCORE options, cut short messages
"""

import os
import struct
import sys

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers.aead import AESCCM

# ---------------------------------------------------------------- pcapng

T0 = 1700000000


class Pcapng:
    def __init__(self):
        self.blocks = []
        self.t = T0 * 1000000
        shb = struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1)
        self.blocks.append(self._block(0x0A0D0D0A, shb))
        for linktype in (1, 252):
            idb = struct.pack('<HHI', linktype, 0, 262144)
            self.blocks.append(self._block(1, idb))

    @staticmethod
    def _block(btype, body):
        body += b'\0' * (-len(body) % 4)
        n = 12 + len(body)
        return struct.pack('<II', btype, n) + body + struct.pack('<I', n)

    def add(self, data, ifc=0, dt=10000):
        self.t += dt
        epb = struct.pack('<IIIII', ifc, self.t >> 32, self.t & 0xffffffff,
                          len(data), len(data)) + data
        self.blocks.append(self._block(6, epb))

    def write(self, path):
        with open(path, 'wb') as f:
            f.write(b''.join(self.blocks))


# ----------------------------------------------------------- link layers

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ip4(a):
    return bytes(int(x) for x in a.split('.'))


def mac(a):
    b = ip4(a)
    return b'\x02\x00' + b


def ether_ip(src, dst, proto, l4):
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(l4), 1, 0, 64, proto,
                     0, ip4(src), ip4(dst))
    ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
    return mac(dst) + mac(src) + b'\x08\x00' + ip + l4


def udp(src, dst, sp, dp, payload):
    u = struct.pack('>HHHH', sp, dp, 8 + len(payload), 0) + payload
    ph = ip4(src) + ip4(dst) + struct.pack('>BBH', 0, 17, len(u))
    c = csum(ph + u) or 0xffff
    u = u[:6] + struct.pack('>H', c) + u[8:]
    return ether_ip(src, dst, 17, u)


class Tcp:
    """One TCP connection with a handshake and correct sequence numbers."""

    def __init__(self, cap, cli, srv, cport, sport):
        self.cap = cap
        self.ep = {0: (cli, cport), 1: (srv, sport)}
        self.seq = {0: 1000, 1: 5000}
        self._seg(0, 0x02, b'')
        self.seq[0] += 1
        self._seg(1, 0x12, b'')
        self.seq[1] += 1
        self._seg(0, 0x10, b'')

    def _seg(self, d, flags, payload, dt=10000):
        (src, sp), (dst, dp) = self.ep[d], self.ep[1 - d]
        ack = self.seq[1 - d] if flags != 0x02 else 0
        opt = b'\x02\x04\x05\xb4' if flags & 0x02 else b''
        t = struct.pack('>HHIIBBHHH', sp, dp, self.seq[d], ack,
                        (5 + len(opt) // 4) << 4, flags, 65535, 0, 0) + \
            opt + payload
        ph = ip4(src) + ip4(dst) + struct.pack('>BBH', 0, 6, len(t))
        t = t[:16] + struct.pack('>H', csum(ph + t)) + t[18:]
        self.cap.add(ether_ip(src, dst, 6, t), dt=dt)

    def send(self, d, payload, dt=10000):
        self._seg(d, 0x18, payload, dt)
        self.seq[d] += len(payload)

    def close(self):
        self._seg(0, 0x11, b'')
        self.seq[0] += 1
        self._seg(1, 0x11, b'')
        self.seq[1] += 1
        self._seg(0, 0x10, b'')


def tlv(t, v):
    return struct.pack('>HH', t, len(v)) + v


def epdu(name, payload, src='192.0.2.1', dst='192.0.2.2', pt=2,
         sp=40000, dp=5683):
    tags = tlv(12, name.encode())
    tags += tlv(20, ip4(src)) + tlv(21, ip4(dst))
    tags += tlv(24, struct.pack('>I', pt))
    tags += tlv(25, struct.pack('>I', sp)) + tlv(26, struct.pack('>I', dp))
    return tags + struct.pack('>HH', 0, 0) + payload


# ------------------------------------------------------------------ CoAP

CON, NON, ACK, RST = 0, 1, 2, 3


def code(c, dd):
    return (c << 5) | dd


GET, POST, PUT, DELETE, FETCH, PATCH, IPATCH = 1, 2, 3, 4, 5, 6, 7


def uint(v):
    if v == 0:
        return b''
    n = (v.bit_length() + 7) // 8
    return v.to_bytes(n, 'big')


def opt_nibble(v):
    if v < 13:
        return v, b''
    if v < 269:
        return 13, bytes([v - 13])
    return 14, struct.pack('>H', v - 269)


def options(opts, raw_tail=b''):
    """opts: list of (number, value bytes), sorted by number here."""
    out = b''
    last = 0
    for num, val in sorted(opts, key=lambda o: o[0]):
        dn, dext = opt_nibble(num - last)
        ln, lext = opt_nibble(len(val))
        out += bytes([(dn << 4) | ln]) + dext + lext + val
        last = num
    return out + raw_tail


def body(opts, payload):
    b = options(opts)
    if payload:
        b += b'\xff' + payload
    return b


def coap_udp(ttype, c, mid, token=b'', opts=(), payload=b''):
    return bytes([0x40 | (ttype << 4) | len(token), c]) + \
        struct.pack('>H', mid) + token + body(list(opts), payload)


def coap_tcp(c, token=b'', opts=(), payload=b'', force=None):
    """RFC 8323 TCP framing; force picks the Len nibble (13, 14, 15)."""
    rest = body(list(opts), payload)
    n = len(rest)
    if force is None:
        force = 0 if n < 13 else 13 if n < 269 else 14 if n < 65805 else 15
    if force < 13:
        hdr = bytes([(n << 4) | len(token)])
    elif force == 13:
        hdr = bytes([0xd0 | len(token), n - 13])
    elif force == 14:
        hdr = bytes([0xe0 | len(token)]) + struct.pack('>H', n - 269)
    else:
        hdr = bytes([0xf0 | len(token)]) + struct.pack('>I', n - 65805)
    return hdr + bytes([c]) + token + rest


def coap_ws(c, token=b'', opts=(), payload=b''):
    return bytes([len(token), c]) + token + body(list(opts), payload)


# Option numbers
IF_MATCH, URI_HOST, ETAG, IF_NONE_MATCH, OBSERVE, URI_PORT = 1, 3, 4, 5, 6, 7
LOCATION_PATH, OSCORE, URI_PATH, CONTENT_FORMAT, MAX_AGE = 8, 9, 11, 12, 14
URI_QUERY, HOP_LIMIT, ACCEPT, QBLOCK1, LOCATION_QUERY, EDHOC = 15, 16, 17, 19, 20, 21
BLOCK2, BLOCK1, SIZE2, QBLOCK2, PROXY_URI, PROXY_SCHEME = 23, 27, 28, 31, 35, 39
SIZE1, ECHO, NO_RESPONSE, REQUEST_TAG = 60, 252, 258, 292
OCF_ACCEPT, OCF_CONTENT = 2049, 2053


def s(x):
    return x.encode() if isinstance(x, str) else x


def path(*parts):
    return [(URI_PATH, s(p)) for p in parts]


def block(num, m, szx, length=None):
    v = (num << 4) | (m << 3) | szx
    if length is None:
        length = 0 if v == 0 else 1 if v < 0x100 else 2 if v < 0x10000 else 3
    return v.to_bytes(length, 'big') if length else b''


# ---------------------------------------------------------------- OSCORE

def cbor_head(major, n):
    if n < 24:
        return bytes([(major << 5) | n])
    if n < 0x100:
        return bytes([(major << 5) | 24, n])
    return bytes([(major << 5) | 25]) + struct.pack('>H', n)


def cbor_bstr(b):
    return cbor_head(2, len(b)) + b


def cbor_tstr(t):
    return cbor_head(3, len(t)) + t.encode()


def hkdf(salt, ikm, info, n):
    h = hmac.HMAC(salt if salt else b'\0' * 32, hashes.SHA256())
    h.update(ikm)
    prk = h.finalize()
    out, t, i = b'', b'', 1
    while len(out) < n:
        h = hmac.HMAC(prk, hashes.SHA256())
        h.update(t + info + bytes([i]))
        t = h.finalize()
        out += t
        i += 1
    return out[:n]


ALG = 10  # AES-CCM-16-64-128


class OscoreCtx:
    def __init__(self, sender, recipient, secret, salt=b'', idctx=b''):
        self.sender, self.recipient = sender, recipient
        self.idctx = idctx
        self.secret, self.salt = secret, salt

        def info(ident, label, n):
            return (cbor_head(4, 5) + cbor_bstr(ident) +
                    (cbor_bstr(idctx) if idctx else b'\xf6') +
                    cbor_head(0, ALG) + cbor_tstr(label) + cbor_head(0, n))
        self.req_key = hkdf(salt, secret, info(sender, 'Key', 16), 16)
        self.rsp_key = hkdf(salt, secret, info(recipient, 'Key', 16), 16)
        self.iv = hkdf(salt, secret, info(b'', 'IV', 13), 13)

    def uat(self):
        return '"%s","%s","%s","%s","%s","AES-CCM-16-64-128 (CCM*)"' % (
            self.sender.hex(), self.recipient.hex(), self.secret.hex(),
            self.salt.hex(), self.idctx.hex())

    def nonce(self, ident, piv):
        p = bytearray(13)
        p[13 - len(piv):] = piv
        p[13 - 5 - len(ident):13 - 5] = ident
        p[0] = len(ident)
        return bytes(a ^ b for a, b in zip(p, self.iv))

    def seal(self, plaintext, request_piv, response=False, piv=None):
        kid = self.sender
        ext = (cbor_head(4, 5) + cbor_head(0, 1) + cbor_head(4, 1) +
               cbor_head(0, ALG) + cbor_bstr(kid) + cbor_bstr(request_piv) +
               cbor_bstr(b''))
        aad = cbor_head(4, 3) + cbor_tstr('Encrypt0') + cbor_bstr(b'') + \
            cbor_bstr(ext)
        if response and piv:
            nonce = self.nonce(self.recipient, piv)
        else:
            nonce = self.nonce(self.sender, request_piv)
        key = self.rsp_key if response else self.req_key
        return AESCCM(key, tag_length=8).encrypt(nonce, plaintext, aad)


def oscore_opt(piv=b'', kid=None, kidctx=None, reserved=0):
    flag = len(piv) | (0x08 if kid is not None else 0) | \
        (0x10 if kidctx is not None else 0) | reserved
    v = bytes([flag]) + piv
    if kidctx is not None:
        v += bytes([len(kidctx)]) + kidctx
    if kid is not None:
        v += kid
    return v


def inner(c, opts=(), payload=b''):
    return bytes([c]) + body(list(opts), payload)


CTX_A = OscoreCtx(b'\x01', b'\x02', bytes(range(1, 17)))
CTX_B = OscoreCtx(b'\x0a', b'\x0b', bytes(range(0x10, 0x20)),
                  salt=bytes.fromhex('9e7ca92223786340'),
                  idctx=bytes.fromhex('37cbf3210017a2d3'))


# --------------------------------------------------------------- captures

CLI, SRV = '192.0.2.1', '192.0.2.2'
CLI6 = '192.0.2.3'


def main_capture(out):
    cap = Pcapng()
    frames = {}

    def u(payload, to_srv=True, cp=40001, sp=5683, cli=CLI, dt=10000):
        if to_srv:
            cap.add(udp(cli, SRV, cp, sp, payload), dt=dt)
        else:
            cap.add(udp(SRV, cli, sp, cp, payload), dt=dt)
        return len(cap.blocks) - 3

    # -- 1-3: GET with many request options, piggybacked response, resend
    req = coap_udp(CON, GET, 0x1001, b'\x01\x02\x03\x04', [
        (URI_HOST, b'sensor.example'), (URI_PORT, uint(5683)),
        *path('sensors', 'temp'), (URI_QUERY, b'unit=c'),
        (URI_QUERY, b'fmt=1'), (ACCEPT, uint(50)), (ETAG, b'\x11\x22'),
        (ETAG, b'\x33\x44\x55\x66\x77\x88\x99\xaa'), (HOP_LIMIT, b'\x10'),
    ])
    frames['get'] = u(req)
    u(coap_udp(ACK, code(2, 5), 0x1001, b'\x01\x02\x03\x04', [
        (ETAG, b'\x11\x22'), (CONTENT_FORMAT, uint(50)),
        (MAX_AGE, uint(60))], b'{"temp": 21}'), to_srv=False)
    u(req)                               # retransmitted request
    # -- 4-7: separate response: empty ACK, CON response, its resend, ACK
    u(coap_udp(CON, GET, 0x1002, b'\xa1', [*path('slow')]))
    u(coap_udp(ACK, 0, 0x1002), to_srv=False)
    rsp = coap_udp(CON, code(2, 5), 0x7001, b'\xa1',
                   [(CONTENT_FORMAT, b'')], b'slow answer')
    u(rsp, to_srv=False)
    u(rsp, to_srv=False)                 # retransmitted response
    u(coap_udp(ACK, 0, 0x7001))
    # -- 9-10: request without a token (MID as key), NON response
    u(coap_udp(NON, PUT, 0x1003, b'', [
        *path('cfg'), (IF_MATCH, b''), (IF_MATCH, b'\x01\x02\x03'),
        (CONTENT_FORMAT, uint(0)), (SIZE1, uint(4)),
        (NO_RESPONSE, uint(0x1a))], b'on=1'))
    u(coap_udp(NON, code(2, 4), 0x1003, b'', [
        (LOCATION_PATH, b'cfg'), (LOCATION_PATH, b''),
        (LOCATION_QUERY, b'v=2'), (LOCATION_QUERY, b'')]), to_srv=False)
    # -- 11-12: POST with If-None-Match, 2.01 Created and Location
    u(coap_udp(CON, POST, 0x1004, b'\xb1\xb2', [
        *path('things'), (IF_NONE_MATCH, b''), (CONTENT_FORMAT, uint(60)),
        (ECHO, b'\x0e\xc0'), (REQUEST_TAG, b''), (REQUEST_TAG, b'\x7a')],
        bytes.fromhex('a2616101616202')))
    u(coap_udp(ACK, code(2, 1), 0x1004, b'\xb1\xb2', [
        (LOCATION_PATH, b'things'), (LOCATION_PATH, b'7')]), to_srv=False)
    # -- 13-14: IPv6 literal Uri-Host, empty Uri-Path, Uri-Port 0 length
    u(coap_udp(CON, DELETE, 0x1005, b'\xc1', [
        (URI_HOST, b'2001:db8::1'), (URI_PORT, b''), (URI_PATH, b''),
        (ACCEPT, b'')]), cli=CLI6, cp=40002)
    u(coap_udp(ACK, code(2, 2), 0x1005, b'\xc1'), to_srv=False, cli=CLI6,
      cp=40002)
    # -- 15-17: proxy request with long Proxy-Uri (2 octet length), errors
    long_uri = ('coap://upstream.example/' + 'p' * 280).encode()
    u(coap_udp(CON, FETCH, 0x1006, b'\xd1', [
        (PROXY_URI, long_uri), (PROXY_SCHEME, b'coap'),
        (CONTENT_FORMAT, uint(40))]))
    u(coap_udp(ACK, code(4, 4), 0x1006, b'\xd1', [], b'not found'),
      to_srv=False)
    u(coap_udp(CON, PATCH, 0x1007, b'\xd2', [
        (PROXY_URI, ('coap://h/' + 'q' * 20).encode()),
        (CONTENT_FORMAT, uint(65000))], b'patch'))
    u(coap_udp(ACK, code(5, 3), 0x1007, b'\xd2', [(MAX_AGE, uint(0x01020304))],
               b'busy'), to_srv=False)
    # -- 19-20: iPATCH, response 2.03 Valid with an unknown content format
    u(coap_udp(CON, IPATCH, 0x1008, b'\xd3', [*path('x'),
               (CONTENT_FORMAT, uint(10000))], b'\xa0'))
    u(coap_udp(ACK, code(2, 3), 0x1008, b'\xd3', [], b'\x00\x01'),
      to_srv=False)
    # -- 21-24: Observe register, notifications with Observe, deregister
    u(coap_udp(CON, GET, 0x1009, b'\x0b\x5e', [
        (OBSERVE, b''), *path('obs'), (ACCEPT, uint(0))]))
    u(coap_udp(ACK, code(2, 5), 0x1009, b'\x0b\x5e', [
        (OBSERVE, uint(12)), (CONTENT_FORMAT, b'')], b'22 C'), to_srv=False)
    u(coap_udp(NON, code(2, 5), 0x7002, b'\x0b\x5e', [
        (OBSERVE, uint(0x10203)), (CONTENT_FORMAT, b'')], b'23 C'),
      to_srv=False)
    u(coap_udp(CON, GET, 0x100a, b'\x0b\x5e', [
        (OBSERVE, uint(1)), *path('obs')]))
    # -- 25-26: OCF version options (delta > 269), unknown vendor option,
    #    Size2, EDHOC, extended deltas
    u(coap_udp(CON, GET, 0x100b, b'\xe1', [
        *path('oic', 'res'), (EDHOC, b''), (SIZE2, b''),
        (OCF_ACCEPT, struct.pack('>H', 0x0800))]))
    u(coap_udp(ACK, code(2, 5), 0x100b, b'\xe1', [
        (CONTENT_FORMAT, uint(10000)), (SIZE2, uint(1000)),
        (OCF_CONTENT, struct.pack('>H', (2 << 11) | (1 << 6) | 3)),
        (2060, b'\xbe\xef')], b'\xa0'), to_srv=False)
    # -- 27: RST, 28: empty CON (ping), 29: unknown code 0.31
    u(coap_udp(RST, 0, 0x7002))
    u(coap_udp(CON, 0, 0x100c))
    u(coap_udp(NON, code(0, 31), 0x100d, b'\x01'))
    # -- 30-35: Block2 download in three blocks, reassembled
    blk = [(b'block-two-' * 7)[:64], (b'block-two-' * 7)[:64], b'last part']
    for i, data in enumerate(blk):
        u(coap_udp(CON, GET, 0x1010 + i, b'\xf2', [
            *path('big'), (BLOCK2, block(i, 0, 2))]))
        u(coap_udp(ACK, code(2, 5), 0x1010 + i, b'\xf2', [
            (CONTENT_FORMAT, b''), (SIZE2, uint(137)) if i == 0 else
            (MAX_AGE, uint(30)), (BLOCK2, block(i, int(i < 2), 2))], data),
          to_srv=False)
    # -- 36-39: Block1 upload with 2.31 Continue, 2 octet block option
    up = [b'A' * 32, b'B' * 32, b'C' * 5]
    for i, data in enumerate(up):
        u(coap_udp(CON, PUT, 0x1020 + i, b'\xf3', [
            *path('fw'), (CONTENT_FORMAT, uint(42)), (SIZE1, uint(69)),
            (BLOCK1, block(i, int(i < 2), 1, length=2))], data))
        u(coap_udp(ACK, code(2, 31) if i < 2 else code(2, 4), 0x1020 + i,
                   b'\xf3', [(BLOCK1, block(i, int(i < 2), 1))]),
          to_srv=False)
    # -- Q-Block2 and Q-Block1 (RFC 9177), Block option of length 3
    u(coap_udp(NON, GET, 0x1030, b'\xf4', [*path('q'), (QBLOCK2, b'')]))
    u(coap_udp(NON, code(2, 5), 0x7010, b'\xf4', [
        (QBLOCK2, block(0, 1, 0, 3))], b'0123456789abcdef'), to_srv=False)
    u(coap_udp(NON, code(2, 5), 0x7011, b'\xf4', [
        (QBLOCK2, block(1, 0, 0))], b'tail'), to_srv=False)
    u(coap_udp(NON, POST, 0x1031, b'\xf5', [*path('q'),
               (QBLOCK1, block(0, 1, 0))], b'fedcba9876543210'))
    u(coap_udp(NON, POST, 0x1032, b'\xf5', [*path('q'),
               (QBLOCK1, block(1, 0, 0))], b'end'))
    u(coap_udp(NON, code(2, 4), 0x7012, b'\xf5', [(QBLOCK1, block(1, 0, 0))]),
      to_srv=False)

    # -- payload dissectors: link-format, CoAP-EAP, URI-Path table (SGP.32)
    u(coap_udp(CON, GET, 0x1040, b'\x41', [*path('.well-known', 'core')]))
    u(coap_udp(ACK, code(2, 5), 0x1040, b'\x41', [(CONTENT_FORMAT, uint(40))],
               b'</sensors/temp>;rt="temperature";if="sensor",</obs>;obs'),
      to_srv=False)
    u(coap_udp(CON, POST, 0x1041, b'\x42', [*path('a', 'ae'),
               (CONTENT_FORMAT, uint(269))], bytes([2, 7, 0, 5, 1])))
    u(coap_udp(CON, POST, 0x1042, b'\x43', [*path('gsma', 'rsp2', 'asn1')],
               bytes.fromhex('bf3800')))

    # -- OSCORE with CTX_A: request (PIV 0x05, kid 01), response without
    #    a Partial IV, then a request PIV 0x0006 and a response with PIV
    p_in = inner(GET, [*path('oscore', 'hello'), (URI_QUERY, b'first=1')])
    ct = CTX_A.seal(p_in, b'\x05')
    frames['oscore_req'] = u(coap_udp(CON, POST, 0x1050, b'\x7c', [
        (URI_HOST, b'secure.example'), (OSCORE, oscore_opt(b'\x05', b'\x01'))],
        ct), cp=40010)
    p_out = inner(code(2, 5), [(CONTENT_FORMAT, b''), (MAX_AGE, uint(10))],
                  b'Hello World!')
    ct = CTX_A.seal(p_out, b'\x05', response=True)
    u(coap_udp(ACK, code(2, 4), 0x1050, b'\x7c', [(OSCORE, b'')], ct),
      to_srv=False, cp=40010)
    p_in = inner(GET, [(OBSERVE, b''), *path('oscore', 'observe')])
    ct = CTX_A.seal(p_in, b'\x00\x06')
    u(coap_udp(CON, FETCH, 0x1051, b'\x7d', [
        (OBSERVE, b''), (OSCORE, oscore_opt(b'\x00\x06', b'\x01'))], ct),
      cp=40010)
    p_out = inner(code(2, 5), [(OBSERVE, uint(7)),
                               (CONTENT_FORMAT, uint(60))], b'\x18\x2a')
    ct = CTX_A.seal(p_out, b'\x00\x06', response=True, piv=b'\x01')
    u(coap_udp(ACK, code(2, 5), 0x1051, b'\x7d', [
        (OBSERVE, uint(7)), (OSCORE, oscore_opt(b'\x01'))], ct),
      to_srv=False, cp=40010)
    # -- OSCORE with CTX_B: kid context in the request, block-wise inner
    p_in = inner(PUT, [*path('oscore', 'ctx'), (CONTENT_FORMAT, uint(0))],
                 b'with kid context')
    ct = CTX_B.seal(p_in, b'\x14')
    u(coap_udp(CON, POST, 0x1052, b'\x7e', [
        (OSCORE, oscore_opt(b'\x14', b'\x0a',
                            bytes.fromhex('37cbf3210017a2d3')))], ct),
      cp=40011)
    p_out = inner(code(2, 4), [], b'')
    ct = CTX_B.seal(p_out, b'\x14', response=True)
    u(coap_udp(ACK, code(2, 4), 0x1052, b'\x7e', [(OSCORE, b'')], ct),
      to_srv=False, cp=40011)

    # -- reproducer of the OSCORE fix (coap_oscore_request_piv_len.py,
    #    its third frame is in the malformed capture)
    tok = b'\x11'
    opt = bytes([0x0f | 0x08]) + bytes(range(1, 8)) + b'\x01'
    frames['repro_piv'] = u(bytes([0x41, 0x02, 0x12, 0x34]) + tok +
                            bytes([0x90 | len(opt)]) + opt + b'\xff' +
                            bytes(16), cp=40020)
    u(bytes([0x61, 0x44, 0x12, 0x34]) + tok + bytes([0x90]) + b'\xff' +
      bytes(16), to_srv=False, cp=40020)

    # -- CoAP over TCP (RFC 8323)
    t = Tcp(cap, CLI, SRV, 50001, 5683)
    frames['tcp_first'] = len(cap.blocks) - 2
    t.send(0, coap_tcp(code(7, 1)))                         # CSM
    t.send(1, coap_tcp(code(7, 1)))
    t.send(0, coap_tcp(GET, b'\x21', [*path('tcp', 'res'),
                                      (ACCEPT, uint(0))]))
    t.send(1, coap_tcp(code(2, 5), b'\x21', [(CONTENT_FORMAT, b'')],
                       b'x' * 20, force=13))
    # Length 14 (2 octets), and two messages in one segment
    t.send(0, coap_tcp(POST, b'\x22\x23', [*path('tcp', 'up'),
                                           (CONTENT_FORMAT, b'')],
                       b'y' * 300) +
           coap_tcp(code(7, 2), b'\x24'))                   # + Ping
    t.send(1, coap_tcp(code(2, 4), b'\x22\x23') +
           coap_tcp(code(7, 3), b'\x24'))                   # + Pong
    # A message split over three segments, the first only the Len octet
    m = coap_tcp(PUT, b'\x25', [*path('tcp', 'split')], b'z' * 40)
    t.send(0, m[:1])
    t.send(0, m[1:10])
    t.send(0, m[10:])
    t.send(1, coap_tcp(code(2, 4), b'\x25'))
    # Length 15 (4 octets): a 66000 octet text payload in 4 segments
    big = coap_tcp(code(2, 5), b'\x26', [(CONTENT_FORMAT, b'')],
                   (b'0123456789abcdef' * 4200)[:66000])
    t.send(0, coap_tcp(GET, b'\x26', [*path('tcp', 'big')]))
    step = (len(big) + 3) // 4
    for i in range(0, len(big), step):
        t.send(1, big[i:i + step], dt=100)
    # Block2 over TCP (BERT-sized block numbers)
    t.send(0, coap_tcp(GET, b'\x27', [*path('tcp', 'blk'),
                                      (BLOCK2, block(0, 0, 6))]))
    t.send(1, coap_tcp(code(2, 5), b'\x27', [(BLOCK2, block(0, 1, 6))],
                       b'k' * 1024))
    t.send(0, coap_tcp(GET, b'\x27', [*path('tcp', 'blk'),
                                      (BLOCK2, block(1, 0, 6))]))
    t.send(1, coap_tcp(code(2, 5), b'\x27', [(BLOCK2, block(1, 0, 6))],
                       b'end of blk'))
    t.send(0, coap_tcp(code(7, 4), b'', [], b''))           # Release
    t.send(1, coap_tcp(code(7, 5), b'', [], b'bye'))        # Abort
    t.close()

    # -- CoAP over WebSockets on port 80
    w = Tcp(cap, CLI, SRV, 50002, 80)
    w.send(0, b'GET /.well-known/coap HTTP/1.1\r\nHost: ' + SRV.encode() +
           b'\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n'
           b'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n'
           b'Sec-WebSocket-Protocol: coap\r\n'
           b'Sec-WebSocket-Version: 13\r\n\r\n')
    w.send(1, b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n'
           b'Connection: Upgrade\r\n'
           b'Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n'
           b'Sec-WebSocket-Protocol: coap\r\n\r\n')

    def wsframe(payload, masked):
        hdr = bytes([0x82])
        if masked:
            key = b'\x37\xfa\x21\x3d'
            data = bytes(b ^ key[i % 4] for i, b in enumerate(payload))
            return hdr + bytes([0x80 | len(payload)]) + key + data
        return hdr + bytes([len(payload)]) + payload

    frames['ws_first'] = len(cap.blocks) - 2
    w.send(0, wsframe(coap_ws(code(7, 1)), True))
    w.send(0, wsframe(coap_ws(GET, b'\x31\x32', [*path('ws', 'res')]), True))
    w.send(1, wsframe(coap_ws(code(2, 5), b'\x31\x32',
                              [(CONTENT_FORMAT, b'')], b'over websockets'),
                      False))
    w.close()

    # -- Exported PDUs (interface 1): the reproducer of the TCP
    #    conversation fix, and CoAP for Thread Management Framework
    frames['epdu_first'] = len(cap.blocks) - 2
    cap.add(epdu('coap', bytes([0x40, 0x01, 0x00, 0x01, 0xb1, ord('a')])),
            ifc=1)
    cap.add(epdu('coap_tcp_tls', bytes([0x20, 0x01, 0xb1, ord('a')])), ifc=1)
    # Thread address query (a/aq) with a Target EID TLV
    tmf = coap_udp(CON, POST, 0x2001, b'\x51\x52', [*path('a', 'aq')],
                   bytes([0, 16]) + bytes.fromhex('fd000db8000000000000ff00fe001234'))
    cap.add(epdu('coap_for_tmf', tmf, src='192.0.2.5', dst='192.0.2.6', pt=3,
                 sp=61631, dp=61631), ifc=1)
    cap.add(epdu('coap_for_tmf', coap_udp(ACK, code(2, 4), 0x2001,
                                          b'\x51\x52'),
                 src='192.0.2.6', dst='192.0.2.5', pt=3, sp=61631,
                 dp=61631), ifc=1)
    cap.write(out)
    return frames


def malformed_capture(out):
    cap = Pcapng()

    def u(payload, cp=41000, to_srv=True):
        if to_srv:
            cap.add(udp(CLI, SRV, cp, 5683, payload))
        else:
            cap.add(udp(SRV, CLI, 5683, cp, payload))

    # invalid option numbers (No-Op name, below 2048), bad ranges
    u(coap_udp(CON, GET, 1, b'', [(42, b'\x01'), (2, b'')]))
    u(coap_udp(CON, GET, 2, b'', [(URI_HOST, b''), (ETAG, b''),
                                  (IF_NONE_MATCH, b'x'), (URI_QUERY, b''),
                                  (HOP_LIMIT, b''), (ECHO, b''),
                                  (OCF_ACCEPT, b'\x01')]))
    # Content-Format and Max-Age longer than 4 octets
    u(coap_udp(CON, GET, 3, b'', [(CONTENT_FORMAT, b'\x01\x02\x03\x04\x05')],
               b'p'))
    u(coap_udp(CON, GET, 4, b'', [(MAX_AGE, b'\x01\x02\x03\x04\x05')]))
    # zero length Proxy-Uri, Proxy-Scheme and OCF version options
    u(coap_udp(CON, GET, 30, b'', [(PROXY_URI, b''), (PROXY_SCHEME, b''),
                                   (OCF_ACCEPT, b''), (OCF_CONTENT, b'')]))
    # Block option 5 octets long
    u(coap_udp(CON, GET, 5, b'', [(BLOCK2, b'\x00\x00\x00\x01\x02')], b'q'))
    # option delta 15 without the payload marker, length 15
    u(coap_udp(CON, GET, 6, b'\x01') + b'\xf1\x00')
    u(coap_udp(CON, GET, 7, b'\x01') + b'\x1f\x00')
    # option longer than the message, and cut-short extensions
    u(coap_udp(CON, GET, 8, b'') + b'\xb5ab')
    u(coap_udp(CON, GET, 9, b'') + b'\xd1')
    u(coap_udp(CON, GET, 10, b'') + b'\xe1\x00')
    u(coap_udp(CON, GET, 11, b'') + b'\x1d')
    u(coap_udp(CON, GET, 12, b'') + b'\x1e\x00')
    # header and token cut short
    u(b'\x48\x01\x00')
    u(b'\x48\x01\x00\x0d\x01\x02')
    # OSCORE: reserved bit, kid context length missing, kid context too
    # long, partial IV without a security context, no Partial IV at all
    u(coap_udp(CON, POST, 20, b'\x91', [(OSCORE, bytes([0x20 | 0x09, 5, 1]))],
               bytes(12)), cp=41001)
    u(coap_udp(CON, POST, 21, b'\x92', [(OSCORE, bytes([0x11, 5]))],
               bytes(12)), cp=41001)
    u(coap_udp(CON, POST, 22, b'\x93', [(OSCORE, bytes([0x11, 5, 9, 1]))],
               bytes(12)), cp=41001)
    u(coap_udp(CON, POST, 23, b'\x94', [(OSCORE, oscore_opt(b'\x01', b'\x77'))],
               bytes(12)), cp=41001)
    u(coap_udp(CON, POST, 24, b'\x95', [(OSCORE, oscore_opt(b'', b'\x01'))],
               bytes(12)), cp=41001)
    # OSCORE with a bad tag, a too short payload, a truncated tag
    u(coap_udp(CON, POST, 25, b'\x96', [(OSCORE, oscore_opt(b'\x09', b'\x01'))],
               bytes(12)), cp=41001)
    u(coap_udp(CON, POST, 26, b'\x97', [(OSCORE, oscore_opt(b'\x0a', b'\x01'))],
               bytes(8)), cp=41001)
    # The response to frame 26 with an empty OSCORE option
    u(coap_udp(ACK, code(2, 4), 26, b'\x97', [(OSCORE, b'')], bytes(10)),
      cp=41001, to_srv=False)
    # The third frame of coap_oscore_request_piv_len.py: a one octet
    # OSCORE option that claims a 7 octet Partial IV and a Key ID
    u(bytes([0x41, 0x02, 0x12, 0x35]) + b'\x22' + bytes([0x91, 0x0f]) +
      b'\xff' + bytes(i & 0xff for i in range(0x20, 0x20 + 255)), cp=40020)
    # TCP: extended lengths cut short (one connection each, the rest of
    # the connection waits for the missing octets)
    for i, seg in enumerate((b'\xd1', b'\xe0\x00', b'\xf0\x00\x00')):
        t = Tcp(cap, CLI, SRV, 51001 + i, 5683)
        t.send(0, seg)
    # TCP: a message that claims more than the rest of the capture
    t = Tcp(cap, CLI, SRV, 51004, 5683)
    t.send(0, b'\xd0\xff\x01abc')
    # Exported PDU reproducers of the original assertion as a malformed
    # TCP-typed message with bad options
    cap.add(epdu('coap_tcp_tls', bytes([0x30, 0x01, 0xf1, 0x00, 0x00])),
            ifc=1)
    cap.write(out)


def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else '.'
    frames = main_capture(os.path.join(outdir, 'coap-coverage.pcapng'))
    malformed_capture(os.path.join(outdir, 'coap-coverage-malformed.pcapng'))
    # The OSCORE security contexts, as a UAT file for a profile directory.
    os.makedirs(os.path.join(outdir, 'cfg'), exist_ok=True)
    with open(os.path.join(outdir, 'cfg', 'oscore_contexts'), 'w') as f:
        f.write(CTX_A.uat() + '\n' + CTX_B.uat() + '\n')
    for k, v in sorted(frames.items(), key=lambda x: x[1]):
        print(k, v)


if __name__ == '__main__':
    main()
