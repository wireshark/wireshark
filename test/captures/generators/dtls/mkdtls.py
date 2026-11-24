#!/usr/bin/env python3
# Generates test/captures/dtls_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the DTLS dissector
(packet-dtls.c): the record layer, the handshake messages and their
fragment reassembly, alerts, heartbeats, ACKs, Connection ID records
and DTLS 1.3 unified headers.

There is no cryptography here: no keys are computed and nothing is
encrypted. Records that would be encrypted (Finished, application data,
encrypted alerts and heartbeats, DTLS 1.3 unified header records) hold
random filler octets, and the key exchange values, signatures and
tickets are filler too. Every packet is built from scratch with struct;
no captured traffic is used.

DTLS is found by the "dtls_udp" heuristic (enabled by default), on UDP
port 5684 (CoAP over DTLS, registered by default) and on SCTP PPI 47
(Diameter over DTLS).

Usage: mkdtls.py <output directory>

Writes:
  dtls-coverage.pcap            DTLS 1.0, 1.2 and 1.3 handshakes, CID
                                records, unified headers, reassembly,
                                heartbeats (the reproducer of the fix)
  dtls-coverage-malformed.pcap  fragments that disagree, bad lengths
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













SRCDIR = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..', '..'))

import random
import struct

from pktlib import eth, ip4, mac, udp, udp_frame, csum

rnd = random.Random(1)


def pcap(path, frames):
    """frames: bytes, or (bytes, original length) for a frame cut short
    by the snapshot length."""
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, fr in enumerate(frames):
            fr, orig = fr if isinstance(fr, tuple) else (fr, len(fr))
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, len(fr), orig))
            f.write(fr)


def ip_fragments(src, dst, proto, payload, mtu_payload=1480, ident=0x4242):
    """IPv4 fragments of one datagram."""
    out = []
    off = 0
    while off < len(payload):
        part = payload[off:off + mtu_payload]
        more = off + len(part) < len(payload)
        hdr = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(part), ident,
                          (0x2000 if more else 0) | (off // 8), 64, proto, 0, bytes(src), bytes(dst))
        hdr = hdr[:10] + struct.pack('!H', csum(hdr)) + hdr[12:]
        out.append(eth(mac(2), mac(1), 0x0800, hdr + part))
        off += len(part)
    return out


def filler(n):
    return bytes(rnd.randrange(256) for _ in range(n))


DTLS10 = 0xfeff
DTLS12 = 0xfefd
DTLS13 = 0xfefc

HRR_RANDOM = bytes.fromhex('cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c')


def record(ctype, body, epoch=0, seq=0, version=DTLS12, cid=b''):
    return struct.pack('!BHH', ctype, version, epoch) + seq.to_bytes(6, 'big') + cid + \
        struct.pack('!H', len(body)) + body


def hs(mtype, body, mseq, foff=0, flen=None, total=None):
    total = len(body) if total is None else total
    frag = body[foff:foff + flen] if flen is not None else body[foff:]
    return struct.pack('!B', mtype) + total.to_bytes(3, 'big') + struct.pack('!H', mseq) + \
        foff.to_bytes(3, 'big') + len(frag).to_bytes(3, 'big') + frag


def ext(t, data):
    return struct.pack('!HH', t, len(data)) + data


def exts(*e):
    b = b''.join(e)
    return struct.pack('!H', len(b)) + b


def v8(b):
    return bytes([len(b)]) + b


def v16(b):
    return struct.pack('!H', len(b)) + b


def v24(b):
    return len(b).to_bytes(3, 'big') + b


def use_srtp(profiles, mki=b''):
    return ext(14, v16(b''.join(struct.pack('!H', p) for p in profiles)) + v8(mki))


def client_hello(version, cookie=b'', suites=(0xc02b, 0xc02f, 0x00ff), extensions=b'', sid=b''):
    return struct.pack('!H', version) + filler(32) + v8(sid) + v8(cookie) + \
        v16(b''.join(struct.pack('!H', s) for s in suites)) + v8(b'\x00') + extensions


def server_hello(version, suite, extensions=b'', random32=None, sid=b''):
    return struct.pack('!H', version) + (random32 or filler(32)) + v8(sid) + \
        struct.pack('!HB', suite, 0) + extensions


COMMON_EXTS = [
    ext(0, v16(b'\x00' + v16(b'dtls.example'))),          # server_name
    ext(10, v16(struct.pack('!HHH', 23, 24, 29))),        # supported_groups
    ext(11, v8(b'\x00')),                                 # ec_point_formats
    ext(13, v16(struct.pack('!HHH', 0x0403, 0x0804, 0x0401))),  # signature_algorithms
    ext(23, b''),                                         # extended_master_secret
    ext(35, b''),                                         # session_ticket
    ext(15, b'\x01'),                                     # heartbeat
    ext(0xff01, b'\x00'),                                 # renegotiation_info
]


class Flow:
    """A UDP flow between a client and a server. dgram() numbers the
    plaintext records of a datagram per direction and epoch."""

    def __init__(self, cport, sport, a=(10, 0, 0, 1), b=(10, 0, 0, 2), cid_len=None):
        self.cport, self.sport, self.a, self.b = cport, sport, a, b
        self.cid_len = cid_len or {}
        self.seq = {}

    def rec(self, ctype, body, srv=False, epoch=0, version=DTLS12, cid=b''):
        # the sequence number is filled in by dgram()
        return record(ctype, body, epoch, 0, version, cid)

    def number(self, data, srv):
        d = 1 if srv else 0
        out = b''
        off = 0
        while off + 13 <= len(data) and 20 <= data[off] <= 26:
            epoch = struct.unpack('!H', data[off + 3:off + 5])[0]
            cl = self.cid_len.get(d, 0) if data[off] == 25 else 0
            ln = struct.unpack('!H', data[off + 11 + cl:off + 13 + cl])[0]
            end = off + 13 + cl + ln
            s = self.seq.get((d, epoch), 0)
            self.seq[(d, epoch)] = s + 1
            out += data[off:off + 5] + s.to_bytes(6, 'big') + data[off + 11:end]
            off = end
        return out + data[off:]

    def dgram(self, data, srv=False):
        data = self.number(data, srv)
        if srv:
            return udp_frame(self.sport, self.cport, data, self.a, self.b, rev=True)
        return udp_frame(self.cport, self.sport, data, self.a, self.b)


def dtls12_session(f):
    """A full DTLS 1.2 handshake with a cookie exchange, use_srtp,
    client authentication, fragmentation and retransmissions."""
    c = Flow(41700, 50100)
    srtp_c = use_srtp((0x0001, 0x0002, 0x0005, 0x0006, 0x0007, 0x0008, 0x0099), b'\x01\x02')
    # 1: ClientHello without a cookie
    ch1 = client_hello(DTLS12, extensions=exts(*COMMON_EXTS, srtp_c))
    f.append(c.dgram(c.rec(22, hs(1, ch1, 0))))
    # 2: HelloVerifyRequest with a cookie
    cookie = filler(20)
    f.append(c.dgram(c.rec(22, hs(3, struct.pack('!H', DTLS10) + v8(cookie), 0)), True))
    # 3: ClientHello with the cookie
    ch2 = client_hello(DTLS12, cookie=cookie, extensions=exts(*COMMON_EXTS, srtp_c))
    f.append(c.dgram(c.rec(22, hs(1, ch2, 1))))
    # 4: ServerHello and Certificate (empty list) in one record
    sh = server_hello(DTLS12, 0xc02b, exts(use_srtp((0x0001,)), ext(23, b''),
                                           ext(0xff01, b'\x00'), ext(11, v8(b'\x00')), ext(35, b''),
                                           ext(15, b'\x01')))
    cert = v24(b'')
    f.append(c.dgram(c.rec(22, hs(2, sh, 1) + hs(11, cert, 2)), True))
    # 5-8: ServerKeyExchange (ECDHE, filler key and signature) in three
    # fragments: the first, a retransmission of it, an overlapping
    # middle part, and the last, which completes it
    ske = struct.pack('!BH', 3, 23) + v8(b'\x04' + filler(64)) + struct.pack('!H', 0x0403) + v16(filler(71))
    f.append(c.dgram(c.rec(22, hs(12, ske, 3, 0, 60)), True))
    f.append(c.dgram(c.rec(22, hs(12, ske, 3, 0, 60)), True))
    f.append(c.dgram(c.rec(22, hs(12, ske, 3, 40, 60)), True))
    f.append(c.dgram(c.rec(22, hs(12, ske, 3, 100)), True))
    # 9: CertificateRequest and ServerHelloDone
    creq = v8(b'\x40\x01') + v16(struct.pack('!HH', 0x0403, 0x0804)) + v16(b'')
    f.append(c.dgram(c.rec(22, hs(13, creq, 4) + hs(14, b'', 5)), True))
    # 10: Certificate (empty), ClientKeyExchange (filler point),
    # CertificateVerify (filler signature), ChangeCipherSpec and an
    # encrypted Finished (filler), all in one datagram
    cke = v8(b'\x04' + filler(64))
    cv = struct.pack('!H', 0x0403) + v16(filler(70))
    f.append(c.dgram(c.rec(22, hs(11, cert, 2)) + c.rec(22, hs(16, cke, 3)) +
                     c.rec(22, hs(15, cv, 4)) + c.rec(20, b'\x01') +
                     c.rec(22, filler(40), epoch=1)))
    # 11: NewSessionTicket, ChangeCipherSpec, encrypted Finished
    nst = struct.pack('!I', 7200) + v16(filler(64))
    f.append(c.dgram(c.rec(22, hs(4, nst, 6)) + c.rec(20, b'\x01') +
                     c.rec(22, filler(40), True, epoch=1), True))
    # 12: a retransmitted ClientKeyExchange (older message sequence)
    f.append(c.dgram(c.rec(22, hs(16, cke, 3))))
    # 13-14: application data both ways (filler)
    f.append(c.dgram(c.rec(23, filler(48), epoch=1)))
    f.append(c.dgram(c.rec(23, filler(64), True, epoch=1), True))
    # 15-16: heartbeat request and response with 16 octets of padding
    f.append(c.dgram(c.rec(24, b'\x01' + v16(b'ping') + filler(16))))
    f.append(c.dgram(c.rec(24, b'\x02' + v16(b'ping') + filler(16)), True))
    # 17-18: the reproducer of the fix (dtls_heartbeat_short.py):
    # heartbeats of 3 and 10 octets, shorter than the minimum padding
    f.append(c.dgram(c.rec(24, b'\x01\x00\x00')))
    f.append(c.dgram(c.rec(24, b'\x01\x00\x02AB' + b'\x00' * 5)))
    # 19: an encrypted heartbeat (filler)
    f.append(c.dgram(c.rec(24, b'\x7f' + filler(30), epoch=1)))
    # 20: an SRTP packet on the ports that negotiated use_srtp
    rtp = struct.pack('!BBHII', 0x80, 0x60, 1, 160, 0x11223344) + filler(40)
    f.append(c.dgram(rtp))
    # 21-22: an encrypted alert and a plaintext close_notify alert
    f.append(c.dgram(c.rec(21, filler(26), epoch=1)))
    f.append(c.dgram(c.rec(21, b'\x01\x00'), True))
    # 23: a fatal alert
    f.append(c.dgram(c.rec(21, b'\x02\x28')))


def srtp_profile_sessions(f):
    """Servers choosing each other SRTP protection profile; the
    first client offers only one profile."""
    for i, prof in enumerate((0x0005, 0x0006, 0x0007, 0x0008, 0x0099)):
        c = Flow(41720 + i, 50120 + i)
        offer = (prof,) if i == 0 else (1, 2, 5, 6, 7, 8)
        f.append(c.dgram(c.rec(22, hs(1, client_hello(DTLS12, extensions=exts(use_srtp(offer))), 0))))
        f.append(c.dgram(c.rec(22, hs(2, server_hello(DTLS12, 0xc02b, exts(use_srtp((prof,), b'\x07'))), 0), True), True))


def dtls10_session(f):
    """DTLS 1.0 and the OpenSSL pre-standard version 0x0100."""
    c = Flow(41701, 50101)
    f.append(c.dgram(c.rec(22, hs(1, client_hello(DTLS10, suites=(0x002f, 0x0035)), 0), version=DTLS10)))
    f.append(c.dgram(c.rec(22, hs(2, server_hello(DTLS10, 0x002f), 0) + hs(14, b'', 1), True,
                           version=DTLS10), True))
    # ClientKeyExchange (RSA, filler encrypted premaster) and CCS
    f.append(c.dgram(c.rec(22, hs(16, v16(filler(128)), 1), version=DTLS10) +
                     c.rec(20, b'\x01', version=DTLS10)))
    o = Flow(41702, 50102)
    f.append(o.dgram(o.rec(22, hs(1, client_hello(0x0100, suites=(0x002f,)), 0), version=0x0100)))
    f.append(o.dgram(o.rec(22, hs(2, server_hello(0x0100, 0x002f), 0), True, version=0x0100), True))


def dtls12_cid_session(f):
    """DTLS 1.2 with Connection IDs: the connection_id extension and
    records of content type 25 (tls12_cid) with filler content."""
    c = Flow(41703, 50103, cid_len={0: 2, 1: 4})
    ccid, scid = b'\xc1\xc2\xc3\xc4', b'\x5a\x5b'
    f.append(c.dgram(c.rec(22, hs(1, client_hello(DTLS12, extensions=exts(ext(54, v8(ccid)))), 0))))
    f.append(c.dgram(c.rec(22, hs(2, server_hello(DTLS12, 0xc02b, exts(ext(54, v8(scid)))), 0)), True))
    # records to the server carry the server's CID, records to the
    # client the client's CID
    f.append(c.dgram(c.rec(25, filler(32), epoch=1, cid=scid)))
    f.append(c.dgram(c.rec(25, filler(32), True, epoch=1, cid=ccid), True))
    # two CID records in one datagram
    f.append(c.dgram(c.rec(25, filler(20), epoch=1, cid=scid) + c.rec(25, filler(8), epoch=1, cid=scid)))


def dtls13_session(f):
    """DTLS 1.3: HelloRetryRequest, ServerHello with supported_versions,
    unified header records with every flag and ACK records."""
    c = Flow(41704, 50104)
    ks = ext(51, v16(struct.pack('!H', 29) + v16(filler(32))))
    ch = client_hello(DTLS12, suites=(0x1301, 0x1302), extensions=exts(
        ext(43, v8(struct.pack('!HH', DTLS13, DTLS12))), ext(10, v16(struct.pack('!HH', 29, 23))),
        ext(13, v16(struct.pack('!H', 0x0403))), ks, ext(54, v8(b'\xaa\xbb'))))
    f.append(c.dgram(c.rec(22, hs(1, ch, 0))))
    # HelloRetryRequest (ServerHello with the special random)
    hrr = server_hello(DTLS12, 0x1301, exts(ext(43, struct.pack('!H', DTLS13)),
                                            ext(51, struct.pack('!H', 23)),
                                            ext(44, v16(filler(16)))), random32=HRR_RANDOM)
    f.append(c.dgram(c.rec(22, hs(2, hrr, 0)), True))
    ch2 = client_hello(DTLS12, suites=(0x1301,), extensions=exts(
        ext(43, v8(struct.pack('!H', DTLS13))), ext(44, v16(filler(16))),
        ext(51, v16(struct.pack('!H', 23) + v16(b'\x04' + filler(64)))), ext(54, v8(b'\xaa\xbb'))))
    f.append(c.dgram(c.rec(22, hs(1, ch2, 1))))
    sh = server_hello(DTLS12, 0x1301, exts(ext(43, struct.pack('!H', DTLS13)),
                                           ext(51, struct.pack('!H', 23) + v16(b'\x04' + filler(64))),
                                           ext(54, v8(b'\xcc'))))
    f.append(c.dgram(c.rec(22, hs(2, sh, 1)), True))
    # unified header records (filler content): S=1 L=1 epoch 2; S=0
    # L=1 epoch 2; S=1 L=0 epoch 3 (length to the end); with a CID
    f.append(c.dgram(b'\x2e' + struct.pack('!HH', 0x0000, 40) + filler(40), True))
    f.append(c.dgram(b'\x26' + bytes([1]) + struct.pack('!H', 30) + filler(30), True))
    f.append(c.dgram(b'\x2b' + struct.pack('!H', 2) + filler(25)))
    f.append(c.dgram(b'\x3e' + b'\xcc' + struct.pack('!HH', 3, 20) + filler(20)))
    # KeyUpdate in a plaintext handshake record
    f.append(c.dgram(c.rec(22, hs(24, b'\x00', 2)), True))
    # two unified header records with lengths in one datagram
    f.append(c.dgram(b'\x2f' + struct.pack('!HH', 4, 10) + filler(10) +
                     b'\x2f' + struct.pack('!HH', 5, 12) + filler(12), True))


def dtls13_early_session(f):
    """A DTLS 1.3 ClientHello offering early data, and a draft style
    HelloRetryRequest handshake message (type 6)."""
    c = Flow(41708, 50108)
    ch = client_hello(DTLS12, suites=(0x1301,), extensions=exts(
        ext(43, v8(struct.pack('!H', DTLS13))), ext(42, b''),
        ext(41, v16(v16(filler(16)) + struct.pack('!I', 1)) + v16(v8(filler(32))))))
    f.append(c.dgram(c.rec(22, hs(1, ch, 0))))
    f.append(c.dgram(c.rec(22, hs(6, struct.pack('!H', DTLS13) + struct.pack('!H', 0x1301) +
                                   exts(ext(51, struct.pack('!H', 23))), 0)), True))
    # datagrams that look like DTLS at first but are not: a record
    # followed by an unknown content type, a TLS record version
    f.append(udp_frame(41715, 50115, record(21, b'\x01\x00') + record(99, b'\x00')))
    f.append(udp_frame(41716, 50116, record(21, b'\x01\x00', version=0x0303)))
    # a unified header with the C bit on a flow without DTLS: not DTLS
    f.append(udp_frame(41709, 50109, b'\x3c\x01\x02\x03' + filler(16)))


def fragmented_session(f):
    """A ClientHello with a padding extension in a UDP datagram that
    is fragmented by IP."""
    a, b = (10, 0, 0, 5), (10, 0, 0, 6)
    ch = client_hello(DTLS12, extensions=exts(ext(21, bytes(1600))))
    rec = record(22, hs(1, ch, 0))
    f.extend(ip_fragments(a, b, 17, udp(a, b, 41712, 50112, rec)))


def misc_session(f):
    """Handshake message types parsed in plaintext, multiple messages
    in one record, a fragment arriving out of order, and records on the
    CoAP over DTLS port."""
    c = Flow(41705, 50105)
    f.append(c.dgram(c.rec(22, hs(1, client_hello(DTLS12), 0))))
    f.append(c.dgram(c.rec(22, hs(2, server_hello(DTLS12, 0xc02b), 0) +
                           hs(22, struct.pack('!B', 1) + v24(bytes.fromhex('30030a0101')), 1), True), True))  # CertificateStatus OCSP
    f.append(c.dgram(c.rec(22, hs(0, b'', 2), True) + c.rec(22, hs(8, v16(b''), 3), True), True))  # HelloRequest, EncryptedExtensions
    f.append(c.dgram(c.rec(22, hs(24, b'\x01', 1)) + c.rec(22, hs(5, b'', 2))))  # KeyUpdate, EndOfEarlyData
    f.append(c.dgram(c.rec(22, hs(20, filler(12), 3))))  # a plaintext Finished
    # out of order fragments of a ClientHello (dtls_hs_fragments.py
    # frames 1-2): the second half first, then the first half
    o = Flow(41706, 50106)
    ch = struct.pack('!H', DTLS12) + b'\x11' * 32 + b'\x00' + b'\x00' + struct.pack('!H', 2) + \
        b'\xc0\x2b' + b'\x01\x00' + struct.pack('!H', 0)
    half = len(ch) // 2
    f.append(o.dgram(o.rec(22, hs(1, ch, 0, half))))
    f.append(o.dgram(o.rec(22, hs(1, ch, 0, 0, half))))
    # CoAP over DTLS (UDP 5684): handshake and application data
    p = Flow(41707, 5684)
    f.append(p.dgram(p.rec(22, hs(1, client_hello(DTLS12, suites=(0xc0ae,)), 0))))
    f.append(p.dgram(p.rec(22, hs(2, server_hello(DTLS12, 0xc0ae), 0) + hs(14, b'', 1), True), True))
    f.append(p.dgram(p.rec(23, filler(24), epoch=1)))
    # an unknown content type (continuation data) on the DTLS port
    f.append(p.dgram(p.rec(23, filler(8), epoch=1) + record(99, filler(6), 1, 9)))
    # Diameter over DTLS on SCTP (PPI 47)
    f.append(sctp_frame(record(22, hs(1, client_hello(DTLS12), 0)), 47))


def crc32c(data):
    crc = 0xffffffff
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82f63b78 if crc & 1 else 0)
    return crc ^ 0xffffffff


def sctp_frame(payload, ppi, a=(10, 0, 0, 3), b=(10, 0, 0, 4)):
    pad = bytes(-len(payload) % 4)
    chunk = struct.pack('!BBHIHHI', 0, 0x03, 16 + len(payload), 1, 0, 0, ppi) + payload + pad
    hdr = struct.pack('!HHII', 3868, 3868, 0x01020304, 0)
    pkt = hdr + chunk
    pkt = pkt[:8] + struct.pack('<I', crc32c(pkt)) + pkt[12:]
    return eth(mac(2), mac(1), 0x0800, ip4(a, b, 132, pkt))


def main_frames():
    f = []
    dtls12_session(f)
    srtp_profile_sessions(f)
    dtls10_session(f)
    dtls12_cid_session(f)
    dtls13_session(f)
    dtls13_early_session(f)
    fragmented_session(f)
    misc_session(f)
    return f


def malformed_frames():
    f = []
    c = Flow(41710, 50110)
    # dtls_hs_fragments.py frames 3-6: a total length that
    # changes between fragments, overlapping fragments that conflict
    f.append(c.dgram(record(22, hs(11, bytes(10), 1, 0, 5), 0, 0)))
    f.append(c.dgram(record(22, struct.pack('!B', 11) + (300).to_bytes(3, 'big') + struct.pack('!H', 1) +
                            (5).to_bytes(3, 'big') + (5).to_bytes(3, 'big') + bytes(5), 0, 1)))
    ch = client_hello(DTLS12)
    half = len(ch) // 2
    f.append(c.dgram(record(22, hs(1, ch, 2, 0, half + 4), 0, 2)))
    f.append(c.dgram(record(22, hs(1, b'\xff' * len(ch), 2, half), 0, 3)))
    # fragment longer than the message (offset 0 and not 0), a zero
    # length fragment at an offset
    f.append(c.dgram(record(22, struct.pack('!B', 1) + (10).to_bytes(3, 'big') + b'\x00\x05' +
                            (0).to_bytes(3, 'big') + (20).to_bytes(3, 'big') + bytes(20), 0, 4)))
    f.append(c.dgram(record(22, struct.pack('!B', 1) + (10).to_bytes(3, 'big') + b'\x00\x06' +
                            (8).to_bytes(3, 'big') + (5).to_bytes(3, 'big') + bytes(5), 0, 5)))
    f.append(c.dgram(record(22, struct.pack('!B', 1) + (10).to_bytes(3, 'big') + b'\x00\x07' +
                            (4).to_bytes(3, 'big') + (0).to_bytes(3, 'big'), 0, 6)))
    # a heartbeat with a payload length past the record (tree decode)
    f.append(c.dgram(record(24, b'\x01\x00\x40' + bytes(20), 0, 7)))
    # use_srtp: profiles length past the extension, server with two
    # profiles, extension of one octet
    u = Flow(41714, 50114)
    f.append(u.dgram(record(22, hs(1, client_hello(DTLS12, extensions=exts(
        ext(14, struct.pack('!H', 10) + b'\x00\x01\x00'))), 0), 0, 0)))
    f.append(u.dgram(record(22, hs(1, client_hello(DTLS12, extensions=exts(ext(14, b'\x00'))), 1), 0, 1)))
    f.append(c.dgram(record(22, hs(2, server_hello(DTLS12, 0xc02b, exts(
        use_srtp((1, 2)))), 0), 0, 0), True))
    # an ACK with a bad length, a HelloVerifyRequest cookie longer than 32
    f.append(c.dgram(record(26, b'\x00\x05' + bytes(5), 0, 9)))
    f.append(c.dgram(record(22, hs(3, struct.pack('!H', DTLS12) + v8(bytes(40)), 1), 0, 1), True))
    # ACK records (content type 26) with one and two record numbers:
    # well formed, but dissect_dtls_ack() passes the record length as
    # the end offset, so the vector is reported as too long
    c13 = Flow(41711, 50111)
    f.append(c13.dgram(c13.rec(22, hs(1, client_hello(DTLS12, extensions=exts(
        ext(43, v8(struct.pack('!H', DTLS13))))), 0))))
    f.append(c13.dgram(c13.rec(22, hs(2, server_hello(DTLS12, 0x1301, exts(
        ext(43, struct.pack('!H', DTLS13)))), 0)), True))
    f.append(c13.dgram(c13.rec(26, v16(struct.pack('!QQ', 2, 0)))))
    f.append(c13.dgram(c13.rec(26, v16(struct.pack('!QQQQ', 2, 1, 3, 0))), True))
    # an ACK padded so that the record length passes the vector check
    f.append(c13.dgram(c13.rec(26, v16(struct.pack('!QQ', 2, 1)) + bytes(16))))
    # a datagram cut short by the snapshot length (two records)
    t = Flow(41713, 50113)
    d = t.dgram(record(22, hs(1, client_hello(DTLS12), 0), 0, 0) + record(21, b'\x01\x00', 0, 1))
    f.append((d[:80], len(d)))
    f.append((d[:50], len(d)))
    # a record cut short
    f.append(c.dgram(record(22, hs(1, client_hello(DTLS12), 0), 0, 10)[:30]))
    return f



# ------------------------------------------------- decryption (pcapng)
# Sessions whose records are really encrypted, with made-up secrets: a
# DTLS 1.2 ECDHE session (CLIENT_RANDOM key log), a DTLS 1.2 RSA session
# (the premaster secret is encrypted with test/keys/snakeoil-rsa.key, so
# the DTLS RSA key table decrypts it), DTLS 1.3 sessions with AES-128-GCM
# and ChaCha20-Poly1305 (handshake and application traffic secrets, a
# KeyUpdate) and DTLS 1.3 early data with AES-256-GCM. The key log goes
# into a pcapng Decryption Secrets Block. The AEAD encryption, HKDF, HMAC
# and the X.509 certificate use the Python 'cryptography' library.

import hashlib
import hmac

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as _pad  # noqa: F401
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.x509.oid import NameOID
import datetime

KEYLOG = []
RSA_KEY_FILE = os.environ.get('RSA_KEY_FILE', os.path.join(SRCDIR, 'test/keys/snakeoil-rsa.key'))


def secret(tag, n=32):
    """A made-up secret: SHA-256 based, so it is fixed and visibly fake."""
    out = b''
    i = 0
    while len(out) < n:
        out += hashlib.sha256(b'wireshark dtls coverage %s %d' % (tag.encode(), i)).digest()
        i += 1
    return out[:n]


def tls12_prf(sec, label, seed, n):
    out, a = b'', label + seed
    while len(out) < n:
        a = hmac.new(sec, a, hashlib.sha256).digest()
        out += hmac.new(sec, a + label + seed, hashlib.sha256).digest()
    return out[:n]


def hkdf_expand_label(sec, label, length, hash_name='sha256', prefix=b'dtls13'):
    info = struct.pack('!H', length) + v8(prefix + label) + v8(b'')
    out, t, i = b'', b'', 1
    while len(out) < length:
        t = hmac.new(sec, t + info + bytes([i]), hash_name).digest()
        out += t
        i += 1
    return out[:length]


def ch_with_random(cr, suites, extensions, version=DTLS12):
    return struct.pack('!H', version) + cr + v8(b'') + v8(b'') + \
        v16(b''.join(struct.pack('!H', s) for s in suites)) + v8(b'\x00') + extensions


def sh_with_random(sr, suite, extensions, version=DTLS12):
    return struct.pack('!H', version) + sr + v8(b'') + struct.pack('!HB', suite, 0) + extensions


class Conn12:
    """DTLS 1.2 AES-GCM records with explicit sequence numbers."""

    def __init__(self, cport, sport, a, b, ms, cr, sr):
        self.cport, self.sport, self.a, self.b = cport, sport, a, b
        kb = tls12_prf(ms, b'key expansion', sr + cr, 40)
        self.key = {False: kb[0:16], True: kb[16:32]}
        self.iv = {False: kb[32:36], True: kb[36:40]}
        self.seq = {}

    def plain(self, ctype, body, srv=False):
        s = self.seq.get((srv, 0), 0)
        self.seq[(srv, 0)] = s + 1
        return record(ctype, body, 0, s)

    def enc(self, ctype, body, srv=False, epoch=1, bad=False):
        s = self.seq.get((srv, epoch), 0)
        self.seq[(srv, epoch)] = s + 1
        explicit = struct.pack('!H', epoch) + s.to_bytes(6, 'big')
        aad = explicit + struct.pack('!BHH', ctype, DTLS12, len(body))
        ct = AESGCM(self.key[srv]).encrypt(self.iv[srv] + explicit, body, aad)
        if bad:
            ct = ct[:-1] + bytes([ct[-1] ^ 1])
        return record(ctype, explicit + ct, epoch, s)

    def dgram(self, data, srv=False):
        if srv:
            return udp_frame(self.sport, self.cport, data, self.a, self.b, rev=True)
        return udp_frame(self.cport, self.sport, data, self.a, self.b)


COAP_MID = [0x1233]


def coap_get():
    """A CoAP GET /test with the next message ID."""
    COAP_MID[0] += 1
    return b'\x40\x01' + struct.pack('!H', COAP_MID[0]) + b'\xb4test'


def coap_ack():
    """The piggybacked response to the last GET."""
    return b'\x60\x45' + struct.pack('!H', COAP_MID[0]) + b'\xffhello'


def dtls12_keylog_session(f):
    """ECDHE-RSA-AES128-GCM-SHA256 on UDP 5684 (CoAP): the key log has
    the master secret. Finished, CoAP requests and responses, a heartbeat
    request and response, a record with a broken tag and an alert are
    encrypted."""
    cr, sr, ms = secret('cr12'), secret('sr12'), secret('ms12', 48)
    KEYLOG.append('CLIENT_RANDOM %s %s' % (cr.hex(), ms.hex()))
    c = Conn12(41800, 5684, (10, 0, 1, 1), (10, 0, 1, 2), ms, cr, sr)
    ch = ch_with_random(cr, (0xc02f,), exts(ext(10, v16(struct.pack('!H', 23))), ext(11, v8(b'\x00')),
                                             ext(15, b'\x01')))
    f.append(c.dgram(c.plain(22, hs(1, ch, 0))))
    sh = sh_with_random(sr, 0xc02f, exts(ext(15, b'\x01'), ext(11, v8(b'\x00'))))
    f.append(c.dgram(c.plain(22, hs(2, sh, 0), True) + c.plain(22, hs(14, b'', 1), True), True))
    f.append(c.dgram(c.plain(22, hs(16, v8(b'\x04' + secret('ecdh', 64)), 1)) +
                     c.plain(20, b'\x01') + c.enc(22, hs(20, secret('cfin', 12), 2))))
    f.append(c.dgram(c.plain(20, b'\x01', True) + c.enc(22, hs(20, secret('sfin', 12), 2), True), True))
    f.append(c.dgram(c.enc(23, coap_get())))
    f.append(c.dgram(c.enc(23, coap_ack(), True), True))
    f.append(c.dgram(c.enc(24, b'\x01' + struct.pack('!H', 4) + b'ping' + bytes(16))))   # heartbeat request
    f.append(c.dgram(c.enc(24, b'\x02' + struct.pack('!H', 4) + b'ping' + bytes(16), True), True))
    f.append(c.dgram(c.enc(23, coap_get(), bad=True)))                     # tag check fails
    f.append(c.dgram(c.enc(23, coap_get()) + c.enc(23, coap_get())))         # two records
    f.append(c.dgram(c.enc(21, b'\x01\x00')))                           # close_notify


def rsa_cert_and_key():
    with open(RSA_KEY_FILE, 'rb') as fh:
        key = serialization.load_pem_private_key(fh.read(), None)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'dtls-rsa.example')])
    t0 = datetime.datetime(2023, 1, 1, tzinfo=datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(0x1234)
            .not_valid_before(t0).not_valid_after(t0 + datetime.timedelta(days=3650))
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.DER), key


def rsa_encrypt_pkcs1(pub, data):
    """PKCS #1 v1.5 type 2 padding with fixed non-zero padding octets (so
    that the capture is reproducible), then the raw RSA operation."""
    n, e = pub.public_numbers().n, pub.public_numbers().e
    k = (n.bit_length() + 7) // 8
    ps = bytes(((i * 37) % 255) + 1 for i in range(k - 3 - len(data)))
    m = int.from_bytes(b'\x00\x02' + ps + b'\x00' + data, 'big')
    return pow(m, e, n).to_bytes(k, 'big')


HTTP_GET = b'GET /dtls HTTP/1.1\r\nHost: dtls-rsa.example\r\n\r\n'
HTTP_OK = b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok'


def dtls12_rsa_session(f):
    """TLS_RSA_WITH_AES_128_GCM_SHA256 on UDP 4433 with the server
    certificate of snakeoil-rsa.key: the RSA key table recovers the
    premaster secret; its protocol column hands the data to HTTP."""
    der, key = rsa_cert_and_key()
    cr, sr = secret('cr-rsa'), secret('sr-rsa')
    pms = struct.pack('!H', DTLS12) + secret('pms-rsa', 46)
    ms = tls12_prf(pms, b'master secret', cr + sr, 48)
    c = Conn12(41801, 4433, (10, 0, 1, 3), (10, 0, 1, 4), ms, cr, sr)
    ch = ch_with_random(cr, (0x009c,), exts(ext(13, v16(struct.pack('!H', 0x0401)))))
    f.append(c.dgram(c.plain(22, hs(1, ch, 0))))
    sh = sh_with_random(sr, 0x009c, exts())
    f.append(c.dgram(c.plain(22, hs(2, sh, 0), True) + c.plain(22, hs(11, v24(v24(der)), 1), True) +
                     c.plain(22, hs(14, b'', 2), True), True))
    f.append(c.dgram(c.plain(22, hs(16, v16(rsa_encrypt_pkcs1(key.public_key(), pms)), 1)) +
                     c.plain(20, b'\x01') + c.enc(22, hs(20, secret('rcfin', 12), 2))))
    f.append(c.dgram(c.plain(20, b'\x01', True) + c.enc(22, hs(20, secret('rsfin', 12), 3), True), True))
    f.append(c.dgram(c.enc(23, HTTP_GET)))
    f.append(c.dgram(c.enc(23, HTTP_OK, True), True))


class Conn13:
    """DTLS 1.3 unified header records (AEAD, record number encryption)."""
    SUITES = {0x1301: ('aes', 16, 'sha256'), 0x1302: ('aes', 32, 'sha384'),
              0x1303: ('chacha', 32, 'sha256')}

    def __init__(self, cport, sport, a, b, suite):
        self.cport, self.sport, self.a, self.b = cport, sport, a, b
        self.alg, self.klen, self.hash = self.SUITES[suite]
        self.keys = {}
        self.seq = {}

    def set_secret(self, srv, epoch, sec):
        h = self.hash
        self.keys[(srv, epoch)] = (hkdf_expand_label(sec, b'key', self.klen, h),
                                   hkdf_expand_label(sec, b'iv', 12, h),
                                   hkdf_expand_label(sec, b'sn', self.klen, h), sec)

    def key_update(self, srv, old, new):
        h = self.hash
        sec = self.keys[(srv, old)][3]
        nxt = hkdf_expand_label(sec, b'traffic upd', hashlib.new(h).digest_size, h)
        self.set_secret(srv, new, nxt)

    def plain(self, ctype, body, srv=False):
        s = self.seq.get((srv, 0), 0)
        self.seq[(srv, 0)] = s + 1
        return record(ctype, body, 0, s)

    def enc(self, ctype, body, srv=False, epoch=2, s16=True, length=True, seq=None, pad=0):
        key, iv, sn, _ = self.keys[(srv, epoch)]
        if seq is None:
            seq = self.seq.get((srv, epoch), 0)
            self.seq[(srv, epoch)] = seq + 1
        inner = body + bytes([ctype]) + bytes(pad)
        clen = len(inner) + 16
        flags = 0x20 | (0x08 if s16 else 0) | (0x04 if length else 0) | (epoch & 3)
        seqb = (seq & 0xffff).to_bytes(2, 'big') if s16 else bytes([seq & 0xff])
        hdr = bytes([flags]) + seqb + (struct.pack('!H', clen) if length else b'')
        nonce = (int.from_bytes(iv, 'big') ^ seq).to_bytes(12, 'big')
        if self.alg == 'aes':
            ct = AESGCM(key).encrypt(nonce, inner, hdr)
            e = Cipher(algorithms.AES(sn), modes.ECB()).encryptor()
            mask = e.update(ct[:16]) + e.finalize()
        else:
            ct = ChaCha20Poly1305(key).encrypt(nonce, inner, hdr)
            e = Cipher(algorithms.ChaCha20(sn, ct[:16]), None).encryptor()
            mask = e.update(bytes(16))
        wire = bytes(a ^ b for a, b in zip(seqb, mask))
        return bytes([flags]) + wire + hdr[1 + len(seqb):] + ct

    def dgram(self, data, srv=False):
        if srv:
            return udp_frame(self.sport, self.cport, data, self.a, self.b, rev=True)
        return udp_frame(self.cport, self.sport, data, self.a, self.b)


def dtls13_hello(c, f, cr, sr, suite, ch_exts=(), sh_exts=()):
    ks = ext(51, v16(struct.pack('!H', 29) + v16(secret('ks' + cr.hex()))))
    ch = ch_with_random(cr, (suite,), exts(ext(43, v8(struct.pack('!H', DTLS13))),
                                           ext(13, v16(struct.pack('!H', 0x0804))), ks, *ch_exts))
    f.append(c.dgram(c.plain(22, hs(1, ch, 0))))
    return sh_with_random(sr, suite, exts(ext(43, struct.pack('!H', DTLS13)),
                                          ext(51, struct.pack('!H', 29) + v16(secret('ss' + sr.hex()))),
                                          *sh_exts))


def dtls13_keylog_session(f):
    """TLS_AES_128_GCM_SHA256: the encrypted handshake (epoch 2) with
    every header form, application data (epoch 3), records out of order,
    an ACK, a KeyUpdate and application data with the next keys (epoch
    4), a record with a padded inner plaintext."""
    cr, sr = secret('cr13'), secret('sr13')
    sec = {k: secret(k + '13') for k in ('chts', 'shts', 'cats', 'sats')}
    KEYLOG.extend(['CLIENT_HANDSHAKE_TRAFFIC_SECRET %s %s' % (cr.hex(), sec['chts'].hex()),
                   'SERVER_HANDSHAKE_TRAFFIC_SECRET %s %s' % (cr.hex(), sec['shts'].hex()),
                   'CLIENT_TRAFFIC_SECRET_0 %s %s' % (cr.hex(), sec['cats'].hex()),
                   'SERVER_TRAFFIC_SECRET_0 %s %s' % (cr.hex(), sec['sats'].hex())])
    c = Conn13(41802, 5684, (10, 0, 1, 5), (10, 0, 1, 6), 0x1301)
    c.set_secret(False, 2, sec['chts'])
    c.set_secret(True, 2, sec['shts'])
    c.set_secret(False, 3, sec['cats'])
    c.set_secret(True, 3, sec['sats'])
    sh = dtls13_hello(c, f, cr, sr, 0x1301)
    ee = hs(8, exts(ext(10, v16(struct.pack('!H', 29)))), 1)
    cert = hs(11, v8(b'') + v24(v24(rsa_cert_and_key()[0]) + v16(b'')), 2)
    cv = hs(15, struct.pack('!H', 0x0804) + v16(secret('cv13', 64)), 3)
    fin = hs(20, secret('sfin13'), 4)
    f.append(c.dgram(c.plain(22, hs(2, sh, 0), True) + c.enc(22, ee, True) +
                     c.enc(22, cert, True, s16=False) + c.enc(22, cv, True, length=False), True))
    f.append(c.dgram(c.enc(22, fin, True, s16=False, length=False), True))
    f.append(c.dgram(c.enc(22, hs(20, secret('cfin13'), 1))))
    f.append(c.dgram(c.enc(26, v16(struct.pack('!QQ', 2, 0)), True, epoch=3), True))   # ACK
    f.append(c.dgram(c.enc(23, coap_get(), epoch=3, s16=False)))
    f.append(c.dgram(c.enc(23, coap_ack(), True, epoch=3, pad=7), True))
    f.append(c.dgram(c.enc(23, coap_get(), epoch=3, seq=3)))                 # seq 3 before 2
    f.append(c.dgram(c.enc(23, coap_get(), epoch=3, seq=2, s16=False)))
    f.append(c.dgram(c.enc(23, coap_get(), epoch=3, seq=6)))                 # a gap
    f.append(c.dgram(c.enc(22, hs(24, b'\x00', 2), epoch=3, seq=7)))      # KeyUpdate
    c.key_update(False, 3, 4)
    f.append(c.dgram(c.enc(23, coap_get(), epoch=4)))
    f.append(c.dgram(c.enc(23, coap_get(), epoch=4, s16=False)))
    # records 2-199 lost: an 8-bit sequence number far above the expected
    # one (no candidate below 0), then the next record
    f.append(c.dgram(c.enc(23, coap_get(), epoch=4, s16=False, seq=200)))
    f.append(c.dgram(c.enc(23, coap_get(), epoch=4, s16=False, seq=201)))


def dtls13_chacha_session(f):
    """TLS_CHACHA20_POLY1305_SHA256: the record numbers are masked with
    ChaCha20."""
    cr, sr = secret('cr13c'), secret('sr13c')
    shts, sats, cats = secret('shts13c'), secret('sats13c'), secret('cats13c')
    KEYLOG.extend(['SERVER_HANDSHAKE_TRAFFIC_SECRET %s %s' % (cr.hex(), shts.hex()),
                   'SERVER_TRAFFIC_SECRET_0 %s %s' % (cr.hex(), sats.hex()),
                   'CLIENT_TRAFFIC_SECRET_0 %s %s' % (cr.hex(), cats.hex())])
    c = Conn13(41803, 5684, (10, 0, 1, 7), (10, 0, 1, 8), 0x1303)
    c.set_secret(True, 2, shts)
    c.set_secret(True, 3, sats)
    c.set_secret(False, 3, cats)
    sh = dtls13_hello(c, f, cr, sr, 0x1303)
    f.append(c.dgram(c.plain(22, hs(2, sh, 0), True) +
                     c.enc(22, hs(8, exts(), 1), True, s16=False), True))
    f.append(c.dgram(c.enc(23, coap_get(), epoch=3)))
    f.append(c.dgram(c.enc(23, coap_ack(), True, epoch=3), True))


def dtls13_early_data_session(f):
    """TLS_AES_256_GCM_SHA384 with early data: the ClientHello offers a
    PSK and early data, the client sends 0-RTT records (epoch 1) that are
    found by trial decryption, then the server handshake."""
    cr, sr = secret('cr13e'), secret('sr13e')
    cets, shts = secret('cets13e', 48), secret('shts13e', 48)
    KEYLOG.extend(['CLIENT_EARLY_TRAFFIC_SECRET %s %s' % (cr.hex(), cets.hex()),
                   'SERVER_HANDSHAKE_TRAFFIC_SECRET %s %s' % (cr.hex(), shts.hex())])
    c = Conn13(41804, 5684, (10, 0, 1, 9), (10, 0, 1, 10), 0x1302)
    c.set_secret(False, 1, cets)
    c.set_secret(True, 2, shts)
    psk = ext(41, v16(v16(b'ticket-1') + struct.pack('!I', 1000)) + v16(v8(secret('binder', 48))))
    sh = dtls13_hello(c, f, cr, sr, 0x1302, (ext(45, v8(b'\x01')), ext(42, b''), psk),
                      (ext(41, struct.pack('!H', 0)),))
    f.append(c.dgram(c.enc(23, coap_get(), epoch=1)))                        # trial decryption
    f.append(c.dgram(c.enc(23, coap_get(), epoch=1, s16=False)))             # same keys
    f.append(c.dgram(c.plain(22, hs(2, sh, 0), True) +
                     c.enc(22, hs(8, exts(ext(42, b'')), 1), True), True))


def crypto_frames():
    f = []
    dtls12_keylog_session(f)
    dtls12_rsa_session(f)
    dtls13_keylog_session(f)
    dtls13_chacha_session(f)
    dtls13_early_data_session(f)
    return f


def pcapng(path, frames, keylog):
    """Ethernet frames with a Decryption Secrets Block (TLS key log)."""
    def block(btype, body):
        body += b'\0' * ((4 - len(body) % 4) % 4)
        ln = 12 + len(body)
        return struct.pack('<II', btype, ln) + body + struct.pack('<I', ln)
    out = block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    out += block(1, struct.pack('<HHI', 1, 0, 262144))
    data = ('\n'.join(keylog) + '\n').encode()
    out += block(10, struct.pack('<II', 0x544c534b, len(data)) + data)
    for i, fr in enumerate(frames):
        ts = (1700000000 + i) * 1000000 + 1000 * i
        out += block(6, struct.pack('<IIIII', 0, ts >> 32, ts & 0xffffffff, len(fr), len(fr)) + fr)
    with open(path, 'wb') as fh:
        fh.write(out)

if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 and sys.argv[1] != '-v' else '.'
    frames = main_frames()
    n = len(frames)
    frames += crypto_frames()
    if '-v' in sys.argv:
        print('frames 1-%d: parsing; %d-%d: decryption' % (n, n + 1, len(frames)))
    pcapng(os.path.join(out, 'dtls-coverage.pcapng'), frames, KEYLOG)
    pcap(os.path.join(out, 'dtls-coverage-malformed.pcap'), malformed_frames())
