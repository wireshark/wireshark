#!/usr/bin/env python3
# Generates test/captures/cose_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the COSE dissector
(packet-cose.c) beyond what the COSE captures already in the tree
(test/captures/cose_*.pcap, which hold the RFC 9052 examples as tagged
messages over HTTP) cover.

Every packet, CBOR item and the X.509 certificate are built from
scratch with struct; no captured traffic is used.

Usage: mkcose.py <output directory>

Writes:
  cose-coverage.pcap            HTTP POSTs with application/cose and every
                                "cose-type" parameter (untagged messages),
                                every header parameter, COSE_Key and
                                COSE_KeySet with every key type and key
                                parameter, the +cose suffix, an EDHOC
                                message 1 (COSE algorithm property lookups)
                                and the AMQP reproducer of the fix
  cose-coverage-malformed.pcap  unknown cose-type values and tags, partial
                                decodes, truncated items, the header key
                                leak reproducer
"""

import os
import struct
import sys

# ---------------------------------------------------------------- CBOR


class Tag:
    def __init__(self, tag, value):
        self.tag = tag
        self.value = value


class Raw:
    """Already encoded CBOR."""
    def __init__(self, data):
        self.data = data


class Simple:
    def __init__(self, value):
        self.value = value


def head(major, val):
    if val < 24:
        return bytes([(major << 5) | val])
    if val < 0x100:
        return bytes([(major << 5) | 24, val])
    if val < 0x10000:
        return bytes([(major << 5) | 25]) + struct.pack('>H', val)
    if val < 0x100000000:
        return bytes([(major << 5) | 26]) + struct.pack('>I', val)
    return bytes([(major << 5) | 27]) + struct.pack('>Q', val)


def cbor(v):
    if isinstance(v, Raw):
        return v.data
    if isinstance(v, Simple):
        return head(7, v.value)
    if v is None:
        return b'\xf6'
    if v is True:
        return b'\xf5'
    if v is False:
        return b'\xf4'
    if isinstance(v, int):
        return head(0, v) if v >= 0 else head(1, -1 - v)
    if isinstance(v, (bytes, bytearray)):
        return head(2, len(v)) + bytes(v)
    if isinstance(v, str):
        b = v.encode()
        return head(3, len(b)) + b
    if isinstance(v, list):
        return head(4, len(v)) + b''.join(cbor(x) for x in v)
    if isinstance(v, dict):
        return head(5, len(v)) + b''.join(cbor(k) + cbor(x) for k, x in v.items())
    if isinstance(v, tuple):
        # map given as a tuple of pairs (keeps order, allows any keys)
        return head(5, len(v)) + b''.join(cbor(k) + cbor(x) for k, x in v)
    if isinstance(v, Tag):
        return head(6, v.tag) + cbor(v.value)
    raise TypeError(v)


def prot(m):
    """A protected header bstr holding the encoded map."""
    return cbor(m) if m is not None else b''

# ---------------------------------------------------------------- X.509


def der(tag, content):
    n = len(content)
    if n < 0x80:
        ln = bytes([n])
    elif n < 0x100:
        ln = bytes([0x81, n])
    else:
        ln = bytes([0x82]) + struct.pack('>H', n)
    return bytes([tag]) + ln + content


def oid(dotted):
    parts = [int(x) for x in dotted.split('.')]
    out = bytes([parts[0] * 40 + parts[1]])
    for p in parts[2:]:
        enc = [p & 0x7f]
        p >>= 7
        while p:
            enc.insert(0, 0x80 | (p & 0x7f))
            p >>= 7
        out += bytes(enc)
    return der(0x06, out)


def name(cn):
    return der(0x30, der(0x31, der(0x30, oid('2.5.4.3') + der(0x0c, cn.encode()))))


def certificate(cn, issuer, serial):
    """A self-consistent (not validly signed) X.509 v3 certificate with
    an EC P-256 key and an ecdsa-with-SHA256 signature."""
    alg = der(0x30, oid('1.2.840.10045.4.3.2'))
    spki = der(0x30, der(0x30, oid('1.2.840.10045.2.1') + oid('1.2.840.10045.3.1.7'))
               + der(0x03, b'\x00\x04' + bytes(range(1, 65))))
    tbs = der(0x30, der(0xa0, der(0x02, b'\x02')) + der(0x02, bytes([serial]))
              + alg + name(issuer)
              + der(0x30, der(0x17, b'200101000000Z') + der(0x17, b'491231235959Z'))
              + name(cn) + spki)
    sig = der(0x03, b'\x00' + der(0x30, der(0x02, b'\x01' * 32) + der(0x02, b'\x02' * 32)))
    return der(0x30, tbs + alg + sig)


CERT_LEAF = certificate('leaf.example', 'ca.example', 2)
CERT_CA = certificate('ca.example', 'ca.example', 1)

# ---------------------------------------------------------------- packets

CLI = (192, 0, 2, 10)
SRV = (198, 51, 100, 20)
MAC_C = bytes.fromhex('020000000001')
MAC_S = bytes.fromhex('020000000002')


def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


def ipv4(proto, payload, src, dst, ident=1):
    hdr = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0,
                      64, proto, 0, bytes(src), bytes(dst))
    return hdr[:10] + struct.pack('>H', csum(hdr)) + hdr[12:] + payload


def tcp(src, dst, sport, dport, seq, ack, flags, payload=b''):
    opts = b'\x02\x04\x05\xb4' if flags & 0x02 else b''   # MSS 1460 on SYN
    hdr = struct.pack('>HHIIBBHHH', sport, dport, seq, ack, (5 + len(opts) // 4) << 4,
                      flags, 65535, 0, 0) + opts
    pseudo = struct.pack('>4s4sBBH', bytes(src), bytes(dst), 0, 6, len(hdr) + len(payload))
    c = csum(pseudo + hdr + payload)
    return hdr[:16] + struct.pack('>H', c) + hdr[18:] + payload


def eth(src, dst, payload):
    return dst + src + b'\x08\x00' + payload


class TcpConn:
    """A TCP connection with a handshake; the client sends requests and
    the server acknowledges each one."""
    def __init__(self, frames, cport, sport, cip=CLI, sip=SRV):
        self.f = frames
        self.cp, self.sp, self.cip, self.sip = cport, sport, cip, sip
        self.cseq, self.sseq = 1000, 5000
        self.pkt(True, 0x02, b'')
        self.cseq += 1
        self.pkt(False, 0x12, b'')
        self.sseq += 1
        self.pkt(True, 0x10, b'')

    def pkt(self, from_client, flags, data):
        if from_client:
            seg = tcp(self.cip, self.sip, self.cp, self.sp, self.cseq,
                      self.sseq if flags != 0x02 else 0, flags, data)
            self.f.append(eth(MAC_C, MAC_S, ipv4(6, seg, self.cip, self.sip)))
        else:
            seg = tcp(self.sip, self.cip, self.sp, self.cp, self.sseq, self.cseq, flags, data)
            self.f.append(eth(MAC_S, MAC_C, ipv4(6, seg, self.sip, self.cip)))

    def send(self, data, ack=True):
        self.pkt(True, 0x18, data)
        self.cseq += len(data)
        if ack:
            self.pkt(False, 0x10, b'')

    def reply(self, data):
        self.pkt(False, 0x18, data)
        self.sseq += len(data)
        self.pkt(True, 0x10, b'')


def http_post(ctype, body, path='/cose'):
    return (('POST %s HTTP/1.1\r\nHost: example.com\r\nContent-Type: %s\r\n'
             'Content-Length: %d\r\n\r\n') % (path, ctype, len(body))).encode() + body


def http_resp(ctype, body):
    return (('HTTP/1.1 200 OK\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\n')
            % (ctype, len(body))).encode() + body


def write_pcap(path, frames, linktype=1):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, p in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)) + p)

# ---------------------------------------------------------------- content

# Header maps used in several messages
UNKNOWN_HDRS = (
    ('reserved', False),      # text label, no dissector -> CBOR
    (-70000, [1, 2]),         # unknown negative label -> CBOR
    (99, {'a': 1}),           # unknown positive label -> CBOR
)


def sign_untagged():
    # Every RFC 9052 header label in the body and signatures
    body_prot = ((1, 'ES256'), (2, [3, 'reserved', True]), (3, 'application/cbor'))
    body_unprot = ((4, b'body-kid'), (6, b'\x01\x02'), (-3, b'\xde\xad\xbe\xef'),
                   *UNKNOWN_HDRS)
    sig1 = [prot(((1, -7), (3, 'application/cbor'))),
            ((4, b'11'), (33, [CERT_LEAF, CERT_CA]), (34, [-16, bytes(32)]),
             (35, 'https://example.com/chain.pem')),
            bytes(64)]
    sig2 = [prot(((1, -35),)),
            ((4, b'\x00\x01\x02'), (5, bytes(13)), (32, [CERT_CA]),
             (-29, CERT_LEAF), (-28, 'coap://example.com/s'), (-27, ['SHA-256', bytes(8)])),
            bytes(96)]
    return [prot(body_prot), body_unprot, None, [sig1, sig2]]


def sign1_untagged():
    return [prot(((1, -8), (3, Simple(22)))),   # crit absent; ctype null -> default branch
            ((4, 'text-label-kid'.encode()), (33, CERT_LEAF), (32, 5),
             (34, [True, bytes(4)])),
            b'payload', bytes(64)]


EC2_EPHEM = ((1, 2), (-1, 1), (-2, bytes(32)), (-3, True))
OKP_STATIC = ((-1, 4), (-2, bytes(32)), (1, 1))   # kty after the curve


def encrypt_untagged():
    inner = [prot(((1, -3),)), ((4, b'inner'),), bytes(24)]
    recip_nested = [prot(((1, -29),)),
                    ((-1, EC2_EPHEM), (4, b'outer')),
                    None,
                    [inner]]
    recip_static = [prot(((1, -27),)),
                    ((-2, OKP_STATIC), (-3, b'static-kid'), (-20, b'salt0123')),
                    b'']
    return [prot(((1, 1),)), ((5, bytes(12)),), None, [recip_nested, recip_static]]


def encrypt0_untagged():
    return [prot(((1, 24), (3, 'text/plain'))), ((5, bytes(12)), (6, b'\x05')), bytes(20)]


def mac_untagged():
    return [prot(((1, 4),)), ((5, bytes(16)),), b'mac payload', bytes(8),
            [[b'', ((1, -6), (4, b'mac-key')), b'']]]


def mac0_untagged():
    return [prot(((1, 'HS256'),)), (), None, bytes(32)]


def cose_key_okp():
    return ((1, 1), (2, b'\xff\xfe'), (3, -8), (4, [1, 'sign', True, 2]), (5, bytes(8)),
            (-1, 6), (-2, bytes(32)), (-3, bytes(32)))


def key_set():
    return [
        # EC2 with a compressed y (bool) and the curve as text
        ((1, 2), (-1, 'P-256'), (-2, bytes(32)), (-3, False), (-4, bytes(32))),
        # EC2 with y as a bstr (uncompressed point)
        ((1, 2), (-1, 1), (-2, bytes(32)), (-3, bytes(32))),
        # EC2 with y as an integer (neither bstr nor bool)
        ((-3, 0), (1, 2), (-1, 2), (-2, bytes(48))),
        # RSA: no key type specific dissectors
        ((1, 3), (-1, bytes(16)), (-2, b'\x01\x00\x01')),
        # Symmetric with key_ops given as text and a Base IV
        ((1, 4), (4, ['MAC create', 9, 10]), (5, bytes(7)), (-1, bytes(16))),
        # HSS-LMS
        ((1, 5), (-1, bytes(60))),
        # WalnutDSA: unknown parameters
        ((1, 6), (-1, 1)),
        # AKP (ML-DSA)
        ((1, 7), (3, -48), (-1, bytes(40)), (-2, bytes(32))),
        # kty as text and as a simple value; key without kty
        ((1, 'OKP'), (-1, 7), (-2, bytes(57))),
        ((1, Simple(22)), (-1, 1)),
        ((2, b'no-kty'), (-1, 3), ('use', 'enc')),
    ]


def edhoc_msg1():
    # EDHOC message 1: METHOD 3, SUITES_I 2 (AES-CCM-16-64-128, SHA-256,
    # P-256), G_X (32 octets), C_I -24
    return cbor(3) + cbor(2) + cbor(bytes(range(32))) + cbor(-24)


def main_frames():
    frames = []
    c = TcpConn(frames, 50000, 80)
    posts = [
        ('application/cose; cose-type="cose-sign"', cbor(sign_untagged())),
        ('application/cose; cose-type="cose-sign1"', cbor(sign1_untagged())),
        ('application/cose; cose-type="cose-encrypt"', cbor(encrypt_untagged())),
        ('application/cose; cose-type=cose-encrypt0', cbor(encrypt0_untagged())),
        ('application/cose; cose-type="cose-mac"', cbor(mac_untagged())),
        ('application/cose; cose-type=COSE-MAC0', cbor(mac0_untagged())),
        # No cose-type: tagged message; the first tag (self-described CBOR)
        # is not a COSE tag, the second is
        ('application/cose', cbor(Tag(55799, Tag(18, sign1_untagged())))),
        # cose-type after another parameter
        ('application/cose; charset=utf-8; cose-type="cose-mac0"', cbor(mac0_untagged())),
        # Structured syntax suffix
        ('application/example+cose; cose-type="cose-encrypt0"', cbor(encrypt0_untagged())),
        ('application/cose-key', cbor(cose_key_okp())),
        ('application/cose-key-set', cbor(key_set())),
        ('application/edhoc+cbor-seq', edhoc_msg1()),
    ]
    for ct, body in posts:
        c.send(http_post(ct, body))

    # AMQP 0-9-1 Content-Body with the content type application/cose: the
    # media_type table is called with no media_content_info_t (reproducer
    # of the fix "COSE: Do not crash without media information",
    # cose_amqp_null_media_info.py)
    a = TcpConn(frames, 40000, 5672, (192, 0, 2, 1), (192, 0, 2, 2))
    a.send(b'AMQP\x00\x00\x09\x01')

    def amqp_frame(ftype, chan, payload):
        return struct.pack('!BHI', ftype, chan, len(payload)) + payload + b'\xce'
    ctype = b'application/cose'
    body = bytes([0xd2, 0x84, 0x40, 0xa0, 0xf6, 0x40])
    hdr = struct.pack('!HHQH', 60, 0, len(body), 0x8000) + bytes([len(ctype)]) + ctype
    a.send(amqp_frame(2, 1, hdr) + amqp_frame(3, 1, body))
    return frames


def malformed_frames():
    frames = []
    c = TcpConn(frames, 50001, 80)
    posts = [
        # Another parameter but no cose-type: ws_find_media_type_parameter()
        # returns the value of the last parameter ("utf-8"), which has no
        # dissector in cose.mediasub either (assertion in
        # call_dissector_only())
        ('application/cose; charset=utf-8', cbor(Tag(17, mac0_untagged()))),
        # Content type as an unsigned integer: hf_hdr_ctype_uint is FT_INT64
        # but added with proto_tree_add_cbor_uint64() (dissector bug)
        ('application/cose; cose-type="cose-mac0"', cbor([prot(((3, 60),)), {}, None, b''])),
        # kty that is neither an integer nor text: the principal peek loses
        # its place and reads past the end of the key
        ('application/cose-key', cbor(((1, b'\x01'), (-1, 1)))),
        # Unknown cose-type value: no dissector in cose.mediasub
        ('application/cose; cose-type="cose-unknown"', cbor(mac0_untagged())),
        # Untagged without a cose-type
        ('application/cose', cbor(mac0_untagged())),
        # Unknown tag only
        ('application/cose', cbor(Tag(1234, mac0_untagged()))),
        # Wrong array sizes for every message type
        ('application/cose; cose-type="cose-sign"', cbor([b'', {}])),
        ('application/cose; cose-type="cose-sign1"', cbor([b''])),
        ('application/cose; cose-type="cose-encrypt"', cbor([b''])),
        ('application/cose; cose-type="cose-encrypt0"', cbor([b''])),
        ('application/cose; cose-type="cose-mac"', cbor([b''])),
        ('application/cose; cose-type="cose-mac0"', cbor({})),
        # Header values that are only partly decoded (content type as an
        # array), signature list not an array, recipient sizes
        ('application/cose; cose-type="cose-sign"',
         cbor([b'', ((3, [1, 2]), (2, 'x'), (34, [1]), (1, [1])), None, {}])),
        ('application/cose; cose-type="cose-encrypt"',
         cbor([b'', {}, None, [[b'', {}]], ])),
        ('application/cose; cose-type="cose-encrypt"',
         cbor([b'', {}, None, 5])),
        # Header map not a map, protected header not a bstr
        ('application/cose; cose-type="cose-mac0"', cbor([5, [], None, b''])),
        # A header value cut short (the dissector of the label throws while
        # its label is held in the context)
        ('application/cose; cose-type="cose-mac0"',
         b'\x84\x40\xa1\x04\x45ab'),
        # A header pair whose value cannot be skipped
        ('application/cose; cose-type="cose-mac0"', b'\x84\x40\xa2\x01\x26\x04'),
        # Keys: key set not an array, key_ops not an array, x5chain array
        # with a bad cert, keys with values of the wrong type
        ('application/cose-key-set', cbor({1: 2})),
        ('application/cose-key', cbor(((1, 2), (4, 5), (-2, 7), (-4, 'd'), (5, 1)))),
        ('application/cose-key', cbor(((1, 4), (-1, 7)))),
        ('application/cose-key', cbor(((1, 5), (-1, 7)))),
        ('application/cose-key', cbor(((1, 7), (-1, 7), (-2, 8)))),
        ('application/cose; cose-type="cose-sign1"',
         cbor([b'', ((33, [b'\x30\x03\x02\x01']), (5, 1), (6, 2), (-20, 3), (35, 4),
                     (4, 5), (-1, 6)), None, b''])),
        # A header label that is neither an integer nor text, a curve
        # given as a bstr, a header value that is a lone break code
        ('application/cose; cose-type="cose-mac0"', cbor([b'', ((b'k', 1),), None, b''])),
        ('application/cose-key', cbor(((1, 2), (-1, b'x'), (-2, bytes(32))))),
        ('application/cose; cose-type="cose-mac0"', b'\x84\x40\xa1\x04\xff\xf6\x40'),
        # Truncated message
        ('application/cose; cose-type="cose-sign"', cbor(sign_untagged())[:40]),
        # Deeply nested recipients
        ('application/cose; cose-type="cose-encrypt"',
         b'\x84\x40\xa0\xf6\x81' + b'\x84\x40\xa0\xf6\x81' * 200 + b'\x83\x40\xa0\xf6'),
    ]
    for ct, body in posts:
        c.send(http_post(ct, body))

    # The header key leak reproducer (cose_gvariant_leak.py):
    # a protected header {1: <missing>} through Exported PDU "cose_sign1"
    return frames


def leak_frames():
    n = b'cose_sign1'
    pdu = struct.pack('!HH', 12, len(n)) + n + struct.pack('!HH', 0, 0)
    return [pdu + bytes([0x84, 0x42, 0xa1, 0x01, 0xa0, 0xf6, 0x40]),
            # the principal value present but not an int or text (bstr)
            pdu + bytes([0x84, 0x43, 0xa1, 0x01, 0x40, 0xa0, 0xf6, 0x40])]


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'cose-coverage.pcap'), main_frames())
    write_pcap(os.path.join(out, 'cose-coverage-malformed.pcap'), malformed_frames())
    write_pcap(os.path.join(out, 'cose-coverage-malformed-exppdu.pcap'), leak_frames(), 252)


if __name__ == '__main__':
    main()
