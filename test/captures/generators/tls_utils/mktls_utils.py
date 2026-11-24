#!/usr/bin/env python3
# Generates test/captures/tls_utils_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise packet-tls-utils.c, the
handshake message and extension dissection shared by TLS, DTLS and QUIC.

Nothing is encrypted and no keys are computed: certificates, key
exchange values, signatures, tickets and Finished messages are filler,
records after a ChangeCipherSpec are random octets. Everything is built
from scratch with struct (and zlib for the compressed certificate).

Usage: mktls_utils.py <output directory> [-v]

Writes:
  tls-utils-coverage.pcap            plain handshakes over TCP port 443 and
                                     DTLS over UDP (heuristic), no errors
  tls-utils-coverage-malformed.pcap  vectors that end early or too late,
                                     illegal key exchanges, bad lengths
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
import zlib

from tlslib import (
    cert, client_hello, ext, exts, filler, Flow, HRR_RANDOM, hs, name, ocsp_response, oid, record,
    seq, server_hello, spki_rsa, u16s, udp_frame, v16, v24, v8, write_pcap,
)

VERBOSE = '-v' in sys.argv
GREASE = [0x0a0a, 0x1a1a, 0x2a2a]

marks = []


def mark(frames, label):
    marks.append((len(frames), label))


def varint(v):
    if v < 0x40:
        return bytes([v])
    if v < 0x4000:
        return struct.pack('!H', 0x4000 | v)
    if v < 0x40000000:
        return struct.pack('!I', 0x80000000 | v)
    return struct.pack('!Q', 0xc000000000000000 | v)


# ------------------------------------------------------------ extensions
def sni(*names):
    lst = b''.join(bytes([t]) + v16(n.encode()) for t, n in names)
    return ext(0, v16(lst))


SNI = sni((0, 'www.example.com'), (1, 'other'))


def sigalgs(t=13, algs=(0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806,
                         0x0601, 0x0201, 0x0203, 0x0807, 0x0808, 0x0809, 0x0904,
                         0x0301, 0x0202, 0x0a0a, 0x0000, 0x0f0f, 0x0105, 0xfe00)):
    return ext(t, v16(u16s(*algs)))


def alpn(*names, t=16):
    return ext(t, v16(b''.join(v8(n) for n in names)))


def key_share_ch(*groups):
    ents = b''
    for g in groups:
        n = {29: 32, 23: 65, 24: 97, 0x6399: 1216}.get(g, 1)
        ents += struct.pack('!H', g) + v16(filler(n))
    return ext(51, v16(ents))


def ecpoint(*f):
    return ext(11, v8(bytes(f)))


def groups(*g):
    return ext(10, v16(u16s(*g)))


def sct(logid=None, ts=1700000000000, exts_=b'', ver=0, sigalg=0x0403):
    if ver:
        return bytes([ver])
    return (b'\x00' + (logid or filler(32)) + struct.pack('!Q', ts) + v16(exts_) +
            u16s(sigalg) + v16(filler(70)))


def sct_list(*scts):
    return v16(b''.join(v16(s) for s in scts))


def quic_tp_new(server=False):
    """QUIC transport parameters, draft -27 and later (varint encoding)."""
    def p(t, v=b''):
        return varint(t) + varint(len(v)) + v

    params = [
        p(0x00, filler(8)), p(0x01, varint(30000)), p(0x02, filler(16)),
        p(0x03, varint(1472)), p(0x04, varint(1 << 20)), p(0x05, varint(65536)),
        p(0x06, varint(65536)), p(0x07, varint(65536)), p(0x08, varint(100)),
        p(0x09, varint(3)), p(0x0a, varint(3)), p(0x0b, varint(25)),
        p(0x0c),
        p(0x0d, bytes([192, 0, 2, 1]) + struct.pack('!H', 4433) + b'\x20\x01\x0d\xb8' + b'\0' * 12 +
          struct.pack('!HB', 4434, 8) + filler(8) + filler(16)),
        p(0x0d, bytes(4) + bytes(2) + bytes(16) + bytes(2) + b'\x00' + filler(16)),
        p(0x0e, varint(4)), p(0x0f, filler(8)), p(0x10, filler(4)),
        p(0x11, struct.pack('!I', 1) + struct.pack('!II', 1, 0x6b3343cf)),
        p(0x20, varint(65535)), p(0x1000, varint(8) + varint(2)),
        p(0x1057, varint(1)), p(0x2ab2), p(0x7157), p(0x7158, varint(1)),
        p(0xde1a, varint(1000)), p(0xff73db, struct.pack('!II', 1, 1)),
        p(0x9f81a176, varint(1)), p(0xff03de1a, varint(1000)),
        p(0xff04de1a, varint(1000)), p(0xff04de1b, varint(1000)),
        p(0x3129, b'chrome'), p(0x312b), p(0x3127, varint(100000)),
        p(0x312a), p(0x3128, b'ABCD'),
        p(0x4751, b'CHLO' + struct.pack('<H', 1) + b'\0\0' + b'COPT' + struct.pack('<I', 4) + b'ABCD'),
        p(0xFF00, varint(1)),
        p(0x0f739bbc1b666d04, varint(1)), p(0x0f739bbc1b666d05), p(0x0f739bbc1b666d06),
        p(0x0f739bbc1b666d07, varint(4)), p(0x0f739bbc1b666d09, varint(3)),
        p(0x0f739bbc1b666d11, varint(3)), p(0x0f739bbc1b666d0c, varint(3)),
        p(0x0f739bbc1b666d0d, varint(3)), p(0x3e, varint(3)),
        p(0x4752, struct.pack('!I', 0x51303433) + (bytes([8]) + struct.pack('!II', 0x51303433, 0x51303436) if server else b'')),
        p(0x1a2a3a4a), p(0x2a * 31 + 27, b'grease'), p(0x7777, b'unknown'),
    ]
    return b''.join(params)


def quic_tp_old():
    """QUIC transport parameters, draft -26 and earlier (16-bit lengths)."""
    def p(t, v):
        return struct.pack('!HH', t, len(v)) + v
    body = p(0x00, filler(8)) + p(0x01, struct.pack('!H', 30)) + p(0x04, struct.pack('!I', 65536))
    return v16(body)


def ech_config(cfg_id=7, kem=0x20, cipher_suites=((1, 1), (1, 3)), name='public.example.com',
               version=0xfe0d, exts_=b'', pk=None):
    key = v16(pk if pk is not None else filler(32))
    cs = v16(b''.join(struct.pack('!HH', k, a) for k, a in cipher_suites))
    contents = (bytes([cfg_id]) + struct.pack('!H', kem) + key + cs + bytes([64]) +
                v8(name.encode()) + v16(exts_))
    return struct.pack('!HH', version, len(contents)) + contents


def ech_ch_outer(kdf=1, aead=1, cid=7, enc_len=32, payload_len=100):
    return ext(65037, b'\x00' + struct.pack('!HH', kdf, aead) + bytes([cid]) +
               v16(filler(enc_len)) + v16(filler(payload_len)))


def oid_filter(oid_der, value):
    return v8(oid_der) + v16(value)


def dn_list(n=3):
    return v16(b''.join(v16(name('CA %d' % i, 'Org %d' % i)) for i in range(n)))


CHROME_EXTS = [
    ext(GREASE[0], b'\x00'), SNI, ext(23), ext(65281, v8(b'')),
    groups(GREASE[1], 29, 23, 24, 0x6399, 4588), ecpoint(0),
    ext(35), alpn(b'h2', b'http/1.1'), ext(5, b'\x01' + v16(b'') + v16(b'')),
    sigalgs(), ext(18), key_share_ch(GREASE[0], 29, 0x6399),
    ext(45, v8(b'\x01')), ext(43, v8(u16s(GREASE[2], 0x0304, 0x0303))),
    ext(27, v8(u16s(2))), ext(17513, v16(v8(b'h2'))),
    ext(0xfe0d, b'\x01'), ext(GREASE[1], b'\x00'), ext(21, bytes(40)),
]


def ch_exts(*e):
    return exts(*e)


def finished(n=40):
    return filler(n)


def enc_hs(n=40):
    """An encrypted handshake message after the ChangeCipherSpec."""
    return record(22, filler(n))


def cert_chain(n=2, rpk=False):
    if rpk:
        return v24(spki_rsa())
    return v24(b''.join(v24(cert('host%d.example.com' % i, san=['host%d.example.com' % i, '*.example.org'], sct=(i == 0)))
                        for i in range(n)))


# ---------------------------------------------------------------- flows
def tls12_flow(port, suite, version=0x0303, ske=None, cke=None, sh_exts=None,
               ch_extensions=None, certreq=True, ticket=True, rpk=False, cert_msg=True,
               sid=b'', suites=None, ch_version=None, sigalg_in_ske=None, finish_hs=None):
    """A full TLS 1.2 style handshake; returns the frames."""
    fl = Flow(port, syn=False)
    ch = client_hello(ch_version or version, suites=suites or (suite, 0x00ff),
                      extensions=ch_extensions if ch_extensions is not None else exts(SNI, ext(23), ecpoint(0), groups(29, 23), sigalgs()),
                      sid=sid)
    fl.c(record(22, ch, 0x0301))
    sh = server_hello(version, suite, extensions=sh_exts if sh_exts is not None else exts(ext(65281, v8(b'')), ext(23), ecpoint(0)),
                      sid=filler(32))
    msgs = [sh]
    if cert_msg:
        msgs.append(hs(11, cert_chain(rpk=rpk)))
    if ske is not None:
        msgs.append(hs(12, ske))
    if certreq:
        sa = v16(u16s(0x0401, 0x0501, 0x0403)) if version == 0x0303 else b''
        msgs.append(hs(13, certreq if isinstance(certreq, bytes) else
                       v8(b'\x01\x02\x40') + sa + dn_list(2)))
    msgs.append(hs(14, b''))
    fl.s(record(22, b''.join(msgs), version))
    if cke is not None:
        fl.c(record(22, hs(16, cke), version), record(20, b'\x01', version), enc_hs())
    else:
        fl.c(record(20, b'\x01', version), enc_hs())
    if ticket:
        fl.s(record(22, hs(4, struct.pack('!I', 7200) + v16(filler(64))), version),
             record(20, b'\x01', version), enc_hs())
    else:
        fl.s(record(20, b'\x01', version), enc_hs())
    fl.c(record(23, filler(60), version))
    fl.s(record(23, filler(60), version))
    return fl.frames


def dh_params(plen=64, glen=1, yslen=64):
    return v16(filler(plen)) + v16(bytes([2]) * glen) + v16(filler(yslen))


def ecdh_params(curve=29, point=32, ctype=3):
    return bytes([ctype]) + struct.pack('!H', curve) + v8(filler(point))


def signed(ver12=True, alg=0x0401, siglen=64):
    return (struct.pack('!H', alg) if ver12 else b'') + v16(filler(siglen))


def build_main():
    F = []

    # --- A: ClientHello with the full Chrome-like extension set, TLS 1.2 handshake
    mark(F, 'Chrome-like ClientHello and an ECDHE_RSA handshake (TLS 1.2)')
    fl = Flow(50001, syn=True)
    ch = client_hello(0x0303, suites=[GREASE[0], 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9,
                                      0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035],
                      sid=filler(32), extensions=exts(*CHROME_EXTS))
    fl.c(record(22, ch, 0x0301))
    sh = server_hello(0x0303, 0xc02f, sid=filler(32), extensions=exts(
        ext(65281, v8(b'')), ext(23), ext(22), ext(35), ecpoint(0, 1, 2), ext(15, b'\x01'),
        alpn(b'h2'), ext(18, sct_list(sct(), sct(ts=1700000001000, exts_=b'\x01\x02'), sct(ver=1))),
        ext(5), ext(1, b'\x03'), ext(28, struct.pack('!H', 16385)),
        ext(13172, v8(b'h2') + v8(b'spdy/3')),
        ext(24, b'\x00\x0d' + v8(b'\x00\x01\x02')), ext(0x7777, filler(5)), ext(GREASE[1], b'')))
    cert_m = hs(11, cert_chain(2))
    ske = hs(12, ecdh_params() + signed())
    creq = hs(13, v8(b'\x01\x02\x40') + v16(u16s(0x0401, 0x0501, 0x0403)) + dn_list(3))
    fl.s(record(22, sh + cert_m + ske + creq + hs(14, b'')))
    fl.c(record(22, hs(11, cert_chain(1)) + hs(16, v8(filler(32))) + hs(15, signed()), 0x0303),
         record(20, b'\x01'), enc_hs())
    fl.s(record(22, hs(4, struct.pack('!I', 300) + v16(filler(100)))), record(20, b'\x01'), enc_hs())
    fl.c(record(23, filler(50)))
    fl.s(record(23, filler(50)))
    F += fl.frames

    # --- B: every key exchange, TLS 1.2
    mark(F, 'TLS 1.2 handshakes for every key exchange algorithm')
    port = 50100
    kex = [
        (0x002f, 'RSA', v16(filler(64)) and (hs(12, b'') and None), v16(filler(128))),
    ]
    # RSA (export style ServerKeyExchange with modulus and exponent), CKE EPMS
    ske_rsa = v16(filler(64)) + v16(b'\x01\x00\x01') + signed()
    F += tls12_flow(port, 0x002f, ske=ske_rsa, cke=v16(filler(128))); port += 1
    # DHE_RSA, DHE_DSS: ServerDHParams + signature, CKE Yc
    F += tls12_flow(port, 0x0033, ske=dh_params() + signed(), cke=v16(filler(64))); port += 1
    F += tls12_flow(port, 0x0032, ske=dh_params(128, 2, 128) + signed(alg=0x0202), cke=v16(filler(128))); port += 1
    # DH_anon: no signature
    F += tls12_flow(port, 0x0034, ske=dh_params(), cke=v16(filler(64)), certreq=False, cert_msg=False); port += 1
    # ECDHE_RSA, ECDHE_ECDSA, ECDH_ECDSA, ECDH_RSA: named curve
    F += tls12_flow(port, 0xc030, ske=ecdh_params(23, 65) + signed(), cke=v8(filler(65))); port += 1
    F += tls12_flow(port, 0xc02b, ske=ecdh_params(24, 97) + signed(alg=0x0503), cke=v8(filler(97))); port += 1
    F += tls12_flow(port, 0xc005, ske=ecdh_params() + signed(), cke=v8(filler(32))); port += 1
    F += tls12_flow(port, 0xc00f, ske=ecdh_params() + signed(), cke=v8(filler(32))); port += 1
    # ECDHE with explicit curve parameters: only named curves are decoded
    F += tls12_flow(port, 0xc02f, ske=ecdh_params(ctype=1) + filler(20), cke=v8(filler(32))); port += 1
    # ECDH_anon
    F += tls12_flow(port, 0xc018, ske=ecdh_params(), cke=v8(filler(32)), certreq=False, cert_msg=False); port += 1
    # PSK family
    F += tls12_flow(port, 0x008c, ske=v16(b'hint'), cke=v16(b'client identity'), certreq=False, cert_msg=False); port += 1
    F += tls12_flow(port, 0x0094, ske=v16(b'hint'), cke=v16(b'identity') + v16(filler(128)), certreq=False); port += 1
    F += tls12_flow(port, 0x0090, ske=v16(b'hint') + dh_params(), cke=v16(b'identity') + v16(filler(64)), certreq=False, cert_msg=False); port += 1
    F += tls12_flow(port, 0xc035, ske=v16(b'') + ecdh_params(), cke=v16(b'identity') + v8(filler(32)), certreq=False, cert_msg=False); port += 1
    # EC J-PAKE (Thread)
    F += tls12_flow(port, 0xc0ff, ske=ecdh_params() + v8(filler(65)) + v8(filler(65)) + v8(filler(32)),
                    cke=v8(filler(65)) + v8(filler(65)) + v8(filler(32)), certreq=False, cert_msg=False); port += 1
    F += tls12_flow(port, 0xc0ff, ske=ecdh_params(ctype=1), cke=v8(filler(65)) + v8(filler(65)) + v8(filler(32)),
                    certreq=False, cert_msg=False); port += 1
    # Kerberos, SRP: undecoded
    F += tls12_flow(port, 0x001e, ske=None, cke=filler(30), certreq=False); port += 1
    F += tls12_flow(port, 0xc01a, ske=filler(30), cke=filler(30), certreq=False); port += 1
    F += tls12_flow(port, 0xc01b, ske=filler(30), cke=filler(30), certreq=False); port += 1
    F += tls12_flow(port, 0xc01c, ske=filler(30), cke=filler(30), certreq=False); port += 1
    # ECC-SM2 (TLCP): signature only
    F += tls12_flow(port, 0xe013, version=0x0101, ske=signed(False), cke=v16(filler(100)), certreq=False); port += 1
    F += tls12_flow(port, 0xe011, version=0x0101, ske=signed(False), cke=v16(filler(100)), certreq=False); port += 1
    # unknown cipher suite, cipher suite 0
    F += tls12_flow(port, 0x1234, ske=filler(30), cke=filler(30), certreq=False); port += 1
    F += tls12_flow(port, 0x0000, ske=filler(30), cke=filler(30), certreq=False); port += 1

    # a CertificateRequest with more names than are added to the tree
    many = v8(b'\x01') + v16(u16s(0x0401)) + v16(b''.join(v16(name('CA %d' % i)) for i in range(105)))
    F += tls12_flow(port, 0xc02f, ske=ecdh_params() + signed(), cke=v8(filler(32)), certreq=many); port += 1

    # --- C: older versions
    mark(F, 'TLS 1.0, TLS 1.1 and SSL 3.0 handshakes')
    F += tls12_flow(port, 0x0033, version=0x0301, ske=dh_params() + signed(False), cke=v16(filler(64))); port += 1
    F += tls12_flow(port, 0xc014, version=0x0302, ske=ecdh_params() + signed(False), cke=v8(filler(32)), ch_version=0x0302); port += 1
    F += tls12_flow(port, 0x0035, version=0x0300, ske=v16(filler(64)) + v16(b'\x01\x00\x01') + v16(filler(64)), cke=filler(128), ch_version=0x0300, certreq=False); port += 1
    # SSL 3.0 Finished (MD5 and SHA hashes)
    fl = Flow(port, syn=False); port += 1
    fl.c(record(22, client_hello(0x0300, suites=(0x0005,), extensions=None), 0x0300))
    fl.s(record(22, server_hello(0x0300, 0x0005, extensions=None) + hs(11, cert_chain(1)) + hs(14, b''), 0x0300))
    fl.c(record(22, hs(16, filler(64)), 0x0300))
    fl.c(record(20, b'\x01', 0x0300))
    fl.c(record(22, hs(20, filler(36)), 0x0300))  # Finished in the clear (never encrypted here)
    F += fl.frames
    # resumed session with a session ID: abbreviated handshake
    fl = Flow(port, syn=False); port += 1
    sid = filler(32)
    fl.c(record(22, client_hello(0x0303, sid=sid, extensions=exts(ext(35, filler(48)), SNI))))
    fl.s(record(22, server_hello(0x0303, 0xc02f, sid=sid, extensions=exts(ext(23)))),
         record(20, b'\x01'), enc_hs())
    fl.c(record(20, b'\x01'), enc_hs())
    F += fl.frames
    # Renegotiation: a second handshake in the clear after the CCS
    fl = Flow(port, syn=False); port += 1
    fl.c(record(22, client_hello()))
    fl.s(record(22, server_hello() + hs(11, cert_chain(1)) + hs(14, b'')))
    fl.c(record(22, hs(16, v8(filler(32)))), record(20, b'\x01'), enc_hs())
    fl.s(record(20, b'\x01'), enc_hs())
    fl.c(record(22, client_hello(extensions=exts(ext(65281, v8(filler(12)))))))
    fl.s(record(22, server_hello(extensions=exts(ext(65281, v8(filler(24)))))))
    F += fl.frames

    # --- D: message types
    mark(F, 'HelloRequest, CertificateURL, CertificateStatus, hello retry request, other handshake types')
    fl = Flow(port, syn=False); port += 1
    fl.c(record(22, client_hello(extensions=exts(ext(2), ext(5, b'\x01' + v16(b'abc') + v16(b'de'))))))
    fl.s(record(22, hs(0, b'') + server_hello(extensions=exts(ext(2), ext(5))) + hs(11, cert_chain(1)) +
                 hs(22, b'\x01' + v24(ocsp_response(0))) + hs(14, b'')))
    fl.s(record(22, hs(22, b'\x02' + v24(v24(ocsp_response(0)) + v24(ocsp_response(1))))))
    fl.s(record(22, hs(21, b'\x01' + v16(v16(b'http://example.com/c1.der') + b'\x01' + filler(20) +
                                        v16(b'http://example.com/c2.der') + b'\x01' + filler(20)))))
    fl.s(record(22, hs(99, b'\x00\x01\x02')))                    # unknown handshake type
    fl.s(record(22, hs(24, b'\x01') + hs(23, b'\x00\x00\x00')))  # KeyUpdate in TLS 1.2, SupplementalData
    F += fl.frames
    # draft style HelloRetryRequest (msg type 6) and old HRR drafts
    fl = Flow(port, syn=False); port += 1
    fl.c(record(22, client_hello(extensions=exts(ext(43, v8(u16s(0x7f17))), key_share_ch(29)))))
    fl.s(record(22, hs(6, struct.pack('!H', 0x7f17) + struct.pack('!H', 0x1301) + exts(ext(43, struct.pack('!H', 0x7f17)), ext(51, struct.pack('!H', 23))))))
    fl.c(record(22, client_hello(extensions=exts(ext(43, v8(u16s(0x7f12))), key_share_ch(23)))))
    fl.s(record(22, hs(6, struct.pack('!H', 0x7f12) + exts(ext(44, v16(b'cookie'))))))
    F += fl.frames

    # --- E: TLS 1.3
    mark(F, 'TLS 1.3 handshakes: HelloRetryRequest, key shares, pre-shared key, early data, plaintext post-ServerHello messages')
    fl = Flow(port, syn=False); port += 1
    ch13 = client_hello(0x0303, suites=(0x1301, 0x1302, 0x1303), sid=filler(32), extensions=exts(
        SNI, groups(29, 23, 24, 0x0100, 0x0101), sigalgs(), sigalgs(50), ext(43, v8(u16s(0x0304, 0x0303))),
        ext(45, v8(b'\x00\x01')), key_share_ch(29), ext(49), ext(42), ext(44, v16(b'cookie-data')),
        ext(47, dn_list(2)), ext(34, v16(u16s(0x0403, 0x0804))),
        ext(48, v16(oid_filter(oid('2.5.29.37'), seq(seq(oid('1.3.6.1.5.5.7.3.2')))) + oid_filter(oid('2.5.29.17'), b''))),
        ext(41, v16(v16(filler(16)) + struct.pack('!I', 0x1234) + v16(filler(8)) + struct.pack('!I', 0x5678)) +
            v16(v8(filler(32)) + v8(filler(32)))),
        ext(54, v8(filler(4))), ext(3, v16(b'\x00' + b'\x01' + filler(20) + b'\x02' + v16(name('CA')) + b'\x03' + filler(20) + b'\x09')),
        ext(25, v16(b'')), ext(9, v8(b'\x00\x02')), ext(19, v8(b'\x00\x02')), ext(20, v8(b'\x02\x00')), ext(0x7777, b'')))
    fl.c(record(22, ch13, 0x0301))
    hrr = server_hello(0x0303, 0x1301, random32=HRR_RANDOM, sid=b'',
                       extensions=exts(ext(43, struct.pack('!H', 0x0304)), ext(51, struct.pack('!H', 23)),
                                       ext(44, v16(b'cookie-data')), ext(65037, filler(8))))
    fl.s(record(22, hrr))
    fl.c(record(20, b'\x01'), record(22, ch13, 0x0303))
    sh13 = server_hello(0x0303, 0x1301, extensions=exts(ext(43, struct.pack('!H', 0x0304)),
                                                      ext(51, struct.pack('!H', 29) + v16(filler(32))),
                                                      ext(41, b'\x00\x00')))
    fl.s(record(22, sh13), record(20, b'\x01'))
    # plaintext handshake messages after the ServerHello in TLS 1.3
    ee = hs(8, exts(ext(10, v16(u16s(29))), alpn(b'h2'), ext(17613, b'settings'), ext(42), ext(16, v16(v8(b'h3'))),
                    ext(65037, v16(ech_config() + ech_config(cfg_id=8, kem=0x10, cipher_suites=((2, 3),), exts_=b'\x00\x01\x00\x00'))), ext(65486, filler(16)),
                    ext(57, quic_tp_new(True)), ext(65445, quic_tp_new(True)), ext(18, sct_list(sct())),
                    ext(1, b'\x01'), ext(0x7777, b'x')))
    ee2 = hs(8, exts(ext(57, quic_tp_old())))
    cert13 = hs(11, b'\x04ctxt' + v24(
        v24(cert('tls13.example.com')) + exts(
            ext(5, b'\x01' + v24(ocsp_response(0))),
            ext(5, b'\x02' + v24(v24(ocsp_response(0)) + v24(ocsp_response(2)))),
            ext(18, sct_list(sct())), ext(0x7777, b''),
        ext(34, struct.pack('!I', 3600) + u16s(0x0804) + v24(spki_rsa()) + u16s(0x0804) + v16(filler(64)))) +
        v24(cert('inter.example.com')) + exts()))
    creq13 = hs(13, b'\x04ctxt' + exts(sigalgs(), ext(47, dn_list(2)), ext(27, v8(u16s(1, 2, 3))), ext(50, v16(u16s(0x0403))),
                                       ext(48, v16(oid_filter(oid('2.5.29.37'), seq(seq(oid('1.3.6.1.5.5.7.3.2')))))),
                                       ext(0x7777, b'')))
    cv = hs(15, signed(alg=0x0804, siglen=256))
    fin = hs(20, filler(32))
    fl.s(record(22, ee + cert13 + creq13 + cv + fin))
    fl.s(record(22, ee2))
    nst = hs(4, struct.pack('!II', 86400, 0x11223344) + v8(b'\x00\x01') + v16(filler(80)) + exts(ext(42, struct.pack('!I', 16384)), ext(0x7777, b'')))
    fl.s(record(22, nst))
    fl.s(record(22, hs(24, b'\x01')))
    fl.c(record(22, hs(5, b'') + hs(24, b'\x00') + hs(20, filler(32))))
    # raw public key certificates and the certificate_authorities in the Certificate message
    F += fl.frames

    # TLS 1.3 certificate compression (zlib)
    mark(F, 'Compressed certificate (zlib)')
    fl = Flow(port, syn=False); port += 1
    fl.c(record(22, client_hello(extensions=exts(ext(43, v8(u16s(0x0304))), ext(27, v8(u16s(1, 2, 3)))))))
    fl.s(record(22, server_hello(extensions=exts(ext(43, struct.pack('!H', 0x0304)), ext(51, struct.pack('!H', 29) + v16(filler(32)))))))
    body = b'\x00' + v24(v24(cert('compressed.example.com')) + exts())
    z = zlib.compress(body, 9)
    fl.s(record(22, hs(25, struct.pack('!H', 1) + len(body).to_bytes(3, 'big') + v24(z))))
    fl.s(record(22, hs(25, struct.pack('!H', 2) + len(body).to_bytes(3, 'big') + v24(filler(30)))))  # brotli
    fl.s(record(22, hs(25, struct.pack('!H', 3) + len(body).to_bytes(3, 'big') + v24(filler(30)))))  # zstd
    fl.s(record(22, hs(25, struct.pack('!H', 9) + len(body).to_bytes(3, 'big') + v24(filler(30)))))  # unknown algorithm
    F += fl.frames

    # --- F: raw public key certificate types negotiated
    mark(F, 'Raw public key certificates (RFC 7250)')
    fl = Flow(port, syn=False); port += 1
    fl.c(record(22, client_hello(extensions=exts(ext(19, v8(b'\x02\x00')), ext(20, v8(b'\x02\x00')), ext(9, v8(b'\x02\x00'))))))
    fl.s(record(22, server_hello(extensions=exts(ext(20, b'\x02'), ext(19, b'\x02'))) +
                hs(11, cert_chain(rpk=True)) + hs(13, v8(b'\x01') + v16(u16s(0x0401)) + v16(b'')) + hs(14, b'')))
    fl.c(record(22, hs(11, cert_chain(rpk=True))))
    F += fl.frames
    # server certificate type from the old cert_type extension
    fl = Flow(port, syn=False); port += 1
    fl.c(record(22, client_hello(extensions=exts(ext(9, v8(b'\x02\x00'))))))
    fl.s(record(22, server_hello(extensions=exts(ext(9, b'\x02'))) + hs(11, cert_chain(rpk=True))))
    F += fl.frames

    # --- G: extensions
    mark(F, 'ClientHello extensions: JA3 and JA4 variants, GREASE, empty vectors, ALPN, ESNI, ECH, QUIC transport parameters')
    fl = Flow(port, syn=False); port += 1
    # ClientHello without extensions; without cipher suites other than GREASE
    fl.c(record(22, client_hello(suites=(0xc02f,), extensions=None, comp=(0, 1, 64, 200))))
    fl.c(record(22, client_hello(suites=(GREASE[0],), extensions=exts())))
    # SNI of a non-host-name type only, empty SNI (server response style), ALPN with binary names
    fl.c(record(22, client_hello(extensions=exts(sni((1, 'x')), ext(16, v16(v8(b'\x01\xff') + v8(b'a\xf0'))), ext(0, b''),
                                                 ext(35, filler(10)), ext(13172), ext(23), ext(22)))))
    # ALPN starting with a non alphanumeric char (hex JA4)
    fl.c(record(22, client_hello(extensions=exts(alpn(b'/x/', b'h2'), ext(43, v8(u16s(0x0303, 0x0302, 0x0301, 0x0300))),
                                                 sigalgs(), ext(12, v8(b'srpuser')), ext(1, b'\x04'), ext(15, b'\x02'),
                                                 ext(3, v16(b'')),
                                                 ext(5, b'\x02' + v16(b'') + v16(b'')), ext(5, b'\x03'),
                                                 ext(5, b'\x01' + v16(b'\x00\x03abc') + v16(b'\x00\x03def')),
                                                 ext(17, v16(b'\x01' + v16(v16(b'ab') + v16(b'cd'))))))))
    # supported_versions with only unknown values, signature algorithm list variations
    fl.c(record(22, client_hello(extensions=exts(ext(43, v8(u16s(0x7f1c, 0xfb17, 0xfb1a, 0x0a0a, 0x1234))),
                                                 ext(0x0a0a, b''), ext(0x3a3a, b''), ext(13, v16(u16s(0x0a0a)))))))
    # ESNI, ECH outer extensions and outer ClientHello, connection ids, trusted CA keys
    fl.c(record(22, client_hello(extensions=exts(
        ext(65486, struct.pack('!H', 0x1301) + struct.pack('!H', 29) + v16(filler(32)) + v16(filler(32)) + v16(filler(50))),
        ext(65486, struct.pack('!H', 0x1301) + struct.pack('!H', 29) + v16(filler(32)) + v16(b'') + v16(b'')),
        ech_ch_outer(), ext(64768, v8(u16s(10, 13, 0xff01))), ext(53, v8(b'')), ext(54, v8(filler(8)))))))
    fl.c(record(22, client_hello(extensions=exts(ext(65037, b'\x01'), ext(64768, b'\x00\x00')))))
    fl.s(record(22, server_hello(extensions=exts(ext(54, v8(filler(5))), ext(53, v8(b'')), ext(0x7777, b'')))))
    # QUIC transport parameters in a TLS ClientHello (both extension types, both encodings)
    fl.c(record(22, client_hello(extensions=exts(ext(57, quic_tp_new()), ext(65445, quic_tp_old())))))
    fl.c(record(22, client_hello(extensions=exts(ext(57, quic_tp_new(True))))))
    # key share without entries; PSK without identities; ticket request, external ids, padding
    fl.c(record(22, client_hello(extensions=exts(ext(51, v16(b'')), ext(41, v16(v16(b'\x00') + b'\x00\x00\x00\x00') +
                                                                          v16(v8(filler(32))))
                                                 , ext(58, b'\x01\x02'), ext(55, b'x'), ext(56, b'y'), ext(59, b''),
                                                 ext(21, b''), ext(28, b'\x40\x01'), ext(25, v16(b''))))))
    F += fl.frames

    # --- H: reproducers of the fixed bugs
    mark(F, 'Reproducers: handshake fragment key, CCS state with -2, connection ID list, JA4 sorted lists')
    fl = Flow(54001, syn=False)
    fl.s(record(22, client_hello() + hs(11, b'\x01' * 10, 256)))
    fl.c(record(22, b'\x02' * 20))
    F += fl.frames
    fl = Flow(54002, syn=False)
    fl.c(record(20, b'\x01'))
    fl.c(record(22, hs(11, b'\x01' * 20, 256)))
    fl.c(record(22, client_hello()))
    fl.c(record(20, b'\x01'))
    F += fl.frames
    # connection ID extensions, repeated: the session is listed once
    cid = ext(54, v8(b'\xaa'))
    fl = Flow(54003, syn=False)
    fl.c(record(22, client_hello(extensions=exts(*([cid] * 40)))))
    F += fl.frames
    # JA4: ascending ciphers and extensions sorted before hashing
    ciphers = [v for v in range(0x0100, 0x0100 + 1500) if (v & 0x0f0f) != 0x0a0a][:1200]
    fl = Flow(54004, syn=False)
    body = (struct.pack('!H', 0x0303) + b'\x11' * 32 + b'\x00' + v16(u16s(*ciphers)) + b'\x01\x00' +
            exts(*[ext(t, b'') for t in range(0x4000, 0x4000 + 120)]))
    msg = hs(1, body)
    fl.c(*[record(22, msg[i:i + 16000]) for i in range(0, len(msg), 16000)])
    F += fl.frames
    JA4_CIPHERS = ciphers
    return F


def build_dtls():
    """DTLS over UDP found by the heuristic: extensions that only DTLS uses."""
    F = []
    mark(F, 'DTLS ClientHello / ServerHello with use_srtp, connection ID and cookie, then CID records')

    def drec(ctype, body, epoch=0, seqn=0, version=0xfefd):
        return struct.pack('!BHH', ctype, version, epoch) + seqn.to_bytes(6, 'big') + v16(body)

    def dhs(mtype, body, mseq=0):
        return struct.pack('!B', mtype) + len(body).to_bytes(3, 'big') + struct.pack('!H', mseq) + \
            b'\0\0\0' + len(body).to_bytes(3, 'big') + body

    def dgram(sport, dport, data, rev=False):
        if rev:
            sport, dport = dport, sport
        return udp_frame(sport, dport, data, rev=rev)

    cid = ext(54, v8(b'\x01\x02\x03\x04'))
    chx = exts(ext(14, v16(u16s(1, 2)) + v8(b'\x01')), cid, ext(0, v16(b'\x00' + v16(b'dtls.example'))),
               alpn(b'coap'), ext(43, v8(u16s(0xfefd, 0xfefc))), ext(13, v16(u16s(0x0403))))
    ch0 = struct.pack('!H', 0xfefd) + filler(32) + v8(b'') + v8(b'') + v16(u16s(0xc02b, 0xc02f)) + v8(b'\0')
    F.append(dgram(40000, 5684, drec(22, dhs(1, ch0, 0))))
    F.append(dgram(40000, 5684, drec(22, dhs(3, struct.pack('!H', 0xfefd) + v8(b'cookie1'))), rev=True))
    ch = struct.pack('!H', 0xfefd) + filler(32) + v8(b'') + v8(b'cookie1') + v16(u16s(0xc02b, 0xc02f)) + v8(b'\0') + chx
    F.append(dgram(40000, 5684, drec(22, dhs(1, ch, 1))))
    shx = exts(ext(14, v16(u16s(1)) + v8(b'')), ext(54, v8(b'\x05\x06')), alpn(b'coap'))
    sh = struct.pack('!H', 0xfefd) + filler(32) + v8(b'') + struct.pack('!HB', 0xc02b, 0) + shx
    F.append(dgram(40000, 5684, drec(22, dhs(2, sh, 1)), rev=True))
    # deprecated connection id extension
    chx2 = exts(ext(53, v8(b'\x09\x08')))
    ch2 = struct.pack('!H', 0xfefd) + filler(32) + v8(b'') + v8(b'') + v16(u16s(0xc02b)) + v8(b'\0') + chx2
    F.append(dgram(40001, 5684, drec(22, dhs(1, ch2, 0))))
    # CID records of the first connection (server CID 5,6 / client CID 1,2,3,4 in the extensions)
    F.append(dgram(40000, 5684, struct.pack('!BHH', 25, 0xfefd, 1) + (5).to_bytes(6, 'big') + b'\x01\x02\x03\x04' + v16(filler(20)), rev=True))
    F.append(dgram(40000, 5684, struct.pack('!BHH', 25, 0xfefd, 1) + (6).to_bytes(6, 'big') + b'\x05\x06' + v16(filler(20))))
    return F


def build_malformed():
    F = []
    mark(F, 'Vectors that end early or run past their end, illegal key exchanges')
    port = 56000
    # illegal ServerKeyExchange for DH_RSA, Kerberos
    F += tls12_flow(port, 0x0031, ske=filler(30), cke=v16(filler(64)), certreq=False); port += 1
    F += tls12_flow(port, 0x001e, ske=filler(30), cke=filler(30), certreq=False); port += 1
    # bad extension lengths: every vector too short or too long
    fl = Flow(port, syn=False); port += 1
    for e in [
        ext(0, v16(b'\x00' + struct.pack('!H', 20) + b'ab')),
        ext(0, v16(b'\x00\x00\x00')),
        ext(10, v16(b'\x00\x04\x00\x1d\x00')),
        ext(10, b'\x00\x02\x00'),
        ext(12, v8(b'abcdefgh')[:3]),
        ext(13, v16(b'\x04\x03\x08')),
        ext(13, b'\x00\x01\x04'),
        ext(16, v16(b'\x05ab')),
        ext(16, b'\x00'),
        ext(17, v16(b'\x01\x00\x08\x00\x00\x00\x00')),
        ext(43, v8(b'\x03\x04\x03')),
        ext(41, v16(v16(b'\x00' * 4)[:5])),
        ext(41, b'\x00\x08' + b'\x00\x01a\x00\x00\x00\x00' + b'\x00\x00'),
        ext(45, v8(b'')),
        ext(44, v16(b'')),
        ext(47, b'\x00\x05\x00\x08ab'),
        ext(47, b'\x00\x08' + v16(b'abc') + b'\x00'),
        ext(48, b'\x00\x08\x03\x06\x03abc'),
        ext(13172, b'\x08ab'),
        ext(65281, b'\x05ab'),
        ext(27, v8(b'\x00\x01\x00')),
        ext(24, b'\x00\x0d\x03\x00'),
        ext(17513, b'\x00\x05\x03a'),
        ext(51, b'\x00\x06\x00\x1d\x00\x20ab'),
        ext(51, b'\x00\x08\x00\x1d\x00\x01a\x00\x1d\x00\x01a'),
        ext(65486, struct.pack('!H', 0x1301) + b'\x00\x1d\x00\x01a\x00\x10'),
        ext(65037, b'\x00' + u16s(1, 1) + b'\x07' + b'\x00\x02ab' + b'\x00\x20'),
        ext(64768, v8(b'\x00\x0a\x00')),
        ext(64768, v8(b'\x00')),
        ext(54, v8(b'\x08ab')[:1] + b'\x08ab'),
        ext(3, v16(b'\x02\x00\x08ab')),
        ext(3, v16(b'\x01' + filler(5))),
        ext(57, quic_tp_new()[:50]),
        ext(57, b'\x00\x08' + struct.pack('!HH', 0, 20) + b'ab'),
        ext(57, b'\x00\x03' + b'\x0d\x04' + b'a'),
        ext(57, varint(0x0d) + varint(40) + filler(30) + b'\x1f' + filler(10)),
        ext(57, varint(0x0d) + varint(45) + bytes(4) + bytes(2) + bytes(16) + bytes(2) + b'\x15' + filler(22)),
        ext(0x1234, b''),
    ]:
        fl.c(record(22, client_hello(extensions=exts(e))))
    # ClientHello vectors: cipher suites odd length, compression methods missing, SNI before end
    fl.c(record(22, hs(1, struct.pack('!H', 0x0303) + filler(32) + b'\x00' + b'\x00\x03\xc0\x2f\x00' + b'\x00')))
    fl.c(record(22, hs(1, struct.pack('!H', 0x0303) + filler(32) + b'\x00' + b'\x00\x02\xc0\x2f')))
    fl.c(record(22, hs(1, struct.pack('!H', 0x0303) + filler(32) + b'\x00' + b'\x00\x01')))
    F += fl.frames
    # ServerHello / NewSessionTicket / Certificate / CertificateRequest with broken vectors
    fl = Flow(port, syn=False); port += 1
    fl.c(record(22, client_hello()))
    fl.s(record(22, server_hello(extensions=exts(ext(14, b'\x00\x08\x00\x01'), ext(16, b'\x00\x03\x05'),
                                                  ext(51, b'\x00\x1d\x00\x08ab'), ext(20, b''), ext(0x1234, b'a')))))
    fl.s(record(22, hs(4, struct.pack('!I', 100) + b'\x00\x20ab')))
    fl.s(record(22, hs(11, b'\x00\x00\x10\x00\x00\x20ab')))
    fl.s(record(22, hs(11, b'\x00\x00\x00')))
    fl.s(record(22, hs(13, b'\x03\x01\x02')))
    fl.s(record(22, hs(13, v8(b'\x01') + v16(b'\x04\x01\x05') + v16(v16(b'abc')))))
    fl.s(record(22, hs(13, v8(b'\x01') + v16(u16s(0x0401)) + b'\x00\x08\x00\x02ab')))
    fl.s(record(22, hs(21, b'\x01\x00\x10\x00\x20' + b'abc')))
    fl.s(record(22, hs(12, ecdh_params())))     # not enough data for the signature
    fl.s(record(22, hs(22, b'\x01\x00\x00\x40' + b'abc')))
    fl.s(record(22, hs(22, b'\x02\x00\x00\x03abc')))
    fl.s(record(22, hs(25, struct.pack('!H', 1) + b'\x00\x00\x10\x00\x00\x08abc')))
    fl.s(record(22, hs(11, b'')))
    F += fl.frames
    # versions that must be ignored in the hello messages, ECH configs of an unknown version
    fl = Flow(port, syn=False); port += 1
    fl.c(record(22, client_hello(version=0x0304)))
    fl.s(record(22, server_hello(version=0x0304)))
    fl.c(record(22, client_hello(extensions=exts(ext(43, v8(u16s(0x0304)))))))
    fl.s(record(22, server_hello(extensions=exts(ext(43, struct.pack('!H', 0x0304)), ext(51, struct.pack('!H', 29) + v16(filler(32)))))))
    fl.s(record(22, hs(8, exts(ext(65037, v16(ech_config(version=0xfe0e) + ech_config(exts_=b'\x00\x01\x00\x00'))), ext(65037, b'\x00\x0d')))))
    body = b'\x00' + v24(v24(cert('compressed.example.com')) + exts())
    z = zlib.compress(body, 9)
    fl.s(record(22, hs(25, struct.pack('!H', 1) + (len(body) + 5).to_bytes(3, 'big') + v24(z))))
    fl.s(record(22, hs(25, struct.pack('!H', 1) + len(body).to_bytes(3, 'big') + v24(b'notzlib'))))
    F += fl.frames
    # TLS 1.3 certificate with broken request context / extensions
    fl = Flow(port, syn=False); port += 1
    fl.c(record(22, client_hello(extensions=exts(ext(43, v8(u16s(0x0304)))))))
    fl.s(record(22, server_hello(extensions=exts(ext(43, struct.pack('!H', 0x0304)), ext(51, struct.pack('!H', 29) + v16(filler(32)))))))
    fl.s(record(22, hs(11, b'\x08ab')))
    fl.s(record(22, hs(11, b'\x00\x00\x00\x30\x00\x00\x20abcd')))
    fl.s(record(22, hs(13, b'\x09ab')))
    fl.s(record(22, hs(4, struct.pack('!II', 0, 0) + b'\x09ab')))
    fl.s(record(22, hs(4, struct.pack('!II', 0, 0) + b'\x00\x00\x08' + b'abc')))
    fl.s(record(22, hs(8, b'\x00\x10\x00\x2a')))
    F += fl.frames
    # DTLS 1.3 version in the hello messages, a cookie longer than 32 octets
    def dhs(mtype, body, mseq=0):
        return struct.pack('!B', mtype) + len(body).to_bytes(3, 'big') + struct.pack('!H', mseq) + \
            b'\0\0\0' + len(body).to_bytes(3, 'big') + body

    def drec(body):
        return struct.pack('!BHH', 22, 0xfefd, 0) + (0).to_bytes(6, 'big') + v16(body)

    ch = struct.pack('!H', 0xfefc) + filler(32) + v8(b'') + v8(filler(40)) + v16(u16s(0xc02b)) + v8(b'\0')
    F.append(udp_frame(41000, 5684, drec(dhs(1, ch))))
    ch = struct.pack('!H', 0xfefc) + filler(32) + v8(b'') + v8(b'') + v16(u16s(0xc02b)) + v8(b'\0')
    F.append(udp_frame(41001, 5684, drec(dhs(1, ch))))
    sh = struct.pack('!H', 0xfefc) + filler(32) + v8(b'') + struct.pack('!HB', 0xc02b, 0)
    F.append(udp_frame(5684, 41001, drec(dhs(2, sh)), rev=True))
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('-') else '.'
    global marks
    main_frames = build_main()
    n_tcp = len(main_frames)
    base = len(main_frames)
    dt = build_dtls()
    marks = [(i + (base if lbl.startswith('DTLS') else 0), lbl) for i, lbl in marks]
    main_frames += dt
    write_pcap(os.path.join(out, 'tls-utils-coverage.pcap'), main_frames)
    marks.append((len(main_frames), 'end'))
    mal_marks_start = len(marks)
    mal = build_malformed()
    write_pcap(os.path.join(out, 'tls-utils-coverage-malformed.pcap'), mal)
    if VERBOSE:
        print('main frames:', len(main_frames), 'malformed frames:', len(mal))
        for i, lbl in marks:
            print(i + 1, lbl)


if __name__ == '__main__':
    main()
