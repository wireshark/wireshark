#!/usr/bin/env python3
# Generates test/captures/ocsp_coverage.pcapng.gz, ocsp_nesting.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic OCSP coverage captures.

Usage: mkocsp.py <outdir>
Writes ocsp-coverage.pcapng (Exported PDU ocsp_req/ocsp_res frames and an
HTTP POST/200 pair over TCP port 80) and ocsp-coverage-malformed.pcapng.
Certificates have placeholder keys/signatures, no crypto."""
import struct
import sys


# ------------------------------------------------------------ DER helpers
def tlv(tag, content=b''):
    n = len(content)
    if n < 0x80:
        ln = bytes([n])
    elif n < 0x100:
        ln = bytes([0x81, n])
    elif n < 0x10000:
        ln = bytes([0x82]) + struct.pack('>H', n)
    else:
        ln = bytes([0x83]) + n.to_bytes(3, 'big')
    return bytes([tag]) + ln + content


def seq(*parts):
    return tlv(0x30, b''.join(parts))


def sset(*parts):
    return tlv(0x31, b''.join(parts))


def ctx(n, content, constructed=True):
    return tlv((0xa0 if constructed else 0x80) | n, content)


def oid(dotted):
    p = [int(x) for x in dotted.split('.')]
    out = bytearray([40 * p[0] + p[1]])
    for v in p[2:]:
        chunk = [v & 0x7f]
        v >>= 7
        while v:
            chunk.append(0x80 | (v & 0x7f))
            v >>= 7
        out += bytes(reversed(chunk))
    return tlv(0x06, bytes(out))


def integer(v):
    n = max(1, (v.bit_length() + 8) // 8)
    return tlv(0x02, v.to_bytes(n, 'big', signed=True))


def boolean(v):
    return tlv(0x01, b'\xff' if v else b'\x00')


def octets(b):
    return tlv(0x04, b)


def bitstr(b, unused=0):
    return tlv(0x03, bytes([unused]) + b)


def ia5(s):
    return tlv(0x16, s.encode())


def utf8(s):
    return tlv(0x0c, s.encode())


def printable(s):
    return tlv(0x13, s.encode())


def gtime(s):
    return tlv(0x18, s.encode())


def null():
    return tlv(0x05)


SHA256_RSA = '1.2.840.113549.1.1.11'
SHA1 = '1.3.14.3.2.26'


def algid(o, params=True):
    return seq(oid(o), null()) if params else seq(oid(o))


def name(cn):
    return seq(sset(seq(oid('2.5.4.3'), utf8(cn))))


def extension(o, value, critical=False):
    return seq(oid(o), *( [boolean(True)] if critical else [] ), octets(value))


def certificate(exts, cn='Synthetic Test CA', serial=0x1234):
    """X.509 v3 certificate with placeholder key and signature bytes."""
    tbs = seq(ctx(0, integer(2)), integer(serial), algid(SHA256_RSA), name(cn),
              seq(tlv(0x17, b'200101000000Z'), tlv(0x17, b'400101000000Z')),
              name('Subject ' + cn),
              seq(algid('1.2.840.113549.1.1.1'), bitstr(seq(integer(0xc5a3 << 112 | 0x1b), integer(65537)))),
              ctx(3, seq(*exts)))
    return seq(tbs, algid(SHA256_RSA), bitstr(b'\x00' * 16))


def exp_pdu(name_, payload):
    n = name_.encode()
    pad = (4 - len(n) % 4) % 4
    return struct.pack('>HH', 12, len(n) + pad) + n + b'\0' * pad + \
        struct.pack('>HH', 0, 0) + payload


def pcap(path, frames, linktype=252):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, p in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
            f.write(p)


def pcapng(path, frames):
    """frames: list of (linktype, bytes); one IDB per distinct link type."""
    def block(btype, body):
        pad = (4 - len(body) % 4) % 4
        total = 12 + len(body) + pad
        return struct.pack('<II', btype, total) + body + b'\0' * pad + struct.pack('<I', total)
    out = block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    ids = {}
    for lt, _ in frames:
        if lt not in ids:
            ids[lt] = len(ids)
            out += block(1, struct.pack('<HHI', lt, 0, 262144))
    for i, (lt, p) in enumerate(frames):
        ts = (1700000000 + i) * 1000000
        out += block(6, struct.pack('<IIIII', ids[lt], ts >> 32, ts & 0xffffffff, len(p), len(p)) + p)
    open(path, 'wb').write(out)


def ip_tcp(payload, sport, dport, seq_, ack, flags=0x18, src='192.0.2.1', dst='192.0.2.2'):
    tcp = struct.pack('>HHIIBBHHH', sport, dport, seq_, ack, 0x50, flags, 65535, 0, 0) + payload
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), 1, 0x4000, 64, 6, 0,
                     bytes(map(int, src.split('.'))), bytes(map(int, dst.split('.')))) + tcp
    return b'\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x08\x00' + ip


BASIC = '1.3.6.1.5.5.7.48.1.1'
NONCE = '1.3.6.1.5.5.7.48.1.2'
CRL = '1.3.6.1.5.5.7.48.1.3'
ACCEPTABLE = '1.3.6.1.5.5.7.48.1.4'
NOCHECK = '1.3.6.1.5.5.7.48.1.5'
CUTOFF = '1.3.6.1.5.5.7.48.1.6'
LOCATOR = '1.3.6.1.5.5.7.48.1.7'
AD_OCSP = '1.3.6.1.5.5.7.48.1'


def cert_id(serial=0x1234, alg=SHA1):
    return seq(algid(alg), octets(bytes(range(20))), octets(bytes(range(20, 40))), integer(serial))


def exts(*items):
    return seq(*items)


def nonce_ext(n=b'0123456789abcdef'):
    return extension(NONCE, octets(n))


def locator_ext():
    loc = seq(name('Issuer CA'),
              seq(seq(oid(AD_OCSP), tlv(0x86, b'http://ocsp.example.test/'))))
    return extension(LOCATOR, loc)


def crl_ext(full=True):
    parts = []
    if full:
        parts = [ctx(0, ia5('http://crl.example.test/ca.crl')), ctx(1, integer(42)),
                 ctx(2, gtime('20260101000000Z'))]
    return extension(CRL, seq(*parts))


def request(reqs, version=False, requestor=False, request_exts=None, signed=False):
    tbs = b''
    if version:
        tbs += ctx(0, integer(0))
    if requestor:
        tbs += ctx(1, tlv(0xa4, name('Requestor')))
    tbs += seq(*reqs)
    if request_exts:
        tbs += ctx(2, exts(*request_exts))
    tbs = seq(tbs)
    out = seq(tbs)
    if signed:
        out = seq(tbs, ctx(0, seq(algid(SHA256_RSA), bitstr(b'\x00' * 16),
                                  ctx(0, seq(certificate([extension(NOCHECK, null())], 'Requestor CA'))))))
    return out


def single(status, with_next=True, single_exts=None, serial=0x1234):
    st = {'good': tlv(0x80), 'unknown': tlv(0x82),
          'revoked': tlv(0xa1, gtime('20251231235959Z') + ctx(0, tlv(0x0a, b'\x01'))),
          'revoked_noreason': tlv(0xa1, gtime('20251231235959Z'))}[status]
    s = cert_id(serial) + st + gtime('20260101000000Z')
    if with_next:
        s += ctx(0, gtime('20260108000000Z'))
    if single_exts:
        s += ctx(1, exts(*single_exts))
    return seq(s)


def basic_response(responses, by='key', version=False, resp_exts=None, certs=None, producedat='20260101000000Z'):
    rid = ctx(2, octets(b'\x01' * 20)) if by == 'key' else ctx(1, name('OCSP Responder'))
    rd = (ctx(0, integer(0)) if version else b'') + rid + gtime(producedat) + seq(*responses)
    if resp_exts:
        rd += ctx(1, exts(*resp_exts))
    body = seq(rd) + algid(SHA256_RSA) + bitstr(b'\x00' * 16)
    if certs:
        body += ctx(0, seq(*certs))
    return seq(body)


def response(status, basic=None, rtype=BASIC):
    out = tlv(0x0a, bytes([status]))
    if basic is not None:
        out += ctx(0, seq(oid(rtype), octets(basic)))
    return seq(out)


def nested(depth):
    """BasicOCSPResponse whose response extension holds another one."""
    msg = None
    for _ in range(depth):
        ext = [extension(BASIC, msg)] if msg is not None else None
        msg = basic_response([], resp_exts=ext)
    return response(0, msg)


def main(out):
    nc = [certificate([extension(NOCHECK, null())], 'OCSP Responder')]
    reqs = [
        request([seq(cert_id())]),
        request([seq(cert_id(1)), seq(cert_id(2, SHA256_RSA.replace('.11', '.11')),
                                      ctx(0, exts(locator_ext())))],
                version=True, requestor=True, request_exts=[nonce_ext()]),
        request([seq(cert_id())], signed=True),
    ]
    resps = [
        response(0, basic_response([single('good')])),
        response(0, basic_response([single('revoked', single_exts=[crl_ext(), extension(CUTOFF, gtime('20250101000000Z'))]),
                                    single('unknown', False), single('revoked_noreason', serial=7)],
                                   by='name', version=True,
                                   resp_exts=[nonce_ext(), extension(ACCEPTABLE, seq(oid(BASIC))),
                                              extension(NOCHECK, null()), locator_ext(),
                                              extension(NOCHECK, null(), True)],
                                   certs=nc)),
        response(0, basic_response([single('good', single_exts=[crl_ext(False)])], resp_exts=[nonce_ext(b'')])),
    ] + [response(s) for s in (1, 2, 3, 5, 6)]
    # response whose responseType is not the basic type, and one without bytes
    resps.append(response(0, b'\x04\x02\x01\x02', '1.3.6.1.5.5.7.48.1.99'))

    http_req = (b'POST /ocsp HTTP/1.1\r\nHost: ocsp.example.test\r\n'
                b'Content-Type: application/ocsp-request\r\nContent-Length: %d\r\n\r\n' % len(reqs[0])) + reqs[0]
    http_resp = (b'HTTP/1.1 200 OK\r\nContent-Type: application/ocsp-response\r\n'
                 b'Content-Length: %d\r\n\r\n' % len(resps[0])) + resps[0]

    frames = []
    for r in reqs:
        frames.append((252, exp_pdu('ocsp_req', r)))
    for r in resps:
        frames.append((252, exp_pdu('ocsp_res', r)))
    frames.append((1, ip_tcp(http_req, 40000, 80, 1, 1)))
    frames.append((1, ip_tcp(http_resp, 80, 40000, 1, 1 + len(http_req))))
    # BasicOCSPResponse nested twice through its own extension: fine
    frames.append((252, exp_pdu('ocsp_res', nested(2))))
    pcapng(out + '/ocsp-coverage.pcapng', frames)
    # the fixed bug: BER OID callbacks nest BasicOCSPResponse inside its own
    # extension; stops at 32 levels with an expert info instead of aborting
    pcapng(out + '/ocsp-nesting.pcapng', [(252, exp_pdu('ocsp_res', nested(40)))])

    mal = [
        (252, exp_pdu('ocsp_req', reqs[0][:30])),                       # truncated
        (252, exp_pdu('ocsp_res', resps[0][:40])),                      # truncated response
        (252, exp_pdu('ocsp_res', seq(tlv(0x0a, b'\x07')))),            # unknown status
        (252, exp_pdu('ocsp_res', nested(600))),                       # the original reproducer (depth 600)
        (252, exp_pdu('ocsp_req', seq(seq(seq(seq(integer(1))))))),     # wrong structure
        (252, exp_pdu('ocsp_res', response(0, basic_response([single('good')])[:60]))),
        (252, exp_pdu('ocsp_res', response(0, b'\x30\x03\x02\x01\x00'))),  # bad basic response
    ]
    pcapng(out + '/ocsp-coverage-malformed.pcapng', mal)


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')
