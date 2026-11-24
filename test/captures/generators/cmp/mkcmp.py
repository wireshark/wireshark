#!/usr/bin/env python3
# Generates test/captures/cmp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the Certificate Management
Protocol dissector (packet-cmp.c, generated from asn1/cmp/).

CMP PKIMessages are carried
  - over TCP port 829 with the RFC 2510 TCP transport header (length,
    type) and with the "Transport Protocols for CMP" draft header
    (length, version 10, flags, type),
  - over HTTP with the media types application/pkixcmp and
    application/x-pkixcmp (a bare PKIMessage) and application/pkixcmp-poll
    and application/x-pkixcmp-poll (a TCP-transport style PDU),
  - over HTTP without a usable Content-Type on TCP ports 8080 and 8081,
    which the cmp.http_alternate_port and cmp.tcp_style_http_alternate_port
    preferences hand to CMP.

Every packet is built from scratch with struct and a small DER encoder;
the certificates, CRLs, keys and signatures are made up. Nothing comes
from a real network.

Usage: mkcmp.py <output directory>

Writes:
  cmp-coverage.pcap            every PKIBody choice, the PKIHeader optional
                               fields, every registered InfoTypeAndValue
                               and registration control OID, protection,
                               extraCerts, the TCP transport types in both
                               header styles, TCP reassembly, the HTTP media
                               types and the reproducer frames
  cmp-coverage-malformed.pcap  truncated and bad BER, short TCP transport
                               PDUs, the original reproducer frame 2
"""

import os
import struct
import sys

# ---------------------------------------------------------------- DER

def length(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(b)]) + b


def tlv(tag, content):
    return bytes([tag]) + length(len(content)) + content


def seq(*items):
    return tlv(0x30, b''.join(items))


def set_(*items):
    return tlv(0x31, b''.join(items))


def ctx(n, content, constructed=True):
    """Context tag [n]; explicit (constructed) by default."""
    return tlv((0xa0 if constructed else 0x80) | n, content)


def integer(v):
    if v == 0:
        b = b'\0'
    else:
        b = v.to_bytes((v.bit_length() + 8) // 8, 'big', signed=True)
    return tlv(0x02, b)


def boolean(v):
    return tlv(0x01, b'\xff' if v else b'\0')


def null():
    return b'\x05\x00'


def enumerated(v):
    return tlv(0x0a, bytes([v]))


def oid(s):
    parts = [int(x) for x in s.split('.')]
    out = bytes([parts[0] * 40 + parts[1]])
    for p in parts[2:]:
        enc = [p & 0x7f]
        p >>= 7
        while p:
            enc.append(0x80 | (p & 0x7f))
            p >>= 7
        out += bytes(reversed(enc))
    return tlv(0x06, out)


def octets(b):
    return tlv(0x04, b)


def bits(b, unused=0):
    return tlv(0x03, bytes([unused]) + b)


def utf8(s):
    return tlv(0x0c, s.encode())


def printable(s):
    return tlv(0x13, s.encode())


def ia5(s):
    return tlv(0x16, s.encode())


def utctime(s):
    return tlv(0x17, s.encode())


def gentime(s):
    return tlv(0x18, s.encode())


def retag(tag, der):
    """Replace the tag of a DER element (IMPLICIT tagging)."""
    n = 2 if der[1] < 0x80 else 2 + (der[1] & 0x7f)
    return tlv(tag, der[n:])


def filler(n, seed):
    return bytes(((seed * 31 + i * 7) & 0xff) for i in range(n))

# ---------------------------------------------------------------- PKIX

RSA = '1.2.840.113549.1.1.1'
SHA256RSA = '1.2.840.113549.1.1.11'
SHA256 = '2.16.840.1.101.3.4.2.1'
HMAC_SHA1 = '1.3.6.1.5.5.8.1.2'
PBM = '1.2.840.113533.7.66.13'
DHBM_CNF = '1.2.640.113533.7.66.30'   # as registered in cmp.cnf (sic)
AES128 = '2.16.840.1.101.3.4.1.2'
ID_IT = '1.3.6.1.5.5.7.4.'
ID_REGCTRL = '1.3.6.1.5.5.7.5.1.'


def alg(o, params=None):
    return seq(oid(o), params) if params is not None else seq(oid(o))


def name(cn, o='Example CMP Test'):
    return seq(set_(seq(oid('2.5.4.6'), printable('XX'))),
               set_(seq(oid('2.5.4.10'), utf8(o))),
               set_(seq(oid('2.5.4.3'), utf8(cn))))


def spki(seed):
    n = b'\x00' + bytes([0xc0 | (seed & 0x3f)]) + filler(63, seed)
    rsapub = seq(tlv(0x02, n), integer(65537))
    return seq(alg(RSA, null()), bits(rsapub))


def extension(o, value, critical=False):
    return seq(oid(o), boolean(True), octets(value)) if critical else \
        seq(oid(o), octets(value))


def cert(serial, subject, issuer, ca=False):
    exts = [extension('2.5.29.15', bits(b'\x06' if ca else b'\xa0', 1), True),
            extension('2.5.29.14', octets(filler(20, serial)))]
    if ca:
        exts.insert(0, extension('2.5.29.19', seq(boolean(True)), True))
    tbs = seq(ctx(0, integer(2)), integer(serial), alg(SHA256RSA, null()),
              name(issuer), seq(utctime('200101000000Z'), utctime('400101000000Z')),
              name(subject), spki(serial), ctx(3, seq(*exts)))
    return seq(tbs, alg(SHA256RSA, null()), bits(filler(64, serial + 100)))


def crl(issuer, number, revoked=(5,)):
    entries = [seq(integer(s), utctime('231101000000Z'),
                   seq(extension('2.5.29.21', enumerated(1))))
               for s in revoked]
    tbs = seq(integer(1), alg(SHA256RSA, null()), name(issuer),
              utctime('231110000000Z'), utctime('231210000000Z'),
              seq(*entries),
              ctx(0, seq(extension('2.5.29.20', integer(number)))))
    return seq(tbs, alg(SHA256RSA, null()), bits(filler(64, number)))


CA_CERT = cert(1, 'CMP Test Root CA', 'CMP Test Root CA', ca=True)
CA2_CERT = cert(2, 'CMP Test Root CA G2', 'CMP Test Root CA G2', ca=True)
EE_CERT = cert(10, 'cmp-client.example', 'CMP Test Root CA')
RA_CERT = cert(11, 'cmp-ra.example', 'CMP Test Root CA')
CRL1 = crl('CMP Test Root CA', 7)
CRL2 = crl('CMP Test Root CA G2', 3, (6, 8))

# GeneralName (x509ce, implicit tags; directoryName is explicit)
def gn_dir(cn):
    return ctx(4, name(cn))


def gn_rfc822(s):
    return tlv(0x81, s.encode())


def gn_dns(s):
    return tlv(0x82, s.encode())


def gn_uri(s):
    return tlv(0x86, s.encode())

# ---------------------------------------------------------------- CRMF (IMPLICIT TAGS)

def cert_template(full=True, serial=None):
    items = []
    if full:
        items.append(tlv(0x80, b'\x02'))                    # version [0] v3
    if serial is not None:
        items.append(retag(0x81, integer(serial)))        # serialNumber [1]
    if full:
        items.append(retag(0xa2, alg(SHA256RSA, null())))  # signingAlg [2]
    items.append(ctx(3, name('CMP Test Root CA')))          # issuer [3]
    if full:
        items.append(tlv(0xa4, ctx(0, utctime('231101000000Z')) +
                         ctx(1, utctime('251101000000Z'))))  # validity [4]
        items.append(ctx(5, name('cmp-client.example')))    # subject [5]
        items.append(retag(0xa6, spki(20)))               # publicKey [6]
        items.append(retag(0xa9, seq(extension('2.5.29.15', bits(b'\xa0', 1)))))
    return seq(*items)


def controls():
    """Controls with the registration controls cmp.cnf registers."""
    return seq(
        seq(oid(ID_REGCTRL + '1'), utf8('one-time-token')),       # regToken (crmf)
        seq(oid(ID_REGCTRL + '11'), alg(RSA, null())),            # algId
        seq(oid(ID_REGCTRL + '12'), integer(2048)),               # rsaKeyLen
        seq(oid(ID_REGCTRL + '7'),                                # altCertTemplate
            seq(oid(ID_REGCTRL + '2'), utf8('authenticator'))))


def cert_req_messages(req_id=0, full=True, popo='ra'):
    items = [integer(req_id), cert_template(full)]
    if full:
        items.append(controls())
    req = [seq(*items)]
    if popo == 'ra':
        req.append(tlv(0x80, b''))                          # raVerified [0] NULL
    elif popo == 'sig':
        req.append(tlv(0xa1, alg(SHA256RSA, null()) + bits(filler(32, 3))))
    if full:
        req.append(seq(seq(oid('1.3.6.1.5.5.7.5.2.1'), utf8('version=1'))))
    return seq(seq(*req))


def encrypted_value(seed):
    return seq(retag(0xa0, alg(AES128)), retag(0xa1, alg(AES128)),
               tlv(0x82, b'\x00' + filler(16, seed)),
               retag(0xa3, alg(RSA, null())),
               tlv(0x84, b'hint'), bits(filler(32, seed)))


def cert_id(serial):
    return seq(gn_dir('CMP Test Root CA'), integer(serial))


def publication_info():
    return seq(integer(1), seq(seq(integer(2), gn_uri('http://pki.example/certs')),
                               seq(integer(0))))

# ---------------------------------------------------------------- CMP (EXPLICIT TAGS)

def free_text(*s):
    return seq(*[utf8(x) for x in s])


def status_info(status, text=None, fail=None):
    items = [integer(status)]
    if text:
        items.append(free_text(text))
    if fail is not None:
        items.append(fail)
    return seq(*items)


def itav(o, value=None):
    return seq(oid(o), value) if value is not None else seq(oid(o))


def header(pvno=2, sender=None, recipient=None, full=False, prot=None,
           general=None, tid=b'\x11' * 16, extra=()):
    items = [integer(pvno),
             sender if sender is not None else gn_dir('cmp-client.example'),
             recipient if recipient is not None else gn_dir('CMP Test Root CA')]
    if full:
        items.append(ctx(0, gentime('20231114221320Z')))
    if prot is not None:
        items.append(ctx(1, prot))
    if full:
        items.append(ctx(2, octets(filler(20, 1))))
        items.append(ctx(3, octets(filler(20, 2))))
    if tid is not None:
        items.append(ctx(4, octets(tid)))
    if full:
        items.append(ctx(5, octets(filler(16, 5))))
        items.append(ctx(6, octets(filler(16, 6))))
        items.append(ctx(7, free_text('synthetic test message', 'second line')))
    if general is not None:
        items.append(ctx(8, seq(*general)))
    items.extend(extra)
    return seq(*items)


def pkimsg(body_tag, body, hdr=None, protection=None, extra_certs=None):
    items = [hdr if hdr is not None else header(), ctx(body_tag, body)]
    if protection is not None:
        items.append(ctx(0, bits(protection)))
    if extra_certs is not None:
        items.append(ctx(1, seq(*extra_certs)))
    return seq(*items)


def cert_rep(status=0, with_ca=True, kind='cert', seed=0):
    if kind == 'cert':
        ckp = seq(ctx(0, EE_CERT),
                  ctx(0, encrypted_value(seed)),
                  ctx(1, publication_info()))
    else:
        ckp = seq(ctx(1, encrypted_value(seed)))
    resp = seq(integer(0), status_info(status, 'issued', bits(b'\x00', 7)
                                       if status == 1 else None),
               ckp, octets(b'rsp-info'))
    items = []
    if with_ca:
        items.append(ctx(1, seq(CA_CERT)))
    items.append(seq(resp))
    return seq(*items)


PBM_PARAMS = seq(octets(filler(16, 9)), alg(SHA256), integer(500), alg(HMAC_SHA1))
DHBM_PARAMS = seq(alg(SHA256), alg(HMAC_SHA1))


def build_messages():
    """Return a dict of named PKIMessages."""
    M = {}
    gi = [itav(ID_IT + '13', null()),                                   # implicitConfirm
          itav(ID_IT + '14', gentime('20231114230000Z')),               # confirmWaitTime
          itav(ID_IT + '21', seq(utf8('tls-server'), utf8('ee'))),       # certProfile
          itav('1.3.6.1.4.1.3029.3.1.1')]                                # cryptlib, no value
    M['ir'] = pkimsg(0, cert_req_messages(0, True, 'ra'),
                     header(full=True, prot=alg(PBM, PBM_PARAMS), general=gi),
                     protection=filler(20, 0x42), extra_certs=[EE_CERT, CA_CERT])
    M['ip'] = pkimsg(1, cert_rep(0, True, 'cert', 1),
                     header(sender=gn_dir('CMP Test Root CA'),
                            recipient=gn_dir('cmp-client.example'),
                            prot=alg(SHA256RSA, null())),
                     protection=filler(64, 0x43), extra_certs=[CA_CERT])
    M['cr'] = pkimsg(2, cert_req_messages(1, True, 'sig'),
                     header(pvno=3, sender=gn_rfc822('client@example.com'),
                            prot=alg(DHBM_CNF, DHBM_PARAMS)),
                     protection=filler(20, 0x44))
    M['cp'] = pkimsg(3, cert_rep(1, False, 'enc', 2),
                     header(sender=gn_dns('ca.example')))
    p10_info = seq(integer(0), name('p10-client.example'), spki(30),
                   tlv(0xa0, seq(oid('1.2.840.113549.1.9.14'),
                                 set_(seq(extension('2.5.29.17',
                                                    seq(gn_dns('p10-client.example'))))))))
    M['p10cr'] = pkimsg(4, seq(p10_info, alg(SHA256RSA, null()), bits(filler(64, 31))))
    M['popdecc'] = pkimsg(5, seq(seq(alg(SHA256), octets(filler(32, 1)), octets(filler(48, 2))),
                                 seq(octets(filler(32, 3)), octets(filler(48, 4)))),
                          header(sender=gn_dir('CMP Test Root CA')))
    M['popdecr'] = pkimsg(6, seq(integer(12345), integer(678)))
    M['kur'] = pkimsg(7, cert_req_messages(2, False, 'ra'),
                      header(prot=alg(SHA256RSA, null())),
                      protection=filler(64, 0x45), extra_certs=[EE_CERT])
    M['kup'] = pkimsg(8, cert_rep(0, False, 'cert', 3),
                      header(sender=gn_dir('CMP Test Root CA')))
    M['krr'] = pkimsg(9, cert_req_messages(3, False, 'ra'))
    ckp = seq(ctx(0, EE_CERT), ctx(0, encrypted_value(4)))
    M['krp'] = pkimsg(10, seq(status_info(0), ctx(0, EE_CERT), ctx(1, seq(CA_CERT, CA2_CERT)),
                              ctx(2, seq(ckp, seq(ctx(1, encrypted_value(5)))))),
                      header(sender=gn_dir('CMP Test Root CA')))
    M['rr'] = pkimsg(11, seq(seq(cert_template(False, serial=10),
                                 seq(extension('2.5.29.21', enumerated(1)))),
                             seq(cert_template(False, serial=11))))
    M['rp'] = pkimsg(12, seq(seq(status_info(0), status_info(2, 'unknown certificate',
                                                             bits(b'\x08', 3))),
                             ctx(0, seq(cert_id(10), cert_id(11))),
                             ctx(1, seq(CRL1))),
                     header(sender=gn_dir('CMP Test Root CA')))
    M['ccr'] = pkimsg(13, cert_req_messages(4, True, 'ra'),
                      header(sender=gn_dir('CMP Test Root CA G2')))
    M['ccp'] = pkimsg(14, cert_rep(0, True, 'cert', 6),
                      header(sender=gn_dir('CMP Test Root CA')))
    M['ckuann'] = pkimsg(15, seq(CA_CERT, CA2_CERT, CA2_CERT),
                         header(sender=gn_dir('CMP Test Root CA'), tid=None))
    M['cann'] = pkimsg(16, EE_CERT, header(sender=gn_dir('CMP Test Root CA'), tid=None))
    M['rann'] = pkimsg(17, seq(integer(5), cert_id(10), gentime('20231201000000Z'),
                               gentime('20231101000000Z'),
                               seq(extension('2.5.29.21', enumerated(1)))),
                       header(sender=gn_dir('CMP Test Root CA'), tid=None))
    M['crlann'] = pkimsg(18, seq(CRL1, CRL2),
                         header(sender=gn_dir('CMP Test Root CA'), tid=None))
    M['pkiconf'] = pkimsg(19, null(), header(sender=gn_dir('CMP Test Root CA')))
    M['certConf'] = pkimsg(24, seq(seq(octets(filler(32, 7)), integer(0), status_info(0),
                                       ctx(0, alg(SHA256))),
                                   seq(octets(filler(32, 8)), integer(1))))
    M['pollReq'] = pkimsg(25, seq(seq(integer(0)), seq(integer(1))))
    M['pollRep'] = pkimsg(26, seq(seq(integer(0), integer(60), free_text('still waiting')),
                                  seq(integer(1), integer(120))),
                          header(sender=gn_dir('CMP Test Root CA')))
    M['error'] = pkimsg(23, seq(status_info(2, 'bad request', bits(b'\x20\x00\x00\x20', 5)),
                                integer(42), free_text('error details', 'more')),
                        header(sender=gn_dir('CMP Test Root CA')))
    M['error_min'] = pkimsg(23, seq(status_info(2)),
                            header(sender=gn_dir('CMP Test Root CA')))
    # One message per PKIStatus value (accepted .. keyUpdateWarning) and
    # one past the defined values.
    for st in range(8):
        M['status%d' % st] = pkimsg(23, seq(status_info(st)),
                                    header(sender=gn_dir('CMP Test Root CA'),
                                           tid=bytes([st]) * 4))
    # General message: request every InfoType without a value.
    M['genm'] = pkimsg(21, seq(*[itav(ID_IT + str(n)) for n in
                                 (1, 2, 3, 4, 5, 6, 10, 16, 17, 18, 19, 20, 21, 22)],
                           itav(ID_IT + '7', seq(oid(ID_IT + '8'), oid(ID_IT + '9'))),
                           itav(ID_IT + '10', oid(RSA)),
                           itav(ID_IT + '22', seq(seq(ctx(1, seq(gn_dir('CMP Test Root CA G2'))),
                                                      utctime('231110000000Z')))),
                           itav('1.3.6.1.4.1.3029.3.1.2')))
    # General response: a value for every InfoType.
    orig = seq(pkimsg(19, null(), header(tid=b'\x22' * 16)))
    M['genp'] = pkimsg(22, seq(
        itav(ID_IT + '1', CA_CERT),
        itav(ID_IT + '2', seq(alg(RSA, null()), alg('1.2.840.10045.2.1', oid('1.2.840.10045.3.1.7')))),
        itav(ID_IT + '3', seq(alg(RSA, null()))),
        itav(ID_IT + '4', alg(AES128)),
        itav(ID_IT + '5', seq(CA_CERT, CA2_CERT, CA2_CERT)),
        itav(ID_IT + '6', CRL1),
        itav(ID_IT + '11', alg(RSA, null())),
        itav(ID_IT + '12', encrypted_value(9)),
        itav(ID_IT + '15', orig),
        itav(ID_IT + '16', seq(utf8('en'), utf8('de'))),
        itav(ID_IT + '17', seq(CA_CERT, CA2_CERT)),
        itav(ID_IT + '18', seq(CA2_CERT, ctx(0, CA2_CERT), ctx(1, CA_CERT))),
        itav(ID_IT + '19', seq(cert_template(True), seq(
            seq(oid(ID_REGCTRL + '11'), alg(RSA, null())),
            seq(oid(ID_REGCTRL + '12'), integer(3072))))),
        itav(ID_IT + '20', CA2_CERT),
        itav(ID_IT + '23', seq(CRL1, CRL2)),
        itav(ID_IT + '22', seq(seq(ctx(1, seq(gn_dir('CMP Test Root CA')))))),
    ), header(sender=gn_dir('CMP Test Root CA')))
    M['nested'] = pkimsg(20, seq(M['cr'], M['pollReq']),
                         header(sender=gn_dir('cmp-ra.example'),
                                prot=alg(SHA256RSA, null())),
                         protection=filler(64, 0x46), extra_certs=[RA_CERT])
    M['genm_rk'] = pkimsg(21, seq(itav(ID_IT + '18', seq(CA2_CERT))))   # rootCaKeyUpdate, only newWithNew
    M['minimal'] = seq(seq(integer(1), gn_dir('a'), gn_dir('b')), ctx(19, null()))
    return M

# ---------------------------------------------------------------- framing

def csum16(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


class Pcap:
    def __init__(self):
        self.frames = []
        self.t = 1700000000

    def add(self, frame):
        self.frames.append((self.t, frame))
        self.t += 1

    def write(self, path):
        with open(path, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            for t, fr in self.frames:
                f.write(struct.pack('<IIII', t, 0, len(fr), len(fr)) + fr)


class Conn:
    """A TCP connection between a client and a server; keeps sequence
    numbers so that TCP analysis has nothing to complain about."""
    def __init__(self, cap, cport, sport, cip=(192, 0, 2, 1), sip=(192, 0, 2, 2)):
        self.cap, self.cport, self.sport = cap, cport, sport
        self.cip, self.sip = bytes(cip), bytes(sip)
        self.cseq, self.sseq = 1000, 5000
        self.handshake()

    def frame(self, from_client, flags, payload):
        if from_client:
            src, dst, sp, dp, seqn, ack = self.cip, self.sip, self.cport, self.sport, self.cseq, self.sseq
        else:
            src, dst, sp, dp, seqn, ack = self.sip, self.cip, self.sport, self.cport, self.sseq, self.cseq
        if flags & 0x02:
            # SYN: no ACK number unless SYN/ACK; MSS option 65000 so that
            # TCP does not note segments as longer than the MSS.
            if not flags & 0x10:
                ack = 0
            opts = struct.pack('>BBHBBBB', 2, 4, 65000, 1, 1, 4, 2)
        else:
            opts = b''
        tcp = struct.pack('>HHIIBBHHH', sp, dp, seqn, ack, (5 + len(opts) // 4) << 4,
                          flags, 65535, 0, 0) + opts + payload
        ph = src + dst + struct.pack('>BBH', 0, 6, len(tcp))
        tcp = tcp[:16] + struct.pack('>H', csum16(ph + tcp)) + tcp[18:]
        ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), 1, 0x4000, 64, 6, 0, src, dst)
        ip = ip[:10] + struct.pack('>H', csum16(ip)) + ip[12:]
        mac_c, mac_s = bytes.fromhex('020000000001'), bytes.fromhex('020000000002')
        eth = (mac_s + mac_c if from_client else mac_c + mac_s) + b'\x08\x00'
        self.cap.add(eth + ip + tcp)
        n = len(payload) + (1 if flags & 0x03 else 0)
        if from_client:
            self.cseq += n
        else:
            self.sseq += n

    def handshake(self):
        self.cseq -= 1
        self.sseq -= 1
        c, s = self.cseq, self.sseq
        # SYN, SYN/ACK, ACK
        self.frame(True, 0x02, b'')
        self.frame(False, 0x12, b'')
        self.frame(True, 0x10, b'')

    def send(self, from_client, data, split=None):
        """Send data, optionally split at the given offsets."""
        cuts = [0] + list(split or []) + [len(data)]
        for a, b in zip(cuts, cuts[1:]):
            self.frame(from_client, 0x18, data[a:b])

    def c(self, data, split=None):
        self.send(True, data, split)

    def s(self, data, split=None):
        self.send(False, data, split)


def rfc2510(ptype, body):
    return struct.pack('>IB', 1 + len(body), ptype) + body


def draft10(ptype, body, flags=0):
    return struct.pack('>IBBB', 3 + len(body), 10, flags, ptype) + body


def http_req(body, ctype, path='/pkix/'):
    h = 'POST %s HTTP/1.1\r\nHost: ca.example\r\n' % path
    if ctype:
        h += 'Content-Type: %s\r\n' % ctype
    h += 'Content-Length: %d\r\n\r\n' % len(body)
    return h.encode() + body


def http_rsp(body, ctype):
    h = 'HTTP/1.1 200 OK\r\n'
    if ctype:
        h += 'Content-Type: %s\r\n' % ctype
    h += 'Content-Length: %d\r\nCache-Control: no-cache\r\n\r\n' % len(body)
    return h.encode() + body

# ---------------------------------------------------------------- captures

def main_capture(M):
    cap = Pcap()
    port = [40000]

    def conn(sport=829):
        port[0] += 1
        return Conn(cap, port[0], sport)

    # TCP port 829, RFC 2510 transport: initialization with confirmation,
    # TCP reassembly of the request (3 segments) and the response (2).
    c = conn()
    c.c(rfc2510(0, M['ir']), split=[10, 700])
    c.s(rfc2510(0, M['ip']), split=[900])
    c.c(rfc2510(0, M['certConf']))
    c.s(rfc2510(0, M['pkiconf']))
    # Certification request answered with polling, then the
    # TCP-transport polling messages.
    c = conn()
    c.c(rfc2510(0, M['cr']))
    c.s(rfc2510(1, struct.pack('>II', 0x1234, 1700000060)))           # pollRep
    c.c(rfc2510(2, struct.pack('>I', 0x1234)))                         # pollReq
    c.s(rfc2510(4, struct.pack('>II', 0x1235, 1700000120) + M['cp']))  # partialMsgRep
    c.c(rfc2510(2, struct.pack('>I', 0x1235)))
    c.s(rfc2510(3, b''))                                               # negPollRep
    c.c(rfc2510(2, struct.pack('>I', 0x1235)))
    c.s(rfc2510(5, M['pollRep']))                                      # finalMsgRep
    c.c(rfc2510(2, struct.pack('>I', 0x1236)))
    c.s(rfc2510(6, b'\x00\x01'))                                       # errorMsgRep
    # Several PDUs in one segment.
    c = conn()
    c.c(rfc2510(0, M['p10cr']) + rfc2510(0, M['popdecr']) + rfc2510(2, struct.pack('>I', 7)))
    c.s(rfc2510(0, M['popdecc']) + rfc2510(0, M['cp']))
    # The other request/response pairs.
    c = conn()
    for req, rsp in (('kur', 'kup'), ('krr', 'krp'), ('rr', 'rp'), ('ccr', 'ccp'),
                     ('genm', 'genp'), ('pollReq', 'pollRep'), ('nested', 'error')):
        c.c(rfc2510(0, M[req]))
        c.s(rfc2510(0, M[rsp]))
    # Announcements from the CA.
    c = conn()
    for a in ('ckuann', 'cann', 'rann', 'crlann', 'genm_rk', 'error_min', 'minimal'):
        c.s(rfc2510(0, M[a]))
    for st in range(8):
        c.s(rfc2510(0, M['status%d' % st]))

    # TCP port 829, draft (version 10) transport.
    c = conn()
    c.c(draft10(0, M['ir']), split=[8, 400])
    c.s(draft10(1, struct.pack('>II', 0xabcd, 1700000300)))            # pollRep
    c.c(draft10(2, struct.pack('>I', 0xabcd)))                         # pollReq
    c.s(draft10(4, struct.pack('>II', 0xabce, 1700000400) + M['ip']))  # partialMsgRep
    c.c(draft10(2, struct.pack('>I', 0xabce)))
    c.s(draft10(5, M['pkiconf']))                                      # finalMsgRep
    c.c(draft10(2, struct.pack('>I', 0xabcf)))
    c.s(draft10(6, b'\x00\x02'))                                       # errorMsgRep

    # Reproducer cmp_tcp_hdr.py: frames 1 and 3 as they are,
    # frame 2 with a valid pkiconf body ([19] NULL; the original uses [21]).
    dn = b'\xa4\x02\x30\x00'
    hdr = b'\x30' + bytes([3 + 2 * len(dn)]) + b'\x02\x01\x02' + dn + dn
    pki = seq(hdr, ctx(19, null()))
    c = conn()
    c.c(struct.pack('>IB', 5, 2) + struct.pack('>I', 0x11223344))
    c.c(struct.pack('>IB', 1 + len(pki), 0) + pki)
    c.c(struct.pack('>IBBB', 7, 10, 0, 2) + struct.pack('>I', 0x55667788))

    # Segments that dissect_cmp_tcp() rejects (shown as TCP payload):
    # fewer than 5 bytes, type 7, draft length 2, length 0, length 20000,
    # pkiMsg with length 2. One connection each.
    for p in (b'\x00\x00\x00', struct.pack('>IB', 5, 7) + b'\0' * 4,
              struct.pack('>IBBB', 2, 10, 0, 2) + b'\0', struct.pack('>IB', 0, 0),
              struct.pack('>IB', 20000, 0) + b'\0' * 8,
              struct.pack('>IB', 2, 0) + b'\x30'):
        c = conn()
        c.c(p)

    # HTTP with the CMP media types.
    c = conn(80)
    c.c(http_req(M['ir'], 'application/pkixcmp'), split=[120, 900])
    c.s(http_rsp(M['ip'], 'application/pkixcmp'))
    c.c(http_req(M['certConf'], 'application/x-pkixcmp'))
    c.s(http_rsp(M['pkiconf'], 'application/x-pkixcmp'))
    c.c(http_req(rfc2510(0, M['cr']), 'application/pkixcmp-poll'))
    c.s(http_rsp(rfc2510(1, struct.pack('>II', 0x99, 1700000500)), 'application/pkixcmp-poll'))
    c.c(http_req(draft10(2, struct.pack('>I', 0x99)), 'application/x-pkixcmp-poll'))
    c.s(http_rsp(draft10(5, M['cp']), 'application/x-pkixcmp-poll'))
    # TCP-style PDUs that only the HTTP path accepts: RFC 2510 type 8
    # and draft type 0x20.
    c.c(http_req(rfc2510(8, b'\0\0\0\0'), 'application/pkixcmp-poll'))
    c.s(http_rsp(draft10(0x20, b'\0\0\0\0'), 'application/pkixcmp-poll'))
    # HTTP without a Content-Type on the ports used for the alternate
    # port preferences (plain HTTP by default).
    c = conn(8080)
    c.c(http_req(M['genm'], None, '/cmp'))
    c.s(http_rsp(M['genp'], None))
    c = conn(8081)
    c.c(http_req(rfc2510(0, M['pollReq']), None, '/cmp'))
    c.s(http_rsp(rfc2510(0, M['pollRep']), None))
    return cap


def malformed_capture(M):
    cap = Pcap()
    port = [50000]

    def conn(sport=829):
        port[0] += 1
        return Conn(cap, port[0], sport)

    ir = M['ir']
    c = conn()
    # Original reproducer frame 2: genm with a NULL body.
    dn = b'\xa4\x02\x30\x00'
    hdr = b'\x30' + bytes([3 + 2 * len(dn)]) + b'\x02\x01\x02' + dn + dn
    pki = b'\x30' + bytes([len(hdr) + 4]) + hdr + b'\xb5\x02\x05\x00'
    c.c(struct.pack('>IB', 1 + len(pki), 0) + pki)
    # Truncated PKIMessage inside a complete TCP transport PDU.
    c.c(rfc2510(0, ir[:200]))
    # Unknown PKIBody choice [27].
    c.c(rfc2510(0, seq(seq(integer(2), gn_dir('a'), gn_dir('b')), ctx(27, null()))))
    # pollRep / pollReq / partialMsgRep too short for their fields.
    c.c(rfc2510(1, b'\x00\x01'))
    c.c(rfc2510(2, b''))
    c.c(rfc2510(4, b'\x00\x00\x00\x01'))
    c.c(draft10(1, b'\x00'))
    # A PDU whose last segment never arrives (reassembly not completed),
    # then the connection is reset.
    c = conn()
    c.c(rfc2510(0, ir)[:300])
    # HTTP with a truncated PKIMessage and a too short poll PDU.
    c = conn(80)
    c.c(http_req(ir[:150], 'application/pkixcmp'))
    c.s(http_rsp(b'\x00\x00', 'application/pkixcmp-poll'))
    c.c(http_req(b'\x00\x00\x00\x09\x01\x00', 'application/x-pkixcmp-poll'))
    # Unknown OID in generalInfo and genm (no dissector registered).
    c.s(http_rsp(pkimsg(21, seq(itav('1.3.6.1.4.1.3029.3.1.2', null()),
                                itav(ID_IT + '99', integer(1)))), 'application/pkixcmp'))
    # Bad PKIStatus type, bad failInfo, bad CRLSource.
    c.c(http_req(pkimsg(23, seq(seq(utf8('x')))), 'application/pkixcmp'))
    c.s(http_rsp(pkimsg(22, seq(itav(ID_IT + '22', seq(seq(ctx(5, null())))))), 'application/pkixcmp'))
    c.c(http_req(pkimsg(22, seq(itav(ID_IT + '18', seq(integer(1))))), 'application/pkixcmp'))
    # CRLStatus with a dpn source: the "dpn" field is FT_NONE (cmp.cnf
    # does not include x509ce-exp.cnf), so dissect_ber_choice() reports a
    # BER error.
    c.s(http_rsp(pkimsg(21, seq(itav(ID_IT + '22', seq(seq(
        ctx(0, tlv(0xa0, gn_uri('http://crl.example/root.crl'))),
        utctime('231110000000Z')))))), 'application/pkixcmp'))
    # Draft (version 10) transport: dissect_cmp_tcp() reads the type at
    # offset 7, so a segment of 5 to 7 bytes throws: a first segment of 5
    # bytes, a negPollRep (7 bytes, valid) and a PDU with length 2.
    c = conn()
    c.c(draft10(0, M['pkiconf']), split=[5])
    c = conn()
    c.c(draft10(3, b''))
    c = conn()
    c.c(struct.pack('>IBBB', 2, 10, 0, 2))
    return cap


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    M = build_messages()
    main_capture(M).write(os.path.join(out, 'cmp-coverage.pcap'))
    malformed_capture(M).write(os.path.join(out, 'cmp-coverage-malformed.pcap'))


if __name__ == '__main__':
    main()
