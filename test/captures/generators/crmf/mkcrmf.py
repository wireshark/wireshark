#!/usr/bin/env python3
# Generates test/captures/crmf_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the Certificate Request
Message Format dissector (packet-crmf.c, generated from asn1/crmf/).

CRMF has no transport of its own. It is reached through CMP
(packet-cmp.c): the PKIBody choices ir, cr, kur, krr and ccr carry
CertReqMessages, CMP responses carry EncryptedKey and
PKIPublicationInfo, revocation requests carry CertTemplate and CertId,
and the BER OID dissectors that CRMF registers (registration controls,
registration info, PasswordBasedMac, id-ct-encKeyWithID) are reached
through AttributeTypeAndValue, a CMP InfoTypeAndValue and the CMP
protectionAlg parameters. The PKIMessages are sent over HTTP
(application/pkixcmp) on port 80 and, once, over TCP port 829 with the
RFC 2510 transport header.

Every packet is built from scratch with struct and a small DER encoder;
the names, keys and signatures are made up. Nothing comes from a real
network.

Usage: mkcrmf.py <output directory>

Writes:
  crmf-coverage.pcap            every CRMF type and choice, every
                                registered OID, every optional field
  crmf-coverage-malformed.pcap  wrong tags and truncated CRMF values
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
AES128 = '2.16.840.1.101.3.4.1.2'


def alg(o, params=None):
    return seq(oid(o), params) if params is not None else seq(oid(o))


def name(cn, o='Example CRMF Test'):
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
#
# CRMF uses IMPLICIT TAGS; a tag on a CHOICE (Name, GeneralName,
# POPOPrivKey, EncryptedKey) is always explicit.

ID_PKIP = '1.3.6.1.5.5.7.5.'
ID_REGCTRL = ID_PKIP + '1.'
ID_REGINFO = ID_PKIP + '2.'
ENC_KEY_WITH_ID = '1.2.840.113549.1.9.16.1.21'
PBM = '1.2.840.113533.7.66.13'
HMAC_SHA256 = '1.2.840.113549.2.9'
RSAES_OAEP = '1.2.840.113549.1.1.7'


def implicit_seq(tag, der):
    """[tag] IMPLICIT SEQUENCE/SET: constructed context tag."""
    return retag(0xa0 | tag, der)


def cert_template_full(serial=0x0123456789abcdef):
    return seq(
        tlv(0x80, b'\x02'),                                   # version [0] v3
        retag(0x81, integer(serial)),                         # serialNumber [1] 64 bit
        implicit_seq(2, alg(SHA256RSA, null())),              # signingAlg [2]
        ctx(3, name('CRMF Test CA')),                         # issuer [3]
        tlv(0xa4, ctx(0, utctime('260101000000Z')) +          # validity [4]
            ctx(1, gentime('20280101000000Z'))),
        ctx(5, name('crmf-client.example')),                  # subject [5]
        implicit_seq(6, spki(20)),                            # publicKey [6]
        tlv(0x87, b'\x00' + filler(8, 7)),                    # issuerUID [7]
        tlv(0x88, b'\x04' + filler(7, 8) + b'\xf0'),                    # subjectUID [8]
        implicit_seq(9, seq(extension('2.5.29.15', bits(b'\xa0', 1)),
                            extension('2.5.29.17', seq(gn_dns('crmf-client.example'))))))


def cert_template_min(cn='crmf-min.example'):
    return seq(ctx(5, name(cn)))


def validity_only(before=True):
    v = ctx(0, utctime('260101000000Z')) if before else ctx(1, utctime('270101000000Z'))
    return seq(tlv(0xa4, v))


def atv(o, value):
    return seq(oid(o), value)


def pkmac(seed):
    return seq(alg(PBM, pbm_param(seed)), bits(filler(20, seed)))


def pbm_param(seed, count=10000):
    return seq(octets(filler(16, seed)), alg(SHA256), integer(count), alg(HMAC_SHA256, null()))


def enveloped_data(seed):
    """A CMS EnvelopedData with one key transport recipient."""
    ktri = seq(integer(0), seq(name('crmf-ra.example'), integer(11)),
               alg(RSAES_OAEP), octets(filler(32, seed)))
    eci = seq(oid(ENC_KEY_WITH_ID), alg(AES128, octets(filler(16, seed + 1))),
              tlv(0x80, filler(48, seed + 2)))
    return seq(integer(0), set_(ktri), eci)


def encrypted_value(seed, full=True):
    items = []
    if full:
        items += [implicit_seq(0, alg(RSA, null())),          # intendedAlg [0]
                  implicit_seq(1, alg(AES128, octets(filler(16, seed)))),  # symmAlg [1]
                  tlv(0x82, b'\x00' + filler(32, seed + 1)),  # encSymmKey [2]
                  implicit_seq(3, alg(RSAES_OAEP)),           # keyAlg [3]
                  tlv(0x84, b'value hint')]                   # valueHint [4]
    items.append(bits(filler(48, seed + 2)))                  # encValue
    return seq(*items)


def cert_id(serial, issuer='CRMF Test CA'):
    return seq(gn_dir(issuer), integer(serial))


def single_pub_info(method, location=None):
    return seq(integer(method), location) if location is not None else seq(integer(method))


def publication_info(action=1, infos=True):
    if not infos:
        return seq(integer(action))
    return seq(integer(action), seq(
        single_pub_info(0),
        single_pub_info(1, gn_dir('CRMF Directory')),
        single_pub_info(2, gn_uri('http://pki.example/certs/')),
        single_pub_info(3, gn_uri('ldap://ldap.example/cn=crmf'))))


def private_key_info(seed, attributes=True):
    items = [integer(0), alg(RSA, null()), octets(filler(64, seed))]
    if attributes:
        items.append(implicit_seq(0, set_(
            seq(oid('1.2.840.113549.1.9.20'), set_(tlv(0x1e, 'crmf key'.encode('utf-16-be')))),
            seq(oid('1.2.840.113549.1.9.21'), set_(octets(filler(8, seed)))))))
    return seq(*items)


def enc_key_with_id(seed, ident=None):
    items = [private_key_info(seed, attributes=(ident == 'string'))]
    if ident == 'string':
        items.append(utf8('crmf-client key 1'))
    elif ident == 'gn':
        items.append(gn_rfc822('client@crmf.example'))
    elif ident == 'gn-dir':
        items.append(gn_dir('crmf-client.example'))
    return seq(*items)


def cert_request(req_id, template, ctrls=None):
    items = [integer(req_id), template]
    if ctrls is not None:
        items.append(seq(*ctrls))
    return seq(*items)


def cert_req_msg(req, popo=None, reg_info=None):
    items = [req]
    if popo is not None:
        items.append(popo)
    if reg_info is not None:
        items.append(seq(*reg_info))
    return seq(*items)

# ProofOfPossession choices

def popo_ra():
    return tlv(0x80, b'')                                     # raVerified [0] NULL


def popo_sig(input_=None, seed=1):
    items = []
    if input_ is not None:
        items.append(implicit_seq(0, input_))                 # poposkInput [0]
    items += [alg(SHA256RSA, null()), bits(filler(64, seed))]
    return tlv(0xa1, b''.join(items))                         # signature [1]


def popo_input_sender():
    return seq(ctx(0, gn_rfc822('client@crmf.example')), spki(21))


def popo_input_mac():
    return seq(pkmac(30), spki(22))


def popo_priv(outer, choice):
    """keyEncipherment [2] / keyAgreement [3] POPOPrivKey (explicit)."""
    return ctx(outer, choice)


def ppk_this_message(seed):
    return tlv(0x80, b'\x00' + filler(24, seed))              # thisMessage [0]


def ppk_subsequent(v):
    return retag(0x81, integer(v))                            # subsequentMessage [1]


def ppk_dhmac(seed):
    return tlv(0x82, b'\x00' + filler(20, seed))              # dhMAC [2]


def ppk_agree_mac(seed):
    return implicit_seq(3, pkmac(seed))                       # agreeMAC [3]


def ppk_encrypted_key(seed):
    return implicit_seq(4, enveloped_data(seed))              # encryptedKey [4]

# Registration controls and registration info

def ctrl_reg_token():
    return atv(ID_REGCTRL + '1', utf8('one-time token 4711'))


def ctrl_authenticator():
    return atv(ID_REGCTRL + '2', utf8('mother\'s maiden name'))


def ctrl_pub_info(action=1, infos=True):
    return atv(ID_REGCTRL + '3', publication_info(action, infos))


def ctrl_archive_encrypted_value(seed):
    return atv(ID_REGCTRL + '4', ctx(0, encrypted_value(seed)))   # encryptedPrivKey [0]


def ctrl_archive_enveloped(seed):
    return atv(ID_REGCTRL + '4', ctx(0, implicit_seq(0, enveloped_data(seed))))


def ctrl_archive_keygen():
    return atv(ID_REGCTRL + '4', tlv(0x81, filler(12, 40)))  # keyGenParameters [1]


def ctrl_archive_rem_gen(v):
    return atv(ID_REGCTRL + '4', tlv(0x82, b'\xff' if v else b'\x00'))  # archiveRemGenPrivKey [2]


def ctrl_old_cert_id(serial):
    return atv(ID_REGCTRL + '5', cert_id(serial))


def ctrl_protocol_encr_key():
    return atv(ID_REGCTRL + '6', spki(23))


def reginfo_utf8_pairs():
    return atv(ID_REGINFO + '1', utf8('version?1%corp_company?Example%org_unit?Test%'))


def reginfo_cert_req(req_id):
    return atv(ID_REGINFO + '2', cert_request(req_id, cert_template_min('crmf-reginfo.example'),
                                              [ctrl_reg_token()]))

# ---------------------------------------------------------------- CMP (EXPLICIT TAGS)

def header(prot_alg=None, tid=b'\x22' * 16):
    items = [integer(2), gn_dir('crmf-client.example'), gn_dir('CRMF Test CA')]
    if prot_alg is not None:
        items.append(ctx(1, prot_alg))
    items.append(ctx(4, octets(tid)))
    return seq(*items)


def pkimsg(body_tag, body, prot_alg=None, protection=None):
    items = [header(prot_alg), ctx(body_tag, body)]
    if protection is not None:
        items.append(ctx(0, bits(protection)))
    return seq(*items)


def itav(o, value=None):
    return seq(oid(o), value) if value is not None else seq(oid(o))


def status_info(status):
    return seq(integer(status))


def build_messages():
    M = {}
    # ir: one request with every CertTemplate field, every registration
    # control CRMF registers, a signature POP with a sender, and both
    # registration info OIDs; a second one with raVerified.
    M['ir'] = pkimsg(0, seq(
        cert_req_msg(cert_request(0, cert_template_full(), [
            ctrl_reg_token(), ctrl_authenticator(), ctrl_pub_info(),
            ctrl_archive_encrypted_value(41), ctrl_old_cert_id(0x1001),
            ctrl_protocol_encr_key()]),
            popo_sig(popo_input_sender(), 1),
            [reginfo_utf8_pairs(), reginfo_cert_req(7)]),
        cert_req_msg(cert_request(1, cert_template_min()), popo_ra())),
        prot_alg=alg(PBM, pbm_param(1)), protection=filler(32, 9))
    # cr: keyEncipherment with thisMessage and subsequentMessage
    # (encrCert, challengeResp, an unnamed value), archive options
    # keyGenParameters and archiveRemGenPrivKey, a request without POP.
    M['cr'] = pkimsg(2, seq(
        cert_req_msg(cert_request(0, cert_template_min('crmf-cr0.example'),
                                  [ctrl_archive_keygen()]),
                     popo_priv(2, ppk_this_message(50))),
        cert_req_msg(cert_request(1, cert_template_min('crmf-cr1.example'),
                                  [ctrl_archive_rem_gen(True)]),
                     popo_priv(2, ppk_subsequent(0))),
        cert_req_msg(cert_request(2, cert_template_min('crmf-cr2.example'),
                                  [ctrl_archive_rem_gen(False)]),
                     popo_priv(2, ppk_subsequent(1))),
        cert_req_msg(cert_request(3, cert_template_min('crmf-cr3.example')),
                     popo_priv(2, ppk_subsequent(5))),
        cert_req_msg(cert_request(4, validity_only(True)))))
    # kur: keyAgreement with dhMAC, agreeMAC and encryptedKey; signature
    # with a publicKeyMAC input and without input; archive options with
    # an EnvelopedData; pkiPublicationInfo dontPublish without pubInfos.
    M['kur'] = pkimsg(7, seq(
        cert_req_msg(cert_request(0, validity_only(False),
                                  [ctrl_old_cert_id(0x1002), ctrl_archive_enveloped(60),
                                   ctrl_pub_info(0, False)]),
                     popo_priv(3, ppk_dhmac(61))),
        cert_req_msg(cert_request(1, cert_template_min('crmf-kur1.example')),
                     popo_priv(3, ppk_agree_mac(62))),
        cert_req_msg(cert_request(2, cert_template_min('crmf-kur2.example')),
                     popo_priv(3, ppk_encrypted_key(63))),
        cert_req_msg(cert_request(3, cert_template_min('crmf-kur3.example')),
                     popo_sig(popo_input_mac(), 64)),
        cert_req_msg(cert_request(4, cert_template_min('crmf-kur4.example')),
                     popo_sig(None, 65))))
    # krr and ccr: a single request each; keyEncipherment encryptedKey.
    M['krr'] = pkimsg(9, seq(
        cert_req_msg(cert_request(0, cert_template_min('crmf-krr.example'),
                                  [ctrl_authenticator()]),
                     popo_priv(2, ppk_encrypted_key(70)))))
    M['ccr'] = pkimsg(13, seq(
        cert_req_msg(cert_request(0, seq(retag(0x81, integer(-1)), ctx(5, name('CRMF Sub CA')),
                                         implicit_seq(6, spki(24)))),
                     popo_sig(popo_input_sender(), 71))))
    # ip: CertifiedKeyPair with an EncryptedKey as encryptedValue (cert)
    # and envelopedData (private key) and a PKIPublicationInfo.
    ckp = seq(ctx(1, implicit_seq(0, enveloped_data(80))),   # certOrEncCert encryptedCert [1]
              ctx(0, encrypted_value(81, full=False)),       # privateKey [0]
              ctx(1, publication_info()))                    # publicationInfo [1]
    M['ip'] = pkimsg(1, seq(seq(seq(integer(0), status_info(0), ckp))))
    # rr: RevDetails with a CertTemplate (issuer, serial); rp with CertIds.
    M['rr'] = pkimsg(11, seq(seq(seq(retag(0x81, integer(0x1001)), ctx(3, name('CRMF Test CA'))))))
    M['rp'] = pkimsg(12, seq(seq(status_info(0)), ctx(0, seq(cert_id(0x1001), cert_id(0x1002)))))
    # genm/genp: the CRMF BER OID dissectors through InfoTypeAndValue:
    # id-ct-encKeyWithID with every identifier choice and none, every
    # registration control and registration info OID, PasswordBasedMac.
    M['genm'] = pkimsg(21, seq(
        itav(ENC_KEY_WITH_ID, enc_key_with_id(90, 'string')),
        itav(ENC_KEY_WITH_ID, enc_key_with_id(91, 'gn')),
        itav(ENC_KEY_WITH_ID, enc_key_with_id(92, 'gn-dir')),
        itav(ENC_KEY_WITH_ID, enc_key_with_id(93))))
    M['genp'] = pkimsg(22, seq(
        itav(ID_REGCTRL + '1', utf8('token via genp')),
        itav(ID_REGCTRL + '2', utf8('authenticator via genp')),
        itav(ID_REGCTRL + '3', publication_info(1)),
        itav(ID_REGCTRL + '4', tlv(0x82, b'\xff')),
        itav(ID_REGCTRL + '5', cert_id(0x7fffffffffffffff)),
        itav(ID_REGCTRL + '6', spki(25)),
        itav(ID_REGINFO + '1', utf8('a?b%')),
        itav(ID_REGINFO + '2', cert_request(9, cert_template_full(1))),
        itav(PBM, pbm_param(2, 1))))
    M['pkiconf'] = pkimsg(19, null())
    return M

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


def http_req(body, ctype='application/pkixcmp', path='/pkix/'):
    h = 'POST %s HTTP/1.1\r\nHost: ca.example\r\n' % path
    h += 'Content-Type: %s\r\nContent-Length: %d\r\n\r\n' % (ctype, len(body))
    return h.encode() + body


def http_rsp(body, ctype='application/pkixcmp'):
    h = 'HTTP/1.1 200 OK\r\nContent-Type: %s\r\n' % ctype
    h += 'Content-Length: %d\r\nCache-Control: no-cache\r\n\r\n' % len(body)
    return h.encode() + body


def rfc2510(ptype, body):
    return struct.pack('>IB', 1 + len(body), ptype) + body

# ---------------------------------------------------------------- captures

def main_capture(M):
    cap = Pcap()
    c = Conn(cap, 40001, 80)
    c.c(http_req(M['ir']))
    c.s(http_rsp(M['ip']))
    c.c(http_req(M['cr']))
    c.s(http_rsp(M['pkiconf']))
    c.c(http_req(M['kur']))
    c.s(http_rsp(M['pkiconf']))
    c.c(http_req(M['krr']))
    c.s(http_rsp(M['pkiconf']))
    c.c(http_req(M['ccr']))
    c.s(http_rsp(M['pkiconf']))
    c.c(http_req(M['rr']))
    c.s(http_rsp(M['rp']))
    c.c(http_req(M['genm']))
    c.s(http_rsp(M['genp']))
    # The same ir over TCP port 829 (RFC 2510 transport header).
    c = Conn(cap, 40002, 829)
    c.c(rfc2510(0, M['ir']))
    c.s(rfc2510(0, M['ip']))
    return cap


def malformed_capture(M):
    cap = Pcap()
    c = Conn(cap, 50001, 80)
    bad = [
        # CertReqMessages truncated in the middle of the CertTemplate.
        M['ir'][:120],
        # ProofOfPossession with an unknown choice [5].
        pkimsg(2, seq(cert_req_msg(cert_request(0, cert_template_min()), tlv(0x85, b'')))),
        # POPOPrivKey with an unknown choice [6].
        pkimsg(2, seq(cert_req_msg(cert_request(0, cert_template_min()), ctx(2, tlv(0x86, b'\x00'))))),
        # PKIArchiveOptions with an unknown choice [3] and with a
        # truncated EncryptedValue.
        pkimsg(21, seq(itav(ID_REGCTRL + '4', tlv(0x83, b'\x00')),
                       itav(ID_REGCTRL + '4', ctx(0, seq(integer(1)))))),
        # Wrong universal types for RegToken, PKIPublicationInfo,
        # OldCertId, UTF8Pairs, PBMParameter.
        pkimsg(21, seq(itav(ID_REGCTRL + '1', integer(1)),
                       itav(ID_REGCTRL + '3', utf8('x')),
                       itav(ID_REGCTRL + '5', seq(integer(1))),
                       itav(ID_REGINFO + '1', octets(b'x')),
                       itav(PBM, seq(integer(1))))),
        # EncKeyWithID with an INTEGER identifier, a missing private key.
        pkimsg(21, seq(itav(ENC_KEY_WITH_ID, seq(private_key_info(1, False), integer(5))),
                       itav(ENC_KEY_WITH_ID, seq()))),
        # An empty CertReqMessages (SIZE (1..MAX)), an empty Controls and
        # an empty pubInfos.
        pkimsg(0, seq()),
        pkimsg(0, seq(cert_req_msg(cert_request(0, cert_template_min(), [])))),
        pkimsg(21, seq(itav(ID_REGCTRL + '3', seq(integer(1), seq())))),
    ]
    for m in bad:
        c.c(http_req(m))
    return cap


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    M = build_messages()
    main_capture(M).write(os.path.join(out, 'crmf-coverage.pcap'))
    malformed_capture(M).write(os.path.join(out, 'crmf-coverage-malformed.pcap'))


if __name__ == '__main__':
    main()
