# Shared helper module for the capture generators in test/captures/generators
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Frame sets per dissector (used by the mk<name>.py of each directory)."""
from pkixlib import (
    ac_attrs, alg, attr, attr_cert, authpack, BIT, cert_with, cms_signed, content_info, crl, csr,
    dh_params, dsa_params, ec_specified, ECDSA_SHA256, enc_data, exp_pdu, EXPL, ext_aacontrols,
    ext_ac_targets, ext_aia, ext_asids, ext_asids_inherit, ext_biometric, ext_eku, ext_ipblocks,
    ext_policies, ext_proxy, ext_proxying, ext_qcstatements, ext_san, ext_subjdirattrs,
    ext_tlsfeature, general_names, gn_dir, gn_dns, gn_email, gn_ip, gn_other, gn_uri, IA5,
    ID_DATA, INT, kdc_dh_key_info, krb5_principal, NULL, OCT, OID, OID_KP, pbe_params, pbes2,
    PBKDF2, pkcs12_pfx, pkcs12_sets, PRINTABLE, pss_params, read_pcap, RSA, safe_contents, SEQ,
    SET, SHA256, sigalg_certs, signer, spki_ec, tlv, tsq, tsr, tst_token, tstinfo, UTF8,
)
from repro import reproducer

# Reproducer pcaps sit beside the generator that uses this module.
B = __import__('os').path.dirname(__import__('os').path.abspath(__import__('sys').argv[0])) + '/'


def cms_cert(*extensions, **kw):
    return exp_pdu(cms_signed(certs=[cert_with(extensions, **kw)]))


def pkix1explicit():
    f = [cms_cert(ext_ipblocks()), cms_cert(ext_ipblocks(safi=True)), cms_cert(ext_asids()),
         cms_cert(ext_asids_inherit()), cms_cert(ext_tlsfeature()), cms_cert(ext_policies()),
         cms_cert(ext_san(gn_dns('a.example'), gn_email('a@example'), gn_uri('http://a'), gn_ip(b'\xc0\x00\x02\x01'),
                          gn_dir('d'), gn_other('1.3.6.1.5.5.7.8.5', UTF8('other')))),
         cms_cert(ext_ipblocks(), ext_asids(), ext_tlsfeature(), ext_policies()),
         cms_cert(spki=SEQ(alg('1.2.840.10046.2.1', dh_params()), BIT(b'\x00\x05' * 4))),
         cms_cert(spki=SEQ(alg('1.2.840.10046.2.1', dh_params(False)), BIT(b'\x00\x05' * 4)))]
    # extensionRequest and challengePassword attributes of a CSR
    c, cri = csr([attr('1.2.840.113549.1.9.14', SEQ(ext_ipblocks(), ext_asids())),
                  attr('1.2.840.113549.1.9.7', UTF8('challenge')),
                  attr('1.2.840.113549.1.9.7', PRINTABLE('challenge2'))])
    f.append(exp_pdu(c, 'pkcs10'))
    return (f

), []

def pkix1implicit():
    return ([cms_cert(ext_eku(OID_KP)), cms_cert(ext_aia()), cms_cert(ext_eku(OID_KP[:3]), ext_aia()),
            cms_cert(ext_eku(['1.2.3.4'])), cms_cert(ext_aia(), version=0)]

), []

def pkixalgs():
    f = [exp_pdu(cms_signed(certs=[c])) for c in sigalg_certs()]
    spkis = [SEQ(alg('1.2.840.10040.4.1', dsa_params()), BIT(INT(0x1234)[0:0] + b'\x02\x02\x12\x34')),
             SEQ(alg('1.2.840.10046.2.1', dh_params()), BIT(b'\x02\x01\x05')),
             SEQ(alg('2.16.840.1.101.2.1.1.22', OCT(b'\x01' * 10)), BIT(b'\x02\x01\x05')),
             spki_ec(OID('1.2.840.10045.3.1.7')), spki_ec(NULL), spki_ec(ec_specified()),
             SEQ(alg('1.3.132.1.12', OID('1.3.132.0.34')), BIT(b'\x04' + b'\x01' * 96)),
             SEQ(alg('1.2.840.10045.2.13', OID('1.3.132.0.35')), BIT(b'\x04' + b'\x01' * 132)),
             SEQ(alg('1.2.840.113549.1.1.10', pss_params()), BIT(b'\x01\x02')),
             SEQ(alg('1.2.840.113549.1.1.10', pss_params(1)), BIT(b'\x01\x02'))]
    f += [exp_pdu(cms_signed(certs=[cert_with(spki=s)])) for s in spkis]
    f.append(exp_pdu(cms_signed(certs=[cert_with(sigalg=alg('1.2.840.113549.1.1.10', pss_params()))])))
    f.append(exp_pdu(cms_signed(certs=[cert_with(sigalg=alg('1.2.840.113549.1.1.10', pss_params(1)))])))
    f.append(exp_pdu(cms_signed(certs=[cert_with(sigalg=alg('1.2.840.113549.1.1.8', alg(SHA256, NULL)))])))
    return (f

), []

def pkixac():
    f = [exp_pdu(cms_signed(attrcerts=[attr_cert(ac_attrs())])),
         exp_pdu(cms_signed(attrcerts=[attr_cert(ac_attrs()[:2], extensions=[ext_ac_targets(), ext_aacontrols(),
                                                                              ext_proxying()])])),
         exp_pdu(cms_signed(attrcerts=[attr_cert([], extensions=[ext_aacontrols(1)])])),
         exp_pdu(cms_signed(attrcerts=[attr_cert(ac_attrs()[2:5], holder=tlv(0xa0, SEQ(general_names('Holder CA'),
                                                                                       INT(5))))]))]
    f.append(exp_pdu(cms_signed(certs=[cert_with((ext_ac_targets(), ext_aacontrols(), ext_proxying()))])))
    # a v2 holder (X.509 2001): packet-x509af.c implements the 1997 structure only
    bad = [exp_pdu(cms_signed(attrcerts=[attr_cert(
        ac_attrs()[:1], holder=SEQ(EXPL(1, general_names('Holder'))), issuer=tlv(0xa0, SEQ(general_names('AA'))))]))]
    return f, bad


def pkixproxy():
    return ([cms_cert(ext_proxy()), cms_cert(ext_proxy(3)), cms_cert(ext_proxy(0, '1.3.6.1.5.5.7.21.2', None)),
            cms_cert(ext_proxy(None, '1.3.6.1.5.5.7.21.0', b'')), cms_cert(ext_proxy(65535, '1.2.3', b'\x00' * 8))]

), []

def pkixqualified():
    return ([cms_cert(ext_qcstatements()), cms_cert(ext_biometric()), cms_cert(ext_subjdirattrs()),
            cms_cert(ext_san(gn_other('1.3.6.1.5.5.7.8.5', UTF8('user@xmpp.example')),
                             gn_other('1.3.6.1.5.5.7.8.7', IA5('_sip._tcp.example.com')))),
            cms_cert(ext_qcstatements(), ext_biometric(), ext_subjdirattrs())]

), []

def pkixtsp():
    f = [exp_pdu(tsq(), 'pkixtsp_query'), exp_pdu(tsq(False), 'pkixtsp_query'),
         exp_pdu(tsr(0, tst_token(), False), 'pkixtsp_reply'),
         exp_pdu(tsr(0, tst_token(tstinfo(False)), False), 'pkixtsp_reply'),
         exp_pdu(tsr(2, None, False, b'\x80'), 'pkixtsp_reply'), exp_pdu(tsr(2, None, False), 'pkixtsp_reply'),
         exp_pdu(tsr(1, tst_token(), False), 'pkixtsp_reply'),
         exp_pdu(cms_signed(content=tstinfo(), ctype='1.2.840.113549.1.9.16.1.4', signers=[signer()]), 'cms')]
    ts = attr('1.2.840.113549.1.9.16.2.14', tst_token())
    f.append(exp_pdu(cms_signed(content=b'data', signers=[signer(unsigned=[ts])]), 'cms'))
    # PKIStatusInfo has no statusString in packet-pkixtsp.c: BER error
    bad = [exp_pdu(tsr(0, tst_token(), True), 'pkixtsp_reply'), exp_pdu(tsr(2, None, True, b'\x80'), 'pkixtsp_reply')]
    return f, bad


def pkcs10():
    out = []
    for attrs, sp, sa in (
            ([], None, None),
            ([attr('1.2.840.113549.1.9.7', PRINTABLE('pw'))], None, None),
            ([attr('1.2.840.113549.1.9.14', SEQ(ext_san(gn_dns('a.example')), ext_eku(OID_KP[:2]), ext_aia()))], None, None),
            ([attr('1.2.840.113549.1.9.9', SET(attr('1.2.840.113549.1.9.7', UTF8('x'))))], None, None),
            ([attr('1.2.840.113549.1.9.7', UTF8('unknown'))], spki_ec(OID('1.2.840.10045.3.1.7')), alg(ECDSA_SHA256)),
            ([], SEQ(alg('1.2.840.10046.2.1', dh_params()), BIT(b'\x00\x05' * 4)), alg('1.2.840.113549.1.1.10', pss_params()))):
        c, cri = csr(attrs, spki=sp, sigalg=sa)
        out.append(exp_pdu(c, 'pkcs10'))
        out.append(exp_pdu(cri, 'pkcs10.cri'))
    return (out

), []

def pkcs12():
    kb, skb, cb, cb2, crb, sb, nested = pkcs12_sets()
    f = []
    # bags as ContentInfo content types
    for bag_oid, val in (('1.2.840.113549.1.12.10.1.1', SEQ(INT(0), alg(RSA, NULL), OCT(b'\xaa' * 16))),
                         ('1.2.840.113549.1.12.10.1.2', SEQ(alg('1.2.840.113549.1.12.1.3', pbe_params()), OCT(b'\xbb' * 16))),
                         ('1.2.840.113549.1.12.10.1.3', SEQ(OID('1.2.840.113549.1.9.22.1'), EXPL(0, OCT(cert_with())))),
                         ('1.2.840.113549.1.12.10.1.4', SEQ(OID('1.2.3.4.5'), EXPL(0, OCT(b's')))),
                         ('1.2.840.113549.1.12.10.1.5', SEQ(OID('1.2.840.113549.1.9.23.1'), EXPL(0, OCT(crl('X', (1,)))))),
                         ('1.2.840.113549.1.12.10.1.6', safe_contents(kb, skb, cb, cb2, crb, sb, nested))):
        f.append(exp_pdu(content_info(bag_oid, val)))
    # PFX through the LDAP attribute OID
    p1 = pkcs12_pfx([content_info(ID_DATA, OCT(safe_contents(kb, cb, crb, sb, nested))),
                     enc_data(alg('1.2.840.113549.1.12.1.3', pbe_params()))])
    f.append(exp_pdu(content_info('2.16.840.1.113730.3.1.216', p1)))
    f.append(exp_pdu(content_info('2.16.840.1.113730.3.1.216', pkcs12_pfx([content_info(ID_DATA, OCT(safe_contents()))], False))))
    # PBE parameter OIDs as the algorithm of EncryptedData
    for o in ('1.2.840.113549.1.12.1.%d' % i for i in range(1, 7)):
        f.append(exp_pdu(enc_data(alg(o, pbe_params()))))
    for o in ('1.2.840.113549.1.5.%d' % i for i in (1, 3, 4, 6, 10, 11)):
        f.append(exp_pdu(enc_data(alg(o, pbe_params(b'\x01' * 8, 100)))))
    for al in (pbes2(), pbes2('alg', alg('1.2.840.113549.2.9', NULL), 16), pbes2(None, alg('1.2.840.113549.2.7', NULL))):
        f.append(exp_pdu(enc_data(al)))
    f.append(exp_pdu(enc_data(alg('1.2.840.113549.1.5.14', SEQ(alg(PBKDF2, SEQ(OCT(b'\x22' * 8), INT(10))),
                                                          alg('1.2.840.113549.2.9', NULL))))))
    f.append(exp_pdu(enc_data(alg('1.3.6.1.4.1.11591.4.11', SEQ(OCT(b'\x22' * 8), INT(16384), INT(8), INT(1), INT(32))))))
    f.append(exp_pdu(enc_data(alg('1.3.6.1.4.1.11591.4.11', SEQ(OCT(b'\x22' * 8), INT(16384), INT(8), INT(1))))))
    for o in range(7, 14):
        f.append(exp_pdu(enc_data(alg('1.2.840.113549.2.%d' % o, NULL))))
    f.append(exp_pdu(content_info('1.2.840.113549.1.9.22.1', OCT(cert_with()))))
    # reproducers of the fixed bugs
    bad = []
    for name_, badidx in (('pkcs12_oid_uaf', (1,)), ('pkcs12_salt_uaf', ()), ('pkcs12_dtbl_leak', (0,))):
        for i, fr in enumerate(read_pcap(reproducer(B + name_ + '.py', name_ + '.pcap'))):
            (bad if i in badidx else f).append(fr)
    return f, bad


def pkinit():
    f = [exp_pdu(cms_signed(content=authpack(), ctype='1.3.6.1.5.2.3.1', signers=[signer()])),
         exp_pdu(cms_signed(content=authpack(False), ctype='1.3.6.1.5.2.3.1', signers=[signer()])),
         exp_pdu(cms_signed(content=kdc_dh_key_info(), ctype='1.3.6.1.5.2.3.2', signers=[signer()])),
         exp_pdu(cms_signed(content=kdc_dh_key_info(False), ctype='1.3.6.1.5.2.3.2', signers=[signer()])),
         exp_pdu(cms_signed(certs=[cert_with((ext_san(gn_other('1.3.6.1.5.2.2', krb5_principal())),))])),
         exp_pdu(cms_signed(certs=[cert_with((ext_san(gn_other('1.3.6.1.5.2.2', krb5_principal('R', ('a', 'b', 'c')))),))]))]
    return (f
), []
