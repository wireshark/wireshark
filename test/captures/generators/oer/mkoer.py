#!/usr/bin/env python3
# Generates test/captures/oer_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic captures for packet-oer.c (the OER runtime library, used by
packet-ieee1609dot2.c).  Usage: mkoer.py <outdir> [-v]
Frames are IEEE 1609.2 PDUs in Exported PDU frames naming
"ieee1609dot2.data".  lib1609.py is the IEEE 1609.2 generator (its frames
form the first part of the main capture); this script adds the OER
encodings that generator does not produce: long-form length determinants,
negative and long INTEGERs, long-form quantities and enumerated values,
unknown extension additions, the reproducers of the OER fixes.
All signatures, hashes, keys and ciphertexts are constant placeholder octet
strings; nothing is verified or decrypted."""
import sys
import os
from lib1609 import (
    cert_explicit, cert_implicit, ch, exported_pdu, header_info, L, octets, payload_hash, pcapng,
    psid_group, psid_ssp, seqof, signature, signer_certs, signer_self, tbs, uint_len,
)
import lib1609

def fixlen(n, octs):                       # long-form length / quantity with 'octs' octets
    return bytes([0x80 | octs]) + n.to_bytes(octs, 'big')
def qtyf(n, octs): return bytes([octs]) + n.to_bytes(octs, 'big')       # quantity: length + unsigned
def seqof_f(items, octs): return qtyf(len(items), octs) + b''.join(items)

def unsecured(b, octs=None):               # Ieee1609Dot2Data unsecuredData with a chosen length form
    return b'\x03' + ch(0, (fixlen(len(b), octs) if octs else L(len(b))) + b)

def sd(tbsdata, signer, sig, hashid=b'\x00'):
    return b'\x03' + ch(1, hashid + tbsdata + signer + sig)

def run(outdir, verbose=False):
    fr, mm, marks = lib1609.build(None, False)
    nbase = len(fr)
    desc = []
    def add(d, pdu):
        fr.append(exported_pdu('ieee1609dot2.data', pdu)); desc.append((len(fr), d))
    def addm(pdu): mm.append(exported_pdu('ieee1609dot2.data', pdu))
    sig0 = signature('p256', 'x')
    hdr = header_info(32)
    base_tbs = tbs(payload_hash(0), hdr)

    # ---- length determinants: 1, 2, 3 and 4 octet long forms (8.6.5) and the short form
    for octs in (1, 2, 3, 4):
        add('unsecuredData, length determinant in long form with %d octet(s)' % octs, unsecured(b'oer-%d' % octs, octs))
    add('unsecuredData, 130 octets (canonical long form)', unsecured(bytes(range(130))))
    add('unsecuredData, 300 octets (two octet long form)', unsecured(bytes(300)))
    # ---- enumerated (HashAlgorithm) in long form, 1 to 4 octets
    for octs in (1, 2, 3, 4):
        add('hashId encoded as enumerated long form %d octet(s)' % octs,
            sd(base_tbs, signer_self(), sig0, hashid=fixlen(0, octs)))
    # ---- INTEGER: negative, 1 to 4 octets, in the PsidGroupPermissions of certIssuePermissions
    def cert_with_groups(groups):
        return sd(base_tbs, signer_certs([cert_explicit(cid=ch(3), issue=seqof(groups))]), sig0)
    add('certIssuePermissions: minChainLength / chainLengthRange as INTEGER of 1, 2, 3 and 4 octets, negative and positive',
        cert_with_groups([psid_group(-5, -2), psid_group(-300, 128), psid_group(-70000, 65535),
                          psid_group(0x12345678, -0x12345678), psid_group(255, 256), psid_group(-128, 127)]))
    # ---- sequence-of quantities in 1 to 4 octet forms (17.2)
    for octs in (1, 2, 3, 4):
        items = [psid_ssp(36 + k) for k in range(3)]
        add('appPermissions SEQUENCE OF with a quantity of %d octet(s)' % octs,
            sd(base_tbs, signer_certs([cert_explicit(app=seqof_f(items, octs))]), sig0))
    add('certificate chain whose SEQUENCE OF quantity has 2 octets',
        sd(base_tbs, ch(1, qtyf(2, 2) + cert_implicit() + cert_implicit()), sig0))
    # ---- extension additions the type does not know (octet string fallback)
    def hi_unknown(bitmap, extra):
        return b'\x80' + uint_len(32) + bitmap + extra
    add('headerInfo with an unknown extension addition (bit 4)',
        sd(tbs(payload_hash(0), hi_unknown(bytes([2, 3, 0x08]), octets(b'future'))), signer_self(), sig0))
    add('headerInfo with two unknown extension additions (bits 5 and 7)',
        sd(tbs(payload_hash(0), hi_unknown(bytes([2, 0, 0x05]), octets(b'xyz') + octets(b'abcd'))), signer_self(), sig0))
    add('headerInfo with a two octet extension bitmap, unknown additions in the second octet',
        sd(tbs(payload_hash(0), hi_unknown(bytes([3, 0, 0x00, 0x80]), octets(b'second'))), signer_self(), sig0))
    # ---- reproducers: open type length (contributedExtensions, two extns) and the
    # named-bits subtree of a fixed-size BIT STRING that is not at offset 0
    blocks = bytes([0x01, 0x01, 0x02, 0x01, 0x02, 0x03, 0x41, 0x42, 0x43, 0x01, 0x44])
    d = bytes([0x03, 0x81, 0x00, 0x00, 0x80, 0x01, 0x20, 0x02, 0x04, 0x10, len(blocks)]) + blocks + bytes([0x82]) + sig0
    add('reproducer of "OER: Fix open type, any OID and NULL lengths": HeaderInfo.contributedExtensions with two extns', d)
    named = bytes([0x03, 0x81, 0x00, 0x00, 0x00, 0x01, 0x20, 0x81, 0x01, 0x01, 0x00, 0x03, 0x00, 0x81, 0x00,
                   0x08, 0x83, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x84, 0x00, 0x01,
                   0x01, 0x01, 0x20, 0x81, 0xC0]) + bytes(40)
    add('reproducer: EndEntityType named bits (app, enrol) of a fixed-size BIT STRING that is not at offset 0',
        cert_with_groups([psid_group(None, None, 0xC0)]))
    add('EndEntityType with only the enrol bit and the app bit, several groups',
        cert_with_groups([psid_group(None, None, 0x40), psid_group(None, None, 0x80), psid_group(None, None, 0x00)]))
    # The two PDUs the IEEE 1609.2 generator keeps for its malformed capture (open types of unknown
    # type): with the open type length handled correctly they decode
    for k, dfr in enumerate(lib1609_deferred_pdus()):
        fr.append(dfr)
        desc.append((len(fr), ('certificate with flags BIT STRING and extensions in open types',
                               'headerInfo with contributedExtensions in open types')[k]))

    # ---------------------------------------------------- malformed
    # (truncated) variants of the reproducers
    addm(d[:-45]); addm(d[:20])
    addm(named[:-41]); addm(named[:30]); addm(named)   # the original reproducer ends inside the certificate
    # length determinants: 5 or more octets (not handled), truncated long forms
    addm(b'\x03' + ch(0, b'\x85\x00\x00\x00\x00\x05abcde'))
    addm(b'\x03' + ch(0, b'\xff'))
    addm(b'\x03' + ch(0, b'\x82\x00'))
    addm(b'\x03' + ch(0, b'\x84\x00\x00'))
    addm(b'\x03' + ch(0, b'\x83\x00\x00'))
    addm(b'\x03' + ch(0, b'\x82\xff\xff' + b'x' * 10))
    # INTEGER of 0 octets and of 5 octets (PsidGroupPermissions.minChainLength), and the
    # unconstrained unsigned Psid with a length of 0 and of 5 octets
    for ib in (b'\x00', b'\x05\x01\x02\x03\x04\x05'):
        addm(sd(base_tbs, signer_certs([cert_explicit(cid=ch(3), issue=seqof([bytes([0x80]) + ch(1) + ib]))]), sig0))
    for pb in (b'\x00', b'\x05\x01\x02\x03\x04\x05'):
        addm(sd(tbs(payload_hash(0), b'\x00' + pb), signer_self(), sig0))
    # sequence-of quantity of 0 and of 5 octets
    addm(sd(base_tbs, signer_certs([cert_explicit(app=b'\x00')]), sig0))
    addm(sd(base_tbs, signer_certs([cert_explicit(app=b'\x05\x00\x00\x00\x00\x01' + psid_ssp(36))]), sig0))
    addm(sd(base_tbs, ch(1, b'\x05\x00\x00\x00\x00\x01'), sig0))
    addm(sd(base_tbs, ch(1, b'\x84\xff\xff\xff\xff'), sig0))
    # choice with a tag of 63 or more (first octet 0xbf and a second tag octet)
    addm(b'\x03\xbf\x40' + L(3) + b'abc')
    addm(b'\x03\xbf\x01' + L(3) + b'abc')
    addm(b'\x03\xbf\x80\x01abc')
    addm(b'\x03\xbf')
    # choice class bits: universal, application, private tags for the content
    addm(b'\x03\x00' + L(3) + b'abc'); addm(b'\x03\x40' + L(3) + b'abc'); addm(b'\x03\xc1' + L(3) + b'abc')
    # extension bitmap: unused-bit octet above 7, zero length, long bitmap, bitmap past the data
    addm(sd(tbs(payload_hash(0), b'\x80' + uint_len(32) + bytes([2, 9, 0x80])), signer_self(), sig0))
    addm(sd(tbs(payload_hash(0), b'\x80' + uint_len(32) + bytes([0])), signer_self(), sig0))
    addm(sd(tbs(payload_hash(0), b'\x80' + uint_len(32) + bytes([40]) + bytes(40)), signer_self(), sig0))
    addm(sd(tbs(payload_hash(0), b'\x80' + uint_len(32) + bytes([2, 3, 0x08]) + octets(b'x' * 50)[:20]), signer_self(), sig0))
    # open type longer than the data, an open type of length 0
    addm(sd(base_tbs, signer_certs([cert_explicit(adds={0: b'\x80'}, app=seqof([psid_ssp(36)]))])[:-60], sig0))
    # enumerated long form that runs out of data
    addm(sd(base_tbs, signer_self(), sig0, hashid=b'\x84\x00\x00'))
    # BIT STRING (EndEntityType) cut after its offset
    addm(cert_with_groups([psid_group(None, None, 0x40)])[:-30])

    os.makedirs(outdir, exist_ok=True)
    pcapng(os.path.join(outdir, 'oer-coverage.pcapng'), fr, ifaces=(252,))
    pcapng(os.path.join(outdir, 'oer-coverage-malformed.pcapng'), [(0, f[1]) for f in mm], ifaces=(252,))
    if verbose:
        print(nbase, 'frames from the IEEE 1609.2 generator, frame numbers of the rest:')
        for k, t in desc: print(k, t)
        print(len(fr), 'frames;', len(mm), 'malformed frames')

def lib1609_deferred_pdus():
    """The two PDUs that generator keeps for its malformed capture because
    open types of unknown type are not skipped by older versions (the open
    type length is now handled correctly)."""
    fr, mm, marks = lib1609.build(None, False)
    return mm[:2]

if __name__ == '__main__':
    run(sys.argv[1] if len(sys.argv) > 1 else '.', '-v' in sys.argv)
