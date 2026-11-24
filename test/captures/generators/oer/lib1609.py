#!/usr/bin/env python3
# Helper module for the oer capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic captures for the IEEE 1609.2 (OER) dissector, packet-ieee1609dot2.c
(generated from asn1/ieee1609dot2/; the hand-written parts are the unsecured
data / psid / SSP sub-dissector calls and the latitude, longitude and time
formatters).  Usage: mkieee1609dot2.py <outdir> [-v]   (needs pcaplib.py)
PDUs are carried in Exported PDU frames naming "ieee1609dot2.data".
Every signature, hash, key and ciphertext is a constant placeholder octet
string (0x00, 0x11, ... patterns), never real cryptographic material, and the
dissector verifies or decrypts nothing."""
import struct
import sys
import os
from pcaplib import exported_pdu, pcapng

# ------------------------------------------------------------ OER building blocks
def L(n):                       # length determinant
    return bytes([n]) if n < 128 else (bytes([0x80 | 1, n]) if n < 256 else bytes([0x80 | 2]) + struct.pack('>H', n))
def octets(b): return L(len(b)) + b
def qty(n): return bytes([1, n]) if n < 256 else b'\x02' + struct.pack('>H', n)    # SEQUENCE OF quantity
def uint_len(v):                # INTEGER (0..MAX): length + unsigned value
    b = v.to_bytes(max(1, (v.bit_length() + 7) // 8), 'big'); return L(len(b)) + b
def sint_len(v):                # unconstrained INTEGER: length + signed value
    n = 1
    while not (-(1 << (8 * n - 1)) <= v < (1 << (8 * n - 1))): n += 1
    return L(n) + v.to_bytes(n, 'big', signed=True)
def ch(i, body=b''): return bytes([0x80 | i]) + body             # CHOICE alternative (tag)
def ext(i, body): return bytes([0x80 | i]) + octets(body)         # extension alternative (open type)
def ph(n, tag=0x11): return bytes((tag + k) & 0xff for k in range(n))   # placeholder octets
def seqof(items): return qty(len(items)) + b''.join(items)

# ------------------------------------------------------------ base types
def p256(kind='x'):
    return {'x': ch(0, ph(32)), 'fill': ch(1), 'y0': ch(2, ph(32, 0x21)), 'y1': ch(3, ph(32, 0x31)),
            'unc': ch(4, ph(32, 0x41) + ph(32, 0x51))}[kind]
def p384(kind='x'):
    return {'x': ch(0, ph(48)), 'fill': ch(1), 'y0': ch(2, ph(48, 0x21)), 'y1': ch(3, ph(48, 0x31)),
            'unc': ch(4, ph(48, 0x41) + ph(48, 0x51))}[kind]
def signature(kind='p256', pt='x'):
    if kind == 'p256': return ch(0, p256(pt) + ph(32, 0x61))
    if kind == 'bp256': return ch(1, p256(pt) + ph(32, 0x61))
    if kind == 'bp384': return ext(2, p384(pt) + ph(48, 0x61))
    if kind == 'p384': return ext(3, p384(pt) + ph(48, 0x61))
    if kind == 'sm2': return ext(4, ph(32) + ph(32, 0x61))
def lat(v): return struct.pack('>i', v)
def threed(la=486000000, lo=22000000, el=3000): return lat(la) + lat(lo) + struct.pack('>H', el)
def twod(la, lo): return lat(la) + lat(lo)
def hashed_data(kind=0):
    return [ch(0, ph(32)), ext(1, ph(48)), ext(2, ph(32))][kind]

def header_info(psid=32, gen=None, exp=None, loc=None, p2pcd=None, missing=None, enckey=None,
                inline=None, reqcert=None, pdutype=None, contrib=None):
    bits = 0
    body = uint_len(psid)
    if gen is not None: bits |= 0x40; body += struct.pack('>Q', gen)
    if exp is not None: bits |= 0x20; body += struct.pack('>Q', exp)
    if loc is not None: bits |= 0x10; body += loc
    if p2pcd is not None: bits |= 0x08; body += p2pcd
    if missing is not None: bits |= 0x04; body += b'\x00' + missing[0] + struct.pack('>H', missing[1])
    if enckey is not None: bits |= 0x02; body += enckey
    adds = []
    if inline is not None: adds.append((0, octets(seqof(inline))))
    if reqcert is not None: adds.append((1, octets(reqcert)))
    if pdutype is not None: adds.append((2, octets(bytes([pdutype]))))
    if contrib is not None: adds.append((3, octets(contrib)))
    pre = bytes([bits | (0x80 if adds else 0)])
    if adds:
        bm = 0
        for i, _ in adds: bm |= 0x80 >> i
        body += bytes([2, 4, bm])
        body += b''.join(a for _, a in adds)
    return pre + body

def enc_key_public(pt='x'): return ch(0, b'\x00' + ch(0, p256(pt)))
def enc_key_sym(): return ch(1, ch(0, ph(16)))

# ------------------------------------------------------------ certificates
def region(kind):
    if kind == 'circ': return ch(0, twod(480000000, 10000000) + struct.pack('>H', 500))
    if kind == 'rect': return ch(1, seqof([twod(480000000, 10000000) + twod(470000000, 11000000)]))
    if kind == 'poly': return ch(2, seqof([twod(1, 2), twod(3, 4), twod(5, 6)]))
    if kind == 'ident': return ch(3, seqof([ch(0, struct.pack('>H', 56)),
                                              ch(1, struct.pack('>H', 56) + seqof([bytes([1]), bytes([2])])),
                                              ch(2, struct.pack('>H', 56) + seqof([bytes([1]) + seqof([b'\x00\x01', b'\x00\x02'])]))]))
def psid_ssp(psid, ssp=None):
    if ssp is None: return b'\x00' + uint_len(psid)
    return b'\x80' + uint_len(psid) + ssp
def psid_group(minchain=None, rng=None, eetype=None, subj='all', ranges=()):
    pre = (0x80 if minchain is not None else 0) | (0x40 if rng is not None else 0) | (0x20 if eetype is not None else 0)
    b = bytes([pre])
    if subj == 'all': b += ch(1)
    else: b += ch(0, seqof(list(ranges)))
    if minchain is not None: b += sint_len(minchain)
    if rng is not None: b += sint_len(rng)
    if eetype is not None: b += bytes([eetype])
    return b
def psid_range(psid, sspr=None):
    if sspr is None: return b'\x00' + uint_len(psid)
    return b'\x80' + uint_len(psid) + sspr

def tbs_cert_ext(base, adds):
    """turn a ToBeSignedCertificate without additions into one with extension additions
    adds: dict index -> encoded value (flags 0, appExtensions 1, certIssueExtensions 2, certRequestExtension 3)"""
    bm = 0
    for i in adds: bm |= 0x80 >> i
    return bytes([base[0] | 0x80]) + base[1:] + bytes([2, 4, bm]) + b''.join(octets(adds[i]) for i in sorted(adds))

def tbs_cert(cid=None, region_=None, assurance=None, app=None, issue=None, request=None, rollover=False,
             enckey=None, vki=None, duration=6):
    bits = 0
    body = (cid if cid is not None else ch(1, octets(b'testcert'))) + ph(3) + struct.pack('>H', 7)
    body += struct.pack('>I', 0x1234abcd) + ch(duration, struct.pack('>H', 10))
    if region_ is not None: bits |= 0x40; body += region_
    if assurance is not None: bits |= 0x20; body += assurance
    if app is not None: bits |= 0x10; body += app
    if issue is not None: bits |= 0x08; body += issue
    if request is not None: bits |= 0x04; body += request
    if rollover: bits |= 0x02
    if enckey is not None: bits |= 0x01; body += enckey
    body += vki if vki is not None else ch(0, ch(0, p256('x')))
    return bytes([bits]) + body

def cert_explicit(issuer=None, adds=None, **kw):
    t = tbs_cert(**kw)
    if adds: t = tbs_cert_ext(t, adds)
    return b'\x80' + b'\x03\x00' + (issuer if issuer is not None else ch(1, b'\x00')) + t + signature('p256', 'x')
def cert_implicit(**kw):
    kw.setdefault('vki', ch(1, p256('y0')))
    return b'\x00' + b'\x03\x01' + ch(0, ph(8)) + tbs_cert(**kw)

# ------------------------------------------------------------ Ieee1609Dot2Data
def data_unsecured(b): return b'\x03' + ch(0, octets(b))
def tbs(payload, header): return payload + header
def payload_data(inner): return b'\x40' + inner
def payload_hash(kind=0): return b'\x20' + hashed_data(kind)
def signed(tbsdata, signer, sig, hashid=0):
    return b'\x03' + ch(1, bytes([hashid]) + tbsdata + signer + sig)
def signer_digest(): return ch(0, ph(8))
def signer_self(): return ch(2)
def signer_certs(certs): return ch(1, seqof(certs))
def ckey(kind):         # EncryptedDataEncryptionKey
    if kind == 'p256': return ch(0, p256('x') + ph(16) + ph(16, 0x71))
    if kind == 'bp': return ch(1, p256('unc') + ph(16) + ph(16, 0x71))
    return ext(2, p256('y1') + ph(16) + ph(32, 0x71))
def ccm(): return ph(12) + octets(ph(24, 0xe0))
def sym_ct(sm4=False): return ext(1, ccm()) if sm4 else ch(0, ccm())
def recip(kind):
    if kind == 'psk': return ch(0, ph(8))
    if kind == 'symm': return ch(1, ph(8) + sym_ct())
    return {'cert': ch(2, ph(8) + ckey('p256')), 'sd': ch(3, ph(8) + ckey('bp')), 'rek': ch(4, ph(8) + ckey('sm2'))}[kind]
def encrypted(recs, sm4=False):
    return b'\x03' + ch(2, seqof([recip(r) for r in recs]) + sym_ct(sm4))

def build(out, verbose):
    fr, marks = [], []
    deferred = []     # PDUs with open types of unknown type: packet-oer.c does not skip their content
    def add(desc, pdu):
        fr.append(exported_pdu('ieee1609dot2.data', pdu)); marks.append((len(fr), desc))
    # unsecured and the two simple extension/opaque choices
    add('unsecuredData', data_unsecured(b'hello world'))
    add('unsecuredData, empty', data_unsecured(b''))
    add('signedCertificateRequest (opaque)', b'\x03' + ch(3, octets(ph(20))))
    add('signedX509CertificateRequest (extension alternative)', b'\x03' + ch(4, octets(octets(ph(20)))))
    # signed data: payload and header variants
    sig0 = signature('p256', 'x')
    add('signedData, self, extDataHash sha256, psid 32',
        signed(tbs(payload_hash(0), header_info(32)), signer_self(), sig0))
    add('signedData, sha384 hash, hashId sha384, extDataHash sha384, psid 36, ECDSA P-384 signature (compressed y-0)',
        signed(tbs(payload_hash(1), header_info(36)), signer_self(), signature('p384', 'y0'), hashid=1))
    add('signedData, sm3, extDataHash sm3, psid 37, SM2 signature',
        signed(tbs(payload_hash(2), header_info(37)), signer_self(), signature('sm2'), hashid=2))
    add('signedData with nested unsecured data (no sub-dissector for psid 32), Brainpool P-256 signature, compressed y-1',
        signed(tbs(payload_data(data_unsecured(b'abcd')), header_info(32)), signer_digest(), signature('bp256', 'y1')))
    add('signedData, uncompressed point signature, Brainpool P-384 (fill point)',
        signed(tbs(payload_hash(0), header_info(0x7fffffff)), signer_digest(), signature('bp384', 'fill')))
    add('signedData, P-256 signature with an uncompressed point',
        signed(tbs(payload_hash(0), header_info(0x1234)), signer_digest(), signature('p256', 'unc')))
    gen = (1 << 40) + 123456789
    add('headerInfo: generationTime, expiryTime, location (north/east), p2pcd learning request, missing CRL identifier, encryption key',
        signed(tbs(payload_hash(0), header_info(32, gen=gen, exp=gen + 10 ** 9, loc=threed(486000000, 22000000, 3000),
               p2pcd=ph(3), missing=(ph(3), 9), enckey=enc_key_public('x'))), signer_self(), sig0))
    add('headerInfo: southern/western location, unavailable lat/lon/elevation, symmetric encryption key',
        signed(tbs(payload_hash(0), header_info(32, gen=0, exp=2 ** 63, loc=threed(-33000000, -151000000, 65535),
               enckey=enc_key_sym())), signer_self(), sig0))
    add('headerInfo: unavailable latitude/longitude, public key (uncompressed), time 0xffff...',
        signed(tbs(payload_hash(0), header_info(32, gen=2 ** 64 - 1, loc=threed(900000001, 1800000001, 0),
               enckey=enc_key_public('unc'))), signer_self(), sig0))
    add('headerInfo: extension additions inlineP2pcdRequest and pduFunctionalType',
        signed(tbs(payload_hash(0), header_info(32, inline=[ph(3), ph(3, 0x40)], pdutype=1)), signer_self(), sig0))
    add('headerInfo: extension addition requestedCertificate',
        signed(tbs(payload_hash(0), header_info(32, reqcert=cert_implicit())), signer_self(), sig0))
    # signer: certificates
    add('signer: certificate chain (explicit certificate with name, region, app permissions)',
        signed(tbs(payload_hash(0), header_info(32)), signer_certs([cert_explicit(
            region_=region('circ'), assurance=b'\x60',
            app=seqof([psid_ssp(36, ch(0, octets(b'\x01\xff\xf0\x0f'))), psid_ssp(37), psid_ssp(40, ext(1, octets(b'\x01\x02\x03')))]),
            enckey=b'\x00' + ch(0, p256('x')))]), sig0))
    add('signer: implicit certificate, rectangular region, link-ed certificate ids',
        signed(tbs(payload_hash(0), header_info(32)), signer_certs([cert_implicit(
            cid=ch(0, b'\x00' + struct.pack('>H', 5) + ph(9)),
            region_=region('rect'), app=seqof([psid_ssp(36)]))]), sig0))
    add('signer: two certificates, polygonal region, linkage data with group linkage value, canRequestRollover',
        signed(tbs(payload_hash(0), header_info(32)), signer_certs([
            cert_explicit(cid=ch(0, b'\x80' + struct.pack('>H', 5) + ph(9) + ph(4) + ph(9)), region_=region('poly'), rollover=True,
                          app=seqof([psid_ssp(36)])),
            cert_implicit(cid=ch(2, octets(ph(10))), region_=region('ident'), app=seqof([psid_ssp(37)]))]), sig0))
    add('signer: certificate with certIssuePermissions and certRequestPermissions, id none, duration years/hours',
        signed(tbs(payload_hash(0), header_info(32)), signer_certs([cert_explicit(
            cid=ch(3), duration=4,
            issue=seqof([psid_group(subj='all'), psid_group(2, 3, 0xc0, 'explicit', [
                psid_range(36), psid_range(37, ch(1)), psid_range(38, ch(0, seqof([octets(b'\x01'), octets(b'')]))),
                psid_range(39, ext(2, octets(ph(1)) + octets(ph(1, 0x80))))])]),
            request=seqof([psid_group(1, 0, 0x80, 'all')]))]), sig0))
    add('signer: certificate with every validity duration unit',
        signed(tbs(payload_hash(0), header_info(32)), signer_certs([cert_explicit(duration=d, app=seqof([psid_ssp(36)])) for d in range(7)]), sig0))
    oid = octets(b'\x2b\x06\x01\x04\x01')
    deferred.append(signed(tbs(payload_hash(0), header_info(32)), signer_certs([cert_explicit(
            app=seqof([psid_ssp(36)]),
            adds={0: b'\x80',
                  1: seqof([b'\x01' + octets(oid), b'\x02' + octets(b'x')]),
                  2: seqof([b'\x01' + ch(0, octets(b'\x05')), b'\x01' + ch(1)]),
                  3: seqof([b'\x01' + ch(0, octets(b'\x06')), b'\x01' + ch(1)])})]), sig0))
    deferred.append(signed(tbs(payload_hash(0), header_info(32, contrib=seqof([b'\x01' + seqof([octets(ph(8))]), b'\x02' + seqof([octets(b'\x01\x02'), octets(b'')])]))), signer_self(), sig0))
    # encrypted data
    add('encryptedData with a pre-shared-key recipient', encrypted(['psk']))
    add('encryptedData with symmetric, certificate, signed-data and rek recipients', encrypted(['symm', 'cert', 'sd', 'rek']))
    add('encryptedData with SM4-CCM ciphertext and no recipients', encrypted([], sm4=True))
    if out: os.makedirs(out, exist_ok=True)
    if out: pcapng(os.path.join(out, 'ieee1609dot2-coverage.pcapng'), fr, ifaces=(252,))
    nmain = len(fr)

    # --------------------------------------------------- malformed / state-dependent capture
    mal, mm = [], []
    def addm(pdu): mm.append(exported_pdu('ieee1609dot2.data', pdu))
    for d in deferred: addm(d)
    base = signed(tbs(payload_hash(0), header_info(32)), signer_self(), sig0)
    for cut in (1, 2, 3, 5, 9, 20, 45, len(base) - 1):
        addm(base[:cut])
    addm(b'\x04' + base[1:])                                         # protocolVersion 4
    addm(b'\x03' + bytes([0x87]) + b'\x00')                         # unknown content choice
    addm(b'\x03' + ch(5, octets(b'x')))                              # unknown extension alternative
    addm(b'\x03' + ch(0, b'\x85abc'))                                # opaque length beyond the data
    addm(signed(tbs(payload_hash(0), header_info(32, loc=threed(), enckey=enc_key_public('unc'))), signer_digest(), signature('p384', 'unc'))[:-30])
    addm(signed(tbs(payload_hash(0), header_info(32, reqcert=cert_implicit())), signer_self(), sig0)[:60])
    addm(signed(tbs(payload_hash(0), header_info(32)), ch(1, qty(200) + b'\x00'), sig0))   # 200 certificates announced
    addm(signed(tbs(payload_hash(0), header_info(32)), signer_self(), ch(9, ph(10))))     # unknown signature alternative
    # unsecured data given to the PSID sub-dissector (psid 256: SecuredCrl, psid 36/37: GeoNetworking)
    # The sub-dissector is called from two places and the psid is remembered in file-scope data,
    # so the first pass and "tshark -2" show the sub-tree at different places.
    inner = bytes.fromhex('0380 02 abcd'.replace(' ', ''))          # Ieee1609Dot2Data{3, unsecuredData 'abcd'}
    addm(signed(tbs(payload_data(data_unsecured(inner)), header_info(256)), signer_self(), sig0))
    addm(signed(tbs(payload_data(data_unsecured(ph(30))), header_info(36)), signer_self(), sig0))
    addm(signed(tbs(payload_data(data_unsecured(ph(30))), header_info(37)), signer_self(), sig0))
    # SecuredCrl (psid 256): signedData with CrlContents of every type
    def crl(typespec, prio=None):
        contents = b'\x01' + struct.pack('>H', 3) + ph(8) + struct.pack('>II', 1000, 2000) \
            + (b'\x40' + bytes([prio]) if prio is not None else b'\x00') + typespec
        return ch(0, contents)
    def hashcrl(i, n=2): return ch(i, b'\x00' + struct.pack('>I', 7) + seqof([b'\x00' + ph(10, 0x10 * (k + 1)) + struct.pack('>I', 500 + k) for k in range(n)]))
    def indiv(): return seqof([b'\x00' + b'\x07' + seqof([b'\x00' + ph(2) + ph(2, 0x20) + seqof([b'\x00' + struct.pack('>H', 9) + seqof([b'\x00' + ph(16) + ph(16, 0x40)])])])])
    def grp(): return seqof([b'\x00' + struct.pack('>H', 9) + ph(2) + ph(16) + ph(2, 0x20) + ph(16, 0x40)])
    def linked(i, which):
        pre = {'ind': 0x40, 'grp': 0x20}[which]
        return ch(i, bytes([pre]) + struct.pack('>H', 5) + b'\x03' + (indiv() if which == 'ind' else grp()))
    def seccrl(typespec, prio=None):
        return ch(0, b'\x80' + crl(typespec, prio) + header_info(256))
    def withalg(i, which):
        pre = {'ind': 0x40, 'grp': 0x20, 'single': 0x10}[which]
        body = bytes([pre]) + struct.pack('>H', 5) + b'\x03'
        if which == 'ind': body += indiv()
        elif which == 'grp': body += grp()
        else: body += seqof([b'\x00' + struct.pack('>H', 9) + ph(2) + ph(2, 0x20) + ph(16)])
        return ext(i, body)
    def indiv_single():
        return seqof([b'\x00' + b'\x07' + seqof([b'\x00' + ph(2) + ph(2, 0x20) + seqof([b'\x80' + struct.pack('>H', 9) + seqof([b'\x00' + ph(16) + ph(16, 0x40)]) + bytes([2, 7, 0x80]) + octets(seqof([ph(16)]))])])])
    for ts, pr in ((withalg(4, 'ind'), None), (withalg(5, 'grp'), 2), (withalg(4, 'single'), None),
                   (ch(2, b'\x40' + struct.pack('>H', 5) + b'\x03' + indiv_single()), None),
                   (hashcrl(0), None), (hashcrl(1, 3), 5), (linked(2, 'ind'), None), (linked(3, 'grp'), 9), (hashcrl(0, 0), None)):
        scrl = seccrl(ts, pr)
        addm(signed(tbs(payload_data(data_unsecured(scrl)), header_info(256)), signer_self(), sig0))
    if out: pcapng(os.path.join(out, 'ieee1609dot2-coverage-malformed.pcapng'), [(0, f[1]) for f in mm], ifaces=(252,))
    return fr, mm, marks
    if verbose:
        for k, d in marks: print(k, d)
        print(nmain, 'frames;', len(mm), 'malformed frames')
