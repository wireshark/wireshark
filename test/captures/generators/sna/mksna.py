#!/usr/bin/env python3
# Generates test/captures/sna_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic captures for packet-sna.c (SNA over 802.2 LLC, over PPP, XID).
# Usage: mksna.py <outdir>
import os
import struct
import sys
from pcaplib import Pcapng, eth8023

DLT_EN10MB, DLT_PPP = 1, 9

def u16(x): return struct.pack('!H', x)
def u32(x): return struct.pack('!I', x)

def ebcdic(s): return s.encode('cp037')

# --- LLC wrappers ---------------------------------------------------------
def llc_ui(sap, payload, ssap=None):
    return bytes([sap, (ssap if ssap is not None else sap) | 0, 0x03]) + payload

def llc_i(sap, payload, ns=0, nr=0, resp=0):
    return bytes([sap, sap | resp, ns << 1, nr << 1]) + payload

def llc_xid(sap, payload, resp=0):
    return bytes([sap, sap | resp, 0xaf if not resp else 0xbf]) + payload

def lan(llc, a=0):
    return eth8023(llc)

# --- RH (3 octets) ----------------------------------------------------------
def rh(resp=False, cat=0, fi=1, sdi=0, bci=1, eci=1, b1=0, b2=0):
    b0 = (0x80 if resp else 0) | (cat << 5) | (fi << 3) | (sdi << 2) | (bci << 1) | eci
    return bytes([b0, b1, b2])

# --- transmission headers ---------------------------------------------------
MPF_MIDDLE, MPF_LAST, MPF_FIRST, MPF_WHOLE = 0, 1, 2, 3

def fid01(fid=1, mpf=MPF_WHOLE, efi=0, daf=0x0102, oaf=0x0304, snf=7, dcf=0):
    return bytes([(fid << 4) | (mpf << 2) | efi, 0]) + u16(daf) + u16(oaf) + u16(snf) + u16(dcf)

def fid2(mpf=MPF_WHOLE, odai=0, efi=0, daf=0x12, oaf=0x34, snf=1):
    return bytes([0x20 | (mpf << 2) | (odai << 1) | efi, 0, daf, oaf]) + u16(snf)

def fid3(mpf=MPF_WHOLE, efi=0, lsid=5):
    return bytes([0x30 | (mpf << 2) | efi, lsid])

def fid4(mft=0, b0=0xc0, snf=0x2222, dcf=0x0007, dsaf=0x11223344, osaf=0x55667788,
         def_=0x0102, oef=0x0304, b2=0x3f, b3=0x85, b4=0x1234, b6=0xabcd, b16=0xc1):
    return (bytes([0x40 | (b0 & 0x0f), 0x04 if mft else 0x00, b2, b3]) + u16(b4) + u16(b6)
            + u32(dsaf) + u32(osaf) + bytes([b16, 0]) + u16(def_) + u16(oef)
            + u16(snf) + u16(dcf))

def fid5(mpf=MPF_WHOLE, efi=0, snf=0x0102):
    return bytes([0x50 | (mpf << 2) | efi, 0]) + u16(snf) + bytes(range(0xa0, 0xa8))

def fidf(fmt=1, typ=2, sn=0x0033, dcf=0x0001):
    return bytes([0xf0, 0, fmt, typ]) + u16(sn) + bytes(18) + u16(dcf)

# --- control vectors --------------------------------------------------------
def cv_lt(key, data=b''):
    return bytes([len(data) + 2, key]) + data

def cv_kl(key, data=b''):
    return bytes([key, len(data)]) + data

def pad4(b):
    return b + b'\0' * ((-len(b)) % 4)

def cv05hpr(subs, ptp=0x80, hdr=True):
    # length, key 5, flags, reserved, then padded length/key vectors. The
    # length counts the whole vector, except in the THDR where it does not
    # count the length and key octets.
    body = bytes([ptp, 0]) + b''.join(pad4(s) for s in subs)
    return bytes([len(body) + (2 if hdr else 0), 5]) + body

# --- XID --------------------------------------------------------------------
def xid(fmt, typ, body, idnum=0x05d12345, length=None):
    n = 6 + len(body) if length is None else length
    return bytes([(fmt << 4) | typ, n]) + u32(idnum) + body

def xid3_body(b8=0xc0e0, b10=0x90, b11=0x80, b12=0xc0, b15=0xff, tg=1, dlc=1, dlc_data=b'', cvs=b''):
    return (b'\0\0' + u16(b8) + bytes([b10, b11, b12]) + b'\0\0' + bytes([b15, tg, dlc, len(dlc_data) + 1])
            + dlc_data + cvs)

# --- NLP (HPR) --------------------------------------------------------------
def thdr(tcid=b'\x01\x02\x03\x04\x05\x06\x07\x08', f8=0x20, f9=0x00, dlf=0, bsn=1, cv=b'', opts=b''):
    body = cv + opts
    body = pad4(body)
    n = 20 + len(body)
    return tcid + bytes([f8, f9]) + u16(n // 4) + u32(dlf) + u32(bsn) + body

def nlp_anr(thdr_bytes, payload=b'', route=b'\x81\x82\x83', n0=0xc3, n1=0x20):
    return bytes([n0, n1]) + route + b'\xff' + b'\0' + thdr_bytes + payload

def nlp_fr(thdr_bytes, payload=b'', route=b'\x01\x02', n0=0xa5, n1=0x20, frh=None):
    if frh is not None:
        return bytes([n0, 0x10 | (n1 & 0x0f)]) + route + b'\xff' + b'\0' + bytes([frh]) + payload
    return bytes([n0, n1]) + route + b'\xff' + b'\0' + thdr_bytes + payload

def opt(typ, body):
    b = bytes([0, typ]) + body
    b += b'\0' * ((-len(b)) % 4)
    return bytes([len(b) // 4]) + b[1:]

def opt_0d(cvs, flags=0xf0):
    body = u16(0x0101) + bytes([flags]) + b'\0\0\0' + b''.join(pad4(c) for c in cvs)
    return opt(0x0d, body)

def opt_0e(idle=False, extra=b''):
    return opt(0x0e, bytes([0x40 if idle else 0xa0]) + bytes([3]) + u16(0x1111) + u16(0x2222)
               + u32(0x33333333) + bytes(8) + extra)

def opt_0f(bits=0x0001, extra=b''):
    return opt(0x0f, u16(bits) + extra)

def opt_10(extra=b''):
    return opt(0x10, b'\0\0' + bytes(range(1, 9)) + extra)

def opt_12(sense=b'\x08\x01\x00\x00'):
    return opt(0x12, b'\0\0' + sense)

def opt_14(good=True, rr_ok=True, extra_cv=None):
    si_cvs = b''.join(pad4(c) for c in [cv_lt(0x00, b'\0' * 6)])
    si_len = 16 + len(si_cvs) + 0
    si = bytes([si_len, 0x83 if good else 0x84, 0xfc, 0]) + u32(1500) + u32(2) + u32(30) + si_cvs
    if si_len <= 16:
        si = bytes([8, 0x83, 0, 0]) + bytes(12)
    rr_cvs = cv_lt(0x00, b'\0' * 6) + cv_lt(0x03, b'AB')
    rr = bytes([4 + len(rr_cvs), 0x85 if rr_ok else 0x86, 0x80, 2]) + rr_cvs
    return opt(0x14, b'\0\0' + si + rr)

def opt_22(typ=0, extra=b''):
    b2 = (typ << 6) | 0x08 | 0x01
    body = bytes([b2, 0xc0]) + u32(100) + u32(200)
    if typ == 0:
        body += u32(300) + u32(400)
    return opt(0x22, body + extra)

def opt_unknown():
    return opt(0x30, b'\xde\xad')

# --- GDS --------------------------------------------------------------------
def gds(typ, info, cont_extra=None):
    ll = 4 + len(info)
    return u16(ll) + u16(typ) + info

def main(out):
    p = Pcapng()
    e = p.iface(DLT_EN10MB)
    ppp = p.iface(DLT_PPP)
    def add(payload, ssap_dsap=0x04, kind='ui'):
        if kind == 'ui':
            return p.add(lan(llc_ui(ssap_dsap, payload)), e)
        if kind == 'i':
            return p.add(lan(llc_i(ssap_dsap, payload, ns=1, nr=2)), e)
        raise ValueError(kind)
    data = ebcdic('HELLO SNA')

    # FID0/1 (frames 1-5): one request and one response, FID0, FID1 with efi
    add(fid01(1) + rh() + data)
    add(fid01(0, efi=1, daf=0x0a0b, oaf=0x0c0d) + rh(resp=True, cat=1, b1=0x9a))
    add(fid01(1, mpf=MPF_FIRST, snf=9) + rh(b1=0xe6, b2=0xff) + data, 0x08)
    add(fid01(1, mpf=MPF_LAST, snf=9) + rh(sdi=1), 0x08, 'i')
    add(fid01(1) + rh(cat=3, b1=0x7e, b2=0x55) + data, 0x0c)
    # FID2: whole BIUs, a response, ODAI/EFI (6-9)
    add(fid2() + rh(b1=0xaa, b2=0x81) + data)
    add(fid2(odai=1, efi=1, snf=2) + rh(resp=True, b1=0x55, b2=0x00))
    add(fid2(snf=3) + rh(cat=2, b1=0xff, b2=0xff))
    add(fid2(snf=4) + rh(), 0x40)
    # FID2 BIU in three segments (10-12) and in two (13-14), reassembled
    big = ebcdic('ABCDEFGHIJKLMNOPQRSTUVWXYZ' * 3)
    biu = rh() + big
    add(fid2(MPF_FIRST, snf=0x100) + biu[:30])
    add(fid2(MPF_MIDDLE, snf=0x100) + biu[30:60])
    add(fid2(MPF_LAST, snf=0x100) + biu[60:])
    add(fid2(MPF_FIRST, snf=0x101, daf=0x21, oaf=0x43) + biu[:40], 0x08)
    add(fid2(MPF_LAST, snf=0x101, daf=0x21, oaf=0x43) + biu[40:], 0x08)
    # FID3 (15), FID4 with and without MFT (16-17), FID5 (18), FIDF (19)
    add(fid3() + rh() + data)
    add(fid3(MPF_FIRST, efi=1, lsid=0x42) + rh())
    add(fid4(mft=0) + rh() + data)
    add(fid4(mft=1, b0=0xf3, b16=0x73) + rh(resp=True) + data)
    add(fid5() + rh() + data)
    add(fid5(MPF_FIRST, efi=1) + rh())
    add(fidf() + data)
    # unknown FIDs 6, 7, 9, e (22-25)
    for fid in (6, 7, 9, 0xe):
        add(bytes([fid << 4]) + data)

    # HPR NLP (frames 26-): ANR, FR, FID5 and fragments
    f5 = fid5() + rh() + data
    cv_a = cv05hpr([cv_lt(0x00, b'\1' * 6), cv_lt(0x03, b'NETID'), cv05hpr([cv_lt(0x00, b'\2' * 6)])])
    add(nlp_anr(thdr(f9=0x04, opts=opt_0d([cv_lt(0x00, b'\1' * 6), cv_lt(0x03, b'ID'), cv05hpr([cv_lt(0x03, b'N')])]))) + f5)
    add(nlp_anr(thdr(f8=0x20, f9=0x08 | 0x04, cv=cv05hpr([cv_lt(0x00, b'\3' * 6)], hdr=False), opts=opt_0e()), f5))
    add(nlp_anr(thdr(f9=0x04, opts=opt_0e(idle=True, extra=b'\x00\x01\x02\x03')), f5))
    add(nlp_anr(thdr(f9=0x04, opts=opt_0f(0x0001)), f5))
    add(nlp_anr(thdr(f9=0x04, opts=opt_0f(0x8000, b'\xaa\xbb\xcc\xdd')), f5))
    add(nlp_anr(thdr(f9=0x04, opts=opt_10()), f5))
    add(nlp_anr(thdr(f9=0x04, opts=opt_10(b'\1\2\3\4')), f5))
    add(nlp_anr(thdr(f9=0x04, opts=opt_12()), f5))
    add(nlp_anr(thdr(f9=0x04, opts=opt_14()), f5))
    add(nlp_anr(thdr(f9=0x04, opts=opt_14(good=False)), f5))
    add(nlp_anr(thdr(f9=0x04, opts=opt_14(rr_ok=False)), f5))
    add(nlp_anr(thdr(f9=0x04, opts=opt_22(0)), f5))
    add(nlp_anr(thdr(f9=0x04, opts=opt_22(1)), f5))
    add(nlp_anr(thdr(f9=0x04, opts=opt_22(2, b'\1\2\3\4')), f5))
    add(nlp_anr(thdr(f9=0x04, opts=opt_22(0, b'\1\2\3\4')), f5))
    add(nlp_anr(thdr(f9=0x04, opts=opt_unknown()), f5))
    add(nlp_anr(thdr(f9=0x04, opts=opt_12() + opt_0f(1) + opt_unknown()), f5))
    # HPR with no optional segment, no payload; ANR "d" nibble
    add(nlp_anr(thdr(f8=0x70, f9=0x80), f5, n0=0xd2))
    add(nlp_anr(thdr(f8=0x20, f9=0x00), b'', n0=0xc0))
    # Fragments: DLF nonzero and no start-of-message flag
    add(nlp_anr(thdr(f8=0x00, f9=0x00, dlf=0x40), b'\x01\x02\x03\x04\x05'))
    add(nlp_anr(thdr(f8=0x00, f9=0x00, dlf=0x40), b''))
    # Function routing: FR list; FR with FRH; FR with THDR
    add(nlp_fr(thdr(f9=0x04, opts=opt_0f(1)), f5))
    add(nlp_fr(b'', b'\x77\x78', frh=0x05))
    add(nlp_fr(b'', b'', frh=0x01, n1=0x03))
    add(nlp_fr(thdr(), f5, n0=0xb1, n1=0x00))
    # Route setup (GDS 12CE) behind a THDR, single and with continuation
    add(nlp_anr(thdr(), gds(0x12ce, ebcdic('ROUTE SETUP'))))
    cont = u16(0x8000 | (4 + 4)) + u16(0x12ce) + b'\1\2\3\4' + u16(2 + 3) + b'xyz' + b'\x00\x00'
    add(nlp_anr(thdr(), u16(0x8000 | 8) + u16(0x12ce) + b'\1\2\3\4' + u16(0x8000 | 5) + b'xyz' + u16(4) + b'\x08\x09'))
    add(nlp_anr(thdr(), gds(0x12ce, b'') + b'\xff\xee'))
    # not FID5 and not route setup: data
    add(nlp_anr(thdr(), b'\x10\x00\x00\x00\x01\x02'))
    # GDS with a first LL of 2 or 3 (escape sequence, fixed on the branch)
    add(nlp_anr(thdr(), u16(2) + u16(0x12ce) + b'\0\0'))
    add(nlp_anr(thdr(), u16(3) + u16(0x12ce) + b'\0\0'))
    add(nlp_anr(thdr(), u16(0x8004) + u16(0x12ce) + u16(2) + b'ab'))

    # XID (LLC XID frames)
    def addxid(body, sap=0x04):
        p.add(lan(llc_xid(sap, body)), e)
    addxid(xid(0, 2, b''))
    addxid(xid(0, 1, b'', length=6) + b'\xaa\xbb', 0x08)       # data after the XID
    addxid(xid(1, 1, b'\0\0'))
    addxid(xid(1, 4, b'\0\0') + b'\x01\x02')
    addxid(xid(2, 2, b'\x08\x00\x00\x00\x00\x00\x00\x00' + cv_kl(0x0e, b'\xf4' + ebcdic('CPNAME')) + cv_kl(0x05, u16(0x1234))), 0x08)
    addxid(xid(2, 2, b'\x02\x00'))
    addxid(xid(3, 2, xid3_body(dlc_data=b'\x01\x02\x03',
        cvs=cv_kl(0x0e, b'\xf1' + ebcdic('PUNAME')) + cv_kl(0x00, b'\0\0\0\0') + cv_kl(0x05, u16(5)))), 0x0c)
    addxid(xid(3, 4, xid3_body(b8=0x0000, b10=0, b11=0, b12=0, b15=0, tg=0, dlc=0), idnum=0x00000001), 0x40)
    addxid(xid(3, 1, xid3_body(b8=0xffff, b10=0xff, b11=0xff, b12=0xff, b15=0xff, dlc_data=b'x',
        cvs=cv_kl(0x0e, b'\xfa' + ebcdic('GEN')) + cv_kl(0x0e, b'\xfa'))))
    addxid(xid(4, 2, b'\x01\x02\x03\x04'))                     # other format: data
    addxid(xid(3, 2, xid3_body(), idnum=0xffffffff) + b'\x00\x01')

    # SNA XID with the PU name
    # SNA over PPP (protocol 0x004d)
    def ppp_frame(payload):
        return b'\xff\x03\x00\x4d' + payload
    p.add(ppp_frame(fid2() + rh() + data), ppp)
    p.add(ppp_frame(fid4() + rh() + data), ppp)
    p.add(ppp_frame(nlp_anr(thdr(f9=0x04, opts=opt_0f(1)), f5)), ppp)

    # extras: THDR control vector that is not key 5, padded vectors in a
    # Connection Setup segment, a Return Route descriptor with an empty vector
    add(nlp_anr(thdr(f9=0x08, cv=bytes([6, 7, 1, 2, 3, 4])), f5))
    add(nlp_anr(thdr(f9=0x04, opts=opt_0d([cv_lt(0x03, b'ABC'), cv_lt(0x00, b'\1' * 5)])), f5))
    si = bytes([20, 0x83, 0xfc, 0]) + u32(1500) + u32(2) + u32(30) + cv_lt(0x00, b'\0\0')
    si += b'\0\0'
    add(nlp_anr(thdr(f9=0x04, opts=opt(0x14, b'\0\0' + si + bytes([8, 0x85, 0x80, 2, 0, 0, 0, 0]))), f5))
    p.write(os.path.join(out, 'sna-coverage.pcapng'))

    # Malformed
    m = Pcapng()
    e = m.iface(DLT_EN10MB)
    def madd(payload, sap=0x04):
        m.add(lan(llc_ui(sap, payload)), e)
    def mxid(body, sap=0x04):
        m.add(lan(llc_xid(sap, body)), e)
    madd(fid01(1)[:6])                                  # truncated TH
    madd(fid2()[:4])
    madd(fid4()[:20] + rh())
    madd(fid5()[:8])
    madd(fidf()[:10])
    madd(fid2(MPF_WHOLE) + b'\x80')                     # RH truncated
    madd(nlp_anr(thdr(f9=0x04, opts=opt_0f(1)), f5)[:18])
    madd(bytes([0xc3, 0x20, 0x81, 0x82]))               # routing list without terminator
    madd(bytes([0xa5, 0x20, 0x81, 0x82]))
    madd(nlp_anr(thdr(f9=0x04, opts=bytes([0, 0x0f, 0, 0])), f5))     # option length 0
    madd(nlp_anr(thdr(f9=0x04, opts=bytes([40, 0x0d]) + bytes(6)), f5))   # option longer than the header
    madd(nlp_anr(thdr(f9=0x04, opts=opt(0x14, b'\0\0' + bytes([40, 0x83]) + bytes(14))), f5))
    madd(nlp_anr(thdr(f9=0x04, opts=opt(0x14, b'\0\0' + bytes([0x14, 0x83, 0, 0]) + bytes(12) + cv_lt(0, bytes(2)) + b'\0\0')), f5))
    madd(nlp_anr(thdr(f9=0x04, opts=opt(0x14, b'\0\0' + bytes([8, 0x83, 0, 0]) + bytes(4) + bytes([4, 0x85, 0, 3]))), f5))
    madd(nlp_anr(thdr(f9=0x04, opts=opt_0d([cv_lt(0x05, b'\x80\x00' + bytes([0, 5]))])), f5))
    madd(nlp_anr(thdr(f9=0x04, opts=opt(0x0d, u16(0x101) + bytes(6) + bytes([0xff, 0, 0, 0]))), f5))
    madd(nlp_anr(thdr(f9=0x04, opts=opt(0x14, b'\0\0' + bytes([0x14, 0x83, 0, 0]) + bytes(12) + cv_lt(0, bytes(2)) + b'\0\0'
         + bytes([6, 0x85, 0x80, 2, 0, 0]))), f5))
    madd(nlp_anr(thdr(f9=0x04, opts=opt(0x14, b'\0\0' + bytes([0x14, 0x83, 0, 0]) + bytes(12) + cv_lt(0, bytes(2)) + b'\0\0'
         + bytes([8, 0x85, 0x80, 1, 0, 0, 0, 0]))), f5))
    madd(nlp_anr(thdr(f9=0x04, opts=opt(0x14, b'\0\0' + bytes([0x14, 0x83, 0, 0]) + bytes(12) + cv_lt(0, bytes(2)) + b'\0\0'
         + bytes([8, 0x85, 0x80, 1, 0, 0, 0, 0]))), f5)[:60])
    madd(nlp_anr(thdr(f9=0x08), f5)[:30])
    madd(u16(0x8004) + u16(0x12ce))
    madd(nlp_anr(thdr(), u16(0x8004) + u16(0x12ce)))
    madd(nlp_anr(thdr(), u16(0x8004) + u16(0x12ce) + u16(0x8010) + b'\0\0'))
    mxid(bytes([0x32, 40, 0, 0, 0, 1]))                 # XID 3 longer than the frame
    mxid(bytes([0x32]))
    mxid(bytes([0x22, 10, 0, 0, 0, 1, 0x08]))           # control vector missing
    mxid(xid(2, 2, b'\x00\x00' + bytes([0x0e, 20, 0xf4])))      # control vector overruns
    mxid(xid(3, 2, xid3_body(dlc_data=b'')[:8]))
    mxid(xid(3, 2, xid3_body(cvs=bytes([0x0e, 30, 0xf4, 0x41]))))
    mxid(xid(3, 2, xid3_body(dlc_data=b'')) + b'')
    # FID2 reassembly mismatch: a last segment with no first segment
    madd(fid2(MPF_LAST, snf=0x777) + b'tail')
    madd(fid2(MPF_MIDDLE, snf=0x778) + b'mid')
    # GDS first LL below four, continuation LL below two
    madd(nlp_anr(thdr(), u16(0x8004) + u16(0x12ce) + u16(1)))
    # Shortlen XID reproducers (fixed on the branch: expert info)
    mxid(bytes([0x32, 0x02, 0, 0, 0, 1]) + bytes(20))
    mxid(bytes([0x22, 0x00, 0, 0, 0, 1, 0x00, 0x0e, 0x02, 0xc1, 0xc2]))
    mxid(bytes([0x12, 0x05, 0, 0, 0, 1]) + bytes(12))
    m.write(os.path.join(out, 'sna-coverage-malformed.pcapng'))

main(sys.argv[1] if len(sys.argv) > 1 else '.')
