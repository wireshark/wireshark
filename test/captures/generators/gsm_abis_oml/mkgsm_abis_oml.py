#!/usr/bin/env python3
# Generates test/captures/gsm_abis_oml_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic captures for packet-gsm_abis_oml.c (A-bis OML, TS 12.21 and the
Siemens BS-11 and ip.access dialects).
Usage: mkgsm_abis_oml.py <outdir> [-v]

Frames are LAPD (pcap linktype 203) UI frames with SAPI 62 (needs the LAPD
preference lapd.use_gsm_sapi_values:TRUE). The dialect is a preference
(gsm_abis_oml.oml_dialect), so the capture is in sections that each decode in
the dialect named in the README: ETSI/default, Siemens, ip.access. The
enumerations and TLV definition tables are read from the dissector source
(SRC) so that every message type and attribute is used."""
import os
SRCDIR = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..', '..'))
import re
import struct
import sys

SRC = os.environ.get('WSSRC', os.path.join(SRCDIR)) + '/epan/dissectors/packet-gsm_abis_oml.c'
S = open(SRC).read()

def write_pcap(path, linktype, pkts):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, p in enumerate(pkts):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
            f.write(p)

def lapd(sapi, tei, payload, cr=0):
    return bytes([(sapi << 2) | (cr << 1), (tei << 1) | 1, 0x03]) + payload

# ---- enumerations and TLV definitions from the source
ENV = {'TLV_TYPE_UNKNOWN': 0, 'TLV_TYPE_FIXED': 1, 'TLV_TYPE_T': 2, 'TLV_TYPE_TV': 3,
       'TLV_TYPE_TLV': 4, 'TLV_TYPE_TL16V': 5, 'TLV_TYPE_TLV16': 6}
FIXED, T_, TV, TLV, TL16V, TLV16 = 1, 2, 3, 4, 5, 6

def enum_block(name):
    i = S.index('enum %s {' % name)
    return S[i:S.index('};', i)]

def load_enum(name):
    names = []
    val = -1
    body = enum_block(name).split('{', 1)[1]
    body = re.sub(r'/\*.*?\*/', '', body, flags=re.S)
    for item in body.split(','):
        item = item.strip()
        if not item:
            continue
        m = re.match(r'(\w+)\s*(?:=\s*(.+))?$', item)
        if not m:
            continue
        n, e = m.groups()
        val = eval(e, {}, ENV) if e else val + 1
        ENV[n] = val
        names.append((n, val))
    return names

MSG = load_enum('abis_nm_msgtype')
MSG_BS11 = load_enum('abis_nm_msgtype_bs11')
MSG_IPA = load_enum('abis_nm_msgtype_ipacc')
OBJ = load_enum('abis_nm_obj_class')
ATT = load_enum('abis_nm_attr')
ATT_BS11 = load_enum('abis_nm_attr_bs11')
ATT_IPA = load_enum('abis_nm_attr_ipa')

def tlvdefs(macro):
    d = {}
    for m in re.finditer(r'%s\((\w+),\s*(TLV_TYPE_\w+),\s*(\d+)\)' % macro, S):
        tag = ENV[m.group(1)] if m.group(1) in ENV else int(m.group(1), 16)
        d[tag] = (ENV[m.group(2)], int(m.group(3)))
    return d

DEF_BASE = tlvdefs('NM_ATT_TLVDEF_BASE')
DEF_BS11 = tlvdefs('NM_ATT_TLVDEV_BS11')
DEF_IPA = tlvdefs('NM_ATT_TLVDEF_IPA')

def tagname(tag):
    for n, v in ATT + ATT_BS11 + ATT_IPA:
        if v == tag:
            return n
    return '0x%02x' % tag

# ---- encoders
def enc(tag, tdef, data=None):
    typ, fl = tdef
    if typ == FIXED:
        data = (data if data is not None else bytes((tag + i) & 0xff for i in range(fl)))
        data = data.ljust(fl, b'\0')[:fl]
        return bytes([tag]) + data
    if typ == T_:
        return bytes([tag])
    if typ == TV:
        return bytes([tag]) + (data if data is not None else b'\x01')[:1]
    if typ == TLV:
        data = data if data is not None else bytes((tag + i) & 0xff for i in range(3))
        return bytes([tag, len(data)]) + data
    if typ == TL16V:
        data = data if data is not None else bytes((tag + i) & 0xff for i in range(4))
        return bytes([tag]) + struct.pack('>H', len(data)) + data
    if typ == TLV16:
        data = data if data is not None else bytes((tag + i) & 0xff for i in range(4))
        return bytes([tag, len(data) // 2]) + data
    raise ValueError

def oml(payload, disc=0x80, placement=0x80, seq=0, length=None):
    return bytes([disc, placement, seq, (len(payload) if length is None else length) & 0xff]) + payload

def fom(mt, oc, bts=0, trx=0, ts=0, attrs=b''):
    return bytes([mt, oc, bts, trx, ts]) + attrs

def manuf(ident, body, **kw):
    return oml(bytes([len(ident)]) + ident + body, disc=0x10, length=len(body), **kw)

def bcch_info(btype, filler=0x30):
    b = struct.pack('<H', btype) + struct.pack('<HBBHHI', 0x0123, 40, 3, 0x0004, 0x00a0, 0x00010002)
    b += bytes([0x2b]) + bytes([0x62, 0xf2, 0x10, 0x00, 0x2a]) + struct.pack('<H', 0x1234)
    # note: the type is read big endian and the other fields little endian
    b = struct.pack('>H', btype) + b[2:]
    for flag in (0x8000, 0x0001, 0x0002, 0x0004):
        if btype & flag:
            b += bytes([filler + (flag & 7)]) * 16
    return b

def test_report(res, ies):
    body = bytes([res])
    for ie, data in ies:
        body += bytes([ie]) + struct.pack('>H', len(data)) + data
    return body

def mkattr(tag, data, defs, extra=None):
    return enc(tag, defs[tag], data)

# ---- special attribute contents (tag -> list of data variants)
def specials():
    N = ENV
    sp = {
        N['NM_ATT_ABIS_CHANNEL']: [bytes([1, 2, 3]), bytes([0, 7, 0xff])],
        N['NM_ATT_ADM_STATE']: [b'\x01', b'\x02', b'\x03', b'\xff', b'\x09'],
        N['NM_ATT_ARFCN_LIST']: [struct.pack('>HHH', 1, 100, 124), struct.pack('>H', 975)],
        N['NM_ATT_RF_MAXPOWR_R']: [b'\x03', b'\x00'],
        N['NM_ATT_AVAIL_STATUS']: [b'', b'\xff', b'\x00', b'\x01', b'\x05', b'\x07', b'\x09'],
        N['NM_ATT_BCCH_ARFCN']: [struct.pack('>H', 20)],
        N['NM_ATT_BSIC']: [b'\x2b'],
        N['NM_ATT_CHAN_COMB']: [bytes([i]) for i in range(0, 9)] + [b'\x20'],
        N['NM_ATT_EVENT_TYPE']: [bytes([i]) for i in range(0, 5)] + [b'\x09'],
        N['NM_ATT_GSM_TIME']: [struct.pack('<H', 0x1c3f)],
        N['NM_ATT_OPER_STATE']: [b'\x01', b'\x02', b'\xff', b'\x07'],
        N['NM_ATT_TEI']: [b'\x19'],
        N['NM_ATT_TSC']: [b'\x05'],
        N['NM_ATT_SEVERITY']: [bytes([i]) for i in range(0, 6)] + [b'\x0b'],
        N['NM_ATT_NACK_CAUSES']: [bytes([c]) for c in (1, 2, 5, 6, 7, 8, 9, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x63)],
        N['NM_ATT_TEST_NO']: [bytes([c]) for c in (1, 2, 3, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x55)],
        N['NM_ATT_HSN']: [b'\x07'],
        N['NM_ATT_MAIO']: [b'\x02'],
        N['NM_ATT_LIST_REQ_ATTR']: [bytes([1, 4, 7, 0x44])],
        N['NM_ATT_INTERF_BOUND']: [bytes([10, 20, 30, 40, 50, 60])],
        N['NM_ATT_GET_ARI']: [bytes([0, 4, 1]), bytes([2, 0x20, 0x21, 4, 2]), bytes([1, 0x06])],
        N['NM_ATT_TEST_REPORT']: [
            test_report(0, [(3, b'\x01\x02'), (8, b'\xaa'), (0x77, b'\x01\x02\x03'), (18, b'\x00\x01'), (4, struct.pack('>HH', 0x0123, 0x4567))]),  # channel usage takes the rest
            test_report(1, []),
            test_report(2, [(6, bcch_info(0x8000))]),
            test_report(3, [(6, bcch_info(0x8001 | 0x0002)), (4, b'\x00\x0a\x00\x0b')]),
            test_report(4, [(6, bcch_info(0x0004)), (6, bcch_info(0x8007))]),
            test_report(0, [(6, bcch_info(0))]),
        ],
    }
    return sp

def ari(not_counted, nested):
    return bytes([len(not_counted)]) + bytes(not_counted) + nested

def ipa_specials():
    N = ENV
    return {
        N['NM_ATT_IPACC_DST_IP']: [bytes([192, 0, 2, 10])],
        N['NM_ATT_IPACC_DST_IP_PORT']: [struct.pack('>H', 3003)],
        N['NM_ATT_IPACC_LOCATION']: [b'Site 1 location'],
        N['NM_ATT_IPACC_UNIT_ID']: [b'1801/0/0'],
        N['NM_ATT_IPACC_UNIT_NAME']: [b'nbts-00-02-95-00-00-01'],
        N['NM_ATT_IPACC_PRIM_OML_CFG_LIST']: [b'\x00' + bytes([192, 0, 2, 20]) + struct.pack('<H', 3002)],
        N['NM_ATT_IPACC_NV_FLAGS']: [bytes([0x1f, 0x7e, 0x01, 0x02, 0x00])],
        N['NM_ATT_IPACC_RAC']: [b'\x01'],
        N['NM_ATT_IPACC_NSEI']: [struct.pack('>H', 1234)],
        N['NM_ATT_IPACC_NSVCI']: [struct.pack('>H', 1235)],
        N['NM_ATT_IPACC_BVCI']: [struct.pack('>H', 1236)],
        N['NM_ATT_IPACC_NS_LINK_CFG']: [struct.pack('>HIH', 23000, 0xc0000203, 23001)],
        N['NM_ATT_IPACC_NS_CFG']: [bytes([3, 3, 3, 3, 30, 3, 10])],
        N['NM_ATT_IPACC_GPRS_PAGING_CFG']: [bytes([20, 2])],
        N['NM_ATT_IPACC_RLC_CFG']: [bytes([10, 11, 12, 13, 14, 15, 16, 17, 18])],
        N['NM_ATT_IPACC_RLC_CFG_2']: [struct.pack('>HHB', 250, 300, 2)],
        N['NM_ATT_IPACC_RLC_CFG_3']: [b'\x05'],
        N['NM_ATT_IPACC_CODING_SCHEMES']: [struct.pack('<H', 0x01ff), b'\x00\x00'],
    }

OBJCLASSES = [v for n, v in OBJ]

def main():
    out = sys.argv[1]
    verbose = '-v' in sys.argv
    frames, notes = [], []
    bad, badnotes = [], []

    def add(note, payload, to_bad=False, sapi=62):
        fr = lapd(sapi, 0, payload)
        if to_bad:
            bad.append(fr); badnotes.append((len(bad), note))
        else:
            frames.append(fr); notes.append((len(frames), note))

    sp = specials()
    sp.update(ipa_specials())
    sections = []

    def section(name):
        sections.append((name, len(frames) + 1))

    # ================= Section 1: ETSI (default dialect) =================
    section('ETSI / default dialect (also decodes with the other dialects, except the three attributes redefined by Siemens)')
    # every base message type with a few attributes
    base_tags = sorted(DEF_BASE)
    redefined = set(DEF_BS11) & set(DEF_BASE)
    plain_tags = [t for t in base_tags if t not in redefined]
    k = 0
    for n, (name, mt) in enumerate(MSG):
        oc = OBJCLASSES[n % len(OBJCLASSES)]
        attrs = b''
        for j in range(3):
            tag = plain_tags[k % len(plain_tags)]; k += 1
            attrs += enc(tag, DEF_BASE[tag], sp.get(tag, [None])[0])
        add('msgtype %s' % name, oml(fom(mt, oc, n & 3, (n >> 2) & 7, n & 7, attrs), seq=n & 0xf))
    # message types that are not in the tables
    for mt in (0x00, 0x7f, 0xff):
        add('unknown message type 0x%02x' % mt, oml(fom(mt, 1, 0, 0, 0xff, enc(ENV['NM_ATT_ADM_STATE'], DEF_BASE[ENV['NM_ATT_ADM_STATE']], b'\x02'))))
    # every base attribute with every special variant
    n = 0
    for tag in base_tags:
        if tag in redefined:
            continue
        variants = sp.get(tag, [None])
        for v in variants:
            n += 1
            add('attribute %s variant' % tagname(tag), oml(fom(ENV['NM_MT_SET_BTS_ATTR'], 1, 0, 0, 0xff, enc(tag, DEF_BASE[tag], v))))
    # a message with every attribute at once (long)
    def chunked(note, items, mk):
        cur = b''
        part = 1
        for it in items + [None]:
            if it is None or len(cur) + len(it) > 200:
                if cur:
                    add('%s (part %d)' % (note, part), mk(cur)); part += 1
                cur = b''
            if it is not None:
                cur += it
    chunked('all attributes in one message', [enc(t, DEF_BASE[t], sp.get(t, [None])[0]) for t in plain_tags],
            lambda a: oml(fom(ENV['NM_MT_GET_ATTR'], 1, 0, 0, 0xff, a)))
    # Get Attribute Response Info (recursive)
    adm = enc(ENV['NM_ATT_ADM_STATE'], DEF_BASE[ENV['NM_ATT_ADM_STATE']], b'\x02')
    opr = enc(ENV['NM_ATT_OPER_STATE'], DEF_BASE[ENV['NM_ATT_OPER_STATE']], b'\x02')
    inner = ari([ENV['NM_ATT_TSC'], ENV['NM_ATT_HSN']], adm + opr)
    gari = ENV['NM_ATT_GET_ARI']
    add('Get ARI', oml(fom(ENV['NM_MT_GET_ATTR_RESP'] if 'NM_MT_GET_ATTR_RESP' in ENV else ENV['NM_MT_GET_ATTR'], 1, 0, 0, 0xff, enc(gari, DEF_BASE[gari], inner))))
    nested = enc(gari, DEF_BASE[gari], inner)
    for _ in range(3):
        nested = enc(gari, DEF_BASE[gari], ari([ENV['NM_ATT_MAIO']], adm + nested))
    add('Get ARI nested four deep', oml(fom(ENV['NM_MT_GET_ATTR'], 1, 0, 0, 0xff, nested)))
    add('Get ARI, empty and with only the counter', oml(fom(ENV['NM_MT_GET_ATTR'], 1, 0, 0, 0xff, enc(gari, DEF_BASE[gari], b'') + enc(gari, DEF_BASE[gari], b'\x00'))))
    # unknown attribute tag: expert note, decoding of the rest stops
    add('unknown attribute tag', oml(fom(ENV['NM_MT_SET_BTS_ATTR'], 1, 0, 0, 0xff, b'\x77\x01\x02\x03')))
    add('unknown attribute tag 0x00', oml(fom(ENV['NM_MT_SET_BTS_ATTR'], 1, 0, 0, 0xff, b'\x00\x01\x02\x03')))
    # empty TLV attribute
    add('empty TLV16/TL16V attribute then more', oml(fom(ENV['NM_MT_SET_BTS_ATTR'], 1, 0, 0, 0xff,
        enc(ENV['NM_ATT_ADD_TEXT'], DEF_BASE[ENV['NM_ATT_ADD_TEXT']], b'') + enc(ENV['NM_ATT_SW_DESCR'], DEF_BASE[ENV['NM_ATT_SW_DESCR']]) + adm)))
    # message discriminators and placement indicators
    for disc in (0x80, 0x40, 0x20, 0x10, 0x00, 0x55):
        for pl in (0x80, 0x40, 0x20, 0x10, 0x00):
            if disc != 0x80 and pl != 0x80 and pl != 0x10:
                continue
            body = fom(ENV['NM_MT_OPSTART'], 2, 0, 1, 0xff, adm) if disc != 0x10 else b'\x04abcd' + fom(1, 0, 0, 0, 0)
            add('disc 0x%02x placement 0x%02x' % (disc, pl), oml(body, disc=disc, placement=pl, seq=pl & 7))
    # indicated length wrong (warning)
    add('OML length too long', oml(fom(ENV['NM_MT_OPSTART'], 2, 0, 1, 0xff, adm), length=60))
    add('OML length too short', oml(fom(ENV['NM_MT_OPSTART'], 2, 0, 1, 0xff, adm), length=2))
    # manufacturer-specific messages: ip.access ID with and without NUL (reproducer), others
    base_attr = adm + opr
    add('manufacturer com.ipaccess without NUL (reproducer)', manuf(b'com.ipaccess', fom(ENV['NM_MT_OPSTART'], 1, 0, 0, 0xff, base_attr)))
    add('manufacturer com.ipaccess with NUL (reproducer)', manuf(b'com.ipaccess\0', fom(ENV['NM_MT_OPSTART'], 1, 0, 0, 0xff, base_attr)))
    add('unknown manufacturer', manuf(b'com.example', fom(ENV['NM_MT_OPSTART'], 1, 0, 0, 0xff, base_attr)))
    add('manufacturer id of 13 octets (any last octet is accepted)', manuf(b'com.ipaccessX', fom(ENV['NM_MT_OPSTART'], 1, 0, 0, 0xff, base_attr)))
    add('manufacturer id shorter than ip.access', manuf(b'com.ip', fom(ENV['NM_MT_OPSTART'], 1, 0, 0, 0xff, base_attr)))
    add('manufacturer id empty', manuf(b'', fom(ENV['NM_MT_OPSTART'], 1, 0, 0, 0xff, base_attr)))
    # every object class
    for oc in range(0, 256):
        if oc in OBJCLASSES or oc in (0x05, 0x7e, 0xfe):
            add('object class 0x%02x' % oc, oml(fom(ENV['NM_MT_STATECHG_EVENT_REP'], oc, 0, 0, 0xff, adm)))
    # the three attributes redefined by Siemens, in their ETSI/ip.access form
    for tag in sorted(redefined):
        add('attribute %s in the ETSI form' % tagname(tag), oml(fom(ENV['NM_MT_SET_BTS_ATTR'], 1, 0, 0, 0xff, enc(tag, DEF_BASE[tag], sp.get(tag, [None])[0]))))
    section('Siemens BS-11 dialect (gsm_abis_oml.oml_dialect:siemens)')
    s1 = len(frames)
    # ================= Section 2: Siemens =================
    bs_tags = sorted(DEF_BS11)
    k = 0
    for n, (name, mt) in enumerate(MSG_BS11):
        oc = [0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa8, 0xa9, 0, 1, 2][n % 12]
        attrs = b''
        for j in range(3):
            tag = bs_tags[k % len(bs_tags)]; k += 1
            attrs += enc(tag, DEF_BS11[tag], sp.get(tag, [None])[0])
        add('BS11 msgtype %s' % name, oml(fom(mt, oc, 0, n & 3, 0xff, attrs)))
    for tag in bs_tags:
        for v in sp.get(tag, [None]):
            add('BS11 attribute %s' % tagname(tag), oml(fom(ENV['NM_MT_BS11_SET_ATTR'], 0xa5, 0, 0, 0xff, enc(tag, DEF_BS11[tag], v))))
    # the redefined standard attributes in the Siemens form
    for tag in sorted(redefined):
        d = sp.get(tag, [None])[0]
        if tag == ENV['NM_ATT_ARFCN_LIST']:
            d = struct.pack('>HHH', 1, 100, 124)
        add('BS11 form of %s' % tagname(tag), oml(fom(ENV['NM_MT_SET_BTS_ATTR'], 1, 0, 0, 0xff, enc(tag, DEF_BS11[tag], d))))
    chunked('BS11 all attributes in one message', [enc(t, DEF_BS11[t], sp.get(t, [None])[0]) for t in bs_tags],
            lambda a: oml(fom(ENV['NM_MT_BS11_SET_ATTR'], 0xa5, 0, 0, 0xff, a)))
    # base attributes that BS11 does not redefine are still known
    add('BS11 with a base attribute', oml(fom(ENV['NM_MT_OPSTART'], 1, 0, 0, 0xff, adm + opr)))
    section('ip.access dialect (gsm_abis_oml.oml_dialect:ipaccess)')
    # ================= Section 3: ip.access =================
    ipa_tags = sorted(DEF_IPA)
    k = 0
    for n, (name, mt) in enumerate(MSG_IPA):
        oc = [0, 1, 2, 3, 0xf0, 0xf1, 0xf2][n % 7]
        attrs = b''
        for j in range(3):
            tag = ipa_tags[k % len(ipa_tags)]; k += 1
            attrs += enc(tag, DEF_IPA[tag], sp.get(tag, [None])[0])
        ident = b'com.ipaccess' if n & 1 else b'com.ipaccess\0'
        add('IPA msgtype %s' % name, manuf(ident, fom(mt, oc, 0, n & 3, 0xff, attrs)))
    for tag in ipa_tags:
        for v in sp.get(tag, [None]):
            add('IPA attribute %s' % tagname(tag), manuf(b'com.ipaccess\0', fom(ENV['NM_MT_IPACC_SET_ATTR'], 0, 0, 0, 0xff, enc(tag, DEF_IPA[tag], v))))
    chunked('IPA all attributes in one message', [enc(t, DEF_IPA[t], sp.get(t, [None])[0]) for t in ipa_tags],
            lambda a: manuf(b'com.ipaccess', fom(ENV['NM_MT_IPACC_SET_NVATTR'], 0, 0, 0, 0xff, a)))
    # standard messages in the ip.access dialect (test report contents are ip.access specific)
    trx = ENV['NM_ATT_TEST_REPORT']
    for i, v in enumerate(sp[trx]):
        add('IPA test report %d' % i, oml(fom(ENV['NM_MT_TEST_REP'], 3, 0, 1, 2, enc(ENV['NM_ATT_TEST_NO'], DEF_BASE[ENV['NM_ATT_TEST_NO']], b'\x43') + enc(trx, DEF_BASE[trx], v))))
    # a manufacturer ID that is not ip.access in the ip.access dialect
    add('IPA dialect, unknown manufacturer', manuf(b'com.example', fom(ENV['NM_MT_OPSTART'], 1, 0, 0, 0xff, base_attr)))
    # base messages with ip.access attribute
    add('IPA dialect, standard message with a base attribute', oml(fom(ENV['NM_MT_OPSTART'], 1, 0, 0, 0xff, adm + opr)))
    write_pcap(out + '/gsm_abis_oml-coverage.pcap', 203, frames)

    # ================= malformed capture =================
    ts = ENV['NM_ATT_TEST_REPORT']
    tr = lambda b: enc(ts, DEF_BASE[ts], b)
    for note, attrs in [
        ('TL16V longer than the message', b'\x03\x00\x40\x01\x02'),
        ('TLV truncated', bytes([ENV['NM_ATT_HW_DESC'], 9, 1])),
        ('fixed attribute cut off', bytes([ENV['NM_ATT_BCCH_ARFCN'], 0x00])),
        ('attribute tag without data', bytes([ENV['NM_ATT_ADM_STATE']])),
        ('ARFCN list of odd length', enc(ENV['NM_ATT_ARFCN_LIST'], DEF_BASE[ENV['NM_ATT_ARFCN_LIST']], b'\x00\x01\x02')),
        ('interference boundaries cut', bytes([ENV['NM_ATT_INTERF_BOUND'], 1, 2, 3])),
        ('abis channel cut', bytes([ENV['NM_ATT_ABIS_CHANNEL'], 1])),
        ('Get ARI count larger than the data', enc(gari, DEF_BASE[gari], b'\x20\x01\x02')),
        ('Get ARI with a negative nested length', enc(gari, DEF_BASE[gari], b'\x05\x01')),
        ('test report with a short BCCH info', tr(test_report(0, [(6, b'\x80\x00\x01')]))),
        ('test report IE longer than the report', tr(b'\x00\x08\x7f\xff\x01')),
        ('test report channel usage odd length', tr(test_report(0, [(4, b'\x01\x02\x03')]))),
        ('test report cut after the IE tag', tr(b'\x00\x04')),
    ]:
        add(note, oml(fom(ENV['NM_MT_SET_BTS_ATTR'], 1, 0, 0, 0xff, attrs)), True)
    # Get ARI nested far deeper than the dissection depth limit
    nest = b''
    for _ in range(300):
        nest = enc(gari, DEF_BASE[gari], b'\x00' + nest)
    add('Get ARI nested 300 deep', oml(fom(ENV['NM_MT_GET_ATTR'], 1, 0, 0, 0xff, nest)), True)
    add('too short for the OML header', bytes([0x80, 0x80]), True)
    add('FOM header cut off', oml(bytes([ENV['NM_MT_OPSTART'], 1])), True)
    add('manufacturer ID longer than the message', oml(b'\x30com.ipaccess', disc=0x10), True)
    add('manufacturer id length zero, no FOM', oml(b'\x00', disc=0x10), True)
    write_pcap(out + '/gsm_abis_oml-coverage-malformed.pcap', 203, bad)

    if verbose:
        for name, first in sections:
            print('section from frame %d: %s' % (first, name))
        for n, t in notes: print(n, t)
        print('--- malformed')
        for n, t in badnotes: print(n, t)
    print(len(frames), 'frames,', len(bad), 'malformed frames;',
          ', '.join('%s from %d' % (n.split(' ')[0], f) for n, f in sections))

main()
