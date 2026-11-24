#!/usr/bin/env python3
# Generates test/captures/gsm_bssmap_le_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic captures for packet-gsm_bssmap_le.c (BSSMAP-LE, Lb interface, 3GPP TS 49.031).

Usage: mkgsm_bssmap_le.py <output directory>

BSSMAP-LE is reached through BSSAP-LE, which a capture only gets from an SCCP
user that is not recognised by default (SSN 250-252 need Decode As), so the
main capture uses Exported PDU naming the dissectors: "bssap_le" (BSSAP-LE
header and BSSMAP-LE message) and "gsm_bssmap_le" (the bare message).  The
malformed capture also has the same messages in SCCP (MTP3, SSN 250), which
runcov.sh decodes with Decode As.

  gsm_bssmap_le-coverage.pcap            valid messages
  gsm_bssmap_le-coverage-malformed.pcap  truncated/odd input, undecoded elements
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import re
import random
from bssmaplib import (
    exp_pdu, mtp3, sccp_cc, sccp_cr, sccp_dt1, SRC, strip_comments, udt, write_pcap,
)
from g4_fuzz import enum_values

SRCF = open(SRC + 'packet-gsm_bssmap_le.c').read()
DEFS = {k: int(v) for k, v in re.findall(r'#define (BSSMAP_LE_[A-Z0-9_]+)\s+(\d+)\n', SRCF)}
PLMN = bytes.fromhex('62f210'); LAC = b'\x00\x2a'; CI = b'\x12\x34'
IMSI = bytes.fromhex('2926102143658709')
IMEI = bytes.fromhex('3a53420754103261')
def cell(d):
    return bytes([d]) + {0: PLMN + LAC + CI, 1: LAC + CI, 2: CI, 4: PLMN + LAC, 5: LAC, 8: PLMN + LAC + b'\x01\x02',
                         9: b'\x01\x02', 0x0b: PLMN + LAC + b'\x00\x07'}[d]
def bits(*fields):
    """fields: (value, width) -> bytes (MSB first, padded with zero bits)"""
    n = sum(w for _, w in fields); v = 0
    for x, w in fields: v = (v << w) | x
    pad = (-n) % 8
    return (v << pad).to_bytes((n + pad) // 8, 'big')
def a_apdu(proto, data): return bytes([proto]) + data
TV = {'BSS_MULTILATERATION_CAPABILITY': 1, 'MULTILATERATION_TIMING_ADVANCE': 2, 'MS_SYNC_ACCURACY': 1,
      'BTS_RECEPTION_ACCURACY_LEVEL': 1, 'COVERAGE_CLASS': 1, 'MULTILATERATION_POSITIONING_METHOD': 1,
      'SHORT_ID': 1, 'RANDOM_ID': 2}
DTAP = bytes.fromhex('051801')
V = {
    'LOCATION_TYPE': [b'\x00', b'\x01\x03', b'\x02\x01', b'\x00\x00'[:1]],
    'CELL_IDENTIFIER': [cell(d) for d in (0, 1, 2, 4, 5, 8, 9, 0x0b)],
    'CLASSMARK_INFORMATION_TYPE_3': [b'\x60\x14\x04\x00'],
    'LCS_CLIENT_TYPE': [b'\x00', b'\x12', b'\x21', b'\x33', b'\xf3', b'\x0f'],
    'CHOSEN_CHANNEL': [b'\x19', b'\x09'],
    'LCS_PRIORITY': [b'\x00', b'\x01'],
    'LCS_QOS': [bits((0, 6), (1, 1), (1, 1), (1, 1), (0x55, 7), (1, 1), (0x2a, 7), (2, 2)),
                bits((0, 6), (0, 1), (0, 1), (0, 1), (0, 7), (0, 1), (0, 7), (1, 2)),
                bits((0, 6), (1, 1), (0, 1), (1, 1), (0x10, 7), (0, 1), (0, 7), (3, 2))],
    'REQUESTED_GPS_ASSISTANCE_DATA': [b'\xff\x07\x01\x02', b'\x00\x00\x00\x00', b'\x7a\x05\x00\x00']  ,
    'APDU': [a_apdu(1, b'\x01'), a_apdu(1, bytes.fromhex('0a1801')), a_apdu(2, b'\x01\x02'), a_apdu(3, b'\x01'), a_apdu(0, b'\x01')],
    'IMSI': [IMSI], 'IMEI': [IMEI],
    'MULTILATERATION_TIMING_ADVANCE': [b'\x00\x00', bytes.fromhex('4a3b'), bytes.fromhex('8fff'), bytes.fromhex('c123')],
    'MS_SYNC_ACCURACY': [b'\x00', b'\x03', b'\x0f'],
    'BTS_RECEPTION_ACCURACY_LEVEL': [b'\x00', b'\x1f', b'\x0a'],
    'COVERAGE_CLASS': [b'\x00', b'\x2d', b'\x3f'],
    'MULTILATERATION_POSITIONING_METHOD': [b'\x00', b'\x2d', b'\x3f'],
    'SHORT_ID': [b'\x05', b'\xff'], 'RANDOM_ID': [b'\x34\x12', b'\xff\xff'],
    'GEOGRAPHIC_LOCATION': [bytes.fromhex('10') + b'\x62\xf2\x10\x00\x00\x00' [:6], bytes.fromhex('00')],
    'POSITIONING_DATA': [b'\x00\x1b\x61\xc1', b'\x01', b'\x00'],
    'DECIPHERING_KEYS': [b'\x01' + bytes(14), b'\x00' + bytes(14)],
    'LCS_CAUSE': [b'\x00', b'\x01\x00', b'\x02', b'\x0d', b'\x0e\x01', b'\xff', b'\x05\xff'],
    'VELOCITY_DATA': [bytes.fromhex('0001')[:0] + b'\x00\x01\x02\x03', b'\x10\x00\x20\x00\x03\x20\x00\x40'],
    'GANSS_POSITIONING_DATA': [b'\x11', b'\x22', b'\xff'],
    'SEGMENTATION': [b'\x01', b'\x02\x00\x00', b'\x00'],
    'NETWORK_ELEMENT_IDENTITY': [cell(0), cell(1), cell(4), cell(5), b'\x06\x01\x02\x03', b'\x02', b'\x07\x01'],
    'RETURN_ERROR_REQUEST': [b'\x00', b'\x01'],
    'RETURN_ERROR_CAUSE': [b'\x00', b'\x01', b'\x02'],
    'CAUSE': [b'\x20', b'\x50'],
    'A_ITF_SEL_FOR_RESET': [b'\x01', b'\x02', b'\x03'],
    'OSMOCOM_OSMUX_SUPPORT': [b''],
}
UV = {n: [bytes(range(4))] for n in ('LCS_CAPABILITY', 'PACKET_MEASUREMENT_REPORT', 'CELL_IDENTITY_LIST', 'BSS_MULTILATERATION_CAPABILITY',
      'GANSS_LOCATION_TYPE', 'REQUESTED_GANSS_ASSISTANCE_DATA', 'CELL_INFORMATION_LIST', 'SHORT_ID_SET', 'RANDOM_ID_SET', 'SHORT_BSS_ID',
      'MTA_ACCESS_SECURITY_REQUIRED')}

def functions():
    fns = {}
    for src in (SRCF, open(SRC + 'packet-gsm_a_bssmap.c').read()):
        for m in re.finditer(r'\n(?:static )?void\s*\n(bssmap_\w+)\s*\(tvbuff_t \*tvb[^)]*unsigned len\)\s*\{', src):
            end = src.find('\n}\n', m.end()); body = strip_comments(src[m.end():end])
            fns.setdefault(m.group(1), [(e.group(1), e.group(2).strip()) for e in re.finditer(r'(ELEM_[A-Z_]+)\(([^,]+),', body)])
    names = [x.strip() for x in strip_comments(re.search(r'bssmap_le_msg_fcn\[\]\)\(.*?\)\s*=\s*\{(.*?)\n\};', SRCF, re.S).group(1)).split(',') if x.strip()]
    codes = []
    ms = re.search(r'gsm_bssmap_le_msg_strings\[\]\s*=\s*\{(.*?)\n\};', SRCF, re.S).group(1)
    for k, v in re.findall(r'\{\s*(\w+)\s*,\s*"([^"]*)"\s*\}', ms):
        codes.append(int(k) if k.isdigit() else DEFS[k])
    return fns, names, codes

BE = enum_values(open(SRC + 'packet-gsm_a_common.h').read(), 'BE_NONE')
def enc(kind, name, val, be=False):
    iei = BE['BE_' + name] if be else DEFS['BSSMAP_LE_' + name]
    if kind == 'T': return bytes([iei])
    if kind == 'TLV': return bytes([iei, len(val)]) + val
    if kind == 'TLV_E': return bytes([iei, len(val) >> 8, len(val) & 255]) + val
    if kind == 'TV': return bytes([iei]) + val
    raise ValueError(kind)

def build(code, elems, r, table, override=None, undecoded=False):
    out = bytes([code])
    for macro, tok in elems:
        be = tok.startswith('BE_')
        name = tok.replace('BSSMAP_LE_', '', 1) if tok.startswith('BSSMAP_LE_') else tok[3:] if be else tok
        kind = macro.split('_', 2)[2]; opt = macro.startswith('ELEM_OPT')
        vals = table.get(name)
        if vals is None:
            if opt: continue
            raise KeyError(name)
        if opt and r >= len(vals) and r > 0: continue
        v = vals[r % len(vals)]
        if override and name in override: v = override[name]
        out += enc(kind, name, v, be)
    return out

def bssap_le(msg): return bytes([0x00, len(msg)]) + msg

def main():
    out = sys.argv[1]
    random.seed(49031)
    fns, names, codes = functions()
    rounds = max(len(v) for v in V.values())
    pk = []; tag = []
    NOT_MAIN = {'REQUESTED_GPS_ASSISTANCE_DATA'}      # followed by "satellite related data not decoded yet"
    table = {k: v for k, v in V.items() if k not in NOT_MAIN}
    for code, fn in zip(codes, names):
        if fn == 'NULL' or fn not in fns: continue
        for r in range(rounds):
            if r > 0 and not any(r < len(table.get(t.replace('BSSMAP_LE_', '', 1) if t.startswith('BSSMAP_LE_') else t[3:], [])) for _, t in fns[fn]): continue
            m = build(code, fns[fn], r, table)
            pk.append(exp_pdu('bssap_le', bssap_le(m)) if r % 2 == 0 else exp_pdu('gsm_bssmap_le', m))
            tag.append((fn, code, r))
    # messages without a decoder (raw "Message Elements") and without data
    for code, fn in zip(codes, names):
        if fn == 'NULL' and code > 31:
            pk.append(exp_pdu('bssap_le', bssap_le(bytes([code]) + b'\x01\x02\x03'))); tag.append(('raw', code, 0))
    pk.append(exp_pdu('gsm_bssmap_le', bytes([49]))); tag.append(('reset ack', 49, 0))
    write_pcap(os.path.join(out, 'gsm_bssmap_le-coverage.pcap'), pk)
    with open(os.path.join(out, 'frames.txt'), 'w') as f:
        for i, (c, code, r) in enumerate(tag, 1): f.write('%d\t%s\t%#x\t%d\n' % (i, c, code, r))
    print(len(pk), 'frames')
    # ---- malformed ----
    mk = []
    full = dict(V); full.update(UV)
    msgs = []
    for code, fn in zip(codes, names):
        if fn == 'NULL' or fn not in fns: continue
        for r in range(2):
            msgs.append((code, fn, build(code, fns[fn], r, full)))
    for code, fn, m in msgs:
        mk.append(exp_pdu('bssap_le', bssap_le(m)))
        for k in range(1, len(m)):
            mk.append(exp_pdu('gsm_bssmap_le', m[:k]))
        for _ in range(6):
            b = bytearray(m)
            for _ in range(random.randint(1, 3)): b[random.randrange(len(b))] = random.getrandbits(8)
            mk.append(exp_pdu('gsm_bssmap_le', bytes(b)))
        mk.append(exp_pdu('gsm_bssmap_le', m + b'\xee\xee'))
    for code in range(256):
        mk.append(exp_pdu('gsm_bssmap_le', bytes([code, 0x01, 0x02, 0x03])))
        mk.append(exp_pdu('gsm_bssmap_le', bytes([code])))
    # BSSAP-LE headers: DTAP, unknown PDU types, bad lengths
    for hdr in (b'\x01\x00\x03\x05\x18\x01', b'\x02\x00', b'\x00\x05\x30', b'\x00', b'\x00\x00', b'\x01\x00\x09\x01\x02'):
        mk.append(exp_pdu('bssap_le', hdr))
    # the same messages in SCCP, decoded with Decode As sccp.ssn 250 (runcov.sh); a connection with association tracking
    def udt250(m): return mtp3(udt(bssap_le(m), 250, 250))
    for code, fn, m in msgs: mk.append(udt250(m))
    for n in range(3):
        mk.append(mtp3(sccp_cr(0x500 + n, bssap_le(msgs[0][2]), 250, 250)))
        mk.append(mtp3(sccp_cc(0x500 + n, 0x600 + n), opc=1, dpc=2))
        mk.append(mtp3(sccp_dt1(0x600 + n, bssap_le(msgs[3][2]))))
        mk.append(mtp3(sccp_dt1(0x500 + n, bssap_le(msgs[1][2])), opc=1, dpc=2))
    write_pcap(os.path.join(out, 'gsm_bssmap_le-coverage-malformed.pcap'), mk)
    print(len(mk), 'malformed frames')

if __name__ == '__main__':
    main()
