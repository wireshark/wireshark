#!/usr/bin/env python3
# Generates test/captures/gsm_bsslap_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic captures for packet-gsm_bsslap.c (BSSLAP, 3GPP TS 48.071).

Usage: mkgsm_bsslap.py <output directory>

BSSLAP is carried in the APDU element (protocol id 1) of BSSMAP messages,
here the Connection Oriented Information message, in SCCP (MTP3, SSN 254,
found by the BSSAP heuristic).  The malformed capture also has BSSLAP PDUs
handed over directly by Exported PDU "gsm_bsslap".

  gsm_bsslap-coverage.pcap            valid PDUs
  gsm_bsslap-coverage-malformed.pcap  truncated and invalid PDUs
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import re
import struct
import random
from bssmaplib import bssmap, exp_pdu, mtp3, SRC, strip_comments, udt, write_pcap

PLMN = bytes.fromhex('62f210'); LAC = b'\x00\x2a'; CI = b'\x12\x34'
SRCF = open(SRC + 'packet-gsm_bsslap.c').read()
DEFS = {k: int(v, 0) for k, v in re.findall(r'#define (BSSLAP_PARAM_\w+)\s+(0x[0-9A-Fa-f]+)', SRCF)}
MSGS = {k: int(v) for k, v in re.findall(r'#define (BSSLAP_[A-Z0-9_]+)\s+(\d+)\n', SRCF)}
# TV lengths (value part)
TV = {'CELL_IDENTITY': 7, 'TIMING_ADVANCE': 1, 'CHANNEL_DESCRIPTION': 3, 'CAUSE': 1, 'RRLP_FLAG': 1, 'RRLP_IE': None,
      'MS_POWER': 1, 'DELTA_TIMER': 1, 'ENCRYPTION_KEY': 8, 'CIPHER_MODE_SETTING': 1, 'CHANNEL_MODE': 1,
      'POLLING_REPETITION': 1, 'TLLI': 4, 'TFI': 1, 'STARTING_TIME': 2}

def cells(*discs):
    d = {0: b'\x00' + PLMN + LAC + CI, 1: b'\x01' + LAC + CI, 2: b'\x02' + bytes(range(9)), 3: b'\x03' + bytes(range(6))}
    return b''.join(d[x] for x in discs)

# an RRLP PDU (referenceNumber 1, msrPositionReq/assistance data absent): tried against the rrlp dissector
RRLP = bytes.fromhex('0800')
V = {
    'CELL_IDENTITY': [CI, b'\x00\x01'],
    'TIMING_ADVANCE': [b'\x00', b'\x1f', b'\x3f'],
    'CHANNEL_DESCRIPTION': [bytes.fromhex('080123'), bytes.fromhex('20a456')],
    'MEASUREMENT_REPORT': [bytes.fromhex('c0000102030405060708090a0b0c0d0e'[:32]), bytes(16)],
    'CAUSE': [bytes([c]) for c in range(0, 10)] + [b'\x0b'],
    'RRLP_FLAG': [b'\x00', b'\x01'],
    'RRLP_IE': [struct.pack('>H', len(RRLP)) + RRLP, b'\x00\x00'],
    'CELL_IDENTITY_LIST': [cells(0), cells(1), cells(2), cells(3), cells(0, 1, 2, 3, 1)],
    'LOCATION_AREA_CODE': [LAC, b'\xff\xfe'],
    'FREQUENCY_LIST': [bytes.fromhex('0f0102030405060708090a0b0c0d0e0f'[:16])],
    'MS_POWER': [b'\x05', b'\x1f'],
    'DELTA_TIMER': [b'\x04', b'\x00'],
    'SERVING_CELL_IDENTIFIER': [b'\x00' + PLMN + LAC + CI, b'\x01' + LAC + CI, b'\x02' + CI],
    'ENCRYPTION_KEY': [bytes(8)],
    'CIPHER_MODE_SETTING': [b'\x01', b'\x00'],
    'CHANNEL_MODE': [b'\x01', b'\x21'],
    'MULTIRATE_CONFIGURATION': [bytes.fromhex('2007 1f2f'.replace(' ', '')), bytes.fromhex('4005 00')],
    'POLLING_REPETITION': [b'\x02', b'\x00'],
    'TLLI': [bytes.fromhex('c0123456')],
    'TFI': [b'\x03', b'\x1f'],
    'STARTING_TIME': [b'\x12\x34'],
}
UNDECODED = {'ENHANCED_MEASUREMENT_REPORT': [b'\x01\x02\x03\x04'], 'PACKET_CHANNEL_DESCRIPTION': [b'\x01\x02\x03\x04']}

def parse():
    fns = {}
    for m in re.finditer(r'\nstatic void\s*\n(dissect_gsm_bsslap_\w+)\s*\([^)]*int offset\)\s*\{', SRCF):
        end = SRCF.find('\n}\n', m.end())
        body = strip_comments(SRCF[m.end():end])
        fns[m.group(1)] = [(e.group(1), e.group(2).strip().replace('BSSLAP_PARAM_', '')) for e in re.finditer(r'(ELEM_[A-Z_]+)\((BSSLAP_PARAM_\w+)', body)]
    out = []
    for case, fn in re.findall(r'case (BSSLAP_[A-Z0-9_]+):\s*\n\s*(?:/\*.*?\*/\s*)?(?:(dissect_gsm_bsslap_\w+)|break)', SRCF):
        out.append((case, MSGS[case], fn if fn else None))
    return fns, out

def enc(kind, name, val):
    iei = DEFS['BSSLAP_PARAM_' + name]
    if kind.endswith('TLV'): return bytes([iei, len(val)]) + val
    if kind.endswith('TV'): return bytes([iei]) + val
    raise ValueError(kind)

def build(code, elems, r, table, allow_missing=False, override=None, skip=()):
    out = bytes([code]); n = {}
    for macro, name in elems:
        kind = macro.split('_', 2)[2]; opt = macro.startswith('ELEM_OPT')
        if name in skip: continue
        vals = table.get(name)
        if vals is None:
            if opt: continue
            raise KeyError(name)
        i = r
        if opt and i >= len(vals) and r > 0: continue
        v = vals[i % len(vals)]
        if override and name in override: v = override[name]
        out += enc(kind, name, v)
    return out

def apdu_frame(bsslap):
    bs = bytes([0x2a]) + bytes([0x49, (len(bsslap) + 1) >> 8, (len(bsslap) + 1) & 0xff, 0x01]) + bsslap
    return mtp3(udt(bssmap(bs)))

def main():
    out = sys.argv[1]
    random.seed(48071)
    fns, msgs = parse()
    table = dict(V)
    rounds = max(len(v) for v in V.values())
    pk = []; tag = []
    for case, code, fn in msgs:
        if fn is None:
            pk.append(apdu_frame(bytes([code]))); tag.append((case, 0)); continue
        for r in range(rounds):
            if r > 0 and not any(r < len(table.get(n, [])) for _, n in fns[fn]): continue
            pk.append(apdu_frame(build(code, fns[fn], r, table))); tag.append((case, r))
    # a Perform Location Request carries the APDU too; reserved/unknown message types
    for code in (0x00, 0x04, 0x05, 0x09, 0x0e, 0x13, 0xff):
        pk.append(apdu_frame(bytes([code]) + b'\x01\x02')); tag.append(('unknown %#x' % code, 0))
    write_pcap(os.path.join(out, 'gsm_bsslap-coverage.pcap'), pk)
    with open(os.path.join(out, 'frames.txt'), 'w') as f:
        for i, (c, r) in enumerate(tag, 1): f.write('%d\t%s\t%d\n' % (i, c, r))
    print(len(pk), 'frames')
    # ---- malformed ----
    mk = []
    full = dict(V); full.update(UNDECODED)
    ex = lambda b: exp_pdu('gsm_bsslap', b)
    for case, code, fn in msgs:
        if fn is None: continue
        mk.append(ex(build(code, fns[fn], 0, full)))
        # cut short at every element boundary and randomly
        m = build(code, fns[fn], 0, full)
        for k in range(1, len(m)):
            mk.append(ex(m[:k]))
        for _ in range(6):
            b = bytearray(m)
            for _ in range(random.randint(1, 3)): b[random.randrange(len(b))] = random.getrandbits(8)
            mk.append(ex(bytes(b)))
    # cell identity list: undecoded discriminator, cell identification longer than the element
    # (the underflow of the fix), several cells, 3G containers cut short
    for lst in (b'\x04\x01\x02', b'\x02\x01\x02', b'\x03\x01', b'\x00\x62\xf2', b'\x01\x00', b'\x00' + PLMN + LAC,
                cells(0) + b'\x02\x00\x00', cells(1, 1) + b'\x09', b'\x00', b''):
        mk.append(ex(bytes([0x02]) + enc('TV', 'CELL_IDENTITY', V['CELL_IDENTITY'][0]) + enc('TV', 'TIMING_ADVANCE', b'\x01') + enc('TLV', 'CELL_IDENTITY_LIST', lst)))
    mk.append(ex(bytes([0x0b]) + enc('TV', 'CELL_IDENTITY', V['CELL_IDENTITY'][0]) + enc('TV', 'TIMING_ADVANCE', b'\x01') + enc('TV', 'CHANNEL_DESCRIPTION', V['CHANNEL_DESCRIPTION'][0]) + enc('TV', 'CAUSE', b'\x01') + enc('TLV', 'CELL_IDENTITY_LIST', b'\x02\x00\x00\x00')))
    # undecoded elements, bad RRLP, unknown message and trailing data
    mk.append(ex(bytes([0x02]) + enc('TV', 'CELL_IDENTITY', V['CELL_IDENTITY'][0]) + enc('TV', 'TIMING_ADVANCE', b'\x01') + enc('TLV', 'ENHANCED_MEASUREMENT_REPORT', b'\x01\x02\x03\x04')))
    mk.append(ex(bytes([0x0b]) + enc('TV', 'CELL_IDENTITY', V['CELL_IDENTITY'][0]) + enc('TV', 'TIMING_ADVANCE', b'\x01') + enc('TV', 'CHANNEL_DESCRIPTION', V['CHANNEL_DESCRIPTION'][0]) + enc('TV', 'CAUSE', b'\x01') + enc('TLV', 'PACKET_CHANNEL_DESCRIPTION', b'\x01\x02\x03\x04')))
    for rr in (b'\x00\x05\x01', b'\x00\x01\xff', b'\x00', b'\xff\xff\x01\x02'):
        mk.append(ex(bytes([0x0f]) + enc('TV', 'RRLP_FLAG', b'\x01') + enc('TV', 'RRLP_IE', rr)))
    for code in range(256):
        mk.append(ex(bytes([code, 0xee, 0xee])))
    write_pcap(os.path.join(out, 'gsm_bsslap-coverage-malformed.pcap'), mk)
    print(len(mk), 'malformed frames')

if __name__ == '__main__':
    main()
