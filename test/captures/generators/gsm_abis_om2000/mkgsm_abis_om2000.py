#!/usr/bin/env python3
# Generates test/captures/gsm_abis_om2000_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic captures for packet-gsm_abis_om2000.c (Ericsson OM 2000).
Usage: mkgsm_abis_om2000.py <outdir> [-v]

OM2000 is only reached through the OML dissector with the dialect
"Ericsson OM2000" (gsm_abis_oml.oml_dialect:om2000) and LAPD with the GSM SAPI
values (SAPI 62), so every frame is a LAPD (pcap linktype 203) UI frame with
SAPI 62 carrying an OML header and the OM2000 message. The message code table
is read from the dissector source (SRC) so that every message code is used."""
import os
SRCDIR = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..', '..'))
import re
import struct
import sys

SRC = os.environ.get('WSSRC', os.path.join(SRCDIR)) + '/epan/dissectors/packet-gsm_abis_om2000.c'

def write_pcap(path, linktype, pkts):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, p in enumerate(pkts):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
            f.write(p)

def lapd(sapi, tei, payload, cr=0):
    return bytes([(sapi << 2) | (cr << 1), (tei << 1) | 1, 0x03]) + payload

def oml(payload, disc=0x80, placement=0x80, seq=0):
    return bytes([disc, placement, seq, len(payload)]) + payload

def msgcodes():
    s = open(SRC).read()
    body = s[s.index('om2k_msgcode_vals[] = {'):]
    body = body[:body.index('{ 0, NULL }')]
    return [(int(a, 16), b) for a, b in re.findall(r'\{\s*(0x[0-9a-fA-F]+),\s*"([^"]*)"', body)]

def mo(cls, sub1=0, sub2=0, inst=0):
    return bytes([cls, sub1, sub2, inst])

def t(iei, *b):
    return bytes([iei]) + bytes(b)

def tl(iei, data):
    return bytes([iei, len(data)]) + data

def con_list(groups):
    # groups: list of lists of (ccp, ci, tag, tei); the length covers the length octet
    body = bytes([len(groups)])
    for g in groups:
        body += bytes([len(g)])
        for ccp, ci, tag, tei in g:
            body += struct.pack('>HBBB', ccp, ci, tag, tei)
    return bytes([0x10, len(body) + 1]) + body

def is_list(entries):
    body = b''.join(struct.pack('>HHB', a, b, c) for a, b, c in entries)
    return bytes([0x27, len(body) + 1]) + body

def neg1(recs):
    # recs: list of (type, [versions])
    body = bytes([len(recs)])
    for typ, vers in recs:
        body += bytes([len(vers), typ]) + b''.join(v.ljust(6)[:6].encode() for v in vers)
    return bytes([0x90, len(body)]) + body

def neg2(recs):
    body = bytes([len(recs)])
    for typ, ver in recs:
        body += bytes([typ]) + ver.ljust(6)[:6].encode()
    return bytes([0x91, len(body)]) + body

def mo_record(cls, inst, attrs):
    body = bytes([cls, inst])
    for aid, data in attrs:
        body += struct.pack('>HB', aid, len(data)) + data
    return bytes([0x85]) + body

# One encoder per attribute (the order is the order of the dissector's switch)
def attr_list():
    A = []
    A.append(t(0x00, 0))
    A.append(t(0x00, 1))                       # accordance not performed (expert)
    for i in (0x06, 0x07, 0x09, 0x0a, 0x0b, 0x0c):
        A.append(t(i, 0x25 if i == 0x0c else (i & 7)))
    A.append(t(0x0d, 25, 11, 5, 13, 30, 59))   # Calendar Time
    A.append(t(0x0f, 0x05))
    A.append(con_list([[(0x0102, 3, 4, 5), (0x0203, 6, 7, 8)], [(0x0304, 9, 10, 11)]]))
    A.append(t(0x12, 4)); A.append(t(0x13, 7))
    A.append(t(0x14, 0x12, 0x34)); A.append(t(0x15, 0x56, 0x78))
    A.append(t(0x16, 0x4a, 0x03))              # ILR / CUR / other
    A.append(t(0x17) + b'R1A01/01')
    A.append(t(0x1c, 1)); A.append(t(0x1d, 0x01, 0x23))
    A.append(tl(0x1e, bytes(range(1, 9))))
    A.append(t(0x1f, 0, 5)); A.append(t(0x20, 0, 6))
    A.append(t(0x21, 5)); A.append(t(0x22, 1))
    for i in (0x23, 0x24, 0x25, 0x26, 0x34, 0x50):
        A.append(t(i, 1, 2, 3, 4, 5, 6))
    A.append(is_list([(0x0101, 0x0202, 1), (0x0303, 0x0404, 2)]))
    A.append(t(0x28, 3))
    A.append(t(0x2a, 0)); A.append(t(0x2a, 1))
    A.append(t(0x2b, 9))
    for st in (0, 1, 2, 3, 9):
        A.append(t(0x2c, st))
    A.append(t(0x2d, 2)); A.append(t(0x2e, 1)); A.append(t(0x2f, 0x2a))
    A.append(t(0x32, 4))
    for d in (1, 2, 3, 4, 9):
        A.append(t(0x33, d))
    A.append(t(0x35, 2)); A.append(t(0x35, 0x0a)); A.append(t(0x35, 0x30))
    A.append(t(0x38, 5))
    for m in (0, 1, 2, 0xff, 7):
        A.append(t(0x3a, m))
    A.append(t(0x3c, 6)); A.append(t(0x3d, 3))
    A.append(t(0x40) + b'ERIG01R01V02'[:12])
    for i in (0x43, 0x44, 0x45, 0x46):
        A.append(tl(i, bytes([0xaa, 0x55, 0x0f])))
    A.append(t(0x47, 1)); A.append(t(0x48, 0x03))
    A.append(t(0x74, 1, 2, 3, 4, 5))
    A.append(t(0x79, 0x35)); A.append(t(0x7a, 4)); A.append(t(0x7b, 8))
    A.append(t(0x7e, 1)); A.append(t(0x7f, 0x00, 0x2f, 1))
    A.append(t(0x84, 0xbe, 0xef))
    A.append(t(0x87, 3)); A.append(t(0x8a, 0xca, 0xfe))
    A.append(neg1([(0, ['R1A', 'R2B']), (1, ['R1A'])]))
    A.append(neg2([(0, 'R1A'), (2, 'R2B')]))
    A.append(t(0x92, 1)); A.append(t(0x94, 1))
    A.append(t(0x95, 1, 2, 3)); A.append(t(0x98, 1, 2, 3, 4, 5))
    A.append(t(0x9c, 1, 2, 3, 4)); A.append(t(0x9d, 0x10, 0x32, 0x21, 0x03))
    A.append(t(0x9e, 1)); A.append(t(0x9f, 5)); A.append(t(0xa0, 1))
    A.append(t(0xa8, 0x0f, 0x00)); A.append(t(0xa9, 40)); A.append(t(0xaa, 4))
    for i in (0xab, 0xae, 0xaf, 0xb0):
        A.append(tl(i, bytes([1, 2, 3])))
    A.append(tl(0xab, b''))
    for i in (0xa3, 0xa5, 0xa6):
        A.append(tl(i, bytes([9, 8])))
    A.append(t(0xb5, 1, 2)); A.append(t(0xd2, 1, 2, 3, 4, 5, 6))
    A.append(t(0xac) + bytes(range(58)))
    A.append(t(0x01, 0x11)); A.append(t(0x55, 0x22))   # unknown tags
    return A

def main():
    out = sys.argv[1]
    verbose = '-v' in sys.argv
    codes = msgcodes()
    frames, notes = [], []
    bad, badnotes = [], []

    def add(note, om, target=None):
        fr = lapd(62, 0, oml(om))
        if target is None:
            frames.append(fr); notes.append((len(frames), note))
        else:
            bad.append(fr); badnotes.append((len(bad), note))

    attrs = attr_list()
    # 1. every message code once with an MO header and attributes, rotating the attribute list
    ai = 0
    classes = [1, 2, 3, 4, 5, 6, 7, 8, 0x0a, 0x0b, 0x0c, 0x0d]
    for n, (code, name) in enumerate(codes):
        body = b''
        for k in range(2):
            body += attrs[ai % len(attrs)]
            ai += 1
        body += t(0x06, 1)      # a trailing attribute: items with a length cover it
        if 'NACK' in name:
            # NACK is an expert error: malformed capture only
            add(name, struct.pack('>H', code) + mo(classes[n % len(classes)], n & 3, 0, n & 7) + body, 'bad')
            continue
        add(name, struct.pack('>H', code) + mo(classes[n % len(classes)], n & 3, 0, n & 7) + body)
    first_attr_frame = len(frames) + 1
    # 2. every attribute on its own
    for n, a in enumerate(attrs):
        if a[0] == 0x85:
            continue
        code = 0x3a if a[0] == 0x2c else 0x42
        add('attribute 0x%02x' % a[0], struct.pack('>H', code) + mo(2, 0, 0, 1) + a + (t(0x06, 1) if a[0] in (0x10, 0x27, 0xab) else b''))
    # 3. MO Record attribute (last in the message)
    add('MO Record', struct.pack('>H', 0x0044) + mo(1, 0, 0, 0) + mo_record(1, 2, [(1, b'\xaa\xbb'), (0x0123, b''), (0x0204, b'\x01\x02\x03')]))
    add('MO Record, no attributes', struct.pack('>H', 0x0044) + mo(3, 0, 0, 0) + mo_record(7, 0, []))
    # 4. results that print the accordance / operational information in the item
    for code in (0x74, 0x1a, 0x66, 0x82, 0xa6, 0xae, 0xb6, 0xe2, 0xf6):
        for v in (0, 1, 3, 9):
            body = (t(0x2e, v) if code == 0x74 else t(0x00, v))
            add('0x%04x value %d' % (code, v), struct.pack('>H', code) + mo(2, 0, 0, 0) + body)
    # 5. reproducers of the fix (MO Record loop bound, Calendar Time at the end)
    hdr = bytes([0x00, 0x10, 0x00, 0x00, 0x00, 0x00])
    add('reproducer 1: MO Record', hdr + bytes([0x85, 0x01, 0x02, 0x00, 0x01, 0x02, 0xAA, 0xBB]))
    add('reproducer 2: Calendar Time last', hdr + bytes([0x0d, 24, 1, 2, 3, 4, 5]))
    # an Ericsson message from a real exchange shape: Reset Command with MO header only
    add('header only', struct.pack('>H', 0x0078) + mo(2, 0, 0, 0))
    # 6. a message with the OML length shorter than the payload (OML mismatch warning)
    frames.append(lapd(62, 0, bytes([0x80, 0x80, 0x00, 6]) + struct.pack('>H', 0x0078) + mo(2, 0, 0, 0)))
    notes.append((len(frames), 'complete with accurate length'))
    write_pcap(out + '/gsm_abis_om2000-coverage.pcap', 203, frames)

    # Malformed capture: NACKs, truncated attributes, wrong OML length
    for n, code in enumerate((0x0005, 0x000d, 0x0019, 0x0039, 0x0081)):
        add('NACK 0x%04x' % code, struct.pack('>H', code) + mo(1, 0, 0, 1) + t(0x2c, 1), 'bad')
    add('MO state not enabled in Enable Result', struct.pack('>H', 0x003a) + mo(1, 0, 0, 1) + t(0x2c, 1), 'bad')
    for a in (t(0x17, 0x41), t(0x0d, 1, 2), t(0x10, 20, 1, 3, 0, 1, 2), t(0x27, 40, 0, 1), neg1([(0, ['R1A'])])[:6],
              t(0xac, 1, 2, 3), tl(0xab, b'\x01'), t(0x00), tl(0x1e, b'\x01\x02')[:3]):
        add('truncated attribute 0x%02x' % a[0], struct.pack('>H', 0x0042) + mo(2, 0, 0, 1) + a, 'bad')
    bad.append(lapd(62, 0, bytes([0x80, 0x80, 0x00, 40]) + struct.pack('>H', 0x0078) + mo(2, 0, 0, 0)))
    badnotes.append((len(bad), 'OML length longer than the data'))
    bad.append(lapd(62, 0, bytes([0x80, 0x80, 0x00, 3]) + struct.pack('>H', 0x0078) + mo(2, 0, 0, 0)))
    badnotes.append((len(bad), 'OML length shorter than the data'))
    bad.append(lapd(62, 0, bytes([0x80, 0x80, 0x00, 1, 0x00])))
    badnotes.append((len(bad), 'one octet'))
    write_pcap(out + '/gsm_abis_om2000-coverage-malformed.pcap', 203, bad)
    if verbose:
        for n, t_ in notes: print(n, t_)
        print('--- malformed')
        for n, t_ in badnotes: print(n, t_)
    print(len(frames), 'frames,', len(bad), 'malformed frames; first single-attribute frame', first_attr_frame)

main()
