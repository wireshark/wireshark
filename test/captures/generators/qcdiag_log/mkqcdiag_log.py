#!/usr/bin/env python3
# Generates test/captures/qcdiag_log_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the QCDIAG LOG coverage captures. Usage: mkqcdiag_log.py <outdir>
All frames are Ethernet/IPv4/UDP 4729 (GSMTAP, type 0x11 QC_DIAG) carrying
Get Log responses (DIAG_LOG_F, 0x10); a few are custom (0xff) messages."""
import struct
import sys
import os

def ip_csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b)//2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def udp_frame(payload, n, dport=4729, sport=40000):
    udp = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    iph = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), n + 1, 0, 64, 17, 0,
                      bytes([192,0,2,1]), bytes([192,0,2,2]))
    iph = iph[:10] + struct.pack('!H', ip_csum(iph)) + iph[12:]
    return bytes([2,0,0,0,0,2, 2,0,0,0,0,1]) + b'\x08\x00' + iph + udp

def gsmtap(diag):
    return struct.pack('!BBBBHbbIBBBB', 2, 4, 0x11, 0, 0, 0, 0, 0, 0, 0, 0, 0) + diag

def udp_plain(payload, n, dport, sport):
    return udp_frame(payload, n, dport, sport)

def write_pcap(name, frames):
    with open(name, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)

def qc_log(code, data, ts=0x0000100000000000, more=0):
    rec = struct.pack('<HHQ', 12 + len(data), code, ts) + data
    return struct.pack('<BBH', 0x10, more, len(rec)) + rec

Z = lambda n: bytes(n)

# ---- builders: payload -> DIAG bytes ----
def b_crr(version, cells3, cells2):
    """0x4005 WCDMA cell reselection ranking"""
    d = bytes([(version << 6) | len(cells3), len(cells2)])
    if version == 2: d += Z(5)
    for (uarfcn, psc, rscp, rscp_rank, ecio, ecio_rank, st, hcs, h, q) in cells3:
        d += struct.pack('<HHBhBh', uarfcn, psc, rscp, rscp_rank, ecio, ecio_rank)
        if version > 0: d += bytes([st])
        if version > 1: d += struct.pack('<HhB', hcs, h, q)
    for (arfcn, bsic, rssi, rank, st, hcs, h, q) in cells2:
        d += struct.pack('<HHbh', arfcn, bsic, rssi, rank)
        if version > 0: d += bytes([st])
        if version > 1: d += struct.pack('<HhB', hcs, h, q)
    return qc_log(0x4005, d)

def b_rrc(ct, p, kind, arfcn=10613, psc=0x1234, sub=3, rb=1):
    hdr = struct.pack('<BBHHH', ct, rb, len(p), arfcn, psc)
    if kind == 'v1': d = hdr[:4] + hdr[4:] + p            # ARFCN/PSC overlap the payload
    elif kind == 'ext1': d = hdr + bytes([sub]) + p        # one subtype octet (inside ARFCN/PSC area)
    elif kind == 'v2': d = hdr + b'\0\0' + p
    else: d = hdr + b'\0\0' + bytes([sub]) + p
    return qc_log(0x412f, d)

def b_cellid(mcc=(2, 4, 0), mnc=(0, 1, 0xf), flags=0x0b):
    d = struct.pack('<IIIH', 10663, 9613, 0x1234567, 77) + bytes([flags, 3]) + struct.pack('<H', 100)
    d += bytes(mcc) + bytes(mnc) + struct.pack('<II', 0x1234, 0x56)
    return qc_log(0x4127, d)

def b_rlc_sig(code, ents):
    d = bytes([len(ents)])
    for lcid, cnt, pdu in ents:
        d += bytes([lcid]) + struct.pack('<HH', cnt, len(pdu)) + pdu
    return qc_log(code, d)

def b_rlc_ctl(code, lcid, pdu):
    return qc_log(code, bytes([lcid]) + struct.pack('<H', len(pdu)) + pdu)

def b_rlc_cipher_dl(n):
    d = struct.pack('<H', n)
    for i in range(n):
        d += bytes([i + 1]) + struct.pack('<I', 0x11111111 * (i + 1)) + bytes([i & 1]) + struct.pack('<II', 0xdead0000 + i, 100 + i)
    return qc_log(0x4168, d)

def b_rlc_cipher_ul(n):
    d = struct.pack('<H', n)
    for i in range(n):
        d += bytes([i + 1]) + struct.pack('<I', 0x22222222 * (i + 1)) + bytes([i & 1]) + struct.pack('<I', 200 + i)
    return qc_log(0x4169, d)

def b_freqscan(typ, vals):
    d = bytes([1, typ]) + struct.pack('<hB', -482, len(vals))
    for rssi, arfcn in vals:
        d += struct.pack('<hH', rssi, arfcn)
    return qc_log(0x41b0, d)

def b_rr(code, chan, mtype, p, length=None):
    return qc_log(code, bytes([chan, mtype, len(p) if length is None else length]) + p)

def b_umts_nas(direction, p):
    return qc_log(0x713a, bytes([direction]) + struct.pack('<I', len(p)) + p)

def b_lte_rrc(ver, pdu, p, earfcn=1300, sfn=0x1234, pci=77, sib=0, rel=(9, 0x20)):
    d = bytes([ver]) + bytes(rel)
    if ver > 24: d += bytes([15, 0x10])
    d += bytes([1]) + struct.pack('<H', pci)
    d += struct.pack('<H', earfcn) if ver < 8 else struct.pack('<I', earfcn)
    d += struct.pack('<H', sfn) + bytes([pdu])
    if ver > 4: d += struct.pack('<I', sib)
    d += struct.pack('<H', len(p))
    if ver > 29: d += Z(3)
    return qc_log(0xb0c0, d + p)

def b_lte_nas(code, p, rel=(9, 2, 1)):
    return qc_log(code, bytes([1]) + bytes(rel) + p)

def b_nr_nas(code, p, rel=(15, 2, 0)):
    return qc_log(code, struct.pack('<I', 1) + bytes(rel) + p)

def b_nr_rrc(ver, pdu, p, ncgi=0x123456789, sfn=0x123456, arfcn=632628, sib=0):
    d = struct.pack('<I', ver) + bytes([15, 0x20, 1]) + struct.pack('<H', 5)
    if ver > 16: d += struct.pack('<Q', ncgi)
    d += struct.pack('<I', arfcn)
    d += struct.pack('<I', sfn) if ver < 12 else struct.pack('<I', sfn)[:3]
    d += bytes([pdu]) + struct.pack('<I', sib) + struct.pack('<H', len(p))
    if ver > 18: d += Z(1)
    if ver > 22: d += Z(2) + bytes([0])
    return qc_log(0xb821, d + p)

# ---- trial templates: (name, builder, candidate payloads) ----
CANDS = [Z(12), Z(24), bytes.fromhex('5555555555555555'), b'\x20' + Z(10), b'']
TEMPLATES = []
for ct in (0, 1, 2, 3, 4, 5, 6, 7, 8, 10):
    TEMPLATES.append(('rrc_v1_%d' % ct, lambda p, ct=ct: b_rrc(ct, p, 'v1', 0, 0), CANDS))
for ct in (0x09, 0xfe, 0xff):
    for sub in (0, 3, 12):
        TEMPLATES.append(('rrc_ext1_%x_%d' % (ct, sub), lambda p, ct=ct, sub=sub: b_rrc(ct, p, 'ext1', 0, 0, sub), CANDS))
for ct in range(0x80, 0x89):
    TEMPLATES.append(('rrc_v2_%x' % ct, lambda p, ct=ct: b_rrc(ct, p, 'v2'), CANDS))
for ct in (0x89, 0xf0):
    for sub in (0, 3, 31):
        TEMPLATES.append(('rrc_ext2_%x_%d' % (ct, sub), lambda p, ct=ct, sub=sub: b_rrc(ct, p, 'ext2', sub=sub), CANDS))
for ch in (0, 4, 1, 2, 3, 5, 6, 7, 0x80, 0x81, 0x84, 0x85, 25, 29):
    TEMPLATES.append(('rr_%x' % ch, lambda p, ch=ch: b_rr(0x512f, ch, 0x06, p), CANDS + [bytes.fromhex('06210000'), bytes.fromhex('0615 0000'.replace(' ', ''))]))
for ch in (1, 2, 3, 4, 0x80, 0x81, 0x82, 0x83):
    TEMPLATES.append(('gmac_%x' % ch, lambda p, ch=ch: b_rr(0x5226, ch, 0x06, p), CANDS))
for d in (0, 1):
    TEMPLATES.append(('umts_nas_%d' % d, lambda p, d=d: b_umts_nas(d, p), CANDS + [bytes.fromhex('0201010a')]))
for ver in (2, 8, 9, 14, 15, 19, 20, 25, 30):
    for pdu in (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15):
        TEMPLATES.append(('lte_rrc_%d_%d' % (ver, pdu), lambda p, ver=ver, pdu=pdu: b_lte_rrc(ver, pdu, p), CANDS[:2]))
LTE_NAS = [bytes.fromhex('075501'), bytes.fromhex('074e0a'), bytes.fromhex('07600f'), bytes.fromhex('074400'), bytes.fromhex('0745')]
for code in (0xb0e0, 0xb0e2, 0xb0ea, 0xb0ec):
    TEMPLATES.append(('lte_nas_%x' % code, lambda p, code=code: b_lte_nas(code, p), LTE_NAS))
NR_NAS = [bytes.fromhex('7e0058'), bytes.fromhex('7e0046'), bytes.fromhex('7e00640f'), bytes.fromhex('7e004403')]
for code in (0xb800, 0xb801, 0xb808, 0xb809, 0xb80a, 0xb80b, 0xb814):
    TEMPLATES.append(('nr_nas_%x' % code, lambda p, code=code: b_nr_nas(code, p), NR_NAS))
for ver, pdus in ((9, (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0xe, 0xf, 0x10, 0x11, 0x18, 0x1c, 0x1d)),
                  (14, (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0x1f, 0x20)),
                  (17, (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0xf, 0x10, 0x11, 0x12, 0x1d)),
                  (20, (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x24)),
                  (26, (1, 2, 3, 4, 5, 6, 7, 8, 9, 0xb, 0xc, 0x13, 0x24)),
                  (28, (1, 2, 3, 4, 5, 6, 7, 8, 0xa, 0xb, 0xc, 0x13, 0x24))):
    for pdu in pdus:
        TEMPLATES.append(('nr_rrc_%d_%x' % (ver, pdu), lambda p, ver=ver, pdu=pdu: b_nr_rrc(ver, pdu, p), CANDS[:3]))

LTE_NAS_DIR = []
for t in (0x41, 0x45, 0x48, 0x4c, 0x4d, 0x52, 0x55, 0x63, 0x69, 0x43, 0x44, 0x4e, 0x54, 0x60):
    LTE_NAS_DIR.append(bytes([0x07, t]) + bytes.fromhex('0f'))
    LTE_NAS_DIR.append(bytes([0x07, t]) + bytes.fromhex('00000000'))
    LTE_NAS_DIR.append(bytes([0x07, t]))
TEMPLATES.append(('lte_nas_types', lambda p: b_lte_nas(0xb0e2, p), LTE_NAS_DIR))
def main(out):
    G, B = [], []          # (diag bytes) for the main and the malformed capture
    U = []                 # plain UDP frames (dport, sport, payload) interleaved by index
    def g(d): G.append(('diag', d))
    def bad(d): B.append(('diag', d))
    # request for Get Log (handled by the log dissector as a request)
    g(bytes([0x10, 0x00]))
    # --- 0x4005 WCDMA search cell reselection ranking
    c3 = [(10663, 100, 80, -5, 0xf0, -7, 2, 5, -3, 1), (10688, 101, 90, 12, 0xe8, 4, 0, 6, 7, 0)]
    c2 = [(33, 0x1234, -70, 3, 1, 4, -1, 1)]
    for v in (0, 1, 2):
        g(b_crr(v, c3, c2))
    g(b_crr(0, [], []))
    g(b_crr(3, c3, c2))                                   # unknown version: header only
    # --- 0x412f WCDMA RRC (zero PDUs decode as the first choice of each channel)
    Zp = Z(24)
    for ct in (0, 1, 2, 3, 4, 5, 6, 7, 8, 10):
        g(b_rrc(ct, Zp, 'v1', 0, 0))
    for ct in (0x09, 0xfe, 0xff):
        for sub in (0, 3):
            g(b_rrc(ct, Zp, 'ext1', 0, 0, sub))
    for ct in range(0x80, 0x89):
        g(b_rrc(ct, Zp, 'v2'))
    for ct in (0x89, 0xf0):
        g(b_rrc(ct, Zp, 'ext2', sub=0))
    g(b_rrc(0x50, Zp, 'v1', 0, 0))                        # unknown channel type
    # reproducer (subtype of the v1 channel types): ARFCN 10613 and four zero octets
    for ct in (0, 2, 3):
        g(qc_log(0x412f, struct.pack('<BBHHH', ct, 1, 4, 10613, 0) + Z(4)))
    # --- RRC states and protocol errors
    for st in (0, 1, 2, 3, 4, 5, 9):
        g(qc_log(0x4125, bytes([st])))
    g(qc_log(0x4126, bytes([2, 1, 3, 4])))
    g(qc_log(0x4126, bytes([9, 12, 200, 7])))
    # --- 0x4127 WCDMA cell id
    g(b_cellid())                                         # MCC 240, MNC 01 (2 digits)
    g(b_cellid(mcc=(3, 1, 0), mnc=(4, 1, 0), flags=0x00)) # MNC 410, no flags
    g(b_cellid(mcc=(2, 6, 2), mnc=(0, 7, 0xf), flags=0x0f))
    g(b_cellid(mcc=(0xff, 0xff, 0xff), mnc=(0xff, 0xff, 0xff)))   # all ones is not reported
    # --- RLC
    pdus = [(16, 1, bytes([0x00])), (17, 2, bytes.fromhex('8000'))]
    g(b_rlc_sig(0x4135, pdus))
    g(b_rlc_sig(0x413c, pdus))
    g(b_rlc_sig(0x4135, []))
    g(b_rlc_ctl(0x4145, 16, bytes([0x00])))
    g(b_rlc_ctl(0x4146, 17, bytes([0x00])))
    g(b_rlc_cipher_dl(2))
    g(b_rlc_cipher_ul(3))
    g(b_rlc_cipher_dl(0))
    g(b_freqscan(2, [(100, 10663), (150, 10688)]))
    g(b_freqscan(3, [(-72, 10663)]))
    g(b_freqscan(1, [(1, 2)]))
    g(b_freqscan(3, []))
    # --- GSM RR
    for ch in (0, 4, 1, 2, 3, 5, 6, 7, 8, 11, 25, 29, 0x80, 0x81, 0x84, 0x85, 0x77):
        g(b_rr(0x512f, ch, 0x06, Zp))
    g(qc_log(0x512f, bytes([0x00, 0x06, 0x03]) + b'\x06\x3f\x00'))      # reproducer of the leak
    for ch in (1, 2, 3, 4, 0x80, 0x81, 0x82, 0x83, 0x55):
        g(b_rr(0x5226, ch, 0x06, Zp))
    for d in (0, 1):
        g(b_umts_nas(d, Z(12)))
    # --- LTE RRC: every version map, every PDU of each map, unknown version
    g(b_lte_rrc(3, 5, Z(24)))
    for ver, pdus_ in ((2, range(1, 9)), (9, range(8, 16)), (14, range(1, 10)), (15, range(1, 10)),
                       (19, (1, 3, 6, 7, 8, 9, 10, 11, 45, 46, 47, 48, 49, 50, 52, 99)),
                       (20, (1, 2, 4, 5, 6, 7, 8, 9, 54, 55, 56, 57, 58, 59, 61, 99)),
                       (26, (1, 3, 6, 11)), (25, (1, 2, 5, 9)), (30, (1, 2, 5, 9)), (8, (1, 8))):
        for pdu in pdus_:
            g(b_lte_rrc(ver, pdu, bytes.fromhex("2000000000") if pdu in (49, 58) else Z(24)))
    g(b_lte_rrc(77, 1, Z(24)))                             # unknown version: no subtype
    g(b_lte_rrc(8, 8, Z(24), earfcn=0x4000 + 5))           # EARFCN above the uplink flag
    # --- LTE NAS: direction is derived from the message type
    for code in (0xb0e0, 0xb0e1, 0xb0e2, 0xb0e3, 0xb0ea, 0xb0eb, 0xb0ec, 0xb0ed):
        g(b_lte_nas(code, bytes.fromhex('075501')))
    for t, body in ((0x45, '0f'), (0x4d, '0f'), (0x44, '0f'), (0x4e, '0f'), (0x54, ''), (0x60, '0f'),
                    (0x48, '00000000'), (0x4c, '00000000'), (0x63, '00000000'), (0x69, '00000000'),
                    (0x43, '00000000')):
        g(b_lte_nas(0xb0e2, bytes([0x07, t]) + bytes.fromhex(body)))
    # --- NR NAS and NR RRC
    for code in (0xb800, 0xb801, 0xb808, 0xb809, 0xb80a, 0xb80b, 0xb814):
        g(b_nr_nas(code, bytes.fromhex('7e0046')))
    for ver, pdus_ in ((9, (1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xe, 0xf, 0x10, 0x11, 0x1c, 0x1d, 0x70)),
                       (12, (1, 8)), (14, (1, 2, 3, 4, 5, 6, 7, 8, 9, 0x1f)),
                       (17, (1, 2, 3, 4, 5, 6, 7, 8, 0xf, 0x1d)), (19, (1, 8)),
                       (20, (1, 2, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x24)),
                       (23, (1, 8)), (24, (1, 8)), (26, (1, 2, 5, 9, 0xb, 0xc, 0x13, 0x24)),
                       (28, (1, 2, 5, 0xa, 0xb, 0xc, 0x13, 0x24)), (10, (1,)), (29, (1,))):
        for pdu in pdus_:
            g(b_nr_rrc(ver, pdu, Z(12) if ver != 29 else Z(12), ncgi=0x123456789 if pdu != 2 else 0))
    # --- unknown log code, and log codes below/above the handled ones (data)
    g(qc_log(0x1234, b'\x01\x02\x03'))
    g(qc_log(0xb7ff, b'\x01\x02\x03'))
    # --- reproducers (see README): the timestamps of the frame times, the RLC heuristic
    g(qc_log(0x4125, bytes([0x05]), ts=0x0000100000000000))
    g(qc_log(0x4125, bytes([0x05]), ts=0xffffffffffffffff))
    g(qc_log(0x4125, bytes([0x05]), ts=0))
    g(qc_log(0x4145, bytes([16]) + struct.pack('<H', 1) + b'\x00'))
    U_idx = len(G)
    G.append(('udp', (40001, 40002, b'umts-rlc' + bytes([0x03, 0x03, 0x04, 0x00, 0x01]) + b'\x80\x00\x00\x00')))
    # --- malformed capture: truncated items of every kind, hostile counts
    bad(qc_log(0x4005, bytes([0x42])))
    bad(qc_log(0x4005, bytes([0x82, 0x03, 0x00])))
    bad(qc_log(0x412f, bytes([0x80, 1])))
    bad(qc_log(0x412f, bytes([0x89, 1, 0, 0, 0, 0, 0, 0])))
    bad(qc_log(0x4125, b''))
    bad(qc_log(0x4126, bytes([1])))
    bad(qc_log(0x4127, Z(10)))
    bad(qc_log(0x4135, bytes([5, 1, 2, 0, 200, 0, 1])))
    bad(qc_log(0x413c, bytes([2])))
    bad(qc_log(0x4145, bytes([1, 200, 0, 1])))
    bad(qc_log(0x4146, bytes([1])))
    bad(qc_log(0x4168, struct.pack('<H', 50) + Z(20)))
    bad(qc_log(0x4169, struct.pack('<H', 50) + Z(20)))
    bad(qc_log(0x41b0, bytes([1, 3]) + struct.pack('<hB', 0, 200) + Z(8)))
    bad(qc_log(0x512f, bytes([0, 6])))
    bad(qc_log(0x5226, bytes([0x80])))
    bad(qc_log(0x713a, bytes([1, 2])))
    bad(qc_log(0xb0c0, bytes([9, 9, 0x20, 1])))
    bad(qc_log(0xb0e0, bytes([1, 9, 2])))
    bad(qc_log(0xb800, bytes([1, 0, 0, 0, 15])))
    bad(qc_log(0xb821, struct.pack('<I', 28) + Z(4)))
    bad(qc_log(0xb821, struct.pack('<I', 17) + Z(10)))
    bad(b_lte_nas(0xb0e2, bytes.fromhex('0741') + bytes.fromhex('0f')))
    bad(b_lte_nas(0xb0e2, bytes.fromhex('075200')))
    bad(b_lte_nas(0xb0e2, bytes.fromhex('0745')))
    bad(b_lte_nas(0xb0e2, bytes.fromhex('0748')))
    bad(b_rrc(0x89, Z(10), 'ext2', sub=3))
    bad(b_rrc(0x89, Z(10), 'ext2', sub=31))
    bad(b_cellid(mcc=(0xa, 1, 2), mnc=(0, 1, 0xf)))        # non decimal MCC (error expert info)
    bad(b_cellid(mcc=(2, 4, 0), mnc=(0xb, 1, 2)))          # non decimal MNC
    bad(bytes([0x10, 0, 0xff, 0xff]))
    # custom (0xff) wrapper: text lines instead of a decoded item
    bad(bytes([0xff]) + qc_log(0x4125, b'\x05'))
    os.makedirs(out, exist_ok=True)
    def frames(lst):
        r = []
        for k, (kind, d) in enumerate(lst):
            r.append(udp_frame(gsmtap(d), k) if kind == 'diag' else udp_frame(d[2], k, d[0], d[1]))
        return r
    write_pcap(os.path.join(out, 'qcdiag_log-coverage.pcap'), frames(G))
    write_pcap(os.path.join(out, 'qcdiag_log-coverage-malformed.pcap'), frames(B))
    print(len(G), len(B), 'udp frame at', U_idx + 1)

if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')
