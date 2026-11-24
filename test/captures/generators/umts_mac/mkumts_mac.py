#!/usr/bin/env python3
# Generates test/captures/umts_mac_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic UMTS MAC captures (epan/dissectors/packet-umts_mac.c).

Usage: mkumts_mac.py <outdir>
Writes umts_mac-coverage.pcapng and umts_mac-coverage-malformed.pcapng.

MAC for FDD is reached from FP, and FP with its per-frame info from the
"fp_hint" dissector (an Exported PDU record naming fp_hint carries the FP Hint
header, an AAL2/ATM header and the FP frame; it sets the FP, MAC and RLC
per-frame info).  Every record of the captures is such an Exported PDU.

MAC-is (E-DCH type 2) is not reachable from a capture: FP only calls it
with a non-NULL "data" pointer (never given by its callers) and RLC info that
only the NBAP conversation code attaches.
"""
import struct
import sys
import os
import json
from umtslib import (
    am_sdu, ATM, bits, blk, crc16, data, DCH, dch_fp, EDCH, exp_pdu, FACH, fach_fp, fp_frame,
    hint, HSDSCH, ipv4_udp, PCH, pch_fp, RACH, rach_fp, rb_entry, tf4, um_sdu, write_pcapng,
)

out = sys.argv[1] if len(sys.argv) > 1 else '.'
UOFF = 0
SEEDS = {}
_sf = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'seeds.json')
if os.path.exists(_sf):
    SEEDS = json.load(open(_sf))

main, mal, names, BUILDERS = [], [], [], []
P = lambda pdu, up=False: exp_pdu('fp_hint', pdu, 1 if up else None)


def add(lst, name, fn, up=False):
    """up: the Exported PDU record carries the P2P direction "received", which
    FP Hint turns into an uplink frame"""
    if lst is main:
        names.append(name)
        BUILDERS.append((name, fn, up))
    lst.append(P(fn(SEEDS.get(name, 0)), up))


def R(urnti, rlc=0, content=0, rbid=0, ctmux=0, ciph=0, deciph=0):
    return rb_entry(urnti + UOFF if urnti else 0, rlc, content, rbid, ctmux, ciph, deciph)


# RLC modes of the hint (enum rlc_mode)
TM, UM, AM = 0, 1, 2
# content values of the hint
UNK, DCCH_, PS, CS = 0, 1, 2, 3


def rrc(n, sd):
    return data(n, sd)


# ----------------------------------------------------------------- PCH
add(main, 'pch_bm1', lambda sd: hint(ATM, PCH, blk(0, 0, 1), pch_fp(1, 0, b'\x5a' * 5, b'')))
add(main, 'pch_tb', lambda sd: hint(ATM, PCH, blk(1, 64, 4), pch_fp(0, 1, b'', rrc(8, sd))))
add(mal, 'pch_tb1', lambda sd: hint(ATM, PCH, blk(1, 64, 1), pch_fp(1, 1, b'\x5a' * 5, rrc(8, sd))))


def ct(c):
    return (c, 4)


def fach(hdrbits, payload, urnti=0x3001, rb=(2, 1, 3)):
    tb, nb = bits(*hdrbits, payload)
    ent = R(urnti, rb[0], rb[1], rb[2], 1)
    return hint(ATM, FACH, blk(1, len(tb) * 8) + b'\x01' + ent, fach_fp(12, tb))


def fach_urnti(u, c, payload, **kw):
    return fach([(3, 2), (0, 2), (u + UOFF, 32), ct(c)], payload, **kw)


# ----------------------------------------------------------------- RRC CellUpdateConfirm that allocates a C-RNTI
def cuc_ccch(srnc, srnti, crnti):
    """DL-CCCH-Message / CellUpdateConfirm-CCCH (r3) with new-C-RNTI (UNALIGNED PER):
    the RRC dissector then stores the U-RNTI / C-RNTI pair for MAC."""
    pre = int(''.join('1' if i == 4 else '0' for i in range(23)), 2)
    return bits((0, 1), (0, 3), (0, 1), (0, 1), (srnc, 12), (srnti, 20), (pre, 23),
                (0, 2), (crnti, 16), (1, 2), (0, 1), (0, 1), (0, 1), (0, 2), (0, 1), (0, 1))[0]


# ----------------------------------------------------------------- RACH
def rach(hdrbits, payload, urnti=0x2001, ctmux=1, rb=(2, 1, 3)):
    tb, nb = bits(*hdrbits, payload)
    ent = R(urnti, rb[0], rb[1], rb[2], ctmux)
    return hint(ATM, RACH, blk(1, len(tb) * 8) + b'\x01' + ent, rach_fp(10, tb))


def ct(c):
    return (c, 4)


def rach_urnti(u, c, payload, **kw):
    return rach([(1, 2), (0, 2), (u + UOFF, 32), ct(c)], payload, **kw)


add(main, 'fach_cuc', lambda sd: fach([(0x40, 8)], um_sdu(0, cuc_ccch(0x123, 0x45678, 0x4321)), urnti=0x3200))
add(main, 'rach_ccch', lambda sd: rach([(0, 2)], rrc(8, sd)), up=True)
add(main, 'rach_dcch_um', lambda sd: rach_urnti(0x2101, 0, um_sdu(0, rrc(6, sd))), up=True)
add(main, 'rach_dcch_am', lambda sd: rach_urnti(0x2102, 1, am_sdu(0, rrc(6, sd))), up=True)
add(main, 'rach_ps_dtch', lambda sd: rach_urnti(0x2103, 8, am_sdu(0, ipv4_udp(8, sd))), up=True)
add(main, 'rach_cs_dtch', lambda sd: rach_urnti(0x2104, 4, rrc(8, sd)), up=True)
add(main, 'rach_crnti', lambda sd: rach([(1, 2), (1, 2), (0x4321, 16), ct(1)], am_sdu(0, rrc(6, sd))), up=True)
add(mal, 'rach_unk_content', lambda sd: rach_urnti(0x2105, 9, rrc(8, sd)), up=True)
add(main, 'rach_ct15', lambda sd: rach_urnti(0x2106, 15, rrc(8, sd)), up=True)
add(mal, 'rach_lchid15', lambda sd: rach_urnti(0x2107, 14, rrc(8, sd)), up=True)
add(mal, 'rach_unk_tctf', lambda sd: rach([(2, 2)], rrc(8, sd)), up=True)


# ----------------------------------------------------------------- FACH
add(main, 'fach_bcch', lambda sd: fach([(0, 2)], rrc(10, sd)))
add(main, 'fach_ccch', lambda sd: fach([(0x40, 8)], um_sdu(0, rrc(8, sd))))
add(main, 'fach_ctch', lambda sd: fach([(0x80, 8)], um_sdu(0, rrc(8, sd)), urnti=0x3002))
add(main, 'fach_dcch_um', lambda sd: fach_urnti(0x3101, 0, um_sdu(0, rrc(6, sd))))
add(main, 'fach_dcch_am', lambda sd: fach_urnti(0x3102, 1, am_sdu(0, rrc(6, sd))))
add(main, 'fach_ps_dtch', lambda sd: fach_urnti(0x3103, 8, am_sdu(0, ipv4_udp(8, sd))))
add(mal, 'fach_cs_dtch', lambda sd: fach_urnti(0x3104, 4, rrc(8, sd)))
add(main, 'fach_crnti', lambda sd: fach([(3, 2), (1, 2), (0x4322, 16), ct(1)], am_sdu(0, rrc(6, sd))))
add(mal, 'fach_unk_content', lambda sd: fach_urnti(0x3105, 9, rrc(8, sd)))
add(main, 'fach_ct15', lambda sd: fach_urnti(0x3106, 15, rrc(8, sd)))
add(main, 'fach_mtch', lambda sd: fach([(6, 4)], rrc(8, sd)))
add(main, 'fach_mcch', lambda sd: fach([(0x50, 8)], rrc(8, sd)))
add(main, 'fach_msch', lambda sd: fach([(0x5f, 8)], rrc(8, sd)))
add(mal, 'fach_unk_tctf', lambda sd: fach([(0x41, 8)], rrc(8, sd)))


# ----------------------------------------------------------------- DCH
def dch(content, mode, rb, ctmux, payload, urnti=0x5001, ciph=0):
    tb, nb = bits(*(([(rb - 1, 4)]) if ctmux else []), payload)
    return hint(ATM, DCH, b'\x01' + tf4(1, 1, len(tb) * 8) + b'\x01' + R(urnti, mode, content, rb, ctmux, ciph),
                dch_fp(20, [0], tb))


add(main, 'dch_dcch_um', lambda sd: dch(DCCH_, UM, 1, 0, um_sdu(0, rrc(6, sd)), 0x5001))
add(main, 'dch_dcch_am_ct', lambda sd: dch(DCCH_, AM, 2, 1, am_sdu(0, rrc(6, sd)), 0x5002))
add(main, 'dch_ps_am', lambda sd: dch(PS, AM, 9, 0, am_sdu(0, ipv4_udp(8, sd)), 0x5003))
add(main, 'dch_ps_am_ct', lambda sd: dch(PS, AM, 9, 1, am_sdu(1, ipv4_udp(8, sd)), 0x5003))
add(main, 'dch_cs', lambda sd: dch(CS, TM, 5, 0, rrc(8, sd), 0x5004))
add(main, 'dch_cs_ct', lambda sd: dch(CS, TM, 5, 1, rrc(8, sd), 0x5004))
add(mal, 'dch_unknown', lambda sd: dch(UNK, AM, 3, 0, rrc(8, sd), 0x5005))


def dch_ul(content, mode, rb, ctmux, payload, urnti):
    tb, nb = bits(*(([(rb - 1, 4)]) if ctmux else []), payload)
    return hint(ATM, DCH, b'\x01' + tf4(1, 1, len(tb) * 8) + b'\x01' + R(urnti, mode, content, rb, ctmux),
                fp_frame(bytes([21, 0]), tb + b'\x00\x00'))   # TB, quality estimate, CRCI bit


add(main, 'dch_ul_dcch_am', lambda sd: dch_ul(DCCH_, AM, 3, 1, am_sdu(0, rrc(6, sd)), 0x5201), up=True)
add(main, 'dch_ul_dcch_um', lambda sd: dch_ul(DCCH_, UM, 1, 0, um_sdu(0, rrc(6, sd)), 0x5202), up=True)
add(main, 'dch_ul_ps', lambda sd: dch_ul(PS, AM, 10, 1, am_sdu(0, ipv4_udp(8, sd)), 0x5203), up=True)


# ----------------------------------------------------------------- HS-DSCH
def hsframe(rbs, pdus, bitlen, entity=0, tail=b'\x00\x00\x00'):
    """HS-DSCH data frame type 1: rbs = [(urnti, mode, content, rbid, ctmux)],
    pdus = list of bytes (4 bit padding first), bitlen = MAC-d PDU length"""
    ent = b''.join(R(*r) for r in rbs)
    hdr = bytes([0x00]) + struct.pack('>H', bitlen << 3) + bytes([len(pdus)]) + struct.pack('>H', 0)
    fp = fp_frame(hdr, b''.join(pdus) + tail)
    return hint(ATM, HSDSCH, bytes([entity << 3, len(rbs)]) + ent, fp)


def hs_ct(c, rlc):
    """a C/T multiplexed MAC-d PDU: padding nibble, C/T, RLC PDU"""
    return bytes([c & 0xf]) + rlc, 4 + 8 * len(rlc)


def hs_plain(rlc):
    """a MAC-d PDU without C/T: padding nibble, then the RLC PDU (4 bit shifted)"""
    return bits((0, 4), rlc)[0], 8 * len(rlc)


def hs1(c, rlc, urnti, mode=AM, content=DCCH_, rbid=2):
    p, bl = hs_ct(c, rlc)
    return hsframe([(urnti, mode, content, rbid, 1)], [p], bl)


add(main, 'hs_ct0_dcch_um', lambda sd: hs1(0, um_sdu(0, rrc(6, sd)), 0x6001))
add(main, 'hs_ct1_dcch_am', lambda sd: hs1(1, am_sdu(0, rrc(6, sd)), 0x6002))
add(main, 'hs_ct8_ps', lambda sd: hs1(8, am_sdu(0, ipv4_udp(8, sd)), 0x6003))
add(main, 'hs_ct4_cs', lambda sd: hs1(4, rrc(8, sd), 0x6004))
add(main, 'hs_ct14_ps', lambda sd: hs1(13, am_sdu(1, ipv4_udp(8, sd)), 0x6003))
add(main, 'hs_ct14_ccch', lambda sd: hs1(14, um_sdu(0, rrc(8, sd)), 0x6005))
add(mal, 'hs_ct9_unknown', lambda sd: hs1(9, rrc(8, sd), 0x6006))
add(main, 'hs_ct15', lambda sd: hs1(15, rrc(8, sd), 0x6007))


def hs_plain_frame(rlc, urnti, mode=UM, content=PS, rbid=2):
    p, bl = hs_plain(rlc)
    return hsframe([(urnti, mode, content, rbid, 0)], [p], bl)


# MACd-flow 0 without C/T: content DCCH (fake logical channel id 1)
add(main, 'hs_plain_dcch', lambda sd: hs_plain_frame(um_sdu(0, rrc(6, sd)), 0x6010))
# two MAC-d PDUs in one frame, each with its own bearer entry
add(main, 'hs_two_pdus', lambda sd: hsframe(
    [(0x6020, AM, DCCH_, 2, 1), (0x6021, AM, PS, 9, 1)],
    [hs_ct(1, am_sdu(0, rrc(6, sd)))[0], hs_ct(8, am_sdu(0, rrc(6, sd)))[0]], 4 + 8 * 8))


def ehs_frame(blocks, urnti=0x6030, mode=AM, content=DCCH_, rbid=2):
    """HS-DSCH type 2 (MAC-ehs): blocks = [(lchid, [pdu bytes...])], every
    PDU of a block has the same length"""
    nb = len(blocks)
    hdr = bytes([0x00, nb << 3, 0x00, 0x00, 0x00])
    for n in range(0, nb, 2):
        l0 = len(blocks[n][1][0])
        lc0, p0 = blocks[n][0], len(blocks[n][1])
        if n + 1 < nb:
            l1 = len(blocks[n + 1][1][0])
            lc1, p1 = blocks[n + 1][0], len(blocks[n + 1][1])
            hdr += bytes([l0 >> 3, ((l0 & 7) << 5) | p0, (lc0 << 4) | (l1 >> 7), (l1 & 0x7f) << 1, (p1 << 4) | lc1])
        else:
            hdr += bytes([l0 >> 3, ((l0 & 7) << 5) | p0, lc0 << 4])
    pl = b''.join(b''.join(p) for _, p in blocks)
    fp = fp_frame(hdr, pl)
    return hint(ATM, HSDSCH, bytes([0x08, 1]) + R(urnti, mode, content, rbid, 0), fp)


add(main, 'ehs_dcch_um', lambda sd: ehs_frame([(0, [um_sdu(0, rrc(6, sd))])], 0x6030))
add(main, 'ehs_two_blocks', lambda sd: ehs_frame(
    [(1, [am_sdu(0, rrc(6, sd))]), (8, [am_sdu(0, rrc(8, sd)), am_sdu(1, rrc(8, sd))])], 0x6031))
add(main, 'ehs_three_blocks', lambda sd: ehs_frame(
    [(4, [rrc(8, sd)]), (8, [am_sdu(0, ipv4_udp(8, sd))]), (14, [um_sdu(0, rrc(8, sd))])], 0x6032))
add(mal, 'ehs_lchid15', lambda sd: ehs_frame([(15, [rrc(8, sd)])], 0x6033))


# ----------------------------------------------------------------- E-DCH (type 1)
def crc11(data):
    r = 0
    for b in data:
        r ^= b << 3
        for _ in range(8):
            r = ((r << 1) ^ 0x307) & 0x7ff if r & 0x400 else (r << 1) & 0x7ff
    return r


def edch_fp(subframes, fsn=1, cfn=7):
    """E-DCH data frame, type 1; subframes = [(sfn, [(ddi, n, [mac-d pdu bytes])])]"""
    rest = bytes([fsn & 0xf, len(subframes) - 1, cfn])
    payload = b''
    for sfn, es in subframes:
        s = ''.join(['{:04b}'.format(len(es))] + ['{:06b}{:06b}'.format(d, n) for d, n, _ in es])
        s += '0' * (-len(s) % 8)
        rest += bytes([(1 << 3) | sfn]) + bytes(int(s[i:i + 8], 2) for i in range(0, len(s), 8))
        for d, n, pdus in es:
            payload += bytes([0x05]) + b''.join(pdus)
    chk = bytes([rest[0] & 0x0f]) + rest[1:]
    c = crc11(chk)
    b0 = (c >> 4) << 1
    rest = bytes([((c & 0xf) << 4) | (rest[0] & 0xf)]) + rest[1:]
    f = bytes([b0]) + rest + payload
    return f + struct.pack('>H', crc16(payload))


def edch_hint(urnti, fp):
    ddis = bytes([1, 3]) + struct.pack('<H', 64) + bytes([2, 9]) + struct.pack('<H', 64)
    return hint(ATM, EDCH, bytes([1, 2]) + ddis + b'\x01' + R(urnti, AM, DCCH_, 3, 0), fp)


add(mal, 'edch_t1', lambda sd: edch_hint(0x7001, edch_fp([(2, [(1, 1, [rrc(8, sd)])])])))
add(mal, 'edch_t1_multi', lambda sd: edch_hint(0x7002, edch_fp(
    [(1, [(1, 2, [rrc(8, sd), rrc(8, sd + 1)]), (2, 1, [rrc(8, sd)])]), (3, [(2, 1, [rrc(8, sd)])])])))



# ----------------------------------------------------------------- no per-frame info (no radio bearer entry)
add(mal, 'rach_norb', lambda sd: hint(ATM, RACH, blk(1, 64) + b'\x00', rach_fp(10, rrc(8, 0))), up=True)
add(mal, 'fach_norb', lambda sd: hint(ATM, FACH, blk(1, 64) + b'\x00', fach_fp(10, rrc(8, 0))))
add(mal, 'dch_norb', lambda sd: hint(ATM, DCH, b'\x01' + tf4(1, 1, 64) + b'\x00', dch_fp(10, [0], rrc(8, 0))))
add(mal, 'hs_norb', lambda sd: hint(ATM, HSDSCH, b'\x00\x00', fp_frame(bytes([0x00]) + struct.pack('>H', 64 << 3) + bytes([1]) + struct.pack('>H', 0), hs_plain(rrc(8, 0))[0] + b'\0\0\0')))
add(mal, 'edch_norb', lambda sd: hint(ATM, EDCH, bytes([1, 2]) + bytes([1, 3]) + struct.pack('<H', 64) + bytes([2, 9]) + struct.pack('<H', 64) + b'\x00',
                                    edch_fp([(2, [(1, 1, [rrc(8, 0)])])])))
# MAC-d PDU shorter than the transport block size (the bits are missing)
add(mal, 'dch_short_tb', lambda sd: hint(ATM, DCH, b'\x01' + tf4(1, 1, 200) + b'\x01' + R(0x5101, AM, DCCH_, 2, 1), dch_fp(10, [0], bits((1, 4), am_sdu(0, rrc(4, 0)))[0])))


# A C-RNTI retrieved twice: the second pass (-2) no longer finds it (the
# RRC allocation is dropped after the second retrieval on the first pass)
add(mal, 'cuc2', lambda sd: fach([(0x40, 8)], um_sdu(0, cuc_ccch(0x321, 0x87654, 0x4330)), urnti=0x3300))
add(mal, 'rach_crnti2a', lambda sd: rach([(1, 2), (1, 2), (0x4330, 16), ct(1)], am_sdu(0, rrc(6, sd)), urnti=0x2300), up=True)
add(mal, 'fach_crnti2b', lambda sd: fach([(3, 2), (1, 2), (0x4330, 16), ct(1)], am_sdu(0, rrc(6, sd)), urnti=0x3301))

if os.environ.get('CAND'):
    cand, cnames = [], []
    for seed in range(int(os.environ['CAND'])):
        UOFF = seed * 0x10
        for name, fn, up in BUILDERS:
            cand.append((0, P(fn(seed), up)))
            cnames.append([name, seed])
    write_pcapng(os.path.join(out, 'cand.pcapng'), cand)
    json.dump(cnames, open(os.path.join(out, 'cand.json'), 'w'))
    sys.exit(0)

write_pcapng(os.path.join(out, 'umts_mac-coverage.pcapng'), [(0, p) for p in main])
write_pcapng(os.path.join(out, 'umts_mac-coverage-malformed.pcapng'), [(0, p) for p in mal])
json.dump(names, open(os.path.join(out, 'names.json'), 'w'))
print(len(main), len(mal))
