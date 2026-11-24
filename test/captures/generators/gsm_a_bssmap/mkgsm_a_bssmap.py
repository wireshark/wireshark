#!/usr/bin/env python3
# Generates test/captures/gsm_a_bssmap_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic captures for packet-gsm_a_bssmap.c (GSM A-interface BSSMAP).

Usage: mkgsm_a_bssmap.py <output directory>

BSSMAP rides in SCCP (UDT, SSN 254) in MTP3 (Exported PDU "mtp3"); the BSSAP
heuristic of the SCCP dissector recognises it.  Every message of the
dissector's message table is built with valid element contents from the
tables below; the generator derives the element order from the dissector
source, so it needs the source tree at SRC.

  gsm_a_bssmap-coverage.pcap            valid messages
  gsm_a_bssmap-coverage-malformed.pcap  truncated/odd input, undecoded IEs
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import re
import struct
from bssmaplib import (
    bssmap, mtp3, sccp_cc, sccp_cr, sccp_dt1, SRC, strip_comments, udt, write_pcap,
)
from g4_fuzz import enum_values, functions, fcn_array, vs_values

PLMN = bytes.fromhex('62f210')
def cid(disc, *parts):
    return bytes([disc]) + b''.join(parts)
LAC = b'\x00\x2a'; CI = b'\x12\x34'; RNC = b'\x01\x02'; SAC = b'\x00\x07'
CELLS = {   # discriminator -> cell identification
    0x00: PLMN + LAC + CI, 0x01: LAC + CI, 0x02: CI, 0x04: PLMN + LAC, 0x05: LAC,
    0x08: PLMN + LAC + RNC, 0x09: RNC, 0x0a: LAC + RNC, 0x0b: PLMN + LAC + SAC,
    0x0c: PLMN + LAC + RNC + CI,
}
def cell(d): return bytes([d]) + CELLS[d]
def cell_list(d, n=2): return bytes([d]) + CELLS.get(d, b'\x01\x02\x03') * n

IMSI = bytes.fromhex('2926102143658709')
IMEI = bytes.fromhex('3a53420754103261')
IMEISV = bytes.fromhex('3b534207541032619f')
TMSIMID = bytes.fromhex('f4deadbeef')
DTAPS = [bytes.fromhex('051801'), bytes.fromhex('051b'), bytes.fromhex('0318')]
def a_apdu(proto, data): return bytes([proto]) + data

# Field elements (Old/New BSS to New/Old BSS information)
def fe(i, d): return bytes([i, len(d)]) + d

V = {}   # element name (without BE_) -> list of value bytes (TLV/TV value part)
V['CIC'] = [b'\x00\x01', b'\x12\x34']
V['CAUSE'] = [b'\x20', b'\x50', b'\x00', b'\x90\x12', b'\x85\x01', b'\x60', b'\x41']
V['IMSI'] = [IMSI]
V['TMSI'] = [b'\xde\xad\xbe\xef']
V['MID'] = [IMSI, IMEI, IMEISV, TMSIMID, b'\x00']
V['IMEI'] = [IMEI]
V['ENC_INFO'] = [b'\x01', b'\x06' + bytes(8), b'\x0a' + bytes(8)]
def _chan_variants():
    v = [b'\x01\x08\x01', b'\x01\x0b\x25\x04\x05', b'\x04\x09\x11', b'\x03\x00\x01']
    for first in (0x08, 0x21, 0x32):          # data: plain channel or 2/3 channels
        n = 0 if first == 0x08 else 1
        nt = [0x00, 0x18, 0x10, 0x11, 0x31, 0x34, 0x2f] if n == 0 else [0x16, 0x14, 0x13, 0x12, 0x11, 0x10, 0x2f]
        tr = [0x18, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x39, 0x3a, 0x3f] if n == 0 else \
             [0x1f, 0x1e, 0x1d, 0x1c, 0x1b, 0x1a, 0x19, 0x18, 0x10, 0x3f]
        if first != 0x32:
            v += [bytes([0x02, first, 0x40 | x, 0x00]) for x in nt] + [bytes([0x02, first, x, 0x00]) for x in tr]
    return v
V['CHAN_TYPE'] = _chan_variants() + [b'\x02\x32\x52\x00']
V['PERIODICITY'] = [b'\x05']
V['EXT_RES_IND'] = [b'\x03']
V['NUM_MS'] = [b'\x07']
V['CM_INFO_1'] = [b'\x57']
V['CM_INFO_2'] = [b'\x57\x18\x81']
V['CM_INFO_3'] = [b'\x60\x14\x04\x00']
V['INT_BAND'] = [b'\x1f']
V['RR_CAUSE'] = [b'\x01', b'\x65']
V['DLCI'] = [b'\x03', b'\xc0']
V['DOWN_DTX_FLAG'] = [b'\x00', b'\x01']
V['PRIO'] = [b'\x4d', b'\x01', b'\x03']
V['L3_HEADER_INFO'] = [b'\x05\x01', b'\x0b']
V['L3_INFO'] = DTAPS
V['L3_MSG'] = DTAPS
V['CELL_ID'] = [cell(d) for d in (0, 1, 2, 4, 5, 8, 9, 0x0a, 0x0b, 0x0c)] + [b'\x03\x00\x00\x00']
V['CELL_ID_LIST'] = [cell_list(0), cell_list(1), cell_list(2), cell_list(4), cell_list(5), cell_list(8),
                     cell_list(9), cell_list(0x0a), cell_list(0x0b), cell_list(0x0c), b'\x03\x00\x00', b'\x01']
V['CIC_LIST'] = [b'\x03\x0f', b'\x01\x01\x02']
V['DIAG'] = [b'\x00\x01', b'\x00\x02\x30\x04\x01\x20']
V['CHOSEN_CHAN'] = [b'\x19', b'\x09', b'\x81']
V['CIPH_RESP_MODE'] = [b'\x01', b'\x00']
V['CHAN_NEEDED'] = [b'\x01', b'\x03']
V['TRACE_TYPE'] = [b'\xa9', b'\x00']
V['TRIGGERID'] = [b'trigger1']
V['TRACE_REF'] = [b'\x12\x34']
V['TRANSID'] = [b'\x42', b'\x12\x34']
V['OMCID'] = [b'omc-1']
V['FOR_IND'] = [b'\x01', b'\x02', b'\x00']
V['CHOSEN_ENC_ALG'] = [b'\x02', b'\x04', b'\x01']
V['CCT_POOL'] = [b'\x01', b'\x81', b'\x33']
V['CURR_CHAN_1'] = [b'\x19', b'\x09']
V['QUE_IND'] = [b'\x01', b'\x00']
V['ASS_REQ'] = [b'\x00', b'\x01', b'\x02', b'\x03']
V['GROUP_CALL_REF'] = [bytes.fromhex('0123456753'), bytes.fromhex('00ffee1100')]
V['EMLPP_PRIO'] = [b'\x03', b'\x01']
V['CONF_EVO_IND'] = [b'\x01', b'\x02']
V['LSA_ID'] = [b'\x00\x00\x01', b'\xff\x00\x01']
V['LSA_ID_LIST'] = [b'\x00\x00\x00\x01', b'\x00\x00\x00\x01\x00\x00\x02']
V['LSA_INFO'] = [b'\x01\x25\x00\x00\x01', b'\x00', b'\x01\x08\x00\x00\x01\x1f\x00\x00\x02']
V['SPEECH_VER'] = [b'\x01', b'\x21', b'\x41', b'\x81', b'\x11']
V['LCS_PRIO'] = [b'\x00', b'\x01']
V['LOC_TYPE'] = [b'\x00', b'\x01\x00', b'\x02\x01', b'\x03', b'\x01\x02']
V['LOC_EST'] = [bytes.fromhex('10f2100001ff00000100'[:2] + '800102030405'), bytes.fromhex('00')]
V['POS_DATA'] = [b'\x00\x08\x0d', b'\x01', b'\x00\x00\x00']
V['APDU'] = [a_apdu(1, b'\x01'), a_apdu(1, bytes.fromhex('0a1801')), a_apdu(2, b'\x01\x02'), a_apdu(3, b'\x01'), a_apdu(0, b'\x01')]
V['SEG'] = [b'\x01', b'\x02\x00\x00', b'\x00']
V['SERV_HO'] = [b'\x01', b'\x02']
V['GERAN_CLS_M'] = [b'\x00\x00', b'\x12\x01\x23', b'\x01\x02\x03\x04\x05']
V['GERAN_BSC_CONT'] = [b'\x00', b'\x01\x02']
V['VEL_EST'] = [bytes.fromhex('0001')[:0] + b'\x00\x01\x02\x03', b'\x10\x00\x20\x00\x03\x20\x00\x40']
V['PAGING_INF'] = [b'\x01', b'\x02', b'\x00']
V['VGCS_FEAT_FLG'] = [b'\x1f', b'\x00']
V['TALKER_PRI'] = [b'\x00', b'\x01', b'\x02']
V['TALKER_ID'] = [b'\x01\x02\x03\x04', b'\x00\x01\x02\x03']
TPDU = bytes.fromhex('04039114f10000') + bytes.fromhex('11223344556600') + bytes.fromhex('02e130')
V['SMS_TO_VGCS'] = [bytes.fromhex('01000491447 7f100'.replace(' ', '')) + bytes([len(TPDU)]) + TPDU, bytes.fromhex('0100010100')]
V['VGCS_TALKER_MODE'] = [b'\x01', b'\x0d']
V['VGS_VBS_CELL_STAT'] = [b'\x01', b'\x00', b'\x03']
V['DATA_ID'] = [b'\x01', b'\x00\x01']
V['APP_DATA_INF'] = [b'\x01', b'\x00', b'\x03']
V['MSISDN'] = [bytes.fromhex('91447752100299f2')[:8]]
V['AOIP_TRANS_LAY_ADD'] = [bytes.fromhex('0a000001') + b'\x13\xc4', bytes.fromhex('20010db8000000000000000000000001') + b'\x13\xc4']
V['SPEECH_CODEC_LST'] = [b'\x00\x01\x02', b'\x03\x0f\x07\x04\x0f\x07\x0b\x0f\x07', b'\x09\x07\x0c\x07\x0d\x01\x0f\x00\x01\x02']
V['SPEECH_CODEC'] = [b'\x00', b'\xa3\x0f\x07', b'\x89\x07', b'\x0f\x01\x02']
V['CALL_ID'] = [b'\x00\x00\x01\x00']
V['CALL_ID_LST'] = [b'\x00\x00\x00\x01\x00\x00\x00\x02', b'']
V['A_ITF_SEL_FOR_RESET'] = [b'\x01', b'\x02', b'\x03']
V['KC128'] = [bytes(16)]
V['CSG_ID'] = [b'\x00\x00\x00\x2a\x01', b'\xff\xff\xff\xff\x80']
V['REROUTE_REJ_CAUSE'] = [b'\x01', b'\x02']
V['SEND_SEQN'] = [b'\x03']
V['REROUTE_OUTCOME'] = [b'\x01', b'\x00']
V['GLOBAL_CALL_REF'] = [bytes.fromhex('03abcdef0201020405aabbccdd')]
V['LCLS_CONF'] = [b'\x01', b'\x00']
V['LCLS_CON_STATUS_CONTROL'] = [b'\x01', b'\x02']
V['LCLS_BSS_STATUS'] = [b'\x01', b'\x00']
V['SELECTED_PLMN_ID'] = [PLMN]
V['LAST_USED_E_UTRAN_PLMN_ID'] = [PLMN]
V['OSMOCOM_OSMUX_CID'] = [b'\x07']
V['TALKER_FLAG'] = V['LCLS_CORR_NOT_NEEDED'] = [b'']
V['DECIPH_KEYS'] = [b'\x01' + bytes(16)]
V['LCS_CAUSE'] = [b'\x00', b'\x04\x01']
V['LCS_CLIENT'] = [bytes.fromhex('0000')]
FEA = fe(1, b'\x07') + fe(2, b'\x2c\x13') + fe(3, b'\x15') + fe(5, b'\x24\x07\x1f\x2f') + fe(6, b'\x09')
FEB = fe(9, b'\x01\x02\x03\x04') + fe(10, b'\x04\x03\x02\x01') + fe(12, b'\x00\x01\x02\x03') + fe(13, b'\x01') + fe(14, b'\x01') + fe(0x6f, b'\x15') + b'\x95' + PLMN
FEC = fe(11, cell(2) + fe(12, b'\x01\x02\x03\x04')) + fe(11, cell(0) + fe(11, cell(1) + fe(9, b'\x01\x02\x03\x04'))) + fe(11, cell(5))
V['OLD2NEW_INFO'] = [FEA, FEB, FEC]
V['NEW_BSS_TO_OLD_BSS_INF'] = V['OLD2NEW_INFO']

UNDECODED = {'CELL_ID_LIST_SEG', 'CELL_ID_LST_SEG_F_EST_CELLS', 'CELL_ID_LST_SEG_F_CELL_TB_EST',
             'CELL_ID_LST_SEG_F_REL_CELL', 'CELL_ID_LST_SEG_F_NOT_EST_CELL', 'GPS_ASSIST_DATA',
             'RET_ERR_REQ', 'RET_ERR_CAUSE', 'SRC_RNC_TO_TAR_RNC_CDMA', 'SNA_ACC_INF', 'GANSS_ASS_DTA',
             'GANSS_LOC_TYP', 'APP_DATA', 'LCS_QOS', 'LSA_ACC_CTRL', 'CCT_POOL_LIST', 'TIME_IND', 'RES_SIT'}
# TV elements whose decoder returns the (unknown) length: consumed wraps to 0
TVBUG = {'RES_IND_METHOD', 'RES_AVAIL', 'TOT_RES_ACC', 'TALKER_PRI'}
V['RES_IND_METHOD'] = [b'\x01', b'\x02']
V['RES_AVAIL'] = [bytes(range(1, 21))]
V['TOT_RES_ACC'] = [b'\x00\x05\x00\x06']
V['TIME_IND'] = [b'\x01']
V['VSTK_RAND_INF'] = [bytes.fromhex('0102030405')]
V['VSTK_INF'] = [bytes(16)]
V['GANSS_POS_DTA'] = [b'\x11', b'\x22']
V['GERAN_BSC_CONT'] = [b'\x00', b'\x01\x02', b'\x81\x7f']


def tables():
    hdr = open(SRC + 'packet-gsm_a_common.h').read()
    be = enum_values(hdr, 'BE_NONE')
    src = open(SRC + 'packet-gsm_a_bssmap.c').read()
    fns = functions(src)
    # messages that use a macro-less parse: add the vgcs setup ones by parsing 'ELEM_' by function name
    names = fcn_array(src, 'bssmap_msg_fcn')
    vals = vs_values(src, 'gsm_a_bssmap_msg_strings')
    # the three VGCS/VBS setup functions have a different signature layout
    for fn in ('bssmap_vgcs_vbs_setup', 'bssmap_vgcs_vbs_setup_ack', 'bssmap_vgcs_vbs_setup_refuse'):
        m = re.search(r'\n\s*' + fn + r'\(tvbuff_t \*tvb.*?\)\s*\{(.*?)\n\}\n', src, re.S)
        fns[fn] = [(e.group(1), e.group(2).strip()) for e in re.finditer(r'(ELEM_[A-Z_]+)\(([^,]+),', strip_comments(m.group(1)))]
    return be, fns, names, vals

def encode(kind, iei, val):
    if kind == 'TLV': return bytes([iei, len(val)]) + val
    if kind == 'TLV_E': return bytes([iei, len(val) >> 8, len(val) & 255]) + val
    if kind == 'TV': return bytes([iei]) + val
    if kind == 'T': return bytes([iei])
    raise ValueError(kind)

L3USERS = {'L3_INFO', 'L3_MSG'}
def build_message(code, elems, be, r, allow_undecoded=False, allow_bug=False, table=None, override=None, skip_bug=False):
    """Return (bytes, used_new) for round r or None."""
    out = bytes([code]); used = set(); fresh = False; n_seen = {}
    missing = []
    for k, (macro, tok) in enumerate(elems):
        name = tok[3:]; kind = macro.split('_', 2)[2]; opt = macro.startswith('ELEM_OPT')
        if skip_bug and name in TVBUG: continue
        if (name in UNDECODED and not allow_undecoded) or (name in TVBUG and not allow_bug):
            if opt: continue
            return None
        vals = (table or V).get(name)
        if override and name in override and n_seen.get(name, 0) == 0:
            vals = [override[name]]
        n_seen[name] = n_seen.get(name, 0) + 1
        if vals and name in ('CELL_ID', 'CELL_ID_LIST') and any(t[3:] in L3USERS for _, t in elems):
            vals = [v for v in vals if (v[0] & 0xf) < 8]
        if vals is None:
            if opt: continue
            missing.append(name); continue
        n = used_count = sum(1 for e in used if e == name)
        idx = r + n
        if opt and idx >= len(vals) and r > 0: continue
        if idx >= len(vals) and r > 0 and not opt:
            idx = idx % len(vals)
        else:
            fresh = fresh or (idx < len(vals) and r > 0) or r == 0
        None
        used = used | {name} if n == 0 else used
        out += encode(kind, be[tok], vals[idx % len(vals)])
    if missing: print('no values for', missing, file=sys.stderr)
    return out

def messages(be, fns, names, vals, rounds, **kw):
    res = []
    for code, fn in zip(vals, names):
        if fn == 'NULL' or fn not in fns: continue
        for r in range(rounds):
            m = build_message(code, fns[fn], be, r, **kw)
            if m is None: continue
            # later rounds only if something new is in it
            if r > 0:
                newv = any(r + 0 < len(V.get(t[3:], [])) for (_, t) in fns[fn])
                if not newv: continue
            res.append((code, fn, r, m))
    return res


# element values that only the malformed capture uses (undecoded or invalid)
UV = {n: [bytes(range(4))] for n in UNDECODED}
UV['LSA_ACC_CTRL'] = [b'']
UV['SRC_RNC_TO_TAR_RNC_UMTS'] = [bytes.fromhex('000102030405060708090a0b')]
UV['INTER_SYS_INF'] = [bytes.fromhex('000102030405060708090a0b')]
UV['SRC_RNC_TO_TAR_RNC_UMTS'] = [bytes.fromhex('000102030405060708090a0b'), b'\x00']
BAD = {
    'AOIP_TRANS_LAY_ADD': [bytes.fromhex('0a000001000000'), b''],
    'SPEECH_CODEC_LST': [b'\x09\x07\x05\xff', b'\x05\x01'],
    'SPEECH_CODEC': [b'\x06\x01', b'\x03'],
    'CHAN_TYPE': [b'\x01', b'\x02', b'\x02\x08', b'\x05\x01', b'\x03'],
    'CELL_ID': [b'\x0d\x01\x02\x03', b'\x00', b'\x01\x00'],
    'CELL_ID_LIST': [b'\x00' + PLMN + LAC + CI + b'\x01', b'\x00', b'\x00' + PLMN],
    'CAUSE': [b'\x80', b'\x81'],
    'OLD2NEW_INFO': [fe(0x77, b'\x01\x02\x03') + fe(8, b'\x01\x02'), fe(1, b'\x01') + b'\x02\xff\x00\x00\x00',
                     fe(0x0b, cell(2)), fe(0x0f, b'\x01\x02\x03'), fe(0x10, bytes(range(1, 20))), fe(7, bytes(range(1, 12))),
                     fe(4, bytes(range(1, 20))), fe(11, b'\x02' + CI + fe(11, b'\x02' + CI)), b'\x01'],
    'L3_INFO': [b'', b'\x05'],
    'L3_MSG': [b'\x17\x09' + bytes(range(9)), b'\x01'],
    'LOC_EST': [b'\x10\x01\x02'],
    'POS_DATA': [b'\x00', b''],
    'TRANSID': [b''],
    'GERAN_CLS_M': [b'\x01', b'\x01\x02\x03\x04\x05\x06\x07\x08'],
    'CALL_ID_LST': [b'\x00\x00\x00'],
    'VEL_EST': [b'\x00'],
    'APDU': [b'\x01', b'\x01\x02\x03\x04'],
    'DIAG': [b'\x00'],
    'CM_INFO_3': [b'\x03\x33'],
    'LCS_CLIENT': [b'\x01'],
    'SEG': [b'\x80\x01'],
    'CIC_LIST': [b'\x00'],
    'MSISDN': [b'\x91'],
    'SMS_TO_VGCS': [b'\x01', b'\x05\x00\x00\x00'],
    'CSG_ID': [b'\x00\x00'],
    'ENC_INFO': [b''],
}

def ranap_reloc_required(old_bss):
    """RANAP Relocation Required (PER) carrying only the Old BSS to New BSS Information IE."""
    ie = bytes([0x00, 0x14, 0x40, len(old_bss) + 1, len(old_bss)]) + old_bss
    val = bytes([0x00, 0x00, 0x01]) + ie
    return bytes([0x00, 0x02, 0x00, len(val)]) + val

def ranap_reloc_command(new_bss):
    """RANAP Relocation Command with the New BSS to Old BSS Information protocol extension."""
    ext = bytes([0x00, 0x64, 0x40, len(new_bss) + 1, len(new_bss)]) + new_bss
    val = bytes([0x40, 0x00, 0x00, 0x00, 0x00]) + ext
    return bytes([0x20, 0x02, 0x00, len(val)]) + val

def deep_fe(levels, closed=True):
    """Cell Load Information Group field elements nested `levels` deep with consistent lengths."""
    inner = b''
    for _ in range(levels):
        body = cell(2) + inner
        inner = bytes([0x0b, len(body)]) + body
        if len(inner) > 250 and not closed:
            break
    return inner

def frame(code_and_body):
    return mtp3(udt(bssmap(code_and_body)))

def main():
    import random
    out = sys.argv[1]
    random.seed(575)
    be, fns, names, vals = tables()
    msgs = messages(be, fns, names, vals, max(len(x) for x in V.values()))
    tag = []
    pk = []
    def add(m, why):
        pk.append(frame(m)); tag.append(why)
    for (c, fn, r, m) in msgs:
        add(m, '%s r%d' % (fn, r))
    # nested Cell Load Information Group: 15 levels decode cleanly (the first one is a reproducer
    # of the unbounded recursion; the chain is bounded by the enclosing lengths now)
    ho = lambda body: bytes([0x10]) + encode('TLV', be['BE_CHAN_TYPE'], V['CHAN_TYPE'][0]) + \
        encode('TLV', be['BE_ENC_INFO'], V['ENC_INFO'][0]) + encode('TLV', be['BE_CELL_ID'], cell(2)) + \
        encode('TLV', be['BE_CELL_ID'], cell(2)) + encode('TLV', be['BE_OLD2NEW_INFO'], body)
    add(ho(deep_fe(15)), 'ho_req nested field elements 15 levels (reproducer, fixed)')
    # resource indication (reproducer for be_res_avail; warns because the TV decoder returns len)
    add(bytes([0x51, 0x03]) + b''.join(struct.pack('>HH', 0x100 + i, 0x200 + i) for i in range(5)), 'res_ind reproducer')
    # connection-oriented flows: the cell discriminator of the first message is
    # remembered for the Layer 3 Information of the next ones (SCCP association tracking)
    def conn(slr, dlr, first, rest, disc_lst, cr_ssn=254):
        fr = [mtp3(sccp_cr(slr, bssmap(first))), mtp3(sccp_cc(slr, dlr), opc=1, dpc=2)]
        for k, m in enumerate(rest):
            fr.append(mtp3(sccp_dt1(dlr if k % 2 == 0 else slr, bssmap(m)), opc=2 if k % 2 == 0 else 1, dpc=1 if k % 2 == 0 else 2))
        return fr
    def ho_reqd(d):
        return bytes([0x11]) + encode('TLV', be['BE_CAUSE'], b'\x0d') + encode('TLV', be['BE_CELL_ID_LIST'], cell_list(d, 1))
    def ho_cmd(l3):
        return bytes([0x13]) + encode('TLV', be['BE_L3_INFO'], l3)
    for n, d in enumerate((0, 1, 2, 4, 5)):
        for f in conn(0x100 + n, 0x200 + n, ho_reqd(d), [ho_cmd(DTAPS[0]), bytes([0x20]) + encode('TLV', be['BE_CAUSE'], b'\x20')], None):
            pk.append(f); tag.append('connection cell disc %d' % d)
    # RANAP carries the same field elements (Old BSS to New BSS / New BSS to Old BSS Information)
    for body in (FEA, FEB, FEC):
        pk.append(mtp3(udt(ranap_reloc_required(body), 142, 142))); tag.append('ranap relocation required')
        pk.append(mtp3(udt(ranap_reloc_command(body), 142, 142))); tag.append('ranap relocation command')
    nmain = len(pk)
    write_pcap(os.path.join(out, 'gsm_a_bssmap-coverage.pcap'), pk)
    with open(os.path.join(out, 'frames.txt'), 'w') as f:
        for i, t in enumerate(tag, 1): f.write('%d\t0\t%s\t0\n' % (i, t))
    print(len(pk), 'frames')
    # ---- malformed capture ----
    mk = []
    def madd(m): mk.append(frame(m) if len(m) < 250 else mtp3(udt(bssmap(m[:240]))))
    full = dict(V); full.update(UV)
    for (c, fn, r, m) in messages(be, fns, names, vals, 1, allow_undecoded=True, allow_bug=True, table=full):
        madd(m)
    for (c, fn, r, m) in messages(be, fns, names, vals, 1, allow_undecoded=True, skip_bug=True, table=full):
        madd(m)
    # invalid element contents, in the first two messages that carry the element
    for name, lst in BAD.items():
        users = [(c, fn) for c, fn in zip(vals, names) if fn in fns and any(t[3:] == name for _, t in fns[fn])]
        for (c, fn) in users[:3]:
            for bv in lst:
                m = build_message(c, fns[fn], be, 0, allow_undecoded=True, allow_bug=True, table=full, override={name: bv})
                if m: madd(m)
    # Total Resource Accessible and Extended Resource Indicator are only reached when the preceding
    # Resource Indication Method (whose decoder wraps the TV length) is absent
    madd(bytes([0x51]) + encode('TLV', be['BE_CELL_ID'], cell(2)) + encode('TV', be['BE_TOT_RES_ACC'], V['TOT_RES_ACC'][0]))
    madd(bytes([0x50]) + encode('TV', be['BE_PERIODICITY'], b'\x05') + encode('TLV', be['BE_CELL_ID'], cell(2)) + encode('TV', be['BE_EXT_RES_IND'], b'\x03'))
    # nested field elements: too deep, length beyond the enclosing element, unknown ids
    madd(ho(deep_fe(40)))
    madd(ho(deep_fe(45)))
    madd(ho(bytes([0x0b, 0xff, 0x02, 0x00, 0x01]) * 50))
    madd(ho(bytes([0x0b, 0xff, 0x02, 0x00, 0x01]) * 3))
    madd(ho(bytes([0x0b, 0x01, 0x02])))
    madd(ho(bytes([0x0b, 0x05, 0x02, 0x00, 0x01, 0x02, 0x00])))
    for body in (deep_fe(40), bytes([0x0b, 0xff, 0x02, 0x00, 0x01]) * 40, fe(0x77, b'\x01'), fe(1, b'\x01') + b'\x02\x09\x00', b'\x01'):
        mk.append(mtp3(udt(ranap_reloc_required(body), 142, 142)))
        mk.append(mtp3(udt(ranap_reloc_command(body), 142, 142)))
    # message types without a decoder and unknown ones
    known = set(vals)
    for code in range(256):
        fn = dict(zip(vals, names)).get(code)
        if fn is None or fn == 'NULL':
            for body in (b'', b'\x01\x02\x03'):
                madd(bytes([code]) + body)
    # unknown trailing octets after the last element (Extraneous Data)
    for (c, fn, r, m) in msgs:
        if r == 0: madd(m + b'\xee\xee')
    # cut messages short and flip bytes
    for k, (c, fn, r, m) in enumerate(msgs):
        if len(m) > 2:
            madd(m[:random.randint(1, len(m) - 1)])
            if len(m) > 4: madd(m[:len(m) - random.randint(1, 3)])
        for _ in range(2):
            b = bytearray(m)
            for _ in range(random.randint(1, 3)):
                b[random.randint(1, len(b) - 1) if len(b) > 1 else 0] = random.getrandbits(8)
            madd(bytes(b))
    for n, d in enumerate((8, 9, 0x0a, 0x0b, 0x0c, 3, 6, 7, 0x0d)):
        for f in conn(0x300 + n, 0x400 + n, ho_reqd(d), [ho_cmd(DTAPS[0]), ho_cmd(bytes(range(1, 9)))], None):
            mk.append(f)
    write_pcap(os.path.join(out, 'gsm_a_bssmap-coverage-malformed.pcap'), mk)
    print(len(mk), 'malformed frames')

if __name__ == '__main__':
    main()
