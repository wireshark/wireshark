#!/usr/bin/env python3
# Generates test/captures/nas_eps_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic NAS-EPS (3GPP TS 24.301) coverage captures.

    mknas_eps.py select <tshark> <workdir>   # once: try random candidates, keep clean ones
    mknas_eps.py <outdir>                    # write the captures (uses selected.json)

Every message of TS 24.301 is built from the IE table in spec.py (read from
the dissector source with extract_spec.py). The mandatory part of a message
and each optional IE are tried with random contents; "select" runs tshark on
the candidates and records those that decode without malformed packets or
warnings in selected.json. No keys, no ciphertext: ciphered frames carry
placeholder bytes and a MAC of zero or a made up value.
"""
import json
import os
import random
import struct
import subprocess
import sys
from spec import SPEC

HERE = os.path.dirname(os.path.abspath(__file__))

EMM = {0x41: ['attach_req'], 0x42: ['attach_acc'], 0x43: ['attach_comp'], 0x44: ['attach_rej'],
       0x45: ['detach_req_UL', 'detach_req_DL'], 0x48: ['trac_area_upd_req'],
       0x49: ['trac_area_upd_acc'], 0x4b: ['trac_area_upd_rej'], 0x4c: ['ext_serv_req'],
       0x4d: ['ctrl_plane_serv_req'], 0x4e: ['serv_rej'], 0x4f: ['serv_accept'],
       0x50: ['guti_realloc_cmd'], 0x52: ['auth_req'], 0x53: ['auth_resp'], 0x55: ['id_req'],
       0x56: ['id_res'], 0x5c: ['auth_fail'], 0x5d: ['sec_mode_cmd'], 0x5e: ['sec_mode_comp'],
       0x5f: ['sec_mode_rej'], 0x60: ['emm_status'], 0x61: ['emm_inf'], 0x62: ['dl_nas_trans'],
       0x63: ['ul_nas_trans'], 0x64: ['cs_serv_not'], 0x68: ['dl_gen_nas_trans'],
       0x69: ['ul_gen_nas_trans']}
EMM_EMPTY = [0x46, 0x4a, 0x51, 0x54]
ESM = {0xc1: 'act_def_eps_bearer_ctx_req', 0xc2: 'act_def_eps_bearer_ctx_acc',
       0xc3: 'act_def_eps_bearer_ctx_rej', 0xc5: 'act_ded_eps_bearer_ctx_req',
       0xc6: 'act_ded_eps_bearer_ctx_acc', 0xc7: 'act_ded_eps_bearer_ctx_rej',
       0xc9: 'mod_eps_bearer_ctx_req', 0xca: 'mod_eps_bearer_ctx_acc',
       0xcb: 'mod_eps_bearer_ctx_rej', 0xcd: 'deact_eps_bearer_ctx_req',
       0xce: 'deact_eps_bearer_ctx_acc', 0xd0: 'pdn_con_req', 0xd1: 'pdn_con_rej',
       0xd2: 'pdn_disc_req', 0xd3: 'pdn_disc_rej', 0xd4: 'bearer_res_all_req',
       0xd5: 'bearer_res_all_rej', 0xd6: 'bearer_res_mod_req', 0xd7: 'bearer_res_mod_rej',
       0xd9: 'inf_req', 0xda: 'inf_resp', 0xdb: 'notification', 0xdc: 'dummy_msg',
       0xe8: 'status', 0xe9: 'remote_ue_report', 0xea: 'remote_ue_report_resp',
       0xeb: 'data_transport'}
ESM_EMPTY = {0xd9, 0xdc, 0xea}

VLEN = {'DE_AUTH_PARAM_RAND': 16, 'DE_EMM_PAGING_ID': 1, 'DE_EMM_SHORT_MAC': 2,
        'DE_GPRS_TIMER': 1, 'DE_ESM_CAUSE': 1, 'DE_EMM_CAUSE': 1, 'DE_EMM_NAS_SEC_ALGS': 1,
        'DE_EMM_GEN_MSG_CONT_TYPE': 1, 'DE_EMM_KSI_AND_SEQ_NO': 1}

# Valid inner messages for the ESM / NAS message containers
PDN_REQ = bytes.fromhex('0201d011')
ACT_DEF = bytes.fromhex('0201c1' '020105' '0443036162' '63' '0a0900000000000000000000')
ESM_INFO_REQ = bytes.fromhex('0201d9')
ESM_STATUS = bytes.fromhex('0201e8' '2b')
GUTI = bytes.fromhex('0bf6130014000101c0000001')
GUTI = bytes.fromhex('0bf613001400010120000001')
IMSI = bytes.fromhex('0829' '43' '65' '87' '09' '21' '43' '65')
IMEI = bytes.fromhex('0833' '5a' '34' '12' '90' '78' '56' '34')
MTMSI = bytes.fromhex('05f4c0000001')


def lv(b):
    return bytes([len(b)]) + b


def lve(b):
    return struct.pack('>H', len(b)) + b


def rb(r, n):
    return bytes(r.randrange(256) for _ in range(n))


def mandatory(r, spec, variant):
    """Random mandatory part for one message function."""
    out = b''
    if spec['nib']:
        out += bytes([r.choice([0x00, 0x01, 0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76,
                                0x07, 0xe1, 0xf2, r.randrange(256)])])
    for kind, de in spec['mand']:
        if kind == 'MAND_V':
            out += rb(r, VLEN[de])
        elif kind == 'MAND_LV':
            if de in ('DE_EMM_EPS_MID', 'DE_EPS_CMN_MOB_ID'):
                out += r.choice([GUTI, IMSI, IMEI, MTMSI])
            elif de == 'DE_ESM_EPS_QOS':
                out += lv(qos(r.choice([1, 2, 3, 5, 6, 9, 11, 13])))
            elif de == 'DE_ACC_POINT_NAME':
                out += lv(bytes.fromhex('03616263') + r.choice([b'', bytes.fromhex('03636f6d')]))
            elif de == 'DE_ESM_PDN_ADDR':
                out += r.choice([lv(bytes.fromhex('01c0a80001')), lv(bytes([2]) + rb(r, 8)), lv(bytes([3]) + rb(r, 12))])
            elif de == 'DE_TRAFFIC_FLOW_TEMPLATE':
                out += r.choice([lv(bytes.fromhex('21310109' '10c0a80001ffffffff')), lv(bytes.fromhex('60')),
                                 lv(bytes.fromhex('2231010910c0a80001ffffffff' '41020b' '50' '0050')[:13])])
            elif de == 'DE_EMM_TRAC_AREA_ID_LST':
                out += lv(bytes([r.choice([0x00, 0x20, 0x40])]) + bytes.fromhex('130014') + rb(r, 2))
            else:
                out += lv(rb(r, r.choice([1, 2, 3, 4, 5, 6, 8, 12, 16])))
        elif kind == 'MAND_LV_E':
            if de == 'DE_EMM_ESM_MSG_CONT':
                out += lve(r.choice([PDN_REQ, ACT_DEF, ESM_INFO_REQ, ESM_STATUS]))
            else:
                out += lve(rb(r, r.choice([1, 2, 5, 12])))
    return out


def opt_ie(r, kind, iei, n=None):
    if kind == 'OPT_TV_SHORT':
        return bytes([iei | r.randrange(16)])
    if kind == 'OPT_TV':
        return bytes([iei]) + rb(r, n if n is not None else r.randrange(1, 9))
    if kind == 'OPT_TLV':
        n = n if n is not None else r.choice([1, 2, 3, 4, 5, 6, 7, 8, 9, 12, 16, 20])
        return bytes([iei]) + lv(rb(r, n))
    n = n if n is not None else r.choice([1, 2, 3, 4, 6, 8, 12, 16, 40])
    return bytes([iei]) + lve(rb(r, n))


def hdr_emm(code):
    return bytes([0x07, code])


def hdr_esm(code, bid=5, pti=1):
    return bytes([(bid << 4) | 2, pti, code])


def specs_of(code):
    if code in EMM:
        return [('nas_emm_' + f, SPEC['nas_emm_' + f]) for f in EMM[code]]
    return [('nas_esm_' + ESM[code], SPEC['nas_esm_' + ESM[code]])]


def candidates():
    """Deterministic list of (info, bytes). info = (code, spec name, iei or -1, kind)"""
    r = random.Random(24301)
    out = []
    codes = list(EMM) + list(ESM)
    for code in codes:
        for name, spec in specs_of(code):
            h = hdr_emm(code) if code in EMM else hdr_esm(code, bid=r.randrange(1, 16), pti=r.randrange(1, 255))
            for i in range(300):
                out.append(((code, name, -1, 'base'), h, mandatory(r, spec, i)))
    return out, r


PLMN = bytes.fromhex('130014')
POOL = {
    'DE_EMM_TRAC_AREA_ID_LST': [bytes([0x00]) + PLMN + b'\x00\x01',
                                bytes([0x01]) + PLMN + b'\x00\x01\x00\x02',
                                bytes([0x20]) + PLMN + b'\x00\x01',
                                bytes([0x40]) + PLMN + b'\x00\x01' + bytes.fromhex('21f354') + b'\x00\x02',
                                bytes([0x41]) + PLMN + b'\x00\x01' + PLMN + b'\x00\x02'],
    'DE_EPS_CMN_LOC_AREA_ID': [PLMN + b'\x00\x01'],
    'DE_EMM_TRAC_AREA_ID': [PLMN + b'\x00\x07'],
    'DE_EMERGENCY_NUM_LIST': [bytes.fromhex('0301' '11f2'), bytes.fromhex('0401' '1121f3' '0301' '1ef2')[:0] +
                              bytes.fromhex('0301' '11f2' '0402' '0912f3')],
    'DE_EMM_ESM_MSG_CONT': [PDN_REQ, ACT_DEF],
    'DE_ESM_NBIFOM_CONT': [bytes.fromhex('010101'), bytes.fromhex('010102020101030100'),
                           bytes.fromhex('0b0a00010000000000'), bytes.fromhex('070100')],
    'DE_EMM_LCS_CLIENT_ID': [bytes.fromhex('3003800100'), bytes.fromhex('3003800101'),
                             bytes.fromhex('300a800103a105040331323334')[:0] + bytes.fromhex('3003800102')],
    'DE_NAS_5GS_MM_PLMNS_LIST_DISASTER_COND': [PLMN, PLMN + bytes.fromhex('21f354')],
}


def optional_candidates(bases, r):
    out = []
    for (code, name), (h, m) in bases.items():
        spec = SPEC[name]
        for kind, iei, de in spec['opt']:
            if kind == 'OPT_TV_SHORT':
                ns = [None] * 16
            elif kind == 'OPT_TV':
                ns = [1, 2, 3, 4, 5, 6, 7, 8] * 4
            elif kind == 'OPT_TLV':
                ns = list(range(1, 42)) * 2 + [60, 98, 200, 250]
            else:
                ns = list(range(1, 42)) + [60, 100, 200, 400]
            for p in POOL.get(de, []):
                if kind == 'OPT_TLV':
                    out.append(((code, name, iei, kind), h, m + bytes([iei]) + lv(p)))
                elif kind == 'OPT_TLV_E':
                    out.append(((code, name, iei, kind), h, m + bytes([iei]) + lve(p)))
                else:
                    out.append(((code, name, iei, kind), h, m + bytes([iei]) + p))
            for n in ns:
                out.append(((code, name, iei, kind), h, m + opt_ie(r, kind, iei, n)))
    return out


def epdu(proto, payload):
    p = proto.encode()
    pad = (4 - len(p) % 4) % 4
    return struct.pack('>HH', 12, len(p) + pad) + p + b'\0' * pad + struct.pack('>HH', 0, 0) + payload


def write_pcap(name, frames, linktype=252):
    with open(name, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)


def run_check(tshark, pcap):
    """-> list of (frame, malformed, expert severity max) per frame"""
    env = dict(os.environ, WIRESHARK_CONFIG_DIR=os.path.join(HERE, 'cfg'))
    o = subprocess.run(['timeout', '-s', 'KILL', '600', tshark, '-r', pcap, '-Tfields', '-eframe.number',
                        '-e_ws.malformed', '-e_ws.expert.severity'], capture_output=True, text=True, env=env).stdout
    res = {}
    for l in o.splitlines():
        p = l.split('\t')
        sev = [int(x, 0) for x in p[2].split(',')] if len(p) > 2 and p[2] else []
        res[int(p[0])] = (len(p) > 1 and p[1] != '', max(sev) if sev else 0)
    return res


def clean(res, n, strict=True):
    bad = res.get(n)
    if bad is None:
        return False
    return not bad[0] and bad[1] < (0x00400000 if strict is True else 0x00600000)


def select(tshark, work):
    os.makedirs(work, exist_ok=True)
    cand, r = candidates()
    pc = os.path.join(work, 'cand_base.pcap')
    write_pcap(pc, [epdu('nas-eps_plain', h + m) for _, h, m in cand])
    res = run_check(tshark, pc)
    bases = {}
    keep = {}
    for i, (info, h, m) in enumerate(cand):
        if clean(res, i + 1) or (not any(clean(res, j + 1) for j, c in enumerate(cand) if c[0][:2] == info[:2]) and clean(res, i + 1, False)):
            key = (info[0], info[1])
            keep.setdefault(key, [])
            if len(keep[key]) < 3 and m not in [x[1] for x in keep[key]]:
                keep[key].append((h, m))
    # one base per message; messages without any clean base are listed
    for key, v in keep.items():
        bases[key] = v[0]
    missing = [(hex(c), n) for c in list(EMM) + list(ESM) for n, _ in specs_of(c) if (c, n) not in bases]
    print('no clean base:', missing)
    oc = optional_candidates(bases, r)
    pc2 = os.path.join(work, 'cand_opt.pcap')
    write_pcap(pc2, [epdu('nas-eps_plain', h + m) for _, h, m in oc])
    res2 = run_check(tshark, pc2)
    good = {}
    for strict in (True, False):
        for i, (info, h, m) in enumerate(oc):
            if clean(res2, i + 1, strict) and (strict is True or not good.get(info[:3])) and m.hex() not in good.setdefault(info[:3], []):
                good[info[:3]].append(m.hex())
    good = {k: v for k, v in good.items() if v}
    chosen = {}
    for k, v in good.items():
        if len(v) <= 4:
            chosen[k] = v
        else:      # spread over the clean ones (they differ in length)
            chosen[k] = [v[0], v[len(v) // 3], v[2 * len(v) // 3], v[-1]]
    sel = {'bases': {'%d|%s' % k: [(h.hex(), m.hex()) for h, m in v] for k, v in keep.items()},
           'opt': {'%d|%s|%d' % k: v for k, v in chosen.items()}}
    # combined frame per message: the first clean payload of every optional IE
    combo = []
    for key, (h, m) in sorted(bases.items()):
        body = m
        for kind, iei, de in SPEC[key[1]]['opt']:
            if (key[0], key[1], iei) in chosen:
                body += bytes.fromhex(chosen[(key[0], key[1], iei)][0])[len(m):]
        combo.append(((key[0], key[1]), h, body))
    pc3 = os.path.join(work, 'cand_combo.pcap')
    write_pcap(pc3, [epdu('nas-eps_plain', h + b) for _, h, b in combo])
    res3 = run_check(tshark, pc3)
    sel_combo = {}
    for i, (k, h, b) in enumerate(combo):
        if clean(res3, i + 1):
            sel_combo['%d|%s' % k] = b.hex()
    print('combined frames clean: %d of %d' % (len(sel_combo), len(combo)))
    sel['combo'] = sel_combo
    json.dump(sel, open(os.path.join(HERE, 'selected.json'), 'w'), indent=0)
    tot = sum(len(spec['opt']) for _, s in [(c, sp) for c in list(EMM) + list(ESM) for sp in specs_of(c)] for spec in [s[1]])
    print('optional IEs with a clean candidate: %d of %d' % (len(chosen), tot))
    nob = [(k) for c in list(EMM) + list(ESM) for n, s in specs_of(c) if (c, n) in bases for kind, iei, de in s['opt']
           if (c, n, iei) not in chosen for k in [(hex(c), n, hex(iei))]]
    print('IEs without clean candidate:', nob)


def sec_wrap(inner, stype, mac, seq):
    return bytes([(stype << 4) | 7]) + struct.pack('>I', mac) + bytes([seq]) + inner


def table_frames():
    """(proto, bytes) for everything the table selected"""
    sel = json.load(open(os.path.join(HERE, 'selected.json')))
    r = random.Random(7)
    fr = []
    n = 0
    for key, v in sel['bases'].items():
        for h, m in v:
            fr.append((key, bytes.fromhex(h) + bytes.fromhex(m)))
    for key, v in sel['opt'].items():
        code, name, iei = key.split('|')
        h = bytes.fromhex(sel['bases']['%s|%s' % (code, name)][0][0])
        for m in v:
            fr.append((key, h + bytes.fromhex(m)))
    for key, b in sel['combo'].items():
        h = bytes.fromhex(sel['bases'][key][0][0])
        fr.append((key, h + bytes.fromhex(b)))
    out = []
    for key, b in fr:
        n += 1
        pd = b[0] & 0x0f
        if n % 7 == 0:        # integrity protected, not ciphered (24.301 9.1)
            st = r.choice([1, 3])
            out.append(('nas-eps', sec_wrap(b, st, r.randrange(1, 1 << 32), r.randrange(256))))
        elif n % 11 == 0 and pd == 7:
            out.append(('nas-eps', bytes([0x07]) + b[1:]))   # security header type 0
        else:
            out.append(('nas-eps_plain', b))
    return out


# ---------------------------------------------------------------------------
# Hand built frames

def esm(code, body=b'', bid=5, pti=1):
    return hdr_esm(code, bid, pti) + body


def tai_list(kind, n, tac=0x0100):
    plmn = bytes.fromhex('130014')
    if kind == 0:
        return bytes([0x00 | (n - 1)]) + plmn + b''.join(struct.pack('>H', tac + 3 * i) for i in range(n))
    if kind == 1:
        return bytes([0x20 | (n - 1)]) + plmn + struct.pack('>H', tac)
    return bytes([0x40 | (n - 1)]) + b''.join(bytes.fromhex('13001' + str(i % 10)) + struct.pack('>H', tac + i) for i in range(n))


def attach_acc(tai, extra=b'', esmc=ACT_DEF, nib=0x02):
    return hdr_emm(0x42) + bytes([nib, 0x21]) + lv(tai) + lve(esmc) + extra


def ciph_set(sid, c0, tail_tai=b''):
    return (struct.pack('>H', sid) + bytes(range(16)) + bytes([len(c0)]) + c0 +
            bytes([0xff, 0xa5, 0x5a, 0x07]) + bytes.fromhex('2511071230') + b'\x00\x3c' + bytes([len(tail_tai)]) + tail_tai)


def qos(n, nonzero=True):
    """EPS QoS value part with n octets (1-13)"""
    base = [9, 0x40, 0x60, 0x10, 0x20, 0x30, 0x4b, 0x60, 0x70, 0x50, 0x20, 0x10, 0x20, 0x30, 0x40]
    z = [9, 0, 0, 0x20, 0x30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    return bytes((base if nonzero else z)[:n])


def ambr_ie(vals):
    return bytes(vals)


def remote_ctx(users, addr, upri4, tpri4i):
    c = bytes([len(users)])
    for t, d in users:
        c += bytes([len(d) + 1, 0x08 | t]) + d
    b = (0x10 if upri4 else 0) | (0x08 if tpri4i else 0)
    c = c[:0] + c
    c += bytes([b | addr[0]])
    c += addr[1]
    if upri4:
        c += struct.pack('>HH', 1000, 2000)
    if tpri4i:
        c += struct.pack('>HH', 3000, 4000)
    return bytes([len(c)]) + c


def hand_frames():
    """(proto, bytes) for the places the random table cannot reach"""
    f = []
    E = lambda b: f.append(('nas-eps_plain', b))
    P = lambda b: f.append(('nas-eps', b))
    # --- TAI lists of every type and size
    for kind, n in ((0, 1), (0, 5), (0, 16), (1, 1), (1, 8), (1, 16), (2, 1), (2, 3), (2, 16)):
        E(attach_acc(tai_list(kind, n)))
    E(attach_acc(tai_list(0, 2) + tai_list(1, 3) + tai_list(2, 2)))
    # --- ciphering key data (IE 7C): several sets, with and without C0 and TAI list
    ck = ciph_set(1, b'') + ciph_set(2, bytes(range(8)), tai_list(0, 2)) + ciph_set(3, b'\x01\x02', tai_list(2, 2))
    E(attach_acc(tai_list(0, 1), bytes([0x7c]) + lve(ck)))
    # --- QoS of every length, zero and non-zero rates
    apn = lv(bytes.fromhex('03616263') + bytes.fromhex('03636f6d'))
    pdn = lv(bytes.fromhex('01c0a80001'))
    for n in range(1, 14):
        for nz in (True, False):
            E(esm(0xc1, lv(qos(n, nz)) + apn + pdn))
    # --- APN-AMBR, extended APN-AMBR, extended QoS in several forms
    for vals in ([0x20, 0x30], [0, 0], [0x30, 0x40, 0, 0], [0x30, 0x40, 0x20, 0x30], [0x30, 0x40, 0x60, 0x7c],
                 [0x30, 0x40, 0x4b, 0x4b, 5, 6], [0x30, 0x40, 0x20, 0x20, 0, 0], [0x30, 0x40, 0x20, 0x20, 4, 5, 0, 0],
                 [0x30, 0x40, 0x20, 0x20, 0xff, 0x01, 0xff, 0x01, 0, 0][:8], [0x30, 0x40, 0x70, 0x70, 0, 0, 0, 0],
                 [0x30, 0x40, 0x20, 0x20, 4, 4, 5, 5], [0x30, 0x40, 0x4b, 0x4b, 4, 4, 5, 5][:8],
                 [0x30, 0x40, 0xf0, 0xf0], [0x30, 0x40, 0x4a, 0x4a, 3, 4], [0x30, 0x40, 0x60], [0x30, 0x40, 0x20, 0x20, 4],
                 [0x30, 0x40, 0x60, 0x60, 4, 4, 0], [0x30, 0x40, 0x60, 0x60, 4, 4, 6], [0x30, 0x40, 0x60, 0x60, 4]):
        E(esm(0xc1, lv(qos(1)) + apn + pdn + bytes([0x5e]) + lv(ambr_ie(vals))))
        E(esm(0xc9, bytes([0x5e]) + lv(ambr_ie(vals))))
    for unit_dl in (0, 1, 2, 3, 6, 7, 11, 12, 16, 17, 21, 22, 255):
        E(esm(0xc1, lv(qos(1)) + apn + pdn + bytes([0x5f]) + lv(bytes([unit_dl]) + struct.pack('>H', 100) +
                                                                  bytes([(unit_dl + 3) % 256]) + struct.pack('>H', 200))))
        E(esm(0xc9, bytes([0x5c]) + lv(bytes([unit_dl]) + struct.pack('>H', 100) + bytes([(unit_dl + 1) % 256]) +
                                    struct.pack('>H', 200) + bytes([unit_dl]) + struct.pack('>H', 3) +
                                    bytes([unit_dl]) + struct.pack('>H', 4))))
    for n in (1, 2, 3):
        E(attach_acc(tai_list(0, 1), bytes([0x64]) + lv(bytes([0x80, 0x40, 0x01][:n]))))
    # Serving PLMN rate control, NBIFOM container
    E(esm(0xc1, lv(qos(1)) + apn + pdn + bytes([0x6e]) + lv(struct.pack('>H', 100))))
    E(esm(0xc1, lv(qos(1)) + apn + pdn + bytes([0x33]) + lv(bytes.fromhex('010101'))))
    # --- messages without IEs, with and without trailing data; test procedures PD in a plain frame
    for code in EMM_EMPTY:
        E(hdr_emm(code))
        E(hdr_emm(code) + bytes([1, 2, 3]))
    E(bytes([0x0f, 0x80, 0x01, 0x00]))
    # --- long (8 octets or more) service requests take the full security header path
    for t in (12, 14):
        P(bytes([(t << 4) | 7, 0x45, 0xab, 0xcd, 0, 0, 0, 0]))
    # --- UE network capability and UE security capability of every length
    for n in range(2, 14):
        E(hdr_emm(0x41) + bytes([0x71]) + IMSI + lv(bytes([0xe0, 0xe0, 0xf0, 0xf0, 0xe0, 0xc0, 0xf0, 0x80, 0xa0, 0x01, 0x20, 0x40, 0x80][:n])) + lve(PDN_REQ))
    for n in (2, 4, 5):
        E(hdr_emm(0x5d) + bytes([0x02, 0x21]) + lv(bytes([0xf0, 0xe0, 0xc0, 0xa0, 0x80][:n])))
    # --- extended service request with trailing data
    E(hdr_emm(0x4c) + bytes([0x01]) + MTMSI + bytes([0x99, 0x99]))
    # --- PDN address types
    for t, a in ((1, bytes([10, 0, 0, 7])), (2, bytes(range(1, 9))), (3, bytes(range(1, 13))), (5, b'\0\0\0\1'), (6, b'\0\0\0\2'), (4, b'')):
        E(esm(0xc1, lv(qos(1)) + apn + lv(bytes([t]) + a)))
    # --- remote UE report: every user id type, address type and port flag
    ctxs = remote_ctx([(1, bytes(range(16))), (2, bytes.fromhex('214365870921f3')), (3, bytes.fromhex('2143658709')),
                       (4, bytes.fromhex('3143658709215f')), (5, bytes.fromhex('31436587092165f4'))], (1, bytes([10, 1, 2, 3]) + struct.pack('>H', 5000)), True, True)
    ctxs += remote_ctx([(2, bytes.fromhex('214365870921f3')), (6, b'\x01\x02')], (2, bytes(range(8))), False, True)
    ctxs += remote_ctx([], (0, b''), True, False)
    E(esm(0xe9, bytes([0x79]) + lve(bytes([3]) + ctxs)))
    E(esm(0xe9, bytes([0x7a]) + lve(bytes([3]) + ctxs) + bytes([0x6f]) + lv(bytes([1, 192, 0, 2, 1]))))
    E(esm(0xe9, bytes([0x6f]) + lv(bytes([2]) + bytes(range(16))) + bytes([0x79]) + lve(bytes([1]) + ctxs[:0] + remote_ctx([(2, bytes.fromhex('214365870921f3'))], (1, bytes([1, 2, 3, 4, 0, 80])), False, False))))
    E(esm(0xe9, bytes([0x6f]) + lv(bytes([3]))))
    # --- ESM data transport with user data containers
    ip4 = bytes.fromhex('4500002c00010000400b7ccdc0a80001c0a80002') + struct.pack('>HHHH', 4000, 5000, 12, 0) + b'abcd'
    ip6 = bytes.fromhex('60000000001b11400000000000000000000000000000000100000000000000000000000000000002') + struct.pack('>HHHH', 4000, 5000, 20, 0) + b'abcdefghijkl'
    eth = bytes.fromhex('0a0b0c0d0e0f010203040506') + b'\x08\x00' + ip4
    for ud in (ip4, ip6, eth, b'non-ip data', bytes([0x45, 1, 2]), bytes([0x60] + [0] * 10)):
        E(esm(0xeb, lve(ud) + bytes([0xf0 | 1])))
    E(esm(0xeb, lve(ip4)))
    # --- EMM transport (security header type 11): the data container types
    dc = [bytes([0x12]) + ip4, bytes([0x01, 0x09, 0x04]), bytes([0x01, 0x09, 0x10, 0x11]),
          bytes([0x06, 0x03, 0xaa, 0xbb, 0xcc, 0x01, 0x02, 0x03]), bytes([0x06, 0x00, 0x01, 0x02]),
          bytes([0x05, 0x01]), bytes([0x03, 0x00, 0x07, 0x08])]
    for d in dc:
        P(bytes([0xb7]) + struct.pack('>I', 0) + bytes([5]) + bytes([0x79]) + d)
        E(bytes([0xb7]) + struct.pack('>I', 0) + bytes([5]) + bytes([0x79]) + d)
    P(bytes([0xb7]) + struct.pack('>I', 0xdeadbeef) + bytes([6]) + bytes([0x79]) + dc[0])
    P(bytes([0xb7]) + struct.pack('>I', 0xdeadbeef) + bytes([6]))
    # --- service request (security header type 12-15), EMM and plain path
    for t in (12, 13, 15):
        P(bytes([(t << 4) | 7, 0x45, 0xab, 0xcd]))
        E(bytes([(t << 4) | 7, 0x65, 0x12, 0x34]))
    # --- generic NAS transport, NAS message container, additional information
    sms_ack = bytes.fromhex('0904')
    sms_err = bytes.fromhex('091011')
    lpp = bytes.fromhex('9001' '00')
    for typ, cont in ((1, bytes.fromhex('9000b70eee7f1a')), (1, bytes.fromhex('900139bef0')), (1, bytes.fromhex('9001544a8721a99a01')),
                      (1, bytes.fromhex('9000219eb59cf6a1')), (2, sms_ack), (3, b'xyz')):
        for code in (0x68, 0x69):
            E(hdr_emm(code) + bytes([typ]) + lve(cont))
            E(hdr_emm(code) + bytes([typ]) + lve(cont) + bytes([0x65]) + lv(bytes.fromhex('0b0c0d0e')))
    for code in (0x62, 0x63):
        for cont in (sms_ack, sms_err, bytes.fromhex('2900')):
            E(hdr_emm(code) + lv(cont))
    # type 5 header: "integrity protected and partially ciphered" -> inner message may be ciphered
    for st5 in (5,):
        for cont in (sms_ack, bytes.fromhex('aa55'), b'\x39'):
            P(bytes([(st5 << 4) | 7]) + struct.pack('>I', 0x11223344) + bytes([3]) + hdr_emm(0x62) + lv(cont))
        for esmc in (PDN_REQ, ESM_STATUS, bytes.fromhex('1201d011'), bytes.fromhex('5201d011'), bytes.fromhex('4501d011'), bytes.fromhex('0f0102')):
            P(bytes([(st5 << 4) | 7]) + struct.pack('>I', 0x11223344) + bytes([3]) + hdr_emm(0x42)[:0] + hdr_emm(0x41)
              + bytes([0x01]) + lv(IMSI[1:]) + lv(bytes([0xe0, 0xe0, 0x40])) + lve(esmc))
    # --- security mode complete with one replayed container (the fix allows one level)
    inner = hdr_emm(0x5e)
    E(hdr_emm(0x5e) + bytes([0x79]) + lve(inner))
    # --- ciphered messages (placeholder bytes only; mac 0 = not ciphered)
    plain_emm = hdr_emm(0x45) + bytes([0x01]) + IMSI
    for st in (2, 4):
        P(bytes([(st << 4) | 7]) + struct.pack('>I', 0) + bytes([9]) + plain_emm)
        P(bytes([(st << 4) | 7]) + struct.pack('>I', 0xcafebabe) + bytes([9]) + plain_emm)
        P(bytes([(st << 4) | 7]) + struct.pack('>I', 0xcafebabe) + bytes([9]) + esm(0xd0, bytes([0x11])))
        P(bytes([(st << 4) | 7]) + struct.pack('>I', 0xcafebabe) + bytes([9]) + bytes.fromhex('f0010203'))
        P(bytes([(st << 4) | 7]) + struct.pack('>I', 0xcafebabe) + bytes([9]) + bytes.fromhex('3a0102030405'))
        P(bytes([(st << 4) | 7]) + struct.pack('>I', 0xcafebabe) + bytes([9]))
    # --- test procedures protocol discriminator (15) and ESM in a protected message
    P(bytes([0x17]) + struct.pack('>I', 0x01020304) + bytes([2]) + bytes([0x0f, 0x80, 0x01, 0x00]))
    P(bytes([0x17]) + struct.pack('>I', 0x01020304) + bytes([2]) + esm(0xd0, bytes([0x11])))
    return f


def malformed_frames():
    f = []
    E = lambda b: f.append(('nas-eps_plain', b))
    P = lambda b: f.append(('nas-eps', b))
    # TAI list errors
    E(attach_acc(bytes([0x60]) + bytes.fromhex('130014') + b'\x00\x01'))             # unknown list type
    E(attach_acc(bytes([0x03]) + bytes.fromhex('130014') + b'\x00\x01'))             # too few TACs
    E(attach_acc(bytes([0x42]) + bytes.fromhex('130014') + b'\x00\x01'))             # too few TAIs
    E(attach_acc(bytes([0x00]) + bytes.fromhex('130014')))
    # unknown identity type, ciphered-looking containers with a type 5 header
    E(hdr_emm(0x41) + bytes([0x71]) + lv(bytes([0xf7, 0x01, 0x02])) + lv(b'\xe0\xe0') + lve(PDN_REQ))
    E(bytes([0x0a, 0x80, 0x01, 0x00]))
    P(bytes([0x57]) + struct.pack('>I', 0x11223344) + bytes([3]) + hdr_emm(0x62) + lv(bytes.fromhex('090105000a')))
    # unknown message types and protocol discriminators
    E(bytes([0x07, 0x7f]))
    E(bytes([0x52, 0x01, 0x7f]))
    P(bytes([0x17]) + struct.pack('>I', 0x01020304) + bytes([2]) + bytes([0x0a, 0x80, 0x01, 0x00]))
    # ESM not protected, wrong PD for a security header
    P(bytes([0x02]) + esm(0xd0, bytes([0x11]))[:0] + bytes.fromhex('0201d011') * 3)
    P(bytes([0x12]) + bytes.fromhex('00112233445566'))
    P(bytes([0x1a]) + bytes.fromhex('00112233445566'))
    # nested replayed containers: the reproducer of "NAS EPS: Bound Replayed NAS message container nesting"
    msg = hdr_emm(0x5e)
    for _ in range(3):
        msg = hdr_emm(0x5e) + bytes([0x79]) + lve(msg)
    E(msg)
    msg = hdr_emm(0x5e)
    for _ in range(13000):
        if len(msg) > 0xffff - 8:
            break
        msg = hdr_emm(0x5e) + bytes([0x79]) + lve(msg)
    P(msg)
    # type 5 header: ESM / NAS message containers that are cut short
    P(bytes([0x57]) + struct.pack('>I', 0x11223344) + bytes([3]) + hdr_emm(0x41) + bytes([0x01]) + lv(IMSI[1:]) + lv(b'\xe0\xe0') + lve(bytes.fromhex('0201')))
    P(bytes([0x57]) + struct.pack('>I', 0x11223344) + bytes([3]) + hdr_emm(0x62) + lv(bytes.fromhex('0901')))
    E(hdr_emm(0x5e) + bytes([0x79]) + lve(bytes.fromhex('075d' '00')))
    # truncated copies of the hand frames and of the table frames
    r = random.Random(11)
    src = [b for _, b in hand_frames()] + [b for _, b in table_frames()]
    for i, b in enumerate(src):
        if len(b) > 6 and i % 3 == 0:
            f.append(('nas-eps_plain', b[:r.randrange(3, len(b))]))
    return f


def crc32c(data):
    crc = 0xffffffff
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82f63b78 if crc & 1 else 0)
    return crc ^ 0xffffffff


def sctp_data(sport, dport, vtag, tsn, ppid, payload):
    chunk_len = 16 + len(payload)
    chunk = struct.pack('>BBHIHHI', 0, 3, chunk_len, tsn, 0, tsn, ppid) + payload + b'\0' * (-chunk_len % 4)
    pkt = struct.pack('>HHII', sport, dport, vtag, 0) + chunk
    return pkt[:8] + struct.pack('<I', crc32c(pkt)) + pkt[12:]


def eth_ip(proto, payload, ident=1):
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0, 64, proto, 0,
                     bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]))
    ck = 0
    for i in range(0, 20, 2):
        ck += (ip[i] << 8) | ip[i + 1]
    ck = ~((ck & 0xffff) + (ck >> 16)) & 0xffff
    ip = ip[:10] + struct.pack('>H', ck) + ip[12:]
    return bytes.fromhex('020000000002020000000001') + b'\x08\x00' + ip + payload


def s1ap_nas(proc, nas, uplink):
    ies = struct.pack('>HBB', 0, 0, 2) + struct.pack('>H', 1) + struct.pack('>HBB', 8, 0, 2) + struct.pack('>H', 1)
    ies += struct.pack('>HBBB', 26, 0, len(nas) + 1, len(nas)) + nas
    n = 3
    if uplink and proc == 13:
        ies += bytes.fromhex('0064400800' '130014' '00000010') + bytes.fromhex('00434006' '00' '130014' '0001')
        n = 5
    if proc == 12:
        ies = struct.pack('>HBB', 8, 0, 2) + struct.pack('>H', 1) + struct.pack('>HBBB', 26, 0, len(nas) + 1, len(nas)) + nas
        ies += bytes.fromhex('00434006' '00' '130014' '0001') + bytes.fromhex('0064400800' '130014' '00000010')
        ies += bytes.fromhex('00' '86' '40' '01' '00')[:0] + bytes.fromhex('0086400100')
        n = 5
    body = bytes([0]) + struct.pack('>H', n) + ies
    return bytes([0x00, proc, 0x40, len(body)]) + body


def s1ap_frames():
    f = []
    attach = hdr_emm(0x41) + bytes([0x71]) + IMSI + lv(bytes.fromhex('e0e0')) + lve(PDN_REQ)
    detach_ul = hdr_emm(0x45) + bytes([0x01]) + IMSI
    detach_dl = hdr_emm(0x45) + bytes([0x02])
    integ = lambda b, t=1: bytes([(t << 4) | 7]) + struct.pack('>I', 0x01020304) + bytes([7]) + b
    for i, (proc, nas, ul) in enumerate(((12, attach, True), (13, integ(detach_ul), True), (13, detach_ul, True),
                                         (11, detach_dl, False), (11, integ(detach_dl, 3), False),
                                         (13, integ(esm(0xd0, bytes([0x11]))), True), (11, integ(ACT_DEF[0:0] + esm(0xc1, lv(qos(5)) + lv(bytes.fromhex('03616263')) + lv(bytes.fromhex('01c0a80001')))), False))):
        f.append(eth_ip(132, sctp_data(40000 + i, 36412, 0x1234abcd, 100 + i, 18, s1ap_nas(proc, nas, ul)), i + 1))
    return f


def udp_heuristic_frames():
    nas = b'nas-eps' + hdr_emm(0x45) + bytes([0x01]) + IMSI
    p = struct.pack('>HHHH', 50000, 50001, 8 + len(nas), 0) + nas
    other = struct.pack('>HHHH', 50000, 50001, 8 + 3, 0) + b'nas'
    other2 = struct.pack('>HHHH', 50000, 50001, 8 + 12, 0) + b'nas-xx\x07\x45\x01\x02\x03\x04'
    return [eth_ip(17, p, 50), eth_ip(17, other, 51), eth_ip(17, other2, 52)]


def write_pcapng(name, frames_by_link):
    """frames_by_link: list of (linktype, [frame, ...]) -> one interface each"""
    def blk(t, body):
        body += b'\0' * (-len(body) % 4)
        return struct.pack('<II', t, len(body) + 12) + body + struct.pack('<I', len(body) + 12)
    out = blk(0x0a0d0d0a, struct.pack('<IHHq', 0x1a2b3c4d, 1, 0, -1))
    for lt, _ in frames_by_link:
        out += blk(1, struct.pack('<HHI', lt, 0, 262144))
    ts = 1700000000 * 1000000
    for i, (lt, frames) in enumerate(frames_by_link):
        for fr in frames:
            ts += 1000
            out += blk(6, struct.pack('<IIIII', i, ts >> 32, ts & 0xffffffff, len(fr), len(fr)) + fr)
    open(name, 'wb').write(out)


def write(outdir):
    os.makedirs(outdir, exist_ok=True)
    frames = [epdu(p, b) for p, b in table_frames() + hand_frames()]
    eth = s1ap_frames() + udp_heuristic_frames()
    write_pcapng(os.path.join(outdir, 'nas_eps-coverage.pcapng'), [(252, frames), (1, eth)])
    print(len(frames), 'Exported PDU frames,', len(eth), 'Ethernet frames')
    mal = [epdu(p, b) for p, b in malformed_frames()]
    write_pcap(os.path.join(outdir, 'nas_eps-coverage-malformed.pcap'), mal)
    print(len(mal), 'malformed-capture frames')


if __name__ == '__main__':
    if sys.argv[1] == 'select':
        select(sys.argv[2], sys.argv[3])
    else:
        write(sys.argv[1])
