# Helper module for the gsm_a_common capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
import re
from gen_tables import SRC, strip_comments, enum_values, fcn_array, vs_values
hdr = open(SRC + 'packet-gsm_a_common.h').read()
BE = enum_values(hdr, 'BE_NONE')


def functions2(src):
    out = {}
    for m in re.finditer(r'\n(?:static )?void\s*\n?(\w+)\s*\(tvbuff_t \*tvb[^)]*unsigned len\)\s*\{', src):
        name = m.group(1)
        end = src.find('\n}\n', m.end())
        body = strip_comments(src[m.end():end])
        elems = []
        for e in re.finditer(r'(ELEM_[A-Z_]+)\(([^,]+),', body):
            tok = e.group(2).strip()
            try:
                iei = int(tok, 0)
            except ValueError:
                iei = BE.get(tok)
            elems.append((e.group(1), iei))
        out[name] = elems
    return out


tab = {}
for fn, specs in [('packet-gsm_a_dtap.c', [(0, 'gsm_a_dtap_msg_gcc_strings', 'dtap_msg_gcc'), (1, 'gsm_a_dtap_msg_bcc_strings', 'dtap_msg_bcc'),
                                            (3, 'gsm_a_dtap_msg_cc_strings', 'dtap_msg_cc_fcn'), (5, 'gsm_a_dtap_msg_mm_strings', 'dtap_msg_mm_fcn'),
                                            (9, 'gsm_a_dtap_msg_sms_strings', 'dtap_msg_sms_fcn'), (11, 'gsm_a_dtap_msg_ss_strings', 'dtap_msg_ss_fcn'),
                                            (15, 'gsm_a_dtap_msg_tp_strings', 'dtap_msg_tp_fcn')]),
                  ('packet-gsm_a_rr.c', [(6, 'gsm_a_dtap_msg_rr_strings', 'dtap_msg_rr_fcn')]),
                  ('packet-gsm_a_gm.c', [(8, 'gsm_a_dtap_msg_gmm_strings', 'dtap_msg_gmm_fcn'), (10, 'gsm_a_dtap_msg_sm_strings', 'dtap_msg_sm_fcn')]),
                  ('packet-gsm_a_bssmap.c', [(100, 'gsm_a_bssmap_msg_strings', 'bssmap_msg_fcn')])]:
    src = open(SRC + fn).read()
    fns = functions2(src)
    for pd, strs, arr in specs:
        names = fcn_array(src, arr)
        vals = vs_values(src, strs)
        for v, n in zip(vals, names):
            tab[(pd, v)] = fns.get(n, []) if n != 'NULL' else None
print("TABLE = {")
for k in sorted(tab):
    print("    %r: %r," % (k, tab[k]))
print("}")
print("BE = {")
for k in ('BE_LOC_EST', 'BE_VEL_EST', 'BE_CELL_ID', 'BE_CM_INFO_3', 'BE_CM_INFO_2', 'BE_IMSI', 'BE_L3_INFO'):
    if k in BE:
        print("    %r: %r," % (k, BE[k]))
print("}")
