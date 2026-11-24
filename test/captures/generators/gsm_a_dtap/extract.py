# Helper module for the gsm_a_dtap capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
import re
from gen_tables import fcn_array, functions, SRC, strip_comments, vs_values
src = open(SRC + 'packet-gsm_a_dtap.c').read()
fns = functions(src)
# also handle VV_SHORT
def functions2(src):
    out = {}
    for m in re.finditer(r'\n(?:static )?void\s*\n?(\w+)\s*\(tvbuff_t \*tvb[^)]*unsigned len\)\s*\{', src):
        name = m.group(1)
        end = src.find('\n}\n', m.end())
        body = strip_comments(src[m.end():end])
        elems = []
        for e in re.finditer(r'(ELEM_[A-Z_]+)\(([^,]+),', body):
            tok = e.group(2).strip()
            try: iei = int(tok, 0)
            except ValueError: iei = None
            elems.append((e.group(1), iei))
        out[name] = elems
    return out
fns = functions2(src)
tab = {}
for pd, strs, arr in [(0, 'gsm_a_dtap_msg_gcc_strings', 'dtap_msg_gcc'),
                      (1, 'gsm_a_dtap_msg_bcc_strings', 'dtap_msg_bcc'),
                      (3, 'gsm_a_dtap_msg_cc_strings', 'dtap_msg_cc_fcn'),
                      (5, 'gsm_a_dtap_msg_mm_strings', 'dtap_msg_mm_fcn'),
                      (9, 'gsm_a_dtap_msg_sms_strings', 'dtap_msg_sms_fcn'),
                      (11, 'gsm_a_dtap_msg_ss_strings', 'dtap_msg_ss_fcn'),
                      (15, 'gsm_a_dtap_msg_tp_strings', 'dtap_msg_tp_fcn')]:
    names = fcn_array(src, arr)
    vals = vs_values(src, strs)
    for v, n in zip(vals, names):
        tab[(pd, v)] = fns.get(n, []) if n != 'NULL' else None
print("TABLE = {")
for k in sorted(tab):
    print("    %r: %r," % (k, tab[k]))
print("}")
