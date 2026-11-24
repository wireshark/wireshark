# Helper module for the xnap capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
import re
def handoffs(cnf):
    keys = []
    txt = open(cnf).read()
    for m in re.finditer(r'^#\.FN_BODY\s+(\S+)([^\n]*)\n(.*?)(?=^#\.)', txt, re.M | re.S):
        name, hdr, body = m.groups()
        if 'VAL_PTR' not in hdr:
            continue
        if re.search(r'dissect_\w+_PDU\s*\(|dissector_try|call_dissector|dissect_\w+_PDU', body):
            if name == 'X2AP-Message':
                continue
            keys.append(name)
    out = []
    for k in keys:
        if '/' in k:
            parts = k.split('/')
            out.append('*/' + parts[-1] if '_item' in parts else '/'.join(parts[-2:]))
        else:
            out.append(k)
    return out
if __name__ == '__main__':
    import sys
    for k in handoffs(sys.argv[1]): print(k)
