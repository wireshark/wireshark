# Helper module for the gtp capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
import os
SRCDIR = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..', '..'))
import re
SRC = open(os.path.join(SRCDIR, 'epan/dissectors/packet-gtp.c')).read()
DEF = {}
H = open(os.path.join(SRCDIR, 'epan/dissectors/packet-gtp.h')).read()
for m in re.finditer(r'^#define\s+(GTP\w+)\s+(0x[0-9a-fA-F]+|\d+)\b', SRC + H, re.M):
    DEF[m.group(1)] = int(m.group(2), 0)
def table(name):
    i = SRC.index('static const _gtp_mess_items %s[]' % name)
    j = SRC.index('\n};', i)
    body = SRC[i:j]
    msgs = []
    for m in re.finditer(r'\{\s*(GTP_MSG_\w+),\s*\{(.*?)\n\s*\}\n\s*\}', body, re.S):
        fields = re.findall(r'\{\s*(GTP\w*_EXT_\w+|GTPv1_EXT_\w+|0),\s*(\w+),\s*(\w+)\s*\}', m.group(2))
        msgs.append((m.group(1), [(f, p, a) for f, p, a in fields if f != '0']))
    return msgs
if __name__ == '__main__':
    for n in ('gprs_mess_items', 'umts_mess_items'):
        t = table(n)
        print(n, len(t))
        miss = set()
        for mn, fl in t:
            if mn not in DEF: miss.add(mn)
            for f, p in fl:
                if f not in DEF: miss.add(f)
        print(miss)
