#!/usr/bin/env python3
# Helper module for the gprscdr capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""extract_schema.py <packet-gprscdr.c> <schema.json>

Reads the BER tables of the generated GPRSCDR dissector (the
ber_sequence_t / ber_choice_t arrays and the dissect_gprscdr_<Type>
functions that use them) and writes the type structure to JSON, so that
mkgprscdr.py can encode a value of every record type."""
import json
import re
import sys

src = open(sys.argv[1]).read()

tables = {}
for m in re.finditer(r'static const (ber_sequence_t|ber_choice_t) (\w+)\[\d*\] = \{\n(.*?)\n\};', src, re.S):
    kind, name, body = m.groups()
    ents = []
    for line in body.splitlines():
        line = line.strip()
        if line.startswith('{ NULL') or not line.startswith('{'):
            continue
        parts = [p.strip() for p in line.strip('{} ,').split(',')]
        if kind == 'ber_choice_t':
            val, hf, cls, tag, flags, fn = parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]
        else:
            hf, cls, tag, flags, fn = parts[0], parts[1], parts[2], parts[3], parts[4]
        if hf == 'NULL':
            continue
        ents.append({'cls': cls, 'tag': tag, 'flags': flags, 'fn': fn})
    tables[name] = ents

funcs = {}
for m in re.finditer(r'\n(?:static )?unsigned\ndissect_(\w+?)\(bool implicit_tag.*?\n\}\n', src, re.S):
    name, body = m.group(1), m.group(0)
    if not name.startswith('gprscdr_'):
        continue
    t = name[len('gprscdr_'):]
    c = re.search(r'dissect_ber_(\w+?)\((.*?)\);', body, re.S)
    info = {'body': body}
    if c:
        kind = c.group(1)
        args = re.sub(r'\s+', ' ', c.group(2))
        info['kind'] = kind
        info['args'] = args
    else:
        info['kind'] = None
    funcs[t] = info

out = {'tables': tables, 'types': {}}
for t, info in funcs.items():
    k = info['kind']
    e = {'kind': k}
    args = info.get('args', '')
    if k in ('sequence', 'set', 'sequence_of', 'set_of', 'choice'):
        m = re.search(r'(\w+_(?:sequence|set|sequence_of|set_of|choice))\b', args)
        e['table'] = m.group(1) if m else None
    elif k in ('constrained_octet_string', 'constrained_integer'):
        nums = re.findall(r'(\d+)U?, (\d+)U?, hf_index', args)
        e['range'] = [int(nums[0][0]), int(nums[0][1])] if nums else None
    elif k == 'restricted_string':
        e['tag'] = re.search(r'BER_UNI_TAG_(\w+)', args).group(1)
    elif k == 'constrained_restricted_string':
        e['tag'] = re.search(r'BER_UNI_TAG_(\w+)', args).group(1)
        nums = re.findall(r'(\d+), (\d+), hf_index', args)
        e['range'] = [int(nums[0][0]), int(nums[0][1])] if nums else None
    elif k == 'bitstring':
        m = re.search(r'(\w+_bits), (\d+),', args)
        e['nbits'] = int(m.group(2)) if m else 8
    else:
        # custom body: remember which helper it calls
        b = info['body']
        m = re.search(r'offset = (dissect_\w+)\(implicit_tag, tvb, offset, actx, tree, hf_index\);', b)
        if m and 'special' not in e:
            e['alias'] = m.group(1)
        for h in ('dissect_gprscdr_uli(tvb, actx, tree, 1)', 'dissect_gprscdr_uli(tvb, actx, tree, 2)'):
            if h in b:
                e['special'] = 'uli' + h[-2]
        e['helpers'] = sorted(set(re.findall(r'\b(dissect_(?:gtp|gtpv2|e212|gsm_a|de_)\w*)', b)))
    out['types'][t] = e
json.dump(out, open(sys.argv[2], 'w'), indent=1, sort_keys=True)
print(len(out['types']), 'types', len(tables), 'tables')
