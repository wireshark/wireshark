#!/usr/bin/env python3
# Developer tool: rebuilds the MAPI tables of mkmapi.py from the MAPI dissector
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""extract_spec.py: read the generated MAPI dissector (packet-dcerpc-mapi.c/.h)
and write mapi_spec.json, a description of what every generated struct,
union, element, enum and bitmap function reads.  mkmapi.py builds the ROP
and AUX payloads from it, so the payloads follow what the dissector
actually parses (for example a switch on a plain integer field always takes
level 0, and conformant arrays inside ROP buffers use the count of the
last NDR conformant run, not the count field before them).

Usage: extract_spec.py [path to packet-dcerpc-mapi.c] > mapi_spec.json"""
import os
SRCDIR = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..', '..'))
import json
import re
import sys

C = sys.argv[1] if len(sys.argv) > 1 else os.path.join(SRCDIR, 'epan/dissectors/packet-dcerpc-mapi.c')
src = open(C).read()
hdr = open(C[:-2] + '.h').read() + open(C.replace('mapi.c', 'nspi.h')).read()

consts = {}
for m in re.finditer(r'#define (\w+) \((-?0x[0-9a-fA-F]+|-?\d+)\)', hdr):
    consts[m.group(1)] = int(m.group(2), 0)

funcs = {}
for m in re.finditer(r'^(?:static )?(?:unsigned|int)\s*\n?(\w+)\(([^)]*)\)\n\{\n(.*?)\n\}$', src, re.S | re.M):
    funcs[m.group(1)] = (m.group(2), m.group(3))

def lead_align(body):
    head = body.split('offset =')[0]
    m = re.search(r'ALIGN_TO_(\d)_BYTES', head)
    return int(m.group(1)) if m else 0


def tail_align(body):
    m = re.search(r'DCERPC_IS_NDR64\) \{\s*ALIGN_TO_(\d)_BYTES;\s*\}\s*return offset;\s*$', body)
    return int(m.group(1)) if m else 0


spec = {'align': {}, 'consts': consts, 'enums': {}, 'bitmaps': {}, 'structs': {}, 'unions': {}, 'elems': {}}
SZ = {'uint1632': 1632, 'uint8': 8, 'uint16': 16, 'uint32': 32, 'uint64': 64, 'uint3264': 32}


def stmts(body):
    return [l.strip() for l in body.split('\n') if l.strip()]


for name, (args, body) in funcs.items():
    if lead_align(body) or tail_align(body):
        spec['align'][name] = [lead_align(body), tail_align(body)]
    if name.startswith('mapi_dissect_enum_'):
        m = re.search(r'dissect_ndr_(uint\d+)\(', body)
        spec['enums'][name] = SZ[m.group(1)]
    elif name.startswith('mapi_dissect_bitmap_'):
        m = re.search(r'dissect_ndr_(uint\d+)\(', body)
        k = re.search(r'flags & \(~(0x[0-9a-fA-F]+)\)', body)
        spec['bitmaps'][name] = [SZ[m.group(1)], int(k.group(1), 16) if k else 0]
    elif name.startswith('mapi_dissect_struct_'):
        vars_ = re.findall(r'^\s*(?:uint\d+_t|int\d+_t) (\w+) = 0;', body, re.M)
        elems = []
        for m in re.finditer(r'offset = (mapi_dissect_element_\w+)\(tvb, offset, pinfo, tree, di, drep(?:, &(\w+))?\);', body):
            elems.append([m.group(1), m.group(2)])
        spec['structs'][name] = {'vars': vars_, 'elems': elems}
    elif name.startswith('mapi_dissect_element_'):
        pm = re.search(r'uint8_t \*drep _U_, (?:uint\d+_t|int\d+_t) \*(\w+)', args)
        ptr = pm.group(1) if pm else None
        ss = stmts(body)
        e = {'ptr': ptr}
        b = body
        m = re.search(r'for \(i = 0; i < (0x[0-9a-fA-F]+|\d+); i\+\+\)\s*\{?\s*offset = (mapi_dissect_element_\w+)\(', b, re.S)
        if m:
            e.update(kind='fixarr', n=int(m.group(1), 0), elem=m.group(2))
        elif 'dissect_ndr_cvstring' in b:
            m = re.search(r'sizeof\((uint\d+)_t\)', b)
            e.update(kind='cvstring', width=SZ[m.group(1)] // 8)
        elif 'dissect_ndr_vstring' in b:
            e.update(kind='vstring')
        elif 'normalize_version' in b:
            e.update(kind='normver')
        else:
            m = re.search(r'offset = (\w+)\((.*)\);', b)
            if not m:
                e.update(kind='other')
            else:
                fn, a = m.group(1), [x.strip() for x in m.group(2).split(',')]
                last = a[-1]
                if fn.startswith('PIDL_dissect_uint'):
                    e.update(kind='u' + fn[len('PIDL_dissect_uint'):].replace('_val', ''))
                elif fn in ('dissect_ndr_uint8', 'dissect_ndr_uint16', 'dissect_ndr_uint32', 'dissect_ndr_uint64'):
                    e.update(kind='u' + fn[len('dissect_ndr_uint'):])
                elif fn == 'dissect_ndr_duint32':
                    e.update(kind='u64')
                elif fn == 'dissect_ndr_uuid_t':
                    e.update(kind='uuid')
                elif fn == 'PIDL_dissect_policy_hnd':
                    e.update(kind='policy')
                elif fn == 'dissect_null_term_string':
                    e.update(kind='str')
                elif fn == 'dissect_null_term_wstring':
                    e.update(kind='wstr')
                elif fn == 'dissect_ndr_datablob':
                    e.update(kind='blob_rem' if last == '1' else 'blob_len')
                elif fn.startswith('mapi_dissect_struct_'):
                    e.update(kind='struct', target=fn)
                elif fn.startswith('mapi_dissect_enum_'):
                    e.update(kind='enum', target=fn, store=(ptr is not None and last == ptr))
                elif fn.startswith('mapi_dissect_bitmap_'):
                    e.update(kind='bitmap', target=fn)
                elif fn == 'dissect_ndr_ucarray':
                    e.update(kind='ucarray', elem=last)
                elif fn == 'dissect_ndr_ucvarray':
                    e.update(kind='ucvarray', elem=last)
                elif fn == 'dissect_ndr_embedded_pointer':
                    e.update(kind='embptr', elem=a[6])
                elif fn == 'dissect_ndr_toplevel_pointer':
                    e.update(kind='topptr', elem=a[6])
                elif fn.startswith('mapi_dissect_element_'):
                    e.update(kind='alias', elem=fn)
                elif fn.startswith('mapi_dissect_'):
                    lev = last
                    if ptr and lev == '*' + ptr:
                        lev = {'var': ptr}
                    else:
                        try:
                            lev = {'const': int(lev, 0)}
                        except ValueError:
                            lev = {'expr': lev}
                    e.update(kind='union', target=fn, level=lev)
                else:
                    e.update(kind='call', fn=fn)
        spec['elems'][name] = e
    elif name.startswith('mapi_dissect_') and 'switch(level)' in body:
        enc = re.search(r'offset = dissect_ndr_(uint\d+)\(tvb, offset, pinfo, tree, di, drep, hf_index, &level\);', body)
        cases = []
        for m in re.finditer(r'(case (\w+):|default:)\s*\n(\s*offset = (mapi_dissect_element_\w+)\(|\s*break;)', body):
            if m.group(2) is None:
                v = None
            else:
                v = m.group(2)
                v = consts[v] if v in consts else int(v, 0)
            cases.append([v, m.group(4)])
        spec['unions'][name] = {'cases': cases, 'encap': SZ[enc.group(1)] if enc else None,
                                'align8': enc is not None and 'ALIGN_TO_8_BYTES' in body}

json.dump(spec, sys.stdout, indent=0, sort_keys=True)
