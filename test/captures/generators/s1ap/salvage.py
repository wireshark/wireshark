# Helper module for the s1ap capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Remove the top-level IEs that make a generated PDU fail to decode, so that the rest of the PDU can go to
the main capture.  A PDU that tshark reports as malformed (or with an error expert info) is decoded again
by asn1tools, the IE that contains the error is found in the -V output ("Item N: id-X" at the top-level
protocolIEs list) and dropped; this is repeated a few rounds."""
import os
import re
import subprocess

ALT = {'initiatingMessage': 'init', 'successfulOutcome': 'succ', 'unsuccessfulOutcome': 'unsucc'}


def culprits(vout, nframes):
    """frame number -> set of top-level IE names that contain an error"""
    res = {}
    frames = re.split(r'\nFrame (\d+):', '\n' + vout)
    # frames: ['', '1', text, '2', text ...]
    for k in range(1, len(frames) - 1, 2):
        n = int(frames[k])
        lines = frames[k + 1].split('\n')
        bad = set()
        for i, l in enumerate(lines):
            if ('Malformed Packet (Exception' in l or 'Expert Info (Error' in l or 'Dissector bug' in l) and not l.lstrip().startswith('['):
                pass
            if 'Expert Info (Error' in l or 'Malformed Packet (Exception' in l or '[Malformed Packet' in l:
                # walk back to the enclosing top-level item
                best = None
                for j in range(i, -1, -1):
                    m = re.match(r'^(\s+)Item \d+: (id-[\w-]+)', lines[j])
                    if m:
                        ind = len(m.group(1))
                        if best is None or ind < best[0]:
                            best = (ind, m.group(2))
                    if re.match(r'^\s+protocolIEs: \d+ items?', lines[j]):
                        break
                if best:
                    bad.add(best[1])
        res[n] = bad
    return res


def drop_ies(cod, procs, sets, pdu, names):
    alt, g = cod.types['PDU'].decode(pdu)
    p = [x for x in procs if x['code'] == g['procedureCode']]
    tn = None
    for x in p:
        if x[ALT[alt]]:
            tn = x[ALT[alt]]
    if tn is None:
        return None
    inner = cod.types[tn].decode(g['value'])
    key = [k for k in inner if k.startswith('protocolIEs')]
    if not key:
        return None
    lst = inner[key[0]]
    idmap = {}
    for ents in sets.values():
        for e in ents:
            idmap[e['idname']] = e['id']
    drop = set(idmap.get(n) for n in names)
    new = []
    for item in lst:
        idk = [k for k in item if k.startswith('id-')][0]
        if item[idk] not in drop:
            new.append(item)
    if len(new) == len(lst):
        return None
    inner[key[0]] = new
    g['value'] = cod.types[tn].encode(inner) or b'\x00'
    return bytes(cod.types['PDU'].encode((alt, g)))


def run(tshark, cfg, path, extra=()):
    r = subprocess.run([tshark, '-r', path, '-V', *extra], capture_output=True, text=True, errors='replace',
                       env=dict(os.environ, WIRESHARK_CONFIG_DIR=cfg))
    return r.stdout
