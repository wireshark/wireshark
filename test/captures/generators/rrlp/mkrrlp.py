#!/usr/bin/env python3
# Generates test/captures/rrlp_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the RRLP (3GPP TS 44.031) coverage captures:
python3 mkrrlp.py <outdir>

Needs asn1tools (pip install asn1tools, or ASN1TOOLS_PATH) and the Wireshark tree (WS_TREE, default: the tree
this script is in) for the ASN.1 files, and tshark (TSHARK) to sort the generated PDUs into the
main capture (decode cleanly) and the malformed capture (do not).  Random values of every RRC PDU type
are made by the generator in asnlib.py and encoded as unaligned PER."""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import random
import re
import struct
import subprocess

import asnlib

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'
TSHARK = os.environ.get('TSHARK', os.environ.get('TSHARK', 'tshark'))
HERE = os.path.dirname(os.path.abspath(__file__))
TREE = asnlib.TREE
NALT = int(os.environ.get('NALT', '4'))
NVAR = int(os.environ.get('NVAR', '12'))
SEED = int(os.environ.get('SEED', '20261110'))


def tlv(t, v):
    v = v + b'\0' * (-len(v) % 4)
    return struct.pack('>HH', t, len(v)) + v


def epdu(name, payload):
    return tlv(12, name.encode()) + tlv(0, b'') + payload


def csum(b):
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def ip_udp(payload, sport=40000, dport=4729, src=(192, 0, 2, 1), dst=(192, 0, 2, 2)):
    udp = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    hdr = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0, bytes(src), bytes(dst))
    hdr = hdr[:10] + struct.pack('>H', csum(hdr)) + hdr[12:]
    return b'\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x08\x00' + hdr + udp


def gsmtap(sub, payload, typ=0x0c):
    return struct.pack('>BBBBHbbIBBBB', 2, 4, typ, 0, 0, 0, 0, 0, sub, 0, 0, 0) + payload


def gsmtap_subs():
    names = []
    for l in open(TREE + '/epan/dissectors/packet-gsmtap.h'):
        m = re.match(r'\s*GSMTAP_RRC_SUB_(\w+?)(?: = \d+)?,?\s*$', l)
        if m and m.group(1) != 'MAX':
            names.append(m.group(1))
    return names


class Cap:
    def __init__(self):
        self.fr = []        # (interface, bytes)

    def eth(self, b):
        self.fr.append((0, b))

    def exp(self, name, payload):
        self.fr.append((1, epdu(name, payload)))

    def write(self, name):
        def blk(t, body):
            body += b'\0' * (-len(body) % 4)
            return struct.pack('<II', t, len(body) + 12) + body + struct.pack('<I', len(body) + 12)
        o = blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
        o += blk(1, struct.pack('<HHI', 1, 0, 262144))
        o += blk(1, struct.pack('<HHI', 252, 0, 262144))
        for i, (itf, fr) in enumerate(self.fr):
            ts = (1700000000 + i) * 1000000
            o += blk(6, struct.pack('<IIIII', itf, ts >> 32, ts & 0xffffffff, len(fr), len(fr)) + fr)
        open(os.path.join(OUT, name), 'wb').write(o)


def tshark_bad(path, opts=()):
    r = subprocess.run([TSHARK, '-r', path, *opts, '-Y', '_ws.malformed || _ws.expert.severity >= 0x00800000',
                        '-T', 'fields', '-e', 'frame.number'], capture_output=True, text=True,
                       env=dict(os.environ, WIRESHARK_CONFIG_DIR=os.path.join(HERE, 'cfg')))
    bad = set(int(x) for x in r.stdout.split())
    # "Dissector bug ... in packet N" warnings (assertions caught as exceptions) are not always in the tree
    bad |= set(int(x) for x in re.findall(r'Dissector bug, protocol \w+, in packet (\d+)', r.stderr))
    return bad


def h_gad(g, t, depth):
    # Ext-GeographicalInformation: a shape description (3GPP TS 23.032): type nibble, then the coordinates
    r = g.r
    typ, ln = r.choice([(0x00, 7), (0x10, 8), (0x30, 11), (0x50, 8), (0x80, 9), (0x90, 14), (0xa0, 13), (0x50, 11), (0x50, 14)])
    b = bytearray(g.rbytes(ln))
    b[0] = typ | (r.randint(1, 3) if typ == 0x50 else 0)
    if typ == 0x50:
        b = b
    return bytes(b)


HOOKS = {'Ext-GeographicalInformation': h_gad}


def main():
    os.makedirs(OUT, exist_ok=True)
    cod, _, _ = asnlib.compile_spec('rrlp', 'uper')
    g = asnlib.Gen(cod, random.Random(SEED), hooks=HOOKS)
    g.maxdepth = 30
    cand = []
    # every component alternative a number of times, with different densities of optional members
    comp = cod.types['PDU'].type
    comps = [m for m in comp.root_members if m.name == 'component'][0]
    alts = list(comps.root_index_to_member.values()) + list((comps.additions_index_to_member or {}).values())
    for alt in alts:
        for k in range(NVAR):
            g.forced = {'RRLP-Component': alt.name}
            g.popt = [0.15, 0.4, 0.7, 0.3, 0.9, 0.55, 1.0, 0.25][k % 8]
            g.padd = [0.0, 0.3, 0.0, 0.6][k % 4]
            try:
                cand.append((alt.name, bytes(g.enc('PDU'))))
            except RecursionError:
                pass
    c = Cap()
    for nm, p in cand:
        c.exp('rrlp', p)
    c.write('cand.pcapng')
    bad = tshark_bad(os.path.join(OUT, 'cand.pcapng'))
    os.remove(os.path.join(OUT, 'cand.pcapng'))
    main_c, mal = Cap(), Cap()
    for i, (nm, p) in enumerate(cand, 1):
        (mal if i in bad else main_c).exp('rrlp', p)
    # the same PDUs over GSMTAP are not dissected as RRLP: RRLP is only reached through Exported PDU or BSSAP/BSSLAP/ULP
    main_c.write('rrlp-coverage.pcapng')
    for i, (nm, p) in enumerate(cand):
        if i % 5 == 0 and len(p) > 2:
            mal.exp('rrlp', p[:max(1, len(p) * (1 + i % 4) // 5)])
    mal.write('rrlp-coverage-malformed.pcapng')
    print(len(cand), 'candidates', len(bad), 'bad;', len(alts), 'component alternatives')


NVAR = int(os.environ.get('NVAR', '80'))
main()
