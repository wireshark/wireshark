#!/usr/bin/env python3
# Generates test/captures/rrc_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the RRC (UMTS, 3GPP TS 25.331) coverage captures:
python3 mkrrc.py <outdir>

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


# exported PDU dissector names (rrc.cnf #.PDU) for every PDU type
def rrc_pdu_names():
    out = {}
    on = False
    for l in open(TREE + '/epan/dissectors/asn1/rrc/rrc.cnf'):
        if l.startswith('#.PDU'):
            on = True
            continue
        if on and l.startswith('#.'):
            break
        m = re.match(r'(\S+)\s+@(\S+)', l)
        if on and m:
            out[m.group(1)] = 'rrc.' + m.group(2)
    return out


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


# ---- hooks: valid contents for the octet/bit strings that RRC passes on to other dissectors -------------
NAS = [bytes.fromhex(x) for x in ('080407', '0521', '0815', '0531e0')]
SIBMAP = {}     # SIB-Type value -> ASN.1 type name, filled in main()
CTX = {}


def h_nas(g, t, depth):
    return g.r.choice(NAS)


def h_sibtype(g, t, depth):
    v = g.gen(t, depth, nohook=True)
    CTX['sib'] = v
    return v


def h_sibdata(g, t, depth):
    # SIB-Data-variable: a complete SIB is dissected according to the previous SIB-Type
    tn = SIBMAP.get(CTX.get('sib'))
    if tn and tn in g.c.types and g.r.random() < 0.8:
        rg = RRC['small']
        for _ in range(8):
            try:
                b = bytes(rg.enc(tn))
            except RecursionError:
                continue
            if len(b) * 8 <= 214:
                return (b, len(b) * 8)
    return None


RRC = {}


def h_rat_info(g, t, depth):
    if type(t).__name__ != 'OctetString':
        return None
    return bytes(RRC['small'].enc('InterRATHandoverInfo'))


def h_uecap(g, t, depth):
    return bytes(RRC['small'].enc('UE-RadioAccessCapabilityInfo'))


def h_dldcch(g, t, depth):
    if type(t).__name__ != 'OctetString':
        return None
    return bytes(RRC['small'].enc('DL-DCCH-Message'))


def sib_member_type(name):
    # System-Information-Container members: octet strings that hold an encoded SIB
    if name == 'mib':
        return 'MasterInformationBlock'
    m = re.match(r'sysInfoType(\w+?)$', name)
    if m:
        return 'SysInfoType' + m.group(1)
    m = re.match(r'sysInfoTypeSB(\d)$', name)
    return 'SysInfoTypeSB' + m.group(1) if m else None


def h_sibmember(g, t, depth):
    tn = sib_member_type(t.name)
    if tn and tn in g.c.types and type(t).__name__ == 'OctetString':
        return bytes(RRC['small'].enc(tn))
    return None


def h_sysinfo2(g, t, depth):
    return g.rbytes(2)      # LAC, or T3212 + ATT, or RAC + NMO: always two octets


HOOKS = {'NAS-SystemInformationGSM-MAP': h_sysinfo2, 'NAS-Message': h_nas, 'SIB-Type': h_sibtype, 'SIB-Data-variable': h_sibdata,
         'interRATHandoverInfo': h_rat_info, 'dL-DCCHmessage': h_dldcch}


def main():
    os.makedirs(OUT, exist_ok=True)
    cod, _, _ = asnlib.compile_spec('rrc', 'uper')
    g = asnlib.Gen(cod, random.Random(SEED), hooks=HOOKS)
    g.maxdepth = 30
    g.rules = [(lambda t: type(t).__name__ == 'OctetString' and sib_member_type(t.name), h_sibmember)]
    small = asnlib.Gen(cod, random.Random(SEED + 1), hooks=HOOKS)
    small.popt, small.padd, small.maxdepth = 0.2, 0.0, 14
    RRC['small'] = small
    sibt = cod.types['SIB-Type'].type
    for i, nm in sibt.root_index_to_data.items():
        m = re.match(r'systemInformationBlockType(\w+)$', nm)
        if m:
            SIBMAP[nm] = 'SysInfoType' + m.group(1)
        elif nm == 'masterInformationBlock':
            SIBMAP[nm] = 'MasterInformationBlock'
        elif nm.startswith('schedulingBlock'):
            SIBMAP[nm] = 'SysInfoTypeSB' + nm[-1]
    names = rrc_pdu_names()
    subs = gsmtap_subs()
    cand = []          # (type name, via, payload bytes)
    for tn, dn in names.items():
        if tn not in cod.types:
            continue
        for k in range(NVAR):
            g.popt = [0.15, 0.4, 0.7, 0.3, 0.9, 0.55][k % 6]
            g.padd = [0.0, 0.2, 0.5][k % 3]
            try:
                v = g.enc(tn)
            except RecursionError:
                continue
            cand.append((tn, dn, bytes(v), k))
    # GSMTAP sub types by ASN.1 type name
    sub_of = {}
    for i, nm in enumerate(subs):
        sub_of[nm.replace('_', '-')] = i
    sub_of['SystemInformation-BCH'] = sub_of.get('SystemInformation-BCH', sub_of.get('SystemInformation-BCH'))

    def frame(c, tn, dn, p, k):
        if tn in sub_of and k % 2 == 0:
            c.eth(ip_udp(gsmtap(sub_of[tn], p)))
        else:
            c.exp(dn, p)

    # every message alternative of the channel PDUs, a few times each
    for tn, dn in names.items():
        if tn not in cod.types or not tn.endswith('-Message') or tn.startswith('BCCH'):
            continue
        top = cod.types[tn].type
        mm = [m for m in top.root_members if m.name == 'message']
        if not mm:
            continue
        ch = mm[0]
        while type(ch).__name__ == 'Recursive':
            ch = ch._inner
        if type(ch).__name__ != 'Choice':
            continue
        cname = getattr(mm[0], 'type_name', None) or 'message'
        for alt in list(ch.root_index_to_member.values()) + list((ch.additions_index_to_member or {}).values()):
            for k in range(NALT):
                g.forced = {cname: alt.name}
                g.popt = [0.3, 0.8, 0.5, 1.0][k % 4]
                g.padd = [0.0, 0.3][k % 2]
                try:
                    v = g.enc(tn)
                except RecursionError:
                    continue
                cand.append((tn, dn, bytes(v), k))
    g.forced = {}
    c = Cap()
    for tn, dn, p, k in cand:
        frame(c, tn, dn, p, k)
    c.write('cand.pcapng')
    bad = tshark_bad(os.path.join(OUT, 'cand.pcapng'))
    os.remove(os.path.join(OUT, 'cand.pcapng'))
    main_c, mal = Cap(), Cap()
    layout = []
    for i, (tn, dn, p, k) in enumerate(cand, 1):
        frame(mal if i in bad else main_c, tn, dn, p, k)
    layout.append(('random PDUs of every type (GSMTAP / Exported PDU)', len(cand) - len(bad)))
    # reproducer of "RRC: Keep the HS-DSCH channel count per PDU": the same DL-DCCH message twice over GSMTAP
    rep = bytes.fromhex('08d98a48a564e26a2749299ef25d4ff00c32dc342ec1107a693263a84095ad2e'
                        '2f21772a3e21330bf52237090a24768da91a3190acfe40c5919aa1da4b9f8ffa'
                        '14a4dc641c293ece1a7703fed04b0b0acbf87b477b58b4419fde389dd798632e'
                        '57c6208f39616d3c9275ebbe37987a87d4aeb72f52cfa976')
    for _ in range(2):
        main_c.eth(ip_udp(gsmtap(0, rep)))
    layout.append(('HS-DSCH channel count reproducer', 2))
    main_c.write('rrc-coverage.pcapng')
    # malformed capture: the PDUs that did not decode, truncated PDUs
    for i, (tn, dn, p, k) in enumerate(cand):
        if i % 9 == 0 and len(p) > 3:
            mal.exp(dn, p[:max(1, len(p) * (1 + i % 5) // 6)])
    mal.write('rrc-coverage-malformed.pcapng')
    print(len(cand), 'candidates', len(bad), 'bad;', ' / '.join('%s: %d' % x for x in layout))


main()
