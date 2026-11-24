#!/usr/bin/env python3
# Generates test/captures/ranap_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the RANAP coverage captures: python3 mkranap.py <outdir>

Needs asn1tools (pip install asn1tools, or ASN1TOOLS_PATH) and the
Wireshark tree (WS_TREE, default: the tree this script is in) for the ASN.1
files.  Candidates are made with a random value generator (asnlib.py)
over the RANAP ASN.1; tshark (TSHARK) is then run over them and the
frames that decode without malformed/error expert go to the main capture,
the others to the malformed capture."""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import random
import re
import struct
import subprocess

import asnlib

OUT = sys.argv[1] if len(sys.argv) > 1 else "."
TSHARK = os.environ.get('TSHARK', os.environ.get('TSHARK', 'tshark'))
HERE = os.path.dirname(os.path.abspath(__file__))
SSN = 142
OPC, DPC = 101, 102


# ---- transport: MTP3 (DLT 141) / SCCP ------------------------------------
def mtp3(dpc, opc, payload, sls=1):
    label = dpc | (opc << 14) | (sls << 28)
    return bytes([0x83]) + struct.pack('<I', label) + payload


def addr(ssn):
    return bytes([0x42, ssn])


def udt(data, ssn=SSN):
    called, calling = addr(ssn), addr(ssn)
    if len(data) <= 200:
        p1 = 3
        p2 = 3 + len(called)
        p3 = 3 + len(called) + len(calling)
        return bytes([0x09, 0x01, p1, p2, p3, len(called)]) + called + bytes([len(calling)]) + calling + bytes([len(data)]) + data
    # LUDT: 4 x 16 bit pointers
    hdr = bytes([0x13, 0x01, 15])
    # long pointers count from the second octet of the pointer
    p1 = 7
    p2 = 6 + len(called)
    p3 = 5 + len(called) + len(calling)
    return (hdr + struct.pack('<HHHH', p1, p2, p3, 0) + bytes([len(called)]) + called + bytes([len(calling)]) + calling
            + struct.pack('<H', len(data)) + data)


def lr(v):
    return struct.pack('>I', v)[1:]


def cr(slr, data, ssn=SSN):
    called = addr(ssn)
    opt = bytes([0x0f, len(data)]) + data + b'\x00'
    return bytes([0x01]) + lr(slr) + bytes([0x02, 0x02, 0x02 + len(called) - 1 + 1, len(called)]) + called + opt


def cc(dlr, slr, data):
    opt = bytes([0x0f, len(data)]) + data + b'\x00'
    return bytes([0x02]) + lr(dlr) + lr(slr) + bytes([0x02, 0x01]) + opt


def rlsd(dlr, slr):
    return bytes([0x04]) + lr(dlr) + lr(slr) + bytes([0x00, 0x00])


def rlc(dlr, slr):
    return bytes([0x05]) + lr(dlr) + lr(slr)


def dt1(dlr, data):
    return bytes([0x06]) + lr(dlr) + bytes([0x00, 0x01, len(data)]) + data


class Cap:
    def __init__(self):
        self.fr = []

    def add(self, sccp, dpc=DPC, opc=OPC):
        self.fr.append(mtp3(dpc, opc, sccp))

    def write(self, name):
        with open(os.path.join(OUT, name), 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 141))
            for i, p in enumerate(self.fr):
                f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
                f.write(p)


def bad_frames(path):
    r = subprocess.run([TSHARK, '-r', path, '-o', 'sccp.trace_sccp:TRUE', '-o', 'ranap.dissect_rrc_container:TRUE', '-Y', '_ws.malformed || _ws.expert.severity >= 0x00800000',
                        '-T', 'fields', '-e', 'frame.number'], capture_output=True, text=True,
                       env=dict(os.environ, WIRESHARK_CONFIG_DIR=os.path.join(HERE, 'cfg')))
    bad = set(int(x) for x in r.stdout.split())
    # "Dissector bug ... in packet N" warnings (assertions caught as exceptions) are not always in the tree
    bad |= set(int(x) for x in re.findall(r'Dissector bug, protocol \w+, in packet (\d+)', r.stderr))
    return bad


def digits(r, n):
    return [r.randint(0, 9) for _ in range(n)]


def h_plmn(g, t, depth):
    d = digits(g.r, 6)
    mnc3 = d[5] if g.r.random() < 0.5 else 0xf
    return bytes([d[1] << 4 | d[0], mnc3 << 4 | d[2], d[4] << 4 | d[3]])


def h_imsi(g, t, depth):
    n = g.r.randint(6, 15)
    d = digits(g.r, n) + ([0xf] if n % 2 else [])
    return bytes(d[i + 1] << 4 | d[i] for i in range(0, len(d), 2))


def h_tla(g, t, depth):
    r = g.r
    n = r.choice([32, 32, 128, 160, 160, 56, 24, 8])
    if n == 32:
        return (bytes([10, 0, r.randint(0, 255), r.randint(1, 254)]), 32)
    if n == 128:
        return (bytes([0x20, 0x01, 0x0d, 0xb8]) + g.rbytes(12), 128)
    if n == 160:
        return (bytes([0x35, 0x00, 0x01, 10, 1, r.randint(0, 255), r.randint(1, 254)]) + g.rbytes(13) if r.random() < 0.7
                else g.rbytes(20), 160)
    if n == 56:
        return (bytes([0x35, 0x00, 0x01, 10, 2, 3, 4]), 56)
    return (g.rbytes((n + 7) // 8), n)


def h_binding(g, t, depth):
    # a UDP port in the first two octets, zero in the last two (shown as a port)
    return struct.pack('>HH', g.r.randint(1024, 65535), 0) if g.r.random() < 0.7 else g.rbytes(4)


def h_nas(g, t, depth):
    return g.r.choice(NAS)


def h_bss_old(g, t, depth):
    # BSSMAP field elements: id, length, value
    el = [bytes([0x7e, 0x00]), bytes([0x7f, 0x01, 0x05]), bytes([0x7d, 0x02, 0x11, 0x22])]
    return b''.join(g.r.sample(el, g.r.randint(1, 3))) + b'\x00\x00'


def h_uehist(g, t, depth):
    # S1AP UE-HistoryInformation: one LastVisitedCell-Item, the UTRAN alternative (an OCTET STRING with
    # the PER encoding of a RANAP LastVisitedUTRANCell-Item); the E-UTRAN and GERAN alternatives are
    # not made here
    item = bytes(g.enc('LastVisitedUTRANCell-Item'))
    return bytes([0x02, len(item)]) + item


def h_rim(g, t, depth):
    # BSSGP: a STATUS PDU with a cause, or a reserved PDU type
    return g.r.choice([bytes.fromhex('41078108'), bytes.fromhex('4b0701')])


RRC = {}    # filled by main(): generator over the RRC ASN.1


def h_s2t(g, t, depth):
    # not an OCTET STRING: "the IE shall be encoded according to the type specifications of the target system"
    g.ctx = 's2t'
    return asnlib.Raw(g.enc('SourceRNC-ToTargetRNC-TransparentContainer'))


def h_t2s(g, t, depth):
    g.ctx = 't2s'
    return asnlib.Raw(g.enc('TargetRNC-ToSourceRNC-TransparentContainer'))


def h_rrc(g, t, depth):
    rg = RRC['g']
    if g.ctx == 's2t':
        return bytes(rg.enc('ToTargetRNC-Container'))
    # Target to Source: a TargetRNC-ToSourceRNC-Container (choice 0-6), now and then a HandoverToUTRANCommand
    # (first octet >= 0xe0)
    if g.r.random() < 0.1:
        return bytes([0xe0]) + g.rbytes(g.r.randint(0, 6))
    return bytes(rg.enc('TargetRNC-ToSourceRNC-Container'))


NAS = [bytes.fromhex(x) for x in ('080407', '0521', '0815', '0531e0')]
HOOKS = {'rIMInformation': h_rim, 'RIMInformation': h_rim, 'PLMNidentity': h_plmn, 'pLMNidentity': h_plmn,
         'IMSI': h_imsi, 'iMSI': h_imsi, 'TransportLayerAddress': h_tla, 'transportLayerAddress': h_tla,
         'BindingID': h_binding, 'NAS-PDU': h_nas, 'L3-Information': h_nas,
         'OldBSS-ToNewBSS-Information': h_bss_old, 'NewBSS-To-OldBSS-Information': h_bss_old,
         'Source-ToTarget-TransparentContainer': h_s2t, 'Target-ToSource-TransparentContainer': h_t2s,
         'rRC-Container': h_rrc, 'UE-History-Information': h_uehist}


def ranap_pdu_ext():
    # RANAP-PDU extension alternative (index 0 of the extension), open type of 1 octet
    return bytes([0x80, 0x01, 0x00])


def main():
    os.makedirs(OUT, exist_ok=True)
    cod, sets, procs = asnlib.compile_spec('ranap', 'per')
    g = asnlib.Gen(cod, random.Random(20261110), sets, procs, HOOKS)
    g.ctx = None
    g.rules = [(lambda t: type(t).__name__ == 'OctetString' and t.minimum == 3 and t.maximum == 3, h_plmn),
               (lambda t: type(t).__name__ == 'OctetString' and t.minimum == 3 and t.maximum == 8, h_imsi)]
    rcod, _, _ = asnlib.compile_spec('rrc', 'uper')
    rg = asnlib.Gen(rcod, random.Random(7))
    rg.popt, rg.padd = 0.25, 0.1
    rg.maxdepth = 16
    RRC['g'] = rg
    cand = []
    for p in procs:
        for which in ('init', 'succ', 'unsucc', 'outcome'):
            if not p[which]:
                continue
            for k in range(NVAR):
                g.popt = [0.0, 0.3, 0.6, 0.9, 1.0, 0.5][k % 6]
                try:
                    pdu = g.pdu(p, which)
                except RecursionError:
                    continue
                cand.append((p[which], bytes(pdu)))
    c = Cap()
    for _, d in cand:
        c.add(udt(d))
    c.write('cand.pcap')
    bad = bad_frames(os.path.join(OUT, 'cand.pcap'))
    os.remove(os.path.join(OUT, 'cand.pcap'))
    clean = [(n, d) for i, (n, d) in enumerate(cand, 1) if i not in bad]
    badl = [(n, d) for i, (n, d) in enumerate(cand, 1) if i in bad]

    def pick(name, k, skip=0):
        return [d for n, d in clean if n == name and len(d) < 200][skip:skip + k]

    main_c, mal = Cap(), Cap()
    layout = []
    # 1. every PDU as a connectionless message (SCCP UDT/LUDT to SSN 142)
    for _, d in clean:
        main_c.add(udt(d))
    layout.append(('UDT/LUDT, one frame per generated PDU', len(clean)))
    # 2. connection oriented sessions: CR (InitialUE-Message), CC, DT1 (CommonID with the IMSI, security mode,
    #    RAB assignment with GTP tunnels), Iu release, RLSD, RLC
    n0 = len(main_c.fr)
    for sess, (slr, dlr) in enumerate(((0x000101, 0x000201), (0x000102, 0x000202))):
        iu = pick('InitialUE-Message', 1, sess)
        main_c.add(cr(slr, iu[0] if iu else ranap_pdu_ext()), DPC, OPC)
        sm = pick('SecurityModeCommand', 1, sess)
        main_c.add(cc(slr, dlr, sm[0] if sm else ranap_pdu_ext()), OPC, DPC)
        for nm in ('CommonID', 'RAB-AssignmentRequest', 'RAB-AssignmentRequest', 'RAB-AssignmentResponse',
                   'RAB-AssignmentResponse', 'DirectTransfer', 'Iu-ReleaseCommand', 'Iu-ReleaseComplete'):
            skip = 0 if nm != 'RAB-AssignmentResponse' else sess
            pl = pick(nm, 1, skip + (1 if nm == 'RAB-AssignmentRequest' and False else 0))
            if not pl:
                continue
            down = nm in ('CommonID', 'RAB-AssignmentRequest', 'DirectTransfer', 'Iu-ReleaseCommand')
            main_c.add(dt1(slr if down else dlr, pl[0]) if not down else dt1(slr, pl[0]),
                       *( (OPC, DPC) if down else (DPC, OPC)))
        main_c.add(rlsd(slr, dlr), OPC, DPC)
        main_c.add(rlc(dlr, slr), DPC, OPC)
    layout.append(('two SCCP connections with RANAP', len(main_c.fr) - n0))
    # 3. RANAP found by the SCCP heuristic (called SSN 200, which has no dissector)
    n0 = len(main_c.fr)
    for _, d in clean[::25][:14]:
        main_c.add(udt(d, ssn=200))
    for _, d in [x for x in clean if 140 < len(x[1]) < 900][::9][:6]:     # long length determinant (two octets)
        main_c.add(udt(d, ssn=200))
    layout.append(('heuristic dissection (unregistered SSN)', len(main_c.fr) - n0))
    # 4. reproducer of "RANAP: Reset ProcedureCode for each PDU" (needs sccp.trace_sccp)
    n0 = len(main_c.fr)
    iu = (pick('InitialUE-Message', 1, 2) or pick('InitialUE-Message', 1) or [ranap_pdu_ext()])[0]
    main_c.add(cr(0x000301, iu), DPC, OPC)
    main_c.add(cc(0x000301, 0x000401, ranap_pdu_ext()), OPC, DPC)
    main_c.add(dt1(0x000401, ranap_pdu_ext()), DPC, OPC)
    layout.append(('stale procedure code reproducer', len(main_c.fr) - n0))
    main_c.write('ranap-coverage.pcap')
    # malformed capture: the generated PDUs that did not decode cleanly, truncated PDUs, unknown alternatives
    for _, d in badl:
        mal.add(udt(d))
    for i, (n, d) in enumerate(clean[::17]):
        cut = max(4, (len(d) * (1 + i % 7)) // 8)
        mal.add(udt(d[:cut]))
    for d in (ranap_pdu_ext(), bytes([0x00, 0xff, 0x40, 0x03, 0x00, 0x00, 0x00]), bytes([0x20, 0x00, 0x40, 0x00]),
              bytes([0x00, 0x00, 0x40, 0x04, 0x00, 0xff, 0xff, 0x00])):
        mal.add(udt(d))
    # PDUs that the heuristic refuses (called SSN 200): wrong PDU type octet, criticality, length, procedure code, IE count
    d0 = clean[0][1]
    for d in (bytes([0x01]) + d0[1:], bytes([d0[0], 0xc0]) + d0[2:], d0 + b'\x00', bytes([d0[0], 0x7f]) + d0[2:],
              bytes([0x80 | (len(d0) >> 8), len(d0) & 0xff]) + d0[1:],
              bytes([d0[0], d0[1], 0xc0]) + d0[3:], d0[:3] + bytes([0xff, 0xff]) + d0[5:]):
        mal.add(udt(d, ssn=200))
    mal.write('ranap-coverage-malformed.pcap')
    print(len(cand), 'candidates', len(bad), 'bad;', ' / '.join('%s: %d' % x for x in layout))


NVAR = int(os.environ.get('NVAR', '6'))
main()
