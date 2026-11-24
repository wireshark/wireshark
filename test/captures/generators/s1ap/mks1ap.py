#!/usr/bin/env python3
# Generates test/captures/s1ap_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the S1AP coverage captures: python3 mks1ap.py <outdir>

Needs asn1tools (looked up in ASN1TOOLS_PATH, ./pylib or the shared pylib of
the batch) and the Wireshark tree (WS_TREE) for the ASN.1 files.  Random
values of every S1AP procedure are made with the generator of asnlib.py,
tshark (TSHARK) is run over the candidates and the frames that decode
without a malformed packet or error expert info go to the main capture, the
others to the malformed capture.  Hand built PDUs (below) cover the state
tracking and the container code."""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import random
import re
import struct
import subprocess

import asnlib
from capio import Cap, Sctp
from asnlib import Raw
from s5_pcaplib import initiating, container, ie as rawie, per_len
import nested
import salvage

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'
HERE = os.path.dirname(os.path.abspath(__file__))
TSHARK = os.environ.get('TSHARK', os.environ.get('TSHARK', 'tshark'))
NVAR = int(os.environ.get('NVAR', '9'))
MAIN_VAR = int(os.environ.get('MAIN_VAR', '4'))     # variants per procedure in the main capture; the rest go to the extra capture
PPID = 18
PORT = 36412


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
    n = r.choice([32, 32, 128, 160, 160, 24])
    if n == 32:
        return (bytes([10, 0, r.randint(0, 255), r.randint(1, 254)]), 32)
    if n == 128:
        return (bytes([0x20, 0x01, 0x0d, 0xb8]) + g.rbytes(12), 128)
    if n == 160:
        return (bytes([10, 1, r.randint(0, 255), r.randint(1, 254)]) + bytes([0x20, 0x01, 0x0d, 0xb8]) + g.rbytes(12), 160)
    return (g.rbytes(3), 24)


NAS = [bytes.fromhex(x) for x in ('0746', '07600f', '62 05 e8 2b'.replace(' ', ''))]
HO = ['intralte', 'eps-to-5gs', 'fivegs-to-eps', 'utrantolte', 'gerantolte', 'ltetoutran', 'ltetogeran']
POOL = {}


def pick(name):
    def h(g, t, depth):
        return g.r.choice(POOL[name])
    return h


def h_plmn_fix(g, t, depth):
    return g.fix_plmn if g.fix_plmn is not None else h_plmn(g, t, depth)


def h_tac(g, t, depth):
    return g.fix_tac if g.fix_tac is not None else g.rbytes(2)


def h_rat(g, t, depth):
    return g.fix_rat


def h_enbid(g, t, depth):
    return g.enb_id


def pick_nb(name):
    def h(g, t, depth):
        return g.r.choice(POOL[name + '-NB' if g.nb else name])
    return h


def h_nas(g, t, depth):
    return g.r.choice(NAS)


def h_ho(g, t, depth):
    return g.ho


def set_ctx(c):
    def h(g, t, depth):
        g.ctx = c
        return None
    return h


def h_rrc(g, t, depth):
    if g.ctx == 's2t':
        return g.r.choice(POOL['HandoverPreparationInformation-NB' if (g.nb and POOL['HandoverPreparationInformation-NB']) else 'HandoverPreparationInformation'])
    return g.r.choice(POOL['HandoverCommand'])


def h_s2t(g, t, depth):
    if g.ho in ('intralte', 'utrantolte', 'gerantolte', 'fivegs-to-eps'):
        g.ctx = 's2t'
        return Raw(g.enc('SourceeNB-ToTargeteNB-TransparentContainer'))
    if g.ho == 'eps-to-5gs':
        return g.r.choice(POOL['SourceNGRANNode-ToTargetNGRANNode-TransparentContainer'])
    return g.rbytes(8)


def h_t2s(g, t, depth):
    if g.ho in ('intralte', 'utrantolte', 'gerantolte', 'fivegs-to-eps'):
        g.ctx = 't2s'
        return Raw(g.enc('TargeteNB-ToSourceeNB-TransparentContainer'))
    if g.ho == 'eps-to-5gs':
        return g.r.choice(POOL['TargetNGRANNode-ToSourceNGRANNode-TransparentContainer'])
    return g.rbytes(8)


def h_dcs(g, t, depth):
    g.dcs = g.r.choice([0x00, 0x01, 0x48, 0x44, 0x10, 0x11, 0x40, 0xf0, 0xf4])
    return (bytes([g.dcs]), 8)


def h_wmc(g, t, depth):
    n = g.r.choice([1, 2, 3, 15, 16, 5])
    out = bytes([n])
    for i in range(min(n, 15)):
        ln = [82, 40, 20, 2, 0, 80][i % 6]
        if g.dcs in (0x48, 0x11):
            ln &= ~1
        out += g.rbytes(82) + bytes([ln])
    return out


def h_trace_id(g, t, depth):
    return h_plmn(g, t, depth) + g.rbytes(5)


def h_s1msg(g, t, depth):
    uepid = bytes([0x0A, 0xB0]) + bytes.fromhex('11223344')
    return initiating(10, container([rawie(43, uepid)]))


def h_cdma(g, t, depth):
    return g.r.choice([bytes.fromhex('0200'), bytes.fromhex('0240'), bytes.fromhex('0301'), bytes.fromhex('0300'), bytes.fromhex('0303')])


def h_lppa(g, t, depth):
    return g.r.choice(POOL['LPPA'])


HOOKS = {'PLMNidentity': h_plmn_fix, 'pLMNidentity': h_plmn_fix, 'TAC': h_tac, 'tAC': h_tac, 'RAT-Type': h_rat,
         'ENB-UE-S1AP-ID': h_enbid, 'eNB-UE-S1AP-ID': h_enbid, 'IMSI': h_imsi, 'iMSI': h_imsi,
         'TransportLayerAddress': h_tla, 'transportLayerAddress': h_tla, 'NAS-PDU': h_nas,
         'HandoverType': h_ho, 'SourceeNB-ToTargeteNB-TransparentContainer': set_ctx('s2t'),
         'TargeteNB-ToSourceeNB-TransparentContainer': set_ctx('t2s'), 'RRC-Container': h_rrc,
         'Source-ToTarget-TransparentContainer': h_s2t, 'Target-ToSource-TransparentContainer': h_t2s,
         'E-UTRAN-Trace-ID': h_trace_id, 'S1-Message': h_s1msg, 'Cdma2000PDU': h_cdma, 'DataCodingScheme': h_dcs, 'WarningMessageContents': h_wmc, 'LPPa-PDU': h_lppa,
         'UERadioCapability': pick_nb('UERadioAccessCapabilityInformation'),
         'UERadioCapabilityForPaging': pick_nb('UERadioPagingInformation'),
         'CELevel': pick_nb('UEPagingCoverageInformation'),
         'UE-RLF-Report-Container': pick('RLF-Report-r9'), 'uERLFReportContainer': pick('RLF-Report-r9'),
         'UE-RLF-Report-Container-for-extended-bands': pick('RLF-Report-v9e0'),
         'NB-IoT-RLF-Report-Container': pick('RLF-Report-NB-r16'),
         'UE-HistoryInformationFromTheUE': pick('VisitedCellInfoList-r12'),
         'sMTC': pick('MTC-SSB-NR-r15'), 'threshRS-Index-r15': pick('ThresholdListNR-r15'),
         'sSBToMeasure': pick('SSB-ToMeasure-r15'), 'sSRSSIMeasurement': pick('SS-RSSI-Measurement-r15'),
         'quantityConfigNR-R15': pick('QuantityConfigNR-r15'),
         'excludedCellsToAddModList': pick('CellsToAddModListNR-r15'),
         'LastVisitedUTRANCellInformation': pick('LastVisitedUTRANCell-Item'),
         'LastVisitedNGRANCellInformation': pick('LastVisitedNGRANCellInformation'),
         'MDT-ConfigurationNR': pick('MDT-Configuration'),
         'IntersystemSONConfigurationTransfer': pick('SONConfigurationTransfer'),
         'CoarseUELocation': pick('Ellipsoid-Point')}


def tx(c, sc, pdu, up=True):
    c.eth(sc.data(pdu, up=up, ppid=PPID))


def bad_frames(path):
    r = subprocess.run([TSHARK, '-r', path, '-Y', '_ws.malformed || _ws.expert.severity >= 0x00800000',
                        '-T', 'fields', '-e', 'frame.number'], capture_output=True, text=True,
                       env=dict(os.environ, WIRESHARK_CONFIG_DIR=os.path.join(HERE, 'cfg')))
    bad = set(int(x) for x in r.stdout.split())
    bad |= set(int(x) for x in re.findall(r'Dissector bug, protocol \w+, in packet (\d+)', r.stderr))
    return bad


def bad_frames2(path, *opts):
    return bad_frames(path, *opts)


def gen_all(g, procs, nvar, seed_off=0):
    out = []
    for p in procs:
        for which in ('init', 'succ', 'unsucc'):
            if not p[which]:
                continue
            for k in range(nvar):
                g.popt = [1.0, 0.0, 0.6, 0.3, 0.9, 0.5][k % 6]
                g.ho = HO[(k + seed_off) % len(HO)]
                try:
                    out.append(((p[which], k), bytes(g.pdu(p, which))))
                except RecursionError:
                    pass
    return out


def screen(cand, sc_factory, prefix=None):
    """Run the candidates through tshark (after the frames of prefix, which keep the conversation state);
    return (clean, bad)."""
    c = Cap()
    sc = sc_factory()
    for d in (prefix or []):
        tx(c, sc, d[1], up=True)
    for i, (_, d) in enumerate(cand):
        tx(c, sc, d, up=(i % 2 == 0))
    c.write(os.path.join(OUT, 'cand.pcapng'))
    bad = bad_frames(os.path.join(OUT, 'cand.pcapng'))
    os.remove(os.path.join(OUT, 'cand.pcapng'))
    k = len(prefix or [])
    clean = [x for i, x in enumerate(cand, 1) if (i + k) not in bad]
    badl = [x for i, x in enumerate(cand, 1) if (i + k) in bad]
    return clean, badl


def do_salvage(cod, procs, sets, badl, sc_factory, prefix=None, rounds=6):
    """Drop the IEs that make PDUs fail, a few rounds; returns (salvaged, still_bad)."""
    cur = list(badl)
    good = []
    for _ in range(rounds):
        if not cur:
            break
        c = Cap()
        sc = sc_factory()
        for d in (prefix or []):
            tx(c, sc, d[1], up=True)
        for i, (_, d) in enumerate(cur):
            tx(c, sc, d, up=(i % 2 == 0))
        path = os.path.join(OUT, 'salv.pcapng')
        c.write(path)
        vout = salvage.run(TSHARK, os.path.join(HERE, 'cfg'), path)
        os.remove(path)
        k = len(prefix or [])
        cul = salvage.culprits(vout, len(cur) + k)
        nxt = []
        for i, (n, d) in enumerate(cur, 1):
            names = cul.get(i + k, set())
            if not names:
                continue
            try:
                nd = salvage.drop_ies(cod, procs, sets, d, names)
            except Exception:
                nd = None
            if nd is not None:
                nxt.append((n, nd))
        # screen the modified PDUs
        if not nxt:
            break
        cl, bd = screen(nxt, sc_factory, prefix)
        good += cl
        cur = bd
    return good, cur


def reset(g):
    g.fix_plmn = g.fix_tac = g.fix_rat = g.enb_id = None
    g.nb = False


def main():
    os.makedirs(OUT, exist_ok=True)
    POOL.update(nested.load())
    # The committed capture carries two LPPa Error-indication PDUs that the pool of
    # nested.py no longer produces (the last procedure of the LPPa pool changed after
    # the capture was made); pin them.
    POOL['LPPA'][49] = bytes.fromhex('0001400a00000000000740020113')
    POOL['LPPA'][50] = bytes.fromhex('0001400a0000000000074002ef76')
    cod, sets, procs = asnlib.compile_spec('s1ap', 'per')
    g = asnlib.Gen(cod, random.Random(20261111), sets, procs, HOOKS)
    g.dcs = 0
    reset(g)
    # cohort A: random PDUs of every procedure
    candA = gen_all(g, procs, NVAR)
    cleanA, badA = screen(candA, lambda: Sctp(40000, PORT))
    # cohort B: an eNB with an NB-IoT tracking area; the S1 Setup Request has the RAT type nbiot for the TA
    # and the Initial UE Message of eNB-UE-S1AP-ID 0x123456 has the same TAI
    reset(g)
    g.nb = True
    g.fix_plmn, g.fix_tac, g.fix_rat, g.enb_id = bytes.fromhex('130014'), bytes.fromhex('0a0b'), 'nbiot', 0x123456
    byname = dict((p['init'], p) for p in procs if p['init'])
    g.popt = 1.0
    setup = bytes(g.pdu(byname['S1SetupRequest'], 'init'))
    g.popt = 0.3
    iue = bytes(g.pdu(byname['InitialUEMessage'], 'init'))
    prefB = [('S1SetupRequest', setup), ('InitialUEMessage', iue)]
    candB = gen_all(g, [p for p in procs if p['init'] not in ('S1SetupRequest', 'InitialUEMessage')], 3, 3)
    cleanB, badB = screen(candB, lambda: Sctp(40001, PORT), prefB)
    origA, origB = list(badA), list(badB)
    gA, badA = do_salvage(cod, procs, sets, badA, lambda: Sctp(40000, PORT))
    gB, badB = do_salvage(cod, procs, sets, badB, lambda: Sctp(40001, PORT), prefB)
    cleanA += gA
    cleanB += gB
    reset(g)
    print(len(candA), 'A candidates', len(badA), 'bad;', len(candB), 'B candidates', len(badB), 'bad')
    main_c, mal = Cap(), Cap()
    layout = []
    sc = Sctp(40000, PORT)
    extra = Cap()
    sce = Sctp(40004, PORT)
    mainA = [x for x in cleanA if x[0][1] < MAIN_VAR]
    for i, (_, d) in enumerate(mainA):
        tx(main_c, sc, d, up=(i % 2 == 0))
    for i, (_, d) in enumerate([x for x in cleanA if x[0][1] >= MAIN_VAR]):
        tx(extra, sce, d, up=(i % 2 == 0))
    layout.append(('random PDUs of every procedure (SCTP PPI 18)', len(main_c.fr)))
    n0 = len(main_c.fr)
    sc = Sctp(40001, PORT)
    for _, d in prefB:
        tx(main_c, sc, d, up=True)
    for i, (_, d) in enumerate(cleanB):
        tx(main_c, sc, d, up=(i % 2 == 0))
    layout.append(('NB-IoT eNB: S1 Setup, Initial UE Message, PDUs with the NB containers', len(main_c.fr) - n0))
    # reproducers of the fixes: Paging with the S-TMSI whose M-TMSI is 0x11223344 (the hidden 3gpp.tmsi item
    # must show the same value), S-TMSI with the iE-Extensions of extension id 300 (a 16-bit field now) and
    # S1-Message IEs (S1AP inside S1AP) a few levels deep, over SCTP and as Exported PDU
    n0 = len(main_c.fr)
    sc = Sctp(40002, PORT)
    uepid = bytes([0x0A, 0xB0]) + bytes.fromhex('11223344')
    paging = initiating(10, container([rawie(43, uepid)]))
    tx(main_c, sc, paging)
    # extension id 300 is ContextatSource: a valid value for the main capture, the one octet value of the
    # original reproducer (malformed inside) for the malformed capture
    g.popt = 0.3
    ctx_src = bytes(g.enc('ContextatSource'))
    uepid300 = bytes([0x1A, 0xB0]) + bytes.fromhex('11223344') + b'\x00\x00' + struct.pack('!H', 300) + b'\x40' + per_len(len(ctx_src)) + ctx_src
    uepid300_bad = bytes([0x1A, 0xB0]) + bytes.fromhex('11223344') + b'\x00\x00' + struct.pack('!H', 300) + b'\x40\x01\x00'
    tx(main_c, sc, initiating(10, container([rawie(43, uepid300)])), up=False)
    main_c.epdu('s1ap', paging)

    def nest(depth):
        p = paging
        for _ in range(depth):
            p = initiating(10, container([rawie(225, per_len(len(p)) + p)]))
        return p
    for dpt in (1, 2, 5):
        tx(main_c, sc, nest(dpt))
        main_c.epdu('s1ap', nest(dpt))
    layout.append(('reproducers: M-TMSI, extension id 300, nested S1-Message', len(main_c.fr) - n0))
    main_c.write(os.path.join(OUT, 's1ap-coverage.pcapng'))
    sc = Sctp(40000, PORT)
    for i, (_, d) in enumerate(origA + origB + badA + badB):
        tx(mal, sc, d, up=(i % 2 == 0))
    extra.write(os.path.join(OUT, 's1ap-coverage-extra.pcapng'))
    tx(mal, sc, initiating(10, container([rawie(43, uepid300_bad)])))
    mal.epdu('s1ap', nest(60))
    sc = Sctp(40003, PORT)
    tx(mal, sc, nest(60))
    mal.write(os.path.join(OUT, 's1ap-coverage-malformed.pcapng'))
    print(' / '.join('%s: %d' % x for x in layout))


main()
