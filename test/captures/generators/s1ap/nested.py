# Helper module for the s1ap capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Pools of valid encodings of the protocols that S1AP carries (LTE RRC, RANAP,
NGAP, LPP, LPPa), made with the random value generator of asnlib.py.  The pools
are cached in s1ap-nested.pkl in the temporary directory (the ASN.1
compiles take a few minutes)."""
import os
import pickle
import random
import sys

import tempfile

import asnlib

HERE = os.path.dirname(os.path.abspath(__file__))
CACHE = os.path.join(tempfile.gettempdir(), 's1ap-nested.pkl')

LTE = ['HandoverPreparationInformation', 'HandoverCommand', 'UERadioAccessCapabilityInformation',
       'UERadioPagingInformation', 'UEPagingCoverageInformation', 'RLF-Report-r9', 'RLF-Report-v9e0',
       'VisitedCellInfoList-r12', 'MTC-SSB-NR-r15', 'ThresholdListNR-r15', 'SSB-ToMeasure-r15',
       'SS-RSSI-Measurement-r15', 'QuantityConfigNR-r15', 'CellsToAddModListNR-r15',
       'HandoverPreparationInformation-NB', 'UEPagingCoverageInformation-NB',
       'UERadioAccessCapabilityInformation-NB', 'UERadioPagingInformation-NB', 'RLF-Report-NB-r16']
NGAP = ['LastVisitedNGRANCellInformation', 'MDT-Configuration', 'SONConfigurationTransfer',
        'SourceNGRANNode-ToTargetNGRANNode-TransparentContainer',
        'TargetNGRANNode-ToSourceNGRANNode-TransparentContainer']
RANAP = ['LastVisitedUTRANCell-Item']
LPP = ['Ellipsoid-Point']


def _fill(pool, spec, codec, names, n, seed, popt=0.4, maxdepth=14, hooks=None, forced=None):
    import time
    print('compile', spec, file=sys.stderr, flush=True)
    cod, sets, procs = asnlib.compile_spec(spec, codec)
    print('compiled', spec, file=sys.stderr, flush=True)
    g = asnlib.Gen(cod, random.Random(seed), sets, procs, hooks)
    g.popt, g.padd, g.maxdepth = popt, 0.1, maxdepth
    for nm in names:
        out = []
        tries = 0
        g.forced = dict(forced.get(nm, {}) if forced else {})
        g.forced['criticalExtensions'] = 'c1'
        t0 = time.time()
        while len(out) < n and tries < n * 6 and time.time() - t0 < 20:
            tries += 1
            try:
                b = bytes(g.enc(nm))
            except Exception:
                continue
            if 0 < len(b) < 1200:
                out.append(b)
        pool[nm] = out
        print(nm, len(out), tries, round(time.time() - t0, 1), file=sys.stderr, flush=True)
    return g, procs


def load():
    if os.path.exists(CACHE):
        return pickle.load(open(CACHE, 'rb'))
    pool = {}
    lte_hooks = {'ueCapabilityRAT-Container': lambda g, t, d: b'',
                 'handoverCommandMessage': lambda g, t, d: bytes(g.enc('DL-DCCH-Message')),
                 'ue-RadioAccessCapabilityInfo': lambda g, t, d: (bytes(g.enc('UECapabilityInformation'))
                                                                  if asnlib.K(t, 'OctetString') else None),
                 'ue-RadioAccessCapabilityInfo-r13': lambda g, t, d: bytes(g.enc('UE-Capability-NB-r13')),
                 'ue-RadioPagingInfo-r12': lambda g, t, d: bytes(g.enc('UE-RadioPagingInfo-r12')),
                 'ue-RadioPagingInfo-r13': lambda g, t, d: bytes(g.enc('UE-RadioPagingInfo-NB-r13'))}
    lte_forced = {'HandoverPreparationInformation': {'c1': 'handoverPreparationInformation-r8'},
                  'HandoverCommand': {'c1': 'handoverCommand-r8'},
                  'UERadioAccessCapabilityInformation': {'c1': 'ueRadioAccessCapabilityInformation-r8'},
                  'UERadioPagingInformation': {'c1': 'ueRadioPagingInformation-r12'},
                  'HandoverPreparationInformation-NB': {'c1': 'handoverPreparationInformation-r13'},
                  'UERadioAccessCapabilityInformation-NB': {'c1': 'ueRadioAccessCapabilityInformation-r13'},
                  'UERadioPagingInformation-NB': {'c1': 'ueRadioPagingInformation-r13'}}
    _fill(pool, 'lte-rrc', 'uper', LTE, 10, 11, popt=0.25, maxdepth=34, hooks=lte_hooks, forced=lte_forced)
    _fill(pool, 'ranap', 'per', RANAP, 10, 12)
    _fill(pool, 'ngap', 'per', NGAP, 10, 13, maxdepth=12)
    _fill(pool, 'lpp', 'uper', LPP, 10, 14)
    g, procs = _fill(pool, 'lppa', 'per', [], 0, 15)
    lppa = []
    for p in procs:
        for w in ('init', 'succ', 'unsucc'):
            if p[w]:
                for k in range(3):
                    g.popt = [0.0, 0.5, 1.0][k]
                    try:
                        lppa.append(bytes(g.pdu(p, w)))
                    except Exception:
                        pass
    pool['LPPA'] = lppa
    pickle.dump(pool, open(CACHE, 'wb'))
    return pool


if __name__ == '__main__':
    p = load()
    for k, v in p.items():
        print(k, len(v), [len(x) for x in v][:6])
