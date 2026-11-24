# Helper module for the xnap capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
import os
SRCDIR = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..', '..'))
import sys
import asngen
import cnfscan
PREFIX = 'XnAP'; PPID = 61; PORT = 38422
HANDOFF = cnfscan.handoffs(os.path.join(SRCDIR, 'epan/dissectors/asn1/xnap/xnap.cnf'))
# containers whose decoder depends on the node types learnt from Xn Setup
STATE_KEYS = ['UEContextInfoHORequest/rrc-Context', 'UEContextInfoRetrUECtxtResp/rrc-Context', 'Target2SourceNG-RANnodeTranspContainer',
              'MN-to-SN-Container', 'Configuration-successfully-applied/m-NG-RANNode-to-S-NG-RANNode-Container']
SCENARIOS = ['gnb', 'ngenb']       # node type of both ends (learnt from the Xn Setup frames)
SKIP = []

def plmn(g):
    r = g.rng
    d = [r.randint(0, 9) for _ in range(5)]
    m3 = r.choice([r.randint(0, 9), 15])
    return bytes([d[1] << 4 | d[0], m3 << 4 | r.randint(0, 9), d[3] << 4 | d[2]])

def bits(g, n):
    nb = (n + 7) // 8
    data = bytes(g.rng.choice(g.alpha) for _ in range(nb))
    if n % 8:
        data = data[:-1] + bytes([data[-1] & (0xff << (8 - n % 8)) & 0xff])
    return (data, n)

def tla(g):
    # IPv4 (32), IPv6 (128), both (160) and lengths that are none of them
    return bits(g, g.rng.choice([32, 32, 128, 128, 160, 160, 24, 72, 1, 8 * 5 + 3]))

def enc(v):
    if isinstance(v, tuple):
        return ['b', v[0].hex(), v[1]]
    return ['o', v.hex()]

def dec(x):
    return (bytes.fromhex(x[1]), x[2]) if x[0] == 'b' else bytes.fromhex(x[1])

def make_gen(spec, rng, **kw):
    g = asngen.Gen(spec, rng, **kw)
    g.handoff = HANDOFF
    g.deep = 40
    g.override['PLMN-Identity'] = plmn
    g.override['TransportLayerAddress'] = tla
    return g

def prelude(spec, scen, g_factory):
    """Xn Setup request (A->B) and response (B->A) announcing the node type of each end"""
    mode = 'gNB' if scen == 'gnb' else 'ng-eNB'
    out = []
    for i, (msg, kind) in enumerate((('XnSetupRequest', 0), ('XnSetupResponse', 1))):
        g = g_factory(__import__('random').Random('prelude%s%d' % (scen, i)))
        sub = 'GlobalgNB-ID' if mode == 'gNB' else 'GlobalngeNB-ID'
        g.override['GlobalNG-RANNode-ID'] = (lambda g, mode=mode, sub=sub: (mode, g.gen_named(sub)))
        proc = [p for p in spec.procs if p[1] == 'XnSetupRequest'][0]
        out.append((i == 1, kind, proc[4], proc[5], g.gen_encode(msg)))
    return out
