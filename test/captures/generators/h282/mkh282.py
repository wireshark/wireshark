#!/usr/bin/env python3
# Generates test/captures/h282_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the H.282 (RDC) coverage captures.  Usage: mkh282.py <outdir> <workdir> [-v]

Run it on a machine with the Wireshark source tree (the .asn files of
H.282 and H.283 are parsed with the parser of
tools/dissector_generators/asn2wrs.py; <workdir> receives parsetab.py).
The aligned PER encodings come from asnper.py (a small PER encoder and
random value generator driven by that syntax tree).  Everything is built
with Python struct; nothing comes from a real network.

H.282 (Remote Device Control) PDUs have no transport of their own in
Wireshark: they are carried by the H.283 LCT protocol (rdcPDU octet
string; the device list of an LCT deviceListResp is the RDC
NonCollapsingCapabilities).  LCT has no registered port; the captures
use UDP port 6283 and are dissected with  -d udp.port==6283,lct
(cfg/decode_as_entries has the same entry).
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import random
import asnper
from _lib import Pcap

FILES = ['h283/LCT-PROTOCOL.asn', 'h282/RDC-PROTOCOL.asn']
A, B = '192.0.2.70', '192.0.2.80'
PORT = 6283

def find_alt(t, name):
    for a in list(t.elt_list) + list(getattr(t, 'ext_list', []) or []):
        if a.name == name:
            return a
    raise KeyError(name)

def main(out, workdir, verbose=False):
    types = asnper.load(FILES, workdir)
    sc = asnper.Schema(types)
    lct = [v for k, v in sc.by_mod.items() if k.endswith('LCT-PROTOCOL.asn')][0]
    rdc = [v for k, v in sc.by_mod.items() if k.endswith('RDC-PROTOCOL.asn')][0]
    rng = random.Random(282)
    covered = set()
    p = Pcap()
    marks = []
    def mark(n): marks.append((len(p.frames) + 1, n))
    lctpdu_t = lct['LCTPDU']
    rdcpdu_t = rdc['RDCPDU']
    ncc_t = rdc['NonCollapsingCapabilities']
    top = {'request': rdc['RequestPDU'], 'response': rdc['ResponsePDU'], 'indication': rdc['IndicationPDU']}
    seqno = [0]

    def lct_wrap(rdc_bytes=None, devlist=None):
        seqno[0] += 1
        if devlist is not None:
            dt = ('lctMessage', ('lctResponse', ('deviceListResp', devlist)))
        else:
            dt = ('rdcPDU', rdc_bytes)
        v = {'srcAddr': {'mAddress': 1, 'tAddress': 2}, 'dstAddr': {'mAddress': 3, 'tAddress': 4},
             'timestamp': 100000 + seqno[0] * 20, 'seqNumber': seqno[0],
             'pduType': ('rdcData', {'reliable': True, 'dataType': dt})}
        return sc.encode(lctpdu_t, v).bytes()

    def newgen(p_ext, p_opt):
        g = asnper.Gen(sc, rng, covered)
        g.p_ext = p_ext; g.p_opt = p_opt
        return g

    recorded = []
    port = [4000]
    def send(d, rev=False):
        port[0] += 1
        recorded.append(d)
        if rev: p.udp(B, A, PORT, port[0], d)
        else: p.udp(A, B, port[0], PORT, d)

    mark('RDC PDUs: random instances of every request, response and indication (kept when they add coverage)')
    for kind, ct in top.items():
        for alt in [a.name for a in list(ct.elt_list) + list(ct.ext_list)]:
            kept = 0
            for attempt in range(2500):
                if kept >= 40:
                    break
                g = newgen(rng.choice((0.3, 0.6, 0.9)), rng.choice((0.4, 0.7, 0.9)))
                depth = rng.choice((5, 6, 7, 8))
                a = find_alt(ct, alt)
                g.mark((ct.name, alt))
                inner = (alt, g.gen(a, depth, ct.name))
                if not g.new and kept > 0:
                    continue
                covered.update(g.new)
                d = sc.encode(rdcpdu_t, (kind, inner)).bytes()
                send(lct_wrap(d), rev=(kind != 'request'))
                kept += 1
    mark('Capability attributes that need deep, fully populated responses (preset, pan/tilt position, lens, slides)')
    targets = {'PanPositionCapability', 'TiltPositionCapability', 'CameraLensCapability', 'MaxNumberOfSlides',
               'MinIrisPositionStepSize', 'DevicePresetCapability', 'T_presetCapability', 'T_accessoryTextLabel',
               'T_lightTextLabel', 'CameraFilterCapability'}
    rt = top['response']
    for attempt in range(6000):
        if not targets:
            break
        g = newgen(0.9, 0.97)
        a = find_alt(rt, 'deviceAttributeResponse')
        g.mark((rt.name, 'deviceAttributeResponse'))
        inner = ('deviceAttributeResponse', g.gen(a, 12, rt.name))
        hit = {t for (k, t) in g.new if k == 'visit' and t in targets}
        if not hit:
            continue
        targets -= hit
        covered.update(g.new)
        send(lct_wrap(sc.encode(rdcpdu_t, ('response', inner)).bytes()), rev=True)
    mark('Capabilities with non-empty text label lists (presets, lens, light)')
    def two(g, t, depth):
        return [g.gen(t.val, depth - 1, 'two') for _ in range(2)]
    def has(v, key):
        if isinstance(v, dict):
            return (key in v and bool(v[key])) or any(has(x, key) for x in v.values())
        if isinstance(v, (list, tuple)):
            return any(has(x, key) for x in v)
        return False
    need = {'presetCapability', 'accessoryTextLabel', 'lightTextLabel'}
    for attempt in range(8000):
        if not need:
            break
        g = newgen(0.9, 0.97)
        g.overrides = {'/presetCapability': two, '/accessoryTextLabel': two, '/lightTextLabel': two}
        a = find_alt(rt, 'deviceAttributeResponse')
        inner = ('deviceAttributeResponse', g.gen(a, 12, rt.name))
        hit = {k for k in need if has(inner, k)}
        if not hit:
            continue
        need -= hit
        send(lct_wrap(sc.encode(rdcpdu_t, ('response', inner)).bytes()), rev=True)
    mark('Device lists (NonCollapsingCapabilities: deviceList and streamList) in an LCT deviceListResp')
    kept = 0
    for attempt in range(1500):
        if kept >= 40:
            break
        g = newgen(0.5, 0.8)
        v = g.gen(ncc_t, 5, '')
        if not g.new and kept > 3:
            continue
        covered.update(g.new)
        send(lct_wrap(devlist=sc.encode(ncc_t, v).bytes() or b'\x00'), rev=True)
        kept += 1
    mark('Unknown extension alternatives of RequestPDU, ResponsePDU, IndicationPDU')
    for k, (ci, nroot) in {'request': (0, 9), 'response': (1, 8), 'indication': (2, 4)}.items():
        w = asnper.PW()
        w.cint(ci, 0, 2)                  # RDCPDU choice (no extension marker)
        w.flag(1); w.small(0)             # extension alternative 0 of the inner CHOICE
        w.length(2); w.raw(b'\x00\x01')
        send(lct_wrap(w.bytes()))
    p.write(os.path.join(out, 'h282-coverage.pcap'))

    mq = Pcap(); mq.ts = 1700100000.0
    step = max(1, len(recorded) // 60)
    for i, d in enumerate(recorded[::step]):
        cut = 1 + (i * 7) % max(1, len(d) - 1)
        mq.udp(A, B, 5000 + i, PORT, d[:cut])
    mq.udp(A, B, 5100, PORT, b'')
    mq.udp(A, B, 5101, PORT, bytes([0xff] * 64))
    mq.write(os.path.join(out, 'h282-coverage-malformed.pcap'))
    if verbose:
        for (n, s), nx in zip(marks, marks[1:] + [(len(p.frames) + 1, '')]):
            print('%d-%d %s' % (n, nx[0] - 1, s))
    print(len(p.frames), 'frames,', len(mq.frames), 'malformed')

if __name__ == '__main__':
    import tempfile
    args = [a for a in sys.argv[1:] if a != '-v']
    with tempfile.TemporaryDirectory() as work:
        main(args[0] if args else '.', args[1] if len(args) > 1 else work, '-v' in sys.argv)
