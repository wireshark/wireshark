#!/usr/bin/env python3
# Generates test/captures/h283_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the H.283 (LCT) coverage captures.  Usage: mkh283.py <outdir> <workdir> [-v]

Run it on a machine with the Wireshark source tree (the .asn files of
H.283 and H.282 are parsed with the parser of
tools/dissector_generators/asn2wrs.py; <workdir> receives parsetab.py).
The aligned PER encodings come from asnper.py (a small PER encoder and
random value generator driven by that syntax tree).  Everything is built
with Python struct; nothing comes from a real network.

The LCT protocol (Logical Channel Transport for H.224 / H.281 / H.282
remote device control) has no registered port: the captures use UDP port
6283 and are dissected with  -d udp.port==6283,lct.  LCT PDUs carry
H.282 RDC PDUs (octet string rdcPDU) and the RDC device list
(deviceListResp).
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

def main(out, workdir, verbose=False):
    types = asnper.load(FILES, workdir)
    sc = asnper.Schema(types)
    mods = {k: v for k, v in sc.by_mod.items()}
    lct = [v for k, v in mods.items() if k.endswith('LCT-PROTOCOL.asn')][0]
    rdc = [v for k, v in mods.items() if k.endswith('RDC-PROTOCOL.asn')][0]
    rng = random.Random(283)
    covered = set()
    rcovered = set()
    p = Pcap()
    marks = []
    def mark(n): marks.append((len(p.frames) + 1, n))
    lctpdu_t = lct['LCTPDU']
    rdcpdu_t = rdc['RDCPDU']
    ncc_t = rdc['NonCollapsingCapabilities']

    def rdc_pdu(g_outer, t, depth):
        g = asnper.Gen(sc, g_outer.rng, rcovered)
        g.p_ext = 0.5
        v = g.gen(rdcpdu_t, 5, '')
        rcovered.update(g.new)
        return sc.encode(rdcpdu_t, v).bytes()
    def devlist(g_outer, t, depth):
        g = asnper.Gen(sc, g_outer.rng, rcovered)
        v = g.gen(ncc_t, 4, '')
        rcovered.update(g.new)
        return sc.encode(ncc_t, v).bytes() or b'\x00'
    overrides = {'/rdcPDU': rdc_pdu, '/deviceListResp': devlist}

    def newgen():
        g = asnper.Gen(sc, rng, covered, overrides=overrides)
        return g

    def lct_msg(patch=None, depth=6, p_ext=0.5, p_opt=0.6, g=None):
        g = g or newgen(); g.p_ext = p_ext; g.p_opt = p_opt
        v = g.gen(lctpdu_t, depth, '')
        if patch: v.update(patch)
        covered.update(g.new)
        return sc.encode(lctpdu_t, v).bytes(), g

    recorded = []
    mark('Random LCT PDUs (ack, rdcData with every LCT message, nonStandardMessage, RDC PDUs, device lists, nonStandardParameters)')
    kept = 0
    for attempt in range(400):
        d, g = lct_msg(depth=rng.choice((4, 5, 6)), p_ext=rng.choice((0.2, 0.6, 0.9)), p_opt=rng.choice((0.4, 0.8)))
        if not g.new and kept > 40:
            continue
        recorded.append(d)
        p.udp(A, B, 4000 + kept, PORT, d)
        kept += 1
        if kept >= 120:
            break
    mark('Every LCT message by value')
    def forced(dtype, name, inner=None):
        # LCTPDU with a given RDCData.dataType
        g = newgen()
        v = g.gen(lctpdu_t, 3, '')
        return v, g
    for (kind, alt, ext) in [('lctRequest', 'announceReq', False), ('lctRequest', 'deviceListReq', False),
                             ('lctResponse', 'announceResp', False), ('lctResponse', 'deviceListResp', False),
                             ('lctIndication', 'deviceChange', False), ('nonStandardMessage', None, False)]:
        for reliable in (True, False):
            if kind == 'nonStandardMessage':
                msg = (kind, {'nonStandardParameters': [{'nonStandardIdentifier': ('h221NonStandard', {'t35CountryCode': 0xb5, 't35Extension': 0, 'manufacturerCode': 0x1234}), 'data': b'\x01\x02'},
                                                        {'nonStandardIdentifier': ('object', [1, 3, 6, 1, 4, 1, 9999, 3]), 'data': b''}]})
            elif kind == 'lctResponse' and alt == 'deviceListResp':
                msg = (kind, (alt, devlist(newgen(), None, 0)))
            else:
                msg = (kind, (alt, None))
            v = {'srcAddr': {'mAddress': 1, 'tAddress': 2}, 'dstAddr': {'mAddress': 3, 'tAddress': 4},
                 'timestamp': 1000 + len(p.frames), 'seqNumber': len(p.frames),
                 'pduType': ('rdcData', {'reliable': reliable, 'dataType': ('lctMessage', msg)})}
            d = sc.encode(lctpdu_t, v).bytes()
            recorded.append(d)
            p.udp(A, B, 4500, PORT, d)
    mark('Unknown extension alternatives of LCTMessage / LCTRequest / LCTResponse / LCTIndication (no Info text from the message type)')
    def raw_lct(level, ext_idx, payload=b'\x00'):
        # LCTPDU{ srcAddr, dstAddr, timestamp, seqNumber, pduType rdcData{ reliable, lctMessage ...}}
        w = asnper.PW()
        w.flag(0); w.flag(0)                      # LCTPDU extension bit, nonStandardParameters absent
        for x in (1, 2, 3, 4):
            w.cint(x, 0, 65535)
        w.cint(77, 0, 4294967295); w.cint(5, 0, 65535)
        w.cint(1, 0, 1)                           # pduType = rdcData
        w.flag(0); w.flag(1)                      # RDCData extension bit, reliable
        w.cint(0, 0, 1)                           # dataType = lctMessage
        def ext_alt(w):
            w.flag(1); w.small(ext_idx)
            asnper.open_type(w, _PWb(payload))
        if level == 'msg':                        # LCTMessage extension alternative
            ext_alt(w)
        else:
            w.flag(0)                             # LCTMessage root
            w.cint({'lctRequest': 0, 'lctResponse': 1, 'lctIndication': 2}[level], 0, 3)
            ext_alt(w)
        return w.bytes()
    class _PWb:
        def __init__(self, b): self.b = b
        def bytes(self): return self.b
    for lvl in ('msg', 'lctRequest', 'lctResponse', 'lctIndication'):
        d = raw_lct(lvl, 0, b'\x00\x01')
        recorded.append(d)
        p.udp(A, B, 4600, PORT, d)
    mark('Ack PDUs')
    for i in range(3):
        v = {'srcAddr': {'mAddress': 1, 'tAddress': 2}, 'dstAddr': {'mAddress': 3, 'tAddress': 4},
             'timestamp': 5000 + i, 'seqNumber': i, 'pduType': ('ack', None)}
        p.udp(B, A, PORT, 4500, sc.encode(lctpdu_t, v).bytes())
    p.write(os.path.join(out, 'h283-coverage.pcap'))

    mq = Pcap(); mq.ts = 1700100000.0
    step = max(1, len(recorded) // 40)
    for i, d in enumerate(recorded[::step]):
        cut = 1 + (i * 7) % max(1, len(d) - 1)
        mq.udp(A, B, 5000 + i, PORT, d[:cut])
    mq.udp(A, B, 5100, PORT, b'')
    mq.udp(A, B, 5101, PORT, bytes([0xff] * 64))
    mq.write(os.path.join(out, 'h283-coverage-malformed.pcap'))
    if verbose:
        for (n, s), nx in zip(marks, marks[1:] + [(len(p.frames) + 1, '')]):
            print('%d-%d %s' % (n, nx[0] - 1, s))
    print(len(p.frames), 'frames,', len(mq.frames), 'malformed')

if __name__ == '__main__':
    import tempfile
    args = [a for a in sys.argv[1:] if a != '-v']
    with tempfile.TemporaryDirectory() as work:
        main(args[0] if args else '.', args[1] if len(args) > 1 else work, '-v' in sys.argv)
