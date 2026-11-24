#!/usr/bin/env python3
# Generates test/captures/h323_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the H.323 (H.323 Annex M4 / Annex R generic data) coverage capture.
Usage: mkh323.py <outdir> <workdir> [-v]

packet-h323.c holds the generic extensible framework helpers and the PDUs
RasTunnelledSignallingMessage (Annex M4) and RobustnessData (Annex R).  They
are carried as raw content of H.225.0 GenericData (RAS and call signalling):
GenericData id 1000 / parameter 1 and id 1 / parameter 1.  The PER encodings
come from asnper.py (aligned PER encoder driven by the ASN.1 syntax tree).
Run where the Wireshark source tree is.  Nothing comes from a real network
(addresses are from 192.0.2.0/24).

Transport as a real network carries it: RAS on UDP 1719; call signalling as
Q.931 in TPKT over TCP port 1720; tunnelled Q.931 (QSIG, 1.3.12.9) in the
H.225.0 tunnelledSignallingMessage.
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import struct
import random
import asnper
from _lib import Pcap

FILES = ['h225/H323-MESSAGES.asn', 'h235/H235-SECURITY-MESSAGES.asn', 'h245/MULTIMEDIA-SYSTEM-CONTROL.asn',
         'h323/RAS-PROTOCOL-TUNNEL.asn', 'h323/ROBUSTNESS-DATA.asn']
SKIP = {'tunnelledSignallingMessage', 'h4501SupplementaryService', 'requestMultiplexEntryRelease'}
GK, EP1, EP2 = '192.0.2.1', '192.0.2.10', '192.0.2.20'

def q931(msgtype, uuie=None, callref=1, from_dest=False, ies=b''):
    cr = struct.pack('!H', callref | (0x8000 if from_dest else 0))
    body = bytes([0x08, 0x02]) + cr + bytes([msgtype]) + ies
    if uuie is not None:
        body += bytes([0x7E]) + struct.pack('!H', len(uuie) + 1) + bytes([0x05]) + uuie
    return body

def tpkt(data):
    return struct.pack('!BBH', 3, 0, 4 + len(data)) + data

def main(out, workdir, verbose=False):
    types = asnper.load(FILES, workdir)
    sc = asnper.Schema(types)
    rng = random.Random(323)
    p = Pcap()
    marks = []
    def mark(n): marks.append((len(p.frames) + 1, n))
    ras_t, uu_t, uupdu = types['RasMessage'], types['H323-UserInformation'], types['H323-UU-PDU']
    body_t = [e.val for e in uupdu.elt_list if e.val.name == 'h323-message-body'][0]
    rob_t, tun_t = types['RobustnessData'], types['RasTunnelledSignallingMessage']
    def find_alt(t, n):
        for a in list(t.elt_list) + list(getattr(t, 'ext_list', []) or []):
            if a.name == n:
                return a
    covered = set()
    # a few Q.931 messages for the tunnelled signalling (QSIG over H.323)
    QS = [q931(0x05, ies=bytes([0x04, 0x03, 0x80, 0x90, 0xa3, 0x70, 0x04, 0x80]) + b'123'),
          q931(0x01, ies=bytes([0x1e, 0x02, 0x80, 0x81])),
          q931(0x5a, ies=bytes([0x08, 0x02, 0x80, 0x90])),
          bytes([0x08, 0x01, 0x02, 0x7d])]
    def gen_for(t, over=None, p_ext=0.7, p_opt=0.7, depth=5):
        g = asnper.Gen(sc, rng, covered, overrides=over or {}, skip=SKIP)
        g.p_ext, g.p_opt = p_ext, p_opt
        return g, g.gen(t, depth, '')
    def robustness(alt):
        for _ in range(60):
            g = asnper.Gen(sc, rng, covered, overrides={}, skip=SKIP)
            g.p_ext, g.p_opt = rng.choice((0.3, 0.9)), rng.choice((0.4, 0.9))
            v = {'versionID': rng.randint(1, 256), 'robustnessData': (alt, g.gen(find_alt(types['RobustnessData'].elt_list[1].val, alt), 5, ''))}
            if g.new or rng.random() < 0.15:
                covered.update(g.new)
                return sc.encode(rob_t, v).bytes()
        return sc.encode(rob_t, v).bytes()
    def tunnelled(tpid=None, n=1, nonstd=False, required=False, sub=None):
        tid = {'id': tpid or ('tunnelledProtocolObjectID', [1, 3, 12, 9])}
        if sub: tid['subIdentifier'] = sub
        v = {'tunnelledProtocolID': tid, 'messageContent': [QS[i % len(QS)] for i in range(n)]}
        if required: v['tunnellingRequired'] = None
        if nonstd:
            v['nonStandardData'] = {'nonStandardIdentifier': ('object', [1, 3, 6, 1, 4, 1, 9999]), 'data': b'\x01\x02'}
        return sc.encode(tun_t, v).bytes()
    def gd(ident, raw, extra_params=()):
        params = [{'id': ('standard', 1), 'content': ('raw', raw)}] + list(extra_params)
        return {'id': ('standard', ident), 'parameters': params}
    def ras(alt, seq, gdata, depth=3):
        g = asnper.Gen(sc, rng, set(), skip=SKIP)
        g.p_ext, g.p_opt = 0.3, 0.3
        v = g.gen(find_alt(ras_t, alt), depth, 'RasMessage')
        v['requestSeqNum'] = seq
        v['genericData'] = gdata
        return sc.encode(ras_t, (alt, v)).bytes()
    NOLIST = {'/fastStart': lambda g, t, d: [], '/h245Control': lambda g, t, d: [], '/parallelH245Control': lambda g, t, d: [],
              '/returnedFunction': lambda g, t, d: b'', '/connectionParameters': lambda g, t, d: None}
    def uu(alt, gdata=None, pdu_patch=None, **kw):
        g = asnper.Gen(sc, rng, set(), overrides={'/fastStart': NOLIST['/fastStart'], '/h245Control': NOLIST['/h245Control'],
                                                  '/parallelH245Control': NOLIST['/parallelH245Control']}, skip=SKIP)
        g.p_ext, g.p_opt = 0.3, 0.3
        pdu = g.gen(uupdu, 3, '')
        b = g.gen(find_alt(body_t, alt), 3, 'h323-message-body')
        if gdata is not None:
            pdu['genericData'] = gdata
        b.update(kw)
        pdu['h323-message-body'] = (alt, b)
        pdu.pop('h245Control', None)
        pdu['h245Tunnelling'] = False
        if pdu_patch:
            pdu.update(pdu_patch)
        return sc.encode(uu_t, {'h323-uu-pdu': pdu}).bytes()

    seq = [100]
    def nseq():
        seq[0] += 1
        return seq[0]
    # ---- RAS with Annex R robustness data
    mark('RAS with RobustnessData (Annex R, GenericData 1/1) in every robustnessData alternative')
    rras = [('registrationRequest', 'rrqData'), ('registrationConfirm', 'rcfData')]
    for alt, ralt in rras:
        for i in range(6):
            p.udp(EP1, GK, 2000 + nseq(), 1719, ras(alt, nseq(), [gd(1, robustness(ralt))]))
    for ralt in ('setupData', 'connectData', 'statusData', 'statusInquiryData'):
        for i in range(5):
            alt = rng.choice(('registrationRequest', 'registrationConfirm', 'admissionRequest', 'admissionConfirm'))
            p.udp(EP1, GK, 2000 + nseq(), 1719, ras(alt, nseq(), [gd(1, robustness(ralt))]))
    # ---- RAS with Annex M4 tunnelled signalling
    mark('RAS with RasTunnelledSignallingMessage (Annex M4, GenericData 1000/1): QSIG, other protocols, non-standard data')
    variants = [dict(), dict(n=3), dict(required=True), dict(nonstd=True), dict(sub='sub1'),
                dict(tpid=('tunnelledProtocolAlternateID', {'protocolType': 'qsig'})),
                dict(tpid=('tunnelledProtocolAlternateID', {'protocolType': 'qsig', 'protocolVariant': 'v2'}), sub='x'),
                dict(tpid=('tunnelledProtocolObjectID', [1, 3, 6, 1, 4, 1, 9999, 1]), n=2),
                dict(n=0)]
    for alt in ('gatekeeperRequest', 'registrationRequest', 'admissionRequest', 'infoRequest', 'serviceControlIndication'):
        for v in variants:
            p.udp(EP1, GK, 2000 + nseq(), 1719, ras(alt, nseq(), [gd(1000, tunnelled(**v))]))
    mark('Other generic data in the same message: robustness and tunnelled data together, unknown identifiers, an OID identifier')
    p.udp(EP1, GK, 2300, 1719, ras('registrationRequest', nseq(), [gd(1, robustness('rrqData')), gd(1000, tunnelled())]))
    p.udp(EP1, GK, 2301, 1719, ras('registrationRequest', nseq(), [gd(1001, robustness('rrqData')), gd(7, tunnelled())]))
    p.udp(EP1, GK, 2302, 1719, ras('registrationRequest', nseq(), [
        {'id': ('oid', [1, 3, 6, 1, 4, 1, 9999, 2]), 'parameters': [{'id': ('standard', 1), 'content': ('raw', b'\x00')}]},
        {'id': ('nonStandard', bytes(range(16))), 'parameters': [{'id': ('oid', [1, 2, 3]), 'content': ('raw', b'\x00')}]},
        gd(1000, tunnelled(), [{'id': ('standard', 2), 'content': ('raw', robustness('rcfData'))}]),
        gd(1, robustness('rcfData'), [{'id': ('standard', 5), 'content': ('number8', 3)}])]))
    # ---- call signalling
    mark('Call signalling (Q.931/TPKT, TCP 1720) with RobustnessData: Setup, Connect, Status, StatusInquiry')
    sp = 31000
    p.tcp(EP1, EP2, 31000, 1720, b'', flags=0x02)
    p.tcp(EP2, EP1, 1720, 31000, b'', flags=0x12)
    p.tcp(EP1, EP2, 31000, 1720, b'', flags=0x10)
    cn = [0]
    for alt, mt, ralt in (('setup', 0x05, 'setupData'), ('connect', 0x07, 'connectData'),
                          ('status', 0x7D, 'statusData'), ('statusInquiry', 0x75, 'statusInquiryData')):
        for i in range(5):
            cn[0] += 1
            u = uu(alt, [gd(1, robustness(ralt))])
            p.tcp(EP1, EP2, 31000, 1720, tpkt(q931(mt, u, callref=cn[0], from_dest=(i % 2 == 1))))
    mark('Call signalling with tunnelledSignallingMessage (1.3.12.9: Q.931 dissector via h225.tp) and tunnelled data in genericData')
    for i, v in enumerate(variants[:8]):
        cn[0] += 1
        tid = v.get('tpid') or ('tunnelledProtocolObjectID', [1, 3, 12, 9])
        patch = {'tunnelledSignallingMessage': {'tunnelledProtocolID': {'id': tid, **({'subIdentifier': v['sub']} if 'sub' in v else {})},
                                                 'messageContent': [QS[j % len(QS)] for j in range(v.get('n', 1))] or [QS[0]],
                                                 **({'tunnellingRequired': None} if v.get('required') else {})}}
        u = uu('facility', [gd(1000, tunnelled(**v))], pdu_patch=patch)
        p.tcp(EP1, EP2, 31000, 1720, tpkt(q931(0x62, u, callref=cn[0])))
    p.write(os.path.join(out, 'h323-coverage.pcap'))

    # ---- malformed input
    mq = Pcap()
    mq.ts = 1700100000.0
    good = [(rob, None) for rob in ('rrqData', 'rcfData', 'setupData', 'statusData')]
    blobs = [robustness('rrqData'), robustness('rcfData'), robustness('setupData'), robustness('statusData'),
             tunnelled(), tunnelled(n=3, nonstd=True), tunnelled(sub='sub1')]
    for i, b in enumerate(blobs):
        for cut in (1, len(b) // 2, len(b) - 1):
            ident = 1 if i < 4 else 1000
            mq.udp(EP1, GK, 5000 + len(mq.frames), 1719, ras('registrationRequest', 900 + len(mq.frames), [gd(ident, b[:max(cut, 0)])]))
    mq.udp(EP1, GK, 5100, 1719, ras('registrationRequest', 950, [gd(1, b'')]))
    mq.udp(EP1, GK, 5101, 1719, ras('registrationRequest', 951, [gd(1000, bytes([0xff] * 30))]))
    mq.udp(EP1, GK, 5102, 1719, ras('registrationRequest', 952, [gd(1, bytes([0xff] * 30))]))
    mq.write(os.path.join(out, 'h323-coverage-malformed.pcap'))
    if verbose:
        for (n, s), nx in zip(marks, marks[1:] + [(len(p.frames) + 1, '')]):
            print('%d-%d %s' % (n, nx[0] - 1, s))

if __name__ == '__main__':
    import tempfile
    args = [a for a in sys.argv[1:] if a != '-v']
    with tempfile.TemporaryDirectory() as work:
        main(args[0] if args else '.', args[1] if len(args) > 1 else work, '-v' in sys.argv)
