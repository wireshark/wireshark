#!/usr/bin/env python3
# Generates test/captures/h460_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the H.460 coverage captures.  Usage: mkh460.py <outdir> <workdir> [-v]

Run it on a machine with the Wireshark source tree: the .asn files of
H.460.x, H.225 and H.235 are parsed with the parser of
tools/dissector_generators/asn2wrs.py (<workdir> receives parsetab.py).
The aligned PER encodings come from asnper.py (a small PER encoder and
random value generator driven by that syntax tree).  Everything is built
with Python struct; nothing comes from a real network.

H.460.x features travel in H.225.0 GenericData / FeatureDescriptor items
(the genericData and featureSet fields of RAS messages and call signalling
messages); here in RAS over UDP port 1719 (registered).  The content of
each feature parameter is the PER encoding of its own ASN.1 type in a
"raw" Content, which the h225.gef.content dissector table hands to
packet-h460.c.  H.460.17 carries a RAS message inside a RAS message (the
nesting is limited to 8 levels, see the reproducer frames).
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import struct
import random
import asnper
from _lib import Pcap

H460 = ['CALL-PARTY-CATEGORY', 'CALL-PRIORITY', 'CIRCUIT-STATUS-MAP', 'MEDIA-TRAVERSAL', 'MESSAGE-BROADCAST', 'MLPP',
        'NUMBER-PORTABILITY', 'QOS-MONITORING-EXTENDED-VOIP-REPORT', 'QOS-MONITORING-REPORT',
        'SIGNALLING-CHANNEL-SUSPEND-REDIRECT', 'SIGNALLING-TRAVERSAL']
FILES = ['h225/H323-MESSAGES.asn', 'h235/H235-SECURITY-MESSAGES.asn', 'h245/MULTIMEDIA-SYSTEM-CONTROL.asn'] + \
        ['h460/%s.asn' % x for x in H460]
SKIP = {'tokens', 'cryptoTokens', 'integrityCheckValue', 'tunnelledSignallingMessage', 'h4501SupplementaryService'}
GK, EP1, EP2 = '192.0.2.1', '192.0.2.10', '192.0.2.20'

# (generic id, parameter id, ASN.1 module file, type) of the features with a content PDU in h460_feature_tab
CONTENT = [
    (2, 1, 'NUMBER-PORTABILITY', 'NumberPortabilityInfo'),
    (3, 1, 'CIRCUIT-STATUS-MAP', 'CircuitStatus'),
    (4, 1, 'CALL-PRIORITY', 'CallPriorityInfo'),
    (4, 2, 'CALL-PRIORITY', 'CallPriorityInfo'),
    (4, 3, 'CALL-PRIORITY', 'CountryInternationalNetworkCallOriginationIdentification'),
    (4, 4, 'CALL-PRIORITY', 'CountryInternationalNetworkCallOriginationIdentification'),
    (9, 1, 'QOS-MONITORING-REPORT', 'QosMonitoringReportData'),
    (9, 2, 'QOS-MONITORING-EXTENDED-VOIP-REPORT', 'ExtendedRTPMetrics'),
    (10, 1, 'CALL-PARTY-CATEGORY', 'CallPartyCategoryInfo'),
    (14, 1, 'MLPP', 'MLPPInfo'),
    (15, 1, 'SIGNALLING-CHANNEL-SUSPEND-REDIRECT', 'SignallingChannelData'),
    (18, 1, 'SIGNALLING-TRAVERSAL', 'IncomingCallIndication'),
    (18, 2, 'SIGNALLING-TRAVERSAL', 'LRQKeepAliveData'),
    (20, 1, 'H323-MESSAGES', 'ExtendedAliasAddress'),
    (21, 1, 'MESSAGE-BROADCAST', 'CapabilityAdvertisement'),
]
# features without a content PDU (name only) of h460_feature_tab: GenericData / FeatureDescriptor ids and parameters
NAMES = [(6, [1, 2, 3, 4]), (7, [1, 2, 3, 4, 5, 6]), (8, [1, 2]), (11, [1, 2, 3, 4]), (12, [1]), (13, [1]), (16, [1, 2]),
         (19, [1, 2]), (22, [1, 2]), (2, []), (3, []), (4, []), (5, []), (9, [0]), (10, []), (14, []), (15, []), (17, []),
         (18, []), (20, []), (21, []), (999, [1]), (0, [])]
# Q.931 information elements for H.460.5 / H.460.16 ("IEs string")
IES = [bytes([0x04, 0x03, 0x88, 0x90, 0xA3]), bytes([0x6C, 0x05, 0x21, 0x80]) + b'123',
       bytes([0x70, 0x04, 0x80]) + b'456' + bytes([0x28, 0x05]) + b'Alice', bytes([0x1E, 0x02, 0x82, 0x88]), b'\x08\x02\x80\x90', b'']

def tpkt(d): return struct.pack('!BBH', 3, 0, 4 + len(d)) + d

def q931(msgtype, uuie, callref=1, from_dest=False):
    cr = struct.pack('!H', callref | (0x8000 if from_dest else 0))
    return bytes([0x08, 0x02]) + cr + bytes([msgtype]) + bytes([0x7E]) + struct.pack('!H', len(uuie) + 1) + bytes([0x05]) + uuie

def main(out, workdir, verbose=False):
    types = asnper.load(FILES, workdir)
    types.pop('__objs__')
    sc = asnper.Schema(types)
    rng = random.Random(460)
    covered = set()
    p = Pcap()
    marks = []
    def mark(n): marks.append((len(p.frames) + 1, n))
    def T(mod, name):
        return [v for k, v in sc.by_mod.items() if k.endswith('/%s.asn' % mod)][0][name]
    ras_t = types['RasMessage']

    def force_alt(g, ct, name, depth):
        a = [x for x in list(ct.elt_list) + list(ct.ext_list) if x.name == name][0]
        g.mark((ct.name or '', name))
        return (name, g.gen(a, depth, ''))

    def gid(n): return ('standard', n)

    def gen_content(mod, name, depth=5):
        g = asnper.Gen(sc, rng, covered, skip={'tokens', 'cryptoTokens'})
        g.p_ext = rng.choice((0.3, 0.6, 0.9)); g.p_opt = rng.choice((0.4, 0.7, 0.95))
        t = T(mod, name)
        v = g.gen(t, depth, '')
        return sc.encode(t, v).bytes() or b'\x00', g

    def generic(gi, params):
        d = {'id': gi}
        if params:
            d['parameters'] = params
        return d

    def raw(pi, data):
        return {'id': gid(pi) if isinstance(pi, int) else pi, 'content': ('raw', data)}

    def ras(alt, seq, generic_data=None, features=None, depth=3):
        g = asnper.Gen(sc, rng, set(), skip=SKIP); g.p_opt = 0.0; g.p_ext = 0.0
        v = force_alt(g, ras_t, alt, depth)
        v[1]['requestSeqNum'] = seq
        if generic_data is not None:
            v[1]['genericData'] = generic_data
        if features is not None:
            v[1]['featureSet'] = features
        return sc.encode(ras_t, v).bytes()

    def feats(lst, which='supportedFeatures'):
        return {'replacementFeatureSet': False, which: lst}

    recorded = []
    sport = [2000]
    def send(data, rev=False):
        sport[0] += 1
        recorded.append(data)
        if rev: p.udp(GK, EP1, 1719, sport[0], data)
        else: p.udp(EP1, GK, sport[0], 1719, data)

    # ------------------------------------------------------------------
    mark('GenericData with the content PDU of every H.460 feature, random values that add coverage (GRQ, genericData)')
    seq = [100]
    def nextseq():
        seq[0] += 1
        return seq[0]
    for gi, pi, mod, name in CONTENT:
        kept = 0
        for attempt in range(60):
            if kept >= 6: break
            data, g = gen_content(mod, name, rng.choice((4, 5, 6, 7)))
            if kept > 0 and not g.new: continue
            covered.update(g.new)
            send(ras('gatekeeperRequest', nextseq(), [generic(gid(gi), [raw(pi, data)])]))
            kept += 1
    mark('The same content in a FeatureDescriptor (featureSet.supportedFeatures)')
    for gi, pi, mod, name in CONTENT:
        data, g = gen_content(mod, name, 5)
        send(ras('gatekeeperRequest', nextseq(), features=feats([generic(gid(gi), [raw(pi, data)])])), rev=False)
    mark('Needed and desired features; names only (features without a content PDU); unknown, oid and nonStandard ids')
    for which in ('neededFeatures', 'desiredFeatures'):
        send(ras('registrationRequest', nextseq(), features=feats([generic(gid(g_), [{'id': gid(q)} for q in qs] or None)
                                                                  for g_, qs in NAMES[:12]], which)))
    for g_, qs in NAMES:
        send(ras('gatekeeperRequest', nextseq(), [generic(gid(g_), [{'id': gid(q), 'content': ('number8', q)} for q in qs] or None)]))
    send(ras('gatekeeperRequest', nextseq(), features=feats([generic(gid(g_), [{'id': gid(q), 'content': ('bool', True)} for q in qs] or None)
                                                           for g_, qs in NAMES])))
    send(ras('admissionRequest', nextseq(), [generic(('oid', [0, 0, 8, 460, 18, 0, 1]), [{'id': ('oid', [0, 0, 8, 460, 18, 0, 1])}]),
                                           generic(('nonStandard', bytes(range(16))), [{'id': ('nonStandard', bytes(range(16)))}])]))
    mark('Content types other than raw (text, unicode, numbers, id, alias, transport, compound, nested)')
    cont = [('text', 'abc'), ('unicode', 'xy'), ('bool', False), ('number8', 7), ('number16', 700), ('number32', 70000),
            ('id', gid(5)), ('alias', ('dialledDigits', '123')),
            ('transport', ('ipAddress', {'ip': bytes([192, 0, 2, 7]), 'port': 1720})),
            ]
    send(ras('gatekeeperRequest', nextseq(), [generic(gid(2), [{'id': gid(1), 'content': c} for c in cont])]))
    send(ras('gatekeeperRequest', nextseq(), [generic(gid(4), [{'id': gid(1), 'content': ('compound', [
        {'id': gid(1), 'content': ('number8', 1)}, {'id': gid(2), 'content': ('raw', b'\x01')}])}])]))
    send(ras('gatekeeperRequest', nextseq(), [generic(gid(4), [{'id': gid(1), 'content': ('nested', [
        generic(gid(2), [{'id': gid(1), 'content': ('raw', b'\x00')}])])}])]))
    mark('H.460.5 / H.460.16 Q.931 information elements')
    for ie in IES:
        send(ras('gatekeeperRequest', nextseq(), [generic(gid(5), [raw(1, ie)])]))
        send(ras('gatekeeperRequest', nextseq(), [generic(gid(16), [raw(3, ie)])]))
    mark('H.460.17: a RAS message carried in a RAS message, 1 to 8 levels and beyond (the nesting limit)')
    inner = ras('gatekeeperRequest', nextseq())
    msg = inner
    for depth in range(1, 11):
        msg = ras('gatekeeperRequest', nextseq(), [generic(gid(17), [raw(1, msg)])])
        if depth <= 9 or depth == 10:
            send(msg)
    msgs = msg
    for depth in range(11, 121):
        msgs = ras('gatekeeperRequest', nextseq(), [generic(gid(17), [raw(1, msgs)])])
        if depth in (20, 60, 120):
            send(msgs)
    mark('H.245 tunnelled in a Facility: H.460.18 generic messages (genericRequest/Response/Command/Indication) and H.460.19 TraversalParameters in a generic information of a TerminalCapabilitySetAck')
    mscm = types['MultimediaSystemControlMessage']
    uu_t = types['H323-UserInformation']; uupdu = types['H323-UU-PDU']
    body_t = [e.val for e in uupdu.elt_list if e.val.name == 'h323-message-body'][0]
    csport = [31000]
    def tunnelled(h245_msgs):
        g = asnper.Gen(sc, rng, set(), skip=SKIP); g.p_opt = 0.0; g.p_ext = 0.0
        pdu = g.gen(uupdu, 3, '')
        a = [x for x in list(body_t.elt_list) + list(body_t.ext_list) if x.name == 'facility'][0]
        pdu['h323-message-body'] = ('facility', g.gen(a, 3, ''))
        pdu['h245Tunnelling'] = True
        pdu['h245Control'] = [sc.encode(mscm, x).bytes() for x in h245_msgs]
        u = sc.encode(uu_t, {'h323-uu-pdu': pdu}).bytes()
        csport[0] += 1
        recorded_cs.append(u)
        p.tcp(EP1, EP2, csport[0], 1720, tpkt(q931(0x62, u, callref=csport[0] & 0x7fff)))
    recorded_cs = []
    OID18 = [0, 0, 8, 460, 18, 0, 1]
    OID19 = [0, 0, 8, 460, 19, 0, 1]
    def gm(oid, sub, params):
        d = {'messageIdentifier': ('standard', oid)}
        if sub is not None: d['subMessageIdentifier'] = sub
        if params is not None: d['messageContent'] = params
        return d
    def gp(pid, val): return {'parameterIdentifier': ('standard', pid), 'parameterValue': val}
    cid = bytes(range(16))
    for kind in ('genericRequest', 'genericResponse', 'genericCommand', 'genericIndication'):
        top = {'genericRequest': 'request', 'genericResponse': 'response', 'genericCommand': 'command',
               'genericIndication': 'indication'}[kind]
        tunnelled([(top, (kind, gm(OID18, 1, [gp(1, ('octetString', cid)), gp(2, ('logical', None))])))])
    tunnelled([('indication', ('genericIndication', gm(OID18, None, None))),
               ('indication', ('genericIndication', gm(OID18, 7, [gp(9, ('unsignedMin', 5))]))),
               ('indication', ('genericIndication', gm([0, 0, 8, 460, 18, 0, 2], 1, [gp(1, ('octetString', b'\x00'))])))])
    kept = 0
    for attempt in range(80):
        if kept >= 8: break
        data, g = gen_content('MEDIA-TRAVERSAL', 'TraversalParameters', rng.choice((4, 5, 6)))
        if kept > 0 and not g.new: continue
        covered.update(g.new)
        gi = gm(OID19, None, [gp(1, ('octetString', data))])
        tunnelled([('response', ('terminalCapabilitySetAck', {'sequenceNumber': 1 + kept, 'genericInformation': [gi]}))])
        kept += 1
    p.write(os.path.join(out, 'h460-coverage.pcap'))

    # ------------------------------------------------------- malformed ----
    mq = Pcap(); mq.ts = 1700100000.0
    step = max(1, len(recorded) // 50)
    for i, data in enumerate(recorded[::step]):
        cut = 1 + (i * 7) % max(1, len(data) - 1)
        mq.udp(EP1, GK, 5000 + i, 1719, data[:cut])
    # content that is not valid for its type
    for gi, pi, mod, name in CONTENT:
        for junk in (b'\x00', b'\xff\xff\xff', bytes(range(40))):
            mq.udp(EP1, GK, 5500, 1719, ras('gatekeeperRequest', nextseq(), [generic(gid(gi), [raw(pi, junk)])]))
    mq.write(os.path.join(out, 'h460-coverage-malformed.pcap'))
    if verbose:
        for (n, s), nx in zip(marks, marks[1:] + [(len(p.frames) + 1, '')]):
            print('%d-%d %s' % (n, nx[0] - 1, s))
    print(len(p.frames), 'frames,', len(mq.frames), 'malformed')

if __name__ == '__main__':
    import tempfile
    args = [a for a in sys.argv[1:] if a != '-v']
    with tempfile.TemporaryDirectory() as work:
        main(args[0] if args else '.', args[1] if len(args) > 1 else work, '-v' in sys.argv)
