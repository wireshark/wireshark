#!/usr/bin/env python3
# Generates test/captures/h225_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the H.225 coverage captures.  Usage: mkh225.py <outdir> <workdir> [-v]

Run it on a machine with the Wireshark source tree (it parses the
.asn files of H.225, H.235 and H.245 with the parser of
tools/dissector_generators/asn2wrs.py; <workdir> receives parsetab.py).
The PER encodings are produced by asnper.py (a small aligned PER encoder
and random value generator driven by that syntax tree).  Everything is
built with Python struct; nothing comes from a real network.

Transport, as a real network carries it:
 * RAS: UDP port 1719 (registered).
 * Call signalling: Q.931 / H.225.0 in TPKT over TCP (Q.931 TPKT heuristic,
   any port; 1720 here) with the H323-UserInformation in the User-user
   information element.
 * H.245 on the TCP connection announced in an h245Address.
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import struct
import random
import asnper
from _lib import Pcap

FILES = ['h225/H323-MESSAGES.asn', 'h235/H235-SECURITY-MESSAGES.asn', 'h245/MULTIMEDIA-SYSTEM-CONTROL.asn']
SKIP = {'tunnelledSignallingMessage', 'h4501SupplementaryService'}

GK, EP1, EP2 = '192.0.2.1', '192.0.2.10', '192.0.2.20'

# Q.931 message types for the H.225 call signalling messages
Q931 = {'setup': 0x05, 'callProceeding': 0x02, 'connect': 0x07, 'alerting': 0x01, 'information': 0x7B,
        'releaseComplete': 0x5A, 'facility': 0x62, 'progress': 0x03, 'empty': 0x62, 'status': 0x7D,
        'statusInquiry': 0x75, 'setupAcknowledge': 0x0D, 'notify': 0x6E}

def q931(msgtype, uuie=None, callref=0x0001, from_dest=False, ies=b''):
    cr = struct.pack('!H', callref | (0x8000 if from_dest else 0))
    body = bytes([0x08, 0x02]) + cr + bytes([msgtype]) + ies
    if uuie is not None:
        body += bytes([0x7E]) + struct.pack('!H', len(uuie) + 1) + bytes([0x05]) + uuie
    return body

def tpkt(data):
    return struct.pack('!BBH', 3, 0, 4 + len(data)) + data

def ie(i, data):
    return bytes([i, len(data)]) + data

class Ctx:
    pass

def load_schema(workdir):
    types = asnper.load(FILES, workdir)
    return types, asnper.Schema(types)

def find_alt(choice_type, name):
    for a in list(choice_type.elt_list) + list(getattr(choice_type, 'ext_list', []) or []):
        if a.name == name:
            return a
    raise KeyError(name)

def force_alt(g, choice_type, name, depth):
    """value of one given alternative of a CHOICE"""
    a = find_alt(choice_type, name)
    g.mark((choice_type.name or '', name))
    return (name, g.gen(a, depth, ''))

def main(out, workdir, verbose=False):
    types, sc = load_schema(workdir)
    rng = random.Random(225)
    covered = set()
    p = Pcap()
    marks = []
    def mark(n): marks.append((len(p.frames) + 1, n))

    # --- helpers that build valid nested H.245 for fastStart / h245Control
    mscm = types['MultimediaSystemControlMessage']
    olc = types['OpenLogicalChannel']
    H245_SKIP = SKIP | {'requestMultiplexEntryRelease'}   # the H.245 dissector rejects this extension
    def sub_gen(rngs):
        g = asnper.Gen(sc, rngs, covered=set(), skip=H245_SKIP)
        return g
    def h245_octets(g_outer, t, depth):
        n = g_outer.rng.randint(1, 2)
        out = []
        for _ in range(n):
            g = sub_gen(g_outer.rng)
            v = g.gen(mscm, 4, '')
            out.append(sc.encode(mscm, v).bytes())
        return out
    def faststart_octets(g_outer, t, depth):
        out = []
        for _ in range(g_outer.rng.randint(1, 2)):
            g = sub_gen(g_outer.rng)
            v = g.gen(olc, 4, '')
            out.append(sc.encode(olc, v).bytes())
        return out
    overrides = {'/fastStart': faststart_octets, '/h245Control': h245_octets,
                 '/parallelH245Control': h245_octets}

    def newgen():
        g = asnper.Gen(sc, rng, covered, overrides=overrides, skip=SKIP)
        return g

    ras_t = types['RasMessage']
    uu_t = types['H323-UserInformation']
    uupdu = types['H323-UU-PDU']
    body_t = [e.val for e in uupdu.elt_list if e.val.name == 'h323-message-body'][0]

    def ras_msg(alt, seq=None, depth=5):
        g = newgen()
        g.p_ext = 0.6
        v = force_alt(g, ras_t, alt, depth)
        if seq is not None and 'requestSeqNum' in v[1]:
            v[1]['requestSeqNum'] = seq
        covered.update(g.new)
        return sc.encode(ras_t, v).bytes()

    def uu_msg(alt, depth=6, tunnelling=None):
        g = newgen()
        g.p_ext = 0.6
        pdu = g.gen(uupdu, depth, '')
        pdu['h323-message-body'] = force_alt(g, body_t, alt, depth)
        if tunnelling is not None:
            pdu['h245Tunnelling'] = tunnelling
        v = {'h323-uu-pdu': pdu}
        covered.update(g.new)
        return sc.encode(uu_t, v).bytes()

    recorded = {'ras': [], 'cs': []}
    ras_names = [a.name for a in list(ras_t.elt_list) + list(ras_t.ext_list)]
    body_names = [a.name for a in list(body_t.elt_list) + list(body_t.ext_list)]

    # ------------------------------------------------------------ RAS ----
    mark('RAS: random instances of every message type that add coverage')
    nras = 0
    for alt in ras_names:
        kept = 0
        for attempt in range(80):
            if kept >= 5:
                break
            g = newgen()
            g.p_ext = rng.choice((0.3, 0.6, 0.9))
            g.p_opt = rng.choice((0.4, 0.7))
            v = force_alt(g, ras_t, alt, rng.choice((4, 5, 6, 7)))
            if not g.new and kept > 0:
                continue
            if 'requestSeqNum' in v[1]:
                v[1]['requestSeqNum'] = 100 + len(p.frames)
            covered.update(g.new)
            data = sc.encode(ras_t, v).bytes()
            recorded['ras'].append(data)
            p.udp(EP1, GK, 2000 + len(p.frames), 1719, data)
            kept += 1
            nras += 1
    # ------------------------------------------------------ call signalling
    mark('Call signalling in Q.931/TPKT: random UUIEs of every type that add coverage')
    sport = 30000
    for alt in body_names:
        kept = 0
        for attempt in range(120):
            if kept >= 7:
                break
            g = newgen()
            g.p_ext = rng.choice((0.3, 0.6, 0.9))
            g.p_opt = rng.choice((0.4, 0.7))
            depth = rng.choice((4, 5, 6, 7))
            pdu = g.gen(uupdu, depth, '')
            pdu['h323-message-body'] = force_alt(g, body_t, alt, depth)
            if not g.new and kept > 0:
                continue
            covered.update(g.new)
            sport += 1
            u = sc.encode(uu_t, {'h323-uu-pdu': pdu}).bytes()
            recorded['cs'].append((Q931[alt], u))
            p.tcp(EP1, EP2, sport, 1720, tpkt(q931(Q931[alt], u, from_dest=(kept % 2 == 1))))
            kept += 1

    # ---------------------------------------- RAS request / response matching
    mark('RAS matching: request/response pairs of all 7 categories, duplicates, late repeats, unmatched responses')
    def ras_fixed(alt, seq, depth=4, **patch):
        g = newgen()
        g.p_ext = 0.3
        v = force_alt(g, ras_t, alt, depth)
        if isinstance(v[1], dict):
            v[1]['requestSeqNum'] = seq
            v[1].update(patch)
        return sc.encode(ras_t, v).bytes()
    for c in range(7):
        rq, cf, rj = ras_names[3 * c], ras_names[3 * c + 1], ras_names[3 * c + 2]
        seq = 1000 + c
        sp = 4000 + c
        p.udp(EP1, GK, sp, 1719, ras_fixed(rq, seq))
        p.ts += 0.2
        p.udp(GK, EP1, 1719, sp, ras_fixed(cf, seq))              # response, matched
        p.udp(EP1, GK, sp, 1719, ras_fixed(rq, seq))              # duplicate request
        p.udp(GK, EP1, 1719, sp, ras_fixed(cf, seq))              # duplicate response
        p.udp(GK, EP1, 1719, sp, ras_fixed(rj, seq))              # another response to the same request
        p.udp(GK, EP1, 1719, sp, ras_fixed(cf, seq + 5000))       # response without request
        p.udp(GK, EP2, 1719, 4500, ras_fixed(cf, seq))            # response in a conversation without request
        p.ts += 400                                               # more than 300 s after the response
        p.udp(EP1, GK, sp, 1719, ras_fixed(rq, seq))              # new request with the same number
        p.udp(GK, EP1, 1719, sp, ras_fixed(rj, seq))
        p.ts += 0.1
        p.udp(EP1, GK, sp, 1719, ras_fixed(rq, seq + 1))          # never answered ...
        p.ts += 1900                                              # ... repeated after 1800 s
        p.udp(EP1, GK, sp, 1719, ras_fixed(rq, seq + 1))
        p.ts += 0.1
        p.udp(EP1, GK, sp, 1719, ras_fixed(rq, seq + 1))
    # RAS messages that are not matched (tag above 20)
    for alt in ras_names[21:]:
        p.udp(EP1, GK, 4100, 1719, ras_fixed(alt, 77))


    mark('NonStandardParameter with the Microsoft NetMeeting H.221 identifier (t35 0xb5, 0x00, manufacturer 0x534c) and others')
    def nsp(data, t35=0xb5, ext=0, man=0x534c):
        return {'nonStandardIdentifier': ('h221NonStandard', {'t35CountryCode': t35, 't35Extension': ext, 'manufacturerCode': man}),
                'data': data}
    codec = bytes(range(32, 52)) + bytes([0x01, 0x11]) + bytes([0x01, 0x00])        # codec value at 20, 0x0100 at 22
    for i, d in enumerate((codec, codec[:24], codec[:23], bytes(range(40)), b'', bytes(10),
                           codec[:20] + bytes([0xFE, 0xFF]) + bytes([0x01, 0x00]) + b'tail')):
        p.udp(EP1, GK, 4200 + i, 1719, ras_fixed('gatekeeperRequest', 500 + i, nonStandardData=nsp(d)))
    p.udp(EP1, GK, 4210, 1719, ras_fixed('gatekeeperRequest', 510, nonStandardData=nsp(codec, man=0x1234)))
    p.udp(EP1, GK, 4211, 1719, ras_fixed('gatekeeperRequest', 511, nonStandardData={
        'nonStandardIdentifier': ('object', [1, 3, 6, 1, 4, 1, 311, 1]), 'data': codec}))
    mark('Long dialed digits (destinationInfo), H.245 address 0.0.0.0')
    dd = '0123456789' * 12 + '01234567'
    p.udp(EP1, GK, 4220, 1719, ras_fixed('admissionRequest', 520, destinationInfo=[('dialledDigits', dd)]))
    p.udp(EP1, GK, 4221, 1719, ras_fixed('admissionRequest', 521, destinationInfo=[('dialledDigits', '12345#'), ('h323-ID', 'bob')]))

    # ---------------------------------------- call signalling in context
    mark('A call: Setup with fast start and H.245 address, Proceeding, Alerting, Connect, H.245 on its own connection, Release Complete')
    def uu(alt, patch=None, tunnelling=None, depth=4, **bodypatch):
        g = newgen()
        g.p_ext = 0.5
        pdu = g.gen(uupdu, depth, '')
        pdu['h323-message-body'] = force_alt(g, body_t, alt, depth)
        pdu['h323-message-body'][1].update(bodypatch)
        if tunnelling is not None:
            pdu['h245Tunnelling'] = tunnelling
        if patch:
            pdu.update(patch)
        return sc.encode(uu_t, {'h323-uu-pdu': pdu}).bytes()
    def h245addr(ip, port):
        return ('ipAddress', {'ip': bytes(int(x) for x in ip.split('.')), 'port': port})
    def h245pdu(alt=None):
        g = sub_gen(rng)
        return sc.encode(mscm, g.gen(mscm, 4, '')).bytes()
    cs = lambda payload, sp=40001, rev=False: (p.tcp(EP2, EP1, 1720, sp, tpkt(payload)) if rev else p.tcp(EP1, EP2, sp, 1720, tpkt(payload)))
    cs(q931(0x05, uu('setup', h245Address=h245addr(EP1, 11000), fastStart=faststart_octets(newgen(), None, 0)),
            callref=7, ies=ie(0x04, bytes([0x88, 0x93, 0xA5])) + ie(0x28, b'Alice') + ie(0x6C, bytes([0x21, 0x80]) + b'1001')
                     + ie(0x70, bytes([0x80]) + b'2002')))
    cs(q931(0x02, uu('callProceeding', tunnelling=False), callref=7, from_dest=True), rev=True)
    cs(q931(0x01, uu('alerting', h245Address=h245addr(EP2, 11001)), callref=7, from_dest=True), rev=True)
    cs(q931(0x07, uu('connect', h245Address=h245addr(EP2, 11001), fastStart=faststart_octets(newgen(), None, 0)),
            callref=7, from_dest=True), rev=True)
    cs(q931(0x02, uu('callProceeding', h245Address=h245addr('0.0.0.0', 11009)), callref=7, from_dest=True), rev=True)
    for i in range(3):
        p.tcp(EP1, EP2, 40100, 11001, tpkt(h245pdu()))
        p.tcp(EP2, EP1, 11001, 40100, tpkt(h245pdu()))
    cs(q931(0x5A, uu('releaseComplete', reason=('undefinedReason', None)), callref=7, ies=ie(0x08, bytes([0x80, 0x90]))))
    mark('H.245 tunnelled in the call signalling; IPv6 H.245 address; two messages in one segment; one message in two segments')
    cs(q931(0x62, uu('facility', tunnelling=True, patch={'h245Control': h245_octets(newgen(), None, 0)}), callref=9), sp=40002)
    cs(q931(0x62, uu('facility', tunnelling=True, patch={'h245Control': h245_octets(newgen(), None, 0),
                                                         'provisionalRespToH245Tunnelling': None}), callref=9, from_dest=True), sp=40002, rev=True)
    cs(q931(0x05, uu('setup', h245Address=('ip6Address', {'ip': bytes(range(1, 17)), 'port': 11002}), tunnelling=True,
                     patch={'h245Control': h245_octets(newgen(), None, 0)})), sp=40003)
    two = tpkt(q931(0x01, uu('alerting'), callref=3)) + tpkt(q931(0x02, uu('callProceeding'), callref=3))
    p.tcp(EP1, EP2, 40004, 1720, two)
    one = tpkt(q931(0x07, uu('connect'), callref=3))
    p.tcp(EP1, EP2, 40005, 1720, one[:11])
    p.tcp(EP1, EP2, 40005, 1720, one[11:])
    mark('Tunnelled signalling messages (unknown protocols)')
    def special(patch, alt='facility'):
        gg = newgen()
        pdu = gg.gen(uupdu, 4, '')
        pdu['h323-message-body'] = force_alt(gg, body_t, alt, 4)
        pdu.update(patch)
        return sc.encode(uu_t, {'h323-uu-pdu': pdu}).bytes()
    p.tcp(EP1, EP2, 7001, 1720, tpkt(q931(0x62, special({'tunnelledSignallingMessage': {
        'tunnelledProtocolID': {'id': ('tunnelledProtocolObjectID', [1, 3, 6, 1, 4, 1, 9999, 1])},
        'messageContent': [b'\x08\x01\x02', b'\x01']}}))))
    p.tcp(EP1, EP2, 7002, 1720, tpkt(q931(0x62, special({'tunnelledSignallingMessage': {
        'tunnelledProtocolID': {'id': ('tunnelledProtocolAlternateID', {'protocolType': 'qsig', 'protocolVariant': 'v1'}),
                                'subIdentifier': 'sub'},
        'messageContent': [b'\x08\x01\x02'], 'tunnellingRequired': None}}))))
    p.write(os.path.join(out, 'h225-coverage.pcap'))

    # ------------------------------------------------------- malformed ----
    mq = Pcap()
    mq.ts = 1700100000.0
    ras_list = recorded['ras']
    cs_list = recorded['cs']
    step = max(1, len(ras_list) // 40)
    for i, data in enumerate(ras_list[::step]):
        cut = 1 + (i * 7) % max(1, len(data) - 1)
        mq.udp(EP1, GK, 5000 + i, 1719, data[:cut])
    mq.udp(EP1, GK, 5100, 1719, b'')
    mq.udp(EP1, GK, 5101, 1719, bytes([0xff] * 64))
    step = max(1, len(cs_list) // 30)
    for i, (mt, u) in enumerate(cs_list[::step]):
        cut = 1 + (i * 5) % max(1, len(u) - 1)
        mq.tcp(EP1, EP2, 6000 + i, 1720, tpkt(q931(mt, u[:cut])))
    mq.tcp(EP1, EP2, 7000, 1720, tpkt(q931(0x62, special({'h4501SupplementaryService': [b'\\xa1\\x08\\x02\\x01\\x01\\x02\\x01\\x0f\\x30\\x00', b'junk']}))))
    mq.write(os.path.join(out, 'h225-coverage-malformed.pcap'))
    if verbose:
        for (n, s), nx in zip(marks, marks[1:] + [(len(p.frames) + 1, '')]):
            print('%d-%d %s' % (n, nx[0] - 1, s))

if __name__ == '__main__':
    import tempfile
    args = [a for a in sys.argv[1:] if a != '-v']
    with tempfile.TemporaryDirectory() as work:
        main(args[0] if args else '.', args[1] if len(args) > 1 else work, '-v' in sys.argv)
