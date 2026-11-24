#!/usr/bin/env python3
# Generates test/captures/h235_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the H.235 coverage captures.  Usage: mkh235.py <outdir> <workdir> [-v]

packet-h235.c (H235-SECURITY-MESSAGES, H235-SRTP) is reached through
H.225.0 tokens / cryptoTokens / integrityCheckValue (RAS and call signalling),
through the SRTP crypto capability that H.245 carries in a GenericCapability
(nonCollapsingRaw) and through MIKEY in H.245 generic capabilities and
EncryptionSync.  The PER encodings come from asnper.py (aligned PER encoder
and random value generator driven by the ASN.1 syntax tree; octet strings and
bit strings are the constant placeholder 0xA5: no keys, signatures or
ciphertext are produced).  Run where the Wireshark source tree is.
Nothing comes from a real network (addresses are from 192.0.2.0/24).

Transport as a real network carries it: RAS on UDP 1719; call signalling as
Q.931 in TPKT over TCP port 1720; H.245 on the TCP connection announced by
an h245Address.
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import struct
import random
import asnper
from _lib import Pcap

FILES = ['h225/H323-MESSAGES.asn', 'h235/H235-SECURITY-MESSAGES.asn', 'h235/H235-SRTP.asn',
         'h245/MULTIMEDIA-SYSTEM-CONTROL.asn']
SKIP = {'tunnelledSignallingMessage', 'h4501SupplementaryService', 'requestMultiplexEntryRelease'}
GK, EP1, EP2 = '192.0.2.1', '192.0.2.10', '192.0.2.20'
MIKEY = bytes([0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00])   # version 1, PSK init, no payloads

def q931(msgtype, uuie, callref=1, from_dest=False):
    cr = struct.pack('!H', callref | (0x8000 if from_dest else 0))
    body = bytes([0x08, 0x02]) + cr + bytes([msgtype])
    return body + bytes([0x7E]) + struct.pack('!H', len(uuie) + 1) + bytes([0x05]) + uuie

def tpkt(data):
    return struct.pack('!BBH', 3, 0, 4 + len(data)) + data

def main(out, workdir, verbose=False):
    types = asnper.load(FILES, workdir)
    bymod = types.get('__by_mod__')
    sc = asnper.Schema(types)
    rng = random.Random(235)
    p = Pcap()
    marks = []
    def mark(n): marks.append((len(p.frames) + 1, n))
    h235 = set()
    for mod, d in bymod.items():
        if 'H235' in mod:
            h235 |= set(d)
    ras_t, uu_t, uupdu = types['RasMessage'], types['H323-UserInformation'], types['H323-UU-PDU']
    mscm = types['MultimediaSystemControlMessage']
    body_t = [e.val for e in uupdu.elt_list if e.val.name == 'h323-message-body'][0]
    def find_alt(t, n):
        for a in list(t.elt_list) + list(getattr(t, 'ext_list', []) or []):
            if a.name == n:
                return a
    covered = set()
    def is235(k):
        return any(x in h235 for x in k if isinstance(x, str))
    NOL = {'/fastStart': lambda g, t, d: [], '/h245Control': lambda g, t, d: [], '/parallelH245Control': lambda g, t, d: [],
           '/returnedFunction': lambda g, t, d: b''}
    def newgen(cov=None):
        return asnper.Gen(sc, rng, covered if cov is None else cov, overrides=NOL, skip=SKIP)
    ras_alts = [a.name for a in list(ras_t.elt_list) + list(ras_t.ext_list)]
    bodies = [a.name for a in list(body_t.elt_list) + list(body_t.ext_list)]
    TOK = types['ClearToken']; CTOK = types['CryptoH323Token']; ICV = types['ICV']
    def tokens(g, depth):
        n = rng.randint(1, 2)
        return [g.gen(TOK, depth, 'ClearToken') for _ in range(n)]
    def ctokens(g, depth):
        return [g.gen(CTOK, depth, 'CryptoH323Token') for _ in range(rng.randint(1, 2))]
    def ras_with(alt, depth, seq):
        g = newgen(); g.p_ext, g.p_opt = rng.choice((0.3, 0.7, 0.95)), rng.choice((0.4, 0.8))
        v = g.gen(find_alt(ras_t, alt), 3, 'RasMessage')
        if not isinstance(v, dict):
            return g, (alt, v)
        v['requestSeqNum'] = seq
        a = find_alt(ras_t, alt)
        names = [x.name for x in list(a.val.elt_list) + list(getattr(a.val, 'ext_list', []) or [])] if hasattr(a, 'val') and hasattr(a.val, 'elt_list') else []
        # tokens / cryptoTokens are present in most messages (as `tokens`, `cryptoTokens`, ...)
        if rng.random() < 0.9: v['tokens'] = tokens(g, depth)
        if rng.random() < 0.9: v['cryptoTokens'] = ctokens(g, depth)
        if rng.random() < 0.5: v['integrityCheckValue'] = g.gen(ICV, depth, 'ICV')
        return g, (alt, v)
    seq = [1000]
    def nseq():
        seq[0] += 1
        return seq[0]
    kept_msgs = []
    mark('RAS: random ClearTokens, CryptoH323Tokens and integrity check values (greedy: kept when they add H.235 coverage)')
    for rnd in range(3):
        for alt in ras_alts:
            if alt in ('serviceControlSession',):
                continue
            for attempt in range(60):
                depth = rng.choice((3, 4, 5, 6, 8))
                g, v = ras_with(alt, depth, nseq())
                new = {k for k in g.new if is235(k)}
                if new or (rnd == 0 and attempt == 5):
                    covered.update(g.new)
                    try:
                        data = sc.encode(ras_t, v).bytes()
                    except Exception as e:
                        if verbose: print('encode', alt, e)
                        continue
                    p.udp(EP1, GK, 2000 + len(p.frames), 1719, data)
                    kept_msgs.append(data)
                    break
    # ---- call signalling
    mark('Call signalling (Q.931/TPKT, TCP 1720) with tokens and cryptoTokens in the UUIEs')
    def hs(a, b, sp, dp):
        p.tcp(a, b, sp, dp, b'', flags=0x02); p.tcp(b, a, dp, sp, b'', flags=0x12); p.tcp(a, b, sp, dp, b'', flags=0x10)
    hs(EP1, EP2, 31000, 1720)
    Q931 = {'setup': 0x05, 'callProceeding': 0x02, 'connect': 0x07, 'alerting': 0x01, 'information': 0x7B,
            'releaseComplete': 0x5A, 'facility': 0x62, 'progress': 0x03, 'empty': 0x62, 'status': 0x7D,
            'statusInquiry': 0x75, 'setupAcknowledge': 0x0D, 'notify': 0x6E}
    cr = [0]
    cs_data = []
    for rnd in range(2):
        for alt in bodies:
            for attempt in range(40):
                g = newgen(); g.p_ext, g.p_opt = rng.choice((0.3, 0.7, 0.95)), rng.choice((0.4, 0.8))
                depth = rng.choice((3, 4, 5, 6, 8))
                pdu = g.gen(uupdu, 3, '')
                b = g.gen(find_alt(body_t, alt), 3, 'h323-message-body')
                if isinstance(b, dict):
                    if rng.random() < 0.9: b['tokens'] = tokens(g, depth)
                    if rng.random() < 0.9: b['cryptoTokens'] = ctokens(g, depth)
                    if rng.random() < 0.4: b['integrityCheckValue'] = g.gen(ICV, depth, 'ICV')
                pdu['h323-message-body'] = (alt, b)
                pdu.pop('h245Control', None); pdu['h245Tunnelling'] = False
                new = {k for k in g.new if is235(k)}
                if new or (rnd == 0 and attempt == 5):
                    covered.update(g.new)
                    try:
                        u = sc.encode(uu_t, {'h323-uu-pdu': pdu}).bytes()
                    except Exception as e:
                        if verbose: print('encode', alt, e)
                        continue
                    cr[0] += 1
                    cs_data.append((Q931[alt], u))
                    p.tcp(EP1, EP2, 31000, 1720, tpkt(q931(Q931[alt], u, callref=cr[0], from_dest=(cr[0] % 2 == 0))))
                    break
    # ---- H.245: SRTP crypto capability, MIKEY, encryption sync, H.235 media
    mark('H.245 on a connection announced by a Connect: SRTP crypto capability (H235-SRTP), MIKEY in generic capabilities and EncryptionSync')
    oid_srtp = [0, 0, 8, 235, 0, 4, 90]
    def srtp(n):
        infos = []
        for i in range(n):
            g = newgen(set())
            g.p_ext, g.p_opt = 0.9, 0.9
            infos.append(g.gen(types['SrtpCryptoInfo'], 5, 'SrtpCryptoInfo'))
        return sc.encode(types['SrtpCryptoCapability'], infos).bytes()
    def tcs(entries, seqn=1):
        return ('request', ('terminalCapabilitySet', {
            'sequenceNumber': seqn, 'protocolIdentifier': [0, 0, 8, 245, 0, 11],
            'capabilityTable': entries}))
    def entry(n, cap):
        return {'capabilityTableEntryNumber': n, 'capability': cap}
    def sec_cap(gen_cap, media=1):
        return ('h235SecurityCapability', {'encryptionAuthenticationAndIntegrity': {'genericH235SecurityCapability': gen_cap},
                                           'mediaCapability': media})
    audio = ('receiveAudioCapability', ('g711Ulaw64k', 20))
    H245 = []
    for n in (1, 2, 3):
        H245.append(tcs([entry(1, audio), entry(2, sec_cap({'capabilityIdentifier': ('standard', oid_srtp),
                                                                'nonCollapsingRaw': srtp(n)}))], n))
    H245.append(tcs([entry(1, audio), entry(2, sec_cap({'capabilityIdentifier': ('standard', oid_srtp),
                                                           'nonCollapsingRaw': srtp(0)}))], 4))
    for i, oid in enumerate(([0, 0, 8, 235, 0, 3, 76], [0, 0, 8, 235, 0, 3, 72], [0, 0, 8, 235, 0, 3, 73],
                             [0, 0, 8, 235, 0, 3, 74], [0, 0, 8, 235, 0, 3, 75])):
        H245.append(tcs([entry(1, audio), entry(2, sec_cap({'capabilityIdentifier': ('standard', oid),
            'nonCollapsing': [{'parameterIdentifier': ('standard', 0), 'parameterValue': ('octetString', MIKEY)}]}))], 5 + i))
        H245.append(tcs([entry(1, audio), entry(2, sec_cap({'capabilityIdentifier': ('standard', oid),
            'nonCollapsing': [{'parameterIdentifier': ('standard', 76 - i), 'parameterValue': ('octetString', MIKEY)}]}))], 10 + i))
    for flag in (0, 76, 72, 73, 74, 75, 99):
        v = {'forwardLogicalChannelNumber': 1,
             'forwardLogicalChannelParameters': {'dataType': ('audioData', ('g711Ulaw64k', 20)),
                  'multiplexParameters': ('h2250LogicalChannelParameters', {'sessionID': 1})},
             'encryptionSync': {'synchFlag': flag, 'h235Key': MIKEY}}
        H245.append(('request', ('openLogicalChannel', v)))
    # H.235 types that H.245 carries inside its own syntax: random messages with H235Media / encryption
    for top, inner in (('command', 'encryptionCommand'), ('request', 'openLogicalChannel'), ('response', 'openLogicalChannelAck'),
                       ('request', 'terminalCapabilitySet'), ('request', 'requestMode')):
        for i in range(3):
            g = asnper.Gen(sc, rng, set(), overrides=NOL, skip=SKIP)
            g.p_ext, g.p_opt = 0.95, 0.9
            tn = {'request': 'RequestMessage', 'response': 'ResponseMessage', 'command': 'CommandMessage'}[top]
            H245.append((top, (inner, g.gen(find_alt(types[tn], inner), 7, tn))))
    port = 11000
    p.tcp(EP1, EP2, 31000, 1720, tpkt(q931(0x07, sc.encode(uu_t, {'h323-uu-pdu': {'h323-message-body': ('connect', {
        'protocolIdentifier': [0, 0, 8, 2250, 0, 4], 'h245Address': ('ipAddress', {'ip': bytes([192, 0, 2, 20]), 'port': port}),
        'destinationInfo': {'mc': False, 'undefinedNode': False}, 'conferenceID': bytes(16)}), 'h245Tunnelling': False}}).bytes(),
        callref=500, from_dest=True)))
    hs(EP1, EP2, 41000, port)
    nok = 0
    for i, m in enumerate(H245):
        try:
            data = sc.encode(mscm, m).bytes()
        except Exception as e:
            if verbose: print('H245 encode', m[0], m[1][0], e)
            continue
        if i % 2 == 0:
            p.tcp(EP1, EP2, 41000, port, tpkt(data))
        else:
            p.tcp(EP2, EP1, port, 41000, tpkt(data))
    p.write(os.path.join(out, 'h235-coverage.pcap'))

    # ---- malformed input
    mq = Pcap()
    mq.ts = 1700100000.0
    step = max(1, len(kept_msgs) // 40)
    for i, data in enumerate(kept_msgs[::step]):
        cut = 1 + (i * 7) % max(1, len(data) - 1)
        mq.udp(EP1, GK, 5000 + i, 1719, data[:cut])
    # SIGNED tokens: ToBeSigned is ANY and is not decoded (the dissector reports it and the packet is malformed)
    for i in range(4):
        g = newgen(set())
        g.p_ext, g.p_opt = 0.8, 0.8
        tok = ('nestedcryptoToken', ('cryptoSignedToken', g.gen(find_alt(types['CryptoToken'], 'cryptoSignedToken'), 5, 'CryptoToken')))
        _, v = ras_with('registrationRequest', 3, 4)
        v[1]['cryptoTokens'] = [tok]
        try:
            mq.udp(EP1, GK, 5200 + i, 1719, sc.encode(ras_t, v).bytes())
        except Exception as e:
            if verbose: print('signed', e)
    mq.write(os.path.join(out, 'h235-coverage-malformed.pcap'))
    if verbose:
        print(len(kept_msgs), 'RAS', len(cs_data), 'CS', len(H245), 'H245')
        for (n, s), nx in zip(marks, marks[1:] + [(len(p.frames) + 1, '')]):
            print('%d-%d %s' % (n, nx[0] - 1, s))

if __name__ == '__main__':
    import tempfile
    args = [a for a in sys.argv[1:] if a != '-v']
    with tempfile.TemporaryDirectory() as work:
        main(args[0] if args else '.', args[1] if len(args) > 1 else work, '-v' in sys.argv)
