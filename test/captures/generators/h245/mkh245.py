#!/usr/bin/env python3
# Generates test/captures/h245_coverage.pcap.gz, h245_stale_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the H.245 coverage captures.  Usage: mkh245.py <outdir> <workdir> [-v]

Run it where the Wireshark source tree is (the .asn files of H.225, H.235
and H.245 are parsed with the parser of tools/dissector_generators/asn2wrs.py;
<workdir> receives parsetab.py).  The PER encodings come from asnper.py
(a small aligned PER encoder and random value generator driven by that syntax
tree).  Everything is built with Python struct; nothing comes from a real
network (addresses are from 192.0.2.0/24).

Transport, as a real network carries it:
 * H.245 on a TCP connection that an h245Address in H.225.0 call signalling
   (Q.931 in TPKT, TCP 1720) announces; each H.245 message is a TPKT.
 * H.245 tunnelled in h245Control and fastStart OpenLogicalChannels of H.225.0.
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import struct
import random
import asnper
from _lib import Pcap

FILES = ['h225/H323-MESSAGES.asn', 'h235/H235-SECURITY-MESSAGES.asn', 'h245/MULTIMEDIA-SYSTEM-CONTROL.asn']
SKIP = {'tunnelledSignallingMessage', 'h4501SupplementaryService', 'requestMultiplexEntryRelease'}
GK, EP1, EP2 = '192.0.2.1', '192.0.2.10', '192.0.2.20'

def q931(msgtype, uuie, callref=1, from_dest=False):
    cr = struct.pack('!H', callref | (0x8000 if from_dest else 0))
    body = bytes([0x08, 0x02]) + cr + bytes([msgtype])
    return body + bytes([0x7E]) + struct.pack('!H', len(uuie) + 1) + bytes([0x05]) + uuie

def tpkt(data):
    return struct.pack('!BBH', 3, 0, 4 + len(data)) + data

def main(out, workdir, verbose=False):
    types = asnper.load(FILES + ['h460/MESSAGE-BROADCAST.asn'], workdir)
    sc = asnper.Schema(types)
    rng = random.Random(245)
    covered = set()
    p = Pcap()
    marks = []
    def mark(n): marks.append((len(p.frames) + 1, n))
    mscm = types['MultimediaSystemControlMessage']
    olc = types['OpenLogicalChannel']
    uu_t = types['H323-UserInformation']
    uupdu = types['H323-UU-PDU']
    body_t = [e.val for e in uupdu.elt_list if e.val.name == 'h323-message-body'][0]

    def alts(t):
        return [a.name for a in list(t.elt_list) + list(getattr(t, 'ext_list', []) or [])]
    def find_alt(t, n):
        for a in list(t.elt_list) + list(getattr(t, 'ext_list', []) or []):
            if a.name == n:
                return a
    def valid_msg(g_outer, t, depth):
        g = asnper.Gen(sc, g_outer.rng, covered=set(), skip=SKIP)
        return sc.encode(mscm, g.gen(mscm, 3, '')).bytes()
    def valid_olcs(g_outer, t, depth):
        out = []
        for _ in range(g_outer.rng.randint(1, 2)):
            g = asnper.Gen(sc, g_outer.rng, covered=set(), skip=SKIP)
            out.append(sc.encode(olc, g.gen(olc, 4, '')).bytes())
        return out
    def valid_msgs(g_outer, t, depth):
        return [valid_msg(g_outer, t, depth) for _ in range(g_outer.rng.randint(1, 2))]
    OVER = {'/returnedFunction': valid_msg, '/fastStart': valid_olcs, '/h245Control': valid_msgs,
            '/parallelH245Control': valid_msgs}
    def newgen(over=None):
        return asnper.Gen(sc, rng, covered, overrides=dict(OVER, **(over or {})), skip=SKIP)

    def msg(top, inner, depth=6, p_ext=0.7, p_opt=0.6, g=None):
        """MultimediaSystemControlMessage with given top/inner alternatives"""
        g = g or newgen()
        g.p_ext, g.p_opt = p_ext, p_opt
        ta = find_alt(mscm, top)
        tt = types[{'request': 'RequestMessage', 'response': 'ResponseMessage',
                    'command': 'CommandMessage', 'indication': 'IndicationMessage'}[top]]
        ia = find_alt(tt, inner)
        g.mark(('MultimediaSystemControlMessage', top)); g.mark((tt.name, inner))
        v = (top, (inner, g.gen(ia, depth, tt.name)))
        return v, g

    def enc(v):
        return sc.encode(mscm, v).bytes()

    h245_alts = []
    for top, tn in (('request', 'RequestMessage'), ('response', 'ResponseMessage'),
                    ('command', 'CommandMessage'), ('indication', 'IndicationMessage')):
        for n in alts(types[tn]):
            if n not in SKIP:
                h245_alts.append((top, n))

    # ---- random greedy messages, kept when they add coverage
    recorded = []
    bag = []
    for top, inner in h245_alts:
        kept = 0
        for attempt in range(600):
            if kept >= 40:
                break
            depth = rng.choice((4, 6, 8, 10, 12, 14))
            v, g = msg(top, inner, depth, rng.choice((0.3, 0.6, 0.9)), rng.choice((0.4, 0.7)))
            if not g.new and (kept > 0 or attempt < 3):
                continue
            covered.update(g.new)
            bag.append(enc(v))
            kept += 1

    # ---- targeted messages are added by hand below (see extra())
    extra = []
    ns = dict(globals(), **locals())
    exec(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'extra245.py')).read(), ns)
    flows = ns['flows']
    bag.extend(extra)
    rng.shuffle(bag)

    # ---- H.225 call signalling that announces the H.245 connections
    def uu(alt, **bodypatch):
        g = newgen()
        g.p_ext, g.p_opt = 0.3, 0.4
        pdu = g.gen(uupdu, 3, '')
        a = find_alt(body_t, alt)
        pdu['h323-message-body'] = (alt, g.gen(a, 3, ''))
        pdu['h323-message-body'][1].update(bodypatch)
        pdu.pop('h245Control', None)
        pdu['h245Tunnelling'] = False
        return sc.encode(uu_t, {'h323-uu-pdu': pdu}).bytes()
    def h245addr(ip, port):
        return ('ipAddress', {'ip': bytes(int(x) for x in ip.split('.')), 'port': port})

    def hs(a, b, sp, dp):
        p.tcp(a, b, sp, dp, b'', flags=0x02)
        p.tcp(b, a, dp, sp, b'', flags=0x12)
        p.tcp(a, b, sp, dp, b'', flags=0x10)
    mark('H.245 connections announced by Connect/Alerting h245Address, random H.245 messages on them')
    per = 24
    hs(EP1, EP2, 30000, 1720)
    hs(EP2, EP1, 30001, 1720)
    nconn = (len(bag) + per - 1) // per
    for c in range(nconn):
        port = 11000 + c
        sp = 41000 + c
        a, b = (EP1, EP2) if c % 2 == 0 else (EP2, EP1)
        p.tcp(*((a, b, 30000, 1720) if a == EP1 else (a, b, 30001, 1720)), tpkt(q931(0x07, uu('connect', h245Address=h245addr(b, port)), callref=100 + c, from_dest=True)))
        hs(a, b, sp, port)
        for i, m in enumerate(bag[c * per:(c + 1) * per]):
            if i % 2 == 0:
                p.tcp(a, b, sp, port, tpkt(m))
            else:
                p.tcp(b, a, port, sp, tpkt(m))
    mark('Logical channel flows: OLC, OLCAck (RTP/RTCP/T.38/H.223 channels), generic messages')
    for fi, fl in enumerate(flows):
        c = nconn + 1 + fi
        port, sp = 11000 + c, 41000 + c
        p.tcp(EP1, EP2, 30000, 1720, tpkt(q931(0x07, uu('connect', h245Address=h245addr(EP2, port)), callref=100 + c, from_dest=True)))
        hs(EP1, EP2, sp, port)
        for d, m in fl:
            if d == 0:
                p.tcp(EP1, EP2, sp, port, tpkt(m))
            else:
                p.tcp(EP2, EP1, port, sp, tpkt(m))
    mark('Media on the channels the OpenLogicalChannelAcks announced: RTP, RTCP, T.38 UDPTL, SRTP-flagged RTP')
    for k in range(3):
        p.udp(EP1, EP2, 20000, 30000, bytes([0x80, 0x00]) + struct.pack('!HII', k, 160 * k, 0x11223344) + bytes(160))
    p.udp(EP2, EP1, 30001, 20001, bytes([0x80, 0xc9, 0, 1]) + struct.pack('!I', 0x55667788))
    p.udp(EP1, EP2, 20021, 30020, struct.pack('!H', 1) + bytes([0x02, 0x00, 0x00, 0x00, 0x00]))
    p.udp(EP1, EP2, 20041, 30040, bytes([0x80, 0x00]) + struct.pack('!HII', 0, 0, 0x99aabbcc) + bytes(40))
    mark('Two H.245 messages in one segment; one message split over two segments')
    c = nconn
    port, sp = 11000 + c, 41000 + c
    p.tcp(EP1, EP2, 30000, 1720, tpkt(q931(0x07, uu('connect', h245Address=h245addr(EP2, port)), callref=100 + c, from_dest=True)))
    hs(EP1, EP2, sp, port)
    two = tpkt(bag[0]) + tpkt(bag[1])
    p.tcp(EP1, EP2, sp, port, two)
    one = tpkt(bag[2])
    p.tcp(EP1, EP2, sp, port, one[:3])
    p.tcp(EP1, EP2, sp, port, one[3:])
    mark('H.245 tunnelled in h245Control (Facility, Setup with IPv6 H.245 address), fast start OpenLogicalChannels in Setup/Connect')
    cs = lambda payload, sp, rev=False: (p.tcp(EP2, EP1, 1720, sp, tpkt(payload)) if rev else p.tcp(EP1, EP2, sp, 1720, tpkt(payload)))
    hs(EP1, EP2, 40002, 1720)
    for i in range(6):
        pat = {'h245Control': valid_msgs(newgen(), None, 0)}
        g = newgen(); g.p_ext, g.p_opt = 0.3, 0.4
        pdu = g.gen(uupdu, 3, '')
        pdu['h323-message-body'] = ('facility', g.gen(find_alt(body_t, 'facility'), 3, ''))
        pdu.update(pat); pdu['h245Tunnelling'] = True
        cs(q931(0x62, sc.encode(uu_t, {'h323-uu-pdu': pdu}).bytes(), callref=9 + i), 40002)
    for i, alt in enumerate(('setup', 'connect', 'setup', 'connect')):
        cs(q931({'setup': 5, 'connect': 7}[alt], uu(alt, fastStart=valid_olcs(newgen(), None, 0),
                h245Address=('ip6Address', {'ip': bytes(range(1, 17)), 'port': 12000 + i})), callref=20 + i, from_dest=(alt == 'connect')), 40002)
    p.write(os.path.join(out, 'h245-coverage.pcap'))

    # ---- malformed / unusual input
    mq = Pcap()
    mq.ts = 1700100000.0
    hs2 = lambda a, b, sp, dp: [mq.tcp(a, b, sp, dp, b'', flags=0x02), mq.tcp(b, a, dp, sp, b'', flags=0x12), mq.tcp(a, b, sp, dp, b'', flags=0x10)]
    mq.tcp(EP1, EP2, 30000, 1720, b'', flags=0x02)
    mq.tcp(EP2, EP1, 1720, 30000, b'', flags=0x12)
    mq.tcp(EP1, EP2, 30000, 1720, b'', flags=0x10)
    mq.tcp(EP1, EP2, 30000, 1720, tpkt(q931(0x07, uu('connect', h245Address=h245addr(EP2, 13000)), from_dest=True)))
    hs2(EP1, EP2, 42000, 13000)
    step = max(1, len(bag) // 120)
    for i, m in enumerate(bag[::step]):
        cut = 1 + (i * 5) % max(1, len(m) - 1)
        mq.tcp(EP1 if i % 2 == 0 else EP2, EP2 if i % 2 == 0 else EP1, *((42000, 13000) if i % 2 == 0 else (13000, 42000)), tpkt(m[:cut]))
    mq.tcp(EP1, EP2, 42000, 13000, tpkt(b''))
    mq.tcp(EP1, EP2, 42000, 13000, tpkt(bytes([0xff] * 40)))
    # RequestMultiplexEntryRelease (the H.245 dissector rejects it)
    mq.tcp(EP1, EP2, 42000, 13000, tpkt(enc(('indication', ('requestMultiplexEntryRelease', {'entryNumbers': [1, 2]})))))
    # a TPKT that is not an H.245 message length, TPKT length smaller than the header
    mq.tcp(EP1, EP2, 42000, 13000, struct.pack('!BBH', 3, 0, 2) + b'\x00\x00')
    # H.245 on UDP (Decode As udp.port 5000 to h245dg)
    for i, m in enumerate(bag[:40:4]):
        mq.udp(EP1, EP2, 5000, 5000, m)
    for i, m in enumerate(bag[1:40:8]):
        mq.udp(EP1, EP2, 5000, 5000, m[:max(1, len(m) // 2)])
    mq.write(os.path.join(out, 'h245-coverage-malformed.pcap'))

    # ---- reproducer of the stale upcoming_channel fix (own small capture)
    rp = Pcap()
    olcack = {'forwardLogicalChannelNumber': 1,
              'forwardMultiplexAckParameters': ('h2250LogicalChannelAckParameters', {
                  'mediaChannel': ns['ip']('192.0.2.10', 5000)})}
    trunc = enc(('response', ('openLogicalChannelAck', olcack)))[:-1]
    ras = types['RasMessage']; capadv = types['CapabilityAdvertisement']
    uub = sc.encode(uu_t, {'h323-uu-pdu': {'h323-message-body': ('empty', None),
                                           'h245Tunnelling': True, 'h245Control': [trunc]}}).bytes()
    rp.tcp(EP1, EP2, 40001, 1720, tpkt(q931(0x62, uub)))
    adv = sc.encode(capadv, {'transmitCapabilities': [{
        'groupIdentifer': bytes(16), 'capability': ('receiveAudioCapability', ('g711Ulaw64k', 20)),
        'sourceAddress': ('iPAddress', {'network': bytes([198, 51, 100, 1]), 'tsapIdentifier': 6000})}]}).bytes()
    grq = {'requestSeqNum': 1, 'protocolIdentifier': [0, 0, 8, 2250, 0, 4],
           'rasAddress': ('ipAddress', {'ip': bytes([192, 0, 2, 20]), 'port': 1719}),
           'endpointType': {'mc': False, 'undefinedNode': False},
           'genericData': [{'id': ('standard', 21), 'parameters': [{'id': ('standard', 1), 'content': ('raw', adv)}]}],
           'supportsAssignedGK': False}
    rp.udp(EP2, GK, 1719, 1719, sc.encode(ras, ('gatekeeperRequest', grq)).bytes())
    rp.write(os.path.join(out, 'h245-stale-channel.pcap'))
    if verbose:
        print(len(bag), 'messages')
        for (n, s), nx in zip(marks, marks[1:] + [(len(p.frames) + 1, '')]):
            print('%d-%d %s' % (n, nx[0] - 1, s))

if __name__ == '__main__':
    import tempfile
    args = [a for a in sys.argv[1:] if a != '-v']
    with tempfile.TemporaryDirectory() as work:
        main(args[0] if args else '.', args[1] if len(args) > 1 else work, '-v' in sys.argv)
