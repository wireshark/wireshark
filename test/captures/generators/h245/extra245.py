# Helper module for the h245 capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Targeted messages, exec'd by mkh245.py inside main().  `flows` are lists of
# (direction, PER bytes) that go on one H.245 connection each, in order.
def ga(tn, alt, depth=6):
    g = asnper.Gen(sc, rng, set(), skip=SKIP)
    g.p_ext = 0.5
    t = types[tn]
    return (alt, g.gen(find_alt(t, alt), depth, tn))
def ip(a, port):
    return ('unicastAddress', ('iPAddress', {'network': bytes(int(x) for x in a.split('.')), 'tsapIdentifier': port}))
def ip6(port):
    return ('unicastAddress', ('iP6Address', {'network': bytes(range(1, 17)), 'tsapIdentifier': port}))
def h2250(session=1, media=None, ctrl=None, **kw):
    d = {'sessionID': session}
    if media: d['mediaChannel'] = media
    if ctrl: d['mediaControlChannel'] = ctrl
    d.update(kw)
    return ('h2250LogicalChannelParameters', d)
def olc_msg(lcn, dt, mux, rev=None, **fkw):
    f = {'dataType': dt, 'multiplexParameters': mux}
    f.update(fkw)
    v = {'forwardLogicalChannelNumber': lcn, 'forwardLogicalChannelParameters': f}
    if rev:
        v['reverseLogicalChannelParameters'] = rev
    return enc(('request', ('openLogicalChannel', v)))
def ack_msg(lcn, media=None, ctrl=None, rev=None, **kw):
    v = {'forwardLogicalChannelNumber': lcn}
    if media or ctrl:
        a = {'flowControlToZero': False}
        if media: a['mediaChannel'] = media
        if ctrl: a['mediaControlChannel'] = ctrl
        v['forwardMultiplexAckParameters'] = ('h2250LogicalChannelAckParameters', a)
    if rev:
        v['reverseLogicalChannelParameters'] = rev
    v.update(kw)
    return enc(('response', ('openLogicalChannelAck', v)))
g711 = ('audioData', ('g711Ulaw64k', 20))
flows = []
# 1. audio channel: RTP and RTCP addresses learned from the OLC and the OLCAck
flows.append([(0, olc_msg(1, g711, h2250(1, None, ip('192.0.2.10', 20001)))),
              (1, ack_msg(1, ip('192.0.2.20', 30000), ip('192.0.2.20', 30001)))])
# 2. bidirectional video channel, IPv6 addresses, reverse channel parameters in OLC and OLCAck
vid = ga('DataType', 'videoData', 7)
flows.append([(0, olc_msg(2, vid, h2250(2, ip6(20010), ip6(20011)),
                          rev={'dataType': vid, 'multiplexParameters': h2250(2, ip('192.0.2.10', 20012), ip('192.0.2.10', 20013))})),
              (1, ack_msg(2, ip6(30010), ip6(30011), rev={'reverseLogicalChannelNumber': 3, 'multiplexParameters': h2250(2, ip('192.0.2.20', 30012), ip('192.0.2.20', 30013))})),
              (0, enc(('indication', ('openLogicalChannelConfirm', {'forwardLogicalChannelNumber': 2}))))])
# 3. T.38 fax channel
t38 = ('data', {'application': ('t38fax', {'t38FaxProtocol': ('udp', None),
        't38FaxProfile': {'fillBitRemoval': False, 'transcodingJBIG': False, 'transcodingMMR': False}}),
        'maxBitRate': 144})
flows.append([(0, olc_msg(4, t38, h2250(3, None, ip('192.0.2.10', 20021)))),
              (1, ack_msg(4, ip('192.0.2.20', 30020), ip('192.0.2.20', 30021)))])
# 4. RFC 2198 redundancy: mediaPacketization rtpPayloadType rfc-number 2198
pk = ('mediaPacketization', ('rtpPayloadType', {'payloadDescriptor': ('rfc-number', 2198), 'payloadType': 99}))
flows.append([(0, olc_msg(5, g711, h2250(1, None, ip('192.0.2.10', 20031), **dict([pk])))),
              (1, ack_msg(5, ip('192.0.2.20', 30030), ip('192.0.2.20', 30031)))])
# 5. generic audio capabilities: MIKEY (SRTP flag) and AMR (H.245 sub dissector)
def gen_audio(oid):
    return ('audioData', ('genericAudioCapability', {'capabilityIdentifier': ('standard', oid)}))
flows.append([(0, olc_msg(6, gen_audio([0, 0, 8, 235, 0, 3, 76]), h2250(1, None, ip('192.0.2.10', 20041)))),
              (1, ack_msg(6, ip('192.0.2.20', 30040), ip('192.0.2.20', 30041)))])
flows.append([(0, olc_msg(7, gen_audio([0, 0, 8, 245, 1, 1, 1]), h2250(1, None, ip('192.0.2.10', 20051)))),
              (1, ack_msg(7, ip('192.0.2.20', 30050), ip('192.0.2.20', 30051)))])
# 6. H.223 logical channels, adaptation layer types, and the OLCAck that completes them
def h223(al, seg=True):
    return ('h223LogicalChannelParameters', {'adaptationLayerType': al, 'segmentableFlag': seg})
als = [('al1Framed', None), ('al1NotFramed', None), ('al2WithoutSequenceNumbers', None),
       ('al2WithSequenceNumbers', None), ('al3', {'controlFieldOctets': 1, 'sendBufferSize': 1000}),
       ('al1M', {'transferMode': ('framed', None), 'headerFEC': ('sebch16-7', None), 'crcLength': ('crc16bit', None),
                 'rcpcCodeRate': 8, 'arqType': ('noArq', None), 'alpduInterleaving': False, 'alsduSplitting': False}),
       ('al2M', {'headerFEC': ('sebch16-5', None), 'alpduInterleaving': False}),
       ('al3M', {'headerFormat': ('sebch16-7', None), 'crcLength': ('crc8bit', None), 'rcpcCodeRate': 8,
                 'arqType': ('noArq', None), 'alpduInterleaving': False}),
       ('nonStandard', {'nonStandardIdentifier': ('object', [1, 3, 6, 1, 4, 1, 9999]), 'data': b'\x01'})]
fl = []
for i, al in enumerate(als):
    lcn = 40 + 2 * i
    rev = {'dataType': g711, 'multiplexParameters': h223(al, i % 2 == 0)} if i % 2 else None
    fl.append((0, olc_msg(lcn, g711, h223(al), rev=rev)))
    ackrev = {'reverseLogicalChannelNumber': lcn + 1} if rev else None
    fl.append((1, ack_msg(lcn, rev=ackrev)))
# AMR (generic audio capability 0.0.8.245.1.1.1) on an H.223 channel: the AMR dissector becomes its sub dissector
fl.append((0, olc_msg(70, gen_audio([0, 0, 8, 245, 1, 1, 1]), h223(('al2WithSequenceNumbers', None)))))
fl.append((1, ack_msg(70)))
flows.append(fl)
# 7. H.239 generic message (subMessageIdentifier translated)
def genmsg(top, name, oid, sub, content=None):
    v = {'messageIdentifier': ('standard', oid), 'subMessageIdentifier': sub}
    if content is not None: v['messageContent'] = content
    return enc((top, (name, v)))
gp = [{'parameterIdentifier': ('standard', 42), 'parameterValue': ('unsignedMin', 3)}]
for sub in (1, 2, 3, 4, 5, 6, 77):
    extra.append(genmsg('command', 'genericCommand', [0, 0, 8, 239, 2], sub, gp))
extra.append(genmsg('request', 'genericRequest', [0, 0, 8, 239, 2], 1))
extra.append(genmsg('response', 'genericResponse', [0, 0, 8, 239, 2], 2, gp))
extra.append(genmsg('indication', 'genericIndication', [0, 0, 8, 239, 2], 3, gp))
extra.append(genmsg('indication', 'genericIndication', [0, 0, 8, 239, 2], 4, gp))
extra.append(genmsg('request', 'genericRequest', [1, 3, 6, 1, 4, 1, 9999], 1, gp))
