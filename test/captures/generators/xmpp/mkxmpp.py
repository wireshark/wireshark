#!/usr/bin/env python3
# Generates test/captures/xmpp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the XMPP coverage captures.  Usage: mkxmpp.py <outdir>

Writes xmpp-coverage.pcap (main capture) and xmpp-coverage-malformed.pcap
(paths only malformed input reaches).  Everything is built with struct;
nothing comes from a real network.
"""
import os
import struct
import sys

# --------------------------------------------------------------------
# Packet building helpers
# --------------------------------------------------------------------


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ipaddr(a):
    return bytes(map(int, a.split('.')))


def ip(proto, payload, src, dst):
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, 0, 64,
                    proto, 0, ipaddr(src), ipaddr(dst))
    h = h[:10] + struct.pack('!H', csum(h)) + h[12:]
    return h + payload


def pseudo(src, dst, proto, seg):
    return ipaddr(src) + ipaddr(dst) + struct.pack('!BBH', 0, proto, len(seg))


def udp(sport, dport, data, src='192.0.2.1', dst='192.0.2.2'):
    seg = struct.pack('!HHHH', sport, dport, 8 + len(data), 0) + data
    c = csum(pseudo(src, dst, 17, seg) + seg) or 0xffff
    seg = seg[:6] + struct.pack('!H', c) + seg[8:]
    return ip(17, seg, src, dst)


def tcp(sport, dport, seq, ack, flags, data=b'', src='192.0.2.1',
        dst='192.0.2.2', opts=b''):
    seg = struct.pack('!HHIIBBHHH', sport, dport, seq, ack,
                      (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts + data
    c = csum(pseudo(src, dst, 6, seg) + seg)
    seg = seg[:16] + struct.pack('!H', c) + seg[18:]
    return ip(6, seg, src, dst)


def eth(p, rev=False):
    a, b = b'\x02\0\0\0\0\x02', b'\x02\0\0\0\0\x01'
    if rev:
        a, b = b, a
    return a + b + b'\x08\x00' + p


MSS = struct.pack('!BBH', 2, 4, 1460)


class Cap:
    def __init__(self):
        self.frames = []

    def add(self, pkt):
        self.frames.append(pkt)

    def write(self, fn):
        with open(fn, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            for i, p in enumerate(self.frames):
                f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p),
                                    len(p)))
                f.write(p)


class Tcp:
    """One TCP connection; the client is 192.0.2.1."""

    def __init__(self, cap, cport, sport, cip='192.0.2.1', sip='192.0.2.2'):
        self.cap, self.cp, self.sp = cap, cport, sport
        self.cip, self.sip = cip, sip
        self.cseq, self.sseq = 1000, 5000
        cap.add(eth(tcp(cport, sport, self.cseq, 0, 0x02, b'', cip, sip, MSS)))
        self.cseq += 1
        cap.add(eth(tcp(sport, cport, self.sseq, self.cseq, 0x12, b'', sip,
                        cip, MSS), True))
        self.sseq += 1
        cap.add(eth(tcp(cport, sport, self.cseq, self.sseq, 0x10, b'', cip,
                        sip)))

    def c(self, data):
        self.cap.add(eth(tcp(self.cp, self.sp, self.cseq, self.sseq, 0x18,
                             data, self.cip, self.sip)))
        self.cseq += len(data)

    def s(self, data):
        self.cap.add(eth(tcp(self.sp, self.cp, self.sseq, self.cseq, 0x18,
                             data, self.sip, self.cip), True))
        self.sseq += len(data)



# --------------------------------------------------------------------
# Stanzas
# --------------------------------------------------------------------

NS_STREAM = "xmlns:stream='http://etherx.jabber.org/streams'"
NS_SASL = "xmlns='urn:ietf:params:xml:ns:xmpp-sasl'"
NS_STANZAS = "xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'"
NS_BIND = "xmlns='urn:ietf:params:xml:ns:xmpp-bind'"
NS_SESSION = "xmlns='urn:ietf:params:xml:ns:xmpp-session'"
NS_TLS = "xmlns='urn:ietf:params:xml:ns:xmpp-tls'"
NS_DISCO_INFO = "xmlns='http://jabber.org/protocol/disco#info'"
NS_DISCO_ITEMS = "xmlns='http://jabber.org/protocol/disco#items'"
NS_JINGLE = "xmlns='urn:xmpp:jingle:1'"
NS_RTP = "xmlns='urn:xmpp:jingle:apps:rtp:1'"
NS_FT = "xmlns='urn:xmpp:jingle:apps:file-transfer:3'"
NS_ICE = "xmlns='urn:xmpp:jingle:transports:ice-udp:1'"
NS_RAW = "xmlns='urn:xmpp:jingle:transports:raw-udp:1'"
NS_S5B = "xmlns='urn:xmpp:jingle:transports:s5b:1'"
NS_IBBT = "xmlns='urn:xmpp:jingle:transports:ibb:1'"
NS_GTP2P = "xmlns='http://www.google.com/transport/p2p'"
NS_IBB = "xmlns='http://jabber.org/protocol/ibb'"
NS_BS = "xmlns='http://jabber.org/protocol/bytestreams'"
NS_DATA = "xmlns='jabber:x:data'"
NS_MUC = "xmlns='http://jabber.org/protocol/muc'"
NS_MUCU = "xmlns='http://jabber.org/protocol/muc#user'"
NS_MUCO = "xmlns='http://jabber.org/protocol/muc#owner'"
NS_MUCA = "xmlns='http://jabber.org/protocol/muc#admin'"
NS_HASH = "xmlns='urn:xmpp:hashes:0'"
NS_INPUT = "xmlns='http://jitsi.org/protocol/inputevt'"
NS_GS = "xmlns='http://www.google.com/session'"
NS_CONF = "xmlns='urn:ietf:params:xml:ns:conference-info'"

XML_DECL = "<?xml version='1.0'?>"


def stream_open(to=None, frm=None, sid=None, lang=None, ver='1.0'):
    a = ''
    if to:
        a += " to='%s'" % to
    if frm:
        a += " from='%s'" % frm
    if sid:
        a += " id='%s'" % sid
    if lang:
        a += " xml:lang='%s'" % lang
    return ("%s<stream:stream%s xmlns='jabber:client' %s version='%s'>"
            % (XML_DECL, a, NS_STREAM, ver))


def iq(typ, id_, inner='', frm=None, to=None, extra=''):
    a = " type='%s' id='%s'" % (typ, id_)
    if frm:
        a += " from='%s'" % frm
    if to:
        a += " to='%s'" % to
    if inner:
        return "<iq%s%s>%s</iq>" % (a, extra, inner)
    return "<iq%s%s/>" % (a, extra)


ME = 'juliet@example.com/laptop'
ROMEO = 'romeo@example.net/orchard'
SRV = 'example.com'
ROOM = 'coven@chat.example.com'

# (direction, text); 'c' = client to server (dst port 5222), 's' = server
# to client.  An entry with a tuple of strings is sent as several TCP
# segments (the XMPP dissector reassembles them).  A trailing "+" in the
# direction (e.g. 'c+') puts the entry in the same segment as the next one.

LOGIN = [
    ('c', stream_open(to=SRV)),
    ('s', stream_open(frm=SRV, sid='s1', lang='en')),
    ('s', "<stream:features><mechanisms %s><mechanism>PLAIN</mechanism>"
          "<mechanism>SCRAM-SHA-1</mechanism></mechanisms>"
          "<bind %s/><session %s/><unknownfeature xmlns='urn:x'><deep/>"
          "</unknownfeature></stream:features>" % (NS_SASL, NS_BIND,
                                                   NS_SESSION)),
    ('s', "<stream:features/>"),
    ('c', "<auth %s mechanism='PLAIN'>AGp1bGlldABzZWNyZXQ=</auth>" % NS_SASL),
    ('c', "<auth xmlns='http://www.google.com/talk/protocol/auth' "
          "client-uses-full-bind-result='true' mechanism='X-OAUTH2'>"
          "AGp1bGlldABzZWNyZXQ=</auth>"),
    ('c', "<auth %s/>" % NS_SASL),
    ('c', "<auth %s mechanism='PLAIN'>AA==</auth>" % NS_SASL),
    ('s', "<challenge %s>cmVhbG09ImV4YW1wbGUuY29tIg==</challenge>" % NS_SASL),
    ('c', "<response %s>dXNlcm5hbWU9Imp1bGlldCI=</response>" % NS_SASL),
    ('c', "<response %s/>" % NS_SASL),
    ('s', "<failure %s><not-authorized/><text xml:lang='en'>Bad password"
          "</text></failure>" % NS_SASL),
    ('s', "<failure %s><text>No condition</text></failure>" % NS_SASL),
    ('s', "<failure %s><weird-condition/></failure>" % NS_SASL),
    ('s', "<success %s/>" % NS_SASL),
    ('c', stream_open(to=SRV)),
    ('s', stream_open(frm=SRV, sid='s2')),
    ('s', "<stream:features><bind %s/><session %s/></stream:features>"
          % (NS_BIND, NS_SESSION)),
    ('c', iq('set', 'bind_1', "<bind %s><resource>laptop</resource></bind>"
             % NS_BIND)),
    ('s', iq('result', 'bind_1', "<bind %s><jid>%s</jid></bind>"
             % (NS_BIND, ME), to=ME)),
    ('c', iq('set', 'sess_1', "<session %s/>" % NS_SESSION)),
    ('s', iq('result', 'sess_1')),
    # roster
    ('c', iq('get', 'r1', "<query xmlns='jabber:iq:roster'/>", frm=ME)),
    ('s', iq('result', 'r1',
             "<query xmlns='jabber:iq:roster' ver='ver7'>"
             "<item jid='romeo@example.net' name='Romeo' subscription='both'>"
             "<group>Friends</group><group>Lovers</group></item>"
             "<item jid='nurse@example.com' subscription='none' "
             "ask='subscribe' approved='true'/>"
             "<item jid='tybalt@example.org' subscription='bogus' ask='no'/>"
             "<item jid='x@example.org' subscription='remove'/>"
             "<item/></query>", to=ME)),
    ('c', iq('set', 'r2', "<query xmlns='jabber:iq:roster'><item "
             "jid='mercutio@example.org' subscription='to'/></query>")),
    # service discovery
    ('c', iq('get', 'd1', "<query %s/>" % NS_DISCO_INFO, to=SRV)),
    ('s', iq('result', 'd1',
             "<query %s node='n1'><identity category='server' type='im' "
             "name='Example'/><identity category='x'/><feature var="
             "'jabber:iq:roster'/><feature var='urn:xmpp:ping'/><feature/>"
             "<x %s type='result'><field var='FORM_TYPE' type='hidden'>"
             "<value>urn:xmpp:dataforms:softwareinfo</value></field></x>"
             "</query>" % (NS_DISCO_INFO, NS_DATA), frm=SRV)),
    ('c', iq('get', 'd2', "<query %s node='n1'/>" % NS_DISCO_ITEMS, to=SRV)),
    ('s', iq('result', 'd2',
             "<query %s node='n1'><item jid='chat.example.com' name='Chat' "
             "node='c1'/><item jid='pubsub.example.com'/></query>"
             % NS_DISCO_ITEMS, frm=SRV)),
    # ping, version, last
    ('c', iq('get', 'p1', "<ping xmlns='urn:xmpp:ping'/>", to=SRV)),
    ('s', iq('result', 'p1', frm=SRV)),
    ('c', iq('get', 'v1', "<query xmlns='jabber:iq:version'/>", to=ROMEO)),
    ('s', iq('result', 'v1', "<query xmlns='jabber:iq:version'><name>Orchard"
             "</name><version>1.2</version><os>Linux</os></query>",
             frm=ROMEO)),
    ('c', iq('get', 'l1', "<query xmlns='jabber:iq:last'/>", to=ROMEO)),
    ('s', iq('result', 'l1', "<query xmlns='jabber:iq:last' seconds='42'>"
             "away</query>", frm=ROMEO)),
    ('s', iq('result', 'l2', "<query xmlns='jabber:iq:last' seconds='7'/>",
             frm=ROMEO)),
    # vCard
    ('c', iq('get', 'vc1', "<vCard xmlns='vcard-temp'/>", to=ROMEO)),
    ('s', iq('result', 'vc1', "<vCard xmlns='vcard-temp'><FN>Romeo</FN>"
             "</vCard>", frm=ROMEO)),
    ('s', iq('result', 'vc2', "<vCard xmlns='vcard-temp'/>", frm=ROMEO)),
    # iq stanzas without an id (no request/response tracking, no session
    # tracking)
    ('c', "<iq type='get'><ping xmlns='urn:xmpp:ping'/></iq>"),
    ('c', "<iq type='set'><jingle %s action='session-info' sid='noid'/></iq>"
          % NS_JINGLE),
    ('c', "<iq type='set'><session %s type='initiate' id='noid'/></iq>"
          % NS_GS),
    # an iq without a type
    ('c', "<iq id='notype'><ping xmlns='urn:xmpp:ping'/></iq>"),
    # an iq without a response, and one response without a request
    ('c', iq('get', 'lonely', "<ping xmlns='urn:xmpp:ping'/>", to=SRV)),
    ('s', iq('result', 'orphan', frm=SRV)),
    # iq errors
    ('s', iq('error', 'p1',
             "<ping xmlns='urn:xmpp:ping'/><error type='cancel' code='503'>"
             "<service-unavailable %s/><text %s>Not offered</text>"
             "<text %s>Two</text></error>" % (NS_STANZAS, NS_STANZAS,
                                              NS_STANZAS), frm=SRV)),
    ('s', iq('error', 'e2', "<error type='modify'><bad-request %s/></error>"
             % NS_STANZAS)),
    ('s', iq('error', 'e3', "<error><odd/></error>")),
    # presence
    ('c', "<presence/>"),
    ('c', "<presence from='%s' to='%s' id='pr1' xml:lang='en'><show>away"
          "</show><status xml:lang='en'>Gone fishing</status><status "
          "xml:lang='de'>Angeln</status><priority>5</priority></presence>"
          % (ME, ROMEO)),
    ('c', "<presence type='unavailable'><status/></presence>"),
    ('c', "<presence type='subscribe' to='romeo@example.net'/>"),
    ('s', "<presence type='subscribed' from='romeo@example.net' "
          "to='juliet@example.com'/>"),
    ('c', "<presence type='probe'/>"),
    ('c', "<presence type='unsubscribe'/>"),
    ('c', "<presence type='unsubscribed'/>"),
    ('s', "<presence type='error' from='x@example.com'><error type='cancel'>"
          "<item-not-found %s/></error></presence>" % NS_STANZAS),
    ('c', "<presence type='bogus'><show>bogus</show></presence>"),
    ('s', "<presence from='%s'><show>dnd</show><show>chat</show>"
          "<c xmlns='http://jabber.org/protocol/caps' hash='sha-1' "
          "node='http://example.com/client' ver='QgayPKawpkPSDYmwT/WM94uA'"
          " ext='voice'/><delay xmlns='urn:xmpp:delay' from='example.com' "
          "stamp='2024-01-01T10:00:00Z'>Offline Storage</delay>"
          "<x xmlns='jabber:x:delay' stamp='20240101T10:00:00'/>"
          "<x xmlns='vcard-temp:x:update'><photo>sha1hash</photo></x>"
          "<query xmlns='jabber:iq:last' seconds='3'/>"
          "<x xmlns='urn:x'><unknown/></x></presence>" % ROMEO),
    ('s', "<presence from='%s'><x xmlns='vcard-temp:x:update'/><show>xa"
          "</show><c xmlns='http://jabber.org/protocol/caps'/></presence>"
          % ROMEO),
    # messages
    ('c', "<message to='%s' type='chat' id='m1' xml:lang='en'><body>Hello"
          "</body><body xml:lang='de'>Hallo</body><subject>Greeting"
          "</subject><thread parent='t0'>t1</thread></message>" % ROMEO),
    ('s', "<message from='%s' to='%s' type='chat'><body>Hi!</body>"
          "<composing xmlns='http://jabber.org/protocol/chatstates'/>"
          "</message>" % (ROMEO, ME)),
    ('s', "<message from='%s' type='chat'><active xmlns='http://jabber.org/"
          "protocol/chatstates'/></message>" % ROMEO),
    ('s', "<message from='%s' type='headline'><body/><subject/><thread/>"
          "<delay xmlns='urn:xmpp:delay' stamp='2024-01-01T00:00:00Z'/>"
          "</message>" % ROMEO),
    ('c', "<message to='%s' type='normal'><x xmlns='jabber:x:event'>"
          "<offline/><delivered/><composing/><displayed/><id>m1</id></x>"
          "</message>" % ROMEO),
    ('c', "<message to='%s' type='groupchat'><x xmlns='google:nosave' "
          "value='enabled'/><body>off the record</body></message>" % ROOM),
    ('s', "<message type='error' from='%s'><error type='cancel'>"
          "<service-unavailable %s/></error></message>" % (ROMEO, NS_STANZAS)),
    ('c', "<message to='x@e.com' type='shout'><body>odd</body></message>"),
    ('c', "<message to='x@e.com'><unknown a='1' b='2'><deeper c='3'>t"
          "</deeper></unknown></message>"),
    # not a stanza; text; a comment alone (no XML element at all)
    ('c', "<bogus xmlns='urn:x' a='1'><b/></bogus>"),
    ('c', "plain text>"),
    ('c', "<!-- a comment alone -->"),
    ('c', "<![CDATA[ cdata alone ]]>"),
    # two stanzas in one segment
    ('c+', "<presence to='a@e.com'/>"),
    ('c', "<presence to='b@e.com'/>"),
    # a stanza split over three segments
    ('c', ("<message to='%s' type='chat'><bo" % ROMEO, "dy>split ",
           "in three</body></message>")),
    # whitespace keepalive, and trailing whitespace after a stanza
    ('c', ' '),
    ('c', "<presence to='c@e.com'/>\n  \n"),
]

# The end of a stream: a closing tag with nothing before it, which the XML
# dissector flags as "Closing an unopened tag" (error)
STREAM_END = [
    ('c', "</stream:stream>"),
    ('s', "</stream:stream>"),
]

STARTTLS = [
    ('c', stream_open(to=SRV)),
    ('s', stream_open(frm=SRV, sid='t1')),
    ('s', "<stream:features><starttls %s><required/></starttls>"
          "<mechanisms %s><mechanism>PLAIN</mechanism></mechanisms>"
          "</stream:features>" % (NS_TLS, NS_SASL)),
    ('c', "<starttls %s/>" % NS_TLS),
    ('c', "<starttls %s/>" % NS_TLS),
    ('s', "<proceed %s/>" % NS_TLS),
]

# A PROCEED without a STARTTLS before it (capture started late)
PROCEED_ONLY = [
    ('s', "<proceed %s/>" % NS_TLS),
]

JINGLE_CAND = ("<candidate component='1' foundation='1' generation='0' "
               "id='c1' ip='192.0.2.10' network='1' port='5000' "
               "priority='2130706431' protocol='udp' type='host'/>")

JINGLE = [
    ('c', iq('set', 'j1',
             "<jingle %s action='session-initiate' sid='sid1' initiator='%s' "
             "responder='%s'><content creator='initiator' name='voice' "
             "senders='both' disposition='session'>"
             "<description %s media='audio' ssrc='1234'>"
             "<payload-type id='96' name='opus' clockrate='48000' "
             "channels='2' maxptime='60' ptime='20'><parameter "
             "name='useinbandfec' value='1'/><parameter name='x'/>"
             "</payload-type><payload-type id='0' name='PCMU'/>"
             "<bandwidth type='AS'>64</bandwidth>"
             "<bandwidth type='CT' value='128'/>"
             "<encryption required='1'><zrtp-hash xmlns='urn:xmpp:jingle:apps:"
             "rtp:zrtp:1' version='1.10'>f4a1</zrtp-hash><crypto "
             "crypto-suite='AES_CM_128_HMAC_SHA1_80' key-params='inline:"
             "AAAAAAAAAAAAAAAAAAAAAAAAAAAA' session-params='UNENCRYPTED_SRTP' "
             "tag='1'/></encryption>"
             "<rtp-hdrext xmlns='urn:xmpp:jingle:apps:rtp:rtp-hdrext:0' "
             "id='1' uri='urn:ietf:params:rtp-hdrext:ssrc-audio-level' "
             "senders='both'><parameter name='p' value='v'/></rtp-hdrext>"
             "<rtp-hdrext id='2' uri='urn:x' senders='nobody'/>"
             "<zrtp-hash version='1.10'>bb22</zrtp-hash>"
             "<unknown-in-description/></description>"
             "<transport %s pwd='pw' ufrag='uf'>%s"
             "<candidate component='1' foundation='2' generation='0' ip="
             "'198.51.100.1' network='1' port='3478' priority='1' "
             "protocol='udp' type='srflx' rel-addr='192.0.2.10' "
             "rel-port='5000'/><remote-candidate component='1' "
             "ip='203.0.113.5' port='6000'/></transport></content>"
             "<conference-info xmlns='urn:xmpp:jingle:conf' isfocus='true'/>"
             "</jingle>" % (NS_JINGLE, ME, ROMEO, NS_RTP, NS_ICE,
                            JINGLE_CAND), to=ROMEO, frm=ME)),
    ('s', iq('result', 'j1', frm=ROMEO, to=ME)),
    ('s', iq('set', 'j2',
             "<jingle %s action='session-info' sid='sid1'><ringing "
             "xmlns='urn:xmpp:jingle:apps:rtp:info:1'/></jingle>" % NS_JINGLE,
             frm=ROMEO, to=ME)),
    ('s', iq('set', 'j3',
             "<jingle %s action='session-info' sid='sid1'><mute "
             "xmlns='urn:xmpp:jingle:apps:rtp:info:1' creator='initiator' "
             "name='voice'/></jingle>" % NS_JINGLE, frm=ROMEO, to=ME)),
    ('s', iq('set', 'j3b',
             "<jingle %s action='session-info' sid='sid1'><unmute "
             "xmlns='urn:xmpp:jingle:apps:rtp:info:1' creator='nobody'/>"
             "</jingle>" % NS_JINGLE, frm=ROMEO, to=ME)),
    ('s', iq('set', 'j3c',
             "<jingle %s action='session-info' sid='sid1'><hold "
             "xmlns='urn:xmpp:jingle:apps:rtp:info:1'/></jingle>" % NS_JINGLE,
             frm=ROMEO, to=ME)),
    ('s', iq('set', 'j4',
             "<jingle %s action='session-accept' sid='sid1' responder='%s'>"
             "<content creator='initiator' name='voice'><description %s "
             "media='audio'><payload-type id='96' name='opus'/>"
             "</description><transport %s ufrag='uf2'/></content></jingle>"
             % (NS_JINGLE, ROMEO, NS_RTP, NS_ICE), frm=ROMEO, to=ME)),
    ('c', iq('result', 'j4', frm=ME, to=ROMEO)),
    ('c', iq('set', 'j5',
             "<jingle %s action='transport-info' sid='sid1'><content "
             "creator='initiator' name='voice'><transport %s ufrag='uf'>"
             "%s</transport></content></jingle>" % (NS_JINGLE, NS_ICE,
                                                    JINGLE_CAND))),
    ('c', iq('set', 'j6',
             "<jingle %s action='content-add' sid='sid1'><content "
             "creator='responder' name='video' disposition='session' "
             "senders='initiator'><description %s media='video'>"
             "<payload-type id='97' name='VP8' clockrate='90000'/>"
             "</description><transport %s><candidate component='1' "
             "generation='0' id='r1' ip='192.0.2.10' port='7000' type='relay'"
             "/></transport></content></jingle>" % (NS_JINGLE, NS_RTP,
                                                    NS_RAW))),
    ('c', iq('set', 'j7', "<jingle %s action='content-modify' sid='sid1'>"
             "<content creator='initiator' name='voice' senders='none'/>"
             "</jingle>" % NS_JINGLE)),
    ('c', iq('set', 'j8', "<jingle %s action='content-remove' sid='sid1'>"
             "<content creator='initiator' name='voice'/></jingle>"
             % NS_JINGLE)),
    ('c', iq('set', 'j9', "<jingle %s action='description-info' sid='sid1'>"
             "<content creator='initiator' name='voice'/></jingle>"
             % NS_JINGLE)),
    ('c', iq('set', 'j10', "<jingle %s action='security-info' sid='sid1'/>"
             % NS_JINGLE)),
    ('c', iq('set', 'j11', "<jingle %s action='transport-replace' "
             "sid='sid1'><content creator='initiator' name='voice'>"
             "<transport %s/></content></jingle>" % (NS_JINGLE, NS_IBBT))),
    ('c', iq('set', 'j12', "<jingle %s action='bogus-action'/>"
             % NS_JINGLE)),
    # terminations: every reason shape
    ('c', iq('set', 't1', "<jingle %s action='session-terminate' "
             "sid='sid1'><reason><success/><text>Done</text></reason>"
             "</jingle>" % NS_JINGLE)),
    ('c', iq('set', 't2', "<jingle %s action='session-terminate' "
             "sid='sid1'><reason><alternative-session><sid>sid2</sid>"
             "</alternative-session></reason></jingle>" % NS_JINGLE)),
    ('c', iq('set', 't3', "<jingle %s action='session-terminate' "
             "sid='sid1'><reason><alternative-session/><crypto-required "
             "xmlns='urn:xmpp:jingle:apps:rtp:1:errors'/></reason></jingle>"
             % NS_JINGLE)),
    ('c', iq('set', 't4', "<jingle %s action='session-terminate' "
             "sid='sid1'><reason><busy/></reason><reason><gone/>"
             "</reason></jingle>" % NS_JINGLE)),
    ('c', iq('set', 't5', "<jingle %s action='session-terminate' "
             "sid='sid1'><reason/></jingle>" % NS_JINGLE)),
    ('c', iq('set', 't6', "<jingle action='session-terminate'/>")),
    # jingle with the conference-info advertisement and a Jitsi input event
    ('c', iq('set', 'j13', "<jingle %s action='session-info' sid='sid1'>"
             "<content creator='initiator' name='desktop'><inputevt %s "
             "action='start'/></content></jingle>" % (NS_JINGLE, NS_INPUT))),
    ('c', iq('set', 'j14',
             "<inputevt %s action='notify'><remote-control %s "
             "action='mouse-move'><mouse-move x='5' y='6'/></remote-control>"
             "<remote-control action='mouse-press'><mouse-press btns='1'/>"
             "</remote-control><remote-control action='mouse-release'>"
             "<mouse-release btns='1'/></remote-control><remote-control "
             "action='key-press'><key-press keycode='65'/></remote-control>"
             "<remote-control action='key-release'><key-release keycode='65'/>"
             "</remote-control><remote-control><key-release/>"
             "</remote-control><remote-control action='other'><x/>"
             "</remote-control><remote-control><mouse-move/></remote-control>"
             "</inputevt>" % (NS_INPUT, NS_INPUT))),
    # file transfer
    ('c', iq('set', 'ft1',
             "<jingle %s action='session-initiate' sid='ft-sid' "
             "initiator='%s'><content creator='initiator' name='file'>"
             "<description %s><offer><file><name>a.txt</name><size>1024"
             "</size><date>2024-01-01T00:00:00Z</date><hashes %s><hash "
             "algo='sha-256' value='aGFzaA=='/></hashes></file><file/>"
             "</offer></description><transport %s mode='tcp' sid='s5b1'>"
             "<candidate cid='c1' jid='proxy.example.com' host='192.0.2.9' "
             "port='7777' priority='8257536' type='proxy'/>"
             "<candidate cid='c2' jid='%s' priority='1' type='odd'/>"
             "</transport></content></jingle>" % (NS_JINGLE, ME, NS_FT,
                                                  NS_HASH, NS_S5B, ME))),
    ('s', iq('set', 'ft2',
             "<jingle %s action='session-accept' sid='ft-sid'><content "
             "creator='initiator' name='file'><description %s><request>"
             "<file><name>b.txt</name></file></request></description>"
             "<transport %s sid='s5b1'><candidate-used cid='c1'/>"
             "</transport></content></jingle>" % (NS_JINGLE, NS_FT, NS_S5B),
             frm=ROMEO, to=ME)),
    ('c', iq('set', 'ft3',
             "<jingle %s action='transport-info' sid='ft-sid'><content "
             "creator='initiator' name='file'><transport %s sid='s5b1'>"
             "<activated cid='c1'/></transport></content></jingle>"
             % (NS_JINGLE, NS_S5B))),
    ('c', iq('set', 'ft4',
             "<jingle %s action='transport-info' sid='ft-sid'><content "
             "creator='initiator' name='file'><transport %s sid='s5b1'>"
             "<candidate-error/><proxy-error/><candidate-used/><activated/>"
             "</transport></content></jingle>" % (NS_JINGLE, NS_S5B))),
    ('c', iq('set', 'ft5',
             "<jingle %s action='session-info' sid='ft-sid'><content "
             "creator='initiator' name='file'><received %s><file><hashes %s>"
             "<hash algo='md5' value='bWQ1'/></hashes></file></received>"
             "<abort %s><file><name>a.txt</name></file></abort>"
             "<checksum %s><file><hashes %s/></file></checksum></content>"
             "</jingle>" % (NS_JINGLE, NS_FT, NS_HASH, NS_FT, NS_FT,
                            NS_HASH))),
    ('c', iq('set', 'ft6',
             "<jingle %s action='transport-info' sid='ft-sid'><content "
             "creator='initiator' name='file'><transport %s block-size="
             "'4096' sid='ibb1' stanza='iq'/></content></jingle>"
             % (NS_JINGLE, NS_IBBT))),
    ('c', iq('set', 'ft7',
             "<jingle %s action='transport-info' sid='ft-sid'><content "
             "creator='initiator' name='file'><transport %s/></content>"
             "</jingle>" % (NS_JINGLE, NS_GTP2P))),
    # Jingle relay nodes
    ('c', iq('get', 'jn1', "<services xmlns='http://jabber.org/protocol/"
             "jinglenodes'/>", to=SRV)),
    ('s', iq('result', 'jn1',
             "<services xmlns='http://jabber.org/protocol/jinglenodes'>"
             "<relay address='192.0.2.50' port='3478' policy='public' "
             "protocol='udp'/><tracker address='192.0.2.51' policy='public' "
             "protocol='tcp'/><stun address='192.0.2.52' port='3478' "
             "policy='public' protocol='udp'/></services>", frm=SRV)),
    ('c', iq('get', 'jn2', "<channel xmlns='http://jabber.org/protocol/"
             "jinglenodes#channel' protocol='udp'/>", to=SRV)),
    ('s', iq('result', 'jn2',
             "<channel xmlns='http://jabber.org/protocol/jinglenodes#channel'"
             " id='ch1' host='192.0.2.50' localport='30000' remoteport="
             "'30001' protocol='udp' maxkbps='100' expire='60'/>", frm=SRV)),
]

GTALK = [
    ('c', iq('set', 'g1',
             "<session %s type='initiate' id='gsid1' initiator='%s'>"
             "<description xmlns='http://www.google.com/session/phone' "
             "xml:lang='en'><payload-type id='103' name='ISAC' clockrate="
             "'16000' bitrate='32000' channels='1' xmlns='http://www.google."
             "com/session/phone'/><payload-type id='97' name='VP8' width="
             "'640' height='480' framerate='30'/></description>"
             "<candidate name='rtp' address='192.0.2.10' port='5000' "
             "preference='1.0' type='local' protocol='udp' network='eth0' "
             "username='u' password='p' generation='0' foundation='f' "
             "component='1'/><transport %s><candidate xmlns='http://www."
             "google.com/transport/p2p' name='rtp' address='192.0.2.10' "
             "port='5000' preference='1' type='stun' protocol='udp' network="
             "'1' username='u' password='p' generation='0' component='1'/>"
             "</transport><conference-info xmlns='urn:x' isfocus='true'/>"
             "</session>" % (NS_GS, ME, NS_GTP2P), to=ROMEO)),
    ('s', iq('result', 'g1', frm=ROMEO)),
    ('s', iq('set', 'g2', "<session %s type='accept' id='gsid1' initiator="
             "'%s'><description xmlns='http://www.google.com/session/phone'>"
             "<payload-type id='0' name='PCMU'/></description></session>"
             % (NS_GS, ME), frm=ROMEO)),
    ('c', iq('set', 'g3', "<session %s type='terminate' id='gsid1' "
             "initiator='%s'><reason><busy/><text>Busy now</text></reason>"
             "</session>" % (NS_GS, ME))),
    ('c', iq('set', 'g4', "<session %s type='terminate' id='gsid1'>"
             "<reason><success/></reason></session>" % NS_GS)),
    ('c', iq('set', 'g5', "<session type='candidates' id='gsid1'/>")),
    ('c', iq('set', 'g6', "<session xmlns='urn:x' type='initiate' "
             "id='other'/>")),
    ('c', iq('set', 'g7', "<session %s type='reject'/>" % NS_GS)),
    # Google jingle info
    ('c', iq('get', 'gji', "<query xmlns='google:jingleinfo'/>", to=SRV)),
    ('s', iq('result', 'gji',
             "<query xmlns='google:jingleinfo'><stun><server host="
             "'stun.example.com' udp='19302'/><server host='stun2' udp="
             "'3478'/></stun><relay><token>tok-abc</token><server host="
             "'relay.example.com' udp='3478' tcp='80' tcpssl='443'/></relay>"
             "</query>", frm=SRV)),
    ('s', iq('result', 'gji2', "<query xmlns='google:jingleinfo'><relay/>"
             "</query>", frm=SRV)),
    # settings
    ('c', iq('get', 'gs1', "<usersetting xmlns='google:setting'/>")),
    ('s', iq('result', 'gs1',
             "<usersetting xmlns='google:setting'><autoacceptrequests "
             "value='true'/><mailnotifications value='false'/><novalue/>"
             "</usersetting>")),
    ('s', iq('result', 'gs2', "<usersetting xmlns='google:setting'/>")),
    # mail notifications
    ('c', iq('get', 'gm1', "<query xmlns='google:mail:notify' "
             "newer-than-time='1700000000000' newer-than-tid='123' "
             "q='is:unread'/>")),
    ('s', iq('result', 'gm1',
             "<mailbox xmlns='google:mail:notify' result-time='1700000001000'"
             " total-matched='2' total-estimate='0' url='https://mail.example"
             ".com/'><mail-thread-info tid='9' participation='1' messages='2'"
             " date='1700000000000' url='https://mail.example.com/t9' "
             "labels='^i|^u'><senders><sender name='Romeo' address="
             "'romeo@example.net' originator='1' unread='1'/><sender "
             "address='x@e.com' unread='0'/></senders><labels>^i</labels>"
             "<subject>Hi</subject><snippet>Hello there</snippet>"
             "</mail-thread-info><mail-thread-info messages='1' date='0' "
             "subject='attr'/></mailbox>")),
    ('s', iq('set', 'gm2', "<new-mail xmlns='google:mail:notify'/>")),
    ('s', iq('set', 'gm3', "<mailbox xmlns='google:mail:notify'/>")),
    # shared status
    ('c', iq('get', 'gst1', "<query xmlns='google:shared-status' "
             "version='2'/>")),
    ('s', iq('result', 'gst1',
             "<query xmlns='google:shared-status' version='2' status-max="
             "'512' status-list-max='5' status-list-contents-max='3' "
             "status-min-ver='2'><status>Working</status><show>dnd</show>"
             "<invisible value='false'/><status-list show='default'>"
             "<status>Busy</status><status>In a meeting</status>"
             "</status-list><status-list show='dnd'><status>Do not disturb"
             "</status></status-list></query>")),
    ('s', iq('result', 'gst2', "<query xmlns='google:shared-status'>"
             "<invisible/></query>")),
]

MUC = [
    ('c', "<presence to='%s/juliet'><x %s><password>cauldron</password>"
          "<history maxchars='65' maxstanzas='20' seconds='180' since="
          "'1970-01-01T00:00:00Z'/></x></presence>" % (ROOM, NS_MUC)),
    ('c', "<presence to='%s/juliet'><x %s/></presence>" % (ROOM, NS_MUC)),
    ('s', "<presence from='%s/romeo' to='%s'><x %s><item affiliation='member'"
          " jid='%s' nick='romeo' role='participant'><reason>Friend</reason>"
          "<actor jid='admin@chat.example.com'/></item><status code='110'/>"
          "<status code='100'/><status/></x></presence>"
          % (ROOM, ME, NS_MUCU, ROMEO)),
    ('s', "<presence from='%s/x' type='unavailable'><x %s><item affiliation="
          "'bogus' role='bogus'/><password>pw</password><invite "
          "from='%s' to='x@e.com'><reason>Join us</reason></invite>"
          "<decline/><destroy/></x></presence>" % (ROOM, NS_MUCU, ME)),
    ('s', "<message from='%s' to='%s' type='groupchat'><x %s><invite from="
          "'%s'><reason>Come in</reason></invite><password>pw</password>"
          "<item jid='%s' role='moderator' affiliation='owner'/><status "
          "code='170'/></x><body>Welcome</body></message>"
          % (ROOM, ME, NS_MUCU, ROMEO, ME)),
    ('c', iq('get', 'mo1', "<query %s/>" % NS_MUCO, to=ROOM)),
    ('s', iq('result', 'mo1',
             "<query %s><x %s type='form'><title>Config</title>"
             "<instructions>Fill in</instructions><instructions>More"
             "</instructions><field var='muc#roomconfig_roomname' "
             "type='text-single' label='Name'><value>Coven</value></field>"
             "<field var='f2' type='boolean'><value>1</value></field>"
             "<field var='f3' type='fixed'/><field var='f4' type='hidden'/>"
             "<field var='f5' type='jid-multi'/><field var='f6' "
             "type='jid-single'/><field var='f7' type='list-multi'>"
             "<option label='A'><value>a</value></option><option>"
             "<value>b</value></option><option/><value>a</value></field>"
             "<field var='f8' type='list-single'/><field var='f9' "
             "type='text-multi'/><field var='f10' type='text-private'/>"
             "<field var='f11' type='odd'/><field/></x></query>"
             % (NS_MUCO, NS_DATA), frm=ROOM)),
    ('c', iq('set', 'mo2', "<query %s><x %s type='submit'/></query>"
             % (NS_MUCO, NS_DATA), to=ROOM)),
    ('c', iq('set', 'mo3', "<query %s><x %s type='bogus'/></query>"
             % (NS_MUCO, NS_DATA), to=ROOM)),
    ('c', iq('get', 'ma1', "<query %s><item affiliation='outcast'/></query>"
             % NS_MUCA, to=ROOM)),
    ('s', iq('result', 'ma1',
             "<query %s><item affiliation='outcast' jid='x@e.com' nick='x' "
             "role='none'><reason>Spam</reason><actor jid='a@e.com'/></item>"
             "<item affiliation='admin' role='visitor'/></query>" % NS_MUCA,
             frm=ROOM)),
    # conference-info (RFC 4575) as a child of iq
    ('s', iq('set', 'ci1',
             "<conference-info %s entity='sip:conf@example.com' state="
             "'full' version='3' sid='sid-9'><conference-description>"
             "<subject>Weekly</subject><display-text>Team</display-text>"
             "<free-text>Free</free-text><maximum-user-count>25"
             "</maximum-user-count><keywords>k</keywords>"
             "</conference-description><conference-state><user-count>2"
             "</user-count><active>true</active><locked>false</locked>"
             "</conference-state><users state='full'><user entity='sip:a@e.com'"
             " state='full'><display-text>A</display-text><cascaded-focus>"
             "no</cascaded-focus><endpoint entity='sip:a@e.com;gruu' "
             "state='full'><display-text>Phone</display-text><status>"
             "connected</status><joining-method>dialed-in</joining-method>"
             "<disconnection-method>departed</disconnection-method>"
             "<media id='1'><display-text>Audio</display-text><type>audio"
             "</type><label>a1</label><src-id>1234</src-id><status>sendrecv"
             "</status></media><media id='2'/><referred/></endpoint>"
             "<endpoint/></user><user/></users><host-info/></conference-info>"
             % NS_CONF, frm=ROOM)),
    ('s', iq('set', 'ci2', "<conference-info state='partial'/>")),
    ('s', iq('set', 'ci3', "<conference-info %s entity='e' state='bogus'/>"
             % NS_CONF)),
]

OTHER = [
    # stream initiation / SI file transfer, feature negotiation, x:data
    ('c', iq('set', 'si1',
             "<si xmlns='http://jabber.org/protocol/si' id='a0' mime-type="
             "'text/plain' profile='http://jabber.org/protocol/si/profile/"
             "file-transfer'><file xmlns='http://jabber.org/protocol/si/"
             "profile/file-transfer' name='test.txt' size='1022' date="
             "'1969-07-21T02:56:15Z' hash='552da749930852c69ae5d2141d3766b1'>"
             "<desc>This is a test.</desc><range offset='0' length='1022'/>"
             "</file><feature xmlns='http://jabber.org/protocol/feature-neg'>"
             "<x %s type='form'><field var='stream-method' "
             "type='list-single'><option><value>http://jabber.org/protocol/"
             "bytestreams</value></option><option><value>http://jabber.org/"
             "protocol/ibb</value></option></field></x></feature></si>"
             % NS_DATA, to=ROMEO, frm=ME)),
    ('s', iq('result', 'si1',
             "<si xmlns='http://jabber.org/protocol/si'><feature xmlns="
             "'http://jabber.org/protocol/feature-neg'><x %s type='submit'>"
             "<field var='stream-method'><value>http://jabber.org/protocol/"
             "bytestreams</value></field></x></feature></si>" % NS_DATA,
             frm=ROMEO, to=ME)),
    ('c', iq('set', 'si2', "<si xmlns='http://jabber.org/protocol/si'>"
             "<file name='n' size='1'/><file xmlns='x'/><feature/></si>")),
    # SOCKS5 bytestreams
    ('c', iq('set', 'bs1',
             "<query %s sid='a0' mode='tcp' dstaddr='ab12'><streamhost jid="
             "'%s' host='192.0.2.1' port='5086'/><streamhost jid='proxy.e.com'"
             " host='192.0.2.2'/><streamhost/></query>" % (NS_BS, ME),
             to=ROMEO)),
    ('s', iq('result', 'bs1', "<query %s><streamhost-used jid='%s'/></query>"
             % (NS_BS, ME), frm=ROMEO)),
    ('c', iq('set', 'bs2', "<query %s sid='a0' mode='udp'><activate>"
             "romeo@example.net/orchard</activate><udpsuccess dstaddr='ab12'/>"
             "</query>" % NS_BS)),
    ('c', iq('set', 'bs3', "<query %s mode='bogus'><streamhost-used/>"
             "<activate/><udpsuccess/></query>" % NS_BS)),
    # in-band bytestreams
    ('c', iq('set', 'ibb1', "<open %s sid='ibb-1' block-size='4096' "
             "stanza='iq'/>" % NS_IBB, to=ROMEO)),
    ('s', iq('result', 'ibb1', frm=ROMEO)),
    ('c', iq('set', 'ibb2', "<data %s sid='ibb-1' seq='0'>QUJDREVGR0g=</data>"
             % NS_IBB, to=ROMEO)),
    ('c', iq('set', 'ibb3', "<data %s sid='ibb-1' seq='1'/>" % NS_IBB)),
    ('c', "<message to='%s' id='ibb4'><data %s sid='ibb-2' seq='0'>QUJD</data>"
          "</message>" % (ROMEO, NS_IBB)),
    ('c', "<message to='%s' id='ibb5'><data %s sid='ibb-2' seq='1'>QUJD</data>"
          "</message>" % (ROMEO, NS_IBB)),
    ('c', iq('set', 'ibb6', "<open %s sid='ibb-3' block-size='1' stanza="
             "'presence'/>" % NS_IBB)),
    ('c', iq('set', 'ibb7', "<close %s sid='ibb-1'/>" % NS_IBB, to=ROMEO)),
    ('s', iq('result', 'ibb7', frm=ROMEO)),
    ('c', iq('set', 'ibb8', "<close xmlns='http://jabber.org/protocol/ibb'/>")),
    # delayed delivery on a message
    ('s', "<message from='%s' type='chat'><body>old</body><x xmlns='jabber:x:"
          "delay' stamp='20020910T23:08:25' from='%s'>Offline</x></message>"
          % (ROMEO, SRV)),
    # unknown attributes, unknown nested elements at several depths
    ('c', iq('get', 'u1', "<query %s odd='1'><extra a='b' xmlns:p='urn:p'>"
             "<p:inner>text</p:inner></extra></query>" % NS_DISCO_INFO,
             extra=" foo='bar' xmlns:q='urn:q'")),
    # a prefixed default namespace on a stanza child
    ('c', iq('get', 'u2', "<ns:thing xmlns:ns='urn:ns'><ns:sub>t</ns:sub>"
             "</ns:thing>")),
]


def nest(n, name='a'):
    return "<%s>" % name * n + "</%s>" % name * n


# Unknown elements nested to just under the limit of 20 levels, and the
# elements at the limit of the XML-to-XMPP conversion (not reachable as an
# unknown chain: see README)
LIMITS_OK = [
    ('c', "<iq type='get' id='deep19'>%s</iq>" % nest(19)),
    ('c', "<iq type='get' id='deep5'>%s</iq>" % nest(5)),
]


def play(cap, cport, script, sport=5222):
    """Send the script over one TCP connection to sport."""
    c = Tcp(cap, cport, sport)
    buf = ''
    for d, text in script:
        if d.endswith('+'):
            buf += text
            continue
        send = c.c if d == 'c' else c.s
        if isinstance(text, tuple):
            for part in text:
                send((buf + part).encode())
                buf = ''
        else:
            send((buf + text).encode())
            buf = ''


def build_main():
    cap = Cap()
    play(cap, 50001, LOGIN)
    play(cap, 50002, STARTTLS)
    play(cap, 50003, PROCEED_ONLY)
    play(cap, 50004, JINGLE)
    play(cap, 50005, GTALK)
    play(cap, 50006, MUC)
    play(cap, 50007, OTHER)
    play(cap, 50008, LIMITS_OK)
    play(cap, 50001 + 100, STREAM_END)
    return cap


def build_malformed():
    cap = Cap()
    s = []
    # XMPP element nesting past the limits
    for n in (20, 21, 25):
        s.append(('c', "<iq type='get' id='d%d'>%s</iq>" % (n, nest(n))))
    for n in (64, 65, 66, 100, 600):
        s.append(('c', "<iq type='get' id='n%d'>%s</iq>" % (n, nest(n))))
    s.append(('c', "<message to='a@e.com'>%s</message>" % nest(30, 'x')))
    s.append(('c', "<presence>%s</presence>" % nest(70, 'y')))
    # nesting past the limit inside a known child
    s.append(('c', "<iq type='get' id='k1'><query xmlns='jabber:iq:roster'>"
                   "<item jid='a@e.com'>%s</item></query></iq>" % nest(25)))
    # tags that are not closed or not opened
    s.append(('c', "</iq>"))
    s.append(('c', "<iq type='get' id='u1'></message></iq>"))
    s.append(('c', "<iq type='get' id='u2'><query></iq>"))
    # unrecognized text and odd tokens
    s.append(('c', "<message to='a@e.com'><body>1 < 2</body></message>"))
    s.append(('c', "<presence/><<>"))
    # elements with empty names or odd attribute syntax
    s.append(('c', "<iq type= id='x'/>"))
    s.append(('c', "<iq type='get' id='x' ='y'/>"))
    # an XML declaration with another encoding: XMPP uses offsets of the
    # re-encoded text against the raw bytes
    s.append(('c', "<?xml version='1.0' encoding='ISO-8859-1'?><message "
                   "to='a@e.com'><body>caf\u00e9 caf\u00e9 caf\u00e9"
                   "</body><subject>x</subject></message>"))
    s.append(('c', "<?xml version='1.0' encoding='windows-1252'?><iq "
                   "type='get' id='w1'><query xmlns='jabber:iq:roster'>"
                   "<item jid='\u20ac\u20ac\u20ac@e.com'/></query></iq>"))
    play(cap, 51001, [(d, t.encode('latin-1', 'replace')
                       .decode('latin-1')) for d, t in s])
    # UTF-16 stanzas (BOM and no BOM); the bytes are not UTF-8
    c = Tcp(cap, 51002, 5222)
    c.c(b'\xff\xfe' + "<presence to='a@e.com'><status>x</status></presence>"
        .encode('utf-16-le'))
    c.c(b'\xfe\xff' + "<presence to='a@e.com'><status>x</status></presence>"
        .encode('utf-16-be'))
    c.c(b'\xff\xfe')
    c.c(b'<')
    c.c(b'>')
    # a stream end after text, an empty stanza name
    c.c(b"<presence/>\xff\xfe\xfd>")
    return cap


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    os.makedirs(out, exist_ok=True)
    m = build_main()
    m.write(os.path.join(out, 'xmpp-coverage.pcap'))
    bad = build_malformed()
    bad.write(os.path.join(out, 'xmpp-coverage-malformed.pcap'))
    print('xmpp-coverage.pcap: %d frames, malformed: %d frames'
          % (len(m.frames), len(bad.frames)))


if __name__ == '__main__':
    main()
