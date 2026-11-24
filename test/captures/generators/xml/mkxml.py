#!/usr/bin/env python3
# Generates test/captures/xml_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the XML coverage captures.  Usage: mkxml.py <outdir>

Writes xml-coverage.pcap (main capture), xml-coverage-malformed.pcap
(paths only malformed input reaches), xml-file.xml (an XML file for the
wtap_file heuristic) and the DTD files used by runcov.sh.  Everything is
built with struct; nothing comes from a real network.
"""
import base64
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


def b64(b):
    return base64.b64encode(b).decode()


def der(tag, body):
    n = len(body)
    if n < 0x80:
        ln = bytes([n])
    elif n < 0x100:
        ln = b'\x81' + bytes([n])
    else:
        ln = b'\x82' + struct.pack('!H', n)
    return bytes([tag]) + ln + body


def der_int(v):
    return der(0x02, bytes([v]))


def krb_ap_req():
    """A GSS-API KRB5 AP-REQ token with opaque (not encrypted) enc-parts."""
    def ctx(n, body):
        return der(0xa0 + n, body)

    def gstr(s):
        return der(0x1b, s)

    def encdata(etype, kvno, cipher):
        return der(0x30, ctx(0, der_int(etype)) + ctx(1, der_int(kvno)) +
                   ctx(2, der(0x04, cipher)))
    sname = der(0x30, ctx(0, der_int(1)) +
                ctx(1, der(0x30, gstr(b'HTTP') + gstr(b'host.example.com'))))
    ticket = der(0x61, der(0x30, ctx(0, der_int(5)) +
                           ctx(1, gstr(b'EXAMPLE.COM')) + ctx(2, sname) +
                           ctx(3, encdata(18, 2, b'T' * 40))))
    apreq = der(0x6e, der(0x30, ctx(0, der_int(5)) + ctx(1, der_int(14)) +
                          ctx(2, der(0x03, b'\x00\x00\x00\x00\x00')) +
                          ctx(3, ticket) + ctx(4, encdata(18, 0, b'A' * 30))))
    oid = bytes.fromhex('06092a864886f712010202')
    return der(0x60, oid + b'\x01\x00' + apreq)


# --------------------------------------------------------------------
# Documents
# --------------------------------------------------------------------

# Plain documents sent to UDP port 3702 (WS-Discovery's port; the XML
# dissector's default).
UDP_DOCS = [
    # 0: a bit of everything
    b'<?xml version="1.0" encoding="UTF-8"?>\n'
    b'<root a="1" b=\'two\' c=3 d=name-value>\n'
    b'  <child x="y">text</child>\n'
    b'  <!-- a comment -->\n'
    b'  <![CDATA[ raw <data> ]]>\n'
    b'  <empty/>\n'
    b'  <empty2 attr="v" />\n'
    b'  <deep><deeper><deepest k="v">z</deepest></deeper></deep>\n'
    b'</root>',
    # 1: processing instructions
    b'<?xml version="1.0" standalone="yes"?><?xml-stylesheet href="a.xsl" '
    b'type="text/xsl"?><?bare?><?target data1="1" data2="2"?><doc/>',
    # 2: DOCTYPE with PUBLIC and SYSTEM identifiers
    b'<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0//EN" '
    b'"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd"><html><body>'
    b'<p class="x">hello</p></body></html>',
    b'<!doctype note SYSTEM "Note.dtd"><note><to>A</to></note>',
    # 4: DOCTYPE with an internal subset
    b'<!DOCTYPE memo [\n<!ELEMENT memo (to,body)>\n<!ELEMENT to (#PCDATA)>\n'
    b'<!ATTLIST memo id CDATA #REQUIRED>\n]>\n<memo id="7"><to>Bob</to>'
    b'<body>hi</body></memo>',
    # 5: scoped names, known and unknown prefixes
    b'<ns:top ns:attr="v" xmlns:ns="urn:x"><ns:inner>t</ns:inner>'
    b'<other:thing a="b"/></ns:top>',
    # 6: unrecognized text (a lone '<' that starts no token)
    b'<a>5 < 6 and <b>ok</b></a>',
    # 7: RSS (DTD with a hierarchy) with iTunes and Dublin Core elements
    b'<?xml version="1.0"?><rss version="2.0" '
    b'xmlns:itunes="http://www.itunes.com/dtds/podcast-1.0.dtd" '
    b'xmlns:dc="http://purl.org/dc/elements/1.1/"><channel>'
    b'<title>Feed</title><link>http://example.com/</link>'
    b'<description>Test</description><language>en</language>'
    b'<pubDate>Mon, 01 Jan 2024 00:00:00 GMT</pubDate>'
    b'<itunes:author>Me</itunes:author><itunes:category text="Tech"/>'
    b'<itunes:explicit>no</itunes:explicit>'
    b'<dc:creator>Me</dc:creator><dc:title>T</dc:title>'
    b'<dc:nothere>x</dc:nothere><image><url>http://e/i.png</url>'
    b'<title>I</title><width>1</width></image>'
    b'<item><title>One</title><guid isPermaLink="false">1</guid>'
    b'<enclosure url="http://e/a.mp3" length="1" type="audio/mpeg"/>'
    b'<category domain="d">c</category><unknowntag>u</unknowntag></item>'
    b'</channel></rss>',
    # 8: RSS child that the DTD does not define under the parent
    b'<rss version="2.0"><channel><title>x</title><width>3</width>'
    b'<item><title>y</title><bogus a="b"/></item></channel></rss>',
    # 9: reginfo, watcherinfo, list (RLMI), xcap-caps, xcap-error, poc-settings
    b'<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="0" '
    b'state="full"><registration aor="sip:a@example.com" id="r" '
    b'state="active"><contact id="c" state="active" event="registered">'
    b'<uri>sip:a@192.0.2.1</uri><display-name lang="en">A</display-name>'
    b'<unknown-param name="p">v</unknown-param></contact></registration>'
    b'</reginfo>',
    b'<watcherinfo xmlns="urn:ietf:params:xml:ns:watcherinfo" version="1" '
    b'state="full"><watcher-list resource="sip:a@e.com" package="presence">'
    b'<watcher status="active" id="w" event="subscribe">sip:b@e.com'
    b'</watcher></watcher-list></watcherinfo>',
    b'<list xmlns="urn:ietf:params:xml:ns:rlmi" uri="sip:l@e.com" '
    b'version="1" fullState="true"><name lang="en">L</name>'
    b'<resource uri="sip:r@e.com"><name lang="en">R</name>'
    b'<instance id="1" state="active"/></resource></list>',
    b'<xcap-caps xmlns="urn:ietf:params:xml:ns:xcap-caps"><auids>'
    b'<auid>resource-lists</auid></auids><extensions/><namespaces>'
    b'<namespace>urn:x</namespace></namespaces></xcap-caps>',
    b'<xcap-error xmlns="urn:ietf:params:xml:ns:xcap-error">'
    b'<no-parent phrase="p"><ancestor>http://e/x</ancestor></no-parent>'
    b'</xcap-error>',
    b'<poc-settings xmlns="urn:oma:xml:poc:poc-settings"><entity id="e">'
    b'<isb-settings/></entity></poc-settings>',
    # 15: the Kerberos-related WS-Security elements without keys.  The
    # DerivedKeyToken has no matching key; CipherValue has no matching
    # key, a KeyInfo without a Reference, and nothing at all.
    b'<Envelope><Header><Security>'
    b'<DerivedKeyToken Algorithm="x" u:Id="_1"><Nonce>QUJDREVGR0hJSktMTU5PUA==</Nonce>'
    b'</DerivedKeyToken>'
    b'<DerivedKeyToken u:Id="_2"><Label>x</Label></DerivedKeyToken>'
    b'<DerivedKeyToken><Nonce>QUJD</Nonce></DerivedKeyToken>'
    b'<EncryptedData><KeyInfo><SecurityTokenReference><Reference '
    b'URI="#_1"/></SecurityTokenReference></KeyInfo><CipherData>'
    b'<CipherValue>QUJDREVGR0hJSktMTU5PUA==</CipherValue></CipherData>'
    b'</EncryptedData>'
    b'<EncryptedData><KeyInfo><SecurityTokenReference/></KeyInfo>'
    b'<CipherData><CipherValue>QUJD</CipherValue></CipherData>'
    b'</EncryptedData>'
    b'<EncryptedData><KeyInfo/><CipherData><CipherValue>QUJD</CipherValue>'
    b'</CipherData></EncryptedData>'
    b'<EncryptedData><CipherData><CipherValue/></CipherData></EncryptedData>'
    b'<EncryptedData><KeyInfo><SecurityTokenReference><Reference/>'
    b'</SecurityTokenReference></KeyInfo><CipherData>'
    b'<CipherValue>QUJD</CipherValue></CipherData></EncryptedData>'
    b'</Security></Header><Body/></Envelope>',
    # 16: BinarySecurityToken without and with the Kerberos ValueType
    b'<Security><BinarySecurityToken ValueType="http://example.com/other" '
    b'EncodingType="Base64Binary">Zm9v</BinarySecurityToken>'
    b'<BinarySecurityToken>Zm9v</BinarySecurityToken>'
    b'<BinarySecurityToken EncodingType="Base64Binary" ValueType='
    b'"http://docs.oasis-open.org/wss/'
    b'oasis-wss-kerberos-token-profile-1.1#GSS_Kerberosv5_AP_REQ">'
    + b64(krb_ap_req()).encode()
    + b'</BinarySecurityToken><BinarySecurityToken ValueType="http://docs.'
    b'oasis-open.org/wss/oasis-wss-kerberos-token-profile-1.1#'
    b'GSS_Kerberosv5_AP_REQ"/></Security>',
    # 17: reproducer of "XML: Fix a NULL dereference for a top-level
    # CipherValue" (a CipherValue directly under the root)
    b'<CipherValue>QUJD</CipherValue>',
    # 18: attribute names with dots, dashes, underscores, colons, digits
    b'<A.b-c_d x.y="1" x-y="2" x_y="3" xml:lang="en" n1="42"/>',
    # 19: odd but valid layout: nested comments, empty CDATA, text at the
    # top level and after the root
    b'before<!----><![CDATA[]]><r>mixed <b>bold</b> text</r>after',
    # 20: a document without XML declaration, only whitespace between tags
    b'\r\n\t <a>\r\n <b/>\r\n</a>\r\n',
    # 21: tags inside the internal subset of a DOCTYPE (no namespace)
    b'<!DOCTYPE d [ <a b="1"/> <c>x</c> ]><d/>',
]

# Documents with an encoding declaration (the encoding is not UTF-8) sent
# as separate datagrams to UDP 3702.
ENC_DOCS = [
    b'<?xml version="1.0" encoding="ISO-8859-1"?><a>caf\xe9</a>',
    b'<?xml version="1.0" encoding="US-ASCII"?><a>plain</a>',
    b'<?xml version="1.0" encoding="no-such-charset"?><a>unknown</a>',
    b'<?xml version="1.0" encoding="windows-1252"?><a>\x80 euro</a>',
    b'<?xml version="1.0" encoding="UTF-8"?><a>\xc3\xa9\xe2\x82\xac</a>',
    b'\xef\xbb\xbf<?xml version="1.0" encoding="UTF-8"?><a>bom</a>',
    # UTF-16 with BOMs (no encoding attribute possible to match)
    b'\xfe\xff' + '<a b="1">utf16be é</a>'.encode('utf-16-be'),
    b'\xff\xfe' + '<a b="1">utf16le é</a>'.encode('utf-16-le'),
]

# HTTP bodies: (media type, body).  Media types with their own DTD or with
# no DTD at all, and suffix types.
HTTP_BODIES = [
    ('text/xml', b'<?xml version="1.0"?><soap><item id="1">one</item></soap>'),
    ('application/soap+xml',
     b'<Envelope xmlns="http://www.w3.org/2003/05/soap-envelope"><Body/>'
     b'</Envelope>'),
    ('application/cpim-pidf+xml',
     b'<?xml version="1.0"?><presence xmlns="urn:ietf:params:xml:ns:cpim-pidf"'
     b' entity="pres:a@e.com"><tuple id="t1"><status><basic>open</basic>'
     b'</status><contact priority="0.8">im:a@e.com</contact>'
     b'<note lang="en">hi</note><timestamp>2024-01-01T00:00:00Z</timestamp>'
     b'<extra x="y"/></tuple></presence>'),
    ('application/mediaservercontrol+xml',
     b'<?xml version="1.0"?><MediaServerControl version="1.0"><request>'
     b'<configure_conference reservedtalkers="2" reservedlisteners="1"/>'
     b'<play id="p1"><prompt baseurl="http://e/"><audio url="a.wav"/>'
     b'</prompt></play></request></MediaServerControl>'),
    ('application/smil',
     b'<smil><head><layout><root-layout width="10" height="10"/>'
     b'<region id="r" width="5"/></layout></head><body><par>'
     b'<img src="a.png" region="r" dur="3s"/><audio src="a.wav"/>'
     b'</par></body></smil>'),
    ('application/atom+xml', b'<feed><entry><title>t</title></entry></feed>'),
    ('application/vnd.example+xml', b'<x/>'),
    ('image/svg+xml', b'<svg width="1"><rect x="0"/></svg>'),
]


def http_req(path, ctype, body):
    return (b'POST %s HTTP/1.1\r\nHost: example.com\r\nContent-Type: %s\r\n'
            b'Content-Length: %d\r\n\r\n' % (path.encode(), ctype.encode(),
                                             len(body))) + body


def http_resp(ctype, body):
    return (b'HTTP/1.1 200 OK\r\nContent-Type: %s\r\nContent-Length: %d\r\n'
            b'\r\n' % (ctype.encode(), len(body))) + body


def build_main():
    cap = Cap()
    # 1: plain documents on UDP 3702
    for i, d in enumerate(UDP_DOCS):
        cap.add(eth(udp(40000 + i, 3702, d)))
    for i, d in enumerate(ENC_DOCS):
        cap.add(eth(udp(41000 + i, 3702, d)))
    # 2: HTTP on TCP 80, one connection per media type
    for i, (ct, body) in enumerate(HTTP_BODIES):
        c = Tcp(cap, 42000 + i, 80)
        c.c(http_req('/x', ct, body))
        c.s(http_resp(ct, body))
    # 3: XML bodies with a media type the dissector does not know; they are
    # XML only through the heuristic dissectors (disabled by default), plus
    # the same over plain TCP and UDP ports
    xml = b'<?xml version="1.0"?><heur a="1"><x>y</x></heur>'
    c = Tcp(cap, 43000, 80)
    c.c(http_req('/h', 'application/x-unknown', xml))
    c.s(http_resp('application/x-unknown', xml))
    sip = (b'MESSAGE sip:b@example.com SIP/2.0\r\nVia: SIP/2.0/UDP '
           b'192.0.2.1:5060;branch=z9hG4bK1\r\nFrom: <sip:a@example.com>;'
           b'tag=1\r\nTo: <sip:b@example.com>\r\nCall-ID: xml1@192.0.2.1\r\n'
           b'CSeq: 1 MESSAGE\r\nContent-Type: application/x-unknown\r\n'
           b'Content-Length: %d\r\n\r\n' % len(xml)) + xml
    cap.add(eth(udp(5060, 5060, sip)))
    sip2 = sip.replace(b'application/x-unknown', b'application/pidf+xml')
    sip2 = sip2.replace(b'xml1@', b'xml2@')
    cap.add(eth(udp(5060, 5060, sip2)))
    c = Tcp(cap, 43001, 9999)
    c.c(xml)
    cap.add(eth(udp(43002, 9999, xml)))
    # UCS-2 little endian without BOM, found by the heuristic with the
    # "heuristic_unicode" preference
    cap.add(eth(udp(43003, 9998, xml.decode().encode('utf-16-le'))))
    # the same with byte order marks
    cap.add(eth(udp(43004, 9998, b'\xfe\xff' +
                    xml.decode().encode('utf-16-be'))))
    cap.add(eth(udp(43005, 9998, b'\xff\xfe' +
                    xml.decode().encode('utf-16-le'))))
    return cap


def build_malformed():
    cap = Cap()
    docs = [
        # closing tags without opening tags (error expert infos)
        b'</a>',
        b'<a/></b></c>',
        b'<a></a></a>',
        # "]>" without a DOCTYPE
        b'<a/>]>',
        # an unterminated tag, comment, CDATA section, PI and DOCTYPE
        b'<a b="1',
        b'<a><!-- never closed',
        b'<a><![CDATA[ never closed',
        b'<?xml version="1.0"',
        b'<!DOCTYPE x [ <!ELEMENT a (b)>',
        # a tag with an unterminated attribute list and stray characters
        b'<a b=>text</a>',
        b'<a b="1" c>x</a>',
        b'<a =1/>',
        b'<<a>>',
        b'<>',
        b'<a><</a>',
        b'<!- not a comment ->',
        # a CipherValue directly under the root with a KeyInfo sibling
        b'<CipherValue>QUJD</CipherValue></CipherValue>',
        # bad base64
        b'<Envelope><Security><BinarySecurityToken ValueType="http://docs.'
        b'oasis-open.org/wss/oasis-wss-kerberos-token-profile-1.1#'
        b'GSS_Kerberosv5_AP_REQ">!!!not base64!!!</BinarySecurityToken>'
        b'</Security></Envelope>',
        # nesting deeper than the tree depth limit: exceptions
        b'<a>' * 520 + b'</a>' * 520,
        # a one byte datagram
        b'<',
        # UTF-16 BOM, then a truncated character
        b'\xfe\xff<\x00',
        b'\xff\xfe<',
        # odd encodings that are not valid in the declared charset
        b'<?xml version="1.0" encoding="UTF-8"?><a>\xff\xfe\xfd</a>',
        b'<?xml version="1.0" encoding="UTF-16"?><a>x</a>',
    ]
    for i, d in enumerate(docs):
        cap.add(eth(udp(44000 + i, 3702, d)))
    return cap


def build_dtd():
    """Documents for the DTDs of runcov.sh (a profile with its own dtds
    directory); not part of the committed capture."""
    cap = Cap()
    docs = [
        b'<top id="1"><a x="1" y="2"><b>t<c/><a x="3"/></b></a><c/></top>',
        b'<fa k="1"><fb>t</fb></fa>',
        b'<npa k="1"><npb>t</npb></npa>',
        b'<nha><nhb>t</nhb><nha><nhb>u</nhb></nha></nha>',
        b'<inroot><ina>t</ina></inroot>',
        b'<ua><ub><missing/></ub></ua>',
        b'<nr1><nr2>t</nr2></nr1>',
        b'<nopi><nopichild>t</nopichild></nopi>',
        b'<manyroot><mc1/><mc299/></manyroot>',
        b'<ch1><ch2><ch3>x</ch3></ch2></ch1>',
    ]
    for i, d in enumerate(docs):
        cap.add(eth(udp(45000 + i, 3702, d)))
    body = b'<top id="1"><a x="1"/></top>'
    c = Tcp(cap, 45100, 80)
    c.c(http_req('/g', 'application/x-goodh+xml', body))
    c.s(http_resp('application/x-goodh+xml', body))
    return cap


XML_FILE = (b'<?xml version="1.0" encoding="UTF-8"?>\n<catalog>\n'
            b'  <book id="1"><title>A</title></book>\n'
            b'  <book id="2"><title>B</title></book>\n</catalog>\n')

# DTDs for runcov.sh: a valid one with a hierarchy, one that is flat, one
# that introduces a protocol with a media type, and invalid ones.
DTDS = {
    'good-hier.dtd': b"""<?wireshark-protocol proto_name="goodh" root="top"
   media="application/x-goodh+xml" description="Good hierarchy DTD"
   hierarchy="yes" ?>
<!ELEMENT top (a|b|c)*>
<!ATTLIST top id CDATA #REQUIRED>
<!ELEMENT a (b)*>
<!ATTLIST a x CDATA #IMPLIED y CDATA #IMPLIED>
<!ELEMENT b (#PCDATA|a|c)*>
<!ELEMENT c EMPTY>
""",
    'good-flat.dtd': b"""<?wireshark-protocol proto_name="goodf" description="Flat" ?>
<!ELEMENT fa (fb)*>
<!ATTLIST fa k CDATA #IMPLIED>
<!ELEMENT fb (#PCDATA)>
""",
    'no-proto-name.dtd': b"""<!ELEMENT npa (npb)*>
<!ATTLIST npa k CDATA #IMPLIED>
<!ELEMENT npb (#PCDATA)>
""",
    'no-proto-hier.dtd': b"""<?wireshark-protocol hierarchy="yes" ?>
<!ELEMENT nha (nhb|nha)*>
<!ELEMENT nhb (#PCDATA)>
""",
    'undefined-child.dtd': b"""<?wireshark-protocol proto_name="undef" hierarchy="yes" ?>
<!ELEMENT ua (ub)>
<!ELEMENT ub (missing)>
""",
    'no-such-root.dtd': b"""<?wireshark-protocol proto_name="noroot" root="nosuchroot" hierarchy="yes" ?>
<!ELEMENT nr1 (nr2)*>
<!ELEMENT nr2 (#PCDATA)>
""",
    'duplicate.dtd': b"""<?wireshark-protocol proto_name="dup" ?>
<!ELEMENT da (#PCDATA)>
<!ELEMENT da (#PCDATA)>
""",
    'attr-no-element.dtd': b"""<?wireshark-protocol proto_name="ane" ?>
<!ELEMENT ea (#PCDATA)>
<!ATTLIST nosuch q CDATA #IMPLIED>
""",
    'broken.dtd': b"""<?wireshark-protocol proto_name="brk" ?>
<!ELEMENT ba (#PCDATA
<!ATTLIST
""",
    # declarations followed by a syntax error: the parsed lists are freed
    'broken-with-decls.dtd': b"""<?wireshark-protocol proto_name="brk2" ?>
<!ELEMENT bwa (bwb)*>
<!ATTLIST bwa x CDATA #IMPLIED>
<!ELEMENT bwb (#PCDATA)>
<!ELEMENT bwc (#PCDATA
""",
    'internal.dtd': b"""<?wireshark-protocol proto_name="internal" ?>
<!DOCTYPE inroot [
<!ELEMENT inroot (ina)*>
<!ELEMENT ina (#PCDATA)>
]>
""",
    'internal-no-pi.dtd': b"""<!DOCTYPE nopi [
<!ELEMENT nopi (nopichild)*>
<!ELEMENT nopichild (#PCDATA)>
]>
""",
    # more than 256 potential children: the list is truncated
    'many-children.dtd': (b'<?wireshark-protocol proto_name="many" ?>\n'
                          b'<!ELEMENT manyroot (' +
                          b'|'.join(b'mc%d' % i for i in range(300)) +
                          b')*>\n' +
                          b''.join(b'<!ELEMENT mc%d EMPTY>\n' % i
                                   for i in range(300))),
    # a chain of 510 distinct elements: deeper than the tree depth limit
    # (500; DTDs are read before the preferences, so only the default counts)
    'chain.dtd': (b'<?wireshark-protocol proto_name="chain" hierarchy="yes" '
                  b'?>\n' +
                  b''.join(b'<!ELEMENT ch%d (ch%d)>\n' % (i, i + 1)
                           for i in range(1, 510)) +
                  b'<!ELEMENT ch510 (#PCDATA)>\n'),
}


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    os.makedirs(out, exist_ok=True)
    main_cap = build_main()
    main_cap.write(os.path.join(out, 'xml-coverage.pcap'))
    bad = build_malformed()
    bad.write(os.path.join(out, 'xml-coverage-malformed.pcap'))
    dtd_cap = build_dtd()
    dtd_cap.write(os.path.join(out, 'xml-coverage-dtd.pcap'))
    with open(os.path.join(out, 'xml-file.xml'), 'wb') as f:
        f.write(XML_FILE)
    d = os.path.join(out, 'dtds')
    os.makedirs(d, exist_ok=True)
    for name, body in DTDS.items():
        with open(os.path.join(d, name), 'wb') as f:
            f.write(body)
    print('xml-coverage.pcap: %d frames, malformed: %d frames'
          % (len(main_cap.frames), len(bad.frames)))


if __name__ == '__main__':
    main()
