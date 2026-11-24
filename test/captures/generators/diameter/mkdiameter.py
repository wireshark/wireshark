#!/usr/bin/env python3
# Generates test/captures/diameter_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Build the synthetic Diameter coverage captures (packet-diameter.c and
# packet-diameter_3gpp.c).  Every packet is built here with struct; nothing
# comes from a real network.  Addresses are from the documentation ranges.
#
# Usage: mkdiameter.py <outdir>
#   writes diameter-coverage.pcapng and diameter-coverage-malformed.pcapng
import os
import struct
import sys

# ---------------------------------------------------------------------------
# Diameter encoding

V3GPP, V3GPP2, VERICSSON, VVERIZON, VSTARENT = 10415, 5535, 193, 12951, 8164

def u32(v): return struct.pack('>I', v)
def i32(v): return struct.pack('>i', v)
def u64(v): return struct.pack('>Q', v)
def i64(v): return struct.pack('>q', v)
def f32(v): return struct.pack('>f', v)
def f64(v): return struct.pack('>d', v)

def avp(code, data=b'', vendor=None, flags=0x40, length=None, pad=None):
    """One AVP; flags 0x40 = M.  The V bit is set when vendor is given."""
    if isinstance(data, str):
        data = data.encode()
    if isinstance(data, (list, tuple)):
        data = b''.join(data)
    hdr = 12 if vendor is not None else 8
    if vendor is not None:
        flags |= 0x80
    if length is None:
        length = hdr + len(data)
    b = struct.pack('>II', code, (flags << 24) | length)
    if vendor is not None:
        b += u32(vendor)
    b += data
    if pad is None:
        pad = b'\0' * ((-len(b)) % 4)
    return b + pad

def g(code, *avps, vendor=None, flags=0x40):
    return avp(code, b''.join(avps), vendor=vendor, flags=flags)

def tg(code, data=b'', **kw):
    """3GPP vendor AVP."""
    return avp(code, data, vendor=V3GPP, **kw)

def diameter(cmd, appid, avps, request=True, hbh=1, e2e=1, flags=None,
             version=1, length=None):
    if isinstance(avps, (list, tuple)):
        avps = b''.join(avps)
    if flags is None:
        flags = 0xc0 if request else 0x40     # R+P / P
    if length is None:
        length = 20 + len(avps)
    return struct.pack('>I', (version << 24) | length) + \
        struct.pack('>I', (flags << 24) | cmd) + \
        struct.pack('>III', appid, hbh, e2e) + avps

def tbcd(digits):
    if len(digits) % 2:
        digits += 'F'
    return bytes(int(digits[i + 1], 16) << 4 | int(digits[i], 16)
                 for i in range(0, len(digits), 2))

def plmn(mcc, mnc):
    """3 octet PLMN id (TS 24.008)."""
    if len(mnc) == 2:
        mnc += 'F'
    return bytes([int(mcc[1]) << 4 | int(mcc[0]),
                  int(mnc[2], 16) << 4 | int(mcc[2]),
                  int(mnc[1]) << 4 | int(mnc[0])])

def gsm7(text):
    bits, nbits, out = 0, 0, bytearray()
    for ch in text.encode():
        bits |= (ch & 0x7f) << nbits
        nbits += 7
        while nbits >= 8:
            out.append(bits & 0xff)
            bits >>= 8
            nbits -= 8
    if nbits:
        out.append(bits & 0xff)
    return bytes(out)

# Common AVPs
def SID(s): return avp(263, s)
OHOST_C = avp(264, 'mme.example.net')
OREALM_C = avp(296, 'example.net')
OHOST_S = avp(264, 'hss.example.net')
OREALM_S = avp(296, 'example.net')
DREALM = avp(283, 'example.net')
DHOST = avp(293, 'hss.example.net')
ASS = avp(277, i32(1))                      # Auth-Session-State NO_STATE_MAINTAINED
RC_OK = avp(268, u32(2001))

def VSAI(appid, auth=True):
    return g(260, avp(266, u32(V3GPP)), avp(258 if auth else 259, u32(appid)))

def supported_features(flid, fl):
    return tg(628, [avp(266, u32(V3GPP)), tg(629, u32(flid)), tg(630, u32(fl))])

# ---------------------------------------------------------------------------
# Link layers

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def crc32c(data):
    crc = 0xffffffff
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
    return crc ^ 0xffffffff

MAC = {1: bytes.fromhex('020000000001'), 2: bytes.fromhex('020000000002')}

def ipv4(src, dst, proto, payload, ident=1):
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident & 0xffff, 0x4000,
                     64, proto, 0, bytes(src), bytes(dst))
    return ip[:10] + struct.pack('>H', csum(ip)) + ip[12:] + payload

def eth(payload, src_mac, dst_mac, etype=0x0800):
    return dst_mac + src_mac + struct.pack('>H', etype) + payload

class TcpFlow:
    def __init__(self, cip, sip, cport, sport):
        self.ip = {0: cip, 1: sip}
        self.port = {0: cport, 1: sport}
        self.seq = {0: 1000, 1: 50000}
        self.ident = 1

    def seg(self, data, d, flags=0x18, seq=None):
        """d = 0 client to server, 1 server to client"""
        src, dst = self.ip[d], self.ip[1 - d]
        s = self.seq[d] if seq is None else seq
        ack = self.seq[1 - d] if flags & 0x10 else 0
        opts = b'\x02\x04\x05\xb4' if flags & 0x02 else b''
        tcp = struct.pack('>HHIIBBHHH', self.port[d], self.port[1 - d], s, ack,
                          (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts
        pseudo = bytes(src) + bytes(dst) + struct.pack('>BBH', 0, 6, len(tcp) + len(data))
        tcp = tcp[:16] + struct.pack('>H', csum(pseudo + tcp + data)) + tcp[18:]
        if seq is None:
            self.seq[d] += len(data) + (1 if flags & 0x03 else 0)
        self.ident += 1
        return eth(ipv4(src, dst, 6, tcp + data, self.ident), MAC[d + 1], MAC[2 - d])

    def handshake(self):
        return [self.seg(b'', 0, 0x02), self.seg(b'', 1, 0x12), self.seg(b'', 0, 0x10)]

class SctpAssoc:
    def __init__(self, cip, sip, cport, sport, ppi=46):
        self.ip = {0: cip, 1: sip}
        self.port = {0: cport, 1: sport}
        self.tsn = {0: 100, 1: 9000}
        self.ssn = {0: 0, 1: 0}
        self.vtag = {0: 0x11223344, 1: 0x55667788}
        self.ppi = ppi

    def data(self, payload, d):
        pad = b'\0' * ((-len(payload)) % 4)
        chunk = struct.pack('>BBHIHHI', 0, 0x03, 16 + len(payload), self.tsn[d], 0,
                            self.ssn[d], self.ppi) + payload + pad
        self.tsn[d] += 1
        self.ssn[d] = (self.ssn[d] + 1) & 0xffff
        hdr = struct.pack('>HHII', self.port[d], self.port[1 - d], self.vtag[1 - d], 0)
        pkt = hdr + chunk
        c = crc32c(pkt)
        pkt = pkt[:8] + struct.pack('<I', c) + pkt[12:]
        return eth(ipv4(self.ip[d], self.ip[1 - d], 132, pkt), MAC[d + 1], MAC[2 - d])

def exppdu(dissector, payload):
    name = dissector.encode()
    tlv = struct.pack('>HH', 12, len(name)) + name
    return tlv + struct.pack('>HH', 0, 0) + payload

# ---------------------------------------------------------------------------
# pcapng writer: interface 0 Ethernet, interface 1 Exported PDU

class Pcapng:
    def __init__(self):
        self.recs = []
        self.ts = 1700000000 * 1000000

    def add(self, data, ifid=0, gap=1000):
        self.ts += gap
        self.recs.append((ifid, self.ts, data))

    def blob(self):
        def block(btype, body):
            body += b'\0' * ((-len(body)) % 4)
            ln = 12 + len(body)
            return struct.pack('<II', btype, ln) + body + struct.pack('<I', ln)
        out = block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
        out += block(1, struct.pack('<HHI', 1, 0, 262144))
        out += block(1, struct.pack('<HHI', 252, 0, 262144))
        for ifid, ts, data in self.recs:
            out += block(6, struct.pack('<IIIII', ifid, ts >> 32, ts & 0xffffffff,
                                        len(data), len(data)) + data)
        return out

# ---------------------------------------------------------------------------
# Messages of the main capture

CLI, SRV = [192, 0, 2, 1], [192, 0, 2, 2]

def imsi_un(): return avp(1, '001010123456789')

def sm_submit():
    return bytes([0x01, 0x07, 0x0b, 0x91]) + tbcd('46701234567') + \
        bytes([0x00, 0x00, 0x05]) + gsm7('hello')

def sm_deliver():
    return bytes([0x04, 0x0b, 0x91]) + tbcd('46701234567') + bytes([0x00, 0x00]) + \
        bytes([0x52, 0x11, 0x30, 0x21, 0x43, 0x65, 0x00]) + bytes([0x02]) + gsm7('hi')

def sm_submit_report():
    return bytes([0x01, 0x00, 0x52, 0x11, 0x30, 0x21, 0x43, 0x65, 0x00])

def sm_deliver_report():
    return bytes([0x00, 0x00])

def qos(*octs):
    return bytes(octs)

XML = '<?xml version="1.0" encoding="UTF-8"?><Sh-Data><PublicIdentifiers><IMSPublicIdentity>sip:alice@example.net</IMSPublicIdentity></PublicIdentifiers></Sh-Data>'
CIVIC = '<?xml version="1.0" encoding="UTF-8"?><civicAddress xmlns="urn:ietf:params:xml:ns:pidf:geopriv10:civicAddr"><country>SE</country><A1>Stockholm</A1></civicAddress>'
CODEC = 'uplink\noffer\nm=audio 49152 RTP/AVP 96\na=rtpmap:96 AMR-WB/16000\n'

def main_messages():
    """List of (cmd, appid, req_avps, ans_avps) request/answer pairs and extras."""
    pairs = []

    # 1. Capabilities exchange: base types, Address family variants, AppId,
    #    grouped Vendor-Specific-Application-Id, Supported-Vendor-Id.
    cer = [OHOST_C, OREALM_C,
           avp(257, b'\x00\x01' + bytes([192, 0, 2, 1])),                     # IPv4
           avp(257, b'\x00\x02' + bytes.fromhex('20010db8000000000000000000000001')),  # IPv6
           avp(257, b'\x00\x08' + b'+46701234567'),                            # E.164 printable
           avp(257, b'\x00\x08' + b'\x01\x02\x03\x04'),                        # E.164 not printable
           avp(257, b'\x00\x06' + bytes.fromhex('020000000001')),              # 802 (other)
           avp(266, u32(V3GPP)), avp(269, 'synthetic-diameter'),
           avp(265, u32(V3GPP)), avp(265, u32(V3GPP2)),
           avp(258, u32(4)), avp(258, u32(16777251)), avp(259, u32(3)),
           avp(299, i32(0)),
           VSAI(16777251), VSAI(16777238), VSAI(16777302, auth=False),
           avp(267, u32(1)), avp(278, u32(1700000000))]
    cea = [RC_OK, OHOST_S, OREALM_S, avp(257, b'\x00\x01' + bytes(SRV)),
           avp(266, u32(V3GPP)), avp(269, 'synthetic-hss'), avp(258, u32(16777251)),
           avp(281, 'all good'),
           # Starent "address" type AVP (Diameter address encoding)
           avp(5, b'\x00\x01' + bytes([198, 51, 100, 53]), vendor=VSTARENT)]
    pairs.append((257, 0, cer, cea))

    # 2. Device watchdog
    pairs.append((280, 0, [OHOST_C, OREALM_C, avp(278, u32(1))], [RC_OK, OHOST_S, OREALM_S]))

    # 3. Credit control (app 4): Subscription-Id of each type, UE-Info of each
    #    type, empty Requested-Service-Unit, MSCC with Total-Octets, Rating-Group,
    #    Result-Code, Time/Float/Integer64 types, CC-Money.
    sid = SID('pgw.example.net;100;1')
    ccr = [sid, OHOST_C, OREALM_C, DREALM, avp(258, u32(4)),
           avp(461, '32251@3gpp.org'), avp(416, i32(1)), avp(415, u32(0)),
           avp(55, u32(0xE9000000)),                                            # Event-Timestamp
           g(443, avp(450, i32(1)), avp(444, '001010123456789')),              # IMSI
           g(443, avp(450, i32(0)), avp(444, '46701234567')),                  # E.164
           g(443, avp(450, i32(2)), avp(444, 'sip:alice@example.net')),        # SIP URI
           g(458, avp(459, i32(0)), avp(460, tbcd('3534900698733190'))),        # IMEISV BCD 8
           g(458, avp(459, i32(0)), avp(460, '3534900698733190')),             # IMEISV ASCII 16
           g(458, avp(459, i32(1)), avp(460, bytes.fromhex('020000000001'))),  # MAC
           g(458, avp(459, i32(2)), avp(460, bytes.fromhex('0200000000000001'))),  # EUI64
           g(458, avp(459, i32(3)), avp(460, bytes.fromhex('0000000000000002'))),  # modified EUI64
           g(458, avp(459, i32(4)), avp(460, b'\x01\x02\x03\x04')),            # unknown type
           g(456, avp(437), avp(432, u32(7))),                                  # empty RSU (allowed)
           g(456, g(446, avp(421, u64(0x100000005)), avp(412, u64(1000)), avp(414, u64(2000))),
             avp(432, u32(8)), avp(439, u32(1))),
           g(437, g(413, g(445, avp(447, i64(-12345)), avp(429, i32(-2))), avp(425, u32(978)))),
           avp(407, 'permit in ip from 192.0.2.0/24 to any'),
           avp(292, 'aaa://ocs.example.net:3868;transport=tcp')]
    cca = [sid, RC_OK, OHOST_S, OREALM_S, avp(258, u32(4)), avp(416, i32(1)), avp(415, u32(0)),
           g(456, g(431, avp(421, u64(4294967296 * 3 + 7))), avp(432, u32(9)), avp(268, u32(2001)),
             avp(448, u32(3600))),
           g(456, avp(432, u32(10)), avp(268, u32(4012))),
           g(297, avp(266, u32(V3GPP)), avp(298, i32(5030))),                   # 3GPP result
           tg(1004, 'base-rule'),
           g(284, avp(280, 'proxy.example.net'), avp(33, 'state-1'), avp(268, u32(2001)))]
    pairs.append((272, 4, ccr, cca))

    # 4. S6a Update-Location: User-Name as IMSI, Visited-PLMN-Id, RAT-Type,
    #    ULR/ULA flags, Feature-List ID 1/2, Subscription-Data contents.
    sid = SID('mme.example.net;200;1')
    ulr = [sid, ASS, OHOST_C, OREALM_C, DREALM, imsi_un(),
           supported_features(1, 0xffffffff), supported_features(2, 0x7fffffff),
           tg(1032, u32(1004)), tg(1405, u32(0x1ff)), tg(1407, plmn('001', '01')),
           tg(1615, u32(0)), avp(124, u64(0x0000000000000003)),
           tg(1617, u32(0x0)), tg(1677, plmn('310', '410'))]
    sub = [tg(701, tbcd('46701234567')), tg(1426, u32(0x1fff)), tg(1417, i32(0)),
           tg(1654, u32(0x3ff)), tg(1704, u32(3)), tg(1689, u32(3)), tg(1686, u32(3)),
           tg(1668, u32(1)), tg(1669, u32(1)),
           tg(1645, b'\x91' + tbcd('46700000001')),
           tg(1538, u32(1)),
           tg(1404, qos(0x23, 0x62, 0x1f, 0x08, 0x93, 0x96, 0x40, 0x40, 0x74, 0x3d, 0x40, 0x40,
                        0x01, 0x4a, 0x10, 0xfa, 0xfb, 0x60)),           # 18 octets
           tg(1404, qos(0x23, 0x62, 0x1f)),                               # 3 octets
           tg(1404, qos(0x23, 0x62, 0x1f, 0x08, 0x00, 0x00, 0x00, 0x00, 0x74, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x20)),            # "subscribed" zeros
           tg(1404, qos(0x23, 0x62, 0x1f, 0x08, 0x93, 0x97, 0xfe, 0xfe, 0x74, 0xfc, 0xfe, 0xfe,
                        0x02, 0xfa, 0xfb, 0x3c, 0xba, 0x41)),
           tg(1404, qos(0x23, 0x62, 0x1f, 0x08, 0x93, 0x98, 0xff, 0xff, 0x74, 0x41, 0xff, 0xff,
                        0x0f, 0x01, 0xc0, 0x4a, 0x00, 0x41)),
           tg(1404, qos(0x23, 0x62, 0x1f, 0x08, 0x93, 0x99, 0x7f, 0x80, 0x74, 0x81, 0x3f, 0x7f,
                        0x01, 0x00, 0x00, 0x00, 0x00, 0x41)),
           tg(1404, qos(0x23, 0x62, 0x1f, 0x08, 0x93, 0x99, 0x7f, 0x80, 0x74, 0x81, 0x3f, 0x7f,
                        0x01, 0xfb, 0xfa, 0xfb, 0xfa, 0x41)),
           tg(1404, qos(0x23, 0x62, 0x1f, 0x08, 0x93, 0x99, 0x7f, 0x80, 0x74, 0x81, 0x3f, 0x7f,
                        0x01, 0x01, 0x01, 0x01, 0x10)),
           tg(1404, qos(0x23, 0x62, 0x1f, 0x08, 0x93, 0xff, 0x01, 0x01, 0x74, 0x01)),
           tg(1404, qos(0x23, 0x62, 0x1f, 0x08, 0x93, 0x50))]
    ula = [sid, RC_OK, ASS, OHOST_S, OREALM_S, supported_features(1, 0x5), tg(1406, u32(3)),
           tg(1400, sub)]
    pairs.append((316, 16777251, ulr, ula))

    # 5. S6a AIR / IDR / DSR / PUR / CLR / NOR
    pairs.append((318, 16777251,
                  [SID('mme.example.net;200;2'), ASS, OHOST_C, OREALM_C, DREALM, imsi_un(),
                   tg(1407, plmn('001', '001')), tg(1679, u32(1))],
                  [SID('mme.example.net;200;2'), RC_OK, ASS, OHOST_S, OREALM_S]))
    pairs.append((319, 16777251,
                  [SID('hss.example.net;300;1'), ASS, OHOST_S, OREALM_S, DREALM, imsi_un(),
                   tg(1490, u32(0x1ff)), tg(1400, [tg(1426, u32(0x10)), tg(1704, u32(1))])],
                  [SID('hss.example.net;300;1'), RC_OK, ASS, OHOST_C, OREALM_C, tg(1441, u32(1))]))
    pairs.append((320, 16777251,
                  [SID('hss.example.net;300;2'), ASS, OHOST_S, OREALM_S, DREALM, imsi_un(),
                   tg(1421, u32(0xffffffff))],
                  [SID('hss.example.net;300;2'), RC_OK, ASS, OHOST_C, OREALM_C, tg(1422, u32(1))]))
    pairs.append((321, 16777251,
                  [SID('mme.example.net;200;3'), ASS, OHOST_C, OREALM_C, DREALM, imsi_un(),
                   tg(1635, u32(7))],
                  [SID('mme.example.net;200;3'), RC_OK, ASS, OHOST_S, OREALM_S, tg(1442, u32(3))]))
    pairs.append((317, 16777251,
                  [SID('hss.example.net;300;3'), ASS, OHOST_S, OREALM_S, DREALM, imsi_un(),
                   tg(1420, i32(0)), tg(1638, u32(3))],
                  [SID('hss.example.net;300;3'), RC_OK, ASS, OHOST_C, OREALM_C]))
    pairs.append((323, 16777251,
                  [SID('mme.example.net;200;4'), ASS, OHOST_C, OREALM_C, DREALM, imsi_un(),
                   tg(1443, u32(0x3ff))],
                  [SID('mme.example.net;200;4'), RC_OK, ASS, OHOST_S, OREALM_S]))

    # 6. Cx UAR / SAR (Feature-List Cx, UAR/SAR flags, Public-Identity, Path,
    #    Contact, User-Data XML)
    pairs.append((300, 16777216,
                  [SID('cscf.example.net;400;1'), VSAI(16777216), ASS, OHOST_C, OREALM_C, DREALM,
                   avp(1, 'alice@example.net'), tg(601, 'sip:alice@example.net'),
                   tg(600, 'example.net'), tg(637, u32(1)), supported_features(1, 0xf)],
                  [SID('cscf.example.net;400;1'), VSAI(16777216), ASS, OHOST_S, OREALM_S,
                   RC_OK, tg(602, 'sip:scscf.example.net')]))
    pairs.append((301, 16777216,
                  [SID('cscf.example.net;400;2'), VSAI(16777216), ASS, OHOST_C, OREALM_C, DREALM,
                   tg(601, 'tel:+46701234567'), tg(602, 'sip:scscf.example.net'),
                   tg(614, i32(1)), tg(655, u32(1)),
                   tg(640, '<sip:p1.example.net;lr>,<sip:p2.example.net;lr>'),
                   tg(641, '<sip:alice@192.0.2.10:5060>;expires=600')],
                  [SID('cscf.example.net;400;2'), VSAI(16777216), ASS, OHOST_S, OREALM_S, RC_OK,
                   tg(606, XML), tg(606, 'short')]))

    # 7. Sh UDR (User-Data XML, Feature-List Sh, Requested-Nodes, MSISDN)
    pairs.append((306, 16777217,
                  [SID('as.example.net;500;1'), VSAI(16777217), ASS, OHOST_C, OREALM_C, DREALM,
                   tg(700, [tg(601, 'sip:alice@example.net')]), tg(701, tbcd('46701234567')),
                   tg(703, i32(0)), tg(713, u32(0xf)), supported_features(1, 0xf)],
                  [SID('as.example.net;500;1'), VSAI(16777217), ASS, OHOST_S, OREALM_S, RC_OK,
                   tg(702, XML), supported_features(1, 0x3)]))

    # 8. Rx AAR (Codec-Data with SDP, AF-Requested-Data, Feature-List ID 1, 2, 3)
    pairs.append((265, 16777236,
                  [SID('pcscf.example.net;600;1'), avp(258, u32(16777236)), OHOST_C, OREALM_C,
                   DREALM, supported_features(1, 0xffffffff), supported_features(2, 0xffff),
                   supported_features(3, 0x1),
                   tg(517, [tg(518, u32(1)), tg(524, CODEC),
                            tg(524, 'downlink\nanswer\nm=audio 50000 RTP/AVP 96\n\0\0'),
                            tg(524, 'uplink\ndescription'), tg(524, 'uplink'),
                            tg(524, 'downlink\nanswer\n')]),
                   tg(551, u32(1)), avp(97, bytes([0, 128]) + bytes.fromhex('20010db8000000000000000000000010'))],
                  [SID('pcscf.example.net;600;1'), avp(258, u32(16777236)), OHOST_S, OREALM_S,
                   RC_OK, tg(1263, '3GPP-E-UTRAN-FDD;utran-cell-id-3gpp=00101000100001;network-provided')]))

    # 9. Gx CCR: 3GPP-* AVPs from TS 29.061, Feature-List Gx 1/2,
    #    RAN-NAS-Release-Cause variants, Framed-IPv6-Prefix /64, Charging rules.
    sid = SID('pgw.example.net;700;1')
    gx_ccr = [sid, avp(258, u32(16777238)), OHOST_C, OREALM_C, DREALM, avp(416, i32(1)),
              avp(415, u32(0)), supported_features(1, 0xffffffff), supported_features(2, 0xff),
              tg(8, '00101'), tg(18, '310410'), tg(12, '0'),
              tg(15, bytes.fromhex('20010db8000000000000000000000002')),
              tg(15, u32(1)),                       # old IMS Unsigned32 meaning: ignored
              tg(21, b'\x06'), tg(23, b'\x40\x01'), tg(23, b'\x8a\x02'),
              tg(29, b'\x00\x04wlan'),
              tg(6, bytes([198, 51, 100, 6])), tg(7, bytes.fromhex('20010db8000000000000000000000007')),
              tg(2, '12345678'),
              avp(8, bytes([192, 0, 2, 100])),
              avp(97, bytes([0, 64]) + bytes.fromhex('20010db800010000')),
              avp(97, bytes([0, 0])),
              tg(2819, b'\x10\x01'), tg(2819, b'\x11\x02'), tg(2819, b'\x12\x03'),
              tg(2819, b'\x13\x04'), tg(2819, b'\x14\x05'), tg(2819, b'\x15\x06'),
              tg(2819, b'\x20\x07'), tg(2819, b'\x30\x08'), tg(2819, b'\x40\x0b\xb9'),
              tg(2819, b'\x50\x00\x18'), tg(2819, b'\x60\x01\x02\x03'),
              tg(1304, b'\x00'),
              tg(1032, u32(1004)),
              tg(1001, [tg(1003, [tg(1005, 'rule-1'), tg(1058, [tg(507, 'permit out 17 from 192.0.2.10 to 198.51.100.1 5004')]),
                                  tg(1028, u32(9))]),
                        tg(1004, 'base-1'), tg(1004, 'base-2')])]
    gx_cca = [sid, avp(258, u32(16777238)), OHOST_S, OREALM_S, RC_OK, avp(416, i32(1)),
              avp(415, u32(0)), tg(1001, [tg(1004, 'base-3')])]
    pairs.append((272, 16777238, gx_ccr, gx_cca))

    # 10. Gy CCR with Credit-Management-Status and Ericsson / Verizon AVPs,
    #     Experimental-Result of 3GPP2 and another vendor.
    sid = SID('pgw.example.net;800;1')
    pairs.append((272, 4,
                  [sid, OHOST_C, OREALM_C, DREALM, avp(258, u32(4)), avp(416, i32(2)),
                   avp(415, u32(1)), avp(461, '32251@3gpp.org'),
                   tg(1082, u32(0x7f)),
                   avp(603, f64(1.5), vendor=VERICSSON),
                   avp(5001, u32(3), vendor=VVERIZON),
                   avp(496, f32(1000.0)), tg(2852, f32(0.25))],
                  [sid, OHOST_S, OREALM_S, avp(258, u32(4)), avp(416, i32(2)), avp(415, u32(1)),
                   g(297, avp(266, u32(V3GPP2)), avp(298, i32(5001))),
                   g(297, avp(266, u32(V3GPP2)), avp(298, i32(5999))),
                   g(297, avp(266, u32(VERICSSON)), avp(298, i32(5555)))],))

    # 11. SWx MAR (User-Name IMSI, Feature-List SWx, MIP6 3GPP bits), PPR (User-Name list)
    pairs.append((303, 16777265,
                  [SID('aaa.example.net;900;1'), VSAI(16777265), ASS, OHOST_C, OREALM_C, DREALM,
                   imsi_un(), supported_features(1, 0x7f), avp(124, u64(0x1c0000000000000f))],
                  [SID('aaa.example.net;900;1'), VSAI(16777265), ASS, OHOST_S, OREALM_S, RC_OK]))
    pairs.append((305, 16777265,
                  [SID('hss.example.net;900;2'), VSAI(16777265), ASS, OHOST_S, OREALM_S, DREALM,
                   avp(1, '00101*'), tg(1508, u32(0x3))],
                  [SID('hss.example.net;900;2'), VSAI(16777265), ASS, OHOST_C, OREALM_C, RC_OK]))

    # 12. STa / SWm / S6b Diameter-EAP: EAP identity in User-Name, DER/DEA flags,
    #     EAP-Payload, MIP6, AAA-Failure-Indication; S6b feature list.
    ident = b'0001010123456789@nai.epc'
    eap_id = struct.pack('>BBHB', 2, 1, 5 + len(ident), 1) + ident
    eap_id2 = struct.pack('>BBHB', 2, 2, 5 + len(ident), 1) + ident
    pairs.append((268, 16777250,
                  [SID('twag.example.net;1000;1'), avp(258, u32(16777250)), OHOST_C, OREALM_C, DREALM,
                   avp(1, '0001010123456789@nai.epc.mnc001.mcc001.3gppnetwork.org'),
                   avp(462, eap_id), tg(1520, u32(1)), avp(124, u64(0x18000000000000))],
                  [SID('twag.example.net;1000;1'), avp(258, u32(16777250)), OHOST_S, OREALM_S, RC_OK,
                   avp(462, b'\x03\x01\x00\x04'), tg(1521, u32(1))]))
    pairs.append((258, 16777250,
                  [SID('aaa.example.net;1000;2'), avp(258, u32(16777250)), OHOST_S, OREALM_S, DREALM,
                   avp(285, i32(0)), tg(1522, u32(1))],
                  [SID('aaa.example.net;1000;2'), OHOST_C, OREALM_C, RC_OK, tg(1518, u32(1))]))
    pairs.append((268, 16777264,
                  [SID('epdg.example.net;1100;1'), avp(258, u32(16777264)), OHOST_C, OREALM_C, DREALM,
                   avp(1, '0001010123456789@nai.epc'), avp(462, eap_id2),
                   avp(124, u64(0x40000000000))],
                  [SID('epdg.example.net;1100;1'), avp(258, u32(16777264)), OHOST_S, OREALM_S, RC_OK]))
    pairs.append((268, 16777272,
                  [SID('pgw.example.net;1200;1'), avp(258, u32(16777272)), OHOST_C, OREALM_C, DREALM,
                   avp(1, '0001010123456789@nai.epc'), supported_features(1, 1),
                   avp(124, u64(0x4))],
                  [SID('pgw.example.net;1200;1'), avp(258, u32(16777272)), OHOST_S, OREALM_S, RC_OK]))
    pairs.append((265, 16777272,
                  [SID('pgw.example.net;1200;2'), avp(258, u32(16777272)), OHOST_C, OREALM_C, DREALM,
                   avp(1, 'user@example.net')],
                  [SID('pgw.example.net;1200;2'), avp(258, u32(16777272)), OHOST_S, OREALM_S, RC_OK]))

    # 13. S6c / SGd: SRR flags, MWD-Status, SC-Address, MO/MT-Forward-Short-Message
    #     with SM-RP-UI to and from GSM SMS (both directions).
    pairs.append((8388647, 16777312,
                  [SID('smsgmsc.example.net;1300;1'), VSAI(16777312), ASS, OHOST_C, OREALM_C, DREALM,
                   tg(701, tbcd('46701234567')), tg(3300, b'\x91' + tbcd('46700000002')),
                   tg(3310, u32(7)), supported_features(1, 1)],
                  [SID('smsgmsc.example.net;1300;1'), VSAI(16777312), ASS, OHOST_S, OREALM_S, RC_OK,
                   imsi_un(), tg(3312, u32(0x3f))]))
    pairs.append((8388645, 16777313,
                  [SID('mme.example.net;1400;1'), VSAI(16777313), ASS, OHOST_C, OREALM_C, DREALM,
                   tg(3300, b'\x91' + tbcd('46700000002')), tg(3301, sm_submit())],
                  [SID('mme.example.net;1400;1'), VSAI(16777313), ASS, OHOST_S, OREALM_S, RC_OK,
                   tg(3301, sm_submit_report())]))
    pairs.append((8388646, 16777313,
                  [SID('smsc.example.net;1400;2'), VSAI(16777313), ASS, OHOST_S, OREALM_S, DREALM,
                   imsi_un(), tg(3300, b'\x91' + tbcd('46700000002')), tg(3301, sm_deliver())],
                  [SID('smsc.example.net;1400;2'), VSAI(16777313), ASS, OHOST_C, OREALM_C, RC_OK,
                   tg(3301, sm_deliver_report())]))
    pairs.append((8388647, 16777313,
                  [SID('smsc.example.net;1400;3'), VSAI(16777313), ASS, OHOST_S, OREALM_S, DREALM,
                   tg(3301, b'\x00\x00'), tg(3301, b'')],
                  [SID('smsc.example.net;1400;3'), VSAI(16777313), ASS, OHOST_C, OREALM_C, RC_OK]))

    # 14. S6t (Feature-List S6t, Supported-Monitoring-Events, RIR-Flags)
    pairs.append((8388718, 16777345,
                  [SID('scef.example.net;1500;1'), VSAI(16777345), ASS, OHOST_C, OREALM_C, DREALM,
                   supported_features(1, 0x3ff), tg(3144, u64(0x1ff))],
                  [SID('scef.example.net;1500;1'), VSAI(16777345), ASS, OHOST_S, OREALM_S, RC_OK,
                   supported_features(1, 0x3ff)]))
    pairs.append((8388722, 16777345,
                  [SID('hss.example.net;1500;2'), VSAI(16777345), ASS, OHOST_S, OREALM_S, DREALM,
                   tg(3167, u32(0xf))],
                  [SID('hss.example.net;1500;2'), VSAI(16777345), ASS, OHOST_C, OREALM_C, RC_OK]))

    # 15. Sd TSR (Feature-List Sd)
    pairs.append((8388637, 16777303,
                  [SID('pcrf.example.net;1600;1'), avp(258, u32(16777303)), OHOST_C, OREALM_C, DREALM,
                   supported_features(1, 0x7ff)],
                  [SID('pcrf.example.net;1600;1'), avp(258, u32(16777303)), OHOST_S, OREALM_S, RC_OK]))

    # 16. SLh LCS-Routing-Info (User-Name IMSI, MSC/GMLC numbers),
    #     SLg PLR/PLA (flags, GAD shapes, deferred location type, location
    #     estimate, E-UTRAN positioning data, civic address)
    pairs.append((8388622, 16777291,
                  [SID('gmlc.example.net;1700;1'), ASS, OHOST_C, OREALM_C, DREALM, imsi_un(),
                   tg(1474, b'\x91' + tbcd('46700000003'))],
                  [SID('gmlc.example.net;1700;1'), ASS, OHOST_S, OREALM_S, RC_OK,
                   tg(2403, b'\x91' + tbcd('46700000004')), tg(1645, b'\x91' + tbcd('46700000005'))]))
    pairs.append((8388620, 16777255,
                  [SID('gmlc.example.net;1800;1'), ASS, OHOST_C, OREALM_C, DREALM, imsi_un(),
                   tg(2545, u32(7)), tg(2510, u32(0x7ff)), tg(2532, u32(0xff))],
                  [SID('gmlc.example.net;1800;1'), ASS, OHOST_S, OREALM_S, RC_OK,
                   tg(2546, u32(0xf)),
                   tg(1242, b'\x00\x12\x34\x56\x01\x23\x45'),
                   tg(1242, b'\x10\x12\x34\x56\x81\x23\x45\x0a'),
                   tg(2516, b'\x00'), tg(2556, CIVIC), tg(2556, 'SE')]))

    # 17. S13 ECR (User-Name IMSI, IMEI), S7a UVR (UVR/UVA flags)
    pairs.append((324, 16777252,
                  [SID('mme.example.net;1900;1'), ASS, OHOST_C, OREALM_C, DREALM, imsi_un(),
                   tg(1401, [tg(1402, '35349006987331')])],
                  [SID('mme.example.net;1900;1'), ASS, OHOST_S, OREALM_S, RC_OK, tg(1445, i32(0))]))
    pairs.append((8388647, 16777308,
                  [SID('vcsg.example.net;2000;1'), ASS, OHOST_C, OREALM_C, DREALM, imsi_un(),
                   tg(1639, u32(1))],
                  [SID('vcsg.example.net;2000;1'), ASS, OHOST_S, OREALM_S, RC_OK, tg(1640, u32(1))]))

    # 18. MBMS (SGmb/Gmb): TMGI, RAI (11 and 12 octets), MBMS-Required-QoS,
    #     IPv6/IPv4 addresses, UDP ports, data transfer times, bearer event/result,
    #     TMGI allocation/deallocation results.
    pairs.append((8388663, 16777292,
                  [SID('bmsc.example.net;2100;1'), avp(258, u32(16777292)), OHOST_C, OREALM_C, DREALM,
                   tg(900, b'\x00\x00\x01' + plmn('001', '01')),
                   tg(909, '00101A2C10A'), tg(909, '310410A2C10B'),
                   tg(913, b'\x05\x23\x62\x1f\x08\x93\x96\x40\x40\x74\x3c\x40\x40'),
                   tg(917, bytes.fromhex('20010db8000000000000000000000917')),
                   tg(918, bytes([198, 51, 100, 18])), tg(926, b'\x10'), tg(927, b'\x11'),
                   tg(929, u64(0xE900000080000000)), tg(930, u64(0xE900010000000000)),
                   tg(3502, u32(7)), tg(3500, b'\x00\x01' + bytes([198, 51, 100, 1]))],
                  [SID('bmsc.example.net;2100;1'), avp(258, u32(16777292)), OHOST_S, OREALM_S, RC_OK,
                   tg(3506, u32(0xfff)), tg(3511, u32(0x1f)), tg(3514, u32(7))]))

    # 19. Feature-List in an application with no special decoding (Gq), which
    #     shows the Diameter item again; nested grouped AVPs 8 levels deep.
    nested = avp(1004, 'deep', vendor=V3GPP)
    for _ in range(8):
        nested = g(260, avp(266, u32(V3GPP)), nested)
    pairs.append((265, 16777222,
                  [SID('af.example.net;2200;1'), OHOST_C, OREALM_C, DREALM, avp(258, u32(16777222)),
                   supported_features(1, 0x3), nested],
                  [SID('af.example.net;2200;1'), OHOST_S, OREALM_S, RC_OK]))

    # 20. Unknown command code, unknown application, unknown AVPs (known and
    #     unknown vendor), AVP without data (warnings, no errors).
    pairs.append((9999, 4294967, [SID('x.example.net;2300;1'), OHOST_C, OREALM_C,
                                  avp(65000, b'\x01\x02\x03\x04'),
                                  avp(65001, b'abcd', vendor=V3GPP),
                                  avp(1, b'abcd', vendor=99999),
                                  avp(281)],
                  [SID('x.example.net;2300;1'), OHOST_S, OREALM_S, RC_OK]))
    return pairs

def build_main(out):
    cap = Pcapng()
    hbh = [0x1000]

    def nxt():
        hbh[0] += 1
        return hbh[0]

    # TCP stream on port 3868: request/answer pairs, one message per segment
    f = TcpFlow(CLI, SRV, 40000, 3868)
    for p in f.handshake():
        cap.add(p)
    pairs = main_messages()
    for i, (cmd, app, req, ans) in enumerate(pairs):
        h = nxt()
        dreq = 1 if OHOST_S in req else 0
        cap.add(f.seg(diameter(cmd, app, req, True, h, h), dreq))
        cap.add(f.seg(diameter(cmd, app, ans, False, h, h), 1 - dreq))
    main_tcp_end = len(cap.recs)

    # Reassembly on a second TCP connection: a message in three segments,
    # two messages in one segment, a message whose first segment has fewer
    # than 5 octets, a request without answer, an answer without request,
    # and a retransmitted answer; error bit; version 1 only.
    f2 = TcpFlow([192, 0, 2, 3], SRV, 40001, 3868)
    for p in f2.handshake():
        cap.add(p)
    big = diameter(272, 4, [SID('pgw.example.net;3000;1'), OHOST_C, OREALM_C, DREALM,
                            avp(258, u32(4)), avp(416, i32(1)), avp(415, u32(0)),
                            avp(281, 'x' * 2600)], True, 0x3001, 0x3001)
    cap.add(f2.seg(big[:1000], 0))
    cap.add(f2.seg(big[1000:2000], 0))
    cap.add(f2.seg(big[2000:], 0))
    a1 = diameter(272, 4, [SID('pgw.example.net;3000;1'), OHOST_S, OREALM_S, RC_OK], False, 0x3001, 0x3001)
    r2 = diameter(280, 0, [OHOST_C, OREALM_C], True, 0x3002, 0x3002)
    cap.add(f2.seg(a1 + diameter(280, 0, [OHOST_S, OREALM_S, RC_OK], False, 0x2fff, 0x2fff), 1))
    cap.add(f2.seg(r2[:3], 0))
    cap.add(f2.seg(r2[3:], 0))
    # answer with the E bit (error) and Failed-AVP / Error-Reporting-Host
    cap.add(f2.seg(diameter(280, 0, [avp(268, u32(3001)), OHOST_S, OREALM_S, avp(294, 'hss.example.net'),
                                     g(279, avp(264, 'bad.example.net'))],
                            False, 0x3002, 0x3002, flags=0x60), 1))
    # request without answer, then T bit (retransmitted) request
    cap.add(f2.seg(diameter(280, 0, [OHOST_C, OREALM_C], True, 0x3003, 0x3003), 0))
    cap.add(f2.seg(diameter(280, 0, [OHOST_C, OREALM_C], True, 0x3003, 0x3003, flags=0xd0), 0))
    reasm_end = len(cap.recs)

    # A capture that starts in the middle of a message: the first segment
    # seen is not the start of a PDU ("Continuation"), the next one is.
    f3 = TcpFlow([192, 0, 2, 4], SRV, 40002, 3868)
    mid = diameter(280, 0, [OHOST_C, OREALM_C, avp(281, 'z' * 40)], True, 0x4001, 0x4001)
    cap.add(f3.seg(mid[24:], 0))
    cap.add(f3.seg(diameter(280, 0, [OHOST_C, OREALM_C], True, 0x4002, 0x4002), 0))
    cont_end = len(cap.recs)

    # SCTP, PPI 46, port 3868 (both registrations): CER/CEA and a ULR/ULA
    s = SctpAssoc(CLI, SRV, 3868, 3868)
    cap.add(s.data(diameter(257, 0, [OHOST_C, OREALM_C, avp(257, b'\x00\x01' + bytes(CLI)),
                                     avp(266, u32(V3GPP)), avp(269, 'sctp-client'), avp(258, u32(16777251))],
                            True, 0x5001, 0x5001), 0))
    cap.add(s.data(diameter(257, 0, [RC_OK, OHOST_S, OREALM_S, avp(257, b'\x00\x01' + bytes(SRV)),
                                     avp(266, u32(V3GPP)), avp(269, 'sctp-server')],
                            False, 0x5001, 0x5001), 1))
    cap.add(s.data(diameter(316, 16777251, [SID('mme.example.net;5000;1'), ASS, OHOST_C, OREALM_C, DREALM,
                                            imsi_un(), tg(1405, u32(0x22)), tg(1407, plmn('001', '01'))],
                            True, 0x5002, 0x5002), 0))
    cap.add(s.data(diameter(316, 16777251, [SID('mme.example.net;5000;1'), RC_OK, ASS, OHOST_S, OREALM_S,
                                            tg(1406, u32(1))], False, 0x5002, 0x5002), 1))
    # SCTP on another port, found by the PPI only
    s2 = SctpAssoc(CLI, SRV, 2905, 2905)
    cap.add(s2.data(diameter(280, 0, [OHOST_C, OREALM_C], True, 0x5003, 0x5003), 0))
    sctp_end = len(cap.recs)

    # Diameter over TCP on a port that is not registered: only the
    # (disabled by default) heuristic dissector finds it
    fh = TcpFlow([192, 0, 2, 7], SRV, 40003, 33868)
    for p in fh.handshake():
        cap.add(p)
    cap.add(fh.seg(diameter(280, 0, [OHOST_C, OREALM_C], True, 0x6001, 0x6001), 0))
    cap.add(fh.seg(diameter(280, 0, [OHOST_S, OREALM_S, RC_OK], False, 0x6001, 0x6001), 1))
    heur_end = len(cap.recs)

    # Exported PDU: "diameter_avps" (bare AVP list, as EAP-TTLS hands it over)
    cap.add(exppdu('diameter_avps', avp(1, 'user@example.net') + avp(79, b'\x02\x05\x00\x06\x01x') +
                   g(443, avp(450, i32(1)), avp(444, '001010123456789')) +
                   g(458, avp(459, i32(1)), avp(460, bytes.fromhex('020000000009'))) +
                   tg(1405, u32(3)) + avp(281, 'ttls')), 1)
    exp_end = len(cap.recs)

    # Reproducers of the fixes on the branch (diameter_*.py),
    # each on its own TCP connection to port 3868.
    SESSION = avp(263, b'host.example.net;1;1')
    OHOST = avp(264, b'host.example.net')
    OREALM = avp(296, b'example.net')

    def repro(port, msgs):
        fr = TcpFlow([192, 0, 2, 9], SRV, port, 3868)
        for m in msgs:
            cap.add(fr.seg(m, 0))

    # diameter_stale_item_hidden: Unsigned64 AVP after an Unsigned32 AVP
    # with a subdissector that hides "the item".
    repro(41001, [diameter(272, 4, [SESSION, OHOST, OREALM, avp(258, u32(4)), avp(124, u64(1)),
                                    avp(266, u32(10415)), tg(3144, u64(3))], True, 1, 1)])
    # diameter_cc_total_octets_fmt
    repro(41002, [diameter(272, 4, [SESSION, OHOST, OREALM, avp(258, u32(4)),
                                    g(456, g(446, avp(421, u64(0x100000005))), avp(432, u32(7)))],
                           True, 1, 1)])
    # diameter_framed_ipv6_prefix_mask (/60)
    repro(41003, [diameter(265, 1, [SESSION, OHOST, OREALM,
                                    avp(97, bytes([0, 60]) + bytes.fromhex('20010db80000ffff'))], True, 1, 1)])
    # diameter_3gpp_path_len
    repro(41004, [diameter(301, 16777216, [SESSION, OHOST, OREALM,
                                           tg(640, b'<sip:p1.example.net>,<sip:p2.example.net>,<sip:p3.example.net>')],
                           True, 1, 1)])
    # diameter_3gpp_qos_trans_delay (0x3d: transfer delay 15 = 150 ms)
    repro(41005, [diameter(316, 16777251, [SESSION, OHOST, OREALM,
                                           tg(1404, bytes([0x23, 0x62, 0x1f, 0x08, 0x93, 0x96, 0x40, 0x40, 0x74, 0x3d]))],
                           True, 1, 1)])
    # diameter_session_imsi_2pass: the IMSI comes in the second message
    sess = avp(263, b'mme.example.net;1;42')
    repro(41006, [diameter(316, 16777251, [sess, OHOST, OREALM], True, 1, 1),
                  diameter(316, 16777251, [sess, OHOST, OREALM, avp(1, b'001010123456789')], True, 2, 2)])
    tcp_repro_end = len(cap.recs)
    # diameter_avps_subid_default: Subscription-Id-Data / UE-Info-Value
    # without a type, through "diameter_avps" and "diameter"
    payload = avp(444, b'user@example.net') + avp(460, b'\x01\x02\x03')
    cap.add(exppdu('diameter_avps', payload), 1)
    cap.add(exppdu('diameter', diameter(272, 4, payload)), 1)

    sections = dict(main_tcp_end=main_tcp_end, reasm_end=reasm_end, cont_end=cont_end,
                    sctp_end=sctp_end, heur_end=heur_end, exp_end=exp_end, tcp_repro_end=tcp_repro_end,
                    total=len(cap.recs), pairs=len(pairs))
    with open(os.path.join(out, 'diameter-coverage.pcapng'), 'wb') as fh:
        fh.write(cap.blob())
    return sections

# ---------------------------------------------------------------------------
# Malformed capture

def nested_grouped(depth, code=260):
    return b''.join(struct.pack('>II', code, (0x40 << 24) | (8 * (depth - i))) for i in range(depth))

def build_malformed(out):
    cap = Pcapng()
    f = TcpFlow([192, 0, 2, 5], SRV, 42000, 3868)
    H = [OHOST_C, OREALM_C]
    msgs = [
        # wrong lengths for every fixed size type
        diameter(272, 4, H + [avp(415, b'\x00\x01'), avp(416, b'\x01'), avp(421, b'\x00' * 4),
                              avp(447, b'\x00' * 4), avp(496, b'\x00\x00'),
                              avp(603, b'\x00' * 4, vendor=VERICSSON), avp(55, b'\x00' * 8),
                              g(437, g(413, g(445, avp(447, b'\x01')))),
                              tg(3144, b'\x00\x00\x00\x01')]),
        # address families with a wrong length, RADIUS address of odd length
        diameter(257, 0, H + [avp(257, b'\x00\x01\x01\x02'), avp(257, b'\x00\x02\x01\x02\x03\x04'),
                              avp(8, b'\x01\x02\x03'), tg(4, b'\x01' * 6)]),
        # version 2, reserved header bits, missing padding of the last AVP:
        # check_diameter() rejects these at the start of a segment, so each
        # follows a valid message in the same segment (tcp_dissect_pdus()
        # only checks the first one)
        diameter(280, 0, H) + diameter(280, 0, H, version=2),
        diameter(280, 0, H) + diameter(280, 0, H, flags=0x8f),
        diameter(280, 0, H) + diameter(280, 0, H + [avp(281, 'abc', pad=b'')]),
        # AVP reserved flag bits, non-zero padding
        diameter(280, 0, H + [avp(281, 'a', flags=0x5f), avp(281, 'b', pad=b'\x01\x02\x03')]),
        # AVP longer than the message, AVP length below the header size
        diameter(280, 0, H + [struct.pack('>II', 281, (0x40 << 24) | 200)]),
        diameter(280, 0, H + [struct.pack('>II', 281, (0x40 << 24) | 4)]),
        diameter(280, 0, H + [struct.pack('>III', 281, (0xc0 << 24) | 8, V3GPP)]),
        # UE info with wrong lengths, IMEI (15 digits) instead of IMEISV
        diameter(272, 4, H + [g(458, avp(459, i32(0)), avp(460, '353490069873319')),
                              g(458, avp(459, i32(0)), avp(460, b'\x01\x02')),
                              g(458, avp(459, i32(1)), avp(460, b'\x01\x02')),
                              g(458, avp(459, i32(2)), avp(460, b'\x01\x02')),
                              g(458, avp(459, i32(3)), avp(460, b'\x01\x02'))]),
        # Framed-IPv6-Prefix > 128
        diameter(265, 1, H + [avp(97, bytes([0, 200]) + b'\x20\x01' * 8)]),
        # Visited-PLMN-Id / Group-PLMN-Id of the wrong length
        diameter(316, 16777251, H + [tg(1407, b'\x00\xf1'), tg(1677, b'\x00\xf1\x10\x00')]),
        # SM-RP-UI that GSM SMS cannot decode (exception inside the subdissector)
        diameter(8388645, 16777313, H + [tg(3301, b'\x01\x07\x0b')]),
        diameter(8388646, 16777313, H + [tg(3301, b'\x04\x0b')], request=False),
        # Short 3GPP AVPs: Selection-Mode empty, MS-TimeZone 1 octet, TMGI 2
        # octets, RAI too short, QoS 1 octet, RAN-NAS cause truncated,
        # MBMS-Required-QoS 1 octet, Feature-List 2 octets
        diameter(272, 16777238, H + [tg(12, b''), tg(23, b'\x40'), tg(900, b'\x00\x01'),
                                     tg(909, '0010'), tg(1404, b'\x23'), tg(2819, b'\x10'),
                                     tg(2819, b'\x40\x01'), tg(913, b'\x05'), tg(630, b'\x00\x01'),
                                     tg(1242, b'\x00\x01'), tg(29, b'\x01\x10ab'),
                                     tg(917, b'\x20\x01'), tg(15, b'\x20\x01\x0d\xb8\x00')]),
        # Codec-Data whose last octets are all NUL after the second line
        diameter(265, 16777236, H + [tg(524, 'uplink\noffer\n\0\0\0')]),
        # DER-S6b-Flags: hf "diameter.3gpp.sb6_flags_spare" has no bitmask,
        # so proto_tree_add_bitmask_with_flags() asserts (dissector bug)
        diameter(268, 16777272, H + [tg(1523, u32(3))]),
        # Unsigned32 subdissector AVPs of the wrong length (item is NULL)
        diameter(316, 16777251, H + [tg(1405, b'\x01'), tg(1426, b'\x01\x02'), tg(551, b'\x01')]),
        # Result-Code / Rating-Group / CC-Total-Octets shorter than needed
        diameter(272, 4, H + [g(456, avp(268, b'\x01'), avp(432, b'\x01'), g(446, avp(421, b'\x01')))]),
        # message length below the AVPs (header claims 20 + 8)
        diameter(280, 0, H, length=28),
        # grouped AVPs nested beyond the dissection depth limit (the fix)
        diameter(272, 4, nested_grouped(600)),
    ]
    for m in msgs:
        cap.add(f.seg(m, 0))
    # message shorter than 36 octets / length not a multiple of 4 / R+E bits:
    # not Diameter at all (Continuation on TCP, rejected on SCTP)
    s = SctpAssoc([192, 0, 2, 5], SRV, 3868, 3868)
    cap.add(s.data(diameter(280, 0, [], length=20), 0))
    cap.add(s.data(diameter(280, 0, H, flags=0xa0), 0))
    cap.add(s.data(diameter(280, 0, H, flags=0x81), 0))
    cap.add(s.data(diameter(280, 0, H, length=37) + b'\0', 0))
    cap.add(s.data(b'\x01\x00', 0))
    # not Diameter on a port only the heuristic looks at
    fh = TcpFlow([192, 0, 2, 7], SRV, 40004, 33869)
    cap.add(fh.seg(b'HELLO, this is not Diameter at all\r\n', 0))
    # the reproducer of the stack overflow: 32000 levels, exported PDU
    cap.add(exppdu('diameter', diameter(272, 4, nested_grouped((262144 - 64) // 8 - 8))), 1)
    # 2 MiB of nesting reassembled from TCP (diameter_grouped_recursion_tcp)
    f2 = TcpFlow([192, 0, 2, 6], SRV, 42001, 3868)
    deep = diameter(272, 4, nested_grouped((2 * 1024 * 1024) // 8))
    for i in range(0, len(deep), 65000):
        cap.add(f2.seg(deep[i:i + 65000], 0))
    with open(os.path.join(out, 'diameter-coverage-malformed.pcapng'), 'wb') as fh:
        fh.write(cap.blob())
    return len(cap.recs)

if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    print(build_main(out))
    print('malformed', build_malformed(out))
