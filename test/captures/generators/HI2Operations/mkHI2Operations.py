#!/usr/bin/env python3
# HI2Operations coverage capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Lawful interception HI2 PDUs (EpsHI2Operations / HI2Operations / HI3CCLinkData).

Usage: mkHI2Operations.py [<output directory>]

Writes HI2Operations-coverage.pcapng (two interfaces: Ethernet and Exported
PDU) and HI2Operations-coverage-malformed.pcapng (truncated and mutated PDUs,
short values, rejected UUS1-Content).

The BER is built with the small helpers below from the ASN.1 of the three
modules (all IMPLICIT TAGS, so a tagged SEQUENCE is constructed [n], a
tagged primitive is primitive [n] and a tagged CHOICE is explicit:
constructed [n] around the chosen alternative). The IRIsContent PDUs are
carried in Exported PDU frames that name the dissector "HI2Operations"; the
UUS1-Content PDUs are carried in the User-user IE of a Q.931 SETUP in TPKT
over TCP 1720 (found by the "q931_user" heuristic). Keys in
MediaDecryption-info are constant placeholders. Addresses are from
192.0.2.0/24 and 2001:db8::/32. Every packet is built here; nothing comes
from a real network.
"""

import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct

from capgen import (IP4_A, IP4_B, LINKTYPE_ETHERNET, LINKTYPE_WIRESHARK_UPPER_PDU,  # noqa: E402
                    MAC_A, MAC_B, Pcapng, eth, ip4, ipv4, tcp)

IP_A = ip4(IP4_A)
IP_B = ip4(IP4_B)


# ---- BER --------------------------------------------------------------

def length(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def tl(cls, cons, num, content, indef=False):
    first = (cls << 6) | (0x20 if cons else 0)
    if num < 31:
        t = bytes([first | num])
    else:
        t = bytes([first | 31])
        digs = [num & 0x7f]
        num >>= 7
        while num:
            digs.append((num & 0x7f) | 0x80)
            num >>= 7
        t += bytes(reversed(digs))
    if indef:
        return t + b"\x80" + content + b"\0\0"
    return t + length(len(content)) + content


def C(n, *kids, indef=False):          # context constructed [n]
    return tl(2, True, n, b"".join(kids), indef)


def P(n, content=b""):                 # context primitive [n]
    if isinstance(content, str):
        content = content.encode()
    return tl(2, False, n, content)


def S(*kids):                          # universal SEQUENCE
    return tl(0, True, 16, b"".join(kids))


def SET(*kids):
    return tl(0, True, 17, b"".join(kids))


def OCT(b):
    return tl(0, False, 4, b if isinstance(b, bytes) else b.encode())


def UTF(s):
    return tl(0, False, 12, s.encode())


def INTU(v):
    return tl(0, False, 2, intb(v))


def ENUMU(v):
    return tl(0, False, 10, bytes([v]))


def intb(v):
    n = max(1, (v.bit_length() + 8) // 8)
    return v.to_bytes(n, "big", signed=True)


def I(n, v):                           # [n] INTEGER
    return P(n, intb(v))


def E(n, v):                           # [n] ENUMERATED
    return P(n, intb(v))


def B(n, v=True):                      # [n] BOOLEAN
    return P(n, b"\xff" if v else b"\x00")


def oid(*arcs):
    b = bytes([arcs[0] * 40 + arcs[1]])
    for a in arcs[2:]:
        d = [a & 0x7f]
        a >>= 7
        while a:
            d.append((a & 0x7f) | 0x80)
            a >>= 7
        b += bytes(reversed(d))
    return b


DOMAIN = oid(0, 4, 0, 2, 2, 4, 8, 16, 1)

# ---- common types --------------------------------------------------------


def ts_local(t=b"20260102123456Z", wsi=1):
    return C(0, P(0, t), E(1, wsi))               # TimeStamp.localTime


def ts_utc(t=b"260102123456Z"):
    return P(1, t)                                 # TimeStamp.utcTime


def ipaddr(v4=IP_A, kind=0, assign=2, text=None, prefix=None, mask=None):
    """IPAddress SEQUENCE, content only."""
    kids = [E(1, kind)]
    if text is not None:
        kids.append(C(2, P(2, text)))
    else:
        kids.append(C(2, P(1, v4)))
    if assign is not None:
        kids.append(E(3, assign))
    if prefix is not None:
        kids.append(I(4, prefix))
    if mask is not None:
        kids.append(P(5, mask))
    return b"".join(kids)


def dna(v4=IP_A, **kw):
    """DataNodeAddress CHOICE ipAddress [1] (content of an explicit tag)."""
    return C(1, ipaddr(v4, **kw))


def party(qual, ident, services=None):
    kids = [E(0, qual), C(1, *ident)]
    if services is not None:
        kids.append(services)
    return S(*kids)


def party_kids(qual, ident, services=None):
    kids = [E(0, qual), C(1, *ident)]
    if services is not None:
        kids.append(services)
    return kids


def PR(s):
    return tl(0, False, 19, s.encode() if isinstance(s, str) else s)


def network_id(opid=b"\x13\x00\x62", elem=None):
    kids = [P(0, opid)]
    if elem is not None:
        kids.append(C(1, elem))                    # CHOICE: explicit
    return kids


ISUP_NUM = b"\x03\x13\x94\x71\x32\x54\x76\x98"  # calling party number octets


def iri(rec, *extra, liid=b"LIID-0001", ts=None, indef=False):
    return C(rec, P(0, DOMAIN), P(1, liid), C(3, ts or ts_local()), *extra, indef=indef)


def gtp(*kids):                                    # ePS-GTPV2-specificParameters
    return C(36, *kids)


# ---- GTPv2 style contents ------------------------------------------------
PAA = b"\x01" + IP_A                                 # PDN type IPv4 + address
APN_LABEL = b"\x08internet\x03foo\x03com"
APN_PLAIN = b"\xf0plain.apn"                         # first octet > length: not label encoded
BEARER_QOS = bytes([0x49, 0x09]) + b"\x00" * 20
AMBR = struct.pack(">II", 100000, 200000)
TFT = bytes([0x21, 0x31, 0x20, 0x00, 0x10, 0x0a, 0x30, 0xc0, 0xa8, 0x00, 0x01, 0xff, 0xff, 0xff, 0x00])
ULI = bytes([0x18]) + bytes([0x13, 0x00, 0x62, 0x00, 0x01]) + bytes([0x13, 0x00, 0x62, 0x00, 0x00, 0x01, 0x02])
OP_ID = b"\x13\x00\x62"


class Cap:
    """Frames of a pcapng file with two interfaces: 0 = Ethernet,
    1 = Exported PDU (linktype 252)."""

    def __init__(self):
        self.frames = []        # (interface, bytes)
        self.ipid = 0x5000
        self.seq = {}

    def epdu(self, name, payload):
        nm = name.encode()
        pad = nm + b"\0" * (-len(nm) % 4)
        hdr = struct.pack("!HH", 12, len(pad)) + pad + struct.pack("!HH", 0, 0)
        self.frames.append((1, hdr + payload))

    def tcp(self, payload=b"", flags=0x18, sport=40000, dport=1720, reverse=False):
        st = self.seq.setdefault((sport, dport), [999, 5000])
        src, dst = (IP_B, IP_A) if reverse else (IP_A, IP_B)
        smac, dmac = (MAC_B, MAC_A) if reverse else (MAC_A, MAC_B)
        a, b = (dport, sport) if reverse else (sport, dport)
        s, k = (st[1], st[0]) if reverse else (st[0], st[1])
        opts = b"\x02\x04\x05\xb4" if flags & 2 else b""
        seg = tcp(payload, a, b, seq=s, ack=k if flags & 0x10 else 0, flags=flags,
                  win=8192, options=opts, src=src, dst=dst)
        adv = len(payload) + (1 if flags & 3 else 0)
        st[1 if reverse else 0] += adv
        self.ipid += 1
        self.frames.append((0, eth(ipv4(seg, 6, src=src, dst=dst, ident=self.ipid), 0x0800,
                                   dst=dmac, src=smac)))

    def write(self, path):
        w = Pcapng()
        w.interface(LINKTYPE_ETHERNET, snaplen=65535)
        w.interface(LINKTYPE_WIRESHARK_UPPER_PDU, snaplen=65535)
        for i, (ifc, fr) in enumerate(self.frames):
            w.packet(ifc, fr, ts=(0, i * 1000))
        w.write(path)


def q931_setup(uu):
    """Q.931 SETUP with a User-user IE; discriminator 0 (user specific)."""
    ie = bytes([0x7e, len(uu) + 1, 0x00]) + uu
    q = bytes([0x08, 0x02, 0x00, 0x01, 0x05]) + bytes([0x04, 0x03, 0x80, 0x90, 0xa3]) + ie
    return struct.pack("!BBH", 3, 0, 4 + len(q)) + q


def uus1(liid=b"LIID-0002", bearer=None, svc=None, direction=1, cc_link=b"12345678",
         domain=False, cin=b"1234"):
    kids = []
    if domain:
        kids.append(P(0, oid(0, 4, 0, 2, 2, 2, 4, 4)))
    kids.append(P(1, liid))
    kids.append(C(2, P(0, cin), C(1, *network_id(OP_ID, P(1, ISUP_NUM)))))
    if cc_link:
        kids.append(P(3, cc_link))
    kids.append(E(4, direction))
    if bearer is not None:
        kids.append(P(5, bearer))
    if svc is not None:
        kids.append(C(7, *svc))
    return S(*kids)


def main(outdir):
    c = Cap()
    pdus = []

    def add(*pdu):
        pdus.append(b"".join(pdu))
        c.epdu("HI2Operations", b"".join(pdu))

    # Records, time stamps, events
    add(iri(1, E(4, 1), E(20, 16)))                                    # Begin, attach
    add(iri(2, E(4, 2), E(20, 17), ts=ts_utc()))                       # End, utcTime
    add(iri(3, E(4, 0), E(20, 18), liid=b"L" * 25))                    # Continue
    add(iri(4, E(20, 55), indef=True))                                 # Report, indefinite length
    add(iri(4, E(29, 1), P(30, b"INVITE sip:a@example.net SIP/2.0\r\n"),
            P(31, b"\x94\x71\x32\x54"), P(32, b"\x94\x71\x32\x54\x76"), E(34, 1)))
    # Party information, IMEI/IMSI
    pi_imsi = party(3, [P(3, b"\x13\x00\x62\x11\x22\x33\x44")])
    pi_imei8 = party(3, [P(1, bytes.fromhex("5301234567890123"))])
    pi_misc = party(0, [P(2, b"tei-0001"), P(6, b"\x94\x71\x32\x54\x76"),
                        P(7, b"4915112345"), P(8, b"sip:alice@example.net"),
                        P(9, b"tel:+4915112345"), P(10, b"alice@example.net"),
                        P(11, b"asserted"), P(12, b"xui"), P(13, b"impi"),
                        P(14, "externalID")])
    pi_calls = party(1, [C(4, P(1, ISUP_NUM)), C(5, P(2, ISUP_NUM))])
    pi_calls2 = party(2, [C(4, P(2, ISUP_NUM)), C(5, P(3, ISUP_NUM))])
    pi_calls3 = party(1, [C(4, P(3, ISUP_NUM)), C(5, P(1, ISUP_NUM))])
    add(iri(1, C(9, pi_imsi, pi_imei8, pi_misc)))
    add(iri(1, C(9, party(3, [P(1, b"490154203237518")]))))              # 15 digit IMEI as text
    add(iri(1, C(9, pi_calls, pi_calls2, pi_calls3)))
    svc = C(2, C(1, OCT(b"\x01\x02"), OCT(b"\x03")), C(2, OCT(b"\x04")), C(3, OCT(b"\x05")))
    supp = C(3, C(1, C(1, OCT(b"\x01")), C(2, OCT(b"\x02")), C(3, OCT(b"\x03")),
                  C(4, OCT(b"\x04")), C(5, OCT(b"\x05")), C(6, OCT(b"\x06")),
                  C(7, OCT(b"\x07")), C(8, OCT(b"\x08")), C(9, OCT(b"\x09"))),
                C(2, P(1, b"\x01"), P(2, b"\x01\x02")), C(3, OCT(b"\x0a"), OCT(b"\x0b")))
    # (Non-Standard-Supplementary-Services is a SET OF CHOICE; see below)
    add(iri(1, C(9, party(0, [P(3, b"\x13\x00\x62\x11\x22\x33\x44")], services=None),
                party(1, [P(6, b"\x94\x71")], services=svc))))
    sdi = C(4, C(1, C(1, dna(IP_A)), P(2, APN_LABEL), P(3, b"\x01\x02"), P(4, b"\x05"), C(5, dna(IP_B))))
    add(iri(1, C(9, party(3, [P(3, b"\x13\x00\x62\x11\x22\x33\x44")], services=sdi))))
    add(iri(1, C(9, party(3, [P(3, b"\x13\x00\x62\x11\x22\x33\x44")], services=supp))))
    add(iri(1, C(9, party(3, [P(3, b"\x13\x00\x62\x11\x22\x33\x44")], services=C(2, C(1, OCT(b"\x01")), C(2, OCT(b"\x02")))))))
    add(iri(1, C(13, *party_kids(0, [P(6, b"\x94\x71\x32")]))))                  # service centre
    # Locations
    gsm_geo = C(1, P(1, b"51.500000"), P(2, b"-000.123456"), E(3, 1), I(4, 90))
    gsm_utm = C(2, P(1, b"0123456789"), P(2, b"1234567"), I(4, 10))
    gsm_utmref = C(3, PR(b"30UXC12345678"), ENUMU(2))
    gsm_wgs = P(4, b"\x01\x02\x03")
    # GSMLocation CHOICE is explicit inside [5]

    def ga(n):
        return S(ENUMU(n), INTU(8388607), INTU(-8388608))

    umts_point = C(1, ga(0))
    umts_unc = C(2, ga(1), INTU(100))
    umts_poly = C(3, S(ga(0)), S(ga(1)))
    civ1 = SET(S(P(1, "Building 7"), P(2, "12"), P(27, "SE"), P(28, "en")))
    add(iri(1, C(8, P(1, b"4915112345"), P(2, b"\x13\x00\x62\x00\x01\x00\x02"),
                P(4, b"\x13\x00\x62\x00\x01\x00"), C(5, gsm_geo), C(6, umts_point),
                P(7, b"\x13\x00\x62\x00\x01\x00\x02"), P(8, b"\x13\x00\x62\x00\x01\x00"),
                C(9, civ1), P(10, b"opspecific"), C(11, C(0, ts_local())))))
    add(iri(1, C(8, C(5, gsm_utm), C(6, umts_unc), C(9, UTF(u"<civicAddress/>")), C(11, P(1, b"")))))
    add(iri(1, C(8, C(5, gsm_utmref), C(6, umts_poly))))
    add(iri(1, C(8, C(5, gsm_wgs))))
    # Network identifier, DataNodeAddress, QoS, SMS, national
    add(iri(1, C(21, dna(IP_A)), C(24, dna(IP_B, kind=1, assign=1, prefix=64, mask=b"\xff\xff\xff\x00")),
            C(25, P(1, b"\x01\x02\x03")), C(26, *network_id(OP_ID, P(1, ISUP_NUM))),
            C(27, dna(IP_A, text=b"192.0.2.1")),
            C(28, P(2, b"25001"))))                                   # x25Address
    add(iri(1, C(25, P(2, b"\x05\x06")), C(26, *network_id(OP_ID, P(2, b"x25addr")))))
    add(iri(1, P(22, b"\x01\x02"), C(26, *network_id(OP_ID, P(3, b"iprepr")))))
    add(iri(1, C(26, *network_id(OP_ID, P(4, b"dns.example.net")))))
    add(iri(1, C(26, *network_id(OP_ID, C(5, ipaddr(IP_B))))))
    add(iri(1, C(26, *network_id(OP_ID))))
    sms = C(14, C(1, P(0, b"1234"), C(1, *network_id(OP_ID, P(1, ISUP_NUM)))), C(2, ts_utc()),
            C(3, E(1, 0), E(2, 0), E(3, 1), P(4, b"hello"),
              C(5, P(1, b"hi"), E(2, 4))))
    add(iri(1, sms))
    add(iri(1, C(14, C(1, C(1, *network_id(OP_ID))), C(2, ts_utc()), C(3, E(1, 1)))))
    add(iri(1, C(16, OCT(b"\x01\x02"), OCT(b"\x03")), C(255, P(1, b"SE"))))
    # EPS correlation number (PRIu64 reproducer), correlation values
    add(iri(1, P(18, struct.pack(">Q", 0xfedcba9876543210))))             # > 2^63: PRIu64
    add(iri(1, P(18, b"\x01\x02\x03\x04")))
    add(iri(1, C(35, C(0, C(0, OCT(b"\x01"), OCT(b"\x02")), P(1, b"\x03")))))
    add(iri(1, C(35, P(1, b"\x04"))))
    add(iri(1, C(35, C(2, C(0, C(0, OCT(b"\x05"))), P(1, b"\x06")))))
    add(iri(1, C(57, S(C(0, OCT(b"\x01")), C(1, C(0, OCT(b"\x07")))))))
    # EPS-GTPV2-SpecificParameters (.cnf)
    add(iri(1, gtp(P(1, PAA), P(2, APN_LABEL), C(3, P(1, b"\x80\x00"), P(2, b"\x80\x01")),
                   P(4, b"\x01"), P(5, b"\x05"), P(6, b"\x02"), P(7, b"\x06"),
                   P(8, b"\x10"), P(9, BEARER_QOS), E(10, 1), P(11, AMBR), P(12, b"\x01"),
                   P(13, b"\x05"), P(14, TFT), P(15, b""), P(16, b"\x01"), P(17, TFT),
                   P(18, b"\x01"), P(19, b"\x01"), P(20, IP_B), E(21, 2), P(22, b"\x01"),
                   C(23, P(1, ULI)), P(24, b"\x01"), P(25, b"\x01"), P(26, b"\x01"),
                   P(27, b"\x01"), P(28, struct.pack(">Q", 0x0123456789abcdef)),
                   P(29, IP_A), P(30, b"\x08\x00"), P(31, b"twan"), P(32, b"\x00\x00\x00\x01"),
                   C(33, S(P(1, b"user1"), P(2, IP_A)), S(P(1, b"user2"), P(2, IP_B))), P(34, b"user1"), P(35))))
    add(iri(1, gtp(P(2, APN_PLAIN))))                                         # non-compliant APN (warning)
    add(iri(1, gtp(P(2, b"\x01a"))))                                           # short label-encoded APN
    add(iri(1, gtp(C(23, P(1, b"\x18"), C(2, gsm_geo), C(3, umts_point), P(4, ULI), P(5, b"\x13\x00\x62\x00\x01"),
                        P(6, b"\x13\x00\x62\x00\x01\x00\x02\x13\x00\x62\x00\x02\x00\x03"),
                        P(7, b"\x01\x02"), C(8, civ1), P(9, b"op"), C(10, C(0, ts_local()))))))   # ULI too short: 1 octet
    add(iri(1, gtp(P(5, b"\x05"), P(13, b"\x06"), C(23, P(1, ULI)))))
    add(iri(1, gtp(P(1, b"\x02\x40" + b"\x20\x01\x0d\xb8" + b"\0" * 12))))
    add(iri(1, gtp(P(1, b"\x03\x40" + b"\x20\x01\x0d\xb8" + b"\0" * 12 + IP_A))))
    add(iri(1, C(53, ipaddr(IP_A)), C(54, P(1, ULI))))
    # Other IRI parameters
    add(iri(1, C(37, I(1, 3600), P(2, b"\x00\x00\x00\x05"), P(3, APN_LABEL),   # PMIP: APN reproducer
                 P(4, b"\0" * 20), P(5, b"\x01"), P(6, b"\x00\x00\x00\x01"), I(7, 0),
                 I(8, 1), P(9, IP_A), P(10, b"\0" * 16), P(11, IP_B), P(12, OP_ID),
                 P(13, b"\x01"), C(14, P(1, ULI)))))
    add(iri(1, C(38, I(1, 100), P(2, b"\0" * 25), P(3, b"\0" * 8), P(4, b"\0" * 8),
                 P(5, b"\0" * 16), P(6, APN_LABEL), I(7, 1), P(8, b"\x01"), P(9, b"\x02"))))
    add(iri(1, C(39, I(1, 100), P(2, IP_A), P(3, IP_B), P(4, IP_A), I(5, 2), P(7, IP_B))))
    mdec = C(42, S(P(1, b"\x11" * 4), P(2, b"\x22" * 16), P(3, b"\x33" * 14)))
    add(iri(1, mdec, E(50, 0), P(51, b"\x00\x00\x00\x01"), P(52, b"henb"),
            C(53, ipaddr(IP_A)), C(54, P(1, ULI)), C(55, P(0, b"\x00\x01"))))
    add(iri(1, C(55, P(1))))
    add(iri(1, P(40, IP_B), P(41, "visited.example.net"), P(43, IP_A),
            P(44, b"hdr"), P(45, b"hdr"), P(46, b"sdp"), P(47, b"sdp"), P(48, b"\x00" * 8)))
    # Packet data header information
    mapped = C(1, C(1, C(1, ipaddr(IP_A)), I(2, 1234), C(3, ipaddr(IP_B)), I(4, 80), I(5, 6),
                    I(6, 100), I(7, 1), I(8, 3), E(9, 1)))
    copy = C(1, C(2, E(1, 2), P(2, b"\x45\x00\x00\x14")))
    summ = C(2, S(C(1, ipaddr(IP_A)), I(2, 1), C(3, ipaddr(IP_B)), I(4, 2), I(5, 17), I(6, 3),
                  C(7, C(0, ts_local()), C(1, ts_utc())), I(8, 4), I(9, 5), E(10, 1)))
    add(iri(1, C(49, mapped)))
    add(iri(1, C(49, copy)))
    add(iri(1, C(49, summ)))
    # Other parameters
    add(iri(1, C(56, S(P(1, b"\x01"), P(2, b"\x02"), P(3), C(4, P(1, b"raw"), C(2, P(1, b"\x01")),
                       C(3, P(1, ULI)))))))
    add(iri(1, C(59, C(1, C(1, ipaddr(IP_A))), E(2, 1), P(3, "node-name-1"))))
    add(iri(1, P(60, "reason"), P(61, b"carrier"), C(62, P(1, b"sys"), C(2, C(1, dna(IP_A))), P(3, b"prev"), C(4, E(2, 1))),
            C(63, C(1, *party_kids(0, [P(6, b"\x94\x71")])), C(5, *party_kids(0, [P(3, b"\x13\x00\x62\x11")]))),
            P(64, b"rq"), E(65, 4), P(66, b"ss"), E(67, 1), P(68, b"\x94\x71"),
            P(69, b"\x13\x00\x62"), P(70, bytes.fromhex("5301234567890123"))))
    add(iri(1, C(71, P(0, "pos"), C(1, P(0, "base64")), C(2, PR("100"), PR("5")),
                P(3, "10"), P(4, "90"), P(5, "67"), B(6), C(7, P(0, "still"), C(1, PR("x")), P(2, "10")),
                C(8, PR("3"), PR("1")), P(9, "info"), P(10, "mlp")),
            I(72, 42), C(73, party(0, [P(6, b"\x94\x71")])), C(74, I(1, 3)),
            P(75, b"node"), E(76, 2), E(77, 1)))
    add(iri(1, C(74, I(2, 4)), C(80, S(C(1, C(1, P(1, "310"), P(2, "260")), P(2, b"\x04" + b"\x00" * 5)),
                                    C(2, gsm_geo), C(3, umts_point), P(4, b"20260102123456Z")))))
    ptc = C(78, P(1, "abandon"), P(2, "fail"), C(3, B(1), B(2), B(3, False), B(4), P(5, "r1"), P(6, "r2")),
            E(5, 1), C(6, P(1, "id"), E(2, 1), B(3)), P(7, "bearer"), B(8), P(9, "contact"), E(10, 2),
            C(11, E(1, 1), E(2, 2)), C(12, ts_local()), E(13, 3), P(14, "code"),
            C(15, B(1), B(2), B(3), B(4), B(5), B(6), B(7), B(8)),
            C(16, P(0, "sip:a@b"), B(1), P(2, "alias"), P(3, "nick")),
            P(17, "ad"), E(19, 2), P(20, "ch"), B(21), E(23, 1), E(24, 1), E(25, 1), P(26, "inv"),
            P(27, "ipa"), E(28, 1), E(29, 1), P(30, "lmf"), E(31, 1), P(32, "20"), P(33, "grp"),
            P(34, "mcptt"), B(35), C(36, P(1, b"4915")), P(37, "org"), B(38), E(40, 1), P(41, "pre"),
            E(42, 1), P(43, "gid"), P(44, "ids"), P(45, "cap"), P(46, "orig"), P(47, "other"),
            P(48, "part"), P(49, "party"), P(50, "drop"), P(51, "sess"), P(52, "uri"), P(53, "pol"),
            C(54, P(0, "sip:c@d"), B(1)), B(55), P(56, "pos"), E(57, 1), E(58, 0), P(59, "ret"),
            C(60, C(0, ipaddr(IP_A)), I(1, 5000)), E(61, 1), P(62, "tb"),
            C(63, P(1, "tbcp"), C(2, tl(0, False, 26, b"p1")), I(3, 7000)),
            P(64, "pres"), I(65, 5004))
    add(iri(1, ptc))
    add(iri(1, C(79, P(1, "AES"), P(2, "ctx"), P(3, "KEYPLACEHOLDER"), P(4, "base64"),
                 P(5, "SALTPLACEHOLDER"), P(6, "other"))))
    add(iri(1, E(20, 1), C(36, P(2, b"\x03abc"))))
    add(C(1, P(0, DOMAIN), P(1, b"LIID-0003"), C(3, ts_local()), E(20, 18)),)    # same as 1, untouched
    # EpsIRISequence
    add(tl(0, True, 16, iri(1, E(20, 16)) + iri(4, E(20, 55)) + iri(2, E(20, 17))))
    add(tl(0, True, 16, b""))
    # UUS1-Content in Q.931 over TPKT
    u = c
    u.tcp(flags=0x02)
    u.tcp(flags=0x12, reverse=True)
    u.tcp(flags=0x10)
    u.tcp(q931_setup(uus1(bearer=bytes([0x88, 0x90, 0xa3]), svc=[P(0, b"\x91"), P(1, b"\x01"), P(2, b"\x20"), P(3, b"\x11")])))
    u.tcp(q931_setup(uus1(direction=2, cc_link=None)))
    u.tcp(q931_setup(uus1(direction=0, bearer=b"\x80")), reverse=True)
    c.write(os.path.join(outdir, "HI2Operations-coverage.pcapng"))
    mal(outdir, pdus)


def mal(outdir, pdus):
    """Malformed and rejected input."""
    import random
    rnd = random.Random(23)
    m = Cap()
    # Truncated copies: BER lengths promise more than the frame holds
    for i in range(0, len(pdus), 3):
        p = pdus[i]
        if len(p) < 12:
            continue
        for cut in (len(p) // 3, 2 * len(p) // 3, len(p) - 1):
            m.epdu("HI2Operations", p[:cut])
    # Single bit/byte mutations of the PDUs that reach the .cnf code
    for i in range(len(pdus)):
        p = bytearray(pdus[i])
        if len(p) < 12:
            continue
        for _ in range(2):
            q = bytearray(p)
            for _ in range(3):
                q[rnd.randrange(8, len(q))] = rnd.randrange(256)
            m.epdu("HI2Operations", bytes(q))
    # Short values in the .cnf fields

    def one(*kids):
        m.epdu("HI2Operations", iri(1, *kids))
    one(P(18, b""))                                          # EPS correlation number of length 0
    one(P(18, b"\x01" * 9))                                  # longer than 8 octets
    one(gtp(P(1, b"")))
    one(gtp(P(1, b"\x01")))
    one(gtp(P(1, b"\x02\x40\x00")))
    one(gtp(P(9, b"\x00")))
    one(gtp(P(11, b"\x00")))
    one(gtp(P(14, b"")))
    one(gtp(P(14, b"\x21")))
    one(gtp(C(23, P(1, b""))))
    one(gtp(C(23, P(1, b"\x18\x13\x00"))))
    one(gtp(P(2, b"")))
    one(C(9, party(3, [P(1, b"")])))
    one(C(9, party(3, [P(1, b"\x01\x02\x03")])))
    one(C(9, party(3, [P(3, b"")])))
    one(C(26, *network_id(b"", P(1, b""))))
    one(C(26, *network_id(b"\xff\xff\xff", P(1, b"\x01"))))
    one(C(37, P(3, b"")))
    one(C(37, P(3, b"\x40" + b"a" * 20)))
    one(C(38, P(6, b"")))
    for sel in (b"", b"\x01", b"\x30\x80"):
        m.epdu("HI2Operations", sel)
    m.epdu("HI2Operations", b"\xa1\x80" + b"\x80\x00" * 3)             # indefinite length
    # UUS1-Content heuristic rejects (each in its own Q.931 SETUP)
    m.tcp(flags=0x02)
    m.tcp(flags=0x12, reverse=True)
    m.tcp(flags=0x10)
    good = uus1()
    for uu in (b"\x30\x03\x80\x01\x01",                       # shorter than 6 octets
               b"\x80\x0b" + good[2:],                        # not a universal tag
               b"\x10\x0b" + good[2:],                        # not constructed
               b"\x31" + good[1:],                              # SET, not SEQUENCE
               b"\x30\x0b\x40\x09" + good[4:],               # first element not context class
               b"\x30\x0b\xa1\x09" + good[4:],               # context but constructed
               b"\x30\x0b\x82\x09" + good[4:],               # context tag 2
               uus1(bearer=b"\x88"),
               uus1(bearer=b"\x88\x90\xa3\x01\x02\x03\x04\x05\x06\x07\x08\x09")[:-3],
               uus1()[:30]):
        m.tcp(q931_setup(uu))
    m.write(os.path.join(outdir, "HI2Operations-coverage-malformed.pcapng"))


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else ".")
