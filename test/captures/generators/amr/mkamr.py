#!/usr/bin/env python3
# AMR coverage capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""AMR (packet-amr.c).

Usage: mkamr.py [<output directory>]

Writes:
  amr-coverage.pcapng            main capture (interface 0 Ethernet,
                                 interface 1 Exported PDU):
    - SIP/SDP calls over UDP that set up RTP sessions with
      a=rtpmap AMR/8000 and AMR-WB/16000 and a=fmtp variants
      (none, octet-align=0/1, crc, interleaving, robust-sorting),
      followed by RTP carrying AMR and AMR-WB in the matching format
    - an RTP flow with no SDP, decoded with Decode As
      (-d udp.port==50000,rtp -d rtp.pt==97,amr -d rtp.pt==98,amr-wb)
      so the AMR preferences apply
    - Exported PDUs (tag 12, dissector name) for "amr", "amr-wb",
      "amr_if1_nb", "amr_if1_wb", "amr_if2_nb" and "amr_if2_wb"
    - the case of "Exported PDU: Only give the TCP information to
      TCP dissectors": "amr"/"amr-wb" with a TCP info tag (tag 34)
    - an H.245 TerminalCapabilitySet (exported PDU "h245dg") with
      genericAudioCapability for GSM AMR (0.0.8.245.1.1.1) and G.722.2
      (0.0.7.7222.1.0), whose parameters are named by dissect_amr_name()
  amr-coverage-malformed.pcapng  paths that end in error expert infos or
                                 exceptions

Every packet is built here; nothing comes from a real network.
"""

import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct

from capgen import (LINKTYPE_ETHERNET, LINKTYPE_WIRESHARK_UPPER_PDU, Pcapng,  # noqa: E402
                    eth, ipv4, udp)

FB_NB = [95, 103, 118, 134, 148, 159, 204, 244, 39, 43, 38, 37, 0, 0, 0, 0]
FB_WB = [132, 177, 253, 285, 317, 365, 397, 461, 477, 40, 0, 0, 0, 0, 0, 0]

NB, WB = 0, 1


# ---------------------------------------------------------------------------
# Bit writer, used for AMR bandwidth-efficient payloads and H.245 PER

class Bits:
    def __init__(self):
        self.bits = []

    def put(self, value, n):
        for i in range(n - 1, -1, -1):
            self.bits.append((value >> i) & 1)
        return self

    def align(self):
        while len(self.bits) % 8:
            self.bits.append(0)
        return self

    def raw(self, data):
        self.align()
        for b in data:
            self.put(b, 8)
        return self

    def bytes(self):
        self.align()
        return bytes(int(''.join(map(str, self.bits[i:i + 8])), 2)
                     for i in range(0, len(self.bits), 8))


def speech_bits(nbits, seed):
    """A deterministic pattern of nbits bits."""
    b = Bits()
    for i in range(nbits):
        b.put(((i * 7 + seed) >> 2) & 1, 1)
    return b.bits


# ---------------------------------------------------------------------------
# AMR payload builders

def amr_oa(mode, frames, cmr=15, il=None, crc=False, toc_pad=0):
    """Octet-aligned payload. frames is a list of (ft, q)."""
    fb = FB_NB if mode == NB else FB_WB
    out = bytearray([cmr << 4])
    if il is not None:
        out.append((il[0] << 4) | il[1])
    for i, (ft, q) in enumerate(frames):
        f = 1 if i < len(frames) - 1 else 0
        out.append((f << 7) | (ft << 3) | (q << 2) | toc_pad)
    if crc:
        for i, _ in enumerate(frames):
            out.append(0xa0 + i)
    for i, (ft, q) in enumerate(frames):
        b = Bits()
        b.bits = speech_bits(fb[ft], i + ft)
        out += b.bytes()
    return bytes(out)


def amr_be(mode, frames, cmr=15):
    """Bandwidth-efficient payload."""
    fb = FB_NB if mode == NB else FB_WB
    b = Bits().put(cmr, 4)
    for i, (ft, q) in enumerate(frames):
        f = 1 if i < len(frames) - 1 else 0
        b.put(f, 1).put(ft, 4).put(q, 1)
    for i, (ft, q) in enumerate(frames):
        b.bits += speech_bits(fb[ft], i + ft)
    return b.bytes()


def mac(ip):
    return b'\x02\x00' + bytes(ip)


class Capture:
    ETH, EXP = 0, 1

    def __init__(self):
        self.frames = []    # (interface, data)
        self.ipid = 0

    def udp(self, src, sport, dst, dport, payload):
        seg = udp(payload, sport, dport, src=bytes(src), dst=bytes(dst))
        self.ipid += 1
        ip = ipv4(seg, 17, src=bytes(src), dst=bytes(dst), ident=self.ipid & 0xffff,
                  flags_frag=0x4000)
        self.frames.append((self.ETH, eth(ip, 0x0800, dst=mac(dst), src=mac(src))))

    def exp(self, name, payload, tcpinfo=False):
        # The tag values are not padded to four octets (capgen.exported_pdu()
        # pads), so the TLVs are built here.
        def tlv(t, v):
            return struct.pack('>HH', t, len(v)) + v
        tags = tlv(12, name.encode())
        if tcpinfo:
            # EXP_PDU_TAG_TCP_INFO_DATA, version 1
            tags += tlv(34, struct.pack('>HIIIBHH', 1, 1, 2, 3, 0, 0x18, 0))
        self.frames.append((self.EXP, tags + tlv(0, b'') + payload))

    def write(self, path):
        w = Pcapng()
        w.interface(LINKTYPE_ETHERNET)
        w.interface(LINKTYPE_WIRESHARK_UPPER_PDU)
        for i, (intf, data) in enumerate(self.frames):
            usec = i * 20000
            w.packet(intf, data, ts=(1700000000 + usec // 1000000, usec % 1000000))
        w.write(path)


# ---------------------------------------------------------------------------
# SIP/SDP and RTP

def sip_msg(start, headers, sdp):
    body = sdp.encode()
    h = start + '\r\n' + ''.join('%s: %s\r\n' % kv for kv in headers)
    h += 'Content-Length: %d\r\n\r\n' % len(body)
    return h.encode() + body


def sdp_body(ip, port, sess, payloads):
    """payloads: list of (pt, rtpmap, [fmtp lines])"""
    s = ('v=0\r\no=- %d 1 IN IP4 %s\r\ns=AMR test\r\nc=IN IP4 %s\r\nt=0 0\r\n'
         % (sess, ip, ip))
    s += 'm=audio %d RTP/AVP %s\r\n' % (port, ' '.join(str(p[0]) for p in payloads))
    for pt, rtpmap, fmtps in payloads:
        s += 'a=rtpmap:%d %s\r\n' % (pt, rtpmap)
        for f in fmtps:
            s += 'a=fmtp:%d %s\r\n' % (pt, f)
    s += 'a=ptime:20\r\na=sendrecv\r\n'
    return s


def ipstr(ip):
    return '.'.join(map(str, ip))


def sip_call(cap, callid, a, b, aport, bport, payloads, sess):
    """INVITE with SDP offer, 200 OK with the same payloads as answer, ACK."""
    common = [('Via', 'SIP/2.0/UDP %s:5060;branch=z9hG4bK%s' % (ipstr(a), callid)),
              ('From', '<sip:alice@%s>;tag=a%s' % (ipstr(a), callid)),
              ('To', '<sip:bob@%s>' % ipstr(b)),
              ('Call-ID', '%s@%s' % (callid, ipstr(a)))]
    inv = sip_msg('INVITE sip:bob@%s SIP/2.0' % ipstr(b),
                  common + [('CSeq', '1 INVITE'),
                            ('Contact', '<sip:alice@%s>' % ipstr(a)),
                            ('Max-Forwards', '70'),
                            ('Content-Type', 'application/sdp')],
                  sdp_body(ipstr(a), aport, sess, payloads))
    cap.udp(a, 5060, b, 5060, inv)
    common_ok = common[:2] + [('To', '<sip:bob@%s>;tag=b%s' % (ipstr(b), callid))] + common[3:]
    ok = sip_msg('SIP/2.0 200 OK',
                 common_ok + [('CSeq', '1 INVITE'),
                              ('Contact', '<sip:bob@%s>' % ipstr(b)),
                              ('Content-Type', 'application/sdp')],
                 sdp_body(ipstr(b), bport, sess + 1, payloads))
    cap.udp(b, 5060, a, 5060, ok)
    ack = sip_msg('ACK sip:bob@%s SIP/2.0' % ipstr(b),
                  common_ok + [('CSeq', '1 ACK'), ('Max-Forwards', '70')], '')
    cap.udp(a, 5060, b, 5060, ack)


class Rtp:
    def __init__(self, cap, src, sport, dst, dport, ssrc):
        self.cap, self.src, self.sport, self.dst, self.dport = cap, src, sport, dst, dport
        self.ssrc, self.seq, self.ts = ssrc, 1000, 160000
        self.first = True

    def send(self, pt, payload, step=160):
        hdr = struct.pack('>BBHII', 0x80, (0x80 if self.first else 0) | pt,
                          self.seq, self.ts, self.ssrc)
        self.first = False
        self.seq += 1
        self.ts += step
        self.cap.udp(self.src, self.sport, self.dst, self.dport, hdr + payload)


# ---------------------------------------------------------------------------
# H.245 (PER aligned) TerminalCapabilitySet with genericAudioCapability

def ber_oid(oid):
    arcs = [int(x) for x in oid.split('.')]
    out = bytearray([arcs[0] * 40 + arcs[1]])
    for a in arcs[2:]:
        enc = [a & 0x7f]
        a >>= 7
        while a:
            enc.insert(0, 0x80 | (a & 0x7f))
            a >>= 7
        out += bytes(enc)
    return bytes(out)


def per_oid(b, oid):
    o = ber_oid(oid)
    b.align().put(len(o), 8).raw(o)


# ParameterValue choice indexes
LOGICAL, BOOLARRAY, UMIN, UMAX = 0, 1, 2, 3


def generic_capability(oid, params, max_bit_rate=None):
    """GenericCapability with collapsing parameters [(id, kind, value)]."""
    b = Bits()
    b.put(0, 1)                                      # extension
    b.put(max_bit_rate is not None, 1).put(1, 1).put(0, 1).put(0, 1).put(0, 1)
    b.put(0, 1).put(0, 2)                            # CapabilityIdentifier: standard
    per_oid(b, oid)
    if max_bit_rate is not None:                     # INTEGER (0..4294967295)
        b.put(0, 2).align().put(max_bit_rate, 8)     # one octet
    b.align().put(len(params), 8)                    # SEQUENCE OF length
    for pid, kind, value in params:
        b.put(0, 1).put(0, 1)                        # ext, no supersedes
        b.put(0, 1).put(0, 2).put(pid, 7)            # ParameterIdentifier standard
        b.put(0, 1).put(kind, 3)                     # ParameterValue
        if kind == BOOLARRAY:
            b.align().put(value, 8)
        elif kind in (UMIN, UMAX):
            b.align().put(value, 16)
    return b.bytes()


def h245_tcs(seq, entries):
    """entries: [(entry number, capability choice index, GenericCapability)]"""
    b = Bits()
    b.put(0, 1).put(0, 2)                    # MultimediaSystemControlMessage: request
    b.put(0, 1).put(2, 4)                    # RequestMessage: terminalCapabilitySet
    b.put(0, 1).put(0, 1).put(1, 1).put(0, 1)  # ext, capabilityTable only
    b.align().put(seq, 8)
    per_oid(b, '0.0.8.245.0.15')
    b.align().put(len(entries) - 1, 8)       # SET SIZE (1..256)
    for num, capidx, gcap in entries:
        b.put(1, 1)                          # capability present
        b.align().put(num - 1, 16)           # CapabilityTableEntryNumber
        b.put(0, 1).put(capidx, 4)           # Capability: *AudioCapability
        b.put(1, 1).put(0, 1).put(6, 6)      # AudioCapability ext: genericAudioCapability
        b.align().put(len(gcap), 8).raw(gcap)  # open type
    return b.bytes()


# ---------------------------------------------------------------------------
# Main capture

CALLER, CALLEE = (10, 0, 0, 1), (10, 0, 0, 2)
WB_CALLER, WB_CALLEE = (10, 0, 0, 3), (10, 0, 0, 4)
DA_SRC, DA_DST = (10, 0, 0, 5), (10, 0, 0, 6)


def main_capture():
    cap = Capture()

    # ---- Call 1: AMR-NB, one payload type per fmtp variant
    nb_payloads = [
        (96, 'AMR/8000', []),                                      # BE
        (97, 'AMR/8000', ['octet-align=1; mode-set=0,2,5,7']),     # OA
        (98, 'AMR/8000', ['octet-align=1; crc=1']),                # OA + CRC
        (99, 'AMR/8000', ['octet-align=1; interleaving=4']),       # OA + ILL/ILP
        (100, 'AMR/8000', ['robust-sorting=1; interleaving=2']),   # OA via robust-sorting
        (101, 'AMR/8000', ['octet-align=0; crc=0; robust-sorting=0',
                           'interleaving=none; mode-change-period=2']),  # BE
        (102, 'AMR/8000/1', ['crc=1']),                            # OA via crc
    ]
    sip_call(cap, 'nb1', CALLER, CALLEE, 30000, 40000, nb_payloads, 1000)
    up = Rtp(cap, CALLER, 30000, CALLEE, 40000, 0x11110001)
    down = Rtp(cap, CALLEE, 40000, CALLER, 30000, 0x22220001)

    # PT 96, bandwidth-efficient: every frame type, CMR values, several
    # frames, NO_DATA, a damaged frame
    for ft in range(16):
        up.send(96, amr_be(NB, [(ft, 1)], cmr=ft if ft < 8 else 15))
    up.send(96, amr_be(NB, [(7, 1), (7, 1), (5, 0)], cmr=3))
    up.send(96, amr_be(NB, [(8, 1), (15, 1)]))
    down.send(96, amr_be(NB, [(0, 1), (1, 1), (2, 1), (3, 1), (4, 1)], cmr=7))
    # PT 97, octet-aligned
    for ft in list(range(12)) + [15]:
        down.send(97, amr_oa(NB, [(ft, 1)], cmr=ft if ft < 8 else 15))
    down.send(97, amr_oa(NB, [(7, 1), (6, 0), (8, 1)], cmr=2))
    # octet-align=1 announced but the packet is bandwidth-efficient
    # (reserved bits set): warning and decoded as bandwidth-efficient
    down.send(97, amr_be(NB, [(7, 1)], cmr=15))
    # PT 98, octet-aligned with CRCs
    up.send(98, amr_oa(NB, [(7, 1)], crc=True))
    up.send(98, amr_oa(NB, [(4, 1), (5, 1), (8, 1)], cmr=1, crc=True))
    # PT 99, interleaving=4: ILL 3, ILP 0..3; then ILL+1 > 4 and ILP > ILL
    for ilp in range(4):
        up.send(99, amr_oa(NB, [(7, 1), (7, 1)], il=(3, ilp)))
    up.send(99, amr_oa(NB, [(2, 1)], il=(4, 0)))   # ILL too big (warning)
    up.send(99, amr_oa(NB, [(2, 1)], il=(1, 3)))   # ILP > ILL (warning)
    # PT 100, robust-sorting=1, interleaving=2
    up.send(100, amr_oa(NB, [(6, 1), (6, 1)], il=(1, 0)))
    up.send(100, amr_oa(NB, [(6, 1), (6, 1)], il=(1, 1)))
    # PT 101, octet-align=0, interleaving not a number: bandwidth-efficient
    down.send(101, amr_be(NB, [(5, 1), (5, 1)], cmr=0))
    # PT 102, crc=1 only: octet-aligned with CRC
    down.send(102, amr_oa(NB, [(0, 1), (1, 1)], crc=True))

    # ---- Call 2: AMR-WB
    wb_payloads = [
        (104, 'AMR-WB/16000', []),
        (105, 'AMR-WB/16000/1', ['octet-align=1']),
        (106, 'AMR-WB/16000', ['octet-align=1;crc=1']),
        (107, 'AMR-WB/16000', ['octet-align=1;interleaving=3']),
        (108, 'AMR-WB/16000', ['robust-sorting=1']),
        (109, 'AMR-WB/16000', ['octet-align=0']),
    ]
    sip_call(cap, 'wb1', WB_CALLER, WB_CALLEE, 32000, 42000, wb_payloads, 2000)
    up = Rtp(cap, WB_CALLER, 32000, WB_CALLEE, 42000, 0x33330001)
    down = Rtp(cap, WB_CALLEE, 42000, WB_CALLER, 32000, 0x44440001)
    for ft in list(range(10)) + [14, 15]:
        up.send(104, amr_be(WB, [(ft, 1)], cmr=ft if ft < 9 else 15), step=320)
    up.send(104, amr_be(WB, [(8, 1), (8, 1), (2, 0)], cmr=8), step=320)
    for ft in list(range(10)) + [14, 15]:
        down.send(105, amr_oa(WB, [(ft, 1)], cmr=ft if ft < 9 else 15), step=320)
    down.send(105, amr_oa(WB, [(1, 1), (9, 1)], cmr=4), step=320)
    down.send(105, amr_be(WB, [(7, 1)]), step=320)    # reserved bits set
    up.send(106, amr_oa(WB, [(2, 1), (2, 1)], crc=True), step=320)
    up.send(107, amr_oa(WB, [(0, 1)], il=(2, 1)), step=320)
    up.send(107, amr_oa(WB, [(0, 1)], il=(5, 6)), step=320)   # both warnings
    up.send(108, amr_oa(WB, [(3, 1), (4, 1)]), step=320)
    down.send(109, amr_be(WB, [(6, 1)], cmr=6), step=320)

    # ---- RTP without SDP, decoded with Decode As (preferences apply)
    da = Rtp(cap, DA_SRC, 50000, DA_DST, 50002, 0x55550001)
    da.send(97, amr_oa(NB, [(7, 1)]))
    da.send(97, amr_oa(NB, [(4, 1), (4, 1)], cmr=4))
    da.send(97, amr_be(NB, [(7, 1)]))       # reserved bits set: decoded as BE
    da.send(98, amr_oa(WB, [(8, 1)]), step=320)
    da.send(98, amr_oa(WB, [(9, 1)]), step=320)

    # ---- Exported PDUs: the reproducer, with a TCP info tag. The AMR-WB
    # one carries a full 23.85 kbit/s frame so it decodes cleanly.
    cap.exp('amr', bytes([0xf0, 0x3c]) + b'\x00' * 31, tcpinfo=True)
    cap.exp('amr-wb', bytes([0xf0, 0x44]) + b'\x00' * 60, tcpinfo=True)
    # "amr" and "amr-wb" without RTP information: preferences apply
    cap.exp('amr', amr_oa(NB, [(7, 1), (8, 1)], cmr=5))
    cap.exp('amr', amr_be(NB, [(6, 1)]))             # reserved bits set
    cap.exp('amr-wb', amr_oa(WB, [(2, 1)], cmr=2))
    cap.exp('amr-wb', amr_be(WB, [(7, 1)]))
    # IF1 / IF2 named dissectors (3GPP TS 26.101 / 26.201)
    cap.exp('amr_if1_nb', bytes([(7 << 4) | 0x08 | 7, 7 << 5]) + bytes(31))   # 12.2
    cap.exp('amr_if1_nb', bytes([(0 << 4) | 0x08 | 0, 2 << 5]) + bytes(12))
    cap.exp('amr_if1_nb', bytes([(8 << 4) | 0x08, 3 << 5]) + bytes(5) + bytes([0x10 | (4 << 1)]))  # SID
    cap.exp('amr_if1_nb', bytes([(8 << 4) | 0x08, (3 << 5) | 0x05]) + bytes(5) + bytes([0x02]))  # SID, spare bits
    cap.exp('amr_if1_nb', bytes([(5 << 4) | 0x08 | 5, (5 << 5) | 0x01]) + bytes(20))   # spare bits
    cap.exp('amr_if1_wb', bytes([(8 << 4) | 0x08, (8 << 4) | 2]) + bytes(60))
    cap.exp('amr_if1_wb', bytes([(0 << 4), (0 << 4) | 0]) + bytes(17))
    cap.exp('amr_if1_wb', bytes([(9 << 4) | 0x08, 0x03]) + bytes(5) + bytes([0x10 | 2]))  # SID
    cap.exp('amr_if1_wb', bytes([(2 << 4) | 0x08 | 0x01, 0x22]) + bytes(32))  # spare bits
    cap.exp('amr_if2_nb', bytes([0x70 | 7]) + bytes(30))
    cap.exp('amr_if2_nb', bytes([0x00 | 2]) + bytes(14))
    cap.exp('amr_if2_nb', bytes([8, 0, 0, 0, 0x80, 0x05]))     # SID
    cap.exp('amr_if2_nb', bytes([15]))                        # NO_DATA
    cap.exp('amr_if2_wb', bytes([(8 << 4) | 0x0a]) + bytes(59))
    cap.exp('amr_if2_wb', bytes([(1 << 4)]) + bytes(22))
    cap.exp('amr_if2_wb', bytes([9 << 4, 0, 0, 0, 0, 0x80 | (3 << 3)]))   # SID
    cap.exp('amr_if2_wb', bytes([15 << 4]))                   # NO_DATA

    # ---- H.245 TerminalCapabilitySet: GSM AMR and G.722.2 capabilities
    amr_cap = generic_capability('0.0.8.245.1.1.1', [
        (0, UMAX, 1),          # maxAl-sduAudioFrames
        (1, UMIN, 122),        # bitRate
        (2, LOGICAL, 0),       # gsmAmrComfortNoise
        (3, LOGICAL, 0),       # gsmEfrComfortNoise
        (4, LOGICAL, 0),       # is-641ComfortNoise
        (5, LOGICAL, 0),       # pdcEFRComfortNoise
        (6, LOGICAL, 0),       # not in the table
    ], max_bit_rate=122)
    g7222_cap = generic_capability('0.0.7.7222.1.0', [
        (0, UMAX, 2),          # maxAl-sduFrames
        (1, UMIN, 239),        # bitRate
        (2, LOGICAL, 0),       # octetAlign
        (3, BOOLARRAY, 0xa5),  # modeSet
        (4, UMAX, 2),          # modeChangePeriod
        (5, LOGICAL, 0),       # modeChangeNeighbour
        (6, LOGICAL, 0),       # crc
        (7, LOGICAL, 0),       # robustSorting
        (8, UMAX, 4),          # interleaving
    ])
    cap.exp('h245dg', h245_tcs(1, [(1, 4, amr_cap), (2, 6, g7222_cap)]))
    return cap


# ---------------------------------------------------------------------------
# Malformed capture: error expert infos and exceptions

def malformed_capture():
    cap = Capture()
    nb_payloads = [
        (96, 'AMR/8000', []),
        (97, 'AMR/8000', ['octet-align=1']),
        (98, 'AMR/8000', ['octet-align=1; crc=1; interleaving=4']),
    ]
    sip_call(cap, 'bad1', CALLER, CALLEE, 30000, 40000, nb_payloads, 3000)
    up = Rtp(cap, CALLER, 30000, CALLEE, 40000, 0x66660001)
    wb_payloads = [(104, 'AMR-WB/16000', []), (105, 'AMR-WB/16000', ['octet-align=1'])]
    sip_call(cap, 'bad2', WB_CALLER, WB_CALLEE, 32000, 42000, wb_payloads, 4000)
    wup = Rtp(cap, WB_CALLER, 32000, WB_CALLEE, 42000, 0x77770001)

    # BE: not enough data, superfluous data with the padding bit set
    # (padding_bits_correct) and clear (padding_bits_not0), exact octets
    up.send(96, amr_be(NB, [(7, 1)])[:10])
    up.send(96, amr_be(NB, [(6, 1)]) + b'\xff\xff')   # 214 bits: pad bit 1
    p = bytearray(amr_be(NB, [(6, 1)]))
    p[-1] |= 0x01
    up.send(96, bytes(p) + b'\x00')
    up.send(96, amr_be(NB, [(6, 1)]) + b'\x00')       # pad bits zero
    up.send(96, amr_be(NB, [(0, 1)]) + b'\x00\x00')
    up.send(96, b'\xf4')                               # throws
    # OA: not enough data, superfluous data with pad bits, ToC padding
    up.send(97, amr_oa(NB, [(7, 1)])[:10])
    p = bytearray(amr_oa(NB, [(0, 1)]))
    p[-1] |= 0x01 << (8 - (95 % 8) - 1)
    up.send(97, bytes(p) + b'\x00')                   # padding_bits_correct
    up.send(97, amr_oa(NB, [(0, 1)]) + b'\x00')       # padding_bits_not0
    up.send(97, amr_oa(NB, [(8, 1)], toc_pad=2))      # ToC P bit set
    up.send(97, amr_oa(NB, [(7, 1)]) + b'\x00\x00')   # 244 bits: no pad check
    up.send(97, b'\xf0' + b'\x80' * 4)                # ToC runs off the end
    up.send(98, b'\xf0')                              # no ILL/ILP octet
    up.send(98, amr_oa(NB, [(7, 1), (7, 1)], il=(3, 0), crc=True)[:5])
    wup.send(104, amr_be(WB, [(8, 1)])[:20], step=320)
    wup.send(104, amr_be(WB, [(2, 1)]) + b'\xff', step=320)
    wup.send(105, amr_oa(WB, [(8, 1)])[:30], step=320)
    wup.send(105, amr_oa(WB, [(0, 1)]) + b'\x00', step=320)

    # The reproducer as it was, with a short AMR-WB payload
    cap.exp('amr', bytes([0xf0, 0x3c]) + b'\x00' * 31, tcpinfo=True)
    cap.exp('amr-wb', bytes([0xf0, 0x44]) + b'\x00' * 40, tcpinfo=True)
    # Truncated IF1/IF2 frames
    cap.exp('amr_if1_nb', bytes([8 << 4, 0]))
    cap.exp('amr_if1_wb', bytes([9 << 4, 0, 0]))
    cap.exp('amr_if2_nb', bytes([8, 0]))
    cap.exp('amr_if2_wb', bytes([9 << 4]))
    cap.exp('amr_if1_nb', b'')
    cap.exp('amr', b'')
    cap.exp('amr-wb', b'\x00')
    return cap


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    main_capture().write(os.path.join(out, 'amr-coverage.pcapng'))
    malformed_capture().write(os.path.join(out, 'amr-coverage-malformed.pcapng'))


if __name__ == '__main__':
    main()
