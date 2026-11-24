#!/usr/bin/env python3
# Generates test/captures/ositp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the COTP / CLTP (packet-ositp.c) coverage captures.

Usage: mkositp.py <outdir>
Writes
  ositp-coverage.pcap            plain OSI TPDUs, default preferences
  ositp-coverage-atn.pcap        ATN TPDUs, decoded with cotp.decode_atn:TRUE
  ositp-coverage-malformed.pcap  error paths (not added to the tree)
Nothing comes from a real network.

COTP is reached by default: over CLNP (LLC SAP 0xFE, NSEL 0x21, plus the
Inactive Subset NLPID 0x00), over IP protocol 39, over TPKT on TCP port 102
and, for CLTP, over UDP with the heuristic (R-GOOSE SPDU).
"""
import os
import struct
import sys

MAC_DST = bytes.fromhex('020000000002')
MAC_SRC = bytes.fromhex('020000000001')
IP_SRC = (192, 0, 2, 1)
IP_DST = (198, 51, 100, 2)

# ------------------------------------------------------------ CLNP helpers


def nsap(sysid, nsel):
    return bytes.fromhex('47000580ffff000000000100010000') + bytes([0x00]) \
        + struct.pack('>I', sysid)[1:] + bytes([nsel])


NSAP_A = lambda nsel: nsap(0x0a0b0c, nsel)
NSAP_B = lambda nsel: nsap(0x0d0e0f, nsel)
DT = 0x1c


def csum16(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def fletcher_clnp(hdr, pos):
    c0 = c1 = 0
    for b in hdr:
        c0 = (c0 + b) % 255
        c1 = (c1 + c0) % 255
    n = pos + 1
    L = len(hdr)
    x = ((L - n) * c0 - c1) % 255
    y = ((L - n + 1) * (-c0) + c1) % 255
    return (x or 255), (y or 255)


def clnp(data, dst=None, src=None, ttl=30, cksum=True):
    dst = NSAP_B(0x21) if dst is None else dst
    src = NSAP_A(0x21) if src is None else src
    addr = bytes([len(dst)]) + dst + bytes([len(src)]) + src
    hl = 9 + len(addr)
    h = bytes([0x81, hl, 1, ttl, DT]) + struct.pack('>HH', hl + len(data), 0) + addr
    if cksum:
        x, y = fletcher_clnp(h, 7)
        h = h[:7] + bytes([x, y]) + h[9:]
    return h + data


def llc_frame(pdu):
    llc = b'\xfe\xfe\x03' + pdu
    return MAC_DST + MAC_SRC + struct.pack('>H', len(llc)) + llc


def ip_hdr(payload, proto, ident=1, src=IP_SRC, dst=IP_DST):
    hdr = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0,
                      64, proto, 0, bytes(src), bytes(dst))
    return hdr[:10] + struct.pack('>H', csum16(hdr)) + hdr[12:] + payload


def ip_frame(payload, proto, ident=1, src=IP_SRC, dst=IP_DST):
    return MAC_DST + MAC_SRC + b'\x08\x00' + ip_hdr(payload, proto, ident, src, dst)


_seq = {}


def tcp_frame(payload, sport, dport, ident=1, src=IP_SRC, dst=IP_DST, flags=0x18):
    key = (sport, dport)
    seq = _seq.get(key, 5000 if sport == 102 else 1000)
    _seq[key] = seq + len(payload)
    ack = _seq.get((dport, sport), 5000 if dport == 102 else 1000)
    tcp = struct.pack('>HHIIBBHHH', sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0) + payload
    ph = bytes(src) + bytes(dst) + struct.pack('>BBH', 0, 6, len(tcp))
    tcp = tcp[:16] + struct.pack('>H', csum16(ph + tcp)) + tcp[18:]
    return ip_frame(tcp, 6, ident, src, dst)


def udp_frame(payload, sport, dport, ident=1):
    udp = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    ph = bytes(IP_SRC) + bytes(IP_DST) + struct.pack('>BBH', 0, 17, len(udp))
    udp = udp[:6] + struct.pack('>H', csum16(ph + udp) or 0xffff) + udp[8:]
    return ip_frame(udp, 17, ident)


def tpkt(payload):
    return struct.pack('>BBH', 3, 0, 4 + len(payload)) + payload


# ------------------------------------------------------------ TPDU helpers

CR, CC, DR, DTP, ED, RJ, DCT, AK, EA, ER, UD = 0xe, 0xd, 0x8, 0xf, 0x1, 0x5, 0xc, 0x6, 0x2, 0x7, 0x4

# parameter codes
P_ACK, P_RES, P_PRIO, P_TRANSIT, P_THRU, P_SEQ, P_REASSIGN, P_FLOW = 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c
P_TPDUSIZE, P_SRC, P_DST, P_CKSUM, P_VERSION, P_PROT, P_OPT, P_CLASS = 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7
P_CLEAR, P_PREF, P_INACT, P_EC32, P_EC16 = 0xe0, 0xf0, 0xf2, 0x08, 0x09


def vp(code, val):
    return bytes([code, len(val)]) + val


def fix_iso_checksum(tpdu, pos):
    """tpdu has 0000 at pos; set the ISO 8073 checksum so C0 = C1 = 0."""
    c0 = c1 = 0
    for b in tpdu:
        c0 = (c0 + b) % 255
        c1 = (c1 + c0) % 255
    L = len(tpdu)
    x = ((L - pos - 1) * c0 - c1) % 255
    y = (-c0 - x) % 255
    return tpdu[:pos] + bytes([x, y]) + tpdu[pos + 2:]


def with_cksum(tpdu_builder):
    """Build a TPDU through tpdu_builder(zero checksum value) and fix it."""
    t = tpdu_builder(b'\0\0')
    pos = t.index(bytes([P_CKSUM, 2])) + 2
    return fix_iso_checksum(t, pos)


def cr_cc(kind, dst, src, cls=0, opts=0, var=b'', data=b''):
    body = struct.pack('>HHB', dst, src, (cls << 4) | opts) + var
    return bytes([1 + len(body), (kind << 4)]) + body + data


def dr(dst, src, reason, var=b'', data=b''):
    body = struct.pack('>HHB', dst, src, reason) + var
    return bytes([1 + len(body), DR << 4]) + body + data


def dtp(dst, nr, eot=True, ext=False, var=b'', data=b'', cls234=True, kind=DTP):
    if not cls234:
        n = (0x80 if eot else 0) | nr
        return bytes([2, kind << 4, n]) + data
    if ext:
        n = struct.pack('>I', (0x80000000 if eot else 0) | nr)
    else:
        n = bytes([(0x80 if eot else 0) | nr])
    body = struct.pack('>H', dst) + n + var
    return bytes([1 + len(body), kind << 4]) + body + data


def rj(dst, nr, cdt=0, ext=False, credit=0, var=b''):
    if ext:
        body = struct.pack('>HIH', dst, nr, credit) + var
    else:
        body = struct.pack('>HB', dst, nr) + var
    return bytes([1 + len(body), (RJ << 4) | cdt]) + body


def dc(dst, src, var=b''):
    body = struct.pack('>HH', dst, src) + var
    return bytes([1 + len(body), DCT << 4]) + body


def ak(dst, nr, cdt=0, ext=False, credit=0, var=b''):
    if ext:
        body = struct.pack('>HIH', dst, nr, credit) + var
    else:
        body = struct.pack('>HB', dst, nr) + var
    return bytes([1 + len(body), (AK << 4) | cdt]) + body


def ea(dst, nr, ext=False, var=b''):
    n = struct.pack('>I', nr) if ext else bytes([nr])
    body = struct.pack('>H', dst) + n + var
    return bytes([1 + len(body), EA << 4]) + body


def er(dst, cause, var=b''):
    body = struct.pack('>HB', dst, cause) + var
    return bytes([1 + len(body), ER << 4]) + body


def ud(var=b'', data=b''):
    return bytes([1 + len(var), UD << 4]) + var + data


DATA = b'DATA-PAYLOAD-0123456789'
H1 = b'S5\x03tail'      # claimed by the H1 heuristic subdissector (cotp and cotp_is lists)

# ------------------------------------------------------------ frame sets


def clnp_frame(tpdu, cksum=True, **kw):
    return llc_frame(clnp(tpdu, cksum=cksum, **kw))


def main_frames():
    F = []
    tsaps = vp(P_SRC, b'client') + vp(P_DST, bytes([0x00, 0x01]))
    # 1-2 CR and CC class 0 over CLNP: printable and binary TSAPs, TPDU size, version,
    # protection, preferred TPDU size, inactivity timer
    F.append(clnp_frame(cr_cc(CR, 0, 0x1234, 0, 0,
                              tsaps + vp(P_TPDUSIZE, b'\x0b') + vp(P_VERSION, b'\x01') +
                              vp(P_PROT, b'\x01\x02\x03') + vp(P_CLASS, b'\x00') +
                              vp(P_PREF, b'\x10') + vp(P_PREF, b'\x01\x00') +
                              vp(P_PREF, b'\x00\x01\x00') + vp(P_PREF, b'\x00\x00\x01\x00') +
                              vp(P_INACT, struct.pack('>I', 600)))))
    F.append(clnp_frame(cr_cc(CC, 0x1234, 0x5678, 0, 0, vp(P_SRC, b'server') + vp(P_DST, b'client'))))
    # 3 CR class 4 with every class 4 parameter and a valid checksum
    def cr4(ck):
        return cr_cc(CR, 0, 0x2222, 4, 0x2,
                     vp(P_ACK, struct.pack('>H', 300)) + vp(P_RES, b'\x01') + vp(P_PRIO, b'\x00\x05') +
                     vp(P_TRANSIT, struct.pack('>HHHH', 1, 2, 3, 4)[:8]) +
                     vp(P_THRU, bytes(range(1, 13))) + vp(P_THRU, bytes(range(1, 25))) +
                     vp(P_REASSIGN, b'\x00\x0a') + vp(P_FLOW, struct.pack('>IHH', 0, 1, 2)) +
                     vp(P_SEQ, b'\x00\x07') +
                     tsaps + vp(P_TPDUSIZE, b'\x0d') + vp(P_CKSUM, ck) +
                     vp(P_VERSION, b'\x01') + vp(P_OPT, b'\x03') + vp(0x77, b'\xaa\xbb'),
                     data=b'')
    F.append(clnp_frame(with_cksum(cr4)))
    # 4 CC class 4 with an invalid-looking TSAP (binary) and the option byte for class 4
    F.append(clnp_frame(cr_cc(CC, 0x2222, 0x3333, 4, 0,
                              vp(P_SRC, bytes([0, 1, 2])) + vp(P_DST, bytes([0xff, 0xfe])) + vp(P_OPT, b'\x02'))))
    # 5 CR class 1 with the options (network expedited, receipt confirmation)
    F.append(clnp_frame(cr_cc(CR, 0, 0x4444, 1, 0, vp(P_OPT, b'\x0e') + vp(P_SRC, b'x'))))
    # the option octet is interpreted with the whole class/option octet (class 0, option bits 1 and 4)
    F.append(clnp_frame(cr_cc(CR, 0, 0x4445, 0, 1, vp(P_OPT, b'\x07'))))
    F.append(clnp_frame(cr_cc(CC, 0x4445, 0x4446, 0, 4, vp(P_OPT, b'\x01'))))
    # 6 CR with a checksum parameter that is zero (not present), CC with user data
    F.append(clnp_frame(cr_cc(CR, 0, 0x5555, 2, 0, vp(P_CKSUM, b'\0\0') + vp(P_OPT, b'\x01'))))
    F.append(clnp_frame(cr_cc(CC, 0x5555, 0x6666, 2, 0, vp(P_SRC, b'abc'), data=DATA)))
    F.append(clnp_frame(cr_cc(CC, 0x5555, 0x6667, 2, 0, vp(P_SRC, b'abc'), data=H1)))
    # 8 CR carrying the RDP negotiation request in its variable part (heuristic subdissector)
    F.append(clnp_frame(cr_cc(CR, 0, 0x7777, 0, 0, b'Cookie: mstshash=user\r\n' + struct.pack('<BBHI', 1, 0, 8, 3))))
    # 9 CC with the RDP negotiation response
    F.append(clnp_frame(cr_cc(CC, 0x7777, 0x8888, 0, 0, struct.pack('<BBHI', 2, 0, 8, 1))))
    # 10-11 DR with each cause, additional info and user data; DC with a checksum
    F.append(clnp_frame(dr(0x1234, 0x5678, 0x80, var=vp(P_CLEAR, b'bye'), data=b'x')))
    F.append(clnp_frame(dr(0x1234, 0x5678, 0x03)))
    F.append(clnp_frame(dc(0x5678, 0x1234, var=with_cksum_dc(0x5678, 0x1234))))
    F.append(clnp_frame(dc(0x5678, 0x1234)))
    F.append(clnp_frame(dc(0x5678, 0x1234, var=vp(P_OPT, b'\x05'))))
    # 14-17 DT class 4 normal and extended, with and without the checksum parameter
    F.append(clnp_frame(dtp(0x1234, 3, data=DATA)))
    F.append(clnp_frame(dtp(0x1234, 3, data=H1)))
    F.append(clnp_frame(with_cksum(lambda ck: dtp(0x1234, 4, var=vp(P_CKSUM, ck), data=DATA))))
    F.append(clnp_frame(dtp(0x1234, 5, ext=True, data=DATA)))
    F.append(clnp_frame(with_cksum(lambda ck: dtp(0x1234, 6, ext=True, var=vp(P_CKSUM, ck), data=DATA))))
    # 18-20 DT segments of one TSDU (class 4, normal numbering)
    F.append(clnp_frame(dtp(0x2345, 1, eot=False, data=b'AAAA')))
    F.append(clnp_frame(dtp(0x2345, 2, eot=False, data=b'BBBB')))
    F.append(clnp_frame(dtp(0x2345, 3, eot=True, data=b'CCCC')))
    # 21-22 DT segments with extended numbering
    F.append(clnp_frame(dtp(0x3456, 1, eot=False, ext=True, data=b'EEEE')))
    F.append(clnp_frame(dtp(0x3456, 2, eot=True, ext=True, data=b'FFFF')))
    # 23-24 ED normal and extended with checksum
    F.append(clnp_frame(with_cksum(lambda ck: dtp(0x1234, 1, var=vp(P_CKSUM, ck), data=b'urgent', kind=ED))))
    F.append(clnp_frame(dtp(0x1234, 2, ext=True, data=b'urgent', kind=ED)))
    F.append(clnp_frame(dtp(0x1234, 3, data=b'urgent', kind=ED)))
    F.append(clnp_frame(dtp(0x1234, 4, data=H1, kind=ED)))
    # 26-27 RJ normal and extended
    F.append(clnp_frame(rj(0x1234, 7, cdt=3)))
    F.append(clnp_frame(rj(0x1234, 8, ext=True, credit=9)))
    # 28-31 AK normal and extended, without and with variable part
    F.append(clnp_frame(ak(0x1234, 5, cdt=2)))
    F.append(clnp_frame(ak(0x1234, 6, cdt=1, var=vp(P_SEQ, b'\x00\x02') + vp(P_FLOW, struct.pack('>IHH', 3, 4, 5)))))
    F.append(clnp_frame(ak(0x1234, 7, ext=True, credit=8)))
    F.append(clnp_frame(ak(0x1234, 9, ext=True, credit=3, var=vp(P_SEQ, b'\x00\x02') + vp(P_FLOW, struct.pack('>IHH', 3, 4, 5)))))
    # 32-35 EA normal / extended with and without checksum
    F.append(clnp_frame(ea(0x1234, 3)))
    F.append(clnp_frame(with_cksum(lambda ck: ea(0x1234, 4, var=vp(P_CKSUM, ck)))))
    F.append(clnp_frame(ea(0x1234, 5, ext=True)))
    F.append(clnp_frame(with_cksum(lambda ck: ea(0x1234, 6, ext=True, var=vp(P_CKSUM, ck)))))
    # 36-39 ER with each reject cause (one with a checksum)
    F.append(clnp_frame(er(0x1234, 0)))
    F.append(clnp_frame(er(0x1234, 1)))
    F.append(clnp_frame(er(0x1234, 2)))
    F.append(clnp_frame(with_cksum(lambda ck: er(0x1234, 3, var=vp(P_CKSUM, ck)))))
    # 40-41 CLTP UD over CLNP with TSAPs and with a checksum
    F.append(clnp_frame(ud(vp(P_DST, bytes([0, 1])) + vp(P_SRC, bytes([0, 2])), DATA)))
    F.append(clnp_frame(with_cksum(lambda ck: ud(vp(P_DST, b'dst') + vp(P_SRC, b'src') + vp(P_CKSUM, ck), DATA))))
    # 42 several TPDUs in one packet (RJ, AK, ER), 43 RJ followed by a zero length indicator
    F.append(clnp_frame(rj(0x1234, 1) + ak(0x1234, 2) + er(0x1234, 1)))
    F.append(clnp_frame(rj(0x1234, 1) + b'\0\0\0'))
    # 44 RJ followed by something that is not a TPDU, 45 RJ followed by an unknown type
    F.append(clnp_frame(rj(0x1234, 1) + bytes([0x04, 0x30, 0, 0, 0])))
    F.append(clnp_frame(rj(0x1234, 1) + dtp(0x1234, 1, ext=True, data=b'x')))
    # 46 length indicator zero in the first TPDU, 47 unknown type
    F.append(clnp_frame(b'\0\xf0\0\0'))
    F.append(clnp_frame(bytes([3, 0x30, 0, 0, 0, 0])))
    # 48-50 over the Inactive Subset (NLPID 0x00): CR, DT with data, CC with data
    F.append(llc_frame(b'\x00' + cr_cc(CR, 0, 0x1111, 0, 0, vp(P_SRC, b'a'), data=b'user data')))
    F.append(llc_frame(b'\x00' + dtp(0x1111, 1, data=DATA)))
    F.append(llc_frame(b'\x00' + dtp(0x1111, 3, data=H1)))
    F.append(llc_frame(b'\x00' + dtp(0x1111, 4, kind=ED, data=H1)))
    F.append(llc_frame(b'\x00' + dtp(0x1111, 2, ext=True, kind=ED, data=DATA)))
    # 51-52 over IP protocol 39 (IP_PROTO_TP)
    F.append(ip_frame(cr_cc(CR, 0, 0x2020, 0, 0, vp(P_SRC, b'ip')), 39))
    F.append(ip_frame(dtp(0x2020, 1, data=DATA), 39, ident=2))
    # --- TPKT over TCP port 102
    cport = 49152
    F.append(tcp_frame(tpkt(cr_cc(CR, 0, 0x0a0a, 0, 0, vp(P_SRC, b'cl') + vp(P_DST, b'sv'))), cport, 102))
    F.append(tcp_frame(tpkt(cr_cc(CC, 0x0a0a, 0x0b0b, 0, 0, vp(P_SRC, b'sv'))), 102, cport, src=IP_DST, dst=IP_SRC))
    # class 0 DT: one segment then the last one (reassembled), then a single TPDU TSDU
    F.append(tcp_frame(tpkt(dtp(0, 0, eot=False, cls234=False, data=b'part one, ')), cport, 102))
    F.append(tcp_frame(tpkt(dtp(0, 0, eot=True, cls234=False, data=b'part two')), cport, 102))
    F.append(tcp_frame(tpkt(dtp(0, 0, eot=True, cls234=False, data=b'whole')), cport, 102))
    # a second TSDU in two segments, answered in the other direction
    F.append(tcp_frame(tpkt(dtp(0, 0, eot=False, cls234=False, data=b'reply 1, ')), 102, cport, src=IP_DST, dst=IP_SRC))
    F.append(tcp_frame(tpkt(dtp(0, 0, eot=True, cls234=False, data=b'reply 2')), 102, cport, src=IP_DST, dst=IP_SRC))
    # DR and DC over TCP
    F.append(tcp_frame(tpkt(dr(0x0b0b, 0x0a0a, 0x80)), cport, 102))
    F.append(tcp_frame(tpkt(dc(0x0a0a, 0x0b0b)), 102, cport, src=IP_DST, dst=IP_SRC))
    # a class 0 DT on a connection whose CR was not captured
    F.append(tcp_frame(tpkt(dtp(0, 0, eot=True, cls234=False, data=b'no CR seen')), 49153, 102))
    # a TPKT carrying a CR class 0 with an RDP cookie
    F.append(tcp_frame(tpkt(cr_cc(CR, 0, 0x0c0c, 0, 0, b'Cookie: mstshash=u\r\n')), 49154, 102))
    # --- CLTP over UDP port 102 (R-GOOSE SPDU identifier 0xA1 after the UD TPDU)
    F.append(udp_frame(ud(vp(P_DST, bytes([0, 1])) + vp(P_SRC, bytes([0, 2])) + vp(P_CKSUM, b'\0\0'), b'\xa1\x03abc'), 49200, 102))
    # R-GOOSE session header with an empty payload (claimed by the cltp heuristic list)
    rg = bytes([0xa1, 23, 0x80, 21]) + struct.pack('>IIH', 29, 1, 1) + struct.pack('>IHI', 0, 0, 0) + bytes([0]) + struct.pack('>I', 0)
    F.append(udp_frame(ud(vp(P_DST, bytes([0, 1])) + vp(P_SRC, bytes([0, 2]))) + rg, 49201, 102))
    # a connection whose two ends have the same address (direction by port)
    same = (127, 0, 0, 1)
    F.append(tcp_frame(tpkt(cr_cc(CR, 0, 0x0d0d, 0, 0, vp(P_SRC, b'lo'))), 49400, 102, src=same, dst=same))
    F.append(tcp_frame(tpkt(cr_cc(CC, 0x0d0d, 0x0e0e, 0, 0, vp(P_SRC, b'lo'))), 102, 49400, src=same, dst=same))
    F.append(tcp_frame(tpkt(dtp(0, 0, eot=True, cls234=False, data=b'loopback')), 49400, 102, src=same, dst=same))
    # the reproducers of the fixed bugs (batch s7, ositp_short_li.py): LI shorter than the fixed
    # part of the TPDU; they are not COTP (data) and used to be misdissected with extra parameters
    F.append(ip_frame(bytes([0x02, 0xe0, 0x00, 0x00, 0x00, 0x01, 0x00]) + bytes(16), 39, ident=10))      # CR li=2
    F.append(ip_frame(bytes([0x01, 0xc0, 0x00, 0x01, 0x00, 0x02]) + b'\xc1\x02AB' * 3, 39, ident=11))    # DC li=1
    F.append(ip_frame(bytes([0x01, 0x70, 0x00, 0x01, 0x00]) + b'\xc0\x01\x07' * 4, 39, ident=12))        # ER li=1
    F.append(ip_frame(bytes([0x03, 0x60, 0x00, 0x01]) + b'\xc1\x02AB', 39, ident=13))                    # AK li=3
    F.append(ip_frame(bytes([0x01, 0x40]) + b'\xc1\x02AB' + b'\xa1\x00', 39, ident=14))                # UD li=1
    F.append(ip_frame(bytes([0x06, 0xe0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x88, 0x00]), 39, ident=15))      # CR, transit delay length 0
    return F + atn_frames()


def with_cksum_dc(dst, src):
    t = dc(dst, src, var=vp(P_CKSUM, b'\0\0'))
    pos = t.index(bytes([P_CKSUM, 2])) + 2
    return fix_iso_checksum(t, pos)[5 + 1:]


# ------------------------------------------------------------ ATN frames

def atn_ec32(tpdu, off_ec, off_iso, dst, src):
    """Mirror of check_atn_ec_32(): the returned sum is zero for a good checksum."""
    def run(vals):
        c = [0, 0, 0, 0]

        def step(v):
            c[0] += v
            if c[0] >= 255:
                c[0] -= 255
            c[1] += c[0]
            if c[1] >= 255:
                c[1] -= 255
            c[2] += c[1]
            if c[2] >= 255:
                c[2] -= 255
            c[3] += c[2]
            if c[3] >= 255:
                c[3] -= 255
        for v in vals:
            step(v)
        return c
    return atn_solve(tpdu, off_ec, off_iso, dst, src, 4)


def atn_ec16(tpdu, off_ec, off_iso, dst, src):
    return atn_solve(tpdu, off_ec, off_iso, dst, src, 2)


def atn_solve(tpdu, off_ec, off_iso, dst, src, n):
    """Find the n checksum octets for which the C code computes zero."""
    def state(ec):
        c0 = c1 = c2 = c3 = 0
        mod = 255

        def acc(v):
            nonlocal c0, c1, c2, c3
            c0 += v
            if c0 >= mod:
                c0 -= mod
            c1 += c0
            if c1 >= mod:
                c1 -= mod
            if n == 4:
                c2 += c1
                if c2 >= mod:
                    c2 -= mod
                c3 += c2
                if c3 >= mod:
                    c3 -= mod
        for i, b in enumerate(tpdu):
            v = b
            if off_ec <= i < off_ec + n:
                v = 0
            if off_iso and off_iso <= i < off_iso + 2:
                v = 0
            acc(v)
        for v in [len(dst)] + list(dst) + [len(src)] + list(src) + list(ec):
            acc(v)
        return (c0, c1, c2, c3)[:n] if n == 4 else (c0, c1)
    base = state([0] * n)
    cols = []
    for i in range(n):
        e = [0] * n
        e[i] = 1
        s = state(e)
        cols.append([(a - b) % 255 for a, b in zip(s, base)])
    # solve sum_i x_i * cols[i] == -base (mod 255) by brute force over the
    # small structure: use Gaussian elimination over the integers with unimodular matrix
    from fractions import Fraction
    M = [[Fraction(cols[i][j]) for i in range(n)] for j in range(n)]
    # the matrix entries are taken mod 255; recover small integer entries
    def small(v):
        v = int(v) % 255
        return v if v < 128 else v - 255
    M = [[Fraction(small(M[j][i])) for i in range(n)] for j in range(n)]
    rhs = [Fraction(-b) for b in base]
    A = [row[:] + [rhs[k]] for k, row in enumerate(M)]
    for c in range(n):
        p = next(r for r in range(c, n) if A[r][c] != 0)
        A[c], A[p] = A[p], A[c]
        A[c] = [v / A[c][c] for v in A[c]]
        for r in range(n):
            if r != c and A[r][c] != 0:
                f = A[r][c]
                A[r] = [a - f * b for a, b in zip(A[r], A[c])]
    x = [int(A[i][n]) % 255 for i in range(n)]
    assert state(x) == (0,) * n or state(x) == tuple([0] * n), (state(x), x)
    return bytes(x)


def atn_frames(variant='main'):
    """TPDUs with the ATN checksums. All are DT/CR/... over CLNP so that the NSAPs are
    the pseudo trailer addresses."""
    dst = NSAP_B(0x21)
    src = NSAP_A(0x21)
    F = []

    def frame(t):
        return clnp_frame(t)

    def ec(kind, build, n):
        """build(ecvalue) -> TPDU with the extended checksum parameter; the first
        parameter byte of the 'EC' is located by its code and length."""
        code = P_EC32 if n == 4 else P_EC16
        t = build(bytes(n))
        pos = t.index(bytes([code, n])) + 2
        iso = 0
        if bytes([P_CKSUM, 2]) in t:
            iso = t.index(bytes([P_CKSUM, 2])) + 2
        val = (atn_ec32 if n == 4 else atn_ec16)(t, pos, iso, dst, src)
        return t[:pos] + val + t[pos + n:]

    def ec_iso(build, n):
        """Both the ATN checksum and the ISO checksum (CR/CC, backward compatible)."""
        t = ec(None, lambda e: build(e, b'\0\0'), n)
        pos = t.index(bytes([P_CKSUM, 2])) + 2
        t = fix_iso_checksum(t, pos)
        # the ATN checksum zeroes the ISO octets, so it stays valid
        return t

    # DT with 16 bit ATN checksum, normal / extended, and with 32 bit
    F.append(frame(ec(None, lambda e: dtp(0x1234, 1, var=vp(P_EC16, e), data=DATA), 2)))
    F.append(frame(ec(None, lambda e: dtp(0x1234, 2, ext=True, var=vp(P_EC16, e), data=DATA), 2)))
    F.append(frame(ec(None, lambda e: dtp(0x1234, 3, var=vp(P_EC32, e), data=DATA), 4)))
    F.append(frame(ec(None, lambda e: dtp(0x1234, 4, ext=True, var=vp(P_EC32, e), data=DATA), 4)))
    # a payload for which the 16 bit sum is >= 235 before the NSAP lengths are added (the carry
    # after adding the length of the destination NSAP)
    for k in range(256):
        data = DATA + bytes([k])
        t = dtp(0x1234, 9, var=vp(P_EC16, bytes(2)), data=data)
        c0 = 0
        for i, b in enumerate(t):
            c0 += 0 if 7 <= i < 9 else b
            if c0 >= 255:
                c0 -= 255
        if c0 >= 235:
            F.append(frame(ec(None, lambda e, d=data: dtp(0x1234, 9, var=vp(P_EC16, e), data=d), 2)))
            break
    # DT with the OSI checksum, and without any checksum, in ATN mode
    F.append(frame(with_cksum(lambda ck: dtp(0x1234, 5, var=vp(P_CKSUM, ck), data=DATA))))
    F.append(frame(with_cksum(lambda ck: dtp(0x1234, 6, ext=True, var=vp(P_CKSUM, ck), data=DATA))))
    F.append(frame(dtp(0x1234, 7, data=DATA)))
    F.append(frame(dtp(0x1234, 8, ext=True, data=DATA)))
    # CR / CC with ATN checksums (the ISO checksum parameter follows or precedes it)
    tsaps = vp(P_SRC, b'atn-c') + vp(P_DST, b'atn-s')
    F.append(frame(ec(None, lambda e: cr_cc(CR, 0, 0x1001, 4, 0, tsaps + vp(P_EC16, e)), 2)))
    F.append(frame(ec(None, lambda e: cr_cc(CC, 0x1001, 0x2002, 4, 0, tsaps + vp(P_EC32, e)), 4)))
    F.append(frame(ec_iso(lambda e, i: cr_cc(CR, 0, 0x1003, 4, 0, tsaps + vp(P_EC16, e) + vp(P_CKSUM, i)), 2)))
    F.append(frame(ec_iso(lambda e, i: cr_cc(CR, 0, 0x1004, 4, 0, tsaps + vp(P_EC32, e) + vp(P_CKSUM, i) + vp(P_OPT, b'\x03')), 4)))
    # ISO checksum first, then the ATN one
    F.append(frame(ec_iso(lambda e, i: cr_cc(CC, 0x1004, 0x1005, 4, 0, tsaps + vp(P_CKSUM, i) + vp(P_EC16, e)), 2)))
    F.append(frame(ec_iso(lambda e, i: cr_cc(CC, 0x1004, 0x1006, 4, 0, tsaps + vp(P_CKSUM, i) + vp(P_EC32, e)), 4)))
    F.append(frame(ec_iso(lambda e, i: cr_cc(CR, 0, 0x1007, 4, 0, vp(P_EC16, e) + tsaps + vp(P_CKSUM, i)), 2)))
    F.append(frame(ec_iso(lambda e, i: cr_cc(CR, 0, 0x1008, 4, 0, vp(P_EC32, e) + tsaps + vp(P_CKSUM, i)), 4)))
    # a bad ATN checksum is in the malformed capture
    # ED with the ATN checksums
    F.append(frame(ec(None, lambda e: dtp(0x1234, 1, var=vp(P_EC16, e), data=b'urgent', kind=ED), 2)))
    F.append(frame(ec(None, lambda e: dtp(0x1234, 2, var=vp(P_EC32, e), data=b'urgent', kind=ED), 4)))
    F.append(frame(ec(None, lambda e: dtp(0x1234, 3, ext=True, var=vp(P_EC16, e), data=b'urgent', kind=ED), 2)))
    F.append(frame(ec(None, lambda e: dtp(0x1234, 4, ext=True, var=vp(P_EC32, e), data=b'urgent', kind=ED), 4)))
    F.append(frame(with_cksum(lambda ck: dtp(0x1234, 5, var=vp(P_CKSUM, ck), data=b'urgent', kind=ED))))
    F.append(frame(dtp(0x1234, 6, data=b'urgent', kind=ED)))
    F.append(frame(dtp(0x1234, 7, ext=True, data=b'urgent', kind=ED)))
    F.append(frame(with_cksum(lambda ck: dtp(0x1234, 8, ext=True, var=vp(P_CKSUM, ck), data=b'urgent', kind=ED))))
    # RJ with ATN checksum parameters (LI +2 / +4)
    F.append(frame(rj(0x1234, 1, var=b'\0\0')))
    F.append(frame(rj(0x1234, 3, ext=True, credit=2, var=b'\0\0')))
    F.append(frame(rj(0x1234, 5)))
    F.append(frame(rj(0x1234, 6, ext=True, credit=1)))
    # AK with ATN checksums
    F.append(frame(ec(None, lambda e: ak(0x1234, 1, var=vp(P_EC16, e)), 2)))
    F.append(frame(ec(None, lambda e: ak(0x1234, 2, var=vp(P_EC32, e)), 4)))
    F.append(frame(ec(None, lambda e: ak(0x1234, 3, ext=True, credit=1, var=vp(P_EC16, e)), 2)))
    # EA with ATN checksums
    F.append(frame(ec(None, lambda e: ea(0x1234, 1, var=vp(P_EC16, e)), 2)))
    F.append(frame(ec(None, lambda e: ea(0x1234, 2, var=vp(P_EC32, e)), 4)))
    F.append(frame(ec(None, lambda e: ea(0x1234, 3, ext=True, var=vp(P_EC16, e)), 2)))
    F.append(frame(ec(None, lambda e: ea(0x1234, 4, ext=True, var=vp(P_EC32, e)), 4)))
    F.append(frame(ea(0x1234, 5)))
    F.append(frame(ea(0x1234, 6, ext=True)))
    F.append(frame(with_cksum(lambda ck: ea(0x1234, 7, var=vp(P_CKSUM, ck)))))
    F.append(frame(with_cksum(lambda ck: ea(0x1234, 8, ext=True, var=vp(P_CKSUM, ck)))))
    # DC and ER with ATN checksums, DR
    F.append(frame(ec(None, lambda e: dc(0x1234, 0x5678, var=vp(P_EC16, e)), 2)))
    F.append(frame(ec(None, lambda e: dc(0x1234, 0x5678, var=vp(P_EC32, e)), 4)))
    F.append(frame(ec(None, lambda e: er(0x1234, 1, var=vp(P_EC16, e)), 2)))
    F.append(frame(ec(None, lambda e: er(0x1234, 2, var=vp(P_EC32, e)), 4)))
    F.append(frame(ec(None, lambda e: dr(0x1234, 0x5678, 0x80, var=vp(P_EC32, e), data=b'x'), 4)))
    # the ATN checksum parameter is shown as "not shown" in a CR when ATN mode is off:
    # that is in the main capture of this directory (frame 3)
    return F


def raw(tpdu_type, rest, li=None):
    """A TPDU with an explicit LI (default: the real one) and type octet."""
    return bytes([len(rest) + 1 if li is None else li, tpdu_type]) + rest


def atn_malformed():
    F = []
    D = struct.pack('>H', 0x1234)
    ck = lambda code, n: bytes([code, n]) + bytes(n)
    nr_e = lambda eot: struct.pack('>I', 0x80000000 if eot else 0)
    nr_n = lambda eot: bytes([0x80 if eot else 0])
    # wrong checksums in ATN mode
    F.append(clnp_frame(dtp(0x1234, 1, var=vp(P_EC16, b'\x12\x34'), data=DATA)))
    F.append(clnp_frame(dtp(0x1234, 2, var=vp(P_EC32, b'\x12\x34\x56\x78'), data=DATA)))
    F.append(clnp_frame(cr_cc(CR, 0, 1, 4, 0, vp(P_EC16, b'\x12\x34') + vp(P_CKSUM, b'\x00\x00'))))
    F.append(clnp_frame(cr_cc(CR, 0, 1, 4, 0, vp(P_EC32, b'\x12\x34\x56\x78') + vp(P_SRC, b'x'))))
    # DT: wrong parameter code, and fragments (no EOT), with the 4 octet ATN checksum
    F.append(clnp_frame(raw(0xf0, D + nr_n(True) + ck(0x30, 4))))                # li 10, wrong code
    F.append(clnp_frame(raw(0xf0, D + nr_n(False) + ck(P_EC32, 4))))             # li 10, fragment
    F.append(clnp_frame(raw(0xf0, D + nr_e(True) + ck(0x30, 4))))                # li 13, wrong code
    F.append(clnp_frame(raw(0xf0, D + nr_e(False) + ck(P_EC32, 4))))             # li 13, fragment
    F.append(clnp_frame(raw(0xf0, D + nr_n(True) + ck(0x30, 2))))                # li 8, wrong code
    F.append(clnp_frame(raw(0xf0, D + nr_e(True) + ck(0x30, 2))))                # li 11, wrong code
    F.append(clnp_frame(raw(0xf0, D + nr_n(True) + b'xx')))                             # li 4 + ... bad li
    # ED: wrong code and no EOT for every length
    for t, nr, ckp, n in ((0x10, nr_n, 0x30, 2), (0x10, nr_n, 0x30, 4), (0x10, nr_e, 0x30, 2), (0x10, nr_e, 0x30, 4)):
        F.append(clnp_frame(raw(t, D + nr(True) + ck(ckp, n))))                  # wrong code
    F.append(clnp_frame(raw(0x10, D + nr_n(False) + ck(P_CKSUM, 2))))            # li 8, no EOT
    F.append(clnp_frame(raw(0x10, D + nr_n(False) + ck(P_EC32, 4))))             # li 10, no EOT
    F.append(clnp_frame(raw(0x10, D + nr_e(False) + ck(P_CKSUM, 2))))            # li 11, no EOT
    F.append(clnp_frame(raw(0x10, D + nr_e(False) + ck(P_EC32, 4))))             # li 13, no EOT
    F.append(clnp_frame(raw(0x10, D + nr_e(True) + b'xx')))                             # bad li
    # EA: wrong code or length, for every checksum size (the LI is right for the ATN sizes)
    for nr, total in ((nr_n, 10), (nr_e, 13)):
        fill = total - 1 - 2 - len(nr(True)) - 2
        for code, n in ((0x30, 4), (P_EC32, 3), (P_EC32, 5), (P_EC16, 3), (0x30, 2)):
            F.append(clnp_frame(raw(0x20, D + nr(True) + bytes([code, n]) + bytes(fill))))
    for nr, total in ((nr_n, 8), (nr_e, 11)):
        fill = total - 1 - 2 - len(nr(True)) - 2
        for code, n in ((0x30, 2), (P_EC16, 3), (P_CKSUM, 3)):
            F.append(clnp_frame(raw(0x20, D + nr(True) + bytes([code, n]) + bytes(fill))))
    F.append(clnp_frame(raw(0x20, D + nr_n(True) + bytes(11))))                          # EA li 15
    F.append(clnp_frame(raw(0x20, D + nr_n(True) + b'xxxxx')))
    # RJ / DC / AK / ER / DR with a LI that is too large or too small
    F.append(clnp_frame(raw(0x50, D + b'\0\0\0')))                                      # RJ li 6 -> fine in ATN; li 5 here
    F.append(clnp_frame(raw(0x50, D + b'\0\0\0\0\0\0\0\0')))
    F.append(clnp_frame(raw(0xc0, D + bytes(2) + bytes(9))))                            # DC li 14
    F.append(clnp_frame(raw(0x60, D + bytes(1) + bytes(28))))                           # AK li 32
    F.append(clnp_frame(raw(0x70, D + bytes([1]) + bytes(8))))                          # ER li 12
    F.append(clnp_frame(raw(0x60, D + b'\0\0', li=3)))                                   # AK li too small
    return F


# ------------------------------------------------------------ malformed

def malformed_frames():
    F = []
    # reproducers of the fixed bugs (batch s7, ositp_short_li.py): LI shorter than the fixed part
    F.append(ip_frame(bytes([0x02, 0xe0, 0x00, 0x00, 0x00, 0x01, 0x00]) + bytes(16), 39))      # CR li=2
    F.append(ip_frame(bytes([0x01, 0xc0, 0x00, 0x01, 0x00, 0x02]) + b'\xc1\x02AB' * 3, 39))    # DC li=1
    F.append(ip_frame(bytes([0x01, 0x70, 0x00, 0x01, 0x00]) + b'\xc0\x01\x07' * 4, 39))        # ER li=1
    F.append(ip_frame(bytes([0x01, 0x40]) + b'\xc1\x02AB' + b'\xa1\x00', 39))                  # UD li=1
    F.append(ip_frame(bytes([0x06, 0xe0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x88, 0x00]), 39))      # CR, transit delay length 0
    F.append(ip_frame(bytes([0x03, 0x60, 0x00, 0x01]) + b'\xc1\x02AB', 39))                    # AK li=3
    F.append(ip_frame(bytes([0x09, 0x61, 0x00, 0x01, 0, 0, 0, 1]) + b'\xc1\x02AB', 39))        # AK li=9 (extended) truncated
    # variable part loops
    F.append(clnp_frame(cr_cc(CR, 0, 1, 4, 0, bytes([P_RES, 1, 1]) * 3)))
    F.append(clnp_frame(cr_cc(CR, 0, 1, 4, 0, vp(P_THRU, b'\1\2\3'))))
    F.append(clnp_frame(cr_cc(CR, 0, 1, 4, 0, vp(P_FLOW, b'\1\2\3'))))
    F.append(clnp_frame(cr_cc(CR, 0, 1, 4, 0, vp(P_SRC, b'\1' * 40))))
    F.append(clnp_frame(cr_cc(CR, 0, 1, 4, 0, vp(P_SRC, b''))))
    F.append(clnp_frame(cr_cc(CR, 0, 1, 4, 0, vp(P_PREF, b'\1\2\3\4\5') + vp(P_SRC, b'x'))))
    F.append(clnp_frame(cr_cc(CR, 0, 1, 4, 0, vp(P_PREF, b''))))
    F.append(clnp_frame(cr_cc(CR, 0, 1, 4, 0, bytes([P_ACK]))))                 # code without a length
    F.append(clnp_frame(cr_cc(CR, 0, 1, 4, 0, bytes([P_ACK, 0x40, 1, 2]))))     # length past the end
    F.append(clnp_frame(cr_cc(CR, 0, 1, 0xf, 0)))                                  # class 15
    # bad ISO checksums
    F.append(clnp_frame(cr_cc(CR, 0, 1, 4, 0, vp(P_CKSUM, b'\x12\x34'))))
    F.append(clnp_frame(dtp(0x1234, 1, var=vp(P_CKSUM, b'\x12\x34'), data=DATA)))
    # DR with an unknown reason, DT with a bad LI and with the wrong parameter, ED without EOT
    F.append(clnp_frame(dr(1, 2, 0x55)))
    F.append(clnp_frame(dr(1, 2, 0x80)[:0] + bytes([5, 0x80, 0, 1, 0, 2])))
    F.append(clnp_frame(bytes([5, 0xf0, 0x12, 0x34, 0x80, 0x00])))                # DT li=5
    F.append(clnp_frame(dtp(0x1234, 1, var=vp(P_ACK, b'\x00\x01'), data=DATA)))     # DT li=8, no checksum
    F.append(clnp_frame(dtp(0x1234, 1, ext=True, var=vp(P_ACK, b'\x00\x01'), data=DATA)))
    F.append(clnp_frame(dtp(0x1234, 1, eot=False, kind=ED, data=b'x')))
    F.append(clnp_frame(dtp(0x1234, 1, eot=False, ext=True, kind=ED, data=b'x')))
    F.append(clnp_frame(bytes([5, 0x10, 0x12, 0x34, 0x80, 0x00])))                # ED li=5
    F.append(clnp_frame(dtp(0x1234, 1, var=vp(P_ACK, b'\x00\x01'), kind=ED, data=b'x')))
    F.append(clnp_frame(dtp(0x1234, 1, ext=True, var=vp(P_ACK, b'\x00\x01'), kind=ED, data=b'x')))
    # RJ with an unknown LI, DC too long, AK too long, EA/ER with bad lengths and values
    F.append(clnp_frame(bytes([5, 0x50, 0x12, 0x34, 0, 0])))
    F.append(clnp_frame(bytes([12, 0xc0, 0x12, 0x34, 0x56, 0x78] + [0] * 7)))
    F.append(clnp_frame(bytes([30, 0x60, 0x12, 0x34, 3] + [0] * 26)))
    F.append(clnp_frame(bytes([12, 0x20, 0x12, 0x34, 3] + [0] * 7)))
    F.append(clnp_frame(bytes([8, 0x20, 0x12, 0x34, 3, 0xc9, 2, 0, 0])))
    F.append(clnp_frame(bytes([8, 0x20, 0x12, 0x34, 3, 0xc3, 3, 0, 0])))
    F.append(clnp_frame(bytes([11, 0x20, 0x12, 0x34, 0, 0, 0, 3, 0xc9, 2, 0, 0])))
    F.append(clnp_frame(bytes([11, 0x20, 0x12, 0x34, 0, 0, 0, 3, 0xc3, 3, 0, 0])))
    F.append(clnp_frame(bytes([6, 0x20, 0x12, 0x34, 3, 0, 0])))
    F.append(clnp_frame(bytes([10, 0x70, 0x12, 0x34, 1] + [0] * 5)))
    F.append(clnp_frame(er(0x1234, 9)))
    F.append(clnp_frame(bytes([3, 0x70, 0x12, 0x34])))
    # TPDU too short for its LI
    F.append(clnp_frame(bytes([6, 0xe0, 0, 0])))
    # CR with the RDP heuristic but a bad length, over TCP the same
    F.append(clnp_frame(cr_cc(CR, 0, 1, 0, 0, b'Cookie: x\r\n')))
    # TPKT-borne frames, CR/CC with ports and bad class
    F.append(tcp_frame(tpkt(cr_cc(CR, 0, 0x0a0a, 0xf, 0)), 49300, 102))
    # truncated capture with a checksum that cannot be verified, UD without data, parameter length 255
    F.append((clnp_frame(cr_cc(CR, 0, 1, 4, 0, vp(P_CKSUM, b'\x12\x34'), data=bytes(100))), 90))
    F.append(clnp_frame(ud(vp(P_SRC, b'\0' * 3))))
    F.append(udp_frame(ud(bytes([P_SRC, 255])) + b'\xa1x', 49209, 102))
    F.append(udp_frame(ud(vp(P_SRC, b'ab')), 49210, 102))
    F.append(udp_frame(ud(vp(P_SRC, b'ab') + bytes([P_DST])) + b'\xa1x', 49211, 102))
    # preferences for tsap display are in runcov; CLTP heuristic with bad parameters
    F.append(udp_frame(ud(vp(0x01, b'\0')) + b'\xa1x', 49201, 102))
    F.append(udp_frame(ud(vp(P_SRC, b'\0' * 5)[:3]) + b'\xa1x', 49202, 102))
    F.append(udp_frame(bytes([0xff, 0x40, 0xa1]), 49203, 102))
    F.append(udp_frame(ud(vp(P_SRC, b'ab')) + b'\xb1x', 49204, 102))
    F.append(udp_frame(bytes([2, 0x30, 0xa1]), 49205, 102))
    F.append(udp_frame(bytes([2, 0x40]), 49206, 102))
    F.append(udp_frame(bytes([1]), 49207, 102))
    F.append(udp_frame(bytes([0, 0x40, 0xa1]), 49208, 102))
    return F + atn_malformed_wrapper()


def atn_malformed_wrapper():
    return []


# ------------------------------------------------------------ pcap output

def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            p, caplen = fr if isinstance(fr, tuple) else (fr, len(fr))
            f.write(struct.pack('<IIII', 1700000000 + i, 0, caplen, len(p)) + p[:caplen])


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'ositp-coverage.pcap'), main_frames())
    write_pcap(os.path.join(out, 'ositp-coverage-atn.pcap'), atn_frames())
    write_pcap(os.path.join(out, 'ositp-coverage-malformed.pcap'), malformed_frames())
    write_pcap(os.path.join(out, 'ositp-coverage-atn-malformed.pcap'), atn_malformed())


if __name__ == '__main__':
    main()
