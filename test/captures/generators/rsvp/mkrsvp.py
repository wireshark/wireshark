#!/usr/bin/env python3
# Generates test/captures/rsvp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Builds rsvp-coverage.pcap and rsvp-coverage-malformed.pcap (Ethernet).
# Usage: mkrsvp.py <outdir> [-v]
import sys
import os
import struct
from rsvplib import a4, a6, Cap, msg, obj, pad4

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'
VERB = '-v' in sys.argv
C = Cap()       # main capture
M = Cap()       # malformed capture
marks = []

def mark(c, label):
    marks.append((len(c.frames) + 1, label))

# classes
SESSION, HOP, INTEGRITY, TIME, ERROR, SCOPE, STYLE, FLOWSPEC, FILTER, TEMPLATE, TSPEC, ADSPEC, POLICY, CONFIRM, LABEL = 1, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
LABEL_REQUEST, ERO, RRO, HELLO, MSGID, MSGID_ACK, MSGID_LIST = 19, 20, 21, 22, 23, 24, 25
RECOVERY_LABEL, UPSTREAM_LABEL, LABEL_SET, PROTECTION = 34, 35, 36, 37
S2L_SUB_LSP, DETOUR, DIFFSERV, CLASSTYPE, LSP_REQ_ATTR = 50, 63, 65, 66, 67
SUGGESTED_LABEL, ACCEPTABLE_LABEL_SET, RESTART_CAP, LINK_CAP, CAPABILITY = 129, 130, 131, 133, 134
TUNNEL_IF_ID, NOTIFY_REQUEST, ADMIN_STATUS, LSP_ATTR, ASSOCIATION = 193, 195, 196, 197, 199
SEC_ERO, SEC_RRO, CALL_ATTR, JUNIPER, FRR, SESS_ATTR = 200, 201, 202, 204, 205, 207
DCLASS, GEN_UNI, CALL_ID, G3PP2, XRO = 225, 229, 230, 231, 232
MSG = dict(PATH=1, RESV=2, PERR=3, RERR=4, PTEAR=5, RTEAR=6, RCONF=7, RTEARCONF=10, BUNDLE=12, ACK=13, SREFRESH=15, HELLO=20, NOTIFY=21)

D4 = a4('198.51.100.1'); S4 = a4('192.0.2.1'); X4 = a4('203.0.113.9')
D6 = a6('2001:db8:1::1'); S6 = a6('2001:db8:2::2'); X6 = a6('2001:db8:3::3')

# ---------------- SESSION (all c-types + unknown) ----------------
def sess_ipv4(): return obj(SESSION, 1, D4 + bytes([17, 0x01]) + struct.pack('!H', 5004))
def sess_ipv6(): return obj(SESSION, 2, D6 + bytes([6, 0]) + struct.pack('!H', 8080))
def sess_lsp4(): return obj(SESSION, 7, D4 + struct.pack('!HHI', 0x0102, 77, 0x0a000001))
def sess_lsp6(): return obj(SESSION, 8, D6 + struct.pack('!HH', 0x0304, 78) + X6)
def sess_agg(): return obj(SESSION, 9, D4 + b'\0\0\0' + bytes([0x2e]) + struct.pack('!I', 0x0a000002))
def sess_uni(): return obj(SESSION, 11, D4 + struct.pack('!HHI', 0, 79, 0xc0000209))
def sess_p2mp4(): return obj(SESSION, 13, struct.pack('!I', 0x0a0a0a0a) + struct.pack('!HHI', 0, 80, 0xc0000209))
def sess_p2mp6(): return obj(SESSION, 14, struct.pack('!I', 0x0a0a0a0b) + struct.pack('!HH', 0, 81) + X6)
def sess_enni(): return obj(SESSION, 15, D4 + struct.pack('!HHI', 0, 82, 0xc0000209))
def sess_unk(): return obj(SESSION, 99, bytes(range(12)))

# ---------------- HOP ----------------
def tlv(t, body, pad=True):
    b = struct.pack('!HH', t, 4 + len(body)) + body
    return pad4(b) if pad else b
def hop4(): return obj(HOP, 1, S4 + struct.pack('!I', 5))
def hop6(): return obj(HOP, 2, S6 + struct.pack('!I', 6))
def hop4_ifid(tlvs): return obj(HOP, 3, S4 + struct.pack('!I', 7) + b''.join(tlvs))
def hop6_ifid(tlvs): return obj(HOP, 4, S6 + struct.pack('!I', 8) + b''.join(tlvs))
def hop_unk(): return obj(HOP, 9, b'\1\2\3\4')

def ifid_all():
    t = []
    for ty in (1, 14, 16): t.append(tlv(ty, S4))
    for ty in (2, 15, 17): t.append(tlv(ty, S6))
    for ty in (3, 4, 5, 18): t.append(tlv(ty, S4 + struct.pack('!I', 0x1234)))
    for ty in (6, 7, 19, 20): t.append(tlv(ty, struct.pack('!I', 0x5555)))
    for ty in (8, 21): t.append(tlv(ty, D4))
    for ty in (9, 22): t.append(tlv(ty, struct.pack('!I', 0)))
    for ty in (10, 23): t.append(tlv(ty, bytes([4, 0x47, 0, 5, 0x80])))       # ISIS area, length 4 (padded)
    for ty in (11, 24): t.append(tlv(ty, struct.pack('!I', 64512)))
    t.append(tlv(26, tlv(1, S4)))                         # node exclusions: nested
    t.append(tlv(27, tlv(3, S4 + struct.pack('!I', 9)) + tlv(14, D4)))
    t.append(tlv(516, b'error text', pad=True))
    t.append(tlv(1000, b'\xaa\xbb\xcc\xdd\xee'))
    return t

# ---------------- ERROR ----------------
def err4(code, val, flags=0, node=S4): return obj(ERROR, 1, node + bytes([flags, code]) + struct.pack('!H', val))
def err6(code, val, flags=0, node=S6): return obj(ERROR, 2, node + bytes([flags, code]) + struct.pack('!H', val))
def err4_ifid(code, val, tlvs, flags=0): return obj(ERROR, 3, S4 + bytes([flags, code]) + struct.pack('!H', val) + b''.join(tlvs))
def err6_ifid(code, val, flags=0): return obj(ERROR, 4, S6 + bytes([flags, code]) + struct.pack('!H', val))

# ---------------- TIME, SCOPE, STYLE, CONFIRM ----------------
def tv(ms=30000): return obj(TIME, 1, struct.pack('!I', ms))
def scope4(n=2): return obj(SCOPE, 1, b''.join(a4('10.0.0.%d' % (i + 1)) for i in range(n)))
def scope6(n=2): return obj(SCOPE, 2, b''.join(a6('2001:db8::%x' % (i + 1)) for i in range(n)))
def style(s=0x12): return obj(STYLE, 1, bytes([0]) + struct.pack('!I', s)[1:])
def conf4(): return obj(CONFIRM, 1, D4)
def conf6(): return obj(CONFIRM, 2, D6)

# ---------------- SENDER TEMPLATE / FILTER SPEC ----------------
def tmpl(cls, ct, body): return obj(cls, ct, body)
def tf_all(cls):
    r = []
    r.append(tmpl(cls, 1, S4 + b'\0\0' + struct.pack('!H', 5004)))
    r.append(tmpl(cls, 2, S6 + b'\0\0' + struct.pack('!H', 5005)))
    r.append(tmpl(cls, 7, S4 + struct.pack('!HH', 3, 11)))
    r.append(tmpl(cls, 8, S6 + struct.pack('!HH', 4, 12)))
    r.append(tmpl(cls, 9, S4))
    r.append(tmpl(cls, 12, S4 + b'\0\0' + struct.pack('!H', 13) + X4 + b'\0\0' + struct.pack('!H', 5)))
    r.append(tmpl(cls, 13, S6 + b'\0\0' + struct.pack('!H', 14) + X6 + b'\0\0' + struct.pack('!H', 6)))
    r.append(tmpl(cls, 99, b'\1\2\3\4\5\6'))
    return r

def mal(m, label, **kw):
    mark(M, label)
    M.add(m, label, **kw)

def send(c, m, label, **kw):
    mark(c, label)
    c.add(m, label, **kw)

# =================== frames ===================
# one message per session type (PATH), with HOP, TIME_VALUES, template
for name, sess in (('IPv4', sess_ipv4), ('IPv6', sess_ipv6), ('IPv4-LSP', sess_lsp4), ('IPv6-LSP', sess_lsp6), ('IPv4-Aggregate', sess_agg),
                   ('IPv4-UNI', sess_uni), ('IPv4-P2MP', sess_p2mp4), ('IPv6-P2MP', sess_p2mp6), ('IPv4-E-NNI', sess_enni), ('unknown c-type', sess_unk)):
    send(C, msg(MSG['PATH'], [sess(), hop4(), tv(), obj(TEMPLATE, 1, S4 + b'\0\0' + struct.pack('!H', 1000))]), 'PATH, SESSION ' + name)

# HOP c-types
send(C, msg(MSG['PATH'], [sess_ipv4(), hop6(), tv(), tmpl(TEMPLATE, 8, S6 + struct.pack('!HH', 4, 12))]), 'PATH, HOP IPv6, IPv6-LSP template')
send(C, msg(MSG['PATH'], [sess_lsp4(), hop4_ifid(ifid_all()), tv()]), 'PATH, HOP IPv4 IF-ID with every TLV type')
send(C, msg(MSG['PATH'], [sess_lsp4(), hop6_ifid(ifid_all()), tv()]), 'PATH, HOP IPv6 IF-ID with every TLV type')
send(C, msg(MSG['PATH'], [sess_lsp4(), hop_unk(), tv(), obj(TIME, 9, b'\1\2\3\4')]), 'PATH, unknown HOP and TIME_VALUES c-types')

# ERROR objects
send(C, msg(MSG['PERR'], [sess_lsp4(), err4(1, 3, 4), tmpl(TEMPLATE, 7, S4 + struct.pack('!HH', 3, 11))]), 'PATHERR: ERROR admission control')
send(C, msg(MSG['RERR'], [sess_ipv4(), hop4(), err6(2, 1, 2), style(), ]), 'RESVERR: ERROR IPv6 policy control')
for code, vals in ((1, (0x01, 0x80 | 3, 0xc0 | 5, 0x05)), (21, (1, 0x85, 0xc4)), (2, (1, 2)), (13, (0x0301,)), (14, (0x0201,)),
                   (24, (1,)), (25, (1,)), (27, (1,)), (28, (1,)), (31, (1,)), (32, (1,)), (35, (1,)), (3, (7,))):
    for v in vals:
        send(C, msg(MSG['RERR'], [sess_ipv4(), hop4(), err4(code, v, 7), style()]), 'RESVERR code %d value %d' % (code, v))
send(C, msg(MSG['PERR'], [sess_lsp4(), err4_ifid(1, 1, ifid_all()[:6])]), 'PATHERR: ERROR IPv4 IF-ID')
send(C, msg(MSG['PERR'], [sess_lsp4(), err6_ifid(1, 1)]), 'PATHERR: ERROR IPv6 IF-ID')
send(C, msg(MSG['PERR'], [sess_lsp4(), obj(ERROR, 1), obj(ERROR, 2), obj(ERROR, 4, S6[:12]), obj(ERROR, 7, b'\1\2\3\4'), obj(ERROR, 7)]), 'ERROR objects without data and an unknown c-type')

# SCOPE, STYLE, CONFIRM
send(C, msg(MSG['RESV'], [sess_ipv4(), hop4(), tv(), scope4(), style(0x0a), obj(CONFIRM, 1, D4)]), 'RESV: SCOPE IPv4, STYLE, CONFIRM')
send(C, msg(MSG['RESV'], [sess_ipv4(), hop6(), tv(), scope6(), style(0x11), conf6()]), 'RESV: SCOPE IPv6, CONFIRM IPv6')
send(C, msg(MSG['RESV'], [sess_ipv4(), hop4(), obj(SCOPE, 5, b'\1\2\3\4'), obj(STYLE, 5, b'\1\2\3\4'), obj(CONFIRM, 5, b'\1\2\3\4')]), 'RESV: unknown SCOPE, STYLE and CONFIRM c-types')
send(C, msg(MSG['RESV'], [sess_ipv4(), hop4(), style(0x0b)]), 'RESV: STYLE with an unknown option vector')

# templates and filter specs
for t in tf_all(TEMPLATE):
    send(C, msg(MSG['PATH'], [sess_lsp4(), hop4(), tv(), t]), 'PATH, SENDER_TEMPLATE c-type %d' % t[3])
for t in tf_all(FILTER):
    send(C, msg(MSG['RESV'], [sess_lsp4(), hop4(), tv(), style(), t]), 'RESV, FILTER_SPEC c-type %d' % t[3])

# message types without objects of interest, ttl, flags, checksums
send(C, msg(MSG['PTEAR'], [sess_ipv4(), hop4(), obj(TEMPLATE, 1, S4 + b'\0\0\0\x50')]), 'PATHTEAR')
send(C, msg(MSG['RTEAR'], [sess_ipv4(), hop4(), style(), obj(FILTER, 1, S4 + b'\0\0\0\x50')]), 'RESVTEAR')
send(C, msg(MSG['RCONF'], [sess_ipv4(), err4(0, 0), style(), conf4()]), 'RESVCONF')
send(C, msg(MSG['RTEARCONF'], [sess_ipv4(), hop4(), style()]), 'RESVTEARCONF')
send(C, msg(MSG['PATH'], [sess_ipv4(), hop4(), tv()], cksum='bad'), 'PATH with a bad checksum')
send(C, msg(MSG['PATH'], [sess_ipv4(), hop4(), tv()], cksum='zero'), 'PATH with checksum 0 and no integrity object')
send(C, msg(MSG['PATH'], [sess_ipv4(), hop4(), tv(), obj(INTEGRITY, 1, bytes(range(24)))], cksum='zero'), 'PATH with checksum 0 and an integrity object')
send(C, msg(77, [sess_ipv4(), hop4()]), 'unknown message type 77')

def fl(x): return struct.pack('!f', x)
def u32(*a): return b''.join(struct.pack('!I', x) for x in a)
def u16(*a): return b''.join(struct.pack('!H', x) for x in a)
def param(pid, flags, val): return struct.pack('!BBH', pid, flags, len(val) // 4) + val
def svc(num, params, brk=0): body = b''.join(params); return struct.pack('!BBH', num, brk, len(body) // 4) + body
def intserv(cls, ct, svcs, ver=0):
    body = b''.join(svcs)
    return obj(cls, ct, struct.pack('!BBH', ver << 4, 0, len(body) // 4) + body)
TB = param(127, 0, fl(12500.5) + fl(1500.0) + fl(25000.0) + u32(64, 1500))
TSPEC_TB = svc(5, [TB])
NULLP = param(128, 0, u32(1500))
HINTP = param(126, 0, u32(7, 3, 2))
RSPEC = param(130, 0, fl(8000.0) + u32(500))
UNKP = param(77, 0, u32(1, 2))

def eth_tlv(t, body): return struct.pack('!HH', t, 4 + len(body)) + body
def eth_profile(t=2, flags=3, idx=1): return eth_tlv(t, bytes([flags, idx]) + b'\0\0' + fl(1000.0) + fl(500.0) + fl(250.0) + fl(125.0))
def eth_body(tlvs, gran=1, mtu=1500): return u16(gran, mtu) + b''.join(tlvs)

def sonet(sig=5, rcc=3, ncc=4, nvc=2, mt=8, transp=0x7fff, prof=3): return struct.pack('!BBHHHII', sig, rcc, ncc, nvc, mt, transp, prof)
def g709(sig=2, nmc=3, nvc=4, mt=5): return struct.pack('!BBHHH', sig, 0, nmc, nvc, mt)

# ---------------- TSPEC / FLOWSPEC / ADSPEC ----------------
send(C, msg(MSG['PATH'], [sess_ipv4(), hop4(), tv(), obj(TEMPLATE, 1, S4 + b'\0\0\0\x50'),
                          intserv(TSPEC, 2, [TSPEC_TB, svc(6, [NULLP]), svc(7, [HINTP, UNKP])])]),
     'PATH: SENDER_TSPEC IntServ (token bucket, null service, compression hint, unknown parameter)')
send(C, msg(MSG['PATH'], [sess_ipv4(), hop4(), intserv(TSPEC, 2, [svc(5, [TB]), svc(2, [TB, RSPEC])])]), 'PATH: TSPEC with guaranteed service')
send(C, msg(MSG['PATH'], [sess_ipv4(), hop4(), obj(TSPEC, 4, sonet())]), 'PATH: TSPEC SONET/SDH')
send(C, msg(MSG['PATH'], [sess_ipv4(), hop4(), obj(TSPEC, 5, g709())]), 'PATH: TSPEC G.709')
send(C, msg(MSG['PATH'], [sess_ipv4(), hop4(), obj(TSPEC, 6, eth_body([eth_profile(0), eth_profile(1, 0), eth_profile(2, 3, 2), eth_tlv(255, b''), eth_tlv(129, bytes([2, 3]) + b'\0\0' + fl(100.0) + fl(50.0) + fl(25.0) + fl(12.0)), eth_tlv(77, b'\1\2\3\4')]))]), 'PATH: TSPEC Ethernet with bandwidth profile TLVs')
# the L2CP TLV bit offset is computed from the object offset, so this object comes first and is followed by filler
send(C, msg(MSG['PATH'], [obj(TSPEC, 6, eth_body([eth_tlv(3, b'\x21\x30\0\0')])), obj(100, 1, bytes(range(256)) * 1)]), 'PATH: TSPEC Ethernet with an L2CP TLV')
send(C, msg(MSG['PATH'], [sess_ipv4(), hop4(), obj(TSPEC, 8, u16(8, 0))]), 'PATH: TSPEC SSON')
send(C, msg(MSG['PATH'], [sess_ipv4(), hop4(), obj(TSPEC, 33, b'\1\2\3\4\5\6\7\x08')]), 'PATH: TSPEC unknown c-type')

send(C, msg(MSG['RESV'], [sess_ipv4(), hop4(), style(), intserv(FLOWSPEC, 2, [svc(5, [TB]), svc(2, [TB, RSPEC]), svc(6, [NULLP])])]), 'RESV: FLOWSPEC IntServ (controlled load, guaranteed, null service)')
send(C, msg(MSG['RESV'], [sess_ipv4(), hop4(), style(), intserv(FLOWSPEC, 2, [svc(5, [TB, UNKP])])]), 'RESV: FLOWSPEC with an unknown parameter')
send(C, msg(MSG['RESV'], [sess_ipv4(), hop4(), style(), obj(FLOWSPEC, 4, sonet())]), 'RESV: FLOWSPEC SONET/SDH')
send(C, msg(MSG['RESV'], [sess_ipv4(), hop4(), style(), obj(FLOWSPEC, 5, g709())]), 'RESV: FLOWSPEC G.709')
send(C, msg(MSG['RESV'], [sess_ipv4(), hop4(), style(), obj(FLOWSPEC, 6, eth_body([eth_profile(1)], 2, 9000))]), 'RESV: FLOWSPEC Ethernet')
send(C, msg(MSG['RESV'], [sess_ipv4(), hop4(), style(), obj(FLOWSPEC, 8, u16(4, 0))]), 'RESV: FLOWSPEC SSON')
send(C, msg(MSG['RESV'], [sess_ipv4(), hop4(), style(), obj(FLOWSPEC, 33, b'\1\2\3\4')]), 'RESV: FLOWSPEC unknown c-type')

ADS_GEN = svc(1, [param(4, 0, u32(3)), param(6, 0, fl(1.0e6)), param(8, 0, u32(250)), param(10, 0, u32(1500)), param(99, 0, u32(1))], brk=0x80)
ADS_G = svc(2, [param(133, 0, u32(10)), param(134, 0, u32(20)), param(135, 0, u32(30)), param(136, 0, u32(40)), param(60, 0, u32(5))])
send(C, msg(MSG['PATH'], [sess_ipv4(), hop4(), obj(ADSPEC, 2, struct.pack('!BBH', 0, 0, len(ADS_GEN + ADS_G) // 4) + ADS_GEN + ADS_G)]), 'PATH: ADSPEC with general and guaranteed services')

# INTEGRITY and POLICY
send(C, msg(MSG['PATH'], [sess_ipv4(), hop4(), obj(INTEGRITY, 1, bytes([0x01, 0]) + b'\0\1\2\3\4\5' + struct.pack('!Q', 99) + bytes(range(16))), obj(POLICY, 1, b'\xaa' * 8)], cksum='zero'), 'PATH: INTEGRITY with handshake flag, POLICY_DATA')

# ---------------- LABEL_REQUEST ----------------
send(C, msg(MSG['PATH'], [sess_lsp4(), obj(LABEL_REQUEST, 1, u16(0, 0x0800))]), 'PATH: LABEL_REQUEST basic (IPv4 L3PID)')
send(C, msg(MSG['PATH'], [sess_lsp4(), obj(LABEL_REQUEST, 2, u16(0, 0x8847) + u16(0x8005, 0x0111, 0x0006, 0x0222))]), 'PATH: LABEL_REQUEST ATM')
for code, hdr in ((0, 0x0000), (2, 0x0100), (1, 0x0080), (3, 0x0180)):
    send(C, msg(MSG['PATH'], [sess_lsp4(), obj(LABEL_REQUEST, 3, u16(0, 0x8847) + u16(hdr, 0x0123) + u32(0x00000456))]), 'PATH: LABEL_REQUEST frame relay, DLCI length code %d' % code)
send(C, msg(MSG['PATH'], [sess_lsp4(), obj(LABEL_REQUEST, 4, bytes([1, 100, 0x08, 0x00]))]), 'PATH: LABEL_REQUEST generalized (packet, PSC, IPv4)')
send(C, msg(MSG['PATH'], [sess_lsp4(), obj(LABEL_REQUEST, 5, bytes([5, 150, 0x00, 0x25]))]), 'PATH: LABEL_REQUEST generalized channel set (SDH, TDM)')
send(C, msg(MSG['PATH'], [sess_lsp4(), obj(LABEL_REQUEST, 9, b'\1\2\3\4')]), 'PATH: LABEL_REQUEST unknown c-type')

# ---------------- LABEL and friends ----------------
send(C, msg(MSG['RESV'], [sess_lsp4(), hop4(), style(), obj(LABEL, 1, u32(1234))]), 'RESV: LABEL packet')
send(C, msg(MSG['RESV'], [sess_lsp4(), hop4(), style(), obj(SUGGESTED_LABEL, 1, u32(55)), obj(UPSTREAM_LABEL, 1, u32(56)), obj(RECOVERY_LABEL, 1, u32(57))]), 'PATH: SUGGESTED, UPSTREAM and RECOVERY labels (c-type 1)')
# generalized labels: several sizes and values for every interpretation of the preference
GL = [bytes([0x22, 0, 0xff, 0xfe]) + b'\0\0\0\0',          # DWDM, 100GHz, n=-2
      bytes([0x24, 0, 0, 5]) + b'\0\0\0\0',                  # DWDM, 50GHz
      bytes([0x26, 0, 0, 5]) + b'\0\0\0\0',                  # DWDM 25GHz
      bytes([0x28, 0, 0, 5]) + b'\0\0\0\0',                  # DWDM 12.5GHz
      bytes([0x20, 0, 0, 5]) + b'\0\0\0\0',                  # DWDM, cs 0
      bytes([0x42, 0, 0, 7]) + b'\0\0\0\0',                  # CWDM 20nm
      bytes([0x4e, 0, 0, 7]) + b'\0\0\0\0',                  # CWDM unknown cs
      bytes([0x6a, 0, 0, 3, 0, 4, 0, 0]),                    # flexi 6.25GHz m=4
      bytes([0x62, 0, 0, 3, 0, 4, 0, 0]),                    # flexi unknown cs
      bytes([0x82, 0, 0, 3]) + b'\0\0\0\0',                  # unknown grid 4
      bytes([0x00, 0x01, 0x23, 0x45]),                       # SONET S/U/K/L/M
      bytes([0x00, 0x00, 0x01, 0x2b]),                       # G.709 labels
      bytes(range(1, 25)),                                   # long generalized label (6 words)
      bytes([0xff, 0xff, 0xff, 0xff]),                       # unassigned upstream label
      ]
for g in GL:
    send(C, msg(MSG['RESV'], [sess_lsp4(), hop4(), style(), obj(LABEL, 2, g)]), 'RESV: generalized LABEL %s' % g[:4].hex())
send(C, msg(MSG['PATH'], [sess_lsp4(), obj(UPSTREAM_LABEL, 2, bytes([0xff, 0xff, 0xff, 0xff])), obj(SUGGESTED_LABEL, 2, bytes([1, 2, 3, 4])), obj(RECOVERY_LABEL, 2, bytes([5, 6, 7, 8]))]), 'PATH: generalized upstream (unassigned), suggested, recovery labels')
send(C, msg(MSG['RESV'], [sess_lsp4(), hop4(), style(), obj(LABEL, 4, u32(1, 2, 3)), obj(LABEL, 9, b'\1\2\3\4')]), 'RESV: LABEL channel set and unknown c-type')
# LABEL_SET
send(C, msg(MSG['PATH'], [sess_lsp4(), obj(LABEL_SET, 1, bytes([0, 0, 0, 1]) + u32(10, 20, 30, 40, 50, 60, 70))]), 'PATH: LABEL_SET inclusive list, packet labels (7 subchannels)')
send(C, msg(MSG['PATH'], [sess_lsp4(), obj(LABEL_SET, 1, bytes([3, 0, 0, 2]) + u32(0x1000, 0x2000))]), 'PATH: LABEL_SET exclusive range, generalized labels')
send(C, msg(MSG['PATH'], [sess_lsp4(), obj(LABEL_SET, 1, bytes([9, 0, 0, 2]))]), 'PATH: LABEL_SET unknown action, no subchannels')

# ---------------- SESSION_ATTRIBUTE ----------------
send(C, msg(MSG['PATH'], [sess_lsp4(), hop4(), obj(SESS_ATTR, 1, u32(1, 2, 3) + bytes([7, 5, 0x1f, 8]) + b'tunnel-1')]), 'PATH: SESSION_ATTRIBUTE with affinities, all flags, name')
send(C, msg(MSG['PATH'], [sess_lsp4(), hop4(), obj(SESS_ATTR, 7, bytes([6, 6, 0, 0]))]), 'PATH: SESSION_ATTRIBUTE c-type 7, empty name')
send(C, msg(MSG['PATH'], [sess_lsp4(), hop4(), obj(SESS_ATTR, 3, b'\1\2\3\4')]), 'PATH: SESSION_ATTRIBUTE unknown c-type')

# ---------------- ERO, RRO, XRO, secondary routes ----------------
def sub(t, body, ln=None, extra=0):
    ln = 2 + len(body) if ln is None else ln
    return bytes([t, ln]) + body
def ero_sub_all(lbit):
    L = 0x80 if lbit else 0
    r = [sub(1 | L, S4 + bytes([32, 0])), sub(2 | L, S6 + bytes([128, 0])),
         sub(3 | L, bytes([0, 1]) + u32(777)), sub(4 | L, b'\0\0' + S4 + u32(12)),
         sub(32 | L, u16(65001)), sub(21, u16(65002)),
         sub(34 | L, u32(4242) + u16(0)), sub(64, u16(5) + S4), sub(65, u16(6) + S6),
         sub(124, b'\0\0' + u32(0x1234) + b'vend'), sub(127, b'\0\0' + u32(0x1234)),
         sub(99, b'\1\2')]
    return r
def rro_sub_all():
    return [sub(1, S4 + bytes([32, 0x2f])), sub(1, S4 + bytes([32, 0x0c])), sub(2, S6 + bytes([128, 0x2f])), sub(2, S6 + bytes([128, 0x0c])),
            sub(3, bytes([1, 1]) + u32(88)), sub(3, bytes([0, 1]) + u32(89)), sub(4, bytes([3, 0]) + S4 + u32(15)), sub(4, bytes([0, 0]) + S4 + u32(16)),
            sub(34, u16(0x8000) + u32(900)), sub(34, u16(0) + u32(901)),
            sub(32, u16(5)), sub(64, u16(5) + S4), sub(65, u16(5) + S6), sub(124, b'\0\0\0\0\0\0'), sub(252, b'\0\0' + u32(0x99) + b'abcd'), sub(255, b'\0\0' + u32(0x99)), sub(98, b'\1\2')]
def xro_sub_all():
    return [sub(1 | 0x80, S4 + bytes([24, 1])), sub(1, S4 + bytes([32, 0])), sub(2 | 0x80, S6 + bytes([64, 1])), sub(2, S6 + bytes([128, 0])),
            sub(3, bytes([0, 1]) + u32(5)), sub(4, b'\0\0' + S4 + u32(3)), sub(34, u32(1000) + u16(0)), sub(34 | 0x80, u32(1001) + u16(0)), sub(32, u16(5)), sub(64, u16(1) + S4),
            sub(124, b'\0\0' + u32(1) + b'xxxx'), sub(77, b'\1\2')]
def ro_split(subs, n):   # chunks so that each object stays small
    return [subs[i:i + n] for i in range(0, len(subs), n)]
for lbit in (0, 1):
    send(C, msg(MSG['PATH'], [sess_lsp4(), obj(ERO, 1, b''.join(ero_sub_all(lbit)))]), 'PATH: EXPLICIT_ROUTE with every subobject type, L bit %d' % lbit)
send(C, msg(MSG['PATH'], [sess_lsp4(), obj(ERO, 1, b''.join(ero_sub_all(0)[:2]))]), 'PATH: EXPLICIT_ROUTE with two subobjects')
send(C, msg(MSG['PATH'], [sess_lsp4(), obj(ERO, 5, b'\1\2\3\4')]), 'PATH: EXPLICIT_ROUTE unknown c-type')
send(C, msg(MSG['PATH'], [sess_lsp4(), obj(RRO, 1, b''.join(rro_sub_all()))]), 'PATH: RECORD_ROUTE with every subobject type')
send(C, msg(MSG['RESV'], [sess_lsp4(), hop4(), style(), obj(RRO, 5, b'\1\2\3\4')]), 'RESV: RECORD_ROUTE unknown c-type')
send(C, msg(MSG['PATH'], [sess_lsp4(), obj(XRO, 1, b''.join(xro_sub_all()))]), 'PATH: EXCLUDE_ROUTE with every subobject type')
send(C, msg(MSG['PATH'], [sess_lsp4(), obj(XRO, 5, b'\1\2\3\4')]), 'PATH: EXCLUDE_ROUTE unknown c-type')
send(C, msg(MSG['PATH'], [sess_p2mp4(), obj(SEC_ERO, 2, b''.join(ero_sub_all(1))), obj(SEC_RRO, 2, b''.join(rro_sub_all())), obj(SEC_ERO, 9, b'\1\2\3\4'), obj(SEC_RRO, 9, b'\1\2\3\4')]), 'PATH: SECONDARY_EXPLICIT_ROUTE and SECONDARY_RECORD_ROUTE')
send(C, msg(MSG['PATH'], [sess_lsp4(), obj(LINK_CAP, 1, b''.join(ero_sub_all(0)[:3])), obj(LINK_CAP, 2, b'\1\2\3\4')]), 'PATH: LINK_CAPABILITY')

# ---------------- MESSAGE_ID family, HELLO, DCLASS, ADMIN_STATUS ----------------
send(C, msg(MSG['PATH'], [sess_lsp4(), hop4(), obj(MSGID, 1, bytes([1, 0, 0, 5]) + u32(1001)), obj(MSGID, 1, bytes([0, 0, 0, 5]) + u32(1002)), obj(MSGID, 7, b'\1\2\3\4')]), 'PATH: MESSAGE_ID (ack desired, not), unknown c-type')
send(C, msg(MSG['ACK'], [obj(MSGID_ACK, 1, bytes([0, 0, 0, 5]) + u32(1001)), obj(MSGID_ACK, 2, bytes([0, 0, 0, 5]) + u32(1002)), obj(MSGID_ACK, 3, b'\1\2\3\4')]), 'ACK: MESSAGE_ID_ACK, NACK, unknown c-type')
send(C, msg(MSG['SREFRESH'], [obj(MSGID_LIST, 1, bytes([0, 0, 0, 5]) + u32(1, 2, 3, 4)), obj(MSGID_LIST, 2, b'\1\2\3\4')]), 'SREFRESH: MESSAGE_ID_LIST')
send(C, msg(MSG['HELLO'], [obj(HELLO, 1, u32(0x1234, 0)), obj(HELLO, 2, u32(0x5678, 0x1234)), obj(HELLO, 3)]), 'HELLO: request, ack, unknown c-type')
send(C, msg(MSG['PATH'], [sess_lsp4(), obj(DCLASS, 1, b'\0\0\0\x2e' * 6), obj(DCLASS, 1, b'\0\0\0\x28'), obj(DCLASS, 2, b'\1\2\3\4')]), 'PATH: DCLASS (6 DSCPs, 1 DSCP), unknown c-type')
send(C, msg(MSG['PATH'], [sess_lsp4(), obj(ADMIN_STATUS, 1, u32(0x800000ff)), obj(ADMIN_STATUS, 1, u32(0)), obj(ADMIN_STATUS, 2, b'\1\2\3\4')]), 'PATH: ADMIN_STATUS (all bits, none), unknown c-type')

# ---------------- LSP attributes, association, tunnel if id, notify request ----------------
send(C, msg(MSG['PATH'], [sess_lsp4(), obj(LSP_ATTR, 1, struct.pack('!HH', 1, 8) + u32(0xffffffff) + struct.pack('!HH', 9, 8) + u32(1)), obj(LSP_REQ_ATTR, 1, struct.pack('!HH', 1, 8) + u32(0xe0002000)), obj(LSP_ATTR, 3, b'\1\2\3\4')]), 'PATH: LSP_ATTRIBUTES and LSP_REQUIRED_ATTRIBUTES')
send(C, msg(MSG['PATH'], [sess_lsp4(), obj(ASSOCIATION, 1, u16(1, 55) + S4), obj(ASSOCIATION, 2, u16(2, 56) + S6), obj(ASSOCIATION, 4, u16(7, 57) + u32(3) + S4 + bytes(8)), obj(ASSOCIATION, 9, b'\1\2\3\4\5\6\7\x08')]), 'PATH: ASSOCIATION IPv4, IPv6, routing area, unknown')
TL = [struct.pack('!HH', 1, 8) + u32(5), struct.pack('!HH', 2, 8) + S4, struct.pack('!HH', 32769, 24) + bytes([1, 100, 5, 0]) + struct.pack('!Q', 0x1122334455667788) + u32(7) + S4, struct.pack('!HH', 55, 8) + u32(0)]
send(C, msg(MSG['PATH'], [sess_lsp4(), obj(TUNNEL_IF_ID, 1, S4 + u32(77)), obj(TUNNEL_IF_ID, 2, S4 + S4 + bytes([2, 0, 0, 0]) + b''.join(TL)),
                          obj(TUNNEL_IF_ID, 3, S6 + S4 + bytes([1, 0, 0, 0]) + TL[0]), obj(TUNNEL_IF_ID, 4, S4 + u32(9) + S4 + bytes([3, 0, 0, 0]) + TL[1]), obj(TUNNEL_IF_ID, 9, b'\1\2\3\4')]), 'PATH: LSP_TUNNEL_INTERFACE_ID all c-types with TLVs')
send(C, msg(MSG['NOTIFY'], [obj(NOTIFY_REQUEST, 1, S4), obj(NOTIFY_REQUEST, 2, S6), obj(NOTIFY_REQUEST, 3, b'\1\2\3\4'), err4(25, 1), sess_lsp4()]), 'NOTIFY: NOTIFY_REQUEST IPv4, IPv6, unknown')

# ---------------- Generalized UNI ----------------
def guni(cls, ty, body): return struct.pack('!HBB', 4 + len(body), cls, ty) + body
SESS_IN_DIV = sess_ipv4()
TMPL_IN_DIV = obj(TEMPLATE, 1, S4 + b'\0\0\0\x50')
GU = [guni(1, 1, S4), guni(2, 1, D4), guni(1, 2, S6), guni(2, 2, D6), guni(1, 3, bytes([20]) + bytes(range(1, 21)) + b'\0\0\0'), guni(2, 3, bytes([20]) + bytes(range(1, 21)) + b'\0\0\0'),
      guni(1, 9, b'\1\2\3\4'),
      guni(3, 1, bytes([1, 0, 0, 0]) + SESS_IN_DIV + TMPL_IN_DIV),
      guni(4, 1, bytes([0x80, 0, 0, 2]) + u32(5, 0x111, 0x222)), guni(4, 2, bytes([0, 0, 0, 1]) + u32(6, 0x333)), guni(4, 7, bytes([0, 0, 0, 1]) + u32(6)),
      guni(5, 1, bytes([2, 0, 0, 0])), guni(9, 1, b'\1\2\3\4')]
for n, g in enumerate(GU):
    send(C, msg(MSG['PATH'], [sess_lsp4(), hop4(), obj(GEN_UNI, 1, g), tv()]), 'PATH: GENERALIZED_UNI sub-object %d' % n)
send(C, msg(MSG['PATH'], [sess_lsp4(), hop4(), obj(GEN_UNI, 1, b''.join(GU[:8])), obj(GEN_UNI, 2, b'\1\2\3\4')]), 'PATH: GENERALIZED_UNI with eight sub-objects, unknown c-type')
send(C, msg(MSG['PATH'], [sess_lsp4(), hop4(), obj(GEN_UNI, 1, GU[0] + guni(4, 1, bytes([0x80, 0, 0, 2]) + u32(5, 0x111, 0x222)) + GU[1])]), 'PATH: GENERALIZED_UNI egress label sub-object between TNAs (advance by the 16-bit length)')

# ---------------- CALL_ID ----------------
send(C, msg(MSG['PATH'], [sess_lsp4(), obj(CALL_ID, 0), obj(CALL_ID, 0, b'\1\2\3\4')]), 'PATH: CALL_ID empty, with data')
for ty, addr in ((1, S4), (2, S6), (3, bytes(range(20))), (4, b'\x02\0\0\0\0\x07'), (0x7f, b'vendordefined'), (9, b'\1\2\3\4')):
    send(C, msg(MSG['PATH'], [sess_lsp4(), obj(CALL_ID, 1, bytes([ty, 0, 0, 0]) + addr + bytes(range(8)))]), 'PATH: CALL_ID operator specific, address type %d' % ty)
    send(C, msg(MSG['PATH'], [sess_lsp4(), obj(CALL_ID, 2, bytes([ty]) + b'ABC' + b'NATIONALSEG' + b'\0' + addr + bytes(range(8)))]), 'PATH: CALL_ID globally unique, address type %d' % ty)
send(C, msg(MSG['PATH'], [sess_lsp4(), obj(CALL_ID, 5, b'\1\2\3\4')]), 'PATH: CALL_ID unknown c-type')

# ---------------- 3GPP2 (reproducers of the QoS fixes) ----------------
def bits(s):
    s = s.replace(' ', ''); s += '0' * (-len(s) % 8)
    return int(s, 2).to_bytes(len(s) // 8, 'big')
def obj3gpp(ies): body = struct.pack('!I', 0x11223344) + b''.join(ies); return struct.pack('!HBB', 4 + len(body), 231, 1) + body + obj(100, 1, bytes(sum(len(i) for i in ies) + 16))
blob = bits('0001 010' + '0011' + '0000001' + '0' + '1111111111111111' + '0' * 5 +
            '1111' + '0000010' + '1' + '011' + '1' * 16 + '1' * 16 + '1' * 16 + '10101010' + '01010101' + '1')
qos_entry = bytes([7, len(blob)]) + blob
def tft_hdr(op, n=0, d=0): return struct.pack('!BBBB', d << 6, 0, op, n)
qos_list = struct.pack('!H', 2 + len(qos_entry)) + qos_entry
def ie(t, body, adj=4): return struct.pack('!HH', adj + len(body), t) + body
send(C, msg(MSG['PATH'], [sess_lsp4(), obj3gpp([ie(0, S4 + tft_hdr(0x01) + qos_list)])]), 'PATH: 3GPP2 TFT IPv4, QoS attribute sets with verbose 0 and 1 (Profile ID 16 bits, Max_Latency 8 bits)')
send(C, msg(MSG['PATH'], [sess_lsp4(), obj3gpp([ie(0x55, b'\xaa' * 8)])]), 'PATH: 3GPP2 unknown IE type (skipped over its data)')
send(C, msg(MSG['PATH'], [sess_lsp4(), obj3gpp([ie(4, b'\1\2\3\4\5\6')])]), 'PATH: 3GPP2 header removal IE')
def pfc(fid, comp, body, treat=False, prec=1, ptype=0, contlen=None):
    # packet filter: flow id, precedence, length, then PF type, content length, component id, component, treatment + hint
    sub_ = {16: 3, 17: 3, 32: 3, 33: 3, 48: 3, 64: 3, 80: 3, 81: 3, 96: 3, 112: 3, 128: 3, 129: 3, 130: 3}.get(comp)
    if contlen is None:
        contlen = (len(body) + sub_ if sub_ is not None else 5) + (5 if treat and sub_ is not None else 0)
    contents = bytes([ptype, contlen, comp]) + body + ((bytes([1]) + u32(3)) if treat else b'')
    return bytes([fid, prec]) + struct.pack('!H', len(contents)) + contents
PFS = [pfc(1, 16, S4 + a4('255.255.255.0')), pfc(2, 17, D4 + a4('255.255.0.0'), treat=True), pfc(3, 32, S6 + b'\x40'), pfc(4, 33, D6 + b'\x30', treat=True),
       pfc(5, 48, b'\x11'), pfc(6, 64, u16(5004)), pfc(7, 80, u16(5005)), pfc(8, 96, u32(0xdeadbeef)), pfc(9, 112, b'\x2e'),
       pfc(10, 128, b'\x01\x02\x03'), pfc(11, 129, S6 + b'\x40'), pfc(12, 130, S6 + b'\x40'), pfc(13, 81, u16(1000, 2000)),
       pfc(14, 65, u16(3000, 4000), treat=True)]
send(C, msg(MSG['PATH'], [sess_lsp4(), obj3gpp([ie(0, S4 + tft_hdr(0x03, len(PFS)) + b''.join(PFS))])]), 'PATH: 3GPP2 TFT IPv4 add packet filters (every filter component type)')
send(C, msg(MSG['PATH'], [sess_lsp4(), obj3gpp([ie(2, S6 + tft_hdr(0x04, 2, 1) + PFS[0] + PFS[3])])]), 'PATH: 3GPP2 TFT IPv6 replace packet filters (reverse direction)')
send(C, msg(MSG['PATH'], [sess_lsp4(), obj3gpp([ie(0, S4 + tft_hdr(0x05, 3) + bytes([1, 2, 3])), ie(0, S4 + tft_hdr(0x82, 2) + bytes([4, 5]))])]), 'PATH: 3GPP2 delete packet filters (flow identifiers only)')
send(C, msg(MSG['PATH'], [sess_lsp4(), obj3gpp([ie(0, S4 + tft_hdr(0x81, 0) + struct.pack('!H', 3 + len(qos_entry)) + qos_entry + b'\x00')])]), 'RESVCONF-style 3GPP2 QoS check confirm with result code')
send(C, msg(MSG['PATH'], [sess_lsp4(), obj3gpp([ie(0, S4 + tft_hdr(0x80, 1) + PFS[0] + qos_list), ie(0, S4 + tft_hdr(0x83, 0) + struct.pack('!H', 2 + len(qos_entry) * 2) + qos_entry * 2)])]), 'PATH: 3GPP2 initiate flow request and replace packet filters with QoS lists')
BLOB0 = bits('0001 001' + '0000')   # one QoS attribute set of length 0
send(C, msg(MSG['PATH'], [sess_lsp4(), obj3gpp([ie(0, S4 + tft_hdr(0x06, 0) + struct.pack('!H', 4 + len(BLOB0)) + bytes([3, len(BLOB0)]) + BLOB0)])]), 'PATH: 3GPP2 QoS check with an attribute set of length 0')
send(C, msg(MSG['PATH'], [sess_lsp4(), obj3gpp([ie(0, S4 + tft_hdr(0x02, 0) + b'\x01\x02')])]), 'PATH: 3GPP2 delete TFT')

# ---------------- restart cap, capability, protection, FRR, S2L, detour, diffserv, classtype, vendor ----------------
send(C, msg(MSG['HELLO'], [obj(HELLO, 1, u32(1, 0)), obj(RESTART_CAP, 1, u32(30000, 120000)), obj(RESTART_CAP, 2, b'\1\2\3\4'), obj(CAPABILITY, 1, u32(0x1f)), obj(CAPABILITY, 1, u32(0)), obj(CAPABILITY, 2, b'\1\2\3\4')]), 'HELLO: RESTART_CAP, CAPABILITY')
send(C, msg(MSG['PATH'], [sess_lsp4(), obj(PROTECTION, 1, bytes([0x80, 0, 0, 0x3f])), obj(PROTECTION, 2, bytes([0xf0, 0x1f, 0, 0x3f, 0xc0, 0x1f, 0, 0])), obj(PROTECTION, 2, bytes([0, 0, 0, 0, 0, 0, 0, 0])), obj(PROTECTION, 9, b'\1\2\3\4')]), 'PATH: PROTECTION (c-types 1, 2 and unknown)')
send(C, msg(MSG['PATH'], [sess_lsp4(), obj(FRR, 1, bytes([7, 7, 255, 3]) + u32(125000, 1, 2, 3)), obj(FRR, 7, bytes([7, 7, 255, 1]) + u32(125000, 1, 2)), obj(FRR, 3, b'\1\2\3\4')]), 'PATH: FAST_REROUTE (c-types 1, 7, unknown)')
mal(msg(MSG['PATH'], [sess_lsp4(), obj(FRR, 1, b'\0' * 8), obj(FRR, 7, b'\0' * 8)]), 'FAST_REROUTE with the wrong object length')
send(C, msg(MSG['PATH'], [sess_p2mp4(), obj(S2L_SUB_LSP, 1, D4), obj(S2L_SUB_LSP, 2, D6), obj(S2L_SUB_LSP, 3, b'\1\2\3\4')]), 'PATH: S2L_SUB_LSP IPv4, IPv6, unknown')
send(C, msg(MSG['PATH'], [sess_lsp4(), obj(DETOUR, 7, S4 + X4 + D4 + S4), obj(DETOUR, 1, b'\1\2\3\4')]), 'PATH: DETOUR (two pairs, unknown c-type)')
mal(msg(MSG['PATH'], [sess_lsp4(), obj(DETOUR, 7, S4 + X4 + D4)]), 'DETOUR with a truncated pair')
send(C, msg(MSG['PATH'], [sess_lsp4(), obj(DIFFSERV, 1, bytes([0, 0, 0, 2]) + u16(0x0020, 0x0000) + u16(0x4000, 0x0008)), obj(DIFFSERV, 2, u16(0, 0x1000)), obj(DIFFSERV, 3, b'\1\2\3\4')]), 'PATH: DIFFSERV E-LSP, L-LSP, unknown')
send(C, msg(MSG['PATH'], [sess_lsp4(), obj(CLASSTYPE, 1, b'\0\0\0\x03'), obj(CLASSTYPE, 2, b'\1\2\3\4')]), 'PATH: CLASSTYPE (DS-TE)')
for cls in (124, 127, 188, 191, 252, 255):
    send(C, msg(MSG['PATH'], [sess_lsp4(), obj(cls, 1, u32(0x1234) + b'private')]), 'PATH: vendor private object class %d' % cls)
send(C, msg(MSG['PATH'], [sess_lsp4(), obj(CALL_ATTR, 1, struct.pack('!HH', 2, 12) + b'endpoint'), obj(CALL_ATTR, 1, struct.pack('!HH', 9, 8) + b'\0' * 4)]), 'PATH: CALL_ATTRIBUTES endpoint ID, unknown TLV')

# ---------------- Juniper (reproducers of the TLV loop fix), unknown classes ----------------
JT = lambda t, v: bytes([t, 2 + len(v)]) + v
jbody = u16(7, 2) + JT(1, b'\x05') + JT(2, u32(100)) + JT(4, u32(200)) + JT(8, u16(3)) + JT(0x10, u32(1)) + JT(0x20, b'\xaa\xbb\xcc') + JT(0x01, b'\x01') + b'\0\0'
send(C, msg(MSG['PATH'], [sess_lsp4(), obj(JUNIPER, 1, jbody), obj(JUNIPER, 2, b'\1\2\3\4'), obj(JUNIPER, 2)]), 'PATH: JUNIPER_PROPERTIES TLVs (CoS, metrics, CCC status, path, unknown), unknown c-type')
# rsvp_juniper_loop.py: 8 octet objects, each claiming as many TLVs as there are objects after it
nobj = (1480 - 8 - 12) // 8
send(C, msg(MSG['PATH'], [sess_ipv4()] + [struct.pack('!HBBHH', 8, 204, 1, nobj - 1 - i, 0) for i in range(nobj)]), 'PATH: JUNIPER_PROPERTIES loop reproducer (%d objects of 8 octets, each claims all the later ones as TLVs)' % nobj)
send(C, msg(MSG['PATH'], [sess_lsp4(), obj(0, 1, b'\1\2\3\4'), obj(0, 1), obj(100, 1, b'\xde\xad\xbe\xef'), obj(40, 1), obj(ACCEPTABLE_LABEL_SET, 1, u32(1)), obj(150, 3, b'\1\2')]), 'PATH: NULL and unknown classes, ACCEPTABLE_LABEL_SET')
send(C, msg(MSG['PATH'], [sess_lsp4(), obj(ERO, 1, sub(4, b'\0\0' + S4 + u32(12)))]), 'PATH: ERO with one unnumbered interface subobject')
send(C, msg(MSG['PATH'], [sess_lsp4(), obj(ERO, 1, sub(32, u16(65001)))]), 'PATH: ERO with one AS subobject')
send(C, msg(MSG['PATH'], [sess_lsp4(), obj(ERO, 1, sub(34, u32(4242) + u16(0)))]), 'PATH: ERO with SRLG (unknown in an ERO)')
send(C, msg(MSG['PATH'], [sess_lsp4(), obj(RRO, 1, sub(34, u16(0x8000) + u32(900)))]), 'PATH: RRO with one SRLG subobject')
send(C, msg(MSG['PATH'], [sess_lsp4(), obj(XRO, 1, sub(34, u32(1000) + u16(0)))]), 'PATH: XRO with one SRLG subobject')
send(C, msg(MSG['PATH'], [sess_lsp4(), obj(ERO, 1, sub(64, u16(5) + S4))]), 'PATH: ERO with one path key (IPv4 PCE-ID)')
send(C, msg(MSG['PATH'], [sess_lsp4(), obj(ERO, 1, sub(65, u16(5) + S6))]), 'PATH: ERO with one path key (IPv6 PCE-ID)')
send(C, msg(MSG['PATH'], [sess_lsp4(), obj(SEC_RRO, 2, b''.join(rro_sub_all()[:4]) + sub(65, u16(5) + S6) + sub(64, u16(5) + S4)), obj(SEC_ERO, 2, sub(34, u32(1)  + u16(0)))]), 'PATH: secondary routes with path key subobjects')
send(C, msg(MSG['PATH'], [sess_lsp4(), obj(CALL_ID, 1, bytes([1, 0, 0, 0]) + S4 + bytes(8))]), 'PATH: CALL_ID short')
send(C, msg(MSG['PATH'], [sess_lsp4(), obj3gpp([ie(0, S4 + tft_hdr(0x03, 1) + pfc(1, 99, b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a', ptype=0, contlen=10))])]), 'PATH: 3GPP2 packet filter with an unknown component type')

# ---------------- bundle, ack and srefresh messages, other transports ----------------
sub1 = msg(MSG['PATH'], [sess_ipv4(), hop4(), tv(), obj(TEMPLATE, 1, S4 + b'\0\0\0\x50')])
sub2 = msg(MSG['RESV'], [sess_ipv4(), hop4(), style(0x0a), obj(FILTER, 1, S4 + b'\0\0\0\x50')])
sub3 = msg(MSG['ACK'], [obj(MSGID_ACK, 1, bytes([0, 0, 0, 5]) + u32(1001))])
send(C, msg(MSG['BUNDLE'], [sub1, sub2, sub3]), 'BUNDLE with PATH, RESV and ACK component messages')
inner = msg(MSG['BUNDLE'], [sub3])
send(C, msg(MSG['BUNDLE'], [inner, sub1]), 'BUNDLE containing a BUNDLE')
send(C, msg(MSG['PATH'], [sess_ipv4(), hop4(), tv()]), 'RSVP-E2EI PATH', proto=134)
send(C, msg(MSG['PATH'], [sess_lsp4(), hop4_ifid(ifid_all()[:4]), tv(), tmpl(TEMPLATE, 7, S4 + struct.pack('!HH', 3, 11))]), 'RSVP-E2EI PATH with IF-ID HOP', proto=134)
send(C, msg(MSG['PATH'], [sess_ipv4(), hop4(), tv(), obj(TEMPLATE, 1, S4 + b'\0\0\0\x50')]), 'RSVP over UDP port 3455 PATH', kind='udp')
send(C, msg(MSG['RESV'], [sess_ipv4(), hop4(), style(), obj(FILTER, 1, S4 + b'\0\0\0\x50')]), 'RSVP over UDP port 3455 RESV', kind='udp', src='192.0.2.2', dst='192.0.2.1')
send(C, msg(MSG['PATH'], [sess_ipv6(), hop6(), tv(), tmpl(TEMPLATE, 2, S6 + b'\0\0\0\x50')]), 'RSVP over IPv6 PATH', kind='ip6')
send(C, msg(MSG['PATH'], [sess_lsp6(), hop6(), tv(), tmpl(TEMPLATE, 8, S6 + struct.pack('!HH', 4, 12))]), 'RSVP over IPv6 PATH IPv6-LSP', kind='ip6')
send(C, msg(MSG['PATH'], [sess_p2mp6(), hop6(), tv(), tmpl(TEMPLATE, 13, S6 + b'\0\0' + struct.pack('!H', 14) + X6 + b'\0\0' + struct.pack('!H', 6))]), 'RSVP over IPv6 PATH P2MP IPv6 (summary of the sender template, Sub-Group ID)', kind='ip6')

# ---------------- reproducer: quadratic request hash (distinct session ports between one pair) ----------------
for port in range(100, 200):
    send(C, msg(MSG['PATH'], [obj(SESSION, 1, D4 + bytes([17, 0]) + struct.pack('!H', port)), hop4(), tv()]), 'PATH hash reproducer port %d' % port) if port in (100, 199) else C.add(msg(MSG['PATH'], [obj(SESSION, 1, D4 + bytes([17, 0]) + struct.pack('!H', port)), hop4(), tv()]), 'hash')
# ---------------- reproducer: Juniper loop with 64 KB frames (6 frames) ----------------
nobj = (65000 - 8 - 12) // 8
bigmsg = msg(MSG['PATH'], [sess_ipv4()] + [struct.pack('!HBBHH', 8, 204, 1, (nobj - 1 - i) if i < 3000 else 0, 0) for i in range(nobj)])
for k in range(6):
    send(C, bigmsg, 'PATH: JUNIPER_PROPERTIES loop reproducer, 64 KB frame %d (%d objects)' % (k + 1, nobj)) if k == 0 else C.add(bigmsg, 'big')
send(C, msg(MSG['PATH'], [sess_ipv4(), hop4(), tv(), obj(TEMPLATE, 1, S4 + b'\0\0\0\x50')], ttl=1), 'PATH with TTL 1 (end of the main capture)')

# =================== malformed capture ===================
# the original reproducers of the 3GPP2 fixes (rsvp_3gpp_qos.py): IE lengths that exclude the two length octets
OLDBLOB = bits('0001 010' + '0011' + '0000001' + '0' + '1111111111111111' + '0' * 4 + '1111' + '0000010' + '1' + '011' + '1' * 16 + '1' * 16 + '1' * 16 + '10101010' + '01010101' + '1')
OLDQ = struct.pack('!H', 2 + len(bytes([7, len(OLDBLOB)]) + OLDBLOB)) + bytes([7, len(OLDBLOB)]) + OLDBLOB
OLDS = obj(SESSION, 1, D4 + bytes([17, 0]) + struct.pack('!H', 1))
def oldobj(ies): body = struct.pack('!I', 0x11223344) + b''.join(ies); return struct.pack('!HBB', 4 + len(body), 231, 1) + body
def oldie(t, body): return struct.pack('!HH', 2 + len(body), t) + body
mal(msg(MSG['PATH'], [OLDS, oldobj([oldie(0, S4 + tft_hdr(0x01) + OLDQ)])]), '3GPP2 QoS attribute sets (original reproducer, IE length without the length field)')
mal(msg(MSG['PATH'], [OLDS, oldobj([oldie(0, S4 + tft_hdr(0x01) + struct.pack('!H', 0) + bytes([7, 0]) * 4)])]), '3GPP2 QoS list length 0 (original reproducer)')
mal(msg(MSG['PATH'], [OLDS, oldobj([oldie(0x55, b'\xaa' * 8), oldie(0x56, b'\xbb' * 8)])]), '3GPP2 unknown IEs (original reproducer)')
mal(msg(MSG['PATH'], [sess_lsp4(), obj3gpp([ie(0, S4 + tft_hdr(0x01) + struct.pack('!H', 1) + qos_entry)])]), '3GPP2 QoS list length 1')
mal(msg(MSG['PATH'], [sess_lsp4(), obj3gpp([ie(0x55, b'', adj=1)])]), '3GPP2 IE length below 2')
# Juniper TLV length errors
mal(msg(MSG['PATH'], [sess_lsp4(), obj(JUNIPER, 1, u16(2, 0) + bytes([1, 0]) + b'\0\0')]), 'JUNIPER TLV length 0')
mal(msg(MSG['PATH'], [sess_lsp4(), obj(JUNIPER, 1, u16(2, 0) + bytes([1, 1]) + b'\0\0')]), 'JUNIPER TLV length 1')
mal(msg(MSG['PATH'], [sess_lsp4(), obj(JUNIPER, 1, u16(2, 0) + bytes([1, 200]) + b'\0\0'), obj(100, 1, bytes(256))]), 'JUNIPER TLV length past the object')
mal(msg(MSG['PATH'], [sess_lsp4(), obj(JUNIPER, 1, u16(1, 0) + bytes([0x08, 8]) + bytes(6))]), 'JUNIPER CCC status TLV of 6 octets')
# IF-ID TLVs
mal(msg(MSG['PATH'], [sess_lsp4(), hop4_ifid([struct.pack('!HH', 1, 0)])]), 'HOP IF-ID TLV length 0')
mal(msg(MSG['PATH'], [sess_lsp4(), hop4_ifid([struct.pack('!HH', 1, 200) + S4])]), 'HOP IF-ID TLV length past the object')
mal(msg(MSG['PATH'], [sess_lsp4(), hop4_ifid([tlv(10, bytes([1, 0x47, 0, 5]))]), obj(100, 1, bytes(32))]), 'HOP IF-ID ISIS area length 1')
mal(msg(MSG['PATH'], [sess_lsp4(), hop4_ifid([tlv(23, bytes([12]) + bytes(11))]), obj(100, 1, bytes(32))]), 'HOP IF-ID ISIS area length 12')
# Ethernet TSPEC TLVs
mal(msg(MSG['PATH'], [sess_lsp4(), obj(TSPEC, 6, eth_body([struct.pack('!HH', 2, 0)]))]), 'TSPEC Ethernet TLV length 0')
mal(msg(MSG['PATH'], [sess_lsp4(), obj(TSPEC, 6, eth_body([eth_tlv(3, b'\x21\x30\0\0\0\0\0\0')])), obj(100, 1, bytes(256))]), 'TSPEC Ethernet L2CP TLV of the wrong length')
mal(msg(MSG['PATH'], [obj(TSPEC, 6, eth_body([eth_tlv(3, b'\x21\x30\0\0')]))]), 'TSPEC Ethernet L2CP TLV at the end of the message (bit offset past the data)')
mal(msg(MSG['RESV'], [sess_lsp4(), style(), obj(FLOWSPEC, 2, b'\0\0')]), 'FLOWSPEC IntServ with object length 6')
mal(msg(MSG['RESV'], [sess_lsp4(), style(), obj(FLOWSPEC, 2, struct.pack('!BBH', 0, 0, 1) + b'\0\0')]), 'FLOWSPEC IntServ with a short service header')
mal(msg(MSG['RESV'], [sess_lsp4(), style(), obj(FLOWSPEC, 2, struct.pack('!BBH', 0, 0, 100) + struct.pack('!BBH', 5, 0, 20) + TB)]), 'FLOWSPEC IntServ with service length past the object')
mal(msg(MSG['PATH'], [sess_lsp4(), obj(TSPEC, 2, struct.pack('!BBH', 0, 0, 100) + struct.pack('!BBH', 5, 0, 20) + TB)]), 'TSPEC IntServ with service length past the object')
# route subobjects, LSP attributes, tunnel IF-ID TLVs, GENERALIZED_UNI
mal(msg(MSG['PATH'], [sess_lsp4(), obj(ERO, 1, bytes([99, 0, 0, 0, 0, 0, 0, 0]))]), 'ERO subobject length 0')
mal(msg(MSG['PATH'], [sess_lsp4(), obj(ERO, 1, bytes([1, 8]) + S4)]), 'ERO IPv4 subobject cut short')
mal(msg(MSG['PATH'], [sess_lsp4(), obj(LSP_ATTR, 1, struct.pack('!HH', 1, 0) + u32(0))]), 'LSP_ATTRIBUTES TLV length 0')
mal(msg(MSG['PATH'], [sess_lsp4(), obj(TUNNEL_IF_ID, 2, S4 + S4 + bytes([2, 0, 0, 0]) + struct.pack('!HH', 1, 0) + u32(0))]), 'LSP_TUNNEL_INTERFACE_ID TLV length 0')
mal(msg(MSG['PATH'], [sess_lsp4(), obj(GEN_UNI, 1, guni(3, 1, bytes([1, 0, 0, 0]) + struct.pack('!HBB', 0, 1, 1) + bytes(8)))]), 'GENERALIZED_UNI diversity with a session of length 0')
mal(msg(MSG['PATH'], [sess_lsp4(), obj(GEN_UNI, 1, guni(3, 1, bytes([1, 0, 0, 0]) + SESS_IN_DIV + struct.pack('!HBB', 0, 11, 1) + bytes(8)) + bytes(16))]), 'GENERALIZED_UNI diversity with a template of length 0')
mal(msg(MSG['PATH'], [sess_lsp4(), obj(GEN_UNI, 1, struct.pack('!HBB', 0, 1, 1) + S4)]), 'GENERALIZED_UNI sub-object length 0')
mal(msg(MSG['PATH'], [sess_lsp4(), obj(GEN_UNI, 1, guni(2, 3, bytes([20]) + bytes(range(1, 21)) + b'\0\0\0'))]), 'GENERALIZED_UNI NSAP TNA as the last sub-object (string length reads past the object)')
mal(msg(MSG['PATH'], [sess_lsp4(), obj(CALL_ATTR, 1, struct.pack('!HH', 2, 2))]), 'CALL_ATTRIBUTES TLV length 2')
# object lengths
mal(msg(MSG['PATH'], [sess_ipv4(), obj(HOP, 1, b'', length=2)]), 'object length 2 (bogus)')
mal(msg(MSG['PATH'], [sess_ipv4(), obj(HOP, 1, b'', length=0)]), 'object length 0 (find_rsvp_session_tempfilt stops)')
mal(msg(MSG['PATH'], [sess_ipv4(), hop4(), tv()], length=500), 'message length longer than the data')
mal(msg(MSG['PATH'], [sess_ipv4(), obj(HOP, 1, S4 + u32(1), length=200)]), 'object length longer than the message')
mal(msg(MSG['PATH'], [sess_ipv4(), hop4()])[:12], 'message cut after the first object header')
mal(msg(MSG['PATH'], [sess_ipv4(), hop4()])[:7], 'message cut inside the common header')
mal(msg(MSG['PATH'], [sess_p2mp6()]), 'P2MP IPv6 session as the last object (the conversation info reads 12 octets past it)')
mal(msg(MSG['BUNDLE'], [sub1[:40]]), 'BUNDLE with a truncated component message')
mal(msg(MSG['BUNDLE'], [msg(MSG['PATH'], [], length=0)]), 'BUNDLE with a component message of length 0')
mal(msg(MSG['PATH'], [sess_ipv4(), obj(ADSPEC, 2, struct.pack('!BBH', 0, 0, 5) + svc(1, [param(4, 0, u32(3))])[:6])]), 'ADSPEC cut short')
mal(msg(MSG['PATH'], [sess_ipv4(), obj(DIFFSERV, 1, bytes([0, 0, 0, 5]) + u16(0x0020, 0))]), 'DIFFSERV E-LSP with MAPNB larger than the data')
mal(msg(MSG['PATH'], [sess_ipv4(), obj(LABEL_SET, 1, b'\0')]), 'LABEL_SET cut short')
mal(msg(MSG['PATH'], [sess_ipv4(), obj(SESS_ATTR, 1, u32(1, 2, 3) + bytes([7, 5, 0x1f, 200]) + b'tunnel')]), 'SESSION_ATTRIBUTE name length past the object')

# =================== output ===================
C.write(os.path.join(OUT, 'rsvp-coverage.pcap'))
M.write(os.path.join(OUT, 'rsvp-coverage-malformed.pcap'))
if VERB:
    for n, l in marks: print(n, l)
    print('main frames', len(C.frames), 'malformed frames', len(M.frames))
