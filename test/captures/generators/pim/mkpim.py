#!/usr/bin/env python3
# Generates test/captures/pim_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic captures for packet-pim.c. usage: mkpim.py <outdir>
#
# PIM v2 over IPv4 and IPv6 (IP protocol 103) with every message type, PIM v1
# in IGMP (type 0x14), the address encodings with Join Attributes, Register
# nesting. Checksums are computed (IPv4: over the PIM message, IPv6 with the
# pseudo-header).
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import struct
from lib import (
    csum, epb, eth, exp_pdu, gz, idb, ip4, ip6, ipv4, ipv6, shb, udp6_payload, udp_payload,
    write_pcap, write_pcapng,
)

out = sys.argv[1]
S4, D4 = '192.0.2.1', '224.0.0.13'
S6, D6 = '2001:db8::1', 'ff02::d'

# --- address encodings (RFC 7761, RFC 5384)
def uni(af=1, et=0, ja=b'', a4='192.0.2.9', a6='2001:db8::9'):
    return bytes((af, et)) + (ip4(a4) if af == 1 else ip6(a6)) + ja
def grp(af=1, mask=32, flags=0, a4='232.1.1.1', a6='ff3e::1234', et=0, ja=b''):
    return bytes((af, et, flags, mask)) + (ip4(a4) if af == 1 else ip6(a6))
def src(af=1, mask=32, flags=0x04, a4='10.0.0.1', a6='2001:db8:1::1', et=0, ja=b''):
    return bytes((af, et, flags, mask)) + (ip4(a4) if af == 1 else ip6(a6)) + ja
def jattr(typ, value, f=0, e=0):
    return bytes((f << 7 | e << 6 | typ, len(value))) + value
RPF4 = jattr(0, uni(1))
RPF6 = jattr(0, uni(2))
RPFX = jattr(0, b'\x01\x02\x03')
RLOC4 = jattr(6, bytes((1,)) + ip4('198.51.100.5'))
RLOC6 = jattr(6, bytes((2,)) + ip6('2001:db8:5::5'))
RLOCX = jattr(6, bytes((9,)) + b'\0' * 4)
TA_U = jattr(5, b'\x01')
TA_M = jattr(5, b'\x00')
MVPN = jattr(1, b'\x00\x01\x02\x03')
MTID = jattr(2, b'\x00\x10')
PCNT = jattr(3, b'\x00\x00\x00\x05')
EXRPF = jattr(4, b'\x01\x02')

# --- checksums
def pim(typever, sub, body, v4=True, cksum=None, whole=True, total=None):
    '''A PIM message: typever byte, subtype/reserved byte, checksum, body'''
    m = bytes((typever, sub)) + b'\0\0' + body
    n = len(m) if (whole and total is None) else (8 if total is None else total)
    if cksum is None:
        if v4:
            c = csum(m[:n])
        else:
            ph = ip6(S6) + ip6(D6) + struct.pack('!II', n, 103)
            c = csum(ph + m[:n])
    else:
        c = cksum
    return m[:2] + struct.pack('!H', c) + m[4:]

def v2(typ, body, sub=0, v4=True, ver=2, **k):
    return pim((ver << 4) | typ, sub, body, v4, whole=(typ != 1), **k)

frames = []
def P4(m, src_=S4, dst=D4): frames.append(eth(ipv4(103, m, src_, dst, ttl=1), 0x0800, dst=b'\x01\x00\x5e\x00\x00\x0d'))
def P6(m): frames.append(eth(ipv6(103, m, S6, D6, hlim=1), 0x86dd, dst=b'\x33\x33\x00\x00\x00\x0d'))

def both(typ, body4, body6, sub=0):
    P4(v2(typ, body4, sub)); P6(v2(typ, body6, sub, v4=False))

# --- Hello: all the options
def hopt(t, val=b''): return struct.pack('!HH', t, len(val)) + val
hello4 = (hopt(1, struct.pack('!H', 105)) + hopt(2, struct.pack('!HH', 0x8000 | 500, 2500)) +
          hopt(19, struct.pack('!I', 1)) + hopt(20, struct.pack('!I', 0xdeadbeef)) +
          hopt(21, bytes((1, 60)) + struct.pack('!H', 0)) +
          hopt(24, uni(1) + uni(1, a4='192.0.2.10') + uni(2)) +
          hopt(65001, uni(1, a4='192.0.2.11')))
P4(v2(0, hello4))
P4(v2(0, hopt(1, struct.pack('!H', 0))))                      # holdtime 0: goodbye
P4(v2(0, hopt(1, struct.pack('!H', 0xffff))))                 # infinity
P4(v2(0, hopt(2, struct.pack('!HH', 100, 200))))              # T bit clear
P4(v2(0, hopt(24, uni(1, et=1, ja=RPF4 + RLOC4)) + hopt(24, uni(2, et=1, ja=RLOC6 + RLOC4))))
P4(v2(0, hopt(24, uni(1, et=1, ja=RLOC4 + jattr(5, b'\x01', e=1)))))   # unicast with join attributes
for t in (17, 18, 22, 23, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 65004, 4000):
    P4(v2(0, hopt(t, b'\x01\x02\x03\x04')))
P4(v2(0, hopt(22)))                                           # no value
P4(v2(0, hopt(24, uni(9)) + hopt(1, struct.pack('!H', 5))))     # address list with an unknown family
P4(v2(0, hopt(24, uni(1, et=7))))                             # unknown encoding type
P6(v2(0, hopt(1, struct.pack('!H', 105)) + hopt(24, uni(2)) + hopt(20, struct.pack('!I', 7)), v4=False))
P4(v2(0, b''))                                                # Hello without options

# --- Register: encapsulated IPv4 / IPv6 data, Null-Register (dummy header), flags
inner4 = ipv4(17, udp_payload(1234, 4321, b'multicast data'), '10.0.0.1', '232.1.1.1')
inner6 = ipv6(17, udp6_payload(1234, 4321, b'multicast data6', '2001:db8:1::1', 'ff3e::1234'), '2001:db8:1::1', 'ff3e::1234')
dummy4 = struct.pack('!BBHHHBBH', 0, 0, 20, 0, 0, 0, 0, 0) + ip4('10.0.0.1') + ip4('232.1.1.1')
dummy6 = bytes(8) + ip6('2001:db8:1::1') + ip6('ff3e::1234') + bytes(0)
def reg(flags, data, v4=True): return v2(1, struct.pack('!I', flags) + data, v4=v4)
P4(reg(0, inner4)); P4(reg(0x80000000, inner6)); P4(reg(0x40000000, dummy4)); P4(reg(0xc0000000, inner4))
P6(reg(0, inner6, False)); P6(reg(0x40000000, dummy6, False)); P6(reg(0x80000000, inner4, False))
P4(reg(0, b'\x20\x00\x00\x00'))                               # version nibble that is neither 0, 4 nor 6
# nested Registers: IPv4 PIM Register inside a Register, three levels (the limit is four)
def nested(levels):
    data = inner4
    for _ in range(levels):
        m = reg(0, data)
        data = ipv4(103, m, '10.1.1.1', '10.2.2.2')
    return data
P4(reg(0, nested(1))); P4(reg(0, nested(2))); P4(reg(0, nested(3)))

# --- Register-Stop, Join/Prune, Graft, Graft-Ack
def groupset(af, njoin, nprune, **k):
    g = grp(af, **k)
    js = b''.join(src(af, a4='10.0.%d.1' % i, a6='2001:db8:1::%x' % (i + 1), flags=(4, 6, 7, 0, 1)[i % 5]) for i in range(njoin))
    ps = b''.join(src(af, a4='10.1.%d.1' % i, a6='2001:db8:2::%x' % (i + 1), flags=(1, 4)[i % 2]) for i in range(nprune))
    return g + struct.pack('!HH', njoin, nprune) + js + ps
def jp(af, groups, holdtime=210, nbr=None):
    return uni(af) + b'\0' + bytes((len(groups),)) + struct.pack('!H', holdtime) + b''.join(groups)
P4(v2(2, grp(1) + uni(1), sub=0)); P4(v2(2, grp(1, a4='224.1.1.1') + uni(1), sub=1))
P6(v2(2, grp(2) + uni(2), v4=False))
for typ in (3, 6, 7):
    P4(v2(typ, jp(1, [groupset(1, 2, 1), groupset(1, 0, 3, a4='232.2.2.2')])))
    P6(v2(typ, jp(2, [groupset(2, 1, 2)]), v4=False))
P4(v2(3, jp(1, [])))
P4(v2(3, jp(1, [grp(1, 24, 0x80 | 0x01) + struct.pack('!HH', 1, 0) + src(1, flags=0x07)])))
# join/prune with source join attributes (RPF, RLOC, transport, other types)
def endja(ja):
    '''set the End-of-Set bit on the last attribute of a chain'''
    pos = 0; last = 0
    while pos + 2 <= len(ja):
        last = pos; pos += 2 + ja[pos + 1]
    return ja[:last] + bytes((ja[last] | 0x40,)) + ja[last + 1:] if ja else ja
ja_src = lambda ja, af=1: src(af, et=1, ja=endja(ja))
P4(v2(3, jp(1, [grp(1) + struct.pack('!HH', 3, 1) + ja_src(RPF4) + ja_src(RPF6 + jattr(0, b'', e=1)) + ja_src(RLOC4 + TA_U + jattr(1, b'\x01', e=1)) +
                  ja_src(RPFX + MVPN + MTID + PCNT + EXRPF + RLOCX + TA_M + jattr(7, b'', e=1)) ])))
P4(v2(3, jp(1, [grp(1) + struct.pack('!HH', 2, 0) + ja_src(RLOC6 + RLOC4 + jattr(6, b'', e=1)) + ja_src(RPF4 + RLOC4 + jattr(5, b'\x00', f=1, e=1))])))
P6(v2(3, jp(2, [grp(2) + struct.pack('!HH', 2, 0) + ja_src(RPF6 + RLOC6 + jattr(4, b'\x00', e=1), 2) + ja_src(RLOC4 + RPF4, 2)]), v4=False))
P4(v2(3, uni(1, et=1, ja=RLOC4 + RLOC6 + jattr(5, b'\x01', e=1)) + b'\0' + bytes((1,)) + struct.pack('!H', 210) +
      grp(1) + struct.pack('!HH', 1, 0) + src(1)))                       # upstream neighbor with join attributes
P4(v2(3, uni(1, et=1, ja=RLOC4 + RLOC6 + jattr(5, b'\x01', e=1)) + b'\0\0' + struct.pack('!H', 210)))   # ... no groups
P6(v2(3, uni(2, et=1, ja=RLOC6 + jattr(5, b'\x01', e=1)) + b'\0' + bytes((1,)) + struct.pack('!H', 210) +
      grp(2) + struct.pack('!HH', 1, 0) + src(2), v4=False))

# --- Bootstrap
def rp(af, i): return uni(af, a4='192.0.2.%d' % (20 + i), a6='2001:db8::%x' % (20 + i)) + struct.pack('!HBB', 150, 192 + i, 0)
def bsm(af):
    body = struct.pack('!HBB', 0x1234, 30, 64) + uni(af)
    body += grp(af, 8, 0, a4='224.0.0.0', a6='ff00::') + bytes((2, 2, 0, 0)) + rp(af, 1) + rp(af, 2)
    body += grp(af, 4, 0, a4='239.0.0.0', a6='ff08::') + bytes((1, 1, 0, 0)) + rp(af, 3)
    body += grp(af, 16, 0x80, a4='225.0.0.0', a6='ff0e::') + bytes((0, 0, 0, 0))
    return body
P4(v2(4, bsm(1))); P6(v2(4, bsm(2), v4=False))
P4(v2(4, struct.pack('!HBB', 1, 0, 0) + uni(1)))                      # no group
# --- Assert, Candidate-RP-Advertisement, State-Refresh
P4(v2(5, grp(1) + uni(1) + struct.pack('!II', 0x80000000 | 101, 55)))
P4(v2(5, grp(1) + uni(1) + struct.pack('!II', 101, 0xffffffff)))
P6(v2(5, grp(2) + uni(2) + struct.pack('!II', 110, 20), v4=False))
P4(v2(8, bytes((2, 192)) + struct.pack('!H', 150) + uni(1) + grp(1, 8, a4='224.0.0.0') + grp(1, 4, a4='239.0.0.0')))
P6(v2(8, bytes((1, 0)) + struct.pack('!H', 150) + uni(2) + grp(2, 8, a6='ff00::'), v4=False))
P4(v2(8, bytes((0, 0)) + struct.pack('!H', 150) + uni(1)))
def srm(af):
    return (grp(af) + uni(af) + uni(af, a4='192.0.2.50', a6='2001:db8::50') +
            struct.pack('!II', 0x80000000 | 120, 30) + bytes((24, 16, 0xe0, 60)))
P4(v2(9, srm(1))); P6(v2(9, srm(2), v4=False))
P4(v2(9, srm(1)[:-2] + bytes((0x80, 60))))                              # only one of the flag bits
# --- DF Election: offer (1), winner (2), backoff (3), pass (4)
def dfe(af, sub):
    b = uni(af) + struct.pack('!II', 0x80000000 | 100, 5)
    if sub == 3:
        b += uni(af, a4='192.0.2.60', a6='2001:db8::60') + struct.pack('!IIH', 100, 10, 1500)
    if sub == 4:
        b += uni(af, a4='192.0.2.70', a6='2001:db8::70') + struct.pack('!II', 100, 10)
    return b
for sub in (1, 2, 3, 4):
    P4(v2(10, dfe(1, sub), sub=sub << 4)); P6(v2(10, dfe(2, sub), sub=sub << 4, v4=False))
P4(v2(10, dfe(1, 0), sub=0)); P4(v2(10, dfe(1, 1), sub=0xf0))
# --- ECMP Redirect (type 11, body not dissected), PFM, Packed Register
P4(v2(11, bytes(16)))
def pfmopt(t, val, tr=0): return struct.pack('!HH', (tr << 15) | t, len(val)) + val
def pfm(af, sub=0):
    o1 = pfmopt(1, grp(af, 32, 0) + struct.pack('!HH', 2, 300) + uni(af, a4='10.0.0.1', a6='2001:db8:1::1') + uni(af, a4='10.0.0.2', a6='2001:db8:1::2'), 1)
    o2 = pfmopt(1, grp(af, 32, 0, a4='232.5.5.5', a6='ff3e::5') + struct.pack('!HH', 0, 300))
    o3 = pfmopt(9, b'\x01\x02\x03', 1) + pfmopt(0x1234, b'')
    return uni(af, a4='192.0.2.80', a6='2001:db8::80') + o1 + o2 + o3
P4(v2(12, pfm(1), sub=0)); P4(v2(12, pfm(1), sub=0x80)); P6(v2(12, pfm(2), v4=False))
P4(v2(12, uni(1)))
def packed(af, n):
    return b''.join(grp(af, 32, 0, a4='232.1.1.%d' % i, a6='ff3e::%x' % i) + uni(af, a4='10.0.0.%d' % i, a6='2001:db8:1::%x' % i) for i in range(1, n + 1))
P4(v2(13, packed(1, 3), sub=0x00)); P4(v2(13, packed(1, 2), sub=0x13)); P4(v2(13, packed(1, 1), sub=0x20))
P6(v2(13, packed(2, 2)[:0] + packed(1, 2), sub=0x00, v4=False))
# unknown types and versions
P4(v2(14, bytes(8))); P4(v2(15, bytes(8)))
P4(v2(0, hopt(1, struct.pack('!H', 5)), ver=3, cksum=0x1234)); P4(v2(0, b'\x00' * 8, ver=1, cksum=0))
# --- PIM v1 (IGMP type 0x14)
def v1(code, body, ver=1, cksum=None, whole=True):
    m = bytes((0x14, code)) + b'\0\0' + bytes((ver << 4,)) + b'\0\0\0' + body
    n = len(m) if (whole and code != 1) else 8
    c = csum(m[:n]) if cksum is None else cksum
    return m[:2] + struct.pack('!H', c) + m[4:]
def P1(m): frames.append(eth(ipv4(2, m, S4, '224.0.0.2', ttl=1), 0x0800, dst=b'\x01\x00\x5e\x00\x00\x02'))
P1(v1(0, bytes((1, 0)) + struct.pack('!H', 105)))                      # query, sparse mode
P1(v1(0, bytes((0, 0)) + struct.pack('!H', 0xffff)))
P1(v1(0, bytes((2, 0)) + struct.pack('!H', 0)))
P1(v1(1, inner4)); P1(v1(1, inner6)); P1(v1(1, dummy4)); P1(v1(1, b'\x20\x00'))
P1(v1(1, ipv4(2, v1(1, inner4), '10.1.1.1', '10.2.2.2')))              # nested
P1(v1(2, ip4('232.1.1.1') + ip4('10.0.0.1')))
def v1addr(flags, mask, a): return bytes((flags, mask)) + ip4(a)
v1jp = ip4('192.0.2.2') + b'\0\0' + struct.pack('!H', 210) + bytes((0, 32, 4, 2))
v1jp += ip4('232.1.1.1') + ip4('255.255.255.255') + struct.pack('!HH', 2, 1) + v1addr(4, 32, '10.0.0.1') + v1addr(6, 32, '10.0.0.2') + v1addr(1, 24, '10.0.1.0')
v1jp += ip4('232.1.1.2') + ip4('255.255.255.0') + struct.pack('!HH', 0, 1) + v1addr(0, 32, '10.0.0.3')
for code in (3, 6, 7): P1(v1(code, v1jp))
P1(v1(4, ip4('232.1.1.1') + ip4('255.255.255.255') + ip4('192.0.2.2') + b'\0\0' + struct.pack('!H', 270)))
P1(v1(5, ip4('232.1.1.1') + ip4('255.255.255.255') + struct.pack('!II', 0x80000000 | 100, 20)))
P1(v1(8, b'\0' * 8)); P1(v1(9, b'\0' * 8))
P1(v1(0, b'', ver=1)); P1(v1(5, b'\0' * 4, ver=2, cksum=0)); P1(v1(0, bytes((1, 0, 0, 105)), ver=1))
# IPv6 PIM v1 does not exist; the dummy header of IPv4 v1 register above
write_pcap(out + '/pim-coverage.pcap', frames)

# --- malformed: bad checksums, deep Register nesting, truncated messages
frames = []
P4(v2(0, hopt(1, struct.pack('!H', 105)), cksum=0x1111)); P6(v2(0, hopt(1, struct.pack('!H', 105)), v4=False, cksum=0x2222))
P1(v1(0, bytes((1, 0, 0, 105)), cksum=0x3333))
# Register nesting well past the limit (the reproducer of "PIM: Bound Register nesting ...")
P4(reg(0, nested(8)))
d = inner4
for _ in range(8):
    d = ipv4(2, v1(1, d), '10.1.1.1', '10.2.2.2')
P1(v1(1, d))
# truncated messages
msgs = [v2(0, hello4), v2(3, jp(1, [groupset(1, 2, 1)])), v2(4, bsm(1)), v2(9, srm(1)), v2(10, dfe(1, 3), sub=0x30),
        v2(10, dfe(1, 4), sub=0x40), v2(12, pfm(1)), v2(13, packed(1, 3)), v2(2, grp(1) + uni(1)), v2(5, grp(1) + uni(1) + bytes(8)),
        v2(3, jp(1, [grp(1) + struct.pack('!HH', 3, 1) + ja_src(RPF4) + ja_src(RLOC6 + RLOC4)])), v2(8, bytes((2, 192)) + struct.pack('!H', 150) + uni(1) + grp(1))]
for m in msgs:
    for cut in range(4, len(m), 3):
        P4(m[:cut])
v1s = [v1(0, bytes((1, 0, 0, 105))), v1(3, v1jp), v1(4, bytes(20)), v1(5, bytes(16))]
for m in v1s:
    for cut in range(8, len(m), 5):
        P1(m[:cut])
# many join/prune entries in a short message
P4(v2(3, uni(1) + b'\0' + bytes((255,)) + struct.pack('!H', 210) + grp(1) + struct.pack('!HH', 65535, 65535)))
P1(v1(3, ip4('192.0.2.2') + b'\0\0' + struct.pack('!H', 210) + bytes((0, 32, 4, 255)) + ip4('232.1.1.1') + ip4('255.255.255.255') + struct.pack('!HH', 65535, 65535)))
# addresses with an unknown family or encoding in every message
for af, et in ((9, 0), (1, 5), (2, 9)):
    for typ, body in ((2, b''), (3, b''), (4, struct.pack('!HBB', 1, 0, 0)), (5, b''), (8, bytes((1, 0, 0, 5))), (9, b''), (10, b''), (12, b''), (13, b'')):
        a = bytes((af, et)) + bytes(18)
        P4(v2(typ, body + a))
write_pcap(out + '/pim-coverage-malformed.pcap', frames)

# Exported PDU frames: no IP layer, so the source address type is not IPv4/IPv6
mal = [shb(), idb(252)]
mal.append(epb(exp_pdu('pim', v2(0, hopt(1, struct.pack('!H', 105))))))
mal.append(epb(exp_pdu('pim', v2(1, struct.pack('!I', 0) + inner4))))
mal.append(epb(exp_pdu('pim', v2(1, struct.pack('!I', 0x40000000) + dummy4))))
mal.append(epb(exp_pdu('pimv1', v1(1, dummy4))))
mal.append(epb(exp_pdu('pimv1', v1(0, bytes((1, 0, 0, 105))))))
write_pcapng(out + '/pim-coverage-malformed.pcapng', mal)
gz(out + '/pim-coverage.pcap')
print('ok')
