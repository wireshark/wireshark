#!/usr/bin/env python3
# Generates test/captures/gre_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the GRE coverage captures. Usage: mkgre.py <outdir>"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
import socket
from common import csum, eth, pcap, udp

EMAC = bytes.fromhex('020000000002'), bytes.fromhex('020000000001')
CK, RT, KY, SQ, SS, AK = 0x8000, 0x4000, 0x2000, 0x1000, 0x0800, 0x0080

def ipv4(payload, proto=47, src='192.0.2.1', dst='192.0.2.2', fl=0):
    h = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, fl, 64, proto, 0,
                    socket.inet_aton(src), socket.inet_aton(dst))
    h = h[:10] + struct.pack('>H', csum(h)) + h[12:]
    return h + payload

def ipv6(payload, nh=47):
    a = b'\x20\x01\x0d\xb8' + b'\0' * 11
    return struct.pack('>IHBB', 0x60000000, len(payload), nh, 64) + a + b'\x01' + a + b'\x02' + payload

def e4(p): return eth(EMAC[0], EMAC[1], 0x0800, p)
def e6(p): return eth(EMAC[0], EMAC[1], 0x86dd, p)

INNER4 = ipv4(udp(40000, 40001, b'hi'), proto=17, src='10.0.0.1', dst='10.0.0.2')

def gre(flags, typ, rest=b'', payload=b'', cksum=False):
    """GRE header: flags, type, [checksum+offset], rest (key.. already built), payload."""
    h = struct.pack('>HH', flags, typ)
    if flags & (CK | RT):
        h += b'\0\0\0\0'
    h += rest + payload
    if cksum:
        c = csum(h)
        h = h[:4] + struct.pack('>H', c) + h[6:]
    return h

def sre(af, off, data): return struct.pack('>HBB', af, off, len(data)) + data
NULLSRE = struct.pack('>HBB', 0, 0, 0)

def a3(attrs):
    out = b''
    for i, (i_, v) in enumerate(attrs):
        out += bytes([i_, len(v)]) + v
    return out

PPP = b'\xff\x03\x00\x21' + INNER4

def fcs16(b):
    f = 0xffff
    for c in b:
        f ^= c
        for _ in range(8):
            f = (f >> 1) ^ 0x8408 if f & 1 else f >> 1
    return (~f) & 0xffff

def hdlc(p):
    p += struct.pack('<H', fcs16(p))
    out = b''
    for c in p:
        out += bytes([0x7d, c ^ 0x20]) if c in (0x7d, 0x7e) or c < 0x20 else bytes([c])
    return b'\x7e' + out + b'\x7e'
HPPP = hdlc(PPP)

def main(outdir):
    F = []       # (gre bytes) wrapped in IPv4 by default
    marks = []
    def add(g, v6=False, wrap=None):
        if wrap: F.append(wrap(g)); return
        F.append(e6(ipv6(g)) if v6 else e4(ipv4(g)))
    def mark(s): marks.append((len(F) + 1, s))

    mark('plain: IPv4, no payload types')
    add(gre(0, 0x0800, payload=INNER4))
    add(gre(0, 0x86dd, payload=ipv6(b'', nh=59)))
    add(gre(0, 0x0000))                      # keepalive, no payload
    add(gre(0, 0x0000, payload=b'\x00' * 4))  # keepalive with data
    add(gre(0, 0x1234, payload=b'unknown'))   # unknown type
    add(gre(0, 0x0800), )                     # empty IPv4 payload -> no payload
    mark('flags: checksum (good, bad), key, sequence, ack/ppp, recursion, strict')
    add(gre(CK, 0x0800, payload=INNER4, cksum=True))
    g = gre(CK, 0x0800, payload=INNER4, cksum=True); g = g[:4] + b'\x12\x34' + g[6:]
    add(g)
    add(gre(KY, 0x0800, struct.pack('>I', 0xdeadbeef), INNER4))
    add(gre(SQ, 0x0800, struct.pack('>I', 77), INNER4))
    add(gre(KY | SQ | SS | 0x0300, 0x0800, struct.pack('>II', 1, 2), INNER4))
    add(gre(0x00f8 & 0x0040, 0x0800, payload=INNER4))     # reserved flag bits
    add(gre(CK | KY | SQ, 0x0800, struct.pack('>II', 5, 6), INNER4, cksum=True), v6=True)
    mark('IPv6 transport and GRE-in-UDP (4754)')
    add(gre(0, 0x86dd, payload=ipv6(b'', nh=59)), v6=True)
    F.append(e4(ipv4(udp(1234, 4754, gre(0, 0x0800, payload=INNER4)), proto=17)))
    mark('enhanced GRE (PPTP): version 1, key = payload length + call id, seq, ack')
    ppp_pl = PPP
    add(gre(KY | 1, 0x880b, struct.pack('>HH', len(ppp_pl), 0x1234), ppp_pl))
    add(gre(KY | SQ | 1, 0x880b, struct.pack('>HHI', len(ppp_pl), 0x1234, 5), ppp_pl))
    add(gre(KY | SQ | AK | 1, 0x880b, struct.pack('>HHII', len(ppp_pl), 0x1234, 6, 5), ppp_pl))
    add(gre(KY | AK | 1, 0x880b, struct.pack('>HHI', 0, 0x1234, 6)))   # ack only, no payload
    add(gre(KY | 0, 0x880b, struct.pack('>I', 0x00010002), ppp_pl))     # version 0 PPP: key is a number
    mark('CDMA2000 A10 unstructured byte stream (key is a number) and 3GPP2')
    add(gre(KY, 0x8881, struct.pack('>I', 0x11223344), HPPP))
    add(gre(KY, 0x8881, struct.pack('>I', 0x11223344)))
    attrs = [(0x01, b'\x80'), (0x02, b'\xc0'), (0x03, b'\x05'), (0x04, b'\x40')]
    mark('3GPP2: SDI, flow control, flow discriminator, segmentation, unknown id; last bit ends the list')
    add(gre(KY, 0x88d2, struct.pack('>I', 0x11223344), a3([(0x01, b'\x80'), (0x82, b'\x40')]) + HPPP))
    add(gre(KY, 0x88d2, struct.pack('>I', 0x11223344), a3([(0x01, b'\x00'), (0x02, b'\xc0'), (0x03, b'\x12\x34'), (0x84, b'\x80')]) + HPPP))
    add(gre(KY, 0x88d2, struct.pack('>I', 0x11223344), a3([(0x04, b'\x40'), (0x05, b'\xaa\xbb'), (0x84, b'\x80')]) + HPPP))
    add(gre(KY, 0x88d2, struct.pack('>I', 0x11223344), a3([(0x04, b'\x00'), (0x84, b'\xc0')]) + HPPP))
    add(gre(KY, 0x88d2, struct.pack('>I', 0x11223344), a3([(0x01, b'\x00'), (0x82, b'\x00'), (0x03, b'\x01\x02\x03'), (0x84, b'\x80')]) + HPPP))
    add(gre(KY, 0x88d2, struct.pack('>I', 0x11223344), a3([(0x82, b'\xc0'), (0x84, b'\x00')]) + HPPP))
    add(gre(KY, 0x88d2, struct.pack('>I', 0x11223344), a3([(0x01, b'\xff'), (0x83, b'\x00')])))   # no payload
    mark('routing: one SRE then the null SRE, several SREs, null SRE only, strict source')
    add(gre(RT, 0x0800, payload=sre(0x0800, 0, bytes([192, 0, 2, 9])) + NULLSRE + INNER4))
    add(gre(RT | CK, 0x0800, payload=sre(0x0800, 4, bytes([192, 0, 2, 9, 192, 0, 2, 10])) + sre(2, 0, b'ab') + NULLSRE + INNER4, cksum=True))
    add(gre(RT | SS, 0x0800, payload=NULLSRE + INNER4))
    add(gre(RT | KY | SQ, 0x0800, struct.pack('>II', 9, 10), sre(0x86dd, 0, b'x') + NULLSRE + INNER4))
    mark('WCCP: version 1 (IPv4 follows), version 2 (redirect header)')
    add(gre(0, 0x883e, payload=INNER4))
    add(gre(0, 0x883e, payload=bytes([0x81, 0x05, 0x06, 0x07]) + INNER4))
    add(gre(0, 0x883e, payload=bytes([0x62, 0x00, 0x00, 0x00]) + INNER4))
    add(gre(0, 0x883e, payload=bytes([0x24, 0xff, 0x01, 0x02]) + INNER4))
    add(gre(0, 0x883e, payload=bytes([0x07, 0x01, 0x01, 0x01]) + INNER4))
    mark('other protocol types: ARP, ERSPAN, CDP, NHRP, EoIP, Airohive, ...')
    arp = struct.pack('>HHBBH6s4s6s4s', 1, 0x0800, 6, 4, 1, EMAC[1], b'\x0a\0\0\1', b'\0' * 6, b'\x0a\0\0\2')
    add(gre(0, 0x0806, payload=arp))
    inner_eth = eth(EMAC[0], EMAC[1], 0x0800, INNER4)
    add(gre(0, 0x6558, payload=inner_eth))
    add(gre(SQ, 0x88be, struct.pack('>I', 3), struct.pack('>HHI', 0x1001, 0x0005, 0x00000007) + inner_eth))
    add(gre(SQ, 0x22eb, struct.pack('>I', 3), struct.pack('>HHIHH', 0x2001, 0x0005, 0x1234, 0, 0) + inner_eth))
    cdp = bytes([2, 180, 0, 0]) + struct.pack('>HH', 1, 8) + b'rtr1'
    cdp = cdp[:2] + struct.pack('>H', csum(cdp)) + cdp[4:]
    add(gre(0, 0x2000, payload=cdp))
    add(gre(KY, 0x6400, struct.pack('>I', 0), inner_eth))
    add(gre(0, 0xfeae, payload=bytes(12)))
    add(gre(0, 0x8847, payload=struct.pack('>I', (16 << 12) | 0x100 | 64) + INNER4))
    add(gre(0, 0x8909, payload=bytes(10)))
    add(gre(0, 0x0001, payload=bytes(4)))
    add(gre(0, 0x00fe, payload=bytes(4)))
    mark('IP fragment (not reassembled, checksum not verified)')
    g = gre(CK, 0x0800, payload=INNER4, cksum=True)
    F.append(e4(ipv4(g, fl=0x2000)))
    mark('truncated capture with the checksum bit')
    full = e4(ipv4(gre(CK, 0x0800, payload=INNER4 + bytes(40), cksum=True)))
    F.append((full[:60], len(full)))

    mal = []
    inner_eth = eth(EMAC[0], EMAC[1], 0x0800, INNER4)
    # header only 2..3 octets, truncated key/sequence, routing past the end, 3GPP2 attributes past the end
    m = lambda g: mal.append(e4(ipv4(g)))
    m(b'\x00\x00')
    m(gre(0, 0x2001, payload=bytes(20)))
    m(gre(0, 0x894f, payload=struct.pack('>IIII', 0x0fc20003, 0x00000001, 0, 0)))
    for t in (0x8200, 0x8210, 0x91f0):
        m(gre(0, t, payload=inner_eth))
    m(gre(0, 0x8137, payload=bytes(30)))
    m(gre(0, 0x6559, payload=bytes(10)))
    m(struct.pack('>H', 0) + b'\x08')
    m(gre(KY, 0x0800)[:5])
    m(gre(SQ | KY, 0x0800, struct.pack('>I', 1)))
    m(gre(CK, 0x0800)[:6])
    m(gre(RT, 0x0800, b'\x08\x00\x00\x40abcd'))
    m(gre(RT, 0x0800, b''))
    m(gre(0, 0x883e, b''))
    m(gre(0, 0x883e, bytes([0x80, 0x05])))
    m(gre(KY, 0x88d2, struct.pack('>I', 1), bytes([1])))
    m(gre(KY, 0x88d2, struct.pack('>I', 1), bytes([1, 5, 0x80])))
    m(gre(KY, 0x88d2, struct.pack('>I', 1), bytes([1, 1, 0x80])))
    m(gre(KY, 0x88d2, struct.pack('>I', 1)))
    m(gre(KY | AK | 1, 0x880b, struct.pack('>HH', 0, 1)))
    m(gre(0, 0x0800, payload=b'\x45\x00'))
    m(gre(0, 0x6558, payload=b'\x02\x00'))
    mal.append(e4(ipv4(b'\x00')))   # one octet of GRE

    pcap(outdir + '/gre-coverage.pcap', F)
    pcap(outdir + '/gre-coverage-malformed.pcap', mal)
    for n, s in marks:
        print(n, s)
    print(len(F), 'frames;', len(mal), 'malformed')

main(sys.argv[1])
