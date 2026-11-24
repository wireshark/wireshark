#!/usr/bin/env python3
# Generates test/captures/mpls_echo_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Shared packet-building helpers (inlined into each mk<proto>.py).
import struct
import sys
import os

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff

class Cap:
    '''pcapng writer: interfaces are linktypes (1 Ethernet, 9 PPP, 104 Cisco HDLC)'''
    def __init__(self, links=(1,)):
        self.links = list(links)
        self.frames = []
    def add(self, data, link=1, comment=None):
        self.frames.append((self.links.index(link), bytes(data)))
        return len(self.frames)
    @staticmethod
    def _blk(t, body):
        body += b'\0' * (-len(body) % 4)
        return struct.pack('<II', t, len(body) + 12) + body + struct.pack('<I', len(body) + 12)
    def write(self, fname):
        out = self._blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
        for l in self.links:
            out += self._blk(1, struct.pack('<HHI', l, 0, 65535))
        ts = 1700000000 * 1000000
        for i, (ifc, d) in enumerate(self.frames):
            t = ts + i * 1000
            out += self._blk(6, struct.pack('<IIIII', ifc, t >> 32, t & 0xffffffff, len(d), len(d)) + d)
        with open(fname, 'wb') as f:
            f.write(out)

def eth(payload, etype=0x0800, dst='020000000002', src='020000000001'):
    return bytes.fromhex(dst + src) + struct.pack('!H', etype) + payload

def ipv4(payload, proto=17, src=(192, 0, 2, 1), dst=(192, 0, 2, 2), ident=1, ttl=64):
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0, ttl, proto, 0,
                     bytes(src), bytes(dst))
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    return ip + payload

def ipv6(payload, nxt=17, src=b'\x20\x01\x0d\xb8' + b'\0' * 11 + b'\x01',
         dst=b'\x20\x01\x0d\xb8' + b'\0' * 11 + b'\x02'):
    return struct.pack('!IHBB', 0x60000000, len(payload), nxt, 64) + src + dst + payload

def udp(payload, sport=1024, dport=9):
    return struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload

def ipv4_udp(payload, sport=1024, dport=9, **kw):
    return ipv4(udp(payload, sport, dport), 17, **kw)

def ipv6_udp(payload, sport=1024, dport=9,
             src=b'\x20\x01\x0d\xb8' + b'\0' * 11 + b'\x01',
             dst=b'\x20\x01\x0d\xb8' + b'\0' * 11 + b'\x02'):
    u = udp(payload, sport, dport)
    ck = csum(src + dst + struct.pack('!IBBBB', len(u), 0, 0, 0, 17) + u) or 0xffff
    u = u[:6] + struct.pack('!H', ck) + u[8:]
    return ipv6(u, 17, src, dst)

def label(lbl, exp=0, bos=0, ttl=64):
    return struct.pack('!I', (lbl << 12) | (exp << 9) | (bos << 8) | ttl)

def stack(*labels):
    '''labels: ints (label values) or (label, exp, bos, ttl) tuples; the last gets S=1'''
    out = b''
    for i, l in enumerate(labels):
        last = i == len(labels) - 1
        if isinstance(l, tuple):
            out += label(*l)
        else:
            out += label(l, 0, 1 if last else 0, 64)
    return out

def ach(chan, ver=1, res=0, nibble=1):
    return struct.pack('!BBH', (nibble << 4) | ver, res, chan)

def gal(chan, body=b'', ver=1, res=0, ttl=1, exp=0):
    '''GAL label (13, S=1) + associated channel header + body'''
    return label(13, exp, 1, ttl) + ach(chan, ver, res) + body

def mplsfr(payload, etype=0x8847):
    return eth(payload, etype)

# ---------------------------------------------------------------------
# MPLS Echo (LSP ping) coverage captures: packet-mpls-echo.c
# ---------------------------------------------------------------------
import socket
SECS = []
def sec(cap, name):
    SECS.append((len(cap.frames) + 1, name))

def a4(s): return socket.inet_aton(s)
def a6(s): return socket.inet_pton(socket.AF_INET6, s)

def echo_hdr(msgtype=1, gflags=0, reply=2, rc=0, rsc=0, handle=0x1234, seq=1, ver=1,
             sent=(0xe8000000, 0x80000000), rec=(0xe8000001, 0)):
    h = struct.pack('!HHBBBBII', ver, gflags, msgtype, reply, rc, rsc, handle, seq)
    # message types 3 and 4 (data plane) and others have a 16 octet header; 1 and 2 have 32
    if msgtype in (1, 2):
        h += struct.pack('!IIII', sent[0], sent[1], rec[0], rec[1])
    return h

def tlv(t, v=b''):
    return struct.pack('!HH', t, len(v)) + v

def sub(t, v=b''):
    '''FEC / DDMAP sub-TLV, padded to four octets (the padding is not in the length)'''
    return struct.pack('!HH', t, len(v)) + v + b'\0' * (-len(v) % 4)

def lbl3(label_, exp=0, bos=0, proto=0):
    return struct.pack('!I', (label_ << 12) | (exp << 9) | (bos << 8) | proto)

def udp_echo(payload, sport=3503, dport=3503):
    return eth(ipv4_udp(payload, sport, dport, dst=(127, 0, 0, 1)), 0x0800)

# Target FEC stack sub-TLVs (value lengths in comments)
LDP4 = sub(1, a4('192.0.2.0') + b'\x18')                 # 5
LDP6 = sub(2, a6('2001:db8::') + b'\x40')                # 17
RSVP4 = sub(3, a4('192.0.2.1') + struct.pack('!HHI4sHH', 0, 7, 0x0a000001, a4('192.0.2.9'), 0, 9))  # 20
RSVP6 = sub(4, a6('2001:db8::1') + struct.pack('!HH', 0, 7) + a6('2001:db8::2') + a6('2001:db8::3') + struct.pack('!HH', 0, 9))  # 56
RES = sub(5, b'reserved fec')
VPN4 = sub(6, bytes(range(8)) + a4('198.51.100.0') + b'\x18')     # 13
VPN6 = sub(7, bytes(range(8)) + a6('2001:db8:1::') + b'\x30')     # 25
L2VPN = sub(8, bytes(range(8)) + struct.pack('!HHH', 1, 2, 5))    # 14
L2OLD = sub(9, a4('192.0.2.5') + struct.pack('!IHH', 100, 5, 0))  # 12
L2NEW = sub(10, a4('192.0.2.6') + a4('192.0.2.7') + struct.pack('!IHH', 200, 5, 0))   # 16
L2NEW14 = sub(10, a4('192.0.2.6') + a4('192.0.2.7') + struct.pack('!IH', 200, 5))      # 14
F129 = sub(11, b'fec 129 value 12')
BGP4 = sub(12, a4('203.0.113.0') + b'\x18')              # 5
BGP6 = sub(13, a6('2001:db8:2::') + b'\x30')             # 17
GEN4 = sub(14, a4('203.0.113.128') + b'\x19')            # 5
GEN6 = sub(15, a6('2001:db8:3::') + b'\x40')             # 17
NIL1 = sub(16, lbl3(0, 0, 1))                            # label 0 (explicit null)
NIL2 = sub(16, lbl3(2) + lbl3(500, 0, 1))                # reserved + normal
NIL3 = sub(16, lbl3(3) + lbl3(16) + lbl3(1000, 0, 1))
P2MP4 = sub(17, a4('192.0.2.1') + struct.pack('!HHI4sHH', 0, 7, 0x0a000001, a4('192.0.2.9'), 0, 9))   # 20
P2MP6 = sub(18, a6('2001:db8::1') + struct.pack('!HH', 0, 7) + a6('2001:db8::2') + a6('2001:db8::3') + struct.pack('!HH', 0, 9))
SLSP = sub(22, struct.pack('!IIHHIIHH', 1, 2, 3, 4, 5, 6, 7, 0))      # 24
SPW = sub(23, struct.pack('!QIIIIII', 77, 1, 2, 3, 4, 5, 6))          # 32
PW6 = sub(24, a6('2001:db8::10') + a6('2001:db8::11') + struct.pack('!HHH', 5, 5, 0))   # 38
PW6_129 = sub(25, b'fec 129 ipv6 pw value')
SR4 = sub(34, a4('192.0.2.77') + struct.pack('!BBH', 32, 1, 0))      # 8
SR6 = sub(35, a6('2001:db8::77') + struct.pack('!BBH', 128, 2, 0))   # 20
def sradj(adjtype, proto, addr, extra):
    return sub(36, struct.pack('!BBH', adjtype, proto, 0) + addr + extra)
SRADJ4_OSPF = sradj(4, 1, a4('10.0.0.1') + a4('10.0.0.2'), struct.pack('!II', 11, 12))
SRADJ6_ISIS = sradj(6, 2, a6('fe80::1') + a6('fe80::2'), bytes(range(6)) + bytes(range(6, 12)))
SRADJ_UN_ANY = sradj(0, 0, struct.pack('!II', 5, 6), struct.pack('!II', 7, 8))
SRADJ_PAR_ANY = sradj(1, 0, struct.pack('!II', 5, 6), struct.pack('!II', 7, 8))
SRADJ_OTHER = sradj(9, 9, b'', b'')                              # neither switch matches
VENDOR_FEC = sub(0xfc10, struct.pack('!I', 9) + b'vendor fec data')
VENDOR_FEC_NOVAL = sub(0xfc11, struct.pack('!I', 9))             # enterprise code only
UNKNOWN_FEC = sub(0x0099, b'unknown fec type 5')

def ilso(addrtype, addr, labels, mbz=0):
    return struct.pack('!B3s', addrtype, struct.pack('!I', mbz)[1:]) + addr + b''.join(labels)

LBLS = [lbl3(100, 0, 0, 64), lbl3(3, 0, 1, 1)]
def ilso4(t=1, labels=LBLS): return ilso(t, a4('192.0.2.20') + (a4('192.0.2.21') if t == 1 else struct.pack('!I', 9)), labels)
def ilso6(t=3, labels=LBLS): return ilso(t, a6('2001:db8::20') + (a6('2001:db8::21') if t == 3 else struct.pack('!I', 9)), labels)

def dsmap(addrtype, flags=0, hashtype=0, depth=0, mp=b'', labels=(), mtu=1500, mplen=None, addr=None):
    if addr is None:
        addr = {1: a4('192.0.2.30') + a4('192.0.2.31'),
                2: a4('192.0.2.30') + struct.pack('!I', 4),
                3: a6('2001:db8::30') + a6('2001:db8::31'),
                4: a4('192.0.2.30') + struct.pack('!I', 4),
                5: struct.pack('!II', 7, 8)}.get(addrtype, b'\0' * 8)
    if mplen is None: mplen = len(mp)
    return (struct.pack('!HBB', mtu, addrtype, flags) + addr +
            struct.pack('!BBH', hashtype, depth, mplen) + mp + b''.join(labels))
DSLBL = [lbl3(100, 5, 0, 3), lbl3(0, 0, 0, 1), lbl3(15, 1, 1, 9)]

def ddmap(addrtype, subs=b'', rc=3, rsc=1, mtu=1500, flags=0, addr=None, sublen=None):
    if addr is None:
        addr = {1: a4('192.0.2.40') + a4('192.0.2.41'),
                3: a6('2001:db8::40') + a6('2001:db8::41'),
                5: struct.pack('!II', 7, 8)}.get(addrtype, b'\0' * 8)
    return struct.pack('!HBB', mtu, addrtype, flags) + addr + struct.pack('!BBH', rc, rsc, len(subs) if sublen is None else sublen) + subs
def mp_sub(mptype, info=b'', mplen=None):
    v = struct.pack('!BHB', mptype, len(info) if mplen is None else mplen, 0) + info
    return struct.pack('!HH', 1, len(v)) + v
def ls_sub(*labels):
    v = b''.join(labels)
    return struct.pack('!HH', 2, len(v)) + v
def sc_sub(op, addrtype, peer, fecs):
    v = struct.pack('!BBBB', op, addrtype, len(fecs), 0) + peer + fecs
    return struct.pack('!HH', 3, len(v)) + v
DDLBL = [lbl3(30, 0, 0, 0), lbl3(0, 0, 1, 0)]

PADTLV8 = tlv(3, b'\x02' + b'padding')

def build_main():
    c = Cap()
    def e(tlvs=b'', **kw):
        return c.add(udp_echo(echo_hdr(**kw) + tlvs))
    sec(c, 'headers: request, reply, data plane and unknown message types, flags, reply modes, return codes; IPv6 and MPLS transports')
    e()
    e(gflags=0x0007, reply=1, seq=2)
    e(msgtype=2, gflags=0x000f, reply=4, rc=8, rsc=3, seq=3)
    e(msgtype=3, seq=4, reply=3)
    e(msgtype=4, seq=5, reply=2, rc=1)
    e(msgtype=5, seq=6, reply=2)
    c.add(eth(ipv6_udp(echo_hdr(seq=7) + tlv(1, LDP6), 3503, 3503), 0x86dd))
    c.add(eth(stack(100, 101) + ipv4_udp(echo_hdr(seq=8) + tlv(1, LDP4), 49152, 3503, dst=(127, 0, 0, 1)), 0x8847))
    c.add(eth(gal(0x0025, echo_hdr(seq=9) + tlv(1, LDP4 + RSVP4)), 0x8847))
    c.add(eth(gal(0x0025, echo_hdr(msgtype=3, seq=10) + tlv(3, b'\x01')), 0x8847))
    sec(c, 'Target FEC stack: every FEC type, with padding')
    e(tlv(1, LDP4 + LDP6 + RSVP4 + RSVP6))
    e(tlv(1, RES + VPN4 + VPN6 + L2VPN))
    e(tlv(1, L2OLD + L2NEW + L2NEW14 + F129))
    e(tlv(1, BGP4 + BGP6 + GEN4 + GEN6))
    e(tlv(1, P2MP4 + P2MP6 + SLSP + SPW))
    e(tlv(1, PW6 + PW6_129 + SR4 + SR6))
    e(tlv(1, SRADJ4_OSPF + SRADJ6_ISIS + SRADJ_UN_ANY + SRADJ_PAR_ANY + SRADJ_OTHER))
    e(tlv(1, VENDOR_FEC + VENDOR_FEC_NOVAL + UNKNOWN_FEC + LDP4))
    e(tlv(1, LDP4 + NIL1))
    e(tlv(1, NIL2))
    e(tlv(1, LDP4 + NIL3))
    e(tlv(0x10, LDP4 + GEN6))                              # reverse path FEC stack
    e(tlv(1, b'') + tlv(0x10, b''))                         # empty TLVs
    sec(c, 'simple TLVs')
    e(tlv(3, b'\x01') + tlv(3, b'\x02' + b'padding 11 octets') + tlv(3))
    e(tlv(5, struct.pack('!I', 9)) + tlv(4, b'\x01\x02\x03\x04') + tlv(6, b'tbd tlv') + tlv(0x0099, b'unknown tlv type'))
    e(tlv(10, b'\xb8\0\0\0'))
    e(tlv(0x0c, struct.pack('!I', 100)) + tlv(0x0d, struct.pack('!II', 1, 2)) + tlv(0x0e, struct.pack('!II', 3, 4)) + tlv(0x0f, struct.pack('!I', 0xdeadbeef)))
    e(tlv(0x0b, struct.pack('!HH', 1, 4) + a4('192.0.2.50')) + tlv(0x0b, struct.pack('!HH', 3, 4) + a4('192.0.2.51')))
    e(tlv(0x0b, struct.pack('!HH', 2, 16) + a6('2001:db8::50')) + tlv(0x0b, struct.pack('!HH', 4, 16) + a6('2001:db8::51')))
    e(tlv(0x0b, struct.pack('!HH', 9, 4) + a4('192.0.2.52')))     # unknown responder identifier type
    e(tlv(0xfc01, struct.pack('!I', 9) + b'vendor private tlv') + tlv(0xffff, struct.pack('!I', 10)))
    sec(c, 'Interface and label stack objects')
    e(tlv(7, ilso4(1)) + tlv(7, ilso4(2)))
    e(tlv(7, ilso4(1, [])) + tlv(7, ilso4(1, [lbl3(0, 0, 1, 64)])))
    e(tlv(8, ilso6(3)) + tlv(8, ilso6(4)))
    e(tlv(8, ilso6(3, [lbl3(1000, 7, 1, 255)])))
    sec(c, 'Errored TLVs')
    e(tlv(9, tlv(3, b'\x01') + tlv(0xfc00, struct.pack('!I', 1))))
    e(tlv(9, tlv(1, LDP4)) + tlv(9, tlv(7, ilso4(1))) + tlv(9, tlv(9, tlv(3, b'\x01'))))
    e(tlv(9, b'') + tlv(9, tlv(3)))
    sec(c, 'Downstream Mapping TLV')
    e(tlv(2, dsmap(1, hashtype=0, labels=DSLBL)))
    e(tlv(2, dsmap(2, flags=3, hashtype=2, mp=a4('198.51.100.1'), depth=2)))
    e(tlv(2, dsmap(3, flags=1, hashtype=4, mp=a4('198.51.100.1') + a4('198.51.100.9'), labels=DSLBL)))
    e(tlv(2, dsmap(4, flags=2, hashtype=8, mp=a4('198.51.100.0') + b'\xf0\x0f')))
    e(tlv(2, dsmap(5, hashtype=8, mp=a4('198.51.100.0'), labels=[lbl3(1048575, 7, 1, 6)])))
    for h in (0, 1, 3, 5, 6, 7, 9, 10):
        e(tlv(2, dsmap(1, hashtype=h, mp=b'\x01\x02\x03\x04\x05\x06', depth=h, labels=[lbl3(100 + h, 0, 1, 1)])))
    sec(c, 'Detailed Downstream Mapping TLV: multipath, label stack and stack change sub-TLVs (each last, see README)')
    e(tlv(0x14, ddmap(1, ls_sub(*DDLBL))))
    e(tlv(0x14, ddmap(1, ls_sub(*DDLBL) + mp_sub(0, b'\0' * 0))))
    e(tlv(0x14, ddmap(1, ls_sub(*DDLBL) + mp_sub(2, a4('198.51.100.1')))))
    e(tlv(0x14, ddmap(3, ls_sub(*DDLBL) + mp_sub(4, a4('198.51.100.1') + a4('198.51.100.9')))))
    e(tlv(0x14, ddmap(5, ls_sub(lbl3(7, 0, 1, 0)) + mp_sub(8, a4('198.51.100.0') + b'\xaa\x55'))))
    e(tlv(0x14, ddmap(1, mp_sub(8, a4('198.51.100.0')))))
    e(tlv(0x14, ddmap(1, mp_sub(9, b'\x01\x02\x03\x04\x05\x06\x07\x08'))))
    e(tlv(0x14, ddmap(1, ls_sub(*DDLBL) + sc_sub(1, 0, b'', LDP4))))
    e(tlv(0x14, ddmap(1, sc_sub(2, 1, a4('203.0.113.1'), LDP4 + GEN4))))
    e(tlv(0x14, ddmap(3, sc_sub(1, 2, a6('2001:db8::99'), GEN6))))
    e(tlv(0x14, ddmap(1, struct.pack('!HH', 0x0777, 6) + b'\x01\x02\x03\x04\x05\x06')))   # unknown sub-TLV type, last
    e(tlv(0x14, ddmap(1, mp_sub(5, b'\x01\x02\x03\x04')) ) + PADTLV8)   # unknown multipath type, followed by a TLV
    e(tlv(0x14, ddmap(1)) )                                             # no sub-TLVs
    sec(c, 'several TLVs in one message')
    e(tlv(1, LDP4 + RSVP4) + tlv(3, b'\x02pad') + tlv(10, b'\xb8\0\0\0') + tlv(7, ilso4(1)) + tlv(5, struct.pack('!I', 9)), msgtype=1, gflags=1)
    e(tlv(7, ilso4(1)) + tlv(2, dsmap(1, labels=DSLBL)) + tlv(4, b'\x05\x06\x07\x08'), msgtype=2, rc=2, reply=2)
    return c

def build_malformed():
    c = Cap()
    def e(tlvs=b'', **kw):
        return c.add(udp_echo(echo_hdr(**kw) + tlvs))
    sec(c, 'message too short, version 2 (not MPLS echo)')
    c.add(udp_echo(echo_hdr()[:20]))                       # request shorter than 32 octets
    c.add(udp_echo(echo_hdr(msgtype=3)[:12]))              # data plane shorter than 16 octets
    c.add(udp_echo(echo_hdr(ver=2) + tlv(3, b'\x01')))     # version != 1: left to UDP/data
    c.add(udp_echo(b'\x00\x01\x00\x00'))                   # fewer than 5 octets
    sec(c, 'TLV and FEC sub-TLV length errors')
    e(tlv(3, b'\x01') + b'\xaa\xbb')                       # two octets after the last TLV
    e(struct.pack('!HH', 3, 100) + b'\x01\x02')            # TLV longer than the message
    e(tlv(1, struct.pack('!HH', 1, 100) + b'\x01\x02\x03\x04'))      # FEC longer than the TLV
    e(tlv(1, LDP4[:-2]))                                   # padded length does not fit
    e(tlv(1, struct.pack('!HH', 3, 8) + b'\0' * 8))        # RSVP IPv4 length != 20
    e(tlv(1, struct.pack('!HH', 4, 8) + b'\0' * 8))        # RSVP IPv6 length != 56
    e(tlv(1, struct.pack('!HH', 10, 8) + b'\0' * 8))       # L2 CID new length < 14
    e(tlv(1, struct.pack('!HH', 24, 8) + b'\0' * 8))       # PW IPv6 length != 38
    e(tlv(1, struct.pack('!HH', 17, 8) + b'\0' * 8))       # P2MP IPv4 length != 20
    e(tlv(1, struct.pack('!HH', 18, 8) + b'\0' * 8))       # P2MP IPv6 length != 56
    e(tlv(1, struct.pack('!HH', 0xfc10, 2) + b'\0' * 4))   # vendor private FEC shorter than 4
    e(tlv(1, struct.pack('!HH', 5, 0)))                    # reserved FEC, empty
    e(tlv(7, b'\0' * 8) + tlv(8, b'\0' * 16))              # ILSO too short
    e(tlv(0x0c, b'\0\0') + tlv(10, b'\0\0') + tlv(0xfc00, b'\0\0'))
    e(tlv(0x0b, struct.pack('!HH', 1, 8) + b'\0' * 8) + tlv(0x0b, struct.pack('!HH', 3, 8) + b'\0' * 8))   # responder identifier length errors
    e(tlv(0x0b, struct.pack('!HH', 2, 4) + b'\0' * 8) + tlv(0x0b, struct.pack('!HH', 4, 4) + b'\0' * 8))
    e(tlv(2, b'\0' * 8) + tlv(0x14, b'\0' * 8))            # downstream mappings shorter than 16
    sec(c, 'incorrect and unknown address types')
    e(tlv(7, ilso4(3)) )                                   # IPv6 type in the IPv4 object (reads on)
    e(tlv(8, ilso6(1, [])) )                               # IPv4 type in the IPv6 object
    e(tlv(7, struct.pack('!B3s', 9, b'\0\0\0') + b'\0' * 16))     # unknown type: ends the object
    e(tlv(2, dsmap(9, hashtype=0, addr=b'\0' * 8)))
    e(tlv(0x14, ddmap(9, addr=b'\0' * 8)))
    sec(c, 'Downstream Mapping multipath errors')
    e(tlv(2, dsmap(1, hashtype=2, mp=b'\1\2\3\4\5\6\7\x08')))        # IP with length 8
    e(tlv(2, dsmap(1, hashtype=4, mp=b'\1\2\3\4')))                # range with length 4
    e(tlv(2, dsmap(1, hashtype=8, mp=b'\1\2')))                    # bit mask with length 2
    e(tlv(2, dsmap(1, hashtype=2, mp=b'\1\2\3\4', mplen=200)))     # multipath longer than the TLV
    sec(c, 'Detailed Downstream Mapping sub-TLV errors, and the bugs of the report')
    e(tlv(0x14, ddmap(1, b'\x00\x07\x00\x64' + b'\0' * 8)))        # sub-TLV longer than the TLV
    e(tlv(0x14, ddmap(1, mp_sub(2, a4('198.51.100.1') + a4('198.51.100.2')))))   # IP, length 8
    e(tlv(0x14, ddmap(1, mp_sub(4, a4('198.51.100.1')))))          # range, length 4
    e(tlv(0x14, ddmap(1, mp_sub(8, b'\1\2'))))                     # bit mask, length 2
    e(tlv(0x14, ddmap(1, mp_sub(5, b'\x01\x02\x03\x04'))))         # unknown multipath type at the end of the message: reads past it
    e(tlv(0x14, ddmap(1, mp_sub(2, a4('198.51.100.1')) + ls_sub(lbl3(1000, 0, 1, 0)))))   # multipath is never skipped (F3)
    e(tlv(0x14, ddmap(1, ls_sub(lbl3(1000, 0, 1, 0)))))            # label 1000 does not fit the FT_UINT8 field
    e(tlv(1, NIL2 + LDP4))                                         # Nil FEC advances twice (F2)
    sec(c, 'Errored TLV depth (F1): 300 Errored TLVs trip the dissection depth assertion')
    e(b''.join(tlv(9, tlv(3)) for _ in range(300)))
    return c

if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('-') else '.'
    c = build_main()
    c.write(os.path.join(out, 'mpls-echo-coverage.pcapng'))
    nmain = len(c.frames)
    main_secs = list(SECS); del SECS[:]
    m = build_malformed()
    m.write(os.path.join(out, 'mpls-echo-coverage-malformed.pcapng'))
    if '-v' in sys.argv:
        for s, n in main_secs: print('main frame %d: %s' % (s, n))
        print('main frames:', nmain)
        for s, n in SECS: print('malformed frame %d: %s' % (s, n))
        print('malformed frames:', len(m.frames))
