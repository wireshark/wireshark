#!/usr/bin/env python3
# Generates test/captures/bfd_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the BFD dissector
(packet-bfd.c): BFD Control and BFD Echo.

All packets are built from scratch with struct; no captured traffic is
used. Two routers, 192.0.2.1 and 192.0.2.2 (2001:db8::1 and 2001:db8::2
for IPv6), run BFD over UDP (control 3784, multihop 4784, LAG 6784,
S-BFD 7784, echo 3785), and over MPLS: the Generic Associated Channel
(GAL, label 13) carrying BFD CC, BFD CV with an MPLS-TP Source MEP-ID TLV
and MPLS-TP Lock Instruct, and a pseudowire control word (VCCV) carrying
BFD.

Usage: mkbfd.py <output directory>

Writes:
  bfd-coverage.pcap            the main capture
  bfd-coverage-malformed.pcap  truncated packets (exceptions)
"""

import struct
import sys

A4 = bytes([192, 0, 2, 1])
B4 = bytes([192, 0, 2, 2])
A6 = bytes.fromhex('20010db8000000000000000000000001')
B6 = bytes.fromhex('20010db8000000000000000000000002')
MAC_A = bytes.fromhex('020000000001')
MAC_B = bytes.fromhex('020000000002')
EPOCH = 1700000000

# Flag bits of version 1 (low 6 bits of octet 1) and version 0
P, F, C, AUTH, D, M = 0x20, 0x10, 0x08, 0x04, 0x02, 0x01
H0, D0, P0, F0 = 0x80, 0x40, 0x20, 0x10


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def ipv4(src, dst, proto, payload, ident=1):
    h = struct.pack('>BBHHHBBH4s4s', 0x45, 0xc0, 20 + len(payload), ident, 0, 255, proto, 0,
                    src, dst)
    return h[:10] + struct.pack('>H', csum(h)) + h[12:] + payload


def udp4(src, dst, sport, dport, payload):
    u = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    c = csum(struct.pack('>4s4sBBH', src, dst, 0, 17, len(u)) + u) or 0xffff
    return u[:6] + struct.pack('>H', c) + u[8:]


def ipv6_udp(src, dst, sport, dport, payload):
    u = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    c = csum(struct.pack('>16s16sIxxxB', src, dst, len(u), 17) + u) or 0xffff
    u = u[:6] + struct.pack('>H', c) + u[8:]
    return struct.pack('>IHBB16s16s', 0x60000000, len(u), 17, 255, src, dst) + u


def bfd(version=1, diag=0, state=3, flags=0, mult=3, length=None, my=0x11111111,
        your=0x22222222, tx=1000000, rx=1000000, echo=50000, auth=b''):
    """A BFD control packet. For version 0 'flags' is the whole second octet
    (H, D, P, F and reserved bits); for other versions it is the low 6 bits
    and 'state' fills the top two."""
    if version == 0:
        b1 = flags
    else:
        b1 = state << 6 | flags
    if length is None:
        length = 24 + len(auth)
    return struct.pack('>BBBBIIIII', version << 5 | diag, b1, mult, length, my, your,
                       tx, rx, echo) + auth


def simple_auth(password, key=1, auth_len=None):
    if auth_len is None:
        auth_len = 3 + len(password)
    return struct.pack('>BBB', 1, auth_len, key) + password


def keyed_auth(atype, seq, key=2, auth_len=None):
    dlen = 16 if atype in (2, 3) else 20
    if auth_len is None:
        auth_len = 8 + dlen
    digest = bytes((0xa0 + i) & 0xff for i in range(dlen))
    return struct.pack('>BBBBI', atype, auth_len, key, 0, seq) + digest


def mpls_label(label, bos, ttl=255, exp=0):
    return struct.pack('>I', label << 12 | exp << 9 | (1 if bos else 0) << 8 | ttl)


def ach(channel):
    return struct.pack('>BBH', 0x10, 0, channel)


def mep_section(global_id, node, ifno):
    return struct.pack('>HHI4sI', 0, 12, global_id, node, ifno)


def mep_lsp(global_id, node, tunnel, lsp):
    return struct.pack('>HHI4sHH', 1, 12, global_id, node, tunnel, lsp)


def mep_pw(global_id, node, ac_id, agi_type, agi):
    body = struct.pack('>I4sIBB', global_id, node, ac_id, agi_type, len(agi)) + agi
    return struct.pack('>HH', 2, len(body)) + body


class Pcap:
    def __init__(self):
        self.frames = []

    def eth(self, etype, payload, rev=False):
        src, dst = (MAC_B, MAC_A) if rev else (MAC_A, MAC_B)
        self.frames.append(dst + src + struct.pack('>H', etype) + payload)

    def udp(self, payload, dport=3784, sport=49152, rev=False):
        src, dst = (B4, A4) if rev else (A4, B4)
        self.eth(0x0800, ipv4(src, dst, 17, udp4(src, dst, sport, dport, payload),
                              len(self.frames) + 1), rev)

    def udp6(self, payload, dport=3784, sport=49152, rev=False):
        src, dst = (B6, A6) if rev else (A6, B6)
        self.eth(0x86dd, ipv6_udp(src, dst, sport, dport, payload), rev)

    def gal(self, channel, payload, rev=False):
        """LSP label, then GAL (13, bottom of stack), G-ACh header."""
        self.eth(0x8847, mpls_label(1000, False) + mpls_label(13, True) + ach(channel) + payload,
                 rev)

    def vccv(self, channel, payload, rev=False):
        """Pseudowire label (bottom of stack), then the PW ACH (first
        nibble 1, the control word of VCCV type 1)."""
        self.eth(0x8847, mpls_label(2000, True) + ach(channel) + payload, rev)

    def write(self, path):
        out = [struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)]
        for i, f in enumerate(self.frames):
            out.append(struct.pack('<IIII', EPOCH + i, 0, len(f), len(f)) + f)
        with open(path, 'wb') as fh:
            fh.write(b''.join(out))


def main_capture():
    c = Pcap()
    # 1-4: version 1 session bring-up, every state: AdminDown, Down, Init, Up
    c.udp(bfd(state=0, diag=7, your=0, tx=2000000, rx=2000000))
    c.udp(bfd(state=1, your=0), rev=True, sport=49153)
    c.udp(bfd(state=2))
    c.udp(bfd(state=3, my=0x22222222, your=0x11111111), rev=True, sport=49153)
    # 5-14: every version 1 diagnostic code (0-9), session Down
    for diag in range(10):
        c.udp(bfd(state=1, diag=diag))
    # 15-16: unknown diagnostic codes (10, 31)
    c.udp(bfd(diag=10))
    c.udp(bfd(diag=31))
    # 17-22: each version 1 flag on its own: P, F, C, D, M, and all but A
    for flags in (P, F, C, D, M, P | F | C | D | M):
        c.udp(bfd(flags=flags))
    # 23-30: version 0 (draft-katz-ward-bfd-01): diagnostics 0-7
    for diag in range(8):
        c.udp(bfd(version=0, diag=diag, flags=H0))
    # 31-36: version 0 flags H, D, P, F, all four, and the reserved bits
    #        (0x04 is the A bit in version 1 but no authentication in 0)
    for flags in (H0, D0, P0, F0, H0 | D0 | P0 | F0, 0x0f):
        c.udp(bfd(version=0, flags=flags))
    # 37: version 0 with an unknown diagnostic (8)
    c.udp(bfd(version=0, diag=8))
    # 38-39: versions 2 and 7 (dissected like version 1)
    c.udp(bfd(version=2, flags=P))
    c.udp(bfd(version=7, state=1, diag=3))
    # 40-43: Simple Password, 1, 8 and 16 octet passwords, key IDs 0, 1, 255
    c.udp(bfd(flags=AUTH, auth=simple_auth(b'x', key=0)))
    c.udp(bfd(flags=AUTH, auth=simple_auth(b'secret12')))
    c.udp(bfd(flags=AUTH | P, auth=simple_auth(b'0123456789abcdef', key=255)))
    c.udp(bfd(flags=AUTH | F, auth=simple_auth(b'0123456789abcdef', key=255)), rev=True,
          sport=49153)
    # 44-47: Keyed MD5, Meticulous Keyed MD5, Keyed SHA1, Meticulous Keyed SHA1
    for atype, seq in ((2, 0x100), (3, 0x101), (4, 0x200), (5, 0x201)):
        c.udp(bfd(flags=AUTH, auth=keyed_auth(atype, seq)))
    # 48: unknown authentication type (6), 8 octets
    c.udp(bfd(flags=AUTH, auth=struct.pack('>BBBB', 6, 8, 1, 0) + b'\x01\x02\x03\x04'))
    # 49-52: wrong authentication lengths for each keyed type (warning
    #        bfd.auth.len.invalid, "Invalid Authentication Section")
    c.udp(bfd(flags=AUTH, auth=keyed_auth(2, 1, auth_len=20)))
    c.udp(bfd(flags=AUTH, auth=keyed_auth(3, 1, auth_len=16)))
    c.udp(bfd(flags=AUTH, auth=keyed_auth(4, 1, auth_len=24)))
    c.udp(bfd(flags=AUTH, auth=keyed_auth(5, 1, auth_len=27)))
    # 53-55: the reproducer bfd_auth_short.py: A flag with
    #        Length 4 (no data), Simple Password with Auth Len 2 and 1
    #        (invalid length, used to run to the end of the frame or throw)
    c.udp(bfd(flags=AUTH, state=3, length=4, my=1, your=2, echo=0))
    c.udp(bfd(flags=AUTH, length=28, my=1, your=2, echo=0, auth=bytes([1, 2, 7, 0x41]) + b'XYZW'))
    c.udp(bfd(flags=AUTH, length=28, my=1, your=2, echo=0, auth=bytes([1, 1, 7, 0x41])))
    # 56: A flag with Length 26 (no data, shows the 2 octets after the header)
    c.udp(bfd(flags=AUTH, length=26, auth=b'\x01\x02'))
    # 57-59: multihop (4784), LAG (6784) and S-BFD (7784) ports
    c.udp(bfd(flags=C, mult=5), dport=4784)
    c.udp(bfd(flags=AUTH, auth=keyed_auth(4, 7)), dport=6784)
    c.udp(bfd(state=3, my=0x7777, your=0x8888), dport=7784)
    # 60-61: BFD Control over IPv6, single hop and multihop
    c.udp6(bfd(flags=AUTH, auth=keyed_auth(5, 9)))
    c.udp6(bfd(state=2), dport=4784)
    # 62-64: BFD Echo over IPv4 (looped back, both directions) and IPv6
    c.udp(b'\x00\x00\x00\x01echo-session-1-seq-1', dport=3785, sport=3785)
    c.udp(b'\x00\x00\x00\x01echo-session-1-seq-1', dport=3785, sport=3785, rev=True)
    c.udp6(struct.pack('>IQ', 2, 0x0123456789abcdef), dport=3785, sport=3785)
    # 65-66: MPLS-TP BFD CC (G-ACh channel 0x0022), Up and with Simple
    #        Password
    c.gal(0x0022, bfd(state=3, flags=C, tx=3333, rx=3333, echo=0))
    c.gal(0x0022, bfd(state=3, flags=AUTH, auth=simple_auth(b'tp-cc')), rev=True)
    # 67-70: MPLS-TP BFD CV (0x0023) with each Source MEP-ID TLV: Section,
    #        LSP, PW, and an unknown type (3)
    c.gal(0x0023, bfd(state=3, echo=0) + mep_section(65000, A4, 7))
    c.gal(0x0023, bfd(state=3, echo=0) + mep_lsp(65000, B4, 10, 1), rev=True)
    c.gal(0x0023, bfd(state=3, echo=0) + mep_pw(65000, A4, 42, 1, b'agi-value'))
    c.gal(0x0023, bfd(state=1, echo=0) + struct.pack('>HHI', 3, 4, 0xdeadbeef))
    # 71: BFD CV with authentication: the MEP TLV follows the Length octets
    c.gal(0x0023, bfd(state=3, flags=AUTH, echo=0, auth=keyed_auth(3, 5))
          + mep_lsp(65001, A4, 11, 2))
    # 72-73: VCCV (PW ACH type 0x0007, BFD without IP/UDP), Down and Up
    c.vccv(0x0007, bfd(state=1, your=0, echo=0))
    c.vccv(0x0007, bfd(state=3, flags=P, echo=0), rev=True)
    # 74-76: MPLS-TP Lock Instruct (0x0026) with a Source MEP-ID TLV of
    #        each type (dissect_bfd_mep called from packet-mplstp-oam.c)
    c.gal(0x0026, b'\x00\x00\x00\x05' + mep_section(1, A4, 3))
    c.gal(0x0026, b'\x00\x00\x00\x05' + mep_lsp(1, A4, 4, 5))
    c.gal(0x0026, b'\x00\x00\x00\x05' + mep_pw(1, A4, 6, 1, b'pw'))
    # 77: Lock Instruct with an unknown MEP-ID type
    c.gal(0x0026, b'\x00\x00\x00\x05' + struct.pack('>HHI', 9, 4, 0))
    return c


def malformed_capture():
    c = Pcap()
    # 1: 23 octets: shorter than the mandatory section
    c.udp(bfd()[:23])
    # 2: A flag, Length 28, but nothing after the mandatory section
    c.udp(bfd(flags=AUTH, length=28))
    # 3: A flag, Length 28, only the authentication type
    c.udp(bfd(flags=AUTH, length=28, auth=b'\x02'))
    # 4: Keyed MD5 cut in the digest
    c.udp(bfd(flags=AUTH, auth=keyed_auth(2, 1))[:40])
    # 5: Simple Password with an Auth Len past the end of the frame
    c.udp(bfd(flags=AUTH, auth=simple_auth(b'abcd', auth_len=40)))
    # 6: Keyed SHA1 cut in the sequence number
    c.udp(bfd(flags=AUTH, length=52, auth=keyed_auth(4, 1)[:6]))
    # 7: BFD CV without a MEP TLV
    c.gal(0x0023, bfd(state=3, echo=0))
    # 8: BFD CV with a PW MEP TLV whose AGI length runs past the frame
    c.gal(0x0023, bfd(state=3, echo=0) + mep_pw(1, A4, 2, 1, b'ab')[:-2] + b'\xff')
    # 9: BFD CV whose Length octet points past the frame
    c.gal(0x0023, bfd(state=3, echo=0, length=200))
    # 10: BFD CV with a Section MEP TLV cut short
    c.gal(0x0023, bfd(state=3, echo=0) + mep_section(1, A4, 1)[:10])
    # 11: Lock Instruct with an LSP MEP TLV cut short
    c.gal(0x0026, b'\x00\x00\x00\x05' + mep_lsp(1, A4, 4, 5)[:12])
    # 12: VCCV BFD cut short
    c.vccv(0x0007, bfd()[:10])
    # 13: Meticulous Keyed MD5 with Auth Len 28 (the section runs 4 octets
    #     past the end of the frame)
    c.udp(bfd(flags=AUTH, auth=keyed_auth(3, 1, auth_len=28)))
    return c


if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    main_capture().write(out + '/bfd-coverage.pcap')
    malformed_capture().write(out + '/bfd-coverage-malformed.pcap')
