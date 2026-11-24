#!/usr/bin/env python3
# Generates test/captures/fr_coverage.pcapng.gz, fr_coverage_visual.vwr.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the Frame Relay dissector
(packet-fr.c).

A Frame Relay frame has a 2 to 4 octet address (DLCI, C/R, FECN, BECN,
DE, EA, DL-CORE), then an RFC 2427 style control octet and NLPID, or a
Cisco HDLC type, raw Ethernet or LAPF. Every packet is built with struct;
no captured traffic is used.

The dissector is reached the way a real capture reaches it:
  link-layer type 107 (Frame Relay)             -> "fr"
  link-layer type 180 (Juniper Frame Relay)     -> juniper -> "fr"
  Linux cooked capture, hardware type 770 (FRAD) -> "fr"
  GRE protocol type 0x6559                      -> "fr"
  sFlow raw header, header protocol 5           -> "fr"
  Exported PDU "fr_uncompressed" / "fr_stripped_address"
  Visual Networks file, media type 32 (pseudo header: DTE/DCE direction)

Usage: mkfr.py <output directory>

Writes:
  fr-coverage.pcapng            all of the above except the Visual file
  fr-coverage-visual.vwr        Frame Relay with the DTE/DCE pseudo header
  fr-coverage-malformed.pcapng  truncated and bogus frames
"""
import os
import socket
import struct
import sys


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ip4(proto, payload, src='192.0.2.1', dst='192.0.2.2', ident=1):
    h = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0, 64, proto, 0,
                    socket.inet_aton(src), socket.inet_aton(dst))
    h = h[:10] + struct.pack('>H', csum(h)) + h[12:]
    return h + payload


def udp(sp, dp, payload):
    return struct.pack('>HHHH', sp, dp, 8 + len(payload), 0) + payload


def ip6():
    # IPv6 header, no next header
    return struct.pack('>IHBB', 0x60000000, 0, 59, 64) + bytes([0x20, 1, 0xd, 0xb8] + [0] * 11 + [1]) \
        + bytes([0x20, 1, 0xd, 0xb8] + [0] * 11 + [2])


def blk(t, body):
    pad = (-len(body)) % 4
    n = 12 + len(body) + pad
    return struct.pack('<II', t, n) + body + b'\0' * pad + struct.pack('<I', n)


def pcapng(path, idbs, frames):
    out = blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    for lt in idbs:
        out += blk(1, struct.pack('<HHI', lt, 0, 65535))
    for i, (ifc, fr) in enumerate(frames):
        ts = (1700000000 + i) * 1000000
        out += blk(6, struct.pack('<IIIII', ifc, ts >> 32, ts & 0xffffffff, len(fr), len(fr)) + fr)
    open(path, 'wb').write(out)


def addr(dlci, cr=0, fecn=0, becn=0, de=0, octets=2, dlcore=0):
    """Address field of 2, 3 or 4 octets (DLCI of 10, 17 or 23 bits).
    dlcore: 6 bit DL-CORE control instead of the lower DLCI bits
    (3 and 4 octet addresses only)."""
    if octets == 2:
        return bytes([((dlci >> 4) << 2) | (cr << 1),
                      ((dlci & 0xf) << 4) | (fecn << 3) | (becn << 2) | (de << 1) | 1])
    flags = (fecn << 3) | (becn << 2) | (de << 1)
    if octets == 3:     # 6 + 4 + 6 bits
        b = [((dlci >> 10) & 0x3f) << 2 | (cr << 1), (((dlci >> 6) & 0xf) << 4) | flags]
    else:               # 6 + 4 + 7 + 6 bits
        b = [((dlci >> 17) & 0x3f) << 2 | (cr << 1), (((dlci >> 13) & 0xf) << 4) | flags,
             ((dlci >> 6) & 0x7f) << 1]
    if dlcore:
        b.append((dlcore << 2) | 0x02 | 1)
    else:
        b.append(((dlci & 0x3f) << 2) | 1)
    return bytes(b)


UI = b'\x03'
FCS = bytes([0xde, 0xad, 0xbe, 0xef])
IP = ip4(17, udp(1000, 2000, b'fr test'))
IP6 = ip6()
LMI = bytes([0x00, 0x7d, 0x01, 0x01, 0x00, 0x03, 0x02, 0x05, 0x04, 0x07, 0x03, 0x00, 0x82, 0x03,
             0x07, 0x03, 0x01, 0x83, 0x02])
Q933 = bytes([0x00, 0x75, 0x51, 0x01, 0x01, 0x53, 0x02, 0x01, 0x00])


def fr_frames():
    f = []
    # 1 IPv4 NLPID 0xCC, DLCI 16
    f.append(addr(16) + UI + b'\xcc' + IP)
    # 2 C/R, FECN, BECN, DE set, DLCI 1023, IPv6 NLPID 0x8E
    f.append(addr(1023, 1, 1, 1, 1) + UI + b'\x8e' + IP6)
    # 3 SNAP: NLPID 0x80, OUI 0, ethertype IPv4
    f.append(addr(17) + UI + b'\x80\x00\x00\x00\x08\x00' + IP)
    # 4 padding octet before the NLPID
    f.append(addr(18) + UI + b'\x00\xcc' + IP)
    # 5 three octet address
    f.append(addr(0x1234, octets=3) + UI + b'\xcc' + IP)
    # 6 three octet address with DL-CORE control
    f.append(addr(0x1234, octets=3, dlcore=0x0a) + UI + b'\xcc' + IP)
    # 7 four octet address
    f.append(addr(0x1abcd, octets=4) + UI + b'\xcc' + IP)
    # 8 DLCI 0, Q.933 (NLPID 8, Frame Relay table)
    f.append(addr(0, 1) + UI + b'\x08' + Q933)
    # 9 DLCI 0, LMI (NLPID 9)
    f.append(addr(0) + UI + b'\x09' + LMI)
    # 10 PPP (NLPID 0xCF)
    f.append(addr(19) + UI + b'\xcf\x00\x21' + IP)
    # 11 unknown NLPID -> data
    f.append(addr(20) + UI + b'\x5a' + b'unknown nlpid payload')
    # 12 DLCI 0 with an information frame: LAPF (not implemented)
    f.append(addr(0) + b'\x00\x00' + b'\x08\x00\x75')
    # 13 XID on a DLCI other than 0
    f.append(addr(21) + b'\xaf' + b'\x82\x80\x00')
    # 14 Cisco HDLC: Ethertype 0x0800
    f.append(addr(22) + b'\x08\x00' + IP)
    # 15 raw Ethernet frame (IPv4)
    f.append(addr(23) + bytes([6, 0x11, 0x22, 0x33, 0x44, 0x55, 2, 0, 0, 0, 0, 1]) + b'\x08\x00' + IP + FCS)
    # 16 raw Ethernet frame with a length instead of a type (LLC SNAP)
    snap = b'\xaa\xaa\x03\x00\x00\x00\x08\x00' + IP
    f.append(addr(23) + bytes([6, 0x11, 0x22, 0x33, 0x44, 0x55, 2, 0, 0, 0, 0, 1])
             + struct.pack('>H', len(snap)) + snap + FCS)
    # 17 something that is neither: data
    f.append(addr(24) + bytes([6, 0x11]) + b'xyz')
    # 18 supervisory control field (extended mode), then NLPID IPv4
    f.append(addr(25) + b'\x01\x00' + b'\xcc' + IP)
    # 19 information control field (extended mode), then NLPID IPv4
    f.append(addr(26) + b'\x02\x00' + b'\xcc' + IP)
    # 20 bogus one octet address (EA set in the first octet)
    f.append(b'\x01' + UI + b'\xcc' + IP)
    # 21 bogus extra address octet in a five octet address
    f.append(bytes([0x04, 0x10, 0x2a, 0x14, 0x15]) + UI + b'\xcc' + IP)
    # 22 ISO 9542 ES-IS end system hello (NLPID 0x82, OSI table)
    f.append(addr(27) + UI + bytes([0x82, 0x0a, 0x01, 0x00, 0x02, 0x00, 0x3c, 0x00, 0x00, 0x00]))
    # 23 padding octet, then a UI control field, before the NLPID (not DLCI 0)
    f.append(addr(28) + b'\x00\x03\xcc' + IP)
    # 24-26 unnumbered control field with the poll bit set (0x13), then an
    # NLPID in the Frame Relay OSI table (Q.933), the OSI table (ES-IS) or
    # SNAP, which switches on the RFC 2427 decoding
    f.append(addr(29) + b'\x13\x08' + Q933)
    f.append(addr(30) + b'\x13' + bytes([0x82, 0x0a, 0x01, 0x00, 0x02, 0x00, 0x3c, 0x00, 0x00, 0x00]))
    f.append(addr(31) + b'\x13\x80\x00\x00\x00\x08\x00' + IP)
    return f


def main(out):
    fr = fr_frames()
    frames = [(0, x) for x in fr]
    # Ethernet + IPv4 + GRE (protocol 0x6559) + Frame Relay
    eth = bytes([2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1]) + b'\x08\x00'
    gre = struct.pack('>HH', 0, 0x6559) + fr[0]
    frames.append((1, eth + ip4(47, gre)))
    gre = struct.pack('>HH', 0, 0x6559) + fr[2]
    frames.append((1, eth + ip4(47, gre)))
    # Linux cooked capture, hardware type 770 (FRAD)
    sll = struct.pack('>HHH8sH', 0, 770, 0, b'\0' * 8, 0)
    frames.append((2, sll + fr[0]))
    # Juniper Frame Relay: "MGC", flags 0 (L2 header present)
    frames.append((3, b'MGC\x00' + fr[0]))
    frames.append((3, b'MGC\x01' + fr[1]))
    # Juniper with extensions (flags 0x80) and the L2 header stripped (0x02)
    frames.append((3, b'MGC\x80' + struct.pack('>H', 0) + fr[2]))
    # sFlow v5 flow sample with a raw packet header of protocol 5 (Frame Relay)
    hdr = fr[0]
    hdr += b'\0' * ((-len(hdr)) % 4)
    rec = struct.pack('>IIII', 5, len(fr[0]) + 4, 0, len(fr[0])) + hdr
    rec = struct.pack('>II', 1, len(rec)) + rec
    smp = struct.pack('>IIIIIIII', 1, 0x1000001, 400, 100, 0, 1, 2, 1) + rec
    smp = struct.pack('>II', 1, len(smp)) + smp
    dg = struct.pack('>II', 5, 1) + socket.inet_aton('192.0.2.1') + struct.pack('>IIII', 0, 1, 1000, 1) + smp
    frames.append((1, eth + ip4(17, udp(40000, 6343, dg))))
    # MPLS pseudowire (RFC 4619): reached with Decode As mpls.label -> pw_fr.
    # Control word: FECN, BECN, DE, C/R bits, length (payload < 64 octets), sequence
    mpls = struct.pack('>I', (100 << 12) | (1 << 8) | 64)
    pl = UI + b'\xcc' + IP
    cw = struct.pack('>BBH', 0x0a, len(pl), 7)
    frames.append((1, eth[:12] + b'\x88\x47' + mpls + cw + pl))
    pl = UI + b'\xcc' + ip4(17, udp(1000, 2000, b'x' * 40))
    cw = struct.pack('>BBH', 0x05, 0, 8)
    frames.append((1, eth[:12] + b'\x88\x47' + mpls + cw + pl))
    # Exported PDU
    def exp(name, payload):
        n = name.encode()
        n += b'\0' * ((-len(n)) % 4)
        return struct.pack('>HH', 12, len(n)) + n + struct.pack('>HH', 0, 0) + payload
    frames.append((4, exp('fr_uncompressed', b'\xcc' + IP)))
    frames.append((4, exp('fr_uncompressed', b'\x00\x80\x00\x00\x00\x08\x00' + IP)))
    frames.append((4, exp('fr_stripped_address', UI + b'\xcc' + IP)))
    frames.append((4, exp('fr_stripped_address', b'\x08\x00' + IP)))
    frames.append((4, exp('fr', fr[0])))
    pcapng(os.path.join(out, 'fr-coverage.pcapng'), [107, 1, 113, 180, 252], frames)

    # Visual Networks file, media type 32 (Frame Relay) with the DTE/DCE
    # pseudo header; each frame ends with a 2 octet FCS that is not stored
    # but counted in the original length.
    vf = []
    for i, x in enumerate([fr[0], fr[1], fr[2], fr[7]]):
        vf.append((x, 0x40 if i % 2 else 0))
    hdr = b'\x05VNF' + struct.pack('<IIHHHHIH', len(vf), 1700000000, 32, 1518, 0, 1, 1544000, 0)
    hdr += b'\0' * 102 + b'synthetic frame relay'.ljust(64, b'\0')
    assert len(hdr) == 192
    body = b''
    for i, (x, st) in enumerate(vf):
        body += struct.pack('<IHHIBB6s', i * 10, len(x) + 2, len(x), st, 0, 0, b'\0' * 6) + x
    open(os.path.join(out, 'fr-coverage-visual.vwr'), 'wb').write(hdr + body)

    # malformed
    bad = []
    bad.append((0, b'\x04'))                                 # address cut after one octet
    bad.append((0, b'\x04\x10'))                             # address with EA clear, third octet missing
    bad.append((0, b'\x04\x01'))                             # no control octet
    bad.append((0, addr(16) + UI))                           # no NLPID
    bad.append((0, addr(16) + UI + b'\xcc' + IP[:10]))       # truncated IP
    bad.append((0, addr(16) + UI + b'\x80\x00\x00'))         # truncated SNAP
    bad.append((0, addr(16) + UI + b'\x00'))                 # padding at the end
    bad.append((0, bytes([0x04, 0x10, 0x2a, 0x14])))         # extra octets run off the end
    bad.append((0, addr(16) + UI + b'\x08' + b'\x00'))       # Q.933 cut
    bad.append((0, addr(0) + UI + b'\x09'))                  # LMI cut
    bad.append((0, addr(16) + b'\x01'))                      # supervisory control cut
    bad.append((0, addr(0)))                                 # DLCI 0, nothing after
    pcapng(os.path.join(out, 'fr-coverage-malformed.pcapng'), [107], bad)


if __name__ == '__main__':
    main(sys.argv[1])
