#!/usr/bin/env python3
# Generates test/captures/smc_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures for the SMC dissector (packet-smc.c,
Shared Memory Communications: SMC-R and SMC-D CLC handshake messages over
TCP and SMC-R LLC messages over RoCE).

Usage: mksmc.py <output directory>

CLC messages start with the EBCDIC identifiers 'SMCR' (0xe2d4c3d9) or
'SMCD' (0xe2d4c3c4) and are found by the TCP heuristic "smc_tcp" (enabled
by default, any port). LLC messages are carried as the payload of RoCEv2
SEND packets (UDP port 4791); the "smcr_infiniband" heuristic of the
InfiniBand payload accepts them by command and length. Every packet is
built with struct; nothing is captured.

Writes:
  smc-coverage.pcapng            CLC proposal, accept, confirm and decline
                                 of SMC-R and SMC-D, versions 1 and 2, over
                                 IPv4 and IPv6; every LLC message of
                                 SMC-R versions 1 and 2 over RoCEv2
  smc-coverage-malformed.pcapng  messages that are too short, wrong
                                 identifiers or lengths
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import struct
from pcaplib import MAC_A, MAC_B, pcapng, tcp6, TcpConn, udp

SMCR = bytes.fromhex('e2d4c3d9')
SMCD = bytes.fromhex('e2d4c3c4')
PROPOSAL, ACCEPT, CONFIRM, DECLINE = 1, 2, 3, 4
R, D, NONE, BOTH = 0, 1, 2, 3


def pat(n, start=1):
    return bytes((start + i) & 0xff for i in range(n))


def clc(msgtype, flags, body, ident=SMCR, length=None, trailer=None):
    """CLC header (id, type, length, flags), body and trailer id."""
    total = 8 + len(body) + 4
    return ident + struct.pack('>BHB', msgtype, total if length is None else length, flags) + \
        body + (ident if trailer is None else trailer)


def flags(version, typ=0, fc=0):
    return (version << 4) | (fc << 3) | typ


def proposal(version, v1type, v2type=0, subnet_prefixes=None, eids=0, gids=0, ident=SMCR,
             rel=1, seid=1):
    """Proposal body. subnet_prefixes: number of IPv6 prefixes (None: no subnet block)."""
    v2 = version >= 2
    typ = (v2type << 2) | v1type if v2 else v1type
    sub = subnet_prefixes is not None
    ext = 28 + ((8 + 17 * subnet_prefixes) if sub else 0)
    b = pat(8, 0x10)                                    # peer id
    b += pat(16, 0x20) + MAC_A                          # preferred gid and mac
    b += struct.pack('>H', 0x0018 if sub else 0)        # subnet extension offset
    b += pat(8, 0x30)                                   # ISM GID
    b += struct.pack('>HH', 0x0102, ext if v2 else 0)   # CHID, v2 extension offset
    b += bytes(28)
    if sub:
        b += bytes([192, 0, 2, 0]) + bytes([24, 0, 0, subnet_prefixes])
        for i in range(subnet_prefixes):
            b += bytes([0x20, 1, 0xd, 0xb8, i] + [0] * 11) + bytes([64])
    if v2:
        b += bytes([eids, gids, 0, (rel << 4) | seid]) + b'\0\0' + struct.pack('>H', 32 + 32 * eids)
        b += pat(16, 0x40) + bytes(16)                  # RoCEv2 gid (or 12 reserved + IPv4), reserved
        for i in range(eids):
            b += ('EID-%d' % i).encode().ljust(32, b'_')
        b += b'SYSTEM-EID'.ljust(32, b'_') + bytes(16)
        for i in range(gids):
            b += pat(8, 0x50 + i) + struct.pack('>H', 0x0100 + i)
    return clc(PROPOSAL, flags(version, typ), b, ident)


def accept_r(version, fc=0, qp_flags=0x32, mtu_flags=None, lg=1, os_=2, rel=1):
    b = pat(8, 0x10) + pat(16, 0x20) + MAC_B + b'\x00\x01\x02' + pat(4, 0x60) + b'\x05' + pat(4, 0x70)
    b += bytes([qp_flags if mtu_flags is None else mtu_flags]) + b'\0' + pat(8, 0x80) + b'\0' + b'\x00\x10\x20'
    if version >= 2:
        b += b'EID-ACCEPT'.ljust(32, b'_') + bytes(8)
        if fc:
            b += bytes([lg << 4, (os_ << 4) | rel]) + bytes(2) + b'peer-name'.ljust(32, b' ') + bytes(16)
    return clc(ACCEPT, flags(version, R, fc), b)


def confirm_r(version, fc=0, qp_flags=0x32, gids=0):
    b = pat(8, 0x10) + pat(16, 0x20) + MAC_A + b'\x00\x01\x03' + pat(4, 0x60) + b'\x05' + pat(4, 0x70)
    b += bytes([qp_flags]) + b'\0' + pat(8, 0x80) + b'\0' + b'\x00\x10\x21'
    if version >= 2:
        b += b'EID-CONFIRM'.ljust(32, b'_') + bytes(8)
        if fc:
            b += bytes([1 << 4, (3 << 4) | 1]) + bytes(2) + b'peer-name'.ljust(32, b' ') + bytes(16)
            b += bytes([gids]) + bytes(3) + b''.join(pat(16, 0x90 + i) for i in range(gids))
    return clc(CONFIRM, flags(version, R, fc), b)


def accept_d(version, fc=0, size=0x30, os_=1, rel=2):
    b = pat(8, 0x10) + pat(8, 0x20) + b'\x05' + bytes([size]) + bytes(2) + pat(4, 0x30)
    if version >= 2:
        b += struct.pack('>H', 0x0102) + b'EID-D'.ljust(32, b'_') + bytes(8)
        if fc:
            b += b'\0' + bytes([(os_ << 4) | rel]) + bytes(2) + b'peer-name'.ljust(32, b' ') + bytes(16)
    return clc(ACCEPT, flags(version, D, fc), b, SMCD)


def confirm_d(version, fc=0, size=0x20, os_=3, rel=3):
    b = pat(8, 0x10) + pat(8, 0x20) + b'\x05' + bytes([size]) + bytes(2) + pat(4, 0x30)
    if version >= 2:
        b += struct.pack('>H', 0x0102) + b'EID-D'.ljust(32, b'_') + bytes(8)
        if fc:
            b += b'\0' + bytes([(os_ << 4) | rel]) + bytes(2) + b'peer-name'.ljust(32, b' ')
    return clc(CONFIRM, flags(version, D, fc), b, SMCD)


def decline(version, sync=0, diag=False, os_=2, ident=SMCR):
    b = pat(8, 0x10) + struct.pack('>I', 0x03010000)
    if version >= 2:
        b += bytes([os_ << 4]) + bytes(3)
        if diag:
            b += struct.pack('>IIII', 1, 2, 3, 4)
    return clc(DECLINE, flags(version, 0, 0) | (0x04 if sync else 0), b, ident)


def llc(cmd, body, resp=False, v2=False, size=44):
    """LLC message: command, length (1 octet for v1 plus one reserved octet,
    2 octets for v2), then the body, which starts with the flags octet
    (offset 3 in both versions; bit 0x80 marks a response)."""
    n = size
    hdr = (bytes([cmd]) + struct.pack('>H', n)) if v2 else bytes([cmd, n, 0])
    m = hdr + body
    return m.ljust(n, b'\0')[:n]


def roce(payload, qp=0x11, psn=0, sport=49152):
    """RoCEv2: UDP 4791, BTH SEND ONLY (RC, opcode 4) plus payload and ICRC."""
    bth = struct.pack('!BBHII', 0x04, 0x00, 0xffff, qp, psn & 0xffffff)
    return udp(bth + payload + b'\0\0\0\0', sport, 4791, ident=psn + 1)


def main(out):
    fr = []
    c = TcpConn(40000, 5000)
    c.handshake()

    def snd(m, client=True):
        c.send(m, client)

    # --- proposals ---------------------------------------------------------
    snd(proposal(1, R, subnet_prefixes=None))                         # SMC-R v1
    snd(proposal(1, R, subnet_prefixes=0))
    snd(proposal(1, R, subnet_prefixes=2))                            # with IPv6 prefixes
    snd(proposal(1, D, subnet_prefixes=0, ident=SMCD), True)          # SMC-D v1
    snd(proposal(1, BOTH, subnet_prefixes=1))                         # both
    snd(proposal(1, NONE))
    snd(proposal(2, R, R, eids=2, gids=0))                            # SMC-Rv2 (IPv4)
    snd(proposal(2, R, D, eids=1, gids=2))                            # v1 R, v2 D
    snd(proposal(2, D, D, eids=0, gids=1, ident=SMCD))
    snd(proposal(2, NONE, BOTH, eids=3, gids=3, subnet_prefixes=1))
    snd(proposal(2, BOTH, BOTH, eids=1, gids=1, rel=3, seid=0))
    snd(proposal(2, R, NONE))
    snd(proposal(2, D, R, eids=1))
    # --- accepts and confirms ---------------------------------------------
    snd(accept_r(1), False)
    snd(accept_r(1, qp_flags=0x76), False)                            # MTU 6: invalid, size 7: invalid
    snd(accept_r(1, qp_flags=0x00), False)                            # MTU 0: invalid
    snd(accept_r(1, qp_flags=0x51), False)                            # MTU 1, size 5
    snd(accept_r(2), False)
    snd(accept_r(2, fc=1), False)
    snd(accept_r(3, fc=1, lg=0, os_=1), False)
    snd(confirm_r(1))
    snd(confirm_r(1, qp_flags=0x65))
    snd(confirm_r(2))
    snd(confirm_r(2, fc=1, gids=0))
    snd(confirm_r(2, fc=1, gids=3))
    snd(accept_d(1), False)
    snd(accept_d(1, size=0x70), False)                                 # size 7: invalid
    snd(accept_d(2), False)
    snd(accept_d(2, fc=1), False)
    snd(accept_d(2, fc=1, os_=15, rel=0), False)
    snd(confirm_d(1))
    snd(confirm_d(1, size=0x60))
    snd(confirm_d(2))
    snd(confirm_d(2, fc=1))
    snd(confirm_d(2, fc=1, os_=3, rel=0))
    # --- declines ----------------------------------------------------------
    snd(decline(1), False)
    snd(decline(1, sync=1), False)
    snd(decline(2), False)
    snd(decline(2, sync=1, diag=True, os_=1), False)
    snd(decline(2, diag=True, os_=3, ident=SMCD), False)
    # --- unknown CLC type 5, SMC-D identifier, two messages in one segment, a
    # message split over two segments
    snd(clc(5, 0x20, pat(10)), False)
    snd(clc(0, 0x10, pat(6)), False)
    snd(decline(1) + decline(2), False)
    m = confirm_r(2, fc=1, gids=1)
    snd(m[:30])
    snd(m[30:90])
    snd(m[90:])
    # TCP payloads that are not SMC: the heuristic declines (3 and 5 octets)
    snd(b'abc')
    snd(b'hello')
    n1 = len(c.frames)

    # --- IPv6 SMC-Rv2 proposal ---------------------------------------------
    v6 = []
    p = proposal(2, R, R, eids=1, gids=0)
    v6.append(tcp6(b'', 40001, 5000, 100, 0, 0x02))
    v6.append(tcp6(p, 40001, 5000, 101))
    v6.append(tcp6(proposal(2, BOTH, BOTH, subnet_prefixes=1, eids=2, gids=1), 40001, 5000, 101 + len(p)))
    frames = c.frames + v6

    # --- LLC messages over RoCEv2 ------------------------------------------
    ll = []
    psn = [0]

    def L(m):
        ll.append(roce(m, psn=psn[0]))
        psn[0] += 1
    g16 = pat(16, 0xa0)
    # v1 (44 octets)
    L(llc(0x01, bytes([0x00]) + MAC_A + g16 + b'\x00\x00\x07\x01' + pat(4, 0x11) + b'\x02'))     # confirm link
    L(llc(0x01, bytes([0x80]) + MAC_A + g16 + b'\x00\x00\x07\x01' + pat(4, 0x11) + b'\x02', resp=True))
    L(llc(0x02, bytes([0x00]) + MAC_A + b'\0\0' + g16 + b'\x00\x00\x08\x02\x03\x00\x01\x02'))    # add link
    L(llc(0x02, bytes([0x80]) + MAC_A + b'\0\0' + g16 + b'\x00\x00\x08\x02\x00\x00\x01\x02', resp=True))
    L(llc(0x02, bytes([0x40]) + MAC_A + b'\0\0' + g16 + b'\x00\x00\x08\x02\x06\x00\x01\x02', resp=True))
    L(llc(0x03, bytes([0x00, 2, 1]) + pat(4, 1) + pat(4, 5) + pat(8, 9) + pat(4, 0x21) + pat(4, 0x25) + pat(8, 0x29)))   # add link cont, 2 keys
    L(llc(0x03, bytes([0x80, 2, 1]) + pat(4, 1) + pat(4, 5) + pat(8, 9), resp=True))
    L(llc(0x03, bytes([0x00, 2, 0])))
    L(llc(0x04, bytes([0x00, 1]) + struct.pack('>I', 0x00010000)))                              # delete link
    L(llc(0x04, bytes([0x80 | 0x40 | 0x20, 1]) + struct.pack('>I', 2), resp=True))
    L(llc(0x06, bytes([0x00, 1]) + pat(4) + pat(8) + b'\x01' + pat(4, 9) + pat(8, 9) + b'\x02' + pat(4, 3) + pat(8, 5)))   # confirm rkey
    L(llc(0x06, bytes([0x80 | 0x20 | 0x10, 5]) + pat(4) + pat(8), resp=True))
    L(llc(0x06, bytes([0x00, 0]) + pat(4) + pat(8)))
    L(llc(0x08, bytes([0x00, 3]) + (b'\x01' + pat(4) + pat(8)) * 3))                            # confirm rkey cont
    L(llc(0x08, bytes([0x80 | 0x20 | 0x10, 7]) + (b'\x01' + pat(4) + pat(8)) * 2, resp=True))
    L(llc(0x09, bytes([0x00, 2, 0x03, 0, 0]) + pat(4, 1) + pat(4, 5)))                          # delete rkey
    L(llc(0x09, bytes([0x80 | 0x20, 1, 0x01]) + b'\0\0' + pat(4, 1), resp=True))
    L(llc(0x07, bytes([0x00]) + pat(16, 1)))                                                    # test link
    L(llc(0x07, bytes([0x80]) + pat(16, 1), resp=True))
    # RMBE control (0xfe), version 1 length
    L(llc(0xfe, struct.pack('>HIH', 1, 0x11223344, 0) + struct.pack('>HIH', 2, 0x100, 0) + struct.pack('>HIBB', 3, 0x200, 0xff, 0xe0)))
    L(llc(0xfe, struct.pack('>HIH', 1, 0x11223344, 0) + struct.pack('>HIH', 2, 0x100, 0) + struct.pack('>HIBB', 3, 0x200, 0x00, 0x00)))
    # v2: length is two octets and the message may be longer
    L(llc(0x21, bytes([0x00]) + MAC_A + g16 + b'\x00\x00\x07\x01' + pat(4, 0x11) + b'\x02', v2=True))      # confirm link
    L(llc(0x21, bytes([0x80]) + MAC_A + g16 + b'\x00\x00\x07\x01' + pat(4, 0x11) + b'\x02', resp=True, v2=True))
    add2 = bytes([0x00]) + MAC_A + b'\0\0' + g16 + b'\x00\x00\x08\x02\x03\x00\x01\x02' + bytes(8) + b'\x01\0' + g16 + bytes(8) + b'\x00\x02' + \
        pat(4, 1) + pat(4, 5) + pat(8, 9) + pat(4, 2) + pat(4, 6) + pat(8, 10)
    L(llc(0x22, add2, v2=True, size=3 + len(add2)))                                             # add link v2 request, 2 rkeys
    L(llc(0x22, add2[:0] + bytes([0x80 | 0x20]) + add2[1:], resp=True, v2=True, size=3 + 1 + 33))   # response
    L(llc(0x24, bytes([0x00, 1]) + struct.pack('>I', 0x00010000), v2=True))                       # delete link v2
    L(llc(0x25, bytes([0x00]) + bytes(20) + b'\x02' + bytes(3) + g16 + pat(16, 2), v2=True, size=3 + 1 + 20 + 4 + 32))
    L(llc(0x25, bytes([0x80 | 0x20]) + bytes(20) + b'\x01' + bytes(3) + g16, resp=True, v2=True, size=3 + 1 + 20 + 4 + 16))
    L(llc(0x26, bytes([0x00, 1]) + pat(4) + pat(8), v2=True))                                     # confirm rkey v2
    L(llc(0x27, bytes([0x00]) + pat(16, 1), v2=True))                                             # test link v2
    L(llc(0x29, bytes([0x00, 2, 0, 0, 0]) + pat(4, 1) + pat(4, 5), v2=True, size=3 + 5 + 8))     # delete rkey v2
    L(llc(0x29, bytes([0x80 | 0x20, 2, 2, 0, 0]) + pat(4, 1) + pat(4, 5), resp=True, v2=True, size=3 + 5 + 8))
    L(llc(0x29, bytes([0x80 | 0x20, 9, 9, 0, 0]) + pat(4, 1) * 9, resp=True, v2=True, size=3 + 5 + 36))   # more than 8 invalid rkeys
    # LLC-looking payloads the heuristic rejects: wrong length, unknown command
    ll.append(roce(b'\x01', psn=psn[0])); psn[0] += 1                                       # one octet only
    L(llc(0x01, b'', size=44)[:20])
    L(bytes([0x05, 44]) + bytes(42))
    L(bytes([0x23, 0, 44]) + bytes(41))
    frames += ll
    pcapng(os.path.join(out, 'smc-coverage.pcapng'), frames)
    print('%d frames: CLC over TCP 5000: 1-%d (IPv4), %d-%d (IPv6), LLC over RoCEv2: %d-%d' %
          (len(frames), n1, n1 + 1, n1 + 3, n1 + 4, len(frames)))

    mal = TcpConn(40010, 5000)
    mal.handshake()
    mal.send(proposal(1, R)[:20])                                   # length field says more
    mal2 = TcpConn(40011, 5000)
    mal2.handshake()
    mal2.send(clc(PROPOSAL, 0x10, pat(20), length=40))              # length > data: waits for more
    mal3 = TcpConn(40012, 5000)
    mal3.handshake()
    mal3.send(accept_r(2, fc=1)[:60] + b'')                         # cut accept
    mal4 = TcpConn(40013, 5000)
    mal4.handshake()
    mal4.send(clc(DECLINE, 0x20, pat(4), length=16))                # decline too short for its fields
    mal5 = TcpConn(40014, 5000)
    mal5.handshake()
    mal5.send(clc(CONFIRM, 0x20, pat(30), length=42))               # confirm cut
    mal6 = TcpConn(40015, 5000)
    mal6.handshake()
    mal6.send(SMCR + b'\x01\x00')                                   # fewer than 7 octets
    mf = []
    for x in (mal, mal2, mal3, mal4, mal5, mal6):
        mf += x.frames
    mr = [roce(llc(0x22, b'\x00' * 10, v2=True, size=13)), roce(llc(0x02, b'\x00' * 5, size=44)[:30]),
          roce(llc(0x25, bytes([0x80]) + bytes(20) + b'\xff' + bytes(3), resp=True, v2=True, size=3 + 1 + 20 + 4)),
          roce(llc(0x09, bytes([0x80, 0xff, 0xff, 0, 0]), resp=True, v2=True, size=3 + 5)),
          roce(llc(0x22, bytes([0x00]) + MAC_A + b'\0\0' + g16 + bytes(12) + bytes(8) + b'\x01\0' + g16 + bytes(8) + b'\xff\xff', v2=True,
                   size=3 + 1 + 6 + 2 + 16 + 12 + 8 + 2 + 16 + 8 + 2)),
          roce(llc(0x03, bytes([0x00, 2, 255]), size=44)),
          roce(llc(0x06, bytes([0x00, 255]) + bytes(40), size=44))]
    pcapng(os.path.join(out, 'smc-coverage-malformed.pcapng'), mf + mr)


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')
