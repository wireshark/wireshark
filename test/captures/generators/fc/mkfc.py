#!/usr/bin/env python3
# Generates test/captures/fc_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic captures for packet-fc.c (Fibre Channel FC-2 frames).
Usage: mkfc.py <outdir> [-v]
Writes fc-coverage.pcapng (clean) and fc-coverage-malformed.pcapng.
Interfaces: 0 = FC-2 (DLT 224), 1 = FC-2 with frame delimiters (DLT 225,
SOF + frame + CRC + EOF), 2 = Ethernet (MDS header 0xFCFC, Boardwalk 0x88AE)."""
import os
import struct
import sys
import zlib

# ---- common helpers (FC frames, pcapng with FC-2, FC-2 + delimiters, Ethernet)
SOFI3 = 0xBCB55656; SOFN3 = 0xBCB53636; SOFI2 = 0xBCB55555; SOFN2 = 0xBCB53535
SOFF = 0xBCB55858; SOFC1 = 0xBCB51717
EOFT = 0xBCB57575; EOFN = 0xBCB5D5D5; EOFDTI = 0xBCAA9595; EOFA = 0xBCB5F5F5
FIRST = 0x200000; LAST = 0x100000; SEQLAST = 0x080000; RESP = 0x800000
RECIP = 0x400000; TSI = 0x010000; RELOFF = 0x000008
A_ID = bytes([0x01, 0x02, 0x03]); B_ID = bytes([0x01, 0x04, 0x05])
DNS_ID = bytes([0xFF, 0xFF, 0xFC])
C_ID = bytes([0x01, 0x06, 0x07]); D_ID = bytes([0x01, 0x08, 0x09])


def fch(r_ctl, d, s, typ, fctl, ox, rx=0xFFFF, seqid=0, dfctl=0, seqcnt=0, param=0, cs=0):
    return (bytes([r_ctl]) + d + bytes([cs]) + s + bytes([typ]) +
            struct.pack('>I', fctl)[1:] + bytes([seqid, dfctl]) +
            struct.pack('>HHHI', seqcnt, ox, rx, param))


def pcapng(path, frames):
    """frames: ('f', fc) on FC-2 (224); ('d', sof, fc, eof, badcrc) FC-2 with
    delimiters (225); ('e', ethernet) Ethernet; ('c', inner, caplen) truncated."""
    def blk(t, body):
        body += b'\0' * (-len(body) % 4)
        return struct.pack('<II', t, len(body) + 12) + body + struct.pack('<I', len(body) + 12)
    out = blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    for lt in (224, 225, 1):
        out += blk(1, struct.pack('<HHI', lt, 0, 65535))
    for i, fr in enumerate(frames):
        cap = None
        if fr[0] == 'c':
            cap = fr[2]; fr = fr[1]
        if fr[0] == 'f':
            ifid, d = 0, fr[1]
        elif fr[0] == 'e':
            ifid, d = 2, fr[1]
        else:
            ifid = 1
            crc = zlib.crc32(fr[2]) & 0xffffffff
            if fr[4]:
                crc ^= 0x55
            d = struct.pack('>I', fr[1]) + fr[2] + struct.pack('<I', crc) + struct.pack('>I', fr[3])
        orig = len(d)
        if cap is not None:
            d = d[:cap]
        ts = 1700000000 * 10**6 + i * 1000
        out += blk(6, struct.pack('<IIIII', ifid, ts >> 32, ts & 0xffffffff, len(d), orig) + d)
    open(path, 'wb').write(out)


def dframe(fc, sof=SOFI3, eof=EOFT, bad=False):
    return ('d', sof, fc, eof, bad)


def eth(payload, ethertype, src=1, dst=2):
    return (bytes([2, 0, 0, 0, 0, dst]) + bytes([2, 0, 0, 0, 0, src]) +
            struct.pack('>H', ethertype) + payload)


def ip4udp():
    udp = struct.pack('>HHHH', 4000, 9, 12, 0) + b'abcd'
    h = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0, bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2]))
    c = sum(struct.unpack('>10H', h)); c = (c & 0xffff) + (c >> 16); c = (c & 0xffff) + (c >> 16)
    return h[:10] + struct.pack('>H', (~c) & 0xffff) + h[12:] + udp


def ct(gstype=0xE0, sub=0, op=0x0001, body=b'', rev=1):
    return bytes([rev, 0, 0, 0, gstype, sub, 0, 0]) + struct.pack('>HH', op, 0) + bytes(4) + body


FCP_CMND = (b'\x00\x05' + b'\x00' * 6 + b'\x00\x00\x00\x02' + b'\x12' + b'\x00' * 15 + b'\x00\x00\x00\x24')
INQ = bytes([0, 0, 5, 2, 31, 0, 0, 0]) + b'ACME    ' + b'SYNTHETIC DISK   ' + b'0001'


def main(out):
    verbose = '-v' in sys.argv
    F = []
    N = []
    def add(f, note=None):
        F.append(f)
        if note: N.append((len(F), note))
    ox = [0x100]
    def nox():
        ox[0] += 1; return ox[0]

    # ---- FC-2 without delimiters: link control, BLS, R_CTL classes
    for code in range(16):
        param = 0
        typ = 0
        if code in (2, 3):
            param = (1 << 24) | (0x03 << 16)       # retryable, N_Port not available
        elif code == 4:
            param = (2 << 24) | (0x01 << 16)       # P_BSY
        elif code in (5, 6):
            typ = 0x10 if code == 5 else 0x30      # F_BSY: fabric busy / N_Port busy
        add(('f', fch(0xC0 | code, B_ID, A_ID, typ, LAST | SEQLAST, nox(), param=param) ),
            'link control 0x%X' % code if code < 3 or code > 14 else None)
    add(('f', fch(0xC2, B_ID, A_ID, 0, LAST | SEQLAST, nox(), param=(2 << 24) | (0x77 << 16))), 'P_RJT unknown reason, non-retryable')
    add(('f', fch(0x80, B_ID, A_ID, 0, FIRST | SEQLAST, nox())), 'BLS NOP')
    add(('f', fch(0x81, B_ID, A_ID, 0, FIRST | SEQLAST, nox(), param=0x01)), 'BLS ABTS abort sequence')
    add(('f', fch(0x81, B_ID, A_ID, 0, FIRST | SEQLAST, nox(), param=0x10)), 'BLS ABTS abort exchange')
    add(('f', fch(0x82, B_ID, A_ID, 0, FIRST | SEQLAST, nox(), param=0x1234)), 'BLS RMC, other parameter')
    add(('f', fch(0x84, B_ID, A_ID, 0, LAST | SEQLAST, nox()) + struct.pack('>BBHHHHH', 0x80, 3, 0, 0x100, 0xFFFF, 0, 0xFFFF)), 'BLS BA_ACC')
    add(('f', fch(0x85, B_ID, A_ID, 0, LAST | SEQLAST, nox()) + bytes([0, 3, 5, 0x11])), 'BLS BA_RJT')
    add(('f', fch(0x86, B_ID, A_ID, 0, LAST | SEQLAST, nox())), 'BLS PRMT')
    add(('f', fch(0x8F, B_ID, A_ID, 0, LAST | SEQLAST, nox())), 'BLS reserved code')
    add(('f', fch(0x81, B_ID, A_ID, 0x20, FIRST | SEQLAST, nox(), param=0x01)), 'BLS R_CTL with non-zero TYPE (default branch)')
    # R_CTL classes; the SEQ_CNT 0 frame that is the last frame of a sequence on an interface without delimiters is a "Bogus Fragment" that is still dissected
    add(('f', fch(0x00, B_ID, A_ID, 0x20, FIRST | SEQLAST, nox()) + ct()), 'device data, FC-CT, bogus fragment')
    add(('f', fch(0x04, B_ID, A_ID, 0x99, FIRST | SEQLAST, nox()) + bytes(20)), 'device data, unknown TYPE')
    add(('f', fch(0x30, B_ID, A_ID, 0xEE, FIRST | SEQLAST, nox()) + bytes(20)), 'link data')
    add(('f', fch(0x40, B_ID, A_ID, 0xEE, FIRST | SEQLAST, nox()) + bytes(20)), 'video data')
    add(('f', fch(0x20, B_ID, A_ID, 0x01, FIRST | SEQLAST, nox()) + bytes(20)), 'ELS R_CTL 0x20 (solicited), TYPE ELS')
    add(('f', fch(0x21, B_ID, A_ID, 0xEE, FIRST | SEQLAST, nox()) + bytes(20)), 'ELS R_CTL 0x21, other TYPE')
    add(('f', fch(0x22, B_ID, A_ID, 0xEE, FIRST | SEQLAST, nox()) + bytes(20)), 'ELS R_CTL 0x22 request, other TYPE (default)')
    add(('f', fch(0x10, B_ID, A_ID, 0xEE, FIRST | SEQLAST, nox()) + bytes(20)), 'R_CTL with unknown routing 0x10')
    add(('f', fch(0x70, B_ID, A_ID, 0xEE, FIRST | SEQLAST, nox()) + bytes(20)), 'R_CTL 0x70')
    # F_CTL bit combinations
    for i, fc in enumerate((0xFFFFFF & ~LAST & ~FIRST, RESP | RECIP | SEQLAST | LAST | (3 << 14) | (3 << 12) | (3 << 4) | 0x200, 0x020000 | SEQLAST)):
        add(('f', fch(0x04, B_ID, A_ID, 0x99, fc, nox()) + bytes(20)), 'F_CTL 0x%06X' % fc)
    # not the last frame in a sequence, fragments that never complete
    add(('f', fch(0x04, B_ID, A_ID, 0x99, FIRST, nox(), seqcnt=0) + bytes(32)), 'first frame of a sequence, SEQ_CNT 0 (Fragmented)')
    add(('f', fch(0x04, B_ID, A_ID, 0x99, SEQLAST | LAST, nox(), seqcnt=3) + bytes(32)), 'last frame of a sequence, SEQ_CNT 3 without the first (not completed)')
    # VFT header and Network_Header
    vft = bytes([0x50, 0x40 | (2 << 2), (5 << 5) | ((0x123 >> 7) & 0x1f), (0x123 << 1) & 0xFF, 7, 0, 0, 0])
    add(('f', vft + fch(0x04, B_ID, A_ID, 0x99, FIRST | SEQLAST, nox()) + bytes(20)), 'VFT header (VF_ID 0x123, pri 5, hop 7)')
    add(('f', fch(0x04, B_ID, A_ID, 0x99, FIRST | SEQLAST, nox(), dfctl=0x20) + bytes(range(16)) + bytes(20)), 'Network_Header (DF_CTL 0x20)')
    # LUN: reproducer of "Keep the LUN of each frame from the first pass"
    add(('f', fch(0x00, B_ID, A_ID, 0xEE, SEQLAST, 0x1234) + bytes(16)), 'REPRO LUN: non-FCP frame on OX_ID 0x1234 before the FCP_CMND')
    add(('f', fch(0x06, B_ID, A_ID, 0x08, FIRST | SEQLAST | TSI, 0x1234) + FCP_CMND), 'REPRO LUN: FCP_CMND for LUN 5 on the same OX_ID')
    nF0 = len(F)

    # ---- FC-2 with delimiters (SOF, CRC, EOF)
    def D(fc, sof=SOFI3, eof=EOFT, note=None):
        add(dframe(fc, sof, eof), note)
    # exchange: FC-CT request/response, SRT
    for i in range(3):
        o = nox()
        D(fch(0x02, B_ID, A_ID, 0x20, FIRST | SEQLAST | TSI, o, 0xFFFF) + ct(body=bytes(8)), SOFI3, EOFT, 'exchange %d request' % i if i == 0 else None)
        D(fch(0x03, A_ID, B_ID, 0x20, RESP | LAST | SEQLAST, o, 0x4000 + i) + ct(op=0x8002, body=bytes(8)), SOFI3, EOFT, 'exchange %d response (time from exchange first)' % i if i == 0 else None)
    o = nox()
    D(fch(0x02, B_ID, A_ID, 0x20, FIRST | TSI, o, 0xFFFF) + ct(body=bytes(8)), SOFI3, EOFN, 'exchange: first sequence, not the last (EOFn)')
    D(fch(0x03, A_ID, B_ID, 0x20, RESP | SEQLAST, o, 0x4005, seqcnt=0) + ct(op=0x8002, body=bytes(8)), SOFI3, EOFN, 'exchange: middle sequence, neither first nor last')
    D(fch(0x03, A_ID, B_ID, 0x20, RESP | LAST | SEQLAST, o, 0x4005, seqcnt=0) + ct(op=0x8002, body=bytes(8)), SOFI3, EOFT, 'exchange: last')
    # SOF/EOF variants
    o = nox(); D(fch(0x02, B_ID, A_ID, 0x20, FIRST | SEQLAST, o) + ct(), SOFI2, EOFT, 'SOFi2')
    o = nox(); D(fch(0x02, B_ID, A_ID, 0x20, FIRST | SEQLAST, o) + ct(), SOFF, EOFT, 'SOFf with SEQ_CNT 0 (first frame)')
    o = nox(); D(fch(0x02, B_ID, A_ID, 0x20, FIRST | SEQLAST, o) + ct(), SOFI3, EOFDTI, 'EOFdti (invalid)')
    o = nox(); D(fch(0x02, B_ID, A_ID, 0x20, SEQLAST, o, seqcnt=0) + ct(), SOFN3, EOFT, 'last frame, not first, SEQ_CNT 0 (Bogus Fragment)')
    o = nox(); D(fch(0x02, B_ID, A_ID, 0x20, SEQLAST, o, seqcnt=0) + ct(), SOFF, EOFA, 'SOFf, EOFa')
    o = nox(); D(fch(0x02, B_ID, A_ID, 0x20, FIRST | SEQLAST, o) + ct(), SOFC1, EOFT, 'SOFc1')
    # multi-frame sequences, reassembly
    big = ct(body=bytes(range(256)) * 4)[:1024]
    for base, label in ((0, 'seq_cnt 0, 1, 2'), (0, 'a second sequence in the same conversation, seq_cnt 0, 1, 2')):
        o = nox()
        D(fch(0x02, B_ID, A_ID, 0x20, FIRST, o, seqid=7, seqcnt=base) + big, SOFI3, EOFN, 'REASSEMBLY ' + label)
        D(fch(0x02, B_ID, A_ID, 0x20, 0, o, seqid=7, seqcnt=base + 1) + bytes(range(256)) * 4, SOFN3, EOFN)
        D(fch(0x02, B_ID, A_ID, 0x20, LAST | SEQLAST, o, seqid=7, seqcnt=base + 2) + bytes(100), SOFN3, EOFT)
    # a streaming sequence count (SEQ_CNT does not start at 0), in a conversation of its own
    o = nox()
    D(fch(0x02, D_ID, C_ID, 0x20, FIRST, o, seqid=7, seqcnt=500) + big, SOFI3, EOFN, 'REASSEMBLY streaming seq_cnt 500, 501, 502')
    D(fch(0x02, D_ID, C_ID, 0x20, 0, o, seqid=7, seqcnt=501) + bytes(range(256)) * 4, SOFN3, EOFN)
    D(fch(0x02, D_ID, C_ID, 0x20, LAST | SEQLAST, o, seqid=7, seqcnt=502) + bytes(100), SOFN3, EOFT)
    # as response direction (frag_id uses the responder bit)
    o = nox()
    D(fch(0x03, A_ID, B_ID, 0x20, RESP | FIRST, o, seqid=8, seqcnt=0) + big, SOFI3, EOFN, 'REASSEMBLY, responder direction')
    D(fch(0x03, A_ID, B_ID, 0x20, RESP | LAST | SEQLAST, o, seqid=8, seqcnt=1) + bytes(50), SOFN3, EOFT)
    # truncated capture: the data is not there, so no reassembly attempt
    add(('c', dframe(fch(0x02, B_ID, A_ID, 0x20, FIRST, nox()) + big, SOFI3, EOFN), 24 + 4 + 100), 'truncated first frame (data not all captured)')
    # FCP: command, transfer ready, data with relative offset, response (LUN 5)
    o = nox()
    D(fch(0x06, B_ID, A_ID, 0x08, FIRST | SEQLAST | TSI, o) + FCP_CMND, SOFI3, EOFT, 'FCP_CMND LUN 5')
    D(fch(0x01, A_ID, B_ID, 0x08, RESP | RECIP | SEQLAST | RELOFF, o, 0x4100, param=0) + INQ, SOFI3, EOFN, 'FCP data, relative offset flag with offset 0')
    D(fch(0x01, A_ID, B_ID, 0x08, RESP | RECIP | SEQLAST | RELOFF, o, 0x4100, param=36, seqcnt=1) + INQ, SOFI3, EOFN, 'FCP data, relative offset 36: data dissector')
    D(fch(0x01, A_ID, B_ID, 0x08, RESP | RECIP | SEQLAST | 0, o, 0x4100, param=0x55, seqcnt=2) + INQ, SOFI3, EOFN, 'FCP data without relative offset flag')
    D(fch(0x07, A_ID, B_ID, 0x08, RESP | LAST | SEQLAST, o, 0x4100) + bytes(24), SOFI3, EOFT, 'FCP_RSP (exchange last)')
    D(fch(0x30, A_ID, B_ID, 0x08, RESP | SEQLAST, o, 0x4100) + bytes(24), SOFI3, EOFT, 'link data with SCSI type')
    # other FC-4 types / ftype values
    o = nox()
    D(fch(0x04, B_ID, A_ID, 0x22, FIRST | SEQLAST, o) + bytes(24), SOFI3, EOFT, 'SW_ILS R_CTL 0x04: undefined ftype')
    D(fch(0x02, B_ID, A_ID, 0x22, FIRST | SEQLAST, nox()) + bytes([0x77, 0, 0, 0]), SOFI3, EOFT, 'SW_ILS R_CTL 0x02, unknown command')
    D(fch(0x03, B_ID, A_ID, 0x22, FIRST | SEQLAST, nox()) + bytes([0x01, 0, 0, 0, 0, 1, 1, 0]), SOFI3, EOFT, 'SW_ILS R_CTL 0x03, SW_RJT')
    D(fch(0x04, B_ID, A_ID, 0x05, FIRST | SEQLAST, nox(), dfctl=0x20) + bytes(16) + bytes([0xaa, 0xaa, 3, 0, 0, 0, 0x08, 0x00]) + ip4udp(), SOFI3, EOFT, 'IP/FC (LLC, IPv4, UDP)')
    D(fch(0x04, B_ID, A_ID, 0xFF, FIRST | SEQLAST, nox()) + bytes(16), SOFI3, EOFT, 'vendor TYPE 0xFF (OHMS)')
    D(fch(0x22, B_ID, A_ID, 0x01, FIRST | SEQLAST, nox()) + bytes([0x01, 0, 0, 0, 0, 1, 1, 0]), SOFI3, EOFT, 'ELS LS_RJT payload in a request')
    o = nox()
    D(fch(0x22, B_ID, A_ID, 0x01, FIRST | SEQLAST | TSI, o) + bytes([0x20, 0, 0, 0]), SOFI3, EOFT, 'ELS PRLI request')
    D(fch(0x23, A_ID, B_ID, 0x01, RESP | LAST | SEQLAST, o) + bytes([0x02, 0, 0, 0]), SOFI3, EOFT, 'ELS LS_ACC')
    D(fch(0x22, B_ID, A_ID, 0x01, FIRST | SEQLAST, nox()) + bytes([0x20, 0, 0, 0]), SOFI3, EOFT, 'ELS other command')
    D(fch(0x80, B_ID, A_ID, 0, FIRST | SEQLAST, nox()), SOFI3, EOFT, 'BLS NOP with delimiters')
    D(fch(0xC0, B_ID, A_ID, 0, LAST | SEQLAST, nox(), param=0x80000000), SOFN3, EOFT, 'ACK_1 with delimiters')
    D(fch(0x40, B_ID, A_ID, 0xEE, FIRST | SEQLAST, nox()) + bytes(20), SOFI3, EOFT, 'video data')
    D(fch(0x04, B_ID, A_ID, 0x99, FIRST | SEQLAST, nox(), param=0x1234) + bytes(20), SOFI3, EOFT, 'unknown TYPE')
    # LUN reproducer again, now with delimiters, and a second command reusing the exchange
    o = 0x2222
    D(fch(0x00, B_ID, A_ID, 0xEE, SEQLAST, o) + bytes(16), SOFI3, EOFT, 'LUN: non-FCP frame, delimiters')
    D(fch(0x06, B_ID, A_ID, 0x08, FIRST | SEQLAST | TSI, o) + FCP_CMND, SOFI3, EOFT, 'LUN: FCP_CMND')
    D(fch(0x07, A_ID, B_ID, 0x08, RESP | LAST | SEQLAST, o) + bytes(24), SOFI3, EOFT, 'LUN: FCP_RSP')
    nD = len(F)

    # ---- Ethernet: MDS header (0xFCFC) and Boardwalk (0x88AE)
    def mds(fc, sof=6, eof=1, cut=0):
        pl = len(fc) + 6
        hdr = bytes([0, sof]) + struct.pack('>H', pl) + bytes([0]) + struct.pack('>HH', 0x0123 << 2 & 0xFFFF, 0) + bytes(4) + struct.pack('>H', 0x0005) + b'\0\0'
        hdr = hdr[:13] + struct.pack('>H', 0x0050) + b'\0'
        return eth(hdr + fc + bytes([eof, 0]) + struct.pack('>I', zlib.crc32(fc) & 0xffffffff), 0xFCFC)
    FCM_SOFI3 = 6
    def brd(fc, sof=FCM_SOFI3, cnt=1, err=0, eof=1, plen=None):
        hdr = bytes([sof << 4 | 0, 0x05])
        mid = b'\0' * 4 if plen is None else struct.pack('>H', plen) + b'\0\0'
        return eth(hdr + fc + mid + struct.pack('>HBB', cnt, err, eof), 0x88AE)
    pay = ct(body=bytes(16))
    add(('e', mds(fch(0x02, B_ID, A_ID, 0x20, FIRST | SEQLAST | TSI, nox()) + pay, 6, 1)), 'MDS header SOFi3 / EOFt')
    add(('e', mds(fch(0x03, A_ID, B_ID, 0x20, RESP | LAST | SEQLAST, ox[0]) + pay, 7, 3)), 'MDS header SOFn3 / EOFn')
    add(('e', mds(fch(0x03, A_ID, B_ID, 0x20, RESP | LAST | SEQLAST, ox[0]) + pay, 8, 2)), 'MDS header SOFf / EOFdt')
    add(('e', mds(fch(0xC0, B_ID, A_ID, 0, LAST | SEQLAST, nox(), param=0x80000000), 6, 1)), 'MDS header, link control with no payload (frag_size == trailer size)')
    add(('e', mds(fch(0x80, B_ID, A_ID, 0, FIRST | SEQLAST, nox()), 6, 1)), 'MDS header, BLS')
    add(('e', brd(fch(0x02, B_ID, A_ID, 0x20, FIRST | SEQLAST | TSI, nox()) + pay, 6, 1)), 'Boardwalk SOFi3, packet count 1')
    add(('e', brd(fch(0x03, A_ID, B_ID, 0x20, RESP | LAST | SEQLAST, ox[0]) + pay, 7, 2)), 'Boardwalk SOFn3, packet count 2')
    add(('e', brd(fch(0x03, A_ID, B_ID, 0x20, RESP | LAST | SEQLAST, ox[0]) + pay, 8, 5, eof=3)), 'Boardwalk SOFf, packet count 5 (dropped packets), EOFn')
    add(('e', brd(fch(0x03, A_ID, B_ID, 0x20, RESP | LAST | SEQLAST, ox[0]) + pay, 6, 6, err=0x01, plen=len(pay) // 4 + 6 + 1)), 'Boardwalk with packet length')
    add(('e', brd(fch(0x03, A_ID, B_ID, 0x20, RESP | LAST | SEQLAST, ox[0]) + pay, 6, 7, err=0x09, plen=40, eof=2)), 'Boardwalk with packet length, truncated bit, EOFdt')
    add(('e', brd(fch(0x03, A_ID, B_ID, 0x20, RESP | LAST | SEQLAST, ox[0]) + pay, 2, 0xFFFF, err=0x06, eof=1)), 'Boardwalk, packet count 0xFFFF, error bits')
    add(('e', brd(fch(0x03, A_ID, B_ID, 0x20, RESP | LAST | SEQLAST, ox[0]) + pay, 10, 0, eof=1)), 'Boardwalk wrapped packet count 0 after 0xFFFF')

    pcapng(os.path.join(out, 'fc-coverage.pcapng'), F)
    if verbose:
        for i, t in N: print(i, t)
        print(len(F), 'frames; FC-2: 1-%d, delimiters: %d-%d, Ethernet: %d-%d' % (nF0, nF0 + 1, nD, nD + 1, len(F)))

    # ---- malformed
    M = []
    ok = fch(0x02, B_ID, A_ID, 0x20, FIRST | SEQLAST, 0x777) + ct()
    M.append(('f', ok[:10]))                         # shorter than the FC header
    M.append(('f', ok[:23]))                         # ends before the parameter
    M.append(('f', vft[:5]))                         # VFT cut short
    M.append(dframe(ok, SOFI3, EOFT, bad=True))      # bad CRC
    M.append(('e', mds(fch(0x02, B_ID, A_ID, 0x20, FIRST | SEQLAST, nox()), 6, 1)))          # MDS: payload shorter than the trailer (frag_size == trailer size)
    M.append(('e', eth(bytes([0, 6]) + struct.pack('>H', 28) + bytes(9) + struct.pack('>H', 5) + b'\0' + fch(0x02, B_ID, A_ID, 0x20, FIRST | SEQLAST, nox())[:25], 0xFCFC)))  # MDS: frag_size < trailer
    M.append(('e', brd(fch(0x02, B_ID, A_ID, 0x20, FIRST | SEQLAST, nox()), 6, 1)))          # Boardwalk: payload too short
    M.append(('e', eth(bytes([0x60, 5]) + b'\0' * 10, 0x88AE)))                               # Boardwalk too short for FC
    M.append(dframe(fch(0x04, B_ID, A_ID, 0x1B, FIRST | SEQLAST, nox()) + bytes(16), SOFI3, EOFT))      # FC-SB3 (SBCCS) with a short payload
    M.append(dframe(fch(0x04, B_ID, A_ID, 0x1C, FIRST | SEQLAST, nox()) + bytes(16), SOFI3, EOFT))
    M.append(dframe(fch(0x04, B_ID, A_ID, 0x22, FIRST | SEQLAST, nox()) + bytes([0x14, 0, 0, 0]), SOFI3, EOFT))  # SW_ILS HLO cut
    # two sequences with a streaming SEQ_CNT in one conversation: the base is kept per conversation, so with -2 the first sequence is reassembled with the base of the second
    for base in (0, 100):
        o = nox()
        M.append(dframe(fch(0x02, B_ID, A_ID, 0x20, FIRST, o, seqid=7, seqcnt=base) + big, SOFI3, EOFN))
        M.append(dframe(fch(0x02, B_ID, A_ID, 0x20, 0, o, seqid=7, seqcnt=base + 1) + bytes(range(256)) * 4, SOFN3, EOFN))
        M.append(dframe(fch(0x02, B_ID, A_ID, 0x20, LAST | SEQLAST, o, seqid=7, seqcnt=base + 2) + bytes(100), SOFN3, EOFT))
    M.append(('c', dframe(ok), 20))
    pcapng(os.path.join(out, 'fc-coverage-malformed.pcapng'), M)


if __name__ == '__main__':
    main(sys.argv[1])
