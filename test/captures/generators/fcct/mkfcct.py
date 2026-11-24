#!/usr/bin/env python3
# Generates test/captures/fcct_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic captures for packet-fcct.c (FC Common Transport, FC type 0x20).
Usage: mkfcct.py <outdir> [-v]
Writes fcct-coverage.pcapng (clean) and fcct-coverage-malformed.pcapng.
All frames are FC-2 with delimiters (DLT 225), as the FC dissector gets them."""
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


def cth(op, gstype, sub, rev=1, in_id=0, options=0, maxres=0, rjt=(0, 0, 0)):
    return (bytes([rev]) + struct.pack('>I', in_id)[1:] + bytes([gstype, sub, options, 0]) +
            struct.pack('>HH', op, maxres) + bytes([0]) + bytes(rjt))


def main(out):
    verbose = '-v' in sys.argv
    F = []; N = []
    def add(f, note=None):
        F.append(f)
        if note: N.append((len(F), note))
    ox = [0x400]
    def nox():
        ox[0] += 1; return ox[0]
    def req(hdr, body=b'', o=None, note=None):
        o = o or nox()
        add(dframe(fch(0x02, DNS_ID, B_ID, 0x20, FIRST | SEQLAST | TSI, o, 0xFFFF) + hdr + body), note)
        return o
    def resp(hdr, body=b'', o=None, note=None):
        add(dframe(fch(0x03, B_ID, DNS_ID, 0x20, RESP | LAST | SEQLAST, o, 0x6000) + hdr + body, SOFI3, EOFT), note)

    # GS type / subtype -> derived server
    servers = [
        (0xF7, 0, 'key service'), (0xF8, 1, 'alias server'), (0xF8, 5, 'alias type, unknown subtype'),
        (0xFA, 1, 'fabric configuration server'), (0xFA, 2, 'unzoned name server'),
        (0xFA, 3, 'fabric zone server'), (0xFA, 9, 'management service, unknown subtype'),
        (0xFB, 1, 'time server'), (0xFB, 2, 'time service, unknown subtype'),
        (0xFC, 2, 'directory service, dNS'), (0xFC, 3, 'directory service, IP'),
        (0xFC, 4, 'directory service, unknown subtype'),
        (0xFD, 0, 'fabric controller (GS type 0xFD)'), (0x09, 0, 'GS type 0x09 / subtype 0 (the "fabric controller" server code)'),
        (0x09, 1, 'GS type 0x09 / subtype 1'),
        (0xE0, 0, 'vendor specific'), (0x77, 7, 'unknown GS type'),
    ]
    for gt, sub, label in servers:
        o = req(cth(0x0001, gt, sub, in_id=0x010203, maxres=0x100), bytes(8), note='request, ' + label)
        resp(cth(0x8002, gt, sub, in_id=0x010203), bytes(8), o, note=('accept, ' + label) if gt in (0xE0,) else None)
    # reject codes, reserved opcode, revision 2, options
    for code in (1, 2, 3, 4, 5, 7, 9, 0xB, 0x42):
        o = req(cth(0x0002, 0xE0, 0), bytes(4))
        resp(cth(0x8001, 0xE0, 0, rjt=(code, 0, 0)), b'', o, note=('reject, code 0x%x' % code) if code in (1, 0x42) else None)
    o = req(cth(0x0002, 0xE0, 0, rev=2, options=0x80, in_id=0xABCDEF), bytes(4), note='request revision 2, options 0x80, IN_ID')
    resp(cth(0x9000, 0xE0, 0), bytes(4), o, note='reserved opcode 0x9000')
    resp(cth(0x7FFF, 0xE0, 0), bytes(4), o, note='opcode 0x7FFF is still a request')
    resp(cth(0x8000, 0xE0, 0), bytes(4), o, note='opcode 0x8000 (reserved)')
    # name server requests that reach dNS through the table
    o = req(cth(0x0112, 0xFC, 2), bytes([0, 1, 2, 3]), note='dNS GPN_ID request through FC-CT')
    resp(cth(0x8002, 0xFC, 2), bytes([0x20, 0, 0, 0xC9, 0, 0, 0, 1]), o, note='dNS accept')
    o = req(cth(0x0171, 0xFA, 2), bytes([0, 1, 2, 8]), note='unzoned name server GID_FT')
    resp(cth(0x8002, 0xFA, 2), bytes([0x80, 1, 2, 3]), o)
    # multi-frame request: the CT header is in the first frame only, reassembled before FC-CT
    big = cth(0x0001, 0xFC, 3) + bytes(range(256)) * 4
    o = nox()
    add(dframe(fch(0x02, DNS_ID, B_ID, 0x20, FIRST, o, seqid=9, seqcnt=0) + big[:1024], SOFI3, EOFN), 'multi-frame CT sequence')
    add(dframe(fch(0x02, DNS_ID, B_ID, 0x20, LAST | SEQLAST, o, seqid=9, seqcnt=1) + big[1024:] + bytes(100), SOFN3, EOFT))
    pcapng(os.path.join(out, 'fcct-coverage.pcapng'), F)
    if verbose:
        for i, t in N: print(i, t)
        print(len(F), 'frames')

    M = []
    M.append(dframe(fch(0x02, DNS_ID, B_ID, 0x20, FIRST | SEQLAST, nox()) + cth(1, 0xE0, 0)[:10]))      # preamble cut
    M.append(dframe(fch(0x02, DNS_ID, B_ID, 0x20, FIRST | SEQLAST, nox()) + cth(1, 0xE0, 0)[:15]))
    M.append(dframe(fch(0x02, DNS_ID, B_ID, 0x20, FIRST | SEQLAST, nox())))                           # no CT at all
    M.append(dframe(fch(0x02, DNS_ID, B_ID, 0x20, FIRST | SEQLAST, nox()) + cth(0x0112, 0xFC, 2) + b'\0\0'))   # dNS body cut
    M.append(dframe(fch(0x02, DNS_ID, B_ID, 0x20, FIRST | SEQLAST, nox()) + cth(0x0212, 0xFA, 2) + b'\0\0'))
    pcapng(os.path.join(out, 'fcct-coverage-malformed.pcapng'), M)


if __name__ == '__main__':
    main(sys.argv[1])
