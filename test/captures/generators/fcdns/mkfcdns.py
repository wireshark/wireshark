#!/usr/bin/env python3
# Generates test/captures/fcdns_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic captures for packet-fcdns.c (FC name server, FC-CT GS type 0xFC /
subtype 2 and the unzoned name server 0xFA / subtype 2).
Usage: mkfcdns.py <outdir> [-v]
Writes fcdns-coverage.pcapng (clean) and fcdns-coverage-malformed.pcapng.
All frames are FC-2 with delimiters (DLT 225), carried as the real FC
dissector gets them."""
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


def ct(op, body=b'', gstype=0xFC, sub=2):
    return bytes([1, 0, 0, 0, gstype, sub, 0, 0]) + struct.pack('>HH', op, 0) + bytes(4) + body


def ctrj(reason, detail, vendor, gstype=0xFC, sub=2):
    # bytes 12..15 of the preamble: rsvd2, rjt_code, rjt_code_det, vendor; the dissector reads 13, 14, 15
    return bytes([1, 0, 0, 0, gstype, sub, 0, 0]) + struct.pack('>H', 0x8001) + struct.pack('>H', 0) + bytes([0, reason, detail, vendor])


def pid(n=0x010203): return bytes([0]) + struct.pack('>I', n)[1:]
def pn(n=1): return bytes([0x20, 0, 0, 0xC9, 0, 0, 0, n])
def nn(n=1): return bytes([0x10, 0, 0, 0xC9, 0, 0, 0, n])
def fc4(*types):
    w = [0] * 8
    for t in types:
        w[t // 32] |= 1 << (t % 32)
    return struct.pack('>8I', *w)
IP16 = bytes([0] * 10 + [0xff, 0xff, 192, 0, 2, 7])
def lst(entries, size):
    """port list entries of 'size' octets, the last one with the 0x80 flag"""
    out = b''
    for i, e in enumerate(entries):
        e = bytearray(e.ljust(size, b'\0'))
        e[0] = 0x80 if i == len(entries) - 1 else 0
        out += bytes(e)
    return out
def name_field(s, size=256): return bytes([len(s)]) + s.ljust(size - 1, b'\0')


def swils_entry(fmt, i=1, nfc4=0):
    """One name server entry of a GE_* accept. fmt bit 0: short form (no port and
    node symbolic names); bit 1: FC-4 features and descriptors follow."""
    e = bytes([fmt]) + pid(0x010000 + i)[1:] + bytes([1]) + pid(0x010100 + i)[1:] + pn(i)      # 16
    if not fmt & 1:
        e += name_field(b'port%d' % i)                      # 256
    e += nn(i)                                              # 8
    if not fmt & 1:
        e += name_field(b'node%d' % i)                      # 256
    blk = pn(0x70 + i) + IP16                               # initial process associator (8), IP address of the node (16)
    blk += bytes([0, 0, 0, 0x78 if i % 2 else 0x20])        # class of service
    blk += fc4(8, 5, 4, 0x22, 0x24, 0x1B, 0x20)             # FC-4 types (32)
    blk += IP16 + nn(0x60 + i)                              # IP address of the port (16), fabric port name (8)
    blk += bytes([0]) + pid(0x010200 + i)[1:]               # reserved, hard address (3)
    assert len(blk) == 88
    e += blk
    if fmt & 2:
        f = bytearray(388)
        f[0] = 0x03
        f[128] = 8
        f[129] = nfc4
        if nfc4:
            f[132] = 4
            f[133:137] = b'ABCD'
        e += bytes(f)
    return e


def main(out):
    verbose = '-v' in sys.argv
    F = []; N = []
    def add(f, note=None):
        F.append(f)
        if note: N.append((len(F), note))
    ox = [0x300]
    def nox():
        ox[0] += 1; return ox[0]
    def req(op, body=b'', o=None, gst=0xFC, sub=2, note=None, last=True, s=B_ID, d=DNS_ID):
        o = o or nox()
        add(dframe(fch(0x02, d, s, 0x20, FIRST | SEQLAST | TSI, o, 0xFFFF) + ct(op, body, gst, sub)), note)
        return o
    def acc(o, body=b'', gst=0xFC, sub=2, note=None, rx=0x5000, s=B_ID, d=DNS_ID):
        add(dframe(fch(0x03, s, d, 0x20, RESP | LAST | SEQLAST, o, rx) + ct(0x8002, body, gst, sub), SOFI3, EOFT), note)
    def rjt(o, reason=1, detail=2, vendor=3, gst=0xFC, sub=2, note=None, rx=0x5000):
        add(dframe(fch(0x03, B_ID, DNS_ID, 0x20, RESP | LAST | SEQLAST, o, rx) + ctrj(reason, detail, vendor, gst, sub), SOFI3, EOFT), note)
    def pair(op, rq, rs, note=None, **kw):
        o = req(op, rq, note=note, **kw)
        acc(o, rs, **{k: v for k, v in kw.items() if k in ('gst', 'sub')})
        return o

    # ---- GET requests / accepts
    pair(0x0100, pid(), b'\x01' + pid() + pn(1) + bytes([4]) + b'p1\x00\x00' + b'\0' * 100, 'GA_NXT, short response (stops after the name)')
    # GA_NXT accept laid out as the dissector reads it (offsets from the start of the CT payload)
    ga = bytes([1]) + pid()[1:] + pn(1) + name_field(b'port-name', 256)[:256]
    ga += nn(2) + name_field(b'node-name', 256)                     # 268 nname, 276 snamelen+sname
    ga += pn(9) + IP16 + bytes([0, 0, 0, 0x78]) + fc4(8, 5) + IP16 + nn(3) + bytes([0]) + pid()[1:]
    # full response (>= 636 octets with the preamble)
    o = req(0x0100, pid(), note='GA_NXT, full response')
    acc(o, ga + bytes(8))
    # truncated copies: each stops at one of the tvb_offset_exists() checks
    for cut in (290, 300, 551, 560, 574, 580, 610, 626, 634):
        o = req(0x0100, pid(), note='GA_NXT truncated at %d' % cut if cut == 290 else None)
        acc(o, (ga + bytes(8))[:cut - 16])
    o = req(0x0100, pid(), note='GA_NXT, response with empty port name')
    acc(o, bytes([1]) + pid()[1:] + pn(1) + bytes([0]) + bytes(300))
    pair(0x0101, pid(), b'', 'GID_A (no dissection)')
    pair(0x0112, pid(), pn(2), 'GPN_ID')
    pair(0x0113, pid(), nn(2), 'GNN_ID')
    pair(0x0114, pid(0), bytes([0, 0, 0, 0x78]), 'GCS_ID')
    pair(0x0117, pid(), fc4(8, 5, 4, 0x22, 0x24, 0x1B, 0x20, 0x1C), 'GFT_ID')
    pair(0x0118, pid(), bytes([6]) + b'spname', 'GSPN_ID')
    pair(0x011A, pid(), bytes([1]), 'GPT_ID')
    pair(0x011B, pid(), b'', 'GIPP_ID (no dissection)')
    pair(0x011C, pid(), nn(5), 'GFPN_ID')
    pair(0x011D, pid(), b'', 'GHA_ID (no dissection)')
    pair(0x011E, pid() + fc4(8), bytes([4]) + b'abcd' + bytes(256 - 5) + bytes([3]) + b'xyz' + bytes(254 - 4), 'GFD_ID (two descriptors)')
    pair(0x011E, pid() + fc4(8), bytes([2]) + b'ab' + bytes(255 - 3), 'GFD_ID (one descriptor)')
    pair(0x011F, pid(), bytes([0x03]), 'GFF_ID')
    pair(0x0121, pn(1), pid(0x010203), 'GID_PN')
    pair(0x012B, pn(1), IP16, 'GIPP_PN')
    pair(0x0131, nn(1), lst([pid(1), pid(2), pid(3)], 4), 'GID_NN')
    pair(0x0132, nn(1), lst([pid(1) + bytes(4) + pn(1), pid(2) + bytes(4) + pn(2)], 16), 'GPN_NN')
    pair(0x0135, nn(1), IP16, 'GIP_NN')
    pair(0x0136, nn(1), b'', 'GIPA_NN (no dissection)')
    pair(0x0139, nn(1), bytes([5]) + b'snode', 'GSNN_NN')
    pair(0x0153, IP16, b'', 'GNN_IP (no dissection)')
    pair(0x0156, IP16, b'', 'GIPA_IP (no dissection)')
    pair(0x0171, bytes([0, 1, 2, 8]), lst([pid(1), pid(2)], 4), 'GID_FT')
    pair(0x0172, bytes([0, 1, 2, 8]), lst([pid(1) + pn(1), pid(2) + pn(2)], 16), 'GPN_FT')
    pair(0x0173, bytes([0, 1, 2, 8]), lst([pid(1) + nn(1), pid(2) + nn(2)], 16), 'GNN_FT')
    pair(0x01A1, bytes([1, 1, 2, 0]), lst([pid(1), pid(2)], 4), 'GID_PT')
    pair(0x01B1, IP16, lst([pid(1)], 4), 'GID_IPP')
    pair(0x01B2, IP16, b'', 'GPN_IPP (no dissection)')
    pair(0x01F1, bytes([0, 1, 2, 0, 0, 0, 0x03, 8]), lst([pid(1), pid(2)], 4), 'GID_FF, SCSI features')
    pair(0x01F1, bytes([0, 1, 2, 0, 0, 0, 0x01, 5]), lst([pid(1)], 4), 'GID_FF, other FC-4 type')
    # ---- REGISTER requests
    pair(0x0212, pid(0x010203) + pn(3), b'', 'RPN_ID')
    pair(0x0213, pid(0x010203) + nn(3), b'', 'RNN_ID')
    pair(0x0214, pid(0x010203) + bytes([0, 0, 0, 0x78]), b'', 'RCS_ID')
    pair(0x0217, pid(0x010203) + fc4(8, 5, 4, 0x22, 0x24, 0x1B, 0x20, 64), b'', 'RFT_ID')
    pair(0x0218, pid(0x010203) + bytes([6]) + b'spname', b'', 'RSPN_ID')
    pair(0x021A, pid(0x010203) + bytes([1]), b'', 'RPT_ID')
    pair(0x021B, pid(0x010203) + IP16, b'', 'RIPP_ID')
    pair(0x021D, pid(0x010203) + bytes(16), b'', 'RHA_ID (no dissection)')
    rf = pid(0x010203) + fc4(8) + bytes([4]) + b'abcd' + bytes(255 - 5)
    pair(0x021E, rf, b'', 'RFD_ID with one descriptor (repro: fixed descriptor length)')
    pair(0x021E, pid(0x010203) + fc4(8) + bytes([3]) + b'abc' + bytes(256 - 4) + bytes([2]) + b'zz' + bytes(255 - 3), b'', 'RFD_ID with two descriptors')
    pair(0x021E, pid(0x010203) + fc4(8), b'', 'RFD_ID without a descriptor')
    pair(0x021F, pid(0x010203) + bytes([0, 0, 0x03, 8]), b'', 'RFF_ID, SCSI')
    pair(0x021F, pid(0x010203) + bytes([0, 0, 0x01, 5]), b'', 'RFF_ID, other FC-4 type')
    pair(0x0235, nn(1) + IP16, b'', 'RIP_NN')
    pair(0x0239, nn(1) + bytes([5]) + b'snode', b'', 'RSNN_NN')
    pair(0x0300, pid(0x010203), b'', 'DA_ID')
    # ---- GE_* with the SW_ILS style entries
    fmts = (0, 1, 2, 3)
    def entries(fm, nfc4=0, n=1):
        return struct.pack('>I', n) + b''.join(swils_entry(fm, i + 1, nfc4) for i in range(n))
    pair(0x0410, pid(0x010203), entries(1, n=2), 'GE_ID (short entries)')
    pair(0x0410, pid(0x010203), entries(0), 'GE_ID (long entry)')
    pair(0x0420, pn(1), entries(3, 1), 'GE_PN (short entry, FC-4 descriptor)')
    pair(0x0430, nn(1), entries(2, 0), 'GE_NN (long entry, FC-4 features, no descriptor)')
    pair(0x0430, nn(1), entries(2, 1), 'GE_NN (long entry with FC-4 descriptor)')
    pair(0x0450, IP16, entries(1), 'GE_IP')
    pair(0x0470, fc4(8), entries(1), 'GE_FT')
    pair(0x04A0, bytes([0, 0, 0, 1]), entries(1), 'GE_PT')
    pair(0x04B0, bytes([1, 0, 0, 8]) + pn(7), entries(1), 'GE_ZM (WWN member)')
    pair(0x04B0, bytes([2, 0, 0, 4]) + struct.pack('>I', 12), entries(1), 'GE_ZM (domain/port member)')
    pair(0x04B0, bytes([3, 0, 0, 3]) + pid(0x010203)[1:], entries(1), 'GE_ZM (FC ID member)')
    pair(0x04B0, bytes([4, 0, 0, 4, 0, 0, 0, 5]) + b'zone' + bytes(8), entries(1), 'GE_ZM (alias member, name length 5)')
    pair(0x04B0, bytes([9, 0, 0, 4]) + bytes(8), entries(1), 'GE_ZM (unknown member type, expert info)')
    pair(0x04C0, bytes([4, 0, 0]) + b'zone', entries(1), 'GE_ZN')
    pair(0x04D0, struct.pack('>I', 0x0a000001), entries(1), 'GE_IPP')
    pair(0x04E0, bytes([0x03]), entries(1), 'GE_FF')
    # ---- RJT, orphan ACC, opcode state on a reused exchange
    o = req(0x0112, pid(), note='request answered by RJT')
    rjt(o, 1, 2, 3)
    o = req(0x0212, pid() + pn(3), note='request answered by RJT with unknown reason')
    rjt(o, 0x99, 0, 0)
    o = nox()
    rjt(o, 1, 2, 3, note='RJT without a request')
    o = nox()
    acc(o, b'', note='ACC without a request: no record of exchange')
    # unzoned name server (GS subtype 2 under 0xFA)
    pair(0x0112, pid(), pn(4), 'Unzoned NS GPN_ID', gst=0xFA, sub=2)
    # an ACC for a conversation that exists but that dNS has no request for
    # (a FC-CT request to another server on the same exchange)
    o = nox()
    req(0x0001, b'', o=o, gst=0xFA, sub=1, note='request to the fabric configuration server (creates its own conversation)')
    acc(o, b'', note='dNS ACC on that exchange: no dNS request record')
    nR = len(F)
    pcapng(os.path.join(out, 'fcdns-coverage.pcapng'), F)
    if verbose:
        for i, t in N: print(i, t)
        print(len(F), 'frames')

    # ---- malformed
    M = []
    def mreq(op, body, trunc=None, **kw):
        o = nox()
        fr = fch(0x02, DNS_ID, B_ID, 0x20, FIRST | SEQLAST | TSI, o, 0xFFFF) + ct(op, body, **kw)
        M.append(dframe(fr))
        return o
    def macc(o, body):
        M.append(dframe(fch(0x03, B_ID, DNS_ID, 0x20, RESP | LAST | SEQLAST, o, 0x5000) + ct(0x8002, body), SOFI3, EOFT))
    # a request whose body is cut short at each kind of field
    for op, body in ((0x0112, b'\x00\x01'), (0x0212, pid()), (0x0218, pid() + bytes([40]) + b'ab'),
                     (0x0239, nn(1) + bytes([60]) + b'x'), (0x011E, pid() + fc4(8)[:20]),
                     (0x04C0, bytes([30, 0, 0]) + b'z'), (0x04B0, bytes([4, 0, 0, 30, 0, 0, 0, 40]) + b'abc'),
                     (0x0171, bytes([0, 1]))):
        mreq(op, body)
    # responses that run past the end of the frame
    o = mreq(0x0131, nn(1)); macc(o, pid(1) + pid(2))               # port list without the last flag
    o = mreq(0x0132, nn(1)); macc(o, bytes(8))
    o = mreq(0x0171, bytes([0, 1, 2, 8])); macc(o, bytes(4) * 3)
    o = mreq(0x0172, bytes([0, 1, 2, 8])); macc(o, bytes(16 * 2))
    o = mreq(0x0173, bytes([0, 1, 2, 8])); macc(o, bytes(16))
    o = mreq(0x01A1, bytes([1, 1, 2, 0])); macc(o, bytes(8))
    o = mreq(0x01B1, IP16); macc(o, bytes(4))
    o = mreq(0x01F1, bytes([0, 1, 2, 0, 0, 0, 3, 8])); macc(o, bytes(4))
    o = mreq(0x011E, pid() + fc4(8)); macc(o, bytes([200]) + b'x' * 10)       # descriptor length past the end
    o = mreq(0x0118, pid()); macc(o, bytes([200]) + b'x' * 10)
    o = mreq(0x0139, nn(1)); macc(o, bytes([200]) + b'x' * 10)
    o = mreq(0x0100, pid()); macc(o, bytes([1]) + pid()[1:] + pn(1) + bytes([200]) + b'x' * 10)
    o = mreq(0x0410, pid()); macc(o, struct.pack('>I', 3) + swils_entry(1, 1))      # three records announced, one present
    o = mreq(0x0410, pid()); macc(o, struct.pack('>I', 1) + swils_entry(1, 1)[:30])
    o = mreq(0x0410, pid()); macc(o, struct.pack('>I', 1) + swils_entry(0, 1)[:300])
    o = mreq(0x0410, pid()); macc(o, struct.pack('>I', 1) + swils_entry(3, 1)[:100])
    o = mreq(0x0410, pid()); macc(o, struct.pack('>I', 1) + swils_entry(2, 1, 1)[:200])
    o = mreq(0x0100, pid()); macc(o, b'\x01')
    M.append(dframe(fch(0x02, DNS_ID, B_ID, 0x20, FIRST | SEQLAST, nox()) + ct(0x0112)[:20]))   # CT header cut
    M.append(dframe(fch(0x03, B_ID, DNS_ID, 0x20, RESP | LAST | SEQLAST, 0x777, 0x5000) + ctrj(1, 2, 3)[:14], SOFI3, EOFT))  # RJT cut inside the reason
    # an exchange reused for two requests: the opcode kept per exchange is the last one, so with -2 the
    # first ACC is decoded as the second request (dNS keeps the opcode per exchange, not per frame)
    o = nox()
    M.append(dframe(fch(0x02, DNS_ID, B_ID, 0x20, FIRST | SEQLAST | TSI, o, 0xFFFF) + ct(0x0112, pid())))
    M.append(dframe(fch(0x03, B_ID, DNS_ID, 0x20, RESP | LAST | SEQLAST, o, 0x5000) + ct(0x8002, pn(5)), SOFI3, EOFT))
    M.append(dframe(fch(0x02, DNS_ID, B_ID, 0x20, FIRST | SEQLAST | TSI, o, 0xFFFF) + ct(0x0113, pid())))
    M.append(dframe(fch(0x03, B_ID, DNS_ID, 0x20, RESP | LAST | SEQLAST, o, 0x5000) + ct(0x8002, nn(5)), SOFI3, EOFT))
    M.append(dframe(fch(0x03, B_ID, DNS_ID, 0x20, RESP | LAST | SEQLAST, o, 0x5000) + ctrj(2, 0, 0), SOFI3, EOFT))
    pcapng(os.path.join(out, 'fcdns-coverage-malformed.pcapng'), M)


if __name__ == '__main__':
    main(sys.argv[1])
