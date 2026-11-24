#!/usr/bin/env python3
# Generates test/captures/wimax_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic coverage captures for the WiMax plugin (plugins/epan/wimax).

usage: mkwimax.py <outdir> [-v]

Writes wimax-coverage.pcapng (the main capture: Ethernet M2M frames on
ethertype 0x08F0 plus Exported PDU frames for the entry points M2M cannot
reach) and wimax-coverage-malformed.pcapng.  Everything is built with
struct; the management message bodies in CORPUS (end of this file) were
produced by a field-guided mutation run (fuzz.py) and are plain bytes.
"""
import os
import struct
import sys
import json

# ---- helpers (also in wxlib.py, which the fuzz/calibration tools import) ----
BS = bytes([2, 0, 0, 0, 0, 1])
MS = bytes([2, 0, 0, 0, 0, 2])
ETH_M2M = 0x08F0


def crc8(data):
    c = 0
    for b in data:
        c ^= b
        for _ in range(8):
            c = ((c << 1) ^ 0x07) & 0xff if c & 0x80 else (c << 1) & 0xff
    return c


def crc32(data):
    c = 0xFFFFFFFF
    for b in data:
        c ^= b << 24
        for _ in range(8):
            c = ((c << 1) ^ 0x04C11DB7) & 0xFFFFFFFF if c & 0x80000000 else (c << 1) & 0xFFFFFFFF
    return (~c) & 0xFFFFFFFF


def tlv(t, v, lenbytes=0):
    """WiMax TLV. lenbytes 0: single byte length (< 0x80); 1-4: that many
    length octets after 0x80|n (n=0 means no length at all)."""
    n = len(v)
    if lenbytes == 0:
        if n >= 0x80:
            lenbytes = 2 if n < 0x10000 else 3
        else:
            return bytes([t, n]) + v
    return bytes([t, 0x80 | lenbytes]) + n.to_bytes(lenbytes, 'big') + v


def m2m_tlvs(tlvs, seq=1, count=None):
    body = struct.pack('>HH', seq, len(tlvs) if count is None else count) + b''.join(tlvs)
    return body


def eth(src, payload, etype=ETH_M2M):
    dst = BS if src == MS else MS
    return dst + src + struct.pack('>H', etype) + payload


# M2M TLV types
T_PROTO, T_FRAME, T_BURSTNUM, T_FRAGTYPE, T_FRAGNUM, T_CDMA, T_FCH, T_PDU = 1, 2, 3, 4, 5, 7, 8, 9
T_FASTFB, T_CRC16, T_POWER, T_CINR, T_PREAMBLE, T_HARQ, T_PHY, T_EXT = 10, 11, 12, 13, 14, 15, 16, 255


def m2m_pdu(burst, src=BS, seq=1, frame=None, burst_no=None, frag=None, extra=()):
    t = []
    if frame is not None:
        t.append(tlv(T_FRAME, frame.to_bytes(3, 'big')))
    if burst_no is not None:
        t.append(tlv(T_BURSTNUM, bytes([burst_no])))
    if frag is not None:
        t.append(tlv(T_FRAGTYPE, bytes([frag[0]])))
        t.append(tlv(T_FRAGNUM, bytes([frag[1]])))
    t.extend(extra)
    t.append(tlv(T_PDU, burst))
    return eth(src, m2m_tlvs(t, seq))


def gmh(cid, payload, ci=1, ec=0, esf=0, subtypes=0, eks=0, subhdrs=b'', length=None, bad_crc=False):
    """Generic MAC header + sub-headers + payload (+CRC32).
    subtypes: bits 0..5 of the first byte (the sub-type bits)."""
    body = subhdrs + payload
    mac_len = 6 + len(body) + (4 if ci else 0)
    if length is not None:
        mac_len = length
    b0 = (ec << 6) | (subtypes & 0x3F)
    b1 = (esf << 7) | (ci << 6) | ((eks & 3) << 4) | ((mac_len >> 8) & 7)
    h = bytes([b0, b1, mac_len & 0xff]) + struct.pack('>H', cid)
    h += bytes([crc8(h)])
    pdu = h + body
    if ci:
        c = crc32(pdu)
        if bad_crc:
            c ^= 0x55
        pdu += struct.pack('>I', c)
    return pdu


def hdr56(b0, b1, b2, cid, fix_hcs=True, bad_hcs=False):
    """Type I / Type II MAC signalling header (6 bytes)."""
    h = bytes([b0, b1, b2]) + struct.pack('>H', cid)
    c = crc8(h)
    if bad_hcs:
        c ^= 1
    return h + bytes([c])


def mgmt(msgtype, body):
    return bytes([msgtype]) + body


def write_pcap(path, frames, linktype=1):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1000 + i, 0, len(fr), len(fr)))
            f.write(fr)


def epdu(name, payload, p2p_dir=None):
    """Exported PDU (link type 252) record naming a dissector (and, if given, the P2P direction)."""
    nm = name.encode()
    pad = (-len(nm)) % 4
    h = struct.pack('>HH', 12, len(nm) + pad) + nm + b'\0' * pad
    if p2p_dir is not None:
        h += struct.pack('>HHI', 35, 4, p2p_dir)
    return h + struct.pack('>HH', 0, 0) + payload


def write_epdu_pcap(path, recs):
    write_pcap(path, recs, linktype=252)


def write_pcapng(path, recs, linktypes=(1, 252)):
    """recs: list of (interface index, packet bytes). One IDB per link type."""
    def blk(t, body):
        body += b'\0' * ((-len(body)) % 4)
        n = 12 + len(body)
        return struct.pack('<II', t, n) + body + struct.pack('<I', n)
    out = blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    for lt in linktypes:
        out += blk(1, struct.pack('<HHI', lt, 0, 262144))
    for i, (ifx, pkt) in enumerate(recs):
        ts = 1000000 + i
        out += blk(6, struct.pack('<IIIII', ifx, ts >> 32, ts & 0xFFFFFFFF, len(pkt), len(pkt)) + pkt)
    open(path, 'wb').write(out)


class BitWriter:
    def __init__(self):
        self.bits = []

    def put(self, val, n):
        for i in range(n - 1, -1, -1):
            self.bits.append((val >> i) & 1)

    def pad(self, mult=8):
        while len(self.bits) % mult:
            self.bits.append(0)

    def nbits(self):
        return len(self.bits)

    def bytes(self):
        b = list(self.bits)
        while len(b) % 8:
            b.append(0)
        out = bytearray()
        for i in range(0, len(b), 8):
            v = 0
            for x in b[i:i + 8]:
                v = (v << 1) | x
            out.append(v)
        return bytes(out)


# ---- fuzz target -> PDU bytes (the same construction fuzz.py evaluates) ----
MGMT_TARGETS = {'ucd': (0, MS, 1), 'dcd': (1, MS, 1), 'rngreq': (4, MS, 1), 'rngrsp': (5, MS, 1),
                'regreq': (6, MS, 1), 'regrsp': (7, MS, 1), 'pkmreq': (9, MS, 1), 'pkmrsp': (10, MS, 1),
                'dsareq': (11, MS, 1), 'dsarsp': (12, MS, 1), 'dsaack': (13, MS, 1), 'dscreq': (14, MS, 1),
                'dscrsp': (15, MS, 1), 'dscack': (16, MS, 1), 'dsdreq': (17, MS, 1), 'dsdrsp': (18, MS, 1),
                'rescmd': (25, MS, 1), 'sbcreq': (26, MS, 1), 'sbcrsp': (27, MS, 1), 'clkcmp': (28, MS, 1),
                'dregcmd': (29, MS, 1), 'dsxrvd': (30, MS, 1), 'arqfb': (33, MS, 1), 'arqdiscard': (34, MS, 1),
                'arqreset': (35, MS, 1), 'repreq': (36, MS, 1), 'reprsp': (37, MS, 1), 'fpc': (38, MS, 1),
                'aasfbreq': (44, MS, 1), 'aasfbrsp': (45, MS, 1), 'aasselect': (46, MS, 1),
                'aasbeamreq': (47, MS, 1), 'aasbeamrsp': (48, MS, 1), 'dregreq': (49, MS, 1),
                'pmcreq': (63, MS, 1), 'pmcrsp': (64, MS, 1), 'prcltctrl': (65, MS, 1),
                'dlmap': (2, BS, 0xffff), 'ulmap': (3, BS, 0xffff), 'dcd_dl': (1, BS, 0xffff),
                'ucd_dl': (0, BS, 0xffff)}


def target_pdu(name, b):
    """-> (source address, PDU bytes) for a fuzz corpus entry; PDU is None for TLV-only targets."""
    if name in MGMT_TARGETS:
        t, src, cid = MGMT_TARGETS[name]
        return src, gmh(cid, mgmt(t, b))
    if name in ('type1', 'type2'):
        b = (b + b'\0' * 5)[:5]
        h = bytes([(b[0] & 0x3F) | (0x80 if name == 'type1' else 0xC0)]) + b[1:]
        return MS, h + bytes([crc8(h)])
    if name == 'gmh':
        b = (b + b'\0' * 4)
        b0, cid = b[0] & 0x3F, (b[2] << 8) | b[3]
        esf = (b[1] >> 6) & 1
        return (MS if (b[1] & 1) else BS), gmh(cid & 0x3ff, b[4:], ci=1, esf=esf, subtypes=b0, ec=0)
    if name == 'dlmapc':
        b = (b + bytes(12))[:max(len(b), 11)]
        total = 2 + len(b) - 1 + 4
        pdu = bytes([0xC0 | (b[0] & 0x18) | ((total >> 8) & 7), total & 0xff]) + b[1:]
        return BS, pdu + struct.pack('>I', crc32(pdu))
    if name in ('harqmap', 'harqmap2'):
        b = (b + bytes(4))
        ie = b[2:]
        total = 3 + len(ie) - 1 + 4
        w = 0xE00000 | ((b[0] & 1) << 20) | ((total & 0x1FF) << 10) | ((b[1] & 0x3F) << 4) | (ie[0] & 0x0F)
        pdu = struct.pack('>I', w)[1:] + ie[1:]
        return BS, pdu + struct.pack('>I', crc32(pdu))
    raise KeyError(name)


def _crc16_table():
    t = []
    for i in range(256):
        c = i << 8
        for _ in range(8):
            c = ((c << 1) ^ 0x1021) & 0xFFFF if c & 0x8000 else (c << 1) & 0xFFFF
        t.append(c)
    return t


_C16 = _crc16_table()


def crc16(data):
    """wimax_mac_calc_crc16(): CRC-16 (poly 0x1021, init 0xFFFF), output inverted."""
    crc = 0xFFFF
    for b in data:
        crc ^= b << 8
        crc = ((crc << 8) & 0xFFFFFFFF) ^ _C16[(crc & 0xff00) >> 8]
    return (crc ^ 0xFFFF) & 0xFFFF

# ---- end of helpers ----

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'
VERBOSE = '-v' in sys.argv

CAPS = {'main': ([], []), 'mal': ([], []), 'sched': ([], [])}
REC, SECT = CAPS['main']      # (interface, bytes), (name, first frame, last frame)


def select(name):
    global REC, SECT
    REC, SECT = CAPS[name]
    CAPS_NAME[0] = name
    if name == 'mal' and not SECT:
        section('Reproducers that report errors or warnings')
    if name == 'sched' and not SECT:
        section('Best effort scheduling type first')


def add(pkt, ifx=0):
    REC.append((ifx, pkt))


def section(name):
    SECT.append([name, len(REC) + 1, None])


MARKS = []


def mark(text):
    MARKS.append((CAPS_NAME[0], len(REC) + 1, text))


CAPS_NAME = ['main']


def end_sections():
    for rec, sect in CAPS.values():
        for i, s in enumerate(sect):
            s[2] = (sect[i + 1][1] - 1) if i + 1 < len(sect) else len(rec)


def ex(name, payload, p2p_dir=None):
    add(epdu(name, payload, p2p_dir), 1)


seq = [0]


def nseq():
    seq[0] += 1
    return seq[0]


def dl(burst, **kw):
    add(m2m_pdu(burst, BS, nseq(), **kw))


def ul(burst, **kw):
    add(m2m_pdu(burst, MS, nseq(), **kw))


def dl_tlvs(tlvs):
    add(eth(BS, m2m_tlvs(tlvs, nseq())))


def ul_tlvs(tlvs):
    add(eth(MS, m2m_tlvs(tlvs, nseq())))


def ip4(payload, proto=17, ident=1):
    h = bytes([0x45, 0, 0, 0]) + struct.pack('>HHBBH', 0, 0, 64, proto, 0) + bytes([10, 0, 0, 1, 10, 0, 0, 2])
    tot = 20 + len(payload)
    h = h[:2] + struct.pack('>H', tot) + h[4:]
    c = 0
    for i in range(0, 20, 2):
        c += (h[i] << 8) | h[i + 1]
    while c >> 16:
        c = (c & 0xffff) + (c >> 16)
    h = h[:10] + struct.pack('>H', (~c) & 0xffff) + h[12:]
    return h + payload


IPDATA = ip4(struct.pack('>HHHH', 5000, 5001, 8 + 6, 0) + b'wimax!')


def dlmapc(body, cnt=0, flags=0):
    """Compressed DL-MAP PDU: body = IEs (after the 11 byte header), with CRC32."""
    total = 11 + len(body) + 4
    pdu = bytes([0xC0 | flags | ((total >> 8) & 7), total & 0xff]) + bytes(8) + bytes([cnt]) + body
    return pdu + struct.pack('>I', crc32(pdu))


def harq_pdu(ie, count, ul=0):
    total = 3 + len(ie) - 1 + 4
    w = 0xE00000 | (ul << 20) | (total << 10) | (count << 4) | (ie[0] & 0x0F)
    pdu = struct.pack('>I', w)[1:] + ie[1:]
    return pdu + struct.pack('>I', crc32(pdu))


def build_basic():
    # ---- 1. The DL frame prefix first: sets the BS address (downlink) ----
    section('FCH, M2M TLVs')
    dl_tlvs([tlv(T_PROTO, b'\x01'), tlv(T_FRAME, b'\x00\x00\x07'), tlv(T_FCH, b'\x00\x00\x00')])
    for v in (b'\xfc\x00\x00', b'\x03\x2a\x15', b'\x05\x40\x00', b'\x07\x5f\xff', b'\x0b\x00\x41'):
        dl_tlvs([tlv(T_FCH, v)])
    ul_tlvs([tlv(T_CDMA, b'\x05\x03\x04')])
    ul_tlvs([tlv(T_CDMA, b'\xff\x00\x3f')])
    ul_tlvs([tlv(T_FASTFB, bytes([2, 1, 3, 4, 5, 6, 7, 8]))])
    ul_tlvs([tlv(T_FASTFB, bytes([0, 0]))])
    ul_tlvs([tlv(T_HARQ, bytes([2, 1, 2, 0, 1, 3, 4, 1, 0]))])
    ul_tlvs([tlv(T_HARQ, bytes([0]))])
    dl_tlvs([tlv(T_PHY, bytes([1, 2, 3, 4, 5, 6, 0, 10, 1, 2, 3, 4]))])
    dl_tlvs([tlv(T_PHY, bytes([0, 0, 0, 0, 0, 0, 0, 0]))])
    ul_tlvs([tlv(T_POWER, b'\x00\x10'), tlv(T_CINR, b'\x12\x34'), tlv(T_PREAMBLE, b'\x00\x02')])
    for st in (0, 1, 2, 3):
        ul_tlvs([tlv(T_CRC16, bytes([st]))])
    ul_tlvs([tlv(T_EXT, b'\x01\x02\x03')])
    ul_tlvs([tlv(99, b'\x01\x02')])                       # unknown TLV type
    ul_tlvs([tlv(T_PROTO, b'\x01', 1), tlv(T_BURSTNUM, b'\x03', 1), tlv(T_FRAME, b'\x01\x02\x03', 2)])
    ul_tlvs([tlv(T_PROTO, b'\x02', 3)])
    ul_tlvs([])                                           # no TLVs
    ul_tlvs([tlv(T_PROTO, b'\x01'), tlv(T_BURSTNUM, b'\x01'), tlv(T_FRAGTYPE, b'\x00'),
             tlv(T_FRAGNUM, b'\x00'), tlv(T_PDU, b'\xff' * 7)])
    # a PDU burst split over three M2M frames (first, middle, last TLV fragment)
    whole = gmh(0x1001, IPDATA) + b'\xff' * 4
    third = len(whole) // 3
    for ft, fn, part in ((1, 1, whole[:third]), (2, 2, whole[third:2 * third]), (3, 3, whole[2 * third:])):
        ul_tlvs([tlv(T_BURSTNUM, b'\x05'), tlv(T_FRAGTYPE, bytes([ft])), tlv(T_FRAGNUM, bytes([fn])), tlv(T_PDU, part)])
    # a last fragment whose first fragment never came
    ul_tlvs([tlv(T_BURSTNUM, b'\x06'), tlv(T_FRAGTYPE, b'\x03'), tlv(T_FRAGNUM, b'\x03'), tlv(T_PDU, whole[:10])])
    # the first service flow of the file sets the scheduling type (UGS), see the grant management frames at the end
    ul(gmh(1, mgmt(11, b'\x00\x01' + tlv(145, tlv(11, bytes([6]))))))


def build_headers():
    section('MAC signalling headers, PDU burst framing')
    dl(b'\xff' * 12)                                      # padding only
    ul(b'\x80\x01\x02\x03\x04\x00')                       # MAC header CRC error
    # Type I headers: every sub-type; EC=0 HT=1
    for sub in range(8):
        for low in (0, 5):
            for cid in (0x0123, 0x00ff):
                h = bytes([0x80 | (sub << 3) | low, (0x37 * (sub + 1)) & 0xff, (0x91 + sub) & 0xff])
                ul(hdr56(h[0], h[1], h[2], cid))
    # Type II headers (EC=1)
    for b0 in range(0xC0, 0xE0, 1):   # 0xE0 and up is a HARQ-MAP to the burst decoder
        ul(hdr56(b0, (b0 * 7) & 0xff, (b0 * 13) & 0xff, 0x0200 + b0))
    # a burst with several headers
    ul(hdr56(0x80, 1, 2, 3) + hdr56(0x88, 3, 4, 5) + hdr56(0xC0, 9, 9, 7) + b'\xff' * 6)
    # Generic header, MAC length 0: skipped by the burst decoder
    ul(bytes([0x00, 0x00, 0x00, 0x00, 0x01]) + bytes([crc8(bytes([0, 0, 0, 0, 1]))]))


def build_generic():
    section('Generic MAC header and sub-headers')
    # Data transport PDUs
    ul(gmh(0x1001, IPDATA))
    ul(gmh(0x1001, b'\x99' * 12))
    ul(gmh(0x1002, IPDATA, ci=0))                          # no CRC
    ul(gmh(0x1004, IPDATA, ec=1))                          # encrypted, with CRC
    ul(gmh(0x1004, IPDATA, ec=1, ci=0))
    dl(gmh(0xfffe, b'\x00' * 9))                           # padding CID
    ul(gmh(0xfeff, bytes([28, 1, 7, 8, 9])))                # AAS ranging CID, management message
    # extended sub-headers (DL, then UL)
    exts_dl = [bytes([2, 0x00, 5]),                         # SDU SN
               bytes([4, 0x01, 0x12, 0x34, 0x56]),          # DL sleep control
               bytes([4, 0x02, 0x12, 0x34, 0x56]),          # feedback request
               bytes([2, 0x03, 0x03]),                      # SN request
               bytes([2, 0x04, 0x44]),                      # PDU SN short
               bytes([3, 0x05, 0x12, 0x34]),                # PDU SN long
               bytes([2, 0x7f, 0x00]),                      # reserved
               ]
    for e in exts_dl:
        dl(gmh(0x1001, IPDATA, esf=1, subhdrs=e))
    dl(gmh(0x1001, IPDATA, esf=1, subhdrs=bytes([0x0B, 0x00, 5, 0x04, 0x44, 0x05, 0x12, 0x34, 0x03, 0x03, 0x00, 7][:12])))
    exts_ul = [bytes([3, 0x00, 0x55]), bytes([3, 0x01, 0x66]), bytes([4, 0x02, 0x12, 0x34]),
               bytes([3, 0x03, 0x77]), bytes([4, 0x04, 0x12, 0x34]), bytes([2, 0x7f, 0x00])]
    for e in exts_ul:
        ul(gmh(0x1001, IPDATA, esf=1, subhdrs=e))
    ul(gmh(0x1001, IPDATA, esf=1, subhdrs=bytes([0x00])))   # zero length extended subheader group
    # mesh sub-header; FFB (DL) / grant management (UL) sub-headers
    ul(gmh(0x1001, IPDATA, subtypes=0x20, subhdrs=b'\x12\x34'))
    dl(gmh(0x1001, IPDATA, subtypes=0x01, subhdrs=b'\xa5'))
    # ARQ feedback payload (also used below as the data of the "arq" fragments)
    def arq_ie(cid, last, at, bsn, maps):
        word = (last << 15) | (at << 13) | ((bsn & 0x3ff) << 2) | ((len(maps) - 1) & 3 if at != 1 else 0)
        return struct.pack('>HH', cid, word) + (b''.join(struct.pack('>H', m) for m in maps) if at != 1 else b'')
    fb = (arq_ie(0x1234, 0, 0, 5, [0xAAAA]) + arq_ie(0x1235, 0, 2, 6, [0x1111, 0x2222]) + arq_ie(0x1236, 0, 1, 7, [])
          + arq_ie(0x1237, 0, 3, 8, [0x0123, 0x8123]) + arq_ie(0x1238, 1, 0, 9, [0x5555, 0x6666, 0x7777]))
    # fragmentation sub-header: standard (1 byte), extended (2), ARQ (2); first/middle/last/none
    for st, fmt in ((0, 'std'), (0x08, 'ext'), (0x10, 'arq')):
        n = 1 if fmt == 'std' else 2
        for ft, nm in ((2, 0), (3, 1), (1, 2), (0, 3)):
            sh = bytes([(ft << 6) | 0x10]) if n == 1 else bytes([(ft << 6) | 0x18, 0x00])
            if fmt == 'arq':
                if ft == 0:
                    data = fb
                else:
                    data = (fb[:6], fb[6:12], fb[12:])[(2, 3, 1).index(ft)] if ft else fb
                    sh = bytes([(ft << 6) | 0x18, 0x00])
            else:
                data = b'FML-'[nm:nm + 1] * 6
            ul(gmh(0x2000 + st, data, subtypes=0x04 | st, subhdrs=sh))
    # fragmented management message: CLK-CMP split in three
    msg = bytes([28, 1, 7, 8, 9])
    ul(gmh(0x0201, msg[:2], subtypes=0x04, subhdrs=bytes([0x80])))
    ul(gmh(0x0201, msg[2:3], subtypes=0x04, subhdrs=bytes([0xc0])))
    ul(gmh(0x0201, msg[3:], subtypes=0x04, subhdrs=bytes([0x40])))
    # packing sub-headers (standard, extended): two SDUs
    def pk(ft, ln, hdr3):
        return struct.pack('>H', (ft << 14) | ln) if not hdr3 else bytes([ft << 6, (ln >> 8) & 7, ln & 0xff])
    ul(gmh(0x3001, b'', subtypes=0x02,
           subhdrs=pk(0, 8, False) + b'AAAAAA' + pk(0, 6, False) + b'BBBB'))
    ul(gmh(0x3001, b'', subtypes=0x0a,
           subhdrs=pk(0, 9, True) + b'AAAAAA' + pk(0, 7, True) + b'BBBB'))
    # ARQ feedback payload with the extended packing sub-header
    ul(gmh(0x4001, b'', subtypes=0x12, subhdrs=pk(0, 3 + len(fb), True) + fb + pk(0, 3 + len(IPDATA), True) + IPDATA))
    ul(gmh(0x4001, fb + IPDATA, subtypes=0x10))
    # a mesh PDU with everything
    ul(gmh(0x4002, IPDATA, subtypes=0x2c, esf=1, subhdrs=bytes([3, 0x00, 1]) + b'\x12\x34\xa5\x80\x00' + b'\x10'))


def build_repro():
    section('Reproducers of the fixed bugs (M2M)')
    mark('p12 bs_address: compressed DL-MAP burst from a station that is not the BS')
    # p12: bs_address decided once per frame: a compressed DL-MAP burst from a new station
    add(eth(bytes([2, 0, 0, 0, 0, 9]), m2m_tlvs([tlv(9, dlmapc(b''))], nseq())))
    mark('p12 M2M TLV length check')
    # p12: M2M TLV length check (a well-formed Protocol Version and Burst Power)
    ul_tlvs([tlv(1, b'\x01'), tlv(12, b'\x00\x10')])
    mark('p12/p13 several compressed DL-MAPs in one burst')
    # p12/p13: several compressed DL-MAPs in one burst (each is consumed once since the fix)
    dl(dlmapc(b'') * 6 + b'\xff' * 8)
    mark('p12 HARQ mode state (3 HARQ-MAPs)')
    # p12: HARQ-MAP state: normal subchannel IE, then HARQ mode switch, then the IE again
    dl(harq_pdu(bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), 1))
    dl(harq_pdu(bytes([0x0E, 0x12, 0x10]), 1))
    dl(harq_pdu(bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), 1))
    mark('p14 REG-RSP with 40 vendor id TLVs')
    # p14: REG-RSP with many vendor id TLVs (quadratic before the fix)
    msg = bytes([0x07, 0x00]) + bytes([0x90, 0x03, 1, 2, 3]) * 40
    ul(gmh(1, msg))
    mark('p14 UCD burst profile sub-TLV length wrap')
    # p14: UCD uplink burst profile whose sub-TLV length wraps
    sub = bytes([0x77, 0x84, 0xff, 0xff, 0xff, 0xfa])
    val = bytes([0x01]) + sub + b'\0\0\0'
    ul(gmh(1, bytes([0x00, 0x01, 0, 0, 0, 0]) + bytes([0x01, len(val)]) + val))
    mark('p14 fragments of one CID (missing first fragment, repeated)')
    # p14: fragments of one CID with a missing first fragment, repeated (two-pass state)
    for ft, d in [(2, b'AAAA'), (3, b'BBBB'), (1, b'CCCC'), (2, b'DDDD'), (1, b'EEEE'), (1, b'FFFF'), (2, b'GGGG'),
                  (3, b'HHHH'), (1, b'IIII')]:
        ul(gmh(0x1300, d, subtypes=0x04, subhdrs=bytes([ft << 6])))


def reduced_aas(mult=0, numie=1, ulmap=0, smcs=0, cidi=0, dcdi=0, phyi=0, cqci=0, ul=(0, 0, 0, 0, 0)):
    return _reduced_aas(0, mult, numie, ulmap, smcs, cidi, dcdi, phyi, cqci, ul)


def _reduced_aas(tweak, mult, numie, ulmap, smcs, cidi, dcdi, phyi, cqci, ul):
    """Reduced AAS private DL-MAP (compressed DL-MAP type 3) with CRC-16.
    Layout: wimax_decode_dlmap_reduced_aas(); fusc, tusc and harq are off."""
    w = BitWriter()
    w.put(6, 3); w.put(ulmap, 1); w.put(3, 2); w.put(mult, 1); w.put(0, 1)
    if mult:
        w.put(numie, 8)
    for i in range(numie if mult else 1):
        w.put(i & 3, 2); w.put(cidi, 1); w.put(dcdi, 1); w.put(phyi, 1); w.put(cqci, 1)
        w.put(1, 2); w.put(smcs, 1)
        if smcs:
            w.put(0x155, 10); w.put(7, 4); w.put(1, 2)
        if cidi:
            w.put(0x1234 + i, 16)
        if cqci:
            w.put(5, 6); w.put(2, 3); w.put(1, 3); w.put(3, 4); w.put(1, 2); w.put(0, 2)
        if dcdi:
            w.put(9, 8)
        if phyi:
            w.put(1, 1); w.put(5, 4); w.put(1, 1); w.put(2, 2)
        w.put(tweak >> 8, 3)           # DL frame offset
        w.put(tweak & 0xff, 8)                # OFDMA symbol offset
        w.put(0x0A, 6); w.put(0x33, 7); w.put(0x15, 6)   # subchannel offset, symbols, subchannels
        w.put(6, 4)                    # DIUC / N_ep
        w.put(1, 2)                    # repetition coding
        if ulmap:
            azci, azpi, umii, phmi, powi = ul
            w.put(azci, 1); w.put(azpi, 1); w.put(umii, 1); w.put(phmi, 1); w.put(powi, 1)
            w.put(0, 2); w.put(2, 2)
            if azci:
                w.put(1, 2); w.put(0x55, 7); w.put(2, 2); w.put(0, 5)
            if azpi:
                w.put(3, 8); w.put(4, 8)
            if umii:
                w.put(7, 8); w.put(0x12345678, 32)
            if phmi:
                w.put(1, 1); w.put(3, 4); w.put(0, 1); w.put(0x2AAAAA, 22)
            if powi:
                w.put(0x7f, 8)
            w.put(1, 3); w.put(0x123, 12); w.put(0x155, 10); w.put(5, 4); w.put(2, 2)
        w.put(0, 3)
    w.pad(8)
    body = w.bytes()
    return body + struct.pack('>H', crc16(body))


def build_aas():
    section('Reduced AAS private DL-MAP (compressed DL-MAP type 3)')
    dl(reduced_aas())
    dl(reduced_aas(smcs=1, cidi=1))
    dl(reduced_aas(mult=1, numie=3, dcdi=1, phyi=1, cqci=1, cidi=1, smcs=1))
    dl(reduced_aas(ulmap=1))
    dl(reduced_aas(ulmap=1, ul=(1, 1, 1, 1, 1), cidi=1))
    dl(reduced_aas(mult=1, numie=2, ulmap=1, ul=(0, 1, 0, 1, 0), dcdi=1))


def build_epdu():
    section('Exported PDU entry points')
    mark('p12 CRC tables: HARQ-MAP, PDU burst, HARQ-MAP via Exported PDU')
    # p12: CRC tables ready before the first PDU burst: HARQ-MAP via Exported PDU first
    harq = harq_pdu(bytes([0x00]) + bytes(9), 1)
    ex('wimax_harq_map_handler', harq)
    ex('wimax_pdu_burst_handler', harq)
    ex('wimax_harq_map_handler', harq)
    # p13: DL-MAP N_layer state
    def dlmap_nl(dci):
        w = BitWriter()
        w.put(0x00, 8); w.put(0x000001, 24)
        w.put(1, 8); w.put(0x020000000001, 48)
        w.put(4, 8)
        w.put(14, 4)
        w.put(7, 4); w.put(3, 2); w.put(0, 2); w.put(0, 2); w.put(0, 3); w.put(1, 1); w.put(0, 8); w.put(3, 4)
        sub = BitWriter()
        sub.put(0, 4); sub.put(0, 6); sub.put(0, 1); sub.put(dci, 1); sub.put(0, 1); sub.put(0x1234, 16)
        if dci:
            sub.put(0, 5); sub.put(0, 1); sub.put(0, 1); sub.put(0, 1); sub.put(3, 2); sub.put(0, 1); sub.put(0, 1)
        sub.put(0x155, 10)
        for i in range(3):
            sub.put(0xA, 4); sub.put(1, 2); sub.put(5, 4); sub.put(1, 1)
        w.put(0x30, 6)
        w.bits.extend(sub.bits)
        w.pad(8)
        return w.bytes() + bytes(220)
    select('mal')
    ex('mac_mgmt_msg_dlmap_handler', dlmap_nl(0))
    ex('mac_mgmt_msg_dlmap_handler', dlmap_nl(1))
    select('main')
    # p14: ARQ feedback / discard handlers straight from Exported PDU
    select('mal')
    ex('mac_mgmt_msg_arq_feedback_handler', bytes([0x00, 0x10, 0x20, 0x00]) + bytes([0x00, 0x11, 0xa0, 0x00]))
    select('main')
    ex('mac_mgmt_msg_arq_discard_handler', bytes([0x12, 0x34, 0x07, 0xff]))
    ex('mac_mgmt_msg_arq_reset_handler', bytes([0x12, 0x34, 0x45]))
    mark('p14 first_gmh: generic handler then a burst')
    # p14: generic header handler fed directly (first_gmh false on the first pass), then a burst
    f1 = bytes([0x04, 0x00, 11]) + struct.pack('>H', 0x1000) + b'\0' + bytes([0x80]) + b'ABCD'
    ex('mac_header_generic_handler', f1)
    ex('wimax_pdu_burst_handler', gmh(0x1001, IPDATA))
    mark('p14 fragments handed to the generic handler and to the burst handler')
    # p14: fragments handed to the generic handler and to the burst handler
    def g(cid, ft, data):
        body = bytes([ft << 6]) + data
        return bytes([0x04, 0, 6 + len(body)]) + struct.pack('>H', cid) + b'\0' + body
    for ft, d in [(2, b'AAAA'), (3, b'BBBB'), (1, b'CCCC'), (2, b'DDDD'), (1, b'EEEE')]:
        ex('mac_header_generic_handler', g(0x1000, ft, d))
    for ft, d in [(2, b'AAAA'), (3, b'BBBB'), (1, b'CCCC')]:
        ex('wimax_pdu_burst_handler', gmh(0x1000, bytes([ft << 6]) + d, subtypes=0x04))
    mark('direct entry points: wmx, short headers, P2P direction, empty sub-headers, HARQ-MAP length 0, TLV length of length 5')
    # entry points that need no M2M TLV, direction from the Exported PDU tag
    ex('wmx', b'\x01\x02')
    ex('mac_header_generic_handler', b'\x00\x00\x00')           # shorter than a header
    ex('mac_header_type_1_handler', b'\x80\x00\x00')
    ex('mac_header_type_2_handler', b'\xc0\x00\x00')
    ex('wimax_pdu_burst_handler', dlmapc(b''), 1)                # received: downlink by the P2P direction
    ex('wimax_pdu_burst_handler', dlmapc(b''), 0)                # sent: uplink, a header CRC error
    ex('wimax_pdu_burst_handler', gmh(0x1001, b'', esf=1, ci=0), 0)   # extended subheader group missing
    ex('wimax_pdu_burst_handler', gmh(0x1001, b'', subtypes=0x10, ci=0), 0)  # ARQ feedback payload missing
    ex('wimax_pdu_burst_handler', b'\xe0\x00\x00')              # HARQ-MAP of length 0
    select('mal')
    ex('mac_header_generic_handler', bytes([0x00, 0x40, 0x08]) + struct.pack('>H', 0x1001) + b'\x00' + b'\x11\x22')  # CRC, too short
    select('main')
    ex('mac_mgmt_msg_dsd_req_handler', b'\x00\x01\x00\x00\x00\x02' + bytes([0x95, 0x85, 0, 0, 0, 0, 1, 7]))  # length of length 5


def build_mal():
    select('mal')
    # p12/p13: compressed DL-MAP claiming 255 IEs in a short map: used to loop
    unit = bytes([0xC0, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0, 0, 0, 0, 0])
    add(eth(bytes([2, 0, 0, 0, 0, 9]), m2m_tlvs([tlv(9, unit)], nseq())))
    dl(unit * 6 + b'\xff' * 8)
    dl(bytes([0xC0, 0x0F, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0, 0, 0, 0]) * 3)
    ul(gmh(0x1003, IPDATA, bad_crc=True))
    ul(gmh(0x1001, IPDATA, subtypes=0x01, subhdrs=b'\x80\x00'))   # scheduling type not known yet
    ul(gmh(1, mgmt(11, b'\x00\x01' + tlv(145, tlv(11, bytes([5]))))))   # extended rtPS first
    ul(gmh(0x1001, IPDATA, subtypes=0x01, subhdrs=b'\x80\x00'))
    # p14: 65 distinct CIDs with a first fragment each (too many CIDs)
    for i in range(70):
        ul(gmh(0x1100 + i, b'ABCD', subtypes=0x04, subhdrs=bytes([0x80]), ci=1))
    # extended and extended-2 IEs of the DL-MAP and UL-MAP, mostly "not implemented" stubs
    # that warn and may run off the end of the map: only the mal capture
    hdr = b'\x00\x00\x00\x01\x01\x02\x00\x00\x00\x00\x01\x04'
    for lead in (0xE0, 0xF0):
        for e in range(16):
            for L in (2, 14):
                body = hdr + bytes([lead | e, (L if lead == 0xE0 else (L // 2) << 4)]) + bytes(range(1, L + 1)) + bytes(48)
                add(m2m_pdu(target_pdu('dlmap', body)[1], BS, nseq()))
    uh = b'\x00\x01\x00\x00\x00\x10\x04'
    for u in (11, 14, 15):
        for e in range(16):
            for L in (2, 12):
                body = uh + b'\x00\x01' + bytes([(u << 4) | e, L]) + bytes(range(1, L + 1)) + bytes(48)
                add(m2m_pdu(target_pdu('ulmap', body)[1], BS, nseq()))
    for target, groups in CORPUS_MAL:      # warnings ("Not implemented" IEs) are allowed here
        for g in groups:
            pdus = [target_pdu(target, bytes.fromhex(h)) for h in g]
            add(m2m_pdu(b''.join(p for _, p in pdus), pdus[0][0], nseq()))
    select('sched')
    ul(gmh(1, mgmt(11, b'\x00\x01' + tlv(145, tlv(11, bytes([2]))))))     # best effort first
    ul(gmh(0x1001, IPDATA, subtypes=0x01, subhdrs=b'\x80\x00'))
    select('main')


# ---BEGIN CORPUS_MAL---
CORPUS_MAL = [
    ('dlmap', [
        ['000000e00101025600007938fe03000107080e0a03207e2000'],
    ]),
    ('dlmapc', [
        ['1601fe341ac6250000000010000000000000b202fe800000000000d2087f9eff7f980110810f000081007f00000000000000810000000000000000', '00000000000000000001e1022007000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000', '341ac62500f600000000007f000000000000000000000000', '00000000000000000001e20208f0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000', '00000000000000000001e302f0a8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000', '00000000000000000001e4028008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'],
        ['00000000000000000001e5020f81000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000', '00000000000000000001ea0240c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000', '00000000000000000001eb02800f000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000', '00000000000000000001ec02ff10000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000', '10fb55010200c62500000000000000000000b60100400000000000000103fe0002000001ff19ff7f0000070000000000000000000000000000000000000b01ff0000000000000000000020000000000000000000f4160f0000000000000000000000'],
    ]),
    ('ulmap', [
        ['000100000010040001b102077f0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000', '000100000010040001b2027f030000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000', '000100000010040001b60201400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000', '000100000010040001a9140210c000c081fffe02037f000f6700018020c0040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000', '0001000000100400010114e0e0c020038103e01b02e008107f0704c00208200f40c00000000000000000ff000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000b1080f026cf00f0f208100000000000000000000000000000000'],
    ]),
]
# ---END CORPUS_MAL---

# ---BEGIN CORPUS---
CORPUS = [
    ('aasbeamreq', [
        ['080f08'],
    ]),
    ('aasbeamrsp', [
        ['e1e0978c3f5fd5'],
    ]),
    ('aasfbreq', [
        ['080f08'],
    ]),
    ('aasfbrsp', [
        ['f6b5887f66'],
    ]),
    ('aasselect', [
        ['e1'],
    ]),
    ('arqdiscard', [
        ['3a07f97f'],
    ]),
    ('arqfb', [
        ['ae4bf87b0fb6bed45926096c6448', '', '21ee232d', '14d58d145a8b'],
    ]),
    ('arqreset', [
        ['080f08'],
    ]),
    ('clkcmp', [
        ['0125f5ca98dbf55fcdf450'],
    ]),
    ('dcd', [
        ['000022020168150111', '000036060301110101f0', '00000181080802010f0102010f090111', '0000320111', '0000210111', '00002001002201002d0111'],
        ['02080881017f80ff0fff00', '0000000111', '0000020111', '0000030111', '0000040111', '0000050111'],
        ['0000060111', '0000070111', '00000a0111', '00000c0111', '00000e0111', '00000f0111'],
        ['0000110111', '0000130111', '0000140111', '0000160111', '00001f0111', '0000230111'],
        ['0000240111', '0000330111', '0000340111', '00003c0111', '0000940111', '0000990111'],
        ['00009a0111', '00000d06112233445566', '000036060201e0030111'],
    ]),
    ('dregcmd', [
        ['ae048120f0fe1c048120f0feb1f7ed', '728d09b9e17905d4d8fed7a97ff8089cf0080a', '720809b9e17905d4d8fed709017fa97ff8109cf0080a', '630220f0090220f0e1', 'e103067fc00f811020', '630520f02f0102090220f0e1'],
        ['720809b9e17905d4d8fed7a97ff89cf0080a', '728d230249c009b9827905dfd8fef7a9f8089cf0080a'],
    ]),
    ('dregreq', [
        ['ae048120f0fe1c048120f0feb1f7ed', '728d09b9e17905d4d8fed7a97ff8089cf0080a', '720809b9e17905d4d8fed709017fa97ff8109cf0080a', '630220f0090220f0e1', 'e103067fc00f811020', '630520f02f0102090220f0e1'],
        ['720809b9e17905d4d8fed7a97ff89cf0080a', '728d230249c009b9827905dfd8fef7a9f8089cf0080a'],
    ]),
    ('dsaack', [
        ['00000092110404812000f020030203c00c04207f40e020060404812000f0900111', '000000920a0504812000f0070215ff20060404812000f0900111', '000000920d8f0111170208c00f0140140101', '00000092121102017d06020f992308800100ff0702c007', '00000092120404812000f01901e012010327040708bb0420060404812000f0900111', '0000008d18920b0404812000f020030203c020060404812000f0900111'],
        ['0000008f0494810111', '000000920d1102017d2e04f54010031c01df', '00000091060101c00e010323030101c0930111', '00000092121102017d28027f03030810040200ffc00840', '000000920c8f01110904e040ff202101c0', '000000920d8f01110b020f401804f001e0ff'],
        ['000000930111', '000000950111', '00000092041502017d', '00000092068f0111290120', '00000092071102017d2a01e0', '000000920c1102017d28027f031302f0f0'],
        ['000000920d8f01112d08077f027f02000801', '000000920e1102017d06020f991f0402f00404', '000000920f8f01110904e040ff200d040281800f', '00000091080101c01e03c0812023030101c0930111', '0000009206020404c0812000f020061004812000f0900111', '000000920b2404812000f020030203c020060404812000f0900111'],
        ['000000920d0404812000f01901e02502e00820060404812000f0900111', '000000920e0404812000f020030203c02c01fe20060404812000f0900111', '000000920f0404812000f01901e01a0440107fc020060404812000f0900111', '000000920f0404812000f020030203c01602e00020060404812000f0900111', '020000920e040481200ff020030203c06601fe2006040404812000f090'],
        ['000000920e1102017d100204101d047f0f01fe'],
        ['00000091070801c0260202c023030101c0930111'],
        ['000000920c0404812000f02b047f03040320060404812000f0900111'],
        ['00000094810111'],
        ['000000900111'],
    ]),
    ('dsareq', [
        ['000092349001110602f0c066812a038200122302fe070e01200b010f0302fe0706027f0f020881f0e0200f070f40660881f0e0200f070f40', '0000922a90011164210404c00202ff06811802031001000303e02001010408e0041005017f04031001002d020f10', '00009220900111661b03191202fe8104810a0303020481040302048102068107070f8000', '000092099001116601ff0c01cf', '0000920b900111020320fff00501d7', '00009215900111630b02090102fe1003030010b319033240f0'],
        ['000092299001110602f0c066811f0382000c0f042302fe070a040302fe070203020101660881f0e0200f070f40', '000092129001111d04e04010040d03fec07f2302005f', '000092359001110602f0c066812b038200182302fe07090c0804fe020f070904fe020f070d040302fe070203020101660881f0e0200f070f40', '0000920d9001112b04c0002008070215ff', '00008d11030403047f0402810107010402810107930111', '0000922b9001110602f0c06681210382000c2302fe070102fe078f0200c002050303020101660883f0e0200f070f40'],
        ['0000920d9001111602087f2e0481010f08', '0000920d900111660803060702ff7f2001', '0000920f90011127047f04041003047f00ff20', '00008f06108103e010c00a06108103e010c092079001112c02f020', '0000922a9001110602f0c0668120038200081304ff0f80037f02fe070302fe0702ff81f0e0200f070f40660881f0150f0f070f40', '000092030901f0900111'],
        ['0000920720011128020408', '000092099001110801a9140104', '000092099001111a01ff150103', '0000920a9001111f01031202feff', '0000920a90011129017b0e020080', '0000920b11810403047fff2102e0fe'],
        ['0000940111', '0000950111', '7c0092030b01f0900111', '000092079001112c02f020', '0000920790011126020407', '0000920790011122028081'],
        ['000092079001110f027520', '000092079001111702f020', '000092089001112a03e02008', '000092091001111d04e0401004', '0000920a66080102101020c003c0', '0000920b9001111602087f040201fe'],
        ['0000920c9001111f01031e0404070080', '0000920c9001111d04e0401004130104', '0000920c900111020320fff01c027f10', '0000920d9001112b04c00020082502e07f', '0000920f9001112b04c0002008180408078120', '0008920d9001116608030610040702ff7f2001'],
        ['00009216900111630c020a0204e008e0010102fe1019033240f0', '0000921b9001110602f0c066811102050103018002660881f0e0200f070f40', '0000922290011164190404c00202ff06811002031001008f040020f0f006031001002d020f10'],
        ['0000921a900111661503131202fe81080d04810a03030204810403020481'],
        ['0000922d9001110602f0c06681230382000b2302fe070c01010302fe07020881f0e0200f070f40660881f0e0200f070f40'],
        ['000092389001110602f0c066812e0382001b05811017061000c008e00805061000c008e0082302fe070302fe070203020101660881f0e0200f070f40'],
        ['00009109010301118f06c0040f01c007b906c0040f01c007'],
        ['0000930111'],
    ]),
    ('dsarsp', [
        ['00000092110404812000f020030203c00c04207f40e020060404812000f0900111', '000000920a0504812000f0070215ff20060404812000f0900111', '000000920d8f0111170208c00f0140140101', '00000092121102017d06020f992308800100ff0702c007', '00000092120404812000f01901e012010327040708bb0420060404812000f0900111', '0000008d18920b0404812000f020030203c020060404812000f0900111'],
        ['0000008f0494810111', '000000920d1102017d2e04f54010031c01df', '00000091060101c00e010323030101c0930111', '00000092121102017d28027f03030810040200ffc00840', '000000920c8f01110904e040ff202101c0', '000000920d8f01110b020f401804f001e0ff'],
        ['000000930111', '000000950111', '00000092041502017d', '00000092068f0111290120', '00000092071102017d2a01e0', '000000920c1102017d28027f031302f0f0'],
        ['000000920d8f01112d08077f027f02000801', '000000920e1102017d06020f991f0402f00404', '000000920f8f01110904e040ff200d040281800f', '00000091080101c01e03c0812023030101c0930111', '0000009206020404c0812000f020061004812000f0900111', '000000920b2404812000f020030203c020060404812000f0900111'],
        ['000000920d0404812000f01901e02502e00820060404812000f0900111', '000000920e0404812000f020030203c02c01fe20060404812000f0900111', '000000920f0404812000f01901e01a0440107fc020060404812000f0900111', '000000920f0404812000f020030203c01602e00020060404812000f0900111', '020000920e040481200ff020030203c06601fe2006040404812000f090'],
        ['000000920e1102017d100204101d047f0f01fe'],
        ['00000091070801c0260202c023030101c0930111'],
        ['000000920c0404812000f02b047f03040320060404812000f0900111'],
        ['00000094810111'],
        ['000000900111'],
    ]),
    ('dscack', [
        ['00000092110404812000f020030203c00c04207f40e020060404812000f0900111', '000000920a0504812000f0070215ff20060404812000f0900111', '000000920d8f0111170208c00f0140140101', '00000092121102017d06020f992308800100ff0702c007', '00000092120404812000f01901e012010327040708bb0420060404812000f0900111', '0000008d18920b0404812000f020030203c020060404812000f0900111'],
        ['0000008f0494810111', '000000920d1102017d2e04f54010031c01df', '00000091060101c00e010323030101c0930111', '00000092121102017d28027f03030810040200ffc00840', '000000920c8f01110904e040ff202101c0', '000000920d8f01110b020f401804f001e0ff'],
        ['000000930111', '000000950111', '00000092041502017d', '00000092068f0111290120', '00000092071102017d2a01e0', '000000920c1102017d28027f031302f0f0'],
        ['000000920d8f01112d08077f027f02000801', '000000920e1102017d06020f991f0402f00404', '000000920f8f01110904e040ff200d040281800f', '00000091080101c01e03c0812023030101c0930111', '0000009206020404c0812000f020061004812000f0900111', '000000920b2404812000f020030203c020060404812000f0900111'],
        ['000000920d0404812000f01901e02502e00820060404812000f0900111', '000000920e0404812000f020030203c02c01fe20060404812000f0900111', '000000920f0404812000f01901e01a0440107fc020060404812000f0900111', '000000920f0404812000f020030203c01602e00020060404812000f0900111', '020000920e040481200ff020030203c06601fe2006040404812000f090'],
        ['000000920e1102017d100204101d047f0f01fe'],
        ['00000091070801c0260202c023030101c0930111'],
        ['000000920c0404812000f02b047f03040320060404812000f0900111'],
        ['00000094810111'],
        ['000000900111'],
    ]),
    ('dscreq', [
        ['000092079001110c02f020', '0000920f90011126020407230308e1800501d7', '0000920b9001112c02f02003020002', '0000920e90011114020f0128010f0b020010', '000092129001112901081702017f2d067f04fe04f010', '00008d0e0281010723080f840f100f030102010402810107930111'],
        ['0000920c90011127047f0404102a0180', '00008d04028101079106010402810107930111', '00008f0e0281010723080f040f100f030102010402810107930111', '000092079001112b020820', '0000920a900111220280811a0140', '0000920a9001110601bc1802ff81'],
        ['0000950111', '000092069001111601bc', '0000920713030403047fff', '000092089001112103e081ff', '0000920a90011114020f010901e0', '0000920a9001112c02f0201501c0'],
        ['0000920a9001112901080e02ff40', '0000920a90011114020f01200101', '0000920b900111220280810f027520', '0000920b9001112c02f02004020804', '0000920b90011114020f0110020708', '0000920c900111260204071f03020004'],
        ['0000920c90011114020f011e03c08120', '0000920d9001111d04e040100425027fff', '0000920d90011127047f040410190220c0', '0000920d9001112c02f020120480087f03', '0000920e90011114020f0128010f0d02a440', '000092069001a90801030140ff070211160108'],
        ['000092119001112202808102037f087f2303000201', '0000921290011126020407230308e1800704aec00081', '000092096e01111d04e0001004', '0000920a9001112901081781017f01020704'],
        ['0000920c9001111d04e04010041c0180'],
        ['0000920711030403047fff'],
        ['000092099001112901082e01e0'],
        ['0000900111'],
        ['0000940111'],
    ]),
    ('dscrsp', [
        ['00000092110404812000f020030203c00c04207f40e020060404812000f0900111', '000000920a0504812000f0070215ff20060404812000f0900111', '000000920d8f0111170208c00f0140140101', '00000092121102017d06020f992308800100ff0702c007', '00000092120404812000f01901e012010327040708bb0420060404812000f0900111', '0000008d18920b0404812000f020030203c020060404812000f0900111'],
        ['0000008f0494810111', '000000920d1102017d2e04f54010031c01df', '00000091060101c00e010323030101c0930111', '00000092121102017d28027f03030810040200ffc00840', '000000920c8f01110904e040ff202101c0', '000000920d8f01110b020f401804f001e0ff'],
        ['000000930111', '000000950111', '00000092041502017d', '00000092068f0111290120', '00000092071102017d2a01e0', '000000920c1102017d28027f031302f0f0'],
        ['000000920d8f01112d08077f027f02000801', '000000920e1102017d06020f991f0402f00404', '000000920f8f01110904e040ff200d040281800f', '00000091080101c01e03c0812023030101c0930111', '0000009206020404c0812000f020061004812000f0900111', '000000920b2404812000f020030203c020060404812000f0900111'],
        ['000000920d0404812000f01901e02502e00820060404812000f0900111', '000000920e0404812000f020030203c02c01fe20060404812000f0900111', '000000920f0404812000f01901e01a0440107fc020060404812000f0900111', '000000920f0404812000f020030203c01602e00020060404812000f0900111', '020000920e040481200ff020030203c06601fe2006040404812000f090'],
        ['000000920e1102017d100204101d047f0f01fe'],
        ['00000091070801c0260202c023030101c0930111'],
        ['000000920c0404812000f02b047f03040320060404812000f0900111'],
        ['00000094810111'],
        ['000000900111'],
    ]),
    ('dsdreq', [
        ['df3d34f87e048d0216f0e0810203c082a403810fc0', '000000000000950111', 'df3d34f87e048d3d34f87e04da038010408d0216f0e0810203c082a403810fc0'],
    ]),
    ('dsdrsp', [
        ['9ceb218325da678d10dc20f002087f0308800404e4020181001206dc20f002087f33cb', '00000000000000950111', '9ceb00000003040281037f04000400950111218325da6733cb'],
    ]),
    ('dsxrvd', [
        ['080f08'],
    ]),
    ('fpc', [
        ['f6b5887f66'],
    ]),
    ('pkmreq', [
        ['0049060300072000ff00260111', '00071b0803810240000101011d0111', '0000070111', '0000080111', '0000090111', '00000a0111'],
        ['00000b0111', '00000c0111', '00000f0111', '0000100111', '0000110111', '0000120111'],
        ['0000180111', '00001e0111', '00001f0111', '0000200111', '0000210111', '0000220111'],
        ['0000230111', '0000250111', '0000260111', '0000290111', '00002a0111', '00002b0111'],
        ['00002c0111', '00002d0111', '00002706112233445566', '0000190711030403047fff', '000019070601110502fecb', '00491b05060300072000ff00260111'],
        ['00491b05070300072000ff00260111', '00000d0111', '0000130111', '0000150111', '0000170111'],
        ['0000190b060111010310c0f0030101'],
        ['00071b1203810240001d01110201e005027f020401fe'],
        ['00001403112233'],
        ['0000190704011102020180'],
        ['0019280404100804040204020200190402040202001dea11'],
    ]),
    ('pkmrsp', [
        ['0049060300072000ff00260111', '00071b0803810240000101011d0111', '0000070111', '0000080111', '0000090111', '00000a0111'],
        ['00000b0111', '00000c0111', '00000f0111', '0000100111', '0000110111', '0000120111'],
        ['0000180111', '00001e0111', '00001f0111', '0000200111', '0000210111', '0000220111'],
        ['0000230111', '0000250111', '0000260111', '0000290111', '00002a0111', '00002b0111'],
        ['00002c0111', '00002d0111', '00002706112233445566', '0000190711030403047fff', '000019070601110502fecb', '00491b05060300072000ff00260111'],
        ['00491b05070300072000ff00260111', '00000d0111', '0000130111', '0000150111', '0000170111'],
        ['0000190b060111010310c0f0030101'],
        ['00071b1203810240001d01110201e005027f020401fe'],
        ['00001403112233'],
        ['0000190704011102020180'],
        ['0019280404100804040204020200190402040202001dea11'],
    ]),
    ('pmcreq', [
        ['000111'],
    ]),
    ('pmcrsp', [
        ['000111', '400111'],
    ]),
    ('prcltctrl', [
        ['e1'],
    ]),
    ('regreq', [
        ['0133910111662a032802047a0207e00a81084002fe030a02fe030481141f0808ff02810248c00f040808ff02810248c00f1c020288', '2b031122e00881048120088003e3', '07021122', '0118910111660f0602e008030906047a0207e01301031c020288', '01089101110c0307ffff', '911a0d0111220481fe08fe23017f640c0104081010ff6404081010ff'],
        ['1b0111', '010a91011105020108140181', '0111020111060240802e0481010f081d02087f', '0125910111661c031a0c8200060e01ff0c01ff088200062a010f08010f02047a0207e01c020288', '1a0111', '280111'],
        ['30021122', '01209101116617031503047a0207e00581082b0208f0050208f00d0281f01c020288', 'db062002020281f001062002020281f0030111', '1f0111', '910d0d0111080220202601072d0110', '010f9101112c01ff150200042903008007'],
        ['01129101110f04c0c00ffe1f047ffe0403010140', '8d1401129101110f04c0c00ffe1f047ffe0403010140', '011991011166100604e0e0807f0308070606047a0207e01c020288', '012a9101116621031f12047a0207e009170481141f0808ff02810248c00f040808ff02810248c00f1c020288', '2f0111', '14020103150111'],
        ['0115910111660c0602e00803060b047a0207e01c020288', '910403020040', '91062a0111100104', '910c0d011109030200ff1e0207e0', '910f0d0111220481fe08fe2b04c0002008', '01109101110b01082108020f0f0210030881'],
        ['01149101110f04c0c00ffe0e0302200127040810e3c0', '920711030403047fff', '1d01111402040411020404', '0117910111660e020c01060404080820027a0207e01c020288', '020111', '040111'],
        ['050111', '060111', '090111', '0a0111', '0b0111', '0c0111'],
        ['0d0111', '0e0111', '0f0111', '160111', '170111', '200111'],
        ['250111', '290111', '2a0111', '2d0111', '2e0111', '950111'],
        ['210411223344', '1206112233445566', '0106020111130120', '920719039003047fff', '010791011128027f20', '01079101111a028020'],
        ['0107910111070215ff', '010702011116020f81', '0108020111120301ff7f', '010a9101112c01ff17027f7f', '010b9101112c01ff0403c0e010', '010b9101110502010825026be0'],
        ['910f0d0111220481fe08fe180408078120', '010f910111660604047a0207e01c020288', '010b9101110502010825026be01402020426020204', '0117910111660e020c03060404080820027a0207e01c020288', '0118910111660f0602e008030906047a0207e00101081c020288', '0118910111660f0602e008060906047a0207e00101081c020288'],
        ['011b91011166120602e008030c0e048181f08006047a0207e01c020288', '01329101116629031d02047a0207e00481141f0808ff02810248c00f040808ff02810248c00f028200066601100201101c020288', '', '920719039003047fff921423080f0003620f207ffe92080f0003620f207ffe'],
    ]),
    ('regrsp', [
        ['00011e6b1503130e0108070208e00206001000f0ff080302e0ff30021122180107', '002b03112233', '008d0402810107110104028101071a0111', '0007021122', '00010b300211221901fe0c020101', '00300211221482000c0204fe0802001404fe080200'],
        ['00010b1a0111290101050303f020', '0001216b1803160a062080f0007f00080895020381080203810302e0ff30021122180107', '00921c0404812000f06e140508020301fee0047f816e08020301fee0047f8120060404812000f0080111', '001b0111', '00910f0f01110a02f0c013010f1d03a88110', '00280111'],
        ['008f0200f018060381ff400740070111', '0001166e14031201011106810c940420801001060420801001', '0001166b0d030b0b050f030480801002010730021122180107', '001f0111', '00010a0601111202027f1f01f0', '00010b8f0200f007011123020001'],
        ['00011a6b11030f0f030480800c82000616017f0c017f30021122180107', '0001091a01111001402e01fe', '00010f6b0606040302e0ff30021122180107', '0001156b0c030a1304070208e00302e0ff30021122180107', '008f041f810111', '000106010111250103'],
        ['0092030e01112a0111', '0001071a01112b020120', '00000111180402022080050402022080', '008d04028101070107028101072c01ff1a0111', '00db062002020281f001062002020281f0040111', '00920e6e060404812000f01c047f1000e020060404812000f0080111'],
        ['000a0111', '000b0111', '000d0111', '000e0111', '000f0111', '00150111'],
        ['00160111', '00170111', '001c0111', '001d0111', '00240111', '00290111'],
        ['00900111', '00940111', '00950111', '000103090111', '0092032a0111', '000103280111'],
        ['000103260111', '000103080111', '009205110302c007', '00140501031a0111', '00180501031a0111', '0001056e03010111'],
        ['001206112233445566', '0091060f01112d0107', '0091060f0111210103', '0001061a0111150103', '0001071a011116023a07', '0091070b01110a02f0c0'],
        ['0001071e0211221901fe', '000108010111140380fe07', '00010906011127040381e004', '0001091a01112901010d0104', '00910a0f01110a02f0c0170140', '00010f6b0605040302e0ff30021122180107'],
        ['0001116b08050601040302e0ff30021122180107', '00911166030f01116d820008060204026d0210e0', '0001116b08060605040302e0ff30021122180107', '00911766030f01116d82000e06080104c0e0c0030fff6d0210e0', '00911766030f01116d82000e06080204c0e0c0030fff6d0210e0', '0001186b0f030d8f061001408f01400f0304808030021122180107'],
        ['00011b6b120310080895020381080203810d040302e0ff30021122180107', '00011f6b160314080895020381080203811204e001e0040302e0ff30021122180107', 'b1f7ed', '009606112233445566', '008d1b02fe800402810107f004028101071a80071a11'],
        ['0001206b1703150e0108070208e009080206001000f0ff080302e0ff30021122180107'],
        ['0001071a011103020007'],
        ['00030111'],
        ['00060111'],
        ['00090111'],
    ]),
    ('repreq', [
        ['d5040702fe0201080502fe0206022020b1f7ed', 'd5040702fe0201090702fe020303ff035ab1f7ed', '01150401c07f0206ffe0088080041d06ffe008808004b1f7ed', '01150702fe0201040702fe02b1f70401c07f0206ffe0088080041d06ffe008808004b1f7ed', '01150702bb0808030720c0c60f40fe0201040702fe02b1f70401c07f0206ffe0088080041d06ffe008808004b1f7ed', '01150702fe020201040702fe02b1f704bac07f0206ffe0088080041d06ffe008808004b1f7ed'],
        ['', '0106ffe0088080041d088080041d06ffe008808104b1f7f7ed'],
    ]),
    ('reprsp', [
        ['06070204040f010380d602030104020301930111', '010e06030408800202fe40040380e0fe08ff25060304088008ffb1f708ffb1f7ed', '0205a202fe040503050403930151', '050b0304088008ff05031002e025060304088008ffb1f7ed', '06010302930111', '01050503930111'],
        ['0401020206e0fe811040040a06e0fe81104004', '030906070204040f010380930111', '05060204ff80085125060304088008ffb1f7ed', '0503040111', '020204020b020402', '0302030207c0f0000111'],
        ['0205a202fe040503050503930151', '020302029301c004040702fec0c0000111', 'be060304f0f0101001060304f0f01010b1f7ed', '060702048e06e0fe01020401040f010380930111', '03030207c0d000010408800898030204feff25060311', '010d06030408800202fe400102102008ff25060304088008ffb1f708ffb1f7ed'],
        ['', '93011106032081012703208101', '0205a202fe040303050403010151'],
    ]),
    ('rescmd', [
        ['8d06810f00f040021506810f00f04002b1f7ed', '95810111', '', '8d16810f0040021506810f00f04002ac0400004000b1f7'],
    ]),
    ('rngreq', [
        ['001502c0b3940111912c9501e06e27031f0704e08002400a1492080131fe7ff00203fe05080131fe7ff00203fe0201080104a3084081', '001502c0b394011191189501e02e01071a0220400d040740feff070200030c028003', '001502c0b394011191329501e06e2d032508082c0240400802404013030281ca061492080131fe7ff00203fe05080131fe7ff00203fe0104a3084081', '001502c0b3940111912c9501e06e270316041492080131fe7ff00203fe05080131fe7ff00203fe060d0401f00104a30840810202017f', '001502c0b394011191129501e00903fe0f0005030f03020f0308770f', '001502c0b394011191269501e06e2103190a1492080131fe7ff00203fe050801011191089501e00303fe31fe7ff00203fe0201080104a3084081'],
        ['001502c0b394011191149501e0020310fb040b0204ff230610fe00c00410', '001502c0b394011191189501e00903fe0f00080201802001c01d03fe20e01e020001', '0003810111', '001503010111', '00060111', '00150a0701110a02020f080102'],
        ['001502c0b3940111910e9501e01002030025010801027f08', '001502c0b39401118d12ff07030320ff03013208810f010010e040f02708ff07030320ff030191079501e02a02ff01', '001502c0b394011191279501e06e22031a0d02807f051492080131fe7ff00203fe05080131fe7ff00203fe0104a3084081', '001502c0b39401118f190b82000c2e04007f407f0b04007f407f91079501e02a02ff01', '001502c0b3940111911f9501e06e1a0104a30840810281110181080d028107010281070f01ff0201ff', '001502c0b394011191269501e06e210319061492080131fe7ff00203fe05080131fe7ff00203fe0b01fe0104a3084081'],
        ['000c0111', '00040111b5030301ff15030301ff', '00150b0701110903e00ffe060102', '00150c070111040401795a070b01f0', '001502c0b3940111910b9501e02b06027f07ff40f0', '001502c0b3940111910d9501e01201071a022040140110'],
        ['001502c0b3940111910d9501e01503e081032803202002', '001502c0b3940111910f9501e00903fe0f002c0210ff16017f', '001502c0b3940111910f9501e00903fe0f0018020180290101', '001502c0b394011191109501e02e01071f02204004010740feff', '001502c0b3940111910c9501e00903fe0f002d0200049303ff1020', '001502c0b394011191129501e00903fe0f002404010307762102ffff'],
        ['00070111', '00080111', '000206112233445566', '000506112233445566', '009606112233445566', '00150c0701110903e00ffe05020408'],
        ['001502c0b394011190069501e02e0107', '00150e0701110903e00ffe020420e0fffe', '001502c0b394011191079501e02a02ff01', '001502c0b394011191089501e0110310fb04', '001502c0b394011191099501e01904e0810202', '001502c0b3940111910b9501e00903fe0f00060181'],
        ['001502c0b3940111910e9501e01201071a0220401c0208fe', '001502c0b3940111910f9501e00903fe0f002c0210ff170181', '001502c0b394011191109501e00903fe0f00080201800e020408', '001502c0b394011191109501e02e01071a0220402604fed3e07f', '001502c0b394011191129501e0680629010f68010f1201071a022040', '001502c0b394011191289501e06e23031b041492080131fe7ff00203fe05080131fe7ff00203fe0e03c0c0030104a3084081'],
        ['001502c0b394011191289501e06e23031b061492080131fe7ff00203fe05080131fe7ff00203fe01030b01fe0104a3084081', '001502c0b3940111912a9501e06e25051d031b041492080131fe7ff00203fe05080131fe7ff00203fe0e03c0c0030104a3084081', '001502c0b3940111912a9501e06e25031b041492080131fe7ff00203fe05080131fe7ff00203fe120302100006060104a3084081', '001502c0b3940111912c9501e06e27031f1004ff01f0070a1492080131fe7ff00203fe05080131fe7ff00203fe0201080104a3084081', '001502c0b394011191329501e06e2d03250a1492080131fe7ff00203fe05080131fe7ff00203fe8f810c2804c00ffe0f8f04c00ffe0f0104a3084081', '001502c0b394011191329501e06e2d03250a1492080131fe3ff00203fe050801fe7ff00203fe8f810c2804c00ffe0f8fff04c00ffe0f0104a3084081'],
        ['001502c0b39401119501e0', '001502c0b394011191079501e02a02ff019203ffff102603ffff10'],
        ['001502c0b394011191159501e02e01071a02204013037f81e0270403040081'],
        ['001502c0b394011191239501e06e1e0316091492080131fe7ff00203fe05080131fe7ff00203fe0104a3084081'],
        ['001502c0b394011191289501e06e23031b0c160a1492080131fe7ff00203fe05080131fe7ff00203fe0201080104a3084081'],
        ['001502c0b3940111912c9501e06e270316041492080131fe7ff00203fe05080131fe7ff00203fe0401f0060a0302fe7f0104a3084081'],
        ['001502c0b394011191169501e0020310fb040b0204ff0308f0a000817f07407f'],
    ]),
    ('rngrsp', [
        ['001d0cb10111a004100207100401e0', '00912c1502112265260e04f0e0f00002820008e502070302020703031202050303d07f8007060403c0087f020101ff', '001e09112a017f2b03030720', '001d0b9e020700010111af0203f0', '00911e6d82000a04036f08fe6d036f08fe1e01110c01f003020400080420007f00', '001e11112a017f1a0140140380fe073003e00808'],
        ['001e14111908812082078180fe010702c3080103080020', '0015021122', '001e1f110f0220ff05038107071c01001f0207029682000a1a037dfe7f96037dfe7f', '001d0db1011110020710ae04fee00402', '001b100201110102207f0601070504100407f0', '001d09010111970440f00820'],
        ['001d0a910111ac01800f020710', '00912215021122651c0e04f0e0f00003140f02c0200601020303d07f800c06b501400c0140', '001e07111b04008140041601fe240101', '001d059803190111', '001d06ad0411223344', '001d07a202f0e0990111'],
        ['001d0da701e09301110fff0207101a0481ff0080', '00913315021122652d0e04f0e0f00003250481102c060fdb8180027f04060fdb8180027f0303d07f800101ff0b820006c001200b0120', '001d059c03010111', '001d099f039101110f020710', '00910b150211220d01c0050210ff', '001e041128017f'],
        ['001d05a303190111', '001d059a03010111', '00b502fe801f02fe80960411223344', '001d0ea1011110020710aa02f0200401e0', '009117150211220e04f0e0f0002b080403f07f817f08000201c0', '001701119208f002e00f2002e003'],
        ['001d0d9d011110d607100304fee00402', '001e12110801fe0b01401d01ff92060898e02080fe', '001806112233445566e5087ffe027f078103011b087ffe027f07810301', '0091271502112265210e04f0e0f000061903120303d07f800101ff0a820006c001200b01200403200fe0', '00913015021122652a0e04f0e0f00003220303d07f8007060403c0087f020e0200000101ff090ca20480800003090480800003', '0021021122'],
        ['001d051903010111', '001d07b3011110020710', '00910b09011129030f08fe0f0100', '001e0d110202c00429030002f01701e0', '001b0d0a0111090202070b0404044080', '001d0db10111100207100304fee00402'],
        ['0091141502112210048040107f23080710e00040c00f81', '0007021122', '001d05b003910111', '001d06960411223344', '001d07190503032401f0', '001d0b9101110f0207101b020f10'],
        ['001d0bb10111100207101c020f81', '001d0b910111100207100202030f', '00910d150211221702040f2e03010ffe', '001d0d9101110f0207101a0408ff0080', '001d10b204fe811020b10111100207100401e0', '001e1111040307fec09181082102078191020781'],
        ['00911315021122650d0e04f0e0f00003051303037ff0', '00912015021122651a0e04f0e0f00003120303d07f800101ff0a820006c001200b0120', '001e07111601fe240101', '001b090201110801e00701fe', '001d0919070401f005020f20', '00910a150211221901fe120103'],
        ['00910b1502112214020081180120', '00910b0901110102fe8113020410', '00910d1e01110b02f0010404c00203c0', '001e0e111508810310c00faf7f7f0a01fe', '00910e150211220d01c006020f99250107', '00910f09011163040102fe8127040708bb04'],
        ['00910f81011163040202030001fe8127210208e0040708bb04', '00020111', '00030111', '00040111', '00050111', '00060111'],
        ['00090111', '000a0111', '000b0111', '000c0111', '00110111', '00140111'],
        ['0091031f0111', '001d03110111', '001b03030111', '00010411223344', '000d0411223344', '001d0519032401f0'],
        ['001d05190306017f', '000806112233445566', '001e06110d03010004', '0091070901112d02ff07', '0091070901112602ff03', '0091081e01110a03ff8010'],
        ['001e08111601fe03020107', '0091080901110703100f03', '001e09112a017f09030200ff', '009109110306ff4040c0ff07', '00910909011165040102fe81', '00910a15021122160481c040c9'],
        ['00910a150211220d01c02a01e0', '001b0a0201110102207f040107', '00910a1d02112210048040107f', '00910b1e01112c01f021038000fe', '00910b1a01110c01f021038000fe', '001d0b9e020700ab0111af0203f0'],
        ['00170111920af002e00f280481020080', '001e0e110f0220ff05038107070e020701', '00910e1502112210048040107f1c02800f', '001e0f112a017f1a0140120637c008087f01', '001e0a1194020101020303040202c00429030002f0', '0091181502112265120e04f0e0f000030a0303d07f8010030101ff'],
        ['00912115021122651b0e04f0e0f00003130303d07f8012018107060403c0087f020101ff', '00912115021122651b06050103c0e010031203d07f80800101ff0a0f0006c001c00b0120', '00912215021122651c0e04f0e0f000061402120303d07f800101ff0b820006c001200b0120', '00912315021122651d0e04f0e0f00003150303d07f800101ff0b820006c001200b01200d015f', '001e1f1193010f9008010240c002408007400f0220ff05038107071c01001f02029682000a1a037dfe7f1196037dfe7f', '00080111'],
        ['001b03000111', '00910a1e01110c01f003020080', '001e0a1195020101020303040202c00429030002f0'],
        ['001f100201110102207f0601070504100407f0'],
        ['001e13110202c0041808088008c010207ff006028001'],
        ['00912015021122651a0e04f0e0f00002120303d07f800101ff0b820006c001200b0120'],
        ['00913015021122652a0e04f0e0f00003220303d07f8007060403c0087f020e0200000101ff080ca20480800003090480800003'],
        ['001d0619040202107f'],
    ]),
    ('sbcreq', [
        ['97021122', '191f1109080f810706032f20030502ff200102fe81040408038010060402fe0f9e', '980111', 'a00111', 'ad0111', 'b10111'],
        ['9e0111', 'ae021122', 'ac0111', '9c021122', '9f021122', 'a2021122'],
        ['9a8103110311', 'a3021122', '4e080700021080007ff019080700021080007ff01c0111', '9d0111', 'aa0111', 'af0111'],
        ['b30111', '030411223344', '010111', '040111', '100111', '1a0111'],
        ['1b0111', '960111', 'a70111', 'b20111', '02021122', 'b003112233'],
        ['19121109080f810706032f20030502ff200301f0', '930111', '19121109080f810706032f20030502ff200201f0', '0f0111', '110111', '990111'],
        ['a10111', 'ab0111', '', 'b1f7ed'],
    ]),
    ('sbcrsp', [
        ['97021122', '191f1109080f810706032f20030502ff200102fe81040408038010060402fe0f9e', '980111', 'a00111', 'ad0111', 'b10111'],
        ['9e0111', 'ae021122', 'ac0111', '9c021122', '9f021122', 'a2021122'],
        ['9a8103110311', 'a3021122', '4e080700021080007ff019080700021080007ff01c0111', '9d0111', 'aa0111', 'af0111'],
        ['b30111', '030411223344', '010111', '040111', '100111', '1a0111'],
        ['1b0111', '960111', 'a70111', 'b20111', '02021122', 'b003112233'],
        ['19121109080f810706032f20030502ff200301f0', '930111', '19121109080f810706032f20030502ff200201f0', '0f0111', '110111', '990111'],
        ['a10111', 'ab0111', '', 'b1f7ed'],
    ]),
    ('ucd', [
        ['0000000000b112ff0f400f40040101150803000881107f040f2408ff0f400f40040101990111', '0000000000c403112233', '00000000a3011100c403000000970111112233', '0000000000c8810111', '0000000000020111', '0000000000030111'],
        ['0000000000040111', '0000000000050111', '0000000000070111', '0000000000080111', '0000000000960111', '0000000000970111'],
        ['0000000000980111', '00000000009a0111', '00000000009b0111', '00000000009c0111', '00000000009d0111', '00000000009e0111'],
        ['00000000009f0111', '0000000000a00111', '0000000000a10111', '0000000000a20111', '0000000000a30111', '0000000000a40111'],
        ['0000000000aa0111', '0000000000ab0111', '0000000000ac0111', '0000000000ae0111', '0000000000b00111', '0000000000ba0111'],
        ['0000000000bb0111', '0000000000bc0111', '0000000000bd0111', '0000000000be0111', '0000000000bf0111', '0000000000c00111'],
        ['0000000000c10111', '0000000000c20111', '0000000000c30111', '0000000000c60111', '0000000000c70111', '0000000000c90111'],
        ['0000000000ca0111', '0000000000b1080000000000c60111ff0f400f400401012408ff0f400f40040101990111'],
    ]),
    ('type1', [
        ['2a32b57908', '3a07f97f21', '1404fff002', 'e13b032e11', 'f032b5792a', ''],
        ['d8017f8ef7'],
    ]),
    ('type2', [
        ['4bf87b0fb6', '0d604931ad', 'd9a5ae9dde', '426e490db1', '859f7f9755', ''],
        ['935d76fa1f', '14d58d145a', 'c808c02003', '1102fff00f', '1a04a495b9', '070fc18b66'],
        ['d6bc19b204', '0cd1fba8b0', '9b0101ca3b', '0f08b1f7ed', '3fe77dcad6', '4d3a154e25'],
        ['5d8fbde0ba'],
    ]),
    ('gmh', [
        ['a08805dd07e007022b03e0070801030301e0020101e002010204', 'a08cde230d021a970301b5', 'a08805dd03e005020b03e007020403e00702180220f006', 'a08805dd03e007020b03e0070801031301e0300381c00f02010204', '1004acaf6c2c7c329908222b0e9863b0dce0c8e92c6f', '88a0010b03440702bcb5de2c6f230702bcb5de2c6f23'],
        ['a0e0de230d7f020301de23021a01030301e00221e020ed', '887208100710078003200f2c802b3d7d83bec60eca13166a4f', 'a08805dd03e007021b03e0078101', '88720810078003020f2c802b3d7d83be460eca13166a4f', '88f03d7d1d020804831e04dc0140e0882b3d7d83882b3d7d83be46810eca13166a4f', '8a2075f6b588'],
        ['00a0b5de239c8500a0b5de239c85f870b22a09a975', 'a000b508b50f05061e060301f0100001050240a9b50f0506085640a94040a94081', '8800f9210303811004fe0c02810001e0ed02070725032b640805810810fff002e0017d83be460eca', '8d145a8b4f994f', '39a0b5de239c85f870b22a09a975', 'a0e0de230d7f020301de23ee040ff31003feff2401021a01030301e00221e022ed'],
        ['a08805dd03e007020a03e0070204', 'a08805cd03e007020e03e0070204', 'a08805dd03e007020b03e007022403e0070204', 'a08805dd03e007020b03e0070801030701e002010204', 'a08805dd03e0073d1c020b0fe00702240204e0070204', '8872080810078003200f2ca9802b3d7d83be460eca13166a4f'],
        ['a000b508b50f0506170240a9b50f0506080240a94040a940a9', 'a08805dd03e007020b0203e00b03a0250b03070801030701e0e0020101030301b5be01031201b53e', '9498a996638e2568adaba4ea', 'a08805dd03e007020b03e0070801036501e002010204', 'a0e0de230d7f020301de23021a01030301e00221e02021e020ed', 'a0e0de230d7f020301de23021a01030301e00221e020be460eca13166aed'],
        ['209a00a602fe018c012b0e98b0dc09c8e92c6f051f08e020ff0f020fe000f6b588'],
        ['a0b5080f0596018125220601020fa940', 'a001de230d021ab104070002e01a035901b5f0050401de230d0f01e002000e030220010190', '887ffe1e0808f001e00e030230ed0702', 'a025010b03a0250b03e007020401030303e0070200b523', '882b3d7d1d7b044010ffc00208048388e13b032b3d7d83882b3d7d83be46810eca13160703100881', 'a0b5de230d0209b6ed0f01250601e0ed020706080f01e0ed020706080f07a802ff810f1a00030800'],
        ['a001de230d021aa001de230d021a9e01041a030301b5f0050401de230d0201e002000e0302200101', 'a001ce230d021a19020fc001030301b5ae0101f001030301403e050401019001', 'a0b5de230d0201e00e15022002090240203c040481c003ed', '882b3d1c068001052501f08d0f01107d8316460eca2201f01300166a4f', 'a0b528b50f7f2506010102', 'a065050b03e007020b2de00702'],
        ['a025010b03a02501030b03e0070225d302070301030b03e0070200b523', 'a0b5de2385b10304fe0d02d1ac0604a908e08010f0087f7f04f6040281f00001e0ed', 'a001de230d021a99020fc017027f2001030301b5be01031001b53e05040101019001', 'a001de230d021a191a19020fc001030301b5b001c804fe0fe0010301030301b5b0010313', 'a0b508b50f05040506010240a9b7a9', 'a0b5de2340020924040703f0fee02201fe2307020d4009e0ed'],
        ['a0b5de230d023fe0ed', '84b5de2302000f9c85f870bc04', 'a0b50808b50f050507010240a940a9', '8823223d1c068001100101f07d8316ae460eca13166a4f', 'a0b5de80021010239c85940320f0fff8708a209af6b5b22a09a97580', 'a001de230d021a1b020fc001030301b5f001030301b53e050401019001'],
        ['a0b5de230d02310d0231e016080220080f81070f080e20030220087002ed', 'a0b5de230d02010daa010102010daa0101021102070801e042fe010801ed', 'a001de230d021a19020fc001030301b5b001030301b53e050401019001960101', '882b3d7d0d01101d930203070208070100048388e13b03293d7d83882b3d7d83be', '882b3d7d2604100457e01d02080483882b3d7d83882b3d7d83be46810eca13166a4f', '2001de230d021a1a030301c904030308fab5f0050401de230d0201e002000e030220010190'],
        ['88f9210303811004fe0c02810001e0ed02070725032b640805810810fff002e0017d83be460eca02', '88f9210308811004fe41fe4102810001e0ed02110201040007060815807d8316ae0408158004ef01', 'a001de230d021a1c01de230d021a9e01041a030301b5f0050401de230d0201e002000e0302200101', 'a0b5de3e400209e0230c0209020903e0ed', 'a01dde23400201e0231101040c0209e0ed', 'a0b50875b50f05060a0240c00d02fea940'],
        ['2003de230d02071a030303b5f00504ff0101', 'a0b5de230d0209002b20030220081e01e0ed', 'a0b5de230d0201e0ed0201e00401e0a10101ed', 'a0b5de23400209e023260640c0e000020f2d0209e0ed', 'a0b5de230d0209e0ed0a030ffb08070218021003feff240100', '882b3d1c0680011029013d95030110811c068001102901f07d8356ae460eca13167a4f'],
        ['8809002b1e', 'a0b50504ff0240a9', 'a0b5de230d0241e0ed', 'a0b508b50fc00401610220f0050609024040a9', 'a0b5de23400209e023290209e0130300f0e0ed', '882b3d7d1d020804831e04dc0140e0882b3d7d83882b3d7d83be46810eca13166a4f'],
        ['882b3d7d190208048388e13b032b7d83802b3d0201e0ed7d83be46810eca1313166a4f', '882b9908222b0e98b01e08070202021003070202021003ee070ff3100307feff2401003d7f83be42', '887f001e08080702', 'a00f10a00fb50504030220ff', 'a0b508b50f05060d02fea940', 'a0b508b50f05060c02fea940'],
        ['a0b508b50f0506080240a940a9', 'a0b508b50f0505ff0240a940a9', 'a0b508b50f0705060c02fea9c0', '84b5de2302000f9c85f8700404', 'a0b5de230d0209002b1f01e0ed', 'a0b508b50f050506010240a940a9'],
        ['a0b5de232302000f9c85f870ac04', 'a0b50807b5080506090240a915a9', 'a0b5de232302000f9c85f870a204', 'a0b5080f05960181250601020fa9', 'a0b5de232302000f9c85f870ae04', 'a0b5de232302000f9c85f8709d04'],
        ['a0b508b50f05050206010240a940a9', 'a0b508b50f05250206010240a940a9', 'a0b50808b50f040507010240a940a9', 'a8b508202f05070216010240a940a9', 'a0b5de23400201e0232d028009e0ed', 'a0b508b52f05050216010240a940a981'],
        ['a0b5de230d0201e00e20030220087002ed', 'a025010b03a02501030303e0070200b523', 'a0b5de230d0209b6ed0b010f1a03030800', 'a01dde23400209e0231101040c0209e0ed', 'a0b5de230d0201e00e13022002db024020', 'a001de230d021a11020fc001030301b5b0'],
        ['a025010b03a02501030203e0070200b523', 'a0b5de230d0209e00e2a030220887002ed', 'a0b5de550d0201e00e030220021f03fe08feed', 'a0b5de230d0201e0020e0302200e03022002eded', 'a025010b03ff01ffa02501030b03e0070200b523', 'a0b5de2323020085f8708a209a0f9c24010785f870'],
        ['a0b5f00504ff0103ff070108140202018102a940a9', 'a0b5f00504ff0103ff070108990202018102a940a9', 'a0b5f585b10304fe0d06d1087f7f04fe0402810001e0ed', 'a0b5f00504ff0103f00504ff0103ff0008810240a940a9', 'a0b508b50f0506170240a9b50f0506080240a94040a940a9', '882b3d1c0680011001100101f07d8316ae460eca13166a4f'],
        ['a0b5de230d0201e00e9a04e08102001502200209024020ed', '882b3d1c0680011001101001f07d8316ae460eca13166a4f', '882b3d1c068001100110d301f07d8316ae460eca13166a4f', 'a0b5de230d0201e00e3404e08102001502200209024020ed', '882b3d1c0680011001100801f07d8316ae460eca13166a4f', 'a001cc030f2007de230d021a1a030301b5f0058bff01019001'],
        ['a0b5de230d0209b6ed0f0125060f07a802ff810f1a00030800', 'a0b5de230d020902002b08090200d1030710812b801f01e0ed', 'a025010b03a025010301030b03e007f825010b03e0070200b523', '882b3d7d1d02080483882b3d7d83882b3d7d83be46810eca13166a4f', '882b1e0807020f021003feff2401003d7d83be460eca4b166a4f4b166a4f', 'a0b5de550d0201e0232302000f9c85f80e030020021f03fe08feed5f03208010'],
        ['a001de230d02070906010fdaf001ff1a1a2201810f0301b5f00504ff01019001', 'a0b5de230d0206800101e00e15024302fefe20150220020902402004040481c0ed', '882b3d260404100457e01d02080483882b3d7d83882b3d7d83be4681810eca13166a4f', 'a0b5f00504ff0107020a03e00703ff070108810340a90108810340a940a99f03001080', '882b2401003d7d83be46c30203fef608810fff08040f100f0eca4b166a4f4b166a4f08ff020110', 'a0b5de230d0209b612020402ed0f0125060f2708c0100102e007000407a802ff810f1a00031800'],
        ['88f9210308811004fe0402810001e0ed0216070725032b640807810810ff02e0013d7d83be460eca', '88f9210308811004fe4102810001e0ed021102040007060815800408158004ef010340040725032b', 'a0b5de230d0209b6030301b5f00504ff01010112020402ed0f0125060f2708c0100102e007000407', '043b043b032e', 'a0b5de231902040015060001', 'a0b54008e00f05061d02fea940'],
        ['a0b5de23400209e0230d0209e0ed', '882b240140083d7d83be460eca4b166a4f4b166a4f', 'a0b5de2340020924041703f0fee02307020d4009e0ed', 'a0b5de2385b10304fe0d02d1087f7f04fe0402810001e0ed', 'a0b5de08080702fe0480030404e0230d0209b6ed0b010f1a03030800', '882b1e08070218021003feff2401003d7d83be460e294b166a4f4b166a4f'],
        ['882b3d1c068001f0050101f08d0f01107d8316460eca2201381300166a4f', '882b3d7d1d0208048388e13b032b3d7d83882b3d7d83be46810eca13166a4f', '882b3d7d1d0208048308b50f0505060140a9405b88e13b0b2b3d7d83882b3d0083be46810eca1316', '88f9210308811004fe0402810001e0ed02070504ff0240a9060815800408158004ef010340040725'],
        ['882b1e07021b0308070202021003c0feff2401003d7d83c0460eca4b166a4fb612020402ed0f'],
        ['a001de230d021a19020fc001030301b5b001039a03e003810301b53e050401019001'],
        ['a0b5de2385b10304fe0d02d1ac0810ff02e0013d7d83be4604a908e08010f0087f7f04f6040281f0'],
        ['a001de230d021a9e01041a030301b5f0050401de230d0201e002000e030220010190'],
        ['88f9210308811004fe0402810001e0ed0207aa010f060815800408158004ef010340040725032b64'],
        ['a0b5de230d02061a0101e00e15024302fefe20fe0c02810001e0150220020902402004040481c0ed'],
        ['a001de230d021a1a027ffeaa02801001030301b5f00103a20401b5f005f0ff01019001'],
        ['a001de230d021ab2030301b5f001030301b5f00504ff0101019c0240ff'],
        ['882b1e08070207021003feff2401003d7d83be460e294b166a4f4b166a4f'],
        ['a001de230d020401030301b5f00103030301b5f0052b3d7d83882b3d7d8304ff010101'],
        ['a001de230d020001e0ed0216070725032b1a19020fc001030301f5b001030301b53e050401019001'],
        ['a0b50504ff0212082010032b0ff0e00340a9'],
        ['a0b5de230d0201e00e2102e00103022002ed'],
        ['a0b7b5de23230200b22a09a90f9c85f80708702b'],
        ['a0b5f00504ff0103ff070108810340a90108810340a940a9'],
    ]),
    ('dlmapc', [
        ['00000000000000000001e73702fe0f028120000002fe0f0281ff0000000000000002000000000000000000800000000040000000000000000000c00003100000000000', '10000000000000000000000000000001ff19ff7f00000800000000040000000025029cc000000000000e08540600408108e0f0fe02c0e0040f81e000000000000000000000d6028140c0000000400000000020000000000000000000', '00000000000000000001ee0e08811008fee0c002e0000000044020e0be0600fe7f7f1003040000000000000000000000de0000000000000000000000000000000000000000000000000000000000000000000000', '00000000000000000001e70e007f03800f6002008c0204810ff000ff03812008fe00000000000000000000000000', 'f00115f707c008c0c00104b0000104047fb2000101047fb30820027fb30820024000ff017f20', '1508071048400000000000c07f0808ff0000000000000000000020730801fe08730820fe01e0f0ca06730703be409b40fe01047fb35e20024000ff40c044c04400f004000000000000000000'],
        ['150807c07f0808730801fe08730820fe01e0f0ca06730703be409b40fef101047fb35e20024000ff40c04400f004'],
        ['01150807c07f08120301fb0c02000f40c0000104'],
        ['150807c07f0808730801fe08730801fe01e0f0ca06730703fe409bf101c044072000f004'],
        ['01a8038108730801fe01e0f04040c044a4fe150807c000'],
        ['f00115080fc07f08c00015080015a815c00015a801040807c0190800ab027f10f081f07f027f10f0007f027f10f0000104bd0840e081f07fff40fe7f08c00001047f'],
        ['01150807c07f08120301f36240c0000104'],
        ['01150807c07f08120201f16240c0000104'],
        ['10150807c07f09120301ff40ff40f101e0e0000104000104'],
        ['f001150807c07f08c000010408bd088040e007f0ff40c0807f'],
        ['f00115080fc07f08c00005080015a815c00015a801040807c0190800ab807f107081f07f027f10f0007f027f10f0000104bd08402981f07ffe04ff40fe7f08c00001047f'],
        ['01150807c07f08c00001fc02004001fc02004004'],
        ['01150807c07f08120301f7ff02e0026240c0000104'],
        ['f00115f707c07f08c0000104b2000101047ff2000101047f'],
        ['f001150807c07f08c00015a801040807c0190800f081f07fff40fe7f08c00001047f'],
        ['150807c07f0808730801fe0873000801fe01e0f0f1b4b6060404e07f0281f0c01a00f004'],
        ['01150807c07f08120301f2067bfe2004ff0ff36240c0000104'],
        ['150807c07f0808730801fe08730801fe01e0f0ca06730703fe400f9bf140c04400f004'],
        ['00000000000000000001e70e007f03200740800f60f002008c0204810ff000ff03812008fe00000000000000000000000000'],
        ['01150807c03f08470301e9cdc03f08470301e9cd5a0803e00fc00710260847e0ae070781f020200740c0000104'],
        ['01150807c07f08c00001e0f001fe04'],
        ['01150807c07f08c00001f802004001fc02004004'],
        ['01150807c07f08c00001fa02804001fc02004004'],
        ['f0a2067f0110fe01c101150807c07f08c0000104bd0840e007f0ff40c0807f'],
        ['01150807c07f08c00001f008c0000104'],
        ['f001150807c07f08c0000104bd088040e007f0ff40c0807f'],
        ['f0a2067f0110fe01c101e80807c01404004040c07f08c000120301ff62400304bd0840e007f0ff010140c0807f'],
        ['00000000000000000001e70a0f00000000987084bfaf67200000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000'],
        ['10000000000000000000000000000001ff19ff7f00000800000000000025029cc0000000000000000000000000000000d6028140000000400000000020000000000000000000000000000000'],
        ['100000000000000000000000000001ff19ff7f000008b700040000000025029cc0000000000000000000000000000000d602814000000040080000002000e20803087fc003c50100000000000000800000000000000000'],
        ['01150807c07f08120301e60c02000f40c0000104'],
        ['01150807c03f08470301ffcd0803e00fc00710260847e0ae070781f0f0200740c0000104'],
        ['0115080807c07f08120301fb40c0ff40c0100104'],
        ['00000000000000000001e70e007f03800f00f000ff0f00'],
        ['00000000000000000001e70e007f03800f6002000df000ff0f03812008fe00000000000000000000000000'],
        ['01150807c07f08c00001f402004004'],
        ['01150807c07f08120301ff6240c0000104'],
        ['01150807c07f08c00001f85a004001fc02004004'],
        ['341ac62500f6000000007f00000000000000000000000000'],
        ['01150807c07f08120301ed028020f3624001ad028020f36240c0028020f36240c000016240c0000104'],
        ['00000000000000000001f7f21408815120f0080f0f03f00f0e0110040308fe071603070f070240fe01f07f1001fffeff04031081fe08040000000000000000000000000000000000000000000000000000000000000000000000000000000c03040f81000000000000000000000000000000000000000000000000'],
    ]),
    ('harqmap', [
        ['2f85d908802f85d98081800ffe08f0027f800ffef0027f800ffe0807027f038ed2cc8d7e06c08110e0007f3ae08c6d9a', '000809c40f04fe070b8001ff020000001301ea00a80681037fff400700000000000000000000', 'a742ffe4149e08e04004c07f0f03f0bebcd11624a07465', 'b1c2fc7fb1c2fc7f3a0fe529163a0fe52916daaee52916e52916daaee52916daae4bb0020701f87b0f', 'b1c2fc1a0fe5298603ff007f9619021002daae4bf87b0f00', 'a72301c3ffe4149e08e04004c07f6b6b03f004c07f6b03f0bebcd11624a074037fff0f65'],
        ['00050e1810fe20fe7f02002081800000000000010004000000', '2f858ed2cc8d3ac08cfe858ed2cc0d3ac08c03080210027f80810f846d98', 'a702e414be42e414be23bcd11624a06465', 'b1c2fc1a0fe5298603ff007f9640daae4bf87b0f', 'a742e414bebcd1168e031008e02414be4214be23a07465', '01010021ff03007fe096044081ff7f40fa817f00fe13027fc0000000000000000000000000'],
        ['2f858ed2cc8d7fc08c6d98', '2f858ed2cc8d7f548c6d98', '2f858ed2cc8d7f29c08c6d98', 'b1c2fc7f0fe52916daae4bf87b0f', 'b1c2fc7f49e52916daae4bf87b0f', 'b1c2fc7f1a0fe52916daae4bf87b0f'],
        ['b1c2fc1a0fe588080207c01040070380', 'b1c2fc801a0fe52996da26047f0226044002b7', 'b1c2fc801a0fe52996da26047f02a6044002b7', '2f85d908800ffe08f0027f078ed2cc8d3ac08c6d98', '01010021ff03007f603cfa817f00fe13027fc0000000', 'b1c2fc801a0fe52996da26047f027ff68c6d9826044002b7'],
        ['a742ffe4149e08e04004c07f3b5603f0bebcd11624a07465', 'b1c2fc7f7708f00f40ff0f1007081a0fe52916daae4bf87b0f', 'b1c2fc7f3a0fe529163a0fe52916daaee52916daae4bb0020701f87b0f', 'a742ffe4149e08e04004c07f6b6b03f004c07f6b03f0bebcd11624a074037fff0f65'],
    ]),
    ('phy', [
        ['27fe53266e490db138', ''],
    ]),
    ('dlmap', [
        ['5a0000010102000000f00004e737047dfe553960720c2f89960d6364d917e37c43a2c92485e10ce0b3403072809283dbe0e761041fcb9bea4018db79a60000000000000000', '000000e00101025600007938ee03080107000e00ffb508fec0ce000f0ff010027f3080e000e0000000000000000000', '000000010102000000000104e737047d55390000000000080010000001006073852f89960d2a63640000002017e3807c43a241c92485e10ce0b3b53072809283dbe0000000', '20c21041890eb01e8c0917d2960304ffffb803f0f008f60f935d76fa', '0000000101020000007902fe030001040e00ff027f0000f6400000', '000000e00102000000f00004e737f27dfeff0256007938ee030801070efd60fbb5087ec0ce000f0ff010027f3080e00000000101e000000000000000000000000000000000'],
        ['000000010102000000000104f47f1600000000', '260380ae20d4f32147a9b294f32147a9b29498a996638e', '5ac200010102000000f00004e737047dfe553940720c2f89960d7364d917e37c43a2c92485e10ce0b3403072809283dbe0e761041fcb9bea40ff18dba60000000000000000', '5a0000010102000000f00004e737047dfe55396072852f8996030d6364d917e37c43a2e024e10ce0b3403072809283dbe0e761081fcb9bea4018db79a60000000000000000', '000000e00101020000007902fa03001fcb9bea0000000000', '20101041890eb01e8c0917daf60f7f5ddaf60f03935d76fa'],
        ['000000e0010102001000f07902fe03000147080e00ff7f7f0000b100008100', '20c21041890eb01e8c0917d2f60f205d76fa', '000000010102000000000104f4160f00000000000000000000000000000000000000000000000000000000000000000000', '260380ae20d401214720a9b294f32147a9b294020098a996638e9608ff407f01e00ff0406c0104000000000000000000', '000000e00101020000007902fa030000', '000000e00101025600007938fe03000107080e00ff027f8000'],
        ['20c21004890eb0045d761e8c0917d2f60fa58104040180fe005d76fae0'],
        ['000000010102000000000104e737047d553900000000000800000000006072852f89960d2a63640000002017e3807c43a241c92485e10ce0b3b53072809283dbe000000000'],
        ['20c21041890eb01e8c0917d2f60f045d76fae0'],
        ['260380ae20d4012147a9b294f32147a9b29498a996638e6c0104'],
        ['20c21004890eb0045d761e8c0917d2f60fa58104040180fe005d76fae0e800'],
        ['000000010102000000000104f416'],
        ['000000e00101020000007902fe03'],
        ['bbf32147a9ff9498a99647a9ff9498a99663'],
        ['bbf321cc02f0ee088047b29498a996638ef000'],
        ['000000e00101025600007938fe03000107080e00ff027f80e0'],
        ['000000e00101025600007938ee03080107000e00ff7f307b80e000feb1e000000000000020000000'],
        ['000000010102000000000104e737047d55396072852f89960d2a6364d917e3807c43a241c92485e10ce0b3b53072809283dbe0e761041fcb9bea4018db79a6778e402000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'],
    ]),
    ('ulmap', [
        ['1f967ce4ea598652b8bf80695e1002c9eac0f1b70380d880b803800207eac0867bc08652d59f0495a6695e1004ff09', '000100000010040001b31420401504fe80fe0002fefe807f0440030fa300f0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000', '1f967ce4e452598652d59fea59e4ea59994f8652d59f04956752d59f9f0495a615c5695e10a20303c0029dff09', '1f967cc5b2e4ea460603207f07ff7c598652d5eb0280feb7038002079fea079fea598652d59f0495a6695e1004ff09', '000100000010040001b708b7088002011040ff10020000000f04fe4081ff000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000', '1f967ce4ea598652c0d5b803800207079f0803ff40035e10ea598652d5390495a6695e1004ff09'],
        ['0001000000100400012814407f7f20fec0e00210206108feff8000000010040001b402408020008020000000e0ff0081000000000000000000fe0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'],
        ['000100000010040001b7088012011206027fc0847ff01040ff100200000000000000000000000000000000000000000000000000000806407f080040800000000000000000000000000000000000fe0800000000000000000000000000'],
        ['1f8a7ce4ea598652d5becd0620e4ea598652c0d5b8038080047f01fe03800227eac0f10380d8c0f10380d880b803800207eac08652c08652d59f0495a6695e1004ff1f09'],
        ['8196ffe4ff59a352d5f3cc01249f049515695e109dff09'],
        ['1f967ce4ea598652d5b803800207eac0f10380d880b803800207eac08652c08652d59f0495a6695e1004ff09'],
        ['1f967ce4ea598652d50c060007030f0f20b803800207eac0e4ea598652f10380d880b803800207eac0867bc08652d59f0495a6695e1004ff09'],
        ['1f967ce4ea598652c0d5b8038002079f5e10ea598652d5390495a6695e1004ff09'],
        ['1f967ce4e452598652d59fea59e4ea598652d59f04958652d59f04958e0610030408f00fa615c5695e10a20303c0029dff09'],
        ['000100000010040001b4408000b1f704070000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'],
        ['0001000000100400012314fe027f0781030181200780087f7f1007ffc0fe0f000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'],
        ['1f967cc5b2e4ea540603207f07ff7c598673d5eb46060320028020b703800207f9ea079fea598652d59f04950308695e10d004ff09'],
        ['000100000010040001b31420407f04fe80fe0002fefe807f0440030fa300f0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'],
        ['8196ffe4ff59a352d5f3cc01209f049515695e109dff09'],
        ['1f967ce4ea598652d5b803800207eac0f10380d880b803800207eac0867bc08652d59f0495a6695e1004ff09'],
        ['1f967ce4e452598652d59fea59e4ea598649017f52d59f04958652d59f0495a615c5695e10a20303c0029dff09'],
    ]),
    ('ucd_dl', [
        ['0000000000b112ff0f400f40040101150803000881107f040f2408ff0f400f40040101990111', '0000000000c403112233', '0000000000010111', '0000000000c8810111', '0000000000020111', '0000000000030111'],
        ['0000000000040111', '0000000000050111', '0000000000070111', '0000000000080111', '0000000000960111', '0000000000970111'],
        ['0000000000980111', '00000000009a0111', '00000000009b0111', '00000000009c0111', '00000000009d0111', '00000000009e0111'],
        ['00000000009f0111', '0000000000a00111', '0000000000a10111', '0000000000a20111', '0000000000a30111', '0000000000a40111'],
        ['0000000000aa0111', '0000000000ab0111', '0000000000ac0111', '0000000000ae0111', '0000000000b00111', '0000000000ba0111'],
        ['0000000000bb0111', '0000000000bc0111', '0000000000bd0111', '0000000000be0111', '0000000000bf0111', '0000000000c00111'],
        ['0000000000c10111', '0000000000c20111', '0000000000c30111', '0000000000c60111', '0000000000c70111', '0000000000c90111'],
        ['0000000000ca0111', '0000000000b1080000000000c60111ff0f400f400401012408ff0f400f40040101990111'],
    ]),
    ('dcd_dl', [
        ['000022020168150111', '00005108e0010410e0a1f0800108e0010410e0a1f080990111', '0000320111', '0000210111', '00002001002201002d0111', '02080881017f80ff0fff00'],
        ['0000020111', '0000030111', '0000040111', '0000050111', '0000060111', '0000070111'],
        ['0000090111', '00000a0111', '00000c0111', '00000e0111', '00000f0111', '0000110111'],
        ['0000130111', '0000140111', '0000160111', '00001f0111', '0000230111', '0000240111'],
        ['0000330111', '0000340111', '00003c0111', '0000940111', '00009a0111', '00000d06112233445566'],
        ['000036021122'],
    ]),
]
# ---END CORPUS---

GS = 6   # corpus entries per burst


def build_corpus():
    section('Field-guided corpus (management messages, maps, headers)')
    for target, groups in CORPUS:
        for g in groups:
            if target == 'phy':
                src = MS
                tl = b''.join(tlv(T_PHY, bytes.fromhex(h)) for h in g)
                add(eth(MS, m2m_tlvs([tlv(T_PHY, bytes.fromhex(h)) for h in g], nseq())))
                MANIFEST.append((len(REC), target, g))
                continue
            pdus = [target_pdu(target, bytes.fromhex(h)) for h in g]
            src = pdus[0][0]
            add(m2m_pdu(b''.join(p for _, p in pdus), src, nseq()))
            MANIFEST.append((len(REC), target, g))


MANIFEST = []


def build_late():
    section('Grant management sub-headers after the service flows (scheduling type known)')
    for g in (b'\x80\x00', b'\x4a\xbc', b'\x20\x00', b'\x0f\xff', b'\xff\xe0'):
        ul(gmh(0x1001, IPDATA, subtypes=0x01, subhdrs=g))


def build():
    build_mal_pre = None
    build_basic()
    build_headers()
    build_generic()
    build_aas()
    build_repro()
    build_epdu()
    build_corpus()
    build_late()
    build_mal()
    end_sections()


def main():
    build()
    os.makedirs(OUT, exist_ok=True)
    write_pcapng(os.path.join(OUT, 'wimax-coverage.pcapng'), CAPS['main'][0])
    write_pcapng(os.path.join(OUT, 'wimax-coverage-malformed.pcapng'), CAPS['mal'][0])
    write_pcapng(os.path.join(OUT, 'wimax-coverage-sched.pcapng'), CAPS['sched'][0])
    json.dump(MANIFEST, open(os.path.join(OUT, 'manifest.json'), 'w'))
    if VERBOSE:
        for k, (rec, sect) in CAPS.items():
            print(k)
            for s in sect:
                print('  %-45s frames %d-%d' % tuple(s))
            print('  total', len(rec))
        for m in MARKS:
            print('  mark %s frame %d: %s' % m)


if __name__ == '__main__':
    main()
