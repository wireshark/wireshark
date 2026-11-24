# Helper module for the wimax capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Frame-building helpers for the WiMax plugin coverage generator.

mkwimax.py inlines nothing from here at run time; this file is imported by
mkwimax.py and by calib.py (the TLV length calibration helper)."""
import struct

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
