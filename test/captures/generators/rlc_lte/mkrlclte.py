#!/usr/bin/env python3
# Generates test/captures/rlc_lte_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the RLC-LTE coverage captures: mkrlclte.py <outdir>.

RLC-LTE PDUs are framed over UDP (signature "rlc-lte", mode, tags, PDU) and
reached through the heuristic dissector rlc_lte_udp.  SDUs go on to PDCP-LTE
(SRB and DRB) and LTE RRC (CCCH, BCCH, PCCH).  All bytes are made up with
struct; the RRC messages are small encodings found by trial (they decode
cleanly) and carry no keys.
"""
import struct
import sys
import os


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def write_pcap(name, frames):
    """pcapng with two interfaces: 0 Ethernet, 1 Exported PDU (252).
    frames: bytes (interface 0) or (interface, bytes)."""
    def blk(typ, body):
        body += b'\0' * ((-len(body)) % 4)
        return struct.pack('<II', typ, len(body) + 12) + body + struct.pack('<I', len(body) + 12)
    out = blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    for lt in (1, 252):
        out += blk(1, struct.pack('<HHI', lt, 0, 65535))
    for i, fr in enumerate(frames):
        ifc, data = fr if isinstance(fr, tuple) else (0, fr)
        ts = (1700000000 + i) * 1000000
        out += blk(6, struct.pack('<IIIII', ifc, ts >> 32, ts & 0xffffffff, len(data), len(data)) + data)
    with open(name, 'wb') as f:
        f.write(out)


ETH = bytes.fromhex('020000000002020000000001')


def udp_frame(payload, sport=40000, dport=40001, src=(192, 0, 2, 1), dst=(192, 0, 2, 2)):
    udp = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
                     bytes(src), bytes(dst))
    ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
    return ETH + b'\x08\x00' + ip + udp


def ipv4_udp(payload=b'data', sport=5000, dport=5001):
    udp = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 7, 0, 64, 17, 0,
                     bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]))
    return ip[:10] + struct.pack('>H', csum(ip)) + ip[12:] + udp


# --------------------------------------------------------------- constants
TM, UM, AM, PREDEF = 1, 2, 4, 8
UL, DL = 0, 1
CCCH, BCCH_BCH, PCCH, SRB, DRB, BCCH_DL_SCH, MCCH, MTCH = range(1, 9)

RRC = {k: bytes.fromhex(v) for k, v in dict(
    mib='232ef1', si='39d1', paging='0a2f', ul_connreq='5ede61a634a9',
    dl_setup='75ca', dl_reconf='25ed0335', dl_release='2b5a5244', dl_infotr='0fd9',
    ul_infotr='4dd6', ul_reconfcompl='1654', dl_countchk='45cb',
    nb_mib='3b107aa1', nb_si='39d1', nb_paging='0be9', nb_ul_req='3e19', nb_dl_setup='36318f',
).items()}


def frame(mode, pdu, sn=None, d=None, prio=None, ueid=None, ctype=None, cid=None,
          extli=False, nb=None, order=None):
    """UDP frame with the RLC-LTE framing (tags in the order given)."""
    t = {}
    if sn is not None:
        t['sn'] = bytes([0x02, sn])
    if d is not None:
        t['d'] = bytes([0x03, d])
    if prio is not None:
        t['p'] = bytes([0x04, prio])
    if ueid is not None:
        t['u'] = struct.pack('>BH', 0x05, ueid)
    if ctype is not None:
        t['t'] = struct.pack('>BH', 0x06, ctype)
    if cid is not None:
        t['c'] = struct.pack('>BH', 0x07, cid)
    if extli:
        t['x'] = bytes([0x08])
    if nb is not None:
        t['n'] = bytes([0x09, nb])
    b = b'rlc-lte' + bytes([mode])
    for k in (order or list(t)):
        b += t[k]
    return udp_frame(b + b'\x01' + pdu)


class Bits:
    def __init__(self):
        self.v = 0
        self.n = 0

    def put(self, val, n):
        self.v = (self.v << n) | (val & ((1 << n) - 1))
        self.n += n
        return self

    def bytes(self):
        pad = (-self.n) % 8
        return (self.v << pad).to_bytes((self.n + pad) // 8, 'big')


# ----------------------------------------------------------- PDU builders
def lis_bytes(lis, ext15=False):
    """Extension part: E + LI per entry (11 bit pairs sharing bytes, or 15 bit)."""
    b = Bits()
    for i, li in enumerate(lis):
        e = 1 if i < len(lis) - 1 else 0
        if ext15:
            b.put(e, 1).put(li, 15)
        else:
            b.put(e, 1).put(li, 11)
    if not ext15 and len(lis) % 2:
        b.put(0, 4)
    return b.bytes()


def um(snlen, sn, fi=0, lis=(), body=b'', resv=0):
    e = 1 if lis else 0
    if snlen == 5:
        h = bytes([(fi << 6) | (e << 5) | (sn & 31)])
    else:
        h = bytes([(resv << 5) | (fi << 3) | (e << 2) | ((sn >> 8) & 3), sn & 0xff])
    return h + (lis_bytes(lis) if lis else b'') + body


def am(sn, fi=0, lis=(), body=b'', p=0, rf=0, lsf=0, so=0, snlen=10, ext15=False, resv=0):
    e = 1 if lis else 0
    b0 = 0x80 | (rf << 6) | (p << 5) | (fi << 3) | (e << 2)
    if snlen == 16:
        if rf:
            b0 |= (lsf << 1) | (resv & 1)
        else:
            b0 |= resv & 3
        h = bytes([b0]) + struct.pack('>H', sn)
        if rf:
            h += struct.pack('>H', so)
    else:
        b0 |= (sn >> 8) & 3
        h = bytes([b0, sn & 0xff])
        if rf:
            h += struct.pack('>H', (lsf << 15) | so)
    return h + (lis_bytes(lis, ext15) if lis else b'') + body


def status(ack, nacks=(), snlen=10, cpt=0, extra=b''):
    """nacks: list of sn or (sn, so_start, so_end)."""
    b = Bits().put(0, 1).put(cpt, 3).put(ack, snlen)
    so = 16 if snlen == 16 else 15
    b.put(1 if nacks else 0, 1)
    for i, nk in enumerate(nacks):
        more = 1 if i < len(nacks) - 1 else 0
        if isinstance(nk, tuple):
            b.put(nk[0], snlen).put(more, 1).put(1, 1).put(nk[1], so).put(nk[2], so)
        else:
            b.put(nk, snlen).put(more, 1).put(0, 1)
    return b.bytes() + extra


# PDCP SDUs
def pdcp_srb(sn, rrc, mac=b'\x00\x00\x00\x00'):
    return bytes([sn & 0x1f]) + rrc + mac


def pdcp_drb(sn, payload):
    return bytes([0x80 | ((sn >> 8) & 0x0f), sn & 0xff]) + payload


# ------------------------------------------------ MAC-LTE (Exported PDU) helpers
def exp_pdu(name, payload):
    n = name.encode()
    pad = (4 - len(n) % 4) % 4
    return struct.pack('>HH', 12, len(n) + pad) + n + b'\0' * pad + struct.pack('>HH', 0, 0) + payload


FDD = 1
C_RNTI = 3


def mctx(direction, rnti, ueid, sfn, sf, retx=None):
    t = struct.pack('>BH', 0x02, rnti) + struct.pack('>BH', 0x03, ueid) + \
        struct.pack('>BH', 0x04, ((sfn & 0xfff) << 4) | (sf & 0xf))
    if retx is not None:
        t += bytes([0x06, retx])
    return bytes([FDD, direction, C_RNTI]) + t + b'\x01'


def msch(direction, items):
    """MAC SDUs: items = [(lcid, body)]; the last subheader has no length."""
    hdr, bodies = b'', b''
    for i, (lcid, body) in enumerate(items):
        last = i == len(items) - 1
        hdr += bytes([((0 if last else 1) << 5) | lcid])
        if not last:
            n = len(body)
            hdr += struct.pack('>H', 0x8000 | n) if n >= 128 else bytes([n])
        bodies += body
    return hdr + bodies


def mac_frame(direction, rnti, ueid, sfn, sf, items, retx=None):
    return (1, exp_pdu('mac-lte-framed', mctx(direction, rnti, ueid, sfn, sf, retx) + msch(direction, items)))


class MBits:
    def __init__(self):
        self.bits = []

    def put(self, val, n):
        for i in range(n - 1, -1, -1):
            self.bits.append((val >> i) & 1)

    def bytes(self):
        b = self.bits + [0] * ((8 - len(self.bits) % 8) % 8)
        return bytes(int(''.join(map(str, b[i:i+8])), 2) for i in range(0, len(b), 8))


def drb_add(b, drbid, lcid, rlc=None, prio=None, pdcp=None):
    b.put(0, 1)
    for fl in [0, pdcp is not None, rlc is not None, lcid is not None, prio is not None]:
        b.put(1 if fl else 0, 1)
    b.put(drbid - 1, 5)
    if pdcp is not None:
        b.put(0, 1)
        b.put(0, 1)
        b.put(1 if pdcp == 'am' else 0, 1)
        b.put(1 if pdcp == 'um' else 0, 1)
        if pdcp == 'am':
            b.put(1, 1)
        if pdcp == 'um':
            b.put(1, 1)
        b.put(0, 1)
    if rlc is not None:
        b.put(0, 1)
        if rlc == 'am':
            b.put(0, 2)
            b.put(3, 6); b.put(2, 3); b.put(4, 4); b.put(1, 3)
            b.put(5, 5); b.put(6, 6)
        elif rlc in ('um5', 'um10'):
            b.put(1, 2)
            b.put(0 if rlc == 'um5' else 1, 1)
            b.put(0 if rlc == 'um5' else 1, 1); b.put(7, 5)
    if lcid is not None:
        b.put(lcid - 3, 3)
    if prio is not None:
        b.put(0, 1)
        b.put(1, 1)
        b.put(0, 1)
        b.put(prio - 1, 4); b.put(3, 4); b.put(2, 3)


def rrc_setup(drbs):
    """RRCConnectionSetup (DL CCCH) with DRB-ToAddMod entries."""
    b = MBits()
    b.put(0, 1); b.put(3, 2)
    b.put(0, 2)
    b.put(0, 1); b.put(0, 3)
    b.put(0, 1)
    b.put(0, 1)
    b.put(0, 1)
    b.put(1, 1)
    b.put(0, 1)
    b.put(0, 1)
    b.put(0, 2)
    b.put(len(drbs) - 1, 4)
    for d in drbs:
        drb_add(b, **d)
    return b.bytes()


FIRST, MID, LAST = 1, 3, 2      # framing info: first byte starts / last byte ends the SDU?
IP = ipv4_udp()


class Ch:
    """One RLC channel direction with its own RLC and PDCP sequence numbers."""

    def __init__(self, F, mode, d, ueid, ctype, cid=None, snlen=None, prio=None, extli=False,
                 nb=None, sn0=0):
        self.F, self.mode, self.d, self.ueid, self.ctype, self.cid = F, mode, d, ueid, ctype, cid
        self.snlen, self.prio, self.extli, self.nb = snlen, prio, extli, nb
        self.sn = sn0
        self.psn = 1

    def sdu(self, payload=None, rrc=None):
        """A PDCP PDU with the next PDCP sequence number."""
        n = self.psn
        self.psn += 1
        if self.ctype == SRB:
            return pdcp_srb(n, rrc or RRC['dl_infotr'] if self.d == DL else rrc or RRC['ul_infotr'])
        return pdcp_drb(n, payload if payload is not None else IP)

    def emit(self, pdu, **over):
        k = dict(d=self.d, ueid=self.ueid, ctype=self.ctype, cid=self.cid, prio=self.prio,
                 extli=self.extli, nb=self.nb)
        if self.snlen is not None and self.mode in (UM, AM):
            k['sn'] = self.snlen
        k.update(over)
        self.F.append(frame(self.mode, pdu, **k))

    def nextsn(self, n):
        s = self.sn if n is None else n
        self.sn = (s + 1) % (1 << (self.snlen or 10))
        return s

    def um(self, fi=0, lis=(), body=b'', n=None, **over):
        self.emit(um(self.snlen, self.nextsn(n), fi, lis, body), **over)

    def am(self, fi=0, lis=(), body=b'', n=None, **kw):
        over = {k: kw.pop(k) for k in list(kw) if k in ('d', 'ueid')}
        self.emit(am(self.nextsn(n), fi, lis, body, snlen=self.snlen or 10,
                     ext15=self.extli, **kw), **over)

    def status(self, ack, nacks=(), **over):
        self.emit(status(ack, nacks, snlen=self.snlen or 10), **over)


def build():
    F = []
    S = []

    def sec(name):
        S.append((len(F) + 1, name))

    def A(*a, **k):
        F.append(frame(*a, **k))

    sec('TM channels (RRC called per channel type), predefined data')
    A(TM, RRC['ul_connreq'], d=UL, ueid=1, ctype=CCCH)
    A(TM, RRC['dl_setup'], d=DL, ueid=1, ctype=CCCH)
    A(TM, RRC['mib'], d=DL, ctype=BCCH_BCH)
    A(TM, RRC['si'], d=DL, ctype=BCCH_DL_SCH)
    A(TM, RRC['paging'], d=DL, ctype=PCCH)
    A(TM, RRC['nb_ul_req'], d=UL, ueid=2, ctype=CCCH, nb=1)
    A(TM, RRC['nb_dl_setup'], d=DL, ueid=2, ctype=CCCH, nb=1)
    A(TM, RRC['nb_mib'], d=DL, ctype=BCCH_BCH, nb=1)
    A(TM, RRC['nb_si'], d=DL, ctype=BCCH_DL_SCH, nb=1)
    A(TM, RRC['nb_paging'], d=DL, ctype=PCCH, nb=1)
    A(TM, b'\x01\x02\x03', d=DL, ueid=3, ctype=SRB, cid=1)       # TM on an SRB: no RRC call
    A(TM, b'\x01\x02\x03', d=UL, ueid=3, ctype=DRB, cid=1, prio=4)
    A(PREDEF, b'\x11\x22\x33\x44', d=UL, ueid=4, ctype=DRB, cid=1, prio=16)
    A(PREDEF, b'\x11\x22', d=DL, ctype=BCCH_BCH)

    sec('UM 5 bit DRB: whole SDUs, extensions, segments with reassembly, SN gaps')
    c = Ch(F, UM, DL, 10, DRB, 1, snlen=5, prio=7)
    c.um(0, (), c.sdu())
    l1 = len(c.sdu())
    c.um(0, (l1,), c.sdu() + c.sdu())                       # one LI
    c.um(0, (l1, l1), c.sdu() * 3)                          # two LIs
    c.um(0, (l1,) * 3, b''.join(c.sdu() for _ in range(4)))    # odd number of LIs
    x = [c.sdu() for _ in range(3)]
    full = x[0] + x[1] + x[2]
    c.um(FIRST, (), full[:10])                              # SDU 1 in three pieces
    c.um(MID, (), full[10:20])
    c.um(LAST, (l1 - 20,), full[20:l1] + full[l1:])         # end of SDU 1 and SDU 2 whole
    y = c.sdu()
    z = c.sdu()
    c.um(FIRST, (), y[:12])
    c.um(MID, (l1 - 12,), y[12:] + z[:9])                   # ...and the first part of next SDU
    c.um(LAST, (), z[9:])
    # a segment that starts mid-SDU but has an LI at the end (first + two SDUs)
    u = c.sdu()
    c.um(FIRST, (3,), b'abc' + u[:10])
    c.um(LAST, (), u[10:])
    # SN gaps, repeats and wrap
    c.um(0, (), c.sdu(), n=c.sn + 2)                        # two missing
    c.um(0, (), c.sdu(), n=(c.sn + 1))
    c.um(0, (), c.sdu(), n=c.sn - 1)                        # repeated
    c.um(0, (), c.sdu(), n=31)
    c.um(0, (), c.sdu(), n=0)
    # segments broken by a gap: the reassembly is dropped
    c.um(FIRST, (), c.sdu()[:10], n=4)
    c.um(LAST, (), c.sdu()[10:], n=8)

    sec('UM 10 bit DRB (uplink, downlink with 15 bit LIs from the framing)')
    c = Ch(F, UM, UL, 11, DRB, 2, snlen=10, prio=9, sn0=100)
    c.um(0, (), c.sdu())
    c.um(0, (l1,), c.sdu() * 2)
    w = c.sdu()
    c.um(FIRST, (), w[:15])
    c.um(LAST, (), w[15:])
    c.um(0, (), c.sdu(), n=1023)
    c.um(0, (), c.sdu(), n=0)
    c.um(0, (), c.sdu(), n=50)
    c.um(0, (), c.sdu(), n=51)
    c = Ch(F, UM, DL, 11, DRB, 2, snlen=10, prio=9, sn0=7)
    c.um(0, (), c.sdu())

    sec('UM on MCCH and MTCH: SN 0, IP and RRC calls (when enabled)')
    c = Ch(F, UM, DL, 0, MTCH, 3, snlen=5)
    for i in range(4):
        c.um(0, (), IP)
    c.um(0, (), IP, n=0)
    c.um(0, (len(IP),), IP * 2)
    c.um(FIRST, (), IP[:9])
    c.um(LAST, (), IP[9:])
    c.um(0, (), IP, n=20)
    c = Ch(F, UM, DL, 0, MCCH, None, snlen=5)
    c.um(0, (), RRC['mib'])
    c.um(0, (), RRC['mib'])
    c.um(FIRST, (), RRC['mib'][:1])
    c.um(LAST, (), RRC['mib'][1:])
    c = Ch(F, UM, DL, 12, SRB, 1, snlen=5)
    c.um(0, (), c.sdu())

    sec('AM 10 bit SRB1: data, polling, segments, extensions, SN anomalies')
    c = Ch(F, AM, DL, 20, SRB, 1, prio=1)
    s1 = c.sdu()
    c.am(0, (), s1)
    c.am(0, (), c.sdu(), p=1)
    l7 = len(s1)
    c.am(0, (l7,), c.sdu() + c.sdu())
    c.am(0, (l7, l7), c.sdu() * 3)
    a = c.sdu()
    c.am(FIRST, (), a[:3])
    c.am(MID, (), a[3:5])
    c.am(LAST, (), a[5:])
    a = c.sdu()
    b2 = c.sdu()
    c.am(FIRST, (), a[:4])
    c.am(LAST, (l7 - 4,), a[4:] + b2)
    # re-segmentation (RF, LSF, SO)
    a = c.sdu()
    c.am(FIRST, (), a[:5], rf=1, lsf=0, so=0)
    c.am(LAST, (), a[5:], rf=1, lsf=1, so=5, p=1)
    c.am(0, (), c.sdu())
    c.am(0, (), c.sdu(), n=c.sn + 7)                         # missing
    c.am(0, (), c.sdu(), n=c.sn + 1)                         # exactly one SN missing
    c.am(0, (), c.sdu(), n=c.sn - 1)                         # repeated (SN - 1)
    c.am(0, (), c.sdu(), n=2)                                # retransmission of an old SN
    c.am(0, (), c.sdu(), n=900)                              # far ahead -> wraps around: missing
    c.am(0, (), c.sdu(), n=c.sn)
    c = Ch(F, AM, UL, 20, SRB, 1, prio=1)
    c.am(0, (), c.sdu())
    c.am(0, (), c.sdu())
    c.am(0, (), c.sdu())

    sec('AM status PDUs (acks inside the window of the other direction)')
    c.status(2)
    c.status(3, [1])
    c.status(4, [0, 2])
    c.status(1022, [1020, 1021, 1])                          # wraps, within half the window of the data seen? (checked below)
    F.pop()
    c = Ch(F, AM, DL, 21, DRB, 1, prio=5)
    for i in range(6):
        c.am(0, (), c.sdu())
    c = Ch(F, AM, UL, 21, DRB, 1, prio=5)
    c.status(5, [2, (3, 0, 10), (4, 5, 0x7fff)])
    c.status(6, [(1, 3, 4)])
    c.status(6)
    c.status(6)
    Ch(F, AM, UL, 22, DRB, 1).status(6)                      # no channel in the other direction yet

    sec('AM 16 bit DRB: data, re-segmentation, status')
    c = Ch(F, AM, DL, 30, DRB, 2, snlen=16, sn0=1000)
    for i in range(4):
        c.am(0, (), c.sdu())
    q = c.sdu()
    c.am(FIRST, (), q[:12], p=1)
    c.am(LAST, (), q[12:], rf=1, lsf=1, so=12)
    q = c.sdu()
    c.am(FIRST, (), q[:8], rf=1, lsf=0, so=3)
    c.am(LAST, (len(q) - 8,), q[8:] + b'zz')
    c.am(0, (), c.sdu(), n=c.sn + 3)                         # three SNs missing (16 bit)
    cu = Ch(F, AM, UL, 30, DRB, 2, snlen=16)
    cu.status(1008)
    cu.status(1008, [1002, (1003, 4, 0xffff)])
    cu.status(1008, [1005])
    sec('AM 15 bit LIs from the framing, many LIs, many NACKs')
    c = Ch(F, AM, DL, 31, DRB, 3, extli=True, sn0=50)
    c.am(0, (len(IP) + 2, len(IP) + 2), b''.join(c.sdu() for _ in range(3)))
    c = Ch(F, AM, UL, 31, DRB, 3, extli=True, sn0=60)
    c.am(0, (len(IP) + 2,), b''.join(c.sdu() for _ in range(2)))
    c = Ch(F, AM, DL, 31, DRB, 4, sn0=70)
    c.am(0, tuple([2] * 40), b'ab' * 41)
    c.am(0, tuple([1] * 191), b'a' * 192)
    c.am(0, tuple([1] * 190), b'a' * 191)
    c.am(0, tuple([1] * 3), b'a' * 4)
    c = Ch(F, AM, UL, 32, DRB, 3, snlen=16)
    c.status(2000, list(range(1000, 1520)))

    sec('Framing info that does not continue the previous PDU (warnings)')
    c = Ch(F, UM, DL, 40, DRB, 1, snlen=5)
    q = c.sdu()
    c.um(FIRST, (), q[:10])
    c.um(0, (), c.sdu())                        # starts a new SDU, the last one was never ended
    r = c.sdu()
    c.um(0, (), r)
    c.um(LAST, (), c.sdu()[:20])                # continues an SDU that was already complete
    c = Ch(F, AM, DL, 40, DRB, 2)
    q = c.sdu()
    c.am(FIRST, (), q[:10])
    c.am(0, (), c.sdu())
    c.am(0, (), c.sdu())
    c.am(LAST, (), c.sdu()[:20])

    sec('Narrowband: SRB1 / SRB1bis (no PDCP header) and a DRB without signalled SN length')
    c = Ch(F, AM, DL, 41, SRB, 1, nb=1)
    c.am(0, (), bytes([c.psn]) + bytes.fromhex('0fd9') + b'\0\0\0\0')
    c = Ch(F, AM, DL, 41, SRB, 3, nb=1)
    c.am(0, (), bytes.fromhex('25ed0335'))
    c = Ch(F, UM, DL, 41, DRB, 1, nb=1, snlen=5)
    c.um(0, (), bytes([0x81]) + IP)
    # RRCConnectionSetup on a TM CCCH with DRB-ToAddMod: the DRB parameters (PDCP SN
    # size, extended LI) are learned for UE 42 and used by later frames
    sec('RRC setup (TM CCCH) with DRB-ToAddMod, then DRB data using the signalled parameters')
    F.append(frame(TM, rrc_setup([dict(drbid=3, lcid=3, rlc='um5', prio=3, pdcp='um'),
                                  dict(drbid=4, lcid=4, rlc='am', pdcp='am', prio=4),
                                  dict(drbid=5, lcid=5, rlc='am', prio=5)]),
                   d=DL, ueid=42, ctype=CCCH))
    c = Ch(F, UM, DL, 42, DRB, 3, snlen=5)
    c.um(0, (), c.sdu())
    c.um(0, (), c.sdu())
    c = Ch(F, AM, DL, 42, DRB, 4)
    c.am(0, (), c.sdu())
    c.am(0, (len(IP) + 2,), c.sdu() + c.sdu())
    c = Ch(F, AM, DL, 42, DRB, 5)
    c.am(0, (), c.sdu())
    c = Ch(F, AM, UL, 42, DRB, 4)
    c.am(0, (len(IP) + 2,), c.sdu() + c.sdu())

    # MAC-LTE frames (Exported PDU "mac-lte-framed"): RLC called by MAC; the default
    # sequence analysis (MAC frames only), MAC retransmissions, bearer reset
    sec('MAC-LTE: RRC setup with DRBs, SRB and DRB PDUs, retransmissions, re-establishment')
    M = F.append
    M(mac_frame(DL, 0x70, 80, 100, 1, [(0, rrc_setup([dict(drbid=3, lcid=3, rlc='um5', prio=3),
                                                         dict(drbid=4, lcid=4, rlc='am', prio=4)]))]))
    sn = 0
    for ueid in (80,):
        for d, base in ((DL, 0), (UL, 0)):
            for i in range(3):
                p = pdcp_srb(i + 1, RRC['dl_infotr'] if d == DL else RRC['ul_infotr'])
                M(mac_frame(d, 0x70, ueid, 110 + i, 2, [(1, am(i, body=p))]))
    # SRB2 and a DRB 3 (UM 5) / DRB 4 (AM) in the same MAC PDU
    M(mac_frame(DL, 0x70, 80, 120, 1, [(2, am(0, body=pdcp_srb(1, RRC['dl_countchk']))),
                                         (3, um(5, 0, 0, (), pdcp_drb(1, IP))),
                                         (4, am(0, body=pdcp_drb(1, IP)))]))
    M(mac_frame(DL, 0x70, 80, 121, 1, [(3, um(5, 1, 0, (), pdcp_drb(2, IP))), (4, am(1, body=pdcp_drb(2, IP)))]))
    M(mac_frame(DL, 0x70, 80, 122, 1, [(3, um(5, 4, 0, (), pdcp_drb(3, IP))), (4, am(2, body=pdcp_drb(3, IP)))]))   # UM gap
    M(mac_frame(UL, 0x70, 80, 123, 1, [(4, status(3, [1]))]))                  # status on the UL
    M(mac_frame(UL, 0x70, 80, 124, 1, [(4, status(3, [(2, 2, 7)]))]))
    # MAC retransmissions (reTxCount > 0): UM and AM
    M(mac_frame(UL, 0x70, 80, 130, 1, [(3, um(5, 9, 0, (), pdcp_drb(4, IP)))]))
    M(mac_frame(UL, 0x70, 80, 140, 1, [(3, um(5, 9, 0, (), pdcp_drb(4, IP)))], retx=1))
    M(mac_frame(UL, 0x70, 80, 131, 1, [(4, am(7, body=pdcp_drb(4, IP)))]))
    M(mac_frame(UL, 0x70, 80, 141, 1, [(4, am(7, body=pdcp_drb(4, IP)))], retx=2))
    M(mac_frame(UL, 0x70, 80, 142, 1, [(1, am(7, body=pdcp_srb(9, RRC['ul_infotr'])))], retx=1))
    # RRCConnectionReestablishmentRequest on the UL CCCH: RLC bearers of the UE are reset
    M(mac_frame(UL, 0x70, 80, 150, 1, [(0, bytes.fromhex('3e19'))]))
    M(mac_frame(UL, 0x70, 80, 151, 1, [(1, am(0, body=pdcp_srb(1, RRC['ul_infotr'])))]))
    M(mac_frame(DL, 0x70, 80, 152, 1, [(1, am(0, body=pdcp_srb(1, RRC['dl_infotr'])))]))
    return F, S


def nested_framing():
    """Review item L1 (not fixed): an RLC-LTE UM PDU whose first SDU is PDCP + IP + UDP carrying
    another RLC-LTE framed PDU. The nested heuristic call reuses the outer frame's info and
    throws, so the frame is shown with the wrong SDU split. The control has no nesting."""
    L_IN = 60
    src, dst = (10, 0, 0, 1), (10, 0, 0, 2)

    def ipudp(payload, sport=40000, dport=40001):
        udp = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
        ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0, bytes(src), bytes(dst))
        return ip[:10] + struct.pack('>H', csum(ip)) + ip[12:] + udp
    inner = bytearray(b'rlc-lte' + bytes(L_IN - 7))
    L2 = L3 = 4
    sdu1 = bytes([0x80, 0x01]) + ipudp(bytes(inner))
    L1 = len(sdu1)
    start = 2 * L_IN - (3 + L1 + L2 + L3)
    inner[start] = 0x02
    sdu1 = bytes([0x80, 0x01]) + ipudp(bytes(inner))
    ext = ((1 << 23) | (L1 << 12) | (0 << 11) | L2).to_bytes(3, 'big')
    rlc = bytes([0x21]) + ext + sdu1 + b'BBBB' + b'CCCC'
    hdr = bytes([0x02, 5, 0x03, 1, 0x05, 0, 1, 0x06, 0, 5, 0x07, 0, 1, 0x01])
    out = [udp_frame(b'rlc-lte' + bytes([2]) + hdr + rlc)]
    sdu1b = bytes([0x80, 0x01]) + ipudp(bytes(L_IN), 40002, 40003)
    rlc2 = bytes([0x21]) + ext + sdu1b + b'BBBB' + b'CCCC'
    out.append(udp_frame(b'rlc-lte' + bytes([2]) + hdr + rlc2))
    return out


def build_malformed():
    F = []
    # unknown mode, unknown tag, missing SN length tag for UM, header only
    F.append(frame(5, b'\x11\x22', d=DL, ctype=BCCH_BCH))
    F.append(udp_frame(b'rlc-lte' + bytes([AM, 0x42, 0x01]) + b'\x00\x01\x02'))
    F.append(udp_frame(b'rlc-lte' + bytes([UM, 0x03, 0x01, 0x01]) + b'\x00\x01\x02'))
    F.append(udp_frame(b'rlc-lte' + bytes([AM])))                                 # too short
    F.append(frame(UM, um(5, 1, 0, (), b'a'), sn=7, d=DL, ueid=1, ctype=DRB, cid=1))   # bad SN length
    F.append(frame(UM, um(10, 1, 0, (), b'a', resv=3), sn=10, d=DL, ueid=1, ctype=DRB, cid=1))
    F.append(frame(AM, am(1, snlen=16, body=b'abc', resv=1), sn=16, d=DL, ueid=1, ctype=DRB, cid=1))
    F.append(frame(AM, am(1, snlen=16, rf=1, lsf=1, so=0, resv=1, body=b'abc'), sn=16, d=DL, ueid=1, ctype=DRB, cid=1))
    # AM data without data
    F.append(frame(AM, am(2), d=DL, ueid=2, ctype=DRB, cid=1))
    F.append(frame(AM, am(3, lis=(3,)), d=DL, ueid=2, ctype=DRB, cid=1))
    # status PDU errors: CPT != 0, NACK = ACK, NACK ahead of ACK, bytes after, repeated NACK, ACK out of window
    F.append(frame(AM, status(5, cpt=1), d=UL, ueid=3, ctype=DRB, cid=1))
    F.append(frame(AM, status(5, [5]), d=UL, ueid=3, ctype=DRB, cid=1))
    F.append(frame(AM, status(5, [500]), d=UL, ueid=3, ctype=DRB, cid=1))
    F.append(frame(AM, status(5, [4], extra=b'\x00\x00'), d=UL, ueid=3, ctype=DRB, cid=1))
    F.append(frame(AM, status(7, [4, 3]), d=UL, ueid=3, ctype=DRB, cid=1))
    F.append(frame(AM, status(7, [4, 3]), d=UL, ueid=3, ctype=DRB, cid=1))
    for i in range(5):
        F.append(frame(AM, am(i, body=b'abcd'), d=DL, ueid=4, ctype=DRB, cid=1))
    F.append(frame(AM, status(100), d=UL, ueid=4, ctype=DRB, cid=1))                # ACK behind the DL window
    F.append(frame(AM, status(2, [1]), d=UL, ueid=4, ctype=DRB, cid=1))
    F.append(frame(AM, status(2, [1]), d=UL, ueid=4, ctype=DRB, cid=1))
    # truncated PDUs
    F.append(frame(UM, b'', sn=5, d=DL, ueid=5, ctype=DRB, cid=1))
    F.append(frame(AM, b'\x80', d=DL, ueid=5, ctype=DRB, cid=1))
    F.append(frame(AM, bytes([0x84, 0x01]) + b'\x80', d=DL, ueid=5, ctype=DRB, cid=1))
    F.append(frame(AM, bytes([0xC0, 0x01, 0x00]), d=DL, ueid=5, ctype=DRB, cid=1))
    F.append(frame(AM, bytes([0x00]), d=UL, ueid=5, ctype=DRB, cid=1))
    F.append(frame(AM, bytes([0x00, 0x10]), d=UL, ueid=5, ctype=DRB, cid=1))
    F.append(frame(AM, bytes([0x00, 0x10, 0x80]), d=UL, ueid=5, ctype=DRB, cid=1))
    F.append(frame(AM, bytes([0x00, 0x10, 0x80, 0x00]), d=UL, ueid=5, ctype=DRB, cid=1))
    F.append(frame(UM, bytes([0x20]), sn=5, d=DL, ueid=5, ctype=DRB, cid=1))
    F.append(frame(UM, bytes([0x20, 0x80]), sn=5, d=DL, ueid=5, ctype=DRB, cid=1))
    F.append(frame(UM, bytes([0x24, 0x80, 0x00, 0x7f]), sn=10, d=DL, ueid=5, ctype=DRB, cid=1))
    F.append(frame(UM, um(5, 3, 0, (200,), b'abc'), sn=5, d=DL, ueid=5, ctype=DRB, cid=1))
    # reproducer of review item L1 (nested RLC-LTE in the SDU resets the shared lengths):
    # the nested call throws first, so the frame decodes (wrong SDU split only)
    F.append(frame(AM, am(4, lis=(3,), body=b'abc'), d=DL, ueid=6, ctype=DRB, cid=1))   # no data beyond the extensions
    F.append(udp_frame(b'this is not an rlc-lte frame, just UDP data'))
    F.append((1, exp_pdu('rlc-lte', b'\x80\x01\x02\x03')))                 # Exported PDU without per-frame info
    F.append((1, exp_pdu('rlc-lte', b'\x80\x01\x02\x03')))
    F.extend(nested_framing())
    # a segmented SDU with more segments than the reassembly keeps (100)
    c = Ch(F, AM, DL, 7, DRB, 1)
    c.am(FIRST, (), b'\x80\x01' + b'a' * 10)
    for i in range(102):
        c.am(MID, (), b'bcde')
    c.am(LAST, (), b'fgh')
    return F


if __name__ == '__main__':
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    F, S = build()
    write_pcap(os.path.join(out, 'rlc-lte-coverage.pcapng'), F)
    write_pcap(os.path.join(out, 'rlc-lte-coverage-malformed.pcapng'), build_malformed())
    with open(os.path.join(out, 'sections.txt'), 'w') as f:
        for n, name in S:
            f.write('%d %s\n' % (n, name))
    print(len(F), 'frames in main capture')
