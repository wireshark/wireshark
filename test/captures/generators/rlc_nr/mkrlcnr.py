#!/usr/bin/env python3
# Generates test/captures/rlc_nr_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the RLC-NR coverage captures: mkrlcnr.py <outdir>.

RLC-NR PDUs are framed over UDP (signature "rlc-nr", mode, SN length, tags,
PDU), reached through the heuristic rlc_nr_udp.  SDUs go on to PDCP-NR (SRB
and, with the rlc-nr.call_pdcp_for_*_drb preferences, DRB) and NR RRC (CCCH,
BCCH, PCCH).  Everything is made up with struct; the RRC messages are small
encodings found by trial and carry no keys.
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
    """pcapng, interface 0 Ethernet, interface 1 Exported PDU."""
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


def udp_frame(payload, sport=40000, dport=40001):
    udp = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
                     bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2]))
    ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
    return ETH + b'\x08\x00' + ip + udp


def ipv4_udp(payload=b'data'):
    udp = struct.pack('>HHHH', 5000, 5001, 8 + len(payload), 0) + payload
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 7, 0, 64, 17, 0,
                     bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]))
    return ip[:10] + struct.pack('>H', csum(ip)) + ip[12:] + udp


def exp_pdu(name, payload):
    n = name.encode()
    pad = (4 - len(n) % 4) % 4
    return struct.pack('>HH', 12, len(n) + pad) + n + b'\0' * pad + struct.pack('>HH', 0, 0) + payload


TM, UM, AM = 1, 2, 4
UL, DL = 0, 1
CCCH, BCCH_BCH, PCCH, SRB, DRB, BCCH_DL_SCH = range(1, 7)

RRC = {k: bytes.fromhex(v) for k, v in dict(
    mib='5d04c6', si='373e', paging='0558', dl_setup='3dba', ul_setupreq='145c8a42d884',
    ul_resumereq1='15c90b999b772b4f', dl_infotr='2936', ul_infotr='3e8c', dl_countchk='3bb3',
    dl_release='1772', ul_setupcompl='11f8b5',
).items()}


def frame(mode, snlen, pdu, d=None, ueid=None, btype=None, bid=None, order=None, extra=b''):
    t = {}
    if d is not None:
        t['d'] = bytes([0x02, d])
    if ueid is not None:
        t['u'] = struct.pack('>BH', 0x03, ueid)
    if btype is not None:
        t['t'] = bytes([0x04, btype])
    if bid is not None:
        t['b'] = bytes([0x05, bid])
    b = b'rlc-nr' + bytes([mode, snlen])
    for k in (order or list(t)):
        b += t[k]
    return udp_frame(b + extra + b'\x01' + pdu)


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


# ---------------------------------------------------------- PDU builders
def um(snlen, si, sn=0, so=0, body=b'', resv=0):
    """UM PDU: SI 0 whole (no SN), 1 first, 2 last, 3 middle (SO for 2 and 3)."""
    if si == 0:
        return bytes([resv & 0x3f]) + body
    if snlen == 6:
        h = bytes([(si << 6) | (sn & 0x3f)])
    else:
        h = struct.pack('>H', (si << 14) | ((resv & 3) << 12) | (sn & 0xfff))
    if si >= 2:
        h += struct.pack('>H', so)
    return h + body


def am(snlen, sn, si=0, so=0, body=b'', p=0, resv=0):
    b0 = 0x80 | (p << 6) | (si << 4)
    if snlen == 12:
        h = struct.pack('>H', (b0 << 8) | (sn & 0xfff))
    else:
        h = struct.pack('>I', (b0 << 16) | ((resv & 3) << 18) | (sn & 0x3ffff))[1:]
    if si >= 2:
        h += struct.pack('>H', so)
    return h + body


def status(snlen, ack, nacks=(), cpt=0, extra=b'', resv1=0, resv2=0):
    """nacks: list of sn | (sn, (so_start, so_end) or None, range or None)."""
    b = Bits().put(0, 1).put(cpt, 3).put(ack, snlen)
    r1 = 7 if snlen == 12 else 1
    r2 = 1 if snlen == 12 else 3
    b.put(1 if nacks else 0, 1).put(resv1, r1)
    for i, nk in enumerate(nacks):
        if not isinstance(nk, tuple):
            nk = (nk, None, None)
        sn, so, rng = nk
        b.put(sn, snlen).put(1 if i < len(nacks) - 1 else 0, 1)
        b.put(1 if so else 0, 1).put(1 if rng is not None else 0, 1).put(resv2, r2)
        if so:
            b.put(so[0], 16).put(so[1], 16)
        if rng is not None:
            b.put(rng, 8)
    return b.bytes() + extra


# PDCP-NR SDUs
def pdcp_srb(sn, rrc, mac=b'\0\0\0\0'):
    return struct.pack('>H', sn & 0xfff) + rrc + mac


def pdcp_drb12(sn, payload, sdap=None):
    return struct.pack('>H', 0x8000 | (sn & 0xfff)) + (bytes([sdap]) if sdap is not None else b'') + payload


def pdcp_drb18(sn, payload, sdap=None):
    return struct.pack('>I', 0x800000 | (sn & 0x3ffff))[1:] + (bytes([sdap]) if sdap is not None else b'') + payload


IP = ipv4_udp()


class Ch:
    """One RLC bearer direction; DRB SDUs follow the preferences of the main run:
    UL PDCP 12 bit SN with SDAP header, DL 18 bit SN (no SDAP: see README)."""

    def __init__(self, F, mode, snlen, d, ueid, btype, bid=None):
        self.F, self.mode, self.snlen, self.d, self.ueid, self.btype, self.bid = F, mode, snlen, d, ueid, btype, bid
        self.sn = 0
        self.psn = 1

    def sdu(self, payload=None):
        n = self.psn
        self.psn += 1
        if self.btype == SRB:
            return pdcp_srb(n, RRC['dl_infotr'] if self.d == DL else RRC['ul_infotr'])
        p = IP if payload is None else payload
        if self.d == UL:
            return pdcp_drb12(n, p, sdap=0x85)
        return pdcp_drb18(n, p)

    def emit(self, pdu, **over):
        k = dict(d=self.d, ueid=self.ueid, btype=self.btype, bid=self.bid)
        k.update(over)
        self.F.append(frame(self.mode, self.snlen, pdu, **k))

    def nextsn(self, n):
        s = self.sn if n is None else n
        self.sn = (s + 1) % (1 << self.snlen)
        return s

    def um(self, si=0, body=b'', so=0, n=None, **over):
        sn = self.nextsn(n) if si else 0
        self.emit(um(self.snlen, si, sn, so, body), **over)

    def am(self, si=0, body=b'', so=0, n=None, p=0, **over):
        self.emit(am(self.snlen, self.nextsn(n), si, so, body, p), **over)

    def status(self, ack, nacks=(), **over):
        self.emit(status(self.snlen, ack, nacks), **over)

    def segmented(self, sdu, cuts, n=None):
        """Send the SDU in pieces: first, middle..., last (SI 1, 3, 2)."""
        parts = [sdu[a:b] for a, b in zip([0] + cuts, cuts + [len(sdu)])]
        s = self.nextsn(n)
        so = 0
        for i, part in enumerate(parts):
            si = 1 if i == 0 else (2 if i == len(parts) - 1 else 3)
            if self.mode == UM:
                self.emit(um(self.snlen, si, s, so, part))
            else:
                self.emit(am(self.snlen, s, si, so, part, p=1 if si == 2 else 0))
            so += len(part)


def build():
    F = []
    S = []

    def sec(name):
        S.append((len(F) + 1, name))

    sec('reproducer of "RLC-NR: Fix 18-bit SN limit and SDAP header flag": status PDU, 18 bit SN, ACK 10, NACK 262140')
    F.append(frame(AM, 18, status(18, 10, [262140]), d=DL, ueid=1, btype=DRB, bid=1))
    sec('TM: common channels, CCCH (UL 6 octets and UL-CCCH1 8 octets), TM on SRB / DRB')
    F.append(frame(TM, 0, RRC['mib'], d=DL, btype=BCCH_BCH))
    F.append(frame(TM, 0, RRC['si'], d=DL, btype=BCCH_DL_SCH))
    F.append(frame(TM, 0, RRC['paging'], d=DL, btype=PCCH))
    F.append(frame(TM, 0, RRC['ul_setupreq'], d=UL, ueid=2, btype=CCCH))
    F.append(frame(TM, 0, RRC['ul_resumereq1'], d=UL, ueid=2, btype=CCCH))
    F.append(frame(TM, 0, RRC['dl_setup'], d=DL, ueid=2, btype=CCCH))
    F.append(frame(TM, 0, b'\x01\x02\x03', d=DL, ueid=2, btype=SRB, bid=1))
    F.append(frame(TM, 0, b'\x01\x02\x03', d=UL, ueid=2, btype=DRB, bid=1))
    sec('UM 6 bit SN: whole SDUs, SRB, segmented SDUs (reassembled), DRB with SDAP')
    c = Ch(F, UM, 6, DL, 10, DRB, 1)
    c.um(0, c.sdu())
    c.um(0, c.sdu())
    c.segmented(c.sdu(), [10, 22])
    c.segmented(c.sdu(), [15])
    c.segmented(c.sdu(), [5, 9, 20, 30])
    c = Ch(F, UM, 6, UL, 10, DRB, 1)
    c.um(0, c.sdu())
    c.segmented(c.sdu(), [13])
    c = Ch(F, UM, 6, DL, 10, SRB, 1)
    c.um(0, c.sdu())
    c.segmented(c.sdu(), [3])
    sec('UM 12 bit SN')
    c = Ch(F, UM, 12, DL, 11, DRB, 2)
    c.um(0, c.sdu())
    c.segmented(c.sdu(), [8, 20], n=4000)
    c.segmented(c.sdu(), [9], n=4095)
    c = Ch(F, UM, 12, UL, 11, DRB, 2)
    c.um(0, c.sdu())
    c.segmented(c.sdu(), [11], n=300)
    sec('AM 12 bit SN: data, polling, segmentation with reassembly, SRB')
    c = Ch(F, AM, 12, DL, 20, DRB, 1)
    c.am(0, c.sdu())
    c.am(0, c.sdu(), p=1)
    c.segmented(c.sdu(), [10, 20])
    c.segmented(c.sdu(), [7])
    c.segmented(c.sdu(), [4, 6, 12, 18, 25])
    c.am(0, c.sdu(), n=4095)
    c.am(0, c.sdu(), n=0)
    c = Ch(F, AM, 12, UL, 20, DRB, 1)
    c.am(0, c.sdu(), p=1)
    c.segmented(c.sdu(), [10])
    c = Ch(F, AM, 12, DL, 20, SRB, 1)
    c.am(0, c.sdu())
    c.segmented(c.sdu(), [2])
    c = Ch(F, AM, 12, UL, 20, SRB, 2)
    c.am(0, c.sdu())
    sec('AM 18 bit SN')
    c = Ch(F, AM, 18, DL, 21, DRB, 2)
    c.am(0, c.sdu())
    c.segmented(c.sdu(), [10, 20], n=262140)
    c.am(0, c.sdu(), p=1)
    c = Ch(F, AM, 18, UL, 21, DRB, 2)
    c.am(0, c.sdu())
    c.segmented(c.sdu(), [12])
    sec('AM status PDUs: ACK only, NACKs, partial NACKs (SO), NACK ranges, many NACKs, both SN sizes')
    for snl, big in ((12, 4000), (18, 262000)):
        c = Ch(F, AM, snl, UL, 22, DRB, 1)
        c.status(5)
        c.status(9, [3])
        c.status(9, [3, 5, 8])
        c.status(20, [(4, (0, 10), None)])
        c.status(20, [(4, (3, 0xffff), None), 7])
        c.status(20, [(4, None, 3)])
        c.status(20, [(4, (1, 2), 5), (12, None, 2), 15])
        c.status(5, [big])                                 # wraps: NACK just behind the ACK
        c.status(30, list(range(2, 12)) * 55)               # more NACKs than the tap holds
        c.status(30, [(10, None, 255)])
    return F, S


def build_malformed():
    F = []
    # unknown mode, unknown tag, bad SN lengths, reserved bits, no data
    F.append(frame(5, 0, b'\x11\x22', d=DL, btype=BCCH_BCH))
    F.append(udp_frame(b'rlc-nr' + bytes([AM, 12, 0x42, 0x01]) + b'\x00\x01\x02'))
    F.append(udp_frame(b'rlc-nr' + bytes([AM, 12])))
    F.append(udp_frame(b'this is not an rlc-nr frame, just plain UDP data'))
    F.append(frame(UM, 7, um(6, 1, 1, 0, b'abc'), d=DL, ueid=1, btype=DRB, bid=1))
    F.append(frame(AM, 15, am(12, 1, 0, 0, b'abc'), d=DL, ueid=1, btype=DRB, bid=1))
    F.append(frame(AM, 15, status(12, 3), d=DL, ueid=1, btype=DRB, bid=1))
    F.append(frame(UM, 6, um(6, 0, 0, 0, b'abc', resv=5), d=DL, ueid=1, btype=DRB, bid=1))
    F.append(frame(UM, 12, um(12, 1, 1, 0, b'abc', resv=2), d=DL, ueid=1, btype=DRB, bid=1))
    F.append(frame(AM, 18, am(18, 1, 0, 0, b'abc', resv=1), d=DL, ueid=1, btype=DRB, bid=1))
    F.append(frame(UM, 6, um(6, 0), d=DL, ueid=1, btype=DRB, bid=1))
    F.append(frame(UM, 6, um(6, 1, 3), d=DL, ueid=1, btype=DRB, bid=1))
    F.append(frame(AM, 12, am(12, 3), d=DL, ueid=1, btype=DRB, bid=1))
    # status PDU errors
    F.append(frame(AM, 12, status(12, 5, cpt=1), d=UL, ueid=3, btype=DRB, bid=1))
    F.append(frame(AM, 12, status(12, 5, [5]), d=UL, ueid=3, btype=DRB, bid=1))
    F.append(frame(AM, 12, status(12, 5, [500]), d=UL, ueid=3, btype=DRB, bid=1))
    F.append(frame(AM, 12, status(12, 5, [4], extra=b'\x00\x00'), d=UL, ueid=3, btype=DRB, bid=1))
    F.append(frame(AM, 12, status(12, 5, [(4, None, 0)]), d=UL, ueid=3, btype=DRB, bid=1))
    F.append(frame(AM, 12, status(12, 5, [4], resv1=3), d=UL, ueid=3, btype=DRB, bid=1))
    F.append(frame(AM, 12, status(12, 5, [4], resv2=1), d=UL, ueid=3, btype=DRB, bid=1))
    F.append(frame(AM, 18, status(18, 5, [4], resv1=1, resv2=2), d=UL, ueid=3, btype=DRB, bid=1))
    # truncated PDUs
    for mode, snl, pdu in ((UM, 6, b''), (UM, 12, b'\x40'), (UM, 12, b'\xc0\x01'), (UM, 6, b'\x80\x00'),
                           (AM, 12, b'\x80'), (AM, 12, b'\xb0\x01'), (AM, 18, b'\x80\x00'),
                           (AM, 12, b'\x00'), (AM, 12, b'\x00\x10'), (AM, 12, b'\x00\x10\x80'),
                           (AM, 12, b'\x00\x10\x80\x05\x00\x00'), (AM, 12, b'\x00\x10\x80\x05\x00\x00\x00\x04')):
        F.append(frame(mode, snl, pdu, d=UL, ueid=5, btype=DRB, bid=1))
    # Exported PDU naming rlc-nr: no per-frame info
    F.append((1, exp_pdu('rlc-nr', b'\x80\x01\x02\x03')))
    F.append((1, exp_pdu('rlc-nr', b'\x80\x01\x02\x03')))
    # more DRB frames with garbage SDUs for the PDCP calls
    for i in range(4):
        F.append(frame(UM, 6, um(6, 0, 0, 0, bytes([0x55 + i]) * 5), d=i & 1, ueid=6, btype=DRB, bid=1))
        F.append(frame(AM, 12, am(12, i, 0, 0, bytes([0x55 + i]) * 5), d=i & 1, ueid=6, btype=DRB, bid=1))
    return F


if __name__ == '__main__':
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    F, S = build()
    write_pcap(os.path.join(out, 'rlc-nr-coverage.pcapng'), F)
    write_pcap(os.path.join(out, 'rlc-nr-coverage-malformed.pcapng'), build_malformed())
    with open(os.path.join(out, 'sections.txt'), 'w') as f:
        for n, name in S:
            f.write('%d %s\n' % (n, name))
    print(len(F), 'frames in main capture')
