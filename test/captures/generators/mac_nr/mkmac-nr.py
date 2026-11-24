#!/usr/bin/env python3
# Generates test/captures/mac_nr_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic MAC-NR coverage captures.  Usage: mkmac-nr.py <outdir>
Writes mac-nr-coverage.pcap (LINKTYPE_WIRESHARK_UPPER_PDU, every frame is an
Exported PDU naming "mac-nr-framed") and mac-nr-coverage-malformed.pcap
(error paths, the unknown framing tag reproducer, the UDP heuristic)."""
import os
import struct
import sys

UL, DL = 0, 1
NO_RNTI, P_RNTI, RA_RNTI, C_RNTI, SI_RNTI, CS_RNTI, MSGB_RNTI = range(7)


def pcapng(name, frames):
    """frames: bytes (Exported PDU, interface 0) or ('eth', bytes) (Ethernet,
    interface 1)."""
    def block(btype, body):
        body += b'\0' * ((4 - len(body) % 4) % 4)
        n = 12 + len(body)
        return struct.pack('<II', btype, n) + body + struct.pack('<I', n)
    out = block(0x0a0d0d0a, struct.pack('<IHHq', 0x1a2b3c4d, 1, 0, -1))
    out += block(1, struct.pack('<HHI', 252, 0, 65535))
    out += block(1, struct.pack('<HHI', 1, 0, 65535))
    for i, fr in enumerate(frames):
        ifid = 0
        if isinstance(fr, tuple):
            ifid, fr = 1, fr[1]
        ts = (1700000000 + i) * 1000000 + 1000 * i
        out += block(6, struct.pack('<IIIII', ifid, ts >> 32, ts & 0xffffffff, len(fr), len(fr)) + fr)
    with open(name, 'wb') as f:
        f.write(out)


def exp_pdu(name, payload):
    n = name.encode()
    pad = (4 - len(n) % 4) % 4
    hdr = struct.pack('>HH', 12, len(n) + pad) + n + b'\0' * pad
    hdr += struct.pack('>HH', 0, 0)
    return hdr + payload


def ip_udp(payload, sport=40000, dport=9999):
    return ('eth', _ip_udp(payload, sport, dport))


def _ip_udp(payload, sport=40000, dport=9999):
    udp = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
                     bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2]))
    eth = bytes.fromhex('020000000001020000000002') + b'\x08\x00'
    return eth + ip + udp


def ctx(direction, rnti_type, rnti=None, ueid=None, harq=None, slot=None,
        subframe=None, phr2=None, radio=1, tags=b''):
    """Context header of packet-mac-nr.h, ending with the payload tag."""
    b = bytes([radio, direction, rnti_type])
    if rnti is not None:
        b += struct.pack('>BH', 0x02, rnti)
    if ueid is not None:
        b += struct.pack('>BH', 0x03, ueid)
    if subframe is not None:
        b += struct.pack('>BH', 0x04, subframe)
    if phr2 is not None:
        b += bytes([0x05, phr2])
    if harq is not None:
        b += bytes([0x06, harq])
    if slot is not None:
        b += struct.pack('>BHH', 0x07, slot[0], slot[1])
    return b + tags + b'\x01'


def framed(c, payload):
    return exp_pdu('mac-nr-framed', c + payload)


class Bits:
    def __init__(self):
        self.bits = []

    def put(self, val, n):
        for i in range(n - 1, -1, -1):
            self.bits.append((val >> i) & 1)

    def bytes(self):
        b = self.bits + [0] * ((8 - len(self.bits) % 8) % 8)
        return bytes(int(''.join(map(str, b[i:i + 8])), 2) for i in range(0, len(b), 8))


# ---------------------------------------------------------------- RRC SDUs
def rrc_ul_ccch_setup_request(tmsi=0x1234567):
    """UL-CCCH-Message: c1, rrcSetupRequest (48 bits)."""
    b = Bits()
    b.put(0, 1)       # c1
    b.put(0, 2)       # rrcSetupRequest
    b.put(1, 1)       # ue-Identity: randomValue
    b.put(tmsi, 39)
    b.put(2, 3)       # establishmentCause
    b.put(0, 1)       # spare
    return b.bytes()


def rrc_dl_ccch_reject():
    """DL-CCCH-Message: c1, rrcReject with waitTime."""
    b = Bits()
    b.put(0, 1)       # c1
    b.put(0, 2)       # rrcReject
    b.put(0, 1)       # criticalExtensions: rrcReject
    b.put(1, 1)       # waitTime present
    b.put(0, 1)       # nonCriticalExtension absent
    b.put(4, 4)       # waitTime
    return b.bytes()


def rrc_mib():
    b = Bits()
    b.put(0, 1)       # mib
    b.put(0x15, 6)    # systemFrameNumber
    b.put(1, 1)
    b.put(5, 4)
    b.put(0, 1)
    b.put(0x21, 8)
    b.put(0, 1)
    b.put(1, 1)
    b.put(0, 1)
    return b.bytes()


def rrc_paging():
    b = Bits()
    b.put(0, 1)       # c1
    b.put(0, 1)       # paging
    b.put(0, 3)       # no optional fields
    return b.bytes()


# ---------------------------------------------------------------- MAC subPDUs
# Which LCIDs/eLCIDs have no length field (is_fixed_sized_lcid / _elcid)
UL_FIXED = {0, 35, 36, 52, 44, 53, 55, 57, 58, 59, 61, 63}
DL_FIXED = {33, 34, 47, 48, 49, 51, 52, 56, 57, 58, 59, 60, 61, 62, 63}
UL_FIXED_ELCID = {231, 238, 242, 243, 244, 245, 247, 252, 253, 254}
DL_FIXED_ELCID = {230, 236, 237, 242, 243, 244, 247, 251, 252, 254, 255}

PAD = b'\x3f'  # a padding subheader: ends the dissection of a CE whose
#                payload the dissector does not consume


def sub(lcid, payload=b'', direction=UL, elcid=None, long_len=False, length=None):
    """One subPDU: header, optional eLCID, optional length, payload."""
    if lcid == 33:
        fixed = True
    elif lcid == 34:
        fixed = elcid in (UL_FIXED_ELCID if direction == UL else DL_FIXED_ELCID)
    else:
        fixed = lcid in (UL_FIXED if direction == UL else DL_FIXED)
    out = bytes([lcid & 0x3f]) if fixed else bytes([(0x40 if long_len else 0) | lcid])
    if lcid == 33:
        out += struct.pack('>H', elcid)
    elif lcid == 34:
        out += bytes([elcid])
    if not fixed:
        n = len(payload) if length is None else length
        out += struct.pack('>H', n) if long_len else bytes([n])
    return out + payload


def rlc_am_data(sn, data, poll=False, si=0):
    return bytes([0x80 | (0x40 if poll else 0) | (si << 4) | (sn >> 8), sn & 0xff]) + data


def rlc_am_status(ack_sn):
    return bytes([ack_sn >> 8, ack_sn & 0xff, 0x00])


class Srb:
    """RLC AM data PDUs that carry a PDCP SRB PDU with a valid RRC message
    (sequence numbers increase per direction, UE and LCID)."""
    sn = {}
    # DL-DCCH RRCRelease, UL-DCCH SecurityModeComplete
    RRC = {DL: bytes([0x12, 0x00]), UL: bytes([0x2a, 0x00])}

    @classmethod
    def pdu(cls, direction, ue, lcid, rrc=None, poll=False):
        k = (direction, ue, lcid)
        n = cls.sn.get(k, 0)
        cls.sn[k] = n + 1
        pdcp = bytes([n >> 8 & 0xf, n & 0xff]) + (rrc or cls.RRC[direction]) + bytes(4)
        return rlc_am_data(n, pdcp, poll=poll)


def me_phr(four, bitmap, othercell=False, pcell_v=0, vmask=0x2a):
    """Multiple Entry PHR payload; bit n of bitmap = C_n (n = 1..7, or 1..31
    with four octets).  Entry n has V set if bit n of vmask is set."""
    b = bytes([bitmap & 0xfe])
    if four:
        b += bytes([(bitmap >> 8) & 0xff, (bitmap >> 16) & 0xff, (bitmap >> 24) & 0xff])

    def entry(ph, v=0, p=0):
        e = bytes([(p << 7) | (v << 6) | (ph & 0x3f)])
        return e if v else e + bytes([0x20 | (ph & 0x1f)])
    if othercell:
        b += entry(33)
    b += entry(40, v=pcell_v)
    top = 32 if four else 8
    for n in range(1, top):
        if bitmap & (1 << n):
            b += entry(n + 5, v=(vmask >> (n % 8)) & 1, p=n & 1)
    return b


MARKS = []


def build():
    main = []
    bad = []
    f = main.append

    def mark(label):
        MARKS.append((len(main) + 1, label))

    mark('BCCH, PCCH')
    # ---- transparent channels
    f(framed(ctx(DL, NO_RNTI), rrc_mib()))                          # BCCH on BCH
    f(framed(ctx(DL, NO_RNTI, slot=(100, 5), rnti=0), rrc_mib()))    # frame/slot tag
    f(framed(ctx(DL, SI_RNTI, rnti=0xffff), bytes([0x01, 0x23, 0x45])))  # BCCH on DL-SCH
    f(framed(ctx(DL, P_RNTI, rnti=0xfffe), rrc_paging()))             # PCCH
    f(framed(ctx(DL, P_RNTI, rnti=0xfffe, subframe=0x1234), rrc_paging()))  # deprecated tag

    mark('RAR')
    # ---- RAR (RA-RNTI)
    def rar_body(ta=0x123, grant=0x4321abc & 0x7ffffff, tcrnti=0x4001):
        v = (ta << 43) | (grant << 16) | tcrnti
        return v.to_bytes(7, 'big')

    def rar_sub(rapid, e, **kw):
        return bytes([(0x80 if e else 0) | 0x40 | rapid]), rar_body(**kw)
    # BI only
    f(framed(ctx(DL, RA_RNTI, rnti=0x0123), bytes([0x05])))
    h, b = rar_sub(7, False)
    f(framed(ctx(DL, RA_RNTI, rnti=0x0123), h + b))
    # BI with E, then two RAPIDs, then padding
    h1, b1 = rar_sub(3, True)
    h2, b2 = rar_sub(60, False, ta=0xfff, tcrnti=0xfffe)
    f(framed(ctx(DL, RA_RNTI, rnti=0x0124, ueid=7), bytes([0x80 | 0x0a]) + h1 + b1 + h2 + b2 + b'\x00\x00\x00'))

    mark('MSGB')
    # ---- MSGB (MSGB-RNTI): BI, FallbackRAR, SuccessRAR (S=0 and S=1)
    def msgb_fallback(rapid, e):
        h, b = rar_sub(rapid, e)
        return h + b
    def msgb_success(e, s):
        # E T1=0 T2=1 S R R R R, ContentionResolutionId(6), R CPext(2) TPC(2) HARQ-FB(3),
        # PUCCH-res(4)+TA(12), C-RNTI(2)
        hdr = bytes([(0x80 if e else 0) | 0x20 | (0x10 if s else 0)])
        return hdr + bytes.fromhex('a1a2a3a4a5a6') + bytes([0x5b]) + bytes([0xa1, 0x23]) + struct.pack('>H', 0x4242)
    f(framed(ctx(DL, MSGB_RNTI, rnti=0x0200), bytes([0x03])))  # BI (T2=0)
    f(framed(ctx(DL, MSGB_RNTI, rnti=0x0200), msgb_fallback(5, False)))
    f(framed(ctx(DL, MSGB_RNTI, rnti=0x0200), bytes([0x80 | 0x02]) + msgb_fallback(5, True)
             + msgb_success(False, False) + b'\x00\x00'))
    f(framed(ctx(DL, MSGB_RNTI, rnti=0x0200), msgb_success(False, False)))
    f(framed(ctx(DL, MSGB_RNTI, rnti=0x0200),
             msgb_success(False, True) + sub(1, Srb.pdu(DL, 0, 1), direction=DL)))

    mark('DL-SCH data')
    # ---- DL-SCH
    dl = dict(direction=DL)
    def dlctx(**kw):
        d = dict(rnti=0x4601, ueid=1, harq=3, slot=(512, 7))
        d.update(kw)
        return ctx(DL, C_RNTI, **d)
    # data: CCCH, SRB1/2 RLC AM, LCID 3/4 (SRB3/4 by default), DRB LCIDs (raw)
    f(framed(dlctx(), sub(0, rrc_dl_ccch_reject(), **dl)))
    f(framed(dlctx(), sub(1, Srb.pdu(DL, 1, 1, poll=True), **dl) + sub(2, rlc_am_status(9), **dl)
             + sub(2, Srb.pdu(DL, 1, 2), **dl) + sub(3, Srb.pdu(DL, 1, 3), **dl) + sub(4, Srb.pdu(DL, 1, 4), **dl, long_len=True)))
    f(framed(dlctx(ueid=0), sub(5, bytes(range(20)), **dl) + sub(32, b'\x11' * 4, **dl, long_len=True)
             + sub(7, b'', **dl)))
    f(framed(dlctx(), sub(5, b'x' * 300, **dl, long_len=True)))
    f(framed(dlctx(), sub(40, PAD + b'\x00\x00', **dl)))     # reserved LCID with a length
    mark('DL-SCH control elements')
    # DL-SCH control elements (CEs come first, then data)
    d = lambda lcid, p=b'': sub(lcid, p, **dl)
    tail = sub(5, b'end', **dl)
    f(framed(dlctx(), d(47, bytes([0x4a, 0x31])) + tail))                 # recommended bit rate
    f(framed(dlctx(), d(47, bytes([0x2f, 0xc0])) + tail))                 # other LCID, other direction
    f(framed(dlctx(), d(48, bytes([0x80 | 0x14, 0x05])) + tail))          # SP ZP CSI-RS
    f(framed(dlctx(), d(49, bytes([0x1b, 0x05, 0xa5])) + tail))           # PUCCH spatial relation
    # SP SRS: activation with resources (c=0), with C=1 (pairs), deactivation, c=0 deact
    f(framed(dlctx(), d(50, bytes([0x80 | 0x25, 0x13, 0x85, 0x05, 0x45]), ) + tail))
    f(framed(dlctx(), d(50, bytes([0x80 | 0x25, 0x20 | 0x13, 0x85, 0x05, 0x05, 0x01, 0x02, 0x03])) + tail))
    f(framed(dlctx(), d(50, bytes([0x25, 0x20 | 0x03, 0x08, 0x09])) + tail))
    f(framed(dlctx(), d(50, bytes([0x25, 0x03])) + tail))
    f(framed(dlctx(), d(51, bytes([0x21, 0xaa])) + tail))                  # SP CSI reporting on PUCCH
    f(framed(dlctx(), d(52, bytes([0x28, 0x4f])) + tail))                  # TCI state ind PDCCH
    f(framed(dlctx(), d(53, bytes([0x65, 0x81, 0x7e, 0x01])) + tail))      # TCI states PDSCH
    f(framed(dlctx(), d(54, bytes([0x65, 0x81, 0x7e])) + tail))            # aperiodic CSI trigger
    f(framed(dlctx(), d(55, bytes([0x80 | 0x25, 0x31, 0x1f, 0x05, 0x1a, 0x3c])) + tail))  # SP CSI-RS/IM act
    f(framed(dlctx(), d(55, bytes([0x25, 0x31, 0x1f])) + tail))            # ... deactivation
    f(framed(dlctx(), d(56, bytes([0xfe])) + tail))                        # duplication
    f(framed(dlctx(), d(57, bytes([0xfe, 0x01, 0x80, 0xff])) + tail))      # SCell act/deact 4
    f(framed(dlctx(), d(58, bytes([0x82])) + tail))                        # SCell act/deact 1
    f(framed(dlctx(), d(59) + d(60) + tail))                               # long DRX, DRX
    f(framed(dlctx(), d(61, bytes([0xc5])) + d(62, bytes.fromhex('0102030405aa')) + tail))  # TA, contention res
    f(framed(dlctx(), d(61, bytes([0x41])) + tail + sub(63, b'\x00' * 5, **dl)))           # padding last
    f(framed(dlctx(), sub(63, b'', **dl)))                                 # padding, nothing after
    mark('DL-SCH eLCIDs')
    # eLCIDs: DL
    f(framed(dlctx(), sub(33, direction=DL, elcid=0x1234) + tail))         # two octet eLCID
    f(framed(dlctx(), sub(34, bytes([0x2a]), direction=DL, elcid=230) + tail))  # differential Koffset
    for e in range(227, 256):
        if e == 230:
            continue
        fixed = e in DL_FIXED_ELCID
        f(framed(dlctx(), sub(34, PAD + b'\x00\x00', direction=DL, elcid=e)))

    f(framed(dlctx(), sub(34, PAD + b'\x00', direction=DL, elcid=100)))        # DL eLCID without a name

    mark('UL-SCH data')
    # ---- UL-SCH
    ul = dict(direction=UL)
    def ulctx(**kw):
        d = dict(rnti=0x4601, ueid=1, harq=3, slot=(513, 9))
        d.update(kw)
        return ctx(UL, C_RNTI, **d)
    f(framed(ulctx(), sub(0, rrc_ul_ccch_setup_request()[:6] + b'\x00\x00', **ul)))   # CCCH 64 bits (RRC UL CCCH1)
    f(framed(ulctx(), sub(52, rrc_ul_ccch_setup_request(), **ul)))                    # CCCH 48 bits
    f(framed(ulctx(), sub(35, rrc_ul_ccch_setup_request(), **ul)))                    # RedCap CCCH
    f(framed(ulctx(), sub(36, rrc_ul_ccch_setup_request() + b'\x00\x00', **ul)))      # RedCap CCCH1
    f(framed(ulctx(), sub(1, Srb.pdu(UL, 1, 1), **ul) + sub(2, Srb.pdu(UL, 1, 2), **ul, long_len=True)
             + sub(3, rlc_am_status(4), **ul) + sub(4, Srb.pdu(UL, 1, 4), **ul)))
    f(framed(ulctx(ueid=2), sub(5, b'\x45\x00' + bytes(20), **ul) + sub(31, b'z' * 3, **ul)))
    mark('UL-SCH control elements')
    # UL CEs after data
    u = lambda lcid, p=b'': sub(lcid, p, **ul)
    data = sub(5, b'data', **ul)
    f(framed(ulctx(), data + u(44, bytes([0x2a, 0xbc]))))                  # timing advance report
    f(framed(ulctx(), data + u(45, PAD + b'\x00\x00')))                    # sidelink BSR
    f(framed(ulctx(), data + u(46, PAD + b'\x00\x00')))
    f(framed(ulctx(), data + u(43, b'\x01\x02\x03')))                      # truncated enhanced BFR
    f(framed(ulctx(), data + u(48, b'\x01\x02\x03\x04')))                  # LBT failure 4 octets
    f(framed(ulctx(), data + u(49, b'\x7f')))                              # LBT failure 1 octet
    f(framed(ulctx(), data + u(50, b'\x11\x22\x33')))                      # BFR
    f(framed(ulctx(), data + u(51, b'\x44\x55')))                          # truncated BFR
    f(framed(ulctx(), data + u(53, bytes([0x4a, 0x31]))))                  # recommended bit rate query
    f(framed(ulctx(), data + u(55)))                                       # configured grant confirmation
    f(framed(ulctx(), data + u(57, bytes([0x15, 0x20 | 9]))))   # single entry PHR
    f(framed(ulctx(), data + u(58, struct.pack('>H', 0x4601))))            # C-RNTI
    for lcg in (0, 3, 7):
        f(framed(ulctx(), data + u(61, bytes([(lcg << 5) | 12]))))         # short BSR
    f(framed(ulctx(), u(59, bytes([0xc0 | 5]))))                           # short truncated BSR
    f(framed(ulctx(), data + u(60, bytes([0x05, 0x10, 0x20]))))            # long truncated BSR
    f(framed(ulctx(), data + u(62, bytes([0xff]) + bytes(range(1, 9)))))   # long BSR, all LCGs
    f(framed(ulctx(), data + u(62, bytes([0x05, 0x31, 0x32]))))            # long BSR, some LCGs
    f(framed(ulctx(), data + u(62, bytes([0xaa, 1, 2, 3, 4]))))
    f(framed(ulctx(), data + u(62, bytes([0x55, 1, 2, 3, 4]))))
    f(framed(ulctx(), data + u(63, b'\x00' * 6)))                          # padding
    f(framed(ulctx(), u(61, bytes([0x2c])) + u(58, struct.pack('>H', 1)) + u(63, b'\x00\x00')))   # CE only
    mark('Multiple Entry PHR')
    # Multiple entry PHR (1 and 4 octet C)
    f(framed(ulctx(), data + u(56, me_phr(False, 0x2a))))
    f(framed(ulctx(phr2=0), data + u(56, me_phr(False, 0x00))))
    f(framed(ulctx(phr2=1), data + u(56, me_phr(False, 0xfe, othercell=True, pcell_v=1))))
    f(framed(ulctx(phr2=1), data + u(54, me_phr(True, 0x80000f2a, othercell=True))))
    f(framed(ulctx(), data + u(54, me_phr(True, 0xfffffffe, vmask=0x55))))
    mark('UL-SCH eLCIDs')
    # UL eLCIDs (the two octet field, and the one octet field for 229..255)
    f(framed(ulctx(), data + sub(33, direction=UL, elcid=0x0102)))
    for e in range(229, 256):
        if e == 231:
            p = b'\x01\x02\x03'                       # consumed, fixed size 3
        elif e in (229, 230, 232, 233, 234, 235, 236, 237, 239):
            p = bytes(range(1, 6))                      # consumed, variable size
        elif e in UL_FIXED_ELCID:
            p = PAD                                     # not consumed, fixed size
        else:
            p = PAD + b'\x00\x00'                       # not consumed, variable size
        f(framed(ulctx(), data + sub(34, p, direction=UL, elcid=e)))

    f(framed(ulctx(), data + sub(34, PAD + b'\x00', direction=UL, elcid=100)))   # eLCID below 227: no name
    # Single entry PHR with the PH and Pcmax,f,c at their limits
    for ph, pc in ((0, 0), (63, 63), (60, 62)):
        f(framed(ulctx(), data + u(57, bytes([ph, pc]))))

    mark('LCIDs 5..9 (RLC modes with the DRB table), CS-RNTI, TDD')
    # ---- RLC modes for LCIDs 5..9 (raw data unless the DRB table maps them;
    # runcov.sh maps them with the "drb_bearerconfig" table)
    for lcid in (5, 6, 7, 8, 9):
        for d_, rlc in ((DL, bytes([0x04, 0x01, 0x02, 0x03, 0x04])), (UL, bytes([0x84, 0x12, 0x9a, 0xbc]))):
            f(framed(ctx(d_, C_RNTI, rnti=0x4602, ueid=3, harq=1),
                     sub(lcid, rlc, direction=d_) + sub(lcid + 10, rlc, direction=d_)))
    f(framed(ctx(UL, CS_RNTI, rnti=0x4603, ueid=4, harq=2, phr2=0), sub(5, b'cs-rnti', direction=UL) + sub(61, bytes([0x23]), direction=UL)))
    f(framed(ctx(DL, CS_RNTI, rnti=0x4603, ueid=4, harq=2), sub(5, b'cs-rnti', direction=DL)))
    f(framed(ctx(DL, C_RNTI, radio=2, rnti=0x4604, ueid=5, harq=15, slot=(1023, 79)), sub(5, b'tdd', direction=DL)))

    mark('unknown framing tag (framed), then UDP heuristic frames')
    # ---- reproducer of the use after free: an unknown framing tag (aborts
    # the dissection with an expert info, once per pass).
    ukn = bytes([1, 1, 3, 0xff]) + bytes(range(32))
    for _ in range(2):
        f(framed(b'', ukn))
    # the same through the UDP heuristic (needs --enable-heuristic mac_nr_udp)
    good = b'mac-nr' + ctx(DL, C_RNTI, rnti=0x4601, ueid=9, harq=2) + sub(5, b'heuristic', direction=DL)
    f(ip_udp(good))
    f(ip_udp(good))                       # a second frame
    f(ip_udp(b'mac-nr' + ukn))
    f(ip_udp(b'mac-nr' + ukn))

    # ================= malformed / warning capture
    g = bad.append
    # truncated PDUs: exceptions inside the dissector
    g(framed(dlctx(), b'\x05'))                              # BI only is fine; next ones are cut
    g(framed(ctx(DL, RA_RNTI, rnti=0x0123), bytes([0x40 | 7, 0x00, 0x01])))     # RAR cut short
    g(framed(ctx(DL, RA_RNTI, rnti=0x0123), bytes([0x80 | 0x05])))             # E set, no more data
    g(framed(ctx(DL, MSGB_RNTI, rnti=0x0200), bytes([0x20, 0xa1, 0xa2])))      # SuccessRAR cut short
    g(framed(dlctx(), sub(5, b'ab', direction=DL, length=40)))                 # SDU longer than the PDU
    g(framed(dlctx(), bytes([0x40 | 5, 0x01])))                               # long length cut
    g(framed(ulctx(), data + u(54, bytes([0xfe, 0x50]))))                      # ME-PHR cut short
    g(framed(ulctx(), u(61, b'')))                                            # short BSR without data
    g(framed(dlctx(), d(62, b'\x01\x02')))                                    # contention resolution cut
    g(framed(ctx(DL, NO_RNTI), b''))                                          # no payload
    g(framed(ctx(DL, 9, rnti=0x1), b'\x01\x02\x03'))                           # unknown RNTI type
    # length different from dissected
    g(framed(ulctx(), data + u(56, me_phr(False, 0x2a) + b'\x00\x00')))         # ME-PHR length too long
    g(framed(ulctx(), data + u(56, me_phr(False, 0x2a)[:-3] + b'\x00')))        # ME-PHR too short
    g(framed(ulctx(), data + u(60, bytes(range(10)))))                         # long truncated BSR > 7 bytes
    g(framed(ulctx(), data + u(62, bytes([0x03, 1, 2, 3, 4]))))                # long BSR: length longer than flags say
    g(framed(ulctx(), data + u(62, bytes([0xff, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10]))))
    # ordering warnings
    g(framed(dlctx(), tail + d(47, bytes([0x4a, 0x31]))))                     # DL CE after data
    g(framed(ulctx(), u(58, struct.pack('>H', 3)) + data))                    # UL data after CE
    # MAC-NR reached without framing (Exported PDU naming "mac-nr"): no per-frame data
    g(exp_pdu('mac-nr', bytes([0x05, 0x01, 0x02, 0x03])))
    # short and wrong heuristic frames (UDP port 9999 with --enable-heuristic)
    g(ip_udp(b'mac-nr\x01\x01'))
    g(ip_udp(b'mac-xx' + ctx(DL, C_RNTI, rnti=1) + b'\x00' * 3))
    # context cut inside the fixed header / a tag
    g(framed(b'', bytes([1, 1, 3, 0x02, 0x01]) ))
    g(framed(b'', bytes([1, 1])))                                         # shorter than 5: framed refuses
    g(framed(b'', bytes([1, 1, 3, 0xff, 0x00])))                          # unknown tag (framed)
    g(ip_udp(good))
    g(ip_udp(b'mac-nr' + ukn))
    return main, bad


if __name__ == '__main__':
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    m, b = build()
    if '--index' in sys.argv:
        for n, label in MARKS:
            print(n, label)
        print(len(m) + 1, 'end')
    pcapng(os.path.join(out, 'mac-nr-coverage.pcapng'), m)
    pcapng(os.path.join(out, 'mac-nr-coverage-malformed.pcapng'), b)
