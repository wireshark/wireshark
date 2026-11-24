#!/usr/bin/env python3
# Generates test/captures/mac_lte_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generator for the MAC-LTE (and MAC-LTE-FRAMED) coverage captures.

Usage: mkmaclte.py <outdir>

Every frame is an Exported PDU ("mac-lte-framed", link type 252) with the
MAC-LTE context fields followed by the MAC PDU, built with struct.
Writes mac-lte-coverage.pcap (clean frames) and
mac-lte-coverage-malformed.pcap (frames that only malformed input reaches).
"""
import struct
import sys
import os

# ---------------------------------------------------------------- helpers
def pcap(name, frames):
    with open(name, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 252))
        for ts, fr in frames:
            f.write(struct.pack('<IIII', ts[0], ts[1], len(fr), len(fr)))
            f.write(fr)

def exp_pdu(name, payload):
    n = name.encode()
    pad = (4 - len(n) % 4) % 4
    hdr = struct.pack('>HH', 12, len(n) + pad) + n + b'\0' * pad
    hdr += struct.pack('>HH', 0, 0)
    return hdr + payload

class Bits:
    def __init__(self):
        self.bits = []
    def put(self, val, n):
        for i in range(n - 1, -1, -1):
            self.bits.append((val >> i) & 1)
    def bytes(self):
        b = self.bits + [0] * ((8 - len(self.bits) % 8) % 8)
        return bytes(int(''.join(map(str, b[i:i+8])), 2) for i in range(0, len(b), 8))

FDD, TDD = 1, 2
UL, DL = 0, 1
(NO_RNTI, P_RNTI, RA_RNTI, C_RNTI, SI_RNTI, SPS_RNTI, M_RNTI, SL_BCH_RNTI,
 SL_RNTI, SC_RNTI, G_RNTI) = range(11)

def ctx(direction, rntitype, rnti=None, ueid=None, sfn=None, sf=None,
        radio=FDD, predef=None, retx=None, crc=None, extbsr=False,
        preamble=None, carrier=None, phy=None, simult_p=False,
        simult_ps=False, ce=None, nb=None, nulrb=None, sr=None,
        grant_sf=None, raw=b'', order=None):
    """Build the framing header (up to and including the payload tag)."""
    t = {}
    if rnti is not None: t['rnti'] = struct.pack('>BH', 0x02, rnti)
    if ueid is not None: t['ueid'] = struct.pack('>BH', 0x03, ueid)
    if sfn is not None:  t['sfn'] = struct.pack('>BH', 0x04, ((sfn & 0xfff) << 4) | (sf & 0xf))
    if predef is not None: t['predef'] = bytes([0x05, predef])
    if retx is not None: t['retx'] = bytes([0x06, retx])
    if crc is not None: t['crc'] = bytes([0x07, crc])
    if extbsr: t['extbsr'] = bytes([0x08])
    if preamble is not None: t['pre'] = bytes([0x09, preamble[0], preamble[1]])
    if carrier is not None: t['car'] = bytes([0x0a, carrier])
    if phy is not None: t['phy'] = bytes([0x0b, len(phy)]) + bytes(phy)
    if simult_p: t['sp'] = bytes([0x0c])
    if simult_ps: t['sps'] = bytes([0x0d])
    if ce is not None: t['ce'] = bytes([0x0e, ce])
    if nb is not None: t['nb'] = bytes([0x0f, nb])
    if nulrb is not None: t['nul'] = bytes([0x10, nulrb])
    if sr is not None:
        t['sr'] = struct.pack('>BH', 0x11, len(sr)) + b''.join(struct.pack('>HH', u, r) for u, r in sr)
    b = bytes([radio, direction, rntitype])
    for k in (order or list(t)):
        b += t[k]
    return b + raw + b'\x01'

def ulphy(mod=2, tbs=10, rbl=6, rbs=2, harq=0, ndi=1):
    return [mod, tbs, rbl, rbs, harq, ndi]

def dlphy(dci=1, ra=0, agg=2, mcs=10, rv=0, rbl=6, harq=0, ndi=1, tb=0, retx=0):
    return [dci, ra, agg, mcs, rv, rbl, harq, ndi, tb, retx]

# ------------------------------------------------- MAC PDU construction
UL_FIXED = {0x0f: 2, 0x11: 1, 0x12: 4, 0x13: 1, 0x14: 2, 0x15: 0, 0x1a: 1,
            0x1b: 2, 0x1c: 1, 0x1d: 1, 0x1e: 3}
DL_FIXED = {0x11: 0, 0x12: 1, 0x13: 1, 0x14: 4, 0x16: 2, 0x17: 0, 0x18: 4,
            0x1a: 0, 0x1b: 1, 0x1c: 6, 0x1d: 1, 0x1e: 0}

def sch(direction, items, fixed=None, mch=False):
    """items: list of (lcid, body[, opts]) ; opts: elcid, f2, r, lenfmt.
    Subheaders first, then bodies. The last subheader has no length."""
    if fixed is None:
        fixed = UL_FIXED if direction == UL else DL_FIXED
    hdr, bodies = b'', b''
    for i, it in enumerate(items):
        lcid, body = it[0], it[1]
        o = it[2] if len(it) > 2 else {}
        last = i == len(items) - 1
        first = (o.get('r', 0) << 7) | (o.get('f2', 0) << 6) | ((0 if last else 1) << 5) | lcid
        hdr += bytes([first])
        if lcid == 0x10 and not mch:
            hdr += bytes([o.get('elcid', 0)])
        if not last and lcid != 0x1f and (mch or lcid not in fixed):
            n = o.get('len', len(body))
            if o.get('f2'):
                hdr += struct.pack('>H', n)
            elif n >= 128 or o.get('f1'):
                hdr += struct.pack('>H', 0x8000 | n)
            else:
                hdr += bytes([n])
        bodies += body
    return hdr + bodies

def srb_rlc(sn=0, data=b'\x01\x00\x00\x00\x00\x00'):
    """RLC AM data PDU, 10 bit SN, no polling, FI=0, E=0."""
    return struct.pack('>H', 0x8000 | (sn & 0x3ff)) + data

def um_rlc(sn, data=b'\xde\xad\xbe\xef', snlen=10):
    if snlen == 5:
        return bytes([(0 << 6) | (0 << 5) | (sn & 0x1f)]) + data
    return struct.pack('>H', (0 << 12) | (sn & 0x3ff)) + data

# ----------------------------------------------------------------- RRC
def rrc_ul_ccch_request(rnd=b'\x11\x22\x33\x44\x55', cause=3):
    b = Bits()
    b.put(0, 1)            # c1
    b.put(1, 1)            # rrcConnectionRequest
    b.put(0, 1)            # criticalExtensions: r8
    b.put(1, 1)            # ue-Identity: randomValue
    for x in rnd:
        b.put(x, 8)
    b.put(cause, 3)        # establishmentCause
    b.put(0, 1)            # spare
    return b.bytes()

def drb_add(b, drbid, lcid, rlc=None, prio=None, pdcp=None):
    b.put(0, 1)                       # DRB-ToAddMod ext bit
    flags = [0, pdcp is not None, rlc is not None, lcid is not None, prio is not None]
    for fl in flags:
        b.put(1 if fl else 0, 1)
    b.put(drbid - 1, 5)
    if pdcp is not None:
        # PDCP-Config: ext(0), discardTimer opt(0), rlc-AM opt, rlc-UM opt, headerCompression
        kind = pdcp
        b.put(0, 1)
        b.put(0, 1)                   # discardTimer absent
        b.put(1 if kind == 'am' else 0, 1)
        b.put(1 if kind == 'um' else 0, 1)
        if kind == 'am':
            b.put(1, 1)               # statusReportRequired
        if kind == 'um':
            b.put(1, 1)               # pdcp-SN-Size len12bits
        b.put(0, 1)                   # headerCompression: notUsed
    if rlc is not None:
        b.put(0, 1)                   # RLC-Config ext
        if rlc == 'am':
            b.put(0, 2)
            b.put(3, 6); b.put(2, 3); b.put(4, 4); b.put(1, 3)   # ul-AM-RLC
            b.put(5, 5); b.put(6, 6)                              # dl-AM-RLC
        elif rlc in ('um5', 'um10'):
            b.put(1, 2)
            b.put(0 if rlc == 'um5' else 1, 1)                    # ul sn-FieldLength
            b.put(0 if rlc == 'um5' else 1, 1); b.put(7, 5)       # dl sn-FieldLength, t-Reordering
        elif rlc in ('um-ul5', 'um-ul10'):
            b.put(2, 2)
            b.put(0 if rlc == 'um-ul5' else 1, 1)
        elif rlc in ('um-dl5', 'um-dl10'):
            b.put(3, 2)
            b.put(0 if rlc == 'um-dl5' else 1, 1); b.put(7, 5)
    if lcid is not None:
        b.put(lcid - 3, 3)
    if prio is not None:
        b.put(0, 1)                   # LogicalChannelConfig ext
        b.put(1, 1)                   # ul-SpecificParameters present
        b.put(0, 1)                   # logicalChannelGroup absent
        b.put(prio - 1, 4); b.put(3, 4); b.put(2, 3)

def rrc_setup(drbs=None, drx=None, mac_ext_phr=False):
    """RRCConnectionSetup (DL CCCH). drbs: list of kwargs for drb_add.
    drx: None, 'release', or dict(short=(cycle, timer)|None)."""
    b = Bits()
    b.put(0, 1); b.put(3, 2)          # c1: rrcConnectionSetup
    b.put(0, 2)                       # transaction id
    b.put(0, 1); b.put(0, 3)          # criticalExtensions c1 -> r8
    b.put(0, 1)                       # RRC-ConnectionSetup-r8-IEs: ext... nonCriticalExtension absent
    b.put(0, 1)                       # RRCD ext
    has_drb = bool(drbs)
    has_mac = drx is not None
    b.put(0, 1)                       # srb
    b.put(1 if has_drb else 0, 1)
    b.put(0, 1)                       # drb release
    b.put(1 if has_mac else 0, 1)
    b.put(0, 2)                       # sps, physical
    if has_drb:
        b.put(len(drbs) - 1, 4)
        for d in drbs:
            drb_add(b, **d)
    if has_mac:
        b.put(0, 1)                   # explicitValue
        b.put(0, 1)                   # MAC-MainConfig ext bit
        b.put(0b010, 3)               # drx-Config only
        if drx == 'release':
            b.put(0, 1)
        else:
            b.put(1, 1)
            sh = drx.get('short')
            b.put(1 if sh else 0, 1)
            b.put(drx.get('on', 0), 4)
            b.put(drx.get('inact', 0), 5)
            b.put(drx.get('retx', 0), 3)
            b.put(0, 4); b.put(drx.get('offset', 0), 4)   # sf10, offset
            if sh:
                b.put(sh[0], 4); b.put(sh[1], 4)
        b.put(7, 3)                   # timeAlignmentTimerDedicated infinity
    return b.bytes()

def mib(sfn=1):
    b = Bits()
    b.put(3, 3); b.put(0, 1); b.put(1, 2); b.put(sfn, 8); b.put(0, 10)
    return b.bytes()

def paging(nrec=2):
    b = Bits()
    b.put(0, 1)                    # c1
    b.put(1, 1); b.put(0, 3)       # pagingRecordList present, others absent
    b.put(nrec - 1, 4)
    for i in range(nrec):
        b.put(0, 1)                # ue-Identity: s-TMSI
        b.put(i, 8); b.put(0x1000 + i, 32)
        b.put(i & 1, 1)            # cn-Domain
    return b.bytes()


# ------------------------------------------------------------- frames
MAIN, MAL = [], []

import atexit
def _write():
    out = sys.argv[1]
    with open(os.path.join(out, 'mac-lte-coverage-udp.pcap'), 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for ts, fr in UDPF:
            f.write(struct.pack('<IIII', ts[0], ts[1], len(fr), len(fr)))
            f.write(fr)
    pcap(os.path.join(out, 'mac-lte-coverage.pcap'), MAIN)
    pcap(os.path.join(out, 'mac-lte-coverage-malformed.pcap'), MAL)
atexit.register(_write)
_t = [1700000000, 0]          # seconds, milliseconds

def tick(ms=1):
    _t[1] += ms
    _t[0] += _t[1] // 1000
    _t[1] %= 1000

def add(cap, c, payload=b'', ms=1):
    tick(ms)
    cap.append(((_t[0], _t[1] * 1000), exp_pdu('mac-lte-framed', c + payload)))

def dl(rnti, items, cap=None, **kw):
    kw.setdefault('rnti', rnti)
    add(cap if cap is not None else MAIN, ctx(DL, C_RNTI, **kw), sch(DL, items))

def ul(rnti, items, cap=None, **kw):
    kw.setdefault('rnti', rnti)
    add(cap if cap is not None else MAIN, ctx(UL, C_RNTI, **kw), sch(UL, items))

B = bytes
PAD = (0x1f, b'\0' * 4)

# ---- out-of-band events
add(MAIN, ctx(UL, C_RNTI, ueid=5, sfn=10, sf=1, preamble=(10, 1)))
add(MAIN, ctx(UL, C_RNTI, ueid=5, sfn=11, sf=2, preamble=(40, 2)))
add(MAIN, ctx(UL, C_RNTI, ueid=6, preamble=(63, 1)))
# Scheduling requests: the first pass has no grant yet, so it flags "SR results in
# neither a grant nor a failure indication" (an error); they go in the malformed capture
add(MAL, ctx(UL, C_RNTI, ueid=5, rnti=0x41, sfn=12, sf=3, sr=[(5, 0x41)]))
add(MAL, ctx(UL, C_RNTI, sr=[(5, 0x41), (6, 0x42), (7, 0x43)]))
add(MAL, ctx(UL, C_RNTI, ueid=6, rnti=0x42, sfn=13, sf=4, sr=[(6, 0x42)]))
# grants that stop the pending SRs (new transmission)
ul(0x41, [(0x1d, B([0x0a]))], cap=MAL, ueid=5, sfn=13, sf=1)
ul(0x42, [(0x1d, B([0x0a]))], cap=MAL, ueid=6, sfn=13, sf=5)
# a grant without a pending SR, and an SR for an RNTI that already has one outstanding
ul(0x43, [(0x1d, B([0x0a]))], ueid=7, sfn=14, sf=1)
add(MAL, ctx(UL, C_RNTI, ueid=8, rnti=0x44, sr=[(8, 0x44)]))
add(MAL, ctx(UL, C_RNTI, ueid=8, rnti=0x44, sr=[(8, 0x44)]))

# ---- RAR
def rar_body(ta=0, grant=0x0a0c05, tc=0x4242, r=0):
    v = (r << 47) | (ta << 36) | (grant << 16) | tc
    return v.to_bytes(6, 'big')

def rar(headers, bodies, ctxkw=None, pad=b'', rnti=0x10, c=None):
    h = b''
    for i, (kind, val) in enumerate(headers):
        e = 0 if i == len(headers) - 1 else 1
        if kind == 'bi':
            h += bytes([(e << 7) | (val & 0xf)])
        else:
            h += bytes([(e << 7) | 0x40 | (val & 0x3f)])
    add(c if c is not None else MAIN, ctx(DL, RA_RNTI, rnti=rnti, sfn=20, sf=4, **(ctxkw or {})),
        h + b''.join(bodies) + pad)

rar([('rapid', 7)], [rar_body()])
rar([('bi', 5), ('rapid', 12)], [rar_body(ta=10)])                    # BI first, TA <= 31 (note)
rar([('bi', 15), ('rapid', 2), ('rapid', 63)], [rar_body(ta=200), rar_body(ta=1, tc=0xfff0)], pad=b'\0\0\0')
rar([('bi', 0)], [])                                                # backoff indicator only
for ce, nul in ((1, 0), (1, 6), (1, 15), (1, 25), (1, 50), (1, 75), (1, 100)):
    rar([('rapid', 5)], [rar_body(grant=0x0abcde & 0xfffff | (nul << 3))],
        ctxkw=dict(ce=ce, nulrb=nul))
rar([('rapid', 5)], [rar_body(grant=0x7f3a1)], ctxkw=dict(ce=2))                  # CE mode B
rar([('bi', 3), ('rapid', 5)], [rar_body(grant=0x5a5a5)], ctxkw=dict(nb=1))       # NB-IoT
rar([('rapid', 5)], [rar_body(grant=0xfedcb)], ctxkw=dict(nb=1, ce=1))
rar([('rapid', 9)], [rar_body()], ctxkw=dict(radio=TDD))

# ---- broadcast channels
SIB1 = bytes.fromhex('68 1a 20 3b 5c 00 41 90'.replace(' ', ''))
add(MAIN, ctx(DL, NO_RNTI, sfn=0, sf=0), mib(1))
add(MAIN, ctx(DL, NO_RNTI, sfn=0, sf=0, nb=1), mib(2))
add(MAIN, ctx(DL, SI_RNTI, sfn=2, sf=5), SIB1)
add(MAIN, ctx(DL, SI_RNTI, sfn=2, sf=5, ce=1), SIB1)
add(MAIN, ctx(DL, SI_RNTI, sfn=2, sf=5, nb=1), SIB1)
add(MAIN, ctx(DL, P_RNTI, sfn=4, sf=9), paging(2))
add(MAIN, ctx(DL, P_RNTI, sfn=4, sf=9), bytes([0x00, 0x00]))                  # no paging records
add(MAIN, ctx(DL, P_RNTI, sfn=4, sf=9, nb=1), paging(1))

# ---- MCH
def mch(items, cap=None, **kw):
    add(cap if cap is not None else MAIN, ctx(DL, M_RNTI, sfn=30, sf=2, **kw), sch(DL, items, mch=True))

mch([(0, b'\x01\x02\x03'), (1, b'\x04' * 5), (28, b'\x05' * 2)])
mch([(0x1e, B([0x01, 0x05, 0x02, 0xff, 0x01, 0xfb, 0x20, 0x00, 0x00, 0x00, 0x03, 0xe0])), (3, b'\xaa\xbb')])
mch([(0x1e, b'\x01\x05\x02\xff')])
mch([(2, b'\x01' * 130), (0x1f, b'\0' * 3)])
mch([(1, b'\x07' * 4, dict(f1=True)), (0x1f, b'\0\0')])
mch([(0x1f, b''), (0x1f, b''), (0x1f, b''), (0, b'\x01')], cap=MAL)

# ---- sidelink
add(MAIN, ctx(DL, SL_BCH_RNTI), bytes([0x12, 0x34, 0x56, 0x78]))
def slsch(items, version=2, cap=None, r=0, **kw):
    hdr = bytes([(version << 4) | r]) + b'\x01\x02\x03' + (b'\x04\x05\x06' if version == 3 else b'\x04\x05')
    sub, bodies = b'', b''
    for i, it in enumerate(items):
        lcid, body = it[0], it[1]
        last = i == len(items) - 1
        sub += bytes([((0 if last else 1) << 5) | lcid])
        if not last and lcid != 0x1f:
            n = len(body)
            sub += struct.pack('>H', 0x8000 | n) if n >= 128 else bytes([n])
        bodies += body
    add(cap if cap is not None else MAIN, ctx(UL, SL_RNTI, sfn=40, sf=1, **kw), hdr + sub + bodies)
slsch([(4, b'\x11' * 6), (5, b'\x22' * 200)])
slsch([(6, b'\x11' * 40)], version=3)
slsch([(0x1f, b''), (7, b'\x33' * 3), (0x1f, b'\0')], version=2, cap=MAL)
slsch([(0x1f, b'')] * 1 + [(8, b'\x44' * 2)], version=2)
slsch([(9, b'')], version=2)

# ---- UL-SCH / DL-SCH
# CCCH Msg3 with the RRCConnectionRequest and the matching contention resolution
REQ = rrc_ul_ccch_request()
ul(0x50, [(0, REQ)], ueid=20, sfn=50, sf=1)
dl(0x50, [(0x1c, REQ[:6]), (0, rrc_setup(drbs=[dict(drbid=1, lcid=3, rlc='am', prio=5, pdcp='am')]))],
   ueid=20, sfn=50, sf=5)
# contention resolution that does not match, and one with no Msg3
dl(0x51, [(0x1c, b'\x01\x02\x03\x04\x05\x06')], ueid=21, sfn=51, sf=5)
ul(0x52, [(0, REQ[::-1])], ueid=22, sfn=52, sf=1)
dl(0x52, [(0x1c, REQ[:6])], ueid=22, sfn=52, sf=5)

# ---- UL-SCH control elements (each last, no length) and data
RN = 0x60
n = 0
def ulsn(items, **kw):
    global n
    n += 1
    kw.setdefault('ueid', 30)
    kw.setdefault('sfn', 100 + n)
    kw.setdefault('sf', n % 10)
    ul(RN, items, **kw)

ulsn([(0x0f, b'\x01\x02')])
ulsn([(0x11, b'\x05')])
ulsn([(0x12, b'\x10\x20\x30\x40')])
ulsn([(0x13, b'\x08')])
ulsn([(0x14, b'\x04\x00')])
ulsn([(0x15, b'')])
ulsn([(0x1a, b'\x15')])
ulsn([(0x1b, b'\x01\x23')])
ulsn([(0x1c, b'\x35')])
ulsn([(0x1d, b'\x2a')])
ulsn([(0x1e, b'\x1b\x2c\x3d')])
ulsn([(0x1e, b'\xff\xff\xff')])
# BSR with the extended sizes tag, buffer size above the warning threshold
ulsn([(0x1d, b'\x7f')], extbsr=True)
ulsn([(0x1e, b'\x6a\xbf\xd4')], extbsr=True)
ulsn([(0x1c, b'\x7f')], extbsr=True)
# PHR, C-RNTI and BSR combined with data and padding
ulsn([(0x1b, b'\x01\x23'), (0x1a, b'\x15'), (0x1d, b'\x2a'), (3, b'\x11\x22\x33\x44')])
ulsn([(0x1a, b'\x05'), (0x1e, b'\x01\x02\x03'), (1, srb_rlc()), (2, srb_rlc(1)), (0x1f, b'\0' * 5)])
ulsn([(0x1f, b''), (0x1a, b'\x15'), (3, b'\xaa' * 130), (4, b'\xbb' * 3), (5, b'\xcc' * 200)])
ulsn([(3, b'\x01' * 20, dict(f1=True)), (10, b'\x02' * 5)])
ulsn([(0x10, b'\x11' * 7, dict(elcid=0)), (0x10, b'\x22' * 4, dict(elcid=5)), (0x10, b'\x33' * 4, dict(elcid=6))])
ulsn([(11, REQ), (12, b'\x01' * 6), (13, b'\x02' * 6), (3, b'\x03' * 3)])
ulsn([(3, b'\x01' * 20)])
ulsn([(0x1f, b''), (0x1f, b''), (0x1a, b'\x10')])
# header-only (SDUs omitted): last subheader data, no body
add(MAIN, ctx(UL, C_RNTI, rnti=RN, ueid=30, sfn=140, sf=2), bytes([0x23, 0x04, 0x03]))

# ---- DL-SCH control elements and data
RD = 0x61
m = 0
def dlsn(items, **kw):
    global m
    m += 1
    kw.setdefault('ueid', 31)
    kw.setdefault('sfn', 200 + m)
    kw.setdefault('sf', m % 10)
    dl(RD, items, **kw)

dlsn([(0x11, b'')])
dlsn([(0x12, b'\xa5')])
dlsn([(0x13, b'\xfe')])
dlsn([(0x14, b'\xfe\xaa\x55\x0f')])
dlsn([(0x15, b'\xc0\x80\x40')])
dlsn([(0x15, b'\xff')])
dlsn([(0x16, b'\x54\x00')])
dlsn([(0x17, b'')])
dlsn([(0x18, b'\x82\x01\x80\xff')])
dlsn([(0x1a, b'')])
dlsn([(0x1b, b'\xe6')])
dlsn([(0x1d, b'\x1f')])
dlsn([(0x1d, b'\x20')])
dlsn([(0x1d, b'\x00')])
dlsn([(0x1e, b'')])
# contention resolution identity, with no earlier Msg3 for this RNTI
dlsn([(0x1c, b'\x01\x02\x03\x04\x05\x06')])
# combinations with data
dlsn([(0x1d, b'\x1f'), (0x1b, b'\xe6'), (1, srb_rlc()), (3, b'\xaa' * 4), (0x1f, b'\0' * 4)])
dlsn([(0x1f, b''), (0x1d, b'\x1f'), (2, srb_rlc(2)), (4, b'\x01' * 200), (5, b'\x02' * 3)])
dlsn([(0x10, b'\x11' * 7, dict(elcid=1)), (10, b'\x22' * 4)])
dlsn([(0, rrc_setup(drbs=[dict(drbid=2, lcid=4, rlc='um10', prio=8, pdcp='um')]))], ueid=40)

# ---- variable-size UL control elements
ulsn([(0x16, b'\x10\x20\x30')])                              # truncated sidelink BSR, 2 entries
ulsn([(0x17, b'\x10\x20\x30\x40\x50')])                      # sidelink BSR, 4 entries
ulsn([(0x17, b'\x10\x20')])                                  # one entry
ulsn([(0x16, b'\x30\x40\x00'), (3, b'\x01\x02')])            # followed by data
# Extended PHR: no SCell; with SCell 1 and 3; with Pcmax,c present
ulsn([(0x19, b'\x00\x45')])
ulsn([(0x19, b'\x00\x05\x2a')])
ulsn([(0x19, b'\xa0\x45\x46\x47')])
ulsn([(0x19, b'\x80\x05\x2a\x46')])
ulsn([(0x19, b'\x00\x45\x46')], simult_p=True)                # Type 2 report for the PCell
ulsn([(0x19, b'\x00\x05\x2a\x45')], simult_p=True)
# Dual connectivity PHR: 1 C octet, with SCell, Pcmax,c, PUCCH reports, 4 C octets
ulsn([(0x18, b'\x00\x45')])
ulsn([(0x18, b'\x02\x45\x46')])
ulsn([(0x18, b'\x00\x05\x2a')])
ulsn([(0x18, b'\x00\x45\x46')], simult_p=True)
ulsn([(0x18, b'\x00\x05\x1b\x46')], simult_p=True)
ulsn([(0x18, b'\x00\x45\x46')], simult_ps=True)
ulsn([(0x18, b'\x00\x45\x05\x1b\x46')], simult_p=True, simult_ps=True)
ulsn([(0x18, b'\x02\x00\x00\x00\x45\x46')])
ulsn([(0x18, b'\x02\x00\x00\x00\x05\x1b\x45')])
ulsn([(0x18, b'\x04\x80\x00\x00\x45\x46\x47')], cap=MAL)
ulsn([(0x18, b'\x00\x00\x01\x00\x45\x46\x47')], cap=MAL)
# NB-IoT: data volume and power headroom in front of CCCH, and the extended PHR variant
ulsn([(0, b'\x1b' + REQ)], nb=1)
ulsn([(13, b'\xa5' + REQ)], nb=1)
ulsn([(0, b'')], nb=1)
ulsn([(1, srb_rlc())], nb=1)
ulsn([(3, srb_rlc())], nb=1)
# SPS, G-RNTI and SC-RNTI C-RNTI types
add(MAIN, ctx(UL, SPS_RNTI, rnti=0x77, ueid=33, sfn=300, sf=1), sch(UL, [(3, b'\x01' * 4)]))
add(MAIN, ctx(DL, G_RNTI, rnti=0x78, ueid=34, sfn=301, sf=1), sch(DL, [(4, b'\x01' * 4)]))
add(MAIN, ctx(DL, SC_RNTI, sfn=302, sf=1), sch(DL, [(0x19, b'\x00' * 2)]))
add(MAIN, ctx(DL, SC_RNTI, sfn=302, sf=2), sch(DL, [(0x1f, b''), (0x19, b'\x01\x02\x03')]))
add(MAIN, ctx(DL, SC_RNTI, sfn=302, sf=3), sch(DL, [(0x19, b'\x00', {}), (0x1f, b'')]))
add(MAL, ctx(DL, SC_RNTI, sfn=302, sf=4), sch(DL, [(0x17, b''), (0x19, b'\x04\x05')]))

# ---- PHY information, carrier, retx, CRC, predefined data
add(MAIN, ctx(UL, C_RNTI, rnti=0x80, ueid=50, sfn=310, sf=1, phy=ulphy(mod=2, harq=0)), sch(UL, [(3, b'\x01' * 8)]))
add(MAIN, ctx(UL, C_RNTI, rnti=0x80, ueid=50, sfn=311, sf=1, phy=ulphy(mod=4, tbs=20, rbl=10, rbs=0, harq=1, ndi=0), carrier=1), sch(UL, [(3, b'\x02' * 8)]))
add(MAIN, ctx(UL, C_RNTI, rnti=0x80, ueid=50, sfn=312, sf=1, phy=ulphy(mod=6, harq=9), carrier=7, crc=1), sch(UL, [(3, b'\x03' * 8)]))
add(MAIN, ctx(UL, C_RNTI, rnti=0x80, ueid=50, sfn=313, sf=1, phy=[0, 0, 0, 0, 0]), sch(UL, [(3, b'\x04' * 8)]))   # PHY too short
add(MAIN, ctx(UL, C_RNTI, rnti=0x80, ueid=50, sfn=314, sf=1, retx=1), sch(UL, [(3, b'\x05' * 8)]))
add(MAIN, ctx(UL, C_RNTI, rnti=0x80, ueid=50, sfn=315, sf=1, retx=4), sch(UL, [(3, b'\x06' * 8)]))
add(MAIN, ctx(DL, C_RNTI, rnti=0x81, ueid=51, sfn=310, sf=1, phy=dlphy(dci=1, agg=1, harq=2)), sch(DL, [(3, b'\x01' * 8)]))
add(MAIN, ctx(DL, C_RNTI, rnti=0x81, ueid=51, sfn=311, sf=1, phy=dlphy(dci=3, ra=1, agg=8, tb=1, harq=3, retx=1), carrier=2), sch(DL, [(3, b'\x02' * 8)]))
add(MAIN, ctx(DL, C_RNTI, rnti=0x81, ueid=51, sfn=312, sf=1, phy=dlphy(dci=5, ra=2, agg=4, harq=14, retx=2, ndi=0)), sch(DL, [(3, b'\x03' * 8)]))
add(MAIN, ctx(DL, C_RNTI, rnti=0x81, ueid=51, sfn=313, sf=1, phy=dlphy(dci=2, harq=15), crc=1), sch(DL, [(3, b'\x04' * 8)]))   # harq id out of range
add(MAIN, ctx(DL, C_RNTI, rnti=0x81, ueid=51, sfn=314, sf=1, phy=dlphy(dci=2, tb=2)), sch(DL, [(3, b'\x05' * 8)]))
add(MAIN, ctx(DL, C_RNTI, rnti=0x81, ueid=51, sfn=315, sf=1, phy=[1, 0, 0, 0, 0, 0, 0, 0, 0]), sch(DL, [(3, b'\x05' * 8)]))
add(MAIN, ctx(DL, C_RNTI, rnti=0x81, ueid=51, sfn=316, sf=1, retx=2), sch(DL, [(3, b'\x06' * 8)]))
add(MAIN, ctx(UL, C_RNTI, rnti=0x82, ueid=52, sfn=320, sf=1, predef=1), b'\xde\xad\xbe\xef' * 4)
add(MAIN, ctx(DL, C_RNTI, rnti=0x82, ueid=52, sfn=321, sf=1, predef=1), b'\xde\xad\xbe\xef' * 4)
add(MAIN, ctx(DL, C_RNTI, rnti=0x82, ueid=52, sfn=322, sf=1, predef=0), sch(DL, [(3, b'\x01' * 4)]))
add(MAIN, ctx(DL, P_RNTI, sfn=323, sf=1), bytes([0x40, 0x80, 0x00]))

# ---- DRX (needs mac-lte.show_drx); config from RRC, then PDUs that move time on
DRX_UE = 70
add(MAIN, ctx(DL, C_RNTI, rnti=0x90, ueid=DRX_UE, sfn=500, sf=0),
    sch(DL, [(0, rrc_setup(drx=dict(short=(1, 4), on=2, inact=3, retx=2, offset=3)))]))
def drxf(direction, sfn, sf, items, secs=0, ms=1, **kw):
    if secs:
        _t[0] += secs
    kw.setdefault('rnti', 0x90)
    kw.setdefault('ueid', DRX_UE)
    add(MAIN, ctx(direction, C_RNTI, sfn=sfn, sf=sf, **kw), sch(direction, items), ms=ms)
drxf(UL, 500, 3, [(3, b'\x01' * 4)])
drxf(UL, 500, 5, [(3, b'\x01' * 4)])
drxf(DL, 501, 2, [(3, b'\x01' * 4)], phy=dlphy(harq=1, retx=0))
drxf(DL, 501, 6, [(3, b'\x02' * 4)], phy=dlphy(harq=1, retx=1, ndi=1))
drxf(DL, 502, 3, [(3, b'\x03' * 4)], phy=dlphy(harq=2, retx=0))
drxf(UL, 503, 9, [(0x1d, b'\x0a')], retx=1)
drxf(DL, 510, 0, [(0x1e, b'')])
drxf(DL, 520, 4, [(0x1a, b''), (3, b'\x01' * 4)])
drxf(UL, 530, 2, [(3, b'\x01' * 4)])
drxf(UL, 1020, 7, [(3, b'\x01' * 4)])
drxf(UL, 1023, 9, [(3, b'\x01' * 4)])
drxf(UL, 3, 1, [(3, b'\x01' * 4)])
drxf(UL, 400, 1, [(3, b'\x01' * 4)], secs=20)                  # more than 9 s since the last PDU
drxf(DL, 410, 1, [(3, b'\x02' * 4)], phy=dlphy(harq=4, retx=0))
drxf(DL, 420, 8, [(3, b'\x02' * 4)], phy=dlphy(harq=5, retx=0), crc=1)
# a second UE with a long cycle only, then a release
add(MAIN, ctx(DL, C_RNTI, rnti=0x91, ueid=71, sfn=600, sf=0),
    sch(DL, [(0, rrc_setup(drx=dict(on=1, inact=1, retx=1, offset=7)))]))
drxf(UL, 600, 4, [(3, b'\x01' * 4)], rnti=0x91, ueid=71)
drxf(UL, 640, 4, [(3, b'\x01' * 4)], rnti=0x91, ueid=71)
add(MAIN, ctx(DL, C_RNTI, rnti=0x91, ueid=71, sfn=641, sf=0), sch(DL, [(0, rrc_setup(drx='release'))]))
drxf(UL, 650, 4, [(3, b'\x01' * 4)], rnti=0x91, ueid=71)
# CRC-failed DL PDU on the DRX UE (the dissector counts it as a DL error) and a UL grant with CRC failure

# ---- several UEs in the same TTI (same subframe within a millisecond)
add(MAIN, ctx(UL, C_RNTI, rnti=0xa0, ueid=80, sfn=700, sf=3), sch(UL, [(3, b'\x01' * 4)]), ms=5)
add(MAIN, ctx(UL, C_RNTI, rnti=0xa1, ueid=81, sfn=700, sf=3), sch(UL, [(3, b'\x01' * 4)]), ms=0)
add(MAIN, ctx(UL, C_RNTI, rnti=0xa2, ueid=82, sfn=700, sf=3), sch(UL, [(3, b'\x01' * 4)]), ms=0)

# ================================================================ malformed
def bad(direction, rntitype, payload, **kw):
    add(MAL, ctx(direction, rntitype, **kw), payload)

# RNTI values that do not fit the RNTI type
bad(DL, M_RNTI, sch(DL, [(0, b'\x01')], mch=True), rnti=5, sfn=1, sf=1)
bad(DL, P_RNTI, paging(1), rnti=5)
bad(DL, SI_RNTI, SIB1, rnti=7)
bad(DL, RA_RNTI, b'\x40' + rar_body(), rnti=0x961)
bad(DL, RA_RNTI, b'\x40' + rar_body(), rnti=0)
bad(UL, C_RNTI, sch(UL, [(3, b'\x01')]), rnti=0xfff4)
bad(UL, C_RNTI, sch(UL, [(3, b'\x01')]), rnti=0)
# system frame and subframe numbers out of range
bad(UL, C_RNTI, sch(UL, [(3, b'\x01')]), rnti=0x20, ueid=1, sfn=2000, sf=3)
bad(UL, C_RNTI, sch(UL, [(3, b'\x01')]), rnti=0x20, ueid=1, sfn=5, sf=12)
# BCH and PCH data in the uplink
bad(UL, NO_RNTI, mib(1))
bad(UL, P_RNTI, paging(1))
# CRC errors (CRC failed PDUs are shown as raw data), with SR tracking on UL
for crc in (0, 2, 3, 4, 5, 9):
    bad(UL, C_RNTI, sch(UL, [(3, b'\x01' * 6)]), rnti=0x21, ueid=2, sfn=10, sf=crc, crc=crc)
    bad(DL, C_RNTI, sch(DL, [(3, b'\x01' * 6)]), rnti=0x21, ueid=2, sfn=10, sf=crc, crc=crc)
bad(UL, C_RNTI, sch(UL, [(3, b'\x01' * 6)]), rnti=0x21, ueid=2, sfn=11, sf=1, crc=0, retx=1)
# RAR errors: reserved bits, two backoff indicators, BI after a RAPID, reserved bit in the body
add(MAL, ctx(DL, RA_RNTI, rnti=0x10, sfn=1, sf=1), bytes([0x80 | 0x30 | 5, 0x40 | 3]) + rar_body())
add(MAL, ctx(DL, RA_RNTI, rnti=0x10, sfn=1, sf=1), bytes([0x80 | 5, 0x80 | 6, 0x40 | 3]) + rar_body())
add(MAL, ctx(DL, RA_RNTI, rnti=0x10, sfn=1, sf=1), bytes([0x80 | 0x40 | 3, 5]) + rar_body())
add(MAL, ctx(DL, RA_RNTI, rnti=0x10, sfn=1, sf=1), bytes([0x40 | 3]) + rar_body(r=1))
# unknown framing tag, empty SR list, SR list too long
add(MAL, ctx(UL, C_RNTI, rnti=0x20, raw=b'\x7f'), sch(UL, [(3, b'\x01')]))
add(MAL, bytes([FDD, UL, C_RNTI, 0x11, 0, 0, 0x01]), sch(UL, [(3, b'\x01')]))
add(MAL, bytes([FDD, UL, C_RNTI, 0x11, 0, 21]) + b'\0' * 84 + b'\x01', sch(UL, [(3, b'\x01')]))
# header errors of UL/DL-SCH
ULX = dict(rnti=0x30, ueid=3)
def ulbad(items, **kw):
    kw = dict(dict(ULX, sfn=20, sf=1), **kw)
    ul(kw.pop('rnti'), items, cap=MAL, **kw)
def dlbad(items, **kw):
    kw = dict(dict(rnti=0x31, ueid=4, sfn=20, sf=1), **kw)
    dl(kw.pop('rnti'), items, cap=MAL, **kw)
ulbad([(3, b'\x01' * 4, dict(r=1)), (0x1f, b'\0')])
ulbad([(3, b'\x01' * 4), (0x1a, b'\x15')])                     # control after data
ulbad([(0x1d, b'\x0a'), (0x1c, b'\x0a')])                      # two BSRs
ulbad([(0x1f, b''), (0x1f, b''), (0x1f, b''), (0x1a, b'\x15')])   # three padding subheaders
ulbad([(0x1a, b'\x15'), (0x1f, b''), (0x1d, b'\x0a')])         # padding after control
ulbad([(0x1f, b''), (0x1d, b'\x0a'), (0x1f, b'\0\0')])         # padding at start and end
ulbad([(3, b'\x01' * 4), (3, b'\x02' * 4, dict(f2=1, len=5)), (4, b'\x03')])   # format2 with a short length
ulbad([(3, b'\x01' * 4), (3, b'\x02' * 4, dict(f2=1, len=0x8004)), (4, b'')][:2] + [(4, b'\x03')])
ulbad([(0x0e, b'\x01' * 4), (0x0d, b'\x01')])                  # unknown LCIDs (13 is NB-IoT CCCH, 14 reserved)
ulbad([(0x10, b'\x01', dict(elcid=0xc0)), (4, b'\x01')])        # reserved bits in the extended LCID byte
ulbad([(0x14, b'\x04\x01')])                                    # recommended bit rate query, reserved bits
ulbad([(0x1a, b'\xc5')])                                        # PHR reserved bits
ulbad([(0x19, b'\x01\x45')])                                    # extended PHR reserved bit
ulbad([(0x19, b'\x00\x05\xc0')])                                # Pcmax reserved bits
ulbad([(0x19, b'\x00\x45\x46\x47\x48')])                        # unexpected extended PHR size
ulbad([(0x19, b'\x00\x45\x46')], simult_p=True)
ulbad([(0x19, b'\x00\x45\x46\x47')], simult_p=True)
ulbad([(0x18, b'\x01\x45')])                                    # DC PHR reserved bit
ulbad([(0x18, b'\x00\x05\xc1')])
ulbad([(0x18, b'\x00\x45\x05\xc1\x46')], simult_p=True)
ulbad([(0x18, b'\x00\x45\x05\xc1\x46')], simult_ps=True, simult_p=True)
ulbad([(0x18, b'\x02\x45\x05\xc1')])
ulbad([(0x17, b'\x10\x21')])                                    # sidelink BSR, reserved bits
ulbad([(0x16, b'\x10\x21')])
ulbad([(0x1b, b'\x01\x02'), (0x1f, b''), (3, b'\x01'), (0x1f, b'\0')])
ulbad([(0x1b, b'\x01\x02')] + [(3, b'\x01')] * 1, rnti=0x32)
add(MAL, ctx(UL, C_RNTI, rnti=0x33, ueid=5, sfn=21, sf=1), sch(UL, [(0x1b, b'\x01\x02')]) + b'\xaa\xbb')   # PDU shorter than reported
add(MAL, ctx(UL, C_RNTI, rnti=0x33, ueid=5, sfn=21, sf=2), sch(UL, [(0x1f, b'')]))
dlbad([(0x1d, b'\x0a'), (0x1b, b'\x0a'), (0x1f, b'')])         # padding at the end
dlbad([(0x1f, b''), (0x1f, b''), (0x1f, b''), (0x1d, b'\x0a')])
dlbad([(0x16, b'\x00\x01')])                                    # recommended bit rate, reserved bits
dlbad([(0x1b, b'\x80')])
dlbad([(0x18, b'\x81\x01\x80\xff')])
dlbad([(0x12, b'\x81')])
dlbad([(0x0d, b''), (0x1e, b'')])                               # unknown LCID
dlbad([(0x19, b''), (0x1a, b'')])                               # SC-MCCH/SC-MTCH header with a control element
dlbad([(0x19, b'\x01'), (0x1f, b'')], rnti=0x34)
# DL-SCH TA command: no correction needed (31) and correction needed
dlbad([(0x1d, b'\x1f')])
dlbad([(0x1d, b'\x00')])
# too many subheaders: 1024 subheaders with the extension bit set
add(MAL, ctx(UL, C_RNTI, rnti=0x35, ueid=6, sfn=22, sf=1), bytes([0x23, 0x00]) * 1024 + b'\x01')
add(MAL, ctx(DL, C_RNTI, rnti=0x36, ueid=6, sfn=22, sf=1), bytes([0x1f | 0x20]) * 1024 + b'\x01')
# PDU shorter and longer than the reported length (the subheader lengths exceed the data)
add(MAL, ctx(UL, C_RNTI, rnti=0x37, ueid=7, sfn=23, sf=1), bytes([0x23, 0x10, 0x04]) + b'\x01' * 6)
add(MAL, ctx(UL, C_RNTI, rnti=0x37, ueid=7, sfn=23, sf=2), bytes([0x23, 0x02, 0x04]) + b'\x01' * 9)
add(MAL, ctx(UL, C_RNTI, rnti=0x37, ueid=7, sfn=23, sf=3), bytes([0x3f, 0x05, 0x1f]) + b'\x01' * 9)
# MCH errors
mch([(0, b'\x01'), (0x1e, b'\x01\x05')], cap=MAL)                # control after data
mch([(3, b'\x01' * 4), (3, b'\x02', dict(f2=1, len=5)), (4, b'')], cap=MAL)
mch([(0x1e, b'\x01\x05\x02'), (0x1f, b'')], cap=MAL)             # odd scheduling info length
mch([(0x1d, b'\x01'), (1, b'')], cap=MAL)
add(MAL, ctx(DL, M_RNTI, sfn=1, sf=1), bytes([0x80 | 0x00]) + b'\x01')
add(MAL, ctx(DL, M_RNTI, sfn=1, sf=1), bytes([0x20 | 0x1e, 0x04, 0x1e, 0x00]) + b'\x01\x02\x03\x04')
add(MAL, ctx(DL, M_RNTI, sfn=1, sf=1), bytes([0x20 | 0x1e, 0x02, 0x1e]) + b'\x07\xfb')   # no data subheaders: reserved stop MTCH
add(MAL, ctx(DL, M_RNTI, sfn=1, sf=1), bytes([0x20 | 0x1e, 0x04, 0x1e]) + b'\x07\xfb\x07\xff')
add(MAL, ctx(DL, M_RNTI, sfn=1, sf=1), bytes([0x20, 0x1e]) + b'\x05')
add(MAL, ctx(DL, M_RNTI, sfn=1, sf=1), bytes([0x20 | 0x1f, 0x00]) + b'\x01\x02')
add(MAL, ctx(DL, M_RNTI, sfn=1, sf=1), bytes([0x20 | 0x00, 0x04, 0x1f]) + b'\x01\x02')
add(MAL, ctx(DL, M_RNTI, sfn=1, sf=1), bytes([0x20 | 0x1f] * 1024) + b'\x01')
# SL-SCH errors: reserved bits, padding at start and end, three paddings, unknown LCID, too many
slsch([(4, b'\x01')], r=1, cap=MAL)
slsch([(0x1f, b''), (4, b'\x01'), (0x1f, b'\0')], cap=MAL)
slsch([(0x1f, b''), (0x1f, b''), (0x1f, b''), (4, b'\x01')], cap=MAL)
slsch([(0x15, b'\x01' * 3), (0x18, b'\x01')], cap=MAL)
add(MAL, ctx(UL, SL_RNTI, rnti=0x10, sfn=1, sf=1), bytes([0x20, 1, 2, 3, 4, 5, 0xc4, 0x04]) + b'\x01\x02\x03\x04')
add(MAL, ctx(UL, SL_RNTI, rnti=0x10, sfn=1, sf=1), bytes([0x20, 1, 2, 3, 4, 5, 0x20 | 0x04, 0x04, 0x04, 0x01]) + b'\x01')
add(MAL, ctx(UL, SL_RNTI, rnti=0x10, sfn=1, sf=1), bytes([0x20, 1, 2, 3, 4, 5] + [0x20 | 0x1f] * 1024) + b'\x01')
add(MAL, ctx(UL, SL_RNTI, rnti=0x10, sfn=1, sf=1), bytes([0x20, 1, 2, 3, 4, 5, 0x04]) + b'\x01\x02\x03')
add(MAL, ctx(UL, SL_RNTI, rnti=0x10, sfn=1, sf=1), bytes([0x20, 1, 2, 3, 4, 5, 0x1f]) + b'\x01\x02\x03')

# ---- RLC channels learned from RRC (mac-lte.lcid_to_drb_mapping_source) and RLC data on them
def amd(sn=0, data=b'\x11\x22\x33\x44'):
    return struct.pack('>H', 0x8000 | sn) + data
def rrc_drbs(ue, drbs, rnti):
    add(MAIN, ctx(DL, C_RNTI, rnti=rnti, ueid=ue, sfn=800, sf=1), sch(DL, [(0, rrc_setup(drbs=drbs))]))
rrc_drbs(20, [dict(drbid=3, lcid=5, rlc='um5', prio=3), dict(drbid=4, lcid=6, rlc='um-ul10'),
              dict(drbid=5, lcid=7, rlc='um-dl5'), dict(drbid=6, lcid=None, rlc='am'),
              dict(drbid=7, lcid=8, pdcp='am'), dict(drbid=8, lcid=9, rlc='um-ul5', pdcp='um'),
              dict(drbid=9, lcid=10, rlc='um-dl10', prio=16)], 0x50)
rrc_drbs(41, [dict(drbid=1, lcid=3, rlc='um10', prio=1)], 0x92)
def drbdata(ue, rnti, items, d=DL, **kw):
    kw.setdefault('sfn', 810)
    kw.setdefault('sf', 2)
    add(MAIN, ctx(d, C_RNTI, rnti=rnti, ueid=ue, **kw), sch(d, items))
for d in (DL, UL):
    drbdata(20, 0x50, [(3, amd()), (5, um_rlc(1, snlen=5)), (6, um_rlc(2)), (7, um_rlc(3, snlen=5)), (8, amd(4)),
                       (9, um_rlc(5, snlen=5)), (10, um_rlc(6))], d=d)
    drbdata(40, 0x95, [(4, um_rlc(7)), (3, b'\x01\x02\x03')], d=d)
    drbdata(41, 0x92, [(3, um_rlc(8))], d=d)
    drbdata(20, 0x50, [(0x10, amd(), dict(elcid=0)), (0x10, um_rlc(9), dict(elcid=3)), (4, b'\x01\x02')], d=d)
# header-only PDUs (SDUs omitted) with extended LCIDs
add(MAIN, ctx(DL, C_RNTI, rnti=0x50, ueid=20, sfn=811, sf=1), bytes([0x30 | 0x00, 0x00, 0x04, 0x10 | 0x00, 0x03]))
add(MAIN, ctx(DL, C_RNTI, rnti=0x50, ueid=20, sfn=811, sf=2), bytes([0x30, 0x03, 0x0a, 0x10, 0x06]))
add(MAIN, ctx(DL, C_RNTI, rnti=0x50, ueid=20, sfn=811, sf=3), bytes([0x30, 0x00, 0x05, 0x1f]))
add(MAIN, ctx(UL, C_RNTI, rnti=0x50, ueid=20, sfn=811, sf=4), bytes([0x30, 0x03, 0x05, 0x1f]))
add(MAIN, ctx(DL, C_RNTI, rnti=0x50, ueid=20, sfn=811, sf=5), bytes([0x3d, 0x03, 0x1f]) )

# ---- HARQ retransmission tracking: the link to the next transmission is added on the
# second pass only, so one pass and two passes differ; these go in the malformed capture
def harq(direction, rnti, harq_id, ndi, gap_ms, data, retx=None, **kw):
    ph = ulphy(harq=harq_id, ndi=ndi) if direction == UL else dlphy(harq=harq_id, ndi=ndi, tb=kw.pop('tb', 0))
    c = ctx(direction, C_RNTI, rnti=rnti, ueid=kw.pop('ueid', 90), sfn=900, sf=1, phy=ph,
            retx=retx)
    add(MAL, c, sch(direction, [(3, data)]), ms=gap_ms)
harq(UL, 0xb0, 1, 1, 1, b'\x01' * 10)
harq(UL, 0xb0, 1, 1, 8, b'\x01' * 10, retx=1)          # retransmission of the first PDU
harq(UL, 0xb0, 1, 1, 8, b'\x01' * 10, retx=2)          # and again
harq(UL, 0xb0, 2, 1, 8, b'\x02' * 10, retx=1)          # no original found (different data)
harq(UL, 0xb0, 1, 1, 100, b'\x01' * 10, retx=1)        # too late
harq(UL, 0xb1, 1, 1, 1, b'\x01' * 10, retx=1)          # first frame of a new UE
harq(DL, 0xb2, 1, 1, 1, b'\x03' * 10)
harq(DL, 0xb2, 1, 1, 8, b'\x03' * 10)                  # DL retransmission detected
harq(DL, 0xb2, 1, 1, 8, b'\x03' * 10)
harq(DL, 0xb2, 1, 1, 30, b'\x03' * 10)                 # gap too large
harq(DL, 0xb2, 2, 0, 1, b'\x04' * 10, tb=1)
harq(DL, 0xb2, 2, 0, 9, b'\x04' * 10, tb=1)
# DRX UE with a CRC-failed DL PDU (starts the retransmission timer)
add(MAL, ctx(DL, C_RNTI, rnti=0xb3, ueid=72, sfn=950, sf=0), sch(DL, [(0, rrc_setup(drx=dict(on=2, inact=3, retx=2, offset=3)))]))
add(MAL, ctx(DL, C_RNTI, rnti=0xb3, ueid=72, sfn=950, sf=5, crc=0), sch(DL, [(3, b'\x01' * 4)]))
add(MAL, ctx(DL, C_RNTI, rnti=0xb3, ueid=72, sfn=951, sf=5, crc=0), sch(DL, [(3, b'\x01' * 4)]))
add(MAL, ctx(UL, C_RNTI, rnti=0xb3, ueid=72, sfn=952, sf=5, crc=0), sch(UL, [(3, b'\x01' * 4)]))
# out of range SFN and SF with DRX configured (the fix of "MAC-LTE: Fix OOB read, per-RNTI memory use and a DRX loop")
add(MAL, ctx(UL, C_RNTI, rnti=0xb3, ueid=72, sfn=953, sf=12), sch(UL, [(3, b'\x01' * 4)]))
add(MAL, ctx(UL, C_RNTI, rnti=0xb3, ueid=72, sfn=2000, sf=3), sch(UL, [(3, b'\x01' * 4)]))
# extended LCID 63 (LCID 95) with a per-UE mapping: out of bounds before the fix
add(MAIN, ctx(DL, C_RNTI, rnti=0x100, ueid=7, sfn=1, sf=1), sch(DL, [(0, rrc_setup(drbs=[dict(drbid=1, lcid=3)]))]))
add(MAIN, ctx(UL, C_RNTI, rnti=0x100, ueid=7, sfn=2, sf=1), bytes([0x10, 0x3f]) + b'\xaa' * 8)
add(MAIN, ctx(UL, C_RNTI, rnti=0x100, ueid=7, sfn=3, sf=1), sch(UL, [(0x10, b'\xaa' * 4, dict(elcid=6)), (0x10, b'\xbb' * 4, dict(elcid=7)), (0x10, b'\xcc' * 4, dict(elcid=63))]))
# many distinct RNTIs with PHY info (the HARQ tables are per RNTI; small here)
for i in range(6):
    add(MAIN, ctx(UL, C_RNTI, rnti=0x200 + i, sfn=4, sf=1, phy=ulphy(harq=0)), sch(UL, [(3, b'\x01' * 4)]))
    add(MAIN, ctx(DL, C_RNTI, rnti=0x200 + i, sfn=4, sf=1, phy=dlphy(harq=0)), sch(DL, [(3, b'\x01' * 4)]))

# ---- UDP framing (heuristic "mac_lte_udp", disabled by default; only runcov.sh enables it)
UDPF = []
def ip_udp(payload, port=9999):
    u = struct.pack('>HHHH', port, port, 8 + len(payload), 0) + payload
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(u), 1, 0, 64, 17, 0, bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]))
    s = sum(struct.unpack('>10H', ip))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    ip = ip[:10] + struct.pack('>H', ~s & 0xffff) + ip[12:]
    return bytes.fromhex('020000000002020000000001') + b'\x08\x00' + ip + u
def udpf(c, payload):
    tick(1)
    UDPF.append(((_t[0], _t[1] * 1000), ip_udp(b'mac-lte' + c + payload)))
udpf(ctx(UL, C_RNTI, rnti=0x41, ueid=1, sfn=1, sf=1), sch(UL, [(3, b'\x01' * 4)]))
udpf(ctx(DL, C_RNTI, rnti=0x41, ueid=1, sfn=1, sf=2, phy=dlphy()), sch(DL, [(1, srb_rlc())]))
udpf(ctx(DL, SI_RNTI), SIB1)
udpf(ctx(UL, C_RNTI, rnti=0x41, raw=b'\x7f'), b'\x01\x02')      # unknown tag
udpf(ctx(UL, C_RNTI, rnti=0x41, sr=[(1, 0x41)]), b'')
udpf(bytes([FDD, UL, C_RNTI, 0x11, 0, 0, 0x01]), b'\x01\x02')   # empty SR list
UDPF.append(((_t[0], _t[1] * 1000), ip_udp(b'mac-lte' + b'\x01\x00')))                 # too short
UDPF.append(((_t[0], _t[1] * 1000), ip_udp(b'not-mac-lte-at-all')))                    # wrong signature

# a framed PDU too short for the fixed fields, the data tag and one octet of MAC PDU
tick(1)
MAL.append(((_t[0], _t[1] * 1000), exp_pdu('mac-lte-framed', bytes([FDD, UL, C_RNTI, 0x01]))))
