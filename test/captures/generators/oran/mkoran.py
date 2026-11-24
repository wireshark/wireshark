#!/usr/bin/env python3
# Generates test/captures/oran_coverage.pcap.gz, oran_fixes_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the O-RAN fronthaul CUS
dissector (epan/dissectors/packet-oran.c).

Every frame is Ethernet (ethertype 0xAEFE) carrying an eCPRI common
header (revision 1) with message type 2 (real-time control data,
O-RAN C-plane) or 0 (IQ data, O-RAN U-plane), followed by the O-RAN
payload.  Every byte is built here with struct and a small bit writer;
the beam weights, I/Q samples and measurement values are made up and
nothing comes from a real network.

The O-DU has MAC address 02:00:00:00:00:01 and the O-RU
02:00:00:00:00:02.  C-plane and downlink U-plane frames go from the
O-DU to the O-RU, uplink U-plane frames from the O-RU to the O-DU, as
the dissector expects when it links the planes.  The dissector
preferences are left at their defaults (eAxC 4/4/4/4 bits, 32 beam
weights, BFP 14 bits, udCompHdr and udCompLen heuristics).

Usage: mkoran.py <output directory>

Writes:
  oran-coverage.pcap            valid C-plane and U-plane frames; no
                                malformed packets and no expert info of
                                severity warning or above, in one or two
                                passes
  oran-coverage-malformed.pcap  truncated and invalid frames, and valid
                                constructs that the dissector warns about
"""

import os
import struct
import sys

DU = bytes.fromhex('020000000001')
RU = bytes.fromhex('020000000002')

DL = 1
UL = 0

# C-plane section types
ST0, ST1, ST3, ST4, ST5, ST6, ST7, ST8, ST9, ST10, ST11, ST12, ST13, ST14 = \
    0, 1, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14

# udCompMeth / bfwCompMeth values
NONE, BFP, BSC, ULAW, MOD, BFP_SRE, MOD_SRE, BFP_SREM, MOD_SREM = range(9)


# ------------------------------------------------------------ bits

class Bits:
    """MSB-first bit writer."""
    def __init__(self):
        self.v = 0
        self.n = 0

    def u(self, val, width):
        assert 0 <= val < (1 << width), (val, width)
        self.v = (self.v << width) | val
        self.n += width
        return self

    def s(self, val, width):
        """Two's complement signed value."""
        return self.u(val & ((1 << width) - 1), width)

    def raw(self, data):
        for b in data:
            self.u(b, 8)
        return self

    def align(self, n=8):
        if self.n % n:
            self.u(0, n - self.n % n)
        return self

    def bytes(self):
        self.align()
        return self.v.to_bytes(self.n // 8, 'big') if self.n else b''

    def __len__(self):
        return (self.n + 7) // 8


def b16(v):
    return struct.pack('>H', v)


# ------------------------------------------------------------ pcap

class Cap:
    def __init__(self):
        self.frames = []
        self.t = 1700000000 * 1000000      # microseconds
        self.seqs = {}

    def add(self, frame, dt=20):
        self.t += dt
        self.frames.append((self.t, frame))
        return len(self.frames)

    def write(self, path):
        with open(path, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            for t, fr in self.frames:
                f.write(struct.pack('<IIII', t // 1000000, t % 1000000, len(fr), len(fr)) + fr)

    def nextseq(self, key):
        s = self.seqs.get(key, 0)
        self.seqs[key] = (s + 1) % 256
        return s

    def ecpri(self, src, dst, msgtype, payload, dt=20, concat=None):
        body = bytes([0x10, msgtype]) + b16(len(payload)) + payload
        return self.add(dst + src + b'\xae\xfe' + body, dt)

    # ---------------------------------------------------- C-plane
    def cplane(self, eaxc, direction, st, body, nsec=1, frame=0, subframe=0, slot=0,
               sym=0, filt=0, src=DU, dst=RU, seq=None, e=1, subseq=0, version=1,
               dt=20, numsec_field=None):
        """body: the section-type specific common header fields and
        everything after the sectionType byte."""
        if seq is None:
            seq = self.nextseq(('C', eaxc, src, dst, direction))
        b4 = nsec if numsec_field is None else numsec_field
        hdr = b16(eaxc) + bytes([seq, (e << 7) | subseq])
        hdr += bytes([(direction << 7) | (version << 4) | filt, frame])
        hdr += b16((subframe << 12) | (slot << 6) | sym)
        hdr += bytes([b4, st])
        return self.ecpri(src, dst, 2, hdr + body, dt)

    # ---------------------------------------------------- U-plane
    def uplane(self, eaxc, direction, sections, frame=0, subframe=0, slot=0, sym=0,
               filt=0, src=None, dst=None, seq=None, e=1, subseq=0, version=1, dt=20):
        if src is None:
            src, dst = (DU, RU) if direction == DL else (RU, DU)
        if seq is None:
            seq = self.nextseq(('U', eaxc, src, dst, direction))
        payload = b16(eaxc) + bytes([seq, (e << 7) | subseq])
        payload += utiming(direction, frame, subframe, slot, sym, filt, version)
        payload += b''.join(sections)
        return self.ecpri(src, dst, 0, payload, dt)

    def uplane_frags(self, eaxc, direction, sections, cuts, frame=0, subframe=0, slot=0,
                     sym=0, dt=20, order=None):
        """Radio-transport fragmentation: the bytes after ecpriSeqid are
        split at the offsets in cuts."""
        src, dst = (DU, RU) if direction == DL else (RU, DU)
        seq = self.nextseq(('U', eaxc, src, dst, direction))
        data = utiming(direction, frame, subframe, slot, sym) + b''.join(sections)
        pieces = []
        prev = 0
        for c in list(cuts) + [len(data)]:
            pieces.append(data[prev:c])
            prev = c
        nums = []
        idx = list(range(len(pieces))) if order is None else order
        for i in idx:
            last = 1 if i == len(pieces) - 1 else 0
            payload = b16(eaxc) + bytes([seq, (last << 7) | i]) + pieces[i]
            nums.append(self.ecpri(src, dst, 0, payload, dt))
        return nums


def utiming(direction, frame, subframe, slot, sym, filt=0, version=1):
    return bytes([(direction << 7) | (version << 4) | filt, frame]) + \
        b16((subframe << 12) | (slot << 6) | sym)


# ------------------------------------------------------------ C-plane parts

def udcomphdr(width=0, meth=0):
    return ((width & 0xf) << 4) | meth


def st_hdr(st, udhdr=0, time_offset=0x0100, fft=0xc, scs=1, cp=0x0120, ci=None,
           num_ues=1, sinr_per_prb=0, sinr_slot_mask=0):
    """Section-type specific fields after the sectionType byte."""
    if st == ST0:
        return b16(time_offset) + bytes([(fft << 4) | scs]) + b16(cp) + b'\0'
    if st in (ST1, ST5):
        return bytes([udhdr, 0])
    if st == ST3:
        return b16(time_offset) + bytes([(fft << 4) | scs]) + b16(cp) + bytes([udhdr])
    if st == ST6:
        width, meth, opt = ci
        return bytes([num_ues, (width << 4) | (meth << 1) | opt])
    if st == ST7:
        return b'\0\0'
    if st == ST9:
        return bytes([(sinr_per_prb << 5) | sinr_slot_mask, 0])
    if st in (ST10, ST11):
        return b'\0\0'
    return b''


def ext(etype, body, ef=0, extlen=None):
    """Section extension: ef, extType, extLen (2 bytes for SE 11, 19, 20)
    and the body padded to a multiple of 4 bytes."""
    if isinstance(body, Bits):
        body = body.bytes()
    long_len = etype in (11, 19, 20)
    hlen = 3 if long_len else 2
    if extlen is None:
        extlen = (hlen + len(body) + 3) // 4
    total = extlen * 4
    pad = total - hlen - len(body)
    assert pad >= 0, (etype, len(body), extlen)
    hdr = bytes([(ef << 7) | etype]) + (b16(extlen) if long_len else bytes([extlen]))
    return hdr + body + bytes(pad)


def exts(*items):
    """items: (etype, body[, extlen]) tuples; sets ef on all but the last."""
    out = b''
    for i, it in enumerate(items):
        etype, body = it[0], it[1]
        extlen = it[2] if len(it) > 2 else None
        out += ext(etype, body, ef=1 if i < len(items) - 1 else 0, extlen=extlen)
    return out


def csec(st, sid=1, start=0, num=1, rb=0, syminc=0, remask=0xfff, numsym=1,
         beam=0, ueid=0, freqoff=0, ext_bytes=b'', tail=b''):
    """A section of type 0, 1, 3, 5, 10, 11, 12, 13 or 14."""
    b = Bits().u(sid, 12).u(rb, 1).u(syminc, 1).u(start, 10).u(num, 8)
    b.u(remask, 12).u(numsym, 4)
    ef = 1 if ext_bytes else 0
    if st == ST0:
        b.u(ef, 1).u(0, 15)
    elif st == ST1:
        b.u(ef, 1).u(beam, 15)
    elif st == ST3:
        b.u(ef, 1).u(beam, 15).s(freqoff, 24).u(0, 8)
    elif st in (ST5, ST10, ST13):
        b.u(ef, 1).u(ueid, 15)
    elif st == ST11:
        b.u(ef, 1).u(0, 15)
    return b.bytes() + ext_bytes + tail


# ------------------------------------------------------------ weights

def weights(b, n, width, start=0, zero=False):
    """n I/Q pairs of 'width' bits each."""
    for i in range(n):
        if zero:
            b.u(0, width).u(0, width)
        else:
            b.u((start + 3 * i + 1) % (1 << width), width)
            b.u((start + 5 * i + 2) % (1 << width), width)
    return b


# ------------------------------------------------------------ U-plane parts

def samples(b, n, width, seed=0, value=None):
    for i in range(n):
        if value is not None:
            b.u(value[0], width).u(value[1], width)
        else:
            b.u((seed + 7 * i + 3) % (1 << width), width)
            b.u((seed + 11 * i + 5) % (1 << width), width)
    return b


def uprb(meth, width, seed=0, exponent=4, sresmask=0xfff, value=None, nres=None):
    """One PRB: udCompParam followed by the samples, byte aligned."""
    b = Bits()
    if meth in (BFP, BFP_SREM):
        b.u(0, 4).u(exponent, 4)
    elif meth in (BSC,):
        b.u(0x40, 8)
    elif meth in (ULAW,):
        b.u(0x84, 8)
    elif meth == BFP_SRE:
        b.u(sresmask >> 8, 4).u(exponent, 4).u(sresmask & 0xff, 8)
    elif meth == MOD_SRE:
        b.u(sresmask >> 8, 4).u(0, 4).u(sresmask & 0xff, 8)
    if nres is None:
        nres = bin(sresmask).count('1') if meth >= BFP_SRE else 12
    samples(b, nres, width, seed, value)
    return b.bytes()


def usec(sid, start, num, prbs, rb=0, syminc=0, hdr=None, complen=False, masks=None):
    """U-plane section.  hdr=(width, meth) adds udCompHdr and its reserved
    byte; complen adds udCompLen; masks=(sReSMask1, sReSMask2)."""
    head = Bits().u(sid, 12).u(rb, 1).u(syminc, 1).u(start, 10).u(num, 8).bytes()
    if hdr is not None:
        head += bytes([udcomphdr(*hdr), 0])
    tail = b''
    if masks is not None:
        tail = b16(masks[0]) + b16(masks[1])
    body = b''.join(prbs)
    if complen:
        total = len(head) + 2 + len(tail) + len(body)
        return head + b16(total) + tail + body
    return head + tail + body




# ------------------------------------------------------------ extension bodies

NANT = 32       # oran.num_bf_antennas default


def bfw_param(b, meth, exponent=3, mask=None):
    """bfwCompParam for the methods the dissector reads."""
    if meth == BFP:
        b.u(0, 4).u(exponent, 4)
    elif meth == BSC:
        b.u(0x50, 8)                       # blockScaler
    elif meth == ULAW:
        b.u(0x42, 8)                       # compBitWidth, compShift
    elif meth in (4, 5):                   # beamspace I / II
        b.u(mask, 32)                      # activeBeamspaceCoefficientMask (K=32)
        if meth == 4:
            b.u(0x50, 8)
        else:
            b.u(0, 4).u(exponent, 4)
    return b


def se1(width, meth, extlen, exponent=3, mask=None, zero=False, start=0):
    """SE 1 with the number of weights the dissector derives: from the
    beamspace mask, or from extLen."""
    b = Bits().u(width & 0xf, 4).u(meth, 4)
    bfw_param(b, meth, exponent, mask)
    w = width or 16
    if mask is not None:
        n = bin(mask).count('1')
    else:
        # every byte after bfwCompParam up to the end of the extension
        hdr = 3 + (1 if meth == BFP else 0)
        n = ((extlen * 4) - hdr) * 8 // (2 * w)
    weights(b, n, w, start=start, zero=zero)
    return (1, b) if mask is not None else (1, b, extlen)


def se11_weights(numbund, bundles, width, meth, rad=0, bundle_offset=0,
                 exponent=2, mask=None, nweights=NANT):
    """SE 11 with weights.  bundles: list of (contInd, beamId, zero)."""
    b = Bits().u(0, 1).u(rad, 1).u(bundle_offset, 6).u(numbund, 8)
    b.u(width & 0xf, 4).u(meth, 4)
    w = width or 16
    for i, (cont, beam, zero) in enumerate(bundles):
        bfw_param(b, meth, exponent, mask)
        b.u(cont, 1).u(beam, 15)
        n = bin(mask).count('1') if mask is not None else nweights
        weights(b, n, w, start=i, zero=zero)
    return (11, b)


def se11_noweights(numbund, beams, rad=0, bundle_offset=0):
    b = Bits().u(1, 1).u(rad, 1).u(bundle_offset, 6).u(numbund, 8)
    for i, beam in enumerate(beams):
        b.u(1 if i < len(beams) - 1 else 0, 1).u(beam, 15)
    return (11, b)


def se6(rbgsize_code, rbgmask, symmask=0x3fff, priority=0, rep=0):
    return (6, Bits().u(rep, 1).u(rbgsize_code, 3).u(rbgmask, 28).u(priority, 2).u(symmask, 14))


def se10(group_type, numportc, ids=(), plis=()):
    b = Bits().u(group_type, 2).u(numportc, 6)
    if group_type in (0, 1):
        b.u(0, 8)
    elif group_type == 2:
        for i in ids:
            b.u(0, 1).u(i, 15)
    else:
        b.u(plis[0], 8)
        for i, pli in zip(ids, plis[1:]):
            b.u(0, 1).u(i, 15).u(pli, 8)
    return (10, b)


def se12(pairs, symmask=0x3fff, priority=1):
    """pairs fill extLen*4-4 bytes."""
    extlen = 1 + (2 * len(pairs) + 3) // 4
    b = Bits().u(priority, 2).u(symmask, 14)
    for off, num in pairs:
        b.u(off, 8).u(num, 8)
    fill = extlen * 4 - 4 - 2 * len(pairs)
    for _ in range(fill // 2):
        b.u(0, 8).u(0, 8)
    return (12, b, extlen)


def se13(allocs):
    """allocs fill extLen*4-2 bytes; the last one is repeated to fill."""
    n = len(allocs)
    extlen = (2 + 2 * n + 3) // 4
    total = (extlen * 4 - 2) // 2
    allocs = list(allocs) + [allocs[-1]] * (total - n)
    b = Bits()
    for sym, prb in allocs:
        b.u(0, 2).u(sym, 4).u(prb, 10)
    return (13, b, extlen)


def se19(numportc, ports, width=4, meth=BFP, disable=0, rep=0, symmask=0x3fff, mask=None):
    """ports: list of (reMask, symbolMask, beamId)."""
    b = Bits().u(disable, 1).u(rep, 1).u(numportc, 6).u(2, 2).u(symmask, 14)
    if not rep:
        if not disable:
            b.u(width & 0xf, 4).u(meth, 4)
        for i, (remask, sym, beam) in enumerate(ports):
            b.u(0, 4).u(remask, 12).u(0, 2).u(sym, 14).u(0, 1).u(beam, 15)
            if not disable:
                bfw_param(b, meth, 1, mask)
                n = bin(mask).count('1') if mask is not None else NANT
                weights(b, n, width or 16, start=i)
                b.align()
    return (19, b)


def se20(patterns):
    """patterns: (symMask, startPuncPrb, numPuncPrb, puncReMask, rb, multiSD, rbg)
    where rbg is None or (rbgSize, rbgMask)."""
    b = Bits().u(len(patterns), 8)
    for sym, start, num, remask, rb, msd, rbg in patterns:
        b.u(sym, 14).u(start, 10).u(num, 8).u(remask, 12).u(rb, 1).u(0, 1).u(msd, 1)
        b.u(1 if rbg else 0, 1)
        if rbg:
            b.u(0, 1).u(rbg[0], 3).u(rbg[1], 28)
    return (20, b)


def se23(prb_mode, patterns):
    """patterns: (symMask, prbPattern_or_(blkOffset, blkSize), [(reMask, csf, offset)])"""
    b = Bits().u(len(patterns), 4).u(0, 3).u(prb_mode, 1).u(0, 8)
    for sym, prb, configs in patterns:
        b.u(0, 2).u(sym, 14).u(len(configs), 4)
        if not prb_mode:
            b.u(prb, 4).u(0, 8).u(0, 4)
        else:
            b.u(prb[0], 8).u(prb[1], 8).u(0, 4)
            b.v >>= 4
            b.n -= 4           # prbBlkSize is followed directly by the first mask
        for i, (remask, csf, off) in enumerate(configs):
            if i > 0:
                b.u(0, 4)
            b.u(remask, 12).u(csf, 1).u(off, 15)
    return (23, b)


def se24_entry2(port, ueid_reset=0, pos=0, dmrs=0x0804, scr=0x1234, nscid=0, dtype=0,
                cdm=1, lam=2, first=0, last=4):
    return Bits().u(2, 3).u(port, 5).u(ueid_reset, 1).u(pos, 1).u(dmrs, 14).u(scr, 16) \
        .u(nscid, 1).u(dtype, 1).u(cdm, 2).u(lam, 2).u(first, 9).u(last, 9).u(0, 16)


def se24_entry3(port, papr=1, hop=2, first=0, last=4):
    return Bits().u(3, 3).u(port, 5).u(1, 1).u(0, 1).u(0x0804, 14).u(0x0042, 16) \
        .u(1, 1).u(0, 1).u(papr, 2).u(hop, 2).u(first, 9).u(last, 9).u(0, 16)


def se24(entries, size=2, group=7, alpn=1, snr=1):
    b = Bits().u(alpn, 1).u(snr, 1).u(0, 1).u(size, 5).u(group, 8)
    for e in entries:
        if isinstance(e, Bits):
            b.raw(e.bytes())
        else:                       # entry type 0/1: inherit
            b.u(e[0], 3).u(e[1], 5)
    return (24, b)


# ------------------------------------------------------------ ST4 / ST8 / LAA

def st4_cmd(ctype, body, numslots=0, acknack=0):
    assert len(body) % 4 == 0, (ctype, len(body))
    return bytes([ctype]) + b16(len(body) // 4) + bytes([numslots]) + b16(acknack) + b'\0\0' + body


def st4(cmds):
    return bytes([len(cmds), 0]) + b''.join(cmds)


def trx_body(log2mask, sleep, slots_ext, symmask, antmask):
    b = Bits().u(0, 2).u(log2mask, 4).u(sleep, 2).u(0, 4).u(slots_ext, 20).u(0, 2).u(symmask, 14)
    out = b.bytes() + antmask
    return out + bytes((-len(out)) % 4)


def laa(mtype, payload):
    mlen = max(0, (len(payload) + 3) // 4 - 1)
    payload = payload + bytes(4 * (mlen + 1) - len(payload))
    return b'\0\0' + bytes([(mtype << 4) | mlen]) + payload


# ------------------------------------------------------------ ST6 / ST9 / ST10

def st6_sec(ueid, start, num, width, meth, opt, regf=0x0100, rb=0, ext_list=(), seed=0,
            align4=False):
    b = Bits().u(1 if ext_list else 0, 1).u(ueid, 15).u(regf, 16).u(0, 4).u(rb, 1).u(0, 1)
    b.u(start, 10).u(num, 8)
    for p in range(num):
        if p == 0 or opt == 1:
            if meth == BFP:
                b.u(0, 4).u(2 + p, 4)
            elif meth == BSC:
                b.u(0x40, 8)
            elif meth == ULAW:
                b.u(0x31, 8)
        samples(b, NANT, width, seed + p)
    b.align(32 if align4 else 8)
    return b.bytes() + (exts(*ext_list) if ext_list else b'')


def st9_sec(sid, start, num, nsinr, rb=0, width=14, bfp=True, seed=0):
    b = Bits().u(sid, 12).u(rb, 1).u(0, 1).u(start, 10).u(num, 8)
    for p in range(num):
        if bfp:
            b.u(0, 4).u(3, 4)
        for n in range(nsinr):
            b.u((seed + 97 * p + 13 * n + 1) % (1 << width), width)
        b.align()
    return b.bytes()


def meas(mtype, data, mf=1, num_elements=0):
    """Measurement report: mf, measTypeId, numElements/reserved, measDataSize
    (in words, including these 4 bytes) and the data padded to 4 bytes."""
    data = data + bytes((-len(data)) % 4)
    return bytes([(mf << 7) | mtype, num_elements]) + b16((4 + len(data)) // 4) + data


def meas_cmd(mtype=5, symmask=0x3fff, mf=0):
    return bytes([(mf << 7) | mtype, 0]) + b16(2) + b16(symmask) + b'\0\0'


# ============================================================ main capture

def main_capture():
    c = Cap()

    # ---- DL ST1 linked to DL U-plane (eAxC 0x0100) ---------------------
    E = 0x0100
    c.cplane(E, DL, ST1, st_hdr(ST1) +
             csec(ST1, sid=1, start=0, num=4, beam=10, numsym=14) +
             csec(ST1, sid=2, start=4, num=4, beam=11, numsym=14),
             nsec=2, frame=1, subframe=2, slot=1)
    for sym in (0, 1):
        c.uplane(E, DL, [usec(1, 0, 4, [uprb(BFP, 9, seed=p + sym) for p in range(4)], hdr=(9, BFP)),
                         usec(2, 4, 4, [uprb(BFP, 9, seed=p + 8) for p in range(4)], hdr=(9, BFP))],
                 frame=1, subframe=2, slot=1, sym=sym, dt=40)

    # ---- UL ST1 whose udCompHdr is used by UL U-plane (eAxC 0x0200) ----
    E = 0x0200
    c.cplane(E, UL, ST1, st_hdr(ST1, udhdr=udcomphdr(9, BFP)) +
             csec(ST1, sid=3, start=0, num=2, beam=20, numsym=14),
             frame=2, subframe=0, slot=0)
    for sym, dt in ((0, 100), (0, 7), (1, 30)):
        # exponent > 8, so the udCompHdr heuristic decides there is none
        c.uplane(E, UL, [usec(3, 0, 2, [uprb(BFP, 9, seed=sym, exponent=9 + p) for p in range(2)])],
                 frame=2, subframe=0, slot=0, sym=sym, dt=dt)

    # ---- UL ST3 (PRACH) and ST5 udCompHdr, used by UL U-plane ----------
    E = 0x0210
    c.cplane(E, UL, ST3, st_hdr(ST3, udhdr=udcomphdr(16, NONE)) +
             csec(ST3, sid=4, start=10, num=1, beam=21, numsym=4, freqoff=-1234),
             frame=2, subframe=1, slot=0, filt=1)
    c.uplane(E, UL, [usec(4, 10, 1, [uprb(NONE, 16, value=(0xa1b2, 0x0102))])],
             frame=2, subframe=1, slot=0, sym=0)
    E = 0x0220
    c.cplane(E, UL, ST5, st_hdr(ST5, udhdr=udcomphdr(8, BFP)) +
             csec(ST5, sid=5, start=0, num=1, ueid=77, numsym=2),
             frame=2, subframe=2, slot=0)
    c.uplane(E, UL, [usec(5, 0, 1, [uprb(BFP, 8, exponent=12)])],
             frame=2, subframe=2, slot=0, sym=1)

    # ---- DL U-plane with every udCompHdr method the dissector decodes --
    # eAxC 0x0300 has no C-plane, so nothing is linked.
    E = 0x0300
    # First selective-RE section of the capture: udCompLen heuristic -> present
    c.uplane(E, DL, [usec(1, 0, 2, [uprb(BFP_SRE, 9, sresmask=0xa5f, exponent=5, seed=p) for p in range(2)],
                          hdr=(9, BFP_SRE), complen=True)], frame=3)
    c.uplane(E, DL, [
        # uncompressed 16 bits: largest positive and negative values
        usec(2, 0, 1, [uprb(NONE, 16, value=(0x7fff, 0x8001))], hdr=(16, NONE)),
        # udIqWidth 0 means 16 bits
        usec(3, 1, 1, [uprb(NONE, 16, seed=1)], hdr=(0, NONE)),
        # uncompressed 1 bit
        usec(4, 2, 2, [uprb(NONE, 1, value=(1, 0)), uprb(NONE, 1, seed=2)], hdr=(1, NONE)),
        # uncompressed 9 bits: largest positive (0x0ff) and a negative value
        usec(12, 6, 1, [uprb(NONE, 9, value=(0x0ff, 0x101))], hdr=(9, NONE)),
        usec(5, 3, 2, [uprb(BFP, 14, exponent=7, seed=3), uprb(BFP, 14, exponent=0, value=(0, 0))],
             hdr=(14, BFP)),
        usec(6, 5, 1, [uprb(BFP, 16, exponent=2, seed=4)], hdr=(0, BFP)),
    ], frame=3, sym=1)
    c.uplane(E, DL, [
        usec(7, 0, 2, [uprb(MOD, 2, seed=p) for p in range(2)], hdr=(2, MOD)),
        usec(8, 4, 3, [uprb(MOD_SRE, 3, sresmask=0x3f0, seed=p) for p in range(3)], rb=1,
             hdr=(3, MOD_SRE), complen=True),
        usec(9, 10, 1, [uprb(BFP_SRE, 12, sresmask=0x800, exponent=1)], hdr=(12, BFP_SRE), complen=True),
    ], frame=3, sym=2)
    # every other PRB, and numPrbu 0 (all 273 PRBs) with 1-bit samples
    c.uplane(E, DL, [usec(10, 0, 3, [uprb(BFP, 9, seed=p) for p in range(3)], rb=1, hdr=(9, BFP))],
             frame=3, sym=3)
    c.uplane(E, DL, [usec(11, 0, 0, [uprb(NONE, 1, seed=p) for p in range(273)], hdr=(1, NONE))],
             frame=3, sym=4)

    # ---- DL U-plane without udCompHdr: preferences (BFP, 14 bits) ------
    E = 0x0310
    c.uplane(E, DL, [usec(1, 0, 2, [uprb(BFP, 14, exponent=10 + p, seed=p) for p in range(2)])], frame=3)
    c.uplane(E, DL, [usec(2, 2, 1, [uprb(BFP, 14, exponent=3, value=(0, 0))])], frame=3, sym=1)

    # ---- UL U-plane with its own udCompHdr, and from preferences -------
    E = 0x0320
    c.uplane(E, UL, [usec(1, 0, 1, [uprb(BFP, 12, exponent=6)], hdr=(12, BFP)),
                     usec(2, 1, 1, [uprb(BFP_SRE, 12, exponent=6, sresmask=0xfff)], hdr=(12, BFP_SRE),
                          complen=True)], frame=4)
    E = 0x0330
    c.uplane(E, UL, [usec(1, 0, 1, [uprb(BFP, 14, exponent=11)])], frame=4)

    # ---- Radio-transport fragmentation (reassembled) -------------------
    E = 0x0340
    secs = [usec(1, 0, 3, [uprb(BFP, 9, seed=p) for p in range(3)], hdr=(9, BFP)),
            usec(2, 3, 2, [uprb(NONE, 8, seed=p) for p in range(2)], hdr=(8, NONE))]
    c.uplane_frags(E, DL, secs, cuts=(40, 80), frame=5)
    c.uplane(E, DL, [usec(3, 0, 1, [uprb(BFP, 9)], hdr=(9, BFP))], frame=5, sym=1)
    E = 0x0350
    c.uplane_frags(E, UL, [usec(1, 0, 2, [uprb(BFP, 10, seed=p) for p in range(2)], hdr=(10, BFP))],
                   cuts=(20,), frame=5)

    # ---- Modulation compression: SE 4, 5, 23 then DL U-plane (eAxC 0x0400)
    E = 0x0400
    def se5(sets, extlen):
        b = Bits()
        for m, csf, off in sets:
            b.u(m, 12).u(csf, 1).u(off, 15)
        return (5, b.align(), extlen)
    c.cplane(E, DL, ST1, st_hdr(ST1) +
             csec(ST1, sid=1, start=0, num=2, beam=1, numsym=14,
                  ext_bytes=exts((4, Bits().u(1, 1).u(0x1400, 15)))) +
             csec(ST1, sid=2, start=2, num=2, beam=2, numsym=14,
                  ext_bytes=exts(se5([(0xf00, 1, 0x0c00), (0x0ff, 0, 0x1200)], 3))) +
             csec(ST1, sid=3, start=4, num=2, beam=3, numsym=14,
                  ext_bytes=exts(se5([(0x800, 1, 0x0400), (0x400, 0, 0x0800), (0x200, 1, 0x1000)], 4),
                                 se5([(0x100, 0, 0x0400), (0x080, 1, 0x0800), (0x040, 0, 0x1000),
                                      (0x03f, 1, 0x1801)], 4))) +
             csec(ST1, sid=4, start=6, num=2, beam=4, numsym=14,
                  ext_bytes=exts(se23(1, [(0x3fff, (6, 2), [(0xfc0, 1, 0x0a00), (0x03f, 0, 0x0300)]),
                                          (0x00ff, (6, 1), [(0xfff, 0, 0x0100)])]))),
             nsec=4, frame=6)
    c.uplane(E, DL, [usec(1, 0, 2, [uprb(MOD, 2, seed=p) for p in range(2)], hdr=(2, MOD)),
                     usec(2, 2, 2, [uprb(MOD, 3, seed=p) for p in range(2)], hdr=(3, MOD)),
                     usec(3, 4, 2, [uprb(MOD_SRE, 4, sresmask=0xe07, seed=p) for p in range(2)],
                          hdr=(4, MOD_SRE), complen=True),
                     usec(4, 6, 2, [uprb(MOD, 4, seed=p) for p in range(2)], hdr=(4, MOD))],
             frame=6, sym=0)
    # UL ST1 with SE 4: csf shift value shown from the UL udCompHdr width
    c.cplane(0x0410, UL, ST1, st_hdr(ST1, udhdr=udcomphdr(3, MOD)) +
             csec(ST1, sid=5, start=0, num=2, beam=5, ext_bytes=exts((4, Bits().u(1, 1).u(0x0800, 15)))),
             frame=6, slot=1)

    # ---- sectionId reused by two C-plane frames; U-plane for each -----
    E = 0x0420
    for frame in (7, 8):
        c.cplane(E, DL, ST1, st_hdr(ST1) + csec(ST1, sid=7, start=0, num=1, beam=60 + frame, numsym=14) +
                 csec(ST1, sid=4095, start=1, num=1, beam=70, numsym=14), nsec=2, frame=frame)
    for frame in (7, 8):
        c.uplane(E, DL, [usec(7, 0, 1, [uprb(BFP, 9, seed=frame)], hdr=(9, BFP)),
                         usec(4095, 1, 1, [uprb(BFP, 9, seed=frame)], hdr=(9, BFP))], frame=frame, sym=2)

    cplane_coverage(c)
    extra_cplane(c)
    return c


def extra_cplane(c):
    """Valid constructs for the remaining branches."""
    E = 0x1020
    # SE 11 bundle allocation corner cases
    c.cplane(E, DL, ST1, st_hdr(ST1) +
             # 4 PRBs in bundles of 3: the second bundle is an orphan
             csec(ST1, sid=90, start=0, num=4,
                  ext_bytes=exts(se11_weights(3, [(1, 130, False), (0, 131, False)], 2, NONE))) +
             # numBundPrb 1: single-PRB bundles
             csec(ST1, sid=91, start=4, num=2,
                  ext_bytes=exts(se11_weights(1, [(1, 132, False), (0, 133, False)], 2, NONE))) +
             # disableBFWs with an orphan bundle
             csec(ST1, sid=92, start=6, num=4, ext_bytes=exts(se11_noweights(3, [130, 131]))) +
             # SE 6 rbgSize 8 (code 6), numBundPrb 16 > rbgSize; 12 PRBs: orphan
             csec(ST1, sid=93, start=0, num=12,
                  ext_bytes=exts(se6(6, 0x3), se11_noweights(16, [130]))) +
             # SE 6 rbgSize 8, 4 PRBs, numBundPrb 2: the third bundle of the rbg starts
             # beyond the section, so allocation stops
             csec(ST1, sid=94, start=0, num=4,
                  ext_bytes=exts(se6(6, 0x1), se11_noweights(2, [130, 131]))) +
             # SE 6 rbgSize 3 (code 3)
             csec(ST1, sid=89, start=0, num=6,
                  ext_bytes=exts(se6(3, 0x3), se11_noweights(3, [130, 131]))) +
             # SE 6 rbgSize 16 (code 7)
             csec(ST1, sid=95, start=0, num=16, ext_bytes=exts(se6(7, 0x1), se11_noweights(8, [130, 131]))) +
             # SE 12 pair with an orphan bundle
             csec(ST1, sid=96, start=0, num=2,
                  ext_bytes=exts(se12([(1, 3)]), se11_noweights(2, [130, 131, 132]))),
             nsec=8, frame=20)
    # SE 22 request that is never answered
    c.cplane(E, DL, ST1, st_hdr(ST1) +
             csec(ST1, sid=97, start=0, num=1, beam=1, ext_bytes=exts((22, b16(0x0999)))), frame=20, slot=1)
    # ST5 with SE 24 userGroupSize 0 and SE 27 numElements 0 (256)
    c.cplane(E, DL, ST5, st_hdr(ST5) +
             csec(ST5, sid=98, start=0, num=1, ueid=1,
                  ext_bytes=exts(se24([se24_entry2(0)], size=0, group=0),
                                 (27, Bits().u(1, 2).u(0, 6).u(0, 8).u(0, 1).u(99, 15)))),
             frame=20, slot=2)
    # ST6 UE with numPrbc 0
    c.cplane(0x1004, DL, ST6, st_hdr(ST6, ci=(2, BFP, 0), num_ues=1) +
             st6_sec(1006, 0, 0, 2, BFP, 0), nsec=1, frame=20, slot=3)
    # SE 12 with orphan bundles in the section range and in the pair
    c.cplane(E, DL, ST1, st_hdr(ST1) +
             csec(ST1, sid=88, start=0, num=1, ext_bytes=exts(se12([(0, 1)]), se11_noweights(3, [130, 131]))),
             frame=20, slot=5)
    # 33 sections with SE 4 in one flow: more than the 32 kept for modulation compression
    c.cplane(0x0430, DL, ST1, st_hdr(ST1) +
             b''.join(csec(ST1, sid=100 + i, start=i, num=1, beam=1,
                           ext_bytes=exts((4, Bits().u(i % 2, 1).u(0x0800 + i, 15)))) for i in range(33)),
             nsec=33, frame=20, slot=6)
    # ST9 with numPrbu 0 (all PRBs)
    c.cplane(0x1007, UL, ST9, st_hdr(ST9, sinr_per_prb=0) + st9_sec(76, 0, 0, 1, seed=9)[:4] +
             b''.join(st9_sec(0, 0, 1, 1, seed=p)[4:] for p in range(273)), frame=20, slot=4)

    # ST4 command 1 with startSymbolId 2 (symbols 0 and 1 not in symbolMask), and
    # with BFP weights (bfwCompParam) followed by padding
    cmd1s = Bits().u(0, 2).u(0x3ffc, 14).u(1, 1).u(0x0041, 15).u(2, 4).u(NONE, 4).u(0, 24)
    cmd1c = Bits().u(0, 2).u(0x00fc, 14).u(0, 1).u(0x0031, 15).u(3, 4).u(BFP, 4).u(0, 24)
    cmd1c.u(1, 1).u(0x0033, 15)                    # entry without weights
    cmd1c.u(0, 1).u(0x0032, 15).u(0, 4).u(4, 4)     # entry with bfwCompParam and 32 weights
    weights(cmd1c, NANT, 3)
    c.cplane(0x1005, DL, ST4, st4([st4_cmd(1, cmd1s.bytes()),
                                   st4_cmd(1, cmd1c.bytes() + bytes((-len(cmd1c)) % 4))]),
             numsec_field=0, filt=1, frame=21, sym=2)
    # SE 1 with 4-bit BFP weights: 4 weights in the bytes after bfwCompParam
    c.cplane(E, DL, ST1, st_hdr(ST1) +
             csec(ST1, sid=87, start=0, num=1, beam=1,
                  ext_bytes=exts((1, weights(Bits().u(4, 4).u(BFP, 4).u(3, 8), 4, 4)))),
             frame=21, slot=1)
    # SE 13 + SE 11: 3 PRBs in bundles of 2 at two frequency-hopping offsets
    c.cplane(E, DL, ST1, st_hdr(ST1) +
             csec(ST1, sid=86, start=10, num=3,
                  ext_bytes=exts(se13([(2, 30), (3, 60)]), se11_noweights(2, [130, 131, 132, 133]))),
             frame=21, slot=2)
    # SE 22 request answered by an ST8 from the O-RU address
    c.cplane(0x1030, DL, ST1, st_hdr(ST1) +
             csec(ST1, sid=85, start=0, num=1, beam=1, ext_bytes=exts((22, b16(0x0601)))), frame=21, slot=3)
    c.cplane(0x1030, UL, ST8, bytes([1, 0]) + b16(0x0601), numsec_field=0, filt=1, frame=21, slot=3,
             sym=1, src=RU, dst=DU, dt=3000)

    # U-plane methods 7 and 8 (selective RE with masks in the section header)
    E = 0x0440
    c.uplane(E, DL, [
        usec(1, 0, 2, [uprb(BFP_SREM, 9, exponent=3, seed=1, nres=4), uprb(BFP_SREM, 9, exponent=3, seed=2, nres=8)],
             hdr=(9, BFP_SREM), complen=True, masks=(0x00f, 0xff0)),
        usec(2, 2, 3, [uprb(BFP_SREM, 9, exponent=0, value=(0, 0), nres=6) for p in range(3)], rb=1,
             hdr=(9, BFP_SREM), complen=True, masks=(0x3f0, 0)),
        usec(3, 8, 2, [uprb(MOD, 4, seed=3, nres=2), uprb(MOD, 4, seed=4, nres=3)],
             hdr=(4, MOD_SREM), complen=True, masks=(0x801, 0x700)),
    ], frame=22)
    # A last section with smaller PRBs than the one before
    c.uplane(E, DL, [usec(4, 0, 2, [uprb(BFP, 16, exponent=2, seed=p) for p in range(2)], hdr=(16, BFP)),
                     usec(5, 2, 1, [uprb(NONE, 2, seed=5)], hdr=(2, NONE))], frame=22, sym=1)



def cplane_coverage(c):
    # ---- ST1 DL with SE 1 (beamforming weights) ---------------------
    E = 0x1000
    se5_4sets = Bits()
    for i, (m, csf, off) in enumerate(((0x800, 1, 0x0400), (0x400, 0, 0x0800), (0x200, 1, 0x1000),
                                       (0x1ff, 0, 0x1801))):
        se5_4sets.u(m, 12).u(csf, 1).u(off, 15)
    c.cplane(E, DL, ST1, st_hdr(ST1) +
             csec(ST1, sid=20, start=0, num=1, beam=1, ext_bytes=exts(se1(8, NONE, 4))) +
             csec(ST1, sid=21, start=1, num=1, beam=2, ext_bytes=exts(se1(8, BFP, 3, exponent=5))) +
             csec(ST1, sid=22, start=2, num=1, beam=3,
                  ext_bytes=exts(se1(6, 5, 3, exponent=2, mask=0x80000105))) +
             csec(ST1, sid=23, start=3, num=1, beam=4, ext_bytes=exts(se1(8, NONE, 2, zero=True))) +
             csec(ST1, sid=24, start=4, num=1, beam=5, ext_bytes=exts(se1(0, NONE, 3))),
             nsec=5, frame=10)

    # ---- ST1 DL with SE 2 and SE 3 -------------------------------------
    se2a = Bits().u(0, 2).u(7, 3).u(7, 3).u(0, 2).u(3, 3).u(3, 3) \
        .u(0x81, 8).u(0x42, 8).u(0x9, 4).u(0x6, 4).u(0, 2).u(5, 3).u(2, 3)
    se2b = Bits().u(0, 2).u(4, 3).u(4, 3).u(0, 2).u(0, 3).u(0, 3).u(0x11, 5).u(0x0a, 5).u(3, 3).u(4, 3)
    se2c = Bits().u(0, 2).u(2, 3).u(0, 3).u(0, 2).u(0, 3).u(0, 3).u(5, 3).align().u(0, 2).u(1, 3).u(1, 3)
    se3a = Bits().u(0, 8).u(0, 4).u(2, 4).u(1, 4).u(0x0f0, 12).u(1, 1).u(0, 3).u(5, 4).u(0, 8) \
        .u(0, 1).u(0x1234, 15).u(0, 1).u(0x0042, 15).u(0, 1).u(0x7fff, 15)
    se3b = Bits().u(0, 8).u(1, 4).u(2, 4)
    c.cplane(E, DL, ST1, st_hdr(ST1) +
             csec(ST1, sid=25, start=0, num=2, beam=6, ext_bytes=exts((2, se2a), (2, se2b), (2, se2c))) +
             csec(ST1, sid=26, start=2, num=2, beam=7, ext_bytes=exts((3, se3a))) +
             csec(ST1, sid=27, start=2, num=2, beam=8, ext_bytes=exts((3, se3b))),
             nsec=3, frame=10, slot=1)

    # ---- ST1 DL with SE 11 (flexible weights) ---------------------------
    c.cplane(E, DL, ST1, st_hdr(ST1) +
             # 5 PRBs in bundles of 2: two full bundles and an orphan; bundle 1 all zero
             csec(ST1, sid=30, start=0, num=5, beam=9,
                  ext_bytes=exts(se11_weights(2, [(1, 100, False), (1, 101, True), (0, 102, False)],
                                              4, BFP))) +
             # uncompressed 1-bit weights
             csec(ST1, sid=31, start=5, num=2, beam=9,
                  ext_bytes=exts(se11_weights(2, [(0, 103, False)], 1, NONE, rad=1, bundle_offset=3))) +
             # beamspace II (BFP) with activeBeamspaceCoefficientMask
             csec(ST1, sid=32, start=7, num=4,
                  ext_bytes=exts(se11_weights(4, [(0, 104, False)], 8, 5, mask=0x00ff0001))),
             nsec=3, frame=11)
    c.cplane(E, DL, ST1, st_hdr(ST1) +
             csec(ST1, sid=33, start=0, num=5, ext_bytes=exts(se11_noweights(2, [100, 101, 102]))),
             frame=11, slot=1)
    # SE 6 + SE 11: 16 PRBs, rbgSize 4, rbgMask bits 0 and 2, numBundPrb 2 -> 4 bundles
    c.cplane(E, DL, ST1, st_hdr(ST1) +
             csec(ST1, sid=34, start=0, num=16,
                  ext_bytes=exts(se6(4, 0x5),
                                 se11_weights(2, [(1, 110, False), (1, 111, False), (1, 112, False),
                                                  (0, 113, False)], 2, BFP))) +
             csec(ST1, sid=35, start=16, num=16,
                  ext_bytes=exts(se6(4, 0x5), se11_noweights(2, [110, 111, 112, 113]))),
             nsec=2, frame=11, slot=2)
    # SE 12 + SE 11 and SE 13 + SE 11
    c.cplane(E, DL, ST1, st_hdr(ST1) +
             csec(ST1, sid=36, start=0, num=4,
                  ext_bytes=exts(se12([(2, 4)]),
                                 se11_weights(2, [(1, 120, False), (1, 121, False), (1, 122, False),
                                                  (0, 123, False)], 2, BFP))) +
             csec(ST1, sid=37, start=20, num=4,
                  ext_bytes=exts(se13([(1, 10), (2, 20)]),
                                 se11_weights(2, [(1, 124, False), (1, 125, False), (1, 126, False),
                                                  (0, 127, False)], 2, NONE))),
             nsec=2, frame=11, slot=3)

    # ---- ST1 DL with SE 10 (all beamGroupTypes) and SE 31 ---------------
    se31_3 = Bits()
    for table, idx in ((1, 5), (2, 17), (3, 33)):
        se31_3.u(0, 4).u(table, 4).u(0, 2).u(idx, 6)
    se31_2 = Bits().u(0, 4).u(0, 4).u(0, 2).u(9, 6).u(0, 4).u(1, 4).u(0, 2).u(27, 6)
    c.cplane(E, DL, ST1, st_hdr(ST1) +
             csec(ST1, sid=40, start=0, num=2, beam=30, ext_bytes=exts(se10(0, 3))) +
             csec(ST1, sid=41, start=2, num=2, beam=31, ext_bytes=exts(se10(1, 3))) +
             csec(ST1, sid=42, start=4, num=2, beam=32,
                  ext_bytes=exts(se10(2, 3, ids=(200, 201, 202)), (31, se31_3))) +
             csec(ST1, sid=43, start=6, num=2, beam=33,
                  ext_bytes=exts(se10(3, 3, ids=(300, 301), plis=(1, 2, 3)), (31, se31_2))),
             nsec=4, frame=12)

    # ---- ST1 DL with SE 18, 19, 20, 22, 29 ------------------------------
    se18 = Bits().u(0x0123, 16).u(0, 2).u(0x0456, 14).u(0, 6).u(2, 2)
    se29 = Bits().u(0, 4).u(3, 4).s(-5, 8)
    c.cplane(E, DL, ST1, st_hdr(ST1) +
             csec(ST1, sid=44, start=0, num=2, beam=34, ext_bytes=exts((18, se18), (29, se29))) +
             csec(ST1, sid=45, start=2, num=2, beam=35,
                  ext_bytes=exts(se19(2, [(0xfff, 0x3fff, 40), (0x0f0, 0x00ff, 41)], width=4, meth=BFP))) +
             csec(ST1, sid=46, start=4, num=2, beam=36,
                  ext_bytes=exts(se19(2, [(0xfff, 0x3fff, 42), (0x00f, 0x0f00, 43)], disable=1))) +
             csec(ST1, sid=47, start=6, num=2, beam=37, ext_bytes=exts(se19(2, [], rep=1))) +
             csec(ST1, sid=48, start=8, num=8, beam=38,
                  ext_bytes=exts(se20([(0x3fff, 9, 2, 0xfff, 0, 1, None),
                                       (0x0003, 12, 1, 0x0f0, 1, 0, (2, 0x0000003))]),
                                 (22, b16(0x0201)))),
             nsec=5, frame=12, slot=1)
    # ST1 with SE 19 using beamspace II weights
    c.cplane(E, DL, ST1, st_hdr(ST1) +
             csec(ST1, sid=49, start=0, num=2,
                  ext_bytes=exts(se19(1, [(0xfff, 0x3fff, 44)], width=8, meth=5, mask=0x0000000f))),
             frame=12, slot=2)

    # ---- ST3 UL with SE 6 and SE 10 -------------------------------------
    c.cplane(E, UL, ST3, st_hdr(ST3, udhdr=udcomphdr(9, BFP), fft=0xd, scs=3) +
             csec(ST3, sid=50, start=0, num=8, beam=50, freqoff=600, numsym=2,
                  ext_bytes=exts(se6(1, 0x0f), se10(0, 2))),
             frame=13, sym=2, filt=3)

    # ---- ST0 with SE 7, 9, 20, 22 ---------------------------------------
    c.cplane(E, DL, ST0, st_hdr(ST0, fft=0, scs=12) +
             csec(ST0, sid=51, start=0, num=0, numsym=14,
                  ext_bytes=exts((7, b16(0x00f0)), (9, b'\x01\x00'),
                                 se20([(0x0ff0, 5, 3, 0x00f, 0, 0, None)]), (22, b16(0x0202)))),
             frame=13, slot=1)

    # ---- ST5 DL with the UE-based extensions ----------------------------
    E = 0x1002
    se8 = Bits()
    for r in (0x0100, 0xff00, 0x0001, 0x7fff):
        se8.u(r, 16)
    se16 = Bits()
    for i in range(4):
        se16.u(0x0123456789abcdef ^ i, 64)
    se17 = Bits().u(1, 4).u(2, 4).u(3, 4).u(4, 4)
    se14_10 = Bits().raw(b'\x80\x00\x80\x00')
    se24a = se24([se24_entry2(1), (0, 2), se24_entry3(3, first=10, last=20), (1, 4)])
    se31_4 = Bits()
    for i in range(4):
        se31_4.u(0, 4).u(i, 4).u(0, 2).u(10 + i, 6)
    se26 = Bits().u(0, 8).u(0, 1).u(2, 7).u(0x0102, 16).u(0x9000, 16)
    se27a = Bits().u(0, 2).u(0, 6).u(2, 8).u(0, 1).u(500, 15).u(0, 1).u(501, 15)
    se27b = Bits().u(1, 2).u(0, 6).u(4, 8).u(0, 1).u(502, 15)
    se28 = Bits().u(0, 3).u(3, 5).u(0, 1).u(1, 3).u(0, 1).u(5, 3).u(0, 1).u(2, 3).u(0, 4)
    se29 = Bits().u(0, 4).u(1, 4).u(7, 8)
    se25_1 = Bits()
    for sym in range(14):
        se25_1.u(15 if sym % 3 == 0 else sym % 15, 4)
    se25_2 = Bits().raw(se25_1.bytes()).raw(bytes([0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde]))
    se15 = Bits().u(0xc, 4).u(1, 4).s(-100, 24).u(0x0090, 16)
    se21 = Bits().u(4, 8).u(0, 6).u(2, 2)
    se32 = Bits().u(0, 3).u(2, 5).u(0, 8)
    for ue, ports, rank in ((600, 2, 1), (601, 4, 2)):
        se32.u(0, 1).u(ue, 15).u(ports, 4).u(rank, 4).u(1, 2).u(5, 6).u(1, 2).u(0x0123, 14).u(0, 16)
    se33 = Bits().u(0, 6).u(2, 2).u(0, 8)
    se34a = Bits().u(1, 1).u(0, 4).u(0, 3).u(0, 2).u(2, 6).u(0x0f, 8).u(700, 16).u(0xf0, 8).u(701, 16) \
        .u(2, 8).u(1, 8).u(2, 8)
    se34b = Bits().u(0, 1).u(0, 4).u(1, 3).u(0, 2).u(1, 6).u(0x03, 8).u(0x1b, 8).u(0xe4, 8).u(702, 16)
    se34c = Bits().u(0, 1).u(0, 4).u(2, 3).u(0, 2).u(1, 6).u(703, 16)
    se4 = Bits().u(1, 1).u(0x1a00, 15)
    se5_1 = Bits().u(0xfff, 12).u(0, 1).u(0x0800, 15).u(0, 20)
    se23m = se23(0, [(0x3fff, 0x5, [(0xfff, 1, 0x0c00), (0x00f, 0, 0x0400)])])
    se18 = Bits().u(0x0010, 16).u(0, 2).u(0x0020, 14).u(0, 6).u(1, 2)
    c.cplane(E, DL, ST5, st_hdr(ST5) +
             csec(ST5, sid=60, start=0, num=4, ueid=400, numsym=2,
                  ext_bytes=exts(se10(2, 3, ids=(401, 402, 403)), (8, se8), (16, se16), (17, se17, 1),
                                 (14, se14_10), se24a, (31, se31_4))) +
             csec(ST5, sid=61, start=4, num=4, ueid=410, numsym=2,
                  ext_bytes=exts((14, b'\x80\x00'), (15, se15), (21, se21), (25, se25_1), (25, se25_2),
                                 (26, se26), (27, se27a), (27, se27b), (28, se28), (29, se29))) +
             csec(ST5, sid=62, start=8, num=2, ueid=0x7fff, numsym=2,
                  ext_bytes=exts((32, se32), (33, se33), (34, se34a), (34, se34b), (34, se34c))) +
             csec(ST5, sid=63, start=10, num=2, ueid=411, numsym=2,
                  ext_bytes=exts((4, se4), (5, se5_1), se23m)) +
             csec(ST5, sid=64, start=0, num=24, ueid=412, numsym=2,
                  ext_bytes=exts(se6(5, 0x7), se13([(3, 40)]), (18, se18),
                                 se20([(0x3fff, 2, 2, 0xfff, 0, 1, None)]))),
             nsec=5, frame=14)

    # ---- ST5 UL with SE 30 (PUSCH repetition) ---------------------------
    se30a = Bits().u(0, 4).u(1, 4).u(0, 8).u(0, 1).u(1, 1).u(3, 6).u(0, 2).u(0, 6).u(0, 16)
    se30b = Bits().u(0, 4).u(2, 4).u(0, 8)
    se30b.u(0, 1).u(0, 1).u(1, 6).u(0, 2).u(2, 6).u(0, 1).u(801, 15).u(0, 1).u(802, 15)
    se30b.u(0, 1).u(1, 1).u(2, 6).u(0, 2).u(3, 6)
    for i in range(3):
        se30b.u(0, 1).u(800 + i % 3, 15)
    c.cplane(E, UL, ST5, st_hdr(ST5, udhdr=udcomphdr(9, BFP)) +
             csec(ST5, sid=65, start=0, num=2, ueid=800, ext_bytes=exts((30, se30a))) +
             csec(ST5, sid=66, start=2, num=2, ueid=800,
                  ext_bytes=exts(se10(2, 2, ids=(801, 802)), (30, se30b))),
             nsec=2, frame=14, slot=1)

    # ---- ST6 channel information, every ciCompMeth ----------------------
    E = 0x1004
    se21b = Bits().u(2, 8).u(0, 6).u(1, 2)
    c.cplane(E, DL, ST6, st_hdr(ST6, ci=(2, BFP, 0), num_ues=2) +
             st6_sec(1000, 0, 2, 2, BFP, 0, ext_list=((21, se21b), (15, Bits().u(0xc, 4).u(1, 4).u(0, 24).u(0, 16)))) +
             st6_sec(1001, 2, 1, 2, BFP, 0, regf=0xff00, seed=5),
             nsec=0, frame=15)
    c.cplane(E, DL, ST6, st_hdr(ST6, ci=(4, NONE, 1), num_ues=1) +
             st6_sec(1002, 0, 1, 4, NONE, 1), nsec=1, frame=15, slot=1)
    c.cplane(E, DL, ST6, st_hdr(ST6, ci=(3, BSC, 1), num_ues=1) +
             st6_sec(1003, 0, 2, 3, BSC, 1), nsec=1, frame=15, slot=2)
    c.cplane(E, DL, ST6, st_hdr(ST6, ci=(0, ULAW, 1), num_ues=1) +
             st6_sec(1004, 0, 1, 16, ULAW, 1), nsec=1, frame=15, slot=3)
    c.cplane(E, DL, ST6, st_hdr(ST6, ci=(2, BFP, 1), num_ues=1) +
             st6_sec(1005, 0, 2, 2, BFP, 1, ext_list=((21, se21b),)), nsec=1, frame=15, slot=4)

    # ---- ST4 slot control, every command, answered by ST8 ---------------
    E = 0x1005
    cmd1 = Bits().u(0, 2).u(0x3fff, 14).u(0, 1).u(0x0011, 15).u(2, 4).u(NONE, 4).u(0, 24)
    cmd1.u(1, 1).u(0x0012, 15)                     # entry without weights
    cmd1.u(0, 1).u(0x0013, 15)
    weights(cmd1, NANT, 2)
    cmd1b = Bits().u(0, 2).u(0x0f0f, 14).u(1, 1).u(0x0021, 15).u(4, 4).u(BFP, 4).u(0, 24)
    cmd1c = Bits().u(0, 2).u(0x00ff, 14).u(0, 1).u(0x0031, 15).u(3, 4).u(BFP, 4).u(0, 24)
    cmd1c.u(0, 1).u(0x0032, 15).u(0, 4).u(4, 4)
    weights(cmd1c, NANT, 3)
    cmd1c.align()
    cmd1c.u(1, 1).u(0x0033, 15)
    cmd2 = Bits().u(0, 2).u(0x0fc0, 14).u(0, 2).u(0x0020, 14)
    cmd6 = bytes([0x05]) + b16(0x0123) + b'\0'
    c.cplane(E, DL, ST4, st4([st4_cmd(1, cmd1.bytes(), acknack=0x301),
                              st4_cmd(1, cmd1b.bytes(), acknack=0)]),
             numsec_field=0, filt=1, frame=16)
    c.cplane(E, DL, ST4, st4([st4_cmd(2, cmd2.bytes(), numslots=10, acknack=0x302),
                              st4_cmd(6, cmd6, numslots=1, acknack=0x306)]),
             numsec_field=0, filt=1, frame=16, slot=2, sym=3)
    c.cplane(E, DL, ST4, st4([st4_cmd(3, trx_body(2, 1, 5, 0x3fff, b'\xa5\x0f'), numslots=4, acknack=0x303),
                              st4_cmd(5, trx_body(6, 2, 0, 0x0000, bytes(range(1, 9))), acknack=0x305)]),
             numsec_field=0, filt=0, frame=16, slot=3)
    c.cplane(E, DL, ST4, st4([st4_cmd(3, trx_body(1, 0, 0, 0x0000, b'\x00\x01'), numslots=0)]),
             numsec_field=0, filt=13, frame=16, slot=4)
    c.cplane(E, DL, ST4, st4([st4_cmd(4, Bits().u(0, 6).u(3, 2).u(0, 4).u(100, 20).u(0, 2).u(0x3fff, 14)
                                      .u(0, 16).bytes(), numslots=2, acknack=0x304),
                              st4_cmd(4, Bits().u(0, 6).u(0, 2).u(0, 4).u(0, 20).u(0, 2).u(0, 14)
                                      .u(0, 16).bytes())]),
             numsec_field=0, filt=2, frame=16, slot=5)
    # ST8 from the same end as the requests, so the dissector finds them
    st8 = bytes([3, 0]) + b16(0x301) + b16(0x302) + b16(0x303)
    c.cplane(E, DL, ST8, st8, numsec_field=0, filt=1, frame=16, slot=6, sym=1, dt=2000)
    st8 = bytes([3, 0]) + b16(0x304) + b16(0x305) + b16(0x306)
    c.cplane(E, UL, ST8, st8, numsec_field=0, filt=1, frame=16, slot=6, sym=2, dt=1500000)
    c.cplane(E, DL, ST8, bytes([0, 0]), numsec_field=1, filt=1, frame=16, slot=7)       # ready
    c.cplane(0x1000, DL, ST8, bytes([2, 0]) + b16(0x201) + b16(0x202), numsec_field=0, frame=16, slot=8)

    # ---- ST7 LAA, every laaMsgType ---------------------------------------
    E = 0x1006
    for mtype, payload in ((0, b16(0x1111) + Bits().u(100, 10).u(1, 2).u(0, 1).u(3, 3).u(200, 10).u(5, 4)
                            .u(0, 10).bytes()),
                           (1, b16(0x2222) + Bits().u(50, 10).u(2, 2).u(0, 28).bytes()),
                           (2, b16(0x3333) + Bits().u(1, 2).u(1, 1).u(1, 1).u(0x123, 12).u(0, 24).bytes()),
                           (3, b16(0x4444) + b'\x80'),
                           (4, b16(0x5555) + b'\x80'),
                           (5, b16(0x6666) + b'\x05\x06' + Bits().u(3, 2).u(4, 3).u(0, 19).bytes()),
                           (6, b16(0x7777) + b'\x80')):
        c.cplane(E, DL, ST7, laa(mtype, payload), numsec_field=0, frame=17, slot=mtype)

    # ---- ST9 SINR reporting, every numSinrPerPrb -------------------------
    E = 0x1007
    for code, nsinr in enumerate((1, 2, 3, 4, 6, 12)):
        c.cplane(E, UL, ST9, st_hdr(ST9, sinr_per_prb=code, sinr_slot_mask=3) +
                 st9_sec(70 + code, 10, 2, nsinr, rb=code % 2, seed=code),
                 frame=18, slot=code, sym=4)

    # ---- ST10 / ST13 measurement reports, ST11 requests -------------------
    E = 0x1008
    r1 = meas(1, b16(0x0123) + b'\0\0') + meas(1, b16(0x9000) + b'\0\0')
    r2 = meas(2, b16(0x9100))
    r3 = meas(3, b16(0x0010) + b16(0x8ad0)) + meas(3, b16(0x8ad0) + b16(0x0010))
    r4 = meas(4, b16(0x3fff) + b16(0x0100) + b16(0x9000) + b16(0x0200))
    r6 = meas(6, b16(0x0001) + b16(0x8ad0) + b16(0x0300), num_elements=3)
    r7 = meas(7, b16(0x0708) + b'\0\0' + b16(0x0100) + b'\0\0' + b16(0x0000) + b'\0\0') + \
        meas(7, b16(0x0100) + b'\0\0' + b16(0x0800) + b'\0\0' + b16(0x0100) + b'\0\0') + \
        meas(7, b16(0x0f00) + b'\0\0' + b16(0x0200) + b'\0\0' + b16(0x8000) + b'\0\0') + \
        meas(7, b16(0xffff) + b'\0\0' + b16(0x0800) + b'\0\0' + b16(0x9000) + b'\0\0')
    r8 = meas(8, b16(1234) + b'\0\0') + meas(8, b16(0x8000) + b'\0\0') + meas(8, b16(20000) + b'\0\0')
    r9 = meas(9, b'\0\0')
    r10 = meas(10, bytes([0x21, 0x11]) + b16(0x0102) + b'\x22' + b16(0x0304) + b16(0x0506)) + \
        meas(10, bytes([0x53, 0x22]) + b16(0x0102) + b'\x22' + b16(0x0304) + b16(0x0506) + b'\x33' +
             b16(1) + b16(2) + b16(3) + b'\x44' + b16(4) + b16(5) + b16(6) + b16(7)) + \
        meas(10, bytes([0x02, 0x33]) + b16(0x0102))
    r11 = meas(11, b16(0x0101) + b16(0x0202) + b16(0x0303) + b16(0x0404))
    r12 = meas(12, b16(0x0005) + b16(0x1111) + b16(0x2222))
    r13 = meas(13, b16(0x8001) + b16(0x3333) + b16(0x4444), mf=0)
    reports = r1 + r2 + r3 + r4 + r6 + r7 + r8 + r9 + r10 + r11 + r12 + r13
    r5a = meas(5, b16(0x3fff) + b16(1) + b16(2) + b16(3) + b16(0x9000), mf=0)
    r5b = meas(5, b16(0x3fff) + b16(1) + b16(2) + b16(3) + b16(4) + b16(5) + b16(6), mf=0)
    c.cplane(E, UL, ST10, st_hdr(ST10) +
             csec(ST10, sid=80, start=0, num=3, ueid=900, numsym=14, tail=reports) +
             csec(ST10, sid=81, start=0, num=8, ueid=901, numsym=14,
                  ext_bytes=exts(se6(2, 0x5)), tail=r5a) +
             csec(ST10, sid=82, start=10, num=4, ueid=0x7fff, numsym=14,
                  ext_bytes=exts(se12([(2, 3)]), se20([(0x3fff, 11, 1, 0xfff, 0, 0, None)])), tail=r5b),
             nsec=3, frame=19)
    c.cplane(E, UL, ST13, csec(ST13, sid=83, start=0, num=2, ueid=902, numsym=14,
                               ext_bytes=exts(se6(1, 0x3)),
                               tail=r1 + meas(7, b16(0x0100) + b'\0\0' + b16(0xffff) + b'\0\0' + b16(0x0010) + b'\0\0') +
                               meas(11, b16(0x0505) + b16(0x0606), mf=0)),
             frame=19, slot=1)
    c.cplane(E, DL, ST11, st_hdr(ST11) +
             csec(ST11, sid=84, start=0, num=10, numsym=14, ext_bytes=exts(se6(2, 0x1f)),
                  tail=meas_cmd(mf=1) + meas_cmd(symmask=0x0fff)),
             frame=19, slot=2)

    # ---- ST12 and ST14 (sections without type-specific fields) -----------
    c.cplane(E, DL, ST12, csec(ST12, sid=85, start=0, num=4, numsym=4), frame=19, slot=3)
    c.cplane(E, DL, ST14, csec(ST14, sid=86, start=0, num=4, numsym=4), frame=19, slot=4)
    return c


# ============================================================ malformed capture

def malformed_capture():
    c = Cap()

    # ---- U-plane first: udCompLen heuristic decides "not present" -------
    # (selective RE without udCompLen; the sReSMask read as udCompLen is
    # larger than the frame)
    c.uplane(0x3000, DL, [usec(1, 0, 1, [uprb(BFP_SRE, 9, sresmask=0x307, exponent=3)], hdr=(9, BFP_SRE))])

    # ---- Sequence number errors (C-plane and U-plane, both directions) --
    E = 0x2000
    for d in (DL, UL):
        c.cplane(E, d, ST1, st_hdr(ST1) + csec(ST1, sid=1, beam=1), seq=10)
        c.cplane(E, d, ST1, st_hdr(ST1) + csec(ST1, sid=1, beam=1), seq=15)     # gap of 4
        c.cplane(E, d, ST1, st_hdr(ST1) + csec(ST1, sid=1, beam=1), seq=12)     # backwards
    for d in (DL, UL):
        for seq in (20, 21, 25):
            c.uplane(0x2001, d, [usec(1, 0, 1, [uprb(BFP, 9)], hdr=(9, BFP))], seq=seq)

    # ---- C-plane header problems ----------------------------------------
    E = 0x2010
    c.cplane(E, DL, ST1, st_hdr(ST1) + csec(ST1, sid=1, beam=1), e=0, subseq=1)   # radio fragmentation
    c.cplane(E, DL, ST1, st_hdr(ST1) + csec(ST1, sid=1, beam=1), version=2)
    c.cplane(E, DL, ST1, bytes([0, 0xff]) + csec(ST1, sid=1, beam=1))             # reserved not zero
    c.cplane(E, DL, ST1, bytes([udcomphdr(9, BFP), 0]) + csec(ST1, sid=1, beam=1))  # DL udCompHdr set
    c.cplane(E, DL, ST1, st_hdr(ST1) + csec(ST1, sid=1, beam=1, numsym=8), sym=10)  # too many symbols
    c.cplane(E, DL, ST1, st_hdr(ST1) + csec(ST1, sid=1, beam=1) + bytes(8))       # bytes left over
    c.cplane(E, DL, ST1, (st_hdr(ST1) + csec(ST1, sid=1, beam=1, ext_bytes=exts(se6(2, 3))))[:9])  # truncated
    c.cplane(E, DL, 2, csec(2, sid=1, num=2))                                     # reserved ST2
    c.cplane(E, DL, 20, csec(20, sid=1, num=2))                                   # unknown ST
    c.cplane(E, DL, ST10, st_hdr(ST10) + csec(ST10, sid=2, numsym=10, ueid=5, tail=meas(1, bytes(4), mf=0)),
             sym=3)                                                               # ST10 DL, numSymbol, start
    c.cplane(E, DL, ST9, st_hdr(ST9, sinr_per_prb=6) +
             Bits().u(3, 12).u(0, 1).u(1, 1).u(0, 10).u(1, 8).u(0, 8).u(5, 14).bytes())  # ST9 DL, bad value
    c.cplane(E, DL, ST6, st_hdr(ST6, ci=(2, BFP, 0)) + st6_sec(7, 0, 1, 2, BFP, 0, rb=1), nsec=1)
    c.cplane(E, DL, ST6, st_hdr(ST6, ci=(2, MOD, 0)) + st6_sec(7, 0, 1, 2, MOD, 0), nsec=1)  # ciCompMeth 4

    # ---- Section extension problems -------------------------------------
    E = 0x2020
    bad = [
        csec(ST1, sid=10, beam=1, ext_bytes=ext(0, b'\0\0')),                   # extType 0
        csec(ST1, sid=11, beam=1, ext_bytes=ext(35, b'\0\0')),                  # SE 35, not supported
        csec(ST1, sid=12, beam=1, ext_bytes=ext(50, b'\0\0')),                  # unknown SE
        csec(ST1, sid=13, beam=1, ext_bytes=ext(40, b'\x12\x34')),              # non-standard SE 40
        csec(ST1, sid=14, beam=1, ext_bytes=ext(41, b'\x12\x34')),              # non-standard SE 41
        csec(ST1, sid=15, beam=1, ext_bytes=ext(7, b16(0x00ff))),                 # SE 7 not allowed in ST1
        csec(ST1, sid=16, beam=1, ext_bytes=ext(9, b'\x01\x00', extlen=3)),      # extLen too long
        csec(ST1, sid=17, beam=1, ext_bytes=ext(5, bytes(18), extlen=5)),         # SE 5 extLen 5
        csec(ST1, sid=18, beam=1, ext_bytes=exts(se6(0, 0x3))),                   # rbgSize 0
        csec(ST1, sid=19, start=0, num=100, beam=1, ext_bytes=exts(se6(1, 0x3))), # lastRbgid > 27
        csec(ST1, sid=20, start=0, num=4, beam=1, ext_bytes=exts(se6(2, 0x10))),  # bit beyond lastRbgid
        csec(ST1, sid=21, beam=1, ext_bytes=exts(se10(3, 3, ids=(5, 6), plis=(0, 0, 2)))),  # portListIndex 0
        csec(ST1, sid=22, beam=1, ext_bytes=exts((11, Bits().u(0, 8).u(0, 8).u(0x40, 8)))),  # numBundPrb 0
        csec(ST1, sid=23, beam=1, ext_bytes=exts((11, Bits().u(0x80, 8).u(0, 8)))),
        csec(ST1, sid=24, start=0, num=2, ext_bytes=exts(se11_noweights(2, [9999]))),  # beamId not defined
        csec(ST1, sid=25, start=0, num=2, rb=1, beam=1, ext_bytes=exts(se12([(1, 1)]))),  # SE 12 with rb
        csec(ST1, sid=27, start=0, num=1, beam=1, ext_bytes=b'\x05\x00\x00\x00'),  # extLen 0
    ]
    c.cplane(E, DL, ST1, st_hdr(ST1) + b''.join(bad), nsec=len(bad))
    # Unsupported beamforming weight compression methods in SE 1, 11, 19
    for meth in (BSC, ULAW, 4, 6, 9):
        mask = 0x0000000f if meth == 4 else None
        b1 = Bits().u(4, 4).u(meth, 4)
        bfw_param(b1, meth, 1, mask)
        weights(b1, 4, 4)
        c.cplane(E, DL, ST1, st_hdr(ST1) +
                 csec(ST1, sid=30, start=0, num=1, beam=1, ext_bytes=exts((1, b1))) +
                 csec(ST1, sid=31, start=0, num=2,
                      ext_bytes=exts(se11_weights(2, [(0, 140, False)], 4, meth, mask=mask))) +
                 csec(ST1, sid=32, start=0, num=2,
                      ext_bytes=exts(se19(1, [(0xfff, 0x3fff, 141)], width=4, meth=meth, mask=mask))),
                 nsec=3, slot=meth)
    # ST5 extension problems
    c.cplane(E, DL, ST5, st_hdr(ST5) +
             csec(ST5, sid=40, start=0, num=1, ueid=1, ext_bytes=exts(se10(0, 2), se10(1, 2))) +
             csec(ST5, sid=41, start=0, num=0, ueid=1,
                  ext_bytes=exts((21, Bits().u(0, 8).u(0, 8)), (21, Bits().u(1, 8).u(0, 8)),
                                 (21, Bits().u(255, 8).u(0, 8)), (21, Bits().u(4, 8).u(0, 8)))) +
             csec(ST5, sid=42, start=0, num=8, ueid=1,
                  ext_bytes=exts(se6(2, 0xf), (21, Bits().u(2, 8).u(0, 8)),
                                 se11_weights(2, [(1, 150, False), (1, 151, False), (1, 152, False), (0, 153, False)],
                                              2, NONE, nweights=8))) +
             csec(ST5, sid=43, start=0, num=1, ueid=1,
                  ext_bytes=exts(se24([(0, 15), se24_entry2(3)], size=20, group=255))) +
             csec(ST5, sid=44, start=0, num=1, ueid=1,
                  ext_bytes=exts(se10(2, 1, ids=(2,)), se24([Bits().u(5, 3).u(1, 5)], size=1))) +
             csec(ST5, sid=45, start=0, num=1, ueid=1, ext_bytes=exts((25, b'', 2))) +
             csec(ST5, sid=46, start=0, num=1, ueid=1,
                  ext_bytes=exts((27, Bits().u(2, 2).u(0, 6).u(1, 8)))) +
             csec(ST5, sid=47, start=0, num=1, ueid=1,
                  ext_bytes=exts((30, Bits().u(0, 4).u(2, 4).u(0, 8).u(0, 1).u(1, 1).u(0, 6).u(0, 2).u(40, 6)
                                  .raw(b''.join(b16(1234) for _ in range(40)))))),
             nsec=8)

    # ---- Measurement problems --------------------------------------------
    E = 0x2030
    c.cplane(E, UL, ST10, st_hdr(ST10) +
             csec(ST10, sid=50, numsym=14, ueid=1,
                  tail=meas(10, bytes([0x12, 0x00, 0x03])) + meas(14, bytes(4)) + meas(30, bytes(4), mf=0)))
    c.cplane(E, DL, ST11, st_hdr(ST11) + csec(ST11, sid=51, numsym=14, tail=meas_cmd(mtype=3, mf=0) + bytes(7)))

    # ---- ST4 problems --------------------------------------------------------
    E = 0x2040
    c.cplane(E, DL, ST4, st4([]), numsec_field=0)                                   # no commands
    c.cplane(E, DL, ST4, bytes([1, 0]) + bytes([2]) + b16(0) + bytes(5), numsec_field=0)  # zero length
    c.cplane(E, DL, ST4, st4([st4_cmd(9, bytes(4))]), numsec_field=0)               # unknown command
    c.cplane(E, DL, ST4, st4([st4_cmd(2, bytes(8))]), numsec_field=0)               # length too long
    cmd1 = Bits().u(0, 2).u(0x3fff, 14).u(1, 1).u(1, 15).u(0, 8).u(0, 24).bytes()
    c.cplane(E, DL, ST4, st4([st4_cmd(1, cmd1, numslots=2)]), numsec_field=0, sym=2)  # numSlots, startSymbolId
    c.cplane(E, DL, ST4, st4([st4_cmd(3, trx_body(2, 1, 0, 0x00ff, b'\x01\x00')),
                              st4_cmd(4, Bits().u(0, 6).u(1, 2).u(0, 4).u(0, 20).u(0, 2).u(0x0ff0, 14)
                                      .u(0, 16).bytes())]),
             numsec_field=1, sym=2)                                                 # cmdScope, symbolMask
    c.cplane(E, DL, ST4, st4([st4_cmd(1, Bits().u(0, 2).u(0x3fff, 14).u(0, 1).u(1, 15).u(0x20 | BSC, 8).u(0, 24).bytes()
                                      + Bits().u(0, 1).u(2, 15).u(0x40, 8).bytes() + bytes(16) + b'\0',
                                      acknack=0x401)]),
             numsec_field=0)                                                        # BSC weights

    # ---- ST7 / ST8 problems --------------------------------------------------
    E = 0x2050
    c.cplane(E, DL, ST7, laa(0, b16(1) + Bits().u(1, 10).u(0, 2).u(0, 1).u(0, 3).u(0, 10).u(0, 4).u(0, 10).bytes()),
             numsec_field=0)                                                        # MCOT 0
    c.cplane(E, DL, ST7, laa(9, bytes(4)), numsec_field=0)                          # unknown laaMsgType
    c.cplane(E, DL, ST7, b'\0\0' + bytes([0x30]) + b16(1) + b'\x80', numsec_field=0)  # laaMsgLen 0
    c.cplane(E, DL, ST1, st_hdr(ST1) + csec(ST1, sid=60, beam=1, ext_bytes=exts((22, b16(0x0501)))))
    c.cplane(E, DL, ST1, st_hdr(ST1) + csec(ST1, sid=61, beam=1, ext_bytes=exts((22, b16(0x0502)))))
    c.cplane(E, DL, ST8, bytes([1, 2]) + b16(0x0501) + b16(0x0502) + b16(0x0777), numsec_field=0)  # NACKs
    # an ST8 from the O-RU for an id that was never requested
    c.cplane(E, UL, ST8, bytes([1, 0]) + b16(0x0888), numsec_field=0, src=RU, dst=DU)

    # ---- U-plane problems ----------------------------------------------------
    E = 0x2060
    c.uplane(E, DL, [usec(1, 0, 1, [uprb(BSC, 9)], hdr=(9, BSC)),
                     usec(2, 1, 1, [uprb(ULAW, 9)], hdr=(9, ULAW)),
                     usec(3, 2, 1, [uprb(NONE, 9)], hdr=(9, 9))])                   # unsupported methods
    c.uplane(E, DL, [usec(4, 0, 2, [uprb(BFP_SREM, 9, exponent=2, nres=4), uprb(BFP_SREM, 9, exponent=2, nres=4)],
                          hdr=(9, BFP_SREM), masks=(0x00f, 0x00f)),
                     usec(5, 2, 2, [uprb(BFP_SREM, 9, exponent=2, nres=4), uprb(BFP_SREM, 9, exponent=2, nres=4)],
                          rb=1, hdr=(9, BFP_SREM), masks=(0x00f, 0x0f0)),
                     usec(6, 6, 2, [uprb(MOD, 4, nres=4), uprb(MOD, 4, nres=4)], hdr=(4, MOD_SREM),
                          masks=(0x00f, 0x0f0))], sym=1)
    c.uplane(E, DL, [usec(7, 0, 1, [uprb(BFP, 9)], syminc=1, hdr=(9, BFP))], sym=2)   # symInc in U-plane
    c.uplane(E, DL, [usec(8, 0, 1, [uprb(BFP, 9)], hdr=(9, BFP))[:4] + bytes([udcomphdr(9, BFP), 0x55]) +
                     uprb(BFP, 9)], sym=3)                                          # reserved byte not 0
    c.uplane(E, DL, [usec(9, 0, 1, [uprb(BFP, 9)], hdr=(9, BFP)) + bytes(10)], sym=4)  # left over bytes
    c.uplane(E, DL, [usec(10, 0, 2, [uprb(BFP, 9)], hdr=(9, BFP))], sym=5)            # truncated
    c.uplane(E, DL, [usec(11, 0, 1, [uprb(BFP, 9)], hdr=(9, BFP))], version=3, sym=6)
    # Linked flow problems: U-plane before its C-plane (warning only with -2),
    # unknown sectionId, timing that does not match
    E = 0x2070
    c.uplane(E, DL, [usec(1, 0, 1, [uprb(BFP, 9)], hdr=(9, BFP))], frame=30)
    c.uplane(E, UL, [usec(2, 0, 1, [uprb(BFP, 9, exponent=12)])], frame=30)
    c.cplane(E, DL, ST1, st_hdr(ST1) + csec(ST1, sid=1, beam=1, numsym=14), frame=30)
    c.cplane(E, UL, ST1, st_hdr(ST1, udhdr=udcomphdr(9, BFP)) + csec(ST1, sid=2, beam=1, numsym=14), frame=30)
    c.uplane(E, DL, [usec(3, 0, 1, [uprb(BFP, 9)], hdr=(9, BFP))], frame=30)
    c.uplane(E, DL, [usec(1, 0, 1, [uprb(BFP, 9)], hdr=(9, BFP))], frame=31)
    c.uplane(E, UL, [usec(2, 0, 1, [uprb(BFP, 9, exponent=12)])], frame=30, sym=1)
    # Fragments: one that never completes, and fragments out of order
    E = 0x2080
    c.uplane_frags(E, DL, [usec(1, 0, 2, [uprb(BFP, 9, seed=p) for p in range(2)], hdr=(9, BFP))],
                   cuts=(30,), order=[0])
    c.uplane_frags(E, DL, [usec(2, 0, 2, [uprb(BFP, 9, seed=p) for p in range(2)], hdr=(9, BFP))],
                   cuts=(10, 30), order=[2, 0, 1])
    c.uplane_frags(E, DL, [usec(3, 0, 2, [uprb(BFP, 9, seed=p) for p in range(2)], hdr=(9, BFP))],
                   cuts=(2,), order=[0, 1])                                         # first fragment < 4 bytes
    # eCPRI one-way delay measurement: not an O-RAN message type
    c.ecpri(DU, RU, 5, bytes([1, 0]) + bytes(10) + bytes(8))
    # U-plane flow whose first frame ends right after the section header
    c.uplane(0x2090, DL, [Bits().u(1, 12).u(0, 1).u(0, 1).u(0, 10).u(1, 8).bytes() + b'\x01'])
    # SE 12 and SE 13 allocations reaching the 512-bundle limit (disableBFWs)
    E = 0x20a0
    c.cplane(E, DL, ST1, st_hdr(ST1) +
             csec(ST1, sid=1, start=0, num=0, ext_bytes=exts(se12([(0, 255)]),
                                                             se11_noweights(1, [i % 32768 for i in range(512)]))))
    c.cplane(E, DL, ST1, st_hdr(ST1) +
             csec(ST1, sid=2, start=0, num=128,
                  ext_bytes=exts(se13([(1, 0), (2, 1), (3, 2), (4, 3), (5, 4)]),
                                 se11_noweights(1, [i for i in range(512)]))))
    # ST8 answering an SE 22 request 4294967295 seconds later (gap clamped)
    E = 0x20c0
    t = c.t
    c.t = -20
    c.cplane(E, DL, ST1, st_hdr(ST1) + csec(ST1, sid=1, beam=1, ext_bytes=exts((22, b16(0x0701)))))
    c.t = 0xffffffff * 1000000 - 20
    c.cplane(E, DL, ST8, bytes([1, 0]) + b16(0x0701), numsec_field=0)
    c.t = t
    # Last two frames: read on their own by runcov.sh (udCompLen heuristic):
    # section too short for udCompLen, and udCompLen smaller than a section
    c.uplane(0x20b0, DL, [Bits().u(1, 12).u(0, 1).u(0, 1).u(0, 10).u(1, 8).bytes() +
                          bytes([udcomphdr(9, BFP_SRE), 0, 0x30])])
    c.uplane(0x20b0, DL, [usec(1, 0, 1, [uprb(BFP_SRE, 9, sresmask=0x003, exponent=0)], hdr=(9, BFP_SRE))])
    return c


def exportpdu_capture():
    """An exported PDU (linktype 252) for dissector "oran_fh_cus": the
    dissector is called without the eCPRI message type and declines."""
    name = b'oran_fh_cus'
    tags = struct.pack('>HH', 12, len(name)) + name + struct.pack('>HH', 0, 0)
    payload = b16(0x0100) + bytes([0, 0x80]) + utiming(DL, 0, 0, 0, 0) + \
        usec(1, 0, 1, [uprb(BFP, 9)], hdr=(9, BFP))
    fr = tags + payload
    out = struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 252)
    out += struct.pack('<IIII', 1700000000, 0, len(fr), len(fr)) + fr
    return out


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    cap = main_capture()
    # Later edits of the committed capture (ST12 and SE 1 changes of packet-oran.c) removed
    # these frames and kept the timestamps of the others.
    cap.frames = [fr for n, fr in enumerate(cap.frames, 1) if n not in (34, 75, 77, 78, 87)]
    cap.write(os.path.join(out, 'oran-coverage.pcap'))
    malformed_capture().write(os.path.join(out, 'oran-coverage-malformed.pcap'))
    with open(os.path.join(out, 'oran-coverage-exportpdu.pcap'), 'wb') as f:
        f.write(exportpdu_capture())


if __name__ == '__main__':
    main()
