#!/usr/bin/env python3
# Generates test/captures/gmr1_bcch_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic GMR-1 BCCH coverage captures, GSMTAP over UDP 4729. Usage: mkgmr1_bcch.py <outdir>"""
import struct
import sys

# GSMTAP (UDP 4729) type 0x0a = GMR-1 air interface; sub-types:
GSMTAP_TYPE_GMR1_UM = 0x0a
SUB_BCCH, SUB_CCCH, SUB_PCH, SUB_AGCH, SUB_RACH, SUB_SDCCH = 1, 2, 3, 4, 6, 8
SUB_FACCH3 = 0x10 | 0x02

_fn = [1000]


def csum(b):
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def frame(sub, payload, uplink=False, arfcn=None):
    """One Ethernet/IPv4/UDP/GSMTAP frame (synthetic addresses)."""
    _fn[0] += 51
    if arfcn is None:
        arfcn = 0x4000 | 321 if uplink else 321
    gsmtap = struct.pack("!BBBBHbbIBBBB", 2, 4, GSMTAP_TYPE_GMR1_UM, 0,
                         arfcn, -60, 10, _fn[0], sub, 0, 0, 0) + payload
    udp = struct.pack("!HHHH", 40000, 4729, 8 + len(gsmtap), 0) + gsmtap
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), _fn[0] & 0xffff,
                     0, 64, 17, 0, bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2]))
    ip = ip[:10] + struct.pack("!H", csum(ip)) + ip[12:]
    eth = bytes.fromhex("020000000002020000000001") + b"\x08\x00"
    return eth + ip + udp


def lapsat(dtap, addr=0x00, ctl=0x003, nibble=0):
    """LAPSat header (address, 12 bit control, last-payload nibble) + L3."""
    return bytes([addr]) + struct.pack("!H", (ctl << 4) | nibble) + dtap


def write_pcap(path, pkts):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, p in enumerate(pkts):
            olen = len(p)
            if isinstance(p, tuple):        # (data, original length): snapped
                p, olen = p
            f.write(struct.pack("<IIII", 1700000000 + i, i * 1000, len(p), olen))
            f.write(p)
    print("wrote %d packets to %s" % (len(pkts), path))


class Bits:
    def __init__(self):
        self.s = ""

    def add(self, v, n):
        self.s += format(v & ((1 << n) - 1), "0%db" % n)
        return self

    def raw(self, bitstr):
        self.s += bitstr
        return self

    def bytes(self):
        s = self.s + "0" * (-len(self.s) % 8)
        return int(s, 2).to_bytes(len(s) // 8, "big") if s else b""


GSMTAP_OFF = 14 + 20 + 8 + 16


def cut(fr, keep):
    """Keep only the first `keep` octets of the GSMTAP payload of a frame and
    fix the IPv4 and UDP lengths (and the IPv4 checksum)."""
    fr = bytearray(fr[:GSMTAP_OFF + keep])
    ip = bytearray(fr[14:34])
    ip[2:4] = struct.pack("!H", len(fr) - 14)
    ip[10:12] = b"\0\0"
    ip[10:12] = struct.pack("!H", csum(bytes(ip)))
    fr[14:34] = ip
    fr[38:40] = struct.pack("!H", len(fr) - 34)
    return bytes(fr)


def payload_of(fr):
    return fr[GSMTAP_OFF:]


def snap(fr, keep):
    """Frame as captured with a snap length: only `keep` octets of the
    GSMTAP payload are present, the lengths in the headers stay."""
    return (fr[:GSMTAP_OFF + keep], len(fr))
# ---- BCCH system information (CSN.1, bit packed) --------------------------
def seg1a(c2=1, c3=2, sb_ts=3, sb_sym=4, sa_freq=5, retr=1, ac=0x0000, cba=0, hyst=3,
          sp=0, prio=0, gbch=1, tgs=0, tgs2=1, sp1=0, cbae2=0, sp2=0, cbae=0):
    return (Bits().add(c2, 3).add(c3, 4).add(sb_ts, 5).add(sb_sym, 6).add(sa_freq, 8)
            .add(retr, 2).add(ac, 16).add(cba, 1).add(hyst, 4).add(sp, 1).add(prio, 1)
            .add(gbch, 1).add(tgs, 1).add(tgs2, 1).add(sp1, 3).add(cbae2, 1).add(sp2, 5).add(cbae, 1))


def seg2a(typ=0, c4=1, sirfn=2, stn=3, sfn=0x123, mfn=2, mffn=1, rxlev=10, selpow=9,
          pch=1, bach=0x55, rach_ts=7, npage=2, imsi=1, ecsc=0, upd=1):
    return (Bits().add(2, 2).add(typ, 4).add(c4, 3).add(sirfn, 4).add(stn, 5).add(sfn, 13).add(mfn, 2)
            .add(mffn, 1).add(rxlev, 5).add(selpow, 4).add(pch, 2).add(bach, 8).add(rach_ts, 5)
            .add(npage, 2).add(imsi, 1).add(ecsc, 1).add(upd, 1))


def seg2b(typ=1):
    return Bits().add(2, 2).add(typ, 4)


def seg3a(mcc=(2, 4, 4), mnc=(5, 5), lac=0xabcd, sat=1, sysid=9, slat=0x12, slon=0x321, srad=1000,
          blat=0x100, blon=0x700, timer=15, spare=0):
    b = Bits().add(0, 1).add(0, 4)
    # LAI: BCD MCC/MNC/LAC as in a location area identification
    b.add((mcc[1] << 4) | mcc[0], 8).add((mnc[1] << 4) | mcc[2], 8).add((mnc[1] << 4) | mnc[0], 8)
    b.add(lac, 16)
    return (b.add(sat, 2).add(sysid, 4).add(slat, 8).add(slon, 12).add(srad, 16)
            .add(blat, 11).add(blon, 12).add(timer, 6).add(spare, 4))


def seg3(typ):
    return Bits().add(0, 1).add(typ, 4)


def seg4(typ):
    return Bits().add(6, 3).add(typ, 4)


def si1(seg, ver=2, rand=1, sp=0, s1a=None, pad=24):
    b = Bits().add(ver, 4).add(1, 1).add(rand, 2).add(sp, 1)
    b.raw((s1a or seg1a()).s).raw(seg.s)
    d = b.bytes()
    return d.ljust(pad, b"\0")


def si2(seg, ver=2, sp=0, pad=24):
    b = Bits().add(ver, 4).add(0, 1).add(sp, 3).raw(seg.s)
    return b.bytes().ljust(pad, b"\0")


def bcch_frames():
    f = []
    A = lambda p: f.append(frame(SUB_BCCH, p))
    # The reproducer first: SA_FREQ_OFFSET = 0xf6 (-10)
    A(si1(seg3(2), s1a=seg1a(sa_freq=0xf6)))
    # SI1 with every segment that follows segment 1A
    A(si1(seg2a(0), rand=0, s1a=seg1a(ac=0xffff, cba=1, retr=3, hyst=15, sp=1, prio=1, gbch=0, tgs=1, tgs2=0,
                                      sp1=5, cbae2=1, sp2=0x1f, cbae=1, c2=7, c3=15, sb_ts=31, sb_sym=63, sa_freq=0x7f)))
    A(si1(seg2b(1), rand=2, s1a=seg1a(ac=0xa5a5, sa_freq=0x80, retr=0)))
    A(si1(seg3a(), rand=3))
    A(si1(seg3a(mcc=(9, 9, 9), mnc=(0, 1), lac=0x0001, slat=0x80, slon=0x6c0, srad=0x8000, blat=0x7ff, blon=0x000, timer=63, spare=15),
          s1a=seg1a(sa_freq=1)))
    A(si1(seg3a(slat=0xff, slon=0x0f00, srad=0xffff, blat=0x400, blon=0x70f), s1a=seg1a(sa_freq=0xff)))
    A(si1(seg3a(slat=0x7f, slon=0x708, srad=0x0000, blat=0, blon=0x707)))
    for typ in (1, 2, 3, 4, 5, 6, 7, 9, 10, 11):
        A(si1(seg3(typ), ver=typ, s1a=seg1a(ac=typ * 257, sa_freq=typ * 25)))
    for typ in range(11):
        A(si1(seg4(typ), ver=typ + 1, s1a=seg1a(sb_ts=typ, sb_sym=typ * 5)))
    # SI2
    A(si2(seg2a(0)))
    A(si2(seg2a(0, c4=7, sirfn=15, stn=31, sfn=0x1fff, mfn=3, mffn=0, rxlev=31, selpow=15, pch=3, bach=0xff, rach_ts=31,
                npage=3, imsi=0, ecsc=1, upd=0), ver=3, sp=7))
    A(si2(seg2b(1)))
    for typ in (1, 4, 6, 10):
        A(si2(seg3(typ), ver=typ))
    # Shorter than a full block (segment 2A/3A are the longest)
    A(si2(seg2b(1), pad=2))
    A(si1(seg2b(1), pad=10))
    return f


def bcch_malformed_frames(clean):
    f = []
    # prefixes of SI1/SI2 with segment 3A and 2A
    si_3a = si1(seg3a(), pad=0)
    si_2a1 = si1(seg2a(0), pad=0)
    si_2a2 = si2(seg2a(0), pad=0)
    si_4a = si1(seg4(0), pad=0)
    for blk in (si_3a, si_2a1, si_2a2, si_4a):
        for n in range(0, len(blk)):
            f.append(frame(SUB_BCCH, blk[:n]))
    # segment choices that are not defined: SI1 and SI2
    for typ in (8, 12, 13, 14, 15):
        f.append(frame(SUB_BCCH, si1(seg3(typ))))
    f.append(frame(SUB_BCCH, si1(Bits().add(0x3f, 6))))            # 111111
    f.append(frame(SUB_BCCH, si1(Bits().add(0x22, 6))))            # 6 bit class 2, type 2
    f.append(frame(SUB_BCCH, si1(Bits().add(0x0f, 7))))
    f.append(frame(SUB_BCCH, si1(Bits().add(0x6b, 7))))            # 4L does not exist
    for seg in (seg3(0), seg3(2), seg3(3), seg3(5), seg3(7), seg3(9), seg3(11), seg4(0), seg4(10), Bits().add(0x22, 6),
                Bits().add(0x3f, 6), seg3(8), seg3(12), Bits().add(0x7f, 7)):
        f.append(frame(SUB_BCCH, si2(seg)))
    return f


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "."
    clean = bcch_frames()
    write_pcap(out + "/gmr1_bcch-coverage.pcap", clean)
    write_pcap(out + "/gmr1_bcch-coverage-malformed.pcap", bcch_malformed_frames(clean))
