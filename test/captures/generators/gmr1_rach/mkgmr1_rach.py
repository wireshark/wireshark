#!/usr/bin/env python3
# Generates test/captures/gmr1_rach_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic GMR-1 RACH coverage captures, GSMTAP over UDP 4729. Usage: mkgmr1_rach.py <outdir>"""
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
# ---- RACH (channel request, 18 octets) ------------------------------------
def gps_pos(cpi, lat, lng):
    """1 bit CPI, 19 bit latitude, 20 bit longitude."""
    return Bits().add(cpi, 1).add(lat, 19).add(lng, 20).bytes()


NULL_POS_LAT = gps_pos(0, 0x40000, 0x12345)       # latitude 0x40000 is the NULL position
NULL_POS_LNG = gps_pos(1, 0x01234, 0x80000)       # so is a longitude of 0x80000


def dialed(pd, g0, g1, g2, g3, g4, gro):
    return Bits().add(pd, 2).add(g0, 10).add(g1, 10).add(g2, 10).add(g3, 10).add(g4, 11).add(gro, 3).bytes()


def rach_pdu(ec, cls2, prio=0, retry=0, precorr=7, rr=0x15):
    return bytes([prio | (ec << 1) | (retry << 6), (precorr << 5) | rr]) + cls2


def k2_gmr1(pwr, sp, mid, pos, ntype, gro=0):
    """GMR-1 class-2: `mid` are the 7 octets at offset 3 (dialed number or
    MSC ID/GPS timestamp/software version), `gro` the GCI/R/O bits."""
    assert len(mid) == 7
    mid = bytearray(mid)
    mid[6] = (mid[6] & 0xf8) | gro
    return bytes([(pwr << 4) | ((sp >> 16) & 0xf), (sp >> 8) & 0xff, sp & 0xff]) + bytes(mid) + pos + bytes([ntype])


def nonmoc_mid(pd, msc, ts, sw, spare, pad=b"\x00\x00"):
    return bytes([(pd << 6) | msc]) + struct.pack("!H", ts) + bytes([(sw << 1) | spare]) + pad + b"\x00"


def k2_type1(hi, l3, sp, prio, spare1, pd, tlli, tail, pos, flags, class_d_dl=0, res=0):
    """GmPRS type 1: terminal type nibble `hi`/`l3`, SP/HPLMN ID (or DL peak
    throughput and the reserved word for the class D types)."""
    if (hi << 3 | l3) in (0x0d, 0x0e, 0x0f):
        b = bytes([(hi << 4) | class_d_dl, res & 0xff, 0])
    else:
        b = bytes([(hi << 4) | ((sp >> 16) & 0xf), (sp >> 8) & 0xff, sp & 0xff])
    b += bytes([(pd << 6) | (spare1 << 5) | (prio << 3) | l3]) + struct.pack("!I", tlli)
    return b + tail + pos + bytes([flags])


def k2_type2(hi, sp, pd_msc, tlli, req, sw, spare, pos, gro):
    b = bytes([(hi << 4) | ((sp >> 16) & 0xf), (sp >> 8) & 0xff, sp & 0xff, pd_msc])
    return b + struct.pack("!I", tlli) + bytes([req, (sw << 1) | spare]) + pos + bytes([gro])


def rach_frames():
    f = []
    A = lambda ec, cls2, **kw: f.append(frame(SUB_RACH, rach_pdu(ec, cls2, **kw), uplink=True))
    pos = gps_pos(1, 0x1a2b3, 0x4c5d6)
    pos_s = gps_pos(0, 0x7f000, 0xf0f00)      # negative latitude and longitude
    # Paging response (establishment cause 0..3: channel needed in bits 2:1)
    for ec in range(4):
        A(ec, k2_gmr1(ec, 0x12345, nonmoc_mid(0, ec * 9, 0x0123, 0x55, ec & 1), pos, 7, 1 << (ec & 1)), prio=ec & 1, retry=ec)
    # Other establishment causes with the GMR-1 class-2 information
    for ec, sp, ts in ((4, 0xfffff, 0xffff), (5, 0xf8123, 0x0000), (6, 0x00abc, 0x1000), (8, 0xf8000, 0x0001),
                       (9, 0xf7fff, 0x7fff), (10, 0x07654, 0xfffe), (11, 0xfffff, 0x0002), (12, 0xf9876, 0x00ff),
                       (15, 0x00001, 0x4000)):
        A(ec, k2_gmr1(ec, sp, nonmoc_mid(1, ec, ts, ec * 7, ec & 1), pos_s if ec & 1 else pos, ec & 7, gro=ec & 7), retry=ec & 3,
          precorr=ec & 7, rr=ec)
    # Mobile originated calls (establishment cause 16..31): dialed numbers
    numbers = [
        (123, 456, 789, 12, 345),         # all digits valid
        (123, 456, 1023, 0, 0),           # last group complete
        (123, 1022, 0, 0, 0),             # last group has two digits
        (123, 456, 789, 1021, 0),         # last group has one digit
        (123, 456, 789, 12, 1150),        # last group of two digits in the final group
        (123, 456, 789, 12, 1205),        # one digit
        (123, 456, 789, 12, 5),           # final group of 3 digits
        (1, 2, 3, 4, 999),
        (999, 998, 997, 996, 1199),
        (123, 1000, 0, 0, 0),             # invalid
        (123, 456, 789, 12, 1050),        # invalid final group
        (123, 456, 789, 1100, 1200),      # group value 1100 shown as invalid
        (0, 0, 0, 0, 1021),
    ]
    for i, g in enumerate(numbers):
        ec = 16 + i
        A(ec, k2_gmr1(i & 15, [0xfffff, 0xf8abc, 0x01234][i % 3], dialed(0, *g, i & 7), pos if i & 1 else pos_s, i & 7, 0), prio=1, retry=i & 3,
          precorr=(i % 7) + 1)
    # Number plans 0..15 in the MOC establishment cause
    for npl in range(0, 16):
        A(0x10 + npl, k2_gmr1(1, 0x12345, dialed(npl & 3, 111, 222, 333, 444, 555, 0), NULL_POS_LAT, npl & 7))
    # Reproducer of the spare field fix: software version 0x7f, spare bit 0, then 1
    A(1, k2_gmr1(1, 0x12345, nonmoc_mid(0, 0, 0, 0x7f, 0), pos, 7))
    A(1, k2_gmr1(1, 0x12345, nonmoc_mid(0, 0, 0, 0x00, 1), pos, 7))
    # Null GPS positions
    A(5, k2_gmr1(2, 0xfffff, nonmoc_mid(0, 3, 0x0102, 0x7f, 0), NULL_POS_LAT, 0))
    A(5, k2_gmr1(2, 0xfffff, nonmoc_mid(0, 3, 0x0102, 0x7f, 0), NULL_POS_LNG, 0))
    # GmPRS channel request type 1: attach (13) and packet data transfer (14)
    for ec in (13, 14):
        for hi, l3 in ((1, 1), (1, 5), (1, 6), (1, 7), (3, 7), (9, 0), (8, 0), (0, 0)):
            tail = bytes([0x0f, 0x3d]) if ec == 14 else struct.pack("!H", 0x0abc)
            A(ec, k2_type1(hi, l3, 0xf8777 if hi & 1 else 0x00fed, l3 & 3, hi & 1, 0, 0xa5a5a5a5 + hi, tail,
                           pos if l3 & 1 else pos_s, (l3 & 3) | ((hi & 1) << 2), class_d_dl=l3, res=0x1234), retry=l3 & 3)
    A(14, k2_type1(1, 5, 0, 2, 0, 0, 0x12345678, bytes([0x80, 0xc3]), NULL_POS_LNG, 7, class_d_dl=9, res=0x7f7f))
    # GmPRS channel request type 2 (suspend/resume): paging answer and others
    for req in (0x00, 0x01, 0x02, 0x03, 0x04, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0f, 0x05, 0x0c, 0x1f):
        A(7, k2_type2(req & 15, 0x0f123 if req & 1 else 0xfffff, (req & 3) << 6 | req, 0xc0de0000 + req, req, req * 3,
                      req & 1, pos if req & 2 else NULL_POS_LAT, req & 7), retry=req & 3)
    # Not 18 octets: no class-2 information, shown as data
    A_len = lambda n: f.append(frame(SUB_RACH, rach_pdu(4, bytes(n - 2))[:n] if n >= 2 else bytes(n), uplink=True))
    for n in (0, 1, 2, 17, 19, 30):
        A_len(n)
    return f


def rach_malformed_frames(clean):
    f = []
    seen = set()
    for fr in clean:
        p = payload_of(fr)
        ec = (p[0] >> 1) & 0x1f if p else -1
        if len(p) == 18 and ec in (0, 4, 7, 13, 14, 16, 0x1b) and ec not in seen:
            seen.add(ec)
            f += [snap(fr, n) for n in (1, 2, 3, 5, 8, 10, 12, 14, 16, 17)]
    # one octet of class-1 information only
    f.append(snap(frame(SUB_RACH, bytes(18), uplink=True), 0))
    return f


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "."
    clean = rach_frames()
    write_pcap(out + "/gmr1_rach-coverage.pcap", clean)
    write_pcap(out + "/gmr1_rach-coverage-malformed.pcap", rach_malformed_frames(clean))
