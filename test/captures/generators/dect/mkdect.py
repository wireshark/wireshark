#!/usr/bin/env python3
# Generates test/captures/dect_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build synthetic DECT (packet-dect.c) coverage captures.

DECT runs over Ethernet with ethertype 0x2323 (the "Ethernet hack" of the
dissector): 11 octets of receiver information (transceiver mode, channel,
slot, frame number, RSSI, preamble, packet type), the 8 octet A-field
(header, 5 octet tail, R-CRC) and the B-field. Every packet is built with
struct; nothing comes from a real network.

Usage: mkdect.py <outdir>
Writes dect-coverage.pcap and dect-coverage-malformed.pcap.
"""
import os
import struct
import sys

ETH = bytes.fromhex("0200000000a1" "0200000000a2")
PP = 0x1675     # Phone (portable part) packet
FP = 0xe98a     # Station (fixed part, RFP) packet


def calc_rcrc(data):
    """EN 300 175-3 6.2.5.2, written like calc_rcrc() in packet-dect.c."""
    gp = 0x0589
    crc = (data[0] << 8) | data[1]
    for y in range(6):
        nxt = data[2 + y]
        x = 0
        while x < 8:
            brk = False
            while not (crc & 0x8000):
                crc = ((crc << 1) | (1 if nxt & 0x80 else 0)) & 0xffff
                nxt = (nxt << 1) & 0xff
                x += 1
                if x > 7:
                    brk = True
                    break
            if brk:
                break
            crc = ((crc << 1) | (1 if nxt & 0x80 else 0)) & 0xffff
            nxt = (nxt << 1) & 0xff
            x += 1
            crc ^= gp
    return crc ^ 1


def getbit(data, bit):
    return (data[bit // 8] >> (bit % 8)) & 1


def calc_xcrc(data):
    """EN 300 175-3 6.2.5.4, written like calc_xcrc() in packet-dect.c
    (length 83)."""
    bits = bytearray(21)
    for y in range(83 - 4 + 1):
        if getbit(data, y + 48 * (1 + y // 16)):
            bits[y // 8] |= 1 << (y % 8)
    length = 10
    gp = 0x1
    crc = bits[0]
    y = 0
    while y < length:
        nxt = bits[y + 1] if y < length - 1 else 0
        y += 1
        x = 0
        while x < 8:
            brk = False
            while not (crc & 0x80):
                crc = ((crc << 1) | (1 if nxt & 0x80 else 0)) & 0xff
                nxt = (nxt << 1) & 0xff
                x += 1
                if x > 7:
                    brk = True
                    break
            if brk:
                break
            crc = ((crc << 1) | (1 if nxt & 0x80 else 0)) & 0xff
            nxt = (nxt << 1) & 0xff
            x += 1
            crc ^= (gp << 4)
    return crc


def afield(ta, ba, tail, q1=0, q2=0, good_rcrc=True):
    head = (ta << 5) | (q1 << 4) | (ba << 1) | q2
    a = bytes([head]) + bytes(tail)
    assert len(a) == 6
    crc = calc_rcrc(a + b"\x00\x00")
    if not good_rcrc:
        crc ^= 0x1234
    return a + struct.pack(">H", crc)


BLEN = {0: 40, 1: 40, 2: 100, 3: 40, 4: 10, 5: 40, 6: 40, 7: 0}


def bfield(ba, n, xcrc="good", seed=0):
    """B-field data of n octets for BA ba. With xcrc "good" octet 40 holds
    the matching X-CRC (full slots), with "bad" it does not."""
    b = bytearray((seed * 7 + i * 13 + 5) & 0xff for i in range(n))
    if n > 40:
        if BLEN[ba] == 40:
            want = calc_xcrc(bytes(b) + bytes(128 - n))
        else:
            want = 0
        b[40] = (b[40] & 0x0f) | (want if xcrc == "good" else (want ^ 0x50))
        if BLEN[ba] == 40:
            # octet 40 is not part of the X-CRC input; recheck
            assert calc_xcrc(bytes(b) + bytes(128 - n)) == want
    return bytes(b)


def dect(ptype, a, b=b"", mode=0x00, channel=5, slot=3, fn=7, rssi=0x40):
    hdr = struct.pack(">BBHBB", mode, channel, slot, fn, rssi) + b"\xaa\xaa\xaa" + struct.pack(">H", ptype)
    return ETH + struct.pack(">H", 0x2323) + hdr + a + b


def full(ptype, ta, tail, ba=0, nb=41, xcrc="good", good_rcrc=True, **kw):
    return dect(ptype, afield(ta, ba, tail, good_rcrc=good_rcrc), bfield(ba, nb, xcrc), **kw)


def main_frames():
    F = []
    # Short packets: only the receiver information ("No Data")
    F.append(("header only, no A-field (No Data)", dect(PP, b"")[:14 + 11]))
    F.append(("unknown packet type", dect(0x1234, b"\x00" * 8)))
    # Ct, Nt for both directions
    for ptype in (FP, PP):
        F.append(("Ct next data", full(ptype, 0, [1, 2, 3, 4, 5])))
        F.append(("Ct first data", full(ptype, 1, [6, 7, 8, 9, 10])))
        F.append(("Nt connectionless", full(ptype, 2, [0x12, 0x34, 0x56, 0x78, 0x9a])))
        F.append(("Nt identities", full(ptype, 3, [0x01, 0x23, 0x45, 0x67, 0x89])))
        F.append(("Escape", full(ptype, 5, [0x70, 0, 0, 0, 0])))
    # Qt: every Qh value
    qt_tails = {
        0: [0x05, 0x83, 0xff, 0x23, 0x45],     # static system info, all carriers
        1: [0x1a, 0x40, 0x00, 0x1f, 0x7f],     # static system info, no carriers
        2: [0x20, 1, 2, 3, 4],
        3: [0x3f, 0xff, 0xff, 0xff, 0xff],     # all FP capabilities
        4: [0x4a, 0xff, 0xff, 0xff, 0xff],     # all extended FP capabilities
        6: [0x60, 0x00, 0x12, 0x34, 0x56],     # multiframe number
        7: [0x70, 0xab, 0xcd, 0xef, 0x01],
    }
    for qh in range(16):
        t = qt_tails.get(qh, [qh << 4, 0x11, 0x22, 0x33, 0x44])
        F.append(("Qt Qh=%d" % qh, full(FP if qh % 2 == 0 else PP, 4, t)))
    F.append(("Qt FP capabilities none", full(FP, 4, [0x30, 0, 0, 0, 0])))
    F.append(("Qt extended FP capabilities none", full(FP, 4, [0x40, 0, 0, 0, 0])))
    # Mt: every Mh value, FP (TA 6) and PP first packet (TA 7)
    for mh in range(16):
        t = [(mh << 4) | 1, 0x12, 0x34, 0x56, 0x78]
        if mh == 5:
            t = [0x5e, 0x12, 0x34, 0x56, 0x78]   # encryption control
        F.append(("Mt Mh=%d FP" % mh, full(FP, 6, t)))
        F.append(("Mt Mh=%d PP first" % mh, full(PP, 7, t)))
    for cmd in range(16):
        F.append(("Mt basic connection control %d" % cmd, full(PP, 6, [cmd, 0xab, 0xcd, 0xef, 0x12])))
    for c1 in range(4):
        for c2 in range(4):
            F.append(("Mt encryption control %d %d" % (c1, c2), full(FP, 6, [0x50 | (c1 << 2) | c2, 1, 2, 3, 4])))
    # Pt (FP only): zero length and short pages with every info type, then
    # every other SDU type
    for sdu in (0, 1):
        for it in range(16):
            t = [(sdu << 4) | 0x0a, 0xbc, 0xde, (it << 4) | 0x0f, 0xff]
            F.append(("Pt SDU %d info type %d" % (sdu, it), full(FP, 7, t)))
    F.append(("Pt bearer marker, no slot pairs", full(FP, 7, [0x00, 0, 0, 0x80, 0x00])))
    F.append(("Pt bearer marker, ext flag", full(FP, 7, [0x80, 0, 0, 0x85, 0x55])))
    for sdu in range(2, 8):
        F.append(("Pt SDU %d" % sdu, full(FP, 7, [(sdu << 4) | 0x81, 1, 2, 3, 4])))
    # B-field types, with and without X-CRC octet, X-CRC match and error,
    # R-CRC error
    for ba in range(8):
        blen = BLEN[ba]
        F.append(("BA %d with X-CRC" % ba, full(PP, 0, [ba] * 5, ba=ba, nb=blen + 1)))
        F.append(("BA %d bad X-CRC" % ba, full(FP, 0, [ba] * 5, ba=ba, nb=blen + 1, xcrc="bad")))
        if blen:
            F.append(("BA %d without X-CRC" % ba, full(FP, 1, [ba] * 5, ba=ba, nb=blen)))
    F.append(("double slot, more than 128 octets", full(FP, 0, [9] * 5, ba=2, nb=140)))
    F.append(("full slot, Q1 and Q2 set", dect(FP, afield(3, 0, [1, 2, 3, 4, 5], q1=1, q2=1), bfield(0, 41))))
    F.append(("R-CRC error", full(FP, 3, [1, 2, 3, 4, 5], good_rcrc=False)))
    F.append(("R-CRC error PP", full(PP, 0, [5, 4, 3, 2, 1], good_rcrc=False, mode=1, channel=9, slot=23, fn=15, rssi=0xff)))
    # Reproducer of "DECT: Name the RFPI tail field RFPI": zero length page
    F.append(("RFPI tail (zero length page)", full(FP, 7, [0x01, 0x23, 0x45, 0x00, 0x00], fn=0)))
    return F


def malformed_frames():
    F = []
    F.append(("A-field cut after the header", dect(FP, b"\x00")))
    F.append(("A-field without R-CRC", dect(FP, afield(0, 0, [1, 2, 3, 4, 5])[:6])))
    F.append(("full slot B-field too short", full(FP, 0, [1] * 5, ba=0, nb=20)))
    F.append(("double slot B-field too short", full(PP, 3, [1] * 5, ba=2, nb=50)))
    F.append(("half slot B-field too short", full(PP, 3, [1] * 5, ba=4, nb=5)))
    F.append(("no B-field data at all", full(FP, 3, [1] * 5, ba=0, nb=0)))
    F.append(("BA 7, nothing after the A-field", full(FP, 1, [7] * 5, ba=7, nb=0)))
    F.append(("Mt basic connection control cut", dect(FP, afield(6, 7, [0x01, 2, 3, 4, 5])[:4])))
    return F


def write_pcap(path, frames, t0=1700000000):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, (_, p) in enumerate(frames):
            f.write(struct.pack("<IIII", t0 + i, 0, len(p), len(p)) + p)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "."
    m = main_frames()
    write_pcap(os.path.join(out, "dect-coverage.pcap"), m)
    write_pcap(os.path.join(out, "dect-coverage-malformed.pcap"), malformed_frames())
    if "-v" in sys.argv:
        for i, (d, _) in enumerate(m):
            print(i + 1, d)


if __name__ == "__main__":
    main()
