#!/usr/bin/env python3
# Generates test/captures/gmr1_dtap_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic GMR-1 DTAP coverage captures, LAPSat over GSMTAP (UDP 4729). Usage: mkgmr1_dtap.py <outdir>"""
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
# ---- RR information element builders -------------------------------------
def req_ref(cause, ra, fn):
    return bytes([(cause << 5) | ra, fn])


def gps_discr(v):
    return struct.pack("!H", v)


def chan_desc(kab, rx, arfcn, tx, ctype):
    return Bits().add(kab, 6).add(rx, 5).add(arfcn, 11).add(tx, 5).add(ctype, 5).bytes()


def timing_ofs(ti, v):
    return Bits().add(ti, 1).add(v, 15).bytes()


def freq_ofs(fi, v, spare=0):
    return Bits().add(fi, 1).add(v, 12).add(spare, 3).bytes()


def pos_upd(valid, dist, tm):
    return bytes([(dist << 1) | valid, tm])


def bcch_carrier(arfcn, si, ri, spare=0):
    return Bits().add(arfcn, 11).add(si, 1).add(ri, 1).add(spare, 3).bytes()


def reject_cause(cause, b):
    return bytes([(cause << 2) | b])


def msc_id(v, spare=0):
    return bytes([(v << 2) | spare])


def almanac(pn, wn, word, sfn, co, spare):
    return bytes([(pn << 3) | wn]) + word.to_bytes(3, "big") + bytes([(sfn << 7) | (co << 6) | spare])


def pia3(rlc, spare, tfi, sfn, slots):
    return bytes([rlc | (spare << 1) | ((tfi >> 4) << 5), (sfn << 4) | (tfi & 0xf), slots])


def pkt_freq(arfcn, plan, dlbw, uldist, ulbw, spare=0):
    return bytes([arfcn >> 3,
                  ((uldist >> 4) << 7) | (dlbw << 4) | (plan << 3) | (arfcn & 7),
                  (spare << 7) | (ulbw << 4) | (uldist & 0xf)])


def pia2(sp1, final, usfg, dlctl, mode, sfn, dblk, mcs, tfi, sp2, slots):
    return bytes([(mode << 6) | (dlctl << 3) | (usfg << 2) | (final << 1) | sp1,
                  ((dblk >> 3) << 4) | sfn,
                  (mcs << 3) | (dblk & 7),
                  (sp2 << 7) | tfi,
                  slots])


def pwr_ctrl(par, spare=0):
    return bytes([(spare << 6) | par])


def pos_display(flag, text):
    """GSM 7 bit packed text, nibble shifted as the dissector expects."""
    septets = [ord(c) for c in text.ljust(12, " ")][:12]
    bits = "".join(format(c, "07b")[::-1] for c in septets)
    bits += "0" * (-len(bits) % 8)
    packed = bytes(int(bits[i:i + 8][::-1], 2) for i in range(0, len(bits), 8))
    packed = packed.ljust(11, b"\0")
    raw = bytearray(11)
    raw[0] = (flag << 4) | (packed[0] >> 4)
    for i in range(9):
        raw[i + 1] = ((packed[i] & 0xf) << 4) | (packed[i + 1] >> 4)
    raw[10] = packed[10]
    return bytes(raw)


TMSI = lambda v: struct.pack("!I", v)
MID_TMSI = bytes([0xf4]) + TMSI(0x01020304)
CM2_FULL = bytes([0x57, 0x23, 0xd0])          # three octets
# ---- RR message bodies (after the message type octet) ---------------------
def ccch(sub, mt, body=b"", pd=0x06, pl=None, uplink=False):
    n = 2 + len(body)
    if pl is None:
        pl = (min(n, 62) << 2) | 1
    return frame(sub, bytes([pl, pd, mt]) + body, uplink)


def dtap(mt, body=b"", pd=0x06, sub=SUB_SDCCH, uplink=False, **kw):
    return frame(sub, lapsat(bytes([pd, mt]) + body, **kw), uplink)


def imm_ass_body(mif, rest=b""):
    b = bytes([mif]) + req_ref(0, 0x11, 0x42)
    if (mif & 3) != 2:
        b += gps_discr(0xbeef)
    if (mif & 3) != 3:
        b += chan_desc(5, 3, 1234, 4, 1) + timing_ofs(1, 0x7ff0) + freq_ofs(1, 0xf9c, 5)
    if mif & 4:
        b += pos_upd(1, 40, 15)
    if mif & 8:
        b += pos_upd(0, 100, 255)
    if mif & 0x10:
        b += req_ref(1, 0x05, 0x43)
    if mif & 0x20:
        b += req_ref(2, 0x06, 0x44)
    if mif & 0x40:
        b += req_ref(5, 0x07, 0x45)
    return b + rest


def imm_ass_rej1_body(rej, extra_msc=0x2a):
    b = req_ref(1, 2, 3) + gps_discr(0x1234) + reject_cause(rej >> 2, rej & 1)
    if (rej & 0xfc) == 0:
        b += bytes([30])
    b += req_ref(2, 3, 4) + bytes([5]) + req_ref(3, 4, 5) + bytes([6]) + req_ref(4, 5, 6) + bytes([7])
    b += pos_upd(1, 3, 4)
    if rej & 1:
        b += bcch_carrier(1500, 1, 1)
    if (rej & 0xfc) == 0x5c:
        b += msc_id(extra_msc, 1)
    return b + bytes([0x2b, 0x2b])


def imm_ass2_body(par):
    return (bytes([0, 0, 0x2a]) + bytes([0x45]) + TMSI(0xc0ffee01) + timing_ofs(0, 0x0100) + freq_ofs(0, 0x010, 0)
            + pia2(1, 1, 1, 5, 2, 9, 0x5a, 17, 0x55, 1, 0xa5)
            + pkt_freq(0x7ff, 1, 5, 0x1d, 3, 1) + pwr_ctrl(par, 2))


def imm_ass3_body(nib, par):
    return (bytes([nib]) + bytes([0x9a, 0xbc]) + bytes([0x21]) + TMSI(0x01234567)
            + pia3(1, 0xf, 0x5a, 7, 0x81) + pkt_freq(5, 0, 3, 2, 6) + pwr_ctrl(par) + bytes(6))


def pag_req3_body(tam, mode=0):
    b = bytes([(tam << 4) | mode])
    for i in range(4):
        b += TMSI(0xa0000001 + i) if tam & (1 << i) else almanac(i + 3, i, 0x112233 + i, i & 1, 1, 0)
    for i in range(4):
        if tam & (1 << i):
            b += bytes([((i + 9) << 2) | (i & 3)])
    return b


def cm2_lv(n):
    return bytes([n]) + (CM2_FULL + b"\x99\x98")[:n]


def pag_resp_body(cksn=3, cm2=3, mid=MID_TMSI, midlen=None):
    b = bytes([cksn]) + cm2_lv(cm2)
    return b + bytes([len(mid) if midlen is None else midlen]) + mid


# message types that have a name but no decoder (CCCH view; 0x3b is
# "Immediate Assignment Reject Type 2" on the CCCH, the "Extended" one on DCCH)
NOFUNC_RR = [0x3b, 0x3c, 0x2a, 0x29, 0x2f, 0x2b, 0x2c, 0x0e, 0x21, 0x22, 0x12, 0x16,
             0x13, 0x14, 0x15, 0x11, 0x01, 0x02, 0x04, 0x40, 0x41, 0x42, 0x43, 0x44,
             0x45, 0x46, 0x4f]


def rr_ccch_frames():
    f = []
    # Immediate Assignment: every MES information flag combination
    for mif in (0x00, 0x01, 0x02, 0x03, 0x05, 0x0a, 0x0c, 0x13, 0x22, 0x44, 0x7d, 0xfe, 0x80):
        f.append(ccch(SUB_AGCH, 0x3f, imm_ass_body(mif, rest=bytes([0x2b] * (mif % 5)))))
    # Immediate Assignment Reject Type 1
    for rej in (0x00, 0x01, 0x48, 0x5c, 0x5d, 0x4c):
        f.append(ccch(SUB_AGCH, 0x3a, imm_ass_rej1_body(rej)))
    # Position Verification Notify, with and without the optional IE
    pv = req_ref(5, 9, 0x66) + gps_discr(0x0102) + pos_display(2, "Atlantis")
    f.append(ccch(SUB_AGCH, 0x39, pv + bytes([0x78]) + pos_upd(1, 9, 8) + b"\x2b\x2b"))
    f.append(ccch(SUB_AGCH, 0x39, pv + b"\x2b\x2b\x2b"))
    f.append(ccch(SUB_AGCH, 0x39, req_ref(5, 9, 0x67) + gps_discr(0x0103) + pos_display(1, "") + bytes([0x78]) + pos_upd(0, 0, 0)))
    # Immediate Assignment Type 2 and 3
    f.append(ccch(SUB_AGCH, 0x3e, imm_ass2_body(33)))
    f.append(ccch(SUB_AGCH, 0x3e, imm_ass2_body(61)))
    f.append(ccch(SUB_AGCH, 0x3e, imm_ass2_body(63)))
    f.append(ccch(SUB_AGCH, 0x3d, imm_ass3_body(0xa1, 12)))
    f.append(ccch(SUB_AGCH, 0x3d, imm_ass3_body(0x03, 60)))
    # Paging Request Type 3 (every TMSI availability mask)
    for tam in range(16):
        f.append(ccch(SUB_PCH, 0x24, pag_req3_body(tam, tam & 3)))
    # Named messages without a decoder and unknown message types
    for mt in NOFUNC_RR:
        f.append(ccch(SUB_CCCH, mt, bytes(range(1, 1 + (mt % 7)))))
    f.append(ccch(SUB_CCCH, 0x01, b""))
    f.append(ccch(SUB_CCCH, 0x77, b"\x01\x02\x03"))
    f.append(ccch(SUB_CCCH, 0xee, b""))
    # Not RR / too short for a CCCH message: shown as data
    f.append(ccch(SUB_CCCH, 0x21, b"\x01", pd=0x05))
    f.append(frame(SUB_CCCH, b"\x0d\x06"))
    f.append(frame(SUB_CCCH, b""))
    # protocol discriminator with the extended form (0x1e: DTRS), CCCH is RR only
    f.append(frame(SUB_CCCH, bytes([0x15, 0x1e, 0x01, 0x02])))
    return f


def rr_dtap_frames():
    f = []
    # Ciphering Mode Command: every algorithm, with and without Position Display
    for algo in range(8):
        b = bytes([(algo << 1) | (algo & 1) | (0x10 if algo & 1 else 0) | (0xe0 if algo == 7 else 0)])
        pdsp = bytes([0x75]) + pos_display(2, "Narnia") if algo in (2, 5) else b""
        f.append(dtap(0x35, b + pdsp))
    # Ciphering Mode Complete: MID, GPS timestamp
    f.append(dtap(0x32, bytes([0x17, 0x05]) + MID_TMSI + bytes([0x76, 0x00, 0x2a])))
    f.append(dtap(0x32, bytes([0x76, 0xff, 0xff])))
    f.append(dtap(0x32, bytes([0x17, 0x05]) + MID_TMSI))
    f.append(dtap(0x32, b"\x00"))
    # Assignment Command 1 with every optional IE
    ac = chan_desc(9, 2, 777, 3, 6)
    f.append(dtap(0x2e, ac))
    f.append(dtap(0x2e, ac + bytes([0x7d]) + timing_ofs(1, 0x0123) + bytes([0x7f]) + freq_ofs(1, 0x0aa, 0)
                  + bytes([0x63, 0x13]) + bytes([0x71]) + bytes([1, 2, 3, 4, 5]) + bytes([0x93])))
    for cm in (0x00, 0x01, 0x03, 0x0b):
        f.append(dtap(0x2e, ac + bytes([0x63, cm])))
    # Channel Release for the known causes
    for c in (0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x09, 0x0a, 0x0b, 0x41, 0x5f, 0x60, 0x61, 0x62, 0x6f, 0x33):
        f.append(dtap(0x0d, bytes([c])))
    # Paging Response: CM2 lengths 3 (full), 1 and 2 (short, fixed), 4 (extra octet), 0
    f.append(dtap(0x27, pag_resp_body(0x03, 3)))
    f.append(dtap(0x27, pag_resp_body(0x02, 1), uplink=True))
    f.append(dtap(0x27, pag_resp_body(0x01, 2), uplink=True))
    f.append(dtap(0x27, pag_resp_body(0x00, 0), uplink=True))
    f.append(dtap(0x27, pag_resp_body(0x04, 5), uplink=True))
    # Channel Mode Modify and its acknowledge
    for cm in (0x00, 0x01, 0x03):
        f.append(dtap(0x10, chan_desc(1, 2, 3, 4, 7) + bytes([cm])))
        f.append(dtap(0x17, chan_desc(1, 2, 3, 4, 7) + bytes([cm]), uplink=True))
    # Messages that share the CCCH decoders when carried on a DCCH
    f.append(dtap(0x3f, imm_ass_body(0x00)))
    f.append(dtap(0x3a, imm_ass_rej1_body(0x5d)))
    f.append(dtap(0x39, req_ref(5, 9, 0x66) + gps_discr(0x0102) + pos_display(2, "Utopia")))
    f.append(dtap(0x3d, imm_ass3_body(0xa1, 12)))
    f.append(dtap(0x24, pag_req3_body(0x5)))
    # DCCH meaning of 0x3e / 0x3b (Extended Immediate Assignment [Reject])
    f.append(dtap(0x3e, bytes(range(10))))
    f.append(dtap(0x3b, bytes(range(10))))
    # Named messages without a decoder and unknown types
    for mt in NOFUNC_RR:
        if mt != 0x3b:
            f.append(dtap(mt, bytes(range(1, 1 + (mt % 5)))))
    f.append(dtap(0x7a, b""))
    f.append(dtap(0xfe, b"\x01\x02"))
    f.append(dtap(0x35, b"\x03", sub=SUB_FACCH3))
    return f


def rr_malformed_frames(ccch_frames, dtap_frames):
    """Every prefix of one frame for each message that has a decoder: the
    short ones end at an IE boundary (missing mandatory element) or inside
    an IE (exception)."""
    f = []
    seen = set()
    for fr in ccch_frames:
        p = payload_of(fr)
        if len(p) >= 3 and p[1] == 0x06 and p[2] in (0x3f, 0x3a, 0x39, 0x3e, 0x3d, 0x24) and p[2] not in seen:
            seen.add(p[2])
            f += [cut(fr, n) for n in range(2, len(p))]
    seen = set()
    for fr in dtap_frames:
        p = payload_of(fr)
        if len(p) >= 5 and p[3] == 0x06 and p[4] in (0x3f, 0x39, 0x3d, 0x24, 0x35, 0x32, 0x2e, 0x0d, 0x27, 0x10, 0x17, 0x3a) and (p[4], len(p)) not in seen:
            seen.add((p[4], len(p)))
            f += [cut(fr, n) for n in range(4, len(p))]
    # DTAP of one octet, empty LAPSat payload with a nibble, mandatory
    # elements missing in the smallest messages
    f.append(frame(SUB_SDCCH, lapsat(b"\x06")))
    f.append(frame(SUB_SDCCH, lapsat(b"\x06\x35")))
    f.append(frame(SUB_SDCCH, lapsat(b"\x06\x0d")))
    f.append(frame(SUB_SDCCH, lapsat(b"\x06\x27\x00")))
    f.append(frame(SUB_SDCCH, lapsat(b"\x06\x27\x00\x03\x57\x23\xd0")))
    f.append(frame(SUB_SDCCH, lapsat(b"\x06\x27\x00\x03\x57\x23\xd0\x05\xf4")))
    return f
# ---- DTAP: non-RR protocol discriminators go to the GSM A-interface DTAP ----
def dtap_frames():
    f = rr_dtap_frames()
    # Other protocol discriminators are handed to gsm_a_dtap
    f.append(dtap(0x01, b"", pd=0x03))                          # CC Alerting
    f.append(dtap(0x02, b"", pd=0x03, uplink=True))             # CC Call Proceeding
    f.append(dtap(0x07, b"", pd=0x43))                          # CC Connect, skip indicator 4
    f.append(dtap(0x2a, b"", pd=0x83, uplink=True))             # CC Release Complete
    f.append(dtap(0x21, b"", pd=0x05))                          # MM CM Service Accept
    f.append(dtap(0x11, b"", pd=0x05))                          # MM Authentication Reject
    f.append(dtap(0x04, b"\x11", pd=0x05))                      # MM Location Updating Reject, cause 17
    f.append(dtap(0x5b, b"", pd=0x05, uplink=True))             # MM TMSI Reallocation Complete
    f.append(dtap(0x47, b"", pd=0x0a))                          # SM Deactivate PDP Context Accept
    f.append(dtap(0x01, b"\x00\x00", pd=0x1e))                  # extended PD (DTRS)
    f.append(dtap(0x01, b"\x00\x00", pd=0x0e))                  # extended PD (0x0e)
    f.append(dtap(0x11, b"", pd=0x08))                          # GMM P-TMSI Reallocation Complete
    f.append(dtap(0x04, b"", pd=0x09))                          # SMS CP-ACK
    # SAPI 3 (SMS/SS) is also handed to this dissector
    f.append(dtap(0x0d, b"\x00", addr=0x0c))
    f.append(dtap(0x01, b"", pd=0x03, addr=0x0c, uplink=True))
    # Information frames (sequence numbers), the message in one frame
    f.append(dtap(0x0d, b"\x05", ctl=0x000))
    f.append(dtap(0x0d, b"\x41", ctl=(3 << 5) | (1 << 4) | (2 << 1), addr=0x02, uplink=True))
    # Unknown RR message type at the end of the capture
    f.append(dtap(0xc3, b"\x01\x02\x03"))
    return f


def dtap_malformed_frames():
    f = []
    # A Paging Response split over two LAPSat I frames (SI bit on the first).
    # Kept out of the main capture: with -2 the first fragment shows
    # "Reassembled in", so the output of one and two passes differs.
    pr = bytes([0x06, 0x27]) + pag_resp_body(0x03, 3)
    f.append(frame(SUB_SDCCH, lapsat(pr[:6], addr=0x12, ctl=0x000), uplink=True))
    f.append(frame(SUB_SDCCH, lapsat(pr[6:], addr=0x02, ctl=(1 << 5) | (1 << 1)), uplink=True))
    f.append(frame(SUB_SDCCH, lapsat(b"\x06")))            # RR without a message type
    f.append(frame(SUB_SDCCH, lapsat(b"\x06\x35")))        # Ciphering Mode Command without elements
    f.append(frame(SUB_SDCCH, lapsat(b"\x06\x0d")))
    f.append(frame(SUB_SDCCH, lapsat(b"\x06\x27\x00\x03\x57\x23")))
    f.append(frame(SUB_SDCCH, lapsat(b"\x06\x3d\xa1\x9a")))
    return f


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "."
    write_pcap(out + "/gmr1_dtap-coverage.pcap", dtap_frames())
    write_pcap(out + "/gmr1_dtap-coverage-malformed.pcap", dtap_malformed_frames())
