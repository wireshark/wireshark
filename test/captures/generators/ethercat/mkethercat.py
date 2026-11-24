#!/usr/bin/env python3
# Generates test/captures/ethercat_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic captures for the EtherCAT plugin (plugins/epan/ethercat):
# ECATF, ECAT datagrams, mailbox (CoE, EoE, FoE, SoE, VoE, AoE), AMS/ADS,
# AMS/TCP, IO-RAW, TC-NV and the ESL heuristic.
#
# Usage: mkethercat.py <outdir> [-v]
# Writes ethercat-coverage.pcap (clean) and ethercat-coverage-malformed.pcap.
# Every packet is built with struct; addresses are documentation or
# locally administered ones; nothing comes from a real network.
import struct
import sys

DST = bytes.fromhex("020000000001")
SRC = bytes.fromhex("020000000002")
BCAST = bytes.fromhex("ffffffffffff")
ESLMAC = bytes.fromhex("010105100000")


class Cap:
    def __init__(self):
        self.frames = []
        self.sections = []
        self.t = 0

    def sec(self, name):
        self.sections.append((len(self.frames) + 1, name))

    def add(self, fr, dt=1000):
        self.t += dt
        self.frames.append((self.t, bytes(fr)))

    def write(self, name):
        with open(name, "wb") as f:
            f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
            for t, fr in self.frames:
                f.write(struct.pack("<IIII", 1700000000 + t // 1000000,
                                    t % 1000000, len(fr), len(fr)))
                f.write(fr)


def pat(n, seed=0):
    return bytes(((i * 7 + seed * 13 + 1) & 0xFF) for i in range(n))


def eth(payload, etype=0x88A4, dst=DST, src=SRC):
    return dst + src + struct.pack(">H", etype) + payload


def ecatf(ptype, payload, reserved=0):
    hdr = (len(payload) & 0x7FF) | (reserved << 11) | (ptype << 12)
    return struct.pack("<H", hdr) + payload


def dg(cmd, adp, ado, data, wc=1, more=False, lenbits=0, idx=0, irq=0):
    """One datagram. For cmd 10-12 adp/ado form the 32 bit logical address."""
    ln = len(data) | lenbits | (0x8000 if more else 0)
    return struct.pack("<BBHHHH", cmd, idx, adp, ado, ln, irq) + data + \
        struct.pack("<H", wc)


def lrw(cmd, laddr, data, wc=1, more=False):
    return dg(cmd, laddr & 0xFFFF, laddr >> 16, data, wc, more)


def mbox(mtype, body, addr=0, cnt=1, chan=0, prio=0, unsup=0, length=None):
    ctl = (chan & 0x3F) | (prio & 3) << 6 | (mtype & 0xF) << 8 | \
        (cnt & 7) << 12 | (unsup & 1) << 15
    return struct.pack("<HHH", len(body) if length is None else length,
                       addr, ctl) + body


def ipv4(proto, payload, src=(192, 0, 2, 1), dst=(192, 0, 2, 2)):
    tot = 20 + len(payload)
    return struct.pack(">BBHHHBBH4s4s", 0x45, 0, tot, 0, 0, 64, proto, 0,
                       bytes(src), bytes(dst)) + payload


def udp(sport, dport, payload):
    return struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload


def tcp(sport, dport, payload, seq, ack=1, flags=0x18):
    return struct.pack(">HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags,
                       65535, 0, 0) + payload


# ---------------------------------------------------------------- CoE

def coe(ctype, body, number=0, reserved=0):
    return struct.pack("<H", (number & 0x1FF) | (reserved & 7) << 9 |
                       (ctype & 0xF) << 12) + body


def sdo(cs, index=0x1018, sub=1, data=b"\x00\x00\x00\x00"):
    return struct.pack("<BHB", cs, index, sub) + data


def idq(sizeind, exp, size, complete):
    return sizeind | exp << 1 | size << 2 | complete << 4 | 1 << 5


def coe_frames():
    f = []
    # Emergency, TxPDO, RxPDO, RTRs and an unknown CoE type: no sub dissection
    for t in (1, 4, 5, 6, 7, 9):
        f.append(coe(t, pat(8, t), number=t))
    # SDO requests (Ccs)
    # 1 initiate download: segmented with size, expedited with 0..3 unused
    f.append(coe(2, sdo(idq(1, 0, 0, 0), 0x2000, 0, struct.pack("<I", 12)) + pat(12)))
    f.append(coe(2, sdo(idq(1, 0, 0, 0), 0x2000, 0, struct.pack("<I", 0))))
    f.append(coe(2, sdo(idq(1, 1, 0, 0), 0x6040, 0, b"\x06\x00\x00\x00")))
    f.append(coe(2, sdo(idq(1, 1, 1, 1), 0x1c12, 0, b"\x01\x02\x03\x00")))
    f.append(coe(2, sdo(idq(1, 1, 2, 0), 0x6041, 0, b"\x37\x02\x00\x00")))
    f.append(coe(2, sdo(idq(1, 1, 3, 0), 0x6060, 0, b"\x08\x00\x00\x00")))
    f.append(coe(2, sdo(idq(0, 1, 0, 0), 0x6061, 0, b"\x08\x00\x00\x00")))
    # 2 initiate upload (complete access or not)
    f.append(coe(2, sdo(2 << 5, 0x1018, 1)))
    f.append(coe(2, sdo(2 << 5 | 0x10, 0x1018, 0)))
    # 0 download segment (last segment, toggle, unused bytes), 3 upload segment
    f.append(coe(2, struct.pack("<B", 0x00 | 0x10 | 0x01 | 3 << 1) + pat(9)))
    f.append(coe(2, struct.pack("<B", 0x00) + pat(9, 1)))
    f.append(coe(2, struct.pack("<B", 3 << 5 | 0x10) + b"\x00" * 7 + b"\x00\x00"))
    f.append(coe(2, struct.pack("<B", 3 << 5) + b"\x00" * 9))
    # 4 abort
    f.append(coe(2, sdo(4 << 5, 0x6040, 0, struct.pack("<I", 0x06020000))))
    f.append(coe(2, sdo(4 << 5, 0x6040, 0, struct.pack("<I", 0x06090011))))
    # Ccs 5..7: no case
    f.append(coe(2, sdo(5 << 5)))
    f.append(coe(2, sdo(7 << 5)))
    # SDO responses (Scs)
    # 2 initiate upload: size indicated and not expedited (data follows),
    # expedited with size 3 / 2 / 0, no size indicator
    f.append(coe(3, sdo(2 << 5 | 1, 0x1008, 0, struct.pack("<I", 8)) + b"EL1004\x00\x00"))
    f.append(coe(3, sdo(2 << 5 | 1, 0x1008, 0, struct.pack("<I", 0))))
    f.append(coe(3, sdo(2 << 5 | 3 | 3 << 2, 0x6041, 0, b"\x37\x00\x00\x00")))
    f.append(coe(3, sdo(2 << 5 | 3 | 2 << 2, 0x6041, 0, b"\x37\x02\x00\x00")))
    f.append(coe(3, sdo(2 << 5 | 3 | 1 << 2 | 0x10, 0x6041, 0, b"\x37\x02\x03\x00")))
    f.append(coe(3, sdo(2 << 5 | 2, 0x6041, 0, b"\x37\x02\x03\x04")))
    f.append(coe(3, sdo(2 << 5, 0x6041, 0, b"\x01\x02\x03\x04")))
    # 3 initiate download response, 1 download segment response
    f.append(coe(3, sdo(3 << 5, 0x6040, 0)))
    f.append(coe(3, struct.pack("<B", 1 << 5 | 0x10) + b"\x00" * 9))
    f.append(coe(3, struct.pack("<B", 1 << 5) + b"\x00" * 9))
    # 0 upload segment response (last segment, bytes, toggle) with data
    f.append(coe(3, struct.pack("<B", 0x01 | 2 << 1 | 0x10) + pat(9)))
    f.append(coe(3, struct.pack("<B", 0x00) + pat(9, 2)))
    # Scs 4..7: no case
    f.append(coe(3, sdo(4 << 5)))
    f.append(coe(3, sdo(6 << 5)))
    # SDO Information: list, object, entry, error; fragments
    def info(op, frag, payload, more=False):
        return coe(8, struct.pack("<BBH", op | (0x80 if more else 0), 0, frag) + payload)
    f.append(info(1, 0, struct.pack("<H", 1)))
    f.append(info(1, 0, struct.pack("<H", 0)))
    f.append(info(2, 0, struct.pack("<H", 1) + struct.pack("<HHHH", 0x1000, 0x1001, 0x1018, 0x1600)))
    f.append(info(2, 3, struct.pack("<H", 1) + struct.pack("<HH", 0x1c12, 0x1c13), more=True))
    f.append(info(3, 0, struct.pack("<H", 0x1018)))
    f.append(info(4, 0, struct.pack("<HHBB", 0x1018, 0x0007, 4, 9) + b"Identity\x00"))
    f.append(info(5, 0, struct.pack("<HBB", 0x1018, 1, 0x7)))
    f.append(info(6, 0, struct.pack("<HBBHHH", 0x1018, 1, 0, 0x0007, 32, 0x0007) + b"Vendor ID\x00"))
    f.append(info(7, 0, struct.pack("<I", 0x06010000) + b"Access denied\x00"))
    f.append(info(8, 0, b"\x00\x00"))
    return f


# ---------------------------------------------------------------- SoE

def soe(op, incomplete=0, error=0, drive=0, elems=0, idn=0, data=b""):
    c = (op & 7) | incomplete << 3 | error << 4 | (drive & 7) << 5
    return struct.pack("<BBH", c, elems, idn) + data


def soe_frames():
    f = []
    # S- IDN (bit 15 clear) and P- IDN, every element flag
    allel = 0x7F
    for op in (1, 4):
        for idn in (0x0022, 0x8123, 0x1ABC):
            f.append(soe(op, elems=allel, idn=idn, drive=2))
    f.append(soe(1, elems=0x01, idn=0x0001))
    f.append(soe(1, elems=0x02 | 0x04, idn=0x0010))
    f.append(soe(1, elems=0x08 | 0x10, idn=0x0011))
    f.append(soe(1, elems=0x20 | 0x40, idn=0x0012, drive=7))
    for op in (2, 3, 5):
        f.append(soe(op, elems=0x40, idn=0x8001, data=pat(6, op)))
        f.append(soe(op, elems=0x01 | 0x02 | 0x04, idn=0x0002, data=pat(8, op)))
    # emergency (6) and the unused opcode 0 and 7
    f.append(soe(6, elems=0, idn=0, data=pat(4)))
    f.append(soe(0, elems=0, idn=0x0001))
    f.append(soe(7, elems=0, idn=0x0001))
    # fragments (InComplete) with the fragments left and data
    f.append(soe(3, incomplete=1, elems=0x40, idn=5, data=pat(10)))
    f.append(soe(2, incomplete=1, elems=0x40, idn=0, data=pat(4, 3)))
    # error responses with an error code
    f.append(soe(2, error=1, elems=0x40, idn=0x0101, data=b"\x01\x00"))
    f.append(soe(4, error=1, idn=0x7001, drive=1, data=b"\x02\x00"))
    return f


# ---------------------------------------------------------------- FoE

def foe_frames():
    f = []
    f.append(struct.pack("<BBI", 1, 0, 0) + b"firmware.efw")
    f.append(struct.pack("<BBI", 2, 0, 4096) + b"config.xml")
    f.append(struct.pack("<BBI", 1, 0, 0))              # RRQ without a name
    f.append(struct.pack("<BBI", 2, 0, 7) + b"n" * 70)  # long name, clipped in Info
    f.append(struct.pack("<BBHH", 3, 0, 1, 0) + pat(20))      # DATA
    f.append(struct.pack("<BBHH", 3, 0, 2, 0) + pat(3))       # short DATA
    f.append(struct.pack("<BBHH", 3, 0, 3, 0))                 # empty DATA
    for cmd in (1, 2, 3, 4, 5, 6, 8, 9, 10, 11, 12):    # EFW update header
        f.append(struct.pack("<BBHH", 3, 0, 10 + cmd, 0) +
                 struct.pack("<HHHH", cmd, 16, 0x1000, 0x0001) + pat(16, cmd))
    f.append(struct.pack("<BBHH", 4, 0, 5, 0))          # ACK
    f.append(struct.pack("<BBI", 5, 0, 1) + b"File not found\x00")
    f.append(struct.pack("<BBI", 5, 0, 8))               # error without text
    f.append(struct.pack("<BBHH", 6, 0, 50, 100))        # BUSY 50%
    f.append(struct.pack("<BBHH", 6, 0, 3, 0))           # BUSY, entire 0
    f.append(struct.pack("<BBI", 7, 0, 0))               # unknown opcode
    f.append(struct.pack("<BBI", 0, 0, 0))
    return f


# ---------------------------------------------------------------- VoE

def voe_frames():
    return [struct.pack("<IH", 0x00000002, 1) + pat(10),
            struct.pack("<IH", 0xDEADBEEF, 0xFFFF),
            struct.pack("<IH", 0x1234, 0x0A) + pat(1)]


# ---------------------------------------------------------------- EoE

def eoe_hdr(typ, port=0, last=0, tsapp=0, tsreq=0, frag=0, offbuf=0, frameno=0):
    info = typ | port << 4 | last << 8 | tsapp << 9 | tsreq << 10
    d = frag | offbuf << 6 | frameno << 12
    return struct.pack("<HH", info, d)


def inner_frames():
    arp = eth(struct.pack(">HHBBH6s4s6s4s", 1, 0x0800, 6, 4, 1, SRC,
                          bytes([192, 0, 2, 1]), b"\0" * 6, bytes([192, 0, 2, 2])),
              etype=0x0806, dst=BCAST)
    pl = udp(5000, 5001, b"EoE payload")
    ip = eth(ipv4(17, pl), etype=0x0800)
    return arp, ip


def eoe_frames():
    arp, ip = inner_frames()
    f = []
    f.append(eoe_hdr(0, port=1, last=1, frag=0, offbuf=2, frameno=1) + arp)
    f.append(eoe_hdr(0, port=1, last=1, tsapp=1, frag=0, offbuf=2, frameno=2) + ip + b"\x01\x02\x03\x04")
    f.append(eoe_hdr(0, tsreq=1, frag=0, offbuf=3, frameno=3) + ip)
    # a frame in three fragments: first (buffer size), middle, last
    big = eth(pat(80), etype=0x88B5)
    f.append(eoe_hdr(0, frag=0, offbuf=3, frameno=4) + big[:64])
    f.append(eoe_hdr(0, frag=1, offbuf=2, frameno=4) + big[64:])
    f.append(eoe_hdr(0, last=1, frag=2, offbuf=3, frameno=4) + pat(24))
    f.append(eoe_hdr(1) + struct.pack("<I", 123456789))        # timestamp response
    # Init request with every flag; without flags; Init response
    init = struct.pack("<I", 0x7F) + SRC + bytes([192, 0, 2, 9]) + \
        bytes([255, 255, 255, 0]) + bytes([192, 0, 2, 1]) + bytes([192, 0, 2, 53]) + \
        b"ecat-slave.example".ljust(32, b"\0")
    f.append(eoe_hdr(2) + init)
    f.append(eoe_hdr(2) + struct.pack("<I", 0) + b"\0" * 54)
    f.append(eoe_hdr(3) + b"")
    f.append(struct.pack("<HH", 3, 0x0201))                    # Init response, error
    # MAC filter request: 15 filters and 3 masks; empty; with NoBroadcasts
    for nflt, nmask, nobc in ((15, 3, 1), (0, 0, 0), (2, 1, 0), (16 - 1, 0, 0)):
        opts = nflt | nmask << 4 | nobc << 7
        mf = struct.pack("<H", opts)
        mf += b"".join(bytes([2, 0, 0, 0, 1, i]) for i in range(16))
        mf += b"".join(bytes([255, 255, 255, 255, 0, i]) for i in range(4))
        f.append(eoe_hdr(4) + mf)
    f.append(eoe_hdr(5))                                       # MAC filter response
    f.append(struct.pack("<HH", 5, 0x0401))
    f.append(eoe_hdr(6) + pat(4))                              # unknown EoE type
    f.append(eoe_hdr(15) + pat(2))
    return f


# ---------------------------------------------------------------- AMS

def amsnet(a):
    return bytes(a)


def ams_pdu(cmd, flags, invoke, body, cbdata=None, err=0,
            tgt=((10, 0, 0, 1, 1, 1), 851), snd=((10, 0, 0, 2, 1, 1), 32905)):
    hdr = amsnet(tgt[0]) + struct.pack("<H", tgt[1]) + amsnet(snd[0]) + \
        struct.pack("<H", snd[1]) + \
        struct.pack("<HHIII", cmd, flags, len(body) if cbdata is None else cbdata,
                    err, invoke)
    return hdr + body


REQ, RSP = 0x0004, 0x0005


def ams_cmds():
    """(request, response) bodies of every ADS command, plus short variants."""
    L = []
    L.append(("read", 2, struct.pack("<III", 0x4020, 0x10, 8),
              struct.pack("<II", 0, 8) + pat(8)))
    L.append(("write", 3, struct.pack("<III", 0x4020, 0x10, 4) + pat(4),
              struct.pack("<I", 0)))
    L.append(("readwrite", 9, struct.pack("<IIII", 0xF080, 0, 8, 4) + pat(4),
              struct.pack("<II", 0, 8) + pat(8)))
    L.append(("readstate", 4, struct.pack("<I", 0),
              struct.pack("<IHH", 0, 5, 0)))
    L.append(("writectrl", 5, struct.pack("<HHI", 5, 0, 2) + pat(2),
              struct.pack("<I", 0)))
    L.append(("readdinfo", 1, b"",
              struct.pack("<IBBH", 0, 3, 1, 4020) + b"Plc Device\x00".ljust(16, b"\0")))
    L.append(("adddn", 6, struct.pack("<IIIIII", 0xF020, 0, 4, 4, 100, 100) + b"\0" * 16,
              struct.pack("<II", 0, 77)))
    L.append(("deldn", 7, struct.pack("<I", 77), struct.pack("<I", 0)))
    L.append(("dn", 8, struct.pack("<II", 24, 1) + pat(24),
              None))
    return L


def ams_frames_ecatf(cap, invoke0=100):
    """Request/response pairs in ECATF type 2."""
    inv = invoke0
    for name, cmd, rq, rs in ams_cmds():
        cap.add(eth(ecatf(2, ams_pdu(cmd, REQ, inv, rq))))
        if rs is not None:
            cap.add(eth(ecatf(2, ams_pdu(cmd, RSP, inv, rs)), dst=SRC, src=DST))
        inv += 1


def ams_frames_extra(cap):
    # cbdata != 0 for ReadDeviceInfo request carrying the invoke ID
    cap.add(eth(ecatf(2, ams_pdu(1, REQ, 300, struct.pack("<I", 0), cbdata=4))))
    cap.add(eth(ecatf(2, ams_pdu(1, RSP, 300, struct.pack("<IBBH", 0, 3, 1, 4020) + b"Dev\x00" * 4)),
                dst=SRC, src=DST))
    # unknown command id and a command without a decoder, request and response
    cap.add(eth(ecatf(2, ams_pdu(0x55, REQ, 301, pat(6)))))
    cap.add(eth(ecatf(2, ams_pdu(0x55, RSP, 301, pat(6))), dst=SRC, src=DST))
    cap.add(eth(ecatf(2, ams_pdu(0, REQ, 302, b""))))
    # not an ADS command (state flags without the ADS bit): with and without data
    cap.add(eth(ecatf(2, ams_pdu(1, 0x0000, 303, pat(5)))))
    cap.add(eth(ecatf(2, ams_pdu(1, 0x0001, 304, pat(5))), dst=SRC, src=DST))
    cap.add(eth(ecatf(2, ams_pdu(1, 0x0000, 305, b""))))
    cap.add(eth(ecatf(2, ams_pdu(1, 0x0001, 306, b""))))
    # every state flag
    cap.add(eth(ecatf(2, ams_pdu(2, 0x80FE | REQ, 307, struct.pack("<III", 1, 2, 3)))))
    # error code in the response, an invoke ID of 0 and of 0xFFFFFFFF
    for e in (0, 1, 6, 0x700, 0x701, 0x702, 0x703, 0x705, 0x706, 0x707, 0x708,
              0x709, 0x70a, 0x70b, 0x70c, 0x70d, 0x70e, 0x70f, 0x710, 0x711,
              0x712, 0x713, 0x714, 0x715, 0x716, 0x717, 0x718, 0x719, 0x71a,
              0x71b, 0x71c, 0x71d, 0x71e, 0x71f, 0x720, 0x721, 0x740,
              0x741, 0x742, 0x743, 0x744, 0x745, 0x746, 0x747, 0x748, 0x749,
              0x74a, 0x74b, 0x74c, 0x74d, 0x74e, 0x74f, 0x750, 0x751, 0x752,
              0x753, 0x754, 0x755, 0x756, 0x757, 0x758, 0x759, 0x75a, 0x4000,
              0x4001, 0x4002, 0x4003, 0x4004, 0x4005, 0x4006, 0x4007, 0x4008,
              0x4009, 0x400a, 0x400b, 0x400c, 0x1234567):
        cap.add(eth(ecatf(2, ams_pdu(4, RSP, 0, struct.pack("<IHH", e, 0, 0), err=e)),
                    dst=SRC, src=DST), dt=10)
    cap.add(eth(ecatf(2, ams_pdu(2, REQ, 0xFFFFFFFF, struct.pack("<III", 1, 2, 3)))))
    cap.add(eth(ecatf(2, ams_pdu(2, RSP, 0xFFFFFFFF, struct.pack("<II", 0, 0))),
                dst=SRC, src=DST))


def ams_mbox_bodies():
    out = []
    for name, cmd, rq, rs in ams_cmds():
        out.append(ams_pdu(cmd, REQ, 900 + cmd, rq))
        if rs is not None:
            out.append(ams_pdu(cmd, RSP, 900 + cmd, rs))
    return out


def ams_tracking(cap):
    """Transaction tracking: the reproducer of the -2 fix (same invoke ID
    twice), a response without a request, a second response, requests in
    the other direction, and an unanswered request."""
    rq = struct.pack("<III", 0x4020, 0, 4)
    rs = struct.pack("<II", 0, 4) + b"\x01\x02\x03\x04"
    for i in range(2):
        cap.add(eth(ecatf(2, ams_pdu(2, REQ, 7, rq))), dt=1000000)
        cap.add(eth(ecatf(2, ams_pdu(2, RSP, 7, rs)), dst=SRC, src=DST), dt=1000000)
    cap.add(eth(ecatf(2, ams_pdu(2, RSP, 8, rs)), dst=SRC, src=DST))   # no request
    cap.add(eth(ecatf(2, ams_pdu(2, REQ, 9, rq))))
    cap.add(eth(ecatf(2, ams_pdu(2, RSP, 9, rs)), dst=SRC, src=DST))
    cap.add(eth(ecatf(2, ams_pdu(2, RSP, 9, rs)), dst=SRC, src=DST))   # answered twice
    cap.add(eth(ecatf(2, ams_pdu(2, REQ, 10, rq))))                     # unanswered
    # the same invoke ID with the opposite direction as a request
    cap.add(eth(ecatf(2, ams_pdu(2, REQ, 11, rq, tgt=((10, 0, 0, 2, 1, 1), 32905),
                                 snd=((10, 0, 0, 1, 1, 1), 851))), dst=SRC, src=DST))
    cap.add(eth(ecatf(2, ams_pdu(2, RSP, 11, rs, tgt=((10, 0, 0, 2, 1, 1), 32905),
                                 snd=((10, 0, 0, 1, 1, 1), 851)))))


def amstcp(pdu):
    return struct.pack("<HI", 0, len(pdu)) + pdu


def ams_tcp(cap):
    c, s = ("192.0.2.10", "192.0.2.20")
    ca = (192, 0, 2, 10)
    sa = (192, 0, 2, 20)
    seq_c, seq_s = 1000, 5000
    def to_srv(payload):
        nonlocal seq_c
        cap.add(eth(ipv4(6, tcp(40000, 48898, payload, seq_c, seq_s), ca, sa), 0x0800))
        seq_c += len(payload)
    def to_cli(payload):
        nonlocal seq_s
        cap.add(eth(ipv4(6, tcp(48898, 40000, payload, seq_s, seq_c), sa, ca), 0x0800,
                    dst=SRC, src=DST))
        seq_s += len(payload)
    # handshake (SYN, SYN/ACK, ACK) so that TCP hands the stream to AMS
    cap.add(eth(ipv4(6, tcp(40000, 48898, b"", seq_c - 1, 0, 0x02), ca, sa), 0x0800))
    cap.add(eth(ipv4(6, tcp(48898, 40000, b"", seq_s - 1, seq_c, 0x12), sa, ca), 0x0800,
                dst=SRC, src=DST))
    cap.add(eth(ipv4(6, tcp(40000, 48898, b"", seq_c, seq_s, 0x10), ca, sa), 0x0800))
    rq = struct.pack("<III", 0x4020, 0, 4)
    rs = struct.pack("<II", 0, 4) + b"\x01\x02\x03\x04"
    cmds = ams_cmds()
    inv = 500
    # one PDU per segment: all commands
    for name, cmd, rqb, rsb in cmds:
        to_srv(amstcp(ams_pdu(cmd, REQ, inv, rqb)))
        if rsb is not None:
            to_cli(amstcp(ams_pdu(cmd, RSP, inv, rsb)))
        inv += 1
    # two PDUs in one segment (same invoke ID, different direction bit)
    to_srv(amstcp(ams_pdu(2, REQ, 600, rq)) + amstcp(ams_pdu(2, REQ, 601, rq)))
    to_cli(amstcp(ams_pdu(2, RSP, 600, rs)) + amstcp(ams_pdu(2, RSP, 601, rs)))
    # a PDU split in three segments (reassembly), then one PDU split in its header
    pdu = amstcp(ams_pdu(3, REQ, 602, struct.pack("<III", 0x4020, 0, 40) + pat(40)))
    to_srv(pdu[:10])
    to_srv(pdu[10:50])
    to_srv(pdu[50:])
    to_cli(amstcp(ams_pdu(3, RSP, 602, struct.pack("<I", 0))))
    pdu = amstcp(ams_pdu(2, REQ, 603, rq))
    to_srv(pdu[:3])
    to_srv(pdu[3:])
    to_cli(amstcp(ams_pdu(2, RSP, 603, rs)))
    # a PDU followed by the start of the next one
    pdu2 = amstcp(ams_pdu(2, REQ, 604, rq))
    to_srv(amstcp(ams_pdu(2, REQ, 605, rq)) + pdu2[:20])
    to_srv(pdu2[20:])
    to_cli(amstcp(ams_pdu(2, RSP, 604, rs)) + amstcp(ams_pdu(2, RSP, 605, rs)))
    # a PDU too short for an AMS header (return without decoding)
    to_srv(amstcp(pat(10)))


# ---------------------------------------------------------------- ESC

def esc_data(n, seed):
    return bytes(((i * 31 + seed * 17 + (i >> 3)) & 0xFF) for i in range(n))


def datagram_frames(cap):
    cap.sec("ECAT commands")
    names = {}
    for cmd in range(0, 15):
        if cmd in (10, 11, 12):
            cap.add(eth(ecatf(1, lrw(cmd, 0x10000 + cmd, pat(12, cmd), wc=3))))
        else:
            cap.add(eth(ecatf(1, dg(cmd, 0x1000 + cmd, 0x0130, pat(2, cmd), wc=cmd & 3,
                                    idx=cmd))))
    cap.add(eth(ecatf(1, dg(255, 0, 0, pat(4)))))          # EXT
    cap.add(eth(ecatf(1, dg(15, 0, 0, pat(4)))))           # unknown
    cap.add(eth(ecatf(1, dg(200, 1, 0x2000, b""))))        # unknown, no data
    cap.add(eth(ecatf(1, dg(0, 0, 0, b"", wc=0))))         # NOP without data
    # length flag bits: roundtrip (0x4000) and the reserved bits (0x3800)
    cap.add(eth(ecatf(1, dg(7, 0, 0x0130, pat(2), lenbits=0x4000))))
    cap.add(eth(ecatf(1, dg(7, 0, 0x0130, pat(2), lenbits=0x3800))))
    # interrupt field, idx
    cap.add(eth(ecatf(1, dg(4, 1001, 0x0130, pat(2), irq=0x0101, idx=77))))

    cap.sec("ECAT multiple datagrams")
    for n in (2, 3, 4, 5, 6, 9, 10, 11, 12):
        dgs = b"".join(dg((i * 3 + 1) % 15 if (i * 3 + 1) % 15 not in (10, 11, 12) else 4,
                          1000 + i, 0x0130 + i, pat(2, i), wc=1, more=(i < n - 1), idx=i)
                       for i in range(n))
        cap.add(eth(ecatf(1, dgs)))
    # logical datagrams mixed with a register access
    cap.add(eth(ecatf(1, lrw(12, 0x00010000, pat(16), wc=3, more=True) +
                      dg(7, 0, 0x0130, pat(2), wc=5))))
    # padding after the last datagram (frames shorter than 60 octets)
    cap.add(eth(ecatf(1, dg(7, 0, 0x0130, pat(2))) + b"\0" * 30))
    cap.add(eth(ecatf(1, dg(7, 0, 0x0130, pat(2), more=True) +
                      dg(7, 0, 0x0130, pat(2))) + b"\0" * 12))

    cap.sec("ECAT ESC registers")
    # Write sweeps over all registers (writes, and reads with and without working counter)
    ranges = [(0x0000, 0x300), (0x0300, 0x300), (0x0600, 0x300), (0x0800, 0x0F0),
              (0x0900, 0x100), (0x0A00, 0x40)]
    for i, (ado, ln) in enumerate(ranges):
        for cmd in (5, 2):
            cap.add(eth(ecatf(1, dg(cmd, 1001, ado, esc_data(ln, i + cmd), wc=1))), dt=100)
    for cmd in (4, 1, 7):
        for i, (ado, ln) in enumerate(ranges):
            if ado == 0x0900:
                ado, ln = 0x0900, 0xF0 if cmd == 7 else 8
            cap.add(eth(ecatf(1, dg(cmd, 1001, ado, esc_data(ln, i), wc=1))), dt=100)
    # reads that matched no slave (working counter 0): no register decoded
    for cmd in (4, 1, 7):
        cap.add(eth(ecatf(1, dg(cmd, 1001, 0x0000, esc_data(0x40, 5), wc=0))), dt=100)
    # other commands that write registers
    for cmd in (3, 6, 8, 9, 13, 14):
        cap.add(eth(ecatf(1, dg(cmd, 1001, 0x0100, esc_data(0x20, cmd), wc=1))), dt=100)
    # single registers one at a time (fixed-width paths, partial overlap)
    for ado, ln in ((0x0000, 1), (0x0002, 2), (0x0008, 2), (0x0110, 2), (0x0120, 2),
                    (0x0130, 2), (0x0134, 2), (0x0140, 1), (0x0500, 2), (0x0502, 2),
                    (0x0510, 2), (0x0600, 16), (0x0800, 8), (0x0980, 6),
                    (0x0910, 8), (0x0918, 8), (0x09b0, 8), (0x0ff0, 4), (0x0001, 1)):
        cap.add(eth(ecatf(1, dg(5, 1001, ado, esc_data(ln, ado & 0xFF), wc=1))), dt=100)
    # a read of the system time with a short length (no DC decoding)
    cap.add(eth(ecatf(1, dg(4, 1001, 0x0900, esc_data(4, 9), wc=1))))
    cap.add(eth(ecatf(1, dg(4, 1001, 0x0900, esc_data(16, 9), wc=0))))  # DC, wc 0

    cap.sec("ECAT DC receive time differences")
    for p in ((1, 2, 3, 4), (1, 0, 3, 4), (1, 0, 0, 4), (1, 2, 0, 0), (1, 0, 3, 0),
              (1, 0, 0, 0), (1, 2, 3, 0), (0, 5, 6, 7), (0, 0, 0, 9), (0, 0, 6, 0),
              (10, 20, 30, 40)):
        for cmd in (4, 1):
            d = struct.pack("<IIII", *p)
            cap.add(eth(ecatf(1, dg(cmd, 1001, 0x0900, d + (b"\0" * 4 if p[0] == 10 else b""),
                                    wc=1))), dt=100)
    # the fix: a 4 octet read at 0x900 that is not the last datagram must not
    # build DC values from the next datagram's header
    cap.add(eth(ecatf(1, dg(4, 1001, 0x0900, b"\x11\x11\x11\x11", more=True) +
                      dg(0, 0, 0, b"\x22" * 8, wc=0))))

    cap.sec("ECAT mailbox over datagram")
    mb_cases = []
    for t, bodies in ((3, [c for c in coe_frames()]), (2, eoe_frames()),
                      (4, foe_frames()), (5, soe_frames()), (15, voe_frames()),
                      (1, ams_mbox_bodies())):
        for i, body in enumerate(bodies):
            mb_cases.append((t, body))
    return mb_cases


def mailbox_datagrams(cap, mb_cases):
    # one datagram per mailbox message; alternate FPWR (master to slave),
    # APWR, FPRW and a FPRD response with working counter 1
    cmds = (5, 2, 6, 3, 4, 1)
    for i, (t, body) in enumerate(mb_cases):
        c = cmds[i % len(cmds)]
        wc = 1
        cap.add(eth(ecatf(1, dg(c, 1001, 0x1000 + (i % 3) * 0x400,
                                mbox(t, body, addr=1001, cnt=(i % 7) + 1,
                                     chan=i % 4, prio=i % 3), wc=wc))), dt=100)
    # mailbox of other types or large length: not decoded as mailbox
    cap.add(eth(ecatf(1, dg(5, 1001, 0x1000, mbox(0, pat(8))))))
    cap.add(eth(ecatf(1, dg(5, 1001, 0x1000, mbox(6, pat(8))))))
    cap.add(eth(ecatf(1, dg(5, 1001, 0x1000, mbox(3, pat(8), length=1501)))))
    # APRD/FPRD with working counter 0 or 2: mailbox not decoded; BWR at 0x1000
    cap.add(eth(ecatf(1, dg(4, 1001, 0x1000, mbox(3, coe_frames()[1]), wc=0))))
    cap.add(eth(ecatf(1, dg(1, 1001, 0x1000, mbox(3, coe_frames()[1]), wc=2))))
    cap.add(eth(ecatf(1, dg(8, 1001, 0x1000, mbox(3, coe_frames()[1])))))
    # mailbox shorter than the datagram (data after the mailbox) and a short datagram
    cap.add(eth(ecatf(1, dg(5, 1001, 0x1000, mbox(15, pat(8)) + pat(10)))))
    cap.add(eth(ecatf(1, dg(5, 1001, 0x1000, pat(4)))))
    cap.add(eth(ecatf(1, dg(5, 1001, 0x1800, pat(64)))))
    # a mailbox followed by another datagram
    cap.add(eth(ecatf(1, dg(5, 1001, 0x1000, mbox(15, voe_frames()[0]), more=True) +
                      dg(4, 1001, 0x1400, mbox(15, voe_frames()[1])))))


def other_frames(cap):
    cap.sec("ECATF types and transports")
    # type 5: mailbox directly (also an unknown mailbox type)
    cap.add(eth(ecatf(5, mbox(3, coe_frames()[1]))))
    cap.add(eth(ecatf(5, mbox(1, ams_pdu(2, REQ, 700, struct.pack("<III", 1, 2, 3))))))
    cap.add(eth(ecatf(5, mbox(1, ams_pdu(2, RSP, 700, struct.pack("<II", 0, 0))))))
    cap.add(eth(ecatf(5, mbox(7, pat(10)))))
    cap.add(eth(ecatf(5, mbox(2, eoe_frames()[0]), reserved=1)))
    # unknown ECATF types (0, 6, 15) carried as data
    for t in (0, 6, 15):
        cap.add(eth(ecatf(t, pat(12, t))))
    cap.add(eth(ecatf(7, b"")))
    # ECATF over UDP and TCP port 0x88a4 (34980)
    d = ecatf(1, dg(4, 1001, 0x0130, pat(2)))
    cap.add(eth(ipv4(17, udp(34980, 34980, d)), 0x0800))
    cap.add(eth(ipv4(17, udp(40001, 34980, d + b"\0" * 4)), 0x0800))
    cap.add(eth(ipv4(6, tcp(40002, 34980, d, 1)), 0x0800))

    cap.sec("IO-RAW")
    cap.add(eth(ecatf(3, pat(8))))
    cap.add(eth(ecatf(3, pat(64, 3))))
    cap.add(eth(ecatf(3, pat(4))))

    cap.sec("TC-NV")
    pub = bytes([0, 1, 5, 0, 0, 1])
    def nv(count, vars_, cycle=1):
        b = pub + struct.pack("<HHH", count, cycle, 0)
        for i, (vid, h, q, data) in enumerate(vars_):
            b += struct.pack("<HHHH", vid, h, len(data), q) + data
        return b
    cap.add(eth(ecatf(4, nv(0, []))))
    cap.add(eth(ecatf(4, nv(1, [(1, 0xABCD, 0, pat(4))]))))
    cap.add(eth(ecatf(4, nv(3, [(1, 1, 0, pat(4)), (2, 2, 1, b""), (3, 3, 0xFFFF, pat(30))], cycle=77))))
    cap.add(eth(ecatf(4, nv(2, [(10, 1, 0, pat(2)), (11, 2, 0, pat(1))]) + b"\0" * 6)))


def esl_frames(cap):
    cap.sec("ESL (heuristic esl_eth)")
    inner = eth(ecatf(1, dg(4, 0x0001, 0x0130, b"\x08\x00")))
    inner2 = eth(ecatf(1, dg(5, 0x0002, 0x0120, b"\x08\x00")))
    # the reproducer of the in_heur fix first: a short Ethernet frame (14 octets)
    cap.add(eth(b"", etype=0x88B5))
    # port flags; 0x0100 extended; alignment error; CRC error; timestamp enabled
    flags = [0x0080, 0x0040, 0x0020, 0x0010, 0x0008, 0x0004, 0x0002, 0x0001,
             0x0200, 0x0400, 0x4000, 0x8000, 0x0000, 0x0180, 0x0800 | 0x0080,
             0x1000 | 0x0040, 0x2000 | 0x0020, 0x3F80]
    ts = 1000000000
    for i, fl in enumerate(flags):
        ts += 1500000000 if i % 3 else 700000
        hdr = ESLMAC + struct.pack("<HQ", fl, ts)
        cap.add(hdr + (inner if i % 2 else inner2), dt=400000)
    # ESL timestamps before the reference and with a second wrap
    for t in (900000000, 4000000000, 1000000500, 999999999, 2 ** 40, 701000, 500000000):
        cap.add(ESLMAC + struct.pack("<HQ", 0x0080, t) + inner, dt=300000)
    # ESL trailer variant: Ethernet frame followed by the 16 octet ESL header
    for i, fl in enumerate((0x0080, 0x0010, 0x1000)):
        tr = ESLMAC + struct.pack("<HQ", fl, 5000000000 + i * 1000000)
        cap.add(inner + tr, dt=200000)
    # a short frame after the ESL ones, and a frame shorter than the ESL header
    cap.add(eth(b"", etype=0x88B5))
    cap.add(inner)


def malformed(cap):
    cap.sec("malformed")
    # datagram that claims more data than the frame holds
    cap.add(eth(ecatf(1, dg(4, 1, 0x0130, pat(2))[:-4])))
    cap.add(eth(ecatf(1, dg(7, 0, 0, pat(2), more=True))))
    cap.add(eth(ecatf(1, b"\x04\x00\x01")))
    cap.add(eth(ecatf(1, b"")))
    # CoE
    def mb(t, b, **k):
        return eth(ecatf(5, mbox(t, b, **k)))
    cap.add(mb(3, b"\x00"))                                  # short CoE
    cap.add(mb(3, coe(2, pat(4))))                           # short SDO req
    cap.add(mb(3, coe(3, pat(4))))                           # short SDO res
    cap.add(mb(3, coe(8, pat(3))))                           # short SDO info
    cap.add(mb(3, struct.pack("<H", 2 << 12)))               # SDO req, no SDO
    cap.add(mb(3, coe(8, struct.pack("<BBH", 6, 0, 0) + pat(4))))   # Entry Res, truncated
    cap.add(mb(3, coe(8, struct.pack("<BBH", 5, 0, 0) + pat(1))))   # Entry Req, truncated
    cap.add(mb(3, coe(8, struct.pack("<BBH", 7, 0, 0) + pat(1))))
    cap.add(mb(3, coe(2, sdo(idq(1, 1, 0, 0)) )[:-2]))
    cap.add(mb(3, coe(2, sdo(4 << 5))[:-2]))
    cap.add(mb(3, coe(2, struct.pack("<B", 0) + b"\0" * 9)[:5]))
    # SoE, FoE, VoE, EoE too short
    cap.add(mb(5, b"\x01\x00"))
    cap.add(mb(5, soe(2, elems=0x40, idn=1)[:4]))
    cap.add(mb(5, soe(2, error=1)[:3]))
    cap.add(mb(5, soe(3, incomplete=1)[:3]))
    cap.add(mb(4, b"\x01\x00\x00"))
    cap.add(mb(4, struct.pack("<BBI", 3, 0, 0)[:5]))
    cap.add(mb(15, b"\x01\x00\x00\x00"))
    cap.add(mb(2, b"\x00\x00"))
    cap.add(mb(2, eoe_hdr(2) + pat(10)))                     # Init too short
    cap.add(mb(2, eoe_hdr(4) + pat(10)))                     # MAC filter too short
    cap.add(mb(2, eoe_hdr(0, frag=0) + b"\0" * 4))           # EoE fragment, truncated Ethernet
    cap.add(mb(2, eoe_hdr(1) + b"\0\0"))                     # timestamp response, truncated
    cap.add(mb(2, eoe_hdr(0, frag=1, tsapp=1, last=1) + pat(2)))
    cap.add(mb(3, coe(2, sdo(2 << 5, 0x1000, 0)), length=200))   # mailbox length too large
    cap.add(mb(1, b"\0" * 8, length=100))
    cap.add(eth(ecatf(5, b"\x00\x00\x00\x00")))              # mailbox header cut short
    cap.add(eth(ecatf(5, b"\x00")))
    # mailbox in a datagram with a length that is too large
    cap.add(eth(ecatf(1, dg(5, 1, 0x1000, mbox(3, coe_frames()[1], length=300)))))
    cap.add(eth(ecatf(1, dg(5, 1, 0x1000, mbox(3, pat(3))))))
    cap.add(eth(ecatf(1, dg(5, 1, 0x1000, mbox(2, eoe_hdr(2) + pat(10))))))
    # ECATF cut short
    cap.add(eth(b"\x01"))
    # AMS
    cap.add(eth(ecatf(2, pat(10))))
    cap.add(eth(ecatf(2, ams_pdu(2, REQ, 1, struct.pack("<II", 1, 2)))))   # read request short
    cap.add(eth(ecatf(2, ams_pdu(2, RSP, 1, b"\0\0"))))
    for cmd in (1, 2, 3, 4, 5, 6, 7, 8, 9):
        for fl in (REQ, RSP):
            cap.add(eth(ecatf(2, ams_pdu(cmd, fl, 50 + cmd, pat(2)))))
    # AMS/TCP: length field larger than the data and never completed
    c = (192, 0, 2, 10)
    s = (192, 0, 2, 20)
    cap.add(eth(ipv4(6, tcp(41000, 48898, struct.pack("<HI", 0, 100) + pat(20), 1), c, s), 0x0800))
    # NV with a variable that is longer than the packet, and a short NV
    pub = bytes([0, 1, 5, 0, 0, 1])
    cap.add(eth(ecatf(4, pub + struct.pack("<HHH", 1, 1, 0) + struct.pack("<HHHH", 1, 1, 100, 0) + pat(4))))
    cap.add(eth(ecatf(4, pub + struct.pack("<HHH", 5, 1, 0))))
    cap.add(eth(ecatf(4, pub[:4])))
    # IO-RAW with truncated data
    cap.add(eth(ecatf(3, pat(2))))
    cap.add(eth(ecatf(3, b"")))
    # ESL: inner Ethernet cut short (heuristic needs esl_eth)
    esl = ESLMAC + struct.pack("<HQ", 0x0080, 1)
    cap.add(esl + b"\x02\x00\x00")
    cap.add(esl + eth(ecatf(1, dg(4, 1, 0x0130, b"\x08\x00"))))
    cap.add(esl + eth(ecatf(1, dg(4, 1, 0x0130, b"\x08\x00"))))
    cap.add(esl + b"")
    cap.add(eth(ecatf(1, dg(4, 1, 0x0130, b"\x08\x00")))[:20] + ESLMAC + struct.pack("<HQ", 0x0080, 3))


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "."
    verbose = "-v" in sys.argv
    cap = Cap()
    mb_cases = datagram_frames(cap)
    mailbox_datagrams(cap, mb_cases)
    cap.sec("AMS/ADS in ECATF type 2")
    ams_frames_ecatf(cap)
    cap.sec("AMS extras")
    ams_frames_extra(cap)
    cap.sec("AMS tracking")
    ams_tracking(cap)
    cap.sec("AMS/TCP port 48898")
    ams_tcp(cap)
    other_frames(cap)
    esl_frames(cap)
    cap.sec("end")
    cap.write(out + "/ethercat-coverage.pcap")
    if verbose:
        for (a, n), (b, _) in zip(cap.sections, cap.sections[1:]):
            print("%4d-%4d %s" % (a, b - 1, n))
        print("total", len(cap.frames))
    mal = Cap()
    malformed(mal)
    mal.write(out + "/ethercat-coverage-malformed.pcap")
    if verbose:
        print("malformed frames", len(mal.frames))


if __name__ == "__main__":
    main()
