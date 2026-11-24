#!/usr/bin/env python3
# ANSI A-interface coverage capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""ANSI A-interface (IOS 4.0.1 / IOS 5.0.1) BSMAP and DTAP for
epan/dissectors/packet-ansi_a.c.

Usage: mkansi_a.py [<output directory>]

Writes ansi_a-coverage.pcap and ansi_a-ios5-coverage.pcap (Linux cooked
captures of A1 over SIGTRAN: IP / SCTP / M3UA / SCCP) and
ansi_a-coverage-malformed.pcap (Exported PDUs). Every packet is built here;
nothing comes from a real network.
"""

import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import base64
import random
import struct

from capgen import (LINKTYPE_WIRESHARK_UPPER_PDU, exp_pdu_tag, exported_pdu, ip4, ip6,  # noqa: E402
                    ipv4, ipv6, sctp, sctp_data, udp, write_pcap)

# ---------------------------------------------------------------- IP / UDP

_ipid = [0x1000]


def ipv4_packet(src, dst, proto, payload):
    _ipid[0] = (_ipid[0] + 1) & 0xffff
    return ipv4(payload, proto, src=src, dst=dst, ident=_ipid[0], flags_frag=0x4000)


def udp4(src, dst, sport, dport, payload):
    return ipv4_packet(src, dst, 17, udp(payload, sport, dport, src=src, dst=dst))


def udp6(src, dst, sport, dport, payload):
    return ipv6(udp(payload, sport, dport, src=src, dst=dst), 17, src=src, dst=dst)


# ---------------------------------------------------------------- SCTP / M3UA

def sctp_packet(src, dst, sport, dport, vtag, chunks):
    return ipv4_packet(src, dst, 132, sctp(b''.join(chunks), sport, dport, vtag))


def m3ua_data(opc, dpc, si, ni, mp, sls, data):
    pd = struct.pack('>IIBBBB', opc, dpc, si, ni, mp, sls) + data
    plen = 4 + len(pd)
    param = struct.pack('>HH', 0x0210, plen) + pd + b'\0' * ((-plen) % 4)
    rc = struct.pack('>HHI', 0x0006, 8, 1)
    body = rc + param
    return struct.pack('>BBBBI', 1, 0, 1, 1, 8 + len(body)) + body


# ---------------------------------------------------------------- SCCP (ITU)

def sccp_addr(ssn, pc=None):
    if pc is None:
        a = bytes([0x42, ssn])
    else:
        a = bytes([0x43]) + struct.pack('<H', pc) + bytes([ssn])
    return bytes([len(a)]) + a


def sccp_udt(called, calling, data):
    # pointers relative to their own position
    p1 = 3
    p2 = p1 - 1 + len(called)
    p3 = p2 - 1 + len(calling)
    return bytes([0x09, 0x00, p1, p2, p3]) + called + calling + bytes([len(data)]) + data


def ref(r):
    return struct.pack('>I', r)[1:]


def opt_params(params):
    if not params:
        return b''
    return b''.join(bytes([t, len(v)]) + v for t, v in params) + b'\0'


def sccp_cr(slr, called, calling=None, data=None):
    opts = []
    if calling is not None:
        opts.append((0x04, calling[1:]))
    if data is not None:
        opts.append((0x0f, data))
    o = opt_params(opts)
    # fixed: type, slr(3), class; ptr to called, ptr to optional
    p_called = 2
    p_opt = (1 + len(called)) if o else 0
    return bytes([0x01]) + ref(slr) + bytes([0x02, p_called, p_opt]) + called + o


def sccp_cc(dlr, slr, data=None):
    opts = [(0x0f, data)] if data is not None else []
    o = opt_params(opts)
    return bytes([0x02]) + ref(dlr) + ref(slr) + bytes([0x02, 1 if o else 0]) + o


def sccp_dt1(dlr, data):
    return bytes([0x06]) + ref(dlr) + bytes([0x00, 0x01, len(data)]) + data


def sccp_rlsd(dlr, slr, cause=0):
    return bytes([0x04]) + ref(dlr) + ref(slr) + bytes([cause, 0])


def sccp_rlc(dlr, slr):
    return bytes([0x05]) + ref(dlr) + ref(slr)


# ---------------------------------------------------------------- link layer

SLL_HOST, SLL_OUTGOING = 0, 4


def sll(pkttype, payload, proto=0x0800):
    return struct.pack('>HHH8sH', pkttype, 1, 6, b'\x02\x00\x00\x00\x00\x01\0\0', proto) + payload


def write_frames(path, frames, linktype=113):
    """frames: (time in seconds, bytes) pairs."""
    def split_ts(i):
        ts = frames[i][0]
        sec = int(ts)
        usec = int(round((ts - sec) * 1e6))
        if usec == 1000000:
            sec, usec = sec + 1, 0
        return sec, usec

    write_pcap(path, [fr for _, fr in frames], linktype=linktype, snaplen=65535, ts=split_ts)


# ================================================================ capture model

MSC_IP, BS_IP = '10.1.0.1', '10.1.0.2'
MSC_PC, BS_PC = 100, 200
SSN_BSAP = 252
M3UA_PORT = 2905


class Capture:
    """Frames as seen on the MSC: Linux cooked capture, so that the
    direction (BS->MSC received, MSC->BS sent) is known to the dissector."""

    def __init__(self):
        self.frames = []
        self.t = 1700000000 * 1000000          # microseconds
        self.tsn = {True: 1000, False: 5000}
        self.ssn = {True: 0, False: 0}
        self.nslr = 0x10

    def add(self, pkttype, pkt, proto=0x0800, dt=10000):
        self.t += dt
        self.frames.append((self.t / 1e6, sll(pkttype, pkt, proto)))
        return len(self.frames)

    # --- SS7 over SIGTRAN
    def m3ua(self, up, sccp_msg):
        """up: True for BS->MSC (reverse link)"""
        opc, dpc = (BS_PC, MSC_PC) if up else (MSC_PC, BS_PC)
        src, dst = (BS_IP, MSC_IP) if up else (MSC_IP, BS_IP)
        self.tsn[up] += 1
        self.ssn[up] = (self.ssn[up] + 1) & 0xffff
        m = m3ua_data(opc, dpc, 3, 2, 0, 1, sccp_msg)
        ch = sctp_data(m, self.tsn[up], 3, sid=1, ssn=self.ssn[up])
        pkt = sctp_packet(src, dst, M3UA_PORT, M3UA_PORT, 0x11223344 if up else 0x55667788, [ch])
        return self.add(SLL_HOST if up else SLL_OUTGOING, pkt)

    def udt(self, up, data, ssn=SSN_BSAP):
        return self.m3ua(up, sccp_udt(sccp_addr(ssn, MSC_PC if up else BS_PC),
                                      sccp_addr(ssn, BS_PC if up else MSC_PC), data))

    # --- SCCP connections
    def connect_down(self, data):
        """MSC opens an SCCP connection (Handoff Request)"""
        self.nslr += 2
        bs_ref, msc_ref = 0x400000 + self.nslr, 0x800000 + self.nslr
        n = self.m3ua(False, sccp_cr(msc_ref, sccp_addr(SSN_BSAP, BS_PC),
                                     sccp_addr(SSN_BSAP, MSC_PC), data))
        return Conn(self, bs_ref, msc_ref), n

    def connect(self, cl3):
        """BS opens an SCCP connection with Complete Layer 3 Information"""
        self.nslr += 2
        bs_ref, msc_ref = self.nslr, 0x800000 + self.nslr
        n = self.m3ua(True, sccp_cr(bs_ref, sccp_addr(SSN_BSAP, MSC_PC),
                                    sccp_addr(SSN_BSAP, BS_PC), cl3))
        self.m3ua(False, sccp_cc(bs_ref, msc_ref))
        return Conn(self, bs_ref, msc_ref), n

    # --- other traffic
    def udp(self, up, src, dst, sport, dport, payload, v6=False):
        if v6:
            return self.add(SLL_HOST if up else SLL_OUTGOING, udp6(src, dst, sport, dport, payload), 0x86dd)
        return self.add(SLL_HOST if up else SLL_OUTGOING, udp4(src, dst, sport, dport, payload))


class Conn:
    def __init__(self, cap, bs_ref, msc_ref):
        self.cap, self.bs_ref, self.msc_ref = cap, bs_ref, msc_ref

    def send(self, up, data):
        return self.cap.m3ua(up, sccp_dt1(self.msc_ref if up else self.bs_ref, data))

    def release(self):
        self.cap.m3ua(False, sccp_rlsd(self.bs_ref, self.msc_ref, 0))
        self.cap.m3ua(True, sccp_rlc(self.msc_ref, self.bs_ref))


# ================================================================ BSAP / IOS

def bsmap(msg):
    assert len(msg) < 256, len(msg)
    return bytes([0x00, len(msg)]) + msg


def dtap(msg, dlci=0):
    assert len(msg) < 256, len(msg)
    return bytes([0x01, dlci, len(msg)]) + msg


def TLV(iei, v):
    assert len(v) < 256
    return bytes([iei, len(v)]) + v


def TV(iei, v):
    return bytes([iei]) + v


def T(iei):
    return bytes([iei])


def LV(v):
    return bytes([len(v)]) + v


def dmsg(mtype, body=b'', pd=3):
    """DTAP message: protocol discriminator, reserved octet, type"""
    return bytes([pd, 0, mtype]) + body


# ---------------------------------------------------------------- element IDs
ACC_NET_ID, ADDS, AMPS_HHO, ANCH_PDSN, ANCH_PP = 0x20, 0x3D, 0x25, 0x30, 0x7C
AUTH_CHLG, AUTH_CNF, AUTH_DATA, AUTH_EVENT, AUTH_COUNT, AUTH_RESP = 0x41, 0x28, 0x59, 0x4A, 0x40, 0x42
BAND_CLASS, CLD_ASCII, CLD_BCD, CLG_ASCII, CAUSE, CAUSE_L3 = 0x37, 0x5B, 0x5E, 0x4B, 0x04, 0x08
CDMA_SOWD, CELL_ID, CELL_ID_LIST, CHAN_NUM, CHAN_TYPE = 0x0C, 0x05, 0x1A, 0x23, 0x0B
CCT_GROUP, CIC, CIC_EXT, CM2, DLRE, DLRE_LIST, ENC_INFO = 0x19, 0x01, 0x24, 0x12, 0x29, 0x2B, 0x0A
EXT_HO_DIR, GEO_LOC, SSCI, HO_POW_LEV, HHO_PARAMS, IE_REQD = 0x10, 0x2C, 0x5A, 0x26, 0x16, 0x2E
IS2000_CHAN_ID, IS2000_CHAN_ID_3X, IS2000_MOB_CAP, IS2000_NN_SCR, IS2000_SCR = 0x09, 0x27, 0x11, 0x0F, 0x0E
IS2000_CAUSE, IS2000_RED_REC, IS95_CHAN_ID, IS95_MS_MEAS = 0x62, 0x67, 0x22, 0x64
L3_INFO, LAI, MWI, MID, FWD_MS_INFO, ORIG_CI = 0x17, 0x13, 0x38, 0x0D, 0x15, 0xA0
PACA_ORDER, PACA_REOI, PACA_TS, PSP, PDSN_IP, PDI = 0x5F, 0x60, 0x4E, 0x70, 0x14, 0xA2
PRIO, P_REV, PTYPE, PSMM, QOS, RE_RES, REG_TYPE = 0x06, 0x3B, 0x18, 0x2D, 0x07, 0x1D, 0x1F
REJ_CAUSE, RESP_REQ, RETURN_CAUSE, RF_CHAN_ID, SO, SOCI, SO_LIST = 0x44, 0x1B, 0x68, 0x21, 0x03, 0x1E, 0x2A
S_RED_INFO, SR_ID, SID, SIGNAL, SCI, SW_VER = 0x69, 0x71, 0x32, 0x34, 0x35, 0x31
SRNC_TRNC, S_PDSN, TAG, TRNC_SRNC, XMODE, UZ_ID, VP_REQ = 0x39, 0x14, 0x33, 0x3A, 0x36, 0x02, 0xA1
REV_MS_INFO, A2P_SESS, A2P_FMT, MS_DES_FREQ, MOB_SUB_INFO, PLCM_ID = 0x15, 0x45, 0x46, 0x73, 0x7D, 0x72

# ---------------------------------------------------------------- element values


def bcd(digits):
    """TBCD, low nibble first, odd count padded with F"""
    d = [int(x, 16) if x not in '*#' else {'*': 0xb, '#': 0xc}[x] for x in digits]
    if len(d) % 2:
        d.append(0xf)
    return bytes(d[i] | (d[i + 1] << 4) for i in range(0, len(d), 2))


def mid_imsi(digits='310004123456789'):
    # first digit in the high nibble of octet 3 with odd/even and type 6
    odd = len(digits) % 2
    rest = digits[1:]
    return bytes([(int(digits[0]) << 4) | (odd << 3) | 6]) + bcd(rest)


def mid_esn(esn=0x8a123456):
    return bytes([0x05]) + struct.pack('>I', esn)


def mid_meid(digits='A0000012345678'):
    odd = len(digits) % 2
    return bytes([(int(digits[0], 16) << 4) | (odd << 3) | 1]) + bcd(digits[1:])


def mid_bcast(prio=1, msgid=3, zone=0x10, svc=0x0101, lang=0x01):
    return bytes([0x02, (prio << 6) | msgid, zone]) + struct.pack('>H', svc) + bytes([lang])


def mid_unknown():
    return bytes([0x03, 0x11, 0x22])


def cm2(p_rev=6, meid=True, bands=((1, 6), (0, 3)), short=None):
    v = bytes([(p_rev << 5) | 0x08 | 0x02, 0x00, 0x4f, 0x00, 0x01, 0x01,
               0xe2 | (0x10 if meid else 0), len(bands), 3])
    for bc, pr in bands:
        v += bytes([bc, 0xf8, pr])
    if short is not None:
        v = v[:short]
    return v


def cell_ci(ci=0x0123):
    return bytes([0x02]) + struct.pack('>H', ci)


def cell_list(disc, cells):
    v = bytes([disc])
    for c in cells:
        v += c
    return v


def mscid_ci(market=0x0101, switch=2, ci=0x0abc):
    return struct.pack('>HBH', market, switch, ci)


def chan_ident_is95(nchans=2):
    v = bytes([0x80 | (nchans << 4) | 0x03])
    for i in range(nchans):
        v += bytes([0x10 + i, 0x05, 0x6a | ((i & 1) << 7), 0x83 if i else 0x01])
    return v


def is2000_chan_id(ios5, types=(1, 2, 3, 9)):
    v = bytes([0x80 | (len(types) << 4) | 0x02])
    for t in types:
        v += bytes([t, 0x81, 0x22, 0x01, 0x47, 0x8b])
    if ios5:
        v += bytes([0x01, 0x02, 0x03, 0x04, 0x05])
    return v


def mob_cap(fch=b'\x12\x34\x56', dcch=b'\xab', fpdch=b'\x01\x02', rpdch=b'\x03', vp=None):
    v = bytes([0xff, len(fch), 0x13]) + fch
    if dcch is None:
        return v
    v += bytes([len(dcch), 0x03]) + dcch
    if fpdch is None:
        return v
    v += bytes([len(fpdch), 0x00]) + fpdch
    if rpdch is None:
        return v
    v += bytes([len(rpdch), 0x05]) + rpdch
    if vp is None:
        return v
    return v + bytes([vp])


def scr(records=1, blob=0, tail=0x00, extra=b''):
    v = struct.pack('>HHBBB', 0x0001, 0x0001, 0x01, 0x01, records)
    for i in range(records):
        if blob:
            body = bytes([i + 1]) + struct.pack('>H', 0x0021) + bytes([0x11, 0x02 | (blob >> 3), ((blob & 7) << 5)]) + bytes(range(blob - 1)) + b'\x80'
        else:
            body = bytes([i + 1]) + struct.pack('>H', 0x0003) + bytes([0x11, 0x08])
        v += bytes([len(body) + 1]) + body
    v += bytes([tail]) + extra
    return bytes([0x03]) + v


class Bits:
    def __init__(self):
        self.b = []

    def put(self, val, n):
        for i in range(n - 1, -1, -1):
            self.b.append((val >> i) & 1)
        return self

    def bytes(self):
        b = self.b + [0] * ((-len(self.b)) % 8)
        return bytes(int(''.join(map(str, b[i:i + 8])), 2) for i in range(0, len(b), 8))


def rec_cld_pn(digits, ntype=4, plan=1):
    b = Bits().put(ntype, 3).put(plan, 4)
    for ch in digits.encode():
        b.put(ch, 8)
    return b.put(0, 1).bytes()


def rec_clg_pn(digits, ntype=2, plan=1, pi=0, si=3):
    b = Bits().put(ntype, 3).put(plan, 4).put(pi, 2).put(si, 2)
    for ch in digits.encode():
        b.put(ch, 8)
    return b.put(0, 5).bytes()


def rec(t, v):
    return bytes([t, len(v)]) + v


def ms_info_fwd():
    return (rec(0x01, b'\x80HI!') +                 # display (no decoder)
            rec(0x02, rec_cld_pn('5551000')) +
            rec(0x02, rec_cld_pn('')) +              # header only
            rec(0x03, rec_clg_pn('5552000')) +
            rec(0x03, bytes([0x12, 0x34])) +         # calling party, no digits
            rec(0x05, bytes([0x40, 0x81])) +         # signal: ISDN alerting
            rec(0x05, bytes([0x00, 0x00])) +         # tone
            rec(0x05, bytes([0x80, 0x00])) +         # IS-54B alerting
            rec(0x05, bytes([0xc0, 0x00])) +         # reserved signal type
            rec(0x06, bytes([0x03])) +               # message waiting
            rec(0x15, bytes([0x80])) +               # call waiting indicator
            rec(0x77, bytes([0x00])) +               # reserved type
            rec(0x0d, b''))                           # empty record


def ms_info_rev():
    return (rec(0x03, b'123') +                       # keypad facility
            rec(0x04, rec_cld_pn('5553000')) +
            rec(0x04, rec_cld_pn('')) +
            rec(0x05, rec_clg_pn('5554000')) +
            rec(0x05, bytes([0x10, 0x00])) +         # calling party, no digits
            rec(0x11, bytes([0x00, 0x00, 0x03, 0x01, 0x80, 0x21])) +   # SO information
            rec(0x0d, bytes([0x8a, 0x12, 0x34, 0x56])) +              # ESN (no decoder)
            rec(0x60, bytes([0x00])) +               # reserved type
            rec(0x0c, b''))


def enc_info():
    return (bytes([0x80 | (1 << 2) | 0x02 | 0x01, 0x08]) + bytes(range(8)) +
            bytes([0x80 | (4 << 2), 0x06]) + bytes(range(6)) +
            bytes([(5 << 2) | 0x01]) +
            bytes([0x80 | (6 << 2), 0x00]))


def adds(app, data):
    return bytes([app]) + data


IS637_P2P = (b'\x00' + bytes([0x00, 0x02, 0x10, 0x02]) +
             bytes([0x08, 0x05, 0x00, 0x03, 0x10, 0x00, 0x10]))
IS683_FWD = bytes([0x00, 0x01, 0x00])                    # Configuration Request, block 0
IS801_FWD = bytes([0x00, 0x00, 0x10, 0x01, 0x00])        # Request Location Response


def downlink_re(disc, cells):
    v = bytes([len(cells), disc])
    for c in cells:
        v += c + bytes([0x15, 0x01, 0x23])
    return v


def a2p_session(addr=None, v6=False, port=6000):
    if addr is None:
        return bytes([0x00])
    if v6:
        return bytes([0x01 | 0x02 | 0x08]) + ip6(addr) + struct.pack('>H', port)
    return bytes([0x01 | 0x08]) + ip4(addr) + struct.pack('>H', port)


def a2p_fmt_entry(tag_type, fmt_id, pt, addr=None, v6=False, port=0, ext=None):
    b = bytes([(0x80 if ext is not None else 0) | (tag_type << 4) | fmt_id,
               (pt << 1) | (1 if addr else 0)])
    if addr:
        b += (ip6(addr) if v6 else ip4(addr)) + struct.pack('>H', port)
    if ext is not None:
        b += bytes([(len(ext) << 4) | 0x01]) + ext
    return bytes([len(b)]) + b


def a2p_format(entries, v6=False):
    return bytes([(len(entries) << 2) | (1 if v6 else 0)]) + b''.join(entries)


# first message of each type with elements, for the trailing data copies
FIRST = {}


def B(mtype, *elems):
    body = b''.join(elems)
    if body:
        FIRST.setdefault(('B', mtype), bytes([mtype]) + body)
    return bsmap(bytes([mtype]) + body)


def D(mtype, *elems, pd=3):
    body = b''.join(elems)
    if body:
        FIRST.setdefault(('D', mtype), dmsg(mtype, body, pd))
    return dtap(dmsg(mtype, body, pd))


NO_ELEMENTS = {('B', 0x15), ('B', 0x47), ('B', 0x48), ('B', 0x49), ('B', 0x4A), ('B', 0x7f),
               ('D', 0x2B), ('D', 0x2C), ('D', 0x31), ('D', 0x7f)}


def build_trailing(c):
    """every message once more with octets after the last element"""
    for key in sorted(FIRST):
        if key in NO_ELEMENTS:
            continue
        msg = FIRST[key] + b'\xfe\xfe'
        if len(msg) > 255:
            continue
        c.udt(False, bsmap(msg) if key[0] == 'B' else dtap(msg))


IMSI = mid_imsi()
IMSI_EVEN = mid_imsi('31000412345678')
ESN = mid_esn()
MEID = mid_meid()
CELL = cell_ci(0x0123)
CELLS_CI = cell_list(0x02, [struct.pack('>H', 0x0123), struct.pack('>H', 0x0456)])
CELLS_LAC = cell_list(0x05, [struct.pack('>H', 0x1001)])
CELLS_MSC = cell_list(0x07, [mscid_ci(), mscid_ci(0x0202, 3, 0x0def)])
CAUSE2 = b'\x81\x23'                # two octet cause
TAGV = struct.pack('>I', 0x01020304)
SO_EVRC = struct.pack('>H', 0x0003)
SO_PROP = struct.pack('>H', 0x8021)
SO_LIST_V = bytes([0x03, 0x00, 0x00, 0x03, 0x09, 0x00, 0x21, 0x12, 0x80, 0x44])
AUTH_CHLG_V = bytes([0x01]) + struct.pack('>I', 0xdeadbeef)
AUTH_RESP_V = bytes([0x01, 0x01, 0x23, 0x45])
CLG_ASCII_V = bytes([0x21, 0x83]) + b'5551234'
CLG_ASCII_EXT = bytes([0xa1]) + b'5559876'
CLD_ASCII_V = bytes([0x81]) + b'18005550100'
CLD_BCD_V = bytes([0x81]) + bcd('5551000')
SOWD = bytes([0x02]) + struct.pack('>H', 0x0123) + struct.pack('>H', 0x0100) + b'\x01' + struct.pack('>H', 0x0042)
SOWD_SHORT = bytes([0x05]) + struct.pack('>H', 0x1001) + struct.pack('>H', 0x0080) + b'\x00'


def build(ios5):
    FIRST.clear()
    c = Capture()
    up, down = True, False

    # ---- connectionless management
    c.udt(down, B(0x30, TLV(CAUSE, b'\x1a'), TLV(SW_VER, b'\x04\x00\x01MFG-SW-1.0')))      # Reset
    c.udt(up, B(0x31, TLV(SW_VER, b'\x05\x00\x01')))                                       # Reset Ack
    c.udt(down, B(0x30, TLV(CAUSE, CAUSE2)))                                               # Reset, 2 octet cause
    c.udt(up, B(0x40, TV(CIC, b'\x00\x21'), TLV(CAUSE, b'\x20'),
                TLV(CCT_GROUP, b'\x03\x05\x00\x21\xf8\x1f')))                            # Block
    c.udt(down, B(0x41, TV(CIC, b'\x00\x21')))                                             # Block Ack
    c.udt(up, B(0x42, TV(CIC, b'\x00\x21'), TLV(CCT_GROUP, b'\x01')))                      # Unblock (short group)
    c.udt(up, B(0x42, TV(CIC, b'\x00\x22'), TLV(CCT_GROUP, b'\x00\x02\x00\x22')))          # Unblock (no bitmap)
    c.udt(down, B(0x43, TV(CIC, b'\x00\x21')))                                             # Unblock Ack
    c.udt(down, B(0x34, TV(CIC, b'\x00\x30'), TLV(CAUSE, b'\x1a'),
                  TLV(CCT_GROUP, b'\x02\x10\x00\x30\xff\xff')))                          # Reset Circuit
    c.udt(up, B(0x35, TV(CIC, b'\x00\x30')))                                               # Reset Circuit Ack
    c.udt(down, B(0x38, TLV(XMODE, b'\x01')))                                              # Transcoder Control Request
    c.udt(up, B(0x39, TLV(CAUSE, b'\x00')))                                                # Transcoder Control Ack
    c.udt(down, B(0x38, TLV(XMODE, b'\x00')))
    # Paging
    pg_tail = b''
    if ios5:
        pg_tail = (TLV(P_REV, b'\x07') + TLV(MS_DES_FREQ, b'\x08\x4b') +
                   TLV(A2P_FMT, a2p_format([a2p_fmt_entry(3, 3, 97)])) +
                   TLV(MID, ESN) + TLV(MOB_SUB_INFO, b'\x01\x02'))
    c.udt(down, B(0x52, TLV(MID, IMSI), TV(TAG, TAGV), TLV(CELL_ID_LIST, CELLS_CI), TV(SCI, b'\x0a'),
                  TV(SO, SO_EVRC), TLV(IS2000_MOB_CAP, mob_cap()), pg_tail))           # Paging Request
    c.udt(down, B(0x52, TLV(MID, IMSI_EVEN), TLV(CELL_ID_LIST, CELLS_LAC), TV(SCI, b'\x02')))
    c.udt(down, B(0x52, TLV(MID, mid_bcast()), TLV(CELL_ID_LIST, CELLS_MSC)))
    c.udt(down, B(0x52, TLV(MID, MEID), TV(SO, SO_PROP)))
    c.udt(down, B(0x52, TLV(MID, mid_unknown())))
    c.udt(down, B(0x52, TLV(MID, b'\x06')))                                               # IMSI, no digits
    c.udt(down, B(0x52, TLV(MID, b'\x01')))                                               # MEID, no digits
    # Feature Notification
    fn_tail = b''
    if ios5:
        fn_tail = TLV(P_REV, b'\x07') + TLV(MS_DES_FREQ, b'\x08\x4b') + TLV(MOB_SUB_INFO, b'\x01')
    c.udt(down, B(0x60, TLV(MID, IMSI), TV(TAG, TAGV), TLV(CELL_ID_LIST, CELLS_CI), TV(SCI, b'\x01'),
                  TV(SIGNAL, b'\x40\x01'), TV(MWI, b'\x05'), TLV(CLG_ASCII, CLG_ASCII_V),
                  TLV(FWD_MS_INFO, ms_info_fwd()), TLV(IS2000_MOB_CAP, mob_cap(fpdch=None)),
                  fn_tail))
    c.udt(up, B(0x61, TLV(MID, IMSI), TV(TAG, TAGV)))                                       # Feature Noti Ack
    # Registration Request
    c.udt(up, B(0x05, TLV(MID, IMSI), TLV(CELL_ID_LIST, CELLS_CI), TV(SCI, b'\x01'), TLV(P_REV, b'\x06'),
                TLV(IS2000_MOB_CAP, mob_cap(fpdch=None)),
                TLV(MS_DES_FREQ, b'\x08\x4b') + TLV(MOB_SUB_INFO, b'\x01') if ios5 else b''))
    # ADDS Page / Ack / Transfer / Ack
    c.udt(down, B(0x65, TLV(MID, IMSI), TLV(ADDS, adds(0x03, IS637_P2P)), TV(TAG, TAGV),
                  TLV(CELL_ID_LIST, CELLS_CI), TV(SCI, b'\x01'), TLV(IS2000_MOB_CAP, mob_cap(rpdch=None)),
                  TLV(P_REV, b'\x06'),
                  TLV(MS_DES_FREQ, b'\x08\x4b') + TLV(MOB_SUB_INFO, b'\x01') if ios5 else b''))
    c.udt(up, B(0x66, TLV(MID, IMSI), TV(TAG, TAGV), TLV(MID, ESN), TLV(CAUSE, b'\x30'), TLV(CELL_ID, CELL),
                TLV(MID, MEID)))
    c.udt(up, B(0x67, TLV(MID, IMSI), TLV(ADDS, adds(0x05, IS801_FWD)), TLV(MID, ESN),
                TLV(AUTH_RESP, AUTH_RESP_V), TV(AUTH_CNF, b'\x5a'), TV(AUTH_COUNT, b'\x07'),
                TLV(AUTH_CHLG, AUTH_CHLG_V), TLV(AUTH_EVENT, b'\x01'), TLV(CELL_ID, CELL),
                TLV(CDMA_SOWD, SOWD), TLV(AUTH_DATA, b'\x01\x02\x03'), TV(TAG, TAGV),
                TLV(CM2, cm2()), TV(SCI, b'\x01'), TV(SO, SO_EVRC), TLV(UZ_ID, b'\x00\x05'),
                TLV(IS2000_MOB_CAP, mob_cap(vp=0x03)), TLV(MID, MEID),
                TLV(MOB_SUB_INFO, b'\x01') if ios5 else b''))
    for app, data in ((0x04, IS683_FWD), (0x06, b'\x45\x00'), (0x3e, b'\x00\x01\xaa'), (0x3f, b'\x00\x02\xbb\xcc'),
                      (0x01, b'\x11\x22'), (0x07, b'\x33')):
        c.udt(up, B(0x67, TLV(MID, IMSI), TLV(ADDS, adds(app, data))))
    c.udt(down, B(0x68, TLV(MID, IMSI), TV(TAG, TAGV), TLV(CAUSE, b'\x00')))              # ADDS Transfer Ack
    # Authentication Request / Response (BSMAP)
    c.udt(down, B(0x45, TLV(AUTH_CHLG, AUTH_CHLG_V), TLV(MID, IMSI), TV(TAG, TAGV), TLV(CELL_ID_LIST, CELLS_CI),
                  TV(SCI, b'\x01'), TLV(IS2000_MOB_CAP, mob_cap()), TLV(P_REV, b'\x06'),
                  TLV(MS_DES_FREQ, b'\x08\x4b') + TLV(MOB_SUB_INFO, b'\x01') if ios5 else b''))
    c.udt(up, B(0x46, TLV(AUTH_RESP, AUTH_RESP_V), TLV(MID, IMSI), TV(TAG, TAGV), TLV(MID, ESN), TLV(MID, MEID)))
    c.udt(up, B(0x46, TLV(AUTH_RESP, AUTH_RESP_V), TLV(MID, IMSI)))                         # missing Tag
    # User Zone Reject / Update (BSMAP)
    c.udt(down, B(0x0B, TLV(UZ_ID, b'\x00\x07'), TLV(MID, IMSI), TLV(CELL_ID_LIST, CELLS_CI), TV(SCI, b'\x01'),
                  TLV(IS2000_MOB_CAP, mob_cap()), TLV(P_REV, b'\x06'),
                  TLV(MS_DES_FREQ, b'\x08\x4b') + TLV(MOB_SUB_INFO, b'\x01') if ios5 else b''))
    # Status Request / Response
    c.udt(down, B(0x6A, TLV(IE_REQD, bytes([0x0d, 0x0c, 0x27, 0x99])), TLV(MID, IMSI), TLV(MID, ESN),
                  TV(SCI, b'\x01'), TLV(CELL_ID_LIST, CELLS_CI), TLV(IS2000_MOB_CAP, mob_cap()),
                  TLV(P_REV, b'\x06'), TLV(MS_DES_FREQ, b'\x08\x4b') if ios5 else b'',
                  TLV(MID, MEID), TV(TAG, TAGV), TLV(MOB_SUB_INFO, b'\x01') if ios5 else b''))
    c.udt(up, B(0x6B, TLV(REV_MS_INFO, ms_info_rev()), TLV(MID, IMSI), TLV(MID, ESN), TLV(MID, MEID), TV(TAG, TAGV)))
    if ios5:
        c.udt(down, B(0x71, TLV(CAUSE, b'\x00')))                                           # MS Registered Noti
        c.udt(down, B(0x07, TLV(MID, IMSI)))                                                # BS Auth Request
        c.udt(up, B(0x08, TLV(MID, IMSI)))                                                  # BS Auth Request Ack
    build_calls(c, ios5)
    build_handoff(c, ios5)
    build_misc(c, ios5)
    build_trailing(c)
    build_femto(c, ios5)
    build_repro(c, ios5)
    build_ansi_map(c, ios5)
    build_fill(c, ios5)
    return c


def cl3(cell, l3):
    return B(0x57, TLV(CELL_ID, cell), TLV(L3_INFO, l3))


def build_calls(c, ios5):
    up, down = True, False
    I5 = (lambda *e: b''.join(e)) if ios5 else (lambda *e: b'')
    RTP_V4 = '10.2.0.10'

    # ---- 1. mobile origination, voice call with every optional element
    cmsr = dmsg(0x24, bytes([0x01]) + LV(cm2()) + LV(IMSI) + TLV(CLD_BCD, CLD_BCD_V) + TLV(MID, ESN) +
                TV(SCI, b'\x01') + TLV(AUTH_RESP, AUTH_RESP_V) + TV(AUTH_CNF, b'\x5a') + TV(AUTH_COUNT, b'\x07') +
                TLV(AUTH_CHLG, AUTH_CHLG_V) + TV(SO, SO_EVRC) + T(VP_REQ) + TV(RE_RES, b'\x7f') +
                TLV(CLD_ASCII, CLD_ASCII_V) + TV(CIC, b'\x00\x40') + TLV(AUTH_EVENT, b'\x02') +
                TLV(AUTH_DATA, b'\x11\x22\x33') + TLV(PACA_REOI, b'\x01') + TLV(UZ_ID, b'\x00\x09') +
                TLV(IS2000_MOB_CAP, mob_cap(fch=b'\x01', vp=0x00)) + TLV(CDMA_SOWD, SOWD_SHORT) +
                I5(TLV(SSCI, b'\x03'), TLV(SOCI, b'\x01'), T(ORIG_CI), TV(RETURN_CAUSE, b'\x01'), TLV(MID, MEID),
                   TLV(A2P_SESS, a2p_session()), TLV(A2P_FMT, a2p_format([a2p_fmt_entry(3, 0, 0)])),
                   TLV(MOB_SUB_INFO, b'\x01\x02')))
    conn, _ = c.connect(cl3(CELL, cmsr))
    conn.send(down, B(0x01, TLV(CHAN_TYPE, b'\x01\x08\x04'), TV(CIC, b'\x00\x40'), TLV(ENC_INFO, enc_info()),
                      TV(SO, SO_EVRC), TV(SIGNAL, b'\x63\x02'), TLV(CLG_ASCII, CLG_ASCII_EXT),
                      TLV(FWD_MS_INFO, rec(0x01, b'\x80CALL')), TLV(PRIO, b'\x3d'), TLV(PACA_TS, b'\x00\x00\x10\x00'),
                      TLV(QOS, b'\x05'),
                      I5(TLV(SOCI, b'\x01'), TLV(SR_ID, b'\x01'), TLV(A2P_SESS, a2p_session(RTP_V4, port=7000)),
                         TLV(A2P_FMT, a2p_format([a2p_fmt_entry(2, 3, 97), a2p_fmt_entry(1, 7, 101)])),
                         TLV(MID, IMSI), TLV(MOB_SUB_INFO, b'\x01'))))
    conn.send(up, B(0x02, TV(CHAN_NUM, b'\x02\x83'), TLV(ENC_INFO, enc_info()), TV(SO, SO_EVRC),
                    I5(TLV(SOCI, b'\x01'), TLV(A2P_SESS, a2p_session('10.2.0.20', port=7002)),
                       TLV(A2P_FMT, a2p_format([a2p_fmt_entry(4, 3, 0)])), TLV(MID, IMSI))))
    conn.send(down, D(0x03, TV(SIGNAL, b'\x01\x00'), TLV(FWD_MS_INFO, ms_info_fwd()), TLV(SOCI, b'\x00')))  # Progress
    conn.send(down, D(0x26, TLV(FWD_MS_INFO, rec(0x05, b'\x40\x81')), TLV(SOCI, b'\x00')))                 # Alert With Info
    conn.send(up, D(0x07, TLV(SOCI, b'\x00')))                                                             # Connect
    conn.send(down, D(0x10, TLV(CLD_BCD, CLD_BCD_V), TV(SIGNAL, b'\x40\x00'), TV(MWI, b'\x01'),
                      TLV(CLG_ASCII, CLG_ASCII_V), TV(TAG, TAGV), TLV(FWD_MS_INFO, ms_info_fwd()),
                      TLV(SSCI, b'\x01'), TLV(SOCI, b'\x00')))                                              # Flash, forward
    conn.send(up, D(0x50, TV(TAG, TAGV), TLV(SOCI, b'\x00')))                                              # Flash Ack
    conn.send(up, D(0x10, TLV(CLD_BCD, CLD_BCD_V), TV(TAG, TAGV), TLV(REV_MS_INFO, ms_info_rev()),
                    TLV(SOCI, b'\x00')))                                                                   # Flash, reverse
    conn.send(up, D(0x33, LV(b'\x1a'), LV(bytes([0x07]) + bcd('5551234')), pd=3))                         # Send Burst DTMF
    conn.send(up, D(0x33, LV(b'\x00'), LV(bytes([0x06]) + bytes([0x21, 0x43, 0xa5])), pd=3))
    conn.send(down, D(0x34, TLV(CAUSE, b'\x00')))                                                           # Burst DTMF Ack
    conn.send(up, D(0x35, LV(bytes([0x01, 0x05]))))                                                        # Start DTMF
    conn.send(up, D(0x35, LV(bytes([0x01]))))                                                              # Start DTMF, no digits
    conn.send(down, D(0x36, TLV(CAUSE, b'\x00')))                                                           # Start DTMF Ack
    conn.send(up, D(0x31))                                                                                 # Stop DTMF
    conn.send(down, D(0x32, TLV(CAUSE, b'\x00')))                                                           # Stop DTMF Ack
    conn.send(up, D(0x2C))                                                                                 # Parameter Update Request
    conn.send(down, D(0x2B))                                                                               # Parameter Update Confirm
    conn.send(down, B(0x53, TLV(ENC_INFO, enc_info())))                                                    # Privacy Mode Command
    conn.send(up, B(0x55, TLV(ENC_INFO, enc_info()), T(VP_REQ)))                                           # Privacy Mode Complete
    conn.send(up, D(0x62, TLV(SOCI, b'\x02'), TLV(CLD_BCD, CLD_BCD_V), TV(SO, struct.pack('>H', 0x0021)), T(VP_REQ),
                    TLV(CLD_ASCII, CLD_ASCII_V), TV(CIC, b'\x00\x41'), TLV(SSCI, b'\x01'),
                    TLV(A2P_SESS, a2p_session()), TLV(A2P_FMT, a2p_format([a2p_fmt_entry(0, 2, 0)]))))  # Additional Service Request
    conn.send(down, B(0x69, TLV(MID, IMSI), TV(SO, SO_EVRC), TLV(A2P_SESS, a2p_session())))               # Additional Service Notification
    conn.send(up, D(0x25, TLV(CLD_BCD, CLD_BCD_V), TLV(CLD_ASCII, CLD_ASCII_V), TLV(REV_MS_INFO, rec(0x03, b'9'))))  # CM Service Req Cont
    conn.send(down, B(0x6C, TLV(PRIO, b'\x3c'), TLV(PACA_TS, b'\x00\x01\x00\x00')))                       # PACA Command
    conn.send(up, B(0x6D, TLV(CAUSE, b'\x00')))                                                           # PACA Command Ack
    conn.send(down, B(0x23, TLV(PSMM, b'\x02')))                                                          # Radio Meas Pos Req
    conn.send(up, B(0x25, TLV(CDMA_SOWD, SOWD), TLV(CAUSE, b'\x00'),
                    TLV(DLRE_LIST, b'\x0a' + downlink_re(0x02, [b'\x01\x23', b'\x04\x56']) +
                        b'\x0f' + downlink_re(0x07, [mscid_ci()])),
                    TLV(GEO_LOC, b'\x01\x02\x03\x04\x05')))                                               # Radio Meas Pos Resp
    conn.send(up, D(0x2E, TLV(SOCI, b'\x00'), TLV(CAUSE, b'\x00'), TLV(CAUSE_L3, b'\x80\x90')))          # Service Release
    conn.send(down, D(0x2F, TLV(SOCI, b'\x00')))                                                           # Service Release Complete
    conn.send(up, B(0x22, TLV(CAUSE, b'\x10'), TLV(CAUSE_L3, b'\x80\x9f')))                               # Clear Request
    conn.send(down, B(0x20, TLV(CAUSE, b'\x09'), TLV(CAUSE_L3, b'\x80\x90')))                             # Clear Command
    conn.send(up, B(0x21, T(PDI), TLV(MOB_SUB_INFO, b'\x01')))                                            # Clear Complete
    conn.release()
    if ios5:
        # RTP from the address and port in the A2p Bearer Session-Level Parameters
        c.udp(up, RTP_V4, '10.2.0.1', 7000, 7100, rtp(97, 1, 160, 0x11111111, b'\x01' * 22))
        c.udp(up, RTP_V4, '10.2.0.1', 7000, 7100, rtp(101, 2, 160, 0x11111111, b'\x05\x0a\x00\xa0'))

    # ---- 2. origination that fails assignment
    conn, _ = c.connect(cl3(cell_ci(0x0200), dmsg(0x24, bytes([0x02]) + LV(cm2(meid=False, bands=())) + LV(ESN))))
    conn.send(down, B(0x01, TLV(CHAN_TYPE, b'\x02\x09\xc0')))                                              # data call
    conn.send(up, B(0x03, TLV(CAUSE, b'\x20'), TLV(SOCI, b'\x00')))                                         # Assignment Failure
    conn.send(down, B(0x01, TLV(CHAN_TYPE, b'\x01')))                                                       # chan type 1 octet
    conn.send(down, B(0x01, TLV(CHAN_TYPE, b'\x01\x08')))                                                   # 2 octets
    conn.send(down, B(0x01, TLV(CHAN_TYPE, b'\x03\x01\x05\x00')))                                          # extraneous
    conn.send(down, B(0x20, TLV(CAUSE, b'\x20')))
    conn.send(up, B(0x21))
    conn.release()

    # ---- 3. mobile termination
    pr = dmsg(0x27, LV(cm2(p_rev=3, bands=((2, 2),))) + LV(IMSI) + TV(TAG, TAGV) + TLV(MID, ESN) + TV(SCI, b'\x01') +
              TLV(AUTH_RESP, AUTH_RESP_V) + TV(AUTH_CNF, b'\x11') + TV(AUTH_COUNT, b'\x02') +
              TLV(AUTH_CHLG, AUTH_CHLG_V) + TV(SO, SO_EVRC) + T(VP_REQ) + TV(CIC, b'\x00\x42') +
              TLV(AUTH_EVENT, b'\x03\x04') + TV(RE_RES, b'\x00') + TLV(UZ_ID, b'\x00\x01') +
              TLV(IS2000_MOB_CAP, mob_cap()) + TLV(CDMA_SOWD, SOWD) +
              I5(TLV(SOCI, b'\x01'), TLV(MID, MEID), TLV(A2P_SESS, a2p_session()),
                 TLV(A2P_FMT, a2p_format([a2p_fmt_entry(3, 4, 0)]))), pd=6)
    conn, _ = c.connect(cl3(CELL, pr))
    conn.send(down, D(0x45, LV(AUTH_CHLG_V), TLV(IS2000_MOB_CAP, mob_cap()), pd=5))                     # Authentication Request
    conn.send(up, D(0x46, LV(AUTH_RESP_V), pd=5))                                                       # Authentication Response
    conn.send(down, D(0x47, LV(AUTH_CHLG_V), pd=5))                                                     # SSD Update Request
    conn.send(up, D(0x48, LV(AUTH_CHLG_V), pd=5))                                                       # BS Challenge
    conn.send(down, D(0x49, LV(AUTH_RESP_V), pd=5))                                                     # BS Challenge Response
    conn.send(up, D(0x4A, TLV(CAUSE_L3, b'\x80\x90'), pd=5))                                            # SSD Update Response
    conn.send(down, D(0x6A, LV(bytes([0x0d, 0x0c, 0x1a])), pd=9))                                       # Status Request
    conn.send(up, D(0x6B, LV(ms_info_rev()), pd=9))                                                     # Status Response
    conn.send(up, D(0x0D, TLV(UZ_ID, b'\x00\x03'), pd=11))                                              # User Zone Update Request
    conn.send(down, D(0x0C, TLV(UZ_ID, b'\x00\x04'), pd=11))                                            # User Zone Update
    conn.send(down, D(0x0B, TLV(UZ_ID, b'\x00\x05'), pd=11))                                            # User Zone Reject
    conn.send(down, B(0x04, TLV(UZ_ID, b'\x00\x06')))                                                   # User Zone Update (BSMAP)
    conn.send(down, D(0x53, LV(adds(0x03, IS637_P2P)), TV(TAG, TAGV), TLV(CDMA_SOWD, SOWD), pd=9))      # ADDS Deliver
    conn.send(up, D(0x53, LV(adds(0x04, IS683_FWD)), pd=9))
    conn.send(up, D(0x54, TV(TAG, TAGV), TLV(CAUSE, b'\x00'), pd=9))                                     # ADDS Deliver Ack
    conn.send(up, B(0x56, TLV(MID, IMSI), TLV(MID, ESN), TLV(IS2000_CAUSE, b'\x07'), TLV(MID, MEID)))     # Rejection (BSMAP)
    conn.send(up, D(0x56, TLV(MID, IMSI), TLV(MID, ESN), TLV(IS2000_CAUSE, b'\x07\x00'), TLV(SOCI, b'\x00'),
                    TLV(MID, MEID), pd=9))                                                              # Rejection (DTAP)
    conn.send(down, D(0x70, TLV(IS2000_RED_REC, b'\x01\x02\x03'), TLV(S_RED_INFO, b'\x40'), TLV(MID, IMSI),
                      TLV(MID, ESN), TLV(P_REV, b'\x06'), TLV(MID, MEID), pd=6))                         # Service Redirection
    conn.send(down, D(0x70, TLV(MID, IMSI), pd=6))                                                      # missing mandatory
    conn.send(down, B(0x20, TLV(CAUSE, b'\x09')))
    conn.send(up, B(0x21))
    conn.release()

    # ---- 4. location updating
    lur = dmsg(0x08, LV(IMSI) + TV(LAI, bytes([0x13, 0xf0, 0x00, 0x00, 0x01])) + TLV(CM2, cm2()) +
               TV(REG_TYPE, b'\x02') + TLV(MID, ESN) + TV(SCI, b'\x01') + TLV(AUTH_RESP, AUTH_RESP_V) +
               TV(AUTH_CNF, b'\x22') + TV(AUTH_COUNT, b'\x03') + TLV(AUTH_CHLG, AUTH_CHLG_V) +
               TLV(AUTH_EVENT, b'\x09') + TLV(UZ_ID, b'\x00\x02') + TLV(IS2000_MOB_CAP, mob_cap()) +
               TV(RETURN_CAUSE, b'\x03') + I5(TLV(MS_DES_FREQ, b'\x08\x4b')) + TLV(MID, MEID) +
               I5(TLV(MOB_SUB_INFO, b'\x01')), pd=5)
    conn, _ = c.connect(cl3(CELL, lur))
    if ios5:
        conn.send(down, D(0x02, TLV(CAUSE, b'\x00'), TLV(P_REV, b'\x07'), TLV(MS_DES_FREQ, b'\x08\x4b'), pd=5))
    else:
        conn.send(down, D(0x02, TV(LAI, bytes([0x13, 0xf0, 0x00, 0x00, 0x01])), pd=5))                   # LU Accept
    conn.send(up, B(0x22, TLV(CAUSE, b'\x09')))
    conn.release()
    conn, _ = c.connect(cl3(CELL, dmsg(0x08, LV(ESN), pd=5)))
    conn.send(down, D(0x04, bytes([0x0b]), I5(TLV(P_REV, b'\x07'), TLV(MS_DES_FREQ, b'\x08\x4b')), pd=5))  # LU Reject
    conn.send(down, D(0x04, bytes([0x99]), pd=5))
    conn.release()


def rtp(pt, seq, ts, ssrc, payload, marker=0):
    return struct.pack('>BBHII', 0x80, (marker << 7) | pt, seq, ts, ssrc) + payload


def build_handoff(c, ios5):
    up, down = True, False
    I5 = (lambda *e: b''.join(e)) if ios5 else (lambda *e: b'')
    conn, _ = c.connect(cl3(CELL, dmsg(0x24, bytes([0x01]) + LV(cm2()) + LV(IMSI) + TV(SO, SO_EVRC))))
    conn.send(down, B(0x01, TLV(CHAN_TYPE, b'\x01\x08\x05'), TV(CIC, b'\x00\x50')))
    conn.send(up, B(0x02, TV(CHAN_NUM, b'\x00\x20')))
    # Handoff Required, in three parts to stay within the BSAP length octet
    m = B(0x11, TLV(CAUSE, b'\x0b'), TLV(CELL_ID_LIST, CELLS_CI), TLV(CM2, cm2()), T(RESP_REQ),
          TLV(ENC_INFO, enc_info()), TLV(IS95_CHAN_ID, chan_ident_is95(2)), TLV(MID, IMSI),
          TLV(DLRE, downlink_re(0x02, [b'\x01\x23', b'\x04\x56'])), TV(SO, SO_EVRC),
          TLV(CDMA_SOWD, SOWD), TLV(IS95_MS_MEAS, b'\x0a\x5b'), TLV(IS2000_CHAN_ID, is2000_chan_id(ios5)))
    conn.send(up, m)
    conn.send(up, B(0x11, TLV(CAUSE, b'\x0b'), TLV(CELL_ID_LIST, CELLS_MSC), TLV(QOS, b'\x0f'),
                    TLV(IS2000_MOB_CAP, mob_cap()), TLV(IS2000_SCR, scr(2)),
                    TLV(PDSN_IP, ip4('10.3.0.1')), TLV(PTYPE, b'\x88\x0b'), TLV(SRNC_TRNC, b'\x01\x02\x03'),
                    TV(SCI, b'\x02'), TV(ACC_NET_ID, struct.pack('>HHB', 0x0101, 0x0202, 0x03)),
                    TLV(SO_LIST, SO_LIST_V)))
    conn.send(up, B(0x11, TLV(CAUSE, b'\x0b'), TLV(CELL_ID_LIST, CELLS_LAC),
                    TLV(IS2000_CHAN_ID_3X, b'\x01\x02\x03\x04'), TLV(IS2000_NN_SCR, b'\x04\x12\x34\x50'),
                    TLV(ANCH_PDSN, ip4('10.3.0.2')), TLV(ANCH_PP, ip4('10.3.0.3')), TLV(PSP, b'\x01\x02'),
                    TLV(PLCM_ID, b'\x13\x01\x02\x03\x04\x05'), TLV(MID, ESN), TLV(MOB_SUB_INFO, b'\x01')))
    conn.send(up, B(0x11, TLV(CAUSE, b'\x0b'), TLV(CELL_ID_LIST, CELLS_CI),
                    TLV(IS2000_SCR, scr(1, blob=4)), TLV(PTYPE, b'\x88\x81'), TLV(IS2000_NN_SCR, b'\x00')))
    conn.send(up, B(0x11, TLV(CAUSE, b'\x0b'), TLV(CELL_ID_LIST, CELLS_CI),
                    TLV(IS2000_SCR, scr(1, blob=1, tail=0x80, extra=b'\x08\x00')), TLV(PTYPE, b'\x12\x34')))
    conn.send(up, B(0x11, TLV(CAUSE, b'\x0b'), TLV(CELL_ID_LIST, CELLS_CI),
                    TLV(IS2000_SCR, scr(1, tail=0x40, extra=b'\x00\x00'))))
    conn.send(up, B(0x11, TLV(CAUSE, b'\x0b'), TLV(CELL_ID_LIST, CELLS_CI),
                    TLV(IS2000_SCR, scr(0, tail=0x80, extra=b'\x08\x00'))))
    conn.send(up, B(0x11, TLV(CAUSE, b'\x0b'), TLV(CELL_ID_LIST, CELLS_CI),
                    TLV(IS2000_SCR, scr(0, tail=0x20, extra=b'\x00'))))
    conn.send(up, B(0x11, TLV(CAUSE, b'\x0b'), TLV(CELL_ID_LIST, CELLS_CI),
                    TLV(IS2000_SCR, scr(0, tail=0x10, extra=b'\x00'))))
    conn.send(up, B(0x11, TLV(CAUSE, b'\x0b'), TLV(CELL_ID_LIST, CELLS_CI),
                    TLV(IS2000_SCR, scr(0, tail=0x80, extra=b'\x04\x00'))))
    conn.send(up, B(0x11, TLV(CAUSE, b'\x0b'), TLV(CELL_ID_LIST, CELLS_CI),
                    TLV(IS2000_SCR, scr(0, tail=0x80, extra=b'\x02'))))
    conn.send(up, B(0x11, TLV(CAUSE, b'\x0b'), TLV(CELL_ID_LIST, CELLS_CI), TLV(IS2000_SCR, b'\x00'),
                    TLV(IS95_CHAN_ID, b'\x00')))
    conn.send(up, B(0x11, TLV(CAUSE, b'\x0b'), TLV(CELL_ID_LIST, CELLS_CI), TLV(IS2000_SCR, b'\x00\x01\x02')))
    conn.send(down, B(0x1A, TLV(CAUSE, b'\x0e')))                                                        # HO Required Reject

    # target side: Handoff Request on a new connection from the MSC
    hreq = B(0x10, TLV(CHAN_TYPE, b'\x01\x08\x04'), TLV(ENC_INFO, enc_info()), TLV(CM2, cm2()),
             TLV(CELL_ID_LIST, CELLS_CI), TLV(CIC_EXT, b'\x00\x51\x00'), TLV(IS95_CHAN_ID, chan_ident_is95(1)),
             TLV(MID, IMSI), TLV(MID, ESN), TLV(DLRE, downlink_re(0x05, [b'\x10\x01'])), TV(SO, SO_EVRC),
             TLV(CDMA_SOWD, SOWD), TLV(IS95_MS_MEAS, b'\x0a\x5b'), TLV(IS2000_CHAN_ID, is2000_chan_id(ios5, (1,))),
             TLV(QOS, b'\x01'), TLV(IS2000_MOB_CAP, mob_cap()), TLV(IS2000_SCR, scr(1)),
             TLV(PDSN_IP, ip4('10.3.0.1')), TLV(PTYPE, b'\x88\x0b'),
             I5(TLV(SRNC_TRNC, b'\x01'), TV(SCI, b'\x01'), TV(ACC_NET_ID, struct.pack('>HHB', 7, 8, 9))))
    tconn, _ = c.connect_down(hreq)
    if ios5:
        tconn2, _ = c.connect_down(B(0x10, TLV(CHAN_TYPE, b'\x01\x08\x04'), TLV(ENC_INFO, enc_info()), TLV(CM2, cm2()),
                           TLV(CELL_ID_LIST, CELLS_CI), TLV(SO_LIST, SO_LIST_V), TLV(IS2000_CHAN_ID_3X, b'\x01'),
                           TLV(IS2000_NN_SCR, b'\x00\x11'), TLV(ANCH_PDSN, ip4('10.3.0.2')),
                           TLV(ANCH_PP, ip4('10.3.0.3')), TLV(PSP, b'\x00'), TLV(PLCM_ID, b'\x00\x00\x00\x00\x00\x01'),
                           TLV(A2P_SESS, a2p_session('2001:db8::10', v6=True, port=8000)),
                           TLV(A2P_FMT, a2p_format([a2p_fmt_entry(2, 10, 102, '2001:db8::11', True, 8002, ext=b'\x01\x02'),
                                                    a2p_fmt_entry(1, 7, 103)], v6=True)),
                           TLV(MID, MEID), TLV(MOB_SUB_INFO, b'\x01')))
        c.m3ua(up, sccp_cc(tconn2.msc_ref, tconn2.bs_ref, B(0x16, TLV(CAUSE, b'\x20'))))
        tconn2.release()
    tconn.cap.m3ua(up, sccp_cc(tconn.msc_ref, tconn.bs_ref,
                               B(0x12, TLV(IS95_CHAN_ID, chan_ident_is95(3)), TLV(CELL_ID_LIST, CELLS_CI),
                                 TLV(EXT_HO_DIR, bytes(range(1, 10))), TV(HHO_PARAMS, b'\x01\x1f\x2a\x15\x03'),
                                 TLV(IS2000_CHAN_ID, is2000_chan_id(ios5, (2,))), TLV(IS2000_SCR, scr(1)),
                                 TLV(IS2000_NN_SCR, b'\x02\xab'),
                                 I5(TLV(TRNC_SRNC, b'\x05\x06'), TLV(SO_LIST, SO_LIST_V), TLV(CAUSE, b'\x00'),
                                    TLV(IS2000_CHAN_ID_3X, b'\x02'), TLV(PLCM_ID, b'\x10\x00\x00\x00\x00\x02'),
                                    TLV(A2P_SESS, a2p_session('10.2.0.30', port=7010)),
                                    TLV(A2P_FMT, a2p_format([a2p_fmt_entry(2, 3, 97)]))))))
    if ios5:
        c.udp(up, '10.2.0.30', '10.2.0.1', 7010, 7110, rtp(97, 10, 1600, 0x22222222, b'\x02' * 22))
        c.udp(down, '2001:db8::11', '2001:db8::1', 8002, 8100,
                                rtp(102, 1, 320, 0x33333333, b'\x03' * 30), v6=True)
    for ln in (1, 3, 4, 5, 6, 7, 8):
        tconn.send(up, B(0x12, TLV(EXT_HO_DIR, bytes(range(1, ln + 1)))))
    tconn.send(down, B(0x20, TLV(CAUSE, b'\x0a')))
    tconn.send(up, B(0x16, TLV(CAUSE, b'\x20')))                                                          # HO Failure
    tconn.send(up, B(0x14, TV(SO, SO_EVRC)))                                                               # HO Complete
    tconn.release()

    # back on the source side
    conn.send(down, B(0x13, TV(RF_CHAN_ID, b'\x01\x01\x02\x01\x23'), TLV(IS95_CHAN_ID, chan_ident_is95(1)),
                      TLV(CELL_ID_LIST, CELLS_CI),
                      TLV(HO_POW_LEV, b'\x02\x15' + mscid_ci() + b'\x16\x01\x23' + b'\x17\x04\x56'),
                      TV(SID, b'\x01\x23'), TLV(EXT_HO_DIR, bytes(range(1, 10))),
                      TV(HHO_PARAMS, b'\x01\x1f\x2a\x15\x03'), TLV(IS2000_CHAN_ID, is2000_chan_id(ios5, (3,))),
                      TLV(IS2000_SCR, scr(1)), TLV(IS2000_NN_SCR, b'\x00\x01'),
                      I5(TLV(TRNC_SRNC, b'\x01'), TLV(SO_LIST, SO_LIST_V), TLV(CAUSE, b'\x00'), TLV(AMPS_HHO, b'\x01'),
                         TLV(IS2000_CHAN_ID_3X, b'\x03'), TLV(PLCM_ID, b'\x20\x00\x00\x00\x00\x03'))))  # HO Command
    conn.send(down, B(0x13, TLV(HO_POW_LEV, b'\x01\x15\x01\x02')))                                       # short HO power level
    conn.send(up, B(0x15))                                                                                 # Handoff Commenced
    conn.send(up, B(0x15, b'\x00\x01'))                                                                   # with data
    conn.send(up, B(0x17, TLV(CAUSE, b'\x0b'), TLV(CELL_ID_LIST, CELLS_CI), TV(CHAN_NUM, b'\x00\x21'),
                    TLV(BAND_CLASS, b'\x01'), TLV(MOB_SUB_INFO, b'\x01')))                                 # HO Performed
    conn.send(down, B(0x20, TLV(CAUSE, b'\x0b')))
    conn.send(up, B(0x21))
    conn.release()


def build_misc(c, ios5):
    up, down = True, False
    I5 = (lambda *e: b''.join(e)) if ios5 else (lambda *e: b'')
    # BS Service Request / Response
    c.udt(up, B(0x09, TLV(MID, IMSI), TLV(MID, ESN), TV(SO, struct.pack('>H', 0x0021)), TV(TAG, TAGV),
                TLV(ADDS, adds(0x06, b'\x45\x00\x00\x14')), TLV(SR_ID, b'\x02'), TLV(MID, MEID)))
    c.udt(down, B(0x0A, TLV(MID, IMSI), TLV(MID, ESN), TV(TAG, TAGV), TLV(CAUSE, b'\x00'), TLV(MID, MEID)))
    # PACA Update / Ack
    c.udt(down, B(0x6E, TLV(MID, IMSI), TLV(MID, ESN), TLV(PACA_ORDER, b'\x02'), TLV(PRIO, b'\x3c'),
                  TLV(AUTH_RESP, AUTH_RESP_V), TV(AUTH_CNF, b'\x12'), TV(AUTH_COUNT, b'\x01'),
                  TLV(AUTH_CHLG, AUTH_CHLG_V), TLV(AUTH_EVENT, b'\x04'), TLV(MID, MEID),
                  TLV(MS_DES_FREQ, b'\x08\x4b')))
    c.udt(up, B(0x6F, TLV(MID, IMSI), TLV(PRIO, b'\x3c'), TLV(CAUSE, b'\x00')))
    # messages without a BSMAP definition, and unknown messages
    for t in (0x47, 0x48, 0x49, 0x4A):
        c.udt(down, B(t, b'\x01\x02'))
    # element variants
    c.udt(down, B(0x52, TLV(MID, IMSI), TLV(CELL_ID_LIST, cell_list(0x03, [b'\x01\x02\x03']))))     # unknown discriminator
    c.udt(up, B(0x66, TLV(MID, IMSI), TLV(CELL_ID, b'\x09\x01\x02')))
    c.udt(up, B(0x46, TLV(AUTH_RESP, AUTH_RESP_V), TLV(MID, IMSI), TV(TAG, TAGV)))
    c.udt(down, B(0x6E, TLV(MID, IMSI), TLV(AUTH_EVENT, b'\x03')))
    c.udt(down, B(0x6E, TLV(MID, IMSI), TLV(AUTH_EVENT, b'\x05')))
    c.udt(down, B(0x60, TLV(MID, IMSI), TLV(FWD_MS_INFO, rec(0x05, b'\x01\x00') + rec(0x05, b'\x02\x00'))))
    c.udt(down, D(0x10, TLV(CLD_BCD, b'\x81')))
    c.udt(down, B(0x10, TLV(CHAN_TYPE, b'\x01\x08\x04'), TLV(ENC_INFO, enc_info()), TLV(CM2, cm2()),
                  TLV(CELL_ID_LIST, CELLS_CI), TLV(CIC_EXT, b'\x00\x52\x05')))
    c.udt(down, B(0x69, TLV(MID, IMSI), TV(SO, struct.pack('>H', 4200))))                              # reserved SO
    c.udt(down, B(0x69, TLV(MID, IMSI), TV(SO, struct.pack('>H', 0x7fff))))
    c.udt(down, B(0x69, TLV(MID, IMSI), TV(SO, struct.pack('>H', 0xffff))))
    # the long DTAP messages again, short, with octets after the last element
    c.udt(up, D(0x24, bytes([0x01]) + LV(cm2()) + LV(IMSI), I5(TLV(MOB_SUB_INFO, b'\x01')), b'\xfe\xfe'))
    c.udt(up, D(0x27, LV(cm2()) + LV(IMSI), I5(TLV(A2P_FMT, a2p_format([a2p_fmt_entry(3, 3, 0)]))), b'\xfe\xfe', pd=6))
    c.udt(up, D(0x08, LV(IMSI), TLV(MID, ESN), b'\xfe\xfe', pd=5))
    if ios5:
        c.udt(down, B(0x58, TLV(A2P_SESS, a2p_session('10.2.0.50', port=7030)),
                      TLV(A2P_FMT, a2p_format([a2p_fmt_entry(1, 7, 101), a2p_fmt_entry(2, 0, 0),
                                               a2p_fmt_entry(2, 1, 8)]))))
    c.udt(down, B(0x7f, b'\x00'))                                                  # unknown BSMAP
    c.udt(down, B(0x7e))
    c.udt(down, D(0x7f, pd=3))                                                     # unknown DTAP
    c.udt(down, dtap(b'\x03\x00'))                                                # too short for DTAP
    for pd in (0, 3, 5, 6, 9, 11, 15):
        c.udt(down, D(0x2C, pd=pd))                                                 # every protocol discriminator
    c.udt(down, D(0x2B, b'\x00', pd=9))                                            # no DTAP definition, with data
    if ios5:
        c.udt(down, B(0x58, TLV(A2P_SESS, a2p_session('10.2.0.40', port=7020)),
                                                TLV(A2P_FMT, a2p_format([a2p_fmt_entry(2, 3, 98),
                                                                         a2p_fmt_entry(2, 4, 99)]))))
        c.udt(up, B(0x59, TLV(CAUSE, b'\x00'), TLV(A2P_SESS, a2p_session('10.2.0.41', port=7022)),
                    TLV(A2P_FMT, a2p_format([a2p_fmt_entry(2, 12, 100, '10.2.0.42', False, 7024)]))))
        c.udt(up, B(0x5A, TLV(CAUSE, b'\x00'), TLV(A2P_SESS, a2p_session('2001:db8::20', v6=True, port=8010)),
                    TLV(A2P_FMT, a2p_format([a2p_fmt_entry(3, 15, 104), a2p_fmt_entry(5, 9, 105)], v6=True))))
        c.udp(down, '10.2.0.40', '10.2.0.1', 7020, 7120, rtp(98, 1, 160, 0x44444444, b'\x04' * 22))


# ================================================================ femtocell (SIP)

FAP_IP = '10.4.0.2'
_sip_n = [0]


def sip_message(body, ctype='application/vnd.3gpp2.femtointerfacemsg'):
    _sip_n[0] += 1
    n = _sip_n[0]
    hdr = ('MESSAGE sip:msc@%s SIP/2.0\r\n'
           'Via: SIP/2.0/UDP %s:5060;branch=z9hG4bK-fap-%d\r\n'
           'From: <sip:fap@%s>;tag=fap%d\r\n'
           'To: <sip:msc@%s>\r\n'
           'Call-ID: femto-%d@%s\r\n'
           'CSeq: %d MESSAGE\r\n'
           'Max-Forwards: 70\r\n'
           'Content-Type: %s\r\n'
           'Content-Length: %d\r\n\r\n' % (MSC_IP, FAP_IP, n, FAP_IP, n, MSC_IP, n, FAP_IP, n, ctype, len(body)))
    return hdr.encode() + body


def femto_body(mtype, elems, bsmap_flag=False):
    """first line: message type in hex (with "1" for BSMAP), then one
    base64 encoded element per line"""
    import base64
    lines = ['%02X' % mtype + (' "1"' if bsmap_flag else '')]
    for i, e in enumerate(elems):
        lines.append('ie%d=%s' % (i, base64.b64encode(e).decode()))
    return ('\r\n'.join(lines) + '\r\n').encode()


def build_femto(c, ios5):
    def send(body, ctype='application/vnd.3gpp2.femtointerfacemsg'):
        return c.udp(True, FAP_IP, MSC_IP, 5060, 5060, sip_message(body, ctype))
    # BSMAP Complete Layer 3 Information (not a DTAP type): no elements
    send(femto_body(0x57, []))
    # DTAP CM Service Request, mandatory LV elements as TLV
    send(femto_body(0x24, [b'\x01', TLV(CM2, cm2()), TLV(MID, IMSI), TV(SO, SO_EVRC)]))
    # DTAP Location Updating Reject: mandatory V element as TV
    send(femto_body(0x04, [TV(REJ_CAUSE, b'\x0b')]), 'application/femtointerfacemsg')
    # BSMAP Authentication Request (also a DTAP type): "1" marks it BSMAP
    send(femto_body(0x45, [TLV(AUTH_CHLG, AUTH_CHLG_V), TLV(MID, IMSI)], True))
    # DTAP Paging Response and Send Burst DTMF
    send(femto_body(0x27, [TLV(CM2, cm2()), TLV(MID, IMSI), TV(TAG, TAGV)]))
    send(femto_body(0x33, [TLV(0x2C, b'\x1a'), TLV(0x2D, bytes([0x04]) + bcd('1234'))]))
    # DTAP type with "0" marker stays DTAP
    send(femto_body(0x2C, [], False).replace(b'2C', b'2C "0"', 1))
    # femtointerfacemsg with an unknown type and with missing parts
    send(b'01"')
    send(b'09\r\nx=\r\ny=\r\n')
    send(b'09')
    send(b'4A\r\nd=BQ==\r\n')
    send(b'ZZ\r\nd=AAAA\r\n')


# ================================================================ edge cases

def build_repro(c, ios5):
    """Edge cases of single elements, carried in SCCP UDT"""
    down = False
    # Access Network Identifiers as a TV element
    c.udt(down, bsmap(bytes([0x11, 0x20, 0x00, 0x01, 0x00, 0x02, 0x03]) +
                                               bytes([0x2a, 0x04, 0x01, 0x00, 0x00, 0x01])))
    # IOS 5 only element looked for before Tag
    c.udt(down, bsmap(bytes([0x6A, 0x2E, 0x01, 0x0D, 0x33, 0x00, 0x00, 0x00, 0x2A])))
    # Cell Identifier List with a cell cut short
    c.udt(down, bsmap(bytes([0x11, 0x04, 0x01, 0x01, 0x1A, 0x02, 0x02, 0x00]) +
                                                  bytes([0x22, 0x01, 0x00]) + bytes(40)))

    # Bearer Update Request, assigned / unassigned format
    def a2p(i, assigned):
        tag = 0x25 if assigned else 0x05
        fmt = bytes([0x08, tag, (98 << 1) | 1]) + bytes([10, 0, (i >> 8) & 0xff, i & 0xff]) + struct.pack('>H', 4000 + (i % 1000) * 2)
        el = bytes([0x04]) + fmt
        return bytes([0x58, 0x46, len(el)]) + el
    c.udt(down, bsmap(a2p(0, True)))
    c.udt(down, bsmap(a2p(1, True)))
    c.udt(down, bsmap(a2p(0, False)))
    c.udt(down, bsmap(a2p(1, False)))
    # assigned format without any bearer address
    el = bytes([0x04, 0x02, 0x25, (98 << 1) | 0])
    c.udt(down, bsmap(bytes([0x58, 0x46, len(el)]) + el))
    c.udt(down, bsmap(bytes([0x58, 0x46, len(el)]) + el))
    if ios5:
        # RTP to the address of the first a2p_dynpl reproducer
        c.udp(True, '10.0.0.0', '10.2.0.1', 4000, 4100,
                                   rtp(98, 1, 160, 0x55555555, b'\x06' * 22))


# ================================================================ ANSI-41 MAP (CDMA2000 A1 elements)

def ber_len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(b)]) + b


def ber_tag(cls, cons, num):
    first = (cls << 6) | (0x20 if cons else 0)
    if num < 31:
        return bytes([first | num])
    out = [num & 0x7f]
    num >>= 7
    while num:
        out.append(0x80 | (num & 0x7f))
        num >>= 7
    return bytes([first | 0x1f]) + bytes(reversed(out))


CTX, PRI = 2, 3


def ber(cls, cons, num, content):
    return ber_tag(cls, cons, num) + ber_len(len(content)) + content


def tcap_invoke(inv_id, opcode, params):
    body = ber(PRI, 0, 15, bytes([inv_id])) + ber(PRI, 0, 17, struct.pack('>H', 0x0900 | opcode))
    return ber(PRI, 1, 9, body + ber(PRI, 1, 18, params))


def tcap_result(inv_id, params):
    return ber(PRI, 1, 10, ber(PRI, 0, 15, bytes([inv_id])) + ber(PRI, 1, 18, params))


def tcap_package(ptype, tid, comps):
    return ber(PRI, 1, ptype, ber(PRI, 0, 7, tid) + ber(PRI, 1, 8, b''.join(comps)))


def a1_elements(ios5):
    e = [TLV(ACC_NET_ID, struct.pack('>HHB', 0x0101, 0x0202, 0x03)),
         TLV(CHAN_NUM, b'\x00\x20'), TLV(CIC, b'\x00\x21'), TLV(SO, SO_EVRC), TLV(TAG, TAGV),
         TLV(SCI, b'\x01'), TLV(SIGNAL, b'\x40\x01'), TLV(MWI, b'\x01'), TLV(AUTH_CNF, b'\x01'),
         TLV(AUTH_COUNT, b'\x01'), TLV(RE_RES, b'\x01'), TLV(LAI, b'\x13\xf0\x00\x00\x01'),
         TLV(REG_TYPE, b'\x01'), TLV(RETURN_CAUSE, b'\x01'), TLV(HHO_PARAMS, b'\x01\x1f\x2a\x15\x03'),
         TLV(RF_CHAN_ID, b'\x01\x01\x02\x01\x23'), TLV(SID, b'\x01\x23'), TLV(REJ_CAUSE, b'\x0b'),
         TLV(IS2000_CHAN_ID, is2000_chan_id(ios5, (1,))), TLV(IS2000_SCR, scr(1)),
         TLV(IS2000_NN_SCR, b'\x02\x12'), TLV(IS2000_MOB_CAP, mob_cap()), TLV(SO_LIST, SO_LIST_V),
         TLV(CELL_ID_LIST, CELLS_CI), TLV(MID, IMSI), TLV(CDMA_SOWD, SOWD), TLV(BAND_CLASS, b'\x01'),
         TLV(DLRE, downlink_re(0x02, [b'\x01\x23'])), TLV(PDSN_IP, ip4('10.3.0.1')), TLV(PTYPE, b'\x88\x0b'),
         TLV(ANCH_PDSN, ip4('10.3.0.2')), TLV(ANCH_PP, ip4('10.3.0.3')), TLV(PSP, b'\x01'),
         TLV(PLCM_ID, b'\x13\x01\x02\x03\x04\x05'), TLV(IS2000_RED_REC, b'\x01'), TLV(S_RED_INFO, b'\x01'),
         TLV(AMPS_HHO, b'\x01'), TLV(XMODE, b'\x01'), TLV(PRIO, b'\x3c'), TLV(P_REV, b'\x06'),
         TLV(QOS, b'\x01'), TLV(SR_ID, b'\x01'), TLV(SOCI, b'\x01'), TLV(SSCI, b'\x01'),
         TLV(CAUSE, b'\x09'), TLV(CAUSE_L3, b'\x80\x90'), TLV(IS2000_CAUSE, b'\x01'),
         TLV(ENC_INFO, enc_info()), TLV(CHAN_TYPE, b'\x01\x08\x04'),
         TLV(0xfd, b'\x01\x02'),                                   # not an A1 element
         TLV(ORIG_CI, b''), TLV(PDI, b'')]
    if ios5:
        e += [TLV(A2P_SESS, a2p_session('10.2.0.60', port=7040)),
              TLV(A2P_FMT, a2p_format([a2p_fmt_entry(3, 3, 0)])), TLV(MOB_SUB_INFO, b'\x01'),
              TLV(MS_DES_FREQ, b'\x08\x4b')]
    return e


def build_ansi_map(c, ios5):
    def mapmsg(up, tcap):
        return c.udt(up, tcap, ssn=8)
    a1 = a1_elements(ios5)
    half = len(a1) // 2
    # FacilitiesDirective2 (36) with CDMA2000HandoffInvokeIOSData
    params = (ber(CTX, 0, 1, b'\x01\x01\x02\x00\x00\x01\x01') + ber(CTX, 0, 9, struct.pack('>I', 0x8a123456)) +
              ber(CTX, 0, 6, b'\x00\x21') + ber(CTX, 0, 7, b'\x01') + ber(CTX, 0, 8, bcd('5551234567')) +
              ber(CTX, 0, 2, b'\x01\x23') + ber(CTX, 0, 356, b''.join(a1[:half])))
    mapmsg(False, tcap_package(2, b'\x00\x00\x00\x61',
                                                          [tcap_invoke(1, 36, params)]))
    # FacilitiesDirective2Res with CDMA2000HandoffResponseIOSData
    # (one octet after the last element)
    mapmsg(True, tcap_package(4, b'\x00\x00\x00\x61', [tcap_result(1, ber(CTX, 0, 357, b''.join(a1[half:]) + b'\xfd'))]))


def mob_cap_fill(fch, dcch, fpdch, rpdch):
    """IS-2000 Mobile Capabilities with the given (content, fill bit count)"""
    v = bytes([0xff, len(fch[0]), 0x10 | fch[1]]) + fch[0]
    for content, fill in (dcch, fpdch, rpdch):
        v += bytes([len(content), fill]) + content
    return v


def build_fill(c, ios5):
    """Bit-exact contents with 1 to 7 fill bits, and CDMA2000 A1 elements
    with an element type 0x00 in ANSI-41 MAP"""
    down = False
    # fill bits are the low bits of the last octet: 1, 3, 7, 4
    c.udt(down, B(0x52, TLV(MID, IMSI), TLV(IS2000_MOB_CAP, mob_cap_fill(
        (b'\x12\x35', 1), (b'\xa5', 3), (b'\x0f\xd5', 7), (b'\x3c', 4)))))
    c.udt(down, B(0x52, TLV(MID, IMSI), TLV(IS2000_MOB_CAP, mob_cap_fill(
        (b'\x81', 2), (b'\x7e', 5), (b'\xc3', 6), (b'\x01\x02', 0)))))
    # IS-2000 Non-Negotiable Service Configuration Record with 1 and 6 fill bits
    c.udt(down, B(0x12, TLV(IS2000_NN_SCR, b'\x01\x13')))
    c.udt(down, B(0x12, TLV(IS2000_NN_SCR, b'\x06\x44\xe9')))
    # CDMA2000 A1 elements: an element type 0x00 is stepped over as a TLV
    params = (ber(CTX, 0, 1, b'\x01\x01\x02\x00\x00\x01\x02') + ber(CTX, 0, 9, struct.pack('>I', 0x8a123456)) +
              ber(CTX, 0, 6, b'\x00\x21') + ber(CTX, 0, 7, b'\x01') + ber(CTX, 0, 8, bcd('5551234567')) +
              ber(CTX, 0, 2, b'\x01\x23') +
              ber(CTX, 0, 356, TLV(CAUSE, b'\x09') + b'\x00\x01\x00' + TLV(MID, ESN)))
    c.udt(down, tcap_package(2, b'\x00\x00\x00\x62', [tcap_invoke(1, 36, params)]), ssn=8)


# ================================================================ main

def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_frames(os.path.join(out, 'ansi_a-coverage.pcap'), build(False).frames)
    write_frames(os.path.join(out, 'ansi_a-ios5-coverage.pcap'), build(True).frames)
    build_malformed(os.path.join(out, 'ansi_a-coverage-malformed.pcap'))


def exp_pdu(name, payload, p2p_dir=None):
    extra = exp_pdu_tag(35, struct.pack('>i', p2p_dir)) if p2p_dir is not None else b''
    return exported_pdu(payload, proto=name, extra=extra)


def randgen(seed=100, n=400):
    """A random structured BSMAP / DTAP / femtointerfacemsg corpus (seed 100,
    400 packets)"""
    BSM = [1, 2, 3, 4, 5, 7, 8, 9, 10, 11, 16, 17, 18, 19, 20, 21, 22, 23, 26, 32, 33, 34, 35, 37, 48, 49, 52, 53, 56, 57,
           64, 65, 66, 67, 69, 70, 71, 72, 73, 74, 82, 83, 85, 86, 87, 88, 89, 90, 96, 97, 101, 102, 103, 104, 105, 106,
           107, 108, 109, 110, 111, 113]
    DTA = [2, 3, 4, 7, 8, 11, 12, 13, 16, 36, 37, 38, 39, 43, 44, 46, 47, 49, 50, 51, 52, 53, 54, 69, 70, 71, 72, 73,
           74, 80, 83, 84, 86, 98, 106, 107, 112]
    ELEMS = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 29, 30,
             31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58,
             59, 61, 64, 65, 66, 68, 69, 70, 74, 75, 78, 89, 90, 91, 94, 95, 96, 98, 100, 103, 104, 105, 112, 113, 114,
             115, 124, 125, 160, 161, 162]

    def rb(k):
        return bytes(random.getrandbits(8) for _ in range(k))

    def body():
        b = b''
        for _ in range(random.randint(0, 12)):
            e = random.choice(ELEMS)
            r = random.random()
            if r < 0.15:
                b += bytes([e]) + rb(random.randint(0, 6))
            elif r < 0.25:
                b += bytes([random.randint(0, 255)]) + rb(random.randint(0, 8))
            else:
                ln = random.choice([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 12, 16, 20, 30, random.randint(0, 255)])
                b += bytes([e, ln]) + rb(min(ln, random.randint(0, ln + 3)))
        return b
    random.seed(seed)
    pkts = []
    for _ in range(n):
        k = random.random()
        if k < 0.45:
            pkts.append(('ansi_a_bsmap', bytes([random.choice(BSM)]) + body()))
        elif k < 0.9:
            pkts.append(('ansi_a_dtap', bytes([random.choice([3, 5, 6, 9, 11, 15]), random.randint(0, 255),
                                               random.choice(DTA)]) + body()))
        else:
            t = random.choice(BSM + DTA)
            lines = ['%02X' % t + ('"1"' if random.random() < 0.5 else '')]
            for _ in range(random.randint(0, 4)):
                lines.append('e=' + base64.b64encode(body()[:20]).decode())
            pkts.append(('ansi_a_dtap_bsmap', ('\r\n'.join(lines) + '\r\n').encode()))
    return pkts


def build_malformed(path):
    """Exported PDU frames (dissector name tag) that end in an exception or
    a dissector bug; not meant for the test suite"""
    BS, DT = 'ansi_a_bsmap', 'ansi_a_dtap'
    f = []

    # elements running past the end of the message
    f.append((BS, bytes([0x12]) + TLV(EXT_HO_DIR, b'\x01\x02')))
    f.append((BS, bytes([0x52]) + TLV(MID, IMSI) + TLV(IS2000_MOB_CAP, mob_cap()[:6])))
    f.append((BS, bytes([0x52]) + TLV(MID, IMSI) + TLV(IS2000_MOB_CAP, b'\xff')))
    f.append((BS, bytes([0x01]) + TLV(CHAN_TYPE, b'\x01\x08\x04') + TV(CIC, b'\x00')))
    f.append((BS, bytes([0x02]) + TV(CHAN_NUM, b'\x00')))
    f.append((BS, bytes([0x6A]) + TLV(IE_REQD, b'\x0d') + TV(TAG, b'\x00\x01')))
    f.append((BS, bytes([0x11]) + TLV(CAUSE, b'\x0b') + TLV(CELL_ID_LIST, b'\x07\x01')))
    f.append((BS, bytes([0x11]) + TLV(CAUSE, b'\x0b') + TLV(CELL_ID_LIST, CELLS_CI) + TV(ACC_NET_ID, b'\x00\x01')))
    f.append((BS, bytes([0x11]) + TLV(CAUSE, b'\x0b') + TLV(CELL_ID_LIST, CELLS_CI) +
              TLV(IS2000_SCR, scr(3)[:12])))
    f.append((BS, bytes([0x13]) + TLV(HO_POW_LEV, b'\x02\x15' + mscid_ci()[:3])))
    f.append((BS, bytes([0x25]) + TLV(CDMA_SOWD, b'\x07\x01')))
    f.append((BS, bytes([0x25]) + TLV(CDMA_SOWD, SOWD) + TLV(CAUSE, b'\x00') + TLV(DLRE_LIST, b'\x05\x02\x02\x01')))
    f.append((BS, bytes([0x30]) + bytes([CAUSE, 0x40])))                      # length past the end
    f.append((DT, dmsg(0x24, bytes([0x01]) + bytes([0x30]) + cm2())))         # LV length past the end
    f.append((DT, dmsg(0x24, bytes([0x01]))))
    f.append((DT, dmsg(0x04, b'')))
    f.append((DT, dmsg(0x08, LV(IMSI) + TV(LAI, b'\x13\xf0'), pd=5)))
    f.append((DT, dmsg(0x10, TV(SIGNAL, b'\x40'))))
    f.append((DT, dmsg(0x33, LV(b'\x1a'))))
    f.append(('ansi_a_dtap_bsmap', b'24\r\nx=AQ==\r\n'))                       # CM Service Request, no CM2
    f.append(('ansi_a_dtap_bsmap', b'04\r\n'))
    # random corpus
    f += randgen()
    frames = []
    for i, (name, payload) in enumerate(f):
        frames.append((1700000000 + i, exp_pdu(name, payload, (i % 3) - 1 if i % 3 != 2 else None)))
    write_frames(path, frames, LINKTYPE_WIRESHARK_UPPER_PDU)


if __name__ == '__main__':
    main()
