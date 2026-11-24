#!/usr/bin/env python3
# ANSI IS-801 coverage capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""ANSI IS-801 dissector (epan/dissectors/packet-ansi_801.c).

All frames use Exported PDU (linktype 252):

  * IS-801 messages given straight to the "ansi_a.pld" dissector table with
    the direction as the table value (0 forward, 1 reverse),
  * IS-801 carried in ANSI MAP SMSDeliveryPointToPoint (ServiceIndicator 4,
    CDMA Position Determination) over ANSI TCAP / SCCP / MTP3 (exported to
    the "mtp3" dissector): the Invoke is the forward link, the ReturnResult
    the reverse link,
  * IS-801 carried in an ANSI A DTAP ADDS Deliver (ADDS User Part with burst
    type PDS), exported to "ansi_a_dtap" with the P2P direction tag (Received
    is the reverse link).

Usage: mkansi_801.py [<output directory>]

Writes ansi_801-coverage.pcap and ansi_801-coverage-malformed.pcap and
prints a frame list. Every packet is built here; nothing comes from a real
network.
"""

import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct

from capgen import LINKTYPE_WIRESHARK_UPPER_PDU, exp_pdu_tag, exported_pdu, write_pcap  # noqa: E402

FWD, REV = 0, 1


# ---------------------------------------------------------------- Exported PDU
def exp_table(direction, payload):
    """Exported PDU to dissector table ansi_a.pld with a uint value."""
    return exported_pdu(payload, table='ansi_a.pld', table_value=direction)


def exp_name(name, payload, p2p_dir=None):
    extra = exp_pdu_tag(35, struct.pack('>i', p2p_dir)) if p2p_dir is not None else b''
    return exported_pdu(payload, proto=name, extra=extra)


def write_frames(path, frames):
    """frames: (description, bytes) pairs."""
    write_pcap(path, [data for _, data in frames], snaplen=65535,
               linktype=LINKTYPE_WIRESHARK_UPPER_PDU, ts=lambda i: (1767225600 + i, 0))


# ---------------------------------------------------------------- IS-801
def sess(tag, start=False, end=False, source=False):
    return (0x80 if start else 0) | (0x40 if end else 0) | (0x20 if source else 0) | (tag & 0x1f)


def hdr0(s, nreq, nrsp):
    """PD_MSG_TYPE 0: NUM_REQUESTS and NUM_RESPONSES in one octet."""
    return bytes([s, 0x00, (nreq << 4) | nrsp])


def hdr1(s, msglen, rsi, nreq, nrsp):
    """PD_MSG_TYPE 1: PD_MSG_LEN(10) REG_SERV_IND(2) NUM_REQUESTS(4),
    then NUM_RESPONSES(4) and four reserved bits."""
    return bytes([s, 0x01]) + struct.pack('>H', (msglen << 6) | (rsi << 4) | nreq) + bytes([nrsp << 4])


def req(rtype, data, reserved=0):
    return bytes([(reserved << 4) | rtype, len(data)]) + data


def rsp(rtype, data, unsol=False, length=None):
    return bytes([(0x10 if unsol else 0) | rtype, len(data) if length is None else length]) + data


def msg0(s, reqs, rsps, extra=b''):
    return hdr0(s, len(reqs), len(rsps)) + b''.join(reqs) + b''.join(rsps) + extra


def msg1(s, reqs, rsps, rsi=0, extra=b''):
    body = b''.join(reqs) + b''.join(rsps) + extra
    return hdr1(s, 5 + len(body), rsi, len(reqs), len(rsps)) + body


class Bits:
    def __init__(self):
        self.v = 0
        self.n = 0

    def add(self, value, nbits):
        assert 0 <= value < (1 << nbits)
        self.v = (self.v << nbits) | value
        self.n += nbits
        return self

    def bytes(self, pad=0):
        v, n = self.v, self.n
        if n % 8:
            k = 8 - n % 8
            v = (v << k) | (pad & ((1 << k) - 1))
            n += k
        return v.to_bytes(n // 8, 'big')


def loc_response(time_ref=0x1234, lat=0x1600000, lng=0x2c00000, ang=5, unc_a=0x0b, unc_p=0x0c,
                 fix3d=True, vel=None, clock=None, height=None):
    """Provide Location Response body (shared by both directions).
    vel = (hor, heading, ver) ver only with fix3d; clock = (bias, drift);
    height = (height, unc_v)."""
    b = Bits().add(time_ref, 14).add(lat, 25).add(lng, 26).add(ang, 4)
    b.add(unc_a, 5).add(unc_p, 5).add(1 if fix3d else 0, 1).add(1 if vel else 0, 1)
    if vel:
        b.add(vel[0], 9).add(vel[1], 10)
        if fix3d:
            b.add(vel[2], 8)
    b.add(1 if clock else 0, 1)
    if clock:
        b.add(clock[0], 18).add(clock[1], 16)
    b.add(1 if height else 0, 1)
    if height:
        b.add(height[0], 14).add(height[1], 5)
    return b.bytes()


def sat_health(bad_svs):
    b = Bits().add(1 if bad_svs else 0, 1)
    if bad_svs:
        b.add(len(bad_svs) - 1, 4)
        for prn in bad_svs:
            b.add(prn - 1, 5)
    return b.bytes()


# Forward request type numbers
F_REQ_LOC, F_REQ_MSINFO, F_REQ_AMWF, F_REQ_PSEUDO, F_REQ_PILOT, F_REQ_TOFF, F_REQ_CANCEL = range(1, 8)
# Forward response type numbers
(F_RSP_REJECT, F_RSP_LOC, F_RSP_BSCAP, F_RSP_BSALM, F_RSP_ACQ, F_RSP_SENS, F_RSP_SPH, F_RSP_CART,
 F_RSP_ALM, F_RSP_EPH, F_RSP_NAV, F_RSP_ALMCORR, F_RSP_HEALTH) = range(13)
# Reverse request type numbers
(R_REQ_RES0, R_REQ_LOC, R_REQ_BSCAP, R_REQ_BSALM, R_REQ_ACQ, R_REQ_SENS, R_REQ_LOCASS, R_REQ_RES7,
 R_REQ_ALM, R_REQ_EPH, R_REQ_NAV, R_REQ_ALMCORR, R_REQ_HEALTH) = range(13)
# Reverse response type numbers
R_RSP_REJECT, R_RSP_LOC, R_RSP_MSINFO, R_RSP_AMWF, R_RSP_PSEUDO, R_RSP_PILOT, R_RSP_TOFF, R_RSP_CANACK = range(8)

# Common bodies
LOC_FULL = loc_response(unc_a=0x1e, unc_p=0x1f, fix3d=True, vel=(0x0c8, 0x100, 0x90),
                        clock=(13250, 0xfff6), height=(612, 0x0b))


def ms_info(pilot_ph_cap, gps=0x07ff, loc=0x7ff):
    """Provide MS Information: MS_LS_REV(6) MS_MODE(4) PILOT_PH_CAP(6),
    GPS_ACQ_CAP(12) LOC_CALC_CAP(12)."""
    return struct.pack('>H', (2 << 10) | (3 << 6) | pilot_ph_cap) + ((gps << 12) | loc).to_bytes(3, 'big')


# ---------------------------------------------------------------- ANSI MAP
def blen(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(b)]) + b


def btag(cls, cons, num):
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


def btlv(cls, cons, num, content):
    return btag(cls, cons, num) + blen(len(content)) + content


def tcap_invoke(inv_id, opcode, params):
    body = btlv(PRI, 0, 15, bytes([inv_id]))
    body += btlv(PRI, 0, 17, struct.pack('>H', 0x0900 | opcode))
    body += btlv(PRI, 1, 18, params)
    return btlv(PRI, 1, 9, body)


def tcap_result(inv_id, params):
    body = btlv(PRI, 0, 15, bytes([inv_id]))
    body += btlv(PRI, 1, 18, params)
    return btlv(PRI, 1, 10, body)


def tcap_package(ptype, tid, comps):
    return btlv(PRI, 1, ptype, btlv(PRI, 0, 7, tid) + btlv(PRI, 1, 8, b''.join(comps)))


def mtp3_sccp(opc, dpc, cd_ssn, cg_ssn, data, sls=0):
    """ITU MTP3 MSU (SIO national, SCCP) with an SCCP UDT."""
    cd = bytes([0x42, cd_ssn])          # route on SSN, SSN present
    cg = bytes([0x42, cg_ssn])
    udt = bytes([0x09, 0x00, 3, 3 + len(cd), 3 + len(cd) + len(cg)])
    udt += bytes([len(cd)]) + cd + bytes([len(cg)]) + cg + bytes([len(data)]) + data
    label = (dpc & 0x3fff) | ((opc & 0x3fff) << 14) | ((sls & 0xf) << 28)
    return bytes([0x83]) + struct.pack('<I', label) + udt


MPC_PC, MSC_PC = 1101, 2202
SSN_MSC, SSN_PDE = 8, 6   # both in ANSI MAP's default SSN range 5-14


def smdpp_invoke(tid, inv_id, is801, si_first=True):
    si = btlv(CTX, 0, 193, b'\x04')             # ServiceIndicator: CDMA PD
    bd = btlv(CTX, 0, 105, is801)               # SMS_BearerData
    tele = btlv(CTX, 0, 116, b'\x00\x00')       # SMS_TeleserviceIdentifier
    esn = btlv(CTX, 0, 9, b'\x9f\x00\x12\x34')  # ElectronicSerialNumber
    params = (si + bd if si_first else bd + si) + tele + esn
    return tcap_package(2, tid, [tcap_invoke(inv_id, 53, params)])


def smdpp_result(tid, inv_id, is801):
    params = btlv(CTX, 0, 105, is801)
    return tcap_package(4, tid, [tcap_result(inv_id, params)])


def map_frame(fwd, tcap):
    if fwd:   # PDE/MPC -> MSC
        return exp_name('mtp3', mtp3_sccp(MPC_PC, MSC_PC, SSN_MSC, SSN_PDE, tcap))
    return exp_name('mtp3', mtp3_sccp(MSC_PC, MPC_PC, SSN_PDE, SSN_MSC, tcap))


# ---------------------------------------------------------------- ANSI A
def adds_deliver(is801, reverse):
    """DTAP ADDS Deliver with an ADDS User Part (burst type PDS) and a Tag."""
    aup = bytes([0x05]) + is801
    dtap = bytes([0x03, 0x00, 0x53, len(aup)]) + aup + bytes([0x33]) + struct.pack('>I', 0x00000017)
    return exp_name('ansi_a_dtap', dtap, 1 if reverse else 0)


# ---------------------------------------------------------------- frames
def main_frames():
    F = []

    def fwd(c, p):
        F.append((c, exp_table(FWD, p)))

    def rev(c, p):
        F.append((c, exp_table(REV, p)))

    # --- further cases (repro 1-8)
    fwd('repro 1: fwd Request Pseudorange Measurement (type 4)',
        bytes([0x00, 0x00, 0x10, 0x04, 0x03, 0xAA, 0xBB, 0xCC]))
    fwd('repro 2: fwd Request Location Response (type 1)',
        bytes([0x00, 0x00, 0x10, 0x01, 0x03, 0xAA, 0xBB, 0xCC]))
    fwd('repro 3: fwd Request Pilot Phase Measurement (type 5)',
        bytes([0x00, 0x00, 0x10, 0x05, 0x03, 0xAA, 0xBB, 0xCC]))
    fwd('repro 4: fwd PD_MSG_TYPE 1, one Reject response',
        bytes([0x00, 0x01, 0x00, 0x00, 0x10, 0x00, 0x01, 0x20]))
    rev('repro 5: rev PD_MSG_TYPE 1, one Reject response',
        bytes([0x00, 0x01, 0x00, 0x00, 0x10, 0x00, 0x01, 0x20]))
    fwd('repro 6: fwd Provide Location Response, all included, length 11 (Extraneous Data)',
        bytes([0x00, 0x00, 0x01, 0x01, 0x0b]) + b'\xff' * 21)
    fwd('repro 7: fwd Provide GPS Satellite Health, 16 bad SVs',
        bytes([0x00, 0x00, 0x01, 0x0c, 0x0b]) + b'\xff' * 11)
    rev('repro 8: rev 15 requests and 15 responses of unknown type 15 (Extraneous Data)',
        bytes([0x00, 0x00, 0xff]) + b'\x0f\x00' * 2)

    # --- forward requests, each type in its own message (PD_MSG_TYPE 0)
    s = sess(1, start=True)
    fwd('fwd Reserved request (type 0) with data', msg0(s, [req(0, b'\x5a')], []))
    fwd('fwd Request Location Response: height, clock, velocity',
        msg0(s, [req(F_REQ_LOC, bytes([0x9a, 0x5f, 0xf8]))], []))
    fwd('fwd Request MS Information (no data)', msg0(s, [req(F_REQ_MSINFO, b'')], []))
    fwd('fwd Request MS Information with unexpected data', msg0(s, [req(F_REQ_MSINFO, b'\x01\x02')], []))
    fwd('fwd Request Autonomous Measurement Weighting Factors', msg0(s, [req(F_REQ_AMWF, b'', reserved=0xf)], []))
    fwd('fwd Request Pseudorange Measurement', msg0(s, [req(F_REQ_PSEUDO, bytes([0x5b, 0x40, 0x88]))], []))
    fwd('fwd Request Pilot Phase Measurement', msg0(s, [req(F_REQ_PILOT, bytes([0x3b, 0x40, 0x8c]))], []))
    fwd('fwd Request Time Offset Measurement, action time',
        msg0(s, [req(F_REQ_TOFF, bytes([0x80 | (0x15 << 1)]))], []))
    fwd('fwd Request Time Offset Measurement, no action time', msg0(s, [req(F_REQ_TOFF, b'\x00')], []))
    fwd('fwd Request Cancellation of Pseudorange Measurement', msg0(sess(1, end=True), [req(F_REQ_CANCEL, b'\x40')], []))
    fwd('fwd Request Cancellation of a reserved type', msg0(s, [req(F_REQ_CANCEL, b'\xe0')], []))

    # --- forward responses
    s = sess(2, source=True)
    fwd('fwd Reject (not supported) of Request GPS Almanac',
        msg0(s, [], [rsp(F_RSP_REJECT, bytes([0x80]))]))
    fwd('fwd Reject (temporarily unavailable) of Request BS Capabilities, unsolicited',
        msg0(s, [], [rsp(F_RSP_REJECT, bytes([0x22]), unsol=True)]))
    fwd('fwd Reject, reserved reason, reserved request type',
        msg0(s, [], [rsp(F_RSP_REJECT, bytes([0xd5]))]))
    fwd('fwd Provide BS Capabilities, APDC_ID none',
        msg0(s, [], [rsp(F_RSP_BSCAP, bytes([(3 << 4) | (1 << 3) | 2, 0x00]))]))
    fwd('fwd Provide BS Capabilities, APDC_ID 0x2a',
        msg0(s, [], [rsp(F_RSP_BSCAP, bytes([(3 << 4) | 5, 0x2a]))]))
    fwd('fwd Provide GPS Acquisition Assistance (shown as data)',
        msg0(s, [], [rsp(F_RSP_ACQ, bytes(range(1, 13)))]))
    fwd('fwd Provide GPS Location Assistance Spherical (data)',
        msg0(s, [], [rsp(F_RSP_SPH, bytes(range(20, 30)))]))
    fwd('fwd Provide GPS Location Assistance Cartesian (data)',
        msg0(s, [], [rsp(F_RSP_CART, bytes(range(30, 40)))]))
    fwd('fwd Provide GPS Sensitivity Assistance, then a Reject',
        msg0(s, [], [rsp(F_RSP_SENS, bytes([0x12, 0x34, 0x56, 0x78])), rsp(F_RSP_REJECT, b'\x80')]))
    # Last in the message: used to be read one octet late and throw
    fwd('fwd Provide GPS Sensitivity Assistance, last in the message',
        msg0(s, [], [rsp(F_RSP_SENS, bytes([0x12, 0x34, 0x56, 0x78]))]))
    fwd('fwd Provide Base Station Almanac (data)',
        msg0(s, [], [rsp(F_RSP_BSALM, bytes(range(40, 48)))]))
    fwd('fwd Provide GPS Almanac',
        msg0(s, [], [rsp(F_RSP_ALM, struct.pack('>I', (7 << 26) | (0x55 << 18) | (0x99 << 10) | (2 << 5) | 3))]))
    fwd('fwd Provide GPS Ephemeris (data)',
        msg0(s, [], [rsp(F_RSP_EPH, bytes(range(50, 66)))]))
    fwd('fwd Provide GPS Navigation Message Bits',
        msg0(s, [], [rsp(F_RSP_NAV, struct.pack('>H', (9 << 11) | (1 << 6) | (4 << 1)))]))
    fwd('fwd Provide GPS Almanac Correction (data)',
        msg0(s, [], [rsp(F_RSP_ALMCORR, bytes(range(70, 76)))]))
    fwd('fwd Provide GPS Satellite Health, no bad SV',
        msg0(s, [], [rsp(F_RSP_HEALTH, sat_health([]))]))
    fwd('fwd Provide GPS Satellite Health, 7 bad SVs (no spare bits)',
        msg0(s, [], [rsp(F_RSP_HEALTH, sat_health([1, 5, 9, 13, 17, 25, 32]))]))
    fwd('fwd Provide Location Response, everything included (3D)',
        msg0(s, [], [rsp(F_RSP_LOC, LOC_FULL)]))
    fwd('fwd Provide Location Response, velocity (2D), height, south/west',
        msg0(s, [], [rsp(F_RSP_LOC, loc_response(lat=0x0400000, lng=0x0800000, unc_a=0x04, unc_p=0x05,
                                                 fix3d=False, vel=(0x1ff, 0x3ff, 0), height=(0, 0x1e)))]))
    fwd('fwd Provide Location Response, nothing optional',
        msg0(s, [], [rsp(F_RSP_LOC, loc_response(unc_a=0x1f, unc_p=0x1e, fix3d=False))]))
    fwd('fwd Provide Location Response, velocity (3D) and clock (no spare bits)',
        msg0(s, [], [rsp(F_RSP_LOC, loc_response(unc_a=0x00, unc_p=0x01, vel=(1, 2, 3), clock=(0, 0x8000)))]))
    fwd('fwd Provide Location Response, height not computable',
        msg0(s, [], [rsp(F_RSP_LOC, loc_response(fix3d=True, height=(0x3fff, 0x1f)))]))

    # --- forward: several requests and responses in one message, both header forms
    reqs = [req(F_REQ_LOC, bytes([0x9a, 0x5f, 0xf8])), req(F_REQ_MSINFO, b''),
            req(F_REQ_PILOT, bytes([0x3b, 0x40, 0x8c]))]
    rsps = [rsp(F_RSP_BSCAP, bytes([0x35, 0x01])), rsp(F_RSP_LOC, LOC_FULL),
            rsp(F_RSP_HEALTH, sat_health([3, 4]))]
    fwd('fwd PD_MSG_TYPE 0: 3 requests and 3 responses', msg0(sess(3, start=True), reqs, rsps))
    fwd('fwd PD_MSG_TYPE 1: 3 responses, no requests',
        msg1(sess(4, start=True), [], rsps, rsi=0))
    fwd('fwd PD_MSG_TYPE 1: 2 responses, emergency service',
        msg1(sess(4), [], [rsp(F_RSP_REJECT, b'\x80'), rsp(F_RSP_ALM, b'\x1c\x00\x00\x00')], rsi=1))
    fwd('fwd PD_MSG_TYPE 1 with a request count (requests not decoded), one Reject',
        bytes([sess(4, end=True), 0x01]) + struct.pack('>H', (8 << 6) | (2 << 4) | 1) + b'\x10' +
        rsp(F_RSP_REJECT, b'\x80'))
    fwd('fwd PD_MSG_TYPE 2 (reserved)', bytes([sess(5), 0x02]) + b'\x01\x02\x03')
    fwd('fwd PD_MSG_TYPE 0xc8 (manufacturer specific)', bytes([sess(5), 0xc8]) + b'\xde\xad\xbe\xef')
    fwd('fwd PD_MSG_TYPE 0xff (reserved)', bytes([sess(5), 0xff, 0x00]))
    fwd('fwd PD_MSG_TYPE 0xff (reserved) with no data', bytes([sess(5), 0xff]))

    # --- reverse requests, each type in its own message
    s = sess(6, source=True)
    rev('rev Reserved request (type 0)', msg0(s, [req(R_REQ_RES0, b'\x01')], []))
    rev('rev Request Location Response: height, clock, velocity',
        msg0(s, [req(R_REQ_LOC, b'\xe0')], []))
    rev('rev Request BS Capabilities', msg0(s, [req(R_REQ_BSCAP, b'')], []))
    rev('rev Request Base Station Almanac, extended', msg0(s, [req(R_REQ_BSALM, b'\x80')], []))
    rev('rev Request GPS Acquisition Assistance, all',
        msg0(s, [req(R_REQ_ACQ, b'\xf0')], []))
    rev('rev Request GPS Sensitivity Assistance', msg0(s, [req(R_REQ_SENS, b'')], []))
    rev('rev Request GPS Location Assistance, spherical', msg0(s, [req(R_REQ_LOCASS, b'\x80')], []))
    rev('rev Request GPS Location Assistance, cartesian', msg0(s, [req(R_REQ_LOCASS, b'\x00')], []))
    rev('rev Reserved request (type 7)', msg0(s, [req(R_REQ_RES7, b'')], []))
    rev('rev Request GPS Almanac', msg0(s, [req(R_REQ_ALM, b'')], []))
    rev('rev Request GPS Ephemeris, alpha and beta', msg0(s, [req(R_REQ_EPH, b'\x80')], []))
    rev('rev Request GPS Navigation Message Bits, subframes 4 and 5', msg0(s, [req(R_REQ_NAV, b'\x80')], []))
    rev('rev Request GPS Almanac Correction', msg0(s, [req(R_REQ_ALMCORR, b'\x93\x2c')], []))
    rev('rev Request GPS Satellite Health Information', msg0(s, [req(R_REQ_HEALTH, b'')], []))

    # --- reverse responses
    s = sess(7)
    rev('rev Reject (not supported) of Request Pseudorange Measurement',
        msg0(s, [], [rsp(R_RSP_REJECT, b'\x40')]))
    rev('rev Reject (temporarily unavailable) of Request Location Response, unsolicited',
        msg0(s, [], [rsp(R_RSP_REJECT, b'\x12', unsol=True)]))
    rev('rev Reject, reserved reason and request type',
        msg0(s, [], [rsp(R_RSP_REJECT, b'\xfe')]))
    for cap in range(6):
        rev('rev Provide MS Information, PILOT_PH_CAP %d' % cap,
            msg0(s, [], [rsp(R_RSP_MSINFO, ms_info(cap if cap < 5 else 0x3f,
                                                   gps=0x07ff if cap % 2 else 0x0000,
                                                   loc=0x7ff if cap % 2 else 0x400))]))
    rev('rev Provide Autonomous Measurement Weighting Factors (data)',
        msg0(s, [], [rsp(R_RSP_AMWF, bytes(range(8)))]))
    rev('rev Provide Pseudorange Measurement (data)',
        msg0(s, [], [rsp(R_RSP_PSEUDO, bytes(range(10, 26)))]))
    rev('rev Provide Pilot Phase Measurement (data)',
        msg0(s, [], [rsp(R_RSP_PILOT, bytes(range(30, 42)))]))
    rev('rev Provide Location Response, everything included',
        msg0(s, [], [rsp(R_RSP_LOC, LOC_FULL)]))
    rev('rev Provide Location Response, clock and height, south/east',
        msg0(s, [], [rsp(R_RSP_LOC, loc_response(lat=0x0100000, lng=0x3000000, fix3d=False,
                                                 clock=(0x3ffff, 0x7fff), height=(0x500, 0x0a)))]))
    rev('rev Provide Time Offset Measurement',
        msg0(s, [], [rsp(R_RSP_TOFF, bytes([0x01, 0x23, 0x45]) + ((0x123 << 15) | (0x1abc << 1)).to_bytes(3, 'big'))]))
    rev('rev Provide Cancellation Acknowledgement, no outstanding request',
        msg0(s, [], [rsp(R_RSP_CANACK, b'\x48')]))
    rev('rev Provide Cancellation Acknowledgement of a reserved type',
        msg0(s, [], [rsp(R_RSP_CANACK, b'\xf0')]))

    # --- reverse: combined messages, both header forms
    reqs = [req(R_REQ_ACQ, b'\xa0'), req(R_REQ_BSCAP, b''), req(R_REQ_ALMCORR, b'\x10\x7f')]
    rsps = [rsp(R_RSP_MSINFO, ms_info(3)), rsp(R_RSP_LOC, LOC_FULL), rsp(R_RSP_TOFF, b'\x00\x00\x10\x00\x80\x00')]
    rev('rev PD_MSG_TYPE 0: 3 requests and 3 responses', msg0(sess(8, start=True, source=True), reqs, rsps))
    rev('rev PD_MSG_TYPE 1: 3 responses, no requests', msg1(sess(8), [], rsps, rsi=1))
    rev('rev PD_MSG_TYPE 1 with a request count (requests not decoded), one Reject',
        bytes([sess(8, end=True), 0x01]) + struct.pack('>H', (8 << 6) | (3 << 4) | 1) + b'\x10' +
        rsp(R_RSP_REJECT, b'\x40'))
    rev('rev PD_MSG_TYPE 0x30 (reserved)', bytes([sess(9), 0x30, 0x00]))
    rev('rev PD_MSG_TYPE 0xfe (manufacturer specific)', bytes([sess(9), 0xfe]) + b'proprietary')
    rev('rev PD_MSG_TYPE 0xff (reserved)', bytes([sess(9), 0xff, 0xff]))
    rev('rev PD_MSG_TYPE 0xc0 (manufacturer specific) with no data', bytes([sess(9), 0xc0]))

    # --- notes: Short Data / Extraneous Data, no exceptions
    s = sess(10)
    fwd('notes: fwd requests shorter than their minimum (types 1, 4, 5)',
        msg0(s, [req(F_REQ_LOC, b'\x01'), req(F_REQ_PSEUDO, b'\x01\x02'), req(F_REQ_PILOT, b'\x01')], []))
    fwd('notes: fwd requests longer than their content (types 1, 4, 5, 6, 7)',
        msg0(s, [req(F_REQ_LOC, b'\x9a\x5f\xf8\xee'), req(F_REQ_PSEUDO, b'\x5b\x40\x88\xee'),
                 req(F_REQ_PILOT, b'\x3b\x40\x8c\xee'), req(F_REQ_TOFF, b'\x00\xee'),
                 req(F_REQ_CANCEL, b'\x40\xee')], []))
    short_f = [rsp(t, b'') for t in (F_RSP_REJECT, F_RSP_BSCAP, F_RSP_SENS, F_RSP_ALM, F_RSP_NAV,
                                     F_RSP_LOC, F_RSP_HEALTH)]
    fwd('notes: fwd responses shorter than their minimum', msg0(s, [], short_f))
    long_f = [rsp(F_RSP_REJECT, b'\x80\xee'), rsp(F_RSP_BSCAP, b'\x35\x01\xee'),
              rsp(F_RSP_SENS, b'\x12\x34\x56\x78\xee'), rsp(F_RSP_ALM, b'\x1c\x00\x00\x00\xee'),
              rsp(F_RSP_NAV, b'\x48\x00\xee'), rsp(F_RSP_LOC, LOC_FULL + b'\xee'),
              rsp(F_RSP_HEALTH, sat_health([]) + b'\xee')]
    fwd('notes: fwd responses longer than their content', msg0(s, [], long_f))
    short_r = [req(t, b'') for t in (R_REQ_LOC, R_REQ_BSALM, R_REQ_ACQ, R_REQ_LOCASS, R_REQ_EPH,
                                     R_REQ_NAV, R_REQ_ALMCORR)]
    rev('notes: rev requests shorter than their minimum', msg0(s, short_r, []))
    long_r = [req(R_REQ_LOC, b'\xe0\xee'), req(R_REQ_BSALM, b'\x80\xee'), req(R_REQ_ACQ, b'\xf0\xee'),
              req(R_REQ_LOCASS, b'\x80\xee'), req(R_REQ_EPH, b'\x80\xee'), req(R_REQ_NAV, b'\x80\xee'),
              req(R_REQ_ALMCORR, b'\x93\x2c\xee')]
    rev('notes: rev requests longer than their content', msg0(s, long_r, []))
    short_rr = [rsp(t, b'') for t in (R_RSP_REJECT, R_RSP_MSINFO, R_RSP_LOC, R_RSP_TOFF, R_RSP_CANACK)]
    rev('notes: rev responses shorter than their minimum', msg0(s, [], short_rr))
    long_rr = [rsp(R_RSP_REJECT, b'\x40\xee'), rsp(R_RSP_MSINFO, ms_info(1) + b'\xee'),
               rsp(R_RSP_LOC, LOC_FULL + b'\xee'), rsp(R_RSP_TOFF, b'\x00' * 6 + b'\xee'),
               rsp(R_RSP_CANACK, b'\x48\xee')]
    rev('notes: rev responses longer than their content', msg0(s, [], long_rr))
    fwd('notes: fwd 2 requests announced, 1 present', hdr0(s, 2, 0) + req(F_REQ_MSINFO, b''))
    fwd('notes: fwd 2 responses announced, 1 present', hdr0(s, 0, 2) + rsp(F_RSP_REJECT, b'\x80'))
    fwd('notes: fwd trailing octets after the elements', msg0(s, [], [rsp(F_RSP_REJECT, b'\x80')], extra=b'\x00\x00'))
    fwd('notes: fwd unknown request and response type 13',
        hdr0(s, 1, 1) + b'\x0d\x00')
    rev('notes: rev 2 requests announced, 1 present', hdr0(s, 2, 0) + req(R_REQ_BSCAP, b''))
    rev('notes: rev 2 responses announced, 1 present', hdr0(s, 0, 2) + rsp(R_RSP_REJECT, b'\x40'))
    rev('notes: rev trailing octet', msg0(s, [req(R_REQ_ALM, b'')], [], extra=b'\x00'))
    fwd('notes: fwd header only, no elements', hdr0(s, 0, 0))

    # --- ANSI MAP SMDPP carriage over TCAP/SCCP/MTP3: an IS-801 session
    tid = b'\x00\x80\x01\x01'
    fwd_msg = msg0(sess(11, start=True), [req(F_REQ_MSINFO, b''), req(F_REQ_LOC, b'\x9a\x5f\xf8')],
                   [rsp(F_RSP_BSCAP, b'\x35\x00')])
    rev_msg = msg0(sess(11, source=True), [req(R_REQ_ACQ, b'\xf0')],
                   [rsp(R_RSP_MSINFO, ms_info(3)), rsp(R_RSP_LOC, LOC_FULL)])
    F.append(('ANSI MAP SMDPP Invoke (ServiceIndicator before BearerData): fwd IS-801',
              map_frame(True, smdpp_invoke(tid, 1, fwd_msg))))
    F.append(('ANSI MAP SMDPP ReturnResult: rev IS-801', map_frame(False, smdpp_result(tid, 1, rev_msg))))
    tid = b'\x00\x80\x01\x02'
    fwd_msg = msg0(sess(11, end=True), [req(F_REQ_CANCEL, b'\x10')], [rsp(F_RSP_ACQ, bytes(8))])
    rev_msg = msg1(sess(11, end=True, source=True), [], [rsp(R_RSP_CANACK, b'\x18')])
    F.append(('ANSI MAP SMDPP Invoke (BearerData before ServiceIndicator): fwd IS-801',
              map_frame(True, smdpp_invoke(tid, 2, fwd_msg, si_first=False))))
    F.append(('ANSI MAP SMDPP ReturnResult: rev IS-801 PD_MSG_TYPE 1', map_frame(False, smdpp_result(tid, 2, rev_msg))))

    # --- ANSI A DTAP ADDS Deliver carriage, direction from the P2P tag
    F.append(('ANSI A DTAP ADDS Deliver (sent): fwd IS-801',
              adds_deliver(msg0(sess(12, start=True), [req(F_REQ_PSEUDO, b'\x5b\x40\x88')],
                                [rsp(F_RSP_SENS, b'\x12\x34\x56\x78'), rsp(F_RSP_BSCAP, b'\x35\x00')]),
                           reverse=False)))
    F.append(('ANSI A DTAP ADDS Deliver (received): rev IS-801',
              adds_deliver(msg0(sess(12, end=True), [], [rsp(R_RSP_LOC, LOC_FULL)]), reverse=True)))
    return F


def malformed_frames():
    F = []

    def fwd(c, p):
        F.append((c, exp_table(FWD, p)))

    def rev(c, p):
        F.append((c, exp_table(REV, p)))

    fwd('repro 9: fwd Provide Location Response, length 255, 5 octets present',
        bytes([0x00, 0x00, 0x01, 0x01, 0xff]) + b'\x00' * 5)
    fwd('fwd session octet only', b'\x80')
    rev('rev session octet only', b'\x80')
    fwd('fwd PD_MSG_TYPE 0 without the count octet', b'\x80\x00')
    rev('rev PD_MSG_TYPE 1 cut in the length field', b'\x80\x01\x00')
    fwd('fwd PD_MSG_TYPE 1 without the response count', b'\x80\x01\x00\x40')
    rev('rev PD_MSG_TYPE 1 without the response count', b'\x80\x01\x00\x40')
    fwd('fwd request type 1 length 3, 1 octet present', hdr0(0, 1, 0) + b'\x01\x03\x9a')
    fwd('fwd request type 2 (data) longer than the packet', hdr0(0, 1, 0) + b'\x02\x09\x00')
    fwd('fwd response Reject length 9, 1 octet present', hdr0(0, 0, 1) + b'\x00\x09\x80')
    fwd('fwd response Acquisition Assistance (data) longer than the packet', hdr0(0, 0, 1) + b'\x04\x09\x00')
    fwd('fwd response Provide Location Response cut short', hdr0(0, 0, 1) + rsp(F_RSP_LOC, LOC_FULL[:12], length=len(LOC_FULL)))
    fwd('fwd response Satellite Health, 16 SVs, 2 octets present', hdr0(0, 0, 1) + b'\x0c\x0b\xff\xff')
    rev('rev request Almanac Correction length 2, 1 octet', hdr0(0, 1, 0) + b'\x0b\x02\x93')
    rev('rev request BS Capabilities (data) longer than the packet', hdr0(0, 1, 0) + b'\x02\x05\x00')
    rev('rev response MS Information length 5, 2 octets', hdr0(0, 0, 1) + b'\x02\x05\x08\xc3')
    rev('rev response Time Offset length 6, 3 octets', hdr0(0, 0, 1) + b'\x06\x06\x00\x00\x00')
    rev('rev response Pseudorange (data) longer than the packet', hdr0(0, 0, 1) + b'\x04\x10\x00')
    rev('rev response Location Response all included, length 255', hdr0(0, 0, 1) + b'\x01\xff' + b'\xff' * 11)
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    m = main_frames()
    b = malformed_frames()
    write_frames(os.path.join(out, 'ansi_801-coverage.pcap'), m)
    write_frames(os.path.join(out, 'ansi_801-coverage-malformed.pcap'), b)
    for name, frames in (('ansi_801-coverage.pcap', m), ('ansi_801-coverage-malformed.pcap', b)):
        print(name)
        for i, (c, _) in enumerate(frames, 1):
            print('  %3d  %s' % (i, c))


if __name__ == '__main__':
    main()
