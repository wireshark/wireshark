#!/usr/bin/env python3
# Generates test/captures/cdma2k_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the CDMA2000 TLAC/L3
message dissector (packet-cdma2k.c).

cdma2k has no port of its own: it is called by GCSNA (packet-gcsna.c),
which is carried in the GCSNA PDU element (0xC0) of an A21 message on
UDP port 23272 (packet-a21.c, registered by default). Every frame here
is Ethernet / IPv4 / UDP 23272 / A21 "1x Air Interface Signalling" /
GCSNA 1x Circuit Service / one or more TLAC encapsulated 1x L3 PDUs.

The TLAC messages are bit strings. The dissector ignores the L3 PDU
length and decodes until the end of the packet, so every message here
is built field by field in exactly the order and widths the dissector
reads them, padded to the octet boundary where the dissector resumes.
Every packet is built from scratch with struct; no captured traffic is
used.

Usage: mkcdma2k.py <output directory>

Writes:
  cdma2k-coverage.pcap            every r-csch and f-csch/f-dsch message
                                  the dissector knows, every header record
                                  type and MSID form, the branches of each
                                  message; decodes without errors
  cdma2k-coverage-malformed.pcap  unknown message types, truncated
                                  messages, the open issues (L3 PDU length
                                  ignored, Data Burst parameter length
                                  between 33 and 63 octets, a zero field
                                  count, an unknown Alert With Info record
                                  with a body) and the reviewer reproducers
                                  as they were written; Exported PDU (DLT
                                  252) naming "cdma2k", so the dissector is
                                  also called without a tree
"""

import os
import struct
import sys

SRC = (192, 0, 2, 21)
DST = (198, 51, 100, 21)
A21_PORT = 23272


class Bits:
    """Big-endian bit writer."""

    def __init__(self):
        self.bits = []

    def put(self, value, n):
        for i in range(n - 1, -1, -1):
            self.bits.append((value >> i) & 1)
        return self

    def extend(self, other):
        self.bits.extend(other.bits)
        return self

    def pad(self, n=8):
        while len(self.bits) % n:
            self.bits.append(0)
        return self

    def __len__(self):
        return len(self.bits)

    def bytes(self):
        self.pad()
        out = bytearray()
        for i in range(0, len(self.bits), 8):
            v = 0
            for b in self.bits[i:i + 8]:
                v = (v << 1) | b
            out.append(v)
        return bytes(out)


def B():
    return Bits()


# ---------------------------------------------------------------------------
# Lower layers

def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


def ipv4(proto, payload, ident):
    hdr = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0,
                      64, proto, 0, bytes(SRC), bytes(DST))
    return hdr[:10] + struct.pack('>H', csum(hdr)) + hdr[12:] + payload


def udp(data):
    hdr = struct.pack('>HHHH', A21_PORT, A21_PORT, 8 + len(data), 0)
    pseudo = struct.pack('>4s4sBBH', bytes(SRC), bytes(DST), 0, 17, 8 + len(data))
    c = csum(pseudo + hdr + data) or 0xffff
    return hdr[:6] + struct.pack('>H', c) + data


def gcsna(tlac, seq, npdu=1):
    """GCSNA 1x Circuit Service: no alternative options, no IWS ID; the
    dissector skips 8 reserved bits after NumTLACEncapsulated1xL3PDU and
    hands the octets from offset 4 on to cdma2k."""
    b = B()
    b.put(1, 8)              # GCSNA1xCircuitService
    b.put(1, 5).put(0, 3)    # GCSNA option: class 1, revision 0
    b.put(0, 1).put(0, 1)    # AltGCSNAOptionIncluded, IWSIDIncl
    b.put(1, 1).put(0, 1)    # AckRequired, StopDupDetect
    b.put(seq & 0x3f, 6)     # MsgSequence
    b.put(npdu - 1, 2)       # NumTLACEncapsulated1xL3PDU
    b.put(0, 4)
    return b.bytes() + tlac


def a21(gpdu, corr):
    msg = bytes([0x01, 0x04, 0x04]) + struct.pack('>I', corr)
    return msg + bytes([0xC0]) + struct.pack('>H', len(gpdu)) + gpdu


def frame(tlac, n, npdu=1):
    payload = a21(gcsna(tlac, n, npdu), 0x10000 + n)
    return (bytes.fromhex('020000000002020000000001') + b'\x08\x00'
            + ipv4(17, udp(payload), n))


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, (i * 1000) % 1000000,
                                len(fr), len(fr)) + fr)


# ---------------------------------------------------------------------------
# TLAC header records

def rec_addr(body, length=None):
    """Addressing record (type 0). length defaults to the octets the body
    needs; a larger length leaves reserved padding, a smaller one gives
    the "Offset corruption" note."""
    if length is None:
        length = (len(body) + 7) // 8
    return (0, length, body)


def rec_auth(body, length=None):
    if length is None:
        length = (len(body) + 7) // 8
    return (1, length, body)


def rec_other(rtype, data):
    b = B()
    for x in data:
        b.put(x, 8)
    return (rtype, len(data), b)


def msid_imsi_m(s1=0x2c8e45, s2=0x1f3, esn=0x8000abcd):
    b = B().put(0, 3).put(10, 4)
    b.put(s1 >> 14, 10).put((s1 >> 10) & 0xf, 4).put(s1 & 0x3ff, 10)
    b.put(s2, 10).put(esn, 32).put(0, 6)
    return b


def msid_esn(esn=0x9f000123):
    return B().put(1, 3).put(4, 4).put(esn, 32)


def imsi_class(b, cls, ctype):
    """IMSI class sub-fields as cdma2k_message_IMSI_CLASS_SUBFIELDS reads them."""
    b.put(cls, 1)
    if cls == 0:
        b.put(ctype, 2)
        if ctype == 0:
            b.put(0, 3).put(0x123, 10).put(0x456789, 24)
        elif ctype == 1:
            b.put(0, 4).put(0x2a, 7).put(0x123, 10).put(0x456789, 24)
        elif ctype == 2:
            b.put(0, 1).put(0x136, 10).put(0x123, 10).put(0x456789, 24)
        else:
            b.put(0, 2).put(0x136, 10).put(0x2a, 7).put(0x123, 10).put(0x456789, 24)
    else:
        b.put(ctype, 1)
        if ctype == 0:
            b.put(0, 2).put(5, 3).put(0x2a, 7).put(0x123, 10).put(0x456789, 24)
        else:
            b.put(6, 3).put(0x136, 10).put(0x2a, 7).put(0x123, 10).put(0x456789, 24)
    return b


def msid_imsi(cls, ctype):
    return imsi_class(B().put(2, 3).put(7, 4), cls, ctype)


def msid_esn_imsi(cls, ctype):
    return imsi_class(B().put(3, 3).put(11, 4).put(0x9f000456, 32), cls, ctype)


def msid_ext(ext, cls=0, ctype=0):
    b = B().put(4, 3).put(ext, 3).put(8, 4)
    if ext == 0:
        b.put(0xA0000012345678, 56)
    elif ext == 1:
        b.put(0xA0000012345679, 56)
        imsi_class(b, cls, ctype)
    elif ext == 2:
        b.put(0x80001111, 32).put(0xA000001234567A, 56)
        imsi_class(b, cls, ctype)
    return b


def msid_tmsi(msidlen, zone=0x0102030405060708, code=0xC0DE1234):
    b = B().put(5, 3).put(msidlen, 4)
    if 4 < msidlen <= 12:
        zl = (msidlen - 4) * 8
        b.put(zone & ((1 << zl) - 1), zl).put(code, 32)
    elif 0 < msidlen <= 4:
        b.put(code & ((1 << (msidlen * 8)) - 1), msidlen * 8)
    return b


def auth_body(mac, auth, sseqh=0):
    b = B().put(mac, 1).put(auth, 1)
    if auth:
        b.put(0x2abcd, 18).put(0x5a, 8).put(0x15, 6)
    if mac:
        if not auth:
            b.put(0x66, 8)
        b.put(2, 2).put(1, 3).put(sseqh, 1)
        if sseqh:
            b.put(0x123456, 24)
        else:
            b.put(0x77, 8)
    return b


# ---------------------------------------------------------------------------
# TLAC message

def tlac(channel, prev, msgtype, records, body, pdu_len=None):
    b = B()
    b.put(channel, 1).put(prev, 8)
    if channel == 0:
        b.put(0, 2).put(msgtype, 6)
    else:
        b.put(msgtype, 8)
    b.put(len(records), 4)
    for rtype, length, rb in records:
        b.put(rtype, 4).put(length, 8)
        rb = Bits().extend(rb)
        while len(rb) < length * 8:
            rb.put(0, 1)
        b.extend(rb)
    hdr = b.bytes()
    if isinstance(body, Bits):
        body = body.bytes()
    if pdu_len is None:
        pdu_len = len(body)
    return hdr + struct.pack('>H', pdu_len) + body


# r-csch message types
REG, ORDER_IND, DBURST_IND, ORIG, PAGE_RSP, AUTH_RSP = 1, 2, 3, 4, 5, 6
ORDER_CMD, DBURST_CMD, AUTH_REQ, GEN_PAGE = 7, 9, 10, 0x11
# f-csch / f-dsch message types
ALERT, UHDM, MEID_UHDM = 3, 0x22, 0x35


def reg_body(v, mob_rev, uzid=None, geo=None):
    """v is min(1x P_REV, MOB_P_REV), as the dissector computes it."""
    b = B().put(5, 4).put(2, 3).put(mob_rev, 8)
    if v == 1:
        b.put(1, 1).put(0, 1).put(1, 1).put(0, 5)
    else:
        b.put(0xa5, 8)
    b.put(1, 1)                       # MOB_TERM
    if v > 3:
        b.put(7, 4)                   # RETURN_CAUSE
    if v >= 6:
        b.put(1, 1).put(0, 1)         # QPCH_SUPPORTED, ENHANCED_RC
        b.put(1 if uzid is not None else 0, 1)
        if uzid is not None:
            b.put(uzid, 16)
    if v >= 7:
        b.put(1 if geo is not None else 0, 1)
        if geo is not None:
            b.put(geo, 3)
    return b


def order_ind(order, addreclen, fields):
    b = B().put(order, 6).put(addreclen, 3)
    for v, n in fields:
        b.put(v, n)
    return b


def order_cmd(order, addreclen, fields):
    b = B().put(order, 6).put(addreclen, 3)
    for v, n in fields:
        b.put(v, n)
    return b


def data_burst(msg_number, burst_type, num_msgs, params, num_fields=None):
    """Data Burst: after the first octet every 8 bit field sits 6 bits
    into an octet, so the fields follow each other bit by bit."""
    b = B().put(msg_number, 8).put(burst_type, 6).put(num_msgs, 8)
    if num_fields is None:
        num_fields = 1 + sum(2 + len(v) for _, v in params)
    b.put(num_fields, 8).put(0x42, 8)    # NUM_FIELDS, msg identifier
    for pid, val in params:
        b.put(pid, 8).put(len(val), 8)
        for x in val:
            b.put(x, 8)
    return b


def fch_caps(b, frame_size, forlen, revlen):
    b.put(frame_size, 1).put(forlen, 3)
    if forlen:
        b.put(0x5b5b5b & ((1 << (3 * forlen)) - 1), 3 * forlen)
    b.put(revlen, 3)
    if revlen:
        b.put(0x2d2d2d & ((1 << (3 * revlen)) - 1), 3 * revlen)


def dcch_caps(b, frame_size, forlen, revlen):
    b.put(frame_size, 2).put(forlen, 3)
    if forlen:
        b.put(0x4924924 & ((1 << (3 * forlen)) - 1), 3 * forlen)
    b.put(revlen, 3)
    if revlen:
        b.put(0x1b6db6 & ((1 << (3 * revlen)) - 1), 3 * revlen)


def enc_info(b, ecmea, rea):
    b.put(1, 1).put(ecmea, 1).put(rea, 1).put(0, 5)    # CMEA, ECMEA, REA, reserved
    b.put(1, 1).put(0, 1)                              # D_SIG_ENCRYPT_REQ, C_SIG_ENCRYPT_REQ
    if ecmea or rea:
        b.put(0xabcdef, 24).put(0x99, 8)
    b.put(1, 1).put(0x3c, 8)                           # UI_ENCRYPT_REQ, UI_ENCRYPT_SUP


def origination(v, mob_rev, auth=False, special=None, digit_mode=0,
                digits=(), alt_so=(), uzid=None, fch=None, dcch=None, geo=None,
                wll=None, gec=None, qos=None, enc=None, sync=None,
                prev_sid=None, prev_nid=None, prev_pzid=None, sobm=0):
    b = B().put(1, 1).put(3, 3).put(mob_rev, 8)
    if v == 1:
        b.put(1, 1).put(0, 1).put(1, 1).put(0, 5)
    else:
        b.put(0x5a, 8)
    b.put(1, 3)                                   # REQUEST_MODE
    b.put(1 if special is not None else 0, 1)
    if special is not None:
        b.put(special, 16)
    b.put(0, 1).put(digit_mode, 1)                # PM, DIGIT_MODE
    if digit_mode:
        b.put(2, 3).put(1, 4)                     # NUMBER_TYPE, NUMBER_PLAN
    b.put(0, 1).put(len(digits), 8)               # MORE_FIELDS, NUM_FIELDS
    for d in digits:
        b.put(d, 8 if digit_mode else 4)
    b.put(1, 1).put(0, 1).put(3, 4).put(0, 1)     # NAR_AN_CAP, PACA_REORIG, RETURN_CAUSE, MORE_RECORDS
    if v < 7 and auth:
        b.put(0xa, 4)                             # ENCRYPTION_SUPPORTED
    b.put(1, 1).put(len(alt_so), 3)               # PACA_SUPPORTED, NUM_ALT_SO
    for so in alt_so:
        b.put(so, 16)
    if v >= 6:
        b.put(1, 1)                               # DRS
        b.put(1 if uzid is not None else 0, 1)
        if uzid is not None:
            b.put(uzid, 16)
        b.put(2, 2).put(5, 3).put(1, 1).put(1, 1).put(1, 1)   # CH_IND, SR_ID, OTD, QPCH, ENHANCED_RC
        b.put(3, 5).put(3, 5)                     # FOR_RC_PREF, REV_RC_PREF
        b.put(1 if fch else 0, 1)
        if fch:
            fch_caps(b, *fch)
        b.put(1 if dcch else 0, 1)
        if dcch:
            dcch_caps(b, *dcch)
        b.put(1 if geo is not None else 0, 1)
        if geo is not None:
            b.put(geo, 3)
        b.put(1, 1)                               # REV_FCH_GATING_REQ
        if v >= 7:
            b.put(1, 1).put(2, 2).put(1, 1).put(0, 1)  # ORIG_REASON, ORIG_COUNT, STS, 3X_CCH
            b.put(1 if wll is not None else 0, 1)
            if wll is not None:
                b.put(wll, 3)
            b.put(1 if gec is not None else 0, 1)
            if gec is not None:
                b.put(gec, 1)
            b.put(1 if qos else 0, 1)
            if qos:
                b.put(len(qos), 5)
                for x in qos:
                    b.put(x, 8)
            b.put(1 if enc else 0, 1)
            if enc:
                enc_info(b, *enc)
            b.put(1 if sync is not None else 0, 1)
            if sync is not None:
                b.put(len(sync), 4)
                for x in sync:
                    b.put(x, 8)
            for val, w in ((prev_sid, 15), (prev_nid, 16), (prev_pzid, 8)):
                b.put(1 if val is not None else 0, 1)
                if val is not None:
                    b.put(val, w)
            b.put(sobm, 2)
            if sobm:
                b.put(4, 5).put(0xfff & ((1 << (4 * sobm)) - 1), 4 * sobm)
    return b


def page_response(v, mob_rev, auth=False, alt_so=(), uzid=None, fch=None,
                  dcch=None, wll=None, enc=None, sync=None, sobm=0):
    b = B().put(0, 1).put(1, 3).put(mob_rev, 8).put(0x5a, 8)
    b.put(2, 3).put(0x0021, 16).put(0, 1).put(1, 1)   # REQUEST_MODE, SERVICE_OPTION, PM, NAR_AN_CAP
    if v < 7 and auth:
        b.put(0x5, 4)
    b.put(len(alt_so), 3)
    for so in alt_so:
        b.put(so, 16)
    if v >= 6:
        b.put(1 if uzid is not None else 0, 1)
        if uzid is not None:
            b.put(uzid, 16)
        b.put(1, 2).put(0, 1).put(1, 1).put(1, 1).put(4, 5).put(4, 5)
        b.put(1 if fch else 0, 1)
        if fch:
            fch_caps(b, *fch)
        b.put(1 if dcch else 0, 1)
        if dcch:
            dcch_caps(b, *dcch)
        b.put(0, 1)                                    # REV_FCH_GATING_REQ
    if v >= 7:
        b.put(1, 1).put(1, 1)                          # STS, 3X_CCH
        b.put(1 if wll is not None else 0, 1)
        if wll is not None:
            b.put(wll[0], 3).put(wll[1], 4)
        b.put(1 if enc else 0, 1)
        if enc:
            enc_info(b, *enc)
        b.put(1 if sync is not None else 0, 1)
        if sync is not None:
            b.put(len(sync), 4)
            for x in sync:
                b.put(x, 8)
        b.put(sobm, 2)
        if sobm:
            b.put(9, 5).put(0xabc & ((1 << (4 * sobm)) - 1), 4 * sobm)
    return b


# ---------------------------------------------------------------------------
# Universal Handoff Direction

def active_set(b, ch_ind, sch_incl, p):
    """Active set record fields (cdma2k_message_ACTIVE_SET_RECORD_FIELDS)."""
    pilots = p.get('pilots', 1)
    srch = p.get('srch_offset', 0)
    if sch_incl:
        fs = p.get('for_sch', 0)
        b.put(fs, 5)
        for i in range(fs):
            b.put(i & 1, 1).put(3, 4).put(5, 4)
        rs = p.get('rev_sch', 0)
        b.put(rs, 5)
        for i in range(rs):
            b.put(i & 1, 1).put(1, 1).put(6, 4)
    b.put(pilots, 3).put(srch, 1)
    num_sch = p.get('num_sch', 0)
    for i in range(pilots):
        b.put(0x40 + i, 9)
        if srch:
            b.put(i & 7, 3)
        apr = p.get('add_pilot_rec')
        b.put(1 if (apr is not None and i == 0) else 0, 1)
        if apr is not None and i == 0:
            b.put(apr[0], 3).put(len(apr[1]), 3)
            for x in apr[1]:
                b.put(x, 8)
        b.put(i & 1, 1)                       # PWR_COMB_IND
        if ch_ind in (5, 7):
            b.put(0x101 + i, 11).put(1, 2)
        if ch_ind in (2, 6, 7):
            b.put(0x202 + i, 11).put(2, 2)
        if sch_incl:
            b.put(num_sch, 5)
            for j in range(num_sch):
                b.put(j & 1, 1).put(2, 4)
                pi = (j == 0)
                b.put(1 if pi else 0, 1)
                if pi:
                    b.put(0x303, 11).put(3, 2)
    fch3 = p.get('fch3', 0) if ch_ind in (5, 7) else 0
    dcch3 = p.get('dcch3', 0) if ch_ind in (2, 6, 7) else 0
    if ch_ind in (5, 7):
        b.put(fch3, 1)
    if ch_ind in (2, 6, 7):
        b.put(dcch3, 1)
    if fch3 or dcch3:
        for i in range(pilots):
            if fch3:
                lo = (i == 0)
                b.put(1 if lo else 0, 1)
                if lo:
                    b.put(1, 2).put(0x111, 11)
                b.put(0 if lo else 1, 1)
                if not lo:
                    b.put(2, 2).put(0x222, 11)
            if dcch3:
                if i == 0:
                    b.put(1, 1).put(1, 2).put(0x333, 11)
                    b.put(1, 1).put(3, 2).put(0x444, 11)
                else:
                    b.put(0, 1).put(0, 1)
            if sch_incl:
                si = p.get('sch3', 0) if i == 0 else 0
                b.put(si, 1)
                if si:
                    for j in range(num_sch):
                        b.put(j & 1, 1)
                        b.put(1 if j == 0 else 0, 1)
                        if j == 0:
                            b.put(0, 2).put(0x055, 11)
                        b.put(j & 1, 1)
                        if j & 1:
                            b.put(1, 2).put(0x066, 11)
    ccsh = p.get('ccsh')
    b.put(1 if ccsh is not None else 0, 1)
    if ccsh is not None:
        b.put(1 if ccsh else 0, 1)
        if ccsh:
            b.put(ccsh, 6)
        for i in range(pilots):
            for j in range(num_sch if sch_incl else 0):
                b.put((i + j) & 1, 1)
    if ch_ind in (2, 6, 7):
        fb = p.get('fund_bcmc', 0)
        b.put(fb, 1)
        cpcch = 0
        if ch_ind == 7 and fb:
            b.put(1, 1)                       # REV_FCH_ASSIGNED
            plcm = p.get('add_plcm_fch')
            b.put(1 if plcm is not None else 0, 1)
            if plcm is not None:
                b.put(plcm, 1)
                if plcm:
                    b.put(0x1234567890 & ((1 << 39) - 1), 39)
            cpcch = p.get('cpcch', 0)
            b.put(cpcch, 1)
        if (ch_ind in (2, 6) and fb) or (ch_ind == 7 and cpcch):
            for i in range(pilots):
                b.put(0x55, 7).put(0x0a + i, 5)
    # the dissector shows the bits to the octet boundary as reserved but
    # does not skip them: the message continues right after the record


def uhdm(msgtype, p):
    """Universal (and MEID Universal) Handoff Direction message."""
    b = B()
    use_time = p.get('action_time')
    b.put(1 if use_time is not None else 0, 1)
    if use_time is not None:
        b.put(use_time, 6)
    b.put(2, 2)                               # HDM_SEQ
    p_rev = p.get('p_rev')
    b.put(1 if p_rev is not None else 0, 1)
    if p_rev is not None:
        b.put(p_rev, 8).put(1, 1)             # P_REV, SERV_NEG_TYPE
    search = p.get('search', 0)
    b.put(search, 1)
    if search:
        b.put(4, 4).put(5, 4).put(6, 4).put(28, 6).put(32, 6).put(5, 4).put(3, 4)
        b.put(10, 6).put(20, 6).put(30, 6)
    extra = p.get('extra')
    b.put(1 if extra is not None else 0, 1)
    encrypt_mode = None
    scr = nnscr = None
    pzid = 0xffff       # PACKET_ZONE_ID starts at 65535 when not included
    if extra is not None:
        pzid = extra.get('pzid', 0)
        encrypt_mode = extra.get('encrypt_mode', 0)
        b.put(pzid, 8).put(3, 4).put(1, 1).put(0, 1).put(1, 1)
        b.put(encrypt_mode, 2)
        b.put(0, 1).put(5, 4).put(12, 6).put(1, 1).put(2, 3).put(1, 5).put(283, 11)
        rihf = extra.get('return_if_fail', 0)
        b.put(rihf, 1)
        if rihf:
            b.put(1, 1)
        b.put(0, 1)                           # PERIODIC_SEARCH
        scr = extra.get('scr')
        b.put(1 if scr is not None else 0, 1)
        if scr is not None:
            b.put(3, 3).put(0x10, 8).put(len(scr), 8)
            for x in scr:
                b.put(x, 8)
        nnscr = extra.get('nnscr')
        b.put(1 if nnscr is not None else 0, 1)
        if nnscr is not None:
            b.put(0x20, 8).put(len(nnscr), 8)
            for x in nnscr:
                b.put(x, 8)
    pcs = p.get('pwr_cntl_step')
    b.put(1 if pcs is not None else 0, 1)
    if pcs is not None:
        b.put(pcs, 3)
    b.put(0, 1)                               # CLEAR_RETRY_DELAY
    sch = p.get('sch')
    b.put(1 if sch is not None else 0, 1)
    num_for_assign = None
    if sch is not None:
        fa, ra = sch
        num_for_assign = len(fa)
        b.put(len(fa), 2)
        for st in fa:
            b.put(1, 1).put(9, 4).put(1 if st is not None else 0, 1)
            if st is not None:
                b.put(st, 5)
            b.put(2, 4)
        b.put(len(ra), 2)
        for st in ra:
            b.put(0, 1).put(8, 4).put(1 if st is not None else 0, 1)
            if st is not None:
                b.put(st, 5)
            b.put(7, 4)
    b.put(11, 5)                              # FPC_SUBCHAN_GAIN
    pct = p.get('pc_action_time')
    b.put(1 if pct is not None else 0, 1)
    if pct is not None:
        b.put(pct, 6)
    ch_ind = p.get('ch_ind', 1)
    b.put(ch_ind, 3)
    asr = p.get('active_set', {})
    if ch_ind != 0 and asr is not None:
        rec = B()
        active_set(rec, ch_ind, 1 if sch is not None else 0, asr)
        b.put((len(rec) + 7) // 8, 8)       # ACTIVE_SET_REC_LEN (not used for parsing)
        b.extend(rec)
        uhdm.active_set_end = len(b)
    else:
        skip = p.get('skip', b'')
        b.put(len(skip), 8)
        for x in skip:
            b.put(x, 8)
    gat = None
    if ch_ind not in (2, 6):
        gat = p.get('gating', 0)
        b.put(gat, 1)
    if gat == 1:
        pcd = p.get('pwr_cntl_delay')
        b.put(1 if pcd is not None else 0, 1)
        if pcd is not None:
            b.put(pcd, 2)
    if encrypt_mode in (2, 3):
        if encrypt_mode == 3:
            b.put(2, 3)
        b.put(1, 3)
    lnk = p.get('xl_freq')
    b.put(1 if lnk is not None else 0, 1)
    if lnk is not None:
        b.put(lnk, 2)
    prev = p_rev if p_rev is not None else 0xffff
    if scr is not None or nnscr is not None or prev >= 11:
        sync = p.get('sync')
        b.put(1 if sync is not None else 0, 1)
        if sync is not None:
            b.put(len(sync), 4)
            for x in sync:
                b.put(x, 8)
    calls = p.get('calls')
    b.put(1 if calls is not None else 0, 1)
    if calls is not None:
        b.put(len(calls), 8)
        for i, tag in enumerate(calls):
            b.put(0x30 + i, 8).put(1 if tag is not None else 0, 1)
            b.put(tag if tag is not None else 1, 4 if tag is not None else 1)
    cs = p.get('cs', 0)
    b.put(cs, 1)
    if msgtype == MEID_UHDM:
        if prev == 6:
            if encrypt_mode == 2 and scr is not None:
                n = 13
            elif encrypt_mode == 2 and nnscr is not None:
                n = 12
            elif encrypt_mode == 2:
                n = 11
            elif scr is not None:
                n = 10
            elif nnscr is not None:
                n = 9
            else:
                n = 8
            b.put(0, n)
        elif prev in (7, 8):
            b.put(0, 6)
        plcm = p.get('plcm')
        b.put(1 if plcm is not None else 0, 1)
        if plcm is not None:
            b.put(plcm, 4)
            if plcm == 1:
                b.put(0x2468ACE013 & ((1 << 39) - 1), 39)
    fwd_pdch = None
    if prev > 7 and msgtype == UHDM:
        b.put(1, 1)                           # CHM_SUPPORTED
        cort = p.get('cdma_off_time')
        b.put(1 if cort is not None else 0, 1)
        if cort is not None:
            b.put(cort[0], 1).put(cort[1], 3)
        b.put(1, 1).put(0, 1).put(1, 1).put(0, 1)
        plcm = p.get('plcm')
        b.put(1 if plcm is not None else 0, 1)
        if plcm is not None:
            b.put(plcm, 4).put(0x13579BDF01 & ((1 << 39) - 1), 39)
        if search:
            tdr = p.get('t_tdrop_range')
            b.put(1 if tdr is not None else 0, 1)
            if tdr is not None:
                b.put(tdr, 4)
        fwd_pdch = p.get('fwd_pdch', 0)
        b.put(fwd_pdch, 1)
        if fwd_pdch:
            b.put(1, 1)
        b.put(1, 1)                           # PILOT_INFO_REQ_SUPPORTED
        encs = p.get('enc_sup', 0)
        b.put(encs, 1)
        if encs:
            b.put(0x81, 8).put(0x42, 8)
        b.put(0, 1)                           # USE_SYNC_ID
        sid = p.get('sid')
        b.put(1 if sid is not None else 0, 1)
        if sid is not None:
            b.put(sid, 15)
        nid = p.get('nid')
        b.put(1 if nid is not None else 0, 1)
        if nid is not None:
            b.put(nid, 16)
        b.put(1, 1)                           # SDB_SUPPORTED
        if cs:
            b.put(1, 1)                       # MOB_QOS
        b.put(0, 1)                           # MS_INIT_POS_LOC_SUP_IND
    if prev > 9 and msgtype == UHDM:
        if fwd_pdch == 1:
            b.put(1, 1)
        if pzid != 0:
            pzh = p.get('pz_hyst')
            b.put(1 if pzh is not None else 0, 1)
            if pzh is not None:
                b.put(pzh, 1)
                if pzh:
                    b.put(3, 4).put(0x40, 8).put(2, 3).put(9, 5)
        bcmc = p.get('bcmc_tch', 0)
        b.put(bcmc, 1)
        if bcmc:
            b.put(1, 1)
        sch_bcmc = 0
        if bcmc == 1 or num_for_assign == 1:
            sch_bcmc = p.get('sch_bcmc', 0)
            b.put(sch_bcmc, 1)
        if sch_bcmc:
            aps = p.get('add_plcm_sch')
            b.put(1 if aps is not None else 0, 1)
            if aps is not None:
                b.put(aps, 1)
                if aps:
                    b.put(0x123456789 & ((1 << 35) - 1), 35)
            for i in range(num_for_assign or 0):
                b.put(1, 1)
                oc = (i == 0) and p.get('outer_code', 0)
                b.put(1 if oc else 0, 1)
                if oc:
                    b.put(5, 3).put(33, 6)
        if cs:
            b.put(4, 3)
        b.put(1, 1)                           # USE_CH_CFG_RRM
        txp = p.get('tx_pwr')
        b.put(1 if txp is not None else 0, 1)
        if txp is not None:
            b.put(1 if txp == 'default' else 0, 1)
            if txp != 'default':
                b.put(txp, 6)
    return b


# ---------------------------------------------------------------------------
# Alert With Info records

def awi_rec(rtype, data, declared=None):
    """An information record: type, length, data. declared overrides the
    length octet (for the records whose data the dissector reads one
    octet short)."""
    return bytes([rtype, len(data) if declared is None else declared]) + bytes(data)


def awi_bits(rtype, length, b):
    return bytes([rtype, length]) + b.bytes()


def alert_with_info(records):
    return b''.join(records)


# ---------------------------------------------------------------------------

def aligned_active_set():
    """A UHDM whose active set record ends on an octet boundary (no
    reserved bits shown after it)."""
    for pilots in range(1, 8):
        for srch in (0, 1):
            p = {'p_rev': 7, 'ch_ind': 5,
                 'active_set': {'pilots': pilots, 'srch_offset': srch}}
            body = uhdm(UHDM, p)
            if uhdm.active_set_end % 8 == 0:
                return ('UHDM CH_IND 5, %d pilots, active set record ends on an '
                        'octet boundary' % pilots, tlac(1, 7, UHDM, [], body))
    raise ValueError('no aligned active set')


def main_frames():
    F = []   # (description, tlac bytes, npdu)

    def add(desc, data, npdu=1):
        F.append((desc, data, npdu))

    # --- Registration (r-csch 1) and header record forms
    add('REG prev 1 (Ext SCM form), no header records',
        tlac(0, 1, REG, [], reg_body(1, 1)))
    add('REG prev 3, addr IMSI_M + ESN (msid type 0)',
        tlac(0, 3, REG, [rec_addr(msid_imsi_m())], reg_body(3, 5)))
    add('REG prev 4 (return cause), addr ESN',
        tlac(0, 6, REG, [rec_addr(msid_esn())], reg_body(4, 4)))
    add('REG prev 6 uzid, addr IMSI class 0 type 0',
        tlac(0, 6, REG, [rec_addr(msid_imsi(0, 0))], reg_body(6, 7, uzid=0x1234)))
    add('REG prev 6 no uzid, addr IMSI class 0 type 1',
        tlac(0, 9, REG, [rec_addr(msid_imsi(0, 1))], reg_body(6, 6)))
    add('REG prev 7 uzid geo, addr IMSI class 0 type 2',
        tlac(0, 7, REG, [rec_addr(msid_imsi(0, 2))], reg_body(7, 7, uzid=0xbeef, geo=5)))
    add('REG prev 7 no geo, addr IMSI class 0 type 3',
        tlac(0, 7, REG, [rec_addr(msid_imsi(0, 3))], reg_body(7, 9)))
    add('REG, addr IMSI class 1 type 0',
        tlac(0, 7, REG, [rec_addr(msid_imsi(1, 0))], reg_body(7, 7)))
    add('REG, addr IMSI class 1 type 1',
        tlac(0, 7, REG, [rec_addr(msid_imsi(1, 1))], reg_body(7, 7)))
    add('REG, addr ESN + IMSI (msid type 3)',
        tlac(0, 7, REG, [rec_addr(msid_esn_imsi(0, 0))], reg_body(7, 7)))
    add('REG, addr extended MEID (ext type 0)',
        tlac(0, 7, REG, [rec_addr(msid_ext(0))], reg_body(7, 7)))
    add('REG, addr extended MEID + IMSI (ext type 1)',
        tlac(0, 7, REG, [rec_addr(msid_ext(1, 1, 0))], reg_body(7, 7)))
    add('REG, addr extended ESN + MEID + IMSI (ext type 2)',
        tlac(0, 7, REG, [rec_addr(msid_ext(2, 0, 3))], reg_body(7, 7)))
    add('REG, addr extended type 5 (invalid)',
        tlac(0, 7, REG, [rec_addr(msid_ext(5), 2)], reg_body(7, 7)))
    add('REG, addr TMSI lengths 0, 3, 4 and 8, 12 (zone)',
        tlac(0, 7, REG, [rec_addr(msid_tmsi(0), 1), rec_addr(msid_tmsi(3)),
                         rec_addr(msid_tmsi(4)), rec_addr(msid_tmsi(8)),
                         rec_addr(msid_tmsi(12))], reg_body(7, 7)))
    add('REG, addr TMSI length 15 in 16 octets (repro cdma2k_tmsi_zone.py), msid type 6 (invalid)',
        tlac(0, 7, REG, [rec_addr(msid_tmsi(15), 16),
                         rec_addr(B().put(6, 3).put(0, 4), 1)], reg_body(7, 7)))
    add('REG, addr ESN with record length 20: 121 bits of padding (fixed bug)',
        tlac(0, 7, 0x01, [rec_addr(msid_esn(0x12345678), 20)], reg_body(7, 7)))
    add('REG, addr ESN in a record of 2 octets (offset corruption note)',
        tlac(0, 7, REG, [rec_addr(msid_esn(), 2)], reg_body(7, 7)))
    add('REG, auth records: none, AUTHR, MAC with SSEQ, both with SSEQ_H',
        tlac(0, 7, REG, [rec_auth(auth_body(0, 0)), rec_auth(auth_body(0, 1)),
                         rec_auth(auth_body(1, 0, 0)), rec_auth(auth_body(1, 1, 1))],
             reg_body(7, 7)))
    add('REG, auth record length 10 without fields: 78 bits padding (fixed bug)',
        tlac(0, 7, REG, [rec_auth(auth_body(0, 0), 10)], reg_body(7, 7)))
    add('REG, auth record of 1 octet with AUTHR (offset corruption note)',
        tlac(0, 7, REG, [rec_auth(auth_body(0, 1), 1)], reg_body(7, 7)))
    add('REG, other record types 2, 9, 15 (one empty)',
        tlac(0, 7, REG, [rec_other(2, [0xab]), rec_other(9, [1, 2, 3]),
                         rec_other(15, [])], reg_body(7, 7)))
    add('REG, 15 header records',
        tlac(0, 7, REG, [rec_other(3 + (i % 12), [i]) for i in range(15)],
             reg_body(7, 7)))

    # --- Order Indication (r-csch 2)
    add('ORDER_IND base station challenge (2)',
        tlac(0, 7, ORDER_IND, [rec_addr(msid_esn())],
             order_ind(2, 5, [(0, 8), (0xdeadbeef, 32)])))
    add('ORDER_IND reorder (4)', tlac(0, 7, ORDER_IND, [], order_ind(4, 1, [(0, 8)])))
    add('ORDER_IND service option request (19)',
        tlac(0, 7, ORDER_IND, [], order_ind(19, 3, [(0, 8), (0x0021, 16)])))
    add('ORDER_IND service option response (20)',
        tlac(0, 7, ORDER_IND, [], order_ind(20, 3, [(0, 8), (0x8022, 16)])))
    add('ORDER_IND MS reject (31) ORDQ 5 rejected type 7 (repro frame 1)',
        tlac(0, 7, ORDER_IND, [], order_ind(31, 7, [(0x05, 8), (7, 8), (0, 2), (0x15, 6), (0x22, 8)])))
    add('ORDER_IND MS reject type 1, ORDQ 16 (CON_REF)',
        tlac(0, 7, ORDER_IND, [], order_ind(31, 4, [(16, 8), (1, 8), (0, 2), (0x10, 6), (0x01, 8), (0x33, 8)])))
    add('ORDER_IND MS reject type 12, ORDQ 19 (CON_REF, TAG)',
        tlac(0, 7, ORDER_IND, [], order_ind(31, 7, [(19, 8), (12, 8), (0x1234, 16), (0x56, 8), (0x44, 8), (9, 4)])))
    add('ORDER_IND MS reject type 3, ORDQ 17',
        tlac(0, 7, ORDER_IND, [], order_ind(31, 3, [(17, 8), (3, 8), (0x01, 8)])))
    add('ORDER_IND MS reject ORDQ 18, type 3',
        tlac(0, 7, ORDER_IND, [], order_ind(31, 3, [(18, 8), (3, 8), (0x02, 8)])))
    add('ORDER_IND release (21) ORDQ 3 RSC 1 (repro frame 2)',
        tlac(0, 7, ORDER_IND, [], order_ind(21, 7, [(3, 8), (1, 1), (0xa, 4), (2, 2), (0x5, 4)])))
    add('ORDER_IND release ORDQ 3 RSC 0',
        tlac(0, 7, ORDER_IND, [], order_ind(21, 2, [(3, 8), (0, 1)])))
    add('ORDER_IND release ORDQ 0',
        tlac(0, 7, ORDER_IND, [], order_ind(21, 1, [(0, 8)])))
    add('ORDER_IND fast call setup (34) RSC 1 (repro frame 3)',
        tlac(0, 7, ORDER_IND, [], order_ind(34, 7, [(0, 8), (1, 1), (0xa, 4), (2, 2), (0x5, 4)])))
    add('ORDER_IND fast call setup RSC 0',
        tlac(0, 7, ORDER_IND, [], order_ind(34, 2, [(0, 8), (0, 1)])))
    add('ORDER_IND order 10 (unsupported)',
        tlac(0, 7, ORDER_IND, [], order_ind(10, 1, [])))
    add('ORDER_IND without additional fields',
        tlac(0, 7, ORDER_IND, [], order_ind(4, 0, [])))

    # --- Data Burst Indication (r-csch 3)
    add('DATA_BURST_IND without parameters',
        tlac(0, 7, DBURST_IND, [], data_burst(1, 3, 1, [])))
    add('DATA_BURST_IND two parameters (3 and 32 octets)',
        tlac(0, 7, DBURST_IND, [], data_burst(2, 4, 1, [(1, [1, 2, 3]), (2, list(range(32)))])))
    add('DATA_BURST_IND parameter of 64 octets (continuation items)',
        tlac(0, 7, DBURST_IND, [], data_burst(3, 5, 2, [(7, [0x40 + i for i in range(64)])])))

    # --- Origination (r-csch 4)
    add('ORIG prev 1, 4 bit digits, special service',
        tlac(0, 1, ORIG, [rec_addr(msid_esn())],
             origination(1, 1, special=0x0003, digits=[1, 2, 3, 4, 5])))
    add('ORIG prev 3 with auth record (encryption supported), alt SO, 8 bit digits',
        tlac(0, 3, ORIG, [rec_auth(auth_body(0, 1))],
             origination(3, 3, auth=True, digit_mode=1, digits=[0x31, 0x32, 0x33],
                         alt_so=(0x0011, 0x0021))))
    add('ORIG prev 6 auth, uzid, FCH/DCCH caps with maps, geo',
        tlac(0, 6, ORIG, [rec_auth(auth_body(1, 0))],
             origination(6, 6, auth=True, uzid=0x4321, fch=(1, 2, 3), dcch=(2, 1, 2), geo=3)))
    add('ORIG prev 6, FCH/DCCH without maps',
        tlac(0, 6, ORIG, [], origination(6, 8, fch=(0, 0, 0), dcch=(1, 0, 0))))
    add('ORIG prev 7, everything included (ECMEA)',
        tlac(0, 7, ORIG, [rec_addr(msid_imsi(0, 3)), rec_auth(auth_body(1, 1, 1))],
             origination(7, 7, auth=True, special=0x8021, digit_mode=1, digits=[0x39] * 4,
                         alt_so=(1, 2, 3, 4, 5, 6, 7), uzid=1, fch=(1, 7, 7),
                         dcch=(3, 7, 7), geo=7, wll=4, gec=1, qos=[0x11, 0x22, 0x33],
                         enc=(1, 0), sync=[0xaa, 0xbb], prev_sid=0x7fff,
                         prev_nid=0xffff, prev_pzid=0x12, sobm=3)))
    add('ORIG prev 7, REA only, SO bitmap 1, nothing else included',
        tlac(0, 7, ORIG, [], origination(7, 7, enc=(0, 1), sobm=1)))
    add('ORIG prev 7, no encryption sequence, SO bitmap 2',
        tlac(0, 7, ORIG, [], origination(7, 9, enc=(0, 0), gec=0, sobm=2)))
    add('ORIG prev 7, WLL only: ends on an octet boundary',
        tlac(0, 7, ORIG, [], origination(7, 7, wll=2)))

    # --- Page Response (r-csch 5)
    add('PAGE_RSP prev 3 with auth record, alt SO',
        tlac(0, 3, PAGE_RSP, [rec_auth(auth_body(0, 1))],
             page_response(3, 3, auth=True, alt_so=(0x0021,))))
    add('PAGE_RSP prev 6, uzid, FCH and DCCH maps',
        tlac(0, 6, PAGE_RSP, [], page_response(6, 6, uzid=7, fch=(1, 3, 1), dcch=(2, 2, 3))))
    add('PAGE_RSP prev 6, FCH and DCCH without maps',
        tlac(0, 6, PAGE_RSP, [], page_response(6, 6, fch=(0, 0, 0), dcch=(0, 0, 0))))
    add('PAGE_RSP prev 7, WLL, ECMEA, sync id, SO bitmap',
        tlac(0, 7, PAGE_RSP, [rec_addr(msid_ext(0))],
             page_response(7, 7, wll=(3, 9), enc=(1, 1), sync=[1, 2, 3], sobm=3)))
    add('PAGE_RSP prev 7, encryption without sequence, empty sync id',
        tlac(0, 7, PAGE_RSP, [], page_response(7, 7, enc=(0, 0), sync=[])))
    add('PAGE_RSP prev 7, REA only',
        tlac(0, 7, PAGE_RSP, [], page_response(7, 7, enc=(0, 1))))
    add('PAGE_RSP prev 7 minimal',
        tlac(0, 7, PAGE_RSP, [], page_response(7, 7)))

    # --- Authentication Challenge Response (r-csch 6)
    add('AUTH_CHALL_RSP', tlac(0, 7, AUTH_RSP, [], B().put(0x2aaaa, 18)))

    # --- Order (f-csch 7)
    add('ORDER_CMD BS challenge confirmation (2)',
        tlac(0, 7, ORDER_CMD, [], order_cmd(2, 4, [(0, 8), (0x3abcd, 18), (0, 6)])))
    add('ORDER_CMD reorder (4)', tlac(0, 7, ORDER_CMD, [], order_cmd(4, 1, [(0, 8)])))
    add('ORDER_CMD release (21) ORDQ 3 RSC 1',
        tlac(0, 7, ORDER_CMD, [], order_cmd(21, 3, [(3, 8), (1, 1), (5, 4), (1, 2), (9, 4)])))
    add('ORDER_CMD release ORDQ 3 RSC 0',
        tlac(0, 7, ORDER_CMD, [], order_cmd(21, 2, [(3, 8), (0, 1)])))
    add('ORDER_CMD release ORDQ 2',
        tlac(0, 7, ORDER_CMD, [], order_cmd(21, 1, [(2, 8)])))
    for ordq in (0, 1, 2, 4, 6):
        add('ORDER_CMD registration (27) ORDQ %d' % ordq,
            tlac(0, 7, ORDER_CMD, [], order_cmd(27, 1, [(ordq, 8)])))
    add('ORDER_CMD registration accepted ORDQ 5 (ROAM_INDI)',
        tlac(0, 7, ORDER_CMD, [], order_cmd(27, 2, [(5, 8), (0x80, 8)])))
    add('ORDER_CMD registration accepted ORDQ 7, C_SIG 1, MSG_INT_INFO 1',
        tlac(0, 7, ORDER_CMD, [], order_cmd(27, 4, [(7, 8), (0x81, 8), (1, 3), (0, 5), (1, 1), (3, 3), (1, 1), (0, 1)])))
    add('ORDER_CMD registration accepted ORDQ 7, C_SIG 2, MSG_INT_INFO 0',
        tlac(0, 7, ORDER_CMD, [], order_cmd(27, 4, [(7, 8), (0x82, 8), (2, 3), (0, 5), (0, 1), (2, 3)])))
    add('ORDER_CMD registration accepted ORDQ 7, C_SIG 0',
        tlac(0, 7, ORDER_CMD, [], order_cmd(27, 4, [(7, 8), (0x83, 8), (0, 3), (0, 5), (0, 1)])))
    add('ORDER_CMD retry (32) type 1',
        tlac(0, 7, ORDER_CMD, [], order_cmd(32, 3, [(0, 8), (1, 3), (0x20, 8), (0, 5)])))
    add('ORDER_CMD retry type 0',
        tlac(0, 7, ORDER_CMD, [], order_cmd(32, 2, [(0, 8), (0, 3), (0, 5)])))
    add('ORDER_CMD BS reject (33)',
        tlac(0, 7, ORDER_CMD, [], order_cmd(33, 3, [(0, 8), (2, 4), (0x14, 8), (5, 3)])))
    # BCMC order: NUM_BCMC_PROGRAMS starts at 65535, so the program
    # section is read even when ALL_BCMC_FLOWS_IND is 1
    add('ORDER_CMD BCMC (35) all flows, clear retry 0',
        tlac(0, 7, ORDER_CMD, [], order_cmd(35, 7, [(0, 8), (1, 1), (0, 1), (3, 4), (0x40, 8),
                                                    (7, 5), (0xab, 8), (2, 3), (1, 2), (2, 2),
                                                    (0, 1), (1, 1), (5, 4), (6, 8)])))
    add('ORDER_CMD BCMC all flows, clear retry 1, same as previous flow',
        tlac(0, 7, ORDER_CMD, [], order_cmd(35, 7, [(0, 8), (1, 1), (1, 1), (2, 4), (0x41, 8),
                                                    (31, 5), (0xdeadbeef, 32), (0, 3),
                                                    (1, 1), (0x12, 8)])))
    add('ORDER_CMD BCMC flow list, flow discriminator length 0 (fixed bug)',
        tlac(0, 7, ORDER_CMD, [], order_cmd(35, 7, [(0, 8), (0, 1), (0x22, 8), (1, 6), (3, 5),
                                                    (0xa, 4), (0, 3), (0, 1), (0, 1), (4, 4),
                                                    (0x33, 8)])))
    # NUM_BCMC_PROGRAMS (6 bits) is read as 8 bits: the message is followed
    # by another one that starts with two 0 bits
    add('ORDER_CMD BCMC flow list, no programs, followed by a Registration',
        tlac(0, 7, ORDER_CMD, [], order_cmd(35, 3, [(0, 8), (0, 1), (0x23, 8), (0, 6)]))
        + tlac(0, 7, REG, [], reg_body(7, 7)), npdu=2)
    add('ORDER_CMD fast call setup (36) ORDQ 0, all included',
        tlac(0, 7, ORDER_CMD, [], order_cmd(36, 7, [(0, 8), (1, 1), (2, 2), (9, 4), (1, 1),
                                                    (5, 4), (1, 1), (1, 1), (3, 3), (2, 3),
                                                    (1, 2), (4, 3), (1, 1), (1, 1), (2, 3),
                                                    (7, 4), (3, 4), (0x44, 8)])))
    add('ORDER_CMD fast call setup ORDQ 1, nothing included, RER_TIME 7',
        tlac(0, 7, ORDER_CMD, [], order_cmd(36, 5, [(1, 8), (0, 1), (0, 1), (0, 3), (7, 3),
                                                    (0, 3), (0, 1), (0, 3), (0, 4), (0, 4),
                                                    (0, 8)])))
    add('ORDER_CMD fast call setup RER enabled 0, RSC supported, ORDQ 2',
        tlac(0, 7, ORDER_CMD, [], order_cmd(36, 5, [(2, 8), (1, 1), (1, 2), (3, 4), (0, 1),
                                                    (1, 1), (0, 1), (1, 3), (1, 3), (0, 3),
                                                    (0, 1), (1, 3), (1, 4), (1, 4), (1, 8)])))
    add('ORDER_CMD fast call setup ORDQ 0, RSC not supported',
        tlac(0, 7, ORDER_CMD, [], order_cmd(36, 4, [(0, 8), (0, 1), (0, 1), (0, 3), (7, 3),
                                                    (0, 3), (0, 1), (0, 3), (0, 4), (0, 4),
                                                    (0, 8)])))
    add('ORDER_CMD service status (37)',
        tlac(0, 7, ORDER_CMD, [], order_cmd(37, 3, [(0, 8), (0x2a, 6), (5, 3)])))
    add('ORDER_CMD service status, other values',
        tlac(0, 7, ORDER_CMD, [], order_cmd(37, 3, [(0, 8), (0x15, 6), (2, 3)])))
    add('ORDER_CMD location services (38) regulatory indicator',
        tlac(0, 7, ORDER_CMD, [], order_cmd(38, 2, [(0, 8), (1, 1), (2, 2)])))
    add('ORDER_CMD location services without indicator',
        tlac(0, 7, ORDER_CMD, [], order_cmd(38, 2, [(0, 8), (0, 1)])))
    add('ORDER_CMD order 50 (unsupported)',
        tlac(0, 7, ORDER_CMD, [], order_cmd(50, 1, [])))
    add('ORDER_CMD without additional fields',
        tlac(0, 7, ORDER_CMD, [], order_cmd(4, 0, [])))

    # --- Data Burst (f-csch 9), Authentication Challenge (10), General Page (0x11)
    add('DATA_BURST_CMD three parameters (incl. 96 octets)',
        tlac(0, 7, DBURST_CMD, [], data_burst(9, 0x3f, 1,
                                              [(1, []), (2, [0x55] * 7),
                                               (3, [i & 0xff for i in range(96)])])))
    add('AUTH_CHALL_REQ', tlac(0, 7, AUTH_REQ, [], B().put(0x123456, 24).put(1, 8)))
    add('GEN_PAGE_REQ with service option', tlac(0, 7, GEN_PAGE, [], B().put(0x0021, 16)))
    # an empty message body at the end of the packet throws (the message
    # item is added with length -1 at the end of the tvb), so the empty
    # General Page Request is followed by another message
    add('GEN_PAGE_REQ empty (L3 PDU length 0), followed by an Authentication Challenge Response',
        tlac(0, 7, GEN_PAGE, [], b'') + tlac(0, 7, AUTH_RSP, [], B().put(0x15555, 18)), npdu=2)

    # --- Alert With Info (f-dsch 3)
    def num_bits(ntype, nplan, chars, tail_bits, pre=None):
        b = B().put(ntype, 3).put(nplan, 4)
        if pre is not None:
            b.put(pre[0], pre[1])
        for c in chars:
            b.put(c, 8)
        b.put(0, tail_bits)
        return b

    pi = B().put(1, 3).put(1, 4).put(1, 2).put(3, 2)
    for c in b'5551234':
        pi.put(c, 8)
    pi.put(0, 5)
    sig = B().put(1, 2).put(2, 2).put(0x3f, 6).put(0, 6)
    meter = B().put(0x5aa, 11).put(0x81, 8).put(0x42, 8).put(9, 4).put(0, 1)
    para = B().put(3, 8).put(2, 4)
    for g in range(2):
        para.put(0x80 + g, 8).put(0x155, 10).put(0x2aa, 10).put(0x10, 8).put(0x20, 8).put(3, 4).put(0x77, 8)
    para.put(2, 2).put(0, 2)
    para0 = B().put(1, 8).put(0, 4).put(1, 2).put(0, 2)
    line1 = B().put(1, 1).put(1, 1).put(0, 1).put(0x96, 8).put(0, 5)
    line0 = B().put(0, 1).put(0x22, 8).put(0, 7)
    add('ALERT_WITH_INFO display, called/calling party number, signal, message waiting',
        tlac(1, 7, ALERT, [], alert_with_info([
            awi_rec(1, b'Hello'),
            awi_bits(2, 8, num_bits(2, 1, b'5551212', 1)),
            awi_bits(3, 9, pi),
            awi_bits(5, 2, sig),
            awi_rec(6, [3]),
        ])))
    # The subaddress and redirecting number records are read one octet
    # short of their length; the next record follows that octet
    redir = B().put(0, 1).put(1, 3).put(1, 4).put(0, 1).put(1, 2).put(0, 3).put(3, 2)
    redir.put(1, 1).put(0, 3).put(0xf, 4)
    for c in b'98765':
        redir.put(c, 8)
    redir1 = B().put(1, 1).put(2, 3).put(2, 4)
    for c in b'12':
        redir1.put(c, 8)
    sub = B().put(1, 1).put(2, 3).put(1, 1).put(0, 3).put(0x50, 8).put(0x51, 8)
    add('ALERT_WITH_INFO subaddresses, redirecting numbers, meter pulses',
        tlac(1, 7, ALERT, [], alert_with_info([
            awi_bits(8, 4, sub),
            awi_bits(9, 4, sub),
            awi_bits(11, 9, redir),
            awi_bits(11, 4, redir1),
            awi_bits(12, 4, sub),
            awi_bits(13, 4, meter),
        ])))
    add('ALERT_WITH_INFO parametric alerting, line control, call waiting, unknown',
        tlac(1, 7, ALERT, [], alert_with_info([
            awi_bits(14, 16, para),
            awi_bits(14, 2, para0),
            awi_bits(15, 2, line1),
            awi_bits(15, 2, line0),
            awi_bits(21, 1, B().put(1, 1).put(0, 7)),
            awi_rec(0x40, []),
        ])))

    # --- Universal Handoff Direction (f-dsch 0x22) and MEID UHDM (0x35)
    add('UHDM minimal (CH_IND 1, one pilot)',
        tlac(1, 7, UHDM, [], uhdm(UHDM, {})))
    add('UHDM P_REV 6, action time, search, extra parms with SCR, NNSCR, SCH assign, '
        'CH_IND 5, 3X FCH, CCSH, gating',
        tlac(1, 7, UHDM, [rec_addr(msid_esn())], uhdm(UHDM, {
            'action_time': 9, 'p_rev': 6, 'search': 1,
            'extra': {'pzid': 3, 'encrypt_mode': 3, 'return_if_fail': 1,
                      'scr': [1, 2, 3], 'nnscr': [4, 5]},
            'pwr_cntl_step': 2, 'sch': ([None, 7], [5]),
            'pc_action_time': 33, 'ch_ind': 5,
            'active_set': {'pilots': 2, 'srch_offset': 1, 'for_sch': 2, 'rev_sch': 1,
                           'add_pilot_rec': (1, [0xaa, 0xbb]), 'num_sch': 2,
                           'fch3': 1, 'sch3': 1, 'ccsh': 21},
            'gating': 1, 'pwr_cntl_delay': 2, 'xl_freq': 1, 'sync': [0xc0, 0xff],
            'calls': [5, None], 'cs': 1})))
    add('UHDM P_REV 9, CH_IND 7 (FCH+DCCH), 3X DCCH, fundicated BCMC with PLCM and CPCCH',
        tlac(1, 9, UHDM, [], uhdm(UHDM, {
            'p_rev': 9, 'search': 1,
            'extra': {'pzid': 0, 'encrypt_mode': 2},
            'ch_ind': 7,
            'active_set': {'pilots': 2, 'fch3': 1, 'dcch3': 1, 'ccsh': 0,
                           'fund_bcmc': 1, 'add_plcm_fch': 1, 'cpcch': 1},
            'gating': 0, 'cdma_off_time': (1, 5), 'plcm': 2, 't_tdrop_range': 4,
            'fwd_pdch': 1, 'enc_sup': 1, 'sid': 0x1234, 'nid': 0x5678, 'cs': 1})))
    add('UHDM P_REV 10, CH_IND 2, SCH, PZ hysteresis, BCMC on traffic, SCH BCMC, TX power limit',
        tlac(1, 10, UHDM, [], uhdm(UHDM, {
            'p_rev': 10,
            'extra': {'pzid': 5, 'encrypt_mode': 1},
            'sch': ([3], []), 'ch_ind': 2,
            'active_set': {'pilots': 1, 'num_sch': 1, 'dcch3': 1, 'sch3': 1,
                           'fund_bcmc': 1},
            'search': 1, 't_tdrop_range': None,
            'fwd_pdch': 1, 'pz_hyst': 1, 'bcmc_tch': 1, 'sch_bcmc': 1,
            'add_plcm_sch': 1, 'outer_code': 1, 'cs': 1, 'tx_pwr': 17})))
    add('UHDM P_REV 11, CH_IND 6, fundicated BCMC, sync id via P_REV, PZ hyst 0, default TX power',
        tlac(1, 11, UHDM, [], uhdm(UHDM, {
            'p_rev': 11,
            'extra': {'pzid': 1, 'encrypt_mode': 0},
            'sch': ([None], [None]), 'ch_ind': 6,
            'active_set': {'pilots': 1, 'fund_bcmc': 1},
            'sync': [], 'pz_hyst': 0, 'sch_bcmc': 1, 'add_plcm_sch': 0,
            'tx_pwr': 'default'})))
    add('UHDM P_REV 12, PZID 0, CH_IND 7 without additional PLCM and CPCCH, SCH BCMC '
        'without additional PLCM, no TX power limit',
        tlac(1, 12, UHDM, [], uhdm(UHDM, {
            'p_rev': 12, 'extra': {'pzid': 0}, 'ch_ind': 7, 'sch': ([None], []),
            'active_set': {'pilots': 1, 'fund_bcmc': 1, 'cpcch': 0},
            'sch_bcmc': 1})))
    add('UHDM P_REV 12, CH_IND 7 without fundicated BCMC, additional PLCM type 0',
        tlac(1, 12, UHDM, [], uhdm(UHDM, {
            'p_rev': 12, 'ch_ind': 7,
            'active_set': {'pilots': 1, 'fund_bcmc': 0}})))
    add('UHDM CH_IND 2 without fundicated BCMC, CH_IND 7 with additional PLCM type 0',
        tlac(1, 12, UHDM, [], uhdm(UHDM, {
            'p_rev': 12, 'ch_ind': 2,
            'active_set': {'pilots': 3, 'fund_bcmc': 0}}))
        + tlac(1, 12, UHDM, [], uhdm(UHDM, {
            'p_rev': 12, 'ch_ind': 7,
            'active_set': {'pilots': 1, 'fund_bcmc': 1, 'add_plcm_fch': 0, 'cpcch': 0}})), npdu=2)
    add('UHDM SCH_INCL 0 with CCSH (repro cdma2k_ccsh_loop.py frame 1 without the 8 KiB padding)',
        tlac(1, 7, UHDM, [], uhdm(UHDM, {'p_rev': 7, 'ch_ind': 1, 'active_set': {'pilots': 1, 'ccsh': 0}})))
    add('UHDM SCH_INCL 1, 2 pilots with 0 SCH (repro cdma2k_ccsh_loop.py frame 2 without the padding)',
        tlac(1, 7, UHDM, [], uhdm(UHDM, {'p_rev': 7, 'ch_ind': 1, 'sch': ([], []),
                                        'active_set': {'pilots': 2, 'num_sch': 0, 'ccsh': 0}})))
    add(*aligned_active_set())
    add('UHDM CH_IND 0 with an active set record that is skipped, P_REV 8 without options',
        tlac(1, 8, UHDM, [], uhdm(UHDM, {
            'p_rev': 8, 'ch_ind': 0, 'active_set': None, 'skip': [1, 2, 3],
            'gating': 1})))
    add('UHDM CH_IND 6 with zero length active set record',
        tlac(1, 7, UHDM, [], uhdm(UHDM, {'ch_ind': 6, 'active_set': None, 'skip': []})))
    # MEID UHDM: the reserved field widths for P_REV 6, 7 and 8
    for i, (em, scr, nnscr) in enumerate(((2, [1], None), (2, None, [2]), (2, None, None),
                                         (1, [3], None), (0, None, [4]), (0, None, None))):
        add('MEID_UHDM P_REV 6, encrypt mode %d, SCR %s, NNSCR %s' % (em, scr is not None, nnscr is not None),
            tlac(1, 6, MEID_UHDM, [], uhdm(MEID_UHDM, {
                'p_rev': 6, 'extra': {'pzid': 0, 'encrypt_mode': em, 'scr': scr, 'nnscr': nnscr},
                'plcm': 1 if i == 0 else (3 if i == 1 else None)})))
    add('MEID_UHDM P_REV 7, PLCM type 1',
        tlac(1, 7, MEID_UHDM, [rec_addr(msid_ext(0))], uhdm(MEID_UHDM, {'p_rev': 7, 'plcm': 1})))
    add('MEID_UHDM P_REV 8',
        tlac(1, 8, MEID_UHDM, [], uhdm(MEID_UHDM, {'p_rev': 8})))
    add('MEID_UHDM without P_REV',
        tlac(1, 8, MEID_UHDM, [], uhdm(MEID_UHDM, {'plcm': 0})))

    # --- More than 8 KiB of messages in one packet: the bit offsets used
    # to be 16 bits and wrapped (repro cdma2k_offset_wrap.py); the last
    # message carries a body so that it does not end at the packet end
    empty = tlac(0, 7, GEN_PAGE, [rec_other(2, [0xab])], b'')
    add('1100 General Page Requests in one PDU, 8802 octets (repro cdma2k_offset_wrap.py)',
        empty * 1099 + tlac(0, 7, GEN_PAGE, [rec_other(2, [0xcd])], B().put(0x0021, 16)))

    # --- Several messages in one GCSNA PDU
    add('Three messages: General Page Request, Order, Registration',
        tlac(0, 7, GEN_PAGE, [], B().put(0x0004, 16))
        + tlac(0, 7, ORDER_CMD, [], order_cmd(4, 1, [(0, 8)]))
        + tlac(0, 7, REG, [rec_addr(msid_esn())], reg_body(7, 7)), npdu=3)
    return F


def malformed_frames():
    F = []

    def add(desc, data):
        F.append((desc, data, 1))

    add('r-csch message type 8 (unknown): error expert info',
        tlac(0, 7, 8, [], b'\x00\x00'))
    add('f-dsch message type 0x10 (unknown): error expert info',
        tlac(1, 7, 0x10, [], b'\x00'))
    add('L3 PDU length 2 but 4 octets of body: the rest is decoded as a new '
        'TLAC message, which runs past the end (open issue)',
        tlac(0, 7, GEN_PAGE, [], b'\x00\x21\x22\x33', pdu_len=2))
    add('Data Burst parameter of 40 octets: the continuation item is given 32 '
        'octets and runs past the end; FT_NONE, so no exception (open issue)',
        tlac(0, 7, DBURST_IND, [], data_burst(1, 1, 1, [(1, [7] * 40)])))
    add('Data Burst with NUM_FIELDS 0: the field counter wraps',
        tlac(0, 7, DBURST_CMD, [], data_burst(1, 1, 1, [], num_fields=0)))
    add('Alert With Info unknown record type with a body that is not skipped '
        '(open issue)',
        tlac(1, 7, ALERT, [], awi_rec(0x41, [0x13, 0x05, 0xee, 0xee, 0xee])))
    add('Alert With Info without records: the message item at the end of '
        'the packet throws', tlac(1, 7, ALERT, [], b''))
    add('Alert With Info display record past the end',
        tlac(1, 7, ALERT, [], bytes([1, 20, 0x41])))
    add('Header cut in the record count', bytes([0x07, 0x00]))
    add('Header records past the end',
        tlac(0, 7, REG, [rec_addr(msid_esn())], b'')[:5])
    add('Registration cut short', tlac(0, 7, REG, [], b'\x52'))
    add('Origination cut short',
        tlac(0, 7, ORIG, [], origination(7, 7).bytes()[:3]))
    add('Page Response cut short',
        tlac(0, 7, PAGE_RSP, [], page_response(7, 7).bytes()[:4]))
    add('UHDM cut short',
        tlac(1, 7, UHDM, [], uhdm(UHDM, {'p_rev': 10, 'search': 1}).bytes()[:5]))
    add('UHDM with 7 pilots and 31 SCH each, cut short',
        tlac(1, 7, UHDM, [], B().put(0, 1).put(0, 2).put(0, 3).put(0, 1).put(0, 1).put(1, 1)
             .put(0, 4).put(0, 5).put(0, 1).put(1, 3).put(50, 8).put(0, 10)
             .put(7, 3).put(0, 1).put(0, 9).put(0, 1).put(0, 1).put(31, 5)))
    add('Order Indication cut short', tlac(0, 7, ORDER_IND, [], b'\x7f'))
    add('Order cut short', tlac(0, 7, ORDER_CMD, [], b'\x8f'))
    add('Alert With Info parametric alerting cut short',
        tlac(1, 7, ALERT, [], bytes([14, 16, 3, 0xf0, 0])))
    add('Authentication challenge cut short', tlac(0, 7, AUTH_REQ, [], b'\x01'))
    # the reviewer reproducers (cdma2k_*.py) as they were
    # written: with the fixes they no longer hit a dissector bug or loop,
    # but they end with leftover octets or an empty body at the end
    F.extend(reproducers())
    return F


def reproducers():
    F = []

    def add(desc, data):
        F.append((desc, data, 1))

    add('repro cdma2k_addr_reserved.py: ESN record of 20 octets',
        tlac(0, 7, GEN_PAGE, [rec_addr(B().put(1, 3).put(4, 4).put(0x12345678, 32), 20)], b''))
    add('repro cdma2k_auth_reserved.py: auth record of 10 octets',
        tlac(0, 7, GEN_PAGE, [rec_auth(B().put(0, 80), 10)], b''))
    m = B().put(35, 6).put(7, 3).put(0, 8).put(0, 1).put(0, 8).put(1, 6).put(3, 5)
    m.put(0xa, 4).put(0, 3).put(0, 24)
    add('repro cdma2k_bcmc_flow_zero.py: BCMC flow discriminator length 0',
        tlac(0, 7, ORDER_CMD, [], m))
    for sch_incl, pilots in ((0, 1), (1, 2)):
        m = B().put(0, 1).put(0, 2).put(0, 1).put(0, 1).put(0, 1).put(0, 1).put(0, 1)
        m.put(sch_incl, 1)
        if sch_incl:
            m.put(0, 2).put(0, 2)
        m.put(0, 5).put(0, 1).put(1, 3).put(4, 8)
        if sch_incl:
            m.put(0, 5).put(0, 5)
        m.put(pilots, 3).put(0, 1)
        for _ in range(pilots):
            m.put(0x55, 9).put(0, 1).put(0, 1)
            if sch_incl:
                m.put(0, 5)
        m.put(1, 1).put(0, 1)
        body = m.bytes() + b'\x00' * 8300
        add('repro cdma2k_ccsh_loop.py frame %d: UHDM with CCSH, padded past 8 KiB'
            % (sch_incl + 1), tlac(1, 7, UHDM, [], body))
    add('repro cdma2k_offset_wrap.py: 1100 empty General Page Requests',
        tlac(0, 7, GEN_PAGE, [rec_other(2, [0xab])], b'') * 1100)
    for order, fields in ((31, [(0x05, 8), (7, 8), (0, 2), (0x15, 6), (0x22, 8)]),
                          (21, [(3, 8), (1, 1), (0xa, 4), (2, 2), (0x5, 4)]),
                          (34, [(0, 8), (1, 1), (0xa, 4), (2, 2), (0x5, 4)])):
        add('repro cdma2k_order_ind_offsets.py: order %d' % order,
            tlac(0, 7, ORDER_IND, [], order_ind(order, 7, fields + [(0, 32)])))
    add('repro cdma2k_tmsi_zone.py frame 1: TMSI MSID_LEN 15',
        tlac(0, 7, GEN_PAGE, [rec_addr(B().put(5, 3).put(15, 4).put(0, 121), 16)], b''))
    add('repro cdma2k_tmsi_zone.py frame 2: TMSI MSID_LEN 0',
        tlac(0, 7, GEN_PAGE, [rec_addr(B().put(5, 3).put(0, 4).put(0, 1), 1)], b''))
    return F


def write_epdu(path, pdus, proto=b'cdma2k'):
    """Exported PDU (DLT 252) naming the cdma2k dissector, so cdma2k is
    also called without a tree."""
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 252))
        for i, pdu in enumerate(pdus):
            fr = (struct.pack('>HH', 12, len(proto)) + proto
                  + struct.pack('>HH', 0, 0) + pdu)
            f.write(struct.pack('<IIII', 1700001000 + i, 0, len(fr), len(fr)) + fr)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    os.makedirs(out, exist_ok=True)
    mf = main_frames()
    write_pcap(os.path.join(out, 'cdma2k-coverage.pcap'),
               [frame(d, i + 1, n) for i, (_, d, n) in enumerate(mf)])
    bf = malformed_frames()
    write_epdu(os.path.join(out, 'cdma2k-coverage-malformed.pcap'),
               [d for _, d, _ in bf])
    if os.environ.get('LIST'):
        for i, (desc, d, _) in enumerate(mf):
            print('%3d %s' % (i + 1, desc))
        print('-- malformed')
        for i, (desc, d, _) in enumerate(bf):
            print('%3d %s' % (i + 1, desc))


if __name__ == '__main__':
    main()
