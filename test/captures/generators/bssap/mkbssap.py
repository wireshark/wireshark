#!/usr/bin/env python3
# Generates test/captures/bssap_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the BSSAP dissector (packet-bssap.c).

The capture uses the Exported PDU link type (252) so that one file can hold
both SS7 transport (Exported PDU "mtp3" -> MTP3 -> SCCP) and PDUs handed
straight to a named dissector ("bssap_plus", "bsap", "bssap_le",
"bssap.imei"). Every packet is built from scratch with struct; no captured
traffic is used.

  - BSSAP+ (Gs interface) on SCCP SSN 98, its default SSN
  - BSSAP via the SCCP heuristic (SSN 254, which has no dissector), over
    connectionless (UDT) and connection-oriented (CR/CC/DT1) SCCP
  - BSSAP via the SUA heuristic (Exported PDU "sua")
  - BSAP and BSSAP-LE via Exported PDU

Usage: mkbssap.py <output directory>

Writes:
  bssap-coverage.pcap            valid messages (frame ranges in README.md)
  bssap-coverage-malformed.pcap  known unfixed bugs, truncated PDUs
"""

import os
import struct
import sys

# --- Encapsulation ---------------------------------------------------------

def exp_pdu(name, payload):
    n = name.encode()
    n += b'\0' * ((4 - len(n) % 4) % 4)
    return struct.pack('>HH', 12, len(n)) + n + struct.pack('>HH', 0, 0) + payload


def pcap(fn, pkts):
    with open(fn, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 252))
        for i, p in enumerate(pkts):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
            f.write(p)


def mtp3(sccp, opc=2, dpc=1, sls=0):
    """ITU MTP3 routing label, SIO national network / SCCP."""
    label = dpc | (opc << 14) | (sls << 28)
    return exp_pdu('mtp3', bytes([0x83]) + struct.pack('<I', label) + sccp)


def gt_addr(ssn):
    # Address indicator: route on SSN, SSN present, no PC, no GT
    return bytes([0x42, ssn])


def udt(data, called=98, calling=98):
    cd = gt_addr(called)
    cg = gt_addr(calling)
    p1 = 3
    p2 = p1 - 1 + 1 + len(cd)
    p3 = p2 - 1 + 1 + len(cg)
    return bytes([0x09, 0x00, p1, p2, p3, len(cd)]) + cd + \
        bytes([len(cg)]) + cg + bytes([len(data)]) + data


def sccp_cr(slr, data, called=254, calling=254):
    cd = gt_addr(called)
    cg = gt_addr(calling)
    # type, SLR, class, ptr to called, ptr to optional
    opt = bytes([0x04, len(cg)]) + cg + bytes([0x0f, len(data)]) + data + b'\0'
    return bytes([0x01]) + slr.to_bytes(3, 'little') + bytes([0x02, 2, 2 + len(cd)]) + \
        bytes([len(cd)]) + cd + opt


def sccp_cc(dlr, slr):
    return bytes([0x02]) + dlr.to_bytes(3, 'little') + slr.to_bytes(3, 'little') + bytes([0x02, 0x00])


def sccp_dt1(dlr, data):
    return bytes([0x06]) + dlr.to_bytes(3, 'little') + bytes([0x00, 0x01, len(data)]) + data


def sua_cldt(data, ssn=254):
    """SUA Connectionless Data Transfer carrying data."""
    def tlv(tag, val):
        ln = 4 + len(val)
        return struct.pack('>HH', tag, ln) + val + b'\0' * ((4 - ln % 4) % 4)
    def addr(ssn):
        # routing indicator 2 (route on SSN + PC), address indicator SSN present
        return struct.pack('>HH', 2, 0x0001) + tlv(0x8003, struct.pack('>I', ssn))
    body = tlv(0x0006, struct.pack('>I', 1))            # routing context
    body += tlv(0x0115, struct.pack('>I', 0))           # protocol class 0
    body += tlv(0x0102, addr(ssn))                      # source address
    body += tlv(0x0103, addr(ssn))                      # destination address
    body += tlv(0x0116, struct.pack('>I', 0))           # sequence control
    body += tlv(0x010b, data)                           # data
    hdr = struct.pack('>BBBBI', 1, 0, 7, 1, 8 + len(body))
    return exp_pdu('sua', hdr + body)


def plus(payload):
    """BSSAP+ over SCCP UDT, SSN 98 both ways."""
    return mtp3(udt(payload, 98, 98))


def plus_exp(payload):
    return exp_pdu('bssap_plus', payload)


def heur(payload, called=254, calling=254):
    return mtp3(udt(payload, called, calling))


# --- BSSAP+ information elements ------------------------------------------

def ie(iei, val):
    return bytes([iei, len(val)]) + val

IMSI = ie(0x01, bytes([0x29, 0x26, 0x10, 0x32, 0x54, 0x76, 0x98, 0x10]))  # 262012345678901
VLR = ie(0x02, bytes([0x91, 0x94, 0x71, 0x00, 0x10, 0xf2]))              # 491700012
TMSI = ie(0x03, bytes([0x11, 0x22, 0x33, 0x44]))
LAI = ie(0x04, bytes([0x62, 0xf2, 0x10, 0x12, 0x34]))                    # 262-01 LAC 0x1234
CHAN = ie(0x05, bytes([0x40]))                                           # channel needed
EMLPP = ie(0x06, bytes([0x03]))
TMSI_ST = ie(0x07, bytes([0x01]))
GS_CAUSE = ie(0x08, bytes([0x06]))
SGSN = ie(0x09, bytes([0x91, 0x94, 0x71, 0x00, 0x20, 0xf3]))             # 491700023
LU_TYPE = ie(0x0a, bytes([0x01]))
GCNID = ie(0x0b, bytes([0x62, 0xf2, 0x10, 0x00, 0x2a]))                  # 262-01 CN-Id 42
CM1 = ie(0x0d, bytes([0x33]))
MOBILE_ID = ie(0x0e, bytes([0xf4, 0x55, 0x66, 0x77, 0x88]))              # TMSI
REJ_CAUSE = ie(0x0f, bytes([0x0b]))                                      # PLMN not allowed
DET_GPRS = ie(0x10, bytes([0x02]))
DET_NON_GPRS = ie(0x11, bytes([0x01]))
INFO_REQ = ie(0x12, bytes([0x07]))
PTMSI = ie(0x13, bytes([0xc1, 0x02, 0x03, 0x04]))
IMEI = ie(0x14, bytes([0x53, 0x09, 0x77, 0x01, 0x23, 0x45, 0x67, 0xf8]))
IMEISV = ie(0x15, bytes([0x53, 0x09, 0x77, 0x01, 0x23, 0x45, 0x67, 0x21]))
# Time zone, and time zone and time
MM_INFO = ie(0x17, bytes([0x46, 0x40, 0x47, 0x62, 0x01, 0x31, 0x21, 0x43, 0x05, 0x40]))
CGI = ie(0x18, bytes([0x62, 0xf2, 0x10, 0x12, 0x34, 0x56, 0x00, 0x99]))  # RAI + CI 0x0099
LOC_AGE = ie(0x19, bytes([0x00, 0x2a]))
MS_STATE = ie(0x1a, bytes([0x05]))
ERR_MSG = ie(0x1b, bytes([0x63, 0x01, 0x02]))                             # unknown msg type 99
SAI = ie(0x1e, bytes([0x62, 0xf2, 0x10, 0x12, 0x34, 0x00, 0x07]))
RRLP_ACK = bytes([0x26])        # RRLP PDU: referenceNumber 1, assistanceDataAck

def dl_tunnel(ctl, payload):
    return ie(0x1c, bytes([ctl]) + payload)

def ul_tunnel(ctl, payload):
    return ie(0x1d, bytes([ctl]) + payload)

EXTRA = b'\xde\xad\xbe\xef'

# message type -> (mandatory IEs, optional IEs in order)
MESSAGES = [
    (1, [IMSI, VLR], [TMSI, LAI, CHAN, EMLPP, GCNID]),
    (2, [IMSI, GS_CAUSE], []),
    (7, [IMSI, VLR, dl_tunnel(0x10 | 0x04 | 0x02, RRLP_ACK)], []),
    (8, [IMSI, SGSN, ul_tunnel(0x10 | 0x03, RRLP_ACK)], []),
    (9, [IMSI, SGSN, LU_TYPE, CGI, CM1], [LAI, TMSI_ST, SAI, IMEISV]),
    (10, [IMSI, LAI], [MOBILE_ID]),
    (11, [IMSI, REJ_CAUSE], []),
    (12, [IMSI], [CGI, SAI]),
    (13, [IMSI], []),
    (14, [IMSI], []),
    (15, [IMSI, GS_CAUSE], []),
    (16, [IMSI], [CGI, SAI]),
    (17, [IMSI, SGSN, DET_GPRS], [CGI, SAI]),
    (18, [IMSI], []),
    (19, [IMSI, SGSN, DET_NON_GPRS], [CGI, LOC_AGE, SAI]),
    (20, [IMSI], []),
    (23, [IMSI, INFO_REQ], []),
    (24, [IMSI], [TMSI, PTMSI, IMEI, IMEISV, CGI, LOC_AGE, MS_STATE, SAI]),
    (26, [IMSI], [MM_INFO]),
    (29, [IMSI, GS_CAUSE, ERR_MSG], []),
    (31, [IMSI, GS_CAUSE], []),
]


def bssap_plus_frames():
    """Every message type: all IEs, all IEs plus extraneous data, mandatory
    IEs followed by each prefix of the optional IEs, and each optional IE
    on its own (so the earlier optional IEs are skipped)."""
    out = []
    for mt, mand, opt in MESSAGES:
        m = bytes([mt]) + b''.join(mand)
        variants = [m + b''.join(opt)]
        for k in range(len(opt)):
            variants.append(m + b''.join(opt[:k]))
        for k in range(1, len(opt)):
            variants.append(m + opt[k])
        variants.append(m + b''.join(opt) + EXTRA)
        seen = set()
        for v in variants:
            if v not in seen:
                seen.add(v)
                out.append(plus(v))
    return out


# --- BSSAP / BSAP / BSSAP-LE ----------------------------------------------

def bssmap(msg):
    return bytes([0x00, len(msg)]) + msg

def dtap(dlci, msg):
    return bytes([0x01, dlci, len(msg)]) + msg

BSSMAP_RESET = bytes([0x30, 0x04, 0x01, 0x20])        # Reset, cause: equipment failure? 0x20
BSSMAP_RESET_ACK = bytes([0x31])
DTAP_ID_REQ = bytes([0x05, 0x18, 0x01])               # MM Identity Request (IMSI)
DTAP_ID_RSP = bytes([0x05, 0x19, 0x08, 0x29, 0x26, 0x10, 0x32, 0x54, 0x76, 0x98, 0x10])
DTAP_TMSI_COMPL = bytes([0x05, 0x1b])


def reset_frames():
    """Reset Indication/Acknowledge: SGSN number, VLR number, neither, and
    each followed by extraneous data."""
    out = []
    for mt in (21, 22):
        for v in (SGSN, VLR, SGSN + EXTRA, VLR + EXTRA, TMSI_ST):
            out.append(plus(bytes([mt]) + v))
    return out


def tunnel_frames():
    """Tunnel payloads: data (TOM protocol discriminator 0, 1) and an empty
    payload, plus the reproducer of bssap_tunnel_len.py with
    the IE lengths and control octets that decode cleanly (frames noted in
    the README)."""
    out = []
    out.append(plus(bytes([7]) + IMSI + VLR + dl_tunnel(0x00 | 0x01, b'\x01\x02\x03')))
    out.append(plus(bytes([8]) + IMSI + SGSN + ul_tunnel(0x08 | 0x04, b'TIA136')))
    out.append(plus(bytes([7]) + IMSI + VLR + dl_tunnel(0x03, b'')))
    out.append(plus(bytes([8]) + IMSI + SGSN + ul_tunnel(0x03, b'')))
    return out


def tunnel_len_repro():
    """bssap_tunnel_len.py: IE length 0-3, control octet 0x10
    (RRLP) and 0x00 (data), uplink and downlink, followed by 8 octets of
    0x55. Returns (clean, malformed)."""
    clean, bad = [], []
    for ielen in (0, 1, 2, 3):
        for ctl in (0x10, 0x00):
            body = bytes([ctl]) * ielen
            for p in (bytes([8]) + IMSI + SGSN + bytes([0x1d, ielen]) + body + b'\x55' * 8,
                      bytes([7]) + IMSI + VLR + bytes([0x1c, ielen]) + body + b'\x55' * 8):
                # RRLP with a missing or one-octet PDU is malformed RRLP
                if ctl == 0x10 and ielen in (1, 2, 3):
                    bad.append(plus_exp(p))
                else:
                    clean.append(plus_exp(p))
    return clean, bad


def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else '.'
    main_pkts = []
    mal = []
    out = main_pkts

    out += bssap_plus_frames()
    out += reset_frames()
    out += tunnel_frames()
    # Unassigned message types: only the message type is shown
    for mt in (0, 3, 25, 30, 99):
        out.append(plus(bytes([mt]) + IMSI))

    # Reproducers (bssap_small.py frames 1 and 3)
    # 1) Paging Request with a TMSI where the IMSI should be: the TMSI IE is
    #    skipped as a whole and the VLR number after it is decoded
    out.append(plus_exp(bytes([1]) + TMSI + VLR))
    # 3) Location Update Request with a short (6 octet) cell global identity,
    #    followed by MS classmark 1
    out.append(plus_exp(bytes([9]) + IMSI + SGSN + LU_TYPE +
                        ie(0x18, bytes([0x62, 0xf2, 0x10, 0x00, 0x01, 0x05])) + CM1))
    clean, bad = tunnel_len_repro()
    out += clean
    mal += bad

    # BSSAP over SCCP UDT via the heuristic
    out.append(heur(bssmap(BSSMAP_RESET)))
    out.append(heur(bssmap(BSSMAP_RESET_ACK)))
    out.append(heur(dtap(0x00, DTAP_ID_REQ)))
    out.append(heur(dtap(0x83, DTAP_ID_RSP)))
    out.append(heur(dtap(0xc3, DTAP_TMSI_COMPL)))
    # Short SCCP payloads and payloads the heuristic rejects
    # (bssap_heur_short.py: 1-3 octets, then 00 02 40 01)
    # (the fifth one, a truncated BSSMAP Block, is in the malformed capture)
    for d in (b'\x00', b'\x00\x00', b'\x01\x00', b'\x05\x06\x07'):
        out.append(heur(d, 200, 200))
    # BSSMAP Block (0x40 followed by the CIC IEI 0x01): accepted
    out.append(heur(bssmap(bytes([0x40, 0x01, 0x00, 0x01, 0x04, 0x01, 0x20])), 200, 200))
    out.append(heur(b'\x00\x05\x30\x04', 200, 200))           # BSSMAP length wrong
    out.append(heur(b'\x00\x02\x40\x02', 200, 200))           # 0x40 not followed by 0x01
    out.append(heur(b'\x00\x01\x40', 200, 200))                # 0x40 with nothing after it
    out.append(heur(b'\x01\x00\x09\x05\x18', 200, 200))      # DTAP length wrong
    # BSSAP over SUA
    out.append(sua_cldt(bssmap(BSSMAP_RESET)))
    # Connection-oriented SCCP: BSSAP and BSSAP+
    out.append(mtp3(sccp_cr(0x000101, dtap(0x00, DTAP_ID_REQ))))
    out.append(mtp3(sccp_cc(0x000101, 0x000202), opc=1, dpc=2))
    out.append(mtp3(sccp_dt1(0x000202, dtap(0x00, DTAP_ID_RSP))))
    out.append(mtp3(sccp_dt1(0x000101, dtap(0x00, DTAP_TMSI_COMPL)), opc=1, dpc=2))
    out.append(mtp3(sccp_cr(0x000303, bytes([13]) + IMSI, 98, 98), sls=1))
    out.append(mtp3(sccp_cc(0x000303, 0x000404), opc=1, dpc=2, sls=1))
    out.append(mtp3(sccp_dt1(0x000303, bytes([14]) + IMSI), opc=1, dpc=2, sls=1))
    # BSAP, BSSAP-LE, bssap.imei
    out.append(exp_pdu('bsap', bssmap(BSSMAP_RESET)))
    out.append(exp_pdu('bsap', dtap(0x00, bytes([0x03, 0x00, 0x03]))))
    out.append(exp_pdu('bssap_le', bssmap(BSSMAP_RESET)))
    out.append(exp_pdu('bssap_le', dtap(0x00, DTAP_ID_REQ)))
    out.append(exp_pdu('bssap.imei', IMEI))

    # ---- malformed ----
    # Unknown BSSAP/BSAP PDU types (warning)
    out = mal
    out.append(exp_pdu('bssap', b'\x02\x01\x31'))
    out.append(exp_pdu('bsap', b'\x05\x00'))
    out.append(exp_pdu('bssap_le', b'\x07'))
    # Not fixed: VLR number with length 0 (bssap_small.py 4),
    # SGSN number with length 0, Global CN-Id with length 7 (bssap_small 2)
    out.append(plus_exp(bytes([1]) + IMSI + bytes([0x02, 0x00, 0x91]) + TMSI))
    out.append(plus_exp(bytes([9]) + IMSI + bytes([0x09, 0x00, 0x91]) + TMSI))
    out.append(plus_exp(bytes([1]) + IMSI + VLR + bytes([0x0b, 7, 0x02, 0xf8, 0x10, 0x00, 0x01, 0xaa, 0xbb])))
    # A missing mandatory IE in every message type (IMSI replaced by TMSI
    # status), and every message type cut after the message type
    for mt, mand, opt in MESSAGES:
        out.append(plus_exp(bytes([mt]) + TMSI_ST + b''.join(mand[1:])))
        out.append(plus_exp(bytes([mt]) + TMSI_ST * 5))
        out.append(plus_exp(bytes([mt])))
    out.append(plus_exp(bytes([29]) + GS_CAUSE + ERR_MSG))   # optional IMSI absent
    # Truncated IEs
    out.append(plus_exp(bytes([24]) + IMSI + bytes([0x03, 0x04, 0x11])))
    out.append(plus_exp(bytes([1]) + IMSI[:5]))
    out.append(plus_exp(b''))
    # Reset Indication/Acknowledge with no IE
    out.append(plus_exp(bytes([21])))
    out.append(plus_exp(bytes([22])))
    # bssap_heur_short.py frame 5: truncated BSSMAP Block
    out.append(heur(b'\x00\x02\x40\x01', 200, 200))
    # Truncated BSSAP
    out.append(exp_pdu('bssap', b'\x00'))
    out.append(exp_pdu('bssap', b'\x01\x00'))
    out.append(exp_pdu('bssap', b'\x00\x09\x30'))
    out.append(exp_pdu('bssap', b''))

    pcap(os.path.join(outdir, 'bssap-coverage.pcap'), main_pkts)
    pcap(os.path.join(outdir, 'bssap-coverage-malformed.pcap'), mal)


if __name__ == '__main__':
    main()
