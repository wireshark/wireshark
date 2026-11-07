#!/usr/bin/env python3
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Generate gtpv2_session.pcap: synthetic GTPv2-C and GTP-U messages for
# GTP session tracking (gtp.track_gtp_session). The IMSIs and addresses
# are made up.
#
# UE A, S11 and S1-U:
#   1  MME -> SGW  Create Session Request with the IMSI
#   2  SGW -> MME  Create Session Response, no IMSI: S11 SGW F-TEID and
#                  S1-U SGW F-TEID
#   3  MME -> SGW  Modify Bearer Request to the S11 SGW TEID, no IMSI
#   4  eNB -> SGW  GTP-U T-PDU to the S1-U SGW TEID
#
# UE B, S5/S8, where an S11 message without a session carries the PGW
# S5/S8 F-TEID of the session:
#   5  SGW -> PGW  Create Session Request with the IMSI
#   6  PGW -> SGW  Create Session Response: PGW S5/S8 F-TEID
#   7  SGW -> MME  Create Session Response whose request is not in the
#                  capture (so no session): S11 SGW F-TEID and the PGW
#                  S5/S8 F-TEID of frame 6
#   8  SGW -> PGW  Modify Bearer Request to the PGW S5/S8 TEID, no IMSI
#
# UE C, whose session started before the capture, and UE D:
#   9  MME -> SGW  Modify Bearer Request to an unknown S11 SGW TEID, no
#                  IMSI: a new session without an IMSI
#  10  MME -> SGW  Create Session Request with the IMSI of UE D: a new
#                  session, not the one of frame 9
#
# UE E, whose Create Session Request is rejected:
#  11  MME -> SGW  Create Session Request with the IMSI: S11 MME F-TEID
#  12  SGW -> MME  Create Session Response, cause No resources available
#  13  SGW -> MME  Downlink Data Notification to the S11 MME TEID of
#                  frame 11: not of the session
#
# UE F, whose Create Session Request on S11 has the PGW S5/S8 F-TEID with
# the reserved TEID 0:
#  14  MME -> SGW  Create Session Request with the IMSI: S11 MME F-TEID and
#                  PGW S5/S8 F-TEID with TEID 0
#  15  SGW -> PGW  Delete PDN Connection Set Request with TEID 0: not of
#                  the session
#  16  SGW -> PGW  Delete Session Request to the S11 MME TEID of frame 14,
#                  but to the PGW address: not of the session

import struct
import sys

GTPV2_PORT = 2123
GTPU_PORT = 2152

MME = (10, 0, 0, 1)
SGW_S11 = (10, 0, 0, 2)
SGW_S5 = (10, 0, 1, 2)
PGW = (10, 0, 1, 3)
SGW_S1U = (10, 0, 2, 2)
ENB = (10, 0, 3, 1)

IMSI_A = '001010000000001'
IMSI_B = '001010000000002'
IMSI_D = '001010000000004'
IMSI_E = '001010000000008'
IMSI_F = '001010000000010'

# GTPv2 message types
CREATE_SESSION_REQUEST = 32
CREATE_SESSION_RESPONSE = 33
MODIFY_BEARER_REQUEST = 34
DELETE_SESSION_REQUEST = 36
DELETE_PDN_CONNECTION_SET_REQUEST = 101
DOWNLINK_DATA_NOTIFICATION = 176

# GTPv2 causes
REQUEST_ACCEPTED = 16
NO_RESOURCES_AVAILABLE = 73

# F-TEID interface types (3GPP TS 29.274 table 8.22-1)
IF_S1U_ENB = 0
IF_S1U_SGW = 1
IF_S5S8_SGW_GTPC = 6
IF_S5S8_PGW_GTPC = 7
IF_S11_MME_GTPC = 10
IF_S11_SGW_GTPC = 11


def tbcd(digits):
    if len(digits) % 2:
        digits += 'f'
    return bytes(int(digits[i + 1], 16) << 4 | int(digits[i], 16)
                 for i in range(0, len(digits), 2))


def ie(ie_type, value, instance=0):
    return struct.pack('!BHB', ie_type, len(value), instance) + value


def imsi_ie(imsi):
    return ie(1, tbcd(imsi))


def cause_ie(cause=REQUEST_ACCEPTED):
    return ie(2, bytes((cause, 0)))


def f_teid_ie(if_type, teid, ipv4, instance=0):
    return ie(87, struct.pack('!BI4s', 0x80 | if_type, teid, bytes(ipv4)), instance)


def bearer_context_ie(*ies):
    return ie(93, ie(73, b'\x05') + b''.join(ies))


def gtpv2(msg_type, teid, seq, *ies):
    body = b''.join(ies)
    # Flags: version 2, TEID present
    return struct.pack('!BBHI', 0x48, msg_type, 8 + len(body), teid) + \
        struct.pack('!I', seq << 8) + body


def gtpu_tpdu(teid):
    # An IPv4 packet with protocol 253 (for experimentation) as the T-PDU
    tpdu = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 24, 0, 0x4000, 64, 253, 0,
                       bytes((192, 168, 0, 1)), bytes((192, 168, 0, 2))) + bytes(4)
    return struct.pack('!BBHI', 0x30, 0xff, len(tpdu), teid) + tpdu


def frame(src, dst, port, payload):
    eth = b'\x00\x11\x22\x33\x44\x55' + b'\x66\x77\x88\x99\xaa\xbb' + b'\x08\x00'
    udp = struct.pack('!HHHH', port, port, 8 + len(payload), 0)
    total = 20 + len(udp) + len(payload)
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, total, 0, 0x4000, 64, 17, 0,
                     bytes(src), bytes(dst))
    return eth + ip + udp + payload


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else 'gtpv2_session.pcap'
    frames = [
        # UE A
        frame(MME, SGW_S11, GTPV2_PORT, gtpv2(
            CREATE_SESSION_REQUEST, 0, 1,
            imsi_ie(IMSI_A),
            f_teid_ie(IF_S11_MME_GTPC, 0x1001, MME))),
        frame(SGW_S11, MME, GTPV2_PORT, gtpv2(
            CREATE_SESSION_RESPONSE, 0x1001, 1,
            cause_ie(),
            f_teid_ie(IF_S11_SGW_GTPC, 0x2001, SGW_S11),
            bearer_context_ie(cause_ie(), f_teid_ie(IF_S1U_SGW, 0x3001, SGW_S1U)))),
        frame(MME, SGW_S11, GTPV2_PORT, gtpv2(
            MODIFY_BEARER_REQUEST, 0x2001, 2,
            bearer_context_ie(f_teid_ie(IF_S1U_ENB, 0x4001, ENB)))),
        frame(ENB, SGW_S1U, GTPU_PORT, gtpu_tpdu(0x3001)),
        # UE B
        frame(SGW_S5, PGW, GTPV2_PORT, gtpv2(
            CREATE_SESSION_REQUEST, 0, 0x10,
            imsi_ie(IMSI_B),
            f_teid_ie(IF_S5S8_SGW_GTPC, 0x5001, SGW_S5))),
        frame(PGW, SGW_S5, GTPV2_PORT, gtpv2(
            CREATE_SESSION_RESPONSE, 0x5001, 0x10,
            cause_ie(),
            f_teid_ie(IF_S5S8_PGW_GTPC, 0x7001, PGW, instance=1))),
        frame(SGW_S11, MME, GTPV2_PORT, gtpv2(
            CREATE_SESSION_RESPONSE, 0x1002, 0x20,
            cause_ie(),
            f_teid_ie(IF_S11_SGW_GTPC, 0x2002, SGW_S11),
            f_teid_ie(IF_S5S8_PGW_GTPC, 0x7001, PGW, instance=1))),
        frame(SGW_S5, PGW, GTPV2_PORT, gtpv2(
            MODIFY_BEARER_REQUEST, 0x7001, 0x11)),
        # UE C
        frame(MME, SGW_S11, GTPV2_PORT, gtpv2(
            MODIFY_BEARER_REQUEST, 0x2003, 0x30,
            bearer_context_ie(f_teid_ie(IF_S1U_ENB, 0x4003, ENB)))),
        # UE D
        frame(MME, SGW_S11, GTPV2_PORT, gtpv2(
            CREATE_SESSION_REQUEST, 0, 0x40,
            imsi_ie(IMSI_D),
            f_teid_ie(IF_S11_MME_GTPC, 0x1004, MME))),
        # UE E
        frame(MME, SGW_S11, GTPV2_PORT, gtpv2(
            CREATE_SESSION_REQUEST, 0, 0x50,
            imsi_ie(IMSI_E),
            f_teid_ie(IF_S11_MME_GTPC, 0x1005, MME))),
        frame(SGW_S11, MME, GTPV2_PORT, gtpv2(
            CREATE_SESSION_RESPONSE, 0x1005, 0x50,
            cause_ie(NO_RESOURCES_AVAILABLE))),
        frame(SGW_S11, MME, GTPV2_PORT, gtpv2(
            DOWNLINK_DATA_NOTIFICATION, 0x1005, 0x51)),
        # UE F
        frame(MME, SGW_S11, GTPV2_PORT, gtpv2(
            CREATE_SESSION_REQUEST, 0, 0x60,
            imsi_ie(IMSI_F),
            f_teid_ie(IF_S11_MME_GTPC, 0x1006, MME),
            f_teid_ie(IF_S5S8_PGW_GTPC, 0, PGW, instance=1))),
        frame(SGW_S5, PGW, GTPV2_PORT, gtpv2(
            DELETE_PDN_CONNECTION_SET_REQUEST, 0, 0x61)),
        frame(SGW_S5, PGW, GTPV2_PORT, gtpv2(
            DELETE_SESSION_REQUEST, 0x1006, 0x62)),
    ]
    with open(path, 'wb') as f:
        # pcap global header, LINKTYPE_ETHERNET (1)
        f.write(struct.pack('!IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, rec in enumerate(frames):
            f.write(struct.pack('!IIII', i, 0, len(rec), len(rec)))
            f.write(rec)


if __name__ == '__main__':
    main()
