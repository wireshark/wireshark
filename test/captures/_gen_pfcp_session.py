#!/usr/bin/env python3
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Generate pfcp_session.pcap: synthetic PFCP sessions for PFCP session
# tracking (pfcp.track_pfcp_session), and the GTP-U of the first one. The
# IMSIs and addresses are made up.
#
#   1  CP -> UP   Session Establishment Request with the IMSI in a User ID,
#                 a Create PDR whose F-TEID the UP chooses
#   2  UP -> CP   Session Establishment Response, no IMSI: UP F-SEID and a
#                 Created PDR with the N3 F-TEID of the UP
#   3  CP -> UP   Session Modification Request to the UP SEID, no IMSI: an
#                 Update FAR with the Outer Header Creation of the gNB
#   4  gNB -> UP  GTP-U T-PDU to the N3 TEID of the UP (frame 2)
#   5  UP -> gNB  GTP-U T-PDU to the TEID of the Outer Header Creation
#                 (frame 3)
#   6  CP -> UP   Session Establishment Request without a User ID: a new
#                 session without an IMSI
#   7  CP -> UP   Session Establishment Request with another IMSI: a new
#                 session, not the one of frame 6
#   8  CP -> UP   Session Establishment Request with a third IMSI: CP F-SEID
#   9  UP -> CP   Session Establishment Response, cause Request rejected
#  10  UP -> CP   Session Report Request to the CP SEID of frame 8: not of
#                 the session
#  11  CP -> UP   Two Session Modification Requests to the UP SEID of frame
#                 2 in one packet, the second with the CP F-SEID of frame 1
#  12  CP -> UP   Session Modification Request to the UP SEID: still of the
#                 session of frame 1

import struct
import sys

PFCP_PORT = 8805
GTPU_PORT = 2152

CP = (10, 0, 4, 1)
UP = (10, 0, 4, 2)
UP_N3 = (10, 0, 5, 2)
GNB = (10, 0, 5, 1)

IMSI = '001010000000003'
IMSI_2 = '001010000000005'
IMSI_3 = '001010000000009'

SESSION_ESTABLISHMENT_REQUEST = 50
SESSION_ESTABLISHMENT_RESPONSE = 51
SESSION_MODIFICATION_REQUEST = 52
SESSION_REPORT_REQUEST = 56

REQUEST_ACCEPTED = 1
REQUEST_REJECTED = 64

CP_SEID = 0xc1
UP_SEID = 0xa1
CP_SEID_2 = 0xc2
CP_SEID_3 = 0xc3
CP_SEID_4 = 0xc4

UP_N3_TEID = 0x3101
GNB_TEID = 0x4101


def tbcd(digits):
    if len(digits) % 2:
        digits += 'f'
    return bytes(int(digits[i + 1], 16) << 4 | int(digits[i], 16)
                 for i in range(0, len(digits), 2))


def ie(ie_type, value):
    return struct.pack('!HH', ie_type, len(value)) + value


def node_id_ie(ipv4):
    return ie(60, b'\x00' + bytes(ipv4))


def cause_ie(cause=REQUEST_ACCEPTED):
    return ie(19, bytes((cause,)))


def f_seid_ie(seid, ipv4):
    return ie(57, struct.pack('!BQ4s', 0x02, seid, bytes(ipv4)))


def user_id_ie(imsi):
    value = tbcd(imsi)
    return ie(141, struct.pack('!BB', 0x01, len(value)) + value)  # IMSIF


def pdr_id_ie(rule_id):
    return ie(56, struct.pack('!H', rule_id))


def f_teid_choose_ie():
    return ie(21, b'\x05')  # CH, V4


def f_teid_ie(teid, ipv4):
    return ie(21, struct.pack('!BI4s', 0x01, teid, bytes(ipv4)))  # V4


def create_pdr_ie():
    pdi = ie(2, ie(20, b'\x00') + f_teid_choose_ie())  # Source Interface: Access
    return ie(1, pdr_id_ie(1) + ie(29, struct.pack('!I', 100)) + pdi)


def created_pdr_ie(teid, ipv4):
    return ie(8, pdr_id_ie(1) + f_teid_ie(teid, ipv4))


def update_far_ie(teid, ipv4):
    # Outer Header Creation: GTP-U/UDP/IPv4
    ohc = ie(84, struct.pack('!HI4s', 0x0100, teid, bytes(ipv4)))
    fwd = ie(11, ie(42, b'\x00') + ohc)  # Destination Interface: Access
    return ie(10, ie(108, struct.pack('!I', 1)) + fwd)


def pfcp(msg_type, seid, seq, *ies, follow_on=False):
    body = b''.join(ies)
    # Flags: version 1, FO (another message follows), SEID present
    flags = 0x21 | (0x04 if follow_on else 0)
    return struct.pack('!BBHQ', flags, msg_type, 12 + len(body), seid) + \
        struct.pack('!I', seq << 8) + body


def gtpu_tpdu(teid):
    # An IPv4 packet with protocol 253 (for experimentation) as the T-PDU
    tpdu = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 24, 0, 0x4000, 64, 253, 0,
                       bytes((192, 168, 0, 1)), bytes((192, 168, 0, 2))) + bytes(4)
    return struct.pack('!BBHI', 0x30, 0xff, len(tpdu), teid) + tpdu


def frame(src, dst, payload, port=PFCP_PORT):
    eth = b'\x00\x11\x22\x33\x44\x55' + b'\x66\x77\x88\x99\xaa\xbb' + b'\x08\x00'
    udp = struct.pack('!HHHH', port, port, 8 + len(payload), 0)
    total = 20 + len(udp) + len(payload)
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, total, 0, 0x4000, 64, 17, 0,
                     bytes(src), bytes(dst))
    return eth + ip + udp + payload


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else 'pfcp_session.pcap'
    frames = [
        frame(CP, UP, pfcp(
            SESSION_ESTABLISHMENT_REQUEST, 0, 1,
            node_id_ie(CP), f_seid_ie(CP_SEID, CP), user_id_ie(IMSI),
            create_pdr_ie())),
        frame(UP, CP, pfcp(
            SESSION_ESTABLISHMENT_RESPONSE, CP_SEID, 1,
            node_id_ie(UP), cause_ie(), f_seid_ie(UP_SEID, UP),
            created_pdr_ie(UP_N3_TEID, UP_N3))),
        frame(CP, UP, pfcp(
            SESSION_MODIFICATION_REQUEST, UP_SEID, 2,
            update_far_ie(GNB_TEID, GNB))),
        frame(GNB, UP_N3, gtpu_tpdu(UP_N3_TEID), GTPU_PORT),
        frame(UP_N3, GNB, gtpu_tpdu(GNB_TEID), GTPU_PORT),
        frame(CP, UP, pfcp(
            SESSION_ESTABLISHMENT_REQUEST, 0, 3,
            node_id_ie(CP), f_seid_ie(CP_SEID_2, CP))),
        frame(CP, UP, pfcp(
            SESSION_ESTABLISHMENT_REQUEST, 0, 4,
            node_id_ie(CP), f_seid_ie(CP_SEID_3, CP), user_id_ie(IMSI_2))),
        frame(CP, UP, pfcp(
            SESSION_ESTABLISHMENT_REQUEST, 0, 5,
            node_id_ie(CP), f_seid_ie(CP_SEID_4, CP), user_id_ie(IMSI_3))),
        frame(UP, CP, pfcp(
            SESSION_ESTABLISHMENT_RESPONSE, CP_SEID_4, 5,
            node_id_ie(UP), cause_ie(REQUEST_REJECTED))),
        frame(UP, CP, pfcp(
            SESSION_REPORT_REQUEST, CP_SEID_4, 6)),
        frame(CP, UP, pfcp(
            SESSION_MODIFICATION_REQUEST, UP_SEID, 7, follow_on=True) + pfcp(
            SESSION_MODIFICATION_REQUEST, UP_SEID, 8, f_seid_ie(CP_SEID, CP))),
        frame(CP, UP, pfcp(
            SESSION_MODIFICATION_REQUEST, UP_SEID, 9)),
    ]
    with open(path, 'wb') as f:
        # pcap global header, LINKTYPE_ETHERNET (1)
        f.write(struct.pack('!IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, rec in enumerate(frames):
            f.write(struct.pack('!IIII', i, 0, len(rec), len(rec)))
            f.write(rec)


if __name__ == '__main__':
    main()
