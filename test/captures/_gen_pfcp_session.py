#!/usr/bin/env python3
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Generate pfcp_session.pcap: a synthetic PFCP session for PFCP session
# tracking (pfcp.track_pfcp_session). The IMSI and addresses are made up.
#
#   1  CP -> UP  Session Establishment Request with the IMSI in a User ID
#   2  UP -> CP  Session Establishment Response, no IMSI: UP F-SEID
#   3  CP -> UP  Session Modification Request to the UP SEID, no IMSI

import struct
import sys

PFCP_PORT = 8805

CP = (10, 0, 4, 1)
UP = (10, 0, 4, 2)

IMSI = '001010000000003'

SESSION_ESTABLISHMENT_REQUEST = 50
SESSION_ESTABLISHMENT_RESPONSE = 51
SESSION_MODIFICATION_REQUEST = 52

CP_SEID = 0xc1
UP_SEID = 0xa1


def tbcd(digits):
    if len(digits) % 2:
        digits += 'f'
    return bytes(int(digits[i + 1], 16) << 4 | int(digits[i], 16)
                 for i in range(0, len(digits), 2))


def ie(ie_type, value):
    return struct.pack('!HH', ie_type, len(value)) + value


def node_id_ie(ipv4):
    return ie(60, b'\x00' + bytes(ipv4))


def cause_ie():
    return ie(19, b'\x01')  # Request accepted


def f_seid_ie(seid, ipv4):
    return ie(57, struct.pack('!BQ4s', 0x02, seid, bytes(ipv4)))


def user_id_ie(imsi):
    value = tbcd(imsi)
    return ie(141, struct.pack('!BB', 0x01, len(value)) + value)  # IMSIF


def pfcp(msg_type, seid, seq, *ies):
    body = b''.join(ies)
    # Flags: version 1, SEID present
    return struct.pack('!BBHQ', 0x21, msg_type, 12 + len(body), seid) + \
        struct.pack('!I', seq << 8) + body


def frame(src, dst, payload):
    eth = b'\x00\x11\x22\x33\x44\x55' + b'\x66\x77\x88\x99\xaa\xbb' + b'\x08\x00'
    udp = struct.pack('!HHHH', PFCP_PORT, PFCP_PORT, 8 + len(payload), 0)
    total = 20 + len(udp) + len(payload)
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, total, 0, 0x4000, 64, 17, 0,
                     bytes(src), bytes(dst))
    return eth + ip + udp + payload


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else 'pfcp_session.pcap'
    frames = [
        frame(CP, UP, pfcp(
            SESSION_ESTABLISHMENT_REQUEST, 0, 1,
            node_id_ie(CP), f_seid_ie(CP_SEID, CP), user_id_ie(IMSI))),
        frame(UP, CP, pfcp(
            SESSION_ESTABLISHMENT_RESPONSE, CP_SEID, 1,
            node_id_ie(UP), cause_ie(), f_seid_ie(UP_SEID, UP))),
        frame(CP, UP, pfcp(
            SESSION_MODIFICATION_REQUEST, UP_SEID, 2)),
    ]
    with open(path, 'wb') as f:
        # pcap global header, LINKTYPE_ETHERNET (1)
        f.write(struct.pack('!IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, rec in enumerate(frames):
            f.write(struct.pack('!IIII', i, 0, len(rec), len(rec)))
            f.write(rec)


if __name__ == '__main__':
    main()
