#!/usr/bin/env python3
# Generates test/captures/ehs_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the EHS dissector
(packet-ehs.c, NASA MSFC "Enhanced HOSC System").

EHS has no port of its own (Decode As on UDP only), so the packets are
Exported PDU records (linktype 252) that name the "ehs" dissector, as a
capture exported from Wireshark would. Each packet has a 16 octet
primary header (version, project, support and data modes, mission,
protocol, ground receipt time, flags, HOSC packet size), a secondary
header whose layout depends on the protocol (TDM with CNT/MET and OBT
times and frame status bytes, PSEUDO, AOS/LOS, PDSS payload and core
CCSDS, payload BPDU, UDSM; the others are skipped by size), then for
the CCSDS based protocols a CCSDS space packet (handed to the CCSDS
dissector) and for AOS/LOS and UDSM a data zone. Every packet is built
from scratch with struct; no captured traffic is used.

Usage: mkehs.py <output directory>

Writes:
  ehs-coverage.pcap            every protocol, every TDM option,
                               CCSDS packets with and without a
                               secondary header, both data zones
  ehs-coverage-malformed.pcap  headers and data zones cut short
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct

from pkt import LINKTYPE_WIRESHARK_UPPER_PDU, exp_pdu, write_pcap

TDM, NASCOM, PSEUDO, TDS, TEST, GSE, CUSTOM, HDRS_DQ, CSS, AOS_LOS = range(1, 11)
PDSS_PAYLOAD_CCSDS, PDSS_CORE_CCSDS, PDSS_PAYLOAD_BPDU, PDSS_UDSM, PDSS_RPSM = range(11, 16)


def primary(protocol, size, version=1, project=3, support=1, data_mode=1,
            mission=42, t=(126, 307, 12, 34, 56, 7), flags=0x08):
    y, jd, h, m, s, tenths = t
    return struct.pack(">BBBBBHBBBBBBBH", (version << 4) | project,
                       (support << 4) | data_mode, mission, protocol, y, jd,
                       h, m, s, (tenths << 4) | flags, 0, 0, 0, size)


def ehs(protocol, secondary, rest=b"", **kw):
    body = secondary + rest
    return primary(protocol, 16 + len(body), **kw) + body


def common_sh(first, vcdu=0x123456, stream=0x80, vc=5, sync=0x1ACF,
              pkt_id=0x1800 | 0x123):
    """AOS/LOS and PDSS secondary header: status octet, VCDU sequence,
    data stream ID, a reserved octet, GSE/payload/APID word, virtual
    channel and the reserved sync word."""
    return (bytes([first]) + struct.pack(">I", vcdu)[1:] +
            bytes([stream, 0]) + struct.pack(">HHH", pkt_id, vc, sync))


def ccsds(apid, data, sec=True, seq=0xC001):
    """CCSDS space packet: primary header (secondary header flag and
    APID), sequence word, length; a 10 octet secondary header."""
    first = 0x0800 * sec | (apid & 0x7FF)
    body = (b"\x00\x00\x00\x01\x00\x02\x30\x00\x01\x05" if sec else b"") + data
    return struct.pack(">HHH", first, seq, len(body) - 1) + body


def tdm_sh(minor=2, cntmet=True, obt=True, mjfs=True, majors=1,
           status=0xFF, status2=0xFF):
    sh = struct.pack(">BB", status, status2)
    sh += struct.pack(">HHHH", 1, 2, 3, 4) + b"\0\0" + struct.pack(">H", 0x0A0B)
    sh += bytes([3, 8, minor - 1, (0x80 * cntmet) | (0x40 * obt) | (0x20 * mjfs)])
    if cntmet:
        sh += struct.pack(">BHBBBB", 126, 100, 1, 2, 3, 0x40)
    if obt:
        sh += struct.pack(">BHBBBB", 125, 365, 23, 59, 59, 0x90)
        # the OBT flags word is shown, but the offset does not move past it
    if mjfs:
        sh += bytes([majors - 1]) + bytes([0xE0 | j for j in range(majors)])
    sh += bytes([0x01 << (j % 8) for j in range(minor)])
    return struct.pack(">H", 2 + len(sh)) + sh


def pseudo_sh():
    return struct.pack(">HHHH", 0, 0x0102, 0x0304, 0x0506)


def udsm_dz(event=1):
    return (bytes([0x80, 0]) + struct.pack(">H", 0x1800 | 0x55) +
            struct.pack(">BHBBB", 126, 1, 0, 0, 0) +
            struct.pack(">BHBBB", 126, 2, 23, 59, 58) + b"\0\0" +
            struct.pack(">HHHHBB", 1000, 1, 2, 3, event, 4))


def main_frames():
    P = []
    # 1: TDM with CNT/MET time, OBT time, two major and three minor frame
    #    status bytes, then a CCSDS packet with a secondary header
    P.append(ehs(TDM, tdm_sh(minor=3, majors=2), ccsds(0x10, b"tdm data")))
    # 2: TDM without the optional parts, one minor frame, other status
    #    bits; CCSDS packet without a secondary header
    P.append(ehs(TDM, tdm_sh(minor=1, cntmet=False, obt=False, mjfs=False,
                             status=0x2A, status2=0x55),
                 ccsds(0x11, b"\x01\x02" * 5, sec=False), project=1, support=2,
                 data_mode=16, flags=0x03))
    # 3: TDM with only the major frame status
    P.append(ehs(TDM, tdm_sh(minor=2, cntmet=False, obt=False, majors=3),
                 ccsds(0x12, b"\x00"), project=4, support=7, data_mode=15))
    # 4: PSEUDO telemetry (8 octet secondary header) and a CCSDS packet
    P.append(ehs(PSEUDO, pseudo_sh(), ccsds(0x13, b"pseudo"), project=0,
                 support=0, data_mode=0))
    # 5: AOS/LOS: secondary header, CCSDS packet whose data is the
    #    AOS/LOS data zone (Ku-band AOS)
    P.append(ehs(AOS_LOS, common_sh(0x3F),
                 ccsds(0x14, b"\x03\x00" + b"\0" * 8, sec=False)))
    # 6: AOS/LOS, S-band LOS, CCSDS with a secondary header
    P.append(ehs(AOS_LOS, common_sh(0x80),
                 ccsds(0x14, b"\x00\x00")))
    # 7: PDSS payload CCSDS packet (sequence error bits)
    P.append(ehs(PDSS_PAYLOAD_CCSDS, common_sh(0x16, stream=0x00),
                 ccsds(0x20, b"payload")))
    # 8: PDSS core CCSDS packet
    P.append(ehs(PDSS_CORE_CCSDS, common_sh(0x21, stream=0x00,
                                            pkt_id=0x0300),
                 ccsds(0x21, b"core-data!", sec=False)))
    # 9: PDSS payload BPDU (no CCSDS packet)
    P.append(ehs(PDSS_PAYLOAD_BPDU, common_sh(0x0F, stream=0x80),
                 b"BPDU-DATA"))
    # 10: PDSS UDSM: CCSDS packet whose data is the UDSM data zone
    P.append(ehs(PDSS_UDSM, common_sh(0x40),
                 ccsds(0x22, udsm_dz(1), sec=False)))
    # 11: PDSS UDSM, CCSDS with a secondary header, event 3
    P.append(ehs(PDSS_UDSM, common_sh(0x00),
                 ccsds(0x22, udsm_dz(3))))
    # 12-20: protocols whose secondary header is only skipped: NASCOM,
    #        TDS, TEST, GSE (16 octets), CUSTOM, HDRS_DQ, CSS, PDSS_RPSM and
    #        "All" (0)
    for proto in (NASCOM, TDS, TEST, GSE, CUSTOM, HDRS_DQ, CSS, PDSS_RPSM, 0):
        size = 16 if proto == GSE else 12
        P.append(ehs(proto, bytes(range(size)), b"rest", version=2))
    # 21: unknown protocol 0x20 (skipped as 12 octets), unknown project,
    #     support and data mode
    P.append(ehs(0x20, b"\xee" * 12, b"x", project=9, support=8,
                 data_mode=0, mission=0, flags=0x00))
    return [exp_pdu("ehs", p) for p in P]


def malformed_frames():
    P = []
    # 1: only the primary header
    P.append(primary(TDM, 16))
    # 2: TDM secondary header cut in the CNT/MET time
    P.append(ehs(TDM, tdm_sh())[:16 + 24])
    # 3: AOS/LOS without a CCSDS packet
    P.append(ehs(AOS_LOS, common_sh(0x01)))
    # 4: UDSM data zone cut short
    P.append(ehs(PDSS_UDSM, common_sh(0x00),
                 ccsds(0x22, udsm_dz(2), sec=False)[:16]))
    # 5: TDM with a secondary header length larger than the packet
    P.append(ehs(TDM, b"\x40\x00" + tdm_sh()[2:], ccsds(1, b"x")))
    return [exp_pdu("ehs", p) for p in P]


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "."
    write_pcap(os.path.join(out, "ehs-coverage.pcap"), main_frames(),
               LINKTYPE_WIRESHARK_UPPER_PDU)
    write_pcap(os.path.join(out, "ehs-coverage-malformed.pcap"),
               malformed_frames(), LINKTYPE_WIRESHARK_UPPER_PDU)


if __name__ == "__main__":
    main()
