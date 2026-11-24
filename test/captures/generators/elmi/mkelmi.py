#!/usr/bin/env python3
# Generates test/captures/elmi_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the E-LMI dissector
(packet-elmi.c, MEF 16 Ethernet Local Management Interface).

E-LMI runs directly over Ethernet with ethertype 0x88EE. A message
holds a protocol version, a message type (0x75 Status enquiry, 0x7D
Status) and information elements (tag, length, value); the UNI Status,
EVC Status and CE-VLAN ID/EVC Map elements carry sub-information
elements. A tag of 0 (the Ethernet padding) ends the message. Every
packet is built from scratch with struct; no captured traffic is used.

Usage: mkelmi.py <output directory>

Writes:
  elmi-coverage.pcap            enquiries and status messages with
                                every element and sub-element, the
                                long UNI Identifier of the fix
  elmi-coverage-malformed.pcap  elements cut short
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct

from pkt import LINKTYPE_ETHERNET, eth, write_pcap

ETHERTYPE_ELMI = 0x88EE
CE, UNIN = 1, 2          # MAC address suffixes of the CE and the UNI-N


def ie(tag, value, length=None):
    return bytes([tag, len(value) if length is None else length]) + value


def sub(tag, value, length=None):
    return ie(tag, value, length)


def report(t):
    return ie(0x01, bytes([t]))


def seq(snd, rcv):
    return ie(0x02, bytes([snd, rcv]))


def data_inst(v):
    return ie(0x03, b"\x00" + struct.pack(">I", v))


def uni_status(map_type, subs):
    return ie(0x11, bytes([map_type]) + b"".join(subs))


def evc_status(ref, status, subs):
    return ie(0x21, struct.pack(">HB", ref, status) + b"".join(subs))


def vlan_evc(ref, last, mapseq, prio, default, subs):
    b1 = (0x40 if last else 0) | (mapseq & 0x3f)
    b2 = (0x02 if prio else 0) | (0x01 if default else 0)
    return ie(0x22, struct.pack(">HBB", ref, b1, b2) + b"".join(subs))


def bw_profile(flags, cir, cbs, eir, ebs, prio_bits):
    """Bandwidth profile sub-element: flags, CIR (magnitude, multiplier),
    CBS, EIR, EBS and the user priority bits."""
    v = bytes([flags])
    v += struct.pack(">BH", *cir) + struct.pack(">BB", *cbs)
    v += struct.pack(">BH", *eir) + struct.pack(">BB", *ebs)
    v += bytes([prio_bits])
    return sub(0x71, v)


def msg(mtype, ies, ver=1, to_ce=True):
    payload = bytes([ver, mtype]) + b"".join(ies)
    return eth(payload, ETHERTYPE_ELMI, UNIN if to_ce else CE,
               CE if to_ce else UNIN)


def main_frames():
    F = []
    # 1: E-LMI check enquiry from the CE
    F.append(msg(0x75, [report(1), seq(1, 0)], to_ce=False))
    # 2: E-LMI check status from the UNI-N: report, sequence numbers,
    #    data instance
    F.append(msg(0x7D, [report(1), seq(1, 1), data_inst(0x00000001)]))
    # 3: full status enquiry
    F.append(msg(0x75, [report(0), seq(2, 1)], to_ce=False))
    # 4: full status: UNI status (bundling) with a UNI identifier and a
    #    bandwidth profile; an EVC status with EVC parameters, an EVC
    #    identifier and a per-CoS bandwidth profile; a CE-VLAN ID/EVC map
    #    with two map entries and a default EVC
    F.append(msg(0x7D, [
        report(0), seq(2, 2), data_inst(0x00000002),
        uni_status(0x03, [sub(0x51, b"UNI-1/0/1"),
                          bw_profile(0x06, (3, 1000), (2, 16),
                                     (1, 500), (0, 8), 0x00)]),
        evc_status(100, 0x02, [sub(0x61, b"\x00"), sub(0x62, b"EVC-100"),
                               bw_profile(0x01, (4, 65535), (5, 255),
                                          (6, 1), (7, 1), 0xa5)]),
        vlan_evc(100, True, 1, False, True,
                 [sub(0x63, struct.pack(">HHH", 10, 20, 30))]),
    ]))
    # 5: full status continued: all-to-one bundling, a multipoint EVC with
    #    every EVC status and the remaining user priority bits
    F.append(msg(0x7D, [
        report(3), seq(3, 3), data_inst(3),
        uni_status(0x01, [sub(0x51, b"U")]),
        evc_status(1, 0x00, [sub(0x61, b"\x01")]),
        evc_status(2, 0x01, []),
        evc_status(3, 0x03, []),
        evc_status(4, 0x04, []),
        evc_status(5, 0x05, [bw_profile(0x07, (0, 0), (0, 0), (0, 0),
                                        (0, 0), 0x5a)]),
        vlan_evc(5, False, 2, True, False,
                 [sub(0x63, struct.pack(">H", 4094))]),
    ]))
    # 6: single EVC asynchronous status; unknown EVC status type,
    #    service multiplexing map type, an unknown sub-element (0x7f)
    F.append(msg(0x7D, [
        report(2), seq(4, 4),
        uni_status(0x02, [sub(0x7f, b"\x01\x02\x03")]),
        evc_status(6, 0x07, [sub(0x62, b"")]),
    ]))
    # 7: unknown report type, unknown map type, unknown information
    #    element 0x40 (skipped by its length), version 2
    F.append(msg(0x7D, [report(9), uni_status(0x09, []),
                        ie(0x40, b"\xde\xad\xbe\xef"), seq(5, 5)], ver=2))
    # 8: unknown message type, no elements (only Ethernet padding)
    F.append(msg(0x42, [], to_ce=False))
    # 9: the fix "ELMI: Do not truncate the sub-information element
    #    length": a UNI Status element (length 255) with a UNI identifier
    #    of 254 octets, a 256 octet sub-element. Its size was truncated to
    #    0 in a uint8_t, which ended the UNI Status element after the map
    #    type and parsed the sub-element as an unknown element 0x51. Now
    #    the identifier is in the UNI Status element and the EVC Status
    #    element follows.
    F.append(msg(0x7D, [
        report(0), seq(6, 6), data_inst(6),
        bytes([0x11, 255, 0x03]) + sub(0x51, b"U" * 254),
        evc_status(7, 0x02, [sub(0x62, b"EVC-7")]),
    ]))
    # 10: an EVC Status element (length 255) with an EVC identifier of
    #     255 octets, a 257 octet sub-element (truncated to 1 before the
    #     fix, which misaligned the parsing), then sequence numbers.
    F.append(msg(0x7D, [
        report(0),
        bytes([0x21, 255]) + struct.pack(">HB", 8, 0x02) +
        sub(0x62, b"E" * 255),
        seq(7, 7),
    ]))
    return F


def malformed_frames():
    F = []
    # 1: an element whose value is cut short (data instance with 2 octets)
    F.append(msg(0x7D, [report(0)])[:14 + 2 + 3] + b"\x03\x05\x00\x00")
    # 2: only the version
    F.append(eth(b"\x01", ETHERTYPE_ELMI)[:15])
    # 3: a bandwidth profile sub-element past the end of the frame
    F.append(eth(bytes([1, 0x7D]) + bytes([0x21, 20]) +
                 struct.pack(">HB", 1, 2) + b"\x71\x0b\x00",
                 ETHERTYPE_ELMI)[:14 + 10])
    # 4: an EVC map sub-element longer than the frame
    F.append(eth(bytes([1, 0x7D]) + bytes([0x22, 30]) +
                 struct.pack(">HBB", 1, 0x41, 0) + b"\x63\x18\x00\x0a",
                 ETHERTYPE_ELMI)[:14 + 14])
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "."
    write_pcap(os.path.join(out, "elmi-coverage.pcap"), main_frames(),
               LINKTYPE_ETHERNET)
    write_pcap(os.path.join(out, "elmi-coverage-malformed.pcap"),
               malformed_frames(), LINKTYPE_ETHERNET)


if __name__ == "__main__":
    main()
