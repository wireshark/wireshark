#!/usr/bin/env python3
# Generates test/captures/gmrp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic GMRP (GARP Multicast Registration Protocol) coverage captures.
GMRP runs over IEEE 802.3 + LLC (SAP 0x42, UI) to the GARP address
01:80:c2:00:00:20, where the BPDU dissector hands it to GMRP.
Usage: mkgmrp.py <outdir>"""
import struct
import sys


def write_pcap(path, pkts):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, p in enumerate(pkts):
            olen = len(p)
            if isinstance(p, tuple):
                p, olen = p
            f.write(struct.pack("<IIII", 1700000000 + i, i * 1000, len(p), olen))
            f.write(p)
    print("wrote %d packets to %s" % (len(pkts), path))


def eth(garp, dst="0180c2000020", src="020000000001", fix_len=None):
    llc = b"\x42\x42\x03" + garp
    return bytes.fromhex(dst) + bytes.fromhex(src) + struct.pack("!H", len(llc) if fix_len is None else fix_len) + llc


MAC1 = bytes.fromhex("01005e000001")
MAC2 = bytes.fromhex("333300000002")
MAC3 = bytes.fromhex("ffffffffffff")


def attr_gm(event, mac):
    return bytes([8, event]) + mac


def attr_sr(event, val):
    return bytes([3, event, val])


def leave_all():
    return bytes([2, 0])


def msg(atype, attrs, end=True):
    return bytes([atype]) + b"".join(attrs) + (b"\0" if end else b"")


def pdu(msgs, end=True, proto=1):
    return struct.pack("!H", proto) + b"".join(msgs) + (b"\0" if end else b"")


def gmrp_frames():
    f = []
    # Group membership: every event, one message each and several attributes
    f.append(eth(pdu([msg(1, [attr_gm(2, MAC1), attr_gm(4, MAC2)])])))
    f.append(eth(pdu([msg(1, [leave_all()])])))
    for ev in (1, 2, 3, 4, 5):
        f.append(eth(pdu([msg(1, [attr_gm(ev, MAC1)])])))
    # Service requirement: forward all / forward all unregistered
    f.append(eth(pdu([msg(2, [attr_sr(1, 0)])])))
    f.append(eth(pdu([msg(2, [attr_sr(2, 1)])])))
    f.append(eth(pdu([msg(2, [attr_sr(3, 0), attr_sr(4, 1), attr_sr(5, 0)])])))
    f.append(eth(pdu([msg(2, [leave_all()])])))
    # Several messages of both types, LeaveAll mixed with registrations
    f.append(eth(pdu([msg(1, [leave_all(), attr_gm(2, MAC1), attr_gm(2, MAC2), attr_gm(1, MAC3)]),
                      msg(2, [attr_sr(2, 1)]),
                      msg(1, [attr_gm(3, MAC2)])])))
    # No end of mark at all: the message ends with the data
    f.append(eth(pdu([msg(1, [attr_gm(2, MAC1)], end=False)], end=False)))
    f.append(eth(pdu([msg(1, [attr_gm(2, MAC1)])], end=False)))
    # Not understood: shown as data without an expert info
    f.append(eth(pdu([msg(3, [attr_gm(2, MAC1)])])))                                  # unknown attribute type
    f.append(eth(struct.pack("!H", 1) + b"\0"))                                       # end of mark first
    f.append(eth(struct.pack("!H", 1) + bytes([1, 0, 0])))                            # no attribute in the message
    f.append(eth(pdu([msg(1, [bytes([2, 3])])])))                                     # LeaveAll with a bad event
    f.append(eth(pdu([msg(1, [bytes([3, 0, 0])])])))                                  # LeaveAll of the wrong length
    f.append(eth(pdu([msg(1, [bytes([9, 2]) + MAC1 + b"\0"])])))                      # bad length for a registration
    f.append(eth(pdu([msg(1, [bytes([8, 9]) + MAC1])])))                              # unknown event
    f.append(eth(pdu([msg(2, [bytes([8, 2]) + MAC1])])))                              # service requirement, bad length
    # Protocol ID other than 1: a warning expert info, the rest shown as data
    f.append(eth(pdu([msg(1, [attr_gm(2, MAC1)])], proto=2)))
    return f


def gmrp_malformed_frames():
    f = []
    f.append(eth(pdu([], proto=0xffff)))
    # Truncated at every position of a message with two attributes
    full = pdu([msg(1, [attr_gm(2, MAC1), attr_gm(4, MAC2)]), msg(2, [attr_sr(1, 0)])])
    for n in range(0, len(full)):
        f.append(eth(full[:n]))
    # Registration cut inside the value, header lengths kept
    one = pdu([msg(1, [attr_gm(2, MAC1)])])
    for n in range(4, len(one)):
        f.append((eth(one)[:14 + 3 + n], len(eth(one))))
    return f


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "."
    write_pcap(out + "/gmrp-coverage.pcap", gmrp_frames())
    write_pcap(out + "/gmrp-coverage-malformed.pcap", gmrp_malformed_frames())
