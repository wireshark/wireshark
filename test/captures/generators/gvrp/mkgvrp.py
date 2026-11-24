#!/usr/bin/env python3
# Generates test/captures/gvrp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic GVRP (GARP VLAN Registration Protocol) coverage captures.
GVRP runs over IEEE 802.3 + LLC (SAP 0x42, UI) to the GARP address
01:80:c2:00:00:21, where the BPDU dissector hands it to GVRP.
Usage: mkgvrp.py <outdir>"""
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


def eth(garp, dst="0180c2000021", src="020000000001", fix_len=None):
    llc = b"\x42\x42\x03" + garp
    return bytes.fromhex(dst) + bytes.fromhex(src) + struct.pack("!H", len(llc) if fix_len is None else fix_len) + llc


def attr(event, vid):
    return bytes([4, event]) + struct.pack("!H", vid)


def leave_all():
    return bytes([2, 0])


def msg(atype, attrs, end=True):
    return bytes([atype]) + b"".join(attrs) + (b"\0" if end else b"")


def pdu(msgs, end=True, proto=1):
    return struct.pack("!H", proto) + b"".join(msgs) + (b"\0" if end else b"")


def gvrp_frames():
    f = []
    for ev in (1, 2, 3, 4, 5):
        f.append(eth(pdu([msg(1, [attr(ev, 100 * ev)])])))
    f.append(eth(pdu([msg(1, [leave_all()])])))
    f.append(eth(pdu([msg(1, [attr(2, 1), attr(2, 2), attr(4, 4094)])])))
    f.append(eth(pdu([msg(1, [leave_all(), attr(2, 10), attr(1, 20)]), msg(1, [attr(3, 30)])])))
    # No end of mark after the attributes / PDU
    f.append(eth(pdu([msg(1, [attr(2, 5)], end=False)], end=False)))
    f.append(eth(pdu([msg(1, [attr(2, 5)])], end=False)))
    # Not understood: shown as data
    f.append(eth(pdu([msg(2, [attr(2, 5)])])))                       # unknown attribute type
    f.append(eth(struct.pack("!H", 1) + b"\0"))                      # end of mark first
    f.append(eth(struct.pack("!H", 1) + bytes([1, 0, 0])))           # no attribute in the message
    f.append(eth(pdu([msg(1, [bytes([3, 0, 0])])])))                 # LeaveAll of the wrong length
    f.append(eth(pdu([msg(1, [bytes([2, 2])])])))                    # registration of the wrong length
    f.append(eth(pdu([msg(1, [bytes([4, 9, 0, 1])])])))              # unknown event
    f.append(eth(pdu([msg(1, [attr(2, 5)])], proto=2)))              # protocol ID 2
    return f


def gvrp_malformed_frames():
    f = []
    f.append(eth(pdu([], proto=0xffff)))
    full = pdu([msg(1, [attr(2, 5), attr(4, 6)]), msg(1, [leave_all()])])
    for n in range(0, len(full)):
        f.append(eth(full[:n]))
    one = pdu([msg(1, [attr(2, 5)])])
    for n in range(4, len(one)):
        f.append((eth(one)[:14 + 3 + n], len(eth(one))))
    return f


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "."
    write_pcap(out + "/gvrp-coverage.pcap", gvrp_frames())
    write_pcap(out + "/gvrp-coverage-malformed.pcap", gvrp_malformed_frames())
