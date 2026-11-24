#!/usr/bin/env python3
# Generates test/captures/ehdlc_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the Ericsson HDLC dissector
(packet-ehdlc.c, A-bis over IP).

EHDLC has no port or other default entry of its own: it is registered
only for Decode As on "l2tp.pw_type" and by name as "ehdlc". The
captures use Exported PDU frames (linktype 252) that name the "ehdlc"
dissector, as a tool exporting the L2TPv3 payload would. dissect_ehdlc()
skips four octets and then loops over frames, each starting with a 16
bit word of compressed SAPI (3 bits), compressed TEI (4 bits) and
DataLen (9 bits, counting this word). SAPI 10/11 (TFP) and 12 (P-GSL)
go straight to their dissectors; the others carry an LAPD-like control
field: I frames to RSL (SAPI 0) or OML (SAPI 62), XID frames with their
IEs. Every packet is built from scratch with struct; no captured traffic
is used.

Usage: mkehdlc.py <output directory>

Writes:
  ehdlc-coverage.pcap            every compressed SAPI, TEIs below and
                                 above 11, I frames (RSL, OML, the 4
                                 octet "ACK"), S frames RR/RNR/REJ, U
                                 frames SABME/UA/DISC/DM/UI/XID (with and
                                 without the P bit), XID IEs, several
                                 frames in one packet, the XID IE loop
                                 bound (an XID frame followed by more
                                 frames)
  ehdlc-coverage-malformed.pcap  the reproducer of the fix (TFP DataLen
                                 0), DataLen 1 for RSL, DataLen shorter
                                 than the I frame header, a DataLen past
                                 the end of the packet, a frame cut short
                                 in the header word
"""

import os
import struct
import sys


def exp_pdu(name, payload):
    n = name.encode()
    pad = (4 - len(n) % 4) % 4
    tags = struct.pack('>HH', 12, len(n) + pad) + n + b'\0' * pad + struct.pack('>HH', 0, 0)
    return tags + payload


def pcap(path, pkts, linktype=252):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, p in enumerate(pkts):
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, len(p), len(p)))
            f.write(p)


PREFIX = b'\x00\x00\x00\x00'   # the four octets dissect_ehdlc() skips


def hdr(csapi, ctei, length):
    return struct.pack('>H', (csapi << 13) | (ctei << 9) | (length & 0x1ff))


def frame(csapi, ctei, body, length=None):
    """A frame whose DataLen covers the header word and the body."""
    if length is None:
        length = 2 + len(body)
    return hdr(csapi, ctei, length) + body


def i_ctrl(ns, nr, p=0):
    # extended (modulo 128) I frame control: N(S) << 1, N(R) << 1 | P
    return bytes([ns << 1, (nr << 1) | p])


def s_ctrl(stype, nr, p=0):
    # extended S frame: 0000 SS01, N(R) << 1 | P/F
    return bytes([(stype << 2) | 0x01, (nr << 1) | p])


def u_ctrl(mod, p=0):
    return bytes([mod | 0x03 | (0x10 if p else 0)])


SABME, UA, DISC, DM, UI, XID = 0x6c, 0x60, 0x40, 0x0c, 0x00, 0xac

# RSL OVERLOAD (TRX management) with a Cause IE: processor overload
RSL_OVERLOAD = bytes([0x10, 0x1b, 0x1a, 0x01, 0x23])
# OML MMI transfer: only the common header (length 2) and two octets
OML_MMI = bytes([0x40, 0x80, 0x00, 0x02, 0xaa, 0xbb])
# TFP: header (ATSR/slot rate/sequence, delay, frame type) and two
# data octets, the last with bit 0 set
TFP = bytes([0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00])
# P-GSL: version/discriminator 0 (downlink data) and its fields
PGSL = bytes([0x00, 0x01, 0x02, 0x10, 0x20, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])

XID_IES = bytes([0x82, 0x80, 0x00, 0x09,       # format, group, length 9
                 0x07, 0x01, 0x05,               # window size Tx 5
                 0x09, 0x01, 0x04,               # ack timer 4 ms
                 0x08, 0x01, 0x05,               # window size Rx 5
                 0x0a, 0x01, 0x77])              # an IE the dissector ignores


def main_frames():
    p = []
    # 1: RSL I frame, SAPI 0 (csapi 0), TEI 0
    p.append(frame(0, 0, i_ctrl(0, 0) + RSL_OVERLOAD))
    # 2: csapi 1 (RSL, C/R 1), TEI 11, the 4 octet I frame "ACK"
    p.append(frame(1, 11, i_ctrl(1, 1, p=1)))
    # 3: OML I frame, csapi 5, compressed TEI 12 (TEI 60)
    p.append(frame(5, 12, i_ctrl(0, 0) + OML_MMI))
    # 4: csapi 6 (OML, C/R 1), compressed TEI 15 (TEI 63), "ACK"
    p.append(frame(6, 15, i_ctrl(2, 1)))
    # 5: TFP on csapi 2 (SAPI 10) and csapi 3 (SAPI 11) in one packet
    p.append(frame(2, 1, TFP) + frame(3, 2, TFP))
    # 6: P-GSL, csapi 4 (SAPI 12)
    p.append(frame(4, 3, PGSL))
    # 7: S frames RR, RNR and REJ (with the P bit) in one packet
    p.append(frame(0, 0, s_ctrl(0, 5)) + frame(0, 0, s_ctrl(1, 6)) +
             frame(0, 0, s_ctrl(2, 7, p=1)))
    # 8: U frames SABME (P), UA (F), DISC, DM, UI to RSL, a 4 octet UI
    p.append(frame(0, 0, u_ctrl(SABME, p=1)) + frame(1, 0, u_ctrl(UA, p=1)) +
             frame(0, 1, u_ctrl(DISC)) + frame(1, 1, u_ctrl(DM)) +
             frame(0, 2, u_ctrl(UI) + RSL_OVERLOAD) + frame(0, 2, u_ctrl(UI, p=1) + b'\x00'))
    # 9: XID with its IEs, then an RSL I frame in the same packet: the
    # IE loop must stop at the end of the XID frame (fixed)
    p.append(frame(5, 4, u_ctrl(XID) + XID_IES) + frame(0, 4, i_ctrl(3, 0) + RSL_OVERLOAD))
    # 10: XID with the P bit set (not dissected as XID) and an XID with
    # only the IE header
    p.append(frame(5, 4, u_ctrl(XID, p=1) + XID_IES) +
             frame(6, 4, u_ctrl(XID) + bytes([0x82, 0x80, 0x00, 0x00])))
    # 11: csapi 7 (no SAPI defined, shown as 0) I frame to RSL
    p.append(frame(7, 5, i_ctrl(4, 4) + RSL_OVERLOAD))
    # 12: a long OML I frame (DataLen 263, bit 8 of the length set)
    p.append(frame(5, 6, i_ctrl(5, 0) + bytes([0x40, 0x80, 0x00, 0xff]) +
                   bytes(range(255))))
    # 13: only the four skipped octets: no frame at all
    return [exp_pdu('ehdlc', PREFIX + b) for b in p] + [exp_pdu('ehdlc', PREFIX)]


def malformed_frames():
    p = []
    # 1: the reproducer of the fix (ehdlc_tfp_len0_loop.py): compressed
    # SAPI 2 (TFP) with DataLen 0 looped until the layer depth assertion
    p.append(PREFIX + struct.pack('>H', 0x4000) +
             bytes([0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00]))
    # 2: RSL SAPI with DataLen 1
    p.append(PREFIX + hdr(0, 0, 1) + i_ctrl(0, 0) + RSL_OVERLOAD)
    # 3: I frame with DataLen 3 (header and control need 4)
    p.append(PREFIX + hdr(0, 0, 3) + i_ctrl(0, 0) + RSL_OVERLOAD)
    # 4: DataLen 100 with only 7 octets of the frame present
    p.append(PREFIX + hdr(0, 0, 100) + i_ctrl(0, 0) + RSL_OVERLOAD)
    # 5: one octet of the header word
    p.append(PREFIX + b'\x00')
    # 6: P-GSL with DataLen 1
    p.append(PREFIX + hdr(4, 0, 1) + PGSL)
    return [exp_pdu('ehdlc', b) for b in p]


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcap(os.path.join(out, 'ehdlc-coverage.pcap'), main_frames())
    pcap(os.path.join(out, 'ehdlc-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()
