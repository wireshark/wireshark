#!/usr/bin/env python3
# Generates test/captures/dect_dlc_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build synthetic DECT DLC (LAPC, packet-dect-dlc.c) coverage captures.

DECT-DLC is reached as a Mitel SIP-DECT capture would reach it: Ethernet
with ethertype 0xA000 (DECT-MITEL-ETH), an LC layer (0x79) LC_DATA_REQ
(0x05, from the RFP towards the portable: P2P sent) or LC_DATA_IND (0x06,
received) message with MCEI, subfield and length, and the DLC frame:
address (NLF, LLN, SAPI, C/R), control (I, S or U format) and length
(6 bit length, M bit, EL bit) octets, then the information field. SAPI 0
and 3 go to DECT-NWK, other SAPIs to the data dissector. Every packet is
built with struct; nothing comes from a real network.

Usage: mkdect_dlc.py <outdir>
Writes dect-dlc-coverage.pcap and dect-dlc-coverage-malformed.pcap.
"""
import os
import struct
import sys

RFP = bytes.fromhex("020000000001")
OMM = bytes.fromhex("020000000002")
LC_DATA_REQ = 0x05
LC_DATA_IND = 0x06


def mitel(prim, dlc, mcei=1, src=OMM, dst=RFP):
    m = bytes([0x79, prim, mcei, 0x00, len(dlc)]) + dlc
    return dst + src + struct.pack(">H", 0xA000) + struct.pack(">HH", len(m), 0) + m


def addr(sapi=0, cr=1, lln=1, nlf=0):
    return (nlf << 7) | (lln << 4) | (sapi << 2) | (cr << 1) | 1


def dlc(a, ctrl, payload=b"", m=0, length=None, fill=b""):
    ln = len(payload) if length is None else length
    assert ln < 64
    return bytes([a, ctrl, (ln << 2) | (m << 1) | 1]) + payload + fill


def i_ctrl(ns, nr=0, p=0):
    return (nr << 5) | (p << 4) | (ns << 1)


def s_ctrl(stype, nr=0, pf=0):
    return (nr << 5) | (pf << 4) | (stype << 2) | 0x01


# U frame control octets (P/F bit 0x10 clear). A frame sent (LC_DATA_REQ)
# with C/R 1 or received (LC_DATA_IND) with C/R 0 is a response.
SABM, DM, UI, DISC, UA = 0x2F, 0x0F, 0x03, 0x43, 0x63
RR, RNR, REJ = 0, 1, 2


# A few DECT NWK messages (the payloads do not matter to DLC)
def ie(t, body):
    return bytes([t, len(body)]) + body


PORTABLE_IPEI = ie(0x05, bytes([0x90, 0x80 | 40, 0x00, 0x12, 0x34, 0x56, 0x78]))
FIXED_PARK = ie(0x06, bytes([0xA0, 0x80 | 36, 0x31, 0x22, 0x33, 0x44, 0x50]))
CC_SETUP = bytes([0x03, 0x05]) + PORTABLE_IPEI + FIXED_PARK + bytes([0xE0, 0x88])
LCE_PAGE_RESP = bytes([0x00, 0x71]) + PORTABLE_IPEI + FIXED_PARK
CC_CONNECT = bytes([0x83, 0x07])
CC_RELEASE_COM = bytes([0x03, 0x5A, 0xE2, 0x00])
MM_LOCATE_REQ = bytes([0x05, 0x54]) + PORTABLE_IPEI + FIXED_PARK
CLMS_VARIABLE = bytes([0x06, 0x01]) + ie(0x28, b"Hello")
# A message too long for one DLC frame: CC-INFO with a long multi-display
LONG_TEXT = b"Synthetic DECT DLC segmentation test, three frames long. " * 2
CC_INFO_LONG = bytes([0x03, 0x7B]) + ie(0x28, LONG_TEXT[:110]) + PORTABLE_IPEI


def segments(msg, size=60):
    return [msg[i:i + size] for i in range(0, len(msg), size)]


def main_frames():
    F = []
    # 1-3: reproducer of "DECT-DLC: Keep a retransmission out of
    # reassembly on later passes" (dect_dlc_retrans_2pass.py):
    # I N(S)=0 with M, its retransmission, I N(S)=1 last segment.
    nwk1 = bytes([0x05, 0x40]) + b"\x00" * 10
    F.append(("I N(S)=0 M=1 (first segment)", mitel(LC_DATA_REQ, dlc(0x01, 0x00, nwk1, m=1))))
    F.append(("I N(S)=0 M=1 retransmission", mitel(LC_DATA_REQ, dlc(0x01, 0x00, nwk1, m=1))))
    F.append(("I N(S)=1 last segment, reassembled", mitel(LC_DATA_REQ, dlc(0x01, 0x02, b"\x00" * 6))))
    # 4-5: Class B link establishment on MCEI 2: SABM with an LCE-PAGE-
    # RESPONSE (resets the last N(S)), UA
    F.append(("SABM with LCE-PAGE-RESPONSE", mitel(LC_DATA_IND, dlc(addr(0, 0), SABM | 0x10, LCE_PAGE_RESP), mcei=2)))
    F.append(("UA", mitel(LC_DATA_REQ, dlc(addr(0, 1), UA | 0x10), mcei=2)))
    # 6-7: I N(S)=0 again after the SABM (not a retransmission), RR
    F.append(("I N(S)=0 CC-SETUP after SABM", mitel(LC_DATA_IND, dlc(addr(0, 0), i_ctrl(0, 0), CC_SETUP), mcei=2)))
    F.append(("RR N(R)=1", mitel(LC_DATA_REQ, dlc(addr(0, 0), s_ctrl(RR, 1)), mcei=2)))
    # 8-10: CC-INFO in three segments, N(S)=1..3 (received)
    segs = segments(CC_INFO_LONG)
    assert len(segs) == 3
    for n, s in enumerate(segs):
        last = n == len(segs) - 1
        F.append(("I N(S)=%d segment %d of 3" % (n + 1, n + 1),
                  mitel(LC_DATA_IND, dlc(addr(0, 0), i_ctrl(n + 1, 0), s, m=0 if last else 1), mcei=2)))
    # 11-13: supervisory frames, poll/final, both C/R values
    F.append(("RNR N(R)=4 poll", mitel(LC_DATA_REQ, dlc(addr(0, 0), s_ctrl(RNR, 4, 1)), mcei=2)))
    F.append(("RR response final", mitel(LC_DATA_IND, dlc(addr(0, 0), s_ctrl(RR, 1, 1)), mcei=2)))
    F.append(("REJ N(R)=4", mitel(LC_DATA_REQ, dlc(addr(0, 1), s_ctrl(REJ, 4)), mcei=2)))
    # 14-16: sent I frames N(S)=0, 1 (CC-CONNECT, CC-RELEASE-COM), RR
    F.append(("I N(S)=0 CC-CONNECT", mitel(LC_DATA_REQ, dlc(addr(0, 0), i_ctrl(0, 4), CC_CONNECT), mcei=2)))
    F.append(("I N(S)=1 CC-RELEASE-COM", mitel(LC_DATA_REQ, dlc(addr(0, 0), i_ctrl(1, 4, 1), CC_RELEASE_COM), mcei=2)))
    F.append(("RR N(R)=3", mitel(LC_DATA_IND, dlc(addr(0, 1), s_ctrl(RR, 3)), mcei=2)))
    # 17-18: DISC, DM
    F.append(("DISC", mitel(LC_DATA_REQ, dlc(addr(0, 0), DISC | 0x10), mcei=2)))
    F.append(("DM final", mitel(LC_DATA_IND, dlc(addr(0, 0), DM | 0x10), mcei=2)))
    # 19-21: Class A on MCEI 3, new link flag, LLN 0 (U0)
    F.append(("I N(S)=0 MM-LOCATE-REQUEST NLF", mitel(LC_DATA_IND, dlc(addr(0, 0, lln=0, nlf=1), i_ctrl(0, 0), MM_LOCATE_REQ), mcei=3)))
    F.append(("I N(S)=0 CC-CONNECT LLN B2", mitel(LC_DATA_REQ, dlc(addr(0, 1, lln=2), i_ctrl(0, 1), CC_CONNECT), mcei=3)))
    F.append(("I N(S)=1 with fill octets", mitel(LC_DATA_IND, dlc(addr(0, 0, lln=0), i_ctrl(1, 1), CC_CONNECT, fill=b"\xf0\xf0\xf0"), mcei=3)))
    # 22-23: connectionless SAPI 3 UI frames, with and without fill
    F.append(("UI SAPI 3 CLMS-VARIABLE", mitel(LC_DATA_REQ, dlc(addr(3, 1, lln=7), UI, CLMS_VARIABLE), mcei=4)))
    F.append(("UI SAPI 3 with fill", mitel(LC_DATA_IND, dlc(addr(3, 0, lln=7), UI, CLMS_VARIABLE, fill=b"\xf0" * 4), mcei=4)))
    # 24-26: SAPIs without a dissector: UI SAPI 1, I SAPI 2 (reassembled
    # and given to the data dissector), UI SAPI 2 response
    F.append(("UI SAPI 1, data", mitel(LC_DATA_REQ, dlc(addr(1, 1, lln=3), UI, b"\x01\x02\x03\x04"), mcei=5)))
    F.append(("I SAPI 2, data", mitel(LC_DATA_REQ, dlc(addr(2, 1, lln=4), i_ctrl(0, 0), b"\x11\x22\x33"), mcei=5)))
    F.append(("UI SAPI 2 response, data", mitel(LC_DATA_IND, dlc(addr(2, 1, lln=5), UI | 0x10, b"\x44\x55"), mcei=5)))
    # 27-28: segmented I SAPI 2 (first segment, last segment)
    F.append(("I SAPI 2 N(S)=1 first segment", mitel(LC_DATA_REQ, dlc(addr(2, 1, lln=6), i_ctrl(1, 0), b"\xaa" * 20, m=1), mcei=5)))
    F.append(("I SAPI 2 N(S)=2 last segment", mitel(LC_DATA_REQ, dlc(addr(2, 1, lln=6), i_ctrl(2, 0), b"\xbb" * 10), mcei=5)))
    # 29: UA response carrying a final bit, LLN unassigned
    F.append(("UA final LLN 7", mitel(LC_DATA_IND, dlc(addr(0, 0, lln=7), UA | 0x10), mcei=6)))
    return F


def malformed_frames():
    F = []
    F.append(("address octet only", mitel(LC_DATA_REQ, bytes([0x01]))))
    F.append(("address and control only", mitel(LC_DATA_REQ, bytes([0x01, 0x03]))))
    F.append(("length beyond the frame", mitel(LC_DATA_REQ, dlc(0x01, 0x03, b"\x05\x40", length=20))))
    F.append(("UI length 0 with fill (empty NWK)", mitel(LC_DATA_IND, dlc(0x01, 0x03, b"", fill=b"\xf0\xf0"))))
    F.append(("I length 0 with fill (empty NWK)", mitel(LC_DATA_IND, dlc(0x01, 0x0C, b"", fill=b"\xf0\xf0"))))
    F.append(("RR with an information field", mitel(LC_DATA_REQ, dlc(0x01, s_ctrl(RR, 2), CC_CONNECT))))
    F.append(("I length beyond the frame", mitel(LC_DATA_REQ, dlc(0x01, 0x0E, b"\x05\x40", length=40, m=1))))
    return F


def write_pcap(path, frames, t0=1700000000):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, (_, p) in enumerate(frames):
            f.write(struct.pack("<IIII", t0 + i, 0, len(p), len(p)) + p)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "."
    m = main_frames()
    write_pcap(os.path.join(out, "dect-dlc-coverage.pcap"), m)
    write_pcap(os.path.join(out, "dect-dlc-coverage-malformed.pcap"), malformed_frames())
    if "-v" in sys.argv:
        for i, (d, _) in enumerate(m):
            print(i + 1, d)


if __name__ == "__main__":
    main()
