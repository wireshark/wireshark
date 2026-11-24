#!/usr/bin/env python3
# Generates test/captures/brdwlk_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the Boardwalk dissector
(packet-brdwlk.c).

Boardwalk is the Cisco MDS Port Analyzer Adapter encapsulation of Fibre
Channel in Ethernet, ethertypes 0x88AE and 0xABCD. Every packet is built
from scratch with struct; no captured traffic is used.

Frame layout (Ethernet payload):
  SOF (4 bits) + VSAN (12 bits)
  FC header (24) + FC payload + FC CRC (4)
  packet length word: plen (16 bits, in 32 bit words, SOF..EOF incl. CRC)
                      + 16 bits reserved
  packet count (16 bits), error flags (8 bits), EOF (low 4 bits)

The FC dissector removes 8 octets from the end of the FC frame for
Boardwalk (the CRC and the packet length word).

Usage: mkbrdwlk.py <output directory>

Writes:
  brdwlk-coverage.pcap            see README.md for the frame list
  brdwlk-coverage-malformed.pcap  short frames, the negative plen offset,
                                  plen with the truncated bit
"""

import os
import struct
import sys
import zlib

MAC_A = bytes.fromhex('020000000001')
MAC_B = bytes.fromhex('020000000002')
ETH_BRDWLK = 0x88AE
ETH_ABCD = 0xABCD

SOFI1, SOFN1, SOFI2, SOFN2, SOFI3, SOFN3, SOFF = 2, 3, 4, 5, 6, 7, 8
SOFC1, SOFC4, SOFI4 = 1, 9, 0xA
EOFT, EOFDT, EOFN, EOFA = 1, 2, 3, 4

# F_CTL bits
EXG_FIRST = 0x200000
EXG_LAST = 0x100000
SEQ_LAST = 0x080000
SEQ_INIT = 0x010000   # TSI
EXG_RESP = 0x800000


def fc(r_ctl, d_id, s_id, ftype, fctl, seq_id, seqcnt, oxid, rxid, param, payload,
       cs_ctl=0, df_ctl=0):
    hdr = (struct.pack('>B', r_ctl) + d_id.to_bytes(3, 'big')
           + struct.pack('>B', cs_ctl) + s_id.to_bytes(3, 'big')
           + struct.pack('>B', ftype) + fctl.to_bytes(3, 'big')
           + struct.pack('>BBHHHI', seq_id, df_ctl, seqcnt, oxid, rxid, param))
    body = hdr + payload
    return body + struct.pack('>I', zlib.crc32(body) & 0xffffffff)


def bw(fcframe, cnt, err=0x01, eof=EOFT, sof=SOFI3, vsan=1, plen=None,
       etype=ETH_BRDWLK):
    """A Boardwalk Ethernet frame. plen defaults to the FC frame length in
    words (FC header + payload + CRC)."""
    if plen is None:
        plen = len(fcframe) // 4
    return (MAC_B + MAC_A + struct.pack('>H', etype)
            + struct.pack('>H', (sof << 12) | vsan) + fcframe
            + struct.pack('>HH', plen, 0)
            + struct.pack('>HBB', cnt, err, eof))


# Some FC frames that decode cleanly ------------------------------------------

def ack1(oxid=0x1000, seqcnt=0):
    # Link control ACK_1, no payload; 4 octets of padding so that the FC
    # frame is longer than the 8 octets the FC dissector removes.
    return fc(0xC0, 0x010203, 0x040506, 0x00, EXG_RESP | SEQ_LAST, 1, seqcnt,
              oxid, 0x2000, 1, b'\0' * 4)


def abts(oxid=0x1001):
    return fc(0x81, 0x010203, 0x040506, 0x00, SEQ_LAST | SEQ_INIT, 2, 0,
              oxid, 0xffff, 0, b'\0' * 4)


def ba_acc(oxid=0x1001):
    # BA_ACC payload: SEQ_ID validity, SEQ_ID, reserved, OX_ID, RX_ID,
    # low and high SEQ_CNT
    return fc(0x84, 0x040506, 0x010203, 0x00, EXG_RESP | SEQ_LAST, 2, 0,
              oxid, 0x2001, 0, struct.pack('>BBHHHHH', 0x80, 2, 0, oxid, 0x2001, 0, 0xffff))


def ba_rjt(oxid=0x1002):
    return fc(0x85, 0x040506, 0x010203, 0x00, EXG_RESP | SEQ_LAST, 3, 0,
              oxid, 0x2002, 0, struct.pack('>BBBB', 0, 0x09, 0x03, 0))


def unsol_data(payload, oxid, seqcnt, fctl, seq_id=5):
    # Device data, unsolicited data (R_CTL 0x04), FC type 0xF0 (vendor
    # specific, no dissector): the payload is shown as data.
    return fc(0x04, 0x0a0b0c, 0x0d0e0f, 0xF0, fctl, seq_id, seqcnt, oxid, 0xffff, 0,
              payload)


# pcap writer ----------------------------------------------------------------

def write_pcap(path, frames, snaplen=262144):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, snaplen, 1))
        for i, fr in enumerate(frames):
            if isinstance(fr, tuple):
                p, origlen = fr
            else:
                p, origlen = fr, len(fr)
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), origlen))
            f.write(p)


def main_frames():
    F = []
    # 1-4: packet counters 1, 2, 5, 6 (the reproducer of
    # brdwlk_drop.py frames 1-4): frame 3 follows a gap
    # and is marked brdwlk.drop
    F.append(bw(ack1(0x1000), 1))
    F.append(bw(ack1(0x1000), 2))
    F.append(bw(ack1(0x1000), 5))
    F.append(bw(ack1(0x1000), 6))
    # 5-11: every SOF the dissector names, and SOFi4, SOFc1, SOFc4 (first
    # frame / SOFf / other), with BLS frames
    F.append(bw(abts(0x1001), 7, sof=SOFI1, vsan=2))
    F.append(bw(ba_acc(0x1001), 8, sof=SOFI2, vsan=2))
    F.append(bw(ba_rjt(0x1002), 9, sof=SOFI4, vsan=3))
    F.append(bw(ack1(0x1003), 10, sof=SOFN1, vsan=4))
    F.append(bw(ack1(0x1004), 11, sof=SOFN2, vsan=4))
    F.append(bw(ack1(0x1005), 12, sof=SOFN3, vsan=4))
    F.append(bw(ack1(0x1006), 13, sof=SOFC1, vsan=4))
    # 12: SOFf, EOFdt
    F.append(bw(ack1(0x1007), 14, sof=SOFF, eof=EOFDT, vsan=0xfff))
    # 13: SOFc4, EOFa, no packet length (plp clear), every other error
    # flag set (the truncated bit is ignored without plp)
    F.append(bw(ack1(0x1008), 15, sof=SOFC4, eof=EOFA, err=0xFE))
    # 14: ethertype 0xABCD
    F.append(bw(abts(0x1009), 16, etype=ETH_ABCD))
    # 15-16: counter wraps from 65535 to 0: frame 15 is a gap (16 ->
    # 65535) and is marked, frame 16 (0 after 65535) is not
    F.append(bw(ack1(0x100a), 0xffff))
    F.append(bw(ack1(0x100a), 0))
    # 17: counter 0 again, not after 65535: marked
    F.append(bw(ack1(0x100a), 0))
    # 18: SOFi3 with EOFn: the dissector sets FC_DATA_EOF_INVALID rather
    # than FC_DATA_EOF_LAST_FRAME; F_CTL has Seq Last set, so the FC
    # dissector still treats it as a complete sequence (no reassembly)
    F.append(bw(unsol_data(bytes(range(100)), 0x3000, 0, EXG_FIRST | SEQ_LAST | SEQ_INIT), 1,
                sof=SOFI3, eof=EOFN, vsan=10))
    # 19: packet length present and the truncated bit set, the original
    # packet length (400) larger than the FC frame captured: the FC
    # subset gets reported length 400
    F.append(bw(abts(0x3001), 2, err=0x09, plen=100))
    # 20: a frame cut short by the snapshot length, 4 octets of the EOF
    # word missing: no packet count or EOF is decoded (len < reported_len)
    full = bw(abts(0x100b), 3)
    F.append((full[:-4], len(full)))
    # 21: a frame cut short by 2 octets, so part of the EOF word is
    # captured; still no packet count
    full = bw(abts(0x100c), 20)
    F.append((full[:-2], len(full)))
    # 22: counter 5 follows 2 (frames 20-21 carry no counter, so the
    # counter is not updated): marked
    F.append(bw(ack1(0x100d), 5))
    return F


def malformed_frames():
    F = []
    # 1: SOF/VSAN only (reported length < 4: no EOF, FC header missing)
    F.append(MAC_B + MAC_A + struct.pack('>HH', ETH_BRDWLK, 0x6001))
    # 2: SOF/VSAN and 3 octets
    F.append(MAC_B + MAC_A + struct.pack('>HH', ETH_BRDWLK, 0x6001) + b'\x01\x02\x03')
    # 3: SOF/VSAN and an EOF word only, plen present: the packet length is
    # read at offset -2 (from brdwlk_drop.py frame 6)
    F.append(MAC_B + MAC_A + struct.pack('>HH', ETH_BRDWLK, 0x6001)
             + struct.pack('>HBB', 8, 0x01, 0x01))
    # 4: 6 octets after SOF/VSAN, plen present: plen read from the SOF/VSAN
    F.append(MAC_B + MAC_A + struct.pack('>HH', ETH_BRDWLK, 0x6001)
             + b'\xab\xcd' + struct.pack('>HBB', 9, 0x01, 0x01))
    # 5: plen present and truncated, plen 2 words, smaller than the FC
    # frame (from brdwlk_drop.py frame 5)
    F.append(bw(ack1(0x4000), 10, err=0x09, plen=2))
    # 6: FC frame of only a header: the FC dissector reports it as short
    F.append(bw(fc(0xC0, 1, 2, 0, SEQ_LAST, 0, 0, 1, 2, 0, b'')[:24], 12, plen=6))
    # 7: EOF word only, plp clear
    F.append(MAC_B + MAC_A + struct.pack('>HH', ETH_BRDWLK, 0x2001)
             + struct.pack('>HBB', 13, 0x00, 0x03))
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'brdwlk-coverage.pcap'), main_frames())
    write_pcap(os.path.join(out, 'brdwlk-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()
