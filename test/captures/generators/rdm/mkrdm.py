#!/usr/bin/env python3
# Generates test/captures/rdm_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the RDM (ANSI E1.20) and RDM-ETC coverage captures.
RDM has no port of its own: it is reached through Art-Net ArtRdm packets
(UDP 6454, heuristic) which hand the RDM message to the "rdm" dissector;
manufacturer specific PIDs of ETC (manufacturer 0x6574) go to rdm_etc through
the rdm.manf_id table. Messages come from rdm_selected.txt, which
selectrdm.py picked (greedily, by new decoded fields) from 58000 random
messages of every PID and command class.
Usage: mkrdm.py <outdir> [-v]"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from rdmlib import artrdm, eth_udp, rdm_msg, write_pcap

HERE = os.path.dirname(os.path.abspath(__file__))
ETC = 0x6574

def main():
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    m = []; bad = []
    def F(msg, tgt=m, old=False):
        tgt.append(eth_udp(artrdm(msg, old)))
    # Reproducers of "RDM: Fix offsets after manufacturer PIDs and the intron length" (rdm_small)
    F(rdm_msg((ETC, 1), (ETC, 2), 0, 0, 0x21, 0x8101, b'\x01\x02\x03'))                  # 1 ETC LED_CURVE response, 3 octets: offset after the PID
    F(rdm_msg((1, 1), (1, 2), 0, 0, 0x21, 0x00f0, b'\x00\x01', intron=b'\x00\x00'))     # 2 intron counted in the message length
    F(rdm_msg((1, 1), (1, 2), 0, 0, 0x21, 0x00f0, b'\x00\x01'))                          # 3 same without intron
    # Message framing variants
    F(rdm_msg((1, 1), (1, 2), 1, 0, 0x20, 0x00f0, b''))                                  # 4 GET DMX_START_ADDRESS
    F(rdm_msg((1, 1), (1, 2), 2, 0, 0x30, 0x00f0, b'\x00\x05'))                          # 5 SET
    F(rdm_msg((1, 1), (1, 2), 3, 0, 0x21, 0x00f0, b'\x00\x05'), old=True)                # 6 old ArtRdm form with the 0xCC start code
    F(rdm_msg((1, 1), (1, 2), 4, 0, 0x21, 0x00f0, b'\x00\x05', trailer=b'\x00\x01\x02')) # 7 trailing octets after the checksum
    F(rdm_msg((1, 1), (1, 2), 5, 0, 0x21, 0x00f0, b'\x00\x05', intron=b'\x01\x02\x03'))  # 8 intron of three octets
    F(rdm_msg((0xffff, 0xffffffff), (1, 2), 6, 0, 0x30, 0x1000, b'\x01'))                # 9 broadcast destination
    F(rdm_msg((0x8001, 5), (0x8002, 6), 7, 0, 0x20, 0x00f0, b''))                         # 10 dynamic UIDs
    F(rdm_msg((1, 1), (1, 2), 8, 0, 0x20, 0x00f0, b'', subdev=0xffff))                    # 11 all sub-devices
    F(rdm_msg((1, 1), (1, 2), 9, 0x80, 0x20, 0x00f0, b'', msgcount=0))                    # 12 controller flags
    F(rdm_msg((1, 1), (1, 2), 10, 1, 0x21, 0x00f0, b'\x00\x05', msgcount=3))              # 13 ACK_TIMER response with PD length 2 (code path), message count
    F(rdm_msg((1, 1), (1, 2), 11, 4, 0x21, 0x00f0, b'\x00\x05'))                          # 14 unknown response type
    for rt in (1, 2, 3, 4):
        F(rdm_msg((1, 1), (1, 2), 12 + rt, rt, 0x21, 0x00f0, b'\x00\x05'))              # 15-18 every response type (the PID data not decoded as for ACK)
    # FTC (E1.37-4) messages with their packet CRC, FTC response statuses and packed PIDs
    # (the random candidates cannot get the CRC right)
    def crc(b):
        c = 0xffff
        for x in b:
            c ^= x
            for _ in range(8):
                c = (c >> 1) ^ 0xa001 if c & 1 else c >> 1
        return b + struct.pack('<H', c)
    D, S = (1, 1), (1, 2)
    F(rdm_msg(D, S, 20, 0, 0x30, 0x1200, crc(bytes([1, 2, 1, 0]) + struct.pack('>HI', 3, 4096) + bytes(range(16)) + b'\x12\x34')))
    F(rdm_msg(D, S, 21, 0, 0x30, 0x1201, crc(b'\x01' + struct.pack('>I', 256) + b'ABCDEFGH')))
    F(rdm_msg(D, S, 22, 0, 0x21, 0x1205, crc(b'\x00' + bytes(4) + b'\x01' + b'abcdef')))
    F(rdm_msg(D, S, 23, 0, 0x21, 0x1202, b'\x00' + struct.pack('>I', 5000) + struct.pack('>HH', 3, 0x1234) + bytes([0, 1, 0, 0, 0, 9])))
    for k, st in enumerate((0x00, 0x01, 0x03, 0x06, 0x07, 0x08, 0x0b, 0x0c, 0x14, 0x15, 0x16, 0x1a)):
        F(rdm_msg(D, S, 24 + k, 0, 0x21, 0x1200, bytes([st]) + bytes([1, 2, 3, 4]) + bytes(33)))
    F(rdm_msg(D, S, 40, 0, 0x21, 0x1201, b'\x04' + bytes(4) + struct.pack('>I', 512)))
    pk = lambda pid, idx, items: struct.pack('>HH', pid, idx) + b''.join(struct.pack('>HB', a, len(d)) + d for a, d in items)
    for (dm, sm) in ((1, 1), (ETC, ETC)):
        for pk_pid, pid in ((0x0000, 0x0058), (0x0058, 0x0058), (0x00f0, 0x0058), (0x8101, 0x0058)):
            F(rdm_msg((dm, 1), (sm, 2), 41, 0, 0x21, pid, pk(pk_pid, 1, [(1, b'\xaa\xbb'), (2, b'\x01')])))
        for pk_pid, pid in ((0x0000, 0x0059), (0x0059, 0x0059), (0x00f0, 0x0059), (0x8101, 0x0059)):
            F(rdm_msg((dm, 1), (sm, 2), 42, 0, 0x21, pid, struct.pack('>H', pk_pid) + b''.join(struct.pack('>HB', a, len(d)) + d for a, d in [(1, b'\x00\x05'), (2, b'\x00\x06')])))
        F(rdm_msg((dm, 1), (sm, 2), 43, 0, 0x20, 0x0058, struct.pack('>HHHH', 0x8101, 1, 0, 2)))
        F(rdm_msg((dm, 1), (sm, 2), 44, 0, 0x20, 0x0059, struct.pack('>HHH', 0x8101, 1, 2)))
        F(rdm_msg((dm, 1), (sm, 2), 45, 0, 0x30, 0x0058, pk(0x8101, 1, [(1, b'\x01')])))
        F(rdm_msg((dm, 1), (sm, 2), 46, 0, 0x30, 0x0059, struct.pack('>H', 0x8101) + struct.pack('>HB', 1, 1) + b'\x01'))
    F(rdm_msg((ETC, 1), (ETC, 2), 47, 0, 0x21, 0x0060, bytes(19)))    # ETC DEVICE_INFO response (model id of ETC)
    # metadata JSON: a response of one octet, text, and a manufacturer PID before the text
    F(rdm_msg(D, S, 48, 0, 0x21, 0x0053, b'{'))
    F(rdm_msg(D, S, 49, 0, 0x21, 0x0053, b'{"a": 1}'))
    F(rdm_msg(D, S, 50, 0, 0x21, 0x0053, b'\x80\x01{"a": 1}'))
    F(rdm_msg(D, S, 51, 9, 0x21, 0x00f0, b'\x00\x05'))                                   # unknown response type with data
    # selected messages
    n0 = len(m)
    for line in open(os.path.join(HERE, 'rdm_selected.txt')):
        manf, cc, rt, pid, pd = line.split()
        manf, cc, rt, pid = int(manf), int(cc), int(rt), int(pid)
        pd = b'' if pd == '-' else bytes.fromhex(pd)
        F(rdm_msg((manf, 1), (manf, 2), len(m), rt, cc, pid, pd))
    n = len(m)
    # malformed: bad checksum, truncated messages
    F(rdm_msg((1, 1), (1, 2), 0, 0, 0x21, 0x00f0, b'\x00\x05', bad_csum=True), bad)
    F(rdm_msg((1, 1), (1, 2), 0, 0, 0x21, 0x00f0, b'\x00\x05')[:10], bad)
    F(rdm_msg((1, 1), (1, 2), 0, 0, 0x21, 0x00f0, b'\x00\x05')[:22], bad)
    F(rdm_msg((1, 1), (1, 2), 0, 0, 0x21, 0x00f0, b'\x00\x05')[:-3], bad)
    F(rdm_msg((1, 1), (1, 2), 0, 0, 0x21, 0x00f0, b'\x00\x05', length=40), bad)       # message length too long: the intron runs past the data
    F(rdm_msg((1, 1), (1, 2), 0, 0, 0x21, 0x00f0, b'\x00\x05', length=5), bad)        # too short
    F(rdm_msg((1, 1), (1, 2), 0, 0, 0x21, 0x00f0, b'\x00\x05')[:3], bad)
    F(rdm_msg(D, S, 0, 0, 0x30, 0x1201, b'\x01' + struct.pack('>I', 256) + b'ABCDEFGH' + b'\x00\x00'), bad)   # wrong FTC packet CRC
    # a PD length byte larger than the data
    x = bytearray(rdm_msg((1, 1), (1, 2), 0, 0, 0x21, 0x00f0, b'\x00\x05')); x[23] = 200
    F(bytes(x), bad)
    write_pcap(os.path.join(out, 'rdm-coverage.pcap'), m)
    write_pcap(os.path.join(out, 'rdm-coverage-malformed.pcap'), bad)
    if '-v' in sys.argv:
        print('main', n, 'selected', n - n0, 'malformed', len(bad))

main()
