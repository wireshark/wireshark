#!/usr/bin/env python3
# Generates test/captures/rdm-etc_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the RDM-ETC (ETC manufacturer PIDs, manufacturer 0x6574) coverage captures.
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

    D, S = (ETC, 1), (ETC, 2)
    pk = lambda pid, idx, items: struct.pack('>HH', pid, idx) + b''.join(struct.pack('>HB', a, len(d)) + d for a, d in items)
    for pk_pid, pid in ((0x0000, 0x0058), (0x8101, 0x0058)):
        F(rdm_msg(D, S, 41, 0, 0x21, pid, pk(pk_pid, 1, [(1, b'\xaa\xbb'), (2, b'\x01')])))
    for pk_pid, pid in ((0x0000, 0x0059), (0x8101, 0x0059)):
        F(rdm_msg(D, S, 42, 0, 0x21, pid, struct.pack('>H', pk_pid) + b''.join(struct.pack('>HB', a, len(d)) + d for a, d in [(1, b'\x00\x05'), (2, b'\x00\x06')])))
    F(rdm_msg(D, S, 43, 0, 0x20, 0x0058, struct.pack('>HHHH', 0x8101, 1, 0, 2)))
    F(rdm_msg(D, S, 47, 0, 0x21, 0x0060, bytes(19)))      # DEVICE_INFO response (ETC model id)
    # selected messages
    n0 = len(m)
    for line in open(os.path.join(HERE, 'rdm_etc_selected.txt')):
        manf, cc, rt, pid, pd = line.split()
        manf, cc, rt, pid = int(manf), int(cc), int(rt), int(pid)
        pd = b'' if pd == '-' else bytes.fromhex(pd)
        F(rdm_msg((manf, 1), (manf, 2), len(m), rt, cc, pid, pd))
    n = len(m)
    # malformed: bad checksum, truncated messages
    F(rdm_msg((ETC, 1), (ETC, 2), 0, 0, 0x21, 0x00f0, b'\x00\x05', bad_csum=True), bad)
    F(rdm_msg((ETC, 1), (ETC, 2), 0, 0, 0x21, 0x00f0, b'\x00\x05')[:10], bad)
    F(rdm_msg((ETC, 1), (ETC, 2), 0, 0, 0x21, 0x00f0, b'\x00\x05')[:22], bad)
    F(rdm_msg((ETC, 1), (ETC, 2), 0, 0, 0x21, 0x00f0, b'\x00\x05')[:-3], bad)
    F(rdm_msg((ETC, 1), (ETC, 2), 0, 0, 0x21, 0x00f0, b'\x00\x05', length=40), bad)       # message length too long: the intron runs past the data
    F(rdm_msg((ETC, 1), (ETC, 2), 0, 0, 0x21, 0x00f0, b'\x00\x05', length=5), bad)        # too short
    F(rdm_msg((ETC, 1), (ETC, 2), 0, 0, 0x21, 0x00f0, b'\x00\x05')[:3], bad)
    F(rdm_msg(D, S, 0, 0, 0x30, 0x1201, b'\x01' + struct.pack('>I', 256) + b'ABCDEFGH' + b'\x00\x00'), bad)   # wrong FTC packet CRC
    # a PD length byte larger than the data
    x = bytearray(rdm_msg((ETC, 1), (ETC, 2), 0, 0, 0x21, 0x00f0, b'\x00\x05')); x[23] = 200
    F(bytes(x), bad)
    write_pcap(os.path.join(out, 'rdm-etc-coverage.pcap'), m)
    write_pcap(os.path.join(out, 'rdm-etc-coverage-malformed.pcap'), bad)
    if '-v' in sys.argv:
        print('main', n, 'selected', n - n0, 'malformed', len(bad))

main()
