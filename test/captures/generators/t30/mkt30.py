#!/usr/bin/env python3
# Generates test/captures/t30_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the T.30 coverage captures. Usage: mkt30.py <outdir> [-v]
Writes t30-coverage.pcap (main) and t30-coverage-malformed.pcap.
T.30 has no port: real captures reach it through T.38 (UDPTL/TCP, only by
Decode As or SDP) which hands a reassembled HDLC frame to the registered
dissector "t30.hdlc". The frames here are Exported PDUs (linktype 252) that
name "t30.hdlc", the way a capture tool would export them; without a T.38
packet there is no t38_packet_info, so the code that fills the T.38
description is not reached. Everything is synthetic."""
import os
import sys
from pcaplib import exp_pdu, write_pcap

def rev(b):
    return int('{:08b}'.format(b)[::-1], 2)

def hdlc(fcf, fif=b'', addr=0xff, ctrl=0xc0):
    return exp_pdu('t30.hdlc', bytes([addr, ctrl, fcf]) + fif)

def num(s):
    """20 octet number field: the digits reversed and every octet bit-reversed, space padded."""
    s = s.ljust(20)[:20].encode()
    return bytes(rev(c) for c in reversed(s))

def dis_chain(n, fill=0x00):
    """n information octets; every octet but the last has its extension bit (bit 1) set."""
    return bytes([(fill | 0x01) if i < n - 1 else (fill & 0xfe) for i in range(n)])

FCF_NAMES = {0x01: 'DIS', 0x02: 'CSI', 0x04: 'NSF', 0x21: 'CFR', 0x22: 'FTT', 0x23: 'CTR', 0x24: 'CSA',
             0x31: 'MCF', 0x32: 'RTN', 0x33: 'RTP', 0x34: 'PIN', 0x35: 'PIP', 0x36: 'PID', 0x37: 'RNR', 0x38: 'ERR',
             0x3d: 'PPR', 0x3f: 'FDM', 0x41: 'DCS', 0x42: 'TSI', 0x43: 'SUB', 0x44: 'NSS', 0x45: 'SID', 0x46: 'TSA',
             0x47: 'IRA', 0x48: 'CTC', 0x53: 'FNV', 0x56: 'TR', 0x57: 'TNR', 0x58: 'CRP', 0x5f: 'DCN', 0x60: 'FCD',
             0x61: 'RCP', 0x71: 'EOM', 0x72: 'MPS', 0x73: 'EOR', 0x74: 'EOP', 0x76: 'RR', 0x78: 'PRI-EOP2',
             0x79: 'PRI-EOM', 0x7a: 'PRI-MPS', 0x7c: 'PRI-EOP', 0x7d: 'PPS', 0x81: 'DTC', 0x82: 'CIG', 0x83: 'PWD',
             0x84: 'NSC', 0x85: 'SEP', 0x86: 'PSA', 0x87: 'CIA', 0x88: 'ISP'}

def main_frames():
    F = []; R = {}
    def add(name, fr):
        R[name] = len(F) + 1; F.append(fr)
    # DIS, DTC (with the same layout) and DCS with 3..15 information octets and every bit set / clear
    for n in range(3, 16):
        add('dis-%d' % n, hdlc(0x01, dis_chain(n, 0xfe if n % 2 else 0x54)))
    add('dis-16-ext-set', hdlc(0x01, dis_chain(15, 0xaa) + b'\xab'))        # extension bit set in the last octet: nothing follows
    for n in (3, 4, 5, 8, 11, 15):
        add('dtc-%d' % n, hdlc(0x81, dis_chain(n, 0xfe)))
    for n in range(3, 16):
        add('dcs-%d' % n, hdlc(0x41, dis_chain(n, 0xfe if n % 2 else 0x54)))
    add('dis-with-fcf-bit8', hdlc(0x81 ^ 0x80, dis_chain(4, 0x2a), ctrl=0xc8))   # 0x01 with the final-frame control octet
    # phase-B frames with 20 digit numbers
    for fcf in (0x02, 0x42, 0x43, 0x45, 0x82, 0x83, 0x85, 0x86):
        add('num-%s' % FCF_NAMES[fcf], hdlc(fcf, num('+61 2 5550 %04d' % fcf)))
        # the same with bit 8 (X) of the FCF set (the last frame of a message is sent with it)
    add('num-csi-x', hdlc(0x82 ^ 0x80, num('0123456789')))  # 0x02 | 0x80 = 0x82 is CIG; use 0x02 with the X bit via CIG
    add('num-blank', hdlc(0x42, num('')))
    # non-standard facilities
    for fcf in (0x04, 0x44, 0x84):
        add('nonstd-%s' % FCF_NAMES[fcf], hdlc(fcf, b'\x61\x01\x02\x03\x04\x05'))
    # FCD (facsimile coded data) with frame number
    add('fcd', hdlc(0x60, bytes([rev(5)]) + bytes(range(30))))
    add('fcd-last', hdlc(0x60 | 0x80, bytes([rev(255)]) + b'\xaa' * 8))
    add('fcd-min', hdlc(0x60, bytes([rev(0)]) + b'\x01'))
    # PPS, PPR (partial page signal / request, the fix reproducer is the all-ones bitmap)
    add('pps', hdlc(0x7d, bytes([0x2d, rev(3), rev(9), rev(17)])))
    add('pps-eop', hdlc(0x7d, bytes([0x74, rev(0), rev(255), rev(1)])))
    add('ppr-none', hdlc(0x3d, b'\x00' * 32))
    add('ppr-some', hdlc(0x3d, bytes([0x81, 0x00, 0xff, 0x01] + [0x00] * 28)))
    add('ppr-all', hdlc(0x3d, b'\xff' * 32))      # reproducer: frame count 256
    add('ppr-all-x', hdlc(0x3d | 0x80, b'\xff' * 31 + b'\xfe'))
    # all the remaining facsimile control codes, no information field
    for fcf, name in FCF_NAMES.items():
        if fcf in (0x01, 0x02, 0x04, 0x41, 0x42, 0x43, 0x44, 0x45, 0x60, 0x3d, 0x7d, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86):
            continue
        add('fcf-%s' % name, hdlc(fcf, b''))
    add('fcf-unknown', hdlc(0x1e, b'\x00'))
    add('fcf-unknown-x', hdlc(0x9e, b'\x00'))
    add('addr-not-ff', hdlc(0x31, b'', addr=0x13))
    add('ctrl-not-c0', hdlc(0x31, b'', ctrl=0x13))
    add('ctrl-c8', hdlc(0x31, b'', ctrl=0xc8))
    return F, R

def malformed_frames():
    F = []; R = {}
    def add(name, fr):
        R[name] = len(F) + 1; F.append(fr)
    add('too-short-2', exp_pdu('t30.hdlc', b'\xff\xc0'))
    add('too-short-0', exp_pdu('t30.hdlc', b''))
    add('dis-2-octets', hdlc(0x01, b'\x00\x00'))
    add('dcs-1-octet', hdlc(0x41, b'\x00'))
    add('dtc-0', hdlc(0x81, b''))
    add('num-short', hdlc(0x42, b'abc'))
    add('num-long', hdlc(0x42, b'x' * 25))
    add('nsf-short', hdlc(0x04, b'\x01'))
    add('nsc-empty', hdlc(0x84, b''))
    add('fcd-empty', hdlc(0x60, b''))
    add('pps-short', hdlc(0x7d, b'\x01\x02'))
    add('pps-long', hdlc(0x7d, b'\x01\x02\x03\x04\x05'))
    add('ppr-short', hdlc(0x3d, b'\x00' * 10))
    add('ppr-long', hdlc(0x3d, b'\xff' * 40))
    add('dis-ext-cut', hdlc(0x01, b'\xff\xff\xff\xff'))     # extension bits set, octets run out
    return F, R

if __name__ == '__main__':
    out = sys.argv[1]
    F, R = main_frames()
    write_pcap(os.path.join(out, 't30-coverage.pcap'), F, dlt=252)
    G, RM = malformed_frames()
    write_pcap(os.path.join(out, 't30-coverage-malformed.pcap'), G, dlt=252)
    if '-v' in sys.argv:
        print(len(F), R); print(len(G), RM)
