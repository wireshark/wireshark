#!/usr/bin/env python3
# Generates test/captures/gsm_abis_pgsl_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic captures for packet-gsm_abis_pgsl.c (Ericsson P-GSL, PCU - CCU
Abis frames).
Usage: mkgsm_abis_pgsl.py <outdir> [-v]

P-GSL is registered in the lapd.gsm.sapi table for SAPI 12, so every frame is
a LAPD (pcap linktype 203) UI frame (needs lapd.use_gsm_sapi_values:TRUE).
The Incremental Redundancy header (preference gsm_abis_pgsl.ir) changes the
layout of DLDATA-IND, so the capture has a section for each setting."""
import struct
import sys

def write_pcap(path, linktype, pkts):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, p in enumerate(pkts):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
            f.write(p)

def lapd(sapi, tei, payload, cr=0):
    return bytes([(sapi << 2) | (cr << 1), (tei << 1) | 1, 0x03]) + payload

def fn3(fn):
    return struct.pack('<I', fn)[:3]

# RLC/MAC payloads -------------------------------------------------------
GPRS_LEN = {1: 23, 2: 34, 3: 40, 4: 54}

def rlc_ul_data(n, tfi=5, bsn=3, cv=15, si=0, e=1, ti=0, fill=0x2b):
    b = bytearray([fill]) * n
    b[0] = (0 << 6) | (cv << 2) | (si << 1)          # payload type 0, countdown, stall, retry
    b[1] = (0 << 7) | (tfi << 2) | (ti << 1)         # PI, TFI, TI
    b[2] = (bsn << 1) | e                            # BSN, E
    return bytes(b)

def rlc_dl_data(n, tfi=5, bsn=3, usf=1, rrbp=0, sp=0, fbi=0, e=1, pr=0, fill=0x2b):
    b = bytearray([fill]) * n
    b[0] = (0 << 6) | (rrbp << 4) | (sp << 3) | usf
    b[1] = (pr << 6) | (tfi << 1) | fbi
    b[2] = (bsn << 1) | e
    return bytes(b)

def ul_ctrl_ack(n=23):
    # Packet Control Acknowledgement: payload type 1, message type 0b001010
    b = bytearray([0x2b]) * n
    b[0] = 0x40 | 0x00
    b[1] = 0x28
    b[2:] = bytes(n - 2)
    return bytes(b)

def dl_ctrl_dummy(n=23):
    # Packet Dummy Control Block: payload type 1, message type 0b100111?
    b = bytearray([0x2b]) * n
    b[0] = 0x40 | 0x01
    b[1] = 0x9c
    return bytes(b)

# EGPRS radio blocks: a header of the given type followed by 0xff (every
# bit pattern of the RLC data block parts is then FBI=1, E=1, no length
# indicators, whichever the alignment); the headers differ in the coding and
# puncturing scheme they select, which sets the size of the data blocks
EGPRS_DL_HDR = {1: ['82b70eee7f', '1a5039bef0', '7ec2347f06', '6ed08f5dc7'],
                2: ['a537bf7f', '336c969c', '89275527', 'd35e7320'],
                3: ['5d034c', 'd93503', 'eea628', 'f94dbc']}
EGPRS_UL_HDR = {1: ['267dd83835', '79c762f2bb', 'cfd305efac', '77a0fc846b'],
                2: ['3d01dbaf1c', '030e98be5b', '7eb050db64', '65f683a6e7'],
                3: ['0da1f20d', 'd3c30109', '39b5dd39', 'bc5ab1d5']}
EGPRS_LEN = {1: 160, 2: 90, 3: 60}

def egprs_ul(htype, k=0):
    h = bytes.fromhex(EGPRS_UL_HDR[htype][k % 4])
    return h + b'\xff' * (EGPRS_LEN[htype] - len(h))

def egprs_dl(htype, k=0):
    h = bytes.fromhex(EGPRS_DL_HDR[htype][k % 4])
    return h + b'\xff' * (EGPRS_LEN[htype] - len(h))

def access_burst(rxlev, delay, abi, abtype, data):
    return bytes([rxlev, delay & 0xff, ((abi & 7) << 4) | ((abtype & 3) << 2) | ((delay >> 8) & 3)]) + data

# P-GSL messages ---------------------------------------------------------
def hdr(msg, version=1):
    return bytes([(version << 4) | msg])

def dldata_req(tnbm, seq, fn, ta, ack):
    return hdr(1) + bytes([tnbm, seq]) + fn3(fn) + bytes([ta, ack])

def dldata_ind(tn, seq, fn, ack, data=None, cs=1, ucm=1, timing=2, power=3, ir=None):
    b = hdr(2) + bytes([tn, seq]) + fn3(fn) + bytes([ack])
    if ack & 1:
        b += bytes([(ucm << 5) | cs, timing, power])
        if ir is not None:
            b += bytes([(ir[0] << 2) | ir[1], ir[2]])
        b += bytes([len(data)]) + data
    return b

def uldata_ind(tn, seq, fn, cs, delay, rxlev, q2, q3, data):
    return hdr(3) + bytes([tn, seq]) + fn3(fn) + bytes([(delay << 5) | cs, rxlev, q2, q3, len(data)]) + data

def status_ind(tn, seq, fn, cause, info):
    return hdr(4) + bytes([tn, seq]) + fn3(fn) + bytes([cause, info])

def main():
    out = sys.argv[1]
    verbose = '-v' in sys.argv
    frames, notes = [], []
    bad, badnotes = [], []

    def add(note, payload, sapi=12, to_bad=False):
        fr = lapd(sapi, 0, payload)
        if to_bad:
            bad.append(fr); badnotes.append((len(bad), note))
        else:
            frames.append(fr); notes.append((len(frames), note))

    sections = []
    sections.append(('IR off (default)', 1))
    # DLDATA-REQ
    for i in range(4):
        add('DLDATA-REQ', dldata_req(0x01 << i, i, 1000 + i, 0x3f if i == 3 else i * 5, i & 1))
    # DLDATA-IND: ACK only (no data), data with each GPRS CS, PRACH, and EGPRS header types
    add('DLDATA-IND, ACK indicator only', dldata_ind(1, 1, 5000, 0x02))
    add('DLDATA-IND, neither', dldata_ind(2, 2, 5001, 0x00))
    for cs in (1, 2, 3, 4):
        add('DLDATA-IND CS-%d data block' % cs, dldata_ind(cs, cs, 5100 + cs, 0x03, rlc_dl_data(GPRS_LEN[cs]), cs=cs, ucm=cs & 3 or 1))
    add('DLDATA-IND CS-1 control block', dldata_ind(3, 9, 5110, 0x01, dl_ctrl_dummy(), cs=1))
    for ucm in (1, 2, 3, 4):
        add('DLDATA-IND ucm %d' % ucm, dldata_ind(1, 7, 5120 + ucm, 0x01, rlc_dl_data(23), cs=1, ucm=ucm, timing=ucm * 3, power=ucm))
    add('DLDATA-IND AB (cs 0)', dldata_ind(4, 3, 5130, 0x01, access_burst(30, 100, 7, 0, b'\x12\x34') * 4, cs=0, ucm=3))
    for k in range(4):
        for cs in (5, 6, 7):
            add('DLDATA-IND header type %d, variant %d' % (cs - 4, k), dldata_ind(5, cs, 5140 + cs, 0x01, egprs_dl(cs - 4, k), cs=cs, ucm=2))
    add('DLDATA-IND CS 8, handled as CS-1', dldata_ind(5, 8, 5150, 0x01, rlc_dl_data(23), cs=8))
    add('DLDATA-IND CS 31, handled as CS-1', dldata_ind(5, 9, 5151, 0x01, rlc_dl_data(23), cs=31))
    # ULDATA-IND
    for cs in (1, 2, 3, 4):
        add('ULDATA-IND CS-%d data block' % cs, uldata_ind(cs, cs, 6000 + cs, cs, cs, 20 + cs, (cs & 1) << 3 | cs, 0, rlc_ul_data(GPRS_LEN[cs])))
    add('ULDATA-IND CS-1 control block', uldata_ind(2, 3, 6010, 1, 0, 33, 0x0f, 0, ul_ctrl_ack()))
    add('ULDATA-IND AB, four valid access bursts', uldata_ind(6, 4, 6020, 0, 2, 40,
        0, 0, access_burst(30, 100, 7, 0, b'\x55\xaa') + access_burst(31, 0x3ff, 7, 1, b'\x12\x34') +
              access_burst(32, 5, 7, 2, b'\x11\x22') + access_burst(33, 900, 7, 3, b'\x33\x44')))
    add('ULDATA-IND AB, invalid bursts', uldata_ind(6, 5, 6021, 0, 0, 41, 0, 0,
        access_burst(10, 0, 0, 0, b'\0\0') + access_burst(11, 1, 0, 1, b'\0\0') +
        access_burst(12, 2, 7, 2, b'\x09\x08') + access_burst(13, 3, 0, 3, b'\0\0')))
    for k in range(4):
        for cs in (5, 6, 7):
            add('ULDATA-IND header type %d, variant %d' % (cs - 4, k), uldata_ind(1, cs, 6030 + cs, cs, 7, 63, 0x55, 0xff, egprs_ul(cs - 4, k)))
    add('ULDATA-IND EGPRS status, header and block quality bits', uldata_ind(1, 9, 6040, 6, 3, 10, 0x7f, 0x3f, egprs_ul(2, 1)))
    add('ULDATA-IND CS 8', uldata_ind(1, 10, 6041, 8, 0, 10, 0x01, 0x03, rlc_ul_data(23)))
    # STATUS-IND with every cause
    for cause in (0, 1, 2, 3, 4):
        add('STATUS-IND cause %d' % cause, status_ind(cause, 20 + cause, 7000 + cause, cause, 0x10 + cause))
    # unknown message discriminators and a different version
    for d in (0, 5, 15):
        add('unknown message discriminator %d' % d, hdr(d) + bytes(8))
    add('version 2', hdr(4, 2) + bytes([1, 2]) + fn3(77) + bytes([1, 2]))
    ir_first = len(frames) + 1
    sections.append(('IR on (gsm_abis_pgsl.ir:TRUE)', ir_first))
    # Incremental Redundancy header present
    for sign in range(4):
        add('DLDATA-IND with IR header, type %d' % sign, dldata_ind(1, 1, 8000 + sign, 0x01, rlc_dl_data(23), cs=1, ir=(sign * 7, sign, 0x0f << sign & 0xff)))
    add('DLDATA-IND with IR header, CS-4', dldata_ind(1, 5, 8010, 0x03, rlc_dl_data(54), cs=4, ir=(31, 3, 0xff)))
    add('DLDATA-IND with IR header, header type 1', dldata_ind(1, 6, 8011, 0x01, egprs_dl(1, 2), cs=5, ir=(1, 1, 3)))
    add('DLDATA-IND with IR header, ACK only', dldata_ind(1, 7, 8012, 0x02))
    write_pcap(out + '/gsm_abis_pgsl-coverage.pcap', 203, frames)

    # malformed
    add('DLDATA-REQ cut', hdr(1) + bytes([1, 2, 3]), to_bad=True)
    add('DLDATA-IND cut in the frame number', hdr(2) + bytes([1, 2, 3]), to_bad=True)
    add('DLDATA-IND data length longer than the data', dldata_ind(1, 1, 5, 0x01, rlc_dl_data(23), cs=1)[:-10], to_bad=True)
    add('DLDATA-IND codec control cut', hdr(2) + bytes([1, 2]) + fn3(5) + bytes([0x01, 0x21]), to_bad=True)
    add('DLDATA-IND AB with too little data', dldata_ind(1, 1, 5, 0x01, b'\x01' * 7, cs=0), to_bad=True)
    add('DLDATA-IND header type 1 with 3 octets', dldata_ind(1, 1, 5, 0x01, b'\x01\x02\x03', cs=5), to_bad=True)
    add('DLDATA-IND header type 2 with 5 octets', dldata_ind(1, 1, 5, 0x01, bytes(5), cs=6), to_bad=True)
    add('DLDATA-IND header type 3 with 4 octets', dldata_ind(1, 1, 5, 0x01, bytes(4), cs=7), to_bad=True)
    add('ULDATA-IND cut', hdr(3) + bytes([1, 2]) + fn3(1) + bytes([0x21, 5]), to_bad=True)
    add('ULDATA-IND empty data', uldata_ind(1, 1, 2, 1, 0, 1, 0, 0, b''), to_bad=True)
    add('ULDATA-IND AB cut', uldata_ind(1, 1, 2, 0, 0, 1, 0, 0, bytes(12)), to_bad=True)
    add('ULDATA-IND header type 3 short', uldata_ind(1, 1, 2, 7, 0, 1, 0, 0, bytes(3)), to_bad=True)
    add('STATUS-IND cut', hdr(4) + bytes([1, 2, 3]), to_bad=True)
    add('only the first octet', hdr(2), to_bad=True)
    add('GPRS block too short for RLC/MAC', dldata_ind(1, 1, 5, 0x01, b'\x00', cs=2), to_bad=True)
    add('IR header cut', hdr(2) + bytes([1, 2]) + fn3(5) + bytes([0x01, 0x21, 1, 2, 3]), to_bad=True)
    write_pcap(out + '/gsm_abis_pgsl-coverage-malformed.pcap', 203, bad)
    write_pcap(out + '/.ir.pcap', 203, [])    # placeholder removed below
    import os; os.remove(out + '/.ir.pcap')
    if verbose:
        for name, first in sections:
            print('section from frame %d: %s' % (first, name))
        for n, t in notes: print(n, t)
        print('--- malformed')
        for n, t in badnotes: print(n, t)
    print(len(frames), 'frames,', len(bad), 'malformed;', ', '.join('%s from %d' % (n, f) for n, f in sections))

main()
