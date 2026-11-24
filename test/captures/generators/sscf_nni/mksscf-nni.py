#!/usr/bin/env python3
# Generates test/captures/sscf_nni_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic captures for packet-sscf-nni.c (SSCF-NNI, MTP3-b over SSCOP).
# Usage: mksscf-nni.py <outdir>
# SSCF-NNI is only reached as the payload of SSCOP Sequenced Data PDUs when
# the SSCOP payload preference is "SSCF-NNI" (-o sscop.payload:SSCF-NNI):
# the frames are SunATM frames of the signalling AAL.
import os
import struct
import sys
from pcaplib import Pcap

DLT_SUNATM = 123
SD = 8

def u24(x): return struct.pack('!I', x & 0xffffff)[1:]

def atm(pdu, flags=0x06, vpi=0, vci=5):
    return struct.pack('!BBH', flags, vpi, vci) + pdu

def sd(payload, ns):
    pad = (-len(payload)) % 4
    return payload + b'\0' * pad + bytes([SD | (pad << 6)]) + u24(ns)

def mtp3_label(dpc, opc, sls):
    return struct.pack('<I', (dpc & 0x3fff) | ((opc & 0x3fff) << 14) | ((sls & 0xf) << 28))

def sltm(dpc, opc, sls, pattern=b'ABCD', resp=False):
    h = 0x21 if resp else 0x11
    return (bytes([0x01]) + mtp3_label(dpc, opc, sls) + bytes([h, (len(pattern) << 4) | 0x0]) + pattern)

def sscf_status(status):
    return b'\0\0\0' + bytes([status])

def main(out):
    p = Pcap(DLT_SUNATM)
    n = [0]
    def add(payload, **kw):
        p.add(atm(sd(payload, n[0]), **kw))
        n[0] += 1
    # 1-12: SSCF-NNI status PDUs (4 octets): every status value, then an unknown one
    for st in (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0xff):
        add(sscf_status(st))
    # 13: a status PDU with a non-zero spare field
    add(b'\x00\x12\x34\x04')
    # 14-17: MTP3-b signalling messages (longer than four octets) go to MTP3
    add(sltm(0x0101, 0x0202, 3))
    add(sltm(0x0202, 0x0101, 3, resp=True))
    add(sltm(0x0101, 0x0202, 4, pattern=b'ABCDEFGHIJKL'))
    add(bytes([0x03]) + mtp3_label(0x0101, 0x0202, 1) + bytes([0x09, 0x00, 0x03, 0x05, 0x07, 0x02, 0x42, 0xf0, 0x02, 0x42, 0xf0, 0x03, 0xaa, 0xbb, 0xcc]))     # SCCP UDT
    p.write(os.path.join(out, 'sscf-nni-coverage.pcap'))

    m = Pcap(DLT_SUNATM)
    n[0] = 0
    # an SD PDU whose payload is empty: nothing for SSCF-NNI to look at
    m.add(atm(bytes([SD]) + u24(0)))
    # a status PDU with no payload beyond the SSCOP trailer
    m.add(atm(b'\x00\x00\x00' + bytes([SD | (3 << 6)]) + u24(1)))
    # a one to three octet payload: shorter than the status PDU
    m.add(atm(sd(b'\x04', 2)))
    m.add(atm(sd(b'\x00\x04', 3)))
    # an MSU too short for the MTP3 label
    m.add(atm(sd(b'\x01\x02\x03\x04\x05', 4)))
    m.write(os.path.join(out, 'sscf-nni-coverage-malformed.pcap'))

main(sys.argv[1] if len(sys.argv) > 1 else '.')
