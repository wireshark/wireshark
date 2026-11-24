#!/usr/bin/env python3
# Helper module for the tcap capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Comparison capture: ITU TCAP Begin with GSM MAP ACN and N invoke components.

Checks whether ITU TCAP/GSM MAP has the same per-frame layer accumulation as
ANSI TCAP/ANSI MAP. Exported PDU (linktype 252), dissector "tcap".
All data is synthetic.

Usage: ansi_tcap_itu_compare_gen.py <outdir>
"""
import os
import sys

from ansi_tcap_gen import tlv, exp_pdu, write_pcap  # noqa: E402

UNI, APP, CTX = 0, 1, 2


def oid(s):
    a = [int(x) for x in s.split('.')]
    out = bytes([a[0] * 40 + a[1]])
    for v in a[2:]:
        enc = [v & 0x7f]
        v >>= 7
        while v:
            enc.append(0x80 | (v & 0x7f))
            v >>= 7
        out += bytes(reversed(enc))
    return tlv(UNI, 0, 6, out)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    aarq = tlv(APP, 1, 0,
               tlv(CTX, 0, 0, b'\x07\x80') +
               tlv(CTX, 1, 1, oid('0.4.0.0.1.0.21.2')))
    ext = tlv(UNI, 1, 8, oid('0.0.17.773.1.1.1') + tlv(CTX, 1, 0, aarq))
    dlg = tlv(APP, 1, 11, ext)
    # invoke [1] { invokeID INTEGER, opCode localValue INTEGER 46 (mo-forwardSM) }
    n = 600
    comps = b''.join(tlv(CTX, 1, 1, tlv(UNI, 0, 2, bytes([i & 0x7f])) +
                         tlv(UNI, 0, 2, b'\x2e') +
                         tlv(UNI, 1, 16, tlv(CTX, 0, 4, b'\x91\x21\x43')))
                     for i in range(n))
    begin = tlv(APP, 1, 2, tlv(APP, 0, 8, b'\x00\x00\x00\x01') + dlg +
                tlv(APP, 1, 12, comps))
    write_pcap(os.path.join(out, 'ansi_tcap_itu_compare.pcap'),
               [exp_pdu(begin, 'tcap')])


if __name__ == '__main__':
    main()
