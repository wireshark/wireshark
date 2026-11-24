#!/usr/bin/env python3
# Generates test/captures/umts_pcap_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Write the synthetic UMTS PCAP (Iupc, packet-pcap.c) coverage captures.

Usage: mkpcap.py <outdir> [<wireshark asn1 dir>]

packet-pcap.c is generated from epan/dissectors/asn1/pcap. Every PCAP
message (each elementary procedure as initiating message, successful
outcome, unsuccessful outcome and outcome where the procedure has them)
is encoded with aper.py (a small ASN.1 reader and aligned PER encoder that
reads the same modules), NVARIANTS times: every optional component and
every IE of each IE set present, a different CHOICE alternative per
variant, plus one message with only the mandatory parts. The PDUs are
carried in Exported PDU frames that name the "pcap" dissector (PCAP has no
default SCCP subsystem number; see runcov.sh for the SCCP route).
Nothing comes from a real network.
"""
import os
SRCDIR = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..', '..'))
import struct
import sys

import aper

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'
ASNROOT = sys.argv[2] if len(sys.argv) > 2 else os.path.join(SRCDIR, 'epan/dissectors/asn1')
PCAP = ['PCAP-CommonDataTypes.asn', 'PCAP-Constants.asn', 'PCAP-Containers.asn',
        'PCAP-IEs.asn', 'PCAP-PDU-Contents.asn', 'PCAP-PDU-Descriptions.asn']
NVARIANTS = int(os.environ.get('NVARIANTS', '12'))
# procedures with CHOICEs that have many alternatives get more variants
EXTRA = {('id-InformationExchangeInitiation', '&InitiatingMessage'): 40}
KINDS = ['&InitiatingMessage', '&SuccessfulOutcome', '&UnsuccessfulOutcome', '&Outcome']


def _bytes(data):
    b = aper.Bits()
    b.octets(data)
    return b


def ov_private(sp, w, t, mod, ctx):
    # PrivateIE-Container: SEQUENCE (SIZE(1..65535)) OF PrivateIE-Field; the
    # PrivateMessage-IEs set is empty, so write a local id and, in the
    # malformed capture, a global id
    glob = ctx.vals.get('private_global', False)
    w.align()
    w.b(1 if glob else 0, 16)
    w.b(0, 1)               # PrivateIE-ID: local
    w.align()
    w.b(7, 16)
    w.b(1, 2)               # ignore
    sp.opentype(w, _bytes(b'\xab\xcd'))
    if not glob:
        return
    w.b(1, 1)               # PrivateIE-ID: global
    oid = bytes([0x2b, 6, 1, 4, 1, 0x83, 0xa0, 0x1c, 99])
    w.lendet(len(oid))
    w.octets(oid)
    w.b(0, 2)               # reject
    sp.opentype(w, _bytes(b'\x01\x02\x03'))


def ov_imsi(sp, w, t, mod, ctx):
    # IMSI is a TBCD string (low nibble first, filler f): 15 digits in 8
    # octets, or 5 digits in 3 octets
    digits = '001010123456789' if ctx.k % 2 == 0 else '00101'
    d = digits + ('f' if len(digits) % 2 else '')
    data = bytes((int(d[i + 1], 16) << 4) | int(d[i], 16) for i in range(0, len(d), 2))
    sp.enc_octets(w, t, data, None, mod)


OVERRIDES = {'PrivateIE-Container': ov_private, 'IMSI': ov_imsi}


def exported_pdu(name, payload):
    n = name.encode() + b'\0'
    n += b'\0' * ((4 - len(n) % 4) % 4)
    return struct.pack('>HH', 12, len(n)) + n + struct.pack('>HH', 0, 0) + payload


def write_pcap(name, frames, link=252):
    with open(name, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, link))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)


def main():
    sp = aper.Spec([os.path.join(ASNROOT, 'pcap', f) for f in PCAP], OVERRIDES)
    procs = sp.procedures('PCAP-ELEMENTARY-PROCEDURES', 'PCAP-PDU-Descriptions')
    frames, pdus, ranges = [], [], []
    for o, om in procs:
        for kind, f in enumerate(KINDS):
            if f not in o:
                continue
            start = len(frames)
            for k in range(EXTRA.get((o['&procedureCode'], f), NVARIANTS)):
                b = sp.pdu('PCAP-PDU', 'PCAP-PDU-Descriptions', kind, (o, om), aper.Ctx(k=k))
                pdus.append(b)
                frames.append(exported_pdu('pcap', b))
            for k in range(2):
                # the CHOICE extension alternatives, and both objects of the
                # extension single containers
                b = sp.pdu('PCAP-PDU', 'PCAP-PDU-Descriptions', kind, (o, om),
                           aper.Ctx(k=k, vals={'ext': True}))
                pdus.append(b)
                frames.append(exported_pdu('pcap', b))
            b = sp.pdu('PCAP-PDU', 'PCAP-PDU-Descriptions', kind, (o, om), aper.Ctx(k=0, full=False))
            frames.append(exported_pdu('pcap', b))
            ranges.append((o['&procedureCode'], f, start + 1, len(frames)))
    write_pcap(os.path.join(OUT, 'pcap-coverage.pcap'), frames)

    mal = []
    for b in pdus[::5]:
        mal.append(exported_pdu('pcap', b[:len(b) // 2]))
    for b in pdus[1::11]:
        x = bytearray(b)
        x[len(x) // 3] ^= 0xff
        mal.append(exported_pdu('pcap', bytes(x)))
    priv = [p for p in procs if p[0]['&procedureCode'] == 'id-privateMessage']
    if priv:
        mal.append(exported_pdu('pcap', sp.pdu('PCAP-PDU', 'PCAP-PDU-Descriptions', 0, priv[0],
                                               aper.Ctx(vals={'private_global': True}))))
    # an Outcome PDU: no PCAP procedure defines one, so the open type goes
    # to the empty pcap.proc.out table and is left as data
    w = aper.Bits()
    w.b(0, 1); w.b(3, 2)        # not extended, CHOICE alternative 3 (outcome)
    w.align(); w.b(1, 8)        # procedureCode
    w.b(0, 2)                   # criticality
    w.b(0, 1); w.b(0, 1); w.b(5, 7)   # TransactionID: shortTID 5
    w.align(); w.b(2, 8); w.b(0xab, 8); w.b(0xcd, 8)    # open type
    mal.append(exported_pdu('pcap', w.get()))
    mal.append(exported_pdu('pcap', b'\x00'))
    write_pcap(os.path.join(OUT, 'pcap-coverage-malformed.pcap'), mal)
    for r in ranges:
        print(r)
    print(len(frames), len(mal), sum(len(f) for f in frames))


if __name__ == '__main__':
    main()
