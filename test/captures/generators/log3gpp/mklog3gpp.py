#!/usr/bin/env python3
# Generates test/captures/log3gpp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the LOG3GPP coverage captures. Usage: mklog3gpp.py <outdir>

Every record is an Exported PDU frame naming "prot3gpp" followed by the
stub header the wiretap module writes for a 3GPP transcript file: the
timestamp string, the protocol name, a direction byte, the option string
and the data. A transcript text file (log3gpp-coverage.txt) with the same
records is written too; it is read through the real file reader.
"""
import os
SRCDIR = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..', '..'))
import re
import struct
import sys

def exp_pdu(name, payload):
    n = name.encode()
    pad = (4 - len(n) % 4) % 4
    tags = struct.pack('>HH', 12, len(n) + pad) + n + b'\0' * pad + struct.pack('>HH', 0, 0)
    return tags + payload

def pcap(path, pkts, linktype=252):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, p in enumerate(pkts):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
            f.write(p)

def rec(ts, proto, direction, option, data):
    return (ts.encode() + b'\0' + proto.encode() + b'\0' +
            bytes([direction]) + option.encode() + b'\0' + data)

SRC = os.path.join(SRCDIR, 'epan/dissectors/packet-log3gpp.c')

def table_names():
    names = []
    lines = open(SRC).read().split('dissector_lookup_table[] = {')[1].split('};')[0].split('\n')
    for l in lines:
        m = re.match(r'\s*\{"([A-Za-z0-9.\-]+)",', l)
        if m and m.group(1) not in names:
            names.append(m.group(1))
    return names

# Payloads that the sub-dissector accepts without a malformed packet.
# Anything not listed gets the default; mkdefault is tuned by running tshark.
# Payloads found by trying short candidates: the first of a list of candidates that the
# sub-dissector accepts without a malformed packet. Names without one go to
# the malformed capture.
PAYLOAD = {
  'DATA': bytes.fromhex('00'),
  'GAN.TCP': bytes.fromhex('0011223344556677'),
  'GAN.UDP': bytes.fromhex('00'),
  'GSM.CCCH': bytes.fromhex('00'),
  'GSM.SACCH': bytes.fromhex('00'),
  'GTP': bytes.fromhex('00'),
  'LLC': bytes.fromhex('00000000'),
  'LTE-MAC': bytes.fromhex('00'),
  'LTE-PDCP': bytes.fromhex('00'),
  'LTE-RRC.BCCH.BCH': bytes.fromhex('000000'),
  'LTE-RRC.BCCH.DL.SCH': bytes.fromhex('00000000000000000000000000000000000000000000000000000000000000000000000000000000'),
  'LTE-RRC.CCCH': bytes.fromhex('0000000000000000'),
  'LTE-RRC.DCCH': bytes.fromhex('0000000000000000'),
  'LTE-RRC.PCCH': bytes.fromhex('00'),
  'NAS': bytes.fromhex('00'),
  'NAS-EPS': bytes.fromhex('ff'),
  'RR': bytes.fromhex('00'),
  'RRC.BCCH.BCH': bytes.fromhex('0000'),
  'RRC.BCCH.FACH': bytes.fromhex('00'),
  'RRC.CCCH': bytes.fromhex('000000000000000000000000'),
  'RRC.DCCH': bytes.fromhex('000000'),
  'RRC.MCCH': bytes.fromhex('000000'),
  'RRC.MSCH': bytes.fromhex('0000000000000000'),
  'RRC.PCCH': bytes.fromhex('00'),
  'RRC.SHCCH': bytes.fromhex('0000'),
  'RRC.SI.MIB': bytes.fromhex('0000000000000000'),
  'RRC.SI.SB1': bytes.fromhex('00'),
  'RRC.SI.SB2': bytes.fromhex('00'),
  'RRC.SI.SIB10': bytes.fromhex('0000'),
  'RRC.SI.SIB11': bytes.fromhex('0000'),
  'RRC.SI.SIB11bis': bytes.fromhex('00'),
  'RRC.SI.SIB12': bytes.fromhex('0000'),
  'RRC.SI.SIB13-1': bytes.fromhex('0000'),
  'RRC.SI.SIB13-2': bytes.fromhex('0000'),
  'RRC.SI.SIB13-3': bytes.fromhex('0000'),
  'RRC.SI.SIB13-4': bytes.fromhex('0000'),
  'RRC.SI.SIB14': bytes.fromhex('0000'),
  'RRC.SI.SIB15': bytes.fromhex('00000000000000000000000000000000000000000000000000000000000000000000000000000000'),
  'RRC.SI.SIB15-1': bytes.fromhex('000000000000000000000000'),
  'RRC.SI.SIB15-1bis': bytes.fromhex('0000'),
  'RRC.SI.SIB15-2': bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'),
  'RRC.SI.SIB15-2bis': bytes.fromhex('00000000000000000000000000000000'),
  'RRC.SI.SIB15-3': bytes.fromhex('00000000'),
  'RRC.SI.SIB15-3bis': bytes.fromhex('00'),
  'RRC.SI.SIB15-4': bytes.fromhex('00'),
  'RRC.SI.SIB15-5': bytes.fromhex('00'),
  'RRC.SI.SIB15-6': bytes.fromhex('0000000000000000'),
  'RRC.SI.SIB15-7': bytes.fromhex('0000000000000000'),
  'RRC.SI.SIB15-8': bytes.fromhex('00'),
  'RRC.SI.SIB15bis': bytes.fromhex('00000000000000000000000000000000'),
  'RRC.SI.SIB17': bytes.fromhex('00'),
  'RRC.SI.SIB18': bytes.fromhex('00'),
  'RRC.SI.SIB2': bytes.fromhex('0000'),
  'RRC.SI.SIB3': bytes.fromhex('000000000000000000000000'),
  'RRC.SI.SIB4': bytes.fromhex('000000000000000000000000'),
  'RRC.SI.SIB5': bytes.fromhex('000000000000000000000000'),
  'RRC.SI.SIB5bis': bytes.fromhex('000000000000000000000000'),
  'RRC.SI.SIB6': bytes.fromhex('0000'),
  'RRC.SI.SIB7': bytes.fromhex('000000'),
  'RRC.SI.SIB8': bytes.fromhex('00000000000000000000000000000000000000000000000000000000000000000000000000000000'),
  'RRC.SI.SIB9': bytes.fromhex('0000'),
  'SNDCP': bytes.fromhex('00'),
  'SNDCPXID': bytes.fromhex('00'),
}
SKIP_MAIN = set(['LTE-RLC', 'RRC.SI.SIB1', 'RRC.SI.SIB13'])
DEFAULT = bytes.fromhex('0011223344556677')

def main(out):
    names = [n for n in table_names()]
    main_pkts, bad_pkts, txt = [], [], []
    t = 0
    def ts():
        nonlocal t
        t += 1
        return '%d.%04d' % (t // 7, (t * 137) % 10000)
    # Reproducers of "log3gpp: Fix unsorted lookup table ...": SIB17,
    # SIB15bis, SIB18 and SIB15-1 were not found by the binary search.
    for n in ('RRC.SI.SIB17', 'RRC.SI.SIB15bis', 'RRC.SI.SIB18', 'RRC.SI.SIB15-1'):
        main_pkts.append(exp_pdu('prot3gpp', rec(ts(), n, 1, '', PAYLOAD.get(n, b'\x00\x11\x22'))))
    for n in names:
        for d in (0, 1):
            data = PAYLOAD.get(n, DEFAULT)
            p = exp_pdu('prot3gpp', rec(ts(), n, d, '', data))
            if n in SKIP_MAIN:
                bad_pkts.append(p)
            else:
                main_pkts.append(p)
            txt.append('%s %s %s $%s' % (ts(), n, 'ud'[d], data.hex()))
    # Unknown protocol names (not in the table), before, between and after
    # the table entries, so the binary search misses on every side
    for n in ('AAA', 'RRC.SI.SIB16', 'ZZZ', 'LTE-RRC', 'RRC.SI.SIB15-9'):
        main_pkts.append(exp_pdu('prot3gpp', rec(ts(), n, 0, '', DEFAULT)))
        main_pkts.append(exp_pdu('prot3gpp', rec(ts(), n, 1, '', DEFAULT)))
        txt.append('%s %s u $%s' % (ts(), n, DEFAULT.hex()))
    # Option strings (only used for the MAC/RLC/PDCP pseudo headers, which
    # are never selected, see README) and an empty data part
    for n, o in (('LTE-MAC', 'FDD C_RNTI 17 SFN 3'), ('LTE-PDCP', 'SRB SN_12b'), ('DATA', 'opt a b'), ('DATA', '')):
        main_pkts.append(exp_pdu('prot3gpp', rec(ts(), n, 0, o, DEFAULT)))
        txt.append('%s %s u %s$%s' % (ts(), n, o, DEFAULT.hex()))
    bad_pkts.append(exp_pdu('prot3gpp', rec(ts(), 'DATA', 1, '', b'')))
    bad_pkts.append(exp_pdu('prot3gpp', rec(ts(), 'LTE-RLC', 0, 'SRB 1 AM', DEFAULT)))
    # Text records
    for s in (b'Hello from the transcript\0', b'second text line\0', b'\0'):
        main_pkts.append(exp_pdu('prot3gpp', rec(ts(), 'TXT', 0, '', s)))
    txt.append('%s TXT Hello from the transcript' % ts())
    txt.append('%s TXT second text line' % ts())
    # Timestamp strings the double conversion handles differently
    for tsv in ('0.0000', '123456.5000', '1.', 'x'):
        main_pkts.append(exp_pdu('prot3gpp', rec(tsv, 'DATA', 0, '', DEFAULT)))
    pcap(os.path.join(out, 'log3gpp-coverage.pcap'), main_pkts)
    # Malformed capture: truncated stub headers (exceptions)
    full = rec('1.0000', 'DATA', 0, 'o', DEFAULT)
    for cut in (3, 9, 14, 16, 18):
        bad_pkts.append(exp_pdu('prot3gpp', full[:cut]))
    bad_pkts.append(exp_pdu('prot3gpp', rec('1.0000', 'DATA', 0, 'o', b'')[:-1]))
    pcap(os.path.join(out, 'log3gpp-coverage-malformed.pcap'), bad_pkts)
    with open(os.path.join(out, 'log3gpp-coverage.txt'), 'w') as f:
        f.write('3GPP protocols transcript\n')
        f.write('January 2, 2024 03:04:05.0000\n')
        f.write('\n'.join(txt) + '\n')
    print(len(main_pkts), len(bad_pkts), len(txt))

main(sys.argv[1])
