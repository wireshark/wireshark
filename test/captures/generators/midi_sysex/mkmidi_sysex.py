#!/usr/bin/python3
# Generates test/captures/midi_sysex_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the MIDI SysEx coverage captures. Usage: mkmidi_sysex.py <outdir> [-v]
Writes midi-sysex-coverage.pcap and midi-sysex-coverage-malformed.pcap
(Exported PDU, link type 252, dissector name "midi_sysex"). Synthetic."""
import struct
import sys
import os

P = struct.pack

def exp_pdu(name, payload):
    n = name.encode()
    pad = (4 - len(n) % 4) % 4
    return P('>HH', 12, len(n) + pad) + n + b'\0' * pad + P('>HH', 0, 0) + payload

def write_pcap(fn, pkts):
    with open(fn, 'wb') as f:
        f.write(P('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 252))
        for i, p in enumerate(pkts):
            f.write(P('<IIII', 1700000000 + i, 0, len(p), len(p)))
            f.write(p)

def sysex(manu, payload=b'', start=0xF0, end=0xF7):
    return exp_pdu('midi_sysex', bytes([start]) + manu + payload + bytes([end]))

def digitech(device, family, product, proc, packed=b''):
    body = bytes([device, family, product, proc]) + packed
    c = 0x10
    for b in body:
        c ^= b
    return body + bytes([c])

def build():
    main = []
    # one-byte manufacturer IDs (payload is not decoded)
    main.append(sysex(b'\x41', bytes.fromhex('10 42 12 40 00 7f 00 41')))      # Roland
    main.append(sysex(b'\x43', bytes.fromhex('10 4c 00 00 7e 00')))            # Yamaha
    main.append(sysex(b'\x42', b'\x30\x00\x01'))                                # Korg
    main.append(sysex(b'\x01', b'\x00'))                                        # Sequential
    main.append(sysex(b'\x7e', bytes.fromhex('7f 06 01')))                      # universal non-real time
    main.append(sysex(b'\x7f', bytes.fromhex('7f 04 01 7f 7f')))                # universal real time
    main.append(sysex(b'\x7d', b'research'))                                    # non-commercial
    # three-byte manufacturer IDs
    main.append(sysex(b'\x00\x20\x29', bytes.fromhex('00 20 33 01 01')))        # Novation
    main.append(sysex(b'\x00\x21\x1d', b'\x01\x02'))                            # unknown extended id
    main.append(sysex(b'\x00\x01\x55', b'\x7f'))
    # no payload
    main.append(sysex(b'\x41'))
    main.append(sysex(b'\x00\x20\x29'))
    # DigiTech (manufacturer ID 00 00 10): decoded by the DigiTech dissector
    main.append(exp_pdu('midi_sysex', b'\xF0\x00\x00\x10' + digitech(0x7F, 0x5E, 0x05, 0x01, bytes([0x00, 0x7F, 0x5E, 0x05])) + b'\xF7'))
    # long payload
    main.append(sysex(b'\x41', bytes(range(0x7f)) * 4))
    marks = len(main)

    mal = []
    mal.append(sysex(b'\x41', b'\x10\x42', start=0xF1))                       # wrong start byte
    mal.append(sysex(b'\x41', b'\x10\x42', end=0xF0))                         # wrong end byte
    mal.append(sysex(b'\x00\x20\x29', b'\x01', start=0x00, end=0x00))         # both
    mal.append(exp_pdu('midi_sysex', b'\xF0'))                                # nothing after the start byte
    mal.append(exp_pdu('midi_sysex', b'\xF0\x00\x20'))                        # three-byte ID cut short
    mal.append(exp_pdu('midi_sysex', b'\xF0\xF7'))                            # EOX as manufacturer
    mal.append(exp_pdu('midi_sysex', b'\xF0\x41\xF7'))                        # exactly one octet less than a payload
    return main, mal, marks

if __name__ == '__main__':
    out = sys.argv[1]
    main, mal, marks = build()
    write_pcap(os.path.join(out, 'midi-sysex-coverage.pcap'), main)
    write_pcap(os.path.join(out, 'midi-sysex-coverage-malformed.pcap'), mal)
    if '-v' in sys.argv:
        print('main frames %d; malformed %d' % (len(main), len(mal)))
