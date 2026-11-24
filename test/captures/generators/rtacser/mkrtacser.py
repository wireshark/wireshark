#!/usr/bin/env python3
# Generates test/captures/rtacser_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the RTAC Serial (DLT 250, LINKTYPE_RTAC_SERIAL) coverage captures.
Usage: mkrtacser.py <outdir> [-v]. Everything is synthetic."""
import struct
import sys
import os

def crc16(b):
    c = 0xffff
    for x in b:
        c ^= x
        for _ in range(8):
            c = (c >> 1) ^ 0xa001 if c & 1 else c >> 1
    return struct.pack('<H', c)

def rtu(pdu):
    return pdu + crc16(pdu)

def hdr(sec, usec, event, ctrl, footer=0):
    return struct.pack('!IIBBH', sec, usec, event, ctrl, footer)

def write_pcap(path, frames, linktype=250):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)

EV = ['STATUS_CHANGE', 'DATA_TX_START', 'DATA_RX_START', 'DATA_TX_END', 'DATA_RX_END', 'CAPTURE_DATA_LOST',
      'CAPTURE_COMPLETE', 'FRAMING_ERROR', 'PARITY_ERROR', 'SERIAL_BREAK_EVENT', 'SERIAL_OVERFLOW_EVENT']
def main_frames():
    F = []; marks = []
    def mark(t): marks.append((len(F) + 1, t))
    mark('every event type (0-10) and an unknown one (11) without payload; control lines 0x00')
    t0 = 1700000000
    for e in range(12):
        F.append(hdr(t0 + e, 90000 * e, e, 0x00))
    mark('every control line alone (CTS, DCD, DSR, RTS, DTR, RING, MBOK), all set (0x7f) and the unused bit 0x80, footer values')
    for i, c in enumerate([0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x7f, 0x80, 0xff]):
        F.append(hdr(t0 + 20 + i, 5, 0, c, footer=i * 0x1111 & 0xffff))
    mark('payload (a Modbus RTU request and response, dissected as mbrtu with Decode As; data otherwise) on TX and RX events')
    F.append(hdr(t0 + 40, 1, 1, 0x58) + rtu(bytes([1, 3, 0, 0, 0, 2])))
    F.append(hdr(t0 + 40, 9000, 3, 0x48))
    F.append(hdr(t0 + 41, 1, 2, 0x41) + rtu(bytes([1, 3, 4, 0, 10, 0, 20])))
    F.append(hdr(t0 + 41, 9000, 4, 0x41))
    F.append(hdr(t0 + 42, 1, 1, 0x18) + rtu(bytes([2, 6, 0, 1, 0, 3])))
    F.append(hdr(t0 + 42, 2, 2, 0x18) + b'\x01')            # one payload octet
    F.append(hdr(t0 + 43, 0, 0xff, 0x00) + bytes(range(64)))  # unknown event with 64 payload octets
    mark('timestamps: zero, microseconds 999999 and a large second count')
    F.append(hdr(0, 0, 0, 0))
    F.append(hdr(0xffffffff, 999999, 0, 0))
    F.append(hdr(1, 1000000, 0, 0))                          # microseconds out of range
    mark('a record shorter than the 12 octet header (the dissector declines it: "Packet")')
    F.append(b'\x00\x01\x02\x03\x04')
    return F, marks

def mal_frames():
    return [b'', b'\x00' * 5, b'\x00' * 11, hdr(0, 0, 0, 0)[:11] + b'\x00']

if __name__ == '__main__':
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    m, marks = main_frames(); x = mal_frames()
    write_pcap(os.path.join(out, 'rtacser-coverage.pcap'), m)
    write_pcap(os.path.join(out, 'rtacser-coverage-malformed.pcap'), x)
    if '-v' in sys.argv:
        for n, t in marks: print(n, t)
        print(len(m), 'frames', len(x), 'malformed')
