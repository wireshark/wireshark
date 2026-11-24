#!/usr/bin/env python3
# Generates test/captures/packetlogger_coverage.pklg.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generator for the PacketLogger coverage captures. Usage: mkpacketlogger.py <outdir> [-v]
# The captures are Apple PacketLogger files (extension .pklg): records of a
# 32 bit length, seconds and microseconds in host (little-endian) byte order
# followed by a type octet and the payload. The file format is recognised by
# content, so no option is needed.
import os
import struct
import sys

def rec(ptype, payload=b'', t=0, us=0):
    return struct.pack('<III', 8 + 1 + len(payload), 1700000000 + t, us) + bytes([ptype]) + payload

def hci_cmd(opcode, params=b''): return struct.pack('<HB', opcode, len(params)) + params
def hci_evt(code, params=b''): return bytes([code, len(params)]) + params
def acl(handle, data): return struct.pack('<HH', handle, len(data)) + data
def l2cap(cid, data): return struct.pack('<HH', len(data), cid) + data
def sco(handle, data): return struct.pack('<HB', handle, len(data)) + data
def syslog(pid, mtype, process, sender, subsystem, category, message):
    return struct.pack('<IB', pid, mtype) + b''.join(s.encode() + b'\0' for s in (process, sender, subsystem, category, message))

def main_records():
    R, marks = [], []
    def mark(n): marks.append((n, len(R) + 1))
    def add(ptype, payload=b'', us=0): R.append(rec(ptype, payload, len(R), us))
    mark('HCI over PacketLogger: commands (Reset, Read BD_ADDR, Inquiry), events (Command Complete, Command Status, Inquiry Complete), a connection (Create Connection, Connection Complete), sent and received ACL data with L2CAP, sent and received SCO data')
    add(0x00, hci_cmd(0x0c03))
    add(0x01, hci_evt(0x0e, bytes([1, 0x03, 0x0c, 0])))
    add(0x00, hci_cmd(0x1009))
    add(0x01, hci_evt(0x0e, bytes([1, 0x09, 0x10, 0]) + bytes([0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5])))
    add(0x00, hci_cmd(0x0401, bytes([0x33, 0x8b, 0x9e, 5, 4])))
    add(0x01, hci_evt(0x0f, bytes([0, 1, 0x01, 0x04])))
    add(0x01, hci_evt(0x01, bytes([0])))
    add(0x00, hci_cmd(0x0405, bytes([0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5]) + struct.pack('<HBBHB', 0xcc18, 1, 0, 0, 1)))
    add(0x01, hci_evt(0x0f, bytes([0, 1, 0x05, 0x04])))
    add(0x01, hci_evt(0x03, bytes([0]) + struct.pack('<H', 0x0040) + bytes([0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 1, 0])))
    add(0x02, acl(0x0040, l2cap(1, bytes([0x0a, 0x01, 0x02, 0x00, 0x01, 0x00]))))
    add(0x03, acl(0x0040, l2cap(1, bytes([0x0b, 0x01, 0x04, 0x00, 0x01, 0x00, 0x01, 0x00]))))
    add(0x08, sco(0x0041, bytes(range(24))))
    add(0x09, sco(0x0041, bytes(range(24, 48))))
    mark('LMP records (not dissected), syslog, kernel, kernel debug, error, power, note, config, new controller records and an unknown type')
    add(0x0a, bytes([1, 2, 3]))
    add(0x0b, bytes([4, 5, 6]))
    add(0xf7, syslog(321, 5, 'bluetoothd', 'libBluetooth', 'com.example.bt', 'discovery', 'Inquiry started'))
    add(0xf7, syslog(322, 6, '', '', '', '', ''))
    add(0xf8, b'kernel: AppleBluetooth: link up\0')
    add(0xf9, b'kernel debug message')
    add(0xfa, b'error: controller reset')
    add(0xfb, b'power: wake')
    add(0xfc, b'note: user clicked connect')
    add(0xfd, b'config: version 1')
    add(0xfe, b'new controller 00:11:22:33:44:55')
    add(0x77, b'unknown record type')
    add(0xf8, b'')
    return R, marks

def malformed_records():
    R = []
    def add(ptype, payload=b''): R.append(rec(ptype, payload, len(R)))
    add(0x00, hci_cmd(0x0c03))
    add(0xf7, struct.pack('<IB', 1, 2) + b'proc')                  # syslog without a NUL
    add(0xf7, struct.pack('<IB', 1, 2) + b'proc\0send')           # sender without a NUL
    add(0xf7, struct.pack('<IB', 1, 2) + b'p\0s\0sub\0cat')       # message missing
    add(0xf7, b'\x01\x02')                                         # shorter than the process id
    add(0x00, b'\x03\x0c')                                         # HCI command cut short
    add(0x01, b'\x0e\x10\x01')                                     # HCI event cut short
    add(0x02, b'\x40\x00\x20\x00abc')                              # ACL data cut short
    add(0x08, b'\x41\x00\x30abc')                                  # SCO data cut short
    R.append(struct.pack('<III', 8, 1700000100, 0))               # record without a type octet
    return R

def write(path, recs):
    with open(path, 'wb') as f:
        for r in recs: f.write(r)

if __name__ == '__main__':
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    R, marks = main_records()
    write(os.path.join(out, 'packetlogger-coverage.pklg'), R)
    M = malformed_records()
    write(os.path.join(out, 'packetlogger-coverage-malformed.pklg'), M)
    if '-v' in sys.argv:
        for n, s in marks: print(s, n)
        print(len(R), 'records', len(M), 'malformed records')
