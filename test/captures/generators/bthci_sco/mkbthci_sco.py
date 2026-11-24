#!/usr/bin/env python3
# Generates test/captures/bthci_sco_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generate synthetic captures for packet-bthci_sco.c coverage.
# Usage: mkbthci_sco.py <outdir>
# Writes bthci_sco-coverage.pcap (main, H4 with direction, DLT 201),
# bthci_sco-coverage-malformed.pcap (DLT 201),
# bthci_sco-coverage-nodir.pcap (H4 without direction, DLT 187) and
# bthci_sco-coverage-epdu.pcap (Exported PDU, DLT 252).
# Every packet is built here with struct; nothing is captured from a
# real network.
import os
import struct
import sys

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'

DLT_H4 = 187
DLT_H4_PHDR = 201
DLT_EXPORTED_PDU = 252

SENT, RECV = 0, 1

LOCAL = bytes.fromhex('001bdc000001')      # display order
REMOTE_A = bytes.fromhex('001bdc0000a2')
REMOTE_B = bytes.fromhex('001bdc0000b3')


def pcap(path, linktype, pkts):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, p in enumerate(pkts):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
            f.write(p)


def phdr(direction, pkt):
    return struct.pack('>I', direction) + pkt


def epdu(name, payload):
    n = name.encode()
    pad = (4 - len(n) % 4) % 4
    return struct.pack('>HH', 12, len(n) + pad) + n + b'\0' * pad + struct.pack('>HH', 0, 0) + payload


def bd(a):
    return a[::-1]


def cmd(opcode, params):
    return phdr(SENT, b'\x01' + struct.pack('<HB', opcode, len(params)) + params)


def evt(code, params):
    return phdr(RECV, b'\x04' + struct.pack('<BB', code, len(params)) + params)


def cmd_complete(opcode, ret):
    return evt(0x0e, struct.pack('<BH', 1, opcode) + ret)


def cmd_status(opcode):
    return evt(0x0f, struct.pack('<BBH', 0, 1, opcode))


def name248(s):
    return s.encode().ljust(248, b'\0')


def sco_raw(handle, status, payload, length=None, reserved=0):
    if length is None:
        length = len(payload)
    return b'\x03' + struct.pack('<HB', (handle & 0xfff) | (status << 12) | (reserved << 14), length) + payload


def sco(direction, handle, status, payload, length=None, reserved=0):
    return phdr(direction, sco_raw(handle, status, payload, length, reserved))


def connection_complete(handle, addr):
    return evt(0x03, struct.pack('<BH', 0, handle) + bd(addr) + b'\x01\x00')


def sync_connection_complete(handle, addr):
    # status, handle, BD_ADDR, link type eSCO, Tx interval, retransmission
    # window, Rx and Tx packet length, air mode CVSD
    return evt(0x2c, struct.pack('<BH', 0, handle) + bd(addr) + struct.pack('<BBBHHB', 2, 12, 2, 60, 60, 2))


def setup_sync(acl_handle):
    # Setup Synchronous Connection: bandwidths, max latency, voice
    # setting, retransmission effort, packet type
    return cmd(0x0428, struct.pack('<HIIHHBH', acl_handle, 8000, 8000, 10, 0x0060, 1, 0x03bf))


def main_capture():
    p = []
    p.append(cmd(0x1009, b''))                                          # 1 Read BD_ADDR
    p.append(cmd_complete(0x1009, b'\x00' + bd(LOCAL)))                 # 2
    p.append(cmd(0x0c14, b''))                                          # 3 Read Local Name
    p.append(cmd_complete(0x0c14, b'\x00' + name248('ws-local')))       # 4
    p.append(connection_complete(0x0001, REMOTE_A))                     # 5 ACL connection to A
    p.append(cmd(0x0419, bd(REMOTE_A) + struct.pack('<BBH', 1, 0, 0)))   # 6 Remote Name Request
    p.append(cmd_status(0x0419))                                        # 7
    p.append(evt(0x07, b'\x00' + bd(REMOTE_A) + name248('ws-headset')))  # 8 Remote Name Request Complete
    p.append(setup_sync(0x0001))                                        # 9 Setup Synchronous Connection
    p.append(cmd_status(0x0428))                                        # 10
    p.append(sync_connection_complete(0x0101, REMOTE_A))                # 11 stream 1
    # 12-17: SCO both ways, packet status 0-3, 60 and 4 octets of data
    voice = bytes((i * 7) & 0xff for i in range(60))
    p.append(sco(SENT, 0x0101, 0, voice))                               # 12
    p.append(sco(RECV, 0x0101, 0, voice[::-1]))                         # 13 correctly received
    p.append(sco(RECV, 0x0101, 1, voice))                               # 14 possibly invalid
    p.append(sco(RECV, 0x0101, 2, bytes(60)))                           # 15 no data received
    p.append(sco(RECV, 0x0101, 3, voice[:30] + bytes(30)))              # 16 partially lost
    p.append(sco(SENT, 0x0101, 0, voice[:4]))                           # 17 4 octets
    # 18-20: SCO stream 1 disconnected
    p.append(cmd(0x0406, struct.pack('<HB', 0x0101, 0x13)))             # 18 Disconnect
    p.append(cmd_status(0x0406))                                        # 19
    p.append(evt(0x05, struct.pack('<BHB', 0, 0x0101, 0x16)))           # 20 Disconnection Complete
    # 21-25: ACL connection to B (no name), SCO stream 2
    p.append(connection_complete(0x0002, REMOTE_B))                     # 21
    p.append(setup_sync(0x0002))                                        # 22
    p.append(cmd_status(0x0428))                                        # 23
    p.append(sync_connection_complete(0x0102, REMOTE_B))                # 24 stream 2
    p.append(sco(SENT, 0x0102, 0, voice[:48]))                          # 25
    p.append(sco(RECV, 0x0102, 0, voice[:48]))                          # 26
    # 27-28: SCO on a handle without a synchronous connection ("remote ()")
    p.append(sco(SENT, 0x0103, 0, voice[:10]))                          # 27
    p.append(sco(RECV, 0x0103, 0, voice[:10]))                          # 28
    return p


def malformed_capture():
    return [phdr(SENT, b'\x03\x01\x01'),                 # header cut in the length
            phdr(RECV, b'\x03'),                         # no header
            sco(RECV, 0x0101, 0, b'\x11\x22', length=10),  # length larger than the data
            sco(RECV, 0x0101, 0, b'\x11\x22' * 4, length=2, reserved=3),  # length smaller, reserved bits
            sco(RECV, 0x0101, 2, b'')]                   # no data: the data item throws


def nodir_capture():
    # H4 without direction: "UnknownDirection", no source/destination
    return [sco_raw(0x0101, 0, b'\x01\x02\x03\x04'),
            sco_raw(0x0101, 1, b'\x05\x06\x07\x08')]


def epdu_capture():
    # bthci_sco_epdu_null.py: "bthci_sco" without dissector
    # data returns 0 (shown as data) instead of asserting
    return [epdu('bthci_sco', bytes.fromhex('010003aabbcc'))]


pcap(os.path.join(OUT, 'bthci_sco-coverage.pcap'), DLT_H4_PHDR, main_capture())
pcap(os.path.join(OUT, 'bthci_sco-coverage-malformed.pcap'), DLT_H4_PHDR, malformed_capture())
pcap(os.path.join(OUT, 'bthci_sco-coverage-nodir.pcap'), DLT_H4, nodir_capture())
pcap(os.path.join(OUT, 'bthci_sco-coverage-epdu.pcap'), DLT_EXPORTED_PDU, epdu_capture())
