#!/usr/bin/env python3
# Generates test/captures/bthci_acl_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generate synthetic captures for packet-bthci_acl.c coverage.
# Usage: mkbthci_acl.py <outdir>
# Writes bthci_acl-coverage.pcap (main, H4 with direction, DLT 201),
# bthci_acl-coverage-malformed.pcap (DLT 201) and
# bthci_acl-coverage-nodir.pcap (H4 without direction, DLT 187).
# Every packet is built here with struct; nothing is captured from a
# real network.
import os
import struct
import sys

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'

DLT_H4 = 187
DLT_H4_PHDR = 201

SENT, RECV = 0, 1

LOCAL = bytes.fromhex('001bdc000001')      # display order
REMOTE_A = bytes.fromhex('001bdc0000a2')
REMOTE_B = bytes.fromhex('001bdc0000b3')
REMOTE_C = bytes.fromhex('c0ffee0000c4')   # LE peer


def pcap(path, linktype, pkts):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, p in enumerate(pkts):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
            f.write(p)


def phdr(direction, pkt):
    return struct.pack('>I', direction) + pkt


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


def acl_raw(handle, pb, bc, payload, length=None):
    if length is None:
        length = len(payload)
    return b'\x02' + struct.pack('<HH', (handle & 0xfff) | (pb << 12) | (bc << 14), length) + payload


def acl(direction, handle, pb, payload, bc=0, length=None):
    return phdr(direction, acl_raw(handle, pb, bc, payload, length))


def l2cap(cid, payload):
    return struct.pack('<HH', len(payload), cid) + payload


def sig(code, ident, data):
    return l2cap(0x0001, struct.pack('<BBH', code, ident, len(data)) + data)


def name248(s):
    return s.encode().ljust(248, b'\0')


def connection_complete(handle, addr):
    return evt(0x03, struct.pack('<BH', 0, handle) + bd(addr) + b'\x01\x00')


def setup():
    """Local address and name, ACL connection 1 to A with name, role and
    mode, ACL connection 2 to B, LE connection 3 to C."""
    p = []
    p.append(cmd(0x1009, b''))                                         # 1 Read BD_ADDR
    p.append(cmd_complete(0x1009, b'\x00' + bd(LOCAL)))                # 2
    p.append(cmd(0x0c14, b''))                                         # 3 Read Local Name
    p.append(cmd_complete(0x0c14, b'\x00' + name248('ws-local')))      # 4
    p.append(cmd(0x0405, bd(REMOTE_A) + struct.pack('<HBBHB', 0xcc18, 1, 0, 0, 1)))  # 5 Create Connection
    p.append(cmd_status(0x0405))                                       # 6
    p.append(connection_complete(0x0001, REMOTE_A))                    # 7
    p.append(cmd(0x0419, bd(REMOTE_A) + struct.pack('<BBH', 1, 0, 0)))  # 8 Remote Name Request
    p.append(cmd_status(0x0419))                                       # 9
    p.append(evt(0x07, b'\x00' + bd(REMOTE_A) + name248('ws-remote')))  # 10 Remote Name Request Complete
    p.append(evt(0x12, b'\x00' + bd(REMOTE_A) + b'\x01'))              # 11 Role Change, role 1
    p.append(evt(0x14, struct.pack('<BHBH', 0, 0x0001, 2, 0x0100)))    # 12 Mode Change: sniff
    return p


def main_capture():
    p = setup()
    # 13-14: unfragmented L2CAP signalling both ways, PB 2 (first
    # automatically flushable)
    p.append(acl(SENT, 1, 2, sig(0x0a, 1, struct.pack('<H', 2))))                   # 13 Information Request
    p.append(acl(RECV, 1, 2, sig(0x0b, 1, struct.pack('<HHI', 2, 0, 0x000002b8))))  # 14 Information Response
    # 15-16: PB 0 (first non-automatically flushable), and BC flag 1
    p.append(acl(SENT, 1, 0, sig(0x08, 2, b'ping')))                                # 15 Echo Request
    p.append(acl(RECV, 1, 0, sig(0x09, 2, b'pong'), bc=1))                          # 16 Echo Response
    # 17-19: Echo Request reassembled from three received fragments
    echo = sig(0x08, 3, bytes(range(0x30, 0x58)))                                   # 4+4+40 = 48 octets
    p.append(acl(RECV, 1, 2, echo[:20], length=20))                                 # 17 first
    p.append(acl(RECV, 1, 1, echo[20:40]))                                          # 18 continuation
    p.append(acl(RECV, 1, 1, echo[40:]))                                            # 19 last continuation
    # 20-22: Echo Response sent in two fragments, with a received
    # unfragmented PDU in between (fragments are kept per direction)
    resp = sig(0x09, 3, bytes(range(0x60, 0x7e)))                                   # 4+4+30 = 38 octets
    p.append(acl(SENT, 1, 0, resp[:10], length=10))                                 # 20 first (PB 0)
    p.append(acl(RECV, 1, 2, sig(0x08, 4, b'4')))                                   # 21 Echo Request
    p.append(acl(SENT, 1, 1, resp[10:]))                                            # 22 continuation, completes
    p.append(acl(SENT, 1, 2, sig(0x09, 4, b'4')))                                   # 23 Echo Response
    # 24: PB 3 (not a known value): passed to L2CAP unfragmented
    p.append(acl(RECV, 1, 3, sig(0x08, 5, b'pb3')))                                 # 24
    p.append(acl(SENT, 1, 2, sig(0x09, 5, b'pb3')))                                 # 25
    # 26-29: second ACL connection, to B (no name), role 0
    p.append(cmd(0x0405, bd(REMOTE_B) + struct.pack('<HBBHB', 0xcc18, 1, 0, 0, 1)))  # 26
    p.append(cmd_status(0x0405))                                                    # 27
    p.append(connection_complete(0x0002, REMOTE_B))                                 # 28
    p.append(evt(0x12, b'\x00' + bd(REMOTE_B) + b'\x00'))                          # 29 Role Change, role 0
    # 30: a continuation whose first fragment is not in the capture
    p.append(acl(RECV, 2, 1, b'\x11\x22\x33\x44\x55\x66'))                          # 30
    p.append(acl(SENT, 2, 2, sig(0x08, 1, b'B')))                                   # 31
    p.append(acl(RECV, 2, 2, sig(0x09, 1, b'B')))                                   # 32
    # 33-35: disconnect B
    p.append(cmd(0x0406, struct.pack('<HB', 0x0002, 0x13)))                         # 33 Disconnect
    p.append(cmd_status(0x0406))                                                    # 34
    p.append(evt(0x05, struct.pack('<BHB', 0, 0x0002, 0x16)))                       # 35 Disconnection Complete
    # 36-38: LE connection 3 to C (no mode), ATT Exchange MTU
    le = struct.pack('<BBHBB', 0x01, 0, 0x0003, 0, 0) + bd(REMOTE_C) + struct.pack('<HHHB', 0x18, 0, 0x48, 0)
    p.append(evt(0x3e, le))                                                         # 36 LE Connection Complete
    p.append(acl(SENT, 3, 0, l2cap(0x0004, struct.pack('<BH', 0x02, 247))))          # 37 ATT Exchange MTU Request
    p.append(acl(RECV, 3, 2, l2cap(0x0004, struct.pack('<BH', 0x03, 185))))          # 38 ATT Exchange MTU Response
    # 39-41: a fragmented L2CAP PDU on connection 3 whose first fragment
    # is the L2CAP header alone
    att = l2cap(0x0004, struct.pack('<BH', 0x0a, 0x0003))                           # ATT Read Request
    p.append(acl(SENT, 3, 0, att[:4], length=4))                                    # 39 first: L2CAP header only
    p.append(acl(SENT, 3, 1, att[4:]))                                              # 40 continuation
    p.append(acl(RECV, 3, 2, l2cap(0x0004, b'\x0b' + b'value')))                    # 41 ATT Read Response
    return p


def malformed_capture():
    p = setup()
    # 13: Data Total Length matches the L2CAP length but two octets
    # follow (ei_length_bad)
    p.append(acl(SENT, 1, 2, sig(0x08, 1, b'abcd') + b'\xee\xee', length=12))
    # 14: first fragment with more data than the L2CAP length claims
    # (not stored for reassembly)
    p.append(acl(RECV, 1, 2, struct.pack('<HH', 2, 0x0040) + b'abcdefgh', length=20))
    # 15-17: bthci_acl_stale_cont.py: a continuation after
    # the PDU is complete is labelled as a continuation of that PDU
    p.append(acl(RECV, 1, 2, struct.pack('<HH', 6, 0x40), length=4))
    p.append(acl(RECV, 1, 1, b'abcdef'))
    p.append(acl(RECV, 1, 1, b'zz'))
    # 18: ACL on a handle without a connection ("remote ()", invalid session)
    p.append(acl(SENT, 9, 2, sig(0x08, 1, b'x')))
    p.append(acl(RECV, 9, 2, sig(0x09, 1, b'x')))
    # 20-22: disconnect connection 1, then ACL after it (invalid session)
    p.append(cmd(0x0406, struct.pack('<HB', 0x0001, 0x13)))
    p.append(evt(0x05, struct.pack('<BHB', 0, 0x0001, 0x16)))
    p.append(acl(SENT, 1, 2, sig(0x08, 1, b'late')))
    # 23: header only, no L2CAP length
    p.append(acl(SENT, 1, 2, b'', length=4))
    # 24: truncated header
    p.append(phdr(SENT, b'\x02\x01\x20'))
    # 25: first fragment of a PDU that never completes, then a
    # continuation without data and one with more data than is still
    # missing (clipped)
    p.append(acl(RECV, 1, 0, struct.pack('<HH', 4, 0x0040) + b'ab', length=6))
    p.append(acl(RECV, 1, 1, b''))                  # empty continuation
    p.append(acl(RECV, 1, 1, b'cdefghij'))
    return p


def nodir_capture():
    # H4 without direction: "UnknownDirection", no source/destination
    p = []
    p.append(b'\x04' + struct.pack('<BB', 0x03, 11) + struct.pack('<BH', 0, 0x0001) + bd(REMOTE_A) + b'\x01\x00')
    p.append(acl_raw(1, 2, 0, sig(0x08, 1, b'nodir')))
    p.append(acl_raw(1, 2, 0, sig(0x09, 1, b'nodir')))
    return p


pcap(os.path.join(OUT, 'bthci_acl-coverage.pcap'), DLT_H4_PHDR, main_capture())
pcap(os.path.join(OUT, 'bthci_acl-coverage-malformed.pcap'), DLT_H4_PHDR, malformed_capture())
pcap(os.path.join(OUT, 'bthci_acl-coverage-nodir.pcap'), DLT_H4, nodir_capture())
