#!/usr/bin/env python3
# Generates test/captures/pcomtcp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic captures for packet-pcomtcp.c. usage: mkpcomtcp.py <outdir>
#
# PCOM/TCP (Unitronics PLC protocol) on TCP port 20256, ASCII and binary
# mode, requests (to 20256) and replies (from 20256).
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import struct
from lib import gz, tcp, write_pcap

out = sys.argv[1]
PORT = 20256
CLI, SRV = '192.0.2.1', '192.0.2.2'

frames = []
seqs = {}

def send(req, payload, tid, mode, reserved=0, length=None):
    '''One PCOM/TCP PDU in its own TCP segment, request or reply'''
    hdr = struct.pack('<HBBH', tid, mode, reserved, len(payload) if length is None else length)
    data = hdr + payload
    if req:
        key = (CLI, SRV)
        seq = seqs.get(key, 1)
        ack = seqs.get((SRV, CLI), 1)
        frames.append(tcp(41000, PORT, seq, ack, data, src=CLI, dst=SRV))
    else:
        key = (SRV, CLI)
        seq = seqs.get(key, 1)
        ack = seqs.get((CLI, SRV), 1)
        frames.append(tcp(PORT, 41000, seq, ack, data, src=SRV, dst=CLI))
    seqs[key] = seq + len(data)

def hexck(b):
    return b'%02X' % (sum(b) & 0xff)

def areq(cc, params=b'', unit=b'00', tid=1):
    '''ASCII request: /, unit id, command code, parameters, checksum, CR'''
    body = unit + cc + params
    send(True, b'/' + body + hexck(b'/' + body) + b'\r', tid, 101)

def arep(cc, data=b'', unit=b'00', tid=1):
    '''ASCII reply: /A, unit id, command code, data, checksum, CR'''
    body = unit + cc + data
    send(False, b'/A' + body + hexck(b'/A' + body) + b'\r', tid, 101)

tid = [100]
def t():
    tid[0] += 1
    return tid[0]

# --- ASCII: administration commands
for cc, rep in ((b'ID', b'0A0000'), (b'CCR', b''), (b'CCS', b''), (b'CCE', b''), (b'CCI', b'')):
    n = t()
    areq(cc, tid=n)
    arep(b'CC' if cc.startswith(b'CC') else cc, rep, tid=n)
n = t(); areq(b'UG', tid=n); arep(b'UG', b'01', tid=n)
n = t(); areq(b'US', b'05', tid=n); arep(b'US', b'', tid=n)
n = t(); areq(b'RC', tid=n); arep(b'RC', b'1234562612', tid=n)
n = t(); areq(b'SC', b'0102032612', tid=n); arep(b'SC', b'', tid=n)

# --- ASCII: reads (address, number of operands) and replies with the values
def rd(cc_req, cc_rep, size, count, addr=b'0000'):
    n = t()
    areq(cc_req, addr + b'%02X' % count, tid=n)
    arep(cc_rep, b''.join((b'%0*X' % (size, (i * 37) % (16 ** size))) for i in range(count)), tid=n)
rd(b'RE', b'RE', 1, 8); rd(b'RA', b'RA', 1, 4); rd(b'GS', b'GS', 1, 3); rd(b'RB', b'RB', 1, 5, b'0010')
rd(b'GF', b'GF', 4, 3); rd(b'RW', b'RW', 4, 4, b'0020')
rd(b'RNH', b'RN', 8, 2); rd(b'RNJ', b'RN', 8, 2); rd(b'RNL', b'RN', 8, 3); rd(b'RND', b'RN', 8, 1)
rd(b'RN', b'RN', 8, 2)
# a read reply that carries no values and a request with nothing after the address
n = t(); areq(b'RW', b'002001', tid=n); arep(b'RW', b'', tid=n)

# --- ASCII: writes (address, number of operands, values) and replies
def wr(cc, size, count, addr=b'0000'):
    n = t()
    areq(cc, addr + b'%02X' % count + b''.join(b'%0*X' % (size, i + 1) for i in range(count)), tid=n)
    arep(cc[:2], b'', tid=n)
wr(b'SA', 1, 4); wr(b'SS', 1, 3); wr(b'SB', 1, 6, b'0030')
wr(b'SF', 4, 2); wr(b'SW', 4, 3, b'0040')
wr(b'SNH', 8, 1); wr(b'SNJ', 8, 2); wr(b'SNL', 8, 2); wr(b'SND', 8, 1); wr(b'SN', 8, 2)

# --- ASCII: commands the dissector does not know (warning expert info), a
# 2 char command with a 3 char prefix, and a request that is not in a reply
n = t(); areq(b'ZZ', b'abc', tid=n); arep(b'ZZ', b'abc', tid=n)
n = t(); areq(b'XY', b'', tid=n)
# a reply for a 3 character code is shown with the 2 character code
n = t(); arep(b'CC', b'', tid=n)
# a unit id other than 00
n = t(); areq(b'ID', unit=b'FF', tid=n); arep(b'ID', b'0A0000', unit=b'FF', tid=n)

# --- binary mode
STX = b'/_OPLC'
def bin_pdu(req, cmd, specific=b'\0' * 6, data=b'', unit=0, r1=0, r2=1, r3=b'\0\0\0', r4=0, hck=0x1234):
    if req:
        mid = bytes((unit, r1))
    else:
        mid = bytes((254 if r1 == 0 else r1, unit))
    pdu = STX + mid + bytes((r2,)) + r3 + bytes((cmd, r4)) + specific + struct.pack('<HH', len(data), hck)
    pdu += data
    pdu += struct.pack('<H', sum(pdu) & 0xffff) + b'\\'
    return pdu
def breq(*a, **k): send(True, bin_pdu(True, *a, **k), t(), 102)
def brep(*a, **k): send(False, bin_pdu(False, *a, **k), t(), 102)

breq(0x0c); brep(0x8c, data=b'PLC-1 name\0')
breq(0x4d, specific=b'\x01\x00\x00\x00\x02\x00', data=b''); brep(0xcd, data=b'\x01\x02\x03\x04')
breq(0x04, specific=b'\x00\x00\x00\x00\x08\x00'); brep(0x84, data=bytes(range(32)))
breq(0x44, specific=b'\x00\x00\x00\x00\x04\x00', data=b'\x01\x02\x03\x04'); brep(0xc4)
# the CAN bus / RS485 unit id
breq(0x0c, unit=7); brep(0x8c, unit=7, data=b'x')
# a packet with the smallest size: no data
breq(0x04); brep(0x84)
# unknown commands (warning), bad reserved bytes (warnings)
breq(0x99); brep(0x99)
breq(0x0c, r1=5); brep(0x8c, r1=9)       # reserved1 is 254 in replies
breq(0x0c, r2=7)
breq(0x0c, r3=b'\x01\x02\x03')
breq(0x0c, r4=3)
# TCP header on both sides: the PCOM/TCP header with a reserved byte
send(True, bin_pdu(True, 0x0c), t(), 102, reserved=1)
send(False, bin_pdu(False, 0x8c), t(), 101 + 1, reserved=0)
write_pcap(out + '/pcomtcp-coverage.pcap', frames)

# --- malformed capture: PDUs that are too short for their dissector, modes
# that are neither ASCII nor binary, a too short PCOM/TCP header
frames = []
seqs.clear()
for cut in range(0, 12):
    send(True, (b'/00ID' + b'AB' + b'\r')[:cut], t(), 101)
    send(False, (b'/A00UG01AB\r')[:cut], t(), 101)
for cc, plen in ((b'RE', 0), (b'RE', 4), (b'RE', 6), (b'SA', 6), (b'SF', 4), (b'RNH', 3), (b'SNH', 6)):
    send(True, b'/00' + cc + b'0' * plen, t(), 101)
    send(False, b'/A00' + cc[:2] + b'0' * plen, t(), 101)
pdu = bin_pdu(True, 0x04, data=b'\x01' * 10)
for cut in (0, 6, 8, 10, 12, 13, 14, 20, 21, 22, 23, 24, 25, 26, 27, 28):
    send(True, pdu[:cut], t(), 102)
    send(False, pdu[:cut], t(), 102)
send(True, b'\x00' * 10, t(), 103)
send(True, b'\x00\x01\x65', t(), 0)
send(True, b'', 1, 101)
send(True, b'/00ID', 1, 101, length=1000)
write_pcap(out + '/pcomtcp-coverage-malformed.pcap', frames)
gz(out + '/pcomtcp-coverage.pcap')
print('ok')
