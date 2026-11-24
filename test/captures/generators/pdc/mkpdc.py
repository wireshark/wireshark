#!/usr/bin/env python3
# Generates test/captures/pdc_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic captures for packet-pdc.c. usage: mkpdc.py <outdir>
#
# PDC (MPDU framing that carries ASTERIX)
# over TCP. It has no default port: it is reached with Decode As tcp.port
# (30000 here). PDUs are reassembled with tcp_dissect_pdus.
import sys
import struct
from lib import gz, TcpStream, write_pcap

out = sys.argv[1]
PORT = 30000

# a small ASTERIX category 34 message (north marker) for the data MPDUs
AST = bytes.fromhex('2200 0a e0 0001 01 000080'.replace(' ', ''))
AST2 = AST + AST

def simpdu(credit=3, state=1, nr=0x01020304, params=b''):
    body = bytes((1, credit, state)) + struct.pack('>I', nr) + params
    return bytes((len(body),)) + body
def p_version(v=2): return bytes((2, 1, v))
def p_refs(src=0x1111, dst=0x2222): return bytes((3, 4)) + struct.pack('>HH', src, dst)
def p_tsel(t=0x4242): return bytes((4, 2)) + struct.pack('>H', t)
def rsmpdu(): return bytes((1, 2))
def drmpdu(b0=0x00, reason=1):
    return bytes((3, 3, b0, reason))
def dtmpdu(data=AST):
    return bytes((len(data) + 3, 4)) + struct.pack('>H', len(data)) + data
def admpdu(nr=7, data=AST):
    body = bytes((5,)) + struct.pack('>IH', nr, len(data)) + data
    return bytes((len(body),)) + body
def edmpdu(data=AST):
    # get_pdc_message_len uses the length indicator for this PDU
    return bytes((len(data) + 3, 6)) + struct.pack('>H', len(data)) + data
def akmpdu(mns=0x1234, nr=9):
    return bytes((7, 8)) + struct.pack('>HI', mns, nr)

frames = []
s = TcpStream(frames, 50000, PORT)
# every MPDU, client to server and back
s.send(True, simpdu())
s.send(False, simpdu(credit=5, state=2, nr=77))
s.send(True, simpdu(params=p_version(2)))
s.send(False, simpdu(params=p_refs()))
s.send(True, simpdu(params=p_tsel()))
s.send(True, simpdu(state=3, params=p_version() + p_refs() + p_tsel()))
s.send(False, simpdu(state=4, params=p_tsel() + p_refs() + p_version()))
s.send(True, simpdu(state=5, params=p_version(3) + p_version(4)))
s.send(True, rsmpdu())
for b0 in (0x00, 0x01, 0x07 << 1, 0x0f << 4, 0x0f << 4 | 0x01):
    s.send(True, drmpdu(b0, reason=b0 % 7))
s.send(True, dtmpdu())
s.send(False, dtmpdu(AST2))
s.send(True, admpdu())
s.send(False, admpdu(8, AST2))
s.send(True, edmpdu())
s.send(False, edmpdu(AST2))
s.send(True, akmpdu())
s.send(False, akmpdu(0xfffe, 0xffffffff))
# reassembly: PDUs split into several segments, and several PDUs in one segment
s.send(True, dtmpdu(AST2), cuts=(2,))
s.send(True, dtmpdu(AST2), cuts=(2, 5))
s.send(False, admpdu(11, AST2), cuts=(3,))
s.send(True, simpdu(params=p_version() + p_refs()), cuts=(2, 9))
s.send(True, akmpdu() + simpdu() + rsmpdu())
s.send(False, dtmpdu() + dtmpdu(AST2) + akmpdu(5, 6))
s.send(True, simpdu() + dtmpdu(AST2)[:5], cuts=(len(simpdu()) + 5,))
s.raw(True, dtmpdu(AST2)[5:])
s.cseq += len(dtmpdu(AST2)) - 5
s.close()
# IPv6
s6 = TcpStream(frames, 50001, PORT, '2001:db8::1', '2001:db8::2', v6=True)
s6.send(True, simpdu(params=p_version()))
s6.send(False, akmpdu())
s6.send(True, dtmpdu())
write_pcap(out + '/pdc-coverage.pcap', frames)

# malformed: a data PDU that claims more user data than there is, PDUs with
# an unknown MPDU code, bad length indicators, short PDUs, simpdu with a
# parameter list that stops early
frames = []
m = TcpStream(frames, 50002, PORT)
m.send(True, bytes((3, 99, 1, 2)))
m.send(True, bytes((1, 0)))
m.send(True, bytes((1, 9)))
m.send(True, bytes((200, 4)) + struct.pack('>H', 3) + b'\x01\x02\x03')
m.send(True, bytes((5, 4)) + struct.pack('>H', 50) + AST)
m.send(True, bytes((5, 5)) + struct.pack('>IH', 1, 500) + AST)
m.send(True, bytes((5, 6)) + struct.pack('>H', 40) + AST)
m.send(True, bytes((3, 1, 1, 1)))
m.send(True, bytes((30, 1, 1, 1, 0, 0, 0, 1, 3)))
m.send(True, bytes((12, 1, 1, 1, 0, 0, 0, 1, 3, 4, 0, 0, 0)))
m.send(True, bytes((9, 1, 1, 1, 0, 0, 0, 1, 77, 1, 1)))
m.send(True, bytes((7, 8, 1)))
m.send(True, bytes((2, 3, 0)))
m.send(True, bytes((1, 4)))
m.send(True, bytes((1, 5)))
m.send(True, bytes((1, 6)))
m.send(True, bytes((1, 8)))
m.send(True, bytes((0, 8)))
m.send(True, bytes((0, 3)))
m.send(True, bytes((0, 0, 0, 0, 0, 0, 0, 0)))
m.send(True, b'\x05')
write_pcap(out + '/pdc-coverage-malformed.pcap', frames)
gz(out + '/pdc-coverage.pcap')
print('ok')
