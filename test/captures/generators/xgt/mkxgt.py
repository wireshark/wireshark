#!/usr/bin/env python3
# Generates test/captures/xgt_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures for the XGT dissector (packet-xgt.c).

XGT FEnet (LS ELECTRIC PLC) runs over TCP port 2004 and UDP port 2005:
a 20 octet header (company ID "LSIS-XGT", PLC info, CPU info, source of
frame, invoke ID, length, FEnet position, BCC) followed by the
instruction: command (read/write/status request and response), data
type (bit, byte, word, dword, lword, continuous), a block or variable
count and the blocks (variable name, data). Everything is little
endian. Every packet is built from scratch with struct.

Usage: mkxgt.py <outdir>
Writes xgt-coverage.pcap and xgt-coverage-malformed.pcap.
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from util import udp, Conn, write_pcap

CLIENT, SERVER = '192.0.2.1', '192.0.2.2'
REQ, RSP = 0x33, 0x11
READ_Q, READ_A, WRITE_Q, WRITE_A, STAT_Q, STAT_A = 0x54, 0x55, 0x58, 0x59, 0xB0, 0xB1
BIT, BYTE, WORD, DWORD, LWORD, CONT = 0, 1, 2, 3, 4, 0x14

def hdr(source, invoke, instr, plc=0x0201, cpu=0xA0, pos=0x13, bcc=0x55, length=None, company=b'LSIS-XGT'):
    return (company + struct.pack('<HHBBHHBB', 0, plc, cpu, source, invoke,
            len(instr) if length is None else length, pos, bcc)) + instr

def var(name):
    name = name.encode() if isinstance(name, str) else name
    return struct.pack('<H', len(name)) + name

def datablk(d):
    return struct.pack('<H', len(d)) + d

def inst(cmd, dtype, rest, reserved=0):
    return struct.pack('<HHH', cmd, dtype, reserved) + rest

def rd_q(dtype, *names):
    return inst(READ_Q, dtype, struct.pack('<H', len(names)) + b''.join(var(x) for x in names))

def rd_a(dtype, *datas):
    return inst(READ_A, dtype, struct.pack('<HH', 0, len(datas)) + b''.join(datablk(d) for d in datas))

def wr_q(dtype, *items):
    return inst(WRITE_Q, dtype, struct.pack('<H', len(items)) + b''.join(var(n) + datablk(d) for n, d in items))

def wr_a(dtype, count=0, blocks=b''):
    return inst(WRITE_A, dtype, struct.pack('<HH', 0, count) + blocks)

def err_a(cmd, dtype, status, code):
    return inst(cmd, dtype, struct.pack('<HH', status, code))

def st_q():
    return inst(STAT_Q, 0, struct.pack('<H', 0))

STATUS = struct.pack('<IHHIHIIH', 0x01020304, 1, 0x0102, 2, 0x55, 0x0a, 0x0b, 0)   # 24 octets

main, mal = [], []

# --- UDP 2005 -------------------------------------------------------------
def u_q(i, ins, **kw):
    main.append(udp(40000, 2005, hdr(REQ, i, ins, **kw), src=CLIENT, dst=SERVER))
def u_a(i, ins, **kw):
    main.append(udp(2005, 40000, hdr(RSP, i, ins, **kw), src=SERVER, dst=CLIENT))

u_q(1, rd_q(WORD, '%DW100'))
u_a(1, rd_a(WORD, b'\x34\x12'))
u_q(2, rd_q(BIT, '%MX10'))
u_a(2, rd_a(BIT, b'\x01'))
u_q(3, rd_q(BYTE, '%MB10'))
u_a(3, rd_a(BYTE, b'\x7f'))
u_q(4, rd_q(DWORD, '%DD100'))
u_a(4, rd_a(DWORD, b'\x78\x56\x34\x12'))
u_q(5, rd_q(LWORD, '%DL100'))
u_a(5, rd_a(LWORD, bytes(range(1, 9))))
u_q(6, rd_q(WORD, '%DW1', '%DW2', '%DW3'))
u_a(6, rd_a(WORD, b'\x01\x00', b'\x02\x00', b'\x03\x00'))
# data that does not match the type: shown as bytes
u_a(7, rd_a(WORD, b'\x01\x02\x03'))
u_a(8, rd_a(DWORD, b'\x01\x02'))
u_a(9, rd_a(BIT, b'\x01\x02\x03\x04'))
u_a(10, rd_a(BYTE, b''))
u_a(11, rd_a(LWORD, b'\x01' * 16))
u_a(12, rd_a(BIT, b'\x00', b'\x01'))                    # several blocks, no request seen: Info shows the first value
# writes
u_q(20, wr_q(WORD, ('%DW100', b'\x01\x02')))
u_a(20, wr_a(WORD))
u_q(21, wr_q(BYTE, ('%MB10', b'\x05'), ('%MB11', b'\x06')))
u_a(21, wr_a(BYTE, 2, struct.pack('<HH', 0, 0) * 2))
u_q(22, wr_q(DWORD, ('%DD100', b'\x01\x02\x03\x04')))
u_q(23, wr_q(LWORD, ('%DL100', bytes(range(8)))))
u_q(24, wr_q(BIT, ('%MX1', b'\x01')))
u_q(25, wr_q(CONT, ('%DB100', b'\x01\x02\x03\x04\x05\x06')))
u_a(25, wr_a(CONT, 1, var('%DB100') + datablk(b'')))
# a request with a variable of 16 octets (the maximum) and none (length 0)
u_q(26, rd_q(WORD, '%DW1234567890123'))
u_q(27, rd_q(WORD, ''))
u_a(27, rd_a(WORD, b'\x01\x00'))
# status
u_q(30, st_q())
u_a(30, inst(STAT_A, 0, struct.pack('<HH', 0, 24) + STATUS))
u_a(31, inst(STAT_A, 0, struct.pack('<HH', 0, 28) + STATUS + b'\x00\x00\x00\x00'))
u_a(32, inst(STAT_A, 0, struct.pack('<HH', 0, 0)))
u_a(33, inst(STAT_A, 0, struct.pack('<HH', 0, 8) + b'\x00' * 8))
# CPU types, redundancy, CPU error bit, system states in the PLC info; CPU infos
for k, (plc, cpu) in enumerate(((0x0101, 0xA0), (0x0202, 0xA4), (0x0405, 0xA8), (0x08c1, 0x00), (0x10ff, 0xA0), (0x0000, 0xff), (0x1f3f, 0xA4))):
    u_a(40 + k, rd_a(BYTE, b'\x01'), plc=plc, cpu=cpu, pos=0x00 if k == 0 else 0x1f if k == 1 else 0xf0 if k == 2 else 0x7a)
# error responses: the error code with and without a known name, other status values
u_a(50, err_a(READ_A, WORD, 0xFFFF, 0x1102))
u_a(51, err_a(WRITE_A, WORD, 0xFFFF, 0x1201))
u_a(52, err_a(READ_A, CONT, 0xFFFF, 0x9999))
u_a(53, err_a(READ_A, WORD, 0x0001, 0x1301))
# an unknown data type
u_q(61, inst(READ_Q, 0x99, struct.pack('<H', 1) + var('%DW1')))
u_a(61, inst(READ_A, 0x99, struct.pack('<HHH', 0, 1, 2) + b'\x01\x02'))
# a source other than 0x33 and 0x11
main.append(udp(40000, 2005, hdr(0x44, 80, rd_q(WORD, '%DW1')), src=CLIENT, dst=SERVER))
# header only, instruction too short is a separate (malformed) case
main.append(udp(40000, 2005, hdr(REQ, 81, b''), src=CLIENT, dst=SERVER))

# --- continuous blocks: translated addresses -------------------------------
for k, (name, nwords) in enumerate((('%DB100', 3), ('%MW10', 2), ('%PW5', 1), ('D100', 2), ('%ABC', 2), ('%', 1), ('%DB0', 4), ('%MB1000', 2))):
    u_q(100 + k, rd_q(CONT, name))
    u_a(100 + k, rd_a(CONT, b''.join(struct.pack('<H', 0x100 + j) for j in range(nwords))))
# continuous responses without a request, with an odd length and a length of one
u_a(120, rd_a(CONT, b'\x01\x02\x03\x04'))
u_a(121, rd_a(CONT, b'\x01\x02\x03'))
u_a(122, rd_a(CONT, b'\x01'))
# a continuous request: byte count after the name
u_q(123, inst(READ_Q, CONT, struct.pack('<H', 1) + var('%DB100') + struct.pack('<H', 6)))
# the invoke ID is reused with the same name, different names on other conversations
u_q(130, rd_q(WORD, '%DW1'))
u_a(130, rd_a(WORD, b'\x01\x00'))
u_q(130, rd_q(WORD, '%DW1'))
u_a(130, rd_a(WORD, b'\x02\x00'))
main.append(udp(40001, 2005, hdr(REQ, 130, rd_q(CONT, '%DB2')), src=CLIENT, dst=SERVER))
main.append(udp(2005, 40001, hdr(RSP, 130, rd_a(CONT, b'\x05\x00\x06\x00')), src=SERVER, dst=CLIENT))

# --- TCP 2004 --------------------------------------------------------------
c = Conn(main, 49000, 2004, caddr=CLIENT, saddr=SERVER)
q = hdr(REQ, 200, rd_q(CONT, '%DB100'))
a = hdr(RSP, 200, rd_a(CONT, b'\x01\x00\x02\x00\x03\x00'))
c.send(q)
c.recv(a)
c.send(hdr(REQ, 201, wr_q(WORD, ('%DW5', b'\x09\x00'))))
c.recv(hdr(RSP, 201, wr_a(WORD)))
c.send(hdr(REQ, 202, st_q()))
c.recv(hdr(RSP, 202, inst(STAT_A, 0, struct.pack('<HH', 0, 24) + STATUS)))
# two PDUs in one segment
c.send(hdr(REQ, 203, rd_q(WORD, '%DW1')) + hdr(REQ, 204, rd_q(WORD, '%DW2')))
c.recv(hdr(RSP, 203, rd_a(WORD, b'\x01\x00')) + hdr(RSP, 204, rd_a(WORD, b'\x02\x00')))
# a PDU over several segments (the first segment holds at least the 20 octet header: shorter ones are not recognised)
big = hdr(REQ, 205, rd_q(BIT, *['%%MX%d' % i for i in range(12)]))
c.send(big[:25], psh=False)
c.send(big[25:60], psh=False)
c.send(big[60:])
resp = hdr(RSP, 205, rd_a(BIT, *[bytes([i & 1]) for i in range(12)]))
c.ssegs(resp, 25)
c.send(big[:20], psh=False)
c.send(big[20:], psh=True)
c.recv(resp[:20], psh=False)
c.recv(resp[20:])
# a PDU followed by the first part of the next one
two = hdr(REQ, 206, rd_q(WORD, '%DW9')) + hdr(REQ, 207, rd_q(WORD, '%DW10'))
c.send(two[:40], psh=False)
c.send(two[40:])
c.fin()
# a second connection: error response, retransmission of the request
c2 = Conn(main, 49001, 2004, caddr=CLIENT, saddr=SERVER, cisn=77, sisn=999)
c2.send(hdr(REQ, 1, rd_q(WORD, '%DW1')))
c2.recv(hdr(RSP, 1, err_a(READ_A, WORD, 0xFFFF, 0x1108)))
c2.send(hdr(REQ, 2, rd_q(CONT, '%MB8')))
c2.recv(hdr(RSP, 2, rd_a(CONT, b'\x11\x00\x22\x00')))
c2.fin()
# a third one: not XGT (no company ID) on the port, then XGT
c3 = Conn(main, 49002, 2004, caddr=CLIENT, saddr=SERVER, cisn=5, sisn=6)
c3.send(b'\x00' * 30)
c3.recv(b'LSIS-XGT')   # only 8 octets: less than a header, not XGT
c3.fin()

# ---------------------------------------------------------------------------
# Malformed
def m(ins, source=REQ, i=1, tcp=False, **kw):
    mal.append(udp(40000, 2005, hdr(source, i, ins, **kw), src=CLIENT, dst=SERVER))

# an unknown command and block counts above 100 and 256 (warnings in the Malformed group)
m(inst(0x1234, WORD, struct.pack('<HH', 0, 0)))
m(rd_q(BIT, *['%%MX%d' % i for i in range(101)]), i=70)
m(rd_q(BIT, *['%%MX%d' % i for i in range(300)]), i=71)
# XGT on another port (only with Decode As, which then rejects the packet)
mal.append(udp(40000, 9999, hdr(REQ, 1, rd_q(WORD, '%DW1')), src=CLIENT, dst=SERVER))
e = Conn(mal, 49200, 9999, caddr=CLIENT, saddr=SERVER)
e.send(hdr(REQ, 1, rd_q(WORD, '%DW1')))
e.fin()
# length field larger than the data (error expert info), header truncated
m(rd_q(WORD, '%DW1'), length=500)
m(rd_q(WORD, '%DW1'), length=0xffff)
mal.append(udp(40000, 2005, hdr(REQ, 1, b'')[:20], src=CLIENT, dst=SERVER))
mal.append(udp(40000, 2005, b'LSIS-XGT' + bytes(14), src=CLIENT, dst=SERVER))     # 22 octets: header + 2
m(b'\x54\x00\x00\x00\x00\x00\x00')                    # instruction shorter than 8
m(b'\x54\x00')
# truncated: block count missing, count above the data, variable length too long (error)
m(inst(READ_Q, WORD, b'\x01'))
m(inst(READ_Q, WORD, struct.pack('<H', 3) + var('%DW1')))
m(inst(READ_Q, WORD, struct.pack('<H', 1) + struct.pack('<H', 17) + b'x' * 17))
m(inst(READ_Q, WORD, struct.pack('<H', 1) + struct.pack('<H', 0xffff)))
m(inst(READ_Q, WORD, struct.pack('<H', 1) + struct.pack('<H', 10) + b'abc'))
m(inst(READ_Q, WORD, struct.pack('<H', 1) + b'\x05'))
m(inst(READ_Q, WORD, struct.pack('<H', 2) + var('%DW1') + b'\x00'))
m(inst(READ_Q, WORD, struct.pack('<H', 2)))
m(inst(READ_Q, WORD, b''))
# write requests: data length missing, past the end, above 8192
m(inst(WRITE_Q, WORD, struct.pack('<H', 1) + var('%DW1')))
m(inst(WRITE_Q, WORD, struct.pack('<H', 1) + var('%DW1') + b'\x00'))
m(inst(WRITE_Q, WORD, struct.pack('<H', 1) + var('%DW1') + struct.pack('<H', 20) + b'\x01\x02'))
m(inst(WRITE_Q, WORD, struct.pack('<H', 1) + var('%DW1') + struct.pack('<H', 9000) + b'\x01' * 9000))
m(inst(WRITE_Q, WORD, struct.pack('<H', 1) + var('%DW1') + struct.pack('<H', 8192) + b'\x01' * 8192))
# read responses: data length missing / past the end
m(inst(READ_A, WORD, struct.pack('<HH', 0, 1)), source=RSP)
m(inst(READ_A, WORD, struct.pack('<HHH', 0, 1, 4) + b'\x01'), source=RSP)
m(inst(READ_A, CONT, struct.pack('<HHH', 0, 1, 40) + b'\x01\x02'), source=RSP)
m(inst(READ_A, WORD, struct.pack('<HH', 0, 3) + datablk(b'\x01\x02')), source=RSP)
m(inst(READ_A, WORD, struct.pack('<H', 0)), source=RSP)
m(inst(READ_A, WORD, b''), source=RSP)
# error response without the error code; status responses cut short
m(inst(READ_A, WORD, struct.pack('<H', 0xffff)), source=RSP)
m(inst(STAT_A, 0, struct.pack('<H', 0)), source=RSP)
m(inst(STAT_A, 0, struct.pack('<HH', 0, 24) + STATUS[:10]), source=RSP)
m(inst(STAT_A, 0, struct.pack('<HH', 0, 24) + STATUS[:23]), source=RSP)
m(inst(STAT_A, 0, struct.pack('<HH', 0, 24) + STATUS[:24]), source=RSP)
# invoke ID reuse: the response of the first request shows the name of the second on the second pass
mal.append(udp(40010, 2005, hdr(REQ, 9, rd_q(CONT, '%DB10')), src=CLIENT, dst=SERVER))
mal.append(udp(2005, 40010, hdr(RSP, 9, rd_a(CONT, b'\x01\x00\x02\x00')), src=SERVER, dst=CLIENT))
mal.append(udp(40010, 2005, hdr(REQ, 9, rd_q(CONT, '%MB20')), src=CLIENT, dst=SERVER))
mal.append(udp(2005, 40010, hdr(RSP, 9, rd_a(CONT, b'\x03\x00\x04\x00')), src=SERVER, dst=CLIENT))
# TCP: a PDU whose length field is shorter than the header content, truncated PDU at the end of the stream
d = Conn(mal, 49100, 2004, caddr=CLIENT, saddr=SERVER)
d.send(hdr(REQ, 1, rd_q(WORD, '%DW1'), length=2))
d.recv(hdr(RSP, 1, rd_a(WORD, b'\x01\x00'))[:30])
d.recv(b'x', psh=False)
d.fin()

out = sys.argv[1]
write_pcap(os.path.join(out, 'xgt-coverage.pcap'), main)
write_pcap(os.path.join(out, 'xgt-coverage-malformed.pcap'), mal)
print(len(main), len(mal))
