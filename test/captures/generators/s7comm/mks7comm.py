#!/usr/bin/env python3
# Generates test/captures/s7comm_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic S7COMM captures: mks7comm.py <outdir> [-v]
Writes s7comm-coverage.pcap (decodes without malformed packets or error
expert infos) and s7comm-coverage-malformed.pcap (error paths)."""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from s7lib import (
    cotp_cc, cotp_cr, dataitem, dt, Flow, item_1200sym, item_any, item_dbread, item_drivees,
    item_nck, item_rec, item_unknown, items_padded, pcap, s7, tis, tpkt, ts10, ts8, ud,
)

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'
VERBOSE = '-v' in sys.argv

main = []
mal = []
ranges = []
_cur = [None, 0]

def sec(name, frames):
    if _cur[0]:
        ranges.append((_cur[0], _cur[1] + 1, len(frames)))
    _cur[0], _cur[1] = name, len(frames)

def endsec(frames):
    sec(None, frames)

class Conn:
    """A TCP connection to port 102 with a COTP connection set up"""
    port = 50000
    def __init__(self, frames, setup=True):
        Conn.port += 1
        self.fl = Flow(Conn.port, frames)
        self.fl.open()
        if setup:
            self.fl.c2s(cotp_cr(1))
            self.fl.s2c(cotp_cc(1, 2))
        self.ref = 0
    def nref(self):
        self.ref += 1
        return self.ref
    def req(self, pdu, eot=True): self.fl.c2s(dt(pdu, eot))
    def rsp(self, pdu, eot=True): self.fl.s2c(dt(pdu, eot))

# =====================================================================
# main capture
# =====================================================================
F = main
c = Conn(F)

# ---- setup communication, mode transition -----------------------------
sec('Setup communication and ROSCTR handling', F)
c.req(s7(1, 1, bytes([0xf0, 0]) + struct.pack('>HHH', 1, 1, 480)))
c.rsp(s7(3, 1, bytes([0xf0, 0]) + struct.pack('>HHH', 1, 1, 240), err=(0, 0)))
# ACK (no parameter decoding) and unknown ROSCTRs
c.rsp(s7(2, 2, err=(0, 0)))
c.rsp(s7(2, 3, err=(0x81, 0x04)))
c.rsp(s7(4, 4))
c.rsp(s7(5, 5, b'\x00\x01'))
# header error codes
c.rsp(s7(3, 6, bytes([0xf0, 0]) + struct.pack('>HHH', 1, 1, 240), err=(0x85, 0x00)))
c.rsp(s7(3, 7, err=(0xd2, 0x01)))
c.req(s7(1, 8, bytes([0x04, 0])))           # read var without items

# ---- read var / write var requests ------------------------------------
sec('Read/Write variable requests, all address formats', F)
areas = [0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x80, 28, 29, 30, 31, 0x03, 0x05, 0x06, 0x07, 0x77]
its = []
for i, a in enumerate(areas):
    its.append(item_any([2, 1, 4, 6, 8, 3, 28, 29, 30, 31, 5, 7, 9, 0x20][i % 14], 1 + i, i % 3, a, (i * 8 + (i % 8)) if a not in (28, 29) else i))
for i in range(0, len(its), 4):
    c.req(s7(1, c.nref(), bytes([0x04, len(its[i:i+4])]) + items_padded(its[i:i+4])))
c.req(s7(1, c.nref(), bytes([0x04, 1]) + item_any(2, 4, 1, 0x84, 80)))
c.req(s7(1, c.nref(), bytes([0x04, 2]) + item_any(2, 4, 1, 0x85, 80) + item_any(1, 1, 0, 0x81, 3)))
# special items
c.req(s7(1, c.nref(), bytes([0x04, 2]) + items_padded([item_dbread([(10, 5, 0)]), item_any(2, 2, 3, 0x84, 16)])))
c.req(s7(1, c.nref(), bytes([0x04, 1]) + item_dbread([(4, 1, 0), (8, 2, 100), (2, 3, 7)])))
c.req(s7(1, c.nref(), bytes([0x04, 5]) + items_padded([
    item_1200sym(0, 0x50, 0x11223344, [(2, 0x123), (3, 0x45)]),
    item_1200sym(0, 0x51, 0x1, [(4, 1)]),
    item_1200sym(0, 0x52, 0x2, [(5, 2)]),
    item_1200sym(0, 0x99, 0x3, [(6, 3)]),
    item_1200sym(0x8a0e, 0x0007, 0x4, [(7, 0xfffffff), (1, 0)])])))
c.req(s7(1, c.nref(), bytes([0x04, 3]) + items_padded([
    item_1200sym(0, 0x53, 0x5, [(2, 3)]), item_1200sym(0, 0x54, 0x6, [(2, 4)]),
    item_1200sym(0x1234, 0x4321, 0x7, [(2, 5)])])))
c.req(s7(1, c.nref(), bytes([0x04, 3]) + items_padded([
    item_nck(0x82, 1, 3, 1, 2, 0x10, 1), item_nck(0x83, 2, 1, 5, 6, 0x20, 2), item_nck(0x84, 7, 31, 0, 0, 0x7f, 1)])))
c.req(s7(1, c.nref(), bytes([0x04, 2]) + items_padded([item_drivees(1, 2, 3, 4, 5), item_unknown()])))
c.req(s7(1, c.nref(), bytes([0x05, 2]) + items_padded([
    item_any(2, 2, 1, 0x84, 0), item_any(1, 1, 0, 0x82, 5)]) +
    dataitem(0, 4, b'\x12\x34', fill=False) + dataitem(0, 3, b'\x01', nbits=1, fill=False), ))
# write var with data
c.req(s7(1, c.nref(), bytes([0x05, 2]) + item_any(2, 2, 1, 0x84, 0) + item_any(1, 1, 0, 0x82, 5),
         dataitem(0, 4, b'\x12\x34', 16) + dataitem(0, 3, b'\x01', 1, fill=True)))
c.req(s7(1, c.nref(), bytes([0x05, 1]) + item_any(2, 2, 1, 0x84, 0),
         dataitem(0xff, 4, b'\x12\x34', 16)))

# ---- read/write responses -----------------------------------------------
sec('Read/Write variable responses', F)
c.rsp(s7(3, 20, bytes([0x04, 3]),
         dataitem(0xff, 4, b'\x01\x02', 16) + dataitem(0xff, 3, b'\x01', 3, fill=True) +
         dataitem(0xff, 2, b'\xaa\xbb\xcc')))
c.rsp(s7(3, 21, bytes([0x04, 4]),
         dataitem(0xff, 5, b'\x01\x02\x03', 17, fill=True) + dataitem(0x0a, 0, b'', 0) +
         dataitem(0x00, 4, b'\x01', 8, fill=True) + dataitem(0x05, 0, b'', 0)))
c.rsp(s7(3, 22, bytes([0x04, 1]), dataitem(0x05, 0, b'', 0)))
c.rsp(s7(3, 23, bytes([0x04, 1]), dataitem(0xff, 9, b'\x00\x01\x02\x03\x04\x05\x06\x07', 8)))
c.rsp(s7(3, 24, bytes([0x04, 2]),
         bytes([0xff, 0x11]) + item_dbread([(4, 1, 0)]) + item_unknown(0x99, b'\x01\x02')))
c.rsp(s7(3, 25, bytes([0x04, 1]), bytes([0xff, 0x12]) + item_nck(0x82, 1, 2, 3, 4, 0x11, 1)))
c.rsp(s7(3, 26, bytes([0x05, 3]), bytes([0xff, 0x0a, 0x03])))
c.rsp(s7(3, 27, bytes([0x05, 1]), bytes([0xff])))
c.rsp(s7(3, 28, bytes([0x04, 0])))
c.rsp(s7(3, 29, bytes([0x04, 1])))
c.rsp(s7(3, 30, bytes([0x05, 1])))

# ---- unknown functions ------------------------------------------------------
sec('Unknown functions (raw parameter and data)', F)
c.req(s7(1, c.nref(), bytes([0x77]), b''))
c.req(s7(1, c.nref(), bytes([0x77, 1, 2, 3, 4]), b'\x00\x04\x00\x00abcd'))
c.rsp(s7(3, 31, bytes([0x78, 1, 2]), b'\xff\x04\x00\x08\x01\x02'))
c.rsp(s7(3, 32, bytes([0x78]), b''))
c.rsp(s7(3, 33, bytes([0x28]), b''))          # PI service ack without status
c.rsp(s7(3, 34, bytes([0x28, 0x00]), b''))    # PI service ack with status
c.req(s7(1, c.nref(), bytes([0x00]), b'\x00\x01'))   # CPU services job

# ---- block up/download --------------------------------------------------------
sec('Download, upload and PLC control', F)
fn = lambda t, n, fs=b'P': b'_' + t + n + fs
blk = lambda t, n, fs=b'A': t + n + fs
c.req(s7(1, c.nref(), bytes([0x1a, 0x01]) + b'\0\0' + b'\0\0\0\1' + bytes([9]) + fn(b'0A', b'00001') ))
c.req(s7(1, c.nref(), bytes([0x1a, 0x01]) + b'\0\0' + b'\0\0\0\1' + bytes([9]) + fn(b'0B', b'00002', b'A') +
         bytes([13, 0x31]) + b'000100' + b'000050'))
c.req(s7(1, c.nref(), bytes([0x1a, 0x00]) + b'\0\0' + b'\0\0\0\2' + bytes([9]) + b'XA0001234'))
c.rsp(s7(3, 40, bytes([0x1a, 0x00])))
c.rsp(s7(3, 41, bytes([0x1a])))
c.req(s7(1, c.nref(), bytes([0x1b, 0x01]) + b'\0\0' + b'\0\0\0\1' + bytes([9]) + fn(b'0C', b'00010', b'P')))
c.req(s7(1, c.nref(), bytes([0x1b, 0x01]) + b'\0\0' + b'\0\0\0\1' + bytes([12]) + b'/path/to/file'[:12]))
c.rsp(s7(3, 42, bytes([0x1b, 0x01]), struct.pack('>HH', 6, 0x0100) + b'123456'))
c.rsp(s7(3, 43, bytes([0x1b]), b''))
c.req(s7(1, c.nref(), bytes([0x1c, 0x00]) + struct.pack('>H', 0) + b'\0\0\0\1' + bytes([9]) + fn(b'0D', b'00011', b'P')))
c.req(s7(1, c.nref(), bytes([0x1c, 0x00]) + struct.pack('>H', 0x8104) + b'\0\0\0\1' + bytes([9]) + fn(b'0E', b'00012', b'P')))
c.req(s7(1, c.nref(), bytes([0x1c, 0x00]) + struct.pack('>H', 0xabcd) + b'\0\0\0\1' + bytes([9]) + fn(b'0F', b'00013', b'P')))
c.rsp(s7(3, 44, bytes([0x1c, 0x00])))
c.rsp(s7(3, 45, bytes([0x1c])))
c.req(s7(1, c.nref(), bytes([0x1d, 0x00]) + b'\0\0' + struct.pack('>I', 0) + bytes([9]) + fn(b'08', b'00001', b'P')))
c.req(s7(1, c.nref(), bytes([0x1d, 0x00]) + b'\0\0' + struct.pack('>I', 0) + bytes([9]) + fn(b'09', b'00002', b'P')))
c.req(s7(1, c.nref(), bytes([0x1d, 0x00]) + b'\0\0' + struct.pack('>I', 0) + bytes([9]) + fn(b'1A', b'00003', b'P')))
c.req(s7(1, c.nref(), bytes([0x1d, 0x00]) + b'\0\0' + struct.pack('>I', 0) + bytes([9]) + b'XA0001234'))
c.req(s7(1, c.nref(), bytes([0x1d, 0x00]) + b'\0\0' + struct.pack('>I', 0) + bytes([5]) + b'/file'))
c.rsp(s7(3, 46, bytes([0x1d, 0x00]) + b'\0\0' + struct.pack('>I', 7) + bytes([7]) + b'0001234'))
c.rsp(s7(3, 47, bytes([0x1d, 0x00]) + b'\0\0' + struct.pack('>I', 7)))
c.req(s7(1, c.nref(), bytes([0x1e, 0x00]) + b'\0\0' + struct.pack('>I', 7)))
c.rsp(s7(3, 48, bytes([0x1e, 0x01]), struct.pack('>HH', 12, 0x0100) + bytes(range(8)) ))
c.rsp(s7(3, 49, bytes([0x1e]), b''))
c.rsp(s7(3, 50, bytes([0x1e, 0x00]), b''))
c.req(s7(1, c.nref(), bytes([0x1f, 0x00]) + struct.pack('>H', 0) + struct.pack('>I', 7)))
c.rsp(s7(3, 51, bytes([0x1f, 0x00])))
c.rsp(s7(3, 52, bytes([0x1f])))
c.req(s7(1, c.nref(), bytes([0x29]) + bytes(5) + bytes([9]) + b'P_PROGRAM'))
c.req(s7(1, c.nref(), bytes([0x29]) + bytes(5) + bytes([0])))
c.rsp(s7(3, 53, bytes([0x29, 0x00])))

# ---- PI services ------------------------------------------------------------------
sec('PI services', F)
def pi(name, params=b'', unknown=b'\0\0\0\0\0\0\0'):
    nm = name.encode()
    return s7(1, c.nref(), bytes([0x28]) + unknown + struct.pack('>H', len(params)) + params + bytes([len(nm)]) + nm)

def pis(vals):
    out = b''
    for v in vals:
        v = v.encode()
        out += bytes([len(v)]) + v + (b'\0' if len(v) % 2 == 0 else b'')
    return out

def blocks(lst):
    out = bytes([len(lst), 0])
    for t, n, fs in lst:
        out += t + n + fs
    return out

c.req(pi('_INSE', blocks([(b'08', b'00001', b'P'), (b'0A', b'00002', b'A')])))
c.req(pi('_INS2', blocks([(b'0C', b'00003', b'P')])))
c.req(pi('_DELE', blocks([(b'0E', b'00004', b'B'), (b'0F', b'00005', b'Q'), (b'09', b'00006', b'P')])))
c.req(pi('_INSE', blocks([])))
c.req(pi('P_PROGRAM', b''))
c.req(pi('P_PROGRAM', b'\x00\x00\x00\x00'[:0] + b'COLD'))
c.req(pi('_MODU', b''))
c.req(pi('_GARB', b'x'))
# a PI service request whose parameter part is too short
c.req(s7(1, c.nref(), bytes([0x28]) + bytes(7)))
c.req(pi('_UNKNOWN', b'abc'))
c.req(pi('_N_LOGIN_', pis(['/NC', 'secret'])))
for nm in ['_N_LOGOUT', '_N_CANCEL', '_N_DASAVE', '_N_DIGIOF', '_N_DIGION', '_N_DZERO_', '_N_ENDEXT',
           '_N_OST_OF', '_N_OST_ON', '_N_SCALE_', '_N_SETUFR', '_N_STRTLK', '_N_STRTUL', '_N_TMRASS']:
    c.req(pi(nm, pis(['/NC'])))
for nm in ['_N_F_DELE', '_N_EXTERN', '_N_EXTMOD', '_N_F_DELR', '_N_F_XFER', '_N_LOCKE_', '_N_SELECT', '_N_SRTEXT']:
    c.req(pi(nm, pis(['/NC', '/_N_MPF_DIR/_N_TEST_MPF'])))
c.req(pi('_N_F_CLOS', pis(['/NC', 'win1'])))
c.req(pi('_N_F_OPEN', pis(['/NC', '/_N_MPF_DIR/_N_TEST_MPF', 'win1'])))
c.req(pi('_N_F_OPER', pis(['/NC', '/_N_MPF_DIR/_N_TEST_MPF', 'win2'])))
npar = {'_N_F_SEEK': 6, '_N_ASUP__': 6, '_N_CHEKDM': 4, '_N_CHKDNO': 4, '_N_CONFIG': 2, '_N_CRCEDN': 3,
        '_N_DELECE': 3, '_N_CREACE': 2, '_N_CREATO': 2, '_N_DELETO': 2, '_N_CRTOCE': 3, '_N_DELVAR': 6,
        '_N_F_COPY': 4, '_N_F_DMDA': 2, '_N_F_PROR': 3, '_N_F_PROT': 3, '_N_F_RENA': 3, '_N_FINDBL': 2,
        '_N_IBN_SS': 2, '_N_MMCSEM': 3, '_N_NCKMOD': 4, '_N_NEWPWD': 3, '_N_SEL_BL': 2, '_N_SETTST': 4,
        '_N_TMAWCO': 4, '_N_TMCRTC': 5, '_N_TMCRTO': 4, '_N_TMFDPL': 6, '_N_TMFPBP': 13, '_N_TMGETT': 3,
        '_N_TMMVTL': 6, '_N_TMPCIT': 3, '_N_TMPOSM': 8, '_N_TRESMO': 4, '_N_TSEARC': 9}
for nm, n in npar.items():
    c.req(pi(nm, pis(['/NC'] + ['%d' % (k * 7) for k in range(1, n)])))
c.rsp(s7(3, 60, bytes([0x28, 0x00])))

# ---- userdata, programmer / test and installation functions -------------------
sec('Userdata: programmer functions (group 1)', F)
def tp(n):
    """request parameter of the given size"""
    return bytes((i * 3 + 1) & 0xff for i in range(n))
TS8 = ts8()
for n in (2, 4, 20, 26, 28):
    c.req(tis(1, 0x01, tp=tp(n), td=b'\0\x01\x02\x03'))
c.req(tis(1, 0x01, tp=tp(36)[:28] + struct.pack('>HHHH', 2, 0, 0x11, 0x22)))
c.req(tis(1, 0x01, tp=tp(36)[:28] + struct.pack('>HH', 0, 0) + struct.pack('>HH', 0x3038, 5)))
c.req(tis(1, 0x01, tp=tp(38)[:28] + struct.pack('>HH', 0, 0) + struct.pack('>HH', 0x3038, 5) + b'\0\x07'))
c.rsp(tis(2, 0x01, tp=tp(4), td=b''))
c.rsp(tis(2, 0x01, tp=tp(2), td=b'\0\0'))
# block status
c.req(tis(1, 0x13, td=bytes([0x80, 2, 0, 0x03]) + struct.pack('>HBB', 0x10, 0, 0x7f) + struct.pack('>HBB', 0x12, 0, 0x02)))
c.req(tis(1, 0x13, td=bytes([0x80, 0, 0, 0x01])))
c.req(tis(1, 0x01, td=bytes([0, 0x05, 0, 0x01, 0, 0x30, 0, 0x40])))
c.req(tis(1, 0x01, td=bytes([0, 0x05])))
c.req(tis(1, 0x01, td=bytes([0, 0x01]), tdn=1))      # td size 1: no lines
c.rsp(tis(0, 0x01, tp=tp(4), td=struct.pack('>H', 0x20) + bytes(range(10))))
c.rsp(tis(2, 0x01, td=bytes(6)))
c.rsp(tis(3, 0x01, td=bytes(6)))
# variable status
def vaddr(area, ln, db, addr): return bytes([area, ln]) + struct.pack('>HH', db, addr)
VS = [0x00, 0x01, 0x02, 0x03, 0x10, 0x11, 0x12, 0x13, 0x20, 0x21, 0x22, 0x23, 0x31, 0x32, 0x33,
      0x70, 0x71, 0x72, 0x73, 0x54, 0x64, 0x74, 0x55]
vs = b''
for i, a in enumerate(VS):
    vs += vaddr(a, 1 + (i % 3) if a & 0x0f else i % 8, 5 + i, 100 + i)
c.req(tis(1, 0x02, td=struct.pack('>H', len(VS)) + vs))
c.req(tis(1, 0x02, td=struct.pack('>H', 1) + vaddr(0x54, 1, 0, 3)))
c.req(tis(1, 0x02, td=struct.pack('>H', 2) + vaddr(0x64, 4, 0, 3) + vaddr(0x64, 1, 0, 9)))
c.req(tis(1, 0x02, td=struct.pack('>H', 1) + vaddr(0x54, 1, 0, 9)))
c.req(tis(1, 0x02, td=struct.pack('>H', 0)))
c.rsp(tis(0, 0x02, td=struct.pack('>H', 3) + dataitem(0xff, 4, b'\x01\x02', 16) + dataitem(0xff, 3, b'\x01', 8, fill=True) +
          dataitem(0xff, 5, b'\x01\x02', 16) + dataitem(0x0a, 0, b'', 0)[:4] ))
c.rsp(tis(0, 0x02, td=struct.pack('>H', 2) + dataitem(0xff, 2, b'\xaa\xbb\xcc', 3, fill=True) + dataitem(0xff, 9, b'ab', 2)))
c.rsp(tis(2, 0x02, td=struct.pack('>H', 0)))
# modify variable, force
for sub in (0x08, 0x09):
    c.req(tis(1, sub, td=struct.pack('>H', 2) + vaddr(0x72, 1, 3, 10) + vaddr(0x00, 3, 0, 5) +
              dataitem(0xff, 4, b'\x01\x02', 16) + dataitem(0xff, 4, b'\x01', 8, fill=True)))
    c.rsp(tis(0, sub, td=struct.pack('>H', 3) + bytes([0xff, 0x0a, 0x05]) + b'\0'))
    c.rsp(tis(0, sub, td=struct.pack('>H', 2) + bytes([0xff, 0xff])))
    c.rsp(tis(2, sub, td=struct.pack('>H', 2)))
# interrupt stack: 56 bytes + OB part + timestamp
# ob_number is read at offset+3 of the OB part: build the OB part with number at byte 3
OBLEN = {1: 12, 20: 13, 21: 13, 22: 13, 23: 13}
def ob_part(n):
    ln = OBLEN.get(n, 12)
    b = bytearray(range(0x41, 0x41 + ln))
    if n == 20 or n == 21 or n == 22 or n == 23:
        # class, strt_inf, priority, scan_1, number: number is the 5th byte, offset+3 is the scan byte
        b[3] = n
    else:
        b[3] = n
    return bytes(b)
OBS = [1, 10, 11, 12, 13, 14, 15, 16, 17, 20, 21, 22, 23, 30, 31, 32, 33, 34, 35, 36, 37, 38, 40, 41, 42, 43, 44, 45, 46, 47, 48,
       55, 56, 57, 80, 81, 82, 83, 84, 85, 86, 87, 90, 100, 101, 102, 121, 122, 2, 200]
# the register part is 56 bytes before the OB part: 6+2+2+4+... see dissector; pad to 56
IS = struct.pack('>HHH', 0x3038, 1, 0x20) + bytes([0x0a, 0x0b]) + struct.pack('>HH', 3, 4) + bytes(4) + \
     struct.pack('>IIIIII', 1, 2, 3, 4, 5, 6) + bytes(2) + struct.pack('>H', 0x1234) + \
     struct.pack('>HHH', 0x3038, 2, 0x30) + bytes(2) + bytes(4)
c.req(tis(1, 0x03, td=b'\0\0'))
for ob in OBS:
    c.rsp(tis(2 if ob % 2 else 0, 0x03, td=IS + ob_part(ob) + ts8(24, 11, 5, 1, 2, 3, 4, 5)))
# block stack
def bs_entry(bt, nr):
    return struct.pack('>HHH', bt, nr, 0x10) + bytes([0x0a, 0x0b]) + struct.pack('>HH', 3, 4) + bytes(4)
c.req(tis(1, 0x04, td=b'\0\0'))
c.rsp(tis(0, 0x04, td=bs_entry(0x08, 1) + bytes([1, 0, 0, 0]) + ts8() + bs_entry(0x0c, 5) + b'\0'))
c.rsp(tis(2, 0x04, td=bs_entry(0x08, 1) + bytes([1, 0, 0, 0]) + bytes(4) + bs_entry(0x0e, 6) + b'\0'))
c.rsp(tis(0, 0x04, td=bs_entry(0x0a, 3) + bs_entry(0x0b, 4) + b'\0\0'))
c.rsp(tis(0, 0x04, td=bs_entry(0x08, 1) + bytes([1, 0, 0, 0]), ))
# an OB entry whose data size is too small for the OB part (the size is 4 bytes too short)
c.rsp(tis(0, 0x04, td=bs_entry(0x08, 1) + bytes([1, 0, 0, 0]) + bytes(4), tdn=17))
# local stack
c.req(tis(1, 0x05, td=bytes([0x0a, 2])))
c.rsp(tis(0, 0x05, td=struct.pack('>HHHH', 0x3038, 1, 0x40, 6) + bytes(6) + bytes([1, 0]) + bytes(2) + ts8()))
c.rsp(tis(2, 0x05, td=struct.pack('>HHHH', 0x3041, 1, 0x40, 0) + bytes([1, 0]) + bytes(2) + ts8()))
# breakpoint
c.req(tis(1, 0x0a, td=b'\0\0'))
c.rsp(tis(0, 0x0a, td=struct.pack('>HHHHHHHH', 0x3038, 1, 2, 0x3041, 3, 4, 5, 6) + struct.pack('>IIII', 1, 2, 3, 4) +
          bytes([1, 2]) + struct.pack('>HH', 7, 8)))
c.rsp(tis(2, 0x0a, td=struct.pack('>HHHHHHHH', 0x3038, 1, 2, 0x3041, 3, 4, 5, 6) + struct.pack('>IIII', 1, 2, 3, 4) +
          bytes([1, 2]) + struct.pack('>HH', 7, 8)))
# exit hold
c.req(tis(1, 0x0b, td=b'\x01\x00'))
c.rsp(tis(0, 0x0b, td=b'\x01\x00'))
# jobs
c.req(tis(1, 0x0d, td=b'\x05\x01'))
c.req(tis(1, 0x0e, td=b'\x05\x02'))
c.req(tis(1, 0x0f, td=b'\0\0\x05\x03'))
c.req(tis(1, 0x11, td=b'\x05\x04'))
c.req(tis(1, 0x10, td=bytes(4)))
c.rsp(tis(2, 0x10, td=bytes([5, 1, 0, 1, 6, 2, 0, 0, 7, 3, 0, 1])))
c.rsp(tis(0, 0x10, td=b''[:0] + bytes([5, 1, 0, 1])))
c.rsp(tis(2, 0x11, td=struct.pack('>HH', 4, 3) + tp(4) + b'abc'))
c.rsp(tis(2, 0x11, td=struct.pack('>HH', 0, 0)))
c.rsp(tis(2, 0x0d, td=b'\x01\x02'))
# replace job with nested jobs (the first one is a plain jobs/parameter pair)
def replace(depth, inner, tpb=b'', job=0x0e):
    """Replace job: reserved(2), job function, seqnr, tp size, td size, tp, td"""
    return b'\0\0' + bytes([job, 1]) + struct.pack('>HH', len(tpb), len(inner)) + tpb + inner
c.req(tis(1, 0x12, td=replace(1, b'\x05\x01', job=0x0e)))
c.req(tis(1, 0x12, td=replace(1, struct.pack('>H', 1) + vaddr(0x72, 1, 3, 10), job=0x02)))
c.req(tis(1, 0x12, td=replace(1, b'', tpb=tp(4), job=0x0e)))
c.req(tis(1, 0x12, td=replace(1, struct.pack('>H', 1) + vaddr(0x54, 1, 3, 10), tpb=tp(20), job=0x02)))
# other subfunctions: unknown data
for sub in (0x06, 0x07, 0x0c, 0x16, 0x55):
    c.req(tis(1, sub, td=b'\x01\x02\x03\x04'))
c.rsp(tis(2, 0x06, td=b'\x01\x02'))
# request with a zero data size (nothing to decode)
c.req(tis(1, 0x02, tp=b'', td=b''))
# type 3 (unknown type)
c.rsp(tis(3, 0x02, td=b'\x00\x00'))

# ---- cyclic data, read record -------------------------------------------------------
sec('Userdata: cyclic services and read record (group 2)', F)
cit = [item_any(2, 2, 1, 0x84, 0), item_any(1, 1, 0, 0x82, 5), item_any(4, 1, 3, 0x83, 16)]
c.req(ud(1, 2, 0x01, seq=3, payload=bytes([0, 3, 1, 5]) + items_padded(cit)))
c.req(ud(1, 2, 0x05, seq=40, payload=bytes([0, 3, 1, 5]) + items_padded([item_unknown(0x99, b'\xaa\xbb\xcc\xdd'), item_unknown(0x98, b'\x01\x02\x03'), item_any(2, 2, 1, 0x84, 0)])))
c.req(ud(1, 2, 0x05, seq=4, payload=bytes([0, 2, 1, 5]) + items_padded(cit[:2])))
c.req(ud(1, 2, 0x07, seq=5, payload=bytes([0, 1, 2, 10]) + cit[0]))
c.rsp(ud(2, 2, 0x01, seq=3, payload=bytes([0, 2]) + dataitem(0xff, 4, b'\x01\x02', 16) + dataitem(0xff, 3, b'\x01', 8)))
c.rsp(ud(0, 2, 0x01, seq=3, payload=bytes([0, 1]) + dataitem(0xff, 4, b'\x01\x02', 16)))
c.rsp(ud(2, 2, 0x07, seq=5, payload=bytes([0, 1]) + dataitem(0xff, 4, b'\x01\x02', 16)))
c.req(ud(1, 2, 0x04, seq=6, payload=bytes([1, 3])))
c.rsp(ud(2, 2, 0x04, seq=6, payload=b'\x00\x00'))
c.req(ud(1, 2, 0x04, seq=7, payload=b'\x00\x00'))     # data of an unknown request type is shown raw
c.req(ud(1, 2, 0x08, seq=7, payload=bytes([0, 1]) + item_rec(8, 0x0100, 0x00abcd)))
c.req(ud(1, 2, 0x08, seq=7, payload=bytes([0, 0])))
c.rsp(ud(2, 2, 0x08, seq=7, payload=bytes([0, 1, 0xff, 0x09, 0]) + b'\0' + struct.pack('>H', 4) + b'\x01\x02\x03\x04'))
c.rsp(ud(2, 2, 0x08, seq=7, payload=bytes([0, 1, 0xff, 0x09, 4]) + b'\x01\x02\x03\x04' + struct.pack('>H', 2) + b'\xaa\xbb'))
c.rsp(ud(2, 2, 0x08, seq=7, payload=bytes([0, 1, 0xff, 0x09, 2]) + b'\x01\x02' + struct.pack('>H', 0)))
c.rsp(ud(2, 2, 0x08, seq=7, payload=bytes([0, 1, 0x0a, 4]) + b'\x01\x02\x03\x04'))
c.rsp(ud(2, 2, 0x08, seq=7, payload=bytes([0, 0])))
c.rsp(ud(2, 2, 0x55, seq=7, payload=b'\x01\x02'))

# ---- block functions ----------------------------------------------------------------------
sec('Userdata: block functions (group 3)', F)
c.req(ud(1, 3, 0x01, payload=b'', ret=0x0a, tsize=0, dlen=0))
c.req(ud(1, 3, 0x01, payload=b'\0\0'))
c.rsp(ud(2, 3, 0x01, ext=True, payload=b'0A\x00\x05' + b'0B\x00\x01' + b'08\x00\x02'))
c.req(ud(1, 3, 0x02, payload=b'0A'))
c.req(ud(1, 3, 0x02, payload=b'', ret=0x0a, tsize=0, dlen=0))
c.rsp(ud(2, 3, 0x02, ext=True, payload=struct.pack('>HBB', 1, 0x01, 0x05) + struct.pack('>HBB', 2, 0x02, 0x06)))
c.rsp(ud(2, 3, 0x02, ext=True, payload=b'', ret=0x0a, tsize=0, dlen=0))
c.req(ud(1, 3, 0x03, payload=b'0A' + b'00001' + b'A'))
c.req(ud(1, 3, 0x03, payload=b'', ret=0x0a, tsize=0, dlen=0))
def blockinfo(bt=b'0A', sub=0x0a, num=1):
    b = bt + struct.pack('>HH', 0x0042, 0x0000) + b'JB' + b'\x01' + bytes([0x19]) + bytes([3, sub]) + struct.pack('>H', num)
    b += struct.pack('>II', 0x1000, 3) + struct.pack('>IH', 43200000, 15000) + struct.pack('>IH', 43300000, 15001)
    b += struct.pack('>HHHH', 10, 20, 30, 40) + b'AUTHOR  ' + b'FAMILY  ' + b'HEADER  ' + bytes([0x12, 0]) + struct.pack('>H', 0xabcd)
    b += struct.pack('>II', 1, 2)
    return b
for bt, sub in ((b'08', 0x08), (b'0A', 0x0a), (b'0B', 0x0b), (b'0C', 0x0c), (b'0D', 0x0d), (b'0E', 0x0e), (b'0F', 0x0f), (b'0A', 0x77)):
    c.rsp(ud(2, 3, 0x03, ext=True, payload=blockinfo(bt, sub, 12)))
c.rsp(ud(2, 3, 0x03, ext=True, payload=b'', ret=0x0a, tsize=0, dlen=0))
c.rsp(ud(2, 3, 0x03, ext=True, payload=b'\x01\x02\x03\x04', ret=0x0a))
c.req(ud(1, 3, 0x55, payload=b'\x01\x02\x03\x04'))
# fragmented block list response: two fragments with the same data unit reference
c.rsp(ud(2, 3, 0x02, ext=True, seq=9, dur=5, last=1, payload=struct.pack('>HBB', 1, 1, 5) * 3))
c.rsp(ud(2, 3, 0x02, ext=True, seq=9, dur=5, last=0, payload=struct.pack('>HBB', 4, 1, 5) * 2))

# ---- CPU functions (non SZL) --------------------------------------------------------------------
sec('Userdata: CPU functions (group 4): alarms, diagnostic and messages', F)
def alarm_obj(syn, nadd=0, evid=0x11000001, sig=0x03, st=0x00, ackg=0x01, ackc=0x02, notify=b'', assoc=b'', body=None):
    if syn == 0x15:
        b = bytes([nadd]) + struct.pack('>I', evid)
    elif syn == 0x16:
        b = bytes([nadd]) + struct.pack('>I', evid) + bytes([sig, st, ackg, ackc]) + assoc
    elif syn == 0x1c:
        b = bytes([nadd]) + struct.pack('>I', evid) + bytes([sig, st, ackg, ackc]) + notify + assoc
    elif syn == 0x19:
        b = bytes([nadd]) + struct.pack('>I', evid) + bytes([ackg, ackc])
    else:
        b = body if body is not None else b'\xaa\xbb\xcc'
    return bytes([0x12, len(b) + 1, syn]) + b
ASSOC = dataitem(0xff, 4, b'\x01\x02', 16) + dataitem(0xff, 9, b'\xaa\xbb\xcc\xdd')
def alarmmsg(objs, fn=1, ts=True, scan=False):
    b = b''
    if scan:
        b += struct.pack('>H', 0x1234) + ts8()
    elif ts:
        b += ts8()
    b += bytes([fn, len(objs)])
    if scan:
        b = struct.pack('>H', 0x1234) + ts8() + struct.pack('>H', 0xabcd)[:0] + bytes([fn, len(objs)])
    return b + b''.join(objs)
# note: the SCAN indication has two unknown bytes after the time stamp
def scanmsg(objs, fn=1):
    return struct.pack('>H', 0x1234) + ts8() + struct.pack('>H', 0xabcd) + bytes([fn, len(objs)]) + b''.join(objs)
c.req(ud(0, 4, 0x09, payload=scanmsg([alarm_obj(0x16, 0)])))
c.req(ud(0, 4, 0x05, payload=alarmmsg([alarm_obj(0x16, 0, sig=0x00, ackg=0, ackc=0)])))
c.req(ud(0, 4, 0x05, payload=alarmmsg([alarm_obj(0x16, 2, sig=0x81, assoc=ASSOC), alarm_obj(0x16, 1, sig=0xff, assoc=dataitem(0xff, 4, b'\1\2', 16))], fn=2)))
c.req(ud(0, 4, 0x06, payload=alarmmsg([alarm_obj(0x1c, 1, notify=bytes([1, 2, 3, 0]), assoc=dataitem(0xff, 4, b'\1\2', 16))])))
c.req(ud(0, 4, 0x16, payload=alarmmsg([alarm_obj(0x1c, 0, sig=0x10, notify=bytes([1, 2, 3, 0]))])))
c.req(ud(0, 4, 0x0c, payload=alarmmsg([alarm_obj(0x19, 0), alarm_obj(0x15, 0, evid=0x12345678)])))
c.req(ud(0, 4, 0x11, payload=alarmmsg([alarm_obj(0x16, 0)])))
c.req(ud(0, 4, 0x12, payload=alarmmsg([alarm_obj(0x16, 0), alarm_obj(0x42)])))
c.req(ud(1, 4, 0x0b, payload=alarmmsg([alarm_obj(0x19, 0)], ts=False)))
c.req(ud(1, 4, 0x07, payload=alarmmsg([alarm_obj(0x15, 0)], ts=False)))
c.req(ud(1, 4, 0x08, payload=alarmmsg([alarm_obj(0x15, 0)], ts=False)))
c.rsp(ud(2, 4, 0x07, payload=alarmmsg([b'\xff'], ts=False)))
c.rsp(ud(2, 4, 0x0b, payload=alarmmsg([b'\xff', b'\x0a'], ts=False)))
c.req(ud(0, 4, 0x0d, payload=alarmmsg([alarm_obj(0x15, 0)], ts=False)))
c.req(ud(0, 4, 0x0e, payload=alarmmsg([alarm_obj(0x15, 0)], ts=False)))
# alarm query
QO = lambda ln: bytes([0x12, 0x08, 0x1a, 0]) + bytes([1 if ln == 1 else 3, 0]) + struct.pack('>I', 4 if ln == 1 else 0x11000001)[0:4]
c.req(ud(1, 4, 0x13, payload=bytes([1, 1]) + bytes([0x12, 8, 0x1a, 0, 1, 0]) + struct.pack('>I', 4), ))
c.req(ud(1, 4, 0x13, payload=bytes([1, 1]) + bytes([0x12, 8, 0x1a, 0, 3, 0]) + struct.pack('>I', 0x11000001)))
c.req(ud(1, 4, 0x13, payload=bytes([1, 1]) + bytes([0x12, 8, 0x1a, 0, 9, 0]) + struct.pack('>I', 0)))
def qobj(atype, evid=0x11000002, st=1, ackg=1, ackc=2, extra=b''):
    b = struct.pack('>HB', 0, 0)[:0] + bytes([0]) + b'\0\0' + bytes([atype]) + struct.pack('>I', evid) + bytes([0, st, ackg, ackc]) + extra
    return bytes([len(b)]) + b[1:]
def qresp(objs, complete=None, ret=0xff):
    body = b''.join(objs)
    return bytes([1, len(objs), ret, 9]) + struct.pack('>H', len(body) if complete is None else complete) + body
sobj = qobj(4, extra=ts8() + dataitem(0xff, 4, b'\1\2', 16) + ts8(24, 11, 5, 13, 0, 0, 0, 0) + dataitem(0xff, 4, b'\3\4', 16))
c.rsp(ud(2, 4, 0x13, ext=True, payload=qresp([qobj(1), qobj(2)])))
c.rsp(ud(2, 4, 0x13, ext=True, payload=qresp([sobj, qobj(2)])))
c.rsp(ud(2, 4, 0x13, ext=True, payload=qresp([qobj(1), qobj(2), b'\0'], complete=0xffff)))
c.rsp(ud(2, 4, 0x13, ext=True, payload=qresp([qobj(4, extra=ts8() + dataitem(0xff, 4, b'\1\2', 16) + bytes(8) + dataitem(0xff, 4, b'\3\4', 16))], complete=0xffff)[:-0] + b'\0'))
c.rsp(ud(2, 4, 0x13, ext=True, payload=qresp([], ret=0x0a)))
# diagnostic message
def diag(ev, prio=0x16, ob=1):
    return struct.pack('>HBBHHI', ev, prio, ob, 0x0102, 0x0304, 0x05060708) + ts8()
for ev in (0x8032, 0x8abc, 0x9fff, 0x113a, 0x1155, 0x1234, 0x0123, 0xa000, 0xe000, 0x4302, 0x6000):
    c.req(ud(0, 4, 0x03, payload=diag(ev)))
c.req(ud(0, 4, 0x03, payload=diag(0xf003), ))
# message service
def msgs_req(events, name=b'USER    ', extra=b''):
    return bytes([events, 0]) + name + extra
c.req(ud(1, 4, 0x02, payload=msgs_req(0x07)))
c.req(ud(1, 4, 0x02, payload=msgs_req(0xff)))
c.req(ud(1, 4, 0x02, payload=msgs_req(0x80, extra=bytes([0x05, 0]))))
c.req(ud(1, 4, 0x02, payload=msgs_req(0x80, extra=bytes([7, 2]) + bytes([0x12, 6, 0x13, 0]) + struct.pack('>I', 0x11) +
         bytes([0x12, 6, 0x13, 0]) + struct.pack('>I', 0x22))))
c.req(ud(1, 4, 0x02, payload=msgs_req(0x80, extra=bytes([6, 1]) + bytes([0x12, 6, 0x13, 0]) + struct.pack('>I', 0x33))))
c.req(ud(1, 4, 0x02, payload=msgs_req(0x80)))
c.rsp(ud(2, 4, 0x02, payload=bytes([0, 0])))
c.rsp(ud(2, 4, 0x02, payload=bytes([0xff, 0, 5, 0, 0])))
c.rsp(ud(2, 4, 0x02, payload=bytes([0xff, 0, 7, 3, 0, 0x0a, 0xff, 0]) ))
c.rsp(ud(2, 4, 0x02, payload=bytes([0xff, 0, 6, 2, 0, 0xff]) + b'\0'))
# AR_SEND indication (the 8 byte header is taken out before reassembly)
c.req(ud(0, 4, 0x10, payload=bytes([0x12, 6, 0x13, 0]) + struct.pack('>I', 0x1234) + struct.pack('<H', 4) + b'abcd', ))
c.req(ud(0, 4, 0x10, payload=b'\x12\x06\x13\x00\x00\x00\x00\x07' + struct.pack('<H', 3) + b'xyz', ext=True, dur=0))
# unknown CPU subfunction
c.req(ud(1, 4, 0x55, payload=b'\x01\x02\x03\x04'))

# ---- other function groups ------------------------------------------------------------------------
sec('Userdata: security, time, data record routing, mode transition (groups 5, 7, 0x20)', F)
c.req(ud(1, 5, 0x01, payload=b'12345678'))
c.rsp(ud(2, 5, 0x01, payload=b'\0\0\0\0'))
c.req(ud(1, 7, 0x01, payload=b'', ret=0x0a, tsize=0, dlen=0))
c.rsp(ud(2, 7, 0x01, payload=ts10()))
c.rsp(ud(2, 7, 0x03, payload=ts10(y=95, y1=0x19)))
c.rsp(ud(2, 7, 0x01, payload=ts10(mo=0)))
c.rsp(ud(2, 7, 0x01, payload=ts10(mo=13, y=0)))
c.rsp(ud(2, 7, 0x01, payload=b'', ret=0x0a, tsize=0, dlen=2))
c.req(ud(1, 7, 0x02, payload=ts10(y=89, y1=0x19)))
c.req(ud(1, 7, 0x04, payload=ts10(y=88, y1=0x20)))
c.req(ud(1, 7, 0x02, payload=b'\0\0', ret=0x0a))
c.req(ud(1, 7, 0x01, payload=b'\x01\x02\x03\x04'))
c.rsp(ud(2, 7, 0x02, payload=b'\x01\x02\x03\x04'))
c.req(ud(1, 7, 0x55, payload=b'\x01\x02\x03\x04'))
c.req(ud(1, 0x20, 0x03, payload=bytes(range(12))))
c.req(ud(1, 0x20, 0x01, payload=b'\0\0', dlen=2))
c.req(ud(1, 0x21, 0x01, payload=b'\x01\x02\x03\x04'))      # unknown function group
# mode transition indication
def modetrans(mode):
    return s7(7, 100, bytes([0x01, 0]) + struct.pack('>I', 0x12345678) + bytes([mode, 0x77]))
for mode in (0, 1, 2, 3, 4, 5, 6, 7, 0x20, 0x99):
    c.req(modetrans(mode))

# ---- block send and USEND ------------------------------------------------------------------------------
sec('Userdata: BSEND/BRECV, USEND (group 6)', F)
def bsend_hdr(rid): return bytes([0x12, 6, 0x13, 0]) + struct.pack('>I', rid)
c.req(ud(1, 6, 0x01, seq=0, payload=bsend_hdr(0x1001) + struct.pack('>H', 4) + b'abcd'))
c.rsp(ud(2, 6, 0x01, seq=0, payload=bsend_hdr(0x1001) + struct.pack('>H', 4) + b'wxyz'))
c.req(ud(1, 6, 0x01, seq=1, ext=True, last=1, payload=bsend_hdr(0x1002) + struct.pack('>H', 8) + b'12345678'))
c.req(ud(1, 6, 0x01, seq=2, ext=True, last=0, payload=bsend_hdr(0x1002) + struct.pack('>H', 4) + b'9abc'))
c.req(ud(0, 6, 0x01, seq=0, payload=struct.pack('>H', 3) + b'xyz'))
c.req(ud(1, 6, 0x01, seq=0, payload=b'\x01\x02\x03\x04\x05\x06'))
# USEND indication, syntax id 0x13
def usend(items, rid=0x2001, retb=0xff):
    return s7(7, c.nref(), bytes([0, 1, 0x12, 8, 0x13, 0]) + struct.pack('>I', rid),
              bytes([retb, 0x01, 0, len(items)]) + b''.join(items))
def uitem(tsize, payload, nbits=None, fill=False):
    if nbits is None:
        nbits = len(payload) * (8 if tsize in (3, 4, 5) else 1)
    return bytes([0x0e, tsize]) + struct.pack('>H', nbits) + payload + (b'\0' if fill else b'')
c.req(usend([uitem(4, b'\1\2\3\4', 32)]))
c.req(usend([uitem(3, b'\1', 3, fill=True), uitem(4, b'\1\2', 16), uitem(5, b'\1\2\3', 17, fill=True), uitem(9, b'abc', 3, fill=True)]))
c.req(usend([]))

# ---- NC programming ------------------------------------------------------------------------------------------
sec('Userdata: NC programming (group 0x3f)', F)
def nc(typ, sub, payload, seq=0, dur=0, last=0, **kw):
    return ud(typ, 0x3f, sub, seq=seq, ext=True, dur=dur, last=last, payload=payload, **kw)
c.req(nc(1, 1, b'/_N_MPF_DIR/_N_TEST_MPF'))
c.rsp(nc(2, 1, b'\x05\x00'))
c.req(nc(1, 6, b'\x05\x00/_N_MPF_DIR/_N_TEST_MPF', seq=1))
c.rsp(nc(2, 6, b'\x00\x00' + b'00000010' + b'20241105120000000'[:16] + b'/_N_MPF_DIR/_N_X_MPF\nG0 X1\n', seq=1))
c.rsp(nc(2, 6, b'\x00\x00' + b'00000010' + b'2024110512000000', seq=2))
c.rsp(nc(0, 2, b'\x00\x00' + b'00000010' + b'2024110512000000' + b'/_N_MPF_DIR/_N_Y_MPF\nG1 X2\n', seq=3, dur=1))
c.rsp(nc(2, 2, b'\x00\x00' + b'00000010' + b'2024110512000000' + b'no newline here', seq=4, dur=2))
c.rsp(nc(2, 7, b'\x00\x00' + b'00000010' + b'2024110512000000' + b'/_N_MPF_DIR/_N_Z_MPF\nG2 X3\n', seq=5, dur=3))
c.rsp(nc(0, 7, b'\x00\x00' + b'00000010' + b'2024110512000000' + b'/_N_MPF_DIR/_N_Z_MPF\nG2 X3\n', seq=5, dur=4, ))
c.req(nc(0, 3, b'\x03\x00', seq=6, dur=5))
c.req(nc(0, 8, b'\x04\x00', seq=7, dur=6))
c.req(nc(1, 4, b'\x01\x02\x03\x04\x05\x06', seq=8))
c.rsp(nc(2, 4, b'\x01\x02\x03\x04\x05\x06', seq=8))
c.req(nc(1, 3, b'\x01\x02', seq=9))
c.req(nc(1, 3, b'\x01', seq=10))
# a file upload in three fragments: the first with more fragments to come
c.rsp(nc(2, 6, b'\x00\x00' + b'00000010' + b'2024110512000000' + b'/_N_MPF_DIR/_N_BIG_MPF\nG0 X1\n', seq=11, dur=7, last=1))
c.rsp(nc(2, 6, b'\x00\x00' + b'N1 G1 X20 F100\n', seq=11, dur=8, last=1))
c.rsp(nc(2, 6, b'\x00\x00' + b'N2 M30\n', seq=11, dur=9, last=0))

# ---- fragmentation of other groups ------------------------------------------------------------------------------------
sec('Userdata: fragments of CPU and other groups', F)
szl_hdr = lambda i, x, ll, cnt: struct.pack('>HHHH', i, x, ll, cnt)
c.req(ud(1, 4, 0x01, payload=struct.pack('>HH', 0x0111, 0x0001)))
c.rsp(ud(2, 4, 0x01, ext=True, seq=20, dur=3, last=1, payload=szl_hdr(0x0111, 1, 28, 2) + bytes(28)))
c.rsp(ud(2, 4, 0x01, ext=True, seq=20, dur=3, last=0, payload=bytes(28)))
c.rsp(ud(2, 4, 0x01, ext=True, seq=21, dur=4, last=0, payload=szl_hdr(0x0111, 1, 28, 1) + bytes(28)))
c.rsp(ud(2, 4, 0x01, ext=True, seq=22, dur=0, last=0, payload=szl_hdr(0x0132, 1, 0, 0)))
c.rsp(ud(2, 4, 0x01, ext=True, seq=22, dur=0, last=0, payload=b'', ret=0x0a, tsize=0, dlen=0))
c.rsp(ud(2, 4, 0x01, ext=True, seq=23, dur=0, last=0, payload=b'', ret=0x0a, tsize=0x09, dlen=0, ))
c.rsp(ud(2, 4, 0x01, ext=True, seq=24, dur=0, last=0, err=0x8104, payload=b'', ret=0x0a, tsize=0x09, dlen=0))

# ---- reproducers of the fixed bugs (Replace job recursion) --------------------------------------------------------
sec('Replace job nested 8 levels (the limit), plain and in two COTP segments', F)
def nested(levels, job_last=0x0e):
    body = b'\x05\x01' if job_last == 0x0e else b''
    for lvl in range(levels):
        # each level: reserved(2) job=0x12 seq tp=0 td
        body = b'\0\0' + bytes([0x12 if lvl < levels - 1 or job_last == 0x12 else job_last, 1]) + struct.pack('>HH', 0, len(body)) + body
    return body
# the outer request is level 0; allowed: nest < 8
def chain(n):
    inner = b'\x05\x01'
    for i in range(n):
        inner = b'\0\0' + bytes([0x0e if i == 0 else 0x12, 1]) + struct.pack('>HH', 0, len(inner)) + inner
    return inner
c.req(tis(1, 0x12, td=chain(8)))
# one 8-byte level per COTP segment fragment: reassembled by COTP
big = tis(1, 0x12, td=chain(8))
c.req(big[:20], eot=False)
c.req(big[20:])
sec('Replace job nested 10 levels (expert info: the reproducer of the fix), plain and in two COTP segments', F)
# beyond the limit: Replace jobs nested 10 levels (expert info, the reproducer of the fix),
# once in one segment and once in two COTP segments that are reassembled
c.req(tis(1, 0x12, td=chain(10)))
deep = tis(1, 0x12, td=chain(10))
c.req(deep[:30], eot=False)
c.req(deep[30:])
sec('COTP payloads that are not S7COMM', F)
# payloads of COTP data TPDUs that are not S7COMM (the heuristic does not match)
c.fl.c2s(b'\x03\x00\x00\x0b\x02\xf0\x80\x01\x02\x03\x04')
c.fl.c2s(tpkt(b'\x02\xf0\x80' + b'\x33\x01\x00\x00\x00\x01\x00\x00\x00\x00'))
c.fl.c2s(tpkt(b'\x02\xf0\x80' + s7(0, 9)))
c.fl.c2s(tpkt(b'\x02\xf0\x80' + s7(8, 9)))
endsec(F)

# =====================================================================
# malformed capture
# =====================================================================
M = mal
m = Conn(M)
sec('malformed', M)
# nested replace jobs beyond the limit (new expert info); the reproducer through COTP reassembly
m.req(tis(1, 0x12, td=chain(12)))
m.req(tis(1, 0x12, td=chain(40)))
big2 = tis(1, 0x12, td=chain(200))
for i in range(0, len(big2), 600):
    m.req(big2[i:i + 600], eot=(i + 600 >= len(big2)))
# block number that is not numeric
m.req(s7(1, m.nref(), bytes([0x1a, 0x01]) + b'\0\0' + b'\0\0\0\1' + bytes([9]) + b'_0A0000XP'))
m.req(s7(1, m.nref(), bytes([0x28]) + bytes(7) + struct.pack('>H', 10) + bytes([1, 0]) + b'0A0X001P' + bytes([5]) + b'_INSE'))
m.req(ud(1, 3, 0x03, payload=b'0A' + b'0000X' + b'A'))
# truncated PDUs: header only, parameter cut, data cut
m.req(s7(1, 1, bytes([0x04, 2]) + item_any(2, 2, 1, 0x84, 0)))               # second item missing
m.req(s7(1, 2, bytes([0x04, 1, 0x12, 0x0a, 0x10])))
m.rsp(s7(3, 3, bytes([0x04, 2]), dataitem(0xff, 4, b'\1\2', 16)))
m.rsp(s7(3, 4, bytes([0x04, 1]), bytes([0xff, 4, 0, 64, 1, 2])))
m.req(s7(1, 5, bytes([0x28]) + bytes(7) + struct.pack('>H', 40) + b'\1\0'))
m.req(s7(1, 6, bytes([0x28]) + bytes(7) + struct.pack('>H', 0) + bytes([9]) + b'_N_LOGIN_' ))
m.req(s7(1, 7, bytes([0x28]) + bytes(7) + struct.pack('>H', 0) + bytes([9]) + b'_N_LOGIN_'))
m.req(s7(1, 8, bytes([0x1a, 1]) + bytes(6) + bytes([9]) + b'_0A00'))
m.req(s7(1, 9, bytes([0x29, 0, 0, 0])))
m.req(ud(1, 1, 0x02, payload=struct.pack('>H', 5) + b'\0\1'))                 # variable status, count past the end
m.req(ud(1, 1, 0x08, payload=struct.pack('>HH', 0, 0xffff)))
m.rsp(ud(0, 1, 0x03, payload=b'\0\0\0\0' + b'\0' * 20))
m.rsp(ud(2, 1, 0x03, payload=b'\0\0\0\0'))
m.rsp(ud(2, 1, 0x04, payload=struct.pack('>HH', 0, 3) + b'\0\1\2'))
m.rsp(ud(2, 1, 0x05, payload=struct.pack('>HH', 0, 6) + b'\0\1\2\3\4\5'))
m.rsp(ud(2, 1, 0x0a, payload=struct.pack('>HH', 0, 6) + b'\0\1\2\3\4\5'))
m.rsp(ud(2, 3, 0x03, ext=True, payload=b'0A\0\0'))
m.req(ud(1, 4, 0x01, payload=b'\x01\x11'))
m.rsp(ud(2, 4, 0x01, ext=True, payload=struct.pack('>HHHH', 0x0111, 1, 28, 1) + bytes(10)))
m.rsp(ud(2, 4, 0x01, ext=True, payload=struct.pack('>HHHH', 0x0111, 1, 0, 5) + bytes(10)))
m.req(ud(0, 4, 0x05, payload=ts8() + bytes([1, 3]) + alarm_obj(0x16, 0)))
m.req(ud(1, 4, 0x13, payload=bytes([1, 1, 0x12, 8, 0x1a, 0, 1])))
m.rsp(ud(2, 4, 0x13, ext=True, payload=bytes([1, 1, 0xff, 9]) + struct.pack('>H', 100) + bytes(14)))
m.req(ud(1, 4, 0x02, payload=bytes([0x80, 0]) + b'USER    ' + bytes([7, 200])))
m.rsp(ud(2, 4, 0x02, payload=bytes([0xff, 0, 7, 100, 0])))
m.req(ud(0, 4, 0x03, payload=bytes(10)))
m.req(ud(1, 2, 0x01, payload=bytes([0, 5, 1, 5])))
m.req(ud(1, 7, 0x02, payload=ts10()[:6]))
m.req(usend([uitem(4, b'\1\2\3\4', 64)]))
m.req(s7(7, 1, bytes([0, 1, 0x12, 8, 0x13, 0, 0, 0])))
m.req(s7(7, 1, bytes([0, 1])))
m.req(s7(7, 1, bytes([1, 0, 0, 0])))
m.req(s7(7, 1, bytes([0, 1, 0x12, 4, 0x11]) ))
m.req(ud(1, 6, 0x01, payload=bsend_hdr(0x1003) + struct.pack('>H', 100) + b'abcd'))
m.req(nc(1, 6, b'\x05'))
m.req(nc(1, 1, b'a', dlen=500))
m.req(s7(1, 10, bytes([0x04, 1, 0x12, 0x0a, 0xb2, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0xff])))
# block stack whose size is larger than the data (the dissector limits it; only reached without a tree)
m.rsp(tis(0, 0x04, td=bs_entry(0x0c, 1) + b'\0', tdn=60))
m.rsp(tis(0, 0x04, td=bs_entry(0x08, 1) + bytes([1, 0, 0, 0]) + bytes(4), tdn=60))
m.req(s7(1, 11, bytes([0x04, 1, 0x12, 0x0a, 0xb0, 3, 1, 0, 1])))
endsec(M)

pcap(os.path.join(OUT, 's7comm-coverage.pcap'), main)
pcap(os.path.join(OUT, 's7comm-coverage-malformed.pcap'), mal)
if VERBOSE:
    for n, a, b in ranges:
        print('%d-%d %s' % (a, b, n))
    print('main', len(main), 'malformed', len(mal))
