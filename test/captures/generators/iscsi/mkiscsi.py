#!/usr/bin/env python3
# Generates test/captures/iscsi_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the iSCSI dissector
(packet-iscsi.c).

iSCSI runs over TCP; port 3260 (target_ports) and 860 (target_system_port)
are accepted by the heuristic dissector, other ports only through a
conversation created by a TargetAddress key.  Every packet is built with
struct; nothing comes from a real network.  All CHAP values, names and
digests are constant placeholders.

Usage: mkiscsi.py <output directory>

Writes:
  iscsi-coverage.pcap            one session per TCP stream: login with every
                                 key, text, NOP, SCSI read/write (R2T, AHS,
                                 immediate data, sense), TMF, async, reject,
                                 SNACK, vendor, logout, header/data digests,
                                 reassembly, TargetAddress conversations
  iscsi-coverage-malformed.pcap  invalid port in TargetAddress, invalid
                                 opcode in a rejected header, truncated PDUs
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import struct
from netlib import TcpStream, write_pcap

def crc32c(data):
    crc = 0xffffffff
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
    return crc ^ 0xffffffff

def hdr(op, b1=0, b2=0, b3=0, ahs=0, dsl=0, lun=b'\0' * 8, itt=1, w20=0, w24=0, w28=0,
        w32=0, w36=0, w40=0, w44=0, cdb=None):
    h = (struct.pack('>BBBBB', op, b1, b2, b3, ahs) + dsl.to_bytes(3, 'big') + lun
         + struct.pack('>IIIIIIII', itt, w20, w24, w28, w32, w36, w40, w44))
    if cdb is not None:
        h = h[:32] + cdb.ljust(16, b'\0')
    return h

def pad(b):
    return b + b'\0' * ((-len(b)) % 4)

def keys(*kv):
    return b''.join(k.encode() + b'\0' for k in kv)

def with_dig(h, data=b'', hd=False, dd=False, ahs=b'', bad_h=False, bad_d=False):
    """Append AHS, header digest, padded data and data digest."""
    h = h + ahs
    out = h
    if hd:
        c = crc32c(h) ^ (1 if bad_h else 0)
        out += struct.pack('<I', c)
    pd = pad(data)
    out += pd
    if dd and data:
        c = crc32c(pd) ^ (1 if bad_d else 0)
        out += struct.pack('<I', c)
    return out

def lun(n):
    return bytes([0, n, 0, 0, 0, 0, 0, 0])

CDB_READ10 = bytes([0x28, 0, 0, 0, 0, 0, 0, 0, 8, 0])
CDB_WRITE10 = bytes([0x2a, 0, 0, 0, 0x10, 0, 0, 0, 8, 0])
CDB_INQ = bytes([0x12, 0, 0, 0, 36, 0])
SENSE = bytes([0x70, 0, 0x05, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0x24, 0, 0, 0, 0, 0])

INI = '192.0.2.1'; TGT = '192.0.2.2'
frames = []
def add(fr):
    frames.extend(fr)

# ---------------------------------------------------------------- stream 1
s1 = TcpStream(INI, 40000, TGT, 3260)
add(s1.syn())
def I(data, cuts=()): add(s1.send('a', data, cuts))
def T(data, cuts=()): add(s1.send('b', data, cuts))

# security phase login with CHAP placeholders (T=1 CSG=0 NSG=1)
isid = bytes([0x80, 0x12, 0x34, 0x56, 0x00, 0x01]) + b'\0\0'
k = keys('InitiatorName=iqn.2026-01.example:init', 'SessionType=Normal', 'AuthMethod=CHAP,None')
I(with_dig(hdr(0x43, 0x81, 0, 0, dsl=len(k), lun=isid, itt=1, w20=0, w24=1, w28=1), k))
k = keys('AuthMethod=CHAP')
T(with_dig(hdr(0x23, 0x01, 0, 0, dsl=len(k), lun=isid[:6] + b'\x00\x01', itt=1, w24=1, w28=2, w32=2), k))
k = keys('CHAP_A=5', 'TargetName=iqn.2026-01.example:tgt', 'TargetAlias=alias', 'SendTargets=All', 'Garbage')
I(with_dig(hdr(0x43, 0x01, 0, 0, dsl=len(k), lun=isid, itt=1, w20=0, w24=1, w28=1), k))
k = keys('CHAP_A=5', 'CHAP_I=7', 'CHAP_C=0x0a0b0c0d0e0f', 'TargetPortalGroupTag=1')
T(with_dig(hdr(0x23, 0x01, 0, 0, dsl=len(k), lun=isid[:6] + b'\x00\x01', itt=1, w24=1, w28=2, w32=2), k))
k = keys('CHAP_N=user1', 'CHAP_R=0x00000000000000000000000000000000', 'CHAP_I=7', 'CHAP_C=0x01020304')
I(with_dig(hdr(0x43, 0x81, 0, 0, dsl=len(k), lun=isid, itt=1, w20=0, w24=1, w28=1), k))
k = keys('CHAP_N=user1', 'CHAP_R=0xabcdef')
T(with_dig(hdr(0x23, 0x01, 0, 0, dsl=len(k), lun=isid[:6] + b'\x00\x01', itt=1, w24=1, w28=2, w32=2), k))
# operational phase login, C bit variants and every operational key
k = keys('HeaderDigest=None', 'DataDigest=None', 'DefaultTime2Wait=2', 'DefaultTime2Retain=20',
         'ErrorRecoveryLevel=0', 'FirstBurstLength=65536', 'IFMarker=No', 'OFMarker=No',
         'ImmediateData=Yes', 'InitialR2T=No', 'MaxBurstLength=262144', 'MaxConnections=1',
         'MaxOutstandingR2T=1', 'MaxRecvDataSegmentLength=8192', 'DataPDUInOrder=Yes',
         'DataSequenceInOrder=Yes', 'X-vendor.key=abc')
I(with_dig(hdr(0x43, 0x87, 0, 0, dsl=len(k), lun=isid, itt=2, w20=0, w24=2, w28=1), k))
k = keys('HeaderDigest=None', 'DataDigest=None', 'MaxRecvDataSegmentLength=8192',
         'TargetAddress=198.51.100.5:3261,1', 'TargetAddress=[2001:db8::5]:3262,1',
         'TargetAddress=iscsi.example.net:3263', 'TargetAddress=198.51.100.6',
         'TargetAddress=[2001:db8::6]', 'TargetAddress=[2001:db8::7', 'TargetAddress=198.51.100.8:3264',
         'TargetAddress=[2001:db8::8]:3265')
T(with_dig(hdr(0x23, 0x87, 0, 0, dsl=len(k), lun=isid[:6] + b'\x01\x00', itt=2, w24=2, w28=2, w32=2,
               w36=0), k))
# an unreachable login response (Target moved, status 0x0101 and flags with C bit)
k = keys('TargetAddress=198.51.100.9:3260,1')
T(with_dig(hdr(0x23, 0x40, 0, 0, dsl=len(k), lun=isid[:6] + b'\x00\x00', itt=3, w24=3, w28=2, w32=2,
               w36=0x0101 << 16), k))
# a login command with C bit and a short data segment
k = keys('InitiatorName=iqn.2026-01.example:init')
I(with_dig(hdr(0x43, 0x44, 0, 0, dsl=len(k), lun=isid, itt=3, w20=1 << 16, w24=3, w28=2), k))

# volume set addressing LUN (bit 6 of the first LUN byte), command with immediate data
# and a NOP-Out behind it in the same segment
d = b'J' * 512
cmdv = with_dig(hdr(0x01, 0xa1, dsl=512, itt=0x28, lun=bytes([0x40, 0x05, 0, 0, 0, 0, 0, 0]), w20=512, w24=3, w28=3, cdb=CDB_WRITE10), d)
nopx = hdr(0x40, 0x80, itt=0x29, w20=0x56, w24=3, w28=3)
I(cmdv + nopx)
snsx = struct.pack('>H', len(SENSE)) + SENSE + b'\0' * 4
T(with_dig(hdr(0x21, 0x80, 0, 2, dsl=len(snsx), itt=0x28, w24=3, w28=4, w32=4, w36=1), snsx))
# first full feature PDU alone in a segment (digest still unknown)
I(hdr(0x00, 0x80, itt=0x10, w20=0xffffffff, w24=3, w28=3))
# NOP-In reply with ping data in same packet as a NOP-In that follows
pd = b'ping-data'
T(with_dig(hdr(0x20, 0x80, dsl=len(pd), itt=0x10, w20=0xffffffff, w24=3, w28=4, w32=20), pd))
# NOP-Out with ping data (target ping answer) and a TMF in one segment
pd = b'pong-data!!'
nop = with_dig(hdr(0x40, 0x80, dsl=len(pd), itt=0xffffffff, w20=0x55, w24=4, w28=4), pd)
tmf = hdr(0x42, 0x81, lun=lun(1), itt=0x11, w20=0x0a, w24=4, w28=4, w32=3)
I(nop + tmf)
T(hdr(0x22, 0x80, 0, 0, itt=0x11, w24=4, w28=5, w32=5))     # TMF response, function complete
T(hdr(0x22, 0x80, 5, 0, itt=0x11, w24=5, w28=5, w32=5))     # not supported
# Text: SendTargets
k = keys('SendTargets=All')
I(with_dig(hdr(0x44, 0x80, dsl=len(k), itt=0x12, w20=0xffffffff, w24=5, w28=5), k))
k = keys('TargetName=iqn.2026-01.example:tgt', 'TargetAddress=198.51.100.5:3261,1', 'TargetAlias=a')
T(with_dig(hdr(0x24, 0x80, dsl=len(k), itt=0x12, w20=0xffffffff, w24=5, w28=6, w32=6), k))
T(with_dig(hdr(0x24, 0x40, dsl=len(k), itt=0x13, w20=0x77, w24=6, w28=6, w32=6), k))   # C bit

# SCSI read: command, Data-In, Data-In with S (phase collapse), then plain response
I(with_dig(hdr(0x01, 0xc1, itt=0x20, lun=lun(1), w20=1024, w24=6, w28=6, cdb=CDB_READ10)))
d0 = bytes(range(256)) * 2
T(with_dig(hdr(0x25, 0x00, dsl=512, itt=0x20, w20=0xffffffff, w24=6, w28=6, w32=6, w36=0, w40=0), d0))
T(with_dig(hdr(0x25, 0x41, dsl=512, itt=0x20, lun=lun(1), w20=0x33, w24=6, w28=6, w32=6, w36=1, w40=512), d0))
T(with_dig(hdr(0x25, 0x81, dsl=512, itt=0x20, w20=0xffffffff, w24=6, w28=6, w32=6, w36=2, w40=1024), d0))
T(with_dig(hdr(0x25, 0x87, dsl=8, itt=0x20, w20=0xffffffff, w24=7, w28=6, w32=6, w36=3, w40=1536, w44=4), d0[:8]))
T(hdr(0x21, 0x80, itt=0x20, w24=7, w28=7, w32=8, w36=4))   # SCSI Response good
# command answered by Data-In with status in the last PDU (S=1) good
I(with_dig(hdr(0x01, 0xc1, itt=0x21, lun=lun(1), w20=512, w24=7, w28=7, cdb=CDB_READ10)))
T(with_dig(hdr(0x25, 0x81, dsl=512, itt=0x21, w20=0xffffffff, w24=7, w28=7, w32=8, w36=0, w40=0), d0))
T(with_dig(hdr(0x25, 0x83, dsl=512, itt=0x21, w20=0xffffffff, w24=8, w28=7, w32=8, w36=1, w40=512, w44=7), d0))
# Data-In with S and Check Condition status in the Data-In itself
T(hdr(0x25, 0x81 | 0x02, 0, 2, dsl=0, itt=0x21, w24=8, w28=7, w32=8, w36=1, w40=0))
# write with R2T, solicited Data-Out and response
I(hdr(0x01, 0xa1, itt=0x22, lun=lun(1), w20=8192, w24=7, w28=8, cdb=CDB_WRITE10))
T(hdr(0x31, 0x80, itt=0x22, lun=lun(1), w20=0x99, w24=8, w28=8, w32=8, w36=0, w40=0, w44=4096))
big = bytes((i * 7) & 0xff for i in range(4096))
# Data-Out spanning three TCP segments (header split too)
I(with_dig(hdr(0x05, 0x00, dsl=4096, itt=0x22, w20=0x99, w28=8, w36=0, w40=0), big), cuts=(30, 1000, 3000))
T(hdr(0x31, 0x80, itt=0x22, lun=lun(1), w20=0x9a, w24=8, w28=8, w32=8, w36=1, w40=4096, w44=4096))
I(with_dig(hdr(0x05, 0x80, dsl=4096, itt=0x22, w20=0x9a, w28=8, w36=1, w40=4096), big), cuts=(48, 2000))
# R2T for command that has no request in the capture
T(hdr(0x31, 0x80, itt=0x7777, w20=0x9b, w24=8, w28=8, w32=8, w36=2, w40=0, w44=512))
T(hdr(0x21, 0x80, itt=0x22, w24=8, w28=8, w32=9, w36=5, w40=0, w44=0))
# write with immediate data and a check condition with sense data
d = b'I' * 512
I(with_dig(hdr(0x01, 0xa1, dsl=512, itt=0x23, lun=lun(2), w20=512, w24=8, w28=8, cdb=CDB_WRITE10), d))
sns = struct.pack('>H', len(SENSE)) + SENSE
T(with_dig(hdr(0x21, 0x80, 0, 2, dsl=len(sns), itt=0x23, w24=9, w28=9, w32=10, w36=6), sns))
# SCSI response with non-zero status, overflow flags and no sense
T(hdr(0x21, 0x80 | 0x1e, 1, 0x08, itt=0x24, w24=9, w28=9, w32=10, w36=6, w40=3, w44=5))
# command with AHS: extended CDB and an unknown AHS, immediate read of INQUIRY
ext = struct.pack('>HBB', 17, 1, 0) + bytes([0x7f] + [0] * 15)
unk = struct.pack('>HBB', 2, 3, 0) + b'\xaa' + b'\0' * 3
ah = ext + unk
I(hdr(0x01, 0xc0, ahs=len(ah) // 4, itt=0x25, lun=lun(0), w20=36, w24=9, w28=9, cdb=bytes([0x7f, 0, 0, 0, 0, 0, 0, 16])) + ah)
# command with bidirectional read-length AHS
bidi = struct.pack('>HBBI', 5, 2, 0, 4096)
I(with_dig(hdr(0x01, 0xe0, ahs=2, itt=0x26, lun=lun(0), w20=512, w24=9, w28=9, cdb=CDB_INQ), ahs=bidi))
# SCSI command in the TCP stream with data and cdb of 16 bytes
I(hdr(0x41, 0x80, itt=0x27, lun=lun(0), w24=10, w28=9, cdb=bytes(6)))
# Async message with sense and event data
ev = struct.pack('>H', len(SENSE)) + SENSE + b'EVENTDATA'
T(with_dig(hdr(0x32, 0x80, dsl=len(ev), lun=lun(1), itt=0xffffffff, w24=10, w28=10, w32=10, w36=0x00010000,
               w40=0x00020003), ev))
T(hdr(0x32, 0x80, itt=0xffffffff, w24=10, w28=10, w32=10, w36=0x01000000 | 0x0102, w40=0x00030004))  # event 1, no data
# async with empty sense and data
ev = struct.pack('>H', 0) + b'DATA'
T(with_dig(hdr(0x32, 0x80, dsl=len(ev), itt=0xffffffff, w24=10, w28=10, w32=10, w36=0x04000000), ev))
# Reject with the rejected header
rej = hdr(0x01, 0xc0, itt=0x66, lun=lun(1), w20=8, w24=11, w28=9, cdb=CDB_READ10)
T(with_dig(hdr(0x3f, 0x80, 0x04, 0, dsl=48, itt=0xffffffff, w24=10, w28=10, w32=10, w36=12), rej))
# Reject with no room for the rejected header
T(hdr(0x3f, 0x80, 0x02, 0, dsl=0, itt=0xffffffff, w24=10, w28=10, w32=10, w36=13))
# thirty Reject PDUs without a data segment in one segment (each is dissected on its own;
# the Reject header is limited to the data segment, so they do not nest)
T(b''.join(hdr(0x3f, 0x80, 0x04, 0, dsl=0, itt=0xffffffff, w24=10, w28=10, w32=10, w36=14 + i) for i in range(30)))
# SNACK requests of every type
I(hdr(0x10, 0x80, itt=0x30, lun=lun(1), w20=0x44, w40=1, w44=3))
I(hdr(0x10, 0x81, itt=0xffffffff, w40=5, w44=1))
I(hdr(0x10, 0x82, itt=0xffffffff, w20=0x45, w40=5, w44=0))
I(hdr(0x10, 0x83, itt=0x31, w20=0x46, w40=8, w44=2))
# vendor specific PDUs with data
vd = b'VENDOR!!'
I(with_dig(hdr(0x5c, 0x80, dsl=len(vd), itt=0x40), vd))
T(with_dig(hdr(0x3c, 0x80, dsl=5, itt=0x41), b'VEND5'))
T(hdr(0x3d, 0x80, itt=0x42)); T(hdr(0x3e, 0x80, itt=0x43)); I(hdr(0x1d, 0x80, itt=0x44)); I(hdr(0x1e, 0x80, itt=0x45))
# two PDUs in one segment, the second without the F bit (dissected unless demand_good_f_bit is set)
T(hdr(0x20, 0x80, itt=0x4f, w20=0xffffffff, w24=10, w28=10, w32=10) + hdr(0x21, 0x00, itt=0x4e, w24=10, w28=10, w32=10, w36=7))
# NOP-In followed by NOP-Out with TTT 0 (bogus filter stops dissecting) and by
# a PDU with an unknown opcode (stops dissecting)
T(hdr(0x20, 0x80, itt=0x50, w20=0x33, w24=10, w28=10, w32=10) + hdr(0x00, 0x80, itt=0x51, w20=0, w24=10))
T(hdr(0x20, 0x80, itt=0x52, w20=0x33, w24=10, w28=10, w32=10) + hdr(0x1a, 0x80, itt=0x51))
# PDU with a huge data segment length is not iSCSI (bogus filter)
T(hdr(0x20, 0x80, dsl=0x7fffff, itt=0x53, w20=0x33, w24=10, w28=10, w32=10))
# a header spread over 3 segments, then the data of a big NOP-In
pd = b'N' * 3000
T(with_dig(hdr(0x20, 0x80, dsl=len(pd), itt=0x54, w20=0xffffffff, w24=10, w28=10, w32=10), pd), cuts=(10, 30, 60))
# logout
I(hdr(0x46, 0x80, itt=0x60, w20=1 << 16, w24=11, w28=10))
T(hdr(0x26, 0x80, 0, 0, itt=0x60, w24=11, w28=11, w32=11, w36=0, w40=(2 << 16) | 20))
I(hdr(0x46, 0x82, itt=0x61, w20=1 << 16, w24=11, w28=10))
I(hdr(0x06, 0x81, itt=0x62, w20=1 << 16, w24=11, w28=10))
T(hdr(0x26, 0x80, 1, 0, itt=0x61, w24=11, w28=11, w32=11, w36=0, w40=0))
add([])

# ---------------------------------------------------------------- stream 2: header and data digests
s2 = TcpStream(INI, 40001, TGT, 3260, mac_a=b'\x02\0\0\0\0\x03')
add(s2.syn())
def I2(data, cuts=()): add(s2.send('a', data, cuts))
def T2(data, cuts=()): add(s2.send('b', data, cuts))
k = keys('InitiatorName=iqn.2026-01.example:init2', 'SessionType=Normal', 'AuthMethod=None')
I2(with_dig(hdr(0x43, 0x87, dsl=len(k), lun=isid, itt=1, w24=1, w28=1), k))
k = keys('HeaderDigest=CRC32C', 'DataDigest=CRC32C')
T2(with_dig(hdr(0x23, 0x87, dsl=len(k), lun=isid[:6] + b'\x00\x02', itt=1, w24=1, w28=1, w32=1), k))
# First non-login PDU has a header digest: autodetected
I2(with_dig(hdr(0x00, 0x80, itt=2, w20=0xffffffff, w24=2, w28=1), hd=True))
# NOP-In with ping data and both digests (data digest autodetected)
pd = b'digested'
T2(with_dig(hdr(0x20, 0x80, dsl=len(pd), itt=2, w20=0xffffffff, w24=1, w28=3, w32=3), pd, hd=True, dd=True))
# the digests of the following PDUs: command, Data-Out, Data-In, response
I2(with_dig(hdr(0x01, 0xa1, itt=3, lun=lun(1), w20=1024, w24=2, w28=2, cdb=CDB_WRITE10), hd=True))
T2(with_dig(hdr(0x31, 0x80, itt=3, lun=lun(1), w20=0x71, w24=2, w28=3, w32=3, w36=0, w40=0, w44=1024), hd=True))
I2(with_dig(hdr(0x05, 0x80, dsl=1024, itt=3, w20=0x71, w28=2), big[:1024], hd=True, dd=True))
T2(with_dig(hdr(0x21, 0x80, itt=3, w24=2, w28=3, w32=3, w36=1), hd=True))
I2(with_dig(hdr(0x01, 0xc1, itt=4, lun=lun(1), w20=512, w24=3, w28=3, cdb=CDB_READ10), hd=True))
T2(with_dig(hdr(0x25, 0x81, dsl=512, itt=4, w20=0xffffffff, w24=3, w28=3, w32=3, w36=0, w40=0), d0, hd=True, dd=True))
# command with AHS and header digest, immediate data with data digest
ah2 = struct.pack('>HBB', 17, 1, 0) + bytes([0x7f] + [0] * 15)
I2(with_dig(hdr(0x01, 0xa0, ahs=len(ah2) // 4, dsl=16, itt=5, lun=lun(1), w20=16, w24=3, w28=3, cdb=bytes([0x7f, 0, 0, 0, 0, 0, 0, 16])),
            b'D' * 16, hd=True, dd=True, ahs=ah2))
# bad header digest, bad data digest
I2(with_dig(hdr(0x00, 0x80, dsl=4, itt=6, w20=0xffffffff, w24=4, w28=3), b'BAD1', hd=True, dd=True, bad_h=True))
I2(with_dig(hdr(0x00, 0x80, dsl=4, itt=7, w20=0xffffffff, w24=5, w28=3), b'BAD2', hd=True, dd=True, bad_d=True))
# every other opcode with a header digest
I2(with_dig(hdr(0x42, 0x81, lun=lun(1), itt=8, w20=0x0a, w24=6, w28=3, w32=3), hd=True))
T2(with_dig(hdr(0x22, 0x80, 0, 0, itt=8, w24=6, w28=7, w32=7), hd=True))
k = keys('SendTargets=All')
I2(with_dig(hdr(0x44, 0x80, dsl=len(k), itt=9, w20=0xffffffff, w24=6, w28=3), k, hd=True, dd=True))
T2(with_dig(hdr(0x24, 0x80, dsl=len(k), itt=9, w20=0xffffffff, w24=6, w28=7, w32=7), k, hd=True, dd=True))
T2(with_dig(hdr(0x32, 0x80, itt=0xffffffff, w24=7, w28=7, w32=7, w36=0x01000000), hd=True))
T2(with_dig(hdr(0x3f, 0x80, 0x09, 0, itt=0xffffffff, w24=7, w28=7, w32=7, w36=0), hd=True))
I2(with_dig(hdr(0x10, 0x81, itt=0xffffffff, w40=5, w44=1), hd=True))
I2(with_dig(hdr(0x46, 0x80, itt=10, w20=1 << 16, w24=7, w28=3), hd=True))
T2(with_dig(hdr(0x26, 0x80, itt=10, w24=7, w28=8, w32=8), hd=True))
I2(with_dig(hdr(0x5c, 0x80, dsl=4, itt=11), b'VEND', hd=True, dd=True))
# digested PDU split over segments, then a PDU whose header is short of the digest
I2(with_dig(hdr(0x00, 0x80, dsl=8, itt=12, w20=0xffffffff, w24=8, w28=3), b'splitted', hd=True, dd=True), cuts=(20, 50))
# a Login command after the digests were detected carries no digest
k = keys('X=Y')
I2(with_dig(hdr(0x43, 0x44, dsl=len(k), lun=isid, itt=13, w24=8, w28=3), k))

# ---------------------------------------------------------------- stream 3: system port 860 and a TargetAddress conversation
s3 = TcpStream(INI, 40002, TGT, 860, mac_a=b'\x02\0\0\0\0\x04')
add(s3.syn())
add(s3.send('a', hdr(0x00, 0x80, itt=1, w20=0xffffffff, w24=1, w28=1)))
add(s3.send('b', hdr(0x20, 0x80, itt=1, w20=0xffffffff, w24=1, w28=2, w32=2)))
s3b = TcpStream(INI, 40010, TGT, 860, mac_a=b'\x02\0\0\0\0\x0b')
add(s3b.syn())
add(s3b.send('b', hdr(0x20, 0x80, itt=1, w20=0xffffffff, w24=1, w28=2, w32=2)))
add(s3b.send('a', hdr(0x00, 0x80, itt=1, w20=0xffffffff, w24=1, w28=1)))
# a target PDU from port 860 and an initiator PDU to an unrelated port are not iSCSI
s4 = TcpStream(INI, 40003, TGT, 24000, mac_a=b'\x02\0\0\0\0\x05')
add(s4.syn())
add(s4.send('a', hdr(0x00, 0x80, itt=1, w20=0xffffffff, w24=1, w28=1)))
add(s4.send('b', hdr(0x20, 0x80, itt=1, w20=0xffffffff, w24=1, w28=2, w32=2)))
# connection to the address and port of a TargetAddress key from stream 1
s5 = TcpStream(INI, 40004, '198.51.100.5', 3261, mac_a=b'\x02\0\0\0\0\x06')
add(s5.syn())
add(s5.send('a', hdr(0x00, 0x80, itt=1, w20=0xffffffff, w24=1, w28=1)))
add(s5.send('b', hdr(0x20, 0x80, itt=1, w20=0xffffffff, w24=1, w28=2, w32=2)))
s6 = TcpStream('2001:db8::1', 40005, '2001:db8::5', 3262, mac_a=b'\x02\0\0\0\0\x07')
add(s6.syn())
add(s6.send('a', hdr(0x00, 0x80, itt=1, w20=0xffffffff, w24=1, w28=1)))
add(s6.send('b', hdr(0x20, 0x80, itt=1, w20=0xffffffff, w24=1, w28=2, w32=2)))
s7 = TcpStream(INI, 40006, '198.51.100.8', 3264, mac_a=b'\x02\0\0\0\0\x08')
add(s7.send('a', hdr(0x00, 0x80, itt=1, w20=0xffffffff, w24=1, w28=1)))
s8 = TcpStream('2001:db8::1', 40007, '2001:db8::8', 3265, mac_a=b'\x02\0\0\0\0\x09')
add(s8.send('a', hdr(0x00, 0x80, itt=1, w20=0xffffffff, w24=1, w28=1)))

# ---------------------------------------------------------------- malformed capture
mal = []
sm = TcpStream(INI, 41000, TGT, 3260, mac_a=b'\x02\0\0\0\0\x0a')
mal += sm.syn()
k = keys('InitiatorName=iqn.2026-01.example:m', 'SessionType=Normal')
mal += sm.send('a', with_dig(hdr(0x43, 0x87, dsl=len(k), lun=isid, itt=1, w24=1, w28=1), k))
k = keys('TargetAddress=198.51.100.20:notaport', 'TargetAddress=[2001:db8::9]:99999,1')
mal += sm.send('b', with_dig(hdr(0x23, 0x87, dsl=len(k), lun=isid[:6] + b'\0\1', itt=1, w24=1, w28=1, w32=1), k))
# Reject whose rejected header carries an unknown opcode
rej = hdr(0x1a, 0xc0, itt=0x66) + b'\0' * 0
mal += sm.send('b', with_dig(hdr(0x3f, 0x80, 0x04, 0, dsl=48, itt=0xffffffff, w24=2, w28=1, w32=1), rej))
# truncated: SCSI command whose CDB is cut off, Reject with data cut short
mal += [(sm.send('a', with_dig(hdr(0x01, 0xa1, dsl=16, itt=2, lun=lun(1), w20=16, w24=2, w28=1, cdb=CDB_WRITE10), b'W' * 16))[0], None, 14 + 20 + 20 + 48)]
mal += sm.send('b', with_dig(hdr(0x3f, 0x80, 0x04, 0, dsl=48, itt=0xffffffff, w24=2, w28=1, w32=1), rej[:20]))
# SCSI command with a longer AHS than the packet carries
mal += sm.send('a', hdr(0x01, 0xc0, ahs=50, itt=3, lun=lun(1), w24=2, w28=1, cdb=CDB_READ10) + struct.pack('>HBB', 17, 1, 0))
# Async message and SCSI response with data segment cut
mal += sm.send('b', hdr(0x32, 0x80, dsl=300, itt=0xffffffff, w24=2, w28=1, w32=1) + struct.pack('>H', 200) + b'\x70')
mal += sm.send('b', hdr(0x21, 0x80, 0, 2, dsl=300, itt=3, w24=2, w28=1, w32=1) + struct.pack('>H', 200) + b'\x70')
# text with key lacking NUL at the end
mal += sm.send('a', hdr(0x44, 0x80, dsl=20, itt=4, w20=0xffffffff, w24=2, w28=1) + b'SendTargets=Al')
# 400 chained rejects (depth limit)
chain = b''
for i in range(400):
    chain += hdr(0x3f, 0x80, 0x04, 0, dsl=48, itt=0xffffffff, w36=0)
chain += hdr(0x20, 0x80, itt=0x99, w20=0x33)
mal += sm.send('b', chain)
# AHS unknown type with bogus length
mal += sm.send('a', hdr(0x01, 0xc0, ahs=2, itt=5, lun=lun(1), w24=2, w28=1, cdb=CDB_READ10) + struct.pack('>HBB', 300, 3, 0) + b'\0' * 4)

# a first segment that is too short for the heuristic (not iSCSI)
ss = TcpStream(INI, 41100, TGT, 3260, mac_a=b'\x02\0\0\0\0\x0c')
mal += ss.syn()
mal += ss.send('a', b'\x43\x81\0\0\0\0\0\0\0\0')
# a PDU larger than the segment when reassembly is not possible is covered by the
# runs with reassembly off; here a PDU whose data segment is cut short by the capture
mal += [(sm.send('b', with_dig(hdr(0x25, 0x81, dsl=512, itt=2, w20=0xffffffff, w24=3, w28=1, w32=1, w36=0, w40=0), d0))[0], None, 14 + 20 + 20 + 100)]
# the heuristic rejects: one base PDU per opcode with one byte changed, each as the first PDU of its own
# connection (so that no conversation exists yet)
bases = {
 0x00: hdr(0x00, 0x80, itt=1, w20=0xffffffff),
 0x01: hdr(0x01, 0xc1, itt=1, w20=512, cdb=CDB_READ10),
 0x02: hdr(0x02, 0x81, itt=1, w20=2),
 0x03: hdr(0x03, 0x87, itt=1),
 0x04: hdr(0x04, 0x80, itt=1, w20=0xffffffff),
 0x05: hdr(0x05, 0x80, itt=1, w20=1),
 0x06: hdr(0x06, 0x80, itt=1),
 0x10: hdr(0x10, 0x81, itt=0xffffffff),
 0x20: hdr(0x20, 0x80, itt=1, w20=0xffffffff),
 0x21: hdr(0x21, 0x80, itt=1),
 0x22: hdr(0x22, 0x80, itt=1),
 0x23: hdr(0x23, 0x87, itt=1),
 0x24: hdr(0x24, 0x80, itt=1),
 0x25: hdr(0x25, 0x80, itt=1),
 0x26: hdr(0x26, 0x80, itt=1),
 0x31: hdr(0x31, 0x80, itt=1, w44=512),
 0x32: hdr(0x32, 0x80, itt=0xffffffff),
 0x3f: hdr(0x3f, 0x80, 0x04, itt=0xffffffff),
}
# opcode specific tweaks that make a byte hit a different branch
extra = [(0x10, 1, 0x80), (0x10, 1, 0x82), (0x10, 1, 0x83), (0x10, 1, 0x84), (0x10, 20, 0xff),
         (0x02, 1, 0x80), (0x06, 1, 0x80), (0x06, 1, 0x83), (0x22, 2, 7), (0x26, 2, 9),
         (0x3f, 2, 0x63), (0x21, 3, 0x01), (0x04, 1, 0x00), (0x24, 1, 0x00), (0x01, 1, 0xc0 | 0x18)]
muts = []
for op in bases:
    for pos in (0, 1, 2, 3, 4, 8, 12, 16, 20, 24, 32, 36, 38, 40, 44):
        muts.append((op, pos, None))
for e in extra:
    muts.append(e)
port = 42000
def one(src, data, dport=3260):
    global port
    st = TcpStream(INI, port, TGT, dport, mac_a=b'\x02\0\0\0\0\x0d')
    port += 1
    return st.syn() + st.send(src, data)
for op, pos, val in muts:
    b = bytearray(bases[op])
    if val is None:
        b[pos] ^= 0xc0 if pos == 0 else 0x01
        if pos == 1:
            b[pos] ^= 0x7e
    else:
        b[pos] = val
    # also zero ITT/TTT variants for NOP-Out
    src = 'a' if (b[0] & 0x20) == 0 else 'b'
    mal += one(src, bytes(b))
# NOP-Out with a zero ITT, with a zero TTT, SCSI Command with a W bit missing, Data-In with a reserved byte
for pos in (16, 20):
    b = bytearray(bases[0x00]); b[pos:pos + 4] = b'\0\0\0\0'
    mal += one('a', bytes(b))
b = bytearray(bases[0x01]); b[20:24] = (512).to_bytes(4, 'big'); b[1] = 0x81
mal += one('a', bytes(b))
b = bytearray(bases[0x01]); b[1] = 0x81; b[2] = 1
mal += one('a', bytes(b))
manual = [
 ('a', hdr(0x03, 0x20, itt=1)),                                   # Login Command, reserved flag bits
 ('a', hdr(0x03, 0x80, itt=1)),                                   # T bit with NSG 0
 ('a', hdr(0x03, 0x4a, itt=1)),                                   # NSG 2
 ('b', hdr(0x23, 0x20, itt=1)),
 ('b', hdr(0x23, 0x80, itt=1)),
 ('b', hdr(0x23, 0x4a, itt=1)),
 ('b', hdr(0x23, 0x01, itt=1, w36=1)),                            # bytes 38/39 not zero
 ('a', hdr(0x10, 0x83, itt=0x31, w20=0xffffffff)),                # R-Data SNACK, TTT 0xffffffff
 ('a', hdr(0x02, 0x01, itt=1)),                                   # TMF without the F bit
 ('a', hdr(0x06, 0x01, itt=1)),                                   # Logout without the F bit
 ('b', hdr(0x21, 0x00, itt=1)),                                   # SCSI Response without the F bit
 ('b', hdr(0x31, 0x80, itt=1, w44=0)),                            # R2T with a zero desired length
]
for src, pdu in manual:
    mal += one(src, pdu)
# a target PDU on a port that is not an iSCSI port, an initiator PDU to such a port, and
# an unknown opcode
mal += one('a', hdr(0x1a, 0x80))
mal += one('a', hdr(0x00, 0x80, itt=1, w20=0xffffffff), 24001)
mal += one('b', hdr(0x20, 0x80, itt=1, w20=0xffffffff), 24001)

out = sys.argv[1] if len(sys.argv) > 1 else '.'
write_pcap(os.path.join(out, 'iscsi-coverage.pcap'), frames)
write_pcap(os.path.join(out, 'iscsi-coverage-malformed.pcap'), mal)
print(len(frames), len(mal))
