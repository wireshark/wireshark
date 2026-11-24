#!/usr/bin/env python3
# Generates test/captures/netbios_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic NetBIOS Frame Protocol (NBF) over 802.2 LLC captures.
# Usage: mknetbios.py <outdir> [-v]
import struct
import sys
import os

def pcap(fn, pkts):
    with open(fn, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, p in enumerate(pkts):
            if isinstance(p, tuple):
                data, orig = p
            else:
                data, orig = p, len(p)
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(data), orig))
            f.write(data)

def name(s, typ):
    return s.encode('latin1').ljust(15, b' ')[:15] + bytes([typ])

def hdr(cmd, d1=0, d2=0, ct=None, xc=0, rc=0, rmt=0, loc=0, rname=None, sname=None,
        length=None):
    """44 octet name header or 14 octet session header (the call name type
    shares the high octet of DATA2)."""
    b = bytearray(14)
    b[0:2] = struct.pack('<H', length or (14 if rname is None and sname is None else 44))
    b[2:4] = b'\xff\xef'
    b[4] = cmd
    b[5] = d1
    b[6:8] = struct.pack('<H', d2)
    if ct is not None:
        b[7] = ct
    b[8:10] = struct.pack('<H', xc)
    b[10:12] = struct.pack('<H', rc)
    b[12] = rmt
    b[13] = loc
    if rname is None and sname is None:
        return bytes(b)
    b = b[:12]
    b += rname if rname is not None else bytes(16)
    b += sname if sname is not None else bytes(16)
    return bytes(b)

def eth(payload, extra=b''):
    llc = b'\xf0\xf0\x03' + extra + payload
    return (b'\x02\x00\x00\x00\x00\x01' + b'\x02\x00\x00\x00\x00\x02' +
            struct.pack('>H', len(llc)) + llc)

RN = name('RECEIVER', 0x20)
SN = name('SENDER', 0x00)
frames = []; marks = []
def add(p, label=None):
    frames.append(p)
    if label: marks.append((len(frames), label))
def nbf(cmd, label=None, extra=b'', data=b'', **kw):
    add(eth(hdr(cmd, **kw) + data, extra), label)

# 1-14: name service commands
nbf(0x00, 'Add Group Name Query', rc=0x1111, sname=name('GROUP', 0x1c), rname=bytes(16))
nbf(0x01, 'Add Name Query', rc=0x2222, sname=name('WORKSTN', 0x03), rname=bytes(16))
nbf(0x02, 'Name In Conflict', rname=name('CONFLICT', 0x00), sname=SN)
nbf(0x03, 'Status Query 1.x', d1=0, d2=0x1000, rc=0x33, rname=RN, sname=SN)
nbf(0x03, d1=1, d2=0x1000, rc=0x33, rname=RN, sname=SN)
nbf(0x03, d1=7, d2=0x1000, rc=0x33, rname=RN, sname=SN)
nbf(0x07, 'Terminate Trace', rname=RN, sname=SN)
nbf(0x13, 'Terminate Trace (LR)', rname=RN, sname=SN)
nbf(0x08, 'Datagram', rname=name('RECEIVER', 0x1d), sname=SN, data=b'datagram payload\x00')
# datagram with 10 zero octets + MAC in the sender name field
add(eth(hdr(0x08, rname=RN, sname=bytes(10) + b'\x02\x00\x00\x00\x00\x09') + b'mac sender'), 'Datagram, MAC sender')
nbf(0x09, 'Broadcast Datagram', rname=bytes(16), sname=name('BCAST', 0x1b), data=b'broadcast')
add(eth(hdr(0x09, rname=bytes(16), sname=bytes(10) + b'\x02\x00\x00\x00\x00\x09') + b'mac bcast'), 'Broadcast Datagram, MAC sender')
nbf(0x0a, 'Name Query FIND.NAME', d2=0, ct=1, rc=0x44, rname=name('FINDME', 0x20), sname=SN)
nbf(0x0a, 'Name Query session', d2=5, ct=2, rc=0x44, rname=name('QUERYME', 0x20), sname=SN)
# 15-: responses
nbf(0x0d, 'Add Name Response', d1=1, d2=0x0100, xc=0x2222, rname=name('NEWNAME', 0x03), sname=name('NEWNAME', 0x03))
nbf(0x0d, d1=0, d2=0x0001, xc=0x2222, rname=name('NEWNAME', 0x03), sname=name('NEWNAME', 0x03))
nbf(0x0e, 'Name Recognized, no listen', d2=0x00, ct=1, xc=0x55, rname=RN, sname=SN)
nbf(0x0e, 'Name Recognized, no resources', d2=0xff, ct=1, xc=0x55, rname=RN, sname=SN)
nbf(0x0e, 'Name Recognized, session', d2=0x07, ct=1, xc=0x55, rc=0x66, rname=RN, sname=SN)
nbf(0x0f, 'Status Response 1.x', d1=0, d2=0x8123, ct=1, xc=0x77, rname=RN, sname=SN)
nbf(0x0f, d1=9, d2=0x0000, ct=1, xc=0x77, rname=RN, sname=SN)
# name with non-printable characters, trailing spaces, unknown name types
nbf(0x01, 'Name with control octets', rc=1, sname=b'\x01AB\xff \x7fZ         ' [:15] + b'\x77', rname=bytes(16))
nbf(0x01, 'Name type 0xbe', rc=1, sname=name('MONITOR', 0xbe), rname=bytes(16))
# all known name types
for t in (0x01, 0x02, 0x05, 0x06, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x2b,
          0x30, 0x31, 0x43, 0x44, 0x45, 0x46, 0x4c, 0x52, 0x6a, 0x87, 0xbf):
    nbf(0x01, rc=t, sname=name('TYPE%02X' % t, t), rname=bytes(16))
# session service
nbf(0x14, 'Data Ack', xc=0x10, rmt=1, loc=2)
nbf(0x17, 'Session Confirm 2.00', d1=0x80, d2=1500, xc=1, rc=2, rmt=1, loc=2)
nbf(0x17, 'Session Confirm 1.xx, no ack', d1=0x01, d2=516, xc=1, rc=2, rmt=1, loc=2)
nbf(0x18, 'Session End normal', d2=0, rmt=1, loc=2)
nbf(0x18, 'Session End abnormal', d2=1, rmt=1, loc=2)
nbf(0x19, 'Session Initialize', d1=0x81, d2=1500, xc=3, rc=4, rmt=1, loc=2)
nbf(0x19, d1=0x07, d2=0, xc=3, rc=4, rmt=1, loc=2)
for fs in range(8):
    nbf(0x19, d1=(fs << 1) | 0x80, d2=0, xc=3, rc=4, rmt=1, loc=2)
nbf(0x1a, 'No Receive', d1=0x01, d2=100, rmt=1, loc=2)
nbf(0x1a, d1=0x00, d2=0, rmt=1, loc=2)
nbf(0x1b, 'Receive Outstanding', d2=1000, rmt=1, loc=2)
nbf(0x1c, 'Receive Continue', xc=5, rmt=1, loc=2)
nbf(0x1f, 'Session Alive', rmt=1, loc=2)
# data frames with all flag/resync variants (resync 0, 1, other)
nbf(0x16, 'Data Only Last', d1=0x07, d2=0, xc=1, rc=2, rmt=1, loc=2, data=b'only last, no resync')
nbf(0x16, d1=0x00, d2=1, xc=1, rc=2, rmt=1, loc=2, data=b'only last, first after Receive Outstanding')
nbf(0x16, d1=0x01, d2=0x1234, xc=1, rc=2, rmt=1, loc=2, data=b'only last, other resync')
nbf(0x15, 'Data First Middle alone', d1=0x01, d2=0, xc=1, rc=2, rmt=9, loc=9, data=b'first alone')
nbf(0x15, d1=0x06, d2=1, xc=1, rc=2, rmt=9, loc=9, data=b'first alone, resync 1')
nbf(0x15, d1=0x00, d2=2, xc=1, rc=2, rmt=9, loc=9, data=b'first alone, resync 2')
# reassembly: session (1,2): first, middle, last
nbf(0x15, 'Reassembly start', d1=0x00, d2=0, xc=1, rc=2, rmt=1, loc=2, data=b'A' * 40)
nbf(0x15, d1=0x00, d2=0, xc=1, rc=2, rmt=1, loc=2, data=b'B' * 40)
nbf(0x16, 'Reassembly end', d1=0x00, d2=0, xc=1, rc=2, rmt=1, loc=2, data=b'C' * 20)
# interleaved second session (3,4) and a session reusing (1,2) afterwards
nbf(0x15, d1=0x00, xc=1, rc=2, rmt=3, loc=4, data=b'D' * 30)
nbf(0x15, d1=0x00, xc=1, rc=2, rmt=1, loc=2, data=b'E' * 30)
nbf(0x16, d1=0x00, xc=1, rc=2, rmt=3, loc=4, data=b'F' * 10)
nbf(0x16, d1=0x00, xc=1, rc=2, rmt=1, loc=2, data=b'G' * 10)
# SMB payload reached through the heuristic subdissector list
smbneg = (b'\xffSMB' + b'\x72' + b'\0' * 4 + b'\x18\x01\x28' + b'\0' * 12 + b'\0\0' + b'\x01\x00\x00\x00' + b'\x00\x00' +
          b'\x00\x0c\x00' + b'\x02NT LM 0.12\x00')
nbf(0x16, 'SMB over NetBIOS', d1=0x00, xc=1, rc=2, rmt=5, loc=6, data=smbneg)
# the extra LLC octet
nbf(0x08, 'Extra LLC octet', extra=b'\x00', rname=RN, sname=SN, data=b'extra llc octet')
nbf(0x1f, 'Extra LLC octet, Session Alive', extra=b'\x00', rmt=1, loc=2)
# commands the table does not name: 0x04-0x06, 0x0b, 0x0c, 0x10-0x12, 0x1d, 0x1e, 0x20, 0x21, > 0x21
for c in (0x04, 0x05, 0x06, 0x0b, 0x0c, 0x10, 0x11, 0x12, 0x1d, 0x1e, 0x20):
    nbf(c, 'Unknown 0x%02x' % c, rmt=1, loc=2, data=b'xx')
# the reproducers of "NetBIOS: Do not clamp the command"
for c in (0x21, 0x22, 0x40, 0xff):
    add(eth(struct.pack('<HHB', 44, 0xEFFF, c) + b'\0' * 7 + RN + SN), 'Unknown 0x%02x (clamp fix)' % c)
# header length variants
add(eth(hdr(0x1f, rmt=1, loc=2, length=14)), 'Session Alive, header length 14')

pcap(os.path.join(sys.argv[1], 'netbios-coverage.pcap'), frames)
if '-v' in sys.argv:
    for n, l in marks: print(n, l)
    print(len(frames), 'frames')

# malformed / odd
mal = []
mal.append(b'\x02\x00\x00\x00\x00\x01' + b'\x02\x00\x00\x00\x00\x02' + struct.pack('>H', 11) + b'\xf0\xf0\x03' + b'\x2c\x00\x00\x00\x08\x00\x00\x00')  # no marker (2 and 3)
mal.append(eth(b'\x2c\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00'))  # no marker, long enough
mal.append(eth(hdr(0x08, rname=RN, sname=SN)[:20]))  # truncated name header
mal.append(eth(hdr(0x1f, rmt=1, loc=2)[:10]))  # truncated session header
mal.append(eth(struct.pack('<HHB', 44, 0xEFFF, 0x99)))  # unknown command, no data
# frames cut by the capture length: payload not present in the capture
full = eth(hdr(0x16, d1=0, xc=1, rc=2, rmt=1, loc=2) + b'Z' * 100)
mal.append((full[:14 + 3 + 14 + 10], len(full)))
full = eth(hdr(0x15, d1=0, xc=1, rc=2, rmt=1, loc=2) + b'Z' * 100)
mal.append((full[:14 + 3 + 14 + 10], len(full)))
full = eth(hdr(0x08, rname=RN, sname=SN) + b'Z' * 100)
mal.append((full[:14 + 3 + 44 + 10], len(full)))
# fragments which overlap: same session sends first, then a last, then a stray last
mal.append(eth(hdr(0x15, rmt=7, loc=7) + b'a' * 10))
mal.append(eth(hdr(0x15, rmt=7, loc=7) + b'b' * 10))
mal.append(eth(hdr(0x16, rmt=7, loc=7) + b'c' * 10))
mal.append(eth(hdr(0x16, rmt=7, loc=7) + b'd' * 10))
mal.append(eth(hdr(0x16, rmt=8, loc=8) + b''))
mal.append(eth(hdr(0x15, rmt=8, loc=8) + b''))
mal.append(eth(hdr(0x16, rmt=8, loc=8) + b''))
mal.append(eth(hdr(0x16, rmt=9, loc=9, length=2000) + b'zz'))  # header length beyond the frame
mal.append(eth(hdr(0x08, rname=RN, sname=SN, length=9000) + b'zz'))
pcap(os.path.join(sys.argv[1], 'netbios-coverage-malformed.pcap'), mal)
