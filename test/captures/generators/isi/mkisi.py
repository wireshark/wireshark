#!/usr/bin/env python3
# Generates test/captures/isi_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the ISI (Nokia Intelligent
Service Interface / Phonet) dissector (packet-isi.c).

ISI is reached by default as the "sll.ltype" 0x00F5 (Linux cooked capture,
link type 113, protocol 0x00F5).  Resource 0x02 (SMS), 0x06 (Subscriber
Services), 0x08 (SIM Authentication), 0x09 (SIM), 0x0A (Network), 0x32
(General Stack Server) and 0x54 (GPS) have their own message dissectors;
other resources are shown as data.  Every packet is built with struct;
SIM PINs are placeholders.

Usage: mkisi.py <output directory>

Writes:
  isi-coverage.pcap            every message type of every resource, every
                               branch of the subpacket loops, the broken
                               length subpackets fixed on the branch
  isi-coverage-malformed.pcap  too short messages, length larger than the
                               frame, subpackets that run past the data
  isi-coverage-usb.pcap        ISI in USB bulk transfers (heuristic dissector,
                               disabled by default; used by runcov.sh only)
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import struct
from netlib import write_pcap

def sll(payload, proto=0x00F5, ptype=0):
    return struct.pack('>HHH8sH', ptype, 0x0337, 6, b'\x02\x00\x00\x00\x00\x01\x00\x00', proto) + payload

def isi(res, content, rdev=0x6c, sdev=0x00, robj=0, sobj=0, mid=0, length=None):
    if length is None:
        length = len(content) + 3
    return struct.pack('>BBBHBBB', rdev, sdev, res, length, robj, sobj, mid) + content

frames = []
def add(res, content, **kw):
    frames.append(sll(isi(res, content, **kw)))

# ------------------------------------------------------------ SIM Authentication (0x08)
PIN = b'0000\0\0\0\0\0\0\0'   # 11 octet placeholder
PUK = b'11111111\0\0\0'
NEWPIN = b'2222\0\0\0\0\0\0\0'
SA = 0x08
add(SA, bytes([0x01, 0x00, 0x00]) + b'0000\0')                        # protected req: disable
add(SA, bytes([0x01, 0x00, 0x01]) + b'0000\0')                        # enable
add(SA, bytes([0x01, 0x00, 0x04]))                                    # status
add(SA, bytes([0x01, 0x00, 0x09]))                                    # unknown
add(SA, bytes([0x02, 0x01]), sdev=0x00)                               # protected resp enabled
add(SA, bytes([0x02, 0x00]))                                          # disabled
add(SA, bytes([0x04, 0x02]) + PIN + NEWPIN)                           # update PIN
add(SA, bytes([0x04, 0x03]))                                          # update PUK
add(SA, bytes([0x04, 0x09]))
add(SA, bytes([0x05]))
add(SA, bytes([0x06]))
add(SA, bytes([0x07, 0x02]) + PIN)                                    # auth with PIN
add(SA, bytes([0x07, 0x03]) + PUK + NEWPIN)                           # auth with PUK
add(SA, bytes([0x07, 0x09]))
add(SA, bytes([0x08]))
add(SA, bytes([0x09]))
for code in (1, 2, 3, 4, 5, 6, 9):                                    # status indication
    add(SA, bytes([0x10, code, 0x02, 0x01]))
add(SA, bytes([0x11]))
for code in (2, 3, 5, 7, 9):
    add(SA, bytes([0x12, code]))
add(SA, bytes([0x55]))                                                # unknown

# ------------------------------------------------------------ SIM (0x09)
SM = 0x09
add(SM, bytes([0x19, 0x2F]))
add(SM, bytes([0x19, 0x00]))
add(SM, bytes([0x1A, 0x2F, 0x00, 0x32, 0xf4, 0x10]))                  # home PLMN (MCC 234 MNC 10)
add(SM, bytes([0x1A, 0x00, 0x00, 0x00, 0x00, 0x00]))
add(SM, bytes([0x1D, 0x01]))
add(SM, bytes([0x1E, 0x01, 0x00, 0x08, 0x29, 0x43, 0x01, 0x70, 0x33, 0x65, 0x49, 0x32]))
add(SM, bytes([0x21, 0x01]))
add(SM, bytes([0x22, 0x2c, 0x05]))
add(SM, bytes([0x22, 0x00, 0x00]))
add(SM, bytes([0xBA, 0x66]))
add(SM, bytes([0xBA, 0x01]))
add(SM, bytes([0xBB, 0x66, 0x00]))
add(SM, bytes([0xBB, 0x01, 0x00]))
add(SM, bytes([0xBC, 0x01]))
add(SM, bytes([0xBD, 0x01]))
pb = bytes([0xDC, 0x01, 0x01, 0x00, 0x07, 0, 0x08, 0x00, 0x02, 0x00, 0x05, 0, 0x09, 0x00, 0x03, 0x04, 0, 0, 0x02, 0, 0x01, 0, 0x02, 0, 0x03])
add(SM, pb)
add(SM, bytes([0xDD, 0x01]))
add(SM, bytes([0xEF, 0x01]))
add(SM, bytes([0xF0, 0x00, 0x01]))
add(SM, bytes([0xF0, 0x12, 0x01]))
add(SM, bytes([0xF0, 0x33, 0x01]))
add(SM, bytes([0x99]))

# ------------------------------------------------------------ General Stack Server (0x32)
GS = 0x32
add(GS, bytes([0x00, 0x0E]))
add(GS, bytes([0x00, 0x9C, 0x01]))
add(GS, bytes([0x00, 0x01]))
add(GS, bytes([0x01, 0x9C]))
add(GS, bytes([0x02, 0x9C, 0x01]))
add(GS, bytes([0x02, 0x01, 0x01]))
for c in (0x01, 0x12, 0x13, 0x14, 0x55):
    add(GS, bytes([0xF0, c]))
add(GS, bytes([0x77]))

# ------------------------------------------------------------ GPS (0x54)
GP = 0x54
add(GP, bytes([0x7d, 0, 0x00]))
add(GP, bytes([0x7d, 0, 0x01]))
add(GP, bytes([0x7d, 0, 0x77]))
for c in (0x84, 0x85, 0x8b):
    add(GP, bytes([c, 0]))
add(GP, bytes([0x90]))
add(GP, bytes([0x91]))
add(GP, bytes([0x33]))

def gps_data(subs):
    """subs: list of (type, data); splen = len(data) + 4."""
    c = bytearray(0x0b)
    c[0] = 0x92
    c[7] = len(subs)
    for t, d in subs:
        c += bytes([0, t, 0, len(d) + 4]) + d
    return bytes(c)

pos = struct.pack('>IIIIHHHH', 0x1000000, 0xF0000000, 0, 1234, 0, 600, 100, 40)
dt = struct.pack('>HBBBBBBH', 2026, 11, 6, 0, 12, 30, 0, 45123)
mv = struct.pack('>HHHHHHH', 18000, 250, 0, 500, 100, 20, 40)
sats = bytes([3, 0, 0, 0]) + b''.join(struct.pack('>BBBHHHHH', 0, 10 + i, i & 1, 4000 + i, 0, 0, 4500, 18000)[:12] for i in range(3))
gsm = struct.pack('>HHHH', 234, 10, 0x1234, 0x5678)
wcdma = struct.pack('>HHI', 234, 10, 0x01234567)
add(GP, gps_data([(0x02, pos), (0x03, dt), (0x04, mv), (0x05, sats), (0x07, gsm), (0x08, wcdma), (0x09, b'\0' * 4)]))
add(GP, gps_data([(0x05, bytes([0, 0, 0, 0]))]))                      # no satellites
add(GP, gps_data([]))                                                 # no subpackets
# reproducer of the fix: subpacket length shorter than the subpacket header
for bad in (0, 1, 3):
    c = bytearray(0x0b); c[0] = 0x92; c[7] = 255
    c += bytes([0, 5, 0, bad]) + bytes(40)
    add(GP, bytes(c))

# ------------------------------------------------------------ Subscriber Services (0x06)
SS = 0x06
add(SS, bytes([0x00, 0x01, 0x05]))
add(SS, bytes([0x00, 0x01, 0x06]))
add(SS, bytes([0x00, 0x01, 0x77]))
add(SS, bytes([0x01, 0x01, 0x05]))
add(SS, bytes([0x01, 0x01, 0x77]))
add(SS, bytes([0x02, 0x01]))
add(SS, bytes([0x04, 0x02, 0x01, 0x01]))                              # USSD command
add(SS, bytes([0x04, 0x01, 0x01, 0x01]))
add(SS, bytes([0x05, 0x01]))
add(SS, bytes([0x06, 0x04, 0x0f, 0x03]) + b'abc')
add(SS, bytes([0x06, 0x01, 0x0f, 0x03]) + b'abc')
for code in (0, 1, 2, 3, 9):
    add(SS, bytes([0x09, code, 0x01, 0x01]))
add(SS, bytes([0x10, 0x01, 0x05]))
add(SS, bytes([0x10, 0x01, 0x77]))
for c in (0x01, 0x12, 0x13, 0x14, 0x55):
    add(SS, bytes([0xF0, c]))
add(SS, bytes([0x88]))

# ------------------------------------------------------------ Network (0x0A)
NW = 0x0A
add(NW, bytes([0x07, 0, 0]))
add(NW, bytes([0x20, 0, 0]))
add(NW, bytes([0x99, 0, 0]))
def netstatus(subs):
    c = bytearray([0xE2, 0, len(subs)])
    for t, d in subs:
        c += bytes([t, len(d) + 2]) + d
    return bytes(c)
msg = 'Test Net'.encode('utf-16-be')
add(NW, netstatus([(0x00, b'\0' * 4), (0x09, struct.pack('>HHI', 0x1234, 0, 0x5678)), (0xe3, bytes([0, 0]) + struct.pack('>H', 8) + msg), (0x55, b'\0' * 3)]))
add(NW, netstatus([]))
def cellinfo(subs):
    c = bytearray([0x42, 0, len(subs)])
    for t, d in subs:
        c += bytes([t, len(d) + 2]) + d
    return bytes(c)
cell = struct.pack('>HIIB', 0x1234, 0x5678, 0x0001000d, 0x00) + b'\x00\x62\xf2' + b'\0' * 5
add(NW, cellinfo([(0x46, cell), (0x46, struct.pack('>HIIBBBB', 1, 2, 0, 0, 0, 0, 0) + b'\0' * 8), (0x50, b'\0' * 6), (0x47, b'\0' * 6), (0x77, b'\0' * 4)]))
add(NW, cellinfo([(0x46, struct.pack('>HII', 1, 2, 0x0f) + b'\x00\x01\x02\x03' + b'\0' * 6)]))     # all GSM bands set
# reproducers of the fix: subpacket length below the 2 octet subpacket header
for sp in (0, 1):
    add(NW, bytes([0xE2, 0, 255, 0x09, sp]) + bytes(40))
    add(NW, bytes([0x42, 0, 255, 0x46, sp]) + bytes(40))

# ------------------------------------------------------------ SMS (0x02)
SMS = 0x02
add(SMS, bytes([0x03, 0x00, 0x01]))
add(SMS, bytes([0x06, 0x01, 0x01]))
add(SMS, bytes([0x07, 0x01]))
add(SMS, bytes([0x0B, 0x00, 0x01]))
add(SMS, bytes([0x0B, 0x01, 0x01]))
add(SMS, bytes([0x0B, 0x02, 0x01]))
add(SMS, bytes([0x0C, 0x01]))
add(SMS, bytes([0x22, 0x02, 0x00, 0x01]))
add(SMS, bytes([0x22, 0x03, 0x00, 0x01]))
add(SMS, bytes([0x22, 0x09, 0x00, 0x01]))
for c in (0x01, 0x12, 0x13, 0x14, 0x55):
    add(SMS, bytes([0xF0, c]))
add(SMS, bytes([0x66]))

# ------------------------------------------------------------ other resources and header variants
add(0x01, b'\x01\x02\x03')                                            # Call: no sub dissector
add(0x1B, b'\x01\x02\x03', rdev=0x00, sdev=0x6c)                      # Phone information, modem as destination
add(0x10, b'\x01', rdev=0xff, sdev=0xff)                              # Indication, device "Any"
add(0x77, b'\x01', rdev=0x42, sdev=0x43)                              # unknown devices and resource
add(0x09, bytes([0x19, 0x2F]), rdev=0x00, sdev=0x6c, robj=1, sobj=2, mid=3)
# a frame with trailing padding behind the ISI message (the length field is respected)
frames.append(sll(isi(SM, bytes([0x19, 0x2F])) + b'\0\0\0\0'))

# ------------------------------------------------------------ malformed
mal = []
def addm(raw, **kw):
    mal.append(sll(raw, **kw))
addm(isi(SM, bytes([0x19, 0x2F]), length=100))                        # length larger than the frame
addm(isi(SM, b'', length=3))                                          # empty content
addm(isi(GP, bytes([0x92]) + bytes(6)))                               # GPS data cut before the package count
addm(isi(GP, gps_data([(0x02, pos)])[:0x0b + 4 + 10]))                # position subpacket cut
addm(isi(GP, gps_data([(0x03, dt)])[:0x0b + 4 + 4]))
addm(isi(GP, gps_data([(0x04, mv)])[:0x0b + 4 + 4]))
addm(isi(GP, gps_data([(0x05, sats)])[:0x0b + 4 + 14]))
addm(isi(GP, gps_data([(0x07, gsm)])[:0x0b + 4 + 3]))
addm(isi(GP, gps_data([(0x08, wcdma)])[:0x0b + 4 + 3]))
addm(isi(GP, bytes([0x92]) + bytes(6) + bytes([5]) + bytes([0, 0, 0, 0]) + bytes([0, 2, 0, 8])))   # second subpacket missing
addm(isi(GP, bytes([0x7d])))                                          # status without the status octet
addm(isi(NW, netstatus([(0x09, b'\0' * 8)])[:3 + 2 + 3]))
addm(isi(NW, netstatus([(0xe3, bytes([0, 0]) + struct.pack('>H', 500) + msg)])))   # message longer than the data
addm(isi(NW, cellinfo([(0x46, cell)])[:3 + 2 + 5]))
addm(isi(NW, bytes([0xE2, 0, 3])))                                    # subpackets missing
addm(isi(NW, bytes([0x42, 0, 3])))
addm(isi(SA, bytes([0x01, 0x00])))
addm(isi(SA, bytes([0x04, 0x02]) + PIN[:5]))
addm(isi(SA, bytes([0x07, 0x03]) + PUK[:5]))
addm(isi(SA, bytes([0x10, 0x06, 0x02])))
addm(isi(SM, pb[:12]))
addm(isi(SM, bytes([0x1A, 0x2F])))
addm(isi(SM, bytes([0x1E, 0x01])))
addm(isi(SS, bytes([0x04, 0x02, 0x01])))
addm(isi(SS, bytes([0x06, 0x04])))
addm(isi(SMS, bytes([0x22, 0x02])))
addm(isi(GS, bytes([0x00, 0x9C])))
addm(isi(GS, bytes([0x02])))
addm(b'\x00\x6c\x09')                                                 # shorter than the header
None

# ------------------------------------------------------------ USB bulk (ISI behind a 0x1B byte)
def usb_frame(payload, ep=0x81):
    # Linux usbmon (mmapped, 64 octet header): URB type 'C', transfer type 3 (bulk), endpoint, device 1, bus 1
    h = struct.pack('<QBBBBHBBqiIIiIIII', 1, ord('C'), 3, ep, 1, 1, 0, 0, 0, 0, len(payload), len(payload), 0, 0, 0, 0, 0)[:48]
    h += struct.pack('<iiII', 0, 0, 0, 0)
    return h[:64].ljust(64, b'\0') + payload

usb = []
for res, content in ((SM, bytes([0x19, 0x2F])), (GP, bytes([0x90])), (NW, bytes([0x07, 0, 0]))):
    usb.append(usb_frame(b'\x1b' + isi(res, content)))
usb.append(usb_frame(b'\x1c' + isi(SM, bytes([0x19, 0x2F]))))         # not ISI (first octet is not 0x1B)
usb.append(usb_frame(b'\x1b' + isi(SM, bytes([0x19, 0x2F])), ep=0x02))

out = sys.argv[1] if len(sys.argv) > 1 else '.'
write_pcap(os.path.join(out, 'isi-coverage.pcap'), frames, 113)
write_pcap(os.path.join(out, 'isi-coverage-malformed.pcap'), mal, 113)
write_pcap(os.path.join(out, 'isi-coverage-usb.pcap'), usb, 220)
print(len(frames), len(mal), len(usb))
