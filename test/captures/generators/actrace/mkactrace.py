#!/usr/bin/env python3
# ACtrace coverage capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""AudioCodes trunk trace (packet-actrace.c) on UDP port 2428: CAS state
machine records (48 octets) and ISDN records that carry a LAPD frame.

Usage: mkactrace.py [<output directory>]

Writes:
  actrace-coverage.pcap            CAS records of the three sources with the
                                   events and functions the dissector labels,
                                   ISDN records in both directions with LAPD
                                   and Q.931, payloads the heuristic rejects,
                                   and the negative ISDN length reproducer
  actrace-coverage-malformed.pcap  ISDN records whose LAPD payload is cut or
                                   whose length field is larger than the data

Port 2428 is the default for the dissector, no Decode As is needed.

Every packet is built here; nothing comes from a real network.
"""

import os
import struct
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))

from capgen import eth, ipv4, udp, write_pcap  # noqa: E402

PSTN_TO_BLADE = 0x49446463
BLADE_TO_PSTN = 0x49644443

SRC_DSP, SRC_USER, SRC_TABLE = 0, 1, 2

# Event numbers
EV_CAS = {11: 17, 10: 18, 1: 19, 0: 20}
EV_DTMF, EV_FIRST_DIGIT = 302, 63

# Functions
F_NILL, F_SET_TIMER, F_SEND_CAS, F_SEND_EVENT, F_SEND_DEST_NUM = 0, 1, 2, 3, 4
F_SEND_MF, F_CHANGE_COLLECT_TYPE = 8, 13

frames = []


def udp_frame(payload, sport=2428, dport=2428):
    seg = udp(payload, sport, dport)
    return eth(ipv4(seg, 17), 0x0800)


def cas(source, event, function, par0=0, par1=0, par2=0, cur=1, nxt=2, trunk=0,
        bchannel=1, conn=100, t=1000):
    return struct.pack('>12i', t, source, cur, event, nxt, function, par0, par1, par2,
                       trunk, bchannel, conn)


def lapd(sapi, tei, ctrl, info=b'', cr=0):
    return bytes([(sapi << 2) | (cr << 1), (tei << 1) | 1]) + ctrl + info


def q931(msg, ies=b'', callref=1, from_origin=True):
    cref = bytes([1, callref | (0 if from_origin else 0x80)])
    return bytes([0x08]) + cref + bytes([msg]) + ies


def isdn(direction, trunk, lapd_bytes, length=None):
    p = struct.pack('>I', 12345)
    p += struct.pack('>I', direction)
    p += struct.pack('>HH', trunk, 0)
    p += b'\0' * 32
    p += struct.pack('>H', len(lapd_bytes) if length is None else length)
    return p + lapd_bytes


def add(payload):
    frames.append(udp_frame(payload))


# ---------------------------------------------------------------- CAS
# DSP source: A/B bit events
for bits in (11, 10, 1, 0):
    add(cas(SRC_DSP, EV_CAS[bits], F_NILL, trunk=1, bchannel=2))
# event in the value table but not an AB/MF/DTMF one (no frame label)
add(cas(SRC_DSP, 21, F_NILL))
# MF tones: first, last, and the neighbours that are not a tone
for ev in (32, 33, 40, 45, 46, 31, 47):
    add(cas(SRC_DSP, ev, F_NILL, trunk=2, bchannel=7))
# DTMF digits
add(cas(SRC_DSP, EV_DTMF, F_NILL, par0=5))
add(cas(SRC_DSP, EV_FIRST_DIGIT, F_NILL, par0=9))
# an event number that is not in the table
add(cas(SRC_DSP, 999, F_NILL))

# User source
add(cas(SRC_USER, 100, F_SET_TIMER, par0=3, par1=500, par2=1, cur=0, nxt=1))
add(cas(SRC_USER, 4, 5, par0=1))                  # DEL_TIMER, generic parameters
# SEND_EVENT: par0 is a PSTN event, par1 a cause
add(cas(SRC_USER, 103, F_SEND_EVENT, par0=66, par1=16))
add(cas(SRC_USER, 103, F_SEND_EVENT, par0=128, par1=17))
add(cas(SRC_USER, 103, F_SEND_EVENT, par0=300, par1=999))   # unknown values
add(cas(SRC_USER, 103, F_SEND_EVENT, par0=71, par1=260))
# CHANGE_COLLECT_TYPE
for v in (0, 1, 3, 9):
    add(cas(SRC_USER, 111, F_CHANGE_COLLECT_TYPE, par0=v))
# SEND_MF / SEND_DEST_NUM from the user: par0 is a send type but no label
add(cas(SRC_USER, 111, F_SEND_MF, par0=1, par1=4))
add(cas(SRC_USER, 111, F_SEND_DEST_NUM, par0=4, par1=1))
add(cas(SRC_USER, 111, F_SEND_DEST_NUM, par0=0))
add(cas(SRC_USER, 112, 14, par0=2))               # GENERATE_CAS_EV
add(cas(SRC_USER, 114, 77, par0=2))               # unknown function

# Table source
for p0, p1 in ((2, 7), (1, 0), (4, 0), (5, 0), (6, 0), (3, 0), (9, 0)):
    add(cas(SRC_TABLE, 104, F_SEND_MF, par0=p0, par1=p1, trunk=3, bchannel=4))
for p0 in (3, 2, 1, 0, 5):                        # label from 20 - par0
    add(cas(SRC_TABLE, 104, F_SEND_CAS, par0=p0))
add(cas(SRC_TABLE, 104, F_SEND_CAS, par0=-2147483647 - 1))   # signed overflow
add(cas(SRC_TABLE, 104, F_SEND_CAS, par0=2147483647))
for p0 in (1, 4, 3):
    add(cas(SRC_TABLE, 104, F_SEND_DEST_NUM, par0=p0))
add(cas(SRC_TABLE, 104, F_SET_TIMER, par0=1, par1=2, par2=3))
add(cas(SRC_TABLE, 104, F_SEND_EVENT, par0=70, par1=31))

# Payloads the heuristic does not accept: they are shown as plain UDP
add(cas(3, 100, F_NILL))                          # source 3
add(cas(-1, 100, F_NILL))                         # source -1
add(cas(0, 100, F_NILL) + b'\0')                  # 49 octets, no direction
add(b'\x00\x01\x02')                              # shorter than 8 octets
add(b'')                                          # empty

# ---------------------------------------------------------------- ISDN
setup = q931(0x05, bytes([0x04, 3, 0x80, 0x90, 0xa3, 0x6c, 4, 0x21, 0x80, 0x31, 0x32,
                          0x70, 4, 0x81, 0x35, 0x36, 0x37]))
alerting = q931(0x01, bytes([0x18, 3, 0xa9, 0x83, 0x81]), from_origin=False)
connect = q931(0x07, b'', from_origin=False)
disc = q931(0x45, bytes([0x08, 2, 0x80, 0x90]))
release = q931(0x4d)
rel_comp = q931(0x5a, bytes([0x08, 2, 0x82, 0x90]), from_origin=False)

add(isdn(PSTN_TO_BLADE, 1, lapd(0, 0, bytes([0x00, 0x00]), setup)))
add(isdn(BLADE_TO_PSTN, 1, lapd(0, 0, bytes([0x00, 0x02]), alerting, cr=1)))
add(isdn(BLADE_TO_PSTN, 1, lapd(0, 0, bytes([0x02, 0x02]), connect, cr=1)))
add(isdn(PSTN_TO_BLADE, 1, lapd(0, 0, bytes([0x02, 0x04]), disc)))
add(isdn(BLADE_TO_PSTN, 2, lapd(0, 0, bytes([0x04, 0x04]), release, cr=1)))
add(isdn(PSTN_TO_BLADE, 2, lapd(0, 0, bytes([0x04, 0x06]), rel_comp)))
# Supervisory frames of 4 octets: no tap, no Q.931
add(isdn(PSTN_TO_BLADE, 1, lapd(0, 0, bytes([0x01, 0x04]))))
add(isdn(BLADE_TO_PSTN, 1, lapd(0, 0, bytes([0x01, 0x06]), cr=1)))
# Unnumbered frames
add(isdn(PSTN_TO_BLADE, 3, lapd(0, 0, bytes([0x03]), q931(0x02, b'\x18\x03\xa9\x83\x81'))))   # UI
add(isdn(BLADE_TO_PSTN, 3, lapd(0, 0, bytes([0x7f]), b'\x0a\x0b\x0c\x0d', cr=1)))  # SABME
# Reproducer of the signed length: the length field 0xFFFF (-1 when signed)
# and 0x8000 were passed on as a 4 GiB reported length. The LAPD frame is a
# supervisory frame, so the large reported length does not make it throw.
rr = lapd(0, 0, bytes([0x01, 0x04]))
add(isdn(PSTN_TO_BLADE, 5, rr, length=0xFFFF))
add(isdn(PSTN_TO_BLADE, 5, rr, length=0x8000))
rep = bytes([0x02, 0x01, 0x00, 0x00, 0x08, 0x01, 0x01, 0x05, 0x04, 0x03, 0x80, 0x90, 0xa3])
add(isdn(PSTN_TO_BLADE, 0, rep))
add(isdn(PSTN_TO_BLADE, 0, rep, length=len(rep)))

main_frames = list(frames)
del frames[:]

# ---------------------------------------------------------------- malformed
add(isdn(PSTN_TO_BLADE, 0, rep, length=0xFFFF))
add(isdn(PSTN_TO_BLADE, 0, rep, length=0x8000))
add(isdn(BLADE_TO_PSTN, 0, rep, length=40))
add(isdn(PSTN_TO_BLADE, 4, lapd(0, 0, bytes([0x00, 0x00]), setup[:5])[:6] + b'\0\0', length=8))
add(isdn(PSTN_TO_BLADE, 4, b'\x00\x01\x00\x00\x08\x01\x01\x05\x04\x40\x80'))   # IE overruns
# a CAS record cut short in the capture but 48 octets reported
cut = cas(SRC_DSP, 17, F_NILL)
frames.append((udp_frame(cut)[:-20], len(udp_frame(cut))))
malformed_frames = list(frames)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    os.makedirs(out, exist_ok=True)
    write_pcap(os.path.join(out, 'actrace-coverage.pcap'), main_frames)
    write_pcap(os.path.join(out, 'actrace-coverage-malformed.pcap'), malformed_frames)


if __name__ == '__main__':
    main()
