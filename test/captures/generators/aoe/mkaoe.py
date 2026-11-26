#!/usr/bin/env python3
# ATA over Ethernet (AoE) coverage capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""AoE (packet-aoe.c, ethertype 0x88a2): an initiator and two targets
exchange ATA commands and responses and query the configuration. Every
packet is built with struct; nothing comes from a real network.

Usage: mkaoe.py [<output directory>]
writes aoe-coverage.pcap and aoe-coverage-malformed.pcap
"""
import os
import struct
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))
import capgen  # noqa: E402

ETHERTYPE_AOE = 0x88a2
INIT = bytes.fromhex('02 00 00 00 00 01')     # initiator
TGT1 = bytes.fromhex('02 00 00 00 00 11')     # target shelf 1
TGT2 = bytes.fromhex('02 00 00 00 00 12')     # target shelf 2
BCAST = b'\xff' * 6

F_RESP = 0x08
F_ERR = 0x04
AF_E = 0x40
AF_D = 0x10
AF_A = 0x02
AF_W = 0x01

# All ATA command codes the dissector names
ATA_CMDS = (0x00, 0x08, 0x10, 0x20, 0x21, 0x22, 0x23, 0x24, 0x30, 0x31, 0x32, 0x33,
            0x34, 0x3c, 0x40, 0x41, 0x50, 0x70, 0x90, 0x91, 0x92, 0x94, 0x95, 0x96,
            0x97, 0x98, 0x99, 0xa0, 0xa1, 0xa2, 0xb0, 0xc4, 0xc5, 0xc6, 0xc8, 0xc9,
            0xca, 0xcb, 0xde, 0xdf, 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe8,
            0xec, 0xed, 0xee, 0xef, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6)

frames = []
times = []
clock = [0]


def add(dst, src, payload, dt=1000):
    """dt: microseconds since the previous frame"""
    clock[0] += dt
    pad = b'\0' * max(0, 46 - len(payload))
    frames.append(dst + src + struct.pack('>H', ETHERTYPE_AOE) + payload + pad)
    times.append(clock[0])


def hdr(flags, cmd, tag, major=1, minor=1, err=0, ver=1):
    return struct.pack(">BBHBB", (ver << 4) | flags, err, major, minor, cmd) + struct.pack("<I", tag)


def ata(aflags=0, feat=0, count=1, cmd=0xec, lba=0, data=b''):
    return struct.pack('<BBBB', aflags, feat, count, cmd) + \
        struct.pack('<Q', lba)[:6] + b'\0\0' + data


def request(tag, cmd, dst=TGT1, src=INIT, major=1, minor=1, dt=1000, **kw):
    add(dst, src, hdr(0, 0, tag, major, minor) + ata(cmd=cmd, **kw), dt)


def response(tag, status, dst=INIT, src=TGT1, major=1, minor=1, flags=0, err=0,
             dt=1000, **kw):
    kw.setdefault('feat', 0)
    add(dst, src, hdr(F_RESP | flags, 0, tag, major, minor, err) + ata(cmd=status, **kw), dt)


# ---- Section A: identify, reads, writes (frames 1-12) -----------------
request(0x00000001, 0xec)                                          # 1
response(0x00000001, 0x50, data=bytes(range(64)), dt=1500)         # 2
request(0x00000002, 0x24, aflags=AF_E | AF_D, count=2, lba=0x123456789a)  # 3
response(0x00000002, 0x50, aflags=AF_E | AF_D, count=2, lba=0x123456789a,
         data=b'\xa5' * 128, dt=2500)                              # 4
request(0x00000003, 0x34, aflags=AF_E | AF_W | AF_A, count=1, lba=0x0000000100,
        data=b'\x5a' * 64)                                         # 5
response(0x00000003, 0x50, aflags=AF_E | AF_W | AF_A, count=1, lba=0x100)  # 6
request(0x00000004, 0x20, aflags=AF_W, count=1, lba=0xffffffffffff)  # 7 W without E
response(0x00000004, 0x50, aflags=AF_W, count=1, lba=0xffffffffffff)  # 8
request(0x00000005, 0x30, aflags=AF_D, count=8, lba=1)             # 9 D without E
response(0x00000005, 0x51, feat=0x04, count=8, lba=1)              # 10 ata error
# Error response (flags E) for an ATA command: device unavailable
request(0x00000006, 0xc8, lba=7)                                   # 11
response(0x00000006, 0x00, flags=F_ERR, err=3, lba=7)              # 12

# ---- Section B: matching corner cases (frames 13-22) ------------------
response(0x00000063, 0x50)                                         # 13 no request
request(0x00000007, 0xe5)                                          # 14 never answered
# The same tag from another initiator/target pair is a different conversation
request(0x00000001, 0xec, dst=TGT2, src=INIT, major=2, minor=0)    # 15
response(0x00000001, 0x50, src=TGT2, major=2, minor=0)             # 16
# Duplicate request tag: the second replaces the first
request(0x00000008, 0xa1)                                          # 17
request(0x00000008, 0xe6)                                          # 18
response(0x00000008, 0x50)                                         # 19
response(0x00000008, 0x50)                                         # 20 second response: no match
# Unknown ATA command code, request and matched response
request(0x00000009, 0xff)                                          # 21
response(0x00000009, 0x50)                                         # 22

# ---- Section C: config query, errors, versions (frames 23-37) ---------
add(BCAST, INIT, hdr(0, 1, 0x10, 0xffff, 0xff) + struct.pack('>HHBBH', 0, 0, 0, 0, 0))  # 23 broadcast
cfg = b'aoe-config-string'
add(INIT, TGT1, hdr(F_RESP, 1, 0x10, 1, 1) +
    struct.pack('>HHBBH', 16, 1, 0x11, 0x10, len(cfg)) + cfg)      # 24
add(TGT1, INIT, hdr(0, 1, 0x11, 1, 1) + struct.pack('>HHBBH', 0, 0, 0, 0, 0))  # 25
add(INIT, TGT1, hdr(F_RESP | F_ERR, 1, 0x11, 1, 1, err=4))         # 26 config string present
add(INIT, TGT1, hdr(F_RESP | F_ERR, 0, 0x12, 1, 1, err=1))         # 27 unrecognized command
add(INIT, TGT1, hdr(F_RESP | F_ERR, 7, 0x13, 1, 1, err=2))         # 28 unknown cmd, bad arg
add(INIT, TGT1, hdr(F_RESP | F_ERR, 1, 0x14, 1, 1, err=5))         # 29 unsupported version
add(INIT, TGT1, hdr(F_RESP | F_ERR, 1, 0x15, 1, 1, err=9))         # 30 unknown error code
add(TGT1, INIT, hdr(0, 7, 0x16, 1, 1) + b'\0' * 12)                # 31 unknown command request
add(INIT, TGT1, hdr(F_RESP, 7, 0x16, 1, 1) + b'\0' * 12)           # 32 unknown command response
add(TGT1, INIT, hdr(0, 0, 0x17, 1, 1, ver=2) + ata())              # 33 version 2: only the version
add(TGT1, INIT, hdr(0, 0, 0x18, 1, 1, ver=0) + ata())              # 34 version 0
add(INIT, TGT1, hdr(F_RESP | F_ERR, 5, 0x19, 0, 0, err=5, ver=2) + b'')  # 35 version 2 error flag
add(TGT1, INIT, hdr(0xf & ~(F_RESP | F_ERR), 1, 0x1a, 1, 1) + b'\0' * 8)  # 36 reserved flag bits
add(INIT, TGT1, hdr(F_RESP | F_ERR | 0x03, 1, 0x1b, 3, 3, err=3) + b'\0' * 8)  # 37

# ---- Section D: every named ATA command (frames 38-95) ----------------
for i, c in enumerate(ATA_CMDS):
    request(0x100 + i, c, count=i & 0xff, lba=0x010203040506 + i)

# ---- Section E: responses to some of them, in a late burst ------------
for i, c in enumerate(ATA_CMDS):
    if i % 7 == 0:
        response(0x100 + i, 0x50, count=i & 0xff, lba=0x010203040506 + i)

n_clean = len(frames)
clean = (list(frames), list(times))


def write(name, fr, tm):
    capgen.write_pcap(os.path.join(outdir, name), fr,
                      ts=lambda i: (capgen.TS_BASE + tm[i] // 1000000, tm[i] % 1000000))


outdir = sys.argv[1] if len(sys.argv) > 1 else '.'
write('aoe-coverage.pcap', *clean)

# ---- Malformed capture: truncated PDUs --------------------------------
frames.clear()
times.clear()
clock[0] = 0
base = TGT1 + INIT + struct.pack('>H', ETHERTYPE_AOE)
for payload in (b'\x10',                                     # only the version byte
                hdr(0, 0, 1)[:3],                            # cut in the major address
                hdr(0, 0, 1)[:5],                            # cut before the command
                hdr(0, 0, 1)[:8],                            # cut in the tag
                hdr(0, 0, 1),                                # ATA PDU missing
                hdr(0, 0, 1) + b'\0\0\0',                    # cut in the ATA header
                hdr(F_RESP, 0, 1) + ata()[:9],               # cut in the LBA
                hdr(F_RESP | F_ERR, 0, 1, err=1)[:1]):       # error byte missing
    clock[0] += 1000
    frames.append(base + payload)
    times.append(clock[0])
write('aoe-coverage-malformed.pcap', frames, times)
print('aoe-coverage.pcap: %d frames' % n_clean)
