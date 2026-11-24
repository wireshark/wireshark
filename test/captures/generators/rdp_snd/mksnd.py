#!/usr/bin/env python3
# Generates test/captures/rdp_snd_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic RDP audio output channel ("rdpsnd") captures for packet-rdp_snd.c.
# Usage: mksnd.py <outdir> [-v]
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from rdplib import Cap, Session
from dvclib import create_req, data, data_first

OUT = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('-') else '.'
VERBOSE = '-v' in sys.argv


def snd(t, body=b'', pad=0):
    # bodySize is a 16 bit field, but the dissector reads 32 bits at offset 2
    # (bodySize and the first two body octets) and adds 4 to find the end:
    # keep the first two body octets zero so both readings agree
    return struct.pack('<BBH', t, pad, len(body)) + body


def build_main():
    cap = Cap()
    s = Session(cap, 50000, ['rdpsnd', 'drdynvc'])
    S = lambda p: s.chan('rdpsnd', p, False)
    C = lambda p: s.chan('rdpsnd', p, True)
    fmts = struct.pack('<IIIHHHH', 0, 0xffffffff, 0, 1, 0, 0, 0) + bytes(2) + b'\0' * 8
    S(snd(0x07, bytes(2) + bytes(20) + fmts))       # formats (server)
    C(snd(0x07, bytes(2) + bytes(20) + fmts))       # formats (client)
    S(snd(0x06, bytes(2) + struct.pack('<HH', 0x1234, 0)))   # training
    C(snd(0x06, bytes(2) + struct.pack('<HH', 0x1234, 0)))
    for t in (0x01, 0x02, 0x03, 0x04, 0x05, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x7f):
        S(snd(t, bytes(6)))
        C(snd(t, bytes(6)))
    S(snd(0x02, bytes(2) + bytes(100)))              # wave, larger
    s.chunks('rdpsnd', snd(0x02, bytes(2000)), size=700)     # reassembled wave
    # two PDUs in one channel PDU
    S(snd(0x06, bytes(2) + bytes(4)) + snd(0x01, bytes(2)))
    # over the dynamic channel (AUDIO_PLAYBACK_DVC)
    S2 = lambda p: s.chan('drdynvc', p, False)
    S2(create_req(5, 'AUDIO_PLAYBACK_DVC'))
    S2(data(5, snd(0x06, bytes(2) + bytes(4))))
    S2(data_first(5, 20, snd(0x02, bytes(2) + bytes(4))))
    S2(data(5, bytes(10)))
    cap.write(os.path.join(OUT, 'snd-coverage.pcapng'))
    if VERBOSE:
        print('snd-coverage.pcapng', len(cap.frames), 'frames')


def build_malformed():
    cap = Cap()
    s = Session(cap, 50000, ['rdpsnd'])
    s.chan('rdpsnd', b'\x06')                                   # cut short
    s.chan('rdpsnd', b'\x06\x00\x04')
    s.chan('rdpsnd', struct.pack('<BBHI', 0x02, 0, 0xffff, 0xffffffff))      # length that wraps (fix: wrapped pduLength)
    s.chan('rdpsnd', struct.pack('<BBI', 0x02, 0, 0xfffffffc) + bytes(8))
    s.chan('rdpsnd', struct.pack('<BBI', 0x02, 0, 0xfffffffb) + bytes(8))
    cap.write(os.path.join(OUT, 'snd-coverage-malformed.pcapng'))


if __name__ == '__main__':
    build_main()
    build_malformed()
