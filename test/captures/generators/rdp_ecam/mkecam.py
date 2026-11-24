#!/usr/bin/env python3
# Generates test/captures/rdp_ecam_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic RDP camera redirection (MS-RDPECAM) captures for packet-rdp_ecam.c.
# Usage: mkecam.py <outdir> [-v]
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from rdplib import Cap, Session
from dvclib import create_req, data, data_first

OUT = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('-') else '.'
VERBOSE = '-v' in sys.argv


def m(mid, body=b'', ver=2):
    return struct.pack('<BB', ver, mid) + body


def stream(src, cat, sel, share):
    return struct.pack('<HBBB', src, cat, sel, share)


def media(fmt, w=1280, h=720, fn=30, fd=1, an=16, ad=9, fl=1):
    return struct.pack('<BIIIIIIB', fmt, w, h, fn, fd, an, ad, fl)


def build_main():
    cap = Cap()
    s = Session(cap, 50000, ['drdynvc'], msgchan=True)
    S = lambda cid, p: s.chan('drdynvc', data(cid, p), False)
    C = lambda cid, p: s.chan('drdynvc', data(cid, p), True)
    s.chan('drdynvc', create_req(1, 'RDCamera_Device_Enumerator'), False)
    s.chan('drdynvc', create_req(2, 'RDCamera_Device_Camera0'), False)
    s.chan('drdynvc', create_req(3, 'RDCamera_Device_'), False)
    for cid in (1, 2, 3):
        S(cid, m(3, stream(1, 1, 1, 1)))                          # select version (stream-like body, as dissected)
        C(cid, m(4))
    C(1, m(5, stream(0, 1, 1, 0) + stream(1, 2, 0, 1)))           # device added
    S(1, m(6, b''))
    S(2, m(7))                                                   # activate device
    S(2, m(8))                                                   # deactivate
    S(2, m(9))                                                   # stream list request
    C(2, m(0xa, stream(0, 1, 1, 1) + stream(1, 2, 1, 0) + stream(2, 3, 0, 0) + b'\0\0'))   # stream list response
    C(2, m(0xa))
    S(2, m(0xb, bytes([0])))                                      # media type list request
    C(2, m(0xc, b''.join(media(f) for f in (1, 2, 3, 4, 5, 6, 7, 0x77)) + b'\0' * 10))
    C(2, m(0xc))
    S(2, m(0xd, bytes([1])))                                      # current media type request
    C(2, m(0xe, media(2)))
    S(2, m(0xf, bytes([0]) + media(3)))                           # start streams
    S(2, m(0x10))                                                 # stop streams
    S(2, m(0x11, bytes([0])))                                     # sample request
    C(2, m(0x12, bytes([0]) + bytes(100)))                        # sample response
    C(2, m(0x13, bytes([0]) + struct.pack('<I', 7)))              # sample error response
    S(2, m(0x14))                                                 # property list request
    C(2, m(0x15, bytes(8)))
    S(2, m(0x16, bytes(4)))
    C(2, m(0x17, bytes(8)))
    S(2, m(0x18, bytes(8)))
    C(2, m(1))                                                    # success
    for code in list(range(1, 11)) + [0x77]:
        C(2, m(2, struct.pack('<I', code)))                       # error response
    S(2, m(0x7f, bytes(4)))                                       # unknown message
    S(2, m(0x30))
    s.chan('drdynvc', data_first(2, 2 + 3 * 26, m(0xc, media(1)) [:10]), False)         # reassembled media type list
    s.chan('drdynvc', data(2, m(0xc, media(1))[10:] + media(2) + media(3)), False)
    cookie = bytes(range(16))
    s.msg(struct.pack('<HH', 0x0002, 0) + struct.pack('<IHH', 0x55667788, 2, 0) + cookie)
    cap.exp('rdpmt', struct.pack('<BHB', 0, 24, 4) + struct.pack('<II', 0x55667788, 0) + cookie, True, sport=50050, pt=3)
    cap.exp('rdp_drdynvc', create_req(5, 'RDCamera_Device_Enumerator'), False, sport=50050, pt=3)
    cap.exp('rdp_drdynvc', data(5, m(3, stream(1, 1, 1, 1))), False, sport=50050, pt=3)
    cap.write(os.path.join(OUT, 'ecam-coverage.pcapng'))
    if VERBOSE:
        print('ecam-coverage.pcapng', len(cap.frames), 'frames')


def build_malformed():
    cap = Cap()
    s = Session(cap, 50000, ['drdynvc'])
    s.chan('drdynvc', create_req(2, 'RDCamera_Device_Camera0'), False)
    S = lambda p: s.chan('drdynvc', data(2, p), False)
    S(b'\x02')                                                    # cut short
    S(m(2, b'\0\0'))                                              # error code cut short
    S(m(0xb))                                                     # stream index missing
    S(m(0xe, bytes(10)))                                          # media descriptor cut short
    S(m(0xf, bytes(3)))
    S(m(0x12))
    S(m(0xc, media(1)[:20]))
    S(m(0xa, stream(0, 1, 1, 1)[:3]))
    cap.write(os.path.join(OUT, 'ecam-coverage-malformed.pcapng'))


if __name__ == '__main__':
    build_main()
    build_malformed()
