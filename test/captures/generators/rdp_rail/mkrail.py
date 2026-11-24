#!/usr/bin/env python3
# Generates test/captures/rdp_rail_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic RAIL (MS-RDPERP RemoteApp) captures for packet-rdp_rail.c.
# Usage: mkrail.py <outdir> [-v]
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from rdplib import Cap, Session
from dvclib import create_req, data, data_first

OUT = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('-') else '.'
VERBOSE = '-v' in sys.argv

WINDOW_ORDERS = (0x02, 0x0c, 0x04, 0x06, 0x0e, 0x15, 0x17, 0x0f, 0x18, 0x14, 0x1b, 0x1c, 0x1d, 0x1f, 0x08, 0x09, 0x0a)
SERVER_SPI = (0x11, 0x77, 0x7777)
CLIENT_SPI = (0x25, 0x100b, 0x45, 0x2f, 0xf001, 0x21, 0xf000, 0x43, 0x2007, 0x3b, 0x35, 0x33,
              0xf002, 0xf003, 0xf004, 0xf005, 0xf006, 0xf007, 0xf008, 0xf009, 0xf00a, 0xf00b,
              0xf00c, 0xf00d, 0xf00e, 0x7777)
ALL_ORDERS = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x80, 0x0e, 0x0f, 0x10,
              0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
              0x21, 0x22, 0x23, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2b, 0x2c, 0x2d, 0x7f]


def rail(order, body=b'', length=None):
    return struct.pack('<HH', order, 4 + len(body) if length is None else length) + body


def build_main():
    cap = Cap()
    s = Session(cap, 50000, ['rail', 'drdynvc'])
    S = lambda p: s.chan('rail', p, False)
    C = lambda p: s.chan('rail', p, True)
    S(rail(0x05, struct.pack('<I', 19041)))                                     # handshake
    C(rail(0x05, struct.pack('<I', 19041)))
    S(rail(0x13, struct.pack('<II', 19041, 0x3f)))                              # handshake ex (all flags)
    C(rail(0x13, struct.pack('<II', 19041, 0)))
    C(rail(0x0b, struct.pack('<I', 0x1ff)))                                     # client status (all flags)
    C(rail(0x0b, struct.pack('<I', 0)))
    for o in ALL_ORDERS:
        body = bytes(48)
        if o in WINDOW_ORDERS:
            body = struct.pack('<I', 0x00020a1c) + bytes(44)
        S(rail(o, body))
        C(rail(o, body))
    for p in SERVER_SPI:
        S(rail(0x03, struct.pack('<IB', p, 1) + bytes(8)))
    for p in CLIENT_SPI:
        C(rail(0x03, struct.pack('<IB', p, 1) + bytes(40)))
    S(rail(0x02, struct.pack('<IB', 0x1234, 1)))                                # activate
    C(rail(0x02, struct.pack('<IB', 0x1234, 0)))
    S(rail(0x15, struct.pack('<IB', 0x1234, 1)))                                # cloak
    S(rail(0x08, struct.pack('<I4H', 0x1234, 1, 2, 3, 4)))                      # window move
    S(rail(0x09, struct.pack('<I4H', 0x1234, 1, 2, 3, 4)))
    S(rail(0x0a, struct.pack('<I8H', 0x1234, 1, 2, 3, 4, 5, 6, 7, 8)))
    S(rail(0x06, struct.pack('<III', 0x1234, 7, 0x201)))                        # notify event
    S(rail(0x26, bytes(12) + struct.pack('<I', 0xabcd)))                        # z-order body
    s.chunks('rail', rail(0x01, bytes(1500)), size=600)                         # reassembled exec
    S(rail(0x01, bytes(10)) + rail(0x02, bytes(10)))                            # two PDUs in one channel PDU: only the first is dissected
    S2 = lambda p: s.chan('drdynvc', p, False)
    S2(create_req(5, 'Microsoft::Windows::RDS::RAIL'))
    S2(create_req(6, 'rail'))
    S2(data(5, rail(0x05, struct.pack('<I', 19041))))
    S2(data(6, rail(0x13, struct.pack('<II', 19041, 1))))
    S2(data_first(5, 8, rail(0x05, struct.pack('<I', 19041))[:5]))
    S2(data(5, rail(0x05, struct.pack('<I', 19041))[5:] + bytes(0)))
    cap.write(os.path.join(OUT, 'rail-coverage.pcapng'))
    if VERBOSE:
        print('rail-coverage.pcapng', len(cap.frames), 'frames')


def build_malformed():
    cap = Cap()
    s = Session(cap, 50000, ['rail'])
    s.chan('rail', b'\x05\x00')                                  # cut short
    s.chan('rail', rail(0x02, bytes(2), length=7))               # window id cut short
    s.chan('rail', rail(0x05, b'', length=0x0100))
    s.chan('rail', struct.pack('<HH', 0x03, 2) + bytes(8))       # length below 4: wraps (fix on the branch)
    s.chan('rail', struct.pack('<HH', 0x03, 3) + bytes(8), )
    s.chan('rail', rail(0x03, struct.pack('<I', 0x25)), True)    # no data after the parameter
    s.chan('rail', rail(0x0a, bytes(8)))
    s.chan('rail', rail(0x13, bytes(4)))
    s.chan('rail', rail(0x26, bytes(6)))
    cap.write(os.path.join(OUT, 'rail-coverage-malformed.pcapng'))


if __name__ == '__main__':
    build_main()
    build_malformed()
