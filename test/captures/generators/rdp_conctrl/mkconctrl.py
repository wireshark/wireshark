#!/usr/bin/env python3
# Generates test/captures/rdp_conctrl_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic RDP connection control channel ("conctrl") captures for
# packet-rdp_conctrl.c.  Usage: mkconctrl.py <outdir> [-v]
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from rdplib import Cap, Session

OUT = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('-') else '.'
VERBOSE = '-v' in sys.argv


def uni(s):
    return s.encode('utf-16le')


def info(order, realm, login, pad=bytes(12)):
    r, l = uni(realm), uni(login)
    return struct.pack('<H', order) + pad + struct.pack('<II', len(r), len(l)) + r + l


def build_main():
    cap = Cap()
    s = Session(cap, 50000, ['conctrl', 'cliprdr'])
    C = lambda p, c2s=False: s.chan('conctrl', p, c2s)
    C(struct.pack('<H', 1), True)                 # client capabilities
    C(struct.pack('<H', 2))                       # server capabilities
    C(struct.pack('<H', 8), True)                 # close
    C(info(0x10, 'EXAMPLE.TEST', 'alice'))        # session info
    C(info(0x10, '', 'bob'))
    C(info(0x10, 'R', ''))
    C(info(0x10, 'REALM', 'u', pad=bytes(range(12))))
    C(struct.pack('<H', 0x33) + b'unknown order')  # unknown order type
    C(struct.pack('<H', 0))
    s.chunks('conctrl', info(0x10, 'CHUNKED.EXAMPLE.TEST', 'carol-with-a-long-login-name'), size=20)   # reassembled
    s.chan('conctrl', info(0x10, 'CLIENT', 'dave'), True)
    s.chan('cliprdr', struct.pack('<HHI', 1, 0, 0))
    cap.write(os.path.join(OUT, 'conctrl-coverage.pcapng'))
    if VERBOSE:
        print('conctrl-coverage.pcapng', len(cap.frames), 'frames')


def build_malformed():
    cap = Cap()
    s = Session(cap, 50000, ['conctrl'])
    s.chan('conctrl', b'\x10')                                  # order type cut short
    s.chan('conctrl', struct.pack('<H', 0x10) + bytes(8))       # cut inside the padding
    s.chan('conctrl', struct.pack('<H', 0x10) + bytes(12) + struct.pack('<II', 1000, 4) + b'ab')
    s.chan('conctrl', struct.pack('<H', 0x10) + bytes(12) + struct.pack('<II', 0xffffffff, 0xffffffff))
    s.chan('conctrl', struct.pack('<H', 0x10) + bytes(12) + struct.pack('<II', 4, 1000) + b'abcd')
    cap.write(os.path.join(OUT, 'conctrl-coverage-malformed.pcapng'))


if __name__ == '__main__':
    build_main()
    build_malformed()
