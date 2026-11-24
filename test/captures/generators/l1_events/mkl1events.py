#!/usr/bin/env python3
# Generates test/captures/l1_events_coverage.eyesdn.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the Layer 1 Events coverage capture (EyeSDN file with message
records). Usage: mkl1events.py <outdir> [-v]. Synthetic data only."""
import struct
import sys

EYESDN_ENCAP_MSG = 1


def esc(b):
    """EyeSDN escaping: 0xff and 0xfe become 0xfe and the value - 2."""
    out = bytearray()
    for c in b:
        if c in (0xff, 0xfe):
            out += bytes([0xfe, c - 2])
        else:
            out.append(c)
    return bytes(out)


def eyesdn(path, records):
    """records: (uton, payload) pairs, written as Layer 1 messages."""
    with open(path, 'wb') as f:
        f.write(b'EyeSDN')
        for i, (uton, payload) in enumerate(records):
            usecs = 1000 * i
            secs = 1700000000 + i
            hdr = struct.pack('>I', usecs)[1:] + struct.pack('>Q', secs)[3:]
            hdr += bytes([0, (EYESDN_ENCAP_MSG << 1) | uton]) + struct.pack('>H', len(payload))
            f.write(b'\xff' + esc(hdr + payload))


MAIN = [
    (0, b'L1 activated\n'),                          # NT, one LF line
    (1, b'L1 deactivated\r\n'),                      # TE, CRLF
    (0, b'INFO 4\r'),                                # CR only
    (1, b'no line terminator'),                      # no end of line
    (0, b'first line\nsecond line\nthird line\n'),   # several lines
    (1, b'one\r\ntwo\r\nthree'),                     # last line open
    (0, b'\nafter an empty first line\n'),           # empty first line
    (1, b'\n'),                                      # only a line end
    (0, b'\r\n\r\n'),                                # only empty lines
    (1, b'text with \xfe and \xff bytes\n'),         # escaped octets
    (0, b'x'),                                       # one octet
    (1, (b'a long line of status text ' * 40) + b'\n'),
    (0, b'tab\tand control\x01\x02 chars\n'),
    (1, b'last record\n'),
    (0, b''),                                        # empty payload
]

def main():
    out = sys.argv[1]
    eyesdn(out + '/l1-events-coverage.eyesdn', MAIN)
    if '-v' in sys.argv:
        print('frames: 1-%d' % len(MAIN))


main()
