#!/usr/bin/env python3
# AMQP coverage capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""amqp_coverage.pcap: the AMQP 0-8/0-9/0-9-1/0-10 capture of mkamqp0.py
followed by the AMQP 1.0 capture of mkamqp10.py and the frames for the
decoding fixes of mkamqp_fixes.py (as `mergecap -a` joins them).

Usage: mkamqp.py [<output directory>]

Writes amqp-coverage.pcap. Every packet is built here; nothing comes from a
real network.
"""

import os
import sys
import tempfile

import mkamqp0
import mkamqp10
import mkamqp_fixes


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    with tempfile.TemporaryDirectory() as tmp:
        mkamqp0.build_main().write(os.path.join(tmp, 'a.pcap'))
        mkamqp10.build_main().write(os.path.join(tmp, 'b.pcap'))
        mkamqp_fixes.build_main().write(os.path.join(tmp, 'c.pcap'))
        with open(os.path.join(tmp, 'a.pcap'), 'rb') as f:
            a = f.read()
        with open(os.path.join(tmp, 'b.pcap'), 'rb') as f:
            b = f.read()
        with open(os.path.join(tmp, 'c.pcap'), 'rb') as f:
            c = f.read()
    # Both are little-endian microsecond pcap files with the same link type;
    # append the records of the second after the first.
    assert a[:24] == b[:24] == c[:24]
    with open(os.path.join(out, 'amqp-coverage.pcap'), 'wb') as f:
        f.write(a + b[24:] + c[24:])


if __name__ == '__main__':
    main()
