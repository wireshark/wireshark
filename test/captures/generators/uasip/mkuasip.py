#!/usr/bin/env python3
# Generates test/captures/uasip_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
'''Generate the UASIP coverage captures (synthetic).

usage: mkuasip.py OUTDIR [-v]

UASIP (the UA/SIP variant of UA/UDP) has no port of its own. It is reached
by Decode As "media_type" or, as in a real capture, as an Exported PDU naming
the dissector "uasip" (the frames here are Exported PDU, linktype 252,
with and without IPv4 addresses). The preference uasip.proxy_ipaddr names
the proxy that decides the direction of Data, uasip.noesip makes Data
dissect the UA messages.
Writes uasip-coverage.pcapng and uasip-coverage-malformed.pcapng.
'''
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct

from u9lib import Pcapng, epdu

PROXY = [192, 0, 2, 9]
TERM = [192, 0, 2, 50]
OTHER = [198, 51, 100, 7]

sections = []


def be(n, size):
    return n.to_bytes(size, 'big')


def tlv(t, v):
    if isinstance(v, int):
        v = bytes([v])
    return bytes([t, len(v)]) + bytes(v)


def ua(op, body=b''):
    m = bytes([op]) + bytes(body)
    return struct.pack('<H', len(m)) + m


def data(msgs, exp=1, snt=1):
    return bytes([7]) + struct.pack('!HH', exp, snt) + b''.join(msgs)


class Gen:
    def __init__(self):
        self.pc = Pcapng([252])

    def sec(self, name):
        sections.append([name, len(self.pc) + 1, None])

    def end(self):
        sections[-1][2] = len(self.pc)

    def add(self, payload, ipv4=None):
        return self.pc.add(epdu('uasip', payload, ipv4, (5060, 5060) if ipv4 else None), 0)


ALL = [(0, be(0x01020304, 4)), (1, be(0x0102, 2)), (2, be(1500, 2)), (3, 5), (4, be(7, 3)),
       (5, be(30, 2)), (6, 0xB8), (7, be(100, 2)), (8, 5)]


def build_main(g):
    g.sec('Connect and Connect ACK with every TLV (lengths 1 to 4), types without a field')
    g.add(bytes([0]) + b''.join(tlv(t, v) for t, v in ALL))
    g.add(bytes([1]) + b''.join(tlv(t, v) for t, v in ALL[:5]))
    g.add(bytes([0]) + b''.join(tlv(t, be(0x01020304, 4)) for t in range(9)))
    g.add(bytes([0]) + b''.join(tlv(t, 1) for t in range(9)))
    g.add(bytes([0]) + tlv(9, 1) + tlv(0x30, b'\x01\x02') + tlv(0xFF, b'\x01') + tlv(0, 1))
    g.add(bytes([0]))
    g.end()

    g.sec('Release, keepalive, NACK, unknown opcodes')
    for op in (2, 3, 4, 5):
        g.add(bytes([op]))
    g.add(bytes([6]) + be(7, 2))
    g.add(bytes([6]) + be(0xFFFF, 2))
    g.add(bytes([64]) + bytes(6) + b'file\0')
    g.add(bytes([0x30, 1, 2]))
    g.end()

    g.sec('Data with and without UA messages (without addresses: direction unknown)')
    nop = ua(0x00)
    mute = ua(0x3F, [1])
    g.add(data([nop, mute], 1, 2))
    g.add(data([], 2, 2))
    g.add(data([ua(0x01)], 65535, 0))
    g.end()

    g.sec('Data with IPv4 addresses: from the proxy, to the proxy, other addresses')
    g.add(data([nop], 3, 3), ipv4=(PROXY, TERM))
    g.add(data([ua(0x01)], 3, 4), ipv4=(TERM, PROXY))
    g.add(data([ua(0x01)], 3, 5), ipv4=(TERM, OTHER))
    g.add(data([], 3, 6), ipv4=(PROXY, TERM))
    g.add(bytes([4]), ipv4=(TERM, PROXY))
    g.add(bytes([0]) + tlv(0, 1), ipv4=(PROXY, TERM))
    g.end()


def build_malformed(g):
    g.sec('TLV with an invalid length (warning) and truncated packets')
    g.add(bytes([0]) + tlv(0, b'') + tlv(1, 1))
    g.add(bytes([0]) + tlv(0, b'\x01\x02\x03\x04\x05') + tlv(1, 1))
    g.add(bytes([0]) + tlv(8, b'') + tlv(7, b'\x01' * 6) + tlv(6, b'') + tlv(5, b'') + tlv(4, b'')
          + tlv(3, b'') + tlv(2, b'') + tlv(1, b'') + tlv(8, b'\x01' * 7))
    g.add(bytes([0]) + bytes([0, 4, 1, 2]))        # TLV longer than the packet
    g.add(bytes([0]) + bytes([5]))                 # TLV type without length
    g.add(bytes([6, 0]))                           # NACK with one octet
    g.add(bytes([7, 0, 1]))                        # Data with a short header
    g.add(bytes([7, 0, 1, 0, 1]) + b'\x01')
    g.end()
    g.sec('Frames without addresses, as in the crash of the proxy comparison (preference set)')
    g.add(bytes([7, 0, 1, 0, 1]) + ua(0x00))
    g.add(bytes([4]))
    g.end()


def main():
    out = sys.argv[1]
    verbose = '-v' in sys.argv
    os.makedirs(out, exist_ok=True)
    g = Gen()
    build_main(g)
    g.pc.write(os.path.join(out, 'uasip-coverage.pcapng'))
    if verbose:
        print('main: %d frames' % len(g.pc))
        for n, a, b in sections:
            print('  %4d-%4d %s' % (a, b, n))
    del sections[:]
    m = Gen()
    build_malformed(m)
    m.pc.write(os.path.join(out, 'uasip-coverage-malformed.pcapng'))
    if verbose:
        print('malformed: %d frames' % len(m.pc))
        for n, a, b in sections:
            print('  %4d-%4d %s' % (a, b, n))


if __name__ == '__main__':
    main()
