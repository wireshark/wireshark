#!/usr/bin/env python3
# Generates test/captures/uaudp_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
'''Generate the UAUDP coverage captures (synthetic).

usage: mkuaudp.py OUTDIR [-v]

UA/UDP is registered on UDP ports 32000 and 32512. The direction of a
data packet comes from the ports (the terminal uses the registered port:
a source port in the registered set means terminal to system, a
destination port means system to terminal), from the preference
uaudp.system_ip, or is unknown (Exported PDU without addresses).
Writes uaudp-coverage.pcapng (Ethernet and Exported PDU interfaces) and
uaudp-coverage-malformed.pcapng.
'''
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct

from u9lib import Pcapng, udp, udp6, epdu

SYS = [192, 0, 2, 10]
TERM = [192, 0, 2, 50]
SYS6 = bytes.fromhex('20010db8000000000000000000000010')
TERM6 = bytes.fromhex('20010db8000000000000000000000050')
PORT = 32000
PORT2 = 32512

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
    def __init__(self, linktypes):
        self.pc = Pcapng(linktypes)
        self.n = 1

    def sec(self, name):
        sections.append([name, len(self.pc) + 1, None])

    def end(self):
        sections[-1][2] = len(self.pc)

    def t2s(self, payload, port=PORT):
        '''terminal (source port 32000) to system'''
        return self.pc.add(udp(TERM, SYS, port, 40000, payload))

    def s2t(self, payload, port=PORT):
        return self.pc.add(udp(SYS, TERM, 40000, port, payload))

    def both(self, payload, sp=PORT, dp=PORT):
        '''system address, both ports registered'''
        return self.pc.add(udp(SYS, TERM, sp, dp, payload))

    def epdu(self, payload, ipv4=None, ports=None):
        return self.pc.add(epdu('uaudp', payload, ipv4, ports), 1)


ALL = [(0, be(0x01020304, 4)), (1, be(0x0102, 2)), (2, be(1500, 2)), (3, 5), (4, be(7, 3)),
       (5, be(30, 2)), (6, 0xB8), (7, be(100, 2)), (8, 5), (9, 1)]


def build_main(g):
    g.sec('Connect and Connect ACK with every TLV (lengths 1 to 4), unknown types')
    g.t2s(bytes([0]) + b''.join(tlv(t, v) for t, v in ALL))
    g.s2t(bytes([1]) + b''.join(tlv(t, v) for t, v in ALL[:6]))
    g.t2s(bytes([0]) + tlv(0, 1) + tlv(0, be(2, 2)) + tlv(0, be(3, 3)) + tlv(0, be(4, 4)))
    g.t2s(bytes([0]) + b''.join(tlv(t, be(0x01020304, 4)) for t in range(10)))
    g.t2s(bytes([0]) + tlv(0x30, b'\x01\x02') + tlv(0xFF, b'\x01') + tlv(0, 1))
    g.t2s(bytes([0]))
    g.s2t(bytes([1]))
    g.end()

    g.sec('Release, keepalive, NACK, unknown opcodes, StartSig')
    for op in (2, 3, 4, 5):
        g.t2s(bytes([op]))
    g.s2t(bytes([4]))
    g.s2t(bytes([5]))
    g.t2s(bytes([6]) + be(7, 2))
    g.s2t(bytes([6]) + be(0xFFFF, 2))
    g.t2s(bytes([0x30]))
    g.t2s(bytes([0xFE, 1, 2, 3]))
    g.s2t(bytes([64]) + bytes(range(1, 7)) + b'firmware.bin\0')
    g.t2s(bytes([65]) + bytes(6) + b'\0')
    g.end()

    g.sec('Data in both directions on both registered ports, Data ACK')
    nop = ua(0x00)
    mute = ua(0x3F, [1])
    g.s2t(data([nop, mute], 1, 2))
    g.t2s(data([ua(0x01)], 2, 1))
    g.s2t(data([ua(0x3F, [0])], 3, 3), port=PORT2)
    g.t2s(data([ua(0x02)], 3, 3), port=PORT2)
    g.s2t(data([], 4, 4))
    g.t2s(data([], 4, 4))
    g.s2t(data([ua(0x21, [1, 2])], 65535, 0))
    g.end()

    g.sec('Both ports registered: the call server address (preference uaudp.system_ip) decides')
    g.both(data([nop], 5, 5))                 # from the system address
    g.pc.add(udp(TERM, SYS, PORT, PORT, data([ua(0x01)], 5, 6)))      # to the system address
    g.pc.add(udp(TERM, TERM, PORT, PORT, data([ua(0x01)], 5, 7)))     # neither address
    g.end()

    g.sec('IPv6 (the call server preference may be an IPv6 address)')
    g.pc.add(udp6(SYS6, TERM6, 40000, PORT, data([nop], 6, 6)))
    g.pc.add(udp6(TERM6, SYS6, PORT, 40000, data([ua(0x01)], 6, 7)))
    g.pc.add(udp6(SYS6, TERM6, PORT, PORT, data([nop], 6, 8)))
    g.pc.add(udp6(TERM6, SYS6, PORT, PORT, data([ua(0x01)], 6, 9)))
    g.end()

    g.sec('Exported PDU naming "uaudp": no ports or addresses, direction unknown')
    g.epdu(data([nop], 7, 7))
    g.epdu(data([], 7, 8))
    g.epdu(bytes([4]))
    g.epdu(bytes([0]) + tlv(0, 1))
    g.epdu(data([nop], 7, 7), ipv4=(SYS, TERM), ports=(PORT, 40000))
    g.end()


def build_malformed(g):
    g.sec('TLV with an invalid length (warning) and truncated TLVs')
    g.t2s(bytes([0]) + tlv(0, b'') + tlv(1, 1))
    g.t2s(bytes([0]) + tlv(0, b'\x01\x02\x03\x04\x05') + tlv(1, 1))
    g.t2s(bytes([0]) + bytes([2, 0]) + bytes([3, 9]) + bytes(9))
    g.t2s(bytes([0]) + bytes([0, 4, 1, 2]))        # TLV longer than the packet
    g.t2s(bytes([0]) + bytes([5]))                 # TLV type without length
    g.t2s(bytes([0]) + tlv(0, 1) + bytes([200, 255, 1]))
    g.end()
    g.sec('Short packets')
    g.t2s(bytes([6, 0]))                           # NACK with one octet
    g.t2s(bytes([7, 0, 1]))                        # Data with a short header
    g.t2s(bytes([7]))
    g.t2s(bytes([64, 1, 2, 3]))                    # StartSig with a short reserved field
    g.t2s(bytes([64]) + bytes(6) + b'no terminator')
    g.t2s(bytes([7, 0, 1, 0, 1]) + b'\x01')       # UA length field cut short
    g.t2s(bytes([7, 0, 1, 0, 1]) + struct.pack('<H', 50) + b'\x3f\x01')   # UA message longer than data
    g.end()


def main():
    out = sys.argv[1]
    verbose = '-v' in sys.argv
    os.makedirs(out, exist_ok=True)
    g = Gen([1, 252])
    build_main(g)
    g.pc.write(os.path.join(out, 'uaudp-coverage.pcapng'))
    if verbose:
        print('main: %d frames' % len(g.pc))
        for n, a, b in sections:
            print('  %4d-%4d %s' % (a, b, n))
    del sections[:]
    m = Gen([1, 252])
    build_malformed(m)
    m.pc.write(os.path.join(out, 'uaudp-coverage-malformed.pcapng'))
    if verbose:
        print('malformed: %d frames' % len(m.pc))
        for n, a, b in sections:
            print('  %4d-%4d %s' % (a, b, n))


if __name__ == '__main__':
    main()
