#!/usr/bin/env python3
# Generates test/captures/scop_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the SCOP (ZigBee SCoP) coverage captures: mkscop.py <outdir> [-v].  All data is synthetic."""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import struct
from c17lib import Cap, Tcp, udp

def scop(transport, service, ptype, payload=b'', version=1, reserved=0, total=None):
    body = bytes([service, ptype, reserved]) + payload
    length = 4 + len(body) if total is None else total
    return bytes([transport, version]) + struct.pack('>H', length) + body

def scopb(transport, service, rest, version=1):
    return bytes([transport, version]) + struct.pack('>H', 5 + len(rest)) + bytes([service]) + rest

def hello_resp(status, transport=1, reserved=0, tail=b''):
    return scop(transport, 0, 1, struct.pack('>H', status) + tail, reserved=reserved)

# IEEE 802.15.4 frames without FCS
def wpan_data(seq, payload, pan=0x1234, dst=0x0001, src=0x0002):
    return struct.pack('<HBHHH', 0x8841, seq, pan, dst, src) + payload
def wpan_ack(seq):
    return struct.pack('<HB', 0x0002, seq)

def main(out, verbose=False):
    c = Cap(1)
    def u(p, port=17755, sport=40000):
        c.add(udp(sport, port, p))
    c.mark('UDP port 17755: Hello, Hello Response (status Success and Failure, reserved octet set: reproducer of the status offset fix), Hello Acknowledgment, Goodbye, Goodbye Response, Keep Alive Ping and Pong')
    u(scop(1, 0, 0))
    u(hello_resp(0))
    u(hello_resp(0, reserved=1))
    u(hello_resp(1))
    u(hello_resp(0xffff, reserved=0x80))
    u(scop(1, 0, 2))
    u(scop(1, 0, 4))
    u(scop(1, 0, 5))
    u(scop(1, 0, 6))
    u(scop(1, 0, 7))
    c.mark('UDP port 17756: reserved packet types and a type with trailing payload (shown as data), version 2, transport TCP mode 3 over UDP')
    u(scop(1, 0, 3), 17756)
    u(scop(1, 0, 0x20, b'trailing data'), 17756)
    u(hello_resp(0, tail=b'\x01\x02\x03'), 17756)
    u(scop(1, 0, 0, version=2), 17756)
    u(scop(131, 0, 6, b''), 17756)
    u(scop(2, 0, 7), 17756)
    c.mark('Bridge service: an IEEE 802.15.4 data frame and an acknowledgment; gateway and unknown services (data)')
    u(scopb(1, 1, wpan_data(7, b'\x01\x02\x03\x04')))
    u(scopb(1, 1, wpan_ack(7)), 17756)
    u(scopb(1, 2, b'gateway'))
    u(scopb(1, 77, b'unknown'))
    c.mark('CCM* transports (decryption not attempted: only the header is shown)')
    u(scop(129, 0, 0, b'\xde\xad\xbe\xef'))
    c.add(udp(40000, 17755, scop(130, 0, 0, b'\xde\xad\xbe\xef')))
    c.mark('TCP port 17755: several PDUs per segment, a PDU split over segments (reassembly), TCP mode 2 and the CCM and SSL transports')
    t = Tcp(c, 40100, 17755)
    t.c2s(scop(2, 0, 0))
    t.s2c(hello_resp(0, transport=2))
    t.c2s(scop(2, 0, 2) + scop(2, 0, 6) + scop(2, 0, 7))
    big = scop(2, 0, 0x30, b'0123456789' * 12)
    t.c2s(big[:3]); t.c2s(big[3:50]); t.c2s(big[50:])
    t.s2c(scop(130, 0, 0, b'\x00' * 8))
    t.s2c(scopb(2, 1, wpan_data(9, b'\x01\x02\x03')))
    t.c2s(scop(2, 0, 4)); t.s2c(scop(2, 0, 5))
    t2 = Tcp(c, 40101, 17756)
    t2.c2s(scop(131, 0, 6)); t2.s2c(scop(131, 0, 7))

    m = Cap(1)
    m.mark('Truncated PDUs (exceptions)')
    mu = lambda p, port=17755: m.add(udp(40000, port, p))
    mu(b'\x01')
    mu(b'\x01\x01\x00')
    mu(b'\x01\x01\x00\x08')
    mu(b'\x01\x01\x00\x08\x00')
    mu(b'\x01\x01\x00\x08\x00\x01\x00')
    mu(b'\x01\x01\x00\x08\x00\x01\x00\x00')
    mu(b'\x01\x01\x00\x08\x01', 17756)
    mu(b'\x01\x01\x00\x08\x01\x01\x00\x01\x00')

    c.write(os.path.join(out, 'scop-coverage.pcap'))
    m.write(os.path.join(out, 'scop-coverage-malformed.pcap'))
    if verbose:
        for n, tx in c.marks:
            print(n, tx)
        print(len(c.frames), 'frames')

if __name__ == '__main__':
    main(sys.argv[1], '-v' in sys.argv)
