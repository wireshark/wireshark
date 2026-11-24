#!/usr/bin/env python3
# Generates test/captures/swipe_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the swIPe coverage captures: mkswipe.py <outdir> [-v].  All data is synthetic."""
import os
import struct
import sys
from c17lib import Cap, eth, ipv4, ipv6, csum

def swipe(ptype, policy, seq, auth=b'', inner=b''):
    return struct.pack('>BBHI', ptype, 8 + len(auth), policy, seq) + auth + inner

def inner6(n=1, payload=b'synthetic'):
    import socket
    u = struct.pack('>HHHH', 4000 + n, 5000, 8 + len(payload), 0) + payload
    ps = socket.inet_pton(socket.AF_INET6, '2001:db8::1') + socket.inet_pton(socket.AF_INET6, '2001:db8::2') + struct.pack('>IBBBB', len(u), 0, 0, 0, 17)
    ck = csum(ps + u) or 0xffff
    u = u[:6] + struct.pack('>H', ck) + u[8:]
    return ipv6(17, u)

def nested(levels, ptype=0):
    """swIPe (ip.proto 53) / IPv6 / swIPe / IPv6 ... with the given number of swIPe layers."""
    body = inner6()
    for i in range(levels):
        body = ipv6(53, swipe(ptype, i, i, b'', body))
    return body

def main(out, verbose):
    c = Cap(1)
    c.mark('swIPe in IPv4 (ip.proto 53): every packet type, with and without authenticator, carrying IPv6/UDP')
    for t in range(4):
        c.add(eth(ipv4(53, swipe(t, 100 + t, 1000 + t, b'\xaa' * (0 if t == 0 else 8 * t), inner6(t)))))
    c.mark('swIPe with a 16 octet authenticator and an undefined packet type')
    c.add(eth(ipv4(53, swipe(7, 9, 5, bytes(range(16)), inner6(9)))))
    c.mark('swIPe in IPv6 (next header 53) carrying IPv6')
    c.add(eth(ipv6(53, swipe(2, 1, 77, b'\x11' * 4, inner6(3))), 0x86dd))
    c.mark('Nested swIPe/IPv6 up to the limit of four levels (no warning)')
    c.add(eth(ipv4(53, swipe(0, 1, 1, b'', nested(3)))))
    c.mark('Reproducer of the nesting bound: swIPe/IPv6 nested 6 levels deep (the fifth layer gets the expert warning)')
    c.add(eth(ipv4(53, swipe(0, 1, 1, b'', nested(5)))))
    c.mark('A deep stack, 300 swIPe layers (about 15 KB, the second reproducer)')
    c.add(eth(ipv4(53, swipe(0, 1, 1, b'', nested(299)))))

    m = Cap(1)
    m.mark('Truncated swIPe header, header length past the packet, and a header length below 8')
    m.add(eth(ipv4(53, swipe(0, 1, 1)[:6])))
    p = bytearray(swipe(1, 1, 1, b'\0' * 8, inner6())); p[1] = 200
    m.add(eth(ipv4(53, bytes(p))))
    p = bytearray(swipe(0, 1, 1, b'', inner6())); p[1] = 0
    m.add(eth(ipv4(53, bytes(p))))
    m.mark('swIPe header only, no payload after the header')
    m.add(eth(ipv4(53, swipe(0, 1, 2))))
    m.mark('Inner packet that is not IPv6')
    m.add(eth(ipv4(53, swipe(0, 1, 1, b'', b'\x45\x00\x00\x14'))))
    c.write(os.path.join(out, 'swipe-coverage.pcap'))
    m.write(os.path.join(out, 'swipe-coverage-malformed.pcap'))
    if verbose:
        for n, tx in c.marks:
            print(n, tx)
        print(len(c.frames), 'frames')

if __name__ == '__main__':
    main(sys.argv[1], '-v' in sys.argv)
