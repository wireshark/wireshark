#!/usr/bin/env python3
# Generates test/captures/synergy_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the Synergy coverage captures: mksynergy.py <outdir> [-v].  All data is synthetic."""
import os
import struct
import sys
from c17lib import Cap, Tcp

def pdu(body):
    return struct.pack('>I', len(body)) + body

def msg(typ, payload=b''):
    return pdu(typ + payload)

def hello(major=1, minor=6):
    return pdu(b'Synergy' + struct.pack('>HH', major, minor))

def hello_back(name, major=1, minor=6):
    return pdu(b'Synergy' + struct.pack('>HHI', major, minor, len(name)) + name)

PAD = b'\0'   # one octet after the type: the dissector adds items with length -1, which throw at the end of the data

def main(out, verbose):
    c = Cap(1)
    t = Tcp(c, 50000, 24800)
    S = t.s2c; C = t.c2s
    c.mark('Handshake: server hello with the protocol version, client reply with its name; a hello without the client name part')
    S(hello()); C(hello_back(b'laptop'))
    S(hello(1, 3)); C(hello_back(b'tablet', 1, 3))
    C(hello(2, 0))
    c.mark('No operation, keep alive and query screen info; client data (DINF) with screen sizes, and the options and resolution messages')
    S(msg(b'CNOP')); S(msg(b'CALV')); C(msg(b'CALV')); S(msg(b'QINF', PAD))
    C(msg(b'DINF', struct.pack('>7H', 0, 0, 1920, 1080, 0, 960, 540)))
    S(msg(b'CIAK', PAD)); S(msg(b'CROP', PAD)); S(msg(b'DSOP', struct.pack('>I', 0x12345678)))
    c.mark('Enter and leave screen (position, sequence number, modifier mask), grab clipboard and clipboard data')
    S(msg(b'CINN', struct.pack('>HHIH', 100, 200, 77, 0x0003)))
    S(msg(b'COUT', PAD))
    S(msg(b'CCLP', struct.pack('>BI', 1, 78)))
    C(msg(b'DCLP', struct.pack('>BI', 0, 79) + b'clipboard text from the synthetic client'))
    C(msg(b'DCLP', struct.pack('>BI', 1, 80) + b'x'))
    c.mark('Keyboard: key pressed, auto-repeat and released, each with and without the key button')
    S(msg(b'DKDN', struct.pack('>HHH', 0x61, 0x0002, 38)))
    S(msg(b'DKDN', struct.pack('>HH', 0x62, 0)))
    S(msg(b'DKRP', struct.pack('>HHHH', 0x61, 0x0002, 5, 38)))
    S(msg(b'DKRP', struct.pack('>HHH', 0x61, 0, 9)))
    S(msg(b'DKUP', struct.pack('>HHH', 0x61, 0x0002, 38)))
    S(msg(b'DKUP', struct.pack('>HH', 0x62, 0)))
    c.mark('Mouse: button pressed and released, absolute and relative moves, wheel, screen saver change')
    S(msg(b'DMDN', b'\x01')); S(msg(b'DMUP', b'\x01'))
    S(msg(b'DMMV', struct.pack('>HH', 640, 480))); S(msg(b'DMRM', struct.pack('>hh', 12, 0xfff0 - 0x10000)))
    S(msg(b'DMWM', struct.pack('>hh', 0, 120)))
    S(msg(b'CSEC', b'\x01'))
    c.mark('Errors and close (messages without payload carry one padding octet, see PAD): incompatible versions, connection in use, unknown client, protocol violation, an unknown packet type, close connection')
    S(msg(b'EICV', struct.pack('>HH', 1, 4)))
    S(msg(b'EBSY', PAD)); S(msg(b'EUNK', PAD)); S(msg(b'EBAD', PAD))
    S(msg(b'XXXX', b'something else'))
    C(msg(b'CBYE', PAD))
    c.mark('Reassembly: one message in three segments, and three messages (two complete and the start of a third) in one segment')
    big = msg(b'DCLP', struct.pack('>BI', 0, 81) + b'long clipboard ' * 20)
    S(big[:7]); S(big[7:100]); S(big[100:])
    a = msg(b'DMMV', struct.pack('>HH', 1, 2)); b = msg(b'DMMV', struct.pack('>HH', 3, 4)); d = msg(b'DMMV', struct.pack('>HH', 5, 6))
    S(a + b + d[:5]); S(d[5:])
    c.mark('A second connection to the same port')
    t2 = Tcp(c, 50001, 24800, '192.0.2.7', '192.0.2.8')
    t2.s2c(hello()); t2.c2s(hello_back(b'second'))
    t2.s2c(msg(b'DMMV', struct.pack('>HH', 9, 9)))

    m = Cap(1)
    tm = Tcp(m, 50002, 24800)
    m.mark('Messages shorter than the packet type, a length past the end (waits for more data), and fields cut short')
    tm.s2c(pdu(b'DMM'))
    tm.s2c(pdu(b'CINN' + b'\0\0'))
    tm.s2c(pdu(b'DINF' + b'\0' * 5))
    tm.s2c(pdu(b'DCLP' + b'\0\0'))
    tm.s2c(pdu(b'DKRP' + b'\0\0\0\0\0'))
    tm.s2c(pdu(b'Synergy' + b'\0'))
    tm.s2c(struct.pack('>I', 0xfffffffc) + b'abcd')
    tm.s2c(struct.pack('>I', 0xffffff00) + b'CBYE')
    m.mark('Messages without any payload (CBYE, COUT, CIAK, CROP, QINF, EBSY, EUNK, EBAD) and an empty clipboard: the dissector adds an item of length -1 behind the type, which throws at the end of the data')
    for typ in (b'QINF', b'CIAK', b'CROP', b'COUT', b'CBYE', b'EBSY', b'EUNK', b'EBAD'):
        tm.s2c(msg(typ))
    tm.s2c(msg(b'DCLP', struct.pack('>BI', 1, 80)))
    c.write(os.path.join(out, 'synergy-coverage.pcap'))
    m.write(os.path.join(out, 'synergy-coverage-malformed.pcap'))
    if verbose:
        for n, tx in c.marks:
            print(n, tx)
        print(len(c.frames), 'frames')

if __name__ == '__main__':
    main(sys.argv[1], '-v' in sys.argv)
