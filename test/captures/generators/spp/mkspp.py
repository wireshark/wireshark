#!/usr/bin/env python3
# Generates test/captures/spp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the SPP coverage captures: mkspp.py <outdir> [-v].  All data is synthetic."""
import os
import struct
import sys
from c17lib import Cap, eth

IDP_SPP = 5
SMB_SOCKET = 0x0bbc

def idp(ptype, payload, dsock, ssock, dnet=0x11, snet=0x22, hops=0, length=None, ck=0xffff):
    n = 30 + len(payload) if length is None else length
    return struct.pack('>HHBBI', ck, n, hops, ptype, dnet) + b'\x02\0\0\0\0\x02' + struct.pack('>H', dsock) \
        + struct.pack('>I', snet) + b'\x02\0\0\0\0\x01' + struct.pack('>H', ssock) + payload

def spp(ctl, dstype, src, dst, seq, ack, alloc, data=b''):
    return struct.pack('>BBHHHHH', ctl, dstype, src, dst, seq, ack, alloc) + data

def frame(payload):
    return eth(payload, 0x0600)

def smb_header():
    """A bare SMB Echo request header (32 octets) plus an empty parameter and data block."""
    return b'\xffSMB' + bytes([0x2b]) + struct.pack('<I', 0) + bytes([0x18]) + struct.pack('<HH', 0xc801, 0) + b'\0' * 8 + struct.pack('<HHHH', 0, 0xfffe, 1000, 1) + b'\x01\x01\0\0\0\0\0'

def main(out, verbose):
    c = Cap(1)
    def add(ctl, dstype, data=b'', src=0x1111, dst=0x2222, seq=1, ack=1, alloc=3, dsock=0x4000, ssock=0x4001, **kw):
        c.add(frame(idp(IDP_SPP, spp(ctl, dstype, src, dst, seq, ack, alloc, data), dsock, ssock, **kw)))
    c.mark('Every connection control value (data, end of message, attention, ack required, send ack with end of message, system packet, system packet with send ack) without payload')
    for ctl in (0x00, 0x10, 0x20, 0x40, 0x50, 0x80, 0xc0):
        add(ctl, 0, seq=ctl + 1)
    c.mark('Other flag combinations (unknown description) and datastream types 0, 1, 0xfe (end of connection) and 0xff (end of connection acknowledgment)')
    add(0x30, 0); add(0xe0, 7); add(0x60, 0)
    add(0x00, 0xfe); add(0x80, 0xff); add(0x40, 1)
    c.mark('Data with sequence, acknowledgment and allocation numbers, sockets in both directions (the lower socket is tried first)')
    add(0x10, 0, b'payload one', seq=10, ack=20, alloc=30, dsock=0x0452, ssock=0x4002)
    add(0x10, 0, b'payload two', seq=11, ack=21, alloc=31, dsock=0x4003, ssock=0x0452)
    add(0x00, 0, b'x' * 400, seq=12, ack=22, alloc=32)
    c.mark('Payload for the SMB socket (the socket table of SPP), as destination and as source, and as the higher of the two sockets (the lower one is tried first)')
    add(0x10, 0, smb_header(), dsock=SMB_SOCKET, ssock=0x4004)
    add(0x10, 0, smb_header(), dsock=0x4005, ssock=SMB_SOCKET)
    add(0x10, 0, smb_header(), dsock=SMB_SOCKET, ssock=0x0010)
    c.mark('IDP with other packet types (RIP, echo, error, PEP, PUP lookup) that do not reach SPP, and a hop count')
    for t in (1, 2, 3, 4, 6):
        c.add(frame(idp(t, b'idp payload %d' % t, 0x1000, 0x1001, hops=t)))

    m = Cap(1)
    m.mark('SPP header cut short at every field, and an IDP length longer than the packet')
    full = idp(IDP_SPP, spp(0x10, 0, 1, 2, 3, 4, 5, b'data'), 0x4000, 0x4001)
    for n in (30, 31, 32, 33, 37, 41):
        m.add(frame(full[:n]))
    m.add(frame(idp(IDP_SPP, spp(0x10, 0, 1, 2, 3, 4, 5, b'data'), 0x4000, 0x4001, length=200)))
    m.add(frame(idp(IDP_SPP, spp(0x10, 0, 1, 2, 3, 4, 5, b'data'), 0x4000, SMB_SOCKET)[:50]))
    c.write(os.path.join(out, 'spp-coverage.pcap'))
    m.write(os.path.join(out, 'spp-coverage-malformed.pcap'))
    if verbose:
        for n, tx in c.marks:
            print(n, tx)
        print(len(c.frames), 'frames')

if __name__ == '__main__':
    main(sys.argv[1], '-v' in sys.argv)
