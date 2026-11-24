#!/usr/bin/env python3
# Generates test/captures/rdp_dr_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic RDP device redirection (MS-RDPEFS) captures for packet-rdp_dr.c.
# Usage: mkrdpdr.py <outdir> [-v]
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from rdplib import Cap, Session
from dvclib import create_req, data, data_first

OUT = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('-') else '.'
VERBOSE = '-v' in sys.argv

CORE, PRN = 0x4472, 0x5052
SCARD_CODES = [0x00090014, 0x00090018, 0x0009001C, 0x00090020, 0x00090024, 0x00090028, 0x0009002C, 0x00090050,
               0x00090054, 0x00090058, 0x0009005C, 0x00090060, 0x00090064, 0x00090068, 0x0009006C, 0x00090070,
               0x00090074, 0x00090078, 0x0009007C, 0x00090098, 0x0009009C, 0x000900A0, 0x000900A4, 0x000900A8,
               0x000900AC, 0x000900B0, 0x000900B4, 0x000900B8, 0x000900BC, 0x000900C0, 0x000900C4, 0x000900C8,
               0x000900CC, 0x000900D0, 0x000900D4, 0x000900D8, 0x000900DC, 0x000900E0, 0x000900E8, 0x000900EC,
               0x000900F0, 0x000900F4, 0x000900F8, 0x000900FC, 0x00090100, 0x000900E4, 0x00090104, 0x00090108,
               0x00090777]


def hdr(comp, pid, body=b''):
    return struct.pack('<HH', comp, pid) + body


def dev(t, i, name, data=b''):
    return struct.pack('<II', t, i) + name.ljust(8, b'\0') + struct.pack('<I', len(data)) + data


def caps(sets, pid=0x5350):
    body = struct.pack('<HH', len(sets), 0)
    for t, v, extra in sets:
        d = struct.pack('<I', v) + extra
        body += struct.pack('<HH', t, len(d) + 4) + d
    return hdr(CORE, pid, body)


def general(v):
    g = struct.pack('<IIHHIIIII', 0x10, 0x0a0000, 1, 0xd, 0xffff, 0x7, 0x1, 0, 0)
    if v == 2:
        g += struct.pack('<I', 3)
    return (1, v, g)


def ioreq(devid, fid, cid, major, minor, body=b''):
    return hdr(CORE, 0x4952, struct.pack('<IIIII', devid, fid, cid, major, minor) + body)


def ioctl(code, ndr=b'', out=64, inp=None):
    return struct.pack('<III', out, len(ndr) if inp is None else inp, code) + bytes(20) + ndr


def iocompl(devid, cid, status, body=b''):
    return hdr(CORE, 0x4943, struct.pack('<III', devid, cid, status) + body)


def ndr(n=200):
    return bytes(16) + bytes(n)           # common type header + zero structure


def build_main():
    cap = Cap()
    s = Session(cap, 50000, ['rdpdr', 'drdynvc'], msgchan=True)
    S = lambda p: s.chan('rdpdr', p, False)
    C = lambda p: s.chan('rdpdr', p, True)
    S(hdr(CORE, 0x496e, struct.pack('<HHI', 1, 12, 7)))                          # server announce
    C(hdr(CORE, 0x4343, struct.pack('<HHI', 1, 12, 7)))                          # client id confirm
    C(hdr(CORE, 0x434e, struct.pack('<III', 1, 0, 8) + b'CLIENT\0\0'))           # client name
    S(caps([general(1), (2, 1, b''), (3, 1, b''), (4, 1, b''), (5, 1, b''), (0x77, 1, b'')]))
    C(caps([general(2), (2, 1, b''), (4, 1, b''), (5, 1, b'')], pid=0x4350))
    S(hdr(CORE, 0x4343, struct.pack('<HHI', 1, 12, 7)))
    C(hdr(CORE, 0x4441, struct.pack('<I', 5) + dev(8, 1, b'C:', b'drive c') + dev(0x20, 2, b'SCARD') +
          dev(4, 3, b'PRN1', bytes(8)) + dev(1, 4, b'COM1') + dev(2, 5, b'LPT1')))   # device list announce
    C(hdr(CORE, 0x4441, struct.pack('<I', 0)))                                   # empty list
    S(hdr(CORE, 0x6472, struct.pack('<II', 1, 0)))                               # device reply, known device
    S(hdr(CORE, 0x6472, struct.pack('<II', 99, 0xc0000001)))                     # unknown device
    S(hdr(CORE, 0x554c))                                                         # user logged on
    S(hdr(CORE, 0x444d, struct.pack('<II', 1, 5)))                               # device list remove
    S(hdr(CORE, 0x7777))                                                         # unknown packet id
    # file system I/O
    for i, (major, minor) in enumerate(((0, 0), (2, 0), (3, 0), (4, 0), (0xa, 0), (0xb, 0), (5, 0), (6, 0), (0xc, 1),
                                        (0xc, 2), (0x11, 0), (0x77, 0))):
        S(ioreq(1, 0x20 + i, 0x100 + i, major, minor, bytes(32)))
        C(iocompl(1, 0x100 + i, 0, b'\x01' if major == 0 else b''))              # create info only for IRP_MJ_CREATE
    S(ioreq(1, 0x40, 0x200, 0xe, 0, struct.pack('<III', 32, 8, 0x00090000) + bytes(20) + bytes(8)))   # device control on a drive
    C(iocompl(1, 0x200, 0))
    S(ioreq(99, 0x40, 0x201, 3, 0, bytes(32)))                                   # unknown device
    C(iocompl(99, 0x201, 0))
    C(iocompl(1, 0x999, 0))                                                      # completion of an unknown request
    C(iocompl(1, 0x100, 0, b''))                                                 # create completion without the info octet
    # smartcard
    for i, code in enumerate(SCARD_CODES):
        S(ioreq(2, 0x50, 0x300 + i, 0xe, 0, ioctl(code, ndr() if code != 0x000900E0 else struct.pack('<I', 0))))
        C(iocompl(2, 0x300 + i, 0, ndr() if code != 0x000900E0 else bytes(16 + 8)))
    S(ioreq(2, 0x50, 0x400, 3, 0, bytes(32)))                                    # smartcard, not a device control
    C(iocompl(2, 0x400, 0))
    # printers
    S(hdr(PRN, 0x5543, struct.pack('<I', 3)))                                    # XPS, known device
    S(hdr(PRN, 0x5543, struct.pack('<I', 44)))                                   # XPS, unknown device
    pn, dn, nm = 'PNP'.encode('utf-16le'), 'Driver'.encode('utf-16le'), 'Printer 1'.encode('utf-16le')
    S(hdr(PRN, 0x5043, struct.pack('<I', 1) + b'PRN1'.ljust(8, b'\0') + struct.pack('<IIII', len(pn), len(dn), len(nm), 4)
          + pn + dn + nm + b'\1\2\3\4'))
    for ev in (2, 3, 4, 9):
        S(hdr(PRN, 0x5043, struct.pack('<I', ev) + bytes(12)))
    S(hdr(PRN, 0x7777))
    S(hdr(0x7777, 0x1234))                                                       # unknown component
    s.chunks('rdpdr', hdr(CORE, 0x4441, struct.pack('<I', 20) + b''.join(dev(8, 10 + i, ('D%d:' % i).encode(), bytes(40)) for i in range(20))), size=300)
    # dynamic channel "rdpdr"
    S2 = lambda p: s.chan('drdynvc', p, False)
    S2(create_req(9, 'rdpdr'))
    S2(data(9, hdr(CORE, 0x496e, struct.pack('<HHI', 1, 12, 7))))
    S2(data_first(9, 8, hdr(CORE, 0x554c)))
    S2(data(9, bytes(4)))
    cookie = bytes(range(16))                                        # the UDP side finds the session of the TCP connection
    s.msg(struct.pack('<HH', 0x0002, 0) + struct.pack('<IHH', 0x55667788, 2, 0) + cookie)
    cap.exp('rdpmt', struct.pack('<BHB', 0, 24, 4) + struct.pack('<II', 0x55667788, 0) + cookie, True, sport=50050, pt=3)
    cap.exp('rdpdr', hdr(CORE, 0x6472, struct.pack('<II', 1, 0)), False, sport=50050, pt=3)
    cap.write(os.path.join(OUT, 'rdpdr-coverage.pcapng'))
    if VERBOSE:
        print('rdpdr-coverage.pcapng', len(cap.frames), 'frames')


def build_malformed():
    cap = Cap()
    s = Session(cap, 50000, ['rdpdr'])
    S = lambda p: s.chan('rdpdr', p, False)
    S(b'\x72\x44')
    # the reproducer of the device list wrap: deviceCount 0xFFFFFFFF and deviceDataLen that moves the offset back
    S(struct.pack('<HHI', CORE, 0x4441, 0xFFFFFFFF) + struct.pack('<II', 0x20, 1) + b'SCARD\0\0\0' + struct.pack('<I', (-20) & 0xffffffff))
    S(hdr(CORE, 0x4441, struct.pack('<I', 2) + dev(8, 1, b'C:')))                  # second device missing
    S(hdr(CORE, 0x4441, struct.pack('<I', 1) + dev(8, 1, b'C:', bytes(10))[:-5]))
    S(caps([general(1)])[:20])
    S(hdr(CORE, 0x5350, struct.pack('<HH', 3, 0) + struct.pack('<HH', 1, 400)))
    S(hdr(CORE, 0x4952, bytes(8)))
    S(ioreq(1, 1, 1, 0xe, 0, bytes(6)))
    S(hdr(PRN, 0x5043, struct.pack('<I', 1) + bytes(10)))
    S(hdr(PRN, 0x5043, struct.pack('<I', 1) + b'PRN1'.ljust(8, b'\0') + struct.pack('<IIII', 1000, 1000, 1000, 1000)))
    S(hdr(CORE, 0x4943, bytes(5)))
    S(hdr(CORE, 0x6472, bytes(3)))
    S(hdr(PRN, 0x5543))
    s.chan('rdpdr', hdr(CORE, 0x4441, struct.pack('<I', 1) + dev(0x20, 2, b'SCARD')), True)
    s.chan('rdpdr', ioreq(2, 1, 0x10, 0xe, 0, ioctl(0x00090014, ndr(4))), False)
    s.chan('rdpdr', ioreq(2, 1, 0x11, 0xe, 0, ioctl(0x000900D0, bytes(30))), False)
    s.chan('rdpdr', iocompl(2, 0x10, 0, bytes(20)), True)
    s.chan('rdpdr', iocompl(2, 0x11, 0, bytes(20)), True)
    cap.write(os.path.join(OUT, 'rdpdr-coverage-malformed.pcapng'))


if __name__ == '__main__':
    build_main()
    build_malformed()
