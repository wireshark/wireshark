#!/usr/bin/env python3
# Generates test/captures/solaredge_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the SolarEdge coverage captures: mksolaredge.py <outdir> [-v].  All data is synthetic."""
import os
import struct
import sys
from c17lib import Cap, exppdu

MAGIC = 0x79563412

def crc16(data, crc=0x5a5a):
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xa001 if crc & 1 else crc >> 1
    return crc

def pkt(cmd, payload=b'', seq=1, src=0x12345678, dst=0x0, length=None, inv=None, crc=None, nocrc=False):
    """A SolarEdge packet: magic, length, inverse length, sequence number, source and destination
    address, command, payload and CRC16 (initial value 0x5a5a over the header fields from the
    sequence number on, in network order, and the payload)."""
    n = len(payload) if length is None else length
    h = struct.pack('<IHHHIIH', MAGIC, n, (0xffff - n) & 0xffff if inv is None else inv, seq, src, dst, cmd)
    c = crc16(struct.pack('>HIIH', seq, src, dst, cmd) + payload) if crc is None else crc
    return h + payload + (b'' if nocrc else struct.pack('<H', c))

def dev(typ, devid, body):
    return struct.pack('<HIH', typ, devid, len(body)) + body

def optimizer(ts=1700000000):
    return dev(0x0000, 0x70000001, struct.pack('<IIIIIIIII', ts, 0x1000, 0, 3600, 0x40a00000, 0x41200000, 0x3f800000, 0x41f00000, 0x42200000))

def inverter1():
    f = [1700000000, 7200, 300, 0x42200000, 0x44160000, 0x43480000, 0x436e0000, 0x40a00000, 0x42480000, 0, 0, 0x43c80000, 0,
         0x4b189680, 0x3f800000, 0, 0, 0, 0x46fa0000, 0, 0, 0, 0, 0x45bb8000, 0, 0]
    assert len(f) == 26
    return dev(0x0010, 0x7f000001, struct.pack('<26I', *f))

def inverter3():
    return dev(0x0011, 0x7f000002, b'\x33' * 40)

def optimizer2(ts=1700000100, data=b'\x12\x34\x56\x78\x9a\xbc', temp=40):
    return dev(0x0080, 0x70000002, struct.pack('<IH', ts, 25) + data + bytes([temp]))

def event(kind):
    base = struct.pack('<III', 1700000200, kind, 1700000000)
    if kind == 1:
        base += struct.pack('<ii', 36000, 1700040000)
    else:
        base += struct.pack('<II', 1700040000, 0)
    return dev(0x0300, 0x70000003, base + struct.pack('<II', 0, 0))

def unknown(devtype=0x1234, n=12):
    return dev(devtype, 0x1, b'\x44' * n)

def main(out, verbose):
    c = Cap(252)
    def add(p):
        c.add(exppdu('solaredge', p))
    c.mark('Commands without a decoded payload: parameter, upgrade, misc, response, Mercury, VenusMngr and other commands, an unknown command, with payloads of 0 to 40 octets')
    cmds = (0x0010, 0x0011, 0x0012, 0x0016, 0x0019, 0x001d, 0x0020, 0x0021, 0x0023, 0x0031, 0x0033, 0x0035, 0x0037, 0x0039,
            0x0040, 0x0042, 0x0080, 0x0081, 0x0090, 0x0094, 0x0095, 0x00a0, 0x00b0, 0x00b3, 0x00b4,
            0x0100, 0x0103, 0x0107, 0x010e, 0x0118, 0x012b, 0x0180, 0x0183, 0x0188,
            0x0200, 0x0206, 0x020e, 0x0218, 0x0300, 0x0500, 0x7777)
    for i, cmd in enumerate(cmds):
        add(pkt(cmd, bytes(range(i % 41)), seq=i + 1, src=0x11111111 * (i % 3 + 1), dst=0x22222222 * (i % 2)))
    c.mark('POST_DATA with one device record of each type: optimizer, single phase inverter, three phase inverter (not decoded), second optimizer format, wake/sleep event of both kinds, unknown device')
    for r in (optimizer(), inverter1(), inverter3(), optimizer2(), event(1), event(0), unknown(), unknown(0x0012, 0)):
        add(pkt(0x0500, r))
    c.mark('POST_DATA with several device records (the list is followed to its end) and one with 50 records of 8 octets (the recursion reproducer)')
    add(pkt(0x0500, optimizer() + optimizer2() + event(1)))
    add(pkt(0x0500, inverter1() + inverter1() + optimizer() + unknown() + optimizer2(ts=5) + event(0) + event(1)))
    add(pkt(0x0500, b''.join(dev(0x2000 + i, i, b'') for i in range(50))))
    add(pkt(0x0500, b''))
    c.mark('Encrypted packets (the payload is opaque filler bytes; no key is configured so they stay undecoded), the session key message (filler; no system key is configured) and a packet with unknown fields shown')
    add(pkt(0x003d, bytes(range(1, 41)), seq=100))
    add(pkt(0x003d, b'\xee' * 22, seq=101))
    add(pkt(0x003d, b'', seq=102))
    add(pkt(0x0503, b'\x66' * 32, seq=103))
    add(pkt(0x0503, b'\x66' * 40, seq=104))
    c.mark('Packets with data after the first packet in the same frame are not split: a packet followed by trailing octets')
    add(pkt(0x0011, b'abc') + b'\xaa' * 7)

    m = Cap(252)
    def madd(p):
        m.add(exppdu('solaredge', p))
    m.mark('Wrong CRC, wrong inverse length (expert infos) and a length that is larger than the frame')
    madd(pkt(0x0011, b'abcd', crc=0x1234))
    madd(pkt(0x0011, b'abcd', inv=0x1234))
    madd(pkt(0x0011, b'abcd', length=400))
    madd(pkt(0x0500, optimizer(), crc=0x4321))
    m.mark('POST_DATA records cut short, device lengths past the end, header only, an OPTIMIZER2 record whose data ends the frame (the one octet over-read) also in a 2048 octet record')
    madd(pkt(0x0500, optimizer()[:20]))
    madd(pkt(0x0500, inverter1()[:50]))
    madd(pkt(0x0500, event(1)[:30]))
    madd(pkt(0x0500, struct.pack('<HIH', 0x0000, 1, 60000) + b'\0' * 4))
    madd(pkt(0x0500, struct.pack('<HIH', 0x0011, 1, 60000) + b'\0' * 4))
    madd(pkt(0x0500, b'\x01\x02\x03'))
    madd(pkt(0x0500, optimizer2()[:8 + 4 + 2 + 6], nocrc=True))
    madd(pkt(0x0500, optimizer2()[:8 + 4 + 2 + 6]))
    madd(pkt(0x0500, optimizer2()[:8 + 4 + 2 + 3]))
    m.mark('Header cut short and wrong magic number')
    full = pkt(0x0011, b'abcd')
    for n in (0, 3, 4, 6, 10, 19):
        madd(full[:n])
    madd(b'\x00\x00\x00\x00' + full[4:])
    # the over-read reproducer: a frame of exactly 2048 octets, see packet-solaredge.c OPTIMIZER2
    pl = pkt(0x0500, optimizer2()[:8 + 4 + 2 + 6], nocrc=True)
    n = exppdu('solaredge', b'')
    pad = 2048 - len(n) - len(pl) - 4
    m.add(struct.pack('>HH', 12, 12) + b'solaredge\0\0\0' + struct.pack('>HH', 0x7fff, 2048 - 16 - 4 - 4 - len(pl)) + b'\0' * (2048 - 16 - 4 - 4 - len(pl)) + struct.pack('>HH', 0, 0) + pl)
    assert len(m.frames[-1]) == 2048
    c.write(os.path.join(out, 'solaredge-coverage.pcap'))
    m.write(os.path.join(out, 'solaredge-coverage-malformed.pcap'))
    if verbose:
        for n, tx in c.marks:
            print(n, tx)
        print(len(c.frames), 'frames')

if __name__ == '__main__':
    main(sys.argv[1], '-v' in sys.argv)
