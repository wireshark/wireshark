#!/usr/bin/env python3
# ARINC 615A coverage capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""ARINC 615A (over TFTP) and FIND for epan/dissectors/packet-arinc615a.c.

Usage: mkarinc615a.py [<output directory>]

Writes arinc615a-coverage.pcapng (two interfaces: Ethernet and Exported
PDU) and arinc615a-coverage-malformed.pcap (Ethernet). Every packet is built
here; nothing comes from a real network.
"""

import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct

from capgen import (LINKTYPE_ETHERNET, LINKTYPE_WIRESHARK_UPPER_PDU, Pcapng,  # noqa: E402
                    eth, ipv4, udp as udp_segment, write_pcap)

LOADER = '10.6.15.1'      # data loader
TARGET = '10.6.15.20'     # target hardware
TARGET2 = '10.6.15.21'
BCAST = '255.255.255.255'
MAC = {LOADER: b'\x02\x00\x00\x00\x06\x01', TARGET: b'\x02\x00\x00\x00\x06\x14',
       TARGET2: b'\x02\x00\x00\x00\x06\x15', BCAST: b'\xff' * 6}

ip_id = [0x100]


def udp(src, sport, dst, dport, payload):
    ip_id[0] += 1
    seg = udp_segment(payload, sport, dport, src=src, dst=dst)
    return eth(ipv4(seg, 17, src=src, dst=dst, ident=ip_id[0], flags_frag=0x4000), 0x0800,
               dst=MAC[dst], src=MAC[src])


# ----------------------------------------------------------------- TFTP
def rrq(name, mode=b'octet'):
    return struct.pack('!H', 1) + name.encode() + b'\0' + mode + b'\0'


def wrq(name, mode=b'octet'):
    return struct.pack('!H', 2) + name.encode() + b'\0' + mode + b'\0'


def data(blk, d):
    return struct.pack('!HH', 3, blk) + d


def ack(blk):
    return struct.pack('!HH', 4, blk)


# ---------------------------------------------------------------- A615A
def s8(s):
    """String with a one octet length (FT_UINT_STRING, 1)."""
    if isinstance(s, str):
        s = s.encode()
    return struct.pack('B', len(s)) + s


def afile(body):
    """A protocol file: 32-bit file length (the whole file) + body."""
    return struct.pack('!I', 4 + len(body)) + body


def lui(ver, status, desc):        # also LCI, LND, LNO
    return afile(ver + struct.pack('!H', status) + s8(desc))


def lus(ver, status, desc, counter, exc, est, ratio, files):
    b = ver + struct.pack('!H', status) + s8(desc) + struct.pack('!H', counter)
    if ver != b'A1':
        b += struct.pack('!H', exc)
    b += struct.pack('!H', est) + ratio + struct.pack('!H', len(files))
    for name, pn, r, st, d in files:
        b += s8(name) + s8(pn) + r + struct.pack('!H', st) + s8(d)
    return afile(b)


def lns(ver, status, desc, counter, exc, est, ratio, files):
    b = ver + struct.pack('!H', status) + s8(desc) + struct.pack('!H', counter)
    if ver != b'A1':
        b += struct.pack('!H', exc)
    b += struct.pack('!H', est) + ratio + struct.pack('!H', len(files))
    for name, st, d in files:
        b += s8(name) + struct.pack('!H', st) + s8(d)
    return afile(b)


def lcs(ver, counter, status, exc, est, desc):
    return afile(ver + struct.pack('!HHHH', counter, status, exc, est) + s8(desc))


def lur(ver, files):
    b = ver + struct.pack('!H', len(files))
    for name, pn in files:
        b += s8(name) + s8(pn)
    return afile(b)


def lnl(ver, files):
    b = ver + struct.pack('!H', len(files))
    for name, d in files:
        b += s8(name) + s8(d)
    return afile(b)


def lnr(ver, files, user):
    b = ver + struct.pack('!H', len(files))
    for name in files:
        b += s8(name)
    return afile(b + s8(user))


def lna(ver, files):
    b = ver + struct.pack('!H', len(files))
    for name in files:
        b += s8(name)
    return afile(b)


def lcl(ver, hw):
    b = ver + struct.pack('!H', len(hw))
    for lit, sn, pns in hw:
        b += s8(lit) + s8(sn) + struct.pack('!H', len(pns))
        for pn, am, des in pns:
            b += s8(pn) + s8(am) + s8(des)
    return afile(b)


# ---------------------------------------------------------------- FIND
def find_irq():
    return struct.pack('!H', 1) + b'\0' + b'\x10'


def find_ian(thw, ttype, pos, lit, mfr):
    def z(s):
        return s.encode() + b'\0'

    return struct.pack('!H', 2) + z(thw) + z(ttype) + z(pos) + z(lit) + z(mfr) + b'\x10'


# ---------------------------------------------------------------- builder
class Cap:
    def __init__(self):
        self.pkts = []          # (interface, bytes)
        self.port = 50000

    def add(self, b, ifc=0):
        self.pkts.append((ifc, b))

    def newport(self):
        self.port += 1
        return self.port

    def read(self, name, content, server=TARGET, client=LOADER, blksize=512):
        """Client reads a file from the server (RRQ, DATA..., ACKs)."""
        cp, sp = self.newport(), self.newport()
        self.add(udp(client, cp, server, 69, rrq(name)))
        blocks = [content[i:i + blksize] for i in range(0, len(content) + 1, blksize)]
        for n, blk in enumerate(blocks, 1):
            self.add(udp(server, sp, client, cp, data(n, blk)))
            self.add(udp(client, cp, server, sp, ack(n)))

    def write(self, name, content, client=LOADER, server=TARGET, blksize=512):
        """Client writes a file to the server (WRQ, ACK 0, DATA..., ACKs).
        The server answers from port 69 (as some servers do, see Wireshark
        issue #18122): UDP finds the TFTP conversation of a request only
        for packets towards the client port, so with an RFC 1350 server
        port the DATA blocks from the client would show as plain UDP."""
        cp, sp = self.newport(), 69
        self.add(udp(client, cp, server, 69, wrq(name)))
        self.add(udp(server, sp, client, cp, ack(0)))
        blocks = [content[i:i + blksize] for i in range(0, len(content) + 1, blksize)]
        for n, blk in enumerate(blocks, 1):
            self.add(udp(client, cp, server, sp, data(n, blk)))
            self.add(udp(server, sp, client, cp, ack(n)))


def pcapng_write(fn, pkts, linktypes):
    w = Pcapng()
    for lt in linktypes:
        w.interface(lt, snaplen=65535)
    for i, (ifc, p) in enumerate(pkts):
        w.packet(ifc, p, ts=(1760000000 + i, 0))
    w.write(fn)


def pcap_write(fn, pkts):
    write_pcap(fn, [p for _, p in pkts], snaplen=65535, ts=lambda i: (1760000000 + i, 0))


def exp_pdu_heur(name, payload):
    """Exported PDU naming a heuristic dissector. The tag value is not padded
    to four octets (capgen.exported_pdu() pads), so this stays local."""
    # tag 13 = heuristic dissector name, then end of options
    return struct.pack('>HH', 13, len(name)) + name.encode() + struct.pack('>HH', 0, 0) + payload


PN = 'ACM12-3456-7890'


def main_capture():
    c = Cap()
    # FIND: Information ReQuest broadcast, two answers, an unknown opcode
    c.add(udp(LOADER, 1001, BCAST, 1001, find_irq()))
    c.add(udp(TARGET, 1001, LOADER, 1001,
              find_ian('FMC_L', 'FMC', 'LEFT', 'Flight Management Computer', 'ACM')))
    c.add(udp(TARGET2, 1001, LOADER, 1001,
              find_ian('DFDAU', 'DFDAU', '1', 'Flight Data Acquisition Unit', 'XYZ')))
    c.add(udp(LOADER, 1001, TARGET, 1001, struct.pack('!H', 7) + b'\0' + b'\x10'))

    # Uploading operation (A2), Load Uploading Initialization etc.
    c.read('FMC_L.LUI', lui(b'A2', 0x0001, 'Accepted'))
    c.write('FMC_L.LUR', lur(b'A2', [('PN1234.LUH', PN), ('PN5678.LUH', 'ACM98-7654-3210')]))
    c.write('FMC_L.LUS', lus(b'A2', 0x0002, 'Uploading', 1, 30, 120, b'010',
                             [('PN1234.LUH', PN, b'020', 0x0002, 'in progress'),
                              ('PN5678.LUH', 'ACM98-7654-3210', b'000', 0x0001, '')]),
            client=TARGET, server=LOADER)
    # A load header file: not an A615A protocol file name (shown as data)
    c.read('PN1234.LUH', afile(b'A2' + b'\0' * 40), server=LOADER, client=TARGET)
    c.write('FMC_L.LUS', lus(b'A2', 0x0004, 'CRC check', 2, 30, 60, b'050',
                             [('PN1234.LUH', PN, b'100', 0x0003, 'done')]),
            client=TARGET, server=LOADER)
    c.write('FMC_L.LUS', lus(b'A2', 0x0003, 'Completed', 3, 0, 0, b'100', []),
            client=TARGET, server=LOADER)
    # A1 Load Uploading Status: no exception timer; failure statuses
    c.read('DFDAU.LUI', lui(b'A1', 0x1000, 'Target busy'), server=TARGET2)
    c.write('DFDAU.LUS', lus(b'A1', 0x1007, 'Header load failed', 1, 0, 5, b'000',
                             [('PN9.LUH', 'XYZ-1', b'000', 0x1007, 'bad CRC')]),
            client=TARGET2, server=LOADER)
    c.write('DFDAU.LUS', lus(b'A1', 0x7777, 'Unknown status', 2, 0, 5, b'000', []),
            client=TARGET2, server=LOADER)

    # Downloading operation (media defined and operator defined)
    c.read('FMC_L.LND', lui(b'A3', 0x0001, ''))
    c.write('FMC_L.LNL', lnl(b'A3', [('FAULTS.BIN', 'Fault history'),
                                     ('TRENDS.BIN', 'Engine trends'),
                                     ('CONFIG.TXT', '')]),
            client=TARGET, server=LOADER)
    c.write('FMC_L.LNR', lnr(b'A3', ['FAULTS.BIN', 'TRENDS.BIN'], b'\x01\x02\x03'))
    c.write('FMC_L.LNS', lns(b'A3', 0x0002, 'Downloading', 1, 30, 40, b'050',
                             [('FAULTS.BIN', 0x0003, 'done'), ('TRENDS.BIN', 0x0002, '')]),
            client=TARGET, server=LOADER)
    c.write('FMC_L.LNS', lns(b'A1', 0x0003, 'Completed', 2, 0, 0, b'100',
                             [('FAULTS.BIN', 0x0003, 'done')]),
            client=TARGET, server=LOADER)
    c.read('DFDAU.LNO', lui(b'A2', 0x1002, 'Operator download not supported'), server=TARGET2)
    c.read('FMC_L.LNO', lui(b'A2', 0x0002, ''))
    c.write('FMC_L.LNA', lna(b'A2', ['FAULTS.BIN', 'CONFIG.TXT']))
    c.read('FMC_L.LND', lui(b'A2', 0x1003, 'Aborted by target'))

    # Information (configuration) operation
    c.read('FMC_L.LCI', lui(b'A2', 0x1004, 'Aborted on dataloader error'))
    c.read('DFDAU.LCI', lui(b'A2', 0x0003, ''), server=TARGET2)
    c.write('FMC_L.LCL', lcl(b'A2', [('FMC_L', 'SN000123',
                                      [(PN, 'A', 'Operational program'),
                                       ('ACM98-7654-3210', 'C', 'Navigation database')]),
                                     ('FMC_R', 'SN000124', [])]),
            client=TARGET, server=LOADER)
    c.write('FMC_L.LCS', lcs(b'A2', 1, 0x0002, 30, 10, 'Collecting'),
            client=TARGET, server=LOADER)
    c.write('FMC_L.LCS', lcs(b'A2', 2, 0x1005, 0, 0, 'Aborted by operator'),
            client=TARGET, server=LOADER)

    # Files the heuristic rejects (shown as data)
    c.read('SHORT.LUI', b'\0\0\0\x05A')                         # shorter than 6
    c.read('BADLEN.LUI', struct.pack('!I', 99) + b'A2\0\x01\0')  # length mismatch
    c.read('NOTA.LUI', struct.pack('!I', 9) + b'B2\0\x01\0')     # no 'A'
    c.read('lower.lui', lui(b'A2', 0x0001, ''))                 # suffix is case sensitive
    # DATA to port 69 with no request seen: TFTP has no file name
    c.add(udp(TARGET, 50999, LOADER, 69, data(1, lui(b'A2', 0x0001, ''))))

    # A file over two TFTP blocks: A615a only with tftp.defragment:TRUE
    many = [('FILE%03d.BIN' % i, 0x0003, 'done') for i in range(40)]
    c.write('FMC_L.LNS', lns(b'A2', 0x0003, 'Completed', 9, 0, 0, b'100', many),
            client=TARGET, server=LOADER)

    # Reproducer: Exported PDU naming the "a615a" heuristic, no TFTP data
    c.add(exp_pdu_heur('a615a', struct.pack('>I', 8) + b'A1' + b'\0\0'), ifc=1)
    return c.pkts


def malformed_capture():
    c = Cap()
    # File length matches, but the content is cut short in each file type
    trunc = [('T.LUI', b'A2\0'), ('T.LCL', b'A2\0\x05' + s8('X')),
             ('T.LCL', b'A2\0\x01' + s8('X') + s8('S') + b'\0\x04'),
             ('T.LCS', b'A2\0\x01'), ('T.LUS', b'A1\0\x01' + s8('x')),
             ('T.LUS', b'A2\0\x01' + s8('x') + b'\0\x01\0\x00\0\x00010\0\x03'),
             ('T.LNS', b'A2\0\x01' + s8('x') + b'\0\x01\0\x00\0\x00010\0\x03'),
             ('T.LUR', b'A2\0\x03' + s8('a')), ('T.LNL', b'A2\0\x02' + s8('a')),
             ('T.LNR', b'A2\0\x01' + s8('a')), ('T.LNA', b'A2\0\x09'),
             ('T.LNO', b'A2\0\x01\x20abc')]
    for name, body in trunc:
        c.read(name, afile(body))
    # FIND answer without terminators, IRQ too short
    c.add(udp(TARGET, 1001, LOADER, 1001, struct.pack('!H', 2) + b'FMC'))
    c.add(udp(LOADER, 1001, BCAST, 1001, struct.pack('!H', 1)))
    c.add(udp(LOADER, 1001, BCAST, 1001, b'\x00'))
    return c.pkts


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcapng_write(os.path.join(out, 'arinc615a-coverage.pcapng'), main_capture(),
                 [LINKTYPE_ETHERNET, LINKTYPE_WIRESHARK_UPPER_PDU])
    pcap_write(os.path.join(out, 'arinc615a-coverage-malformed.pcap'), malformed_capture())


if __name__ == '__main__':
    main()
