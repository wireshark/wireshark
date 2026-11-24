#!/usr/bin/env python3
# Generates test/captures/indigocare_icall_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic captures for packet-indigocare-icall.c (iCall).  The
dissector registers only for Decode As, so the tests and runcov.sh use
-d tcp.port==7000,icall and -d udp.port==7001,icall.
Usage: mkindigocare-icall.py <outdir> [-v]
Writes indigocare-icall-coverage.pcap (main) and
indigocare-icall-coverage-malformed.pcap."""
import struct
import sys
import os

ETH = bytes.fromhex('020000000002' '020000000001') + b'\x08\x00'
SOH, STX, ETX, EOT, US, RS = 1, 2, 3, 4, 0x1f, 0x1e


def cksum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


class Cap:
    def __init__(self):
        self.frames = []
        self.marks = []
        self.seq = {}
        self.ipid = 1

    def mark(self, name):
        self.marks.append((len(self.frames) + 1, name))

    def _ip(self, proto, l4):
        h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(l4), self.ipid, 0, 64,
                        proto, 0, bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2]))
        self.ipid += 1
        h = h[:10] + struct.pack('!H', cksum(h)) + h[12:]
        return ETH + h + l4

    def tcp(self, payload, sport=40000, dport=7000, flags=0x18):
        key = (sport, dport)
        seq = self.seq.get(key, 1000)
        t = struct.pack('!HHIIBBHHH', sport, dport, seq, 1, 0x50, flags, 65535, 0, 0) + payload
        self.seq[key] = seq + len(payload)
        self.frames.append(self._ip(6, t))

    def udp(self, payload, sport=40000, dport=7001):
        self.frames.append(self._ip(17, struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload))

    def write(self, path):
        with open(path, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            for i, d in enumerate(self.frames):
                f.write(struct.pack('<IIII', 1700000000 + i, 0, len(d), len(d)))
                f.write(d)


def msg(header, records, end=bytes([EOT]), pad=b''):
    """SOH header STX (id US data RS)* ETX EOT padding."""
    b = bytes([SOH]) + str(header).encode() + bytes([STX])
    for rid, data in records:
        b += str(rid).encode() + bytes([US]) + data + bytes([RS])
    return b + bytes([ETX]) + end + pad


def main_cap():
    c = Cap()
    c.mark('call_records')
    full = [(1, b'101'), (2, b'Emergency'), (3, b'Bed A'), (4, b'4711'), (5, b'Assist'),
            (6, b'Ward 3'), (7, b'Doe, John'), (8, b'Roe, Jane'), (9, b'12'), (10, b'Nurse X')]
    c.tcp(msg(10, full))                          # every record of a Call Info
    for rec in full:
        c.tcp(msg(10, [rec]))
    c.tcp(msg(10, []))                            # no records
    c.mark('call_variants')
    c.tcp(msg(10, [(1, b''), (2, b'')]))          # empty values
    c.tcp(msg(10, [(1, b'7' * 200), (7, b'n' * 300)]))
    c.tcp(msg(10, [(2, b'Call'), (1, b'9'), (6, b'Hall')]))          # other order
    c.tcp(msg(10, [(1, b'1'), (1, b'2'), (1, b'3')]))                # a record repeated
    c.tcp(msg(10, [(1, b'1')], pad=b'\0\0\0\0'))                     # padding
    c.tcp(msg(10, [(1, b'1')], pad=b'padding after EOT'))
    c.tcp(msg(10, [(1, b'unicode-free')]))
    c.mark('udp')
    c.udp(msg(10, full))
    c.udp(msg(10, [(1, b'12'), (2, b'Test')]))
    c.mark('warnings')
    c.tcp(msg(10, [(1, b'1')], end=b'\x05'))                         # no EOT: unexpected end
    c.tcp(msg(10, [(1, b'1')], end=b'\x00'))
    c.tcp(msg(10, [(99, b'who knows'), (1, b'5')]))                  # unexpected record
    c.tcp(msg(10, [(0, b'zero'), (11, b'eleven'), (255, b'big')]))
    # a rejected message (return 0) makes TCP stop offering the stream to
    # the dissector, so every one has its own connection
    c.tcp(msg(11, [(1, b'1')]), sport=40101)                         # unexpected header
    c.tcp(msg(0, [(1, b'1')]), sport=40102)
    c.tcp(msg(-5, [(1, b'1')]), sport=40103)
    c.tcp(msg(10, [(1, b'1')]).replace(bytes([ETX, EOT]), bytes([ETX, EOT]) + b'\x01'))
    c.mark('not_icall')
    c.tcp(b'\x02not an icall message', sport=40104)                  # no SOH: not dissected
    c.udp(b'\x00\x01\x02')
    return c


def malformed_cap():
    c = Cap()
    c.tcp(bytes([SOH]))                                              # SOH only
    c.tcp(bytes([SOH]) + b'10')                                      # no STX
    c.tcp(bytes([SOH]) + b'10' + bytes([STX]))                       # no ETX: reads past the end
    c.tcp(bytes([SOH]) + b'10' + bytes([STX]) + b'1')                # id only
    c.tcp(bytes([SOH]) + b'10' + bytes([STX]) + b'1' + bytes([US]))  # no RS
    c.tcp(bytes([SOH]) + b'10' + bytes([STX]) + b'1' + bytes([US]) + b'data')
    c.tcp(bytes([SOH]) + b'10' + bytes([STX]) + b'1' + bytes([US]) + b'data' + bytes([RS]))
    c.tcp(bytes([SOH]) + b'10' + bytes([STX]) + b'1' + bytes([US]) + b'data' + bytes([RS, ETX]))
    c.tcp(bytes([SOH]) + b'10' + bytes([STX]) + b'xx' + bytes([US]) + b'data' + bytes([RS, ETX, EOT]))
    c.tcp(bytes([SOH]) + b'99999999999' + bytes([STX]) + bytes([ETX, EOT]))
    c.tcp(bytes([SOH]) + b'abc' + bytes([STX]) + bytes([ETX, EOT]))
    c.tcp(bytes([SOH]) + bytes([STX]) + bytes([ETX, EOT]))
    c.tcp(bytes([SOH]) + b'10' + bytes([STX]) + b'99999999999' + bytes([US]) + b'd' + bytes([RS, ETX, EOT]))
    c.udp(bytes([SOH]) + b'10' + bytes([STX]))
    return c


def main():
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    m = main_cap()
    m.write(os.path.join(out, 'indigocare-icall-coverage.pcap'))
    x = malformed_cap()
    x.write(os.path.join(out, 'indigocare-icall-coverage-malformed.pcap'))
    if '-v' in sys.argv:
        for n, nm in m.marks:
            print(n, nm)
        print('main frames', len(m.frames), 'malformed', len(x.frames))


main()
