#!/usr/bin/env python3
# Generates test/captures/indigocare_netrix_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic captures for packet-indigocare-netrix.c (Netrix).  The
dissector registers only for Decode As, so the tests and runcov.sh use
-d tcp.port==7010,netrix.
Usage: mkindigocare-netrix.py <outdir> [-v]
Writes indigocare-netrix-coverage.pcap (main) and
indigocare-netrix-coverage-malformed.pcap."""
import struct
import sys
import os

ETH = bytes.fromhex('020000000002' '020000000001') + b'\x08\x00'
SOH, STX, ETX, EOT, ACK, US, RS = 1, 2, 3, 4, 6, 0x1f, 0x1e
SYSTEMINFO, GROUP, PROFILE, GET_CT, SEARCH_CT, BOSCH = 1, 10, 15, 0x23, 0x24, 0x69
GET_CT_BEGIN, GET_CT_END, GET_CT_NONE = 0x88B8, 0x8C9E, 0x8C9F
SEARCH_CT_BEGIN, SEARCH_CT_END, SEARCH_CT_NONE = 0x8CA0, 0x9086, 0x9087


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

    def tcp(self, payload, sport=40000, dport=7010, flags=0x18):
        key = (sport, dport)
        seq = self.seq.get(key, 1000)
        t = struct.pack('!HHIIBBHHH', sport, dport, seq, 1, 0x50, flags, 65535, 0, 0) + payload
        self.seq[key] = seq + len(payload)
        h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(t), self.ipid, 0, 64, 6, 0,
                        bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2]))
        self.ipid += 1
        h = h[:10] + struct.pack('!H', cksum(h)) + h[12:]
        self.frames.append(ETH + h + t)

    def write(self, path):
        with open(path, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            for i, d in enumerate(self.frames):
                f.write(struct.pack('<IIII', 1700000000 + i, 0, len(d), len(d)))
                f.write(d)


def msg(header, records, end=bytes([ETX]), tail=bytes([EOT])):
    """SOH header STX (id US data RS)* ETX [EOT]."""
    b = bytes([SOH]) + str(header).encode() + bytes([STX])
    for rid, data in records:
        b += str(rid).encode() + bytes([US]) + data + bytes([RS])
    return b + end + tail


def main_cap():
    c = Cap()
    c.mark('ack')
    c.tcp(bytes([ACK]))
    c.tcp(bytes([ACK, ACK]), sport=40100)                                   # two octets: not the Ack case
    c.mark('systeminfo')
    c.tcp(msg(SYSTEMINFO, [(1, b'NETRIX01'), (2, b'192.0.2.5'), (3, b'7.2.1'), (4, b'1')]))
    for rec in ((1, b'host'), (2, b'192.0.2.9'), (3, b'1.0'), (4, b'0'), (9, b'x')):
        c.tcp(msg(SYSTEMINFO, [rec]))
    c.mark('group')
    c.tcp(msg(GROUP, [(1, b'12'), (2, b'Alarm'), (3, b'Add'), (4, b'B-7'), (5, b'Group 12'),
                      (6, b'Room 9'), (7, b'West wing')]))
    for rec in ((1, b'3'), (2, b't'), (3, b'a'), (4, b'i'), (5, b'n'), (6, b'r'), (7, b'l'),
                (8, b'?'), (1, b'notanumber')):
        c.tcp(msg(GROUP, [rec]))
    c.mark('profile')
    c.tcp(msg(PROFILE, [(1, b'5'), (2, b'Nurse'), (3, b'Add'), (4, b'P-1'), (5, b'Profile 5'),
                        (6, b'Room 2'), (7, b'East wing')]))
    for rec in ((1, b'8'), (2, b't'), (3, b'a'), (4, b'i'), (5, b'n'), (6, b'r'), (7, b'l'),
                (8, b'?'), (1, b'-1')):
        c.tcp(msg(PROFILE, [rec]))
    c.mark('conversiontables')
    c.tcp(msg(GET_CT, [(1, b'Rooms')]))
    c.tcp(msg(GET_CT, [(2, b'other')]))                        # unknown record: not shown
    c.tcp(msg(GET_CT_NONE, []))
    c.tcp(msg(GET_CT_BEGIN, [(1, b'k1'), (2, b'v1')]))
    c.tcp(msg(GET_CT_BEGIN + 7, [(1, b'k2'), (2, b'v2'), (3, b'extra')]))
    c.tcp(msg(GET_CT_END, [(1, b'last'), (2, b'one')]))
    c.tcp(msg(SEARCH_CT, [(1, b'key')]))
    c.tcp(msg(SEARCH_CT, [(2, b'other')]))
    c.tcp(msg(SEARCH_CT_NONE, []))
    c.tcp(msg(SEARCH_CT_BEGIN, [(1, b'Rooms')]))
    c.tcp(msg(SEARCH_CT_BEGIN + 99, [(1, b'Beds'), (7, b'x')]))
    c.tcp(msg(SEARCH_CT_END, [(1, b'Last')]))
    c.mark('bosch')
    c.tcp(msg(BOSCH, [(1, b'ignored'), (2, b'records')]))
    c.tcp(msg(BOSCH, []))
    c.mark('framing')
    c.tcp(msg(GROUP, [(1, b'1')], tail=b''))                   # ETX last
    c.tcp(msg(GROUP, [(1, b'1')], tail=bytes([EOT]) + b'trailing'), sport=40104)   # does not end in ETX/EOT: rejected
    c.tcp(msg(SYSTEMINFO, []))
    c.tcp(msg(SYSTEMINFO, [(1, b'')]))
    c.mark('warnings')
    c.tcp(msg(5, [(1, b'1')]))                                 # unexpected header 5
    c.tcp(msg(0, [(1, b'1'), (2, b'2')]))
    c.tcp(msg(GET_CT_BEGIN - 1, [(1, b'1')]))
    c.tcp(msg(40000, [(1, b'1')]))
    c.tcp(msg(SEARCH_CT_NONE + 1, [(1, b'1')]))
    c.mark('not_netrix')
    # a rejected message makes TCP stop offering the stream to the dissector
    c.tcp(b'\x02not a netrix message' + bytes([ETX]), sport=40101)    # no SOH
    c.tcp(bytes([SOH]) + b'1' + bytes([STX]) + bytes([ETX]) + b'junk', sport=40102)   # bad ending
    c.tcp(bytes([SOH]) + b'abc' + bytes([STX]) + bytes([ETX, EOT]), sport=40103)     # header not a number
    return c


def malformed_cap():
    c = Cap()
    c.tcp(bytes([SOH, ETX]))
    c.tcp(bytes([SOH]) + b'10' + bytes([STX, ETX]))            # ETX only, no EOT needed
    c.tcp(bytes([SOH]) + b'10' + bytes([STX]) + b'1' + bytes([US]) + b'x' + bytes([RS, ETX, EOT]) + b'x')
    c.tcp(bytes([SOH]) + b'10' + bytes([STX, 0x20, ETX, EOT]))
    c.tcp(bytes([SOH]) + b'10' + bytes([STX]) + b'1' + bytes([US]) + b'x')
    c.tcp(bytes([SOH]) + b'10' + bytes([STX]) + b'1' + bytes([US]) + b'x' + bytes([RS]) + b'1' + bytes([ETX, EOT]))
    c.tcp(bytes([SOH]) + b'10' + bytes([STX]) + b'1' + bytes([ETX, EOT]))
    c.tcp(bytes([SOH]) + b'10' + bytes([STX]) + b'99999999999' + bytes([US]) + b'x' + bytes([RS, ETX, EOT]))
    c.tcp(bytes([SOH]) + b'99999999999' + bytes([STX, ETX, EOT]))
    c.tcp(bytes([SOH]) + b'10')
    c.tcp(bytes([SOH]) + b'10' + bytes([STX]))
    c.tcp(bytes([SOH]) + b'35000' + bytes([STX]) + b'1' + bytes([US]) + b'x' + bytes([RS]))
    c.tcp(bytes([SOH]) + b'35000' + bytes([STX]) + b'1' + bytes([US]) + b'x' + bytes([RS, ETX]))
    c.tcp(bytes([SOH]) + b'1' + bytes([STX]) + b'1' + bytes([US]) + b'x' + bytes([RS]))
    c.tcp(bytes([SOH]))
    c.tcp(bytes([SOH, STX]))
    return c


def main():
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    m = main_cap()
    m.write(os.path.join(out, 'indigocare-netrix-coverage.pcap'))
    x = malformed_cap()
    x.write(os.path.join(out, 'indigocare-netrix-coverage-malformed.pcap'))
    if '-v' in sys.argv:
        for n, nm in m.marks:
            print(n, nm)
        print('main frames', len(m.frames), 'malformed', len(x.frames))


main()
