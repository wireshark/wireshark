#!/usr/bin/env python3
# Generates test/captures/armagetronad_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the Armagetronad dissector
(packet-armagetronad.c).

All packets are built from scratch with struct; no captured traffic is
used. A game client (192.0.2.1, 2001:db8::1) talks to a server
(192.0.2.2, 2001:db8::2) on UDP ports 4533 and 4534, which the dissector
registers by default.

Usage: mkarmagetronad.py <output directory>

Writes:
  armagetronad-coverage.pcap            every descriptor, ACKs, unknown
                                        descriptors, empty messages, the
                                        "No message" reproducer, packets
                                        the dissector turns down
  armagetronad-coverage-malformed.pcap  packets that end in an exception
"""

import os
import struct
import sys

CLIENT4, SERVER4 = bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2])
CLIENT6 = bytes.fromhex('20010db8000000000000000000000001')
SERVER6 = bytes.fromhex('20010db8000000000000000000000002')

DESCRIPTORS = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 20, 21, 22, 23, 24, 25, 26,
               27, 28, 40, 41, 50, 51, 52, 53, 54, 55, 60, 200, 201, 202, 203,
               210, 220, 230, 231, 232, 233, 300, 310, 311, 320, 321, 330, 331,
               340]


def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


class Pcap:
    def __init__(self):
        self.frames = []

    def udp(self, sport, dport, payload, v6=False, reverse=False, caplen=None):
        if v6:
            src, dst = (SERVER6, CLIENT6) if reverse else (CLIENT6, SERVER6)
        else:
            src, dst = (SERVER4, CLIENT4) if reverse else (CLIENT4, SERVER4)
        ulen = 8 + len(payload)
        if v6:
            pseudo = struct.pack('>16s16sIxxxB', src, dst, ulen, 17)
        else:
            pseudo = struct.pack('>4s4sBBH', src, dst, 0, 17, ulen)
        c = csum(pseudo + struct.pack('>HHHH', sport, dport, ulen, 0) + payload) or 0xffff
        udp = struct.pack('>HHHH', sport, dport, ulen, c) + payload
        if v6:
            ip = struct.pack('>IHBB16s16s', 0x60000000, len(udp), 17, 64, src, dst)
            eth = b'\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x86\xdd'
        else:
            ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(udp),
                             len(self.frames) & 0xffff, 0, 64, 17, 0, src, dst)
            ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
            eth = b'\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x08\x00'
        if reverse:
            eth = eth[6:12] + eth[0:6] + eth[12:]
        self.frames.append((eth + ip + udp, caplen))

    def write(self, path):
        out = [struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1)]
        t = 1700000000
        for i, (f, caplen) in enumerate(self.frames):
            cap = f if caplen is None else f[:14 + 20 + 8 + caplen]
            out.append(struct.pack('<IIII', t + i // 100, (i % 100) * 10000,
                                   len(cap), len(f)) + cap)
        with open(path, 'wb') as fh:
            fh.write(b''.join(out))


def msg(descriptor, message_id, data=b''):
    """A message: DescriptorID, MessageID, DataLen (in shorts), Data."""
    assert len(data) % 2 == 0
    return struct.pack('>HHH', descriptor, message_id, len(data) // 2) + data


def ack(*ids):
    """An ACK: descriptor 1, no real MessageID, the acked IDs as data."""
    return msg(1, 0, b''.join(struct.pack('>H', i) for i in ids))


def packet(sender, *messages):
    return b''.join(messages) + struct.pack('>H', sender)


def main_capture():
    p = Pcap()
    # 1: the reproducer of the fix: no message, only the SenderID
    #    (armagetronad_empty_info.py), port 4534 both ways
    p.udp(4534, 4534, b'\x12\x34')
    # 2: the same from the server, port 4533 (sender 0x0000)
    p.udp(4533, 4533, packet(0x0000), reverse=True)
    # 3: login1 from the client, 4: login_accept and version from the server
    p.udp(40000, 4534, packet(0x0000, msg(6, 0x0001, b'\x00\x01\x00\x02')))
    p.udp(4534, 40000, packet(0x0000, msg(5, 0x0100, b'\x00\x03\x00\x00'),
                              msg(10, 0x0101, b'\x00\x14\x00\x15')), reverse=True)
    # 5: an ACK of three messages, 6: an ACK of none
    p.udp(40000, 4534, packet(0x0003, ack(0x0100, 0x0101, 0x0102)))
    p.udp(40000, 4534, packet(0x0003, ack()))
    # 7-11: every known descriptor, ten per packet, with 0 to 9 shorts of data
    for start in range(0, len(DESCRIPTORS), 10):
        ms = [msg(d, 0x0200 + start + i, bytes(range(2 * (i % 10))))
              for i, d in enumerate(DESCRIPTORS[start:start + 10])]
        p.udp(4534, 40000, packet(0x0000, *ms), reverse=True)
    # 12: unknown descriptors (0, 12, 999, 0xffff) among known ones
    p.udp(40000, 4534, packet(0x0003, msg(0, 0x0300), msg(200, 0x0301, b'hi'),
                              msg(12, 0x0302, b'\xde\xad'), msg(999, 0x0303),
                              msg(0xffff, 0xffff, b'\xff' * 4)))
    # 13: a chat message with longer data, 14: an ACK and a message
    p.udp(40000, 4534, packet(0x0003, msg(203, 0x0304, b'hello, world!\0\0\0')))
    p.udp(4534, 40000, packet(0x0000, ack(0x0304), msg(320, 0x0400, b'\x01\x02' * 20)),
          reverse=True)
    # 15-16: over IPv6
    p.udp(40001, 4533, packet(0x0007, msg(2, 0x0001)), v6=True)
    p.udp(4533, 40001, packet(0x0000, ack(0x0001), msg(51, 0x0010, b'\x00' * 8)),
          v6=True, reverse=True)
    # 17-21: turned down by the dissector, left as UDP data: an empty
    # payload, a single octet, a DataLen past the end, a message followed
    # by one octet instead of the SenderID, a message without a SenderID
    p.udp(40000, 4534, b'')
    p.udp(40000, 4534, b'\x01')
    p.udp(40000, 4534, msg(6, 0x0005)[:4] + b'\x00\x10' + b'\x00' * 6)
    p.udp(40000, 4534, msg(6, 0x0005, b'\x00\x01') + b'\x00')
    p.udp(40000, 4534, msg(6, 0x0005, b'\x00\x01'))
    # 22: data cut by the snapshot length: turned down (captured data is
    # checked)
    p.udp(40000, 4534, packet(0x0003, msg(200, 0x0306, b'x' * 40)), caplen=20)
    # 23: logout
    p.udp(40000, 4534, packet(0x0003, msg(7, 0x0307)))
    return p


def malformed_capture():
    p = Pcap()
    # 1-3: three, four and five octets: DataLen is read past the end
    for n in (3, 4, 5):
        p.udp(40000, 4534, b'\x00\x06\x00\x01\x00'[:n])
    # 4: a message, then four octets
    p.udp(40000, 4534, msg(6, 0x0001, b'\x00\x01') + b'\x00\x06\x00\x02')
    # 5: a message and three octets after the SenderID: the next DataLen
    # is read past the end
    p.udp(40000, 4534, msg(6, 0x0005, b'\x00\x01') + b'\x00\x03' + b'\x00' * 7)
    # 6: cut by the snapshot length right after a complete message and
    # SenderID-sized tail; the dissector goes on to the reported length
    full = packet(0x0003, msg(6, 0x0001, b'\x00\x01'), msg(7, 0x0002, b'\x00' * 8))
    p.udp(40000, 4534, full, caplen=6 + 2 + 2)
    return p


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    main_capture().write(os.path.join(out, 'armagetronad-coverage.pcap'))
    malformed_capture().write(os.path.join(out, 'armagetronad-coverage-malformed.pcap'))


if __name__ == '__main__':
    main()
