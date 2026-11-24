#!/usr/bin/env python3
# Generates test/captures/bat_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the B.A.T.M.A.N. Layer 3
dissector (packet-bat.c).

UDP port 4305 (batman originator messages), 4306 (gateway tunnel) and 4307
(vis). Every packet is built from scratch with struct; no captured traffic
is used.

Usage: mkbat.py <output directory>

Writes:
  bat-coverage.pcap            batman v5 with and without HNAs, aggregated
                               packets, unsupported versions, every gateway
                               type, vis v22 and v23 with every entry type,
                               trailing octets and the branch reproducers
  bat-coverage-malformed.pcap  truncated headers, HNA counts past the end,
                               short gateway and vis packets
"""

import os
import struct
import sys

MAC_A = bytes.fromhex('020000000001')
MAC_B = bytes.fromhex('020000000002')

BATMAN, GW, VIS = 4305, 4306, 4307


def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


def ip4(a):
    return bytes(int(x) for x in a.split('.'))


def ipv4(proto, payload, src='192.0.2.1', dst='192.0.2.2', ident=1):
    hdr = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0,
                      64, proto, 0, ip4(src), ip4(dst))
    hdr = hdr[:10] + struct.pack('>H', csum(hdr)) + hdr[12:]
    return hdr + payload


def udp(sport, dport, data, src='192.0.2.1', dst='192.0.2.2'):
    hdr = struct.pack('>HHHH', sport, dport, 8 + len(data), 0)
    pseudo = struct.pack('>4s4sBBH', ip4(src), ip4(dst), 0, 17, 8 + len(data))
    c = csum(pseudo + hdr + data) or 0xffff
    return hdr[:6] + struct.pack('>H', c) + data


def frame(port, payload, sport=None, src='192.0.2.1', dst='192.0.2.2', ident=1):
    sport = port if sport is None else sport
    return (MAC_B + MAC_A + b'\x08\x00' +
            ipv4(17, udp(sport, port, payload, src, dst), src, dst, ident))


def write_pcap(path, pkts):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, p in enumerate(pkts):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)) + p)


# batman --------------------------------------------------------------------

def batman_v5(seq, orig, old_orig, flags=0, ttl=50, gwflags=0, gwport=4306,
              tq=255, hnas=(), hna_len=None):
    hna_len = len(hnas) if hna_len is None else hna_len
    p = struct.pack('>BBBBHH4s4sBB', 5, flags, ttl, gwflags, seq, gwport,
                    ip4(orig), ip4(old_orig), tq, hna_len)
    for net, mask in hnas:
        p += ip4(net) + bytes([mask])
    return p


# gateway -------------------------------------------------------------------

def inner_udp(seq):
    """IPv4/UDP to the discard port, carried in a gateway DATA tunnel."""
    return ipv4(17, udp(40000 + seq, 9, b'bat-gw-%d' % seq, '10.0.0.1',
                        '10.0.0.2'), '10.0.0.1', '10.0.0.2', seq)


# vis -----------------------------------------------------------------------

def vis_v22(sender, gw, tq_max, entries=(), trailer=b''):
    p = ip4(sender) + struct.pack('>BBH', 22, gw, tq_max)
    for typ, data, ip in entries:
        p += struct.pack('>BH', typ, data) + ip4(ip)
    return p + trailer


def vis_v23(sender, gw, tq_max, entries=(), trailer=b''):
    p = ip4(sender) + struct.pack('>BBB', 23, gw, tq_max)
    for typ, data, ip in entries:
        p += struct.pack('>BB', typ, data) + ip4(ip)
    return p + trailer


def main_capture():
    pkts = []
    # 1-4: batman v5
    pkts.append(frame(BATMAN, batman_v5(1, '192.0.2.1', '192.0.2.1')))
    pkts.append(frame(BATMAN, batman_v5(2, '192.0.2.3', '192.0.2.1', flags=0xc0,
                                        ttl=49, gwflags=0xff, tq=200,
                                        hnas=[('10.1.0.0', 16), ('10.2.0.0', 24),
                                              ('198.51.100.0', 24)])))
    # Aggregation: three originator messages in one datagram.
    agg = (batman_v5(10, '192.0.2.4', '192.0.2.4', flags=0x40, gwflags=0x21,
                     hnas=[('10.4.0.0', 16)]) +
           batman_v5(11, '192.0.2.5', '192.0.2.4', flags=0x80, gwflags=0x00, tq=128) +
           batman_v5(12, '192.0.2.6', '192.0.2.4', gwflags=0x80, tq=64,
                     hnas=[('10.6.0.0', 16), ('10.6.1.0', 24)]))
    pkts.append(frame(BATMAN, agg))
    # From an ephemeral source port (the dissector is found by dport).
    pkts.append(frame(BATMAN, batman_v5(3, '192.0.2.7', '192.0.2.1', gwflags=0x4a),
                      sport=50000))
    # 5-9: other batman versions (unsupported: handed to data)
    for v in (4, 6, 7, 8, 9):
        pkts.append(frame(BATMAN, bytes([v, 0, 50, 0]) + struct.pack('>H', v) +
                          b'\x11\x30' + ip4('192.0.2.8') + ip4('192.0.2.8') +
                          b'\xff\x00'))
    # 10-19: gateway
    pkts.append(frame(GW, bytes([1]) + inner_udp(1)))                   # DATA
    pkts.append(frame(GW, bytes([2]) + ip4('0.0.0.0')))                 # IP_REQUEST, no IP
    pkts.append(frame(GW, bytes([2]) + ip4('169.254.0.10')))            # IP_REQUEST
    pkts.append(frame(GW, bytes([3]) + bytes(12) + ip4('169.254.0.11')))  # IP_INVALID
    pkts.append(frame(GW, bytes([3]) + bytes(16) + b'xyz'))             # IP_INVALID, IP 0
    pkts.append(frame(GW, bytes([4]) + ip4('169.254.0.12')))            # KEEPALIVE_REQUEST
    pkts.append(frame(GW, bytes([5]) + ip4('169.254.0.12') + b'pad'))   # KEEPALIVE_REPLY + data
    pkts.append(frame(GW, bytes([9]) + ip4('169.254.0.13') + b'\x01\x02'))  # unknown type
    pkts.append(frame(GW, bytes([1]) + inner_udp(2), sport=50001))      # DATA again
    pkts.append(frame(GW, bytes([2]) + ip4('0.0.0.0') + b'\xaa\xbb'))   # no IP, then data
    # 20-29: vis
    ents = [(1, 200, '192.0.2.10'), (2, 0, '192.0.2.11'), (3, 24, '10.9.0.0'),
            (7, 0x1234, '192.0.2.12')]
    pkts.append(frame(VIS, vis_v22('192.0.2.1', 0x21, 255, ents)))
    pkts.append(frame(VIS, vis_v22('192.0.2.1', 0, 255)))               # no entries
    # Reproducer bat_vis_trailing.py: one entry and 3 octets
    pkts.append(frame(VIS, vis_v22('192.0.2.1', 0, 255, [(1, 200, '192.0.2.10')],
                                   b'\xde\xad\xbe')))
    # Reproducer bat_vis_v23_entry_len.py: three NEIGH entries
    pkts.append(frame(VIS, vis_v23('192.0.2.1', 0, 255,
                                   [(1, 200, '192.0.2.%d' % (10 + i)) for i in range(3)])))
    ents23 = [(1, 180, '192.0.2.20'), (2, 0, '192.0.2.21'), (3, 16, '10.8.0.0'),
              (9, 0x55, '192.0.2.22')]
    pkts.append(frame(VIS, vis_v23('192.0.2.2', 0x11, 200, ents23, b'\x01\x02\x03\x04\x05'),
                      src='192.0.2.2', dst='192.0.2.1'))
    pkts.append(frame(VIS, vis_v23('192.0.2.2', 0, 100)))               # no entries
    pkts.append(frame(VIS, vis_v23('192.0.2.2', 0, 100, trailer=b'\x07')))  # only trailer
    pkts.append(frame(VIS, vis_v22('192.0.2.3', 0, 1000, ents[:2], b'\x00' * 6),
                      sport=50002))
    for v in (21, 24):                                                  # unsupported
        pkts.append(frame(VIS, ip4('192.0.2.1') + bytes([v, 0, 0, 255]) + b'\x01\x00\xc8' +
                          ip4('192.0.2.10')))
    return pkts


def malformed_capture():
    pkts = []
    pkts.append(frame(BATMAN, batman_v5(1, '192.0.2.1', '192.0.2.1')[:10]))  # short
    pkts.append(frame(BATMAN, batman_v5(2, '192.0.2.1', '192.0.2.1', hna_len=3,
                                        hnas=[('10.1.0.0', 16)])))      # HNAs missing
    pkts.append(frame(BATMAN, batman_v5(3, '192.0.2.1', '192.0.2.1') + b'\x05\x00'))  # partial agg
    pkts.append(frame(GW, bytes([2, 10, 0])))                           # short IP
    pkts.append(frame(GW, bytes([3]) + bytes(8)))                       # IP_INVALID short
    pkts.append(frame(GW, bytes([1]) + b'\x45\x00\x00\x10'))            # DATA, bad IPv4
    pkts.append(frame(VIS, ip4('192.0.2.1')))                           # no version
    pkts.append(frame(VIS, ip4('192.0.2.1') + bytes([22, 0])))          # short v22
    pkts.append(frame(VIS, ip4('192.0.2.1') + bytes([23, 0])))          # short v23
    return pkts


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'bat-coverage.pcap'), main_capture())
    write_pcap(os.path.join(out, 'bat-coverage-malformed.pcap'), malformed_capture())


if __name__ == '__main__':
    main()
