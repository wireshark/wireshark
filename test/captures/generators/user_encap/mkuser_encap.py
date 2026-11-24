#!/usr/bin/env python3
# Generates test/captures/user_encap_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the DLT_USER (user_encap) coverage captures (packet-user_encap.c).

usage: mkuser_encap.py <outdir> [-v]
Writes user_encap-coverage.pcapng, user_encap-coverage-malformed.pcapng and
cfg/user_dlts (the UAT rows the main capture is built for).

The dissector is reached by the link-layer types 147-162. Nothing is decoded
without a row in the "User DLTs" table, except DLT_USER2 (149), which defaults
to PKTAP. The main capture therefore needs these rows (see ROWS; the tests give
them with -o uat:user_dlts:...); without them every frame but the PKTAP ones
gets the "User encapsulation not handled" warning.

pcapng interfaces: one per link-layer type used. UAT row format:
  DLT, payload dissector, header size, header dissector, trailer size, trailer dissector
"""
import os
import socket
import struct
import sys

OUT = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('-') else '.'
VERBOSE = '-v' in sys.argv
RANGES = []

ROWS = [
    ('User 0 (DLT=147)', 'eth_withoutfcs', 4, '', 0, ''),         # 4 octet header kept as data
    ('User 1 (DLT=148)', 'ip', 0, '', 0, ''),
    ('User 3 (DLT=150)', 'ip', 2, 'data', 4, 'data'),               # header and trailer given as "data"
    ('User 4 (DLT=151)', 'ppp', 0, '', 0, ''),
    ('User 5 (DLT=152)', 'tcp', 0, '', 0, ''),
    ('User 6 (DLT=153)', 'udp', 0, '', 0, ''),
    ('User 7 (DLT=154)', 'data', 0, '', 0, ''),
    ('User 8 (DLT=155)', 'eth_withoutfcs', 4, '', 20, ''),         # the row of the fix: header and trailer larger than a short frame
    ('User 15 (DLT=162)', 'eth_withfcs', 0, '', 4, 'data'),
    ('User 9 (DLT=156)', 'arp', 8, 'data', 8, 'data'),            # ARP payload between an 8 octet header and trailer
]


class Pcapng:
    def __init__(self):
        self.b = bytearray()
        self.t = 1700000000 * 1000000
        self.n = 0
        self.ifs = {}
        self._block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))

    def _block(self, typ, body):
        body += b'\0' * (-len(body) % 4)
        n = len(body) + 12
        self.b += struct.pack('<II', typ, n) + body + struct.pack('<I', n)

    def pkt(self, dlt, data, origlen=None):
        if dlt not in self.ifs:
            self._block(1, struct.pack('<HHI', dlt, 0, 262144))
            self.ifs[dlt] = len(self.ifs)
        self.t += 1000
        self._block(6, struct.pack('<IIIII', self.ifs[dlt], self.t >> 32, self.t & 0xffffffff, len(data),
                                   len(data) if origlen is None else origlen) + data)
        self.n += 1

    def write(self, fn):
        open(fn, 'wb').write(self.b)


def mark(p, name, start):
    RANGES.append((name, start + 1, p.n))


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def udp_ip(payload=b'userdata', sport=1234, dport=5678, src='192.0.2.1', dst='192.0.2.2'):
    udp = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
                     socket.inet_aton(src), socket.inet_aton(dst))
    return ip[:10] + struct.pack('!H', csum(ip)) + ip[12:] + udp


def eth_ip_udp(payload=b'userdata'):
    return bytes.fromhex('020000000002020000000001') + b'\x08\x00' + udp_ip(payload)


def tcp_segment(payload=b'GET / HTTP/1.1\r\n\r\n'):
    return struct.pack('!HHIIBBHHH', 40000, 80, 1, 1, 0x50, 0x18, 65535, 0, 0) + payload


def udp_only(payload=b'datagram'):
    return struct.pack('!HHHH', 5000, 5001, 8 + len(payload), 0) + payload


def arp_req():
    return struct.pack('!HHBBH', 1, 0x0800, 6, 4, 1) + bytes.fromhex('020000000001') + bytes([192, 0, 2, 1]) + \
        bytes(6) + bytes([192, 0, 2, 2])


def pktap(dlt, rectype=1, hdrlen=108, ifname=b'en0', extra=b''):
    h = struct.pack('<III', hdrlen, rectype, dlt)
    h += ifname.ljust(24, b'\0')
    h += struct.pack('<IIIII', 0, 2, 0, 0, 1)
    h += b'synthetic'.ljust(20, b'\0')
    h += struct.pack('<IHHI', 0, 6, 0, 1)
    h += b'synthetic'.ljust(20, b'\0')
    assert len(h) == 108
    return h + extra


def main_capture():
    p = Pcapng()
    s0 = p.n
    p.pkt(147, b'\xaa\xbb\xcc\xdd' + eth_ip_udp())                       # 4 octet header, Ethernet payload
    p.pkt(148, udp_ip())                                                  # IP, no header
    p.pkt(150, b'\x01\x02' + udp_ip() + b'\xde\xad\xbe\xef')              # header 2, trailer 4
    p.pkt(151, b'\x00\x21' + udp_ip())                                   # PPP: protocol field 0x0021 (IP)
    p.pkt(152, tcp_segment())
    p.pkt(153, udp_only())
    p.pkt(154, b'plain data for a DLT without header or trailer')
    p.pkt(162, eth_ip_udp() + b'\x00\x00\x00\x00' + b'\xca\xfe\xba\xbe')   # Ethernet with FCS, then a 4 octet trailer as data
    p.pkt(156, bytes([0, 0, 0, 0, 0, 0, 0, 0]) + arp_req() + bytes(8))    # 8 octet header and trailer (a real dissector given)
    mark(p, 'rows of the table: header, payload and trailer', s0)

    s0 = p.n
    # the fix: a frame cut by snaplen to 20 octets (original length 100), row 155 has header 4 and trailer 20
    p.pkt(155, (b'\xaa\xbb\xcc\xdd' + eth_ip_udp())[:20], origlen=100)
    # the same row on a frame that holds header, payload and trailer
    p.pkt(155, b'\xaa\xbb\xcc\xdd' + eth_ip_udp(b'x' * 8) + bytes(range(20)))
    # the frame is shorter than the header only by the trailer (captured 10, reported 30)
    p.pkt(155, (b'\xaa\xbb\xcc\xdd' + eth_ip_udp())[:10], origlen=30)
    mark(p, 'row 155: truncated frames (the fix) and full frames', s0)

    s0 = p.n
    # DLT_USER2 has no row: PKTAP. Every nesting level up to the limit of 4 pcap_pktdata calls.
    inner = bytes.fromhex('020000000002020000000001') + b'\x08\x00' + udp_ip()
    p.pkt(149, pktap(1) + inner)                                          # PKTAP, then Ethernet
    p.pkt(149, pktap(149) + pktap(1) + inner)                             # two levels
    p.pkt(149, pktap(149) + pktap(149) + pktap(149) + pktap(1) + inner)    # four levels: the limit
    p.pkt(149, pktap(1, rectype=2) + inner)                               # PKTAP record that is not a packet: no payload dissection
    mark(p, 'DLT_USER2 default PKTAP, nested to the limit', s0)
    return p


def malformed_capture():
    p = Pcapng()
    inner = bytes.fromhex('020000000002020000000001') + b'\x08\x00' + udp_ip()
    p.pkt(149, b''.join(pktap(149) for _ in range(4)) + pktap(1) + inner)     # five levels: one over the limit
    p.pkt(149, b''.join(pktap(149) for _ in range(20)) + pktap(1) + inner)    # twenty levels
    p.pkt(149, pktap(149, hdrlen=60)[:60] + inner)                             # PKTAP header length below the minimum
    p.pkt(157, b'frame of a DLT that has no row in the table')               # User 10: not handled
    p.pkt(158, b'another one')
    p.pkt(155, b'\xaa\xbb\xcc\xdd' + bytes(20))                               # exactly header + trailer long: empty payload
    p.pkt(147, b'\xaa\xbb')                                                    # shorter than the 4 octet header of row 147
    p.pkt(156, b'\x00\x01\x02\x03')                                            # shorter than header 8 + trailer 8 of row 156
    p.pkt(150, b'\x01\x02\x03')                                                # header 2, one octet of payload, trailer cut
    return p


if __name__ == '__main__':
    p = main_capture()
    p.write(os.path.join(OUT, 'user_encap-coverage.pcapng'))
    m = malformed_capture()
    m.write(os.path.join(OUT, 'user_encap-coverage-malformed.pcapng'))
    os.makedirs(os.path.join(OUT, 'cfg'), exist_ok=True)
    with open(os.path.join(OUT, 'cfg', 'user_dlts'), 'w') as f:
        for dlt, pay, hs, hp, ts, tp in ROWS:
            f.write('"%s","%s","%d","%s","%d","%s"\n' % (dlt, pay, hs, hp, ts, tp))
    # the same rows with "data" written out for every header and trailer: with an empty name the
    # Exported PDU tap asserts (see the README), so the export run of runcov.sh uses this profile
    os.makedirs(os.path.join(OUT, 'cfg-exp'), exist_ok=True)
    with open(os.path.join(OUT, 'cfg-exp', 'user_dlts'), 'w') as f:
        for dlt, pay, hs, hp, ts, tp in ROWS:
            f.write('"%s","%s","%d","%s","%d","%s"\n' % (dlt, pay, hs, hp or 'data', ts, tp or 'data'))
    if VERBOSE:
        for n, a, b in RANGES:
            print('%-60s frames %d-%d' % (n, a, b))
        print('main', p.n, 'malformed', m.n)
