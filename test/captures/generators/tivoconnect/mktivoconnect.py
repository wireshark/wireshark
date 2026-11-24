#!/usr/bin/env python3
# Generates test/captures/tivoconnect_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures for the TiVoConnect Discovery Protocol
dissector (packet-tivoconnect.c): "key=value" lines over UDP (broadcast
beacons) and TCP (connections) port 2190.

Usage: mktivoconnect.py <output directory>

Writes:
  tivoconnect-coverage.pcap            beacons and connections with every
                                       field, odd field order and case,
                                       lines without "=", unknown fields,
                                       blank lines (reproducer of the
                                       field offset fix) and a payload that
                                       is not TiVoConnect
  tivoconnect-coverage-malformed.pcap  (see the README) no packet makes
                                       this dissector throw; holds
                                       odd inputs for the coverage number
"""

import struct
import sys
import os

MAC_A = bytes.fromhex('020000000001')
MAC_B = bytes.fromhex('020000000002')


def pcap(path, frames, linktype=1):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def ip4(proto, payload, src='192.0.2.1', dst='192.0.2.2'):
    s = bytes(map(int, src.split('.')))
    d = bytes(map(int, dst.split('.')))
    h = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0, s, d)
    h = h[:10] + struct.pack('>H', csum(h)) + h[12:]
    return h + payload


def eth(payload, ethertype=0x0800, src=MAC_A, dst=MAC_B):
    return dst + src + struct.pack('>H', ethertype) + payload


def udp(sport, dport, payload, rev=False):
    u = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    if rev:
        return eth(ip4(17, u, src='192.0.2.2', dst='192.0.2.1'), src=MAC_B, dst=MAC_A)
    return eth(ip4(17, u))


def tcp(sport, dport, seq, ack, payload, flags=0x18, rev=False):
    t = struct.pack('>HHIIBBHHH', sport, dport, seq, ack, 0x50, flags, 8192, 0, 0) + payload
    if rev:
        return eth(ip4(6, t, src='192.0.2.2', dst='192.0.2.1'), src=MAC_B, dst=MAC_A)
    return eth(ip4(6, t))


def lines(*ls, eol='\n'):
    return (eol.join(ls) + eol).encode()


def main_frames():
    F = []
    # 1: UDP beacon with every field
    F.append(udp(2190, 2190, lines(
        'tivoconnect=1', 'method=broadcast', 'platform=tcd/Series3',
        'machine=Living Room', 'identity=6520001800A1234',
        'services=TiVoMediaServer:80/http', 'swversion=20.4.4.RC2')))
    # 2: TCP connection message with every field, machine and identity
    F.append(tcp(45000, 2190, 1, 1, lines(
        'tivoconnect=1', 'method=connected', 'platform=pc/linux',
        'machine=Study', 'identity={1234-5678}',
        'services=TiVoMediaServer:80/http', 'swversion=1.0')))
    # 3: only the machine name (no identity)
    F.append(udp(2190, 2190, lines('tivoconnect=1', 'machine=Kitchen')))
    # 4: only the identity (no machine name)
    F.append(udp(2190, 2190, lines('tivoconnect=1', 'identity=ABC123')))
    # 5: neither machine nor identity
    F.append(udp(2190, 2190, lines('tivoconnect=1', 'method=broadcast')))
    # 6: field names in upper case and mixed case, protocol name in
    #    upper case, no trailing newline
    F.append(udp(2190, 2190, b'TIVOCONNECT=1\nMETHOD=broadcast\nPlatform=pc\n'
                 b'MACHINE=Den\nIDENTITY=ZZ9\nServices=none\nSWVERSION=2'))
    # 7: a line without "=" and an unknown field
    F.append(udp(2190, 2190, lines('tivoconnect=1', 'garbage line',
                                   'unknownfield=value', 'machine=Odd')))
    # 8: blank lines between the fields (the offsets of the following
    #    fields were shifted before the fix: Method showed "od=broadc")
    F.append(udp(2190, 2190, b'tivoconnect=1\n\n\nmethod=broadcast\n\n'
                 b'platform=pc\n\nmachine=TEST\n'))
    # 9: CRLF line ends (the CR stays in the values)
    F.append(udp(2190, 2190, lines('tivoconnect=1', 'method=broadcast',
                                   'machine=Crlf', eol='\r\n')))
    # 10: empty values
    F.append(udp(2190, 2190, lines('tivoconnect=', 'method=', 'machine=',
                                   'identity=')))
    # 11: not TiVoConnect (does not start with the protocol name)
    F.append(udp(2190, 2190, b'hello world, this is not TiVoConnect\n'))
    # 12: not TiVoConnect over TCP, shorter than the protocol name
    F.append(tcp(45001, 2190, 1, 1, b'tivo'))
    # 13: only the protocol name, no field separator
    F.append(udp(2190, 2190, b'tivoconnect'))
    return F


def malformed_frames():
    F = []
    # no exception can be raised by the field loop; the second frame is a
    # long value, the third has only blank lines after the first
    F.append(udp(2190, 2190, lines('tivoconnect=1', 'machine=' + 'A' * 600)))
    F.append(udp(2190, 2190, b'tivoconnect=1\n\n\n\n\n\n'))
    F.append(udp(2190, 2190, b'tivoconnect=1\n=novalue\n==\n'))
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcap(os.path.join(out, 'tivoconnect-coverage.pcap'), main_frames())
    pcap(os.path.join(out, 'tivoconnect-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()
