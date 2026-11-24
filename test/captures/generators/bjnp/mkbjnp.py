#!/usr/bin/env python3
# Generates test/captures/bjnp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the Canon BJNP dissector
(packet-bjnp.c), UDP ports 8611-8614. Every packet is built from scratch
with struct; no captured traffic is used.

Usage: mkbjnp.py <output directory>

Writes:
  bjnp-coverage.pcap            every device type and command code, unknown
                                ones, empty and non-empty payloads, all four
                                ports, a payload exactly filling the datagram,
                                and a datagram that is not BJNP
  bjnp-coverage-malformed.pcap  the payload length reproducer (0xffffffff),
                                other lengths past the datagram, truncated
                                headers
"""

import os
import struct
import sys

MAC_A = bytes.fromhex('020000000001')
MAC_B = bytes.fromhex('020000000002')
HOST = (192, 0, 2, 1)
PRINTER = (192, 0, 2, 2)


def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


def ipv4(proto, payload, src, dst, ident):
    hdr = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0,
                      64, proto, 0, bytes(src), bytes(dst))
    hdr = hdr[:10] + struct.pack('>H', csum(hdr)) + hdr[12:]
    return hdr + payload


def udp(sport, dport, data, src, dst):
    hdr = struct.pack('>HHHH', sport, dport, 8 + len(data), 0)
    pseudo = struct.pack('>4s4sBBH', bytes(src), bytes(dst), 0, 17, 8 + len(data))
    c = csum(pseudo + hdr + data) or 0xffff
    return hdr[:6] + struct.pack('>H', c) + data


IDENT = [0]


def frame(data, port=8611, response=False):
    """Ethernet/IPv4/UDP between the host (port 40000) and the printer."""
    IDENT[0] += 1
    if response:
        src, dst, sport, dport, smac, dmac = PRINTER, HOST, port, 40000, MAC_B, MAC_A
    else:
        src, dst, sport, dport, smac, dmac = HOST, PRINTER, 40000, port, MAC_A, MAC_B
    return (dmac + smac + struct.pack('>H', 0x0800)
            + ipv4(17, udp(sport, dport, data, src, dst), src, dst, IDENT[0]))


def bjnp(dev, cmd, seq, session, payload, plen=None, magic=b'BJNP'):
    if plen is None:
        plen = len(payload)
    return magic + struct.pack('>BBIHI', dev, cmd, seq, session, plen) + payload


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, p in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
            f.write(p)


def main_frames():
    F = []
    # 1-14: printer command / response pairs on port 8611, every command code
    seq = 1
    for cmd, req, rsp in (
            (0x01, b'', bytes.fromhex('000100080000060400') + bytes(7)),  # Discover
            (0x10, b'\0' * 2 + b'user\0'.ljust(64, b'\0') + b'host\0'.ljust(64, b'\0')
                   + b'document\0'.ljust(256, b'\0'), b'\0\0\0\0'),       # Print Job Details
            (0x11, b'', b''),                                            # Request Closure
            (0x20, b'', struct.pack('>H', 9) + b'STA:READY'),            # Get Printer Status
            (0x21, b'%!PS-Adobe-3.0\n' * 4, struct.pack('>I', 60)),      # Print
            (0x30, b'', struct.pack('>H', 25) + b'MFG:Canon;MDL:Test;'),  # Get Printer Identity
            (0x32, b'\0' * 8, b'')):                                     # Scan Job Details
        F.append(frame(bjnp(0x01, cmd, seq, 0x0100 + seq, req)))
        F.append(frame(bjnp(0x81, cmd, seq, 0x0100 + seq, rsp), response=True))
        seq += 1
    # 15-18: scanner command and response on 8612, Discover and Get Identity
    F.append(frame(bjnp(0x02, 0x01, 20, 0, b''), port=8612))
    F.append(frame(bjnp(0x82, 0x01, 20, 0, b'\x00\x01\x08\x00' + bytes(12)), port=8612, response=True))
    F.append(frame(bjnp(0x02, 0x30, 21, 0, b''), port=8612))
    F.append(frame(bjnp(0x82, 0x30, 21, 0, b'\x00\x10MFG:Canon;SCN:1'), port=8612, response=True))
    # 19-20: ports 8613 and 8614
    F.append(frame(bjnp(0x01, 0x20, 30, 7, b''), port=8613))
    F.append(frame(bjnp(0x81, 0x20, 30, 7, b'\x00\x02OK'), port=8614, response=True))
    # 21: unknown device type and command code (0x7f/0x7f, as in the
    # reproducer bjnp_payload_len.pcap frame 4)
    F.append(frame(bjnp(0x7f, 0x7f, 1, 0, b'')))
    # 22: known type, unknown code; 23: unknown type, known code
    F.append(frame(bjnp(0x01, 0x42, 40, 1, b'\x01\x02')))
    F.append(frame(bjnp(0x55, 0x21, 41, 2, b'\x03')))
    # 24: another magic (printable first octet): still BJNP ("MFNP")
    F.append(frame(bjnp(0x01, 0x01, 42, 0, b'', magic=b'MFNP')))
    # 25: the valid frame of the reproducer (Get Printer Identity, payload 4)
    F.append(frame(bjnp(0x01, 0x30, 1, 0, b'abcd')))
    # 26: the payload length is exactly what is left of the datagram
    F.append(frame(bjnp(0x81, 0x21, 43, 3, bytes(range(256)) * 4), response=True))
    # 27: the payload length is shorter than the datagram: the rest is not
    # dissected by BJNP
    F.append(frame(bjnp(0x01, 0x21, 44, 4, b'ABCD', plen=2)))
    # 28: first octet not printable: not BJNP, the datagram is data
    F.append(frame(b'\x00\x01\x02\x03' + bytes(12)))
    return F


def malformed_frames():
    F = []
    # 1: the reproducer (bjnp_payload_len.pcap frame 2): payload
    # length 0xffffffff with 4 octets present
    F.append(frame(bjnp(0x01, 0x30, 1, 0, b'abcd', plen=0xffffffff)))
    # 2: payload length 0x7ffffff0 (reproducer frame 3)
    F.append(frame(bjnp(0x81, 0x01, 1, 0, b'x' * 8, plen=0x7ffffff0), response=True))
    # 3: payload length one more than what is left
    F.append(frame(bjnp(0x01, 0x21, 2, 0, b'abcd', plen=5)))
    # 4: one octet (reproducer frame 5)
    F.append(frame(b'B'))
    # 5: header cut inside the payload length
    F.append(frame(bjnp(0x01, 0x20, 3, 0, b'')[:14]))
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'bjnp-coverage.pcap'), main_frames())
    write_pcap(os.path.join(out, 'bjnp-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()
