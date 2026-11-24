#!/usr/bin/env python3
# Generates test/captures/pmproxy_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the PMPROXY dissector
(packet-pmproxy.c), the Performance Co-Pilot proxy on TCP port 44322.

A client and a proxy exchange the banners "pmproxy-server 1\\n" and
"pmproxy-client 1\\n", the client names the real host and port in a line
such as "localhost 44321\\n", and from then on the conversation is plain
PCP, which PMPROXY hands to the PCP dissector. Every packet is built from
scratch with struct; no captured traffic is used.

Usage: mkpmproxy.py <output directory>

Writes:
  pmproxy-coverage.pcap            four conversations: banners, proxy
                                   lines (host and port, host only), PCP
                                   PDUs after the exchange, the reproducer
                                   of the first-PDU fix
  pmproxy-coverage-malformed.pcap  PCP PDUs that are too short
"""
import os
import struct
import sys


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


class Conv:
    """One TCP connection, client 10.0.0.1:cport to server 10.0.0.2:44322."""

    def __init__(self, frames, cport, port=44322):
        self.frames = frames
        self.c = (bytes([10, 0, 0, 1]), cport)
        self.s = (bytes([10, 0, 0, 2]), port)
        self.seq = [1000, 5000]

    def send(self, d, payload):
        """d = 0 client to server, 1 server to client."""
        src, dst = (self.c, self.s) if d == 0 else (self.s, self.c)
        t = struct.pack('!HHIIBBHHH', src[1], dst[1], self.seq[d],
                        self.seq[1 - d], 0x50, 0x18, 65535, 0, 0) + payload
        self.seq[d] += len(payload)
        iph = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(t), 1, 0, 64, 6,
                          0, src[0], dst[0])
        iph = iph[:10] + struct.pack('!H', csum(iph)) + iph[12:]
        mac = (b'\x02\0\0\0\0\x02', b'\x02\0\0\0\0\x01') if d == 0 else \
              (b'\x02\0\0\0\0\x01', b'\x02\0\0\0\0\x02')
        self.frames.append(mac[0] + mac[1] + b'\x08\x00' + iph + t)


def pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)


def pdu(ptype, pid, body=b''):
    return struct.pack('>III', 12 + len(body), ptype, pid) + body


def error_pdu(err):
    return pdu(0x7000, 0, struct.pack('>i', err))


def creds_pdu():
    """CREDS with one version credential: type, version, flags."""
    return pdu(0x700c, 4242, struct.pack('>IBBH', 1, 1, 2, 0x0004))


def main(outdir):
    frames = []
    # Conversation 1: the full exchange, then PCP in both directions.
    c = Conv(frames, 50001)
    c.send(1, b'pmproxy-server 1\n')
    c.send(0, b'pmproxy-client 1\n')
    c.send(0, b'localhost 44321\n')
    c.send(1, error_pdu(-12357))            # first PCP PDU after the exchange
    c.send(0, creds_pdu())
    c.send(1, error_pdu(-12376))
    # Conversation 2: a proxy line with a host only, and an empty line.
    c = Conv(frames, 50002)
    c.send(0, b'pmproxy-client 1\n')
    c.send(0, b'hostonly\n')
    c.send(0, b'\n')
    c.send(0, b'a.example.org 80 extra\n')
    c.send(1, creds_pdu())
    # Conversation 3: the reproducer of the first-PDU fix (a binary PDU
    # right after the proxy line must be dissected as PCP on the first pass).
    c = Conv(frames, 50003)
    c.send(1, b'pmproxy-server 1\n')
    c.send(0, b'pmproxy-client 1\n')
    c.send(0, b'localhost 44321\n')
    c.send(1, pdu(0x7000, 0, struct.pack('>IBBH', 0, 2, 0, 0)))   # START, all ASCII
    c.send(0, error_pdu(-12357))
    # Conversation 4: no exchange at all; a banner of another version,
    # and PCP without an exchange.
    c = Conv(frames, 50004)
    c.send(1, b'pmproxy-server 2\n')
    c.send(0, creds_pdu())
    c.send(1, error_pdu(-12357))
    pcap(os.path.join(outdir, 'pmproxy-coverage.pcap'), frames)

    bad = []
    c = Conv(bad, 50010)
    c.send(0, b'pmproxy-client 1\n')
    c.send(0, b'localhost 44321\n')
    c.send(1, b'\x00\x00\x00\x10\x70\x00\x00\x00\x00')  # cut inside the PCP header
    c.send(0, pdu(0x700c, 1, struct.pack('>I', 3) + b'\x01\x02'))  # creds cut short
    pcap(os.path.join(outdir, 'pmproxy-coverage-malformed.pcap'), bad)


if __name__ == '__main__':
    main(sys.argv[1])
