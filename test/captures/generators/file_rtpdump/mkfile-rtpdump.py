#!/usr/bin/env python3
# Generates test/captures/file_rtpdump_coverage.rtp.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic rtpdump files for the rtpdump file dissector.

usage: mkfile-rtpdump.py <outdir>
file-rtpdump-coverage.rtp: the main capture (text header with matching
IPv4 address and port, then RTP packets).  Variants for the other header
cases and malformed.  All are read with
-X read_format:"MIME Files Format" (magic "#!rtpplay1.0 ").
"""
import struct
import sys
import os

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'


def rtp(seq, ts, ssrc=0x11223344, pt=0, payload=b'\x55' * 20):
    return struct.pack('>BBHII', 0x80, pt, seq, ts, ssrc) + payload


def pkt(offset_ms, data, length=None, plen=None):
    return struct.pack('>HHI', 8 + len(data) if length is None else length,
                       len(data) if plen is None else plen, offset_ms) + data


def header(text=b'#!rtpplay1.0 192.0.2.1/5004\n', ts=(1700000000, 123456),
           addr=(192, 0, 2, 1), port=5004):
    return text + struct.pack('>II', *ts) + bytes(addr) + struct.pack('>HH', port, 0)


def main():
    w = lambda n, d: open(os.path.join(OUT, n), 'wb').write(d)
    body = b''.join(pkt(i * 20, rtp(100 + i, 160 * i)) for i in range(8))
    w('file-rtpdump-coverage.rtp', header() + body)
    # the address and port of the binary header differ
    w('file-rtpdump-coverage-mismatch.rtp', header(addr=(192, 0, 2, 9), port=6000) + body[:80])
    w('file-rtpdump-coverage-port-mismatch.rtp', header(port=5006) + body[:80])
    # IPv6 text address (the binary header can only hold IPv4)
    w('file-rtpdump-coverage-ipv6.rtp', header(text=b'#!rtpplay1.0 2001:db8::1/5004\n') + body[:80])
    # unknown program and version
    w('file-rtpdump-coverage-program.rtp', header(text=b'#!rtpfoo1.0 192.0.2.1/5004\n') + body[:80])
    w('file-rtpdump-coverage-version.rtp', header(text=b'#!rtpplay2.5 192.0.2.1/5004\n') + body[:80])
    # a text address and a port that cannot be parsed
    w('file-rtpdump-coverage-badaddr.rtp', header(text=b'#!rtpplay1.0 not.an.address/5004\n') + body[:80])
    w('file-rtpdump-coverage-badport.rtp', header(text=b'#!rtpplay1.0 192.0.2.1/99999\n') + body[:80])
    # packets: data length larger than the packet; zero length packet
    m = header() + pkt(0, rtp(1, 1), plen=500) + body[:28]
    w('file-rtpdump-coverage-malformed.rtp', m)
    # a packet whose length is below 8 (the length underflows), and a
    # packet that runs past the end of the file
    w('file-rtpdump-coverage-malformed-len.rtp', header() + pkt(0, rtp(1, 1), length=3))
    w('file-rtpdump-coverage-malformed-trunc.rtp', header() + pkt(0, rtp(1, 1), length=2000))
    # a file that ends in the header (shorter than the minimum: not rtpdump), and no newline
    pdus = [b'#!rtpplay1.0 192.0.2.1', header() + body[:30], header(text=b'#!rtpplay1.0 192.0.2.1:5004 x\n'.ljust(40, b' ')),
            b'#!rtpplay1.0' + b'x' * 40, b'XX' + b'\0' * 50,
            header(text=b'#!rtpfoo1.0 192.0.2.1/5004\n') + body[:30], header(text=b'#!rtpplay2.5 192.0.2.1/5004\n') + body[:30],
            b'#!rtpplay1.0 192.0.2.1' + b' ' * 30 + b'\n']
    with open(os.path.join(OUT, 'file-rtpdump-coverage-exppdu.pcap'), 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 252))
        for i, b in enumerate(pdus):
            pdu = struct.pack('>HH', 12, 8) + b'rtpdump\0' + struct.pack('>HH', 0, 0) + b
            f.write(struct.pack('<IIII', 1000 + i, 0, len(pdu), len(pdu)) + pdu)


main()
