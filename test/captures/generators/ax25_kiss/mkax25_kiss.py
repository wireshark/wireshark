#!/usr/bin/env python3
# Generates test/captures/ax25_kiss_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Build synthetic AX.25 KISS captures (LINKTYPE_AX25_KISS) for
# packet-ax25-kiss.c. Every packet is built with struct; nothing comes
# from a real network.
# Usage: mkax25_kiss.py <outdir>
import os
import struct
import sys

LINKTYPE_AX25_KISS = 202


def write_pcap(fn, linktype, pkts):
    with open(fn, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, p in enumerate(pkts):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
            f.write(p)


def call(cs, ssid=0, last=False, c=False):
    cs = cs.ljust(6)[:6]
    s = 0x60 | ((ssid & 0xf) << 1) | (0x80 if c else 0) | (1 if last else 0)
    return bytes(ord(ch) << 1 for ch in cs) + bytes([s])


def ax25(ctl, info=b'', pid=None, dst='NOCALL', src='N0CALL', src_ssid=1):
    a = call(dst, 0, c=True) + call(src, src_ssid, last=True) + bytes([ctl])
    if pid is not None:
        a += bytes([pid])
    return a + info


def kiss(cmd, port=0, data=b''):
    return bytes([(port << 4) | cmd]) + data


def cksum(p):
    c = 0
    for x in p:
        c ^= x
    return bytes([c])


def main(outdir):
    P = []
    M = []
    # 1-4: data frames (type 0) on ports 0, 1, 7 and 15: a UI frame, an
    # I frame, an RR and a SABM
    P.append(kiss(0, 0, ax25(0x03, b'hello', pid=0xF0)))
    P.append(kiss(0, 1, ax25(0x00, b'I frame on port 1', pid=0xF0)))
    P.append(kiss(0, 7, ax25(0x21)))
    P.append(kiss(0, 15, ax25(0x3F)))
    # 5-11: the one octet parameters
    P.append(kiss(1, 0, b'\x32'))          # TXDELAY 50 (500 ms)
    P.append(kiss(2, 0, b'\x3f'))          # Persistence 63
    P.append(kiss(3, 0, b'\x0a'))          # Slot time 10
    P.append(kiss(4, 0, b'\x05'))          # TX tail 5
    P.append(kiss(5, 0, b'\x00'))          # Full duplex off
    P.append(kiss(5, 3, b'\x01'))          # Full duplex on, port 3
    P.append(kiss(1, 2, b'\xff'))          # TXDELAY 255, port 2
    # 12-13: Set hardware with parameter octets and without
    P.append(kiss(6, 0, b'\x01\x02\x03\x04'))
    P.append(kiss(6, 4))
    # 14-16: Data frame with ack request (G8BPQ, type 12). Frame 14 is
    # the reproducer from ax25_kiss_dataack.py: ack ID 0x1234
    P.append(kiss(12, 0, b'\x12\x34' + ax25(0x03, b'hello', pid=0xF0)))
    P.append(kiss(12, 2, b'\xff\xfe' + ax25(0x00, b'acked I frame', pid=0xF0)))
    P.append(kiss(12, 0, b'\x00\x01' + ax25(0x01)))
    # 17-18: Poll mode (type 14) and Return (0xFF: type 15, port 15)
    P.append(kiss(14, 0))
    P.append(b'\xff')
    # 19-24: frame types not in the table
    for t in (7, 8, 9, 10, 11, 13):
        P.append(kiss(t, t % 16, b'\x00'))
    # 25: a data frame with a checksum octet, as the G8BPQ checksum mode
    # (preference ax25_kiss.showcksum) would send it
    d = kiss(0, 0, ax25(0x03, b'with checksum', pid=0xF0))
    P.append(d + cksum(d))

    # Malformed capture
    M.append(b'')                          # empty frame
    M.append(kiss(1, 0))                   # TXDELAY without its parameter
    M.append(kiss(12, 0, b'\x12'))         # data ack with one octet of ID
    M.append(kiss(12, 0, b'\x12\x34'))     # data ack without an AX.25 frame
    M.append(kiss(0, 0))                   # data frame without an AX.25 frame
    M.append(kiss(0, 0, ax25(0x03)[:10]))  # data frame with a truncated AX.25 frame

    write_pcap(os.path.join(outdir, 'ax25_kiss-coverage.pcap'), LINKTYPE_AX25_KISS, P)
    write_pcap(os.path.join(outdir, 'ax25_kiss-coverage-malformed.pcap'), LINKTYPE_AX25_KISS, M)
    print('ax25_kiss-coverage.pcap: %d frames, ax25_kiss-coverage-malformed.pcap: %d frames' % (len(P), len(M)))


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')
