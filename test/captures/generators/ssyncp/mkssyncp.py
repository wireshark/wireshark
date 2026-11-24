#!/usr/bin/env python3
# Generates test/captures/ssyncp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the SSyncP dissector
(packet-ssyncp.c, mosh's State Synchronization Protocol). Nothing comes
from a real network.

SSyncP is UDP port 60001: an 8 octet header (direction bit and 63 bit
sequence number) followed by an AES-128-OCB encrypted payload. No key is
used here: the payload is made-up filler that stays opaque, so only the
framing, the sequence number tracking and the length and sequence number
checks are covered. The decryption code is not covered on purpose.

Usage: mkssyncp.py <output directory>

Writes:
  ssyncp-coverage.pcap            datagrams in both directions, sequence
                                  number deltas (first, 1, loss, reorder,
                                  duplicate), minimum length, the limits
                                  of the length and sequence number
                                  checks, a second conversation, and the
                                  truncated datagrams of the fixed leak
  ssyncp-coverage-malformed.pcap  only the truncated datagrams (run with
                                  the ssyncp.key preference set, which
                                  skips them since the fix)
"""
import os
import struct
import sys

CMAC = bytes.fromhex("020000000001")
SMAC = bytes.fromhex("020000000002")


def pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, (fr, incl) in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, incl, len(fr)))
            f.write(fr[:incl])


def csum(b):
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def dgram(payload, to_server=True, cport=40001, incl=None):
    sport, dport = (cport, 60001) if to_server else (60001, cport)
    src, dst = ((192, 0, 2, 1), (192, 0, 2, 2)) if to_server else ((192, 0, 2, 2), (192, 0, 2, 1))
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
                     bytes(src), bytes(dst))
    ip = ip[:10] + struct.pack("!H", csum(ip)) + ip[12:]
    mac = (SMAC + CMAC) if to_server else (CMAC + SMAC)
    fr = mac + b"\x08\x00" + ip + udp
    return (fr, len(fr) if incl is None else incl)


def msg(seq, server=False, n=60):
    """Header plus n - 8 octets of filler (not ciphertext, just a counter
    pattern)."""
    head = struct.pack("!Q", (1 << 63 | seq) if server else seq)
    return head + bytes((seq * 7 + k * 13 + 5) & 0xff for k in range(n - 8))


def build(outdir):
    fr = []
    fr.append(dgram(msg(0), True))                       # 1 first, client
    fr.append(dgram(msg(0, True, 80), False))            # 2 first, server
    fr.append(dgram(msg(1), True))                       # 3 delta 1
    fr.append(dgram(msg(1, True, 100), False))           # 4 delta 1
    fr.append(dgram(msg(3), True))                       # 5 delta 2 (loss)
    fr.append(dgram(msg(2), True))                       # 6 delta -1 (reorder)
    fr.append(dgram(msg(2), True))                       # 7 delta 0 (duplicate)
    fr.append(dgram(msg(2, True, 38), False))            # 8 minimum length, delta 1
    fr.append(dgram(msg(9, False, 38), True))            # 9 minimum length
    fr.append(dgram(msg(10, False, 37), True))           # 10 one octet too short: not SSyncP
    fr.append(dgram(msg(1 << 35), True))                 # 11 highest accepted sequence number
    fr.append(dgram(msg((1 << 35) + 1), True))           # 12 too high: not SSyncP
    fr.append(dgram(msg(5, True, 1200), False))          # 13 large datagram, server delta 3
    fr.append(dgram(msg(0, False, 64), True, cport=40002))   # 14 second conversation
    fr.append(dgram(msg(0, True, 64), False, cport=40002))   # 15
    # Truncated datagrams: reported length 60, 20 octets captured
    for i in range(3):
        fr.append(dgram(msg(20 + i), True, cport=40003, incl=14 + 20 + 8 + 20))   # 16-18
    fr.append(dgram(msg(30, True, 38), False, cport=40003, incl=14 + 20 + 8 + 5))  # 19 cut inside the sequence number
    pcap(os.path.join(outdir, "ssyncp-coverage.pcap"), fr)

    m = [dgram(msg(i), True, incl=14 + 20 + 8 + 20) for i in range(3)]
    m.append(dgram(msg(7, True, 200), False, incl=14 + 20 + 8 + 37))
    pcap(os.path.join(outdir, "ssyncp-coverage-malformed.pcap"), m)


if __name__ == "__main__":
    build(sys.argv[1])
