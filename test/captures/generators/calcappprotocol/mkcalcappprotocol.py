#!/usr/bin/env python3
# Generates test/captures/calcappprotocol_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the Calculation Application
Protocol dissector (packet-calcappprotocol.c).

CalcAppProtocol is the RSerPool demonstration protocol: a pool user
(192.0.2.1) sends a job to a pool element (192.0.2.2) over SCTP with
payload protocol identifier 34 (or the legacy 0x29097603). A message is
24 octets: Type, Flags, Length, JobID, JobSize and Completed. Every
packet is built from scratch with struct; no captured traffic is used.

Usage: mkcalcappprotocol.py <output directory>

Writes:
  calcappprotocol-coverage.pcap            every message type with both
                                           PPIs, unknown types, extreme
                                           values, time stamps spread out
                                           for the statistics
  calcappprotocol-coverage-malformed.pcapng truncated messages and frames
                                           without a time stamp (Simple
                                           Packet Blocks)
"""

import os
import struct
import sys

PU = '192.0.2.1'
PE = '192.0.2.2'
PPI = 34
PPI_LEGACY = 0x29097603


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return (~s) & 0xffff


def ip(proto, payload, src, dst):
    a = bytes(map(int, src.split('.')))
    b = bytes(map(int, dst.split('.')))
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0, a, b)
    h = h[:10] + struct.pack('!H', csum(h)) + h[12:]
    eth = b'\x02\0\0\0\0\x02\x02\0\0\0\0\x01' if src == PU else b'\x02\0\0\0\0\x01\x02\0\0\0\0\x02'
    return eth + b'\x08\x00' + h + payload


def data_chunk(tsn, ppi, payload, flags=3, sid=0, ssn=0):
    ln = 16 + len(payload)
    return struct.pack('!BBHIHHI', 0, flags, ln, tsn, sid, ssn, ppi) + payload + b'\0' * ((-ln) % 4)


class Assoc:
    """One SCTP association (both directions); SCTP checksums are left at
    0, they are not verified by default."""
    def __init__(self, sport, dport, vtag, ppi):
        self.sport, self.dport, self.vtag, self.ppi = sport, dport, vtag, ppi
        self.tsn = {True: 1000, False: 5000}
        self.ssn = {True: 0, False: 0}

    def send(self, msgs, to_pe=True):
        chunks = []
        for m in msgs:
            chunks.append(data_chunk(self.tsn[to_pe], self.ppi, m, ssn=self.ssn[to_pe]))
            self.tsn[to_pe] += 1
            self.ssn[to_pe] = (self.ssn[to_pe] + 1) & 0xffff
        if to_pe:
            sp, dp, vt, s, d = self.sport, self.dport, self.vtag, PU, PE
        else:
            sp, dp, vt, s, d = self.dport, self.sport, self.vtag ^ 0xffffffff, PE, PU
        return ip(132, struct.pack('!HHII', sp, dp, vt, 0) + b''.join(chunks), s, d)


def msg(mtype, jobid, jobsize, completed, flags=0, length=24):
    return struct.pack('!BBHIQQ', mtype, flags, length, jobid, jobsize, completed)


class Pcap:
    def __init__(self):
        self.frames = []

    def add(self, data, ts):
        self.frames.append((ts, data))

    def write(self, name):
        with open(name, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            for ts, p in self.frames:
                f.write(struct.pack('<IIII', 1700000000 + ts // 1000, (ts % 1000) * 1000,
                                    len(p), len(p)) + p)


def pcapng_block(btype, body):
    body += b'\0' * ((-len(body)) % 4)
    ln = 12 + len(body)
    return struct.pack('<II', btype, ln) + body + struct.pack('<I', ln)


class Pcapng:
    """Enhanced Packet Blocks, or Simple Packet Blocks (no time stamp)."""
    def __init__(self):
        self.blocks = []

    def add(self, data, ts=None):
        if ts is None:
            self.blocks.append(pcapng_block(3, struct.pack('<I', len(data)) + data))
        else:
            ts = (1700000000 + ts) * 1000000
            self.blocks.append(pcapng_block(6, struct.pack('<IIIII', 0, ts >> 32, ts & 0xffffffff,
                                                           len(data), len(data)) + data))

    def write(self, name):
        shb = pcapng_block(0x0a0d0d0a, struct.pack('<IHHq', 0x1a2b3c4d, 1, 0, -1))
        idb = pcapng_block(1, struct.pack('<HHI', 1, 0, 0))
        with open(name, 'wb') as f:
            f.write(shb + idb + b''.join(self.blocks))


def main_capture(out):
    p = Pcap()
    a = Assoc(49152, 9000, 0x11223344, PPI)
    # Time stamps in milliseconds from the start
    # 1-7: a job with PPI 34
    p.add(a.send([msg(1, 1, 10000, 0)]), 0)                       # Request
    p.add(a.send([msg(2, 1, 10000, 0)], False), 500)              # Accept
    p.add(a.send([msg(6, 1, 0, 0)], False), 1000)                 # Keep-Alive
    p.add(a.send([msg(7, 1, 0, 2500)]), 1250)                     # Keep-Alive Ack
    p.add(a.send([msg(6, 1, 0, 0)], False), 2000)                 # Keep-Alive
    p.add(a.send([msg(7, 1, 0, 5000)]), 2500)                     # Keep-Alive Ack
    p.add(a.send([msg(5, 1, 10000, 10000)], False), 4000)         # Complete
    # 8-9: rejected job, extreme values, every flag bit
    p.add(a.send([msg(1, 0xffffffff, 0xffffffffffffffff, 0, flags=0xff)]), 4500)
    p.add(a.send([msg(3, 0xffffffff, 0xffffffffffffffff, 0, flags=0x80)], False), 5000)
    # 10-11: aborted job on the legacy PPI (another association)
    b = Assoc(49153, 9000, 0x55667788, PPI_LEGACY)
    p.add(b.send([msg(1, 2, 123456789, 0)]), 6000)
    p.add(b.send([msg(4, 2, 123456789, 42)]), 7000)
    # 12: two messages bundled in one SCTP packet (Accept and Keep-Alive)
    p.add(b.send([msg(2, 3, 500, 0), msg(6, 3, 0, 0)], False), 8000)
    # 13-14: unknown message types 0 and 200 (no statistics row), a Length
    # that does not match the message (shown as is) and a message with
    # trailing octets (not dissected)
    p.add(a.send([msg(0, 4, 1, 1, length=0)]), 9000)
    p.add(a.send([msg(200, 4, 1, 1, length=65535) + b'trailing']), 10000)
    p.write(os.path.join(out, 'calcappprotocol-coverage.pcap'))


def malformed_capture(out):
    p = Pcapng()
    a = Assoc(49154, 9000, 0x99aabbcc, PPI)
    # 1: only the type; 2: cut in JobID; 3: cut in Completed
    p.add(a.send([msg(1, 5, 10, 0)[:1]]), 0)
    p.add(a.send([msg(1, 5, 10, 0)[:6]]), 1)
    p.add(a.send([msg(1, 5, 10, 0)[:20]]), 2)
    # 4-5: Simple Packet Blocks (no time stamp) for the statistics
    p.add(a.send([msg(1, 6, 10, 0)]))
    p.add(a.send([msg(2, 6, 10, 0)], False))
    # 6: a Request time stamped before the others (Last Seen stays)
    p.add(a.send([msg(1, 7, 10, 0)]), -100)
    p.write(os.path.join(out, 'calcappprotocol-coverage-malformed.pcapng'))


if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    main_capture(out)
    malformed_capture(out)
