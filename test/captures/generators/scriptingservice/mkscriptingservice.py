#!/usr/bin/env python3
# Generates test/captures/scriptingservice_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the Scripting Service Protocol (SSP) coverage captures:
mkscriptingservice.py <outdir> [-v].  All data is synthetic.

SSP is carried in SCTP DATA chunks with the payload protocol identifier 35
(or the legacy value 0x29097604)."""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import struct
from c17lib import Cap, eth, ipv4

PPI = 35
PPI_LEGACY = 0x29097604

def ssp(typ, flags=0, body=b'', length=None):
    return struct.pack('>BBH', typ, flags, 4 + len(body) if length is None else length) + body

def status(typ, st, flags=0):
    return ssp(typ, flags, struct.pack('>I', st))

def sctp_pkt(sport, dport, chunks, vtag=0x11223344, src='192.0.2.1', dst='192.0.2.2'):
    return eth(ipv4(132, struct.pack('>HHII', sport, dport, vtag, 0) + b''.join(chunks), src, dst))

def data_chunk(tsn, ppi, payload, flags=3, sid=0, ssn=0):
    ln = 16 + len(payload)
    return struct.pack('>BBHIHHI', 0, flags, ln, tsn, sid, ssn, ppi) + payload + b'\0' * ((-ln) % 4)

class Assoc:
    def __init__(self, cap, sport=40000, dport=4000, vtag=0x11223344, src='192.0.2.1', dst='192.0.2.2'):
        self.cap = cap; self.sport = sport; self.dport = dport; self.vtag = vtag
        self.src = src; self.dst = dst; self.tsn = {True: 100, False: 5000}; self.ssn = {True: 0, False: 0}
    def send(self, payload, to_server=True, ppi=PPI, flags=3, sid=0):
        tsn = self.tsn[to_server]; self.tsn[to_server] += 1
        ssn = self.ssn[to_server]
        if flags & 1:
            self.ssn[to_server] += 1
        ch = data_chunk(tsn, ppi, payload, flags, sid, ssn)
        if to_server:
            self.cap.add(sctp_pkt(self.sport, self.dport, [ch], self.vtag, self.src, self.dst))
        else:
            self.cap.add(sctp_pkt(self.dport, self.sport, [ch], self.vtag ^ 0xffffffff, self.dst, self.src))

def main(out, verbose=False):
    c = Cap(1)
    a = Assoc(c)
    c.mark('Ready messages (with and without information text), legacy payload protocol identifier')
    a.send(ssp(1, 0, b'ssp server 1.0'))
    a.send(ssp(1), False)
    a.send(ssp(1, 0, b'legacy'), False, ppi=PPI_LEGACY)
    c.mark('Not Ready: Fully Loaded, Out of Resources, another reason, without information')
    a.send(ssp(0, 0, struct.pack('>I', 1) + b'busy'), False)
    a.send(ssp(0, 0, struct.pack('>I', 2) + b'no memory'), False)
    a.send(ssp(0, 0, struct.pack('>I', 99) + b'?'), False)
    a.send(ssp(0, 0, struct.pack('>I', 2)), False)
    c.mark('Upload and Download with data, and without data')
    a.send(ssp(2, 0, bytes(range(40))))
    a.send(ssp(3, 0, b'\x00\x01\x02\x03' * 10), False)
    a.send(ssp(2))
    a.send(ssp(3), False)
    c.mark('Keep-Alive, Keep-Alive Ack and Status with a status value; a status with a body of other sizes')
    a.send(ssp(4))
    a.send(status(5, 0), False)
    a.send(status(6, 7), False)
    a.send(status(6, 0xffffffff), False)
    a.send(ssp(5), False)
    a.send(ssp(6, 0, b'\x01\x02'), False)
    c.mark('Environment: U bit set and clear, flags with other bits set')
    a.send(ssp(7, 1, bytes(range(20))))
    a.send(ssp(7, 0, bytes(range(20, 40))))
    a.send(ssp(7, 0xff, bytes(range(40, 60))))
    c.mark('Unknown message type')
    a.send(ssp(9, 0, b'unknown'))
    a.send(ssp(200, 0x55, b''), False)
    c.mark('An Upload in three SCTP fragments (reassembly), then another message on stream 1')
    up = ssp(2, 0, bytes(range(256)) * 2)
    a.send(up[:200], flags=2)
    a.send(up[200:400], flags=0)
    a.send(up[400:], flags=1)
    a.send(ssp(4), sid=1)
    c.mark('Second association on another port and vtag')
    b = Assoc(c, 40001, 4001, 0x55667788, '192.0.2.9', '192.0.2.2')
    b.send(ssp(1, 0, b'second'))
    b.send(status(6, 1), False)

    m = Cap(1)
    m.mark('Truncated messages (exceptions with a tree)')
    mm = Assoc(m)
    mm.send(b'')
    mm.send(ssp(0, 0, b''))
    mm.send(ssp(0, 0, struct.pack('>I', 1)))
    mm.send(ssp(6, 0, b'', length=4))
    mm.send(ssp(1, 0, b'', length=2))
    mm.send(b'\x01')
    mm.send(b'\x01\x00\x00')
    mm.send(ssp(1, 0, b'', length=40))
    mm.send(ssp(2, 0, b'', length=40))
    mm.send(ssp(3, 0, b'abc', length=4 + 20))
    mm.send(ssp(0, 0, b'\x00\x00\x00', length=12))
    mm.send(ssp(6, 0, b'\x00\x00\x00\x01', length=8)[:6])
    mm.send(ssp(7, 1, b'\x01' * 5))
    mm.send(ssp(7, 1, b'', length=2))
    mm.send(ssp(2, 0, b'xx', length=2))

    c.write(os.path.join(out, 'scriptingservice-coverage.pcap'))
    m.write(os.path.join(out, 'scriptingservice-coverage-malformed.pcap'))
    if verbose:
        for n, tx in c.marks:
            print(n, tx)
        print(len(c.frames), 'frames')

if __name__ == '__main__':
    main(sys.argv[1], '-v' in sys.argv)
