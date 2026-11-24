#!/usr/bin/env python3
# Generates test/captures/ms-nns_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the MS-NNS coverage captures: mkms-nns.py <outdir> [-v]
MS-NNS (.NET NegotiateStream) has no port of its own: it follows an
"application/negotiate" upgrade of a .NET Message Framing (MC-NMF) connection.
TCP 9389 is claimed by the NMF dissector (packet-nmf.c), so MC-NMF and with it
MS-NNS is reached by default only through Exported PDU (dissector "ms-nns");
frames 21 on of ms-nns-coverage.pcapng are the same conversation over TCP
(NMF by default; Decode As tcp.port==9389,mc-nmf makes it MS-NNS). The authentication payloads are placeholder
bytes, not a real GSS token."""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from k11lib import Conn, exp_port_tags, exported_pdu, pcapng_write

PORT = 9389
def lenpfx(b):
    return bytes([len(b)]) + b
def preamble(upgrade=b'application/negotiate'):
    via = b'net.tcp://server.example.test:9389/svc'
    return (b'\x00\x01\x00' + b'\x01\x02' + b'\x02' + lenpfx(via) + b'\x03\x08' +
            b'\x09' + lenpfx(upgrade))
UPGRADE_RSP = b'\x0a'

def hs(mid, payload=b'', size=None):
    """NegotiateStream handshake record: id, major, minor, size (big endian)"""
    return bytes([mid, 1, 0]) + struct.pack('!H', len(payload) if size is None else size) + payload

def data(payload, size=None):
    return struct.pack('<I', len(payload) if size is None else size) + payload

def build():
    main, nmf, mal, notes = [], [], [], []
    def mark(t): notes.append((len(main) + 1, t))
    tok = lambda n, b=0x41: bytes([b]) * n          # placeholder authentication payload
    def e(payload, sport, dport):
        return exported_pdu('ms-nns', payload, exp_port_tags(sport, dport))
    C, S = 50010, PORT
    mark('two-way handshake (progress, done, done), data in both directions, an empty one, two records in one frame')
    main.append(e(hs(22, tok(40)), C, S))
    main.append(e(hs(22, tok(60, 0x42)), S, C))
    main.append(e(hs(22, tok(24)), C, S))
    main.append(e(hs(20, tok(20, 0x43)), S, C))             # server Handshake Done
    main.append(e(hs(20), C, S))                              # client Handshake Done (two-way)
    main.append(e(data(tok(30, 0x50)), C, S))
    main.append(e(data(tok(18, 0x51)), S, C))
    main.append(e(data(b''), S, C))
    main.append(e(data(tok(8, 0x53)) + data(tok(5, 0x54)), S, C))
    main.append(e(data(tok(100, 0x52))[:44], C, S))          # data record cut (asks for the missing bytes)
    mark('second conversation: handshake error, unknown record, cut authentication payload, one-way Handshake Done and data')
    C = 50011
    main.append(e(hs(22, tok(50))[:20], C, S))               # authentication payload cut
    main.append(e(hs(21, tok(6, 0x45)), S, C))               # Handshake Error
    main.append(e(hs(0x63, tok(4)), S, C))                   # unknown record
    main.append(e(hs(21), S, C))
    C = 50012
    main.append(e(hs(22, tok(16)), C, S))
    main.append(e(hs(20, tok(12, 0x46)), S, C))              # one-way Handshake Done from the server
    main.append(e(data(tok(16, 0x55)), C, S))
    main.append(e(data(tok(16, 0x56)), S, C))
    main.append(e(data(tok(16, 0x57)), C, S))
    mark('shorter than 4 octets: not NNS')
    main.append(e(b'abc', C, S))
    # ---- the same conversation over MC-NMF (TCP 9389, needs Decode As tcp.port==9389,mc-nmf)
    c = Conn(50010, PORT, isn_c=100, isn_s=900)
    nmf += c.syn()
    nmf.append(c.cs(preamble()))
    nmf.append(c.sc(UPGRADE_RSP))
    nmf.append(c.cs(hs(22, tok(40))))
    nmf.append(c.sc(hs(22, tok(60, 0x42))))
    nmf.append(c.cs(hs(22, tok(24))))
    nmf.append(c.sc(hs(20, tok(20, 0x43))))
    nmf.append(c.cs(hs(20)))
    nmf.append(c.cs(data(tok(30, 0x50))))
    nmf.append(c.sc(data(tok(18, 0x51))))
    d = data(tok(100, 0x52))
    nmf.append(c.cs(d[:44]))
    nmf.append(c.cs(d[44:]))
    nmf.append(c.sc(data(b'')))
    nmf.append(c.sc(data(tok(8, 0x53)) + data(tok(5, 0x54))))
    c2 = Conn(50011, PORT, isn_c=2000, isn_s=3000)
    nmf += c2.syn()
    nmf.append(c2.cs(preamble()))
    nmf.append(c2.sc(UPGRADE_RSP))
    m = hs(22, tok(50))
    nmf.append(c2.cs(m[:20]))
    nmf.append(c2.cs(m[20:]))
    nmf.append(c2.sc(hs(21, tok(6, 0x45))))
    nmf.append(c2.sc(hs(0x63, tok(4))))
    c3 = Conn(50012, PORT, isn_c=4000, isn_s=5000)
    nmf += c3.syn()
    nmf.append(c3.cs(preamble()))
    nmf.append(c3.sc(UPGRADE_RSP))
    nmf.append(c3.cs(hs(22, tok(16))))
    nmf.append(c3.sc(hs(20, tok(12, 0x46))))
    nmf.append(c3.cs(data(tok(16, 0x55))))
    nmf.append(c3.sc(data(tok(16, 0x56))))
    nmf.append(c3.cs(data(tok(16, 0x57))))
    # ---- malformed
    mal.append(e(hs(22, b'\0\0\0\0')[:4], 50013, S))               # cut inside the header
    mal.append(e(hs(22, tok(10), size=0xffff), 50013, S))
    mal.append(e(hs(20, tok(8)), S, 50013))
    mal.append(e(hs(20), 50013, S))
    mal.append(e(data(tok(10), size=0x7fffffff), 50013, S))
    mal.append(e(data(b'', size=0), S, 50013))
    mal.append(e(data(tok(3), size=3), S, 50013))
    return main, nmf, mal, notes

if __name__ == '__main__':
    out = sys.argv[1]
    main, nmf, mal, notes = build()
    pcapng_write(os.path.join(out, 'ms-nns-coverage.pcapng'), [(252, main), (1, nmf)])
    pcapng_write(os.path.join(out, 'ms-nns-coverage-malformed.pcapng'), [(252, mal)])
    if '-v' in sys.argv:
        print('main', len(main), '+ nmf', len(nmf), 'malformed', len(mal))
        for n, t in notes: print(n, t)
