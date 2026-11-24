#!/usr/bin/env python3
# Generates test/captures/hsfz_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic captures for packet-hsfz.c (HSFZ over TCP port 6801 and UDP
port 6811).  The dissector has no default port: the heuristics
(hsfz_over_tcp, hsfz_over_udp) have to be enabled, as the tests and
runcov.sh do.  Usage: mkhsfz.py <outdir>"""
import struct
import sys
import os
from pylib import A, B, eth, eth_udp, H, ipv4, Pcap, S, tcp, udp

TP, EP = 50000, 6801     # tester port, ECU (gateway) port
T_ADDR, E_ADDR = 0xf4, 0x12

class Tcp:
    def __init__(self, p, sport=TP, dport=EP, rev=False):
        self.p = p; self.sport = sport; self.dport = dport
        self.seq = {True: 1000, False: 5000}
    def seg(self, data, fwd=True, flags=0x18):
        s, d = (self.sport, self.dport) if fwd else (self.dport, self.sport)
        src, dst = (A, B) if fwd else (B, A)
        e1, e2 = (H, S) if fwd else (S, H)
        t = tcp(s, d, self.seq[fwd], 0 if flags == 2 else self.seq[not fwd], flags, data)
        self.seq[fwd] += len(data) + (1 if flags & 3 else 0)
        return self.p.add(eth(e2, e1, 0x0800, ipv4(src, dst, 6, t)))
    def hs(self):
        self.seg(b'', True, 0x02); self.seg(b'', False, 0x12); self.seg(b'', True, 0x10)

def hsfz(ctrl, payload=b'', length=None):
    return struct.pack('>IH', len(payload) if length is None else length, ctrl) + payload

def diag(src, dst, uds, ctrl=0x0001):
    return hsfz(ctrl, bytes([src, dst]) + uds)

VIN = b'WTESTVIN0000000001'     # placeholder, not a real VIN

def main(out):
    p = Pcap(1)
    # --- TCP stream 1 (heuristic finds it with the first message) ---
    t = Tcp(p)
    t.hs()
    t.seg(diag(T_ADDR, E_ADDR, bytes([0x22, 0xf1, 0x90])))                      # request, read DID
    t.seg(diag(T_ADDR, E_ADDR, bytes([0x22, 0xf1]), ctrl=0x0002), fwd=False)      # ack (shortened UDS)
    t.seg(diag(E_ADDR, T_ADDR, bytes([0x62, 0xf1, 0x90]) + VIN), fwd=False)      # response
    t.seg(diag(T_ADDR, E_ADDR, bytes([0x3e, 0x00])))                             # tester present
    t.seg(diag(E_ADDR, T_ADDR, bytes([0x7e, 0x00])), fwd=False)
    t.seg(diag(T_ADDR, 0x40, bytes([0x10, 0x03])))                               # session control
    t.seg(diag(0x40, T_ADDR, bytes([0x7f, 0x10, 0x22])), fwd=False)              # negative response
    # Two messages in one segment
    t.seg(diag(T_ADDR, E_ADDR, bytes([0x3e, 0x00])) + diag(T_ADDR, 0x40, bytes([0x3e, 0x00])))
    # One message in two segments (reassembly)
    m = diag(T_ADDR, E_ADDR, bytes([0x22, 0xf1, 0x86]))
    t.seg(m[:5]); t.seg(m[5:])
    # Alive check: addresses, identification string, empty
    t.seg(hsfz(0x0012, bytes([T_ADDR, E_ADDR])))
    t.seg(hsfz(0x0012, b'DIAGADR10BMWMAC0090B7000001'), fwd=False)
    t.seg(hsfz(0x0012))
    # Terminal 15 control, status inquiry (no data and with data)
    t.seg(hsfz(0x0010, b'\x01'))
    t.seg(hsfz(0x0013))
    t.seg(hsfz(0x0013, b'\x00\x01\x02'), fwd=False)
    # Vehicle identification data
    t.seg(hsfz(0x0011, b'DIAGADR10BMWMAC0090B7000001BMWVIN' + VIN), fwd=False)
    t.seg(hsfz(0x0011))
    # Error messages
    t.seg(hsfz(0x0040, bytes([T_ADDR, 0xf5])), fwd=False)       # incorrect tester address
    t.seg(hsfz(0x0041, b'\x00'), fwd=False)                     # incorrect control word
    t.seg(hsfz(0x0042), fwd=False)                              # incorrect format
    t.seg(hsfz(0x0043, bytes([T_ADDR, 0x77])), fwd=False)       # incorrect destination address
    t.seg(hsfz(0x0044, b'\x00\x10'), fwd=False)                 # message too large
    t.seg(hsfz(0x0045, b'\x00'), fwd=False)                     # diagnostic application not ready
    t.seg(hsfz(0x00ff, bytes([T_ADDR, E_ADDR])), fwd=False)     # out of memory with addresses
    t.seg(hsfz(0x00ff), fwd=False)                              # out of memory, no data
    t.seg(hsfz(0x00ff, b'\x01'), fwd=False)                     # out of memory, 1 octet
    # Unknown control word (accepted: the conversation is already HSFZ)
    t.seg(hsfz(0x0050, b'\x00\x01'))
    t.seg(b'', True, 0x11); t.seg(b'', False, 0x11)

    # --- TCP stream 2: first message is an alive check (heuristic start) ---
    t2 = Tcp(p, sport=50001)
    t2.hs()
    t2.seg(hsfz(0x0012, bytes([T_ADDR, E_ADDR])))
    t2.seg(diag(T_ADDR, E_ADDR, bytes([0x19, 0x02, 0xff])))
    t2.seg(diag(E_ADDR, T_ADDR, bytes([0x59, 0x02, 0xff, 0x00, 0x1a, 0x01, 0x08]), ctrl=1), fwd=False)

    # --- TCP stream 3: not HSFZ (heuristic rejects it) ---
    t3 = Tcp(p, sport=50002, dport=7777)
    t3.hs()
    t3.seg(b'GET / HTTP/1.1\r\n\r\n')

    # --- UDP port 6811: vehicle identification and alive check ---
    for i, pay in enumerate([hsfz(0x0011, b'DIAGADR10BMWMAC0090B7000001BMWVIN' + VIN),
                             hsfz(0x0011),
                             hsfz(0x0012, bytes([T_ADDR, E_ADDR])),
                             diag(T_ADDR, E_ADDR, bytes([0x3e, 0x00])),
                             diag(T_ADDR, E_ADDR, bytes([0x3e, 0x00]), ctrl=0x0002),
                             hsfz(0x0045, b'\x00')]):
        p.add(eth(S if i & 1 else H, H if i & 1 else S, 0x0800,
                  ipv4(B if i & 1 else A, A if i & 1 else B, 17, udp(6811 if i & 1 else 50100 + i, 50100 + i if i & 1 else 6811, pay))))
    # TCP stream 4: a valid length but an unknown control word as the first
    # message (heuristic rejects it)
    t4 = Tcp(p, sport=50004)
    t4.hs()
    t4.seg(hsfz(0x0099, b'\x01\x02'))
    # UDP with an unknown control word (heuristic rejects it)
    p.add(eth_udp(50201, 6811, hsfz(0x0099, b'\x01\x02')))
    # UDP not HSFZ (rejected)
    p.add(eth_udp(50200, 7778, b'not hsfz at all, just text'))
    p.write(os.path.join(out, 'hsfz-coverage.pcap'))

    m = Pcap(1)
    t = Tcp(m)
    t.hs()
    # Start a conversation with a good message, then bad ones
    t.seg(hsfz(0x0012, bytes([T_ADDR, E_ADDR])))
    # Diagnostic message with length 1 (less than the two addresses)
    t.seg(hsfz(0x0001, b'\xf4'))
    # Length 0 diagnostic message, ack message length 1
    t.seg(hsfz(0x0001))
    t.seg(hsfz(0x0002, b'\xf4'))
    # Length field far beyond the data (waits for more data) and header cut short
    t.seg(hsfz(0x0001, b'\xf4\x12\x22', length=60000))
    t.seg(b'\x00\x00\x00')
    # Control word above 0xff and length above 1 MiB (only checked with the preference)
    t2 = Tcp(m, sport=50003)
    t2.hs()
    t2.seg(hsfz(0x0012, bytes([T_ADDR, E_ADDR])))
    t2.seg(hsfz(0x1234, b'\x00\x01'))
    t2.seg(hsfz(0x0001, b'', length=0x00200000))
    t2.seg(b'\xff' * 20)
    for fr in (hsfz(0x0001, bytes([0xf4, 0x12, 0x22, 0xf1, 0x90])),):
        m.add(eth(S, H, 0x0800, ipv4(B, A, 17, udp(6811, 50300, fr[:5]))))
    m.write(os.path.join(out, 'hsfz-coverage-malformed.pcap'))

main(sys.argv[1])
