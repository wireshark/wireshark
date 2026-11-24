#!/usr/bin/env python3
# Generates test/captures/xyplex_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures for the Xyplex dissector (packet-xyplex.c).

Xyplex terminal servers register a TCP return connection over UDP port 173:
the Unix host sends an 8 octet Registration Request (type, pad, server
port, return port, reserved), the Xyplex answers from port 173 with a 4
octet Registration Reply (type, pad, reply code). The TCP stream that the
Xyplex then opens to the return port is claimed through a conversation
that the request creates; it carries the raw serial port data.

Usage: mkxyplex.py <outdir>
Writes xyplex-coverage.pcap and xyplex-coverage-malformed.pcap.
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from util import udp, Conn, write_pcap

UNIX = '192.0.2.1'
XYP = '192.0.2.2'

def req(srv, ret, typ=1, pad=0, res=0, sport=5000, src=UNIX, dst=XYP):
    return udp(sport, 173, struct.pack('>BBHHH', typ, pad, srv, ret, res), src=src, dst=dst)

def rep(code, typ=1, pad=0, dport=5000, src=XYP, dst=UNIX):
    return udp(173, dport, struct.pack('>BBH', typ, pad, code), src=src, dst=dst)

main = []
# Registration request, reply OK, then the TCP stream on the return port
main.append(req(2000, 7001))
main.append(rep(0))
c = Conn(main, 33000, 7001, caddr=XYP, saddr=UNIX)   # Xyplex connects to UNIX:7001
c.send(b'login: ')
c.recv(b'root\r\n')
c.send(b'Password:')
c.recv(b'\r\n')
c.fin()
# A second port: request, Queue Full reply (the Xyplex refuses), retry, OK
main.append(req(2001, 7002, sport=5001))
main.append(rep(5, dport=5001))
main.append(req(2001, 7002, sport=5001))
main.append(rep(0, dport=5001))
c = Conn(main, 33001, 7002, caddr=XYP, saddr=UNIX, cisn=100, sisn=900)
c.send(bytes(range(32)))
c.recv(b'\x00' * 16)
c.fin()
# A repeated request for a known return port finds the existing conversation
main.append(req(2002, 7001, sport=5002))
# Unknown reply code, nonzero type, pad and reserved fields
main.append(rep(0x42, typ=2, pad=3, dport=5002))
main.append(req(65535, 65535, typ=9, pad=0xff, res=0xffff, sport=5003))
# Request from another Unix host to another Xyplex
main.append(req(2003, 7003, sport=5004, src='192.0.2.5', dst='192.0.2.6'))
main.append(rep(0, dport=5004, src='192.0.2.6', dst='192.0.2.5'))
c = Conn(main, 33002, 7003, caddr='192.0.2.6', saddr='192.0.2.5', cisn=10, sisn=20)
c.send(b'A' * 400)
c.fin()
# Registration request with trailing data (the dissector consumes 8 octets)
main.append(udp(5005, 173, struct.pack('>BBHHH', 1, 0, 2004, 7004, 0) + b'extra', src=UNIX, dst=XYP))
main.append(udp(173, 5005, struct.pack('>BBH', 1, 0, 0) + b'extra', src=XYP, dst=UNIX))

bad = []
bad.append(udp(5006, 173, b'\x01\x00\x07', src=UNIX, dst=XYP))              # request cut short
bad.append(udp(5006, 173, b'\x01', src=UNIX, dst=XYP))
bad.append(udp(173, 5006, b'\x01\x00\x00', src=XYP, dst=UNIX))              # reply cut short
bad.append(udp(173, 5006, b"\x01", src=XYP, dst=UNIX))

out = sys.argv[1]
write_pcap(os.path.join(out, 'xyplex-coverage.pcap'), main)
write_pcap(os.path.join(out, 'xyplex-coverage-malformed.pcap'), bad)
print(len(main), len(bad))
