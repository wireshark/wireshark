#!/usr/bin/env python3
# Generates test/captures/pdu_transport_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic captures for packet-pdu-transport.c. usage: mkpdu_transport.py <outdir>
#
# PDU Transport (AUTOSAR Socket Adaptor PDU header option: ID and length)
# over UDP and TCP. The port preferences are empty by default, so the ports
# are given with preferences or Decode As; names and header layouts come from
# the two UATs (see runcov.sh for the option strings).
#
#   UDP 30500            default layout: 32 bit ID, 32 bit length
#   UDP 30501            8 bit ID, 16 bit length   (extended config, any source port)
#   UDP 30502            source port 40002: no ID (default ID 0x77), 8 bit length
#   UDP 30503            16 bit ID, no length (the PDU is the rest of the datagram)
#   UDP 30504 from 40004 no ID (default ID 0xabc), no length
#   TCP 30500            default layout, reassembled
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import struct
from lib import epb, exp_pdu, gz, idb, shb, TcpStream, udp, udp6, write_pcap, write_pcapng

out = sys.argv[1]

def pdu(i, data, idsz=4, lensz=4):
    f = {1: '!B', 2: '!H', 4: '!I'}
    b = b''
    if idsz: b += struct.pack(f[idsz], i)
    if lensz: b += struct.pack(f[lensz], len(data))
    return b + data

frames = []
def U(dport, payload, sport=40001, v6=False):
    frames.append(udp6(sport, dport, payload) if v6 else udp(sport, dport, payload))

# default layout, IDs with and without names (see the UAT in runcov.sh)
U(30500, pdu(0x100, b'\x01\x02\x03\x04'))
U(30500, pdu(0x200, b'hello world'))
U(30500, pdu(0x300, b''))
U(30500, pdu(0xdeadbeef, b'\xff' * 20))
# several PDUs in one datagram
U(30500, pdu(0x100, b'aa') + pdu(0x200, b'bbbb') + pdu(0x300, b'c'))
U(30500, pdu(0x100, b'\x80' * 8), v6=True)
# payload for the AUTOSAR NM and ISO 15765 payload dissectors
U(30500, pdu(0x400, bytes((0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08))))
# extended config: 8 bit ID, 16 bit length
# (udp_dissect_pdus needs 8 bytes and splits with the default layout, so
# the extended layouts are used with one PDU of at least 8 bytes per datagram)
U(30501, pdu(0x10, b'\x01\x02\x03\x04\x05', 1, 2))
U(30501, pdu(0x20, b'xyzxyzxyz', 1, 2))
# source port 40002: no ID, 8 bit length, default ID 0x77
U(30502, pdu(0, b'\x05\x06\x07\x08\x09\x0a\x0b', 0, 1), sport=40002)
U(30502, pdu(0, b'abcdefghij', 0, 1), sport=40002)
# 16 bit ID, no length field
U(30503, pdu(0x1234, b'rest of the datagram', 2, 0))
# no ID and no length
U(30504, b'whole datagram is the PDU', sport=40004)
# no entry for the port pair: the "Any / Any" entry
U(30505, pdu(0x200, b'any any'))
write_pcap_udp = list(frames)

# TCP, default layout, with reassembly
s = TcpStream(frames, 50000, 30500)
s.send(True, pdu(0x100, b'\x01\x02\x03\x04'))
s.send(False, pdu(0x200, b'reply'))
s.send(True, pdu(0x300, b'x' * 40), cuts=(5, 12, 30))
s.send(True, pdu(0x100, b'a') + pdu(0x200, b'bb') + pdu(0x300, b'ccc'))
s.send(False, pdu(0x100, b'a') + pdu(0x200, b'split')[:11], cuts=(len(pdu(0x100, b'a')) + 11,))
s.raw(False, pdu(0x200, b'split')[11:])
s.sseq += len(pdu(0x200, b'split')) - 11
s.close()
write_pcap(out + '/pdu-transport-coverage.pcap', frames)

# malformed: truncated PDUs (length larger than the data), data shorter than
# the header for the extended layouts, UDP with fewer than 8 bytes
frames = []
U(30500, pdu(0x100, b'abc')[:-1])
U(30500, struct.pack('!II', 0x100, 100) + b'short')
U(30500, struct.pack('!II', 0x100, 0xffffffff) + b'short')
U(30500, b'\x00\x00\x01\x00\x00\x00')
U(30500, b'')
U(30501, b'\x10\x00')
U(30501, b'\x10\x00\x20' + b'ab')
U(30502, b'', sport=40002)
U(30502, b'\x09abc', sport=40002)
U(30503, b'\x12', sport=40001)
U(30504, b'', sport=40004)
s = TcpStream(frames, 50001, 30500)
s.send(True, struct.pack('!II', 1, 3) + b'ab')
s.send(True, struct.pack('!II', 1, 100) + b'ab')
s.send(True, struct.pack('!II', 1, 0xffffffff) + b'ab')
# frames cut short by the snap length: the PDU is longer than the captured data
frames.append((udp(40001, 30500, pdu(0x100, b'x' * 100))[:60], len(udp(40001, 30500, pdu(0x100, b'x' * 100)))))
frames.append((udp(40001, 30500, pdu(0x100, b'x' * 100))[:50], len(udp(40001, 30500, pdu(0x100, b'x' * 100)))))
write_pcap(out + '/pdu-transport-coverage-malformed.pcap', frames)
# Exported PDU frames naming the dissectors: no UDP or TCP layer, no ports
mal = [shb(), idb(252)]
for n in ('pdu_transport_over_udp', 'pdu_transport_over_tcp'):
    mal.append(epb(exp_pdu(n, pdu(0x100, b'abcdefgh'))))
    mal.append(epb(exp_pdu(n, pdu(0x200, b'abc') + pdu(0x300, b'defg'))))
write_pcapng(out + '/pdu-transport-coverage-malformed.pcapng', mal)
gz(out + '/pdu-transport-coverage.pcap')
print('ok')
