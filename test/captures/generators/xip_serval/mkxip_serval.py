#!/usr/bin/env python3
# Generates test/captures/xip_serval_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures for the XIP Serval dissector
(packet-xip-serval.c).

XIP Serval follows an XIP header whose destination DAG ends in a FLOWID
or SERVAL XID (XIP is on Ethernet, ethertype 0xC0DE). The header is 4
octets (length in 32 bit words, protocol, 16 bit checksum), then control
extension headers (20 octets each: type/length, flags, verification and
acknowledgement numbers, nonce), then Data, a TCP header or a UDP
header (only the header is handed to TCP/UDP).

Usage: mkxip_serval.py <outdir>
Writes xip-serval-coverage.pcap and xip-serval-coverage-malformed.pcap.
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from util import write_pcap
from xiplib import (
    AD, dag, eth_xip, FLOWID, HID, node, SERVAL, serval_cext, serval_hdr, tcp_hdr, udp_hdr, xip,
)

main = []
mal = []
MSS = b'\x02\x04\x05\xb4'

def frame(lst, serval, ty=SERVAL, extra=b'', **kw):
    d = dag(node(AD, 1, [1]), node(ty, 2, [0]))
    s = dag(node(HID, 3, [0]))
    lst.append(eth_xip(xip(d, s, serval + extra, **kw)))

# Data: no extension, with data; FLOWID and SERVAL sinks; control extension flags
frame(main, serval_hdr(0), extra=b'application data')
frame(main, serval_hdr(0), ty=FLOWID, extra=b'flow data')
frame(main, serval_hdr(0))
for flags in (0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0xa0, 0xfc, 0x00, 0x03, 0xff):
    frame(main, serval_hdr(0, serval_cext(flags, 0x11223344, 0x55667788)), extra=b'ctl')
# TCP and UDP behind Serval, with and without extensions; TCP with options
frame(main, serval_hdr(6) + tcp_hdr(1000, 2000, 1, 0, 0x02, opts=MSS))
frame(main, serval_hdr(6, serval_cext(0x80, 1, 0)) + tcp_hdr(1100, 2000, 100, 0, 0x02, opts=MSS + b'\x03\x03\x07\x01'), extra=b'tcp data')
frame(main, serval_hdr(6, serval_cext(0x20, 2, 1)) + tcp_hdr(2000, 1100, 500, 101, 0x12, opts=MSS + b'\x04\x02' + b'\x08\x0a' + bytes(8) + b'\x01\x03\x03\x07'), ty=FLOWID)
frame(main, serval_hdr(17) + udp_hdr(5000, 6000), extra=b'udp payload')
frame(main, serval_hdr(17, serval_cext(0x04, 9, 9)) + udp_hdr(6000, 5000), extra=b'udp!')
# A header length of 0 and 1 word; two control extensions
frame(main, serval_hdr(0, serval_cext(0x80, 1, 2) + serval_cext(0x20, 3, 4)), extra=b'two extensions')
frame(main, serval_hdr(6, serval_cext(0x80, 1, 2) + serval_cext(0x20, 3, 4)) + tcp_hdr(80, 81, 5, 6, 0x10))
# Extension length field other than 20 (not used by the dissector)
frame(main, serval_hdr(0, serval_cext(0x80, 1, 2, length=0)), extra=b'x')
frame(main, serval_hdr(0, serval_cext(0x80, 1, 2, length=255)), extra=b'x')
# Extension type with the low nibble set (only the high nibble is the type)
frame(main, serval_hdr(0, serval_cext(0x80, 1, 2, typ=0x0f)), extra=b'x')
# Only 4 octets, the minimum: a Serval header with nothing else; 3 words with a padding word
frame(main, serval_hdr(0, hlen=1))
# Malformed: bad length, bad protocol, bad extension type, bad checksum, truncation
frame(mal, serval_hdr(0, hlen=200), extra=b'abc')
frame(mal, serval_hdr(0, hlen=2), extra=b'abc')
frame(mal, serval_hdr(5), extra=b'unknown protocol')
frame(mal, serval_hdr(255), extra=b'unknown protocol')
frame(mal, serval_hdr(0, serval_cext(0x80, 1, 2, typ=0x10)), extra=b'unknown extension')
frame(mal, serval_hdr(0, serval_cext(0x80, 1, 2, typ=0xf0)), extra=b'unknown extension')
frame(mal, serval_hdr(0, serval_cext(0x80, 1, 2) + serval_cext(0x20, 3, 4, typ=0x40)), extra=b'unknown second')
frame(mal, serval_hdr(0, chk=False), extra=b'bad checksum')
frame(mal, serval_hdr(6, serval_cext(0x80, 1, 2), chk=False) + tcp_hdr(80, 81, 5, 6, 0x10))
# The reproducer of "XIP Serval: Use an unsigned header length": header length 0 (the
# checksum of an empty header never verifies, so this is an error frame)
for hl in (0,):
    frame(mal, struct.pack('>BBH', hl, 0, 0) + b'rest of the packet that is never an extension header.' * 3)
frame(mal, serval_hdr(0, hlen=0), extra=b'hl=0')
frame(mal, struct.pack('>BBH', 0, 0, 0))
# Extension cut short (header length says 24 but only 8 octets follow); control extension cut
frame(mal, struct.pack('>BBH', 6, 0, 0) + b'\x00\x14\x80\x00\x00\x00\x00\x01')
frame(mal, struct.pack('>BBH', 6, 0, 0) + b'\x00\x14')
frame(mal, struct.pack('>BBH', 2, 0, 0) + b'\x00\x14\x80\x00')
# One word of padding after an extension: the next extension is parsed past the header
frame(mal, serval_hdr(0, serval_cext(0x80, 1, 2) + b'\x00\x00\x00\x00', hlen=7), extra=b'tail of 16 octets..')
# TCP: data offset 0, TCP header cut, data offset larger than the remainder; UDP cut
frame(mal, serval_hdr(6) + b'\x00' * 12 + b'\x00' + b'\x00' * 7)
frame(mal, serval_hdr(6) + b'\x00' * 8)
frame(mal, serval_hdr(6) + tcp_hdr(1, 2, 3, 4, 0x10)[:12] + b'\xf0\x10' + b'\x00' * 6)
frame(mal, serval_hdr(6))
frame(mal, serval_hdr(17) + b'\x00\x01\x00')
frame(mal, serval_hdr(17))
frame(mal, serval_hdr(0, serval_cext(0x80, 1, 2) )[:10])
# Serval header of 3 octets (below the minimum of 4, XIP Serval declines)
frame(mal, b'\x01\x00\x00')
frame(mal, b'')

out = sys.argv[1]
write_pcap(os.path.join(out, 'xip-serval-coverage.pcap'), main)
write_pcap(os.path.join(out, 'xip-serval-coverage-malformed.pcap'), mal)
print(len(main), len(mal))
