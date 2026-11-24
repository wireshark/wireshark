#!/usr/bin/env python3
# Generates test/captures/pingpongprotocol_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic captures for packet-pingpongprotocol.c. usage: mkpingpongprotocol.py <outdir>
#
# Ping Pong Protocol over SCTP, payload protocol identifiers 33 and the legacy
# 0x29097602. Ping and Pong messages with and without data, unknown message
# types, several chunks in a packet, IPv4 and IPv6.
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import struct
from lib import eth, gz, ipv4, ipv6, sctp_data_chunk, sctp_packet, write_pcap

out = sys.argv[1]
PPID, LEGACY = 33, 0x29097602

def ping(msgno, data=b'', flags=0, length=None):
    ln = 12 + len(data) if length is None else length
    return struct.pack('!BBHQ', 1, flags, ln, msgno) + data
def pong(msgno, replyno, data=b'', flags=0, length=None):
    ln = 20 + len(data) if length is None else length
    return struct.pack('!BBHQQ', 2, flags, ln, msgno, replyno) + data
def other(t, body=b'\0' * 12): return struct.pack('!BBH', t, 0, 4 + len(body)) + body

frames = []
tsn = [100]
def S(msg, ppid=PPID, sport=2000, dport=3000, sid=0, ssn=None, v6=False, extra=()):
    tsn[0] += 1
    ch = [sctp_data_chunk(tsn[0], sid, tsn[0] if ssn is None else ssn, ppid, msg)]
    for m in extra:
        tsn[0] += 1
        ch.append(sctp_data_chunk(tsn[0], sid, tsn[0], ppid, m))
    p = sctp_packet(sport, dport, ch)
    frames.append(eth(ipv6(132, p, '2001:db8::1', '2001:db8::2'), 0x86dd) if v6 else eth(ipv4(132, p)))

# ping and pong with data, without data, bigger data
S(ping(1, b'hello'))
S(pong(2, 1, b'hello'), sport=3000, dport=2000)
S(ping(3)); S(pong(4, 3), sport=3000, dport=2000)
S(ping(5, bytes(range(200)))); S(pong(6, 5, bytes(range(200))), sport=3000, dport=2000)
S(ping(0xffffffffffffffff, b'x', flags=0xff)); S(pong(0xffffffffffffffff, 0, b'', flags=0x01), sport=3000, dport=2000)
# legacy payload protocol identifier
S(ping(7, b'legacy'), ppid=LEGACY); S(pong(8, 7, b'legacy'), ppid=LEGACY, sport=3000, dport=2000)
# unknown message types
S(other(0)); S(other(3)); S(other(0xff, b''))
# several chunks in one packet
S(ping(9, b'a'), extra=(pong(10, 9, b'b'), ping(11, b'c')))
S(pong(12, 11, b'd'), extra=(other(5),))
# IPv6
S(ping(13, b'v6'), v6=True)
S(pong(14, 13, b'v6'), v6=True, sport=3000, dport=2000)
# length field shorter than the fixed part (the fix: no data item, no exception)
S(ping(15, b'', length=8)); S(ping(16, b'', length=4)); S(ping(17, b'', length=0))
S(pong(18, 15, b'', length=16)); S(pong(19, 15, b'', length=4)); S(pong(20, 15, b'', length=0))
S(ping(21, b'tail', length=12)); S(pong(22, 21, b'tail', length=20))      # data not covered by the length field
write_pcap(out + '/pingpongprotocol-coverage.pcap', frames)

# malformed: the length field larger than the message, truncated messages
frames = []
S(ping(30, b'abc', length=100)); S(pong(31, 30, b'abc', length=100))
S(ping(32, b'abc', length=0xffff)); S(pong(33, 32, b'abc', length=0xffff))
for cut in (0, 1, 2, 3, 4, 8, 11, 12, 16, 19, 20):
    S(ping(34, b'abcd')[:cut]); S(pong(35, 34, b'abcd')[:cut])
write_pcap(out + '/pingpongprotocol-coverage-malformed.pcap', frames)
gz(out + '/pingpongprotocol-coverage.pcap')
print('ok')
