#!/usr/bin/env python3
# Generates test/captures/pcli_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic captures for packet-pcli.c. usage: mkpcli.py <outdir>
#
# PCLI (PacketCable lawful intercept CCC) has no fixed port: it is reached
# with Decode As on udp.port. The four dissectors (pcli, pcli8, pcli12,
# pcli20) get the ports 4000, 4008, 4012 and 4020; the payload is handed to
# the "pcli.payload" Decode As table (Decode As "pcli.payload,ip"; without it the payload is shown as data).
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import struct
from lib import gz, ipv4, udp, udp6, write_pcap

out = sys.argv[1]
PORTS = {'pcli': 4000, 'pcli8': 4008, 'pcli12': 4012, 'pcli20': 4020}

def rtp(seq, payload=b'\x80\x80\x80\x80'):
    '''The content of the call: an IPv4 UDP packet (Decode As pcli.payload,ip)'''
    u = struct.pack('!HHHH', 6000 + seq, 6001, 8 + len(payload), 0) + payload
    return ipv4(17, u, '198.51.100.1', '198.51.100.2', ident=seq)

def ntp(sec, frac): return struct.pack('!II', sec, frac)

frames = []
def U(port, payload, sp=5000): frames.append(udp(sp, port, payload))

# pcli: only the 4 byte CCCID, then the payload
for i, cccid in enumerate((1, 0x12345678, 0xffffffff)):
    U(PORTS['pcli'], struct.pack('!I', cccid) + rtp(i))
U(PORTS['pcli'], struct.pack('!I', 7) + rtp(10))
# pcli8: CCCID and a second 4 byte word
for i in range(3):
    U(PORTS['pcli8'], struct.pack('!II', 0x100 + i, 0xdeadbeef) + rtp(i))
U(PORTS['pcli8'], struct.pack('!II', 9, 0) + rtp(11))
# pcli12: CCCID and an NTP timestamp (including a fraction)
for i in range(3):
    U(PORTS['pcli12'], struct.pack('!I', 0x200 + i) + ntp(3900000000 + i, 0x80000000 * (i % 2)) + rtp(i))
U(PORTS['pcli12'], struct.pack('!I', 5) + ntp(0, 0) + rtp(11))
# pcli20: CCCID, NTP timestamp and a case ID
for i in range(3):
    U(PORTS['pcli20'], struct.pack('!I', 0x300 + i) + ntp(3900000000 + i, 1 << 28) + struct.pack('!Q', 0xcafe0000 + i) + rtp(i))
U(PORTS['pcli20'], struct.pack('!I', 5) + ntp(0, 0) + struct.pack('!Q', 0) + rtp(11))
# IPv6 transport
frames.append(udp6(5000, PORTS['pcli20'], struct.pack('!I', 0x400) + ntp(3900000100, 0) + struct.pack('!Q', 1) + rtp(1)))
write_pcap(out + '/pcli-coverage.pcap', frames)

mal = []
for p in PORTS.values():
    U_ = lambda payload: mal.append(udp(5000, p, payload))
    U_(b'')
    U_(b'\x00\x01')
    U_(struct.pack('!I', 1))
    U_(struct.pack('!I', 1) + b'\x00\x01\x02')
    U_(struct.pack('!I', 1) + b'\x00' * 11)
    U_(struct.pack('!I', 1) + b'\x00' * 15)
write_pcap(out + '/pcli-coverage-malformed.pcap', mal)
gz(out + '/pcli-coverage.pcap')
print('ok')
