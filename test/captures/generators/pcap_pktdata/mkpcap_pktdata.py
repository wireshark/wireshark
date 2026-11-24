#!/usr/bin/env python3
# Generates test/captures/pcap_pktdata_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic captures for packet-pcap_pktdata.c. usage: mkpcap_pktdata.py <outdir>
#
# pcap_pktdata dissects packet data given a LINKTYPE_ value. It is called by
# PPI (link type 192), PKTAP (258), RFtap, RPCAP and by the pcap and pcapng
# file dissectors. The main capture reaches it through PPI and PKTAP frames
# (default preferences). runcov.sh also reads the capture as a file
# ("MIME Files Format") with the pcapng "dissect next layer" preference.
import sys
import struct
from lib import (
    epb, exp_pdu, gz, idb, ipv4, ipv6, shb, udp, udp6, udp6_payload, udp_payload, write_pcap,
    write_pcapng,
)

out = sys.argv[1]

def ppi(dlt, payload):
    return struct.pack('<BBHI', 0, 0, 8, dlt) + payload

def pktap(dlt, payload, hdrlen=108, rectype=1):
    h = struct.pack('<III24sIIIII20sIHHI20s', hdrlen, rectype, dlt, b'en0', 0, 2, 0, 0, 1234,
                    b'curl', 0, 6, 0, 1234, b'curl')
    assert len(h) == 108
    return h + payload

ipu = ipv4(17, udp_payload(1000, 2000, b'hello'))
ipu6 = ipv6(17, udp6_payload(1000, 2000, b"hello"))
ethf = udp(1000, 2000, b'hello')

frames = []   # (interface, bytes)
def P(dlt, payload): frames.append((0, ppi(dlt, payload)))

P(1, ethf)                                     # Ethernet: phdr (struct eth_phdr)
P(1, udp6(1000, 2000, b'hello6'))
P(0, struct.pack('<I', 2) + ipu)                # NULL / loopback, AF_INET
P(101, ipu)                                    # RAW
P(228, ipu)                                    # IPV4
P(229, ipu6)                                   # IPV6
P(113, struct.pack('!HHHH8sH', 0, 1, 6, 6, b'\2\0\0\0\0\1\0\0', 0x0800) + ipu)  # Linux cooked
P(104, b'\x0f\x00\x08\x00' + ipu)               # Cisco HDLC
P(50, b'\xff\x03\x00\x21' + ipu)                # PPP in HDLC-like framing
P(108, struct.pack('>I', 2) + ipu)              # OpenBSD loopback
# Bluetooth H4 with pseudo-header: direction 0 (sent), 1 (received), 2 (other).
# The H4 packet type is not a HCI one: the HCI command and event dissectors add
# Source/Destination items only on the second pass.
for d in (0, 1, 2):
    P(201, struct.pack('>I', d) + b'\x7f\x00\x01')
# link types that need a pseudo-header that cannot be generated from the data
for dlt in (139, 144, 177, 196, 204, 245, 209, 197, 254):
    P(dlt, b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b')
# a link type that does not exist
P(9999, b'\x00\x01\x02\x03')
P(65000, b'')
# PPI inside PPI inside PPI (below the nesting limit of 4)
P(192, ppi(192, ppi(1, ethf)))
# PKTAP with Ethernet, with raw IP and with an unknown link type; PKTAP in PPI
frames.append((2, pktap(1, ethf)))
frames.append((2, pktap(101, ipu)))
frames.append((2, pktap(9999, b'abcd')))
P(258, pktap(1, ethf))
# a PPI that nests a PKTAP that nests a PPI
P(258, pktap(192, ppi(1, ethf)))
# no pseudo-header data: Exported PDU naming the dissector (no "data" argument)
frames.append((1, exp_pdu('pcap_pktdata', b'\x01\x02\x03\x04')))

blocks = [shb(), idb(192), idb(252), idb(258)]
for i, f in frames:
    blocks.append(epb(f, {0: 0, 1: 1, 2: 2}[i]))
write_pcapng(out + '/pcap_pktdata-coverage.pcapng', blocks)

# malformed: nesting above the limit (PPI in PPI six times, PKTAP in PKTAP), and short data
mal = [shb(), idb(192), idb(258)]
d = ethf
for i in range(6):
    d = ppi(192, d)
mal.append(epb(d, 0))
d = ethf
for i in range(6):
    d = ppi(258, pktap(192, d))
mal.append(epb(d, 0))
d = ethf
for i in range(6):
    d = pktap(258, d)
mal.append(epb(d, 1))
# Bluetooth H4 with pseudo-header: direction 0 (sent), 1 (received), 2 (other)
hci_reset = b'\x01\x03\x0c\x00'
for dd in (0, 1, 2):
    mal.append(epb(ppi(201, struct.pack('>I', dd) + hci_reset), 0))
mal.append(epb(ppi(201, struct.pack('>I', 0) + b'\x04\x0e\x04\x01\x03\x0c\x00'), 0))
mal.append(epb(ppi(1, b''), 0))
mal.append(epb(ppi(1, b'\x01\x02'), 0))
mal.append(epb(ppi(201, b'\x00\x00'), 0))
mal.append(epb(ppi(201, b''), 0))
write_pcapng(out + '/pcap_pktdata-coverage-malformed.pcapng', mal)
# classic pcap files for the file-pcap dissector (read as a file)
write_pcap(out + '/pcap_pktdata-coverage.pcap', [ethf, udp6(1000, 2000, b'hello6')], 1)
write_pcap(out + '/pcap_pktdata-coverage-bt.pcap', [struct.pack('>I', 1) + b'\x01\x03\x0c\x00'], 201)
gz(out + '/pcap_pktdata-coverage.pcapng')
print('ok')
