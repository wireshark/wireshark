#!/usr/bin/env python3
#
# Copyright Keysight Technologies 2026
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Generate various contrived IPv4, IPv6 and UDP encapsulations
# for UltraEthernet Transport packets with CRC.
#
# ruff: noqa: F403, F405
#
# Requires:
# scapy==2.7.0
# crc32c==2.8

from scapy.all import *
import crc32c

a='203.0.113.42'
b='198.51.100.42'
c='2001:db8::beef'
d='2001:db8::cafe'
uet = b'\x00\x00\x00\x00\x19\x88\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0f\x05\x0b\x00\x00\x00\x00\x00\x01\x00\x00\x00\x0f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff'
templates = [
	IP(src=a, dst=b, proto=253) / Raw(uet),
	IP(src=a, dst=b) / UDP(sport=4242, dport=4793) / Raw(uet),
	IPv6(src=c, dst=d, nh=253) / Raw(uet),
	IPv6(src=c, dst=d) / UDP(sport=4242, dport=4793) / Raw(uet),
]
def imaginate(tmpl, first_pass=False):
	for pkt in tmpl:
		yield Ether() / pkt
		yield Ether() / IP(src=b, dst=a) / pkt
		yield Ether() / IPv6(src=d, dst=c) / pkt
		if IP in pkt:
			yield Ether() / IP(src=b, dst=a) / ICMP(type='dest-unreach') / pkt
			if first_pass:
				other = pkt.copy()
				other[IP].options=[IPOption_RR()]
				yield from imaginate(other)
		if IPv6 in pkt:
			yield Ether() / IPv6(src=d, dst=c) / ICMPv6DestUnreach() / pkt
			if first_pass:
				other = pkt.copy()
				rest = other[IPv6].payload
				other[IPv6].remove_payload()
				yield from imaginate(other[IPv6] / IPv6ExtHdrHopByHop(options=[RouterAlert()]) / rest)
				yield from imaginate(other[IPv6] / IPv6ExtHdrDestOpt(options=HAO(hoa="2001:db8::1")) / rest)
				yield from imaginate(other[IPv6] / IPv6ExtHdrHopByHop(options=[RouterAlert()]) / IPv6ExtHdrDestOpt(options=HAO(hoa="2001:db8::1")) / rest)

idx = 0
with PcapWriter('_generated.pcap') as pcap:
	for pkt in imaginate(templates, True):
		idx += 1
		print("@@@", idx)

		last = None
		p = pkt
		off = 0
		while p:
			if issubclass(type(p), IP):
				last = p
				off = 12
			elif issubclass(type(p), IPv6):
				last = p
				off = 8
			p = p.payload
		print("last:", last)
		assert last
		if UDP in last:
			last[UDP].chksum = 0 # force
		buf = raw(last)[off:-4] # N.B. assuming placeholder for CRC
		crc = crc32c.CRC32CHash(data=buf).digest()
		print("input:", buf.hex())
		print("CRC:", crc.hex())
		if UDP in last:
			last[UDP].chksum = None # recompute
		last[Raw].load = last[Raw].load[:-4] + crc
		pcap.write(pkt)
