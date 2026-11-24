#!/usr/bin/env python3
# Generates test/captures/pktap_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the PKTAP coverage captures.
Usage: mkpktap.py <outdir>.  Writes pktap-coverage.pcap and
pktap-coverage-malformed.pcap (DLT 258, LINKTYPE_PKTAP).  Every packet is
built with struct; nothing comes from a real network."""
import os
import sys
import struct

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    s = (s & 0xffff) + (s >> 16)
    s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def ipv4(payload, proto=17, src=(192, 0, 2, 1), dst=(192, 0, 2, 2), ident=1):
    h = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0, 64, proto, 0, bytes(src), bytes(dst))
    h = h[:10] + struct.pack('>H', csum(h)) + h[12:]
    return h + payload

def udp(payload, sport, dport, src=(192, 0, 2, 1), dst=(192, 0, 2, 2)):
    h = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0)
    ph = bytes(src) + bytes(dst) + struct.pack('>BBH', 0, 17, 8 + len(payload))
    c = csum(ph + h + payload) or 0xffff
    return struct.pack('>HHHH', sport, dport, 8 + len(payload), c) + payload

ETH_A = bytes([2, 0, 0, 0, 0, 1])
ETH_B = bytes([2, 0, 0, 0, 0, 2])
def eth(payload, etype=0x0800, src=ETH_A, dst=ETH_B):
    return dst + src + struct.pack('>H', etype) + payload

def eth_udp(payload, sport, dport, **kw):
    return eth(ipv4(udp(payload, sport, dport), **kw))

def pcap(fn, pkts, lt=1, snaplen=262144):
    with open(fn, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, snaplen, lt))
        for i, p in enumerate(pkts):
            f.write(struct.pack('<IIII', 1000 + i, 0, len(p), len(p)))
            f.write(p)

LT = 258

def pktap(payload, dlt=1, rectype=1, hdrlen=108, ifname=b'en0', pid=1234, cmd=b'curl', epid=4321,
          ecmd=b'effective', flags=0x2, pfamily=2, llh=14, llt=0, svc=0x4, iftype=6, ifunit=0, extra=b''):
    h = struct.pack('<III24sIIII', hdrlen, rectype, dlt, ifname, flags, pfamily, llh, llt)
    h += struct.pack('<I20sIHHI20s', pid, cmd, svc, iftype, ifunit, epid, ecmd)
    assert len(h) == 108
    h += extra
    if hdrlen > len(h):
        h += b'\0' * (hdrlen - len(h))
    return h + payload

good = []
bad = []
inner_eth = eth_udp(b'pktap udp payload', 40000, 9)
raw_ip = ipv4(udp(b'raw ip payload', 40001, 9))
null_ip = struct.pack('<I', 2) + raw_ip          # DLT_NULL: AF_INET in host (little endian) order

good.append(pktap(inner_eth))                                                        # 1 Ethernet
good.append(pktap(eth(b'local experimental ethertype'.ljust(50, b'.'), 0x88b5), ifname=b'en1',
                  pid=1, cmd=b'', epid=0, ecmd=b'', flags=0, pfamily=0, llh=0, svc=0, iftype=0xffff, ifunit=0xffff))  # 2 empty names
good.append(pktap(null_ip, dlt=0, pfamily=2, llh=4))                                 # 3 BSD loopback
good.append(pktap(raw_ip, dlt=12, pfamily=2, llh=0, ifname=b'utun0'))                # 4 raw IP
good.append(pktap(raw_ip, dlt=101, pfamily=2, llh=0, ifname=b'utun1'))               # 5 raw IP (DLT 101)
good.append(pktap(b'', rectype=0, ifname=b'lo0'))                                    # 6 no packet follows
good.append(pktap(b'', rectype=2, ifname=b'lo0'))                                    # 7 a record type that is not a packet
good.append(pktap(inner_eth, hdrlen=124, extra=b'\xaa' * 16))                        # 8 extended header
good.append(pktap(pktap(inner_eth, ifname=b'inner'), dlt=258, ifname=b'outer'))      # 9 PKTAP in PKTAP
good.append(pktap(eth(b'x' * 60, 0x88b5), ifname=b'abcdefghijklmnopqrstuvw'))        # 10 longest interface name (23 + NUL)
good.append(pktap(eth(b'y' * 60, 0x88b5), ifname=b'abcdefghijklmnopqrstuvw'.replace(b'w', b'\xc3\xa9')))  # 11 non-ASCII name
good.append(pktap(b'\x00' * 20, dlt=1))                                              # 12 short payload (Ethernet needs 14 octets)

# reproducer: PKTAP inside PKTAP, 8 levels, stopped by the nesting limit of pcap_pktdata
p = inner_eth
for i in range(8):
    p = pktap(p, dlt=1 if i == 0 else 258)
bad.append(p)                                                                        # 1
bad.append(struct.pack('<III', 107, 1, 1) + bytes(104))                             # 2 header length below the minimum
bad.append(struct.pack('<III', 0, 1, 1) + bytes(104))                               # 3 header length 0
bad.append(struct.pack('<III', 108, 1, 1) + bytes(40))                              # 4 header cut short
bad.append(struct.pack('<I', 108))                                                  # 5 only the header length
bad.append(pktap(inner_eth, dlt=0xffff))                                            # 6 unknown DLT
bad.append(pktap(inner_eth, hdrlen=5000))                                           # 7 header length beyond the packet

if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcap(os.path.join(out, 'pktap-coverage.pcap'), good, LT)
    pcap(os.path.join(out, 'pktap-coverage-malformed.pcap'), bad, LT)
