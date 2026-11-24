#!/usr/bin/env python3
# Generates test/captures/xip_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures for the XIP dissector (packet-xip.c).

XIP (eXpressive Internet Protocol, the network layer of XIA) runs
directly over Ethernet, ethertype 0xC0DE. The 8 octet header holds
version, next header, payload length, hop limit, the number of
destination and source DAG nodes and the last node, followed by the
destination and source DAGs, 28 octets per node (type, 20 octet XID, 4
edges). When the sink node of the destination DAG is a Serval FLOWID or
SERVAL XID the XIP Serval header follows (XIP Serval has its own
coverage directory).

Usage: mkxip.py <outdir>
Writes xip-coverage.pcap and xip-coverage-malformed.pcap.
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















from util import write_pcap
from xiplib import (
    AD, CID, dag, EMPTY, ENTRY, eth_xip, FLOWID, HID, I4, NAT, node, SERVAL, serval_hdr, SID, U4,
    UNI4, XDP, xip, ZF,
)

main = []
mal = []

def add(lst, p, **kw):
    lst.append(eth_xip(xip(*p, **kw)))

DATA = b'payload-data-0123456789'

# Valid DAGs: a single node, a chain, a fallback, an entry with two edges,
# nine nodes; one frame per principal type
single = lambda ty, n=1: dag(node(ty, n, [0]))
for ty in (AD, HID, CID, SID, UNI4, I4, U4, XDP, SERVAL & 0 | CID, ZF, 0x1f, 0x7fffffff):
    add(main, (single(ty), single(HID, 99)), payload=DATA)
# two nodes: AD -> HID; entry edge to node 0
add(main, (dag(node(AD, 1, [1]), node(HID, 2, [0])), single(HID, 5)), payload=DATA)
# fallback: node 0 has two out edges (to 1 and 2), node 1 to 2, entry edges to 0 and 1
add(main, (dag(node(CID, 1, [2, 1]), node(AD, 2, [2]), node(HID, 3, [0, 1])), single(HID, 6)), payload=DATA)
# four edges on the entry node and on a node
add(main, (dag(node(AD, 1, [1, 2, 3, 4]), node(HID, 2, [2, 3]), node(SID, 3, [3]), node(CID, 4, [4]),
               node(XDP, 5, [0, 1, 2, 3])), single(HID, 7)), payload=DATA)
# nine nodes in a chain
chain = [node(AD + (i % 4), i + 1, [i + 1]) for i in range(8)] + [node(HID, 9, [0])]
add(main, (dag(*chain), dag(*chain[4:])), payload=DATA)
# the last node chosen: the entry node marker (default), 0, an intermediate node and past the DAG
for last in (ENTRY, 0, 1, 2, 9, 0xff):
    add(main, (dag(node(AD, 1, [1]), node(HID, 2, [0])), single(HID, 5)), payload=DATA, last=last)
# Source DAG only, destination DAG only, none (long payload to reach 36 octets)
add(main, (b'', single(HID, 8)), payload=DATA)
add(main, (single(HID, 8), b''), payload=DATA)
add(main, (b'', b''), payload=bytes(range(40)))
# an empty payload; hop limit 0 and 255; version other than 1; payload to be handed to the data dissector
add(main, (single(HID, 8), single(HID, 9)))
add(main, (single(HID, 8), single(HID, 9)), payload=DATA, hop=0)
add(main, (single(HID, 8), single(HID, 9)), payload=DATA, hop=255, ver=0)
add(main, (single(HID, 8), single(HID, 9)), payload=bytes(1000), ver=7)
# Ill-formed DAGs, shown with a '!' (no error: xia_ntop describes them)
bad_dags = [
    # NAT type in the middle of the DAG
    dag(node(AD, 1, [1]), node(NAT, 0, [0]), node(HID, 2, [0])),
    # NAT row followed by a real row
    dag(node(AD, 1, [1]), node(NAT, 0, []), node(HID, 2, [0])),
    # an edge chosen (0x80 bit)
    dag(node(AD, 1, raw_edges=[0x81, EMPTY, EMPTY, EMPTY]), node(HID, 2, [0])),
    dag(node(AD, 1, [1]), node(HID, 2, raw_edges=[0x80, 0x80, 0x80, 0x80])),
    # non-empty edge after an empty edge
    dag(node(AD, 1, raw_edges=[EMPTY, 1, EMPTY, EMPTY]), node(HID, 2, [0])),
    # edge out of range, with the + and * characters
    dag(node(AD, 1, raw_edges=[1, 5, EMPTY, EMPTY]), node(HID, 2, [0])),
    dag(node(AD, 1, raw_edges=[0x30, EMPTY, EMPTY, EMPTY]), node(HID, 2, [0])),
    dag(node(AD, 1, raw_edges=[0x7e, 0x70, 0x60, 0x2a]), node(HID, 2, [0])),
    # not in topological order (edge to itself, to a lower node)
    dag(node(AD, 1, [0]), node(HID, 2, [0])),
    dag(node(AD, 1, [1]), node(HID, 2, [0]), node(SID, 3, [1]) ),
    # two components: node 2 is never reached
    dag(node(AD, 1, [1]), node(HID, 2, []), node(SID, 3, [0])),
    dag(node(AD, 1, [1]), node(HID, 2, [0]), node(SID, 3, [])),
    # no entry edges on the last node
    dag(node(AD, 1, [1]), node(HID, 2, [])),
    dag(node(AD, 1, [])),
]
for d in bad_dags:
    add(main, (d, single(HID, 5)), payload=DATA)
    add(main, (single(HID, 5), d), payload=DATA)
# Serval FLOWID and SERVAL sink nodes hand over to XIP Serval (a minimal Data header)
sv = serval_hdr(0)
for ty in (FLOWID, SERVAL):
    add(main, (dag(node(AD, 1, [1]), node(ty, 2, [0])), single(HID, 5)), payload=sv + b'serval data')
# A sink that is another type with a payload that looks like Serval
add(main, (dag(node(AD, 1, [1]), node(CID, 2, [0])), single(HID, 5)), payload=sv + b'serval data')
# ARP-like noise on the ethertype is not XIP: too short
main.append(eth_xip(b'\x01' * 20))

# Malformed: payload length that does not match, next header, DAG node counts, truncation
d1, d2 = single(HID, 1), single(HID, 2)
add(mal, (d1, d2), payload=DATA, plen=5)
add(mal, (d1, d2), payload=DATA, plen=0xffff)
add(mal, (d1, d2), payload=b'', plen=1)
add(mal, (d1, d2), payload=DATA, nxth=1)
add(mal, (d1, d2), payload=DATA, nxth=0xff)
add(mal, (dag(*[node(HID, i + 1, [0]) for i in range(10)]), d2), payload=DATA, ndst=10)
add(mal, (dag(*[node(HID, i + 1, [0]) for i in range(9)]), d2), payload=DATA, ndst=200)
add(mal, (d1, dag(*[node(HID, i + 1, [0]) for i in range(10)])), payload=DATA, nsrc=10)
add(mal, (d1, dag(*[node(HID, i + 1, [0]) for i in range(9)])), payload=DATA, nsrc=255)
add(mal, (d1, d2), payload=DATA, ndst=9)            # DAG nodes past the end
add(mal, (d1, d2), payload=DATA, nsrc=9)
add(mal, (d1, d2), payload=DATA, ndst=2, nsrc=2)
add(mal, (d1, b''), payload=DATA, nsrc=1)
add(mal, (b'', b''), payload=bytes(range(40)), ndst=1)   # sink node read past the end
add(mal, (dag(node(AD, 1, [1]), node(SERVAL, 2, [0])), d2), payload=b'\x01')   # Serval header cut
add(mal, (dag(node(AD, 1, [1]), node(FLOWID, 2, [0])), d2), payload=b'')
full = xip(d1, d2, DATA)
for cut in (37, 40, 47, 63, 64, 70):
    mal.append(eth_xip(full[:cut]))
# last destination type truncated
mal.append(eth_xip(xip(d1, d2, DATA)[:12] + b''.ljust(0) + b'\x00' * 30))

mal.append(eth_xip(xip(single(HID, 1), single(HID, 2), b'')[:35] + b'\x00'))
out = sys.argv[1]
write_pcap(os.path.join(out, 'xip-coverage.pcap'), main)
write_pcap(os.path.join(out, 'xip-coverage-malformed.pcap'), mal)
print(len(main), len(mal))
