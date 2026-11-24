#!/usr/bin/env python3
# Generates test/captures/q708_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic captures for the Q.708 ISPC analysis (packet-q708.c).
Usage: mkq708.py <outdir> [-v]

packet-q708.c holds one function, analyze_q708_ispc(), called by MTP3 and
M3UA for the point codes of messages whose network indicator is 0
(international). The main capture therefore has MTP3 frames (link type
MTP3, 141) and M3UA DATA messages over SCTP (Ethernet) with network
indicator 0 and point codes taken from the tables of the dissector
(the point code and operator names, the signalling area network codes),
codes with a known SANC but no name, and unknown codes; and, for
contrast, frames with the network indicators 1, 2 and 3, which are not
analysed. All values are made up; the frames are built with struct."""
import os
SRCDIR = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..', '..'))
import re
import struct
import sys
import random

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'
VERBOSE = '-v' in sys.argv
random.seed(708)
SRC = os.path.join(SRCDIR, 'epan/dissectors/packet-q708.c')
text = open(SRC).read()

def keys(name):
    body = re.search(r'static const value_string %s\[\] = \{(.*?)\n\};' % name, text, re.S).group(1)
    return [int(k) for k in re.findall(r'\{\s*(\d+),', body)]

SANC = keys('q708_sanc_areas')
NAMES = keys('q708_ispc_point_name')
OPERS = keys('q708_ispc_operator_name')
nameset, operset, sancset = set(NAMES), set(OPERS), set(SANC)

class Pcapng:
    def __init__(self, linktypes):
        self.out = bytearray()
        self.blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
        for lt in linktypes:
            self.blk(1, struct.pack('<HHI', lt, 0, 65535))
        self.n = 0
    def blk(self, t, body):
        body += b'\0' * ((-len(body)) % 4)
        self.out += struct.pack('<II', t, len(body) + 12) + body + struct.pack('<I', len(body) + 12)
    def packet(self, iface, data):
        ts = (1700000000 + self.n) * 1000000
        self.n += 1
        self.blk(6, struct.pack('<IIIII', iface, ts >> 32, ts & 0xffffffff, len(data), len(data)) + data)
    def save(self, fn):
        open(fn, 'wb').write(bytes(self.out))

def mtp3(opc, dpc, ni=0, si=15, sls=0, payload=b'\x00\x01\x02'):
    sio = (ni << 6) | si
    label = (dpc & 0x3fff) | ((opc & 0x3fff) << 14) | ((sls & 0xf) << 28)
    return bytes([sio]) + struct.pack('<I', label) + payload

def eth_sctp(payload, tsn):
    pad = (-len(payload)) % 4
    chunk = struct.pack('>BBHIHHI', 0, 3, 16 + len(payload), tsn, 0, tsn - 1, 3) + payload + b'\0' * pad
    sctp = struct.pack('>HHII', 2905, 2905, 0x11223344, 0) + chunk
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(sctp), tsn, 0, 64, 132, 0,
                     bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2])) + sctp
    return bytes.fromhex('020000000002020000000001') + b'\x08\x00' + ip

def m3ua_data(opc, dpc, ni=0, si=15, mp=0, sls=0, payload=b'\x00\x01\x02\x03'):
    pd = struct.pack('>IIBBBB', opc, dpc, si, ni, mp, sls) + payload
    param = struct.pack('>HH', 0x0210, 4 + len(pd)) + pd
    param += b'\0' * ((-len(param)) % 4)
    return struct.pack('>BBBBI', 1, 0, 1, 1, 8 + len(param)) + param

frames = []
def add(iface, data, note):
    frames.append((iface, data, note))

# MTP3, network indicator 0: point codes from the tables
pcs = NAMES[:24] + NAMES[len(NAMES) // 3:len(NAMES) // 3 + 8] + NAMES[-8:] + OPERS[::400][:10]
pcs = [p for p in pcs if p < 0x4000]
for i, p in enumerate(pcs):
    q = pcs[(i + 7) % len(pcs)]
    add(0, mtp3(p, q, sls=i), 'MTP3 NI 0, OPC %d (%s) DPC %d' % (p, 'name' if p in nameset else 'no name', q))
# a SANC from the table but a code with no name, and unknown SANCs
known_sanc_codes = [(s << 3) | 7 for s in SANC[:10] if ((s << 3) | 7) < 0x4000 and ((s << 3) | 7) not in nameset]
for p in known_sanc_codes:
    add(0, mtp3(p, pcs[0]), 'MTP3 NI 0, SANC known, point code %d without a name' % p)
unknown = [p for p in (0, 1, 7, 100, 200, 0x3fff, 0x3ffe, 0x2000) if (p >> 3) not in sancset]
for p in unknown:
    add(0, mtp3(pcs[1], p), 'MTP3 NI 0, unknown SANC, DPC %d' % p)
# a name known without operator (if any) and the other way round
for p in sorted(nameset - operset)[:3]:
    if p < 0x4000:
        add(0, mtp3(p, pcs[2]), 'MTP3 NI 0, point name without operator name, OPC %d' % p)
for p in sorted(operset - nameset)[:3]:
    if p < 0x4000:
        add(0, mtp3(p, pcs[2]), 'MTP3 NI 0, operator name without point name, OPC %d' % p)
# other network indicators are not analysed
for ni in (1, 2, 3):
    add(0, mtp3(pcs[0], pcs[1], ni=ni), 'MTP3 NI %d (not analysed)' % ni)
# other service indicators
for si in (0, 1, 2):
    add(0, mtp3(pcs[3], pcs[4], si=si, payload=b'\x11\x22\x33\x44'), 'MTP3 NI 0, service indicator %d' % si)

# M3UA over SCTP, network indicator 0 and others
tsn = 1
for i, p in enumerate(pcs[:20]):
    q = pcs[(i + 3) % len(pcs)]
    add(1, eth_sctp(m3ua_data(p, q, sls=i % 16), tsn), 'M3UA NI 0, OPC %d DPC %d' % (p, q)); tsn += 1
for p in known_sanc_codes[:3]:
    add(1, eth_sctp(m3ua_data(p, pcs[0]), tsn), 'M3UA NI 0, SANC known, no name'); tsn += 1
for p in unknown[:4]:
    add(1, eth_sctp(m3ua_data(pcs[1], p), tsn), 'M3UA NI 0, unknown SANC, DPC %d' % p); tsn += 1
add(1, eth_sctp(m3ua_data(pcs[0] + 0x10000, pcs[1] + 0x20000), tsn), 'M3UA NI 0, point codes above 16 bits (truncated for the analysis)'); tsn += 1
for ni in (1, 2, 3):
    add(1, eth_sctp(m3ua_data(pcs[0], pcs[1], ni=ni), tsn), 'M3UA NI %d (not analysed)' % ni); tsn += 1

pn = Pcapng([141, 1])
for iface, data, note in frames:
    pn.packet(iface, data)
pn.save(os.path.join(OUT, 'q708-coverage.pcapng'))

# ---------------------------------------------------------------- malformed
mal = []
mal.append((0, mtp3(pcs[0], pcs[1])[:3], 'MTP3 cut in the routing label'))
mal.append((0, mtp3(pcs[0], pcs[1])[:1], 'MTP3 SIO only'))
d = m3ua_data(pcs[0], pcs[1])
mal.append((1, eth_sctp(d[:14], 1), 'M3UA protocol data cut'))
mal.append((1, eth_sctp(d[:8 + 6], 2), 'M3UA protocol data parameter cut'))
for i in range(40):
    mal.append((0, mtp3(random.getrandbits(14), random.getrandbits(14), ni=0, si=random.choice([0, 1, 2, 3, 5, 15])), 'random MTP3 NI 0'))
mw = Pcapng([141, 1])
for iface, data, note in mal:
    mw.packet(iface, data)
mw.save(os.path.join(OUT, 'q708-coverage-malformed.pcapng'))

if VERBOSE:
    print('frames', len(frames), 'malformed', len(mal), 'tables', len(SANC), len(NAMES), len(OPERS))
    for i, (f, d, n) in enumerate(frames, 1):
        print(i, n)
