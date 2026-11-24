#!/usr/bin/env python3
# Generates test/captures/wsmp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures for the WSMP dissector (packet-wsmp.c,
WAVE Short Message Protocol, IEEE 1609.3), Ethernet type 0x88DC.

Usage: mkwsmp.py <output directory> [-v]
Writes wsmp-coverage.pcap (main) and wsmp-coverage-malformed.pcap.
Every packet is built with struct; nothing comes from a real network.
"""
import os
import struct
import sys
from pcaplib import pcap, eth

ETH_WSMP = 0x88DC
BC = 'ff:ff:ff:ff:ff:ff'

def f(payload):
    return eth(payload, ETH_WSMP, dst=BC)

def psid(v):
    """P-encoding of a PSID value."""
    if v < 0x80: return bytes([v])
    if v < 0x4080: return struct.pack('!H', 0x8000 | (v - 0x80))
    if v < 0x204080: return struct.pack('!I', 0xC0000000 | ((v - 0x4080) << 8))[:3]
    return struct.pack('!I', 0xE0000000 | (v - 0x204080))

def lc(v):
    """Length and count encoding (8.1.3)."""
    return bytes([v]) if v < 0x80 else struct.pack('!H', 0x8000 | v)

def legacy(version, ps, elems, wid, data, supp=b''):
    """Legacy (version != 3) WSMP: TLVs (channel/rate/txpower), then the
    WAVE element id, a 16-bit length, optional WSMP-S supplement."""
    b = bytes([version]) + ps
    for t, v in elems:
        b += bytes([t, len(v)]) + v
    b += bytes([wid]) + struct.pack('!H', len(supp) + len(data)) + supp + data
    return b

def v3(ies, tpid, ps, data, subtype=0, version=3, wlen=None):
    """Version 3 WSMP: N-header with optional IE extension, TPID,
    T-header (PSID for TPID 0), WSM length and data."""
    b = bytes([(subtype << 4) | (8 if ies is not None else 0) | version])
    if ies is not None:
        b += lc(len(ies))
        for ie, d in ies:
            b += bytes([ie]) + lc(len(d)) + d
    b += bytes([tpid])
    if tpid == 0:
        b += ps
    b += lc(len(data) if wlen is None else wlen) + data
    return b

# An unsecured IEEE 1609.2 Ieee1609Dot2Data: version 3, unsecuredData
DOT2 = bytes.fromhex('0380') + b'\x05hello'

main, ranges = [], []
def add(label, payload):
    main.append(f(payload)); ranges.append((len(main), label))

# --- legacy format
add('legacy: PSID 0x4070 (2 octets), WSMP, data to the data dissector',
    legacy(2, psid(0x4070), [], 0x80, b'legacy payload'))
add('legacy: 1-octet PSID, channel, rate, tx power elements, WSMP',
    legacy(1, psid(0x20), [(0x0F, b'\x95'), (0x10, b'\x0c'), (0x04, b'\x14')], 0x80, b'abc'))
add('legacy: WSMP-S with 1-octet supplement',
    legacy(2, psid(0x4070), [(0x0F, b'\xb2')], 0x81, b'supp one', supp=b'\x05'))
add('legacy: WSMP-S with 3-octet supplement (continuation bits)',
    legacy(2, psid(0x4070), [(0x10, b'\x06')], 0x81, b'supp three', supp=b'\x81\x82\x03'))
add('legacy: WSMP-I',
    legacy(1, psid(0x4070), [], 0x82, b'wsmp-i data'))
add('legacy: 3-octet PSID',
    legacy(2, psid(0x5000), [(0x04, b'\x1e')], 0x80, b'three octet psid'))
add('legacy: 4-octet PSID',
    legacy(2, psid(0x300000), [], 0x80, b'four octet psid'))
add('legacy: 2-octet PSID that is not 0x4070 (no data dissector)',
    legacy(2, psid(0x8000), [], 0x80, b'other psid'))
add('legacy: 2-byte channel element (multi-octet length)',
    legacy(2, psid(0x4070), [(0x0F, b'\x00\x95'), (0x10, b'\x00\x0c'), (0x04, b'\x00\x14')], 0x80, b'wide'))
add('legacy: element IDs the loop does not know are skipped one octet at a time',
    legacy(2, psid(0x4070), [], 0x80, b'x')[:0] + bytes([2]) + psid(0x4070) + b'\x33\x44' + bytes([0x80]) + struct.pack('!H', 3) + b'xyz')
# just under the 16-bit offset limit: 65000 octets of non-WSMP bytes then WSMP
add('legacy: 60000 unknown octets before the WAVE element id (control for the offset wrap)',
    bytes([2]) + psid(0x4070) + b'\x00' * 60000 + bytes([0x80]) + struct.pack('!H', 4) + b'data')
add('legacy: 70000 unknown octets before the WAVE element id (offset past 65536)',
    bytes([2]) + psid(0x4070) + b'\x00' * 70000 + bytes([0x80]) + struct.pack('!H', 4) + b'data')

# --- version 3
add('v3: TPID 0, 1-octet PSID, no IE extension, PSID 32 -> IEEE 1609.2',
    v3(None, 0, psid(32), DOT2))
add('v3: IE extension with transmit power, channel, data rate',
    v3([(4, b'\x14'), (15, b'\x95'), (16, b'\x0c')], 0, psid(32), DOT2))
add('v3: IE with a 2-octet length (130 octets)',
    v3([(8, b'\xaa' * 130)], 0, psid(32), DOT2))
add('v3: unknown IE id 99 and 3D location 6',
    v3([(99, b'\x01\x02'), (6, bytes(10))], 0, psid(32), DOT2))
add('v3: 2-octet PSID 0x8000 (not in the 1609.2 range)',
    v3(None, 0, psid(0x8000), b'unregistered psid'))
add('v3: 3-octet PSID',
    v3(None, 0, psid(0x5000), b'three'))
add('v3: 4-octet PSID 2113685 (default range, 1609.2)',
    v3(None, 0, psid(2113685), DOT2))
add('v3: PSID 128 (2 octets, default range)',
    v3(None, 0, psid(128), DOT2))
add('v3: TPID 2 (ITS port numbers), no T-header decoding',
    v3(None, 2, b'', b'\x00\x01\x00\x02datagram', wlen=None)[:0] + bytes([3, 2]) + b'\x04' + b'port-data')
add('v3: TPID 1 with IE extension',
    v3([(15, b'\x95')], 1, b'', b'abcd'))
add('v3: subtype 3 (GeoNetworking), 2-octet WSM length',
    v3(None, 0, psid(0x8000), b'g' * 200, subtype=3))
add('v3: empty IE extension (count 0)',
    v3([], 0, psid(32), DOT2))
add('v3: 130 octet WSM data, 2-octet WSM length',
    v3(None, 0, psid(0x8000), bytes(130)))

nmain = len(main)
mal = []
def addm(payload):
    mal.append(f(payload))
# --- malformed
addm(legacy(2, psid(0xF0), [], 0x80, b'x'))                                  # invalid PSID in the legacy format
addm(bytes([3]) + bytes([0xF5]) + bytes(8))                                   # v3 with TPID 0xF5, PSID invalid below
addm(v3(None, 0, bytes([0xF0]), b'abc'))                                      # v3 invalid PSID
addm(bytes([3, 0, 0xC1, 0x05, 0x00]) + b'abcde')                              # IE count with the bad 0xC0 encoding
addm(bytes([3 | 8, 1, 15, 0xC2, 0x00, 0x00, 0x00]) + b'abcde')                 # IE length with the bad encoding
addm(bytes([2]) + psid(0x4070) + b'\x00' * 20)                                # legacy: no WAVE element id, runs off the end
addm(bytes([2]) + psid(0x4070) + bytes([0x0F, 0xFF, 0x00]))                   # legacy: element length past the end
addm(legacy(2, psid(0x4070), [], 0x81, b'', supp=b'\x81\x82'))                # legacy: WSMP-S supplement never ends
addm(legacy(2, psid(0x4070), [], 0x80, b'xyz')[:-2])                          # legacy: WSM length past the end
addm(v3([(4, b'\x14')], 0, psid(32), DOT2)[:5])                               # v3: truncated in the IE
addm(v3(None, 0, psid(32), DOT2, wlen=200))                                   # v3: WSM length past the end
addm(bytes([2]))                                                              # truncated before the PSID
addm(bytes([0x1B]))                                                           # v3 header only
# WSMP-S with a supplement longer than the WSM length (wsmlength underflow)
addm(bytes([2]) + psid(0x4070) + bytes([0x81]) + struct.pack('!H', 1) + b'\x81\x81\x05' + b'zz')

out = sys.argv[1]
os.makedirs(out, exist_ok=True)
pcap(os.path.join(out, "wsmp-coverage.pcap"), main)
pcap(os.path.join(out, 'wsmp-coverage-malformed.pcap'), mal)
if '-v' in sys.argv:
    for n, l in ranges: print(n, l)
    print('main', nmain, 'malformed', len(mal))
