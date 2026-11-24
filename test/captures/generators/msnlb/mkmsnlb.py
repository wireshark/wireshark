#!/usr/bin/env python3
# Generates test/captures/msnlb_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the MS NLB coverage captures: mkmsnlb.py <outdir> [-v]"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from k11lib import eth, exported_pdu, pcap, pcapng_write

HB, EXT, REL = 0xC0DE01BF, 0xC0DE01C0, 0xC0DE01DE

def ip4(a): return bytes(int(x) for x in a.split('.'))

def hdr(sig, ver=0x0201, uid=1, cip='10.0.0.100', hip='10.0.0.1'):
    return struct.pack('<III', sig, ver, uid) + ip4(cip) + ip4(hip)

def hb(team=0x00ABCD55 | (3 << 3), nrules=2, seed=0):
    b = hdr(HB) + struct.pack('<HHHHII', 1, 2, 1, nrules, 0x11223344, 5000)
    b += struct.pack('<I', team) + b'\0' * 4
    b += b''.join(struct.pack('<I', 0x100 + i + seed) for i in range(33))
    for k in range(4):
        b += b''.join(struct.pack('<Q', (k << 32) + i + seed) for i in range(33))
    b += b''.join(struct.pack('<I', 50 + i) for i in range(33))
    b += b'\0' * (4 * 33)
    return b

def fqdn(name):
    s = name.encode('utf-16-le') + b'\0\0'
    return b'\x01' + bytes([len(s)]) + b'\0\0' + b'\0' * 4 + s + b'\0' * 6

def ipent(fam, addr, pad=b''):
    return b'\x02' + b'\x14' + b'\0\0' + b'\0' * 4 + struct.pack('<H', fam) + addr + pad

def build():
    main, exp, mal, notes = [], [], [], []
    def mark(t): notes.append((len(main) + 1, t))
    mark('membership heartbeats (Ethernet 0x886F): teaming flags, port rule counts')
    main.append(eth(hb(), 0x886F))
    main.append(eth(hb(team=0, nrules=0, seed=7), 0x886F))
    main.append(eth(hb(team=0xFFFFFFFF, nrules=33, seed=9), 0x886F))
    main.append(eth(hb(team=0x00123401 | (2 << 3) | 2), 0x886F))
    mark('extended heartbeats: host names, IPv4/IPv6 addresses, unknown entry type; reliable protocol; unknown signature')
    main.append(eth(hdr(EXT) + fqdn('node1.example.test'), 0x886F))
    main.append(eth(hdr(EXT) + fqdn('a') + fqdn('node2.example.test') + fqdn(''), 0x886F))
    main.append(eth(hdr(EXT) + fqdn('node3') + ipent(2, ip4('192.0.2.77'), b'\0\0'), 0x886F))
    main.append(eth(hdr(EXT) + ipent(2, ip4('192.0.2.78'), b'\0' * 8), 0x886F))
    main.append(eth(hdr(EXT) + ipent(0x17, bytes([0x20, 0x01, 0x0d, 0xb8] + [0] * 11 + [1]), b'\0' * 4), 0x886F))
    main.append(eth(hdr(EXT) + fqdn('node4') + b'\x07' + b'unknown entry', 0x886F))
    mal.append(eth(hdr(EXT), 0x886F))                                 # no entries (malformed)
    main.append(eth(hdr(REL) + b'reliable protocol data', 0x886F))
    main.append(eth(hdr(0x12345678) + b'xyz', 0x886F))
    mark('reproducer of "MSNLB: Use an unsigned offset": an extended heartbeat of 65,556 octets (Ethernet) and the same as Exported PDU msnlb')
    L = 65536 + 20
    body = hdr(EXT, uid=1, cip='192.0.2.1', hip='192.0.2.2')
    ent = fqdn('A')
    assert len(ent) == 18
    body += ent * 3639
    body += b'\x03' + b'\0' * (L - len(body) - 1)
    assert len(body) == L
    main.append(eth(body, 0x886F))
    exp.append(exported_pdu('msnlb', hdr(EXT) + fqdn('exported.example.test')))
    exp.append(exported_pdu('msnlb', hb()))
    exp.append(exported_pdu('msnlb', body))
    # ---- malformed
    mal.append(eth(hdr(EXT) + ipent(0x99, b'\1\2\3\4\5\6', b'\0'), 0x886F))   # unknown family: the padding item starts at the end
    mal.append(eth(hb()[:100], 0x886F))                            # cut in the heartbeat
    mal.append(eth(hb()[:30], 0x886F))
    mal.append(eth(hdr(EXT)[:16], 0x886F))
    mal.append(eth(hdr(EXT) + b'\x01', 0x886F))                    # entry cut after the type
    mal.append(eth(hdr(EXT) + b'\x01\x10\0\0\0\0\0\0' + b'ab', 0x886F))   # unterminated name
    mal.append(eth(hdr(EXT) + b'\x02\x14\0\0\0\0\0\0\x02', 0x886F))       # address cut
    mal.append(eth(hdr(EXT) + b'\x02\x14\0\0\0\0\0\0\x02\0\x01\x02', 0x886F))
    mal.append(eth(hdr(EXT) + b'\x02\x14\0\0\0\0\0\0\x17\0' + b'\1' * 8, 0x886F))
    mal.append(eth(b'\xbf\x01', 0x886F))
    return main, exp, mal, notes

if __name__ == '__main__':
    out = sys.argv[1]
    main, exp, mal, notes = build()
    pcapng_write(os.path.join(out, 'msnlb-coverage.pcapng'), [(1, main), (252, exp)])
    pcap(os.path.join(out, 'msnlb-coverage-malformed.pcap'), mal)
    if '-v' in sys.argv:
        print('main', len(main), '+ exp', len(exp), 'malformed', len(mal))
        for n, t in notes: print(n, t)
