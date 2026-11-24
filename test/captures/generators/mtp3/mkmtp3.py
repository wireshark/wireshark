#!/usr/bin/env python3
# Generates test/captures/mtp3_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the MTP3 coverage captures. Usage: mkmtp3.py <outdir>
mtp3-coverage.pcapng            main capture (LINKTYPE_MTP3), see README.md
mtp3-coverage-malformed.pcapng  truncated and odd input
Everything is synthetic."""
import struct
import sys
import os

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'

def blk(t, body):
    pad = (-len(body)) % 4
    n = 12 + len(body) + pad
    return struct.pack('<II', t, n) + body + b'\0' * pad + struct.pack('<I', n)

class Pcapng:
    def __init__(self, linktype=141):
        self.b = blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
        self.b += blk(1, struct.pack('<HHI', linktype, 0, 65535))
        self.ts = 1700000000
        self.n = 0
    def pkt(self, data):
        self.ts += 1
        t = self.ts * 1000000
        self.b += blk(6, struct.pack('<IIIII', 0, t >> 32, t & 0xffffffff, len(data), len(data)) + data)
        self.n += 1
        return self.n
    def write(self, name):
        with open(os.path.join(OUT, name), 'wb') as f:
            f.write(self.b)

# ------------------------------------------------------------ MSU builders
def sio(si, ni=0, prio=0):
    return bytes([si | prio << 4 | ni << 6])

def itu(si, dpc, opc, sls, payload, ni=0, prio=0):
    return sio(si, ni, prio) + struct.pack('<I', dpc | opc << 14 | sls << 28) + payload

def pc24(net, cluster, member):
    return bytes([member, cluster, net])

def ansi(si, dpc, opc, sls, payload, ni=2, prio=0):
    return sio(si, ni, prio) + pc24(*dpc) + pc24(*opc) + bytes([sls]) + payload

def japan(si, dpc, opc, sls, payload, ni=2, prio=0, spare=0):
    return sio(si, ni, prio) + struct.pack('<HH', dpc, opc) + bytes([sls | spare << 5]) + payload

# SCCP UDT: called/calling with SSN only (ai selects the layout)
def udt(ai=0x42, called_ssn=1, calling_ssn=1, data=b'\x01\x08\x64\x00\x00', pad=0):
    called = bytes([2, ai, called_ssn]); calling = bytes([2, ai, calling_ssn])
    p1 = 3 + pad
    p2 = p1 - 1 + len(called)
    p3 = p2 - 1 + len(calling)
    return bytes([9, 0, p1, p2, p3]) + b'\0' * pad + called + calling + bytes([len(data)]) + data

SSA24 = b'\x01\x08\x01\x02\x03\x00'      # SSA, 3 octet point code

def isup_rel(cic=1):
    return struct.pack('<H', cic) + bytes([0x0c, 0x02, 0x00, 0x02, 0x80, 0x90])
def isup_rlc(cic=1):
    return struct.pack('<H', cic) + bytes([0x10, 0x00])
def isup_iam_min(cic=1):
    # IAM: nature of connection, forward call indicators, calling party category,
    # transmission medium, pointer to called party number (7 octets), no optional
    return (struct.pack('<H', cic) + bytes([0x01, 0x00, 0x60, 0x01, 0x0a, 0x00, 0x02, 0x00, 0x04, 0x01, 0x10, 0x21, 0x43]))

def snm_coo(fsn=5):      # changeover order (ITU, SLC in label)
    return bytes([0x11, fsn])
def sltm(pattern=b'TESTPATTERN12'):
    return bytes([0x11, len(pattern) << 4]) + pattern

SI_SNM, SI_MTN, SI_MTNS, SI_SCCP, SI_TUP, SI_ISUP = 0, 1, 2, 3, 4, 5

def intl(zone, area, sp):               # 3-8-3 international signalling point code
    return zone << 11 | area << 3 | sp

def main():
    pc = Pcapng()
    R = {}                                           # section name -> (first, last)
    def sect(name, first): R[name] = [first, None]
    def end(name): R[name][1] = pc.n
    # ---------------------------------------------------------- ITU, default prefs
    sect('itu', pc.n + 1)
    for si in range(16):                              # every service indicator
        if si == SI_SNM: pl = snm_coo()
        elif si == SI_MTN or si == SI_MTNS: pl = sltm()
        elif si == SI_SCCP: pl = udt()
        elif si == SI_ISUP or si == 0x0a: pl = isup_rel()
        elif si == 0x0d: pl = struct.pack('<I', 9) + b'\x10\x00'
        elif si in (0x0c, 0x0e): continue
        else: pl = b'\x01\x02\x03\x04'
        pc.pkt(itu(si, intl(2, 100, 3), intl(3, 120, 5), si, pl, ni=0, prio=si & 3))
    for ni in (1, 2, 3):                              # the other network indicators
        pc.pkt(itu(SI_SCCP, 1000 + ni, 2000 + ni, ni, udt(), ni=ni))
        pc.pkt(itu(SI_ISUP, 1000 + ni, 2000 + ni, ni + 4, isup_rlc(ni), ni=ni))
    pc.pkt(itu(SI_ISUP, 0x3fff, 0x3fff, 15, isup_iam_min(7), ni=0))      # largest point code, SLS 15
    pc.pkt(itu(SI_SCCP, 0, 0, 0, udt(), ni=0))
    pc.pkt(itu(SI_SNM, 12, 13, 1, bytes([0x51, 0x00, 0x00]), ni=2))      # TFP-ish (management)
    end('itu')
    # ---------------------------------------------------------- ANSI
    sect('ansi', pc.n + 1)
    for si in (SI_SNM, SI_MTN, SI_SCCP, SI_ISUP, 6, 9):
        pl = {SI_SNM: bytes([0x11, 0x00, 0x05]), SI_MTN: sltm(), SI_SCCP: udt(ai=0xc1, data=SSA24),
              SI_ISUP: isup_rel(), }.get(si, b'\x01\x02')
        pc.pkt(ansi(si, (1, 2, 3), (4, 5, 6), 9 + si, pl, ni=2, prio=si % 4))
    pc.pkt(ansi(SI_SCCP, (255, 255, 255), (0, 0, 0), 0x1f, udt(ai=0xc1, data=SSA24), ni=0))
    pc.pkt(ansi(SI_SCCP, (7, 8, 9), (10, 11, 12), 0xe0 | 5, udt(ai=0xc1, data=SSA24), ni=1, prio=3))
    end('ansi')
    # ---------------------------------------------------------- Chinese ITU
    sect('china', pc.n + 1)
    for si in (SI_SNM, SI_MTN, SI_SCCP, SI_ISUP, 7):
        pl = {SI_SNM: bytes([0x11, 0x00]), SI_MTN: sltm(), SI_SCCP: udt(data=SSA24),
              SI_ISUP: isup_rel()}.get(si, b'\x01\x02')
        pc.pkt(ansi(si, (1, 2, 3), (4, 5, 6), si + 3, pl, ni=2))
    end('china')
    # ---------------------------------------------------------- Japan
    sect('japan', pc.n + 1)
    for si in (6, 7, SI_SCCP, SI_ISUP, 8):
        pl = {SI_SCCP: udt(),
              SI_ISUP: isup_rel()}.get(si, b'\x01\x02')
        pc.pkt(japan(si, 0x1234 + si, 0x4321 + si, si + 3, pl, ni=2, spare=si & 7))
    pc.pkt(japan(SI_SCCP, 0xffff, 0x0001, 0x1f, udt(), ni=3, prio=1))
    end('japan')
    # ---------------------------------------------------------- heuristic standard (SCCP)
    sect('heur', pc.n + 1)
    pc.pkt(itu(SI_SCCP, 100, 200, 1, udt(), ni=2))                                  # ITU
    pc.pkt(ansi(SI_SCCP, (1, 2, 3), (4, 0, 6), 1, udt(ai=0xc1, data=SSA24), ni=2))                # ANSI
    pc.pkt(ansi(SI_SCCP, (1, 2, 3), (4, 0, 6), 1, udt(ai=0x42, data=SSA24), ni=2))                # Chinese ITU
    pc.pkt(japan(SI_SCCP, 100, 200, 0, udt(pad=0), ni=2))                             # Japan
    pc.pkt(itu(SI_SCCP, 100, 200, 1, b'\x00\x00\x00\x00\x00\x00', ni=2))              # no standard fits
    pc.pkt(itu(SI_ISUP, 100, 200, 1, isup_rel(), ni=2))                               # not SCCP
    end('heur')
    pc.write('mtp3-coverage.pcapng')
    with open(os.path.join(OUT, 'sections.txt'), 'w') as f:
        for k, v in R.items():
            f.write('%s %d %d\n' % (k, v[0], v[1]))

    # ---------------------------------------------------------- malformed
    pm = Pcapng()
    pm.pkt(b'\x03')                                   # SIO only
    pm.pkt(b'\x03\x01\x02')                           # short ITU label
    pm.pkt(itu(SI_SCCP, 1, 2, 3, b''))                # no payload
    pm.pkt(itu(SI_SCCP, 1, 2, 3, b'\x09\x00\x03'))    # truncated SCCP
    pm.pkt(itu(SI_ISUP, 1, 2, 3, b'\x01'))            # truncated ISUP
    pm.pkt(itu(SI_SNM, 1, 2, 3, b''))
    pm.pkt(itu(0x0c, 1, 2, 3, b'\x00\x01\x02\x03'))   # AAL2
    pm.pkt(itu(0x0e, 1, 2, 3, b'\x00\x01\x02\x03'))   # GCP
    pm.pkt(itu(SI_TUP, 1, 2, 3, b'\x00'))
    pm.pkt(itu(16 - 1, 1, 2, 3, b'\x00'))
    pm.pkt(ansi(SI_SCCP, (1, 2, 3), (4, 5, 6), 1, b''))
    pm.pkt(japan(SI_SCCP, 1, 2, 3, b''))
    pm.write('mtp3-coverage-malformed.pcapng')

main()
