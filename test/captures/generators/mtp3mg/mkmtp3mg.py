#!/usr/bin/env python3
# Generates test/captures/mtp3mg_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the MTP3MG coverage captures. Usage: mkmtp3mg.py <outdir>
mtp3mg-coverage.pcapng            main capture (LINKTYPE_MTP3), see README.md
mtp3mg-coverage-malformed.pcapng  truncated and odd input
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


def lab(std, si, payload, ni=2):
    if std == 'itu':
        return itu(si, 0x123, 0x234, 3, payload, ni=ni)
    if std in ('ansi', 'china'):
        return ansi(si, (1, 2, 3), (4, 5, 6), 3, payload, ni=ni)
    return japan(si, 0x1234, 0x4321, 3, payload, ni=ni)

def mg(std, h0, h1, body=b'', si=0):
    """A management message: H0/H1 octet then the body; Japan has a spare octet first."""
    pl = bytes([h1 << 4 | h0]) + body
    if std == 'japan':
        pl = b'\x00' + pl
    return lab(std, si, pl)

def test(std, h1, body, h0=1, si=1):
    pl = bytes([h1 << 4 | h0]) + body
    return lab(std, si, pl)

def itu_apc(pc, status=0): return struct.pack('<H', pc | status << 14)
def a3(n, c, m): return bytes([m, c, n])

def main():
    pc = Pcapng()
    R = {}
    def sect(name): R[name] = [pc.n + 1, None]
    def end(name): R[name][1] = pc.n
    P = pc.pkt

    # ------------------------------------------------------------ ITU
    sect('itu')
    P(mg('itu', 1, 1, b'\x05'));  P(mg('itu', 1, 2, b'\x06'))                  # COO COA
    P(mg('itu', 1, 3, b'\x01\x02\x03')); P(mg('itu', 1, 4, b'\x01\x02\x03'))     # XCO XCA
    P(mg('itu', 1, 5, b'\x02')); P(mg('itu', 1, 6, b'\x03'))                    # CBD CBA
    P(mg('itu', 1, 9, b'\x00'))                                                 # unknown CHM
    P(mg('itu', 2, 1)); P(mg('itu', 2, 2)); P(mg('itu', 2, 7))                  # ECO ECA unknown
    P(mg('itu', 3, 1)); P(mg('itu', 3, 2, itu_apc(0x0123, 2)))                  # RCT TFC
    P(mg('itu', 3, 5))                                                          # unknown FCM
    for h1 in (1, 3, 5): P(mg('itu', 4, h1, itu_apc(0x0456)))                   # TFP TFR TFA
    for h1 in (2, 4, 6): P(mg('itu', 4, h1, itu_apc(0x0456)))                   # TCP.. (ANSI only)
    P(mg('itu', 4, 9))
    for h1 in (1, 2): P(mg('itu', 5, h1, itu_apc(0x0789)))                      # RST RSR
    for h1 in (3, 4): P(mg('itu', 5, h1, itu_apc(0x0789)))                      # RCP RCR (ANSI only)
    P(mg('itu', 5, 9))
    for h1 in range(1, 9): P(mg('itu', 6, h1))                                  # MIM
    P(mg('itu', 6, 9))
    P(mg('itu', 7, 1)); P(mg('itu', 7, 2)); P(mg('itu', 7, 5))                  # TRA TRW unknown
    P(mg('itu', 8, 1, b'\x34\x02')); P(mg('itu', 8, 2)); P(mg('itu', 8, 3)); P(mg('itu', 8, 4)); P(mg('itu', 8, 5))
    P(mg('itu', 10, 1, itu_apc(0x0abc) + b'\x21')); P(mg('itu', 10, 3))         # UPU unknown UFC
    P(mg('itu', 9, 1))                                                          # unknown H0
    P(test('itu', 1, bytes([5 << 4]) + b'ABCDE'))                               # SLTM
    P(test('itu', 2, bytes([3 << 4]) + b'XYZ'))                                 # SLTA
    P(test('itu', 9, b'\x00'))                                                  # unknown test H1
    P(test('itu', 1, b'\x00', h0=2))                                            # unknown test H0
    P(test('itu', 1, bytes([0]), si=2))                                         # SI 2 too
    P(mg('itu', 3, 9, bytes(300)))                                              # unknown FCM, 300 octets of body
    P(mg('itu', 1, 9, bytes(300)))                                              # same: reproduces "Unknown message (300 bytes)"
    end('itu')

    # ------------------------------------------------------------ ANSI
    sect('ansi')
    P(mg('ansi', 1, 1, b'\x35\x02')); P(mg('ansi', 1, 2, b'\x35\x02'))          # COO COA: SLC + 11 bit FSN
    P(mg('ansi', 1, 3, b'\x31\x02\x03\x04')); P(mg('ansi', 1, 4, b'\x31\x02\x03\x04'))
    P(mg('ansi', 1, 5, b'\x35\x02')); P(mg('ansi', 1, 6, b'\x35\x02'))
    P(mg('ansi', 1, 9, b'\x00'))
    P(mg('ansi', 2, 1, b'\x03')); P(mg('ansi', 2, 2, b'\x03')); P(mg('ansi', 2, 7))
    P(mg('ansi', 3, 1)); P(mg('ansi', 3, 2, a3(7, 8, 9) + b'\x02')); P(mg('ansi', 3, 5))
    for h1 in range(1, 7): P(mg('ansi', 4, h1, a3(10, 11, 12)))                 # TFP TCP TFR TCR TFA TCA
    P(mg('ansi', 4, 9))
    for h1 in range(1, 5): P(mg('ansi', 5, h1, a3(10, 11, 12)))                 # RST RSR RCP RCR
    P(mg('ansi', 5, 9))
    for h1 in range(1, 9): P(mg('ansi', 6, h1, b'\x05'))
    P(mg('ansi', 6, 9))
    P(mg('ansi', 7, 1)); P(mg('ansi', 7, 2)); P(mg('ansi', 7, 5))
    P(mg('ansi', 8, 1, b'\x34\x02\x00')); P(mg('ansi', 8, 2)); P(mg('ansi', 8, 3)); P(mg('ansi', 8, 4)); P(mg('ansi', 8, 5))
    P(mg('ansi', 10, 1, a3(1, 2, 3) + b'\x21')); P(mg('ansi', 10, 3))
    P(mg('ansi', 9, 1))
    P(test('ansi', 1, bytes([5 << 4 | 3]) + b'ABCDE', si=2))                    # SLTM with SLC
    P(test('ansi', 2, bytes([2 << 4 | 1]) + b'XY', si=2))
    P(test('ansi', 9, b'\x00', si=2)); P(test('ansi', 1, b'\x00', h0=2, si=2))
    end('ansi')

    # ------------------------------------------------------------ Chinese ITU
    sect('china')
    P(mg('china', 1, 1, b'\x05')); P(mg('china', 1, 3, b'\x01\x02\x03')); P(mg('china', 1, 5, b'\x02'))
    P(mg('china', 2, 1))
    P(mg('china', 3, 2, a3(7, 8, 9) + b'\x02'))
    for h1 in (1, 3, 5): P(mg('china', 4, h1, a3(10, 11, 12)))
    for h1 in (2, 4, 6): P(mg('china', 4, h1, a3(10, 11, 12)))
    for h1 in (1, 2): P(mg('china', 5, h1, a3(10, 11, 12)))
    for h1 in (3, 4): P(mg('china', 5, h1, a3(10, 11, 12)))
    P(mg('china', 6, 1)); P(mg('china', 7, 1)); P(mg('china', 7, 2)); P(mg('china', 8, 1, b'\x34\x02'))
    P(mg('china', 10, 1, a3(1, 2, 3) + b'\x21'))
    P(test('china', 1, bytes([4 << 4]) + b'ABCD', si=1))
    end('china')

    # ------------------------------------------------------------ Japan
    sect('japan')
    P(mg('japan', 1, 1, b'\x05')); P(mg('japan', 1, 5, b'\x02')); P(mg('japan', 1, 6, b'\x03'))
    P(mg('japan', 1, 3, b'\x01\x02\x03'))
    P(mg('japan', 2, 1))
    P(mg('japan', 3, 1)); P(mg('japan', 3, 2, b'\x00' + struct.pack('<H', 0x1234) + b'\x02'))
    P(mg('japan', 4, 1, b'\x02' + struct.pack('<HHHH', 0x0102, 0, 0x0304, 0)))   # TFP, two point codes
    P(mg('japan', 4, 5, b'\x01' + struct.pack('<HH', 0x1111, 0)))                # TFA
    P(mg('japan', 4, 3, b'\x00'))                                                 # TFR: unknown
    P(mg('japan', 4, 2, b'\x00')); P(mg('japan', 4, 4, b'\x00')); P(mg('japan', 4, 6, b'\x00'))
    P(mg('japan', 5, 1, b'\x02' + struct.pack('<HHHH', 0x0a0b, 0, 0x0c0d, 0)))   # RST, two point codes
    P(mg('japan', 5, 2, b'\x00'))                                                 # RSR: unknown
    for h0 in (6, 7, 8, 10): P(mg('japan', h0, 1))                               # not used in Japan
    P(mg('japan', 10, 1, struct.pack('<H', 0x2222) + b'\x21'))
    P(mg('japan', 9, 1))
    for h1 in (1, 2): P(mg('japan', 10, h1, struct.pack('<H', 0x2222) + b'\x21'))
    P(lab('japan', 1, b'\x00\x23\x00' + struct.pack('<H', 0x7711)))              # SRT, correct pattern
    P(lab('japan', 2, b'\x00\x84\x00' + struct.pack('<H', 0x1234)))              # SRA, wrong pattern
    P(lab('japan', 1, b'\x00\x55\x00\x00\x00'))                                  # unknown test message
    end('japan')
    pc.write('mtp3mg-coverage.pcapng')
    with open(os.path.join(OUT, 'sections.txt'), 'w') as f:
        for k, v in R.items():
            f.write('%s %d %d\n' % (k, v[0], v[1]))

    # ------------------------------------------------------------ malformed
    pm = Pcapng()
    for std in ('itu', 'ansi', 'china', 'japan'):
        pm.pkt(lab(std, 0, b''))                       # nothing after the label
        if std == 'japan':
            pm.pkt(lab(std, 0, b'\x00'))
        pm.pkt(mg(std, 1, 1, b''))                     # COO without body
        pm.pkt(mg(std, 4, 1, b''))                     # TFP without point code
        pm.pkt(mg(std, 3, 2, b'\x01'))                 # TFC truncated
        pm.pkt(mg(std, 10, 1, b'\x01'))                # UPU truncated
        pm.pkt(test(std, 1, b'', si=1))                # SLTM without length
        pm.pkt(test(std, 1, bytes([15 << 4]) + b'AB', si=1))   # test pattern longer than the frame
        pm.pkt(mg(std, 5, 1, b'\x03' + b'\x00\x01'))   # Japan RST count beyond the data
    pm.pkt(lab('japan', 1, b'\x00\x23\x00\x00'))      # SRT with a short pattern
    pm.pkt(lab('japan', 1, b'\x00'))
    pm.write('mtp3mg-coverage-malformed.pcapng')

main()
