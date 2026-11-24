#!/usr/bin/env python3
# Generates test/captures/tcap_gaps_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the TCAP coverage captures (gaps left by tcap_coverage.pcap.gz).
Usage: mktcap.py <outdir>.  All packets are synthetic.  TCAP is carried in
SCCP UDT messages over MTP3 (pcap link type 141); SSN 6 (HLR) selects
TCAP/GSM MAP, and the TCAP dialogue application context 0.0.17.773.1.1.1
makes TCAP dissect the components itself."""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import struct
from berlib import gz, integer, octets, seq, tlv, write_pcap

def mtp3_sccp(called_ssn, calling_ssn, tcap, dpc=100, opc=200, sls=0, cls=0):
    called = bytes([0x42, called_ssn]); calling = bytes([0x42, calling_ssn])
    lc, lg = len(called), len(calling)
    # pointers are relative to their own position
    p1 = 3; p2 = 3 + lc; p3 = 3 + lc + lg
    sccp = bytes([0x09, cls, p1, p2, p3, lc]) + called + bytes([lg]) + calling + bytes([len(tcap)]) + tcap
    rl = struct.pack('<I', dpc | (opc << 14) | (sls << 28))
    return bytes([0x83]) + rl + sccp

def tid(tag, v): return tlv(tag, v)
def otid(b): return tlv(0x48, b)
def dtid(b): return tlv(0x49, b)
def comp_invoke(iid, opcode, param=None):
    b = integer(iid) + integer(opcode, tag=0x02)
    if param is not None: b += param
    return tlv(0xa1, b)
def comps(*c): return tlv(0x6c, b''.join(c))
def begin(o, *items): return tlv(0x62, otid(o) + b''.join(items))
def cont(o, d, *items): return tlv(0x65, otid(o) + dtid(d) + b''.join(items))
def end(d, *items): return tlv(0x64, dtid(d) + b''.join(items))
def abort(d, cause=0): return tlv(0x67, dtid(d) + tlv(0x4a, bytes([cause])))
def uni(*items): return tlv(0x61, b''.join(items))

def dialogue(acn_oid_bytes):
    """AARQ dialogue portion with an application context given as OID content bytes"""
    acn = tlv(0xa1, tlv(0x06, acn_oid_bytes))
    aarq = tlv(0x60, acn)
    return tlv(0x6b, tlv(0x28, tlv(0x06, bytes.fromhex('00118605010101')) + tlv(0xa0, aarq)))
def acn_map(v=3): return bytes.fromhex('04000001000e') + bytes([v])         # 0.4.0.0.1.0.14.v  (locationCancellation)
TCAP_ACN = bytes.fromhex('0011860501010 1'.replace(' ', ''))                   # 0.0.17.773.1.1.1

def sai_param(): return seq(octets(bytes.fromhex('00f110aabbccddee')), b'')

def main(out):
    f = []
    t = [1750000000.0]
    def add(fr, dt=0.25): t[0] += dt; f.append((t[0], fr))
    P = lambda tcap, ssn=6, dt=0.25: add(mtp3_sccp(ssn, ssn, tcap), dt)
    inv = lambda iid=1, op=56: comps(comp_invoke(iid, op, seq(octets(bytes.fromhex('00f110aabbccddee')))))
    res = lambda iid=1: comps(tlv(0xa2, integer(iid) + seq(integer(56), seq())))
    D = dialogue(TCAP_ACN)
    # --- transaction ids of 1 to 4 octets (the SRT keeps the value of such TIDs)
    for n, v in enumerate((b'\x01', b'\x01\x02', b'\x01\x02\x03', b'\x01\x02\x03\x04')):
        P(begin(v, D, inv()), dt=1.0)
        P(end(v, comps(tlv(0xa2, integer(1) + seq(integer(56), seq())))), dt=0.25)
    # Continue and Abort with TIDs of 3 and 4 octets in both directions
    P(begin(b'\xaa\xbb\xcc\xdd', D, inv(2)), dt=1.0)
    P(cont(b'\x11\x22\x33', b'\xaa\xbb\xcc\xdd', res(2)))
    P(cont(b'\xaa\xbb\xcc\xdd', b'\x11\x22\x33', inv(3)))
    P(end(b'\x11\x22\x33', res(3)))
    P(abort(b'\x01\x02\x03\x04'))
    # --- parameter nesting inside the limit, decoded by TCAP itself (ACN: TCAP dialogue)
    def nested(n, leaf=seq(integer(7), octets(b'x'))):
        v = leaf
        for _ in range(n): v = tlv(0x30, v)
        return v
    for n, tag_ in ((1, 0x30), (4, 0x30), (15, 0x30)):
        P(begin(bytes([1, 2, 3, n]), D, comps(comp_invoke(1, 0x2e, nested(n)))), dt=1.0)
    # constructed context-specific and application parameters, primitive ones of many types
    par = seq(tlv(0xa0, integer(1)), tlv(0x41, b'\x01\x02'), tlv(0x81, b'\xff'), tlv(0xa5, tlv(0x04, b'abc')),
              tlv(0x06, bytes.fromhex('2a0304')), tlv(0x0a, b'\x02'), tlv(0x13, b'printable'), tlv(0x17, b'250101000000Z'),
              tlv(0x03, b'\x00\xff'), tlv(0x05, b''), tlv(0x01, b'\x00'), tlv(0x1b, b'general'))
    P(begin(b'\x05\x05\x05\x01', D, comps(comp_invoke(1, 0x2e, par))), dt=1.0)
    P(end(b'\x05\x05\x05\x01', comps(tlv(0xa2, integer(1) + seq(integer(0x2e), par)),
                                     tlv(0xa3, integer(1) + integer(2)))), ssn=10, dt=0.25)
    # unidirectional with the TCAP ACN
    P(uni(D, comps(comp_invoke(1, 0x2e, nested(3)))))
    write_pcap(os.path.join(out, 'tcap-coverage.pcap'), f, linktype=141)
    gz(os.path.join(out, 'tcap-coverage.pcap'), os.path.join(out, 'tcap_gaps_coverage.pcap.gz'))

    # --- malformed: TIDs of other lengths (expert warnings), parameters nested past the limit
    f = []
    t = [1750000000.0]
    for v in (b'', b'\x01\x02\x03\x04\x05', b'\x01\x02\x03\x04\x05\x06', bytes(range(1, 9))):
        P(begin(v, D, inv()), dt=1.0)
        P(end(v, comps(tlv(0xa2, integer(1) + seq(integer(56), seq())))), dt=0.25)
        P(cont(v, v, res(4)))
        P(abort(v))
    # the reproducer of the unbounded parameter recursion: 40 levels (the limit is 16)
    for n in (16, 17, 40):
        P(begin(bytes([9, 9, 9, n]), D, comps(comp_invoke(1, 0x2e, nested(n)))), dt=1.0)
    P(uni(D, comps(comp_invoke(1, 0x2e, nested(30)))))
    # the SRT chain: many Begins with the same OTID, more than 30 s apart (the chain stops at 1000)
    for i in range(1100):
        add(mtp3_sccp(6, 6, begin(b'\x77\x77\x77\x77', D, inv())), 31.0)
    # a TID of 4 octets with a damaged component and truncated messages
    good = begin(b'\x01\x02\x03\x04', D, inv())
    for n in (2, 4, 6, 9, 14, len(good) - 1):
        P(good[:n], dt=1.0)
    write_pcap(os.path.join(out, 'tcap-coverage-malformed.pcap'), f, linktype=141)

if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')
