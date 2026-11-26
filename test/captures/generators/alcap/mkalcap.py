#!/usr/bin/env python3
# ALCAP coverage capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""ALCAP, the AAL type 2 signalling protocol (ITU-T Q.2630.x), carried in
MTP3 with the service indicator 12 (AAL2 signalling), as in a UMTS Iub/Iur
transport network. The capture has the link-layer type MTP3 (141) and the
default (ITU, 14 bit point code) MTP3 settings apply.

An ALCAP message is a destination signalling association ID (DSAID), a
message type and a compatibility octet, followed by parameters (id,
compatibility octet, length, data). The main capture has every message
type, every parameter with a valid length and the leg state of a call:
ERQ (originating SAID), ECF (destination SAID), MOD/MOA/MOR, REL and RLC
with the release cause. The legs are found through both SAIDs, and the
frames of a leg are listed in each of its frames ("ALCAP: Fix parameter
decoding and leg state"; it includes the frames of its reproducers:
DESEA/OESEA as the last parameter, SUT with data, SUCI of four octets and
the REL, RLC, REL sequence whose leg state must be the same in the second
pass).

Usage: mkalcap.py [<output directory>]

Writes alcap-coverage.pcap (linktype MTP3) and alcap-coverage-malformed.pcap
(parameters with wrong lengths, a truncated header). Every packet is built
here; nothing comes from a real network.
"""

import os
import struct
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))

from capgen import write_pcap  # noqa: E402

LINKTYPE_MTP3 = 141
SI_AAL2 = 12

# Message types
BLC, BLO, CFN, ECF, ERQ, RLC, REL, RSC, RES, UBC, UBL, MOA, MOR, MOD = range(1, 15)
# Parameter ids
(CAU, CEID, DESEA, DNSEA, ALC, OSAID, SUGR, SUT, SSIA, SSIM, SSISA, SSISU, TCI, MSLC, MSSSI, PT, PLC,
 PSSIAE, PSSIME, SUCI, ONSEA, SSIAE, SSIME, ACC, CP, HC, OESEA, PFBW, PVBWS, PVBWT, TCC, FBW, VBWS,
 VBWT, TCS) = range(1, 36)

NSAP_A = bytes.fromhex('39840f00000000000000000000000000000000aa')
NSAP_B = bytes.fromhex('47000580ffe1000000f21a0b0100000000000bb0')
NSAP_C = bytes.fromhex('450000000000000000000000000000000000cc00')


def mtp3(payload, dpc=2, opc=1, sls=0, si=SI_AAL2, ni=0):
    return bytes([si | (ni << 6)]) + struct.pack('<I', dpc | opc << 14 | sls << 28) + payload


def param(pid, data, compat=0x00):
    return struct.pack('>BBB', pid, compat, len(data)) + data


def msg(dsaid, mtype, params=(), compat=0x00):
    return struct.pack('>IBB', dsaid, mtype, compat) + b''.join(params)


def u32(v):
    return struct.pack('>I', v)


def ceid(path, cid):
    return param(CEID, struct.pack('>IB', path, cid))


def cause(value, coding=0, diag=b''):
    return param(CAU, bytes([(coding & 3), value]) + diag)


def alc(a=64000 // 100, b=2, c=3, d=4, e=45, f=46, g=47, h=48):
    return struct.pack('>HHHHBBBB', a, b, c, d, e, f, g, h)


def stt(v):
    return bytes([v])


def build():
    f = []
    A, B, C, D = 0x0a0a0a0a, 0x0b0b0b0b, 0x0c0c0c0c, 0x0d0d0d0d

    def add(payload, **kw):
        f.append(mtp3(payload, **kw))

    # ---- Call 1: ERQ with the common parameters, ECF, MOD/MOA, REL, RLC
    add(msg(0, ERQ, [param(OSAID, u32(A), 0x40), ceid(7, 9), param(SUGR, u32(0x11223344)),
                     param(DNSEA, NSAP_A), param(ONSEA, NSAP_B), param(DESEA, b'\x04' + b'12345678'),
                     param(OESEA, b'\x03' + b'8765432'), param(ALC, alc()), param(SSIA, bytes.fromhex('c10a7f0a0b0c0d0e')),
                     param(SUT, b'\x03abc'), param(PT, b'\x05'), param(PLC, alc(1, 2, 3, 4, 5, 6, 7, 8)),
                     param(CP, b'\x02'), param(HC, b'\x0f'), param(ACC, b'\x01'), param(SUCI, u32(0x01020304))],
             compat=0x55), sls=1)
    add(msg(A, ECF, [param(OSAID, u32(B)), ceid(7, 9)]), dpc=1, opc=2)
    add(msg(B, MOD, [ceid(7, 9), param(ALC, alc(9, 8, 7, 6, 5, 4, 3, 2)), param(MSLC, b''), param(MSSSI, b''),
                     param(PSSIAE, bytes.fromhex('e21a02ab01020380')), param(PSSIME, bytes.fromhex('e00102'))]))
    add(msg(A, MOA, [ceid(7, 9)]), dpc=1, opc=2)
    add(msg(B, MOR, [ceid(7, 9), cause(34)]))
    add(msg(B, REL, [cause(41)]))
    add(msg(A, RLC, [cause(31)]), dpc=1, opc=2)
    # The reproducer: REL, RLC and a second REL; the leg state is the same in every pass
    add(msg(0, ERQ, [param(OSAID, u32(C)), ceid(8, 1), param(SUGR, u32(5))]))
    add(msg(C, ECF, [param(OSAID, u32(D))]), dpc=1, opc=2)
    add(msg(D, REL, [param(CAU, b'\x00\x29')]))
    add(msg(C, RLC, [param(CAU, b'\x00\x1f')]), dpc=1, opc=2)
    add(msg(D, REL, [param(CAU, b'\x00\x10')]))

    # ---- Every message type
    for mt in (BLC, BLO, CFN, RSC, RES, UBC, UBL, 0, 15, 99):
        add(msg(0x01000000 + mt, mt, [ceid(0, 0)] if mt in (BLC, BLO, UBC, UBL) else
                [ceid(4, 0)] if mt in (RSC, RES) else [cause(97, diag=bytes([3, ERQ, 4, 1]))] if mt == CFN else []))
    # ---- Parameter ids: every one with a valid length (also unknown ids)
    ok = {CAU: cause(31), CEID: ceid(1, 2), DESEA: b'\x01' + b'4915',
          DNSEA: NSAP_C, ALC: alc(), OSAID: u32(0x12345678), SUGR: u32(1), SUT: b'\x02ab' + b'',
          SSIA: bytes(8), SSIM: bytes.fromhex('c00a0b'), SSISA: bytes(14), SSISU: bytes(7), TCI: b'',
          MSLC: b'', MSSSI: b'', PT: b'\x00', PLC: alc(), PSSIAE: bytes(8), PSSIME: bytes(3), SUCI: u32(7),
          ONSEA: NSAP_A, SSIAE: bytes(8), SSIME: bytes(3), ACC: b'\x02', CP: b'\x04', HC: b'\x01',
          OESEA: b'\x02' + b'99', PFBW: bytes(12), PVBWS: bytes(13), PVBWT: bytes(22), TCC: b'', FBW: bytes(12),
          VBWS: bytes(13), VBWT: bytes(22), TCS: b''}
    ok[CEID] = struct.pack('>IB', 1, 2)
    ok[CAU] = bytes([0, 31])
    ok[SUT] = b'\x02ab'
    ok[DESEA] = b'\x01' + b'4915'
    ok[OESEA] = b'\x02' + b'99'
    ok[SSIM] = bytes.fromhex('c00a0b')
    for pid in range(0, 40):
        data = ok.get(pid, b'\x00\x01\x02')
        add(msg(0x02000000 + pid, MOD, [param(pid, data, compat=pid & 0x77)]))
    # Parameters filled with values: audio profiles, bit fields, cause coding, multirate
    for i, pr in enumerate((0x00, 0x40, 0x80, 0xc0)):
        body = bytes([pr | 0x3f, 0x10 + i, 0, 0xff >> i, 0, 100 + i, 0xaa, 0xbb])
        add(msg(0x03000000 + i, MOD, [param(SSIA, body), param(SSIAE, bytes([pr | (i << 1) | 1, 5, 0, 0xaa >> i, 0, 80, 1, 2, ][:8])),
                                     param(PSSIAE, bytes([pr | 0x0f, 6, 0, 0x55, 0, 90, 3, 4])),
                                     param(SSIME, bytes([pr | 0x1f, 0, 160 + i])),
                                     param(PSSIME, bytes([pr | 0x2a, 1, 2])), param(SSIM, bytes([pr | 0x0a, 0, 40 + i]))]))
    for i, (v, a) in enumerate(((1, 1), (2, 2), (0, 0), (9, 3))):
        add(msg(0x04000000 + i, MOD, [param(ACC, bytes([v])), param(CP, bytes([a + 4 * (i & 1)])),
                                     param(HC, bytes([i * 60])), param(PT, bytes([i * 80]))]))
    # Bandwidth parameters
    add(msg(0x05000000, MOD, [param(PFBW, bytes.fromhex('000001000002 0003 0004 0506'.replace(' ', ''))),
                              param(FBW, bytes.fromhex('000011000012 0013 0014 1516'.replace(' ', ''))),
                              param(PVBWS, bytes.fromhex('000021000022 0023 0024 2526 02'.replace(' ', ''))),
                              param(VBWS, bytes.fromhex('000031000032 0033 0034 3536 03'.replace(' ', ''))),
                              param(PVBWT, bytes(range(1, 23))), param(VBWT, bytes(range(101, 123))),
                              param(SSISA, bytes(range(14))), param(SSISU, bytes(range(7))),
                              param(TCC, b''), param(TCS, b''), param(TCI, b'')]))
    # ---- Cause: codings, ITU values (known and not), diagnostics
    for i, (val, coding, diag) in enumerate((
            (1, 0, b''), (3, 0, b''), (31, 0, b''), (34, 0, b''), (38, 0, b''), (42, 0, b''), (44, 0, b''),
            (47, 0, b''), (93, 0, b''), (95, 0, b''), (96, 0, b''), (100, 0, b''), (102, 0, b''),
            (111, 0, b''), (77, 0, b''), (0, 0, b''), (16, 1, b''), (17, 2, b''), (18, 3, b''),
            (0xff, 0, b''), (41, 0, bytes([2, 0xaa, 0xbb])),
            (97, 0, bytes([0])), (97, 0, bytes([1, ERQ])), (99, 0, bytes([3, ERQ, SUT, 2])),
            (110, 0, bytes([5, ECF, OSAID, 1, SUGR, 2])), (99, 0, bytes([3, REL, DESEA, 1])))):
        # Q.2630: the diagnostics length counts the message identifier and
        # one parameter id and field number pair per 2 octets
        add(msg(0x06000000 + i, REL, [cause(val, coding, diag)]))
    # ---- E.164 and NSAP addresses of several kinds
    for i, (na, num) in enumerate(((0x01, b'1'), (0x03, b'0123456789'), (0x04, b'4655551234'), (0x7f, b'999'), (0xff, b'12'))):
        add(msg(0x07000000 + i, ERQ, [param(OSAID, u32(0x07000000 + i)), param(DESEA, bytes([na]) + num),
                                      param(OESEA, bytes([na]) + num)]))
    for i, ns in enumerate((NSAP_A, NSAP_B, NSAP_C, bytes(20), bytes([0xff] * 20), bytes.fromhex('50') + bytes(19))):
        add(msg(0, ERQ, [param(OSAID, u32(0x08000000 + i)), param(SUGR, u32(0x100 + i)),
                         param(DNSEA, ns), param(ONSEA, ns[::-1])]))
    # ---- Served user transport of several lengths, SUCI values
    for i, n in enumerate((1, 5, 20)):
        add(msg(0, ERQ, [param(OSAID, u32(0x09000000 + i)), param(SUT, bytes([n]) + bytes(range(n))),
                         param(SUCI, u32(0xffffffff >> (8 * i)))]))
    # ---- Compatibility octets and DSAIDs of several kinds
    for i in range(8):
        add(msg(0xffffff00 + i, MOD, [param(CP, b'\x01', compat=(0x73 << (i & 1)) & 0xff ^ i)], compat=(0x47 * (i + 1)) & 0xff))
    # ---- Leg state: a leg found only by its destination SAID, messages of
    # legs that do not exist, ERQ for an OSAID that exists, one-sided legs
    E, F, G, H = 0x0e0e0e0e, 0x0f0f0f0f, 0x1a1a1a1a, 0x1b1b1b1b
    add(msg(0, ERQ, [param(OSAID, u32(E)), ceid(11, 3), param(SUGR, u32(0xabcdef01)), param(DNSEA, NSAP_A)]))
    add(msg(0, ERQ, [param(OSAID, u32(E)), ceid(12, 4)]))                       # same OSAID: the leg stays
    add(msg(E, ECF, [param(OSAID, u32(F))]), dpc=1, opc=2)
    add(msg(F, MOD, [cause(44)]))                                              # by DSAID, release cause set
    add(msg(F, MOR, [cause(31)]))
    add(msg(E, MOA, [param(CAU, b'\x00\x00')]))                                 # cause 0 is ignored
    add(msg(F, REL, [cause(47)]))
    add(msg(E, RLC, [cause(31)]), dpc=1, opc=2)
    add(msg(0x7777, REL, [cause(41)]))                                         # no such leg
    add(msg(0x7777, RLC, [cause(31)]))
    add(msg(0x7777, ECF, [param(OSAID, u32(0x8888))]))
    add(msg(0, ERQ, [param(OSAID, u32(G)), param(ONSEA, NSAP_B)]))              # only an originating NSAP
    add(msg(G, ECF, [param(OSAID, u32(H))]), dpc=1, opc=2)
    add(msg(H, REL, [cause(31)]))
    add(msg(G, RLC, []), dpc=1, opc=2)
    # Other MTP3 point codes and sequence numbers, messages without parameters
    for i in range(4):
        add(msg(0x0a0a0a0a, MOA, []), dpc=100 + i, opc=200 + i, sls=i)
    return f


def build_malformed():
    m = []

    def add(payload):
        m.append(mtp3(payload))

    # Parameters with a wrong length for their fields, one parameter each
    wrong = {CAU: b'\x00', CEID: bytes(4), DESEA: b'\x04', DNSEA: bytes(19), ALC: bytes(11), OSAID: bytes(3),
             SUGR: bytes(5), SUT: b'\x09ab', SSIA: bytes(7), SSIM: bytes(4), SSISA: bytes(13), SSISU: bytes(8),
             TCI: b'\x00', MSLC: b'\x00', MSSSI: b'\x01\x02', PT: b'', PLC: bytes(13), PSSIAE: bytes(9),
             PSSIME: bytes(2), SUCI: bytes(5), ONSEA: bytes(21), SSIAE: bytes(7), SSIME: bytes(4), ACC: bytes(2),
             CP: b'', HC: bytes(2), OESEA: b'\x01', PFBW: bytes(11), PVBWS: bytes(12), PVBWT: bytes(21),
             TCC: b'\x00', FBW: bytes(13), VBWS: bytes(14), VBWT: bytes(23), TCS: b'\x01'}
    for pid, data in wrong.items():
        add(msg(0x0a000000 + pid, MOD, [param(pid, data)]))
    add(msg(0x0b000001, ERQ, [param(DNSEA, b'\x45')]))           # the DNSEA reproducer: length 1
    add(msg(0x0b000002, ERQ, [param(SUT, b'\x01')]))
    add(msg(0x0b000003, ERQ, [param(SUT, b'')]))
    add(msg(0x0b000004, ERQ, [param(CAU, b'')]))
    add(msg(0x0b000005, ERQ, [param(DESEA, b'')]))
    add(msg(0x0b000006, ERQ, [param(OESEA, b'')]))
    # Truncated: header, parameter header, parameter data, diagnostics
    full = msg(0x0c000001, ERQ, [param(OSAID, u32(1)), param(CAU, bytes([0, 97, 3, ERQ, SUT, 2]))])
    for n in (0, 3, 5, 6, 8, 9, 12, 14, 17, 18, 20, 22):
        if n <= len(full):
            m.append(mtp3(full[:n]))
    # A parameter length past the end
    add(msg(0x0c000002, ERQ, [struct.pack('>BBB', OSAID, 0, 200) + bytes(4)]))
    return m


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    clean = build()
    malformed = build_malformed()
    write_pcap(os.path.join(out, 'alcap-coverage.pcap'), clean, linktype=LINKTYPE_MTP3)
    write_pcap(os.path.join(out, 'alcap-coverage-malformed.pcap'), malformed, linktype=LINKTYPE_MTP3)
    print('%d + %d frames' % (len(clean), len(malformed)), file=sys.stderr)


if __name__ == '__main__':
    main()
