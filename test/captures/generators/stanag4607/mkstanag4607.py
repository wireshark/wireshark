#!/usr/bin/env python3
# Generates test/captures/stanag4607_coverage.4607.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures for the STANAG 4607 (GMTI format) dissector
(packet-stanag4607.c).

Usage: mkstanag4607.py <output directory>

Writes:
  stanag4607-coverage.4607            a native STANAG 4607 file (the wiretap
                                      module opens it by its version field):
                                      mission, job definition, platform
                                      location and dwell segments with every
                                      optional field, target reports, other
                                      segment types, several segments per packet
  stanag4607-coverage-pdu.pcapng      the same kinds of packets with other
                                      header versions (Exported PDU naming the
                                      dissector; UDP needs Decode As)
  stanag4607-coverage-malformed.pcapng  wrong packet and segment sizes, a dwell
                                      without job id, cut-short segments, dwell
                                      count 65535 with no target report fields

Every packet is built with struct; nothing is captured. Positions are
made up.
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import struct
from pcaplib import exported_pdu, LT_ETH, LT_EXPORTED_PDU, pcapng, udp

# ---- dwell existence mask: field number -> bit
D = {'d2': 63, 'd3': 62, 'd4': 61, 'd5': 60, 'd6': 59, 'd7': 58, 'd8': 57, 'd9': 56,
     'd10': 55, 'd11': 54, 'd12': 53, 'd13': 52, 'd14': 51, 'd15': 50, 'd16': 49, 'd17': 48,
     'd18': 47, 'd19': 46, 'd20': 45, 'd21': 44, 'd22': 43, 'd23': 42, 'd24': 41, 'd25': 40,
     'd26': 39, 'd27': 38, 'd28': 37, 'd29': 36, 'd30': 35, 'd31': 34}
for i in range(1, 19):
    D['t%d' % i] = 34 - i       # D32_1 is bit 33 ... D32_18 is bit 16

OPT = [  # optional fields before the dwell area, in order: (name, size)
    ('d10', 4), ('d11', 4), ('d12', 4), ('d13', 4), ('d14', 2), ('d15', 2), ('d16', 4), ('d17', 1),
    ('d18', 1), ('d19', 2), ('d20', 2), ('d21', 2), ('d22', 2), ('d23', 2)]
OPT2 = [('d28', 2), ('d29', 2), ('d30', 2), ('d31', 1)]
TGT = [('t1', 2), ('t2', 4), ('t3', 4), ('t4', 2), ('t5', 2), ('t6', 2), ('t7', 2), ('t8', 2), ('t9', 1),
       ('t10', 1), ('t11', 1), ('t12', 2), ('t13', 2), ('t14', 1), ('t15', 2), ('t16', 1), ('t17', 4), ('t18', 1)]


def seg(kind, body, size=None):
    return struct.pack('>BI', kind, 5 + len(body) if size is None else size) + body


def pkt(segs, version=b'30', nat=b'US', cls=5, sysname=b'NA', code=0x0100, exind=0,
        platform=b'PLATFORM01', mission=0x01020304, job=0x0a0b0c0d, size=None):
    body = b''.join(segs)
    n = 32 + len(body) if size is None else size
    return (version + struct.pack('>I', n) + nat + bytes([cls]) + sysname + struct.pack('>HB', code, exind)
            + platform.ljust(10, b' ')[:10] + struct.pack('>II', mission, job)) + body


def mission(plat=7, year=2026, month=11, day=11, plan=b'PLAN-ALPHA', flight=b'FLIGHT-0001', cfg=b'CFG-A'):
    return seg(1, plan.ljust(12) + flight.ljust(12) + bytes([plat]) + cfg.ljust(10)
               + struct.pack('>HBB', year, month, day))


def jobdef(job=0x0a0b0c0d, cross=0x1234, extra=0):
    return seg(5, struct.pack('>IB', job, 3) + b'MODEL1' + bytes([1, 200])
               + struct.pack('>iiiiiiii', 100000000, 200000000, 100100000, 200100000,
                             100200000, 200200000, 100300000, 200300000)
               + bytes([4]) + struct.pack('>HHHHBH', 5000, 300, 400, 12, 3, 20)
               + struct.pack('>HHH', 111, cross, 333) + bytes([9, 90, 2, 1, 2]))


def platloc(ms=1234567, track=0x1000):
    return seg(13, struct.pack('>IiiiHIb', ms, 123456789, -987654321, 12345, track, 150000, -3))


def dwell(fields=(), count=1, ntargets=None, job_ok=True, revisit=1, idx=1, last=1):
    mask = 0
    for f in fields:
        mask |= 1 << D[f]
    b = struct.pack('>QHHBHIiiI', mask, revisit, idx, last, count, 3600000, 123456, -654321, 15000)
    for name, size in OPT:
        if name in fields:
            b += bytes(range(0x11, 0x11 + size))
    b += struct.pack('>iiHH', 1000000, -2000000, 5000, 4000)
    for name, size in OPT2:
        if name in fields:
            b += bytes(range(0x21, 0x21 + size))
    for k in range(count if ntargets is None else ntargets):
        for name, size in TGT:
            if name in fields:
                b += struct.pack('>I', 0x41424344 + k)[-size:] if size < 4 else struct.pack('>I', 0x41424344 + k)
    return seg(2, b)


ALL_OPT = [n for n, _ in OPT] + [n for n, _ in OPT2]
ALL_T = [n for n, _ in TGT]


def main(out):
    P = []
    P.append(pkt([mission()]))
    P.append(pkt([jobdef()]))
    P.append(pkt([platloc()]))
    P.append(pkt([jobdef(cross=0xffff)]))                           # "No Statement" for 0xffff
    P.append(pkt([platloc(ms=0, track=0)], version=b'21', cls=1, sysname=b'ZZ', code=0x0001, exind=1))
    for plat in (3, 4, 9, 20, 36, 44, 52, 56, 255, 99):
        P.append(pkt([mission(plat=plat, year=2020 + plat % 7, month=1 + plat % 12, day=1 + plat % 28)],
                     cls=1 + plat % 5, exind=(0, 1, 2, 128, 129, 130, 77)[plat % 7],
                     code=1 << (plat % 9)))
    # dwell segments: minimal mask, each optional field alone, all fields, target reports
    P.append(pkt([dwell(())]))
    P.append(pkt([dwell(['d10'], count=0)]))
    for f in ALL_OPT:
        P.append(pkt([dwell([f], count=0)]))
    P.append(pkt([dwell(ALL_OPT, count=0)]))
    P.append(pkt([dwell(ALL_T, count=3)]))
    for f in ALL_T:
        P.append(pkt([dwell([f], count=2)]))
    P.append(pkt([dwell(['t1', 't2', 't3'], count=4)]))
    P.append(pkt([dwell(['t2', 't3', 't4', 't5'], count=2)]))          # no report index: subtree from lat
    P.append(pkt([dwell(['t4', 't5', 't6'], count=2)]))                # delta lat/lon first
    P.append(pkt([dwell(['t5'], count=2)]))
    P.append(pkt([dwell(['d2', 'd3', 'd4', 'd5', 'd6', 'd7', 'd8', 'd9', 'd24', 'd25', 'd26', 'd27'] + ALL_OPT
                        + ALL_T, count=2)]))
    P.append(pkt([dwell(ALL_OPT + ALL_T, count=5, revisit=65535, idx=65535, last=0)]))
    # several segments in one packet, in several orders
    P.append(pkt([mission(), jobdef(), platloc(), dwell(['d10', 't1', 't2', 't3'], count=2),
                  dwell(['d28', 't9'], count=3), platloc(ms=2000000)]))
    P.append(pkt([platloc(ms=999), dwell([], count=0), mission(plat=8)], version=b'21'))
    # other segment types: skipped by their size
    for t in (3, 6, 7, 8, 9, 10, 11, 12, 4, 14, 99, 255):
        P.append(pkt([seg(t, bytes(range(1, 20)))]))
    P.append(pkt([seg(6, b'free text segment\x00\x00'), mission(), seg(10, b'\0' * 9)]))
    # the reproducer of the dwell target loop: count 0xFFFF but no target report field in the mask
    P.append(pkt([dwell([], count=65535, ntargets=0) for _ in range(30)]))
    P.append(pkt([dwell(['d10', 'd28'], count=65535, ntargets=0)]))
    # job definition whose uncertainty and sense fields all say "No Statement" (all ones)
    P.append(pkt([seg(5, jobdef()[5:5 + 45] + b'\xff' * 23)]))
    with open(os.path.join(out, 'stanag4607-coverage.4607'), 'wb') as f:
        for p in P:
            f.write(p)
    print('main capture: %d packets, %d octets' % (len(P), sum(len(p) for p in P)))

    # ---------------------------------------------------------------- Exported PDU and UDP
    pdus = [
        pkt([mission(), platloc()], version=b'40'),
        pkt([mission(plat=3)], version=b'50', platform=b'ABCDEFGHIJ'),
        pkt([mission(plat=5)], version=b'70'),
        pkt([mission(plat=5)], version=b'80'),
        pkt([mission(plat=5)], version=b'90'),
        pkt([mission(plat=5)], version=b'3A'),            # edition 3, not a digit version
        pkt([mission(plat=5)], version=b'/0'),            # edition below '0'
        pkt([mission(plat=5)], version=b':0'),            # edition above '9'
        pkt([dwell(ALL_OPT + ALL_T, count=2), jobdef()], version=b'20'),
        pkt([platloc(ms=61000)]),
    ]
    frames = [(1, exported_pdu('stanag4607', p)) for p in pdus]
    frames += [(0, udp(p, 4607, 4607, ident=i + 1)) for i, p in enumerate(pdus[:3])]
    pcapng(os.path.join(out, 'stanag4607-coverage-pdu.pcapng'), frames, (LT_ETH, LT_EXPORTED_PDU))

    # ---------------------------------------------------------------- malformed
    M = []
    M.append(pkt([mission()], size=1000))                                  # packet size does not match
    M.append(pkt([mission()], size=40))
    M.append(pkt([seg(1, mission()[5:], size=10)]))                        # segment size below the minimum
    M.append(pkt([seg(99, b'0123456789', size=3)]))
    M.append(pkt([seg(1, mission()[5:], size=50)]))                        # mission with a wrong size
    M.append(pkt([seg(5, jobdef()[5:], size=60)]))
    M.append(pkt([seg(13, platloc()[5:], size=20)]))
    M.append(pkt([dwell(ALL_OPT, count=0)], job=0))                        # dwell with job id zero
    M.append(pkt([dwell(ALL_T, count=3)])[:-10])                           # dwell target reports cut short
    M.append(pkt([mission()])[:-10])
    M.append(pkt([jobdef()])[:60])
    M.append(pkt([platloc()])[:44])
    M.append(pkt([mission()])[:36])                                        # shorter than the minimum
    M.append(pkt([dwell([], count=65535, ntargets=0) for _ in range(40)]))   # the loop reproducer, several segments
    M.append(pkt([seg(6, b'x' * 40, size=2 ** 32 - 1)]))                   # huge segment size
    M.append(pkt([seg(6, b'x' * 40, size=2 ** 32 - 1), mission()], version=b'21'))
    M.append(pkt([seg(2, struct.pack('>QHH', 0, 1, 1))]))                  # dwell cut off in the mandatory part
    M.append(b'30' + bytes(20))                                            # not a whole header
    pcapng(os.path.join(out, 'stanag4607-coverage-malformed.pcapng'),
           [(1, exported_pdu('stanag4607', p)) for p in M],
           (LT_ETH, LT_EXPORTED_PDU))
    print('pdu capture: %d frames, malformed capture: %d frames' % (len(frames), len(M)))


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')
