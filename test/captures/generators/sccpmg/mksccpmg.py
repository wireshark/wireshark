#!/usr/bin/env python3
# Generates test/captures/sccpmg_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generate the synthetic coverage captures for packet-sccpmg.c (SCCP
# management messages: UDT/XUDT/LUDT with the called party SSN 1).
# Usage: mksccpmg.py <outdir>   writes
#   sccpmg-coverage.pcapng            main capture (ITU), SCCP and MTP3 interfaces
#   sccpmg-coverage-ansi.pcapng       ANSI messages (preference mtp3.standard)
#   sccpmg-coverage-japan.pcapng      Japan (preference)
#   sccpmg-coverage-chinese.pcapng    Chinese ITU (preference)
#   sccpmg-coverage-malformed.pcapng  truncated messages
# Everything is built with struct; point codes are made up.
import os
import sys
from sccplib import ansi_addr, Cap, gt4, itu_addr, ludt, U16, udt, XUDT, xudt

SSA, SSP, SST, SOR, SOG, SSC, SBR, SNR, SRT = 1, 2, 3, 4, 5, 6, 0xfd, 0xfe, 0xff


def mg(typ, ssn, pc, smi=0, cong=None):
    """A management message: type, affected SSN, affected point code (bytes), SMI [, congestion]."""
    b = bytes([typ, ssn]) + pc + bytes([smi])
    if cong is not None:
        b += bytes([cong])
    return b


def itu_pc(pc):
    return U16(pc)


def pc3(member, cluster, network):
    return bytes([member, cluster, network])


def carrier(data, ansi=False, cls=0, calling_ssn=1):
    """UDT to SSN 1 (route on SSN) with the message as data."""
    if ansi:
        return udt(ansi_addr(ssn=1), ansi_addr(ssn=calling_ssn), data, cls=cls)
    return udt(itu_addr(ssn=1), itu_addr(ssn=calling_ssn), data, cls=cls)


def main_cap(name):
    c = Cap(name)
    S = c.mtp3
    # every ITU message: SSA, SSP, SST, SOR, SOG with SMI 0-3, SSC with each congestion level
    for typ in (SSA, SSP, SST, SOR, SOG):
        for smi in range(4):
            S(carrier(mg(typ, 6 + smi, itu_pc(0x1000 + typ * 16 + smi), smi)))
    for level in range(16):
        S(carrier(mg(SSC, 7, itu_pc(0x2001), 1, level)))
    # the other ways to carry the same messages: class 1 and 'return on error', XUDT, LUDT,
    # a connectionless message on the SCCP interface, the calling SSN 1
    S(carrier(mg(SSA, 8, itu_pc(0x0102), 0), cls=1))
    S(udt(itu_addr(ssn=1), itu_addr(ssn=1), mg(SST, 9, itu_pc(0x0102), 0), cls=0, handling=8))
    S(xudt(itu_addr(ssn=1), itu_addr(ssn=1), mg(SSP, 10, itu_pc(0x0103), 2)))
    S(ludt(itu_addr(ssn=1), itu_addr(ssn=1), mg(SOR, 11, itu_pc(0x0104), 3)))
    S(xudt(itu_addr(pc=0x0102, ssn=1), itu_addr(pc=0x0201, ssn=1), mg(SSC, 12, itu_pc(0x0104), 0, 5), typ=XUDT))
    c.sccp(carrier(mg(SOG, 13, itu_pc(0x0105), 1)))
    # point code and GT based called addresses ending at SSN 1
    S(udt(itu_addr(pc=0x0102, ssn=1), itu_addr(pc=0x0201, ssn=1), mg(SSA, 14, itu_pc(0x0106), 1)))
    S(udt(itu_addr(ssn=1, gti=4, gt=gt4('491721234567'), ri_ssn=True), itu_addr(ssn=1), mg(SSA, 15, itu_pc(0x0107), 0)))
    # messages that do not apply to ITU: backup routing (ANSI), unknown types; shown as unknown
    # message with a warning
    S(carrier(bytes([SBR, 6]) + itu_pc(0x0108) + bytes([0])))
    S(carrier(bytes([SNR, 6]) + itu_pc(0x0108) + bytes([0])))
    S(carrier(bytes([SRT, 6]) + itu_pc(0x0108) + bytes([0])))
    S(carrier(bytes([0x42, 1, 2, 3, 4])))
    S(carrier(bytes([0x00, 1, 2, 3, 4])))
    # an SSA with trailing bytes, an SST with the maximum SMI bits set
    S(carrier(mg(SSA, 6, itu_pc(0x0102), 0xff) + b'\0\0'))
    c.close()
    return c.n


def ansi_cap(name):
    c = Cap(name, 'ansi')
    S = c.mtp3
    for typ in (SSA, SSP, SST, SOR, SOG):
        for smi in range(4):
            S(carrier(mg(typ, 6 + smi, pc3(1 + smi, 2, 3), smi), ansi=True))
    # SSC is ITU only: in ANSI it is an unknown message
    S(carrier(mg(SSC, 7, pc3(1, 2, 3), 1, 5), ansi=True))
    # ANSI only: backup routing, normal routing, routing status test (nothing but the type is decoded)
    S(carrier(mg(SBR, 6, pc3(1, 2, 3), 1), ansi=True))
    S(carrier(mg(SNR, 6, pc3(1, 2, 3), 1), ansi=True))
    S(carrier(mg(SRT, 6, pc3(1, 2, 3), 1), ansi=True))
    S(carrier(bytes([0x42, 1, 2, 3, 4]), ansi=True))
    c.close()


def japan_cap(name):
    c = Cap(name, 'japan')
    S = c.mtp3
    for typ in (SSA, SSP, SST, SOR, SOG):
        S(carrier(mg(typ, 6, itu_pc(0x1234), 2)))
    S(carrier(mg(SSC, 7, itu_pc(0x1234), 1, 7)))
    S(carrier(bytes([SBR, 6]) + itu_pc(0x0108) + bytes([0])))
    c.close()


def chinese_cap(name):
    c = Cap(name, 'chinese')
    S = c.mtp3
    for typ in (SSA, SSP, SST, SOR, SOG):
        S(carrier(mg(typ, 6, pc3(1, 2, 3), 2)))
    # SSC with the congestion level after the three octet point code
    for level in (0, 3, 15):
        S(carrier(mg(SSC, 7, pc3(1, 2, 3), 1, level)))
    S(carrier(bytes([SNR, 6]) + pc3(1, 2, 3) + bytes([0])))
    c.close()


def malformed_cap(name):
    c = Cap(name)
    S = c.mtp3
    # cut short at each field: type only, + SSN, + point code (1 octet), + point code, + SMI
    full = mg(SSC, 7, itu_pc(0x2001), 1, 3)
    for n in range(1, len(full)):
        S(carrier(full[:n]))
    for typ in (SSA, SSP, SST, SOR, SOG):
        S(carrier(mg(typ, 6, itu_pc(0x1000), 1)[:4]))
    c.close()


def main(outdir):
    n = main_cap(os.path.join(outdir, 'sccpmg-coverage.pcapng'))
    ansi_cap(os.path.join(outdir, 'sccpmg-coverage-ansi.pcapng'))
    japan_cap(os.path.join(outdir, 'sccpmg-coverage-japan.pcapng'))
    chinese_cap(os.path.join(outdir, 'sccpmg-coverage-chinese.pcapng'))
    malformed_cap(os.path.join(outdir, 'sccpmg-coverage-malformed.pcapng'))
    if '-v' in sys.argv:
        print('main frames', n)


if __name__ == '__main__':
    main(sys.argv[1])
