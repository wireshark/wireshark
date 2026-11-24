#!/usr/bin/env python3
# Generates test/captures/sccp_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generate the synthetic coverage captures for packet-sccp.c.
# Usage: mksccp.py <outdir>   writes
#   sccp-coverage.pcapng            main capture (ITU), two interfaces: SCCP
#                                   (linktype 142) and MTP3 (linktype 141)
#   sccp-coverage-ansi.pcapng       messages with ANSI addressing (for the MTP3
#                                   standard preference ANSI, see runcov.sh)
#   sccp-coverage-japan.pcapng      Japan addressing (preference)
#   sccp-coverage-chinese.pcapng    Chinese ITU addressing (preference)
#   sccp-coverage-malformed.pcapng  frames that only malformed input reaches
# Everything is built with struct; point codes, GT digits and so on are made
# up, nothing comes from a network.
import os
import struct
import sys

U16 = lambda *a: struct.pack('<%dH' % len(a), *a)
U32 = lambda *a: struct.pack('<%dI' % len(a), *a)

DLT_MTP3, DLT_SCCP = 141, 142
CR, CC, CREF, RLSD, RLC, DT1, DT2, AK, UDT, UDTS, ED, EA, RSR, RSC, ERR, IT, XUDT, XUDTS, LUDT, LUDTS = range(1, 21)

# a minimal TCAP Begin (otid only): decoded by the TCAP dissector for SSN 6 (HLR)
TCAP = bytes.fromhex('6206480400000001')


class Cap:
    """pcapng with an SCCP interface (0) and an MTP3 interface (1)."""

    def __init__(self, name, std='itu'):
        self.f = open(name, 'wb')
        self.t = 1700000000
        self.std = std
        self.block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
        for dlt in (DLT_SCCP, DLT_MTP3):
            self.block(1, struct.pack('<HHI', dlt, 0, 0))
        self.n = 0

    def block(self, typ, body):
        body += b'\0' * ((-len(body)) % 4)
        self.f.write(struct.pack('<II', typ, len(body) + 12) + body + struct.pack('<I', len(body) + 12))

    def sccp(self, data):
        self.pkt(0, data)

    def mtp3(self, data, dpc=0x0102, opc=0x0201, ni=2, sls=0):
        sio = bytes([(ni << 6) | 3])
        if self.std in ('ansi', 'chinese'):       # 24 bit point codes: member, cluster, network
            label = bytes([dpc & 0xff, (dpc >> 8) & 0xff, 1, opc & 0xff, (opc >> 8) & 0xff, 1, sls])
        elif self.std == 'japan':                 # 16 bit point codes, SLS and a spare octet
            label = U16(dpc, opc) + bytes([sls])
        else:
            label = struct.pack('<I', (dpc & 0x3fff) | ((opc & 0x3fff) << 14) | (sls << 28))
        self.pkt(1, sio + label + data)

    def pkt(self, iface, data):
        self.n += 1
        self.t += 1
        self.block(6, struct.pack('<IIIII', iface, 0, self.t, len(data), len(data)) + data)

    def close(self):
        self.f.close()


# --- addresses -------------------------------------------------------------
def bcd(digits):
    """BCD digits, low nibble first; an odd count pads with a zero nibble."""
    d = [int(c, 16) for c in digits]
    if len(d) % 2:
        d.append(0)
    return bytes(d[i] | (d[i + 1] << 4) for i in range(0, len(d), 2))


def itu_addr(pc=None, ssn=None, gti=0, gt=b'', ri_ssn=None, natl=0):
    """ITU address: address indicator, point code, SSN, global title."""
    if ri_ssn is None:
        ri_ssn = ssn is not None and gti == 0
    ai = (1 if pc is not None else 0) | (2 if ssn is not None else 0) | (gti << 2) | (0x40 if ri_ssn else 0) | (0x80 if natl else 0)
    b = bytes([ai])
    if pc is not None:
        b += U16(pc)
    if ssn is not None:
        b += bytes([ssn])
    return b + gt


def gt1(digits, nai=4, odd=None):
    odd = len(digits) % 2 if odd is None else odd
    return bytes([nai | (0x80 if odd else 0)]) + bcd(digits)


def gt2(digits, tt=0):
    return bytes([tt]) + bcd(digits)


def gt3(digits, np=1, tt=0, es=None):
    es = (1 if len(digits) % 2 else 2) if es is None else es
    return bytes([tt, (np << 4) | es]) + bcd(digits)


def gt4(digits, np=1, nai=4, tt=0, es=None):
    es = (1 if len(digits) % 2 else 2) if es is None else es
    return bytes([tt, (np << 4) | es, nai]) + bcd(digits)


def ansi_addr(pc=None, ssn=None, gt=b'', gti=0, ri_ssn=None, natl=1):
    """ANSI address: indicator, SSN, point code (member, cluster, network), global title."""
    if ri_ssn is None:
        ri_ssn = ssn is not None and gti == 0
    ai = (1 if ssn is not None else 0) | (2 if pc is not None else 0) | (gti << 2) | (0x40 if ri_ssn else 0) | (0x80 if natl else 0)
    b = bytes([ai])
    if ssn is not None:
        b += bytes([ssn])
    if pc is not None:
        b += bytes(pc)
    return b + gt


def lv(b):
    return bytes([len(b)]) + b


# --- messages ----------------------------------------------------------------
def msg(typ, fixed=b'', variables=(), optional=None, long=False):
    """Message type, mandatory fixed parameters, pointers, mandatory variable
    parameters (each one given with its length octet(s)) and the optional
    parameters. `optional` is None when the message has no optional pointer,
    b'' for a zero optional pointer, or the encoded optional parameters
    (including the end octet). Pointers are relative to their own octet (for
    2 octet pointers to the octet after the first one, as the dissector reads
    them)."""
    head = bytes([typ]) + fixed
    psz = 2 if long else 1
    npt = len(variables) + (0 if optional is None else 1)
    pos = len(head) + npt * psz
    ptrs = []
    for i, v in enumerate(variables):
        ptrs.append(pos - (len(head) + i * psz) - (1 if long else 0))
        pos += len(v)
    if optional is not None:
        at = len(head) + len(variables) * psz
        ptrs.append(pos - at - (1 if long else 0) if optional else 0)
    pb = b''.join(U16(p) if long else bytes([p]) for p in ptrs)
    return head + pb + b''.join(variables) + (optional or b'')


def opt(*params, end=True):
    return b''.join(bytes([t, len(v)]) + v for t, v in params) + (b'\0' if end else b'')


def seg(first, cls, remaining, slr):
    return (0x10, bytes([(0x80 if first else 0) | (0x40 if cls else 0) | remaining]) + slr.to_bytes(3, 'little'))


def lr(n):
    return n.to_bytes(3, 'little')


def udt(called, calling, data, cls=0, handling=0):
    return msg(UDT, bytes([cls | (handling << 4)]), [lv(called), lv(calling), lv(data)])


def udts(called, calling, data, cause=0):
    return msg(UDTS, bytes([cause]), [lv(called), lv(calling), lv(data)])


def xudt(called, calling, data, cls=0, hop=15, optional=b'', typ=XUDT, cause=0):
    first = cause if typ == XUDTS else cls
    return msg(typ, bytes([first, hop]), [lv(called), lv(calling), lv(data)], optional)


def ludt(called, calling, data, cls=0, hop=15, optional=b'', typ=LUDT, cause=0):
    first = cause if typ == LUDTS else cls
    return msg(typ, bytes([first, hop]), [lv(called), lv(calling), U16(len(data)) + data], optional, long=True)


def cr(slr, called, cls=2, optional=b''):
    return msg(CR, lr(slr) + bytes([cls]), [lv(called)], optional)


def cc(dlr, slr, cls=2, optional=b''):
    return msg(CC, lr(dlr) + lr(slr) + bytes([cls]), [], optional)


def cref(dlr, cause, optional=b''):
    return msg(CREF, lr(dlr) + bytes([cause]), [], optional)


def rlsd(dlr, slr, cause, optional=b''):
    return msg(RLSD, lr(dlr) + lr(slr) + bytes([cause]), [], optional)


def rlc(dlr, slr):
    return msg(RLC, lr(dlr) + lr(slr))


def dt1(dlr, more, data):
    return msg(DT1, lr(dlr) + bytes([1 if more else 0]), [lv(data)])


def dt2(dlr, ps, pr, more, data):
    return msg(DT2, lr(dlr) + bytes([(ps << 1) | (1 if more else 0), pr << 1]), [lv(data)])


def ak(dlr, pr, credit):
    return msg(AK, lr(dlr) + bytes([pr << 1, credit]))


def ed(dlr, data):
    return msg(ED, lr(dlr), [lv(data)])


def ea(dlr):
    return msg(EA, lr(dlr))


def rsr(dlr, slr, cause):
    return msg(RSR, lr(dlr) + lr(slr) + bytes([cause]))


def rsc(dlr, slr):
    return msg(RSC, lr(dlr) + lr(slr))


def err(dlr, cause):
    return msg(ERR, lr(dlr) + bytes([cause]))


def it(dlr, slr, cls, ps, pr, more, credit):
    return msg(IT, lr(dlr) + lr(slr) + bytes([cls, (ps << 1) | (1 if more else 0), pr << 1, credit]))


# --- the main capture --------------------------------------------------------
def main_cap(name):
    c = Cap(name)
    S = c.mtp3
    called = itu_addr(ssn=250)                   # route on SSN, no dissector registered: payload is data
    calling = itu_addr(ssn=251)
    tcalled = itu_addr(ssn=6)                    # HLR (MAP), linked to TCAP
    tcalling = itu_addr(ssn=8)
    # ---- UDT with different address forms --------------------------------
    S(udt(tcalled, tcalling, TCAP))
    S(udt(itu_addr(pc=0x1234, ssn=146), itu_addr(pc=0x2345, ssn=147), TCAP, cls=1))           # CAMEL, class 1
    S(udt(itu_addr(pc=0x1234, ssn=250), itu_addr(pc=0x2345, ssn=251), b'opaque payload'))      # unassigned SSNs
    S(udt(itu_addr(pc=0x1234, ri_ssn=False), itu_addr(pc=0x2345, ri_ssn=False), b'pc only, route on GT'))
    # global titles: every format, odd and even numbers, number plans
    S(udt(itu_addr(gti=1, gt=gt1('491721234567', 4)), itu_addr(gti=1, gt=gt1('4917212345679', 4)), b'gti 1 even/odd'))
    S(udt(itu_addr(gti=1, gt=gt1('12345', 1)), itu_addr(gti=1, gt=gt1('123456', 3, odd=False)), b'gti 1 subscriber, national'))
    S(udt(itu_addr(gti=2, gt=gt2('0123456789ab')), itu_addr(gti=2, gt=gt2('9876')), b'gti 2'))
    S(udt(itu_addr(gti=3, gt=gt3('491721234567', np=1)), itu_addr(gti=3, gt=gt3('4917212345679', np=1)), b'gti 3 isdn'))
    S(udt(itu_addr(gti=3, gt=gt3('262021234567', np=7)), itu_addr(gti=3, gt=gt3('310150123456789', np=6)), b'gti 3 isdn mobile, land mobile (E.212)'))
    S(udt(itu_addr(gti=4, gt=gt4('491721234567', np=1, nai=4)), itu_addr(gti=4, gt=gt4('491721234567', np=7, nai=4, tt=2)), b'gti 4 international'))
    S(udt(itu_addr(gti=4, gt=gt4('4912345', np=1, nai=3)), itu_addr(gti=4, gt=gt4('12345', np=3, nai=1)), b'gti 4 national, data plan'))
    S(udt(itu_addr(gti=4, ssn=252, pc=0x0abc, gt=gt4('4917212345', np=1, nai=4), ri_ssn=True),
          itu_addr(gti=3, ssn=253, pc=0x0def, gt=gt3('49172', np=6)), b'pc, ssn and gt'))
    S(udt(itu_addr(gti=3, gt=gt3('1fb', np=0xe, es=3)), itu_addr(gti=3, gt=gt3('ad', np=0xf, es=0xf)), b'unusual digits and encoding schemes'))
    S(udt(itu_addr(gti=2, gt=gt2('12f'), natl=1), itu_addr(ssn=5, natl=1), b'national bit'))
    # class values, with and without the "return message on error" handling
    S(udt(called, calling, b'x', cls=0, handling=8))
    S(udt(called, calling, b'x', cls=1, handling=8))
    # UDTS with every return cause
    for cause in range(0, 13):
        S(udts(called, calling, b'returned %d' % cause, cause=cause))
    # an address that is a GT with an unknown translation type and SSN; the SCCP interface directly
    c.sccp(udt(tcalled, tcalling, TCAP))
    c.sccp(udt(itu_addr(gti=4, gt=gt4('491721234567')), itu_addr(ssn=249), b'an unassigned ssn'))
    # ---- XUDT: optional parameters, segmentation, hop counter, importance ----
    o_imp = opt((0x12, b'\x05'), (0x11, b'\x0f'))            # importance (ITU)
    S(xudt(called, calling, b'xudt data', optional=o_imp))
    S(xudt(called, calling, b'xudt data', cls=1, hop=1))
    S(xudt(called, calling, b'xudt returned', typ=XUDTS, cause=2, optional=o_imp))
    S(xudt(called, calling, b'xudt data', optional=opt((0xf0, b'unknown optional parameter'))))
    # the optional parameters carry a short DLR/SLR/ISNI that the ITU decoder shows as unknown or plain
    S(xudt(called, calling, b'xudt data', optional=opt((0xfa, b'\x01\x02'))))
    # segmented XUDT (three segments) whose reassembled payload is a TCAP message, SLR 0x0100
    full = TCAP
    S(xudt(tcalled, tcalling, full[:3], optional=opt(seg(True, 0, 2, 0x0100))))
    S(xudt(tcalled, tcalling, full[3:6], optional=opt(seg(False, 0, 1, 0x0100))))
    S(xudt(tcalled, tcalling, full[6:], optional=opt(seg(False, 0, 0, 0x0100))))
    # a segmented message with another key and class 1; two segments
    S(xudt(called, calling, b'0123456789', cls=1, optional=opt(seg(True, 1, 1, 0x0200))))
    S(xudt(called, calling, b'abcdefghij', cls=1, optional=opt(seg(False, 1, 0, 0x0200))))
    # two interleaved segmented messages; the first never finishes within the capture
    S(xudt(called, calling, b'AAAA', optional=opt(seg(True, 0, 1, 0x0300))))
    S(xudt(called, calling, b'BBBB', optional=opt(seg(True, 0, 1, 0x0301))))
    S(xudt(called, calling, b'bbbb', optional=opt(seg(False, 0, 0, 0x0301))))
    # a segment with other optional parameters before it
    S(xudt(called, calling, b'seg after importance', optional=opt((0x12, b'\x03'), seg(True, 0, 0, 0x0400))))
    # ---- LUDT / LUDTS (2 octet pointers), also segmented -------------------
    S(ludt(called, calling, b'long data unit ' * 20))
    S(ludt(called, calling, b'long data returned', typ=LUDTS, cause=3, optional=o_imp))
    S(ludt(called, calling, b'L1 ' * 100, optional=opt(seg(True, 0, 1, 0x0500))))
    S(ludt(called, calling, b'L2 ' * 100, optional=opt(seg(False, 0, 0, 0x0500))))
    # ---- connection oriented, with an association ------------------------
    A, B = dict(dpc=0x0102, opc=0x0201), dict(dpc=0x0201, opc=0x0102)
    S(cr(0x000011, called, cls=2), **A)
    S(cc(0x000011, 0x000022, cls=2), **B)
    S(dt1(0x000022, False, b'data from A'), **A)
    S(dt1(0x000011, False, b'data from B'), **B)
    S(dt1(0x000022, True, b'segment 1 '), **A)               # DT1 with the "more data" bit: reassembled
    S(dt1(0x000022, True, b'segment 2 '), **A)
    S(dt1(0x000022, False, b'segment 3'), **A)
    S(it(0x000011, 0x000022, 2, 3, 4, False, 5), **B)
    S(rlsd(0x000011, 0x000022, 0), **B)
    S(rlc(0x000022, 0x000011), **A)
    # class 3: CR with optional parameters, CC, DT2, AK, ED, EA, RSR, RSC, ERR
    S(cr(0x000033, called, cls=3, optional=opt((0x09, b'\x08'), (0x04, itu_addr(ssn=249)), (0x0f, b'user data in CR'),
                                              (0x11, b'\x0f'), (0x12, b'\x02'), (0xf1, b'\x00'))), **A)
    S(cc(0x000033, 0x000044, cls=3, optional=opt((0x09, b'\x10'), (0x0f, b'user data in CC'))), **B)
    S(dt2(0x000044, 0, 0, False, b'dt2 one'), **A)
    S(dt2(0x000033, 0, 1, True, b'dt2 more'), **B)
    S(dt2(0x000044, 1, 1, False, b'dt2 two'), **A)
    S(ak(0x000033, 2, 7), **B)
    S(ed(0x000044, b'expedited data'), **A)
    S(ea(0x000033), **B)
    S(rsr(0x000044, 0x000033, 0), **A)
    S(rsc(0x000033, 0x000044), **B)
    S(err(0x000044, 1), **A)
    S(it(0x000033, 0x000044, 3, 1, 2, True, 9), **B)
    S(rlsd(0x000033, 0x000044, 0x0f, optional=opt((0x0f, b'release data'))), **B)
    S(rlc(0x000044, 0x000033), **A)
    # refused connection: CREF with causes
    S(cr(0x000055, called, cls=2), **A)
    S(cref(0x000055, 2), **B)
    # release causes, reset causes, error causes, refusal causes (a set of values each)
    for i, cause in enumerate((0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 0xfe)):
        S(rlsd(0x000100 + i, 0x000200 + i, cause), **B)
    for cause in range(0, 14):
        S(rsr(0x000300, 0x000301, cause), **A)
    for cause in range(0, 6):
        S(err(0x000300, cause), **B)
    for cause in range(0, 16):
        S(cref(0x000400, cause), **B)
    # connection oriented messages with an unknown association (no CR seen)
    S(dt1(0x00beef, False, b'no association'), **A)
    S(dt2(0x00beef, 0, 0, False, b'no association'), **A)
    S(ak(0x00beef, 0, 1), **B)
    S(rlc(0x00beef, 0x00cafe), **A)
    # a CR whose SLR is reused (second CR for the same association)
    S(cr(0x000011, called, cls=2), **A)
    # the data in a class 2 message with a segmenting bit, no payload
    S(dt1(0x000022, False, b''), **A)
    # a DT1 whose data parameter says 255 octets and is followed by more data: "possibly externally
    # reassembled" (a note; the dt1_ignore_length preference takes all the octets)
    S(msg(UDT, bytes([0]), [lv(called), lv(calling), bytes([255]) + bytes(range(256)) + bytes(40)]))
    S(msg(DT2, lr(0x000044) + bytes([0, 0]), [bytes([255]) + bytes(range(256)) + bytes(40)]), **A)
    S(msg(DT1, lr(0x000022) + bytes([0]), [bytes([255]) + bytes(range(256)) + bytes(40)]), **A)
    # an unknown message type is shown as unknown message
    S(bytes([0x7f, 1, 2, 3, 4, 5]))
    # point codes with another network indicator
    S(udt(tcalled, tcalling, TCAP), ni=0)
    # the reproducer of "SCCP: Use wide pointers for XUDT optional parameter scan": an XUDT
    # whose optional parameters run past 64 KiB (unknown parameters of 255 octets, no
    # segmentation parameter): the scan for SEGMENTATION used 16 bit pointers and never ended
    params = [(0x80, bytes([0x01]) * 255)] * 260
    c.sccp(xudt(called, calling, b'data before 64 KiB of optional parameters', optional=opt(*params)))
    # the same over MTP3, where a message in a frame over 64 KiB is rare; LUDT with 64 KiB of optional parameters
    c.sccp(ludt(called, calling, b'long data', optional=opt(*params)))
    c.close()
    return c.n


# --- ANSI --------------------------------------------------------------------
def ansi_cap(name):
    c = Cap(name, 'ansi')
    S = c.mtp3
    pc1, pc2 = (1, 2, 3), (4, 5, 6)
    called = ansi_addr(ssn=250)
    calling = ansi_addr(ssn=251)
    S(udt(ansi_addr(ssn=6), ansi_addr(ssn=8), TCAP))
    S(udt(ansi_addr(ssn=146, pc=pc1), ansi_addr(ssn=147, pc=pc2), TCAP, cls=1))
    S(udt(ansi_addr(pc=pc1, ri_ssn=False), ansi_addr(pc=pc2, ri_ssn=False), b'pc only'))
    S(udt(ansi_addr(gti=1, gt=bytes([0, 0x12]) + bcd('1234567')), ansi_addr(gti=1, gt=bytes([5, 0x11]) + bcd('12345')), b'ansi gt'))
    S(udt(ansi_addr(gti=1, ssn=252, pc=pc1, gt=bytes([0, 0x12]) + bcd('1234567890')), ansi_addr(gti=2, gt=bytes([3]) + bcd('1234')), b'ansi gt tt only, pc ssn gt'))
    S(udt(ansi_addr(natl=0, ssn=250), ansi_addr(natl=0, ssn=251), b'international address in ANSI: warning'))
    S(udt(ansi_addr(ssn=None, ri_ssn=True), ansi_addr(ssn=0, ri_ssn=True), b'route on ssn, no or zero ssn'))
    S(xudt(called, calling, b'xudt', optional=opt((0x12, b'\x05'))))
    S(xudt(called, calling, b'xudt isni', optional=opt((0xfa, bytes([0x20, 1, 2, 3, 4])))))
    S(xudt(called, calling, b'xudt isni 1', optional=opt((0xfa, bytes([0x11, 0x02, 1, 2])))))
    S(xudt(ansi_addr(ssn=6), ansi_addr(ssn=8), TCAP[:3], optional=opt(seg(True, 0, 1, 0x70))))
    S(xudt(ansi_addr(ssn=6), ansi_addr(ssn=8), TCAP[3:], optional=opt(seg(False, 0, 0, 0x70))))
    S(xudt(called, calling, b'returned', typ=XUDTS, cause=1))
    S(ludt(called, calling, b'ludt'))
    S(cr(0x11, called, cls=2))
    S(cc(0x11, 0x22, cls=2))
    S(dt1(0x22, False, b'ansi data'))
    S(rlsd(0x11, 0x22, 0))
    S(rlc(0x22, 0x11))
    c.close()


def japan_cap(name):
    # Japan: 2 octet point codes (16 bit) in the address
    c = Cap(name, 'japan')
    S = c.mtp3
    S(udt(itu_addr(pc=0x1234, ssn=6), itu_addr(pc=0x2345, ssn=8), TCAP))
    S(udt(itu_addr(pc=0x1234, ssn=250), itu_addr(pc=0x2345, ssn=251), b'japan point codes'))
    S(udt(itu_addr(ssn=250, gti=2, gt=gt2('123456')), itu_addr(ssn=251), b'gt'))
    S(udt(itu_addr(gti=4, gt=gt4('8135551234')), itu_addr(gti=3, gt=gt3('81355')), b'gt 3 and 4'))
    S(xudt(itu_addr(pc=0x1234, ssn=250), itu_addr(pc=0x2345, ssn=251), b'xudt'))
    S(udt(bytes([0x01, 0x12]), bytes([0x01, 0x12]), b'short point codes'))
    c.close()


def chinese_cap(name):
    # Chinese ITU: 3 octet point codes in the address
    c = Cap(name, 'chinese')
    S = c.mtp3
    S(udt(bytes([0x03, 6]) + bytes([1, 2, 3]), bytes([0x03, 8]) + bytes([4, 5, 6]), TCAP))
    S(udt(bytes([0x43, 250]) + bytes([1, 2, 3]), bytes([0x43, 251]) + bytes([4, 5, 6]), b'chinese point codes'))
    S(udt(bytes([0x01]) + bytes([1, 2, 3]), bytes([0x01]) + bytes([4, 5, 6]), b'pc only'))
    S(udt(itu_addr(ssn=250, gti=2, gt=gt2('123456')), itu_addr(ssn=251), b'gt'))
    S(xudt(bytes([0x43, 250]) + bytes([1, 2, 3]), bytes([0x43, 251]) + bytes([4, 5, 6]), b'xudt'))
    S(udt(bytes([0x01, 0x12, 0x13]), bytes([0x01, 0x12, 0x13]), b'short point codes'))
    c.close()


def malformed_cap(name):
    c = Cap(name)
    S = c.mtp3
    called = itu_addr(ssn=6)
    calling = itu_addr(ssn=8)
    # a class that does not fit the message type, and an invalid handling value
    S(udt(called, calling, b'x', cls=2))
    S(msg(DT1, lr(1) + bytes([0]), [lv(b'x')]))       # fine; DT1 has no class parameter (kept for the message below)
    S(cc(1, 2, cls=0))
    S(udt(called, calling, b'x', cls=1, handling=3))
    S(udt(called, calling, b'x', cls=0, handling=0xf))
    # a class parameter of the wrong length (an IT message with class and length)
    # called party address with a zero length (digits missing), a GT of 1 octet only
    S(udt(itu_addr(gti=4, gt=b''), calling, b'x'))
    S(udt(itu_addr(gti=2, gt=b''), calling, b'x'))
    S(udt(itu_addr(gti=3, gt=b''), calling, b'x'))
    # routing on SSN without SSN, and with SSN zero (warnings)
    S(udt(itu_addr(ri_ssn=True), itu_addr(ssn=0, ri_ssn=True), b'x'))
    # an address cut short: point code announced, only one octet there
    S(udt(bytes([0x01, 0x12]), calling, b'x'))
    # an address with GT but the length is smaller than the GT header
    S(udt(bytes([0x10]), calling, b'x'))
    S(udt(bytes([0x0c, 0x00]), calling, b'x'))
    S(udt(bytes([0x0d, 0x00, 0x00]), calling, b'x'))
    # pointers that point exactly at the end of the message (the standard detection of MTP3 and M3UA
    # asks the SCCP heuristics, which must not throw)
    S(bytes([UDT, 0, 3, 0, 0]))
    S(bytes([UDT, 0, 2, 2, 0]))
    S(bytes([UDT, 0, 2, 1, 1]))
    S(bytes([XUDT, 0, 15, 4, 4, 4, 4]))
    S(bytes([LUDT, 0, 15, 8, 0, 8, 0, 8, 0, 8, 0]))
    # optional parameters with a wrong length: causes, credit, sequence numbers, importance, segmenting
    for t in (0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e):
        S(cc(1, 2, optional=opt((t, b'\x01\x02\x03'))))
        S(xudt(called, calling, b'x', optional=opt((t, b'\x01\x02\x03'))))
    # global title indicators that are reserved: no GT digits (error), some octets
    S(udt(itu_addr(gti=7, gt=b''), calling, b'x'))
    S(udt(itu_addr(gti=8, gt=b'\x01\x02'), calling, b'x'))
    # a message type alone
    for t in (UDT, XUDT, LUDT, DT1, CR, CC, RLSD):
        S(bytes([t]))
    # variable pointers beyond the message
    S(bytes([UDT, 0, 200, 200, 200, 1, 2, 3]))
    S(bytes([XUDT, 0, 15, 200, 200, 200, 200, 1, 2, 3]))
    # XUDT whose optional pointer leads outside, an optional parameter without end
    S(xudt(called, calling, b'x', optional=opt((0x80, b'abc'), end=False)))
    S(xudt(called, calling, b'x', optional=opt((0x80, b'abc'), (0x81, b'\x01') , end=False)[:-1]))
    # segmentation parameter of the wrong length, a segment of nothing
    S(xudt(called, calling, b'x', optional=opt((0x10, b'\x80\x01\x02'))))
    S(xudt(called, calling, b'x', optional=opt((0x12, b'\x01\x02'))))
    S(xudt(called, calling, b'x', optional=opt((0x10, b'\x80'))))
    # class parameter inside an optional parameters list with a wrong length
    S(cr(1, called, optional=opt((0x05, b'\x01\x02'))))
    # CC, CREF etc. with a wrong length parameter in the optional part
    S(cc(1, 2, optional=opt((0x01, b'\x01\x02\x03\x04'), (0x0f, b''))))
    # a data parameter longer than the message
    m = bytearray(udt(called, calling, b'abc'))
    m[-4] = 100
    S(bytes(m))
    # LUDT cut short
    S(ludt(called, calling, b'abc')[:12])
    # truncated DT2 / IT / AK
    S(dt2(1, 0, 0, False, b'abc')[:6])
    S(it(1, 2, 2, 0, 0, False, 1)[:9])
    S(ak(1, 0, 1)[:5])
    # SCCP over MTP3 with a one octet payload
    S(bytes([UDT]))
    # reassembly: a middle segment without the first one, a last one that does not fit
    S(xudt(called, calling, b'mid', optional=opt(seg(False, 0, 2, 0x0600))))
    S(xudt(called, calling, b'end', optional=opt(seg(False, 0, 0, 0x0600))))
    S(xudt(called, calling, b'end2', optional=opt(seg(False, 0, 0, 0x0600))))
    # the same segmentation key reused by a first segment after finishing
    S(xudt(called, calling, b'first', optional=opt(seg(True, 0, 1, 0x0700))))
    S(xudt(called, calling, b'first again', optional=opt(seg(True, 0, 1, 0x0700))))
    S(xudt(called, calling, b'last', optional=opt(seg(False, 0, 0, 0x0700))))
    c.close()


def main(outdir):
    n = main_cap(os.path.join(outdir, 'sccp-coverage.pcapng'))
    ansi_cap(os.path.join(outdir, 'sccp-coverage-ansi.pcapng'))
    japan_cap(os.path.join(outdir, 'sccp-coverage-japan.pcapng'))
    chinese_cap(os.path.join(outdir, 'sccp-coverage-chinese.pcapng'))
    malformed_cap(os.path.join(outdir, 'sccp-coverage-malformed.pcapng'))
    if '-v' in sys.argv:
        print('main frames', n)


if __name__ == '__main__':
    main(sys.argv[1])
