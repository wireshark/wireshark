#!/usr/bin/env python3
# Helper module for the sccpmg capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# SCCP message builders (from the sccp-coverage generator): pcapng writer with an SCCP and an MTP3 interface, addresses, messages.
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
