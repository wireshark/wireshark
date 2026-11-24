#!/usr/bin/env python3
# Generates test/captures/sscop_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic captures for packet-sscop.c (SSCOP, with Q.2931 payloads).
# Usage: mksscop.py <outdir>
# The frames are SunATM captures (DLT 123, type 0x06 = signalling AAL), so
# the ATM dissector hands them to SSCOP by default.
import os
import struct
import sys
from pcaplib import Pcap

DLT_SUNATM = 123

def u24(x): return struct.pack('!I', x & 0xffffff)[1:]

def atm(pdu, flags=0x06, vpi=0, vci=5):
    return struct.pack('!BBH', flags, vpi, vci) + pdu

def padded(payload):
    pad = (-len(payload)) % 4
    return payload + b'\0' * pad, pad

BGN, BGAK, END, ENDAK, RS, RSAK, BGREJ, SD, ER, POLL, STAT, USTAT, UD, MD, ERAK = range(1, 16)

def sd(payload, ns):
    d, pad = padded(payload)
    return d + bytes([SD | (pad << 6)]) + u24(ns)

def with_trailer8(typ, payload, sq, mr, pad_override=None, extra=0):
    d, pad = padded(payload)
    if pad_override is not None:
        pad = pad_override
    return d + b'\0\0\0' + bytes([sq, typ | (pad << 6) | extra]) + u24(mr)

def poll(ps, s):
    return b'\0' + u24(ps) + bytes([POLL]) + u24(s)

def stat(slist, ps, mr, r):
    return b''.join(b'\0' + u24(x) for x in slist) + b'\0' + u24(ps) + b'\0' + u24(mr) + bytes([STAT]) + u24(r)

def ustat(slist, mr, r):
    return b''.join(b'\0' + u24(x) for x in slist) + b'\0' + u24(mr) + bytes([USTAT]) + u24(r)

def ie(ident, content, flags=0x80):
    return struct.pack('!BBH', ident, flags, len(content)) + content

def q2931(msg, ies=b'', callref=0x000001, flag=0, mflags=0x00):
    body = ies
    return (bytes([0x09, 0x03, (flag << 7) | ((callref >> 16) & 0x7f), (callref >> 8) & 0xff, callref & 0xff])
            + bytes([msg, mflags]) + struct.pack('!H', len(body)) + body)

CAUSE = ie(0x08, bytes([0x80 | 0x02, 0x80 | 0x10]))
CALLED = ie(0x70, bytes([0x80 | 0x20 | 0x01]) + b'39246000000000000000000000000000000000000')
AAL = ie(0x58, bytes([0x05, 0x01, 0x00, 0x00]))
BLLI = ie(0x5e, bytes([0xa2]))
ENDPOINT = ie(0x54, bytes([0x00, 0x80]))

def main(out):
    p = Pcap(DLT_SUNATM)
    add = lambda pdu, **kw: p.add(atm(pdu, **kw))
    # 1-3 connection setup: BGN (with UU data), BGAK, BGREJ
    add(with_trailer8(BGN, b'', 0x01, 0x20))
    add(with_trailer8(BGN, b'UUDATA', 0x02, 0x40))
    add(with_trailer8(BGAK, b'', 0, 0x10) )
    add(with_trailer8(BGREJ, b'xy', 0, 0))
    # 5-6 END with the source bit clear and set, 7 ENDAK
    add(with_trailer8(END, b'', 0, 0))
    add(with_trailer8(END, b'', 0, 0, extra=0x10))
    add(b'\0\0\0\0' + bytes([ENDAK]) + b'\0\0\0')
    # 8-9 RS, RSAK; 10-11 ER, ERAK
    add(with_trailer8(RS, b'', 0x03, 0x30))
    add(b'\0\0\0\0' + bytes([RSAK]) + u24(0x77))
    add(b'\0\0\0' + bytes([0x04]) + bytes([ER]) + u24(0x55))
    add(b'\0\0\0\0' + bytes([ERAK]) + u24(0x66))
    # 12-17 SD carrying Q.2931 messages, with pad 0, 1, 2 and 3
    add(sd(q2931(0x05, CALLED + BLLI), 0))
    add(sd(q2931(0x02, b''), 1))
    add(sd(q2931(0x07, ENDPOINT), 2))
    add(sd(q2931(0x4d, CAUSE, flag=1), 3))
    add(sd(q2931(0x5a, CAUSE), 4))
    add(sd(q2931(0x7d, ie(0x14, bytes([0x0a])), mflags=0x01), 5))
    # 18 SD with N(S) 0xffffff, no payload at all (pad 0, 4 octet PDU)
    add(bytes([SD]) + u24(0xffffff))
    # 19-20 POLL, 21-22 STAT (with and without a list), 23-24 USTAT
    add(poll(7, 8))
    add(poll(0xffffff, 0))
    add(stat([1, 3, 5], 9, 0x100, 6))
    add(stat([], 9, 0x100, 6))
    add(ustat([2], 0x200, 10))
    add(ustat([], 0x200, 10))
    # 25-26 UD (pad 0 and 1), 27 MD, 28 unknown type 0x00 and 29 type 0x10
    d, pad = padded(b'UDDATA')
    add(d + bytes([UD | (pad << 6)]) + b'\0\0\0')
    add(b'12345678' + bytes([UD]) + b'\0\0\0')
    add(b'\0\0\0\0' + bytes([MD]) + b'\0\0\0' + b'\0\0\0\0')
    add(b'\0\0\0\0' + bytes([0x00]) + b'\0\0\0')
    add(b'\0\0\0\0' + bytes([0x10]) + b'\0\0\0')
    # 30-33 short non-SD PDUs with a pad length larger than the PDU
    # (no expert info: only SD hands a payload on)
    add(bytes([UD | (3 << 6)]) + b'\0\0\0')
    add(bytes([UD | (2 << 6)]) + b'\0\0\0')
    add(b'\0\0\0\0' + bytes([BGN | (3 << 6)]) + b'\0\0\0')
    add(b'\0\0\0\0' + bytes([END | (2 << 6)]) + b'\0\0\0')
    # 34-35 the same SunATM frames with other virtual circuits and flag values
    add(sd(q2931(0x05, CALLED), 9), vpi=1, vci=5)
    add(sd(q2931(0x02, b''), 10), flags=0x86, vpi=0, vci=5)
    p.write(os.path.join(out, 'sscop-coverage.pcap'))

    m = Pcap(DLT_SUNATM)
    madd = lambda pdu, **kw: m.add(atm(pdu, **kw))
    # SD PDUs whose pad length is larger than the payload (reproducers of
    # "SSCOP: Do not pass a wrapped payload length to the SD payload")
    madd(bytes([SD | (3 << 6)]) + u24(1))
    madd(b'\x01' + bytes([SD | (3 << 6)]) + u24(2))
    madd(b'\x01\x02' + bytes([SD | (3 << 6)]) + u24(3))
    madd(b'\x01\x02\x03' + bytes([SD | (2 << 6)]) + u24(4))
    # truncated PDUs: shorter than the trailer
    madd(b'\x00\x00')
    madd(b'')
    # Q.2931 payload that is cut short
    madd(sd(q2931(0x05, CALLED)[:12], 6))
    # a status list that is not a multiple of four
    madd(stat([1], 1, 1, 1)[1:])
    m.write(os.path.join(out, 'sscop-coverage-malformed.pcap'))

main(sys.argv[1] if len(sys.argv) > 1 else '.')
