#!/usr/bin/env python3
# Generates test/captures/rtls_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generator for the RTLS coverage captures.
# Usage: mkrtls.py <outdir>  (rtls-coverage.pcap, rtls-coverage-malformed.pcap)
# RTLS has no default port (UDP Decode As only), so the frames are Exported
# PDUs (linktype 252) naming the "rtls" dissector.
import struct
import sys
import os

APMAC = b'\x02\x00\x00\x00\x00\x05'

def exported(payload):
    name = b'rtls'
    tags = struct.pack('!HH', 12, len(name)) + name + struct.pack('!HH', 0, 0)
    return tags + payload

def hdr(t, mid=1, plen=0, vmaj=1, vmin=0):
    return struct.pack('!HHBBH', t, mid, vmaj, vmin, plen) + APMAC + b'\0\0'

SIG = bytes(range(0xa0, 0xb4))
def mac(n):
    return bytes([0x02, 0, 0, 0, 0, n])

def body(t):
    if t == 0x0000:
        return (mac(0x31) + b'\0\0')
    if t == 0x0001:
        return mac(0x32) + b'\0\0'
    if t in (0x0010, 0x0015):
        return b''
    if t == 0x0011:
        return struct.pack('!H', 0x0003) + b'\0\0'
    if t == 0x0012:
        return (mac(0x33) + bytes([0xb0, 0xa5]) + struct.pack('!I', 123456) + mac(0x34)
                + struct.pack('!HH', 0x8008, 77) + bytes([3, 17, 6, 90]) + b'\0\0')
    if t == 0x0013:
        return (mac(0x35) + bytes([0xa0, 0x0b, 11, 0xc8, 1, 2]) + mac(0x36) + mac(0x37)
                + struct.pack('!I', 5000))
    if t == 0x0017:
        return (mac(0x38) + mac(0x39) + b'ESSID-one'.ljust(33, b'\0') + bytes([36, 3, 0xb4])
                + struct.pack('!HH', 100, 55) + bytes([0xa0, 2]) + b'\0\0')
    if t == 0x0018:
        return (mac(0x3a) + b'ap-essid'.ljust(33, b'\0') + bytes([6, 4, 0xc0])
                + struct.pack('!HH', 200, 66) + bytes([0xa5, 3, 1, 2]) + b'\0\0')
    raise ValueError(t)

def msg(t, nested=False, mid=1):
    b = body(t)
    m = hdr(t, mid, len(b)) + b
    return m if nested else m + SIG

def compound(subs, nested=False, mid=1, count=None):
    b = struct.pack('!HH', len(subs) if count is None else count, 0) + b''.join(subs)
    m = hdr(0x0014, mid, len(b)) + b
    return m if nested else m + SIG

def write(path, pkts):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 252))
        for i, p in enumerate(pkts):
            p = exported(p)
            f.write(struct.pack('<IIII', 1000 + i, 0, len(p), len(p)))
            f.write(p)

def main(outd):
    P = []
    # every message type with a payload decoder
    for i, t in enumerate((0x0000, 0x0001, 0x0010, 0x0011, 0x0012, 0x0013,
                           0x0015, 0x0017, 0x0018)):
        P.append(msg(t, mid=i + 1))
    # NACK flag combinations (bit 0 internal error, bit 1 station not found, reserved)
    for fl in (0x0000, 0x0001, 0x0002, 0xfffc, 0xffff):
        b = struct.pack('!H', fl) + b'\0\0'
        P.append(hdr(0x0011, 50 + fl % 7, 4) + b + SIG)
    # data rates and RSSI values, types and associated values of station reports
    for dr, ty, asc in ((0, 1, 1), (5, 2, 2), (0x0b, 3, 0), (0x20, 1, 1)):
        b = (mac(1) + bytes([0xa0, dr, 6, 0x9c, ty, asc]) + mac(2) + mac(3) + struct.pack('!I', 1))
        P.append(hdr(0x0013, 60, len(b)) + b + SIG)
    # Types handled by the default branch: MMS config set (0x16), unknown type
    for t, n in ((0x0016, 24), (0x0099, 0), (0x0016, 1)):
        b = bytes(range(n))
        P.append(hdr(t, 70, len(b)) + b + SIG)
    # Compound messages
    P.append(compound([msg(0x0012, True), msg(0x0013, True), msg(0x0010, True)]))
    P.append(compound([msg(0x0012, True)] * 4, mid=2))
    P.append(compound([msg(t, True) for t in (0x0000, 0x0001, 0x0011, 0x0015, 0x0017, 0x0018)], mid=3))
    # compound within compound, up to depth 7 and 8 (the limit)
    def nest(levels):
        m = msg(0x0010, True)
        for _ in range(levels):
            m = compound([m], True)
        return compound([m], False)
    P.append(nest(3))
    P.append(nest(7))
    # an unknown message type inside a compound, with 2 messages
    b = bytes(range(10))
    P.append(compound([hdr(0x0077, 5, 10) + b + SIG]) )
    # compound with zero messages
    P.append(compound([], mid=4))
    # Reproducer of "RTLS: Bound the nesting of compound messages": compound
    # reports nested inside themselves, 12 levels (limit 8). The expert info
    # ends the packet early so that the signature is past the end.
    # Kept as the last frame of the main capture.
    mainP = list(P)
    lvl = lambda: hdr(0x0014, 1, 4) + struct.pack('!HH', 1, 0)
    rep = lvl() * 12 + hdr(0x0010) + b'\0' * 20
    mainP.append(rep)
    write(os.path.join(outd, 'rtls-coverage.pcap'), mainP)

    M = []
    # too short for the dissector (less than 36 octets): not RTLS
    M.append(hdr(0x0010)[:10])
    M.append(hdr(0x0010) + SIG[:19])
    # truncated bodies
    M.append(hdr(0x0012, 1, 28) + b'\0' * 10 + SIG[:12])
    M.append(hdr(0x0017, 1, 56) + b'\0' * 30 + SIG)
    M.append(hdr(0x0018, 1, 52) + b'\0' * 30 + SIG)
    # compound claims more messages than present
    M.append(compound([msg(0x0010, True)], count=5))
    M.append(compound([msg(0x0012, True)], count=2))
    # compound message with a truncated sub header
    M.append(hdr(0x0014, 1, 4) + struct.pack('!HH', 1, 0) + hdr(0x0010)[:8] + b'\0' * 20)
    # deep nesting (past the limit) in a few forms
    M.append(rep)
    M.append(lvl() * 9 + hdr(0x0010) + b'\0' * 40)
    M.append(lvl() * 5 + hdr(0x0014, 1, 4) + struct.pack('!HH', 3, 0) + hdr(0x0010) + b'\0' * 20)
    write(os.path.join(outd, 'rtls-coverage-malformed.pcap'), M)

main(sys.argv[1] if len(sys.argv) > 1 else '.')
