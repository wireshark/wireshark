#!/usr/bin/env python3
# Generates test/captures/isdn_coverage.i4b.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the ISDN dissector
(packet-isdn.c).

The dissector is reached through WTAP_ENCAP_ISDN, which the wiretap
library produces for I4B trace files (i4btrace, FreeBSD isdn4bsd).  An
I4B record has a 32 octet little endian header (length, unit, type,
direction, truncation, count, seconds, microseconds) followed by the
frame.  Type 1 is the D channel (LAPD), 2 and 3 are the B1 and B2
channels; type 0 (layer 1 INFO) is a different encapsulation.  Direction
0 is from the terminal equipment (User->Network), 1 from the network.
All frames are built with struct; nothing comes from a real line.

Usage: mkisdn.py <output directory>

Writes:
  isdn-coverage.i4b            D channel LAPD/Q.931 frames in both
                               directions, a B1 channel running V.120
                               (SABME in the first frame) and a B2 channel
                               running PPP in HDLC framing; each channel is
                               recognised by its first frame
  isdn-coverage-malformed.i4b  a B channel whose first frames are not
                               recognised and whose V.120 SABME comes later
                               (the circuit's dissector is then applied
                               to the earlier frames on the second pass),
                               record header edge cases (layer 1 INFO
                               record, truncated frames)
  isdn-coverage-swapped.i4b    the main capture in big endian byte order
"""
import os
import struct
import sys

TRC_I, TRC_D, TRC_B1, TRC_B2 = 0, 1, 2, 3

def rec(chan_type, direction, payload, sec, usec=0, big=False, trunc=0):
    f = '>IIIiIIII' if big else '<IIIiIIII'
    return struct.pack(f, 32 + len(payload), 0, chan_type, direction, trunc, 0, sec, usec) + payload

def build(big=False):
    t = [1700000000]
    out = []
    def add(ch, d, payload, usec=0):
        t[0] += 1
        out.append(rec(ch, d, payload, t[0], usec, big))
    # LAPD (address: SAPI 0 / TEI 64 from the user; the network answers with C/R set)
    TE_ADDR = bytes([0x00, 0x81]); NT_ADDR = bytes([0x02, 0x81])
    q931_setup = bytes([0x08, 0x01, 0x01, 0x05, 0x04, 0x03, 0x80, 0x90, 0xa3, 0x70, 0x06, 0x81, 0x31, 0x32, 0x33, 0x34, 0x35])
    q931_connect = bytes([0x08, 0x81, 0x01, 0x07])
    q931_release = bytes([0x08, 0x01, 0x01, 0x4d])
    add(TRC_D, 0, TE_ADDR + bytes([0x7f]), 100)                      # SABME with P bit
    add(TRC_D, 1, NT_ADDR + bytes([0x73]), 200)                      # UA
    add(TRC_D, 0, TE_ADDR + bytes([0x00, 0x00]) + q931_setup)        # I frame N(S)=0 N(R)=0, SETUP
    add(TRC_D, 1, NT_ADDR + bytes([0x01, 0x02]))                     # RR N(R)=1
    add(TRC_D, 1, NT_ADDR + bytes([0x00, 0x02]) + q931_connect)      # I frame, CONNECT
    add(TRC_D, 0, TE_ADDR + bytes([0x02, 0x02]) + q931_release)      # I frame, RELEASE
    add(TRC_D, 0, TE_ADDR + bytes([0x53]))                           # DISC
    add(TRC_D, 1, NT_ADDR + bytes([0x73]))                           # UA
    # B1: V.120 (SABME first), then a V.120 data frame and a response
    add(TRC_B1, 0, bytes([0x08, 0x01, 0x7f]))
    add(TRC_B1, 1, bytes([0x08, 0x01, 0x73]))
    add(TRC_B1, 0, bytes([0x08, 0x01, 0x00, 0x00, 0x00]) + b'v120 data')
    add(TRC_B1, 1, bytes([0x08, 0x01, 0x01, 0x02]))
    # B2: PPP in HDLC framing (starts with FF 03): LCP Configure-Request and Configure-Ack
    add(TRC_B2, 0, bytes([0xff, 0x03, 0xc0, 0x21, 0x01, 0x01, 0x00, 0x04]))
    add(TRC_B2, 1, bytes([0xff, 0x03, 0xc0, 0x21, 0x02, 0x01, 0x00, 0x04]))
    add(TRC_B2, 0, bytes([0xff, 0x03, 0xc0, 0x21, 0x09, 0x05, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01]))  # Echo-Request
    return out

def build_unknown_b(big=False):
    """A B channel whose first frame is not V.120 or PPP: data; the V.120
    SABME comes later and the circuit is then V.120 (the conversation
    dissector is set by a later frame)."""
    out = []
    t = 1700001000
    out.append(rec(TRC_B1, 0, b'\x01\x02\x03\x04hello', t, 0, big))
    out.append(rec(TRC_B1, 1, b'\x01', t + 1, 0, big))               # shorter than the SABME pattern
    out.append(rec(TRC_B1, 1, bytes([0x08, 0x01, 0x7f]), t + 2, 0, big))
    out.append(rec(TRC_B1, 0, bytes([0x08, 0x01, 0x03, 0x00]) + b'abc', t + 3, 0, big))
    return out

main = build()
mal = list(build_unknown_b())
mal.append(rec(TRC_I, 0, b'\x00\x00\x00\x02' + bytes(20), 1700002000))          # layer 1 INFO record
mal.append(rec(TRC_D, 0, b'', 1700002001))                                       # empty D frame
mal.append(rec(TRC_D, 1, b'\x00', 1700002002))                                   # one octet D frame
mal.append(rec(TRC_B2, 0, b'', 1700002003))                                      # empty B frame
mal.append(rec(TRC_B2, 1, b'\xff', 1700002004))                                  # a lone 0xFF (shorter than the PPP pattern)
mal.append(rec(TRC_B2, 0, bytes([0xff, 0x03]), 1700002005))                      # HDLC header only
mal.append(rec(TRC_D, 0, bytes([0x00, 0x81, 0x00, 0x00, 0x08, 0x01, 0x01, 0x05, 0x04, 0x03]), 1700002006, trunc=2))

out = sys.argv[1] if len(sys.argv) > 1 else '.'
open(os.path.join(out, 'isdn-coverage.i4b'), 'wb').write(b''.join(main))
open(os.path.join(out, 'isdn-coverage-malformed.i4b'), 'wb').write(b''.join(mal))
open(os.path.join(out, 'isdn-coverage-swapped.i4b'), 'wb').write(b''.join(build(True)))
print(len(main), len(mal))
