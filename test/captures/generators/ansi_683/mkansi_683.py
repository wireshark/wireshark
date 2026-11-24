#!/usr/bin/env python3
# ANSI IS-683 coverage capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""ANSI IS-683 (OTASP/OTAPA).

Usage: mkansi_683.py [<output directory>]

Writes ansi_683-coverage.pcap (clean) and ansi_683-coverage-malformed.pcap.
Every packet is built here; nothing comes from a real network.

Carriage (all in Exported PDU, linktype 252):
  - the "ansi_a.ota" dissector table (tag 14) with the direction as the
    table value (tag 32): 0 forward (base station to mobile), 1 reverse;
  - ANSI A DTAP ADDS Deliver (dissector "ansi_a_dtap") with an ADDS User
    Part of burst type OTA; the direction comes from the P2P direction
    tag (35): sent is forward, received is reverse;
  - ANSI MAP SMSDeliveryPointToPoint over ANSI TCAP (dissector
    "ansi_tcap") with ServiceIndicator CDMA OTASP / OTAPA: the Invoke
    carries a forward message, the ReturnResult a reverse one.
"""

import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct

from capgen import LINKTYPE_WIRESHARK_UPPER_PDU, exp_pdu_tag, exported_pdu, write_pcap  # noqa: E402

F, R = 0, 1


# ---------------------------------------------------------------- Exported PDU
def exp_table(direction, payload):
    return exported_pdu(payload, table='ansi_a.ota', table_value=direction)


def exp_name(name, payload, p2p=None):
    extra = exp_pdu_tag(35, struct.pack('>i', p2p)) if p2p is not None else b''
    return exported_pdu(payload, proto=name, extra=extra)


# ---------------------------------------------------------------- helpers
def b(*args):
    """bytes from ints and bytes objects"""
    out = b''
    for a in args:
        out += a if isinstance(a, (bytes, bytearray)) else bytes([a])
    return out


def blk(block_id, data):
    return b(block_id, len(data), data)


def seq(n, start=0x10):
    return bytes((start + i) & 0xff for i in range(n))


def mdn(digits):
    """MDN parameter block: N_DIGITS then the digits, 4 bits each, DTMF
    coded (0 is 10; 11 to 15 and 0 show as '?')"""
    nib = [len(digits)] + [10 if d == '0' else int(d, 16) for d in digits]
    if len(nib) % 2:
        nib.append(0)
    return bytes((nib[i] << 4) | nib[i + 1] for i in range(0, len(nib), 2))


# ---------------------------------------------------------------- NAM blocks
# Forward CDMA/Analog NAM Download (4.5.2.1), 14 octets minimum
def for_nam_cdma_analog(ex_bit, extra=b''):
    d = bytearray(seq(14, 0x21))
    d[3] = (d[3] & ~0x10) | (0x10 if ex_bit else 0)
    return bytes(d) + extra


# Forward CDMA NAM Download (4.5.2.3), 10 octets minimum
def for_nam_cdma(class_bit, extra=b''):
    d = bytearray(seq(10, 0x31))
    d[0] = (d[0] & 0x7f) | (0x80 if class_bit else 0)
    return bytes(d) + extra


# IMSI_T (3.5.2.4, 4.5.2.4), 7 octets
def nam_imsi_t(class_bit):
    d = bytearray(seq(7, 0x41))
    d[0] = (d[0] & 0x7f) | (0x80 if class_bit else 0)
    return bytes(d)


# Reverse CDMA/Analog NAM (3.5.2.1), 17 octets minimum
def rev_nam_cdma_analog(meid, ex_bit, extra=b''):
    d = bytearray(seq(17, 0x51))
    d[3] = (d[3] & ~0x02) | (0x02 if meid else 0)     # SCM MEID bit 0x0200
    d[5] = (d[5] & ~0x10) | (0x10 if ex_bit else 0)
    return bytes(d) + extra


# Reverse CDMA NAM (3.5.2.3), 12 octets minimum
def rev_nam_cdma(class_bit, extra=b''):
    d = bytearray(seq(12, 0x61))
    d[0] = 0xe5     # reserved 11, SLOTTED_MODE 1, reserved 00101
    d[2] = (d[2] & 0x7f) | (0x80 if class_bit else 0)
    return bytes(d) + extra


# ---------------------------------------------------------------- clean
def forward_clean():
    """(description, payload) of forward messages that decode cleanly
    (no exceptions, no error expert infos; some get a warning)"""
    m = []
    # 0 Configuration Request
    m.append(b(0, 4, 0, 1, 2, 3))
    m.append(b(0, 3, 4, 0x80, 0xff))
    m.append(b(0, 1, 0, 0xaa))                      # extraneous data
    # 1 Download Request: every NAM block, reserved block, empty block
    m.append(b(1, 6,
               blk(0, for_nam_cdma_analog(1)),
               blk(0, for_nam_cdma_analog(0, b'\xee\xee')),
               blk(1, mdn('6135550123')),
               blk(1, mdn('5550199')),
               blk(2, for_nam_cdma(1)),
               blk(2, for_nam_cdma(0, b'\xee'))))
    m.append(b(1, 4, blk(3, nam_imsi_t(1)), blk(3, nam_imsi_t(0)),
               blk(0x80, b'\x01\x02\x03'), blk(1, b'\x00')))
    m.append(b(1, 2, blk(4, b''), blk(0xff, b'\x99')))   # empty block
    m.append(b(1, 1, blk(1, b'\x3b\xcf')))              # digits not 0-9
    m.append(b(1, 1, blk(1, mdn('180055501234567'))))     # 15 digits
    m.append(b(1, 1, blk(3, nam_imsi_t(1)), 0x7f))         # FRESH_INCL 0
    m.append(b(1, 1, blk(3, nam_imsi_t(1)), 0x81, 0x23))   # FRESH 15 bits
    m.append(b(1, 0, 0x00, 0xaa))                         # extraneous
    # 2 MS Key Request
    m.append(b(2, 2, 4, seq(4), 3, seq(3, 0x80)))
    m.append(b(2, 2, 0, 0))
    m.append(b(2, 3))
    m.append(b(2, 5))
    m.append(b(2, 4, 0xaa))                               # extraneous
    # 3 Key Generation Request
    m.append(b(3, 4, seq(4, 0x90)))
    m.append(b(3, 0, 0xaa))                               # extraneous
    # 4 Re-Authenticate Request
    m.append(b(4, 0xde, 0xad, 0xbe, 0xef))
    m.append(b(4, 0xde, 0xad, 0xbe))                      # wrong length
    # 5 Commit Request
    m.append(b(5))
    # 6 Protocol Capability Request
    m.append(b(6))
    m.append(b(6, 4, 7, 0, 1, 2, 3, 4, 5, 6))
    m.append(b(6, 4, 1, 0x20, 0xaa))                      # extraneous
    # 7 SSPR Configuration Request
    m.append(b(7, 1, 0x01, 0x40, 0x80))
    m.append(b(7, 0))
    m.append(b(7, 2))
    m.append(b(7, 0, 0xaa))                               # extraneous
    # 8 SSPR Download Request
    m.append(b(8, 0, 5, seq(5, 0xa0)))
    m.append(b(8, 1, 0))
    m.append(b(8, 0, 2, 0x11, 0x22, 0x55))                # FRESH_INCL 0
    m.append(b(8, 1, 2, 0x11, 0x22, 0x80, 0x07))          # FRESH
    m.append(b(8, 0x80, 0, 0x80, 0x07, 0xaa))             # extraneous
    # 9 Validation Request
    m.append(b(9, 6,
               blk(0, b'\x21\x43\x65'),
               blk(1, b'\x89\x67\x45'),
               blk(2, b'\xc0'),
               blk(2, b'\x81\x23\x50'),
               blk(3, b'\xab\xcd'),
               blk(0x80, b'')))
    m.append(b(9, 2, blk(0, b'\x21\x43'), blk(2, b'\x80\x00')))   # lengths
    m.append(b(9, 1, blk(0xff, b'\x01'), 0xaa))           # extraneous
    # 10 OTAPA Request
    m.append(b(10, 0x80))
    m.append(b(10, 0x7f))
    m.append(b(10, 0x80, 0x00))                           # wrong length
    # 11 PUZL Configuration Request
    m.append(b(11, 3))
    m.append(b(11, 0x80, 0x01, 0x02, 0x03, 0x04))
    # 12 PUZL Download Request
    m.append(b(12, 6, blk(0, seq(4)), blk(1, seq(3)), blk(2, seq(2)),
               blk(3, seq(2)), blk(4, b'\x80'), blk(0x80, b''), 0x00))
    m.append(b(12, 1, blk(5, b'\x01'), 0x80, 0x01))
    m.append(b(12, 0, 0x00, 0xaa))
    m.append(b(12, 1, blk(0, seq(2))))                    # no FRESH
    # 13 3GPD Configuration Request
    m.append(b(13, 15, bytes(range(14)), 0x20))
    # 14 3GPD Download Request
    m.append(b(14, 11, blk(0, b'\x01'), blk(1, seq(3)), blk(2, seq(3)),
               blk(6, b'\x02'), blk(7, b'\x03'), blk(8, seq(4)),
               blk(9, seq(4)), blk(10, seq(4)), blk(11, seq(2)),
               blk(12, seq(2)), blk(3, b'')))
    m.append(b(14, 1, blk(0, b'\x01'), 0x81, 0x00))
    m.append(b(14, 0, 0x00, 0xaa))
    # 15 Secure Mode Request; START_SECURE_MODE, SECURE_MODE_IND, reserved
    m.append(b(15, 0x85, seq(8, 0xc0)))     # SSD_A/SSD_B, reserved 101
    m.append(b(15, 0x8d, seq(8, 0xc8)))     # 3G Root Key, reserved 101
    m.append(b(15, 0xf3, seq(8, 0xd0)))     # other key type, reserved 011
    m.append(b(15, 0x02))                   # stop
    m.append(b(15, 0x05, 0xaa))             # extraneous
    # 16 Reserved
    m.append(b(16, 0x01, 0x02))
    # 17 MMD Configuration Request
    m.append(b(17, 2, 0, 1))
    # 18 MMD Download Request
    m.append(b(18, 2, blk(0, seq(6)), blk(1, b''), 0x00))
    m.append(b(18, 1, blk(0, seq(2)), 0x80, 0x00, 0xaa))
    m.append(b(18, 1, blk(0, seq(2))))                    # no FRESH
    # 19 System Tag Configuration Request
    m.append(b(19, 0))
    m.append(b(19, 2, 0x00, 0x20, 0x80))
    m.append(b(19, 6, 0x00, 0x00, 0x40, 0xaa))            # extraneous
    # 20 System Tag Download Request
    m.append(b(20, 0, 3, seq(3)))
    m.append(b(20, 1, 0, 0xaa))                           # extraneous
    m.append(b(20, 0x80, 2, 0x01, 0x02))
    # 21 Service Key Generation Request
    m.append(b(21, 0xe0, 0x00))
    m.append(b(21, 0x40, 0x00, 0xaa))                     # extraneous
    # 22 MMS Configuration Request
    m.append(b(22, 3, 0, 1, 2))
    # 23 MMS Download Request
    m.append(b(23, 2, blk(0, b'http://mms.example/'), blk(1, b''), 0x00))
    m.append(b(23, 1, blk(0, b'x'), 0x80, 0x00))
    m.append(b(23, 0, 0x00, 0xaa))                        # extraneous
    m.append(b(23, 1, blk(0, b'x')))                      # no FRESH
    # unknown message types
    m.append(b(24))
    m.append(b(0xff, 0x00))
    return m


def reverse_clean():
    m = []
    # 0 Configuration Response
    m.append(b(0, 5,
               blk(0, rev_nam_cdma_analog(1, 1)),
               blk(0, rev_nam_cdma_analog(0, 0, b'\xee\xee')),
               blk(1, mdn('6135550123')),
               blk(2, rev_nam_cdma(1)),
               blk(2, rev_nam_cdma(0, b'\xee')),
               0, 1, 7, 0x80, 0xff))
    m.append(b(0, 4, blk(1, mdn('5550199')), blk(3, nam_imsi_t(1)),
               blk(3, nam_imsi_t(0)), blk(0x80, b'\x01\x02'),
               0, 0, 0, 47))
    m.append(b(0, 1, blk(4, b''), 2, 0x7f))           # FRESH_INCL 0
    m.append(b(0, 1, blk(1, mdn('')), 0, 0x80, 0x01))  # FRESH
    m.append(b(0, 0, 0x00, 0xaa))                     # extraneous
    # 1 Download Response
    m.append(b(1, 3, 0, 0, 1, 1, 0x80, 200))
    m.append(b(1, 0, 0xaa))
    # 2 MS Key Response
    m.append(b(2, 0))
    m.append(b(2, 0, 0))                              # wrong length
    # 3 Key Generation Response
    m.append(b(3, 0, 4, seq(4, 0x70)))
    m.append(b(3, 1, 0))
    m.append(b(3, 0, 0, 0xaa))                        # extraneous
    # 4 Re-Authenticate Response
    m.append(b(4, seq(7, 0x30)))
    m.append(b(4, seq(6, 0x30)))                      # wrong length
    # 5 Commit Response
    m.append(b(5, 0))
    # 6 Protocol Capability Response
    m.append(b(6, 0x01, 0x23, 0x45, 3, 0, 2, 1, 3, 200, 1,
               3, 0xf8, 0x12, 0x34))
    m.append(b(6, 0x01, 0x23, 0x45, 0, 0))
    m.append(b(6, 0x01, 0x23, 0x45, 1, 11, 1, 1, 0x50))
    m.append(b(6, 0x01, 0x23, 0x45, 0, 0, 0xaa))      # extraneous
    # 7 SSPR Configuration Response
    m.append(b(7, 1, 0, 4, seq(4, 0x20)))
    m.append(b(7, 0, 0, 0, 0x7f))
    m.append(b(7, 2, 8, 2, 0x01, 0x02, 0x80, 0x10))
    m.append(b(7, 0x80, 0, 0, 0x80, 0x10, 0xaa))      # extraneous
    # 8 SSPR Download Response
    m.append(b(8, 0, 0, 0x00, 0x40, 0x80))
    m.append(b(8, 1, 9, 0x01, 0x00, 0x20))
    m.append(b(8, 2, 0, 0x00, 0x00, 0x00))
    m.append(b(8, 0, 0))                              # wrong length
    # 9 Validation Response
    m.append(b(9, 3, 0, 0, 1, 11, 2, 13))
    m.append(b(9, 0, 0xaa))
    # 10 OTAPA Response
    m.append(b(10, 0, 0x00))
    m.append(b(10, 0, 0x01, 0x12, 0x34, 0x56, 0x78))
    m.append(b(10, 10, 0x00, 0xaa))                   # extraneous
    # 11 PUZL Configuration Response
    m.append(b(11, 3, 0, 3, seq(3), 0x00))
    m.append(b(11, 0, 17, 0, 0x80, 0x02))
    m.append(b(11, 1, 0, 0))
    m.append(b(11, 2, 0, 0, 0x00, 0xaa))              # extraneous
    # 12 PUZL Download Response
    m.append(b(12, 2, 0, 0, 0x80, 0x15, 0x00, 0x7b, 1, 16, 0x00))
    m.append(b(12, 1, 4, 15, 0x7f, 0xaa))             # extraneous
    # 13 3GPD Configuration Response
    m.append(b(13, 3, blk(0, seq(2)), 0, blk(4, seq(3)), 19, blk(14, b''),
               0, 0x00))
    m.append(b(13, 1, blk(13, b'\x01'), 0, 0x80, 0x00))
    m.append(b(13, 0, 0x00, 0xaa))
    m.append(b(13, 1, blk(1, b'\x01'), 0))           # no FRESH
    # 14 3GPD Download Response
    m.append(b(14, 2, 0, 0, 12, 36))
    m.append(b(14, 0, 0xaa))                          # extraneous
    # 15 Secure Mode Response
    m.append(b(15, 0))
    # 16 Extended Protocol Capability Response
    m.append(b(16, 4, 0x01, 0x23, 0x45, 2, 0, 3, 10, 1,
               4, blk(0, b'\x03'), blk(1, seq(3)), blk(2, seq(7)),
               blk(6, b'')))
    m.append(b(16, 4, 0x01, 0x23, 0x45, 0, 1, blk(5, seq(7)), 0xaa))
    # 17 MMD Configuration Response
    m.append(b(17, 2, blk(0, seq(5)), 0, blk(1, b''), 38, 0x00))
    m.append(b(17, 1, blk(0, b'\x01'), 0, 0x80, 0x00, 0xaa))
    m.append(b(17, 1, blk(0, b'\x01'), 0))           # no FRESH
    # 18 MMD Download Response
    m.append(b(18, 1, 0, 0))
    m.append(b(18, 0, 0xaa))                          # extraneous
    # 19 System Tag Configuration Response
    m.append(b(19, 0, 0, 3, seq(3)))
    m.append(b(19, 6, 42, 0))
    m.append(b(19, 1, 0, 0, 0xaa))                    # extraneous
    # 20 System Tag Download Response
    m.append(b(20, 0, 0))
    m.append(b(20, 1, 0, 0x00, 0x10, 0x20))
    m.append(b(20, 2, 0, 0x00, 0x30, 0x20))
    m.append(b(20, 3, 43, 0x01, 0x00, 0x08))
    m.append(b(20, 0, 0, 0xaa))                       # extraneous
    # 21 Service Key Generation Response
    m.append(b(21, 0))
    # 22 MMS Configuration Response
    m.append(b(22, 2, blk(0, b'http://mms.example/'), 0, blk(1, b''), 44,
               0x00))
    m.append(b(22, 1, blk(2, b'\x01'), 0, 0x80, 0x00, 0xaa))
    m.append(b(22, 1, blk(1, b'\x01'), 0))           # no FRESH
    # 23 MMS Download Response
    m.append(b(23, 1, 0, 46))
    m.append(b(23, 0, 0xaa))                          # extraneous
    # unknown message types
    m.append(b(24))
    m.append(b(0x80, 0x01))
    return m


# ---------------------------------------------------------------- malformed
def forward_malformed():
    m = []
    for t in (0, 1, 2, 7, 9, 11, 12, 13, 14, 15, 17, 18, 19, 22, 23):
        m.append(b(t))                                     # no data
    m.append(b(0, 3, 0))                                   # blocks missing
    m.append(b(1, 1, 0, 20, 0x00))                         # block too long
    m.append(b(3, 0))                                      # < 2
    m.append(b(3, 5, 0x00))                                # param too long
    m.append(b(6, 4, 3, 0))                                # records missing
    m.append(b(7, 1, 0x00))                                # PRL short
    m.append(b(8, 0))                                      # < 2
    m.append(b(8, 0, 4, 0x00))                             # block too long
    m.append(b(9, 2, 0, 3))                                # < 2 * blocks
    m.append(b(9, 1, 0, 9, 0x00))                          # block too long
    m.append(b(12, 1, 0, 5, 0x00))
    m.append(b(13, 2, 0))
    m.append(b(14, 1, 0, 5, 0x00))
    m.append(b(15, 0x80, seq(7)))                          # 7 of 8 octets
    m.append(b(17, 2, 0))
    m.append(b(18, 1, 0, 5, 0x00))
    m.append(b(19, 0, 0x00))                               # 2 octets
    m.append(b(19, 0, 0x00, 0x10))                         # 3 octets
    m.append(b(20, 0))                                     # < 2
    m.append(b(20, 0, 4, 0x00))                            # block too long
    m.append(b(21, 0x80))                                  # < 2
    m.append(b(22, 2, 0))
    m.append(b(23, 1, 0, 5, 0x00))
    # NAM blocks shorter than their fields
    m.append(b(1, 1, blk(0, seq(10))))
    m.append(b(1, 1, blk(2, seq(6))))
    m.append(b(1, 1, 3, 3, seq(3)))
    m.append(b(9, 1, 2, 1))                                # missing data
    return m


def reverse_malformed():
    m = []
    for t in (0, 1, 3, 6, 7, 9, 10, 11, 12, 13, 14, 16, 17, 18, 19, 20, 22, 23):
        m.append(b(t))                                     # no data / short
    m.append(b(0, 2, 0, 0))                                # < 2 * blocks
    m.append(b(0, 1, 0, 9, 0x00))                          # block too long
    m.append(b(0, 2, 4, 0, 4, 0, 0x00))                    # results short
    m.append(b(1, 2, 0, 0))
    m.append(b(3, 0, 5, 0x00))                             # result too long
    m.append(b(6, 0, 0, 0, 3, 0x00))                       # features short
    m.append(b(6, 0, 0, 0, 1, 0, 1))                       # no ADD_LENGTH
    m.append(b(6, 0, 0, 0, 0, 5, 0x00))                    # ADD_LENGTH long
    m.append(b(7, 0, 0, 5, 0x00))                          # block too long
    m.append(b(9, 2, 0, 0))
    m.append(b(10, 0, 0x01, 0x12))                         # RAND short
    m.append(b(11, 0, 0, 5, 0x00))
    m.append(b(12, 2, 0, 0, 0))
    m.append(b(13, 2, 0, 0, 0))                            # < 3 * blocks
    m.append(b(13, 1, 0, 9, 0x00))                         # block too long
    m.append(b(14, 2, 0, 0))
    m.append(b(16, 0, 0, 0, 0, 2, 0x00))                   # features short
    m.append(b(16, 0, 0, 0, 0, 1, 0, 1))                   # no NUM_CAP
    m.append(b(16, 0, 0, 0, 0, 0, 2, 0, 0))                # records short
    m.append(b(16, 0, 0, 0, 0, 0, 1, 0, 9))                # record too long
    m.append(b(17, 2, 0, 0, 0))
    m.append(b(17, 1, 0, 9, 0x00))
    m.append(b(18, 2, 0, 0))
    m.append(b(19, 0, 0, 4, 0x00))
    m.append(b(20, 1, 0, 0x00))                            # 3 of 5 octets
    m.append(b(20, 2, 0, 0x00, 0x10))                      # 4 of 5 octets
    m.append(b(22, 2, 0, 0, 0))
    m.append(b(22, 1, 0, 9, 0x00))
    m.append(b(23, 2, 0, 0))
    # NAM blocks shorter than their fields
    m.append(b(0, 1, blk(0, seq(10)), 0))
    m.append(b(0, 1, blk(2, seq(6)), 0))
    m.append(b(0, 1, 3, 3, seq(3)))
    m.append(b(0, 1, 1, 1, 0xf0))                          # 15 digits in 1
    return m


# ---------------------------------------------------------------- reproducers
def reproducers():
    """Targeted cases, in a fixed order (REPRO_BAD lists the malformed ones)"""
    pk = []
    for bid in range(4):
        pk.append((F, bytes([1, 1, bid, 1, 0xff]) + b'\x00' * 30))
    for bid in range(4):
        pk.append((R, bytes([0, 1, bid, 1, 0xff, 0x00]) + b'\x00' * 30))
    pk.append((F, bytes([1, 1, 1, 8, 0xf1, 0x23, 0x45, 0x67, 0x89, 0x0a, 0xbc, 0xde])))
    pk.append((R, bytes([0, 1, 1, 8, 0xf1, 0x23, 0x45, 0x67, 0x89, 0x0a, 0xbc, 0xde, 0x00])))
    pk.append((F, bytes([1, 1, 1, 1, 0xff])))
    pk.append((F, bytes([11, 0x01, 0xaa, 0xbb])))
    pk.append((F, bytes([15, 0x80]) + b'\x11' * 7))
    pk.append((F, bytes([19, 0x01, 0x00, 0x10])))
    pk.append((R, bytes([20, 0x01, 0x00, 0x10])))
    for d in (F, R):
        for t in range(0, 26):
            pk.append((d, bytes([t])))
            pk.append((d, bytes([t, 0xff])))
            pk.append((d, bytes([t]) + b'\xff' * 300))
    pk.append((F, b''))
    return pk


# Indexes into reproducers() that end in an exception or an error expert
# info even with the fix (found with tshark): they go to the malformed
# capture, the others to the main capture.
REPRO_BAD = {0, 2, 4, 6, 10, 12, 13, 14, 15, 16, 18, 19, 20, 21, 24, 25,
    34, 36, 39, 40, 42, 43, 44, 48, 51, 52, 53, 54, 55, 57, 58, 59, 60, 61,
    66, 67, 69, 70, 71, 72, 75, 76, 78, 79, 81, 82, 84, 85, 86, 93, 94, 95,
    96, 97, 98, 102, 103, 111, 112, 113, 114, 115, 120, 121, 122, 123, 124,
    126, 127, 129, 130, 131, 132, 133, 134, 135, 136, 137, 141, 142, 143,
    144, 145, 146, 147, 148, 149, 150, 151, 153, 154, 159, 160, 161, 162,
    163, 164, 171}


# ---------------------------------------------------------------- carriage
def dtap_adds_deliver(ota):
    """ANSI A DTAP ADDS Deliver, ADDS User Part of burst type OTA"""
    up = b'\x04' + ota
    assert len(up) < 256
    return b(0x03, 0x00, 0x53, len(up), up)


def blen(n):
    if n < 0x80:
        return bytes([n])
    v = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(v)]) + v


def ber_tag(cls, cons, num):
    first = (cls << 6) | (0x20 if cons else 0)
    if num < 31:
        return bytes([first | num])
    out = [num & 0x7f]
    num >>= 7
    while num:
        out.append(0x80 | (num & 0x7f))
        num >>= 7
    return bytes([first | 0x1f]) + bytes(reversed(out))


CTX, PRI = 2, 3


def ber(cls, cons, num, content):
    return ber_tag(cls, cons, num) + blen(len(content)) + content


def tcap_package(ptype, tid, comp):
    body = ber(PRI, 0, 7, tid) + ber(PRI, 1, 8, comp)
    return ber(PRI, 1, ptype, body)


def smdpp_invoke(inv_id, ota, service):
    params = ber(CTX, 0, 193, bytes([service]))     # ServiceIndicator
    params += ber(CTX, 0, 105, ota)                  # SMS_BearerData
    params += ber(CTX, 0, 116, b'\x10\x02')          # SMS_TeleserviceIdentifier
    body = ber(PRI, 0, 15, bytes([inv_id]))
    body += ber(PRI, 0, 17, struct.pack('>H', 0x0900 | 53))
    body += ber(PRI, 1, 18, params)
    return ber(PRI, 1, 9, body)


def smdpp_result(inv_id, ota):
    params = ber(CTX, 0, 105, ota)
    body = ber(PRI, 0, 15, bytes([inv_id])) + ber(PRI, 1, 18, params)
    return ber(PRI, 1, 10, body)


# OTASP session carried over ANSI A and ANSI MAP
SESSION = [
    (F, b(6, 4, 2, 0, 1)),                                  # Protocol Capability Req
    (R, b(16, 4, 0x01, 0x23, 0x45, 2, 0, 3, 7, 1, 2, blk(0, b'\x03'),
          blk(2, seq(7)))),                                 # Ext Protocol Cap Rsp
    (F, b(15, 0x8d, seq(8, 0xc8))),                         # Secure Mode Req
    (R, b(15, 0)),                                          # Secure Mode Rsp
    (F, b(0, 2, 0, 1)),                                     # Config Req
    (R, b(0, 2, blk(0, rev_nam_cdma_analog(1, 1)), blk(1, mdn('6135550123')),
          0, 0)),                                           # Config Rsp
    (F, b(1, 1, blk(1, mdn('6135550199')))),                # Download Req
    (R, b(1, 1, 1, 0)),                                     # Download Rsp
    (F, b(11, 0x02)),                                       # PUZL Config Req
    (R, b(11, 2, 0, 3, seq(3))),                            # PUZL Config Rsp
    (F, b(5)),                                              # Commit Req
    (R, b(5, 0)),                                           # Commit Rsp
]


def frame_ts(i):
    return 1700000000 + i, 0


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    clean, bad = [], []

    # 1. every message over the ansi_a.ota table
    for p in forward_clean():
        clean.append(exp_table(F, p))
    for p in reverse_clean():
        clean.append(exp_table(R, p))

    # 2. the targeted cases
    for i, (d, p) in enumerate(reproducers()):
        (bad if i in REPRO_BAD else clean).append(exp_table(d, p))

    # 3. ANSI A DTAP ADDS Deliver (P2P direction: 0 sent = forward,
    #    1 received = reverse)
    for d, p in SESSION:
        clean.append(exp_name('ansi_a_dtap', dtap_adds_deliver(p), p2p=d))

    # 4. ANSI MAP SMDPP: Invoke with ServiceIndicator OTASP (1) or OTAPA
    #    (3) carries the forward message, the ReturnResult the reverse one
    for n in range(0, len(SESSION), 2):
        tid = struct.pack('>I', 0x683000 + n)
        service = 1 if n < 8 else 3
        clean.append(exp_name('ansi_tcap', tcap_package(
            2, tid, smdpp_invoke(1, SESSION[n][1], service))))
        clean.append(exp_name('ansi_tcap', tcap_package(
            4, tid, smdpp_result(1, SESSION[n + 1][1]))))

    for p in forward_malformed():
        bad.append(exp_table(F, p))
    for p in reverse_malformed():
        bad.append(exp_table(R, p))

    write_pcap(os.path.join(out, 'ansi_683-coverage.pcap'), clean, snaplen=65535,
               linktype=LINKTYPE_WIRESHARK_UPPER_PDU, ts=frame_ts)
    write_pcap(os.path.join(out, 'ansi_683-coverage-malformed.pcap'), bad, snaplen=65535,
               linktype=LINKTYPE_WIRESHARK_UPPER_PDU, ts=frame_ts)
    print(len(clean), 'clean frames,', len(bad), 'malformed frames')


if __name__ == '__main__':
    main()
