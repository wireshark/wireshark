#!/usr/bin/env python3
# Generates test/captures/dect_nwk_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build synthetic DECT NWK (packet-dect-nwk.c) coverage captures.

DECT-NWK is reached as in a Mitel SIP-DECT capture: Ethernet with
ethertype 0xA000 (DECT-MITEL-ETH), an LC layer LC_DATA_REQ (0x05) or
LC_DATA_IND (0x06) message, a DECT DLC (LAPC) frame with SAPI 0
(connection oriented) or SAPI 3 (connectionless), and the NWK message:
transaction identifier and protocol discriminator, message type and
information elements (EN 300 175-5). Messages up to 63 octets go in one
UI frame; longer ones in segmented I frames that DECT-DLC reassembles.
Every packet is built with struct; nothing comes from a real network.

Usage: mkdect_nwk.py <outdir> [-v]
Writes dect-nwk-coverage.pcap and dect-nwk-coverage-malformed.pcap.
"""
import os
import struct
import sys

RFP = bytes.fromhex("020000000001")
OMM = bytes.fromhex("020000000002")
LC_DATA_REQ = 0x05
LC_DATA_IND = 0x06

# ---------------------------------------------------------------- transport


def mitel(prim, dlc, mcei=1):
    m = bytes([0x79, prim, mcei, 0x00, len(dlc)]) + dlc
    return RFP + OMM + struct.pack(">H", 0xA000) + struct.pack(">HH", len(m), 0) + m


def dlc(sapi, ctrl, payload, m=0, cr=1):
    assert len(payload) < 64, len(payload)
    a = (1 << 4) | (sapi << 2) | (cr << 1) | 1
    return bytes([a, ctrl, (len(payload) << 2) | (m << 1) | 1]) + payload


class Link:
    """Builds the frames of the capture; keeps N(S) per direction for
    segmented I frames."""

    def __init__(self):
        self.frames = []
        self.ns = {LC_DATA_REQ: 0, LC_DATA_IND: 0}
        self.n = 0

    def add(self, desc, nwk, sapi=0):
        prim = LC_DATA_IND if self.n % 2 == 0 else LC_DATA_REQ
        self.n += 1
        if len(nwk) < 64:
            self.frames.append((desc, mitel(prim, dlc(sapi, 0x03, nwk), mcei=1 + self.n % 7)))
            return
        segs = [nwk[i:i + 60] for i in range(0, len(nwk), 60)]
        for k, s in enumerate(segs):
            ns = self.ns[prim]
            self.ns[prim] = (ns + 1) % 8
            last = k == len(segs) - 1
            self.frames.append(("%s (segment %d of %d)" % (desc, k + 1, len(segs)),
                                mitel(prim, dlc(sapi, ns << 1, s, m=0 if last else 1), mcei=9)))

    def raw(self, desc, frame):
        self.frames.append((desc, frame))


# --------------------------------------------------------------- NWK pieces

PD_LCE, PD_CC, PD_CISS, PD_MM, PD_CLMS, PD_COMS = 0, 3, 4, 5, 6, 7


def msg(pd, mt, *ies, ti=0):
    return bytes([(ti << 4) | pd, mt]) + b"".join(ies)


def ie(t, body):
    return bytes([t, len(body)]) + bytes(body)


def bits(fields):
    """Pack (value, width) pairs MSB first; pad to whole octets with 0."""
    v, n = 0, 0
    for val, w in fields:
        assert val < (1 << w)
        v = (v << w) | val
        n += w
    pad = (-n) % 8
    return (v << pad).to_bytes((n + pad) // 8, "big")


def bcd(digits):
    return [int(d) for d in digits]


def ipei_check(emc, psn):
    d = "%05d%07d" % (emc, psn)
    return sum(int(c) * (i + 1) for i, c in enumerate(d)) % 11


# Portable identity (7.7.30)
def portable_ipui(put, value_bits, vlen):
    """IPUI: type 0x00 (with ext bit 0x80), value length, PUT nibble then
    value_bits (list of (value, width))."""
    return ie(0x05, bytes([0x80, 0x80 | vlen]) + bits([(put, 4)] + value_bits))


def portable_ipei(emc, psn):
    return ie(0x05, bytes([0x90, 0x80 | 40]) + bits([(0, 4), (emc, 16), (psn, 20)]))


def portable_tpui(assign, value):
    return ie(0x05, bytes([0xA0, 0x80 | 20]) + bits([(assign, 4), (value, 20)]))


def fixed_identity(typ, arc, ard, ard_bits):
    vlen = 4 + ard_bits
    return ie(0x06, bytes([0x80 | typ, 0x80 | vlen]) + bits([(0, 1), (arc, 3), (ard, ard_bits)]))


def nwk_assigned(typ, value, vbits):
    return ie(0x09, bytes([0x80 | typ, 0x80 | vbits]) + bits([(value, vbits)]))


def bcd_digits(ds):
    return [(d, 4) for d in bcd(ds)]


IPEI_A = portable_ipei(0x0123, 0x45678)
EMC_STAR, PSN_STAR = None, None
for psn in range(1, 200):
    if ipei_check(0x0123, psn) == 10:
        EMC_STAR, PSN_STAR = 0x0123, psn
        break
IPEI_STAR = portable_ipei(EMC_STAR, PSN_STAR)

PORTABLE_IDENTITIES = [
    ("IPUI-N (IPEI)", portable_ipui(0, [(0x0123, 16), (0x45678, 20)], 40)),
    ("IPUI-O", portable_ipui(1, [(0x0123456789abcde, 60)], 64)),
    ("IPUI-P", portable_ipui(2, [(0x1234, 16), (0x112233445566778899aa, 80)], 100)),
    ("IPUI-Q odd", portable_ipui(3, bcd_digits("12345678"), 36)),
    ("IPUI-Q even", portable_ipui(3, bcd_digits("123456789"), 40)),
    ("IPUI-R (IMSI)", portable_ipui(4, bcd_digits("262011234567890"), 64)),
    ("IPUI-S", portable_ipui(5, bcd_digits("49891234567"), 48)),
    ("IPUI-T", portable_ipui(6, [(0x2468, 16)] + bcd_digits("1357924"), 48)),
    ("IPUI-U", portable_ipui(7, bcd_digits("4111111111111111"), 68)),
    ("IPUI-R odd", portable_ipui(4, bcd_digits("26201123456789"), 60)),
    ("IPUI-S odd", portable_ipui(5, bcd_digits("4989123456"), 44)),
    ("IPUI-T odd", portable_ipui(6, [(0x2468, 16)] + bcd_digits("13579246"), 52)),
    ("IPUI-U even", portable_ipui(7, bcd_digits("411111111111111"), 64)),
    ("IPUI PUT 8 (reserved)", portable_ipui(8, [(0xabcd, 16)], 20)),
    ("IPEI", IPEI_A),
    ("IPEI check digit *", IPEI_STAR),
    ("TPUI", portable_tpui(0, 0xc1234)),
    ("TPUI with number", portable_tpui(1, 0x0abcd)),
    ("identity type 0x30 (unknown)", ie(0x05, bytes([0xB0, 0x80 | 16, 0x12, 0x34]))),
]

FIXED_IDENTITIES = [
    ("ARI class A", fixed_identity(0x00, 0, 0x12345678, 32)),          # 36 bits, padding
    ("ARI+RPN class B", fixed_identity(0x01, 1, 0x123456789, 36)),     # 40 bits
    ("ARI+RPN for WRS class C", fixed_identity(0x02, 2, 0x1abcdef, 27)),  # 31 bits
    ("PARK class D", fixed_identity(0x20, 3, 0x1234567, 28)),          # 32 bits
    ("PARK class E", fixed_identity(0x20, 4, 0x2468ace, 29)),
    ("PARK class F (no name)", fixed_identity(0x20, 5, 0x1, 4)),
]

NWK_ASSIGNED = [
    ("TMSI", nwk_assigned(0x74, 0xdeadbeef, 32)),
    ("proprietary 20 bit", nwk_assigned(0x7f, 0xabcde, 20)),
    ("type 0x64", nwk_assigned(0x64, 0x12, 8)),
]

# Fixed length elements (7.6)
FL_SHIFT_LOCK = bytes([0x90 | 0x00])          # shift, locking, codeset 0
FL_SHIFT_NONLOCK = bytes([0x98 | 0x04])       # shift, non-locking, codeset 4
FL_SENDING_COMPLETE = bytes([0xA1])
FL_DELIMITER_REQUEST = bytes([0xA2])
FL_USE_TPUI = bytes([0xA3])
FL_CONTROL_UNKNOWN = bytes([0xA7])
FL_REPEAT_NONPRIO = bytes([0xD1])
FL_REPEAT_PRIO = bytes([0xD2])
FL_RESERVED = [bytes([0x80]), bytes([0xB0]), bytes([0xC0]), bytes([0xF0])]
BASIC_SERVICE = bytes([0xE0, 0x80])            # normal call, basic speech
BASIC_SERVICE_WB = bytes([0xE0, 0x88])
RELEASE_REASON = bytes([0xE2, 0x00])
SIGNAL = bytes([0xE4, 0x40])
TIMER_RESTART = bytes([0xE5, 0x01])
TEST_HOOK = bytes([0xE6, 0x01])
SINGLE_DISPLAY = bytes([0xE8, 0x41])
SINGLE_DISPLAY_CTRL = bytes([0xE8, 0x0C])
SINGLE_KEYPAD = bytes([0xE9, 0x35])
SINGLE_KEYPAD_CTRL = bytes([0xE9, 0x05])
DOUBLE_UNKNOWN = [bytes([0xE0 | t, 0x11]) for t in (1, 3, 7, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF)]

# Variable length elements (7.7)
AUTH_DSAA = ie(0x0A, [0x01, 0x18, 0x08])                    # DSAA, user AK 8, no DEF
AUTH_DSAA2_DEF = ie(0x0A, [0x02, 0x18, 0x58, 0x12, 0x34, 0x01])  # DEF: index, DSC2
AUTH_PROPRIETARY = ie(0x0A, [0x7F, 0x33, 0x48, 0xB8])       # proprietary algorithm, UPC
AUTH_UMTS = ie(0x0A, [0x20, 0x30, 0x20])
CALLING_NUMBER_3A = ie(0x6C, [0x21, 0x80 | 0x01, 0x30, 0x34, 0x39, 0x38, 0x39])  # national/ISDN, restricted, screened
CALLING_NUMBER = ie(0x6C, [0x80 | 0x11, 0x31, 0x32, 0x33])
CIPHER_DSC = ie(0x19, [0x81, 0x98])                         # yes, DSC, derived key
CIPHER_PROPRIETARY = ie(0x19, [0x7F, 0x55, 0xA2])           # no, proprietary
DURATION_3A = ie(0x72, [0x61, 0x0A])                        # temporary, defined time 1, duration 10
DURATION = ie(0x72, [0xF4])                                 # no limits, standard
IWU_USER_EMC = ie(0x77, [0x80, 0x81, 0x01, 0x23, 0xde, 0xad, 0xbe, 0xef])
IWU_USER = ie(0x77, [0x80, 0x80, 0x11, 0x22, 0x33])
IWU_LIST_ACCESS = ie(0x77, [0x83, 0x01, 0x02, 0x03, 0x04])
IWU_SUOTA = ie(0x77, [0xC6, 0x0a, 0x0b])
LOCATION_PLAIN = ie(0x07, [0x45])                           # no extended LI, LA level 5
LOCATION_LI = ie(0x07, [0xC0 | 0x24, 0xF0, 0x62, 0xF2, 0x10, 0x12, 0x34, 0x56, 0x78])
LOCATION_REQ = ie(0x07, [0x80 | 0x10, 0x70])                # extended, LI requested not included
MULTI_DISPLAY = ie(0x28, b"\x0cCall from\x0d\x0aAlice\x1b\x01!")
MULTI_KEYPAD = ie(0x2C, b"\x170123*#\x05")
RAND = ie(0x0C, bytes(range(1, 9)))
RES = ie(0x0D, bytes([0x9a, 0xbc, 0xde, 0xf0]))
RS = ie(0x0E, bytes(range(0x10, 0x18)))
TERMINAL_CAP_FULL = ie(0x63, [
    # group 3: 3, 3b..3h, one more
    0x42, 0x23, 0x1F, 0x01, 0x40, 0x03, 0x10, 0x02, 0x81,
    # group 4: 4, 4a..4i, one more
    0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x6F, 0x7F, 0x1F, 0x80,
    # group 5: 5, 5a, one more
    0x7A, 0x0F, 0x80,
    # group 6: 6, 6a, one more
    0x5F, 0x7F, 0x80])
TERMINAL_CAP_MIN = ie(0x63, [0x80 | 0x21, 0x80 | 0x02, 0x80 | 0x01])
TERMINAL_CAP_6 = ie(0x63, [0x80 | 0x21, 0x80 | 0x02, 0x80 | 0x01, 0x80 | 0x15])
ESCAPE_EMC = ie(0x7B, [0x81, 0x01, 0x23, 0x10, 0x20, 0x30])
ESCAPE_UNSPECIFIED = ie(0x7B, [0x80, 0x55, 0x66])
MODEL_ID_3 = ie(0x78, [0x01, 0x23, 0x45])
MODEL_ID_20 = ie(0x78, bytes(range(0x30, 0x44)))
CODEC_1 = ie(0x7C, [0x90, 0x02, 0x00, 0x81])                 # G.726, last
CODEC_2 = ie(0x7C, [0x91, 0x03, 0x00, 0x04, 0x02, 0x00, 0x82])

OTHER_IES = [0x01, 0x02, 0x0B, 0x12, 0x13, 0x16, 0x17, 0x1A, 0x1B, 0x1C, 0x1E,
             0x20, 0x21, 0x22, 0x23, 0x38, 0x39, 0x41, 0x42, 0x52, 0x54, 0x56,
             0x60, 0x62, 0x64, 0x65, 0x66, 0x67, 0x68, 0x6D, 0x70, 0x71, 0x73,
             0x74, 0x75, 0x76, 0x7A, 0x7D, 0x7E, 0x7F]

LCE_MSGS = [0x71, 0x72]
CC_MSGS = [0x01, 0x02, 0x05, 0x07, 0x0d, 0x0f, 0x20, 0x21, 0x23, 0x4d, 0x5a, 0x60, 0x6e, 0x7b]
CRSS_MSGS = [0x24, 0x28, 0x30, 0x31, 0x33, 0x37, 0x62]
CISS_MSGS = [0x5a, 0x62, 0x64]
MM_MSGS = [0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x47, 0x48, 0x49, 0x4b, 0x4c, 0x4e,
           0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5b,
           0x5c, 0x5d, 0x5f, 0x6e]
CLMS_MSGS = [0x01]
COMS_MSGS = [0x05, 0x07, 0x08, 0x4d, 0x5a, 0x7b, 0x78]


def body_for(pd, mt):
    """Typical elements for a message, so every message carries something."""
    if pd == PD_LCE:
        return [IPEI_A, FIXED_IDENTITIES[3][1]] if mt == 0x71 else [IPEI_A, RELEASE_REASON]
    if pd == PD_CC:
        if mt == 0x05:      # CC-SETUP
            return [IPEI_A, FIXED_IDENTITIES[3][1], BASIC_SERVICE, FL_SENDING_COMPLETE]
        if mt in (0x4d, 0x5a):
            return [RELEASE_REASON]
        if mt == 0x7b:
            return [MULTI_KEYPAD, SIGNAL]
        if mt == 0x01:
            return [SIGNAL, CODEC_1]
        return [FL_DELIMITER_REQUEST] if mt == 0x0d else []
    if pd == PD_MM:
        return {
            0x40: [AUTH_DSAA, RAND, RS],
            0x41: [RES],
            0x42: [AUTH_DSAA2_DEF, RAND, RS],
            0x44: [IPEI_A, AUTH_DSAA, CIPHER_DSC, TERMINAL_CAP_MIN],
            0x45: [IPEI_A, FIXED_IDENTITIES[3][1], DURATION],
            0x4c: [CIPHER_DSC],
            0x54: [IPEI_A, FIXED_IDENTITIES[0][1], LOCATION_PLAIN],
            0x55: [LOCATION_PLAIN, NWK_ASSIGNED[0][1], DURATION_3A],
            0x58: [ie(0x02, [0x80])],
            0x59: [IPEI_A],
            0x5c: [IPEI_A, NWK_ASSIGNED[0][1]],
        }.get(mt, [])
    if pd == PD_CISS:
        return [IWU_USER] if mt != 0x5a else [RELEASE_REASON]
    if pd == PD_COMS:
        return [IPEI_A] if mt == 0x05 else []
    if pd == PD_CLMS:
        return [MULTI_DISPLAY]
    return []


def main_frames():
    L = Link()
    # Every message of every protocol discriminator, then unknown types
    for pd, msgs in ((PD_LCE, LCE_MSGS), (PD_CC, CC_MSGS + CRSS_MSGS),
                     (PD_CISS, CISS_MSGS), (PD_MM, MM_MSGS), (PD_COMS, COMS_MSGS)):
        for mt in msgs:
            L.add("pd %d message 0x%02x" % (pd, mt), msg(pd, mt, *body_for(pd, mt), ti=(mt % 8)))
        L.add("pd %d unknown message" % pd, msg(pd, 0x7e))
    for mt in CLMS_MSGS + [0x02]:
        L.add("CLMS message 0x%02x (SAPI 3)" % mt, msg(PD_CLMS, mt, *body_for(PD_CLMS, mt)), sapi=3)
    # Unknown protocol discriminators: the rest goes to the data dissector
    for pd in (1, 2, 8, 15):
        L.add("unknown pd %d" % pd, msg(pd, 0x01, b"\x11\x22\x33"))
    # Fixed length elements
    L.add("fixed length shift/control/repeat",
          msg(PD_CC, 0x7b, FL_SHIFT_LOCK, FL_SHIFT_NONLOCK, FL_SENDING_COMPLETE, FL_DELIMITER_REQUEST,
              FL_USE_TPUI, FL_CONTROL_UNKNOWN, FL_REPEAT_NONPRIO, FL_REPEAT_PRIO, *FL_RESERVED))
    L.add("double octet elements",
          msg(PD_CC, 0x7b, BASIC_SERVICE_WB, RELEASE_REASON, SIGNAL, TIMER_RESTART, TEST_HOOK,
              SINGLE_DISPLAY, SINGLE_DISPLAY_CTRL, SINGLE_KEYPAD, SINGLE_KEYPAD_CTRL))
    L.add("unknown double octet elements", msg(PD_CC, 0x7b, *DOUBLE_UNKNOWN))
    # Identities of every type
    for name, e in PORTABLE_IDENTITIES:
        L.add("portable identity " + name, msg(PD_MM, 0x59, e))
    for name, e in FIXED_IDENTITIES:
        L.add("fixed identity " + name, msg(PD_MM, 0x45, e))
    for name, e in NWK_ASSIGNED:
        L.add("NWK assigned identity " + name, msg(PD_MM, 0x5c, IPEI_A, e))
    # Other decoded elements
    L.add("auth types", msg(PD_MM, 0x40, AUTH_DSAA, AUTH_DSAA2_DEF, AUTH_PROPRIETARY, AUTH_UMTS))
    L.add("calling party numbers", msg(PD_CC, 0x05, CALLING_NUMBER_3A, CALLING_NUMBER))
    L.add("cipher info", msg(PD_MM, 0x4c, CIPHER_DSC, CIPHER_PROPRIETARY))
    L.add("durations", msg(PD_MM, 0x45, DURATION_3A, DURATION))
    L.add("IWU-TO-IWU", msg(PD_CC, 0x60, IWU_USER_EMC, IWU_USER, IWU_LIST_ACCESS, IWU_SUOTA))
    L.add("location areas", msg(PD_MM, 0x55, LOCATION_PLAIN, LOCATION_LI, LOCATION_REQ))
    L.add("multi display and keypad", msg(PD_CC, 0x7b, MULTI_DISPLAY, MULTI_KEYPAD))
    L.add("RAND RES RS", msg(PD_MM, 0x40, RAND, RES, RS))
    L.add("terminal capability, every octet", msg(PD_MM, 0x44, TERMINAL_CAP_FULL))
    L.add("terminal capability, short", msg(PD_MM, 0x44, TERMINAL_CAP_MIN, TERMINAL_CAP_6))
    L.add("escape to proprietary", msg(PD_CC, 0x7b, ESCAPE_EMC, ESCAPE_UNSPECIFIED))
    L.add("model identifiers", msg(PD_MM, 0x44, MODEL_ID_3, MODEL_ID_20))
    L.add("codec lists", msg(PD_CC, 0x05, CODEC_1, CODEC_2))
    L.add("element of length 0", msg(PD_CC, 0x7b, ie(0x28, b""), ie(0x0C, b"")))
    # Every other element type (no decoder: skipped by length), and unknown
    others = [ie(t, bytes([t, 0x5a])) for t in OTHER_IES] + [ie(0x03, b"\x01"), ie(0x50, b"")]
    for k in range(0, len(others), 12):
        L.add("other elements %d" % k, msg(PD_CC, 0x7b, *others[k:k + 12]))
    # A long CC-SETUP in three segmented I frames
    long_setup = msg(PD_CC, 0x05, IPEI_A, FIXED_IDENTITIES[3][1], BASIC_SERVICE, CALLING_NUMBER_3A,
                     ie(0x28, b"Synthetic DECT NWK display text that needs DLC segmentation"),
                     TERMINAL_CAP_FULL, CODEC_2, FL_SENDING_COMPLETE, ti=0x8)
    assert 120 < len(long_setup) < 180
    L.add("long CC-SETUP", long_setup)
    # Reproducer of "find each IE after the one before"
    # (dect_nwk_ie_resync.py): a MODEL-IDENTIFIER of length 5
    # and an IPEI with 2 extra octets; with the fix nothing in them is
    # taken for a further element.
    L.add("resync: model identifier length 5",
          bytes([0x05, 0x40, 0x78, 5, 0x0C, 3, 0xAA, 0xBB, 0xCC]))
    L.add("resync: IPEI with two extra octets",
          bytes([0x05, 0x40, 0x05, 9, 0x90, 0x80 | 40, 0x01, 0x23, 0x45, 0x67, 0x89, 0x0C, 0x00]))
    return L.frames


def malformed_frames():
    L = Link()
    # Reproducer of "Check identity bit widths"
    # (dect_nwk_bits_width.py): widths 0 and too wide
    bad = [
        ("fixed identity, value length 4 -> 0 bits", ie(0x06, bytes([0x80, 0x80 | 4]) + b"\x11" * 10)),
        ("fixed identity, value length 72 -> 68 bits", ie(0x06, bytes([0x80, 0x80 | 72]) + b"\x22" * 12)),
        ("nwk assigned identity, value length 0", ie(0x09, bytes([0x80, 0x80 | 0]) + b"\x33" * 4)),
        ("portable IPUI-N, value length 4 -> 0 bits", ie(0x05, bytes([0x80, 0x80 | 4, 0x00]) + b"\x44" * 8)),
        ("portable IPUI-O, value length 80 -> 76 bits", ie(0x05, bytes([0x80, 0x80 | 80, 0x10]) + b"\x45" * 12)),
        ("portable IPUI-P, value length 20 -> ACC 0 bits", ie(0x05, bytes([0x80, 0x80 | 20, 0x20]) + b"\x55" * 8)),
        ("portable IPEI, value length 4 -> 0 bits", ie(0x05, bytes([0x90, 0x80 | 4, 0x00]) + b"\x66" * 8)),
        ("portable TPUI, value length 0", ie(0x05, bytes([0xA0, 0x80 | 0, 0x00]) + b"\x77" * 4)),
        ("portable TPUI, value length 72", ie(0x05, bytes([0xA0, 0x80 | 72, 0x00]) + b"\x88" * 12)),
    ]
    for d, e in bad:
        L.add(d, bytes([0x05, 0x40]) + e)
    # Other malformed input
    L.add("one octet NWK message", bytes([0x05]))
    L.add("element length beyond the message", msg(PD_CC, 0x7b, bytes([0x28, 20, 0x41])))
    L.add("element type without length", msg(PD_CC, 0x7b, bytes([0x28])))
    L.add("double octet element cut", msg(PD_CC, 0x7b, bytes([0xE4])))
    L.add("terminal capability without end", msg(PD_MM, 0x44, ie(0x63, [0x01, 0x02])))
    L.add("codec list without last codec", msg(PD_CC, 0x05, ie(0x7C, [0x90, 0x02, 0x00, 0x01])))
    L.add("calling party number length 1", msg(PD_CC, 0x05, ie(0x6C, [0x01])))
    L.add("IWU-TO-IWU length 0", msg(PD_CC, 0x60, ie(0x77, [])))
    L.add("IWU-TO-IWU EMC cut", msg(PD_CC, 0x60, ie(0x77, [0x80, 0x81])))
    L.add("location area LI cut", msg(PD_MM, 0x55, ie(0x07, [0xC0, 0xF0, 0x62])))
    L.add("auth type DEF cut", msg(PD_MM, 0x40, ie(0x0A, [0x7F, 0x01, 0x18, 0x40])))
    L.add("portable identity cut", msg(PD_MM, 0x59, ie(0x05, [0x90, 0x80 | 40, 0x01])))
    L.add("IPUI-T value too short", msg(PD_MM, 0x59, ie(0x05, [0x80, 0x80 | 12, 0x60, 0x12])))
    L.add("fixed identity cut", msg(PD_MM, 0x45, ie(0x06, [0x80, 0x80 | 36, 0x01])))
    return L.frames


def write_pcap(path, frames, t0=1700000000):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, (_, p) in enumerate(frames):
            f.write(struct.pack("<IIII", t0 + i, 0, len(p), len(p)) + p)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "."
    m = main_frames()
    write_pcap(os.path.join(out, "dect-nwk-coverage.pcap"), m)
    bad = malformed_frames()
    write_pcap(os.path.join(out, "dect-nwk-coverage-malformed.pcap"), bad)
    if "-v" in sys.argv:
        for i, (d, _) in enumerate(m):
            print(i + 1, d)
        print("malformed:")
        for i, (d, _) in enumerate(bad):
            print(i + 1, d)


if __name__ == "__main__":
    main()
