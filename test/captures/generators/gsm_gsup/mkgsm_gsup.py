#!/usr/bin/env python3
# Generates test/captures/gsm_gsup_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic GSUP captures.  Usage: mkgsm_gsup.py <outdir>

GSUP rides in IPA (OSMO EXT, protocol 5) over TCP.  Port 3003 is one of the
default IPA ports (4222, the Osmocom default, is claimed by NATS first).
All IE contents are patterned filler bytes, no key material is computed."""
import struct
import sys
import os
from pcaplib import pcap, Flow

def ie(t, v): return bytes([t, len(v)]) + v
def ipa_gsup(msg):
    p = b'\x05' + msg
    return struct.pack('>HB', len(p), 0xee) + p

def tbcd(digits):
    if len(digits) % 2: digits += 'f'
    return bytes((int(digits[i + 1], 16) << 4) | int(digits[i], 16) for i in range(0, len(digits), 2))

IMSI = ie(0x01, tbcd('262019876543210'))
def fill(n, base=0x10): return bytes((base + i) & 0xff for i in range(n))

RAND = ie(0x20, fill(16)); SRES = ie(0x21, fill(4, 0x40)); KC = ie(0x22, fill(8, 0x50))
IK = ie(0x23, fill(16, 0x60)); CK = ie(0x24, fill(16, 0x70))
AUTN = ie(0x25, fill(16, 0x80)); AUTS = ie(0x26, fill(14, 0x90)); RES = ie(0x27, fill(8, 0xa0))
APN = ie(0x12, b'\x07example\x03com')
PCO = ie(0x15, bytes.fromhex('80 80 21 04 01 01 00 04'.replace(' ', '')))
def msisdn(d): return ie(0x08, b'\x91' + tbcd(d))
def pdp_info(ctx, addr=None, qos=b'\x01\x02\x03'):
    body = ie(0x10, bytes([ctx]))
    if addr is not None: body += ie(0x11, addr)
    body += APN + ie(0x13, qos) + ie(0x14, b'\x08\x00')
    return ie(0x05, body)

def sm_da(t, v=b''): return ie(0x41, bytes([t]) + v)
def sm_oa(t, v=b''): return ie(0x42, bytes([t]) + v)
SMSC = tbcd('491760000000')
# SMS-DELIVER TPDU: no more, originator 0x0c912143658709, pid, dcs, scts, ud
TPDU = bytes.fromhex('0405a12143f0' '0000' '62110102020040' '04c8329bfd06')

def map_components():
    inv = bytes.fromhex('a1' '0f' '0201' '01' '0201' '3b' '3007' '0401' '0f' '0402' 'aa18')
    res = bytes.fromhex('a2' '11' '0201' '01' '300c' '0201' '3b' '3007' '0401' '0f' '0402' 'aa18')
    err = bytes.fromhex('a3' '06' '0201' '01' '0201' '22' )
    return inv, res, err

def msgs():
    L = []  # (frame group, bytes) one message per entry
    A = L.append
    # Subscriber management class
    A(bytes([0x04]) + IMSI + ie(0x0a, b'\x01') + ie(0x29, bytes([1, 2, 3])) + ie(0x2a, b'\x02') + ie(0x28, b'\x02'))
    A(bytes([0x05]) + IMSI + ie(0x02, b'\x07'))
    A(bytes([0x06]) + IMSI + msisdn('491701234567') + ie(0x09, b'\x91\x94\x71\x21') + ie(0x04, b'')
      + pdp_info(1, bytes([0xf1, 0x21, 0x04, 10, 0, 0, 1])) + pdp_info(2, bytes([0xf1, 0x57, 0x10]) + fill(16))
      + pdp_info(3, bytes([0xf1, 0x8d, 0x14, 10, 0, 0, 2]) + fill(16))
      + pdp_info(4, bytes([0xf1, 0x01, 0x00])) + pdp_info(5, bytes([0xf0, 0x21, 0x04, 1, 2, 3, 4]))
      + pdp_info(6, bytes([0xf1, 0x00, 0x04, 1, 2, 3, 4])) + pdp_info(7, bytes([0xf1, 0x21]))
      + ie(0x07, b'') + ie(0x06, b'\x00'))
    # APN of length 1: wildcard, and other single octet; QoS-less PDP info
    A(bytes([0x10]) + IMSI + ie(0x05, ie(0x10, b'\x08') + ie(0x12, b'*') + ie(0x13, b'\x04'))
      + ie(0x05, ie(0x10, b'\x09') + ie(0x12, b'x')) + ie(0x09, b'\x91\x94') + ie(0x04, b''))
    A(bytes([0x11]) + IMSI + ie(0x02, b'\x11'))
    A(bytes([0x12]) + IMSI)
    A(bytes([0x08]) + IMSI + ie(0x52, b'\x03') + AUTS + RAND + ie(0x0a, b'\x01'))
    A(bytes([0x09]) + IMSI + ie(0x02, b'\x11'))
    A(bytes([0x0a]) + IMSI + ie(0x03, RAND + SRES + KC) + ie(0x03, RAND + IK + CK + AUTN + RES + SRES + KC))
    A(bytes([0x0b]) + IMSI)
    A(bytes([0x0c]) + IMSI + ie(0x28, b'\x01'))
    A(bytes([0x0d]) + IMSI + ie(0x02, b'\x03'))
    A(bytes([0x0e]) + IMSI + ie(0x07, b''))
    A(bytes([0x14]) + IMSI + ie(0x10, b'\x01') + ie(0x10, b'\x02'))
    A(bytes([0x15]) + IMSI + ie(0x02, b'\x05'))
    A(bytes([0x16]) + IMSI)
    A(bytes([0x1c]) + IMSI + ie(0x06, b'\x01') + ie(0x28, b'\x01'))
    A(bytes([0x1d]) + IMSI + ie(0x02, b'\x07'))
    A(bytes([0x1e]) + IMSI)
    # unknown IE type, HLR number, PDP QoS at top level, unknown message type
    A(bytes([0x11]) + IMSI + ie(0x7e, b'\x01\x02') + ie(0x13, b'\x01') + ie(0x7d, b''))
    A(bytes([0x7f]) + IMSI)
    # supplementary services
    inv, res, err = map_components()
    A(bytes([0x20]) + IMSI + ie(0x30, struct.pack('>I', 0x01020304)) + ie(0x31, b'\x01') + ie(0x35, inv))
    A(bytes([0x22]) + IMSI + ie(0x30, struct.pack('>I', 0x01020304)) + ie(0x31, b'\x03') + ie(0x35, res + res))
    A(bytes([0x21]) + IMSI + ie(0x30, struct.pack('>I', 0x01020304)) + ie(0x31, b'\x00') + ie(0x35, err) + ie(0x02, b'\x20'))
    # SMS
    A(bytes([0x24]) + IMSI + ie(0x0a, b'\x02') + ie(0x40, b'\x05') + sm_da(2, SMSC) + sm_oa(2, tbcd('491701234567')) + ie(0x43, TPDU) + ie(0x45, b'\x01'))
    A(bytes([0x25]) + IMSI + ie(0x44, b'\x1d') + ie(0x43, TPDU))
    A(bytes([0x26]) + IMSI + ie(0x40, b'\x05') + ie(0x43, TPDU))
    A(bytes([0x28]) + IMSI + ie(0x40, b'\x06') + sm_da(1, tbcd('262019876543210')) + sm_oa(3, SMSC) + ie(0x43, TPDU))
    A(bytes([0x29]) + IMSI + ie(0x44, b'\x1d'))
    A(bytes([0x2a]) + IMSI + ie(0x40, b'\x06'))
    A(bytes([0x2c]) + IMSI + ie(0x46, b'\x01') + ie(0x42, bytes([0xff])) + ie(0x43, TPDU))
    A(bytes([0x2d]) + IMSI + ie(0x44, b'\x01') + sm_da(3, SMSC) + sm_oa(0xff))
    A(bytes([0x2e]) + IMSI + ie(0x46, b'\x02') + sm_da(0xff))
    # Check IMEI: the first octet after the length is read as the length by the
    # bssap.imei dissector (see README), keep it small
    A(bytes([0x30]) + IMSI + ie(0x50, b'\x07' + tbcd('3540930123456780')[:8]))
    A(bytes([0x31]) + IMSI + ie(0x02, b'\x11'))
    A(bytes([0x32]) + IMSI + ie(0x51, b'\x00'))
    A(bytes([0x32]) + IMSI + ie(0x51, b'\x01') + ie(0x02, b'\x06'))
    # inter-MSC
    BSSMAP_CLEAR = bytes.fromhex('0004' '30' '040120')   # BSSMAP Reset with a cause
    # RANAP Iu Release Command with a cause
    RANAP = bytes.fromhex('00' '01' '00' '0a' '00000100' '04' '40' '03' '0201' '80')
    A(bytes([0x34]) + ie(0x0a, b'\x04') + ie(0x60, b'MSC-A\x00') + ie(0x61, b'MSC-B\x00') + ie(0x62, b'\x01' + BSSMAP_CLEAR)
      + ie(0x30, struct.pack('>I', 7)) + ie(0x31, b'\x01') + IMSI)
    A(bytes([0x36]) + ie(0x0a, b'\x04') + ie(0x60, b'MSC-B\x00') + ie(0x61, b'MSC-A\x00') + ie(0x62, b'\x01' + BSSMAP_CLEAR) + ie(0x30, struct.pack('>I', 7)))
    A(bytes([0x35]) + ie(0x0a, b'\x04') + ie(0x60, b'MSC-B') + ie(0x61, b'MSC-A') + ie(0x63, b'\x01') + ie(0x64, b'\x20') + ie(0x65, b'\x1d') + ie(0x30, struct.pack('>I', 7)))
    A(bytes([0x38]) + ie(0x0a, b'\x04') + ie(0x60, b'A') + ie(0x61, b'B') + ie(0x62, b'\x02' + RANAP) + ie(0x30, struct.pack('>I', 7)))
    A(bytes([0x39]) + ie(0x0a, b'\x04') + ie(0x62, b'\x07\x01\x02\x03') + ie(0x30, struct.pack('>I', 7)))
    A(bytes([0x3a]) + ie(0x0a, b'\x04') + ie(0x62, b'\x07\x09') + ie(0x30, struct.pack('>I', 7)))
    A(bytes([0x3c]) + ie(0x0a, b'\x04') + ie(0x30, struct.pack('>I', 7)) + ie(0x31, b'\x02'))
    A(bytes([0x3d]) + ie(0x0a, b'\x04') + ie(0x30, struct.pack('>I', 7)) + ie(0x02, b'\x01'))
    A(bytes([0x3e]) + ie(0x0a, b'\x04') + ie(0x30, struct.pack('>I', 7)))
    A(bytes([0x40]) + ie(0x0a, b'\x04') + ie(0x30, struct.pack('>I', 8)) + ie(0x31, b'\x01') + ie(0x62, b'\x01' + BSSMAP_CLEAR))
    A(bytes([0x44]) + ie(0x0a, b'\x04') + ie(0x30, struct.pack('>I', 8)) + ie(0x31, b'\x02') + ie(0x62, b'\x01' + BSSMAP_CLEAR))
    A(bytes([0x47]) + ie(0x0a, b'\x04') + ie(0x30, struct.pack('>I', 8)) + ie(0x31, b'\x03'))
    A(bytes([0x4b]) + ie(0x0a, b'\x04') + ie(0x30, struct.pack('>I', 8)) + ie(0x31, b'\x03') + ie(0x02, b'\x01'))
    A(bytes([0x4e]) + ie(0x0a, b'\x04') + ie(0x61, b'MSC-X\x00') + ie(0x02, b'\x7a'))
    # ePDG tunnel (PCO direction)
    A(bytes([0x50]) + IMSI + APN + PCO + ie(0x11, bytes([0xf1, 0x21, 0x04, 10, 1, 1, 1])))
    A(bytes([0x51]) + IMSI + ie(0x02, b'\x1d') + PCO)
    A(bytes([0x52]) + IMSI + PCO + APN)
    # PCO in a message type that sets no direction
    A(bytes([0x06]) + IMSI + PCO)
    return L

def build(outdir):
    fr = []
    f = Flow(42001, 3003, fr)
    f.open()
    L = msgs()
    i = 0
    while i < len(L):
        m = L[i]
        # every 7th message: two GSUP PDUs in one segment
        if i % 7 == 3 and i + 1 < len(L):
            data = ipa_gsup(m) + ipa_gsup(L[i + 1]); i += 2
        else:
            data = ipa_gsup(m); i += 1
        (f.c2s if len(fr) % 2 else f.s2c)(data)
    f.ack_c()
    pcap(os.path.join(outdir, 'gsm_gsup-coverage.pcap'), fr)

    # malformed / error capture
    ml = []
    g = Flow(42002, 3003, ml)
    g.open()
    bad = []
    bad.append(bytes([0x04]) + IMSI + bytes([0x08, 0x20, 1, 2]))                   # IE longer than the message (error)
    bad.append(bytes([0x04]) + IMSI + ie(0x41, b''))                                # SM-RP-DA missing type
    bad.append(bytes([0x24]) + IMSI + ie(0x41, bytes([0x00])) + ie(0x42, bytes([0x00])))   # type NONE
    bad.append(bytes([0x24]) + IMSI + ie(0x41, bytes([0x07])) + ie(0x42, bytes([0x07])))   # unknown type
    bad.append(bytes([0x24]) + IMSI + ie(0x41, bytes([0xff, 1])) + ie(0x42, bytes([0xff, 2])))   # NULL with a value
    bad.append(bytes([0x24]) + IMSI + ie(0x42, b'') + ie(0x41, bytes([0x01])))      # OA missing type; IMSI empty
    bad.append(bytes([0x30]) + IMSI + ie(0x50, tbcd('3540930123456780')[:8]))       # a real IMEI: first octet read as the BSSAP length
    # zero length IEs (reproducer gsup_zerolen_ie)
    z = bytes([0x10])
    for t in (0x08, 0x62, 0x40, 0x50, 0x15, 0x7c, 0x05, 0x03):
        z += ie(t, b'')
    bad.append(z)
    # nested TLV deeper than the IE: inner length past the outer one
    bad.append(bytes([0x0a]) + IMSI + ie(0x03, bytes([0x20, 0x30]) + fill(4)))
    bad.append(bytes([0x0a]) + IMSI + ie(0x03, ie(0x03, ie(0x03, ie(0x03, ie(0x03, ie(0x20, fill(16))))))))
    bad.append(bytes([0x06]) + IMSI + ie(0x11, b'\xf1'))                            # PDP address of one octet
    bad.append(bytes([0x06]) + IMSI + ie(0x08, b'\x91'))                            # MSISDN of one octet
    bad.append(bytes([0x34]) + ie(0x62, b'\x01') + ie(0x60, b''))                   # AN-APDU with no payload, empty name
    bad.append(bytes([0x3a]) + ie(0x62, b'\x01'))                                  # AN-APDU with the type only
    bad.append(bytes([0x34]))                                                       # type only
    for b in bad:
        g.c2s(ipa_gsup(b))
    g.ack_s()
    pcap(os.path.join(outdir, 'gsm_gsup-coverage-malformed.pcap'), ml)

if __name__ == '__main__':
    build(sys.argv[1] if len(sys.argv) > 1 else '.')
