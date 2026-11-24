#!/usr/bin/env python3
# Generates test/captures/cfm_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the CFM EOAM dissector
(epan/dissectors/packet-cfm.c, IEEE 802.1Q CFM / ITU-T G.8013/Y.1731).

All packets are built from scratch with struct; no captured traffic is
used. Two bridges (02:00:00:00:00:01 and 02:00:00:00:00:02) exchange CFM
PDUs in Ethernet II frames with ethertype 0x8902, some in an 802.1Q VLAN
tag, and two in MPLS-TP (GAL + G-ACh channel type 0x8902).

Usage: mkcfm.py <output directory>

Writes:
  cfm-coverage.pcap            every OpCode, every MAID MD/MA name format,
                               every TLV type and subtype, and the
                               reproducers of the branch fix that decode
                               cleanly
  cfm-coverage-malformed.pcap  paths that only malformed input reaches
"""

import os
import struct
import sys

SRC = bytes.fromhex('020000000001')
DST_MC = bytes.fromhex('0180c2000037')   # CFM group address, level 7
DST = bytes.fromhex('020000000002')


# --------------------------------------------------------------------------
# framing

def eth(pdu, dst=DST_MC, src=SRC):
    return dst + src + b'\x89\x02' + pdu


def eth_vlan(pdu, vid=100, pcp=7):
    return DST_MC + SRC + b'\x81\x00' + struct.pack('>H', (pcp << 13) | vid) + b'\x89\x02' + pdu


def mpls_gal(pdu):
    # Label 13 (GAL), TC 0, bottom of stack, TTL 1; then the G-ACh header
    # (first nibble 1, version 0, channel type 0x8902 = MPLS-TP OAM)
    lse = struct.pack('>I', (13 << 12) | (1 << 8) | 1)
    return DST + SRC + b'\x88\x47' + lse + b'\x10\x00\x89\x02' + pdu


def write_pcap(path, frames):
    out = [struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)]
    t = 1700000000
    for i, f in enumerate(frames):
        out.append(struct.pack('<IIII', t + i, (i * 1000) % 1000000, len(f), len(f)) + f)
    with open(path, 'wb') as fh:
        fh.write(b''.join(out))


# --------------------------------------------------------------------------
# CFM building blocks

END = b'\x00'


def hdr(opcode, flags, fto, level=7, version=0):
    return bytes([(level << 5) | version, opcode, flags, fto])


def tlv(typ, value, length=None):
    if length is None:
        length = len(value)
    return bytes([typ]) + struct.pack('>H', length) + value


def maid(md_fmt, md_name, ma_fmt=None, ma_name=b''):
    """48-octet MAID. md_fmt 1 has no MD name length/name."""
    m = bytes([md_fmt])
    if md_fmt != 1:
        m += bytes([len(md_name)]) + md_name
    if ma_fmt is not None:
        m += bytes([ma_fmt, len(ma_name)]) + ma_name
    assert len(m) <= 48, len(m)
    return m + b'\x00' * (48 - len(m))


def ccm(maid_bytes, tlvs=END, flags=0x84, seq=1, mep=101, fto=70, extra=b'', level=7):
    body = struct.pack('>IH', seq, mep) + maid_bytes
    body += struct.pack('>III', 1000, 2000, 3000) + b'\x00' * 4   # TxFCf RxFCb TxFCb reserved
    return hdr(0x01, flags, fto, level) + body + extra + tlvs


def sender_id(chassis=None, domain=None, mgmt=None):
    """chassis = (subtype, id) or None for a zero chassis ID length.
    domain = OID bytes or None (absent); mgmt = address bytes or None."""
    if chassis is None:
        v = b'\x00'
    else:
        st, cid = chassis
        v = bytes([len(cid), st]) + cid
    if domain is not None:
        v += bytes([len(domain)]) + domain
        if mgmt is not None:
            v += bytes([len(mgmt)]) + mgmt
    return tlv(0x01, v)


def reply_tlv(typ, action, mac, portid=None):
    v = bytes([action]) + mac
    if portid is not None:
        st, pid = portid
        if st is None:
            v += b'\x00'           # port ID length 0
        else:
            v += bytes([len(pid), st]) + pid
    return tlv(typ, v)


OID_UDP4 = bytes.fromhex('2b06010201640101')
OID_UDP6 = bytes.fromhex('2b06010201640102')
OID_TCP4 = bytes.fromhex('2b06010201640105')
OID_TCP6 = bytes.fromhex('2b06010201640106')
OID_SCTP4 = bytes.fromhex('2b06010201640109')
OID_SCTP6 = bytes.fromhex('2b0601020164010a')
OID_IEEE802 = bytes.fromhex('2b0601060106')
OID_OTHER8 = bytes.fromhex('2b06010201640163')   # same length, not in the table
OID_OTHER = bytes.fromhex('2b060104')            # other length

IP4 = bytes([192, 0, 2, 1])
IP6 = bytes.fromhex('20010db8000000000000000000000001')
MAC_A = bytes.fromhex('020000000001')
MAC_B = bytes.fromhex('020000000002')
MAC_C = bytes.fromhex('02000000000c')


def mipid_value(subtype, extra_pad=0, short=False):
    """MIP ID: ICC (6) + Node ID (4) + IF Num (4) + CC (2) = 16 octets."""
    v = b'ICC001' + struct.pack('>II', 0x0a000001, 7) + b'GB'
    if short:
        v = v[:15]
    return bytes([subtype]) + v + b'\x00' * extra_pad


def mep_maid_tlv(lb, mep, maid_bytes):
    return tlv(0x23, bytes([lb]) + struct.pack('>H', mep) + maid_bytes + b'\x00\x00')


# --------------------------------------------------------------------------
# main capture

def main_frames():
    F = []
    S = lambda s: s.encode()

    # ---- CCM: every MD name format and every MA name format -------------
    ccm_tlvs = (sender_id((4, MAC_A)) + tlv(0x02, b'\x02') + tlv(0x04, b'\x01') +
                tlv(0x1f, bytes.fromhex('0019a7') + b'\x01' + b'org-value') + END)
    F.append(eth(ccm(maid(4, S('MD-Level-Seven'), 2, S('MA-Customer-A')), ccm_tlvs)))  # 1
    F.append(eth(ccm(maid(1, b'', 1, struct.pack('>H', 100)), flags=0x01)))         # 2 none / PVID
    F.append(eth(ccm(maid(2, S('example.net'), 1, b'\x00\x64\x00'), flags=0x02)))  # 3 domain / PVID len 3
    F.append(eth(ccm(maid(3, MAC_A + b'\x00\x07', 3, b'\x01\x2c'), flags=0x03)))   # 4 MAC+int / ID
    F.append(eth(ccm(maid(3, MAC_A[:5], 3, b'\x05'), flags=0x05)))                  # 5 MAC len 5 / ID len 1
    F.append(eth(ccm(maid(0, b'\x01\x02\x03\x04', 4, bytes.fromhex('00000a') + struct.pack('>I', 42)),
                     flags=0x06)))                                                  # 6 reserved / VPN ID
    F.append(eth(ccm(maid(7, b'\xaa\xbb\xcc', 4, b'\x00\x00\x0a\x00\x01'), flags=0x07)))  # 7 unknown / VPN len 5
    F.append(eth(ccm(maid(1, b'', 32, S('ABCDEF0123456')), level=4)))              # 8 Y.1731 ICC
    F.append(eth(ccm(maid(1, b'', 32, S('ABCDEF0123')), level=4)))                 # 9 ICC len 10
    F.append(eth(ccm(maid(1, b'', 33, S('GB') + S('ABCDEF0123456')), level=4)))    # 10 ICC+CC
    F.append(eth(ccm(maid(1, b'', 33, S('GBABCDEF0123')), level=4)))               # 11 ICC+CC len 12
    F.append(eth(ccm(maid(1, b'', 0, b'\xde\xad\xbe\xef'))))                       # 12 MA reserved
    F.append(eth(ccm(maid(1, b'', 9, b'\xde\xad\xbe\xef'))))                       # 13 MA unknown fmt
    F.append(eth(ccm(maid(4, b'', 2, S('zero-length-md')))))                       # 14 MD len 0
    F.append(eth(ccm(maid(1, b'', 2, S('M' * 45)))))                               # 15 no padding
    F.append(eth(ccm(maid(4, S('D' * 46)))))                                       # 16 MD fills MAID
    F.append(eth(ccm(maid(4, S('D' * 45)))))                                       # 17 1 octet left
    F.append(eth(ccm(maid(4, S('MD'), 2, S('MA')), fto=74, extra=b'\xee' * 4)))    # 18 unknown data
    F.append(eth(ccm(maid(4, S('MD'), 2, S('MA')), fto=0)))                        # 19 First TLV Offset 0
    F.append(eth_vlan(ccm(maid(4, S('MD'), 2, S('MA')), flags=0x04, seq=2)))       # 20 in a VLAN tag

    # ---- LBM / LBR with Sender ID variants ----------------------------
    def lbm(tlvs, trans=1, fto=4, extra=b''):
        return hdr(0x03, 0, fto, 5) + struct.pack('>I', trans) + extra + tlvs

    def lbr(tlvs, trans=1, fto=4, extra=b''):
        return hdr(0x02, 0, fto, 5) + struct.pack('>I', trans) + extra + tlvs

    F.append(eth(lbm(sender_id((1, S('chassis-1'))) + tlv(0x03, b'0123456789abcdef') + END), dst=DST))  # 21
    F.append(eth(lbr(sender_id((2, S('if-alias'))) + tlv(0x03, b'0123456789abcdef') + END), dst=DST, src=DST))
    F.append(eth(lbm(sender_id((3, b'\x01\x02\x03'), OID_UDP4, IP4) + END, 2), dst=DST))
    F.append(eth(lbm(sender_id((5, b'\x01' + IP4), OID_UDP6, IP6) + END, 3), dst=DST))
    F.append(eth(lbm(sender_id((5, b'\x02' + IP6), OID_TCP4, IP4) + END, 4), dst=DST))   # 25
    F.append(eth(lbm(sender_id((5, b'\x07\x01\x02\x03'), OID_TCP6, IP6) + END, 5), dst=DST))
    F.append(eth(lbm(sender_id((5, b'\x01'), OID_SCTP4, IP4) + END, 6), dst=DST))
    F.append(eth(lbm(sender_id((6, S('eth0')), OID_SCTP6, IP6) + END, 7), dst=DST))
    F.append(eth(lbm(sender_id((7, S('local-7')), OID_IEEE802, MAC_A) + END, 8), dst=DST))
    F.append(eth(lbm(sender_id((9, b'\x99\x98'), OID_OTHER8, b'\x01\x02\x03') + END, 9), dst=DST))  # 30
    F.append(eth(lbm(sender_id(None, OID_OTHER, b'\x01\x02') + END, 10), dst=DST))
    F.append(eth(lbm(sender_id(None) + END, 11), dst=DST))                    # chassis length 0 only
    F.append(eth(lbm(sender_id(None, b'') + END, 12), dst=DST))               # MA domain length 0
    F.append(eth(lbm(sender_id((4, MAC_A), b'', b'') + END, 13), dst=DST))    # mgmt length w/o domain (warn)
    F.append(eth(lbm(sender_id((4, MAC_A), OID_UDP4, b'') + END, 14), dst=DST))  # 35 mgmt length 0
    F.append(eth(lbm(sender_id((4, MAC_A), OID_UDP4) + END, 15), dst=DST))    # domain, no mgmt length
    # Reproducers: short chassis ID MAC / network address / management address
    F.append(eth(lbm(sender_id((4, b'\x02\x00\x00')) + END, 16), dst=DST))
    F.append(eth(lbm(sender_id((5, b'\x01\xc0\x00')) + END, 17), dst=DST))
    F.append(eth(lbm(sender_id((5, b'\x02' + IP6[:8])) + END, 18), dst=DST))
    F.append(eth(lbm(sender_id((4, MAC_A), OID_UDP4, IP4[:2]) + END, 19), dst=DST))   # 40
    F.append(eth(lbm(sender_id((4, MAC_A), OID_UDP6, IP6[:4]) + END, 20), dst=DST))
    F.append(eth(lbm(sender_id((4, MAC_A), OID_IEEE802, MAC_A[:3]) + END, 21), dst=DST))
    F.append(eth(lbm(sender_id(None) + END, 22, fto=8, extra=b'\xee' * 4), dst=DST))
    F.append(eth(lbr(END, 22, fto=8, extra=b'\xee' * 4), dst=DST, src=DST))

    # ---- Y.1731 LBM/LBR TLVs: Requesting / Target / Replying MEP/MIP ----
    req_maid = maid(1, b'', 32, S('ABCDEF0123456'))
    F.append(eth(lbm(mep_maid_tlv(0, 101, req_maid) + tlv(0x21, b'\x02' + struct.pack('>H', 202)) +
                     END, 30), dst=DST))                                          # 45
    F.append(eth(lbr(mep_maid_tlv(1, 202, req_maid) +
                     tlv(0x22, b'\x02' + struct.pack('>H', 202)) + END, 30), dst=DST, src=DST))
    F.append(eth(lbm(tlv(0x21, b'\x00' + b'\x00' * 24) + END, 31), dst=DST))   # discovery ingress
    F.append(eth(lbm(tlv(0x21, b'\x01' + b'\x00' * 24) + END, 32), dst=DST))   # discovery egress
    F.append(eth(lbm(tlv(0x21, mipid_value(3)) + END, 33), dst=DST))           # MIP ID, 17
    F.append(eth(lbr(tlv(0x22, mipid_value(3, 8)) + END, 33), dst=DST, src=DST))  # 50 MIP ID + padding
    F.append(eth(lbm(tlv(0x21, b'\x07\x01\x02\x03') + END, 34), dst=DST))      # unknown subtype
    F.append(eth(lbm(tlv(0x21, b'\x02') + END, 35), dst=DST))                  # length 1
    # Reproducers: Target MEP ID with padding then End at the frame end,
    # MEP ID length 2, MIP ID length 16
    F.append(eth(lbm(tlv(0x21, b'\x02\x00\x01' + b'\x00' * 22) + END, 36), dst=DST))
    F.append(eth(lbm(tlv(0x21, b'\x02\x11') + END, 37), dst=DST))
    F.append(eth(lbr(tlv(0x22, mipid_value(3, short=True)) + END, 37), dst=DST, src=DST))  # 55

    # ---- LTM / LTR --------------------------------------------------------
    def ltm(tlvs, flags=0x80, fto=17, extra=b''):
        return (hdr(0x05, flags, fto, 6) + struct.pack('>IB', 0x100, 64) + MAC_A + MAC_C + extra + tlvs)

    def ltr(tlvs, flags=0xe0, relay=1, fto=6, extra=b''):
        return hdr(0x04, flags, fto, 6) + struct.pack('>IBB', 0x100, 63, relay) + extra + tlvs

    F.append(eth(ltm(tlv(0x07, b'\x00\x01' + MAC_A) + sender_id((4, MAC_A)) + END)))   # 56
    F.append(eth(ltr(tlv(0x08, b'\x00\x01' + MAC_A + b'\x00\x02' + MAC_B) +
                     reply_tlv(0x05, 1, MAC_B, (1, S('ge-0/0/1'))) +
                     reply_tlv(0x06, 1, MAC_B, (5, S('ge-0/0/2'))) + END), dst=DST, src=DST))
    F.append(eth(ltr(reply_tlv(0x05, 2, MAC_B) + reply_tlv(0x06, 2, MAC_B) + END, relay=2),
                 dst=DST, src=DST))                                              # no port ID
    F.append(eth(ltr(reply_tlv(0x05, 3, MAC_B, (2, b'\x01\x02')) +
                     reply_tlv(0x06, 3, MAC_B, (3, MAC_B)) + END, relay=3), dst=DST, src=DST))
    F.append(eth(ltr(reply_tlv(0x05, 4, MAC_B, (4, b'\x01' + IP4)) +
                     reply_tlv(0x06, 4, MAC_B, (4, b'\x02' + IP6)) + END, flags=0x40), dst=DST, src=DST))  # 60
    F.append(eth(ltr(reply_tlv(0x05, 1, MAC_B, (4, b'\x09\x01\x02')) +
                     reply_tlv(0x06, 1, MAC_B, (4, b'\x01')) + END), dst=DST, src=DST))
    F.append(eth(ltr(reply_tlv(0x05, 1, MAC_B, (6, b'\xc1\xc2\xc3')) +
                     reply_tlv(0x06, 1, MAC_B, (7, S('local-port'))) + END), dst=DST, src=DST))
    F.append(eth(ltr(reply_tlv(0x05, 1, MAC_B, (9, b'\x99')) +
                     reply_tlv(0x06, 1, MAC_B, (None, b'')) + END), dst=DST, src=DST))
    # Reproducers: short reply port ID MAC and network addresses
    F.append(eth(ltr(reply_tlv(0x05, 1, MAC_B, (3, MAC_B[:4])) +
                     reply_tlv(0x06, 1, MAC_B, (4, b'\x01\xc0\x00')) + END), dst=DST, src=DST))
    F.append(eth(ltr(reply_tlv(0x05, 1, MAC_B, (4, b'\x02' + IP6[:6])) +
                     reply_tlv(0x06, 4, MAC_B) + END), dst=DST, src=DST))       # 65
    F.append(eth(ltm(tlv(0x09, MAC_C + struct.pack('>H', 200) + MAC_A) + END, flags=0x00)))
    F.append(eth(ltm(END, fto=21, extra=b'\xee' * 4)))
    F.append(eth(ltr(END, fto=10, extra=b'\xee' * 4), dst=DST, src=DST))

    # ---- RFM / SFM (802.1Q Data-driven and Data-dependent CFM) ----------
    inner = DST + SRC + b'\x08\x00' + b'\x45' + b'\x00' * 19
    F.append(eth(hdr(0x06, 0, 4, 3) + struct.pack('>I', 77) + tlv(0x0a, inner[:20]) +
                 tlv(0x0b, inner[20:]) + tlv(0x0c, inner[:12]) + END))           # 69
    F.append(eth(hdr(0x07, 0, 4, 3) + struct.pack('>I', 78) + tlv(0x03, b'sfm') + END))
    F.append(eth(hdr(0x06, 0, 8, 3) + struct.pack('>I', 79) + b'\xee' * 4 + END))
    F.append(eth(hdr(0x07, 0, 8, 3) + struct.pack('>I', 80) + b'\xee' * 4 + END))

    # ---- GNM: BNM and an unknown sub-OpCode ------------------------------
    F.append(eth(hdr(0x20, 0x04, 13, 3) + b'\x01' + struct.pack('>III', 1000, 500, 3) + END))  # 73
    F.append(eth(hdr(0x20, 0x05, 17, 3) + b'\x01' + struct.pack('>III', 1000, 500, 3) +
                 b'\xee' * 4 + END))
    F.append(eth(hdr(0x20, 0x01, 1, 3) + b'\x09' + END))
    F.append(eth(hdr(0x20, 0x01, 5, 3) + b'\x09' + b'\xee' * 4 + END))

    # ---- AIS / LCK / CSF ---------------------------------------------------
    F.append(eth(hdr(0x21, 0x04, 0, 4) + END))                                   # 77
    F.append(eth(hdr(0x21, 0x06, 4, 4) + b'\xee' * 4 + END))
    F.append(eth(hdr(0x23, 0x04, 0, 4) + END))
    F.append(eth(hdr(0x23, 0x06, 4, 4) + b'\xee' * 4 + END))                     # 80
    F.append(eth(hdr(0x34, 0x0c, 0, 4) + END))                                   # CSF RDI, 1s
    F.append(eth(hdr(0x34, 0x1e, 4, 4) + b'\xee' * 4 + END))                     # CSF DCI, 1 min

    # ---- TST with the Test TLV pattern types ----------------------------
    def tst(tlvs, seq, fto=4, extra=b''):
        return hdr(0x25, 0, fto, 4) + struct.pack('>I', seq) + extra + tlvs

    F.append(eth(tst(tlv(0x20, b'\x00' + b'\x00' * 16) + END, 1)))               # 83 null, no CRC
    F.append(eth(tst(tlv(0x20, b'\x01' + b'\x00' * 16 + b'\x12\x34\x56\x78') + END, 2)))  # null + CRC
    F.append(eth(tst(tlv(0x20, b'\x02' + bytes(range(1, 17))) + END, 3)))       # PRBS
    F.append(eth(tst(tlv(0x20, b'\x03' + bytes(range(1, 17)) + b'\x9a\xbc\xde\xf0') + END, 4)))
    F.append(eth(tst(tlv(0x20, b'\x05\x01\x02') + END, 5)))                     # unknown pattern
    F.append(eth(tst(tlv(0x20, b'\x00') + END, 6)))                             # length 1
    F.append(eth(tst(tlv(0x20, b'\x01\x02\x03\x04') + END, 7)))                 # reproducer: CRC, length 4
    F.append(eth(tst(tlv(0x20, b'\x03\x00') + END, 8)))                         # 90 reproducer: length 2
    F.append(eth(tst(END, 9, fto=8, extra=b'\xee' * 4)))

    # ---- APS / R-APS --------------------------------------------------------
    F.append(eth(hdr(0x27, 0, 4, 7) + bytes([0xbf, 0x01, 0x01, 0x80]) + END))   # 92
    F.append(eth(hdr(0x27, 0, 8, 7) + bytes([0x00, 0x00, 0x00, 0x00]) + b'\xee' * 4 + END))
    F.append(eth(hdr(0x28, 0, 32, 7, 0) + bytes([0xb0, 0xc0]) + MAC_A + b'\x00' * 24 + END))  # v1 SF
    F.append(eth(hdr(0x28, 0, 32, 7, 1) + bytes([0xe0, 0xe0]) + MAC_A + b'\x00' * 24 + END))  # 95 v2 event
    F.append(eth(hdr(0x28, 0, 32, 7, 1) + bytes([0x70, 0x20]) + MAC_B + b'\x00' * 24 + END))  # v2 MS
    F.append(eth(hdr(0x28, 0, 36, 7, 0) + bytes([0x00, 0x00]) + MAC_B + b'\x00' * 24 +
                 b'\xee' * 4 + END))

    # ---- MCC / EXM / EXR / VSM / VSR ------------------------------------
    OUI = bytes.fromhex('0019a7')
    for op in (0x29, 0x31, 0x30, 0x33, 0x32):
        data = b'\xd0\xd1\xd2\xd3\xd4'
        # End TLV right after the data
        F.append(eth(hdr(op, 0, 4 + len(data), 2) + OUI + b'\x01' + data + END))
        # No data: End TLV right after the sub-OpCode
        F.append(eth(hdr(op, 0, 4, 2) + OUI + b'\x02' + END))
        # First TLV Offset points to a vendor TLV inside the data, then End
        vt = tlv(0x55, b'\xaa\xbb')
        F.append(eth(hdr(op, 0, 4 + 2, 2) + OUI + b'\x03' + b'\xd0\xd1' + vt + END))
    # (frames 98-112)

    # ---- LMM / LMR ---------------------------------------------------------
    F.append(eth(hdr(0x2b, 0x00, 12, 5) + struct.pack('>III', 100, 0, 0) + END))    # 113
    F.append(eth(hdr(0x2a, 0x00, 12, 5) + struct.pack('>III', 100, 99, 98) + END, dst=DST, src=DST))
    F.append(eth(hdr(0x2b, 0x01, 16, 5) + struct.pack('>III', 101, 0, 0) + b'\xee' * 4 + END))
    F.append(eth(hdr(0x2a, 0x01, 16, 5) + struct.pack('>III', 101, 100, 99) + b'\xee' * 4 + END,
                 dst=DST, src=DST))

    # ---- 1DM / DMM / DMR ----------------------------------------------------
    ts = lambda s, ns: struct.pack('>II', s, ns)
    F.append(eth(hdr(0x2d, 0x00, 16, 5) + ts(1700000000, 1000) + ts(0, 0) + END))   # 117
    F.append(eth(hdr(0x2d, 0x01, 20, 5) + ts(1700000000, 2000) + ts(0, 0) + b'\xee' * 4 + END))
    F.append(eth(hdr(0x2f, 0x00, 32, 5) + ts(1700000001, 0) + ts(0, 0) * 3 + END))
    F.append(eth(hdr(0x2e, 0x00, 32, 5) + ts(1700000001, 0) + ts(1700000001, 500) +
                 ts(1700000001, 600) + ts(1700000001, 1200) + END, dst=DST, src=DST))   # 120
    F.append(eth(hdr(0x2f, 0x01, 36, 5) + ts(1700000002, 0) + ts(0, 0) * 3 + b'\xee' * 4 + END))
    F.append(eth(hdr(0x2e, 0x01, 36, 5) + ts(1700000002, 0) + ts(1700000002, 500) +
                 ts(1700000002, 600) + ts(1700000002, 1200) + b'\xee' * 4 + END, dst=DST, src=DST))

    # ---- 1SL / SLM / SLR with Test ID TLVs ----------------------------------
    F.append(eth(hdr(0x35, 0, 16, 5) + struct.pack('>HH', 101, 0) + b'\x00\x00\x00\x07' +
                 struct.pack('>I', 5) + b'\x00' * 4 + tlv(0x24, b'\x00\x00\x00\x07') + END))   # 123
    F.append(eth(hdr(0x37, 0, 16, 5) + struct.pack('>HH', 101, 0) + b'\x00\x00\x00\x08' +
                 struct.pack('>I', 6) + b'\x00' * 4 + tlv(0x24, b'\x00\x00\x00\x08', 32) + END))
    F.append(eth(hdr(0x36, 0, 16, 5) + struct.pack('>HH', 101, 202) + b'\x00\x00\x00\x08' +
                 struct.pack('>II', 6, 6) + END, dst=DST, src=DST))                   # 125
    F.append(eth(hdr(0x35, 0, 20, 5) + struct.pack('>HH', 101, 0) + b'\x00\x00\x00\x09' +
                 struct.pack('>I', 7) + b'\x00' * 4 + b'\xee' * 4 + END))
    F.append(eth(hdr(0x37, 0, 20, 5) + struct.pack('>HH', 101, 0) + b'\x00\x00\x00\x09' +
                 struct.pack('>I', 7) + b'\x00' * 4 + b'\xee' * 4 + END))
    F.append(eth(hdr(0x36, 0, 20, 5) + struct.pack('>HH', 101, 202) + b'\x00\x00\x00\x09' +
                 struct.pack('>II', 7, 7) + b'\xee' * 4 + END, dst=DST, src=DST))

    # ---- Unknown OpCodes, other TLVs ------------------------------------
    F.append(eth(hdr(0x00, 0x55, 0, 1) + END))                                   # 129 IEEE 802.1 reserved
    F.append(eth(hdr(0x40, 0x55, 4, 1) + b'\xee' * 4 + END))                     # 130 unknown OpCode
    F.append(eth(hdr(0x40, 0x00, 0, 1) +
                 tlv(0x0d, b'\x01\x02') +                 # GNM TLV (no specific decoding)
                 tlv(0x30, b'\x01\x02\x03') +             # unknown TLV type
                 tlv(0x03, b'') +                         # zero-length TLV
                 tlv(0x1f, b'\x00\x19\xa7') +             # Org specific, length 3
                 tlv(0x1f, bytes.fromhex('0019a7') + b'\x05') +   # Org specific, no value
                 END))

    # ---- MPLS-TP: CFM PDUs in the G-ACh (pwach.channel_type 0x8902) --------
    F.append(mpls_gal(ccm(maid(1, b'', 32, S('ABCDEF0123456')), flags=0x04, level=0)))   # 132
    F.append(mpls_gal(hdr(0x2f, 0x00, 32, 0) + ts(1700000003, 0) + ts(0, 0) * 3 + END))  # 133

    # ---- Reproducers: MCC/EXM/EXR/VSM/VSR with the First TLV Offset (3)
    # inside the OUI and sub-OpCode already consumed. The End TLV search
    # starts at the sub-OpCode (0x01), reads a zero length from the data
    # and finds the End TLV after it.  (frames 134-138)
    for op in (0x29, 0x31, 0x30, 0x33, 0x32):
        F.append(eth(hdr(op, 0, 3, 2) + OUI + b'\x01' + b'\x00\x00' + END))
    return F


# --------------------------------------------------------------------------
# malformed capture

def malformed_frames():
    F = []
    S = lambda s: s.encode()

    def lbm(tlvs, trans=1):
        return hdr(0x03, 0, 4, 5) + struct.pack('>I', trans) + tlvs

    # 1: MD name length 47 runs past the MAID (error expert info)
    F.append(eth(ccm(maid(4, S('D' * 46)) [:1] + b'\x2f' + S('D' * 46))))
    # 2: Requesting MEP ID with an MD name length of 255 (reproducer)
    m = bytes([4, 255]) + b'A' * 46
    F.append(eth(lbm(mep_maid_tlv(0, 1, m) + END)))
    # 3: MA name length past the MAID
    m = bytes([1, 2, 60]) + b'A' * 45
    F.append(eth(ccm(m)))
    # 4: no End TLV: the TLV loop runs off the frame
    F.append(eth(lbm(tlv(0x03, b'abcd'))))
    # 5: frame ends inside the common header
    F.append(eth(b'\xe0\x01'))
    # 6: TLV length past the end of the frame
    F.append(eth(lbm(tlv(0x03, b'abcd', 40) + END)))
    # 7: MCC with a First TLV Offset inside the OUI that starts with 0x00
    #    (reproducer): no TLV loop start is left once the rest is PDU data
    F.append(eth(bytes([0x00, 0x29, 0x00, 0x00, 0x00, 0x11, 0x22, 0x33, 0x00])))
    # 8: VSM with no End TLV reachable (vendor TLV length runs off the frame)
    F.append(eth(hdr(0x33, 0, 4, 2) + bytes.fromhex('0019a7') + b'\x01' + tlv(0x55, b'\xaa', 40)))
    # 9: EXR whose TLV walk leaves fewer than 3 octets
    F.append(eth(hdr(0x30, 0, 4, 2) + bytes.fromhex('0019a7') + b'\x01' + b'\x55\x00'))
    # 10: Sender ID chassis ID longer than the frame
    F.append(eth(lbm(tlv(0x01, bytes([40, 1]) + b'abc'))))
    # 11: Truncated CCM (MAID cut short)
    F.append(eth(ccm(maid(4, S('MD'), 2, S('MA')))[:30]))
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'cfm-coverage.pcap'), main_frames())
    write_pcap(os.path.join(out, 'cfm-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()
