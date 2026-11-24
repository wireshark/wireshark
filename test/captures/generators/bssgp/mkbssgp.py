#!/usr/bin/env python3
# Generates test/captures/bssgp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the BSSGP dissector (packet-bssgp.c).

BSSGP (3GPP TS 48.018) is carried in NS-UNITDATA PDUs of NS over UDP
(packet-nsip.c, UDP ports 2157 and 19999 by default). Every packet is built
from scratch with struct; no captured traffic is used.

Usage: mkbssgp.py <output directory>

Writes:
  bssgp-coverage.pcap            every BSSGP PDU type with its IEs, the RIM
                                 PDUs with every RIM application, the
                                 reproducers of the fixes on the branch
  bssgp-coverage-malformed.pcap  missing mandatory IEs, truncated IEs, unknown
                                 message type, paths that hit unfixed bugs
"""

import os
import struct
import sys


# ---------------------------------------------------------------------------
# Framing: Ethernet / IPv4 / UDP 2157 / NS-UNITDATA / BSSGP

def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


SRC = bytes([192, 0, 2, 1])
DST = bytes([192, 0, 2, 2])


def frame(bssgp, bvci=2, port=2157, ident=1):
    ns = bytes([0x00, 0x00]) + struct.pack('!H', bvci) + bssgp
    udp = struct.pack('!HHHH', port, port, 8 + len(ns), 0)
    pseudo = SRC + DST + struct.pack('!BBH', 0, 17, len(udp) + len(ns))
    c = csum(pseudo + udp + ns) or 0xffff
    udp = udp[:6] + struct.pack('!H', c) + ns
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), ident & 0xffff, 0,
                     64, 17, 0, SRC, DST)
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    eth = bytes.fromhex('020000000002' '020000000001') + b'\x08\x00'
    return eth + ip + udp


def write_pcap(path, pdus):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, p in enumerate(pdus):
            if isinstance(p, tuple):
                b, kw = p
            else:
                b, kw = p, {}
            pkt = frame(b, ident=i + 1, **kw)
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(pkt), len(pkt)))
            f.write(pkt)


# ---------------------------------------------------------------------------
# IE helpers

def telv(iei, val):
    """TLV with the extended length indicator: one octet with bit 8 set, or
    two octets for 128 and more."""
    n = len(val)
    if n < 0x80:
        return bytes([iei, 0x80 | n]) + val
    return bytes([iei]) + struct.pack('!H', n) + val


def telv2(iei, val):
    """The same with a two octet length even for short values."""
    return bytes([iei]) + struct.pack('!H', len(val)) + val


def tlv(iei, val):
    return bytes([iei, len(val)]) + val


PLMN = bytes.fromhex('00f110')           # MCC 001 MNC 01
RAI = PLMN + bytes.fromhex('0001' '01')  # LAC 1, RAC 1
LAI = PLMN + bytes.fromhex('0001')
CELL_ID = RAI + bytes.fromhex('0001')    # RAI + CI 1
TAI = PLMN + bytes.fromhex('0001')       # TAC 1
TLLI = bytes.fromhex('c0000001')
IMSI = bytes.fromhex('0910101032547698')  # 001011234567890 (15 digits)
IMEI = bytes.fromhex('3a21436587092143')  # IMEI, odd, type 2
IMEISV = bytes.fromhex('03214365870921f3')  # IMEISV, even, type 3
TMSI = bytes.fromhex('11223344')

# MS Radio Access Capability: GSM E access technology with RF power class,
# no A5 bits, ES/PS/VGCS/VBS, no multislot capability, no further entries.
MS_RAC = bytes.fromhex('113080')

# Global-ENB-ID (S1AP, aligned PER): PLMN 00f110, macro eNB id 1
GLOBAL_ENB_ID = bytes.fromhex('00' '00f110' '00' '000010')
# RANAP SourceCellID, sourceGERANCellID: PLMN, LAC 1, CI 1
SRC_CELL_GERAN = bytes([0x40]) + PLMN + b'\x00\x01' + b'\x00\x01'

# UE-EUTRA-Capability (LTE RRC, unaligned PER): rel8, category 1, no ROHC,
# band 1, one inter-frequency band entry, no inter-RAT parameters
UE_EUTRA_CAP = bytes(7)

# 3GPP TS 24.008 QoS (ABQP), 14 octets value part
QOS = bytes.fromhex('0b921f7396fefe742bffff004a00')


def crc24(data):
    poly = 0xad85dd
    c = 0xffffff
    for b in data:
        c ^= b
        for _ in range(8):
            c = (c >> 1) ^ poly if c & 1 else c >> 1
    return ~c & 0xffffff


def llc_ui(sapi, payload, nu=0):
    """An LLC UI frame (3GPP TS 44.064), protected mode, valid FCS."""
    hdr = bytes([sapi & 0x0f]) + struct.pack('!H', 0xc000 | (nu << 2) | 0x01)
    body = hdr + payload
    return body + crc24(body).to_bytes(3, 'little')


# GMM Identity Request (IMSI) in LLC SAPI 1
LLC_GMM = llc_ui(1, bytes.fromhex('081501'))
LLC_GMM2 = llc_ui(1, bytes.fromhex('081502'), nu=1)


# ---------------------------------------------------------------------------
# SI messages for the NACC application container (each 21 octets: message
# type + 20 octets)

def si3():
    body = (b'\x00\x01' + LAI +              # cell identity, LAI
            bytes.fromhex('490390') +         # control channel description
            bytes.fromhex('28') +             # cell options
            bytes.fromhex('6500') +           # cell selection parameters
            bytes.fromhex('0f0000') +         # RACH control parameters
            bytes.fromhex('2b2b2b2b'))        # SI3 rest octets
    return b'\x1b' + body[:20].ljust(20, b'\x2b')


def si1():
    body = bytes(16) + bytes.fromhex('0f0000') + b'\x2b'
    return b'\x19' + body[:20]


def si13():
    return b'\x00' + bytes.fromhex('90005800') + b'\x2b' * 16


# ---------------------------------------------------------------------------
# PDUs

def pdus_main():
    P = []
    note = []

    def add(desc, b, **kw):
        P.append((b, kw))
        note.append(desc)

    tlli_ie = telv(0x1f, TLLI)
    imsi_ie = telv(0x0d, IMSI)

    # 0x00 DL-UNITDATA with every optional IE
    qos_dl = b'\x00\x00' + b'\x01'        # best effort, precedence 1
    dl = (bytes([0x00]) + TLLI + qos_dl +
          telv(0x16, b'\x01\xf4') +          # PDU lifetime
          telv(0x13, MS_RAC) +
          telv(0x17, b'\x45') +              # priority
          telv(0x0a, b'\x00\x00') +          # DRX
          imsi_ie +
          telv(0x1f, bytes.fromhex('c0000002')) +   # TLLI (old)
          telv(0x28, b'\x05') +              # PFI
          telv(0x27, b'\x00' + b'\x01\x00\x00\x01') +  # LSA information
          telv(0x3d, b'\x09') +              # service UTRAN CCO
          telv(0x81, b'\x10') +              # SPID
          telv(0x88, b'\x0b') +              # redirection indication
          telv(0x89, b'\x01') +              # redirection completed
          telv(0x8a, b'\x01\x23') +          # unconfirmed send state var
          telv(0x8c, b'\x01') +              # SCI
          telv(0x8d, b'\x01') +              # GGSN/P-GW location
          telv(0x92, b'\x05') +              # eDRX
          telv(0x98, b'\x12') +              # coverage class
          telv(0x9b, RAI) +                  # old RAI
          telv(0x9c, b'\x01') +              # attach indicator
          telv(0x00, b'\x00\x00') +          # alignment
          telv(0x0e, LLC_GMM) +
          telv(0x0e, LLC_GMM2))              # initial LLC-PDU
    add('DL-UNITDATA, all IEs', dl)
    # DL-UNITDATA, mandatory only, peak rate not zero
    add('DL-UNITDATA, minimal', bytes([0x00]) + TLLI + b'\x01\x00\x04' +
        telv(0x16, b'\xff\xff') + telv(0x0e, LLC_GMM))

    # 0x01 UL-UNITDATA
    ul = (bytes([0x01]) + TLLI + b'\x00\x64\x22' +
          telv(0x08, CELL_ID) +
          telv(0x28, b'\x05') +
          telv(0x26, bytes.fromhex('000001000002')) +   # LSA identifier list
          telv(0x87, b'\x00') +              # redirect attempt flag
          imsi_ie +
          telv(0x8a, b'\x00\x10') +
          telv(0x8e, PLMN) +                 # selected PLMN ID
          telv(0x98, b'\x21') +
          telv(0x9a, b'\x01') +              # exception report flag
          telv(0x9d, PLMN) +                 # selected operator
          telv(0x9d, bytes.fromhex('13f254')) +  # CS registered operator
          telv(0x00, b'\x00') +
          telv(0x0e, LLC_GMM))
    add('UL-UNITDATA, all IEs', ul)

    # 0x02 RA-CAPABILITY
    add('RA-CAPABILITY', bytes([0x02]) + tlli_ie + telv(0x13, MS_RAC))
    # 0x03 PTM-UNITDATA (no function: message elements)
    add('PTM-UNITDATA', bytes([0x03]) + b'\x01\x02\x03\x04')
    # 0x04 DL-MBMS-UNITDATA
    tmgi = telv(0x5c, bytes.fromhex('010203') + PLMN)
    add('DL-MBMS-UNITDATA', bytes([0x04]) + telv(0x16, b'\x00\x64') + tmgi +
        telv(0x5d, b'\x07') + telv(0x00, b'\x00\x00\x00') + telv(0x0e, LLC_GMM))
    # 0x05 UL-MBMS-UNITDATA
    add('UL-MBMS-UNITDATA', bytes([0x05]) + tmgi + telv(0x5d, b'\x07') +
        telv(0x00, b'\x00') + telv(0x0e, LLC_GMM))

    # 0x06 PAGING-PS
    add('PAGING-PS', bytes([0x06]) + imsi_ie + telv(0x0a, b'\x00\x00') +
        telv(0x04, b'\x00\x02') + telv(0x10, LAI) + telv(0x1b, RAI) +
        telv(0x02, b'\x01') + telv(0x28, b'\x05') + telv(0x3a, QOS) +
        telv(0x18, b'\x00\x00\x02') + telv(0x20, TMSI) + telv(0x92, b'\x03') +
        telv(0x98, b'\x11') + telv(0x08, CELL_ID) + telv(0x13, MS_RAC) +
        telv(0x99, b'\x93'))
    # 0x07 PAGING-CS: TMSI and Global CN-Id after Channel Needed
    add('PAGING-CS', bytes([0x07]) + imsi_ie + telv(0x0a, b'\x00\x00') +
        telv(0x04, b'\x00\x02') + telv(0x10, LAI) + telv(0x1b, RAI) +
        telv(0x02, b'\x01') + tlli_ie + telv(0x09, b'\x06') +
        telv(0x0b, b'\x03') + telv(0x20, TMSI) +
        telv(0x53, PLMN + b'\x00\x05'))
    # 0x08 RA-CAPABILITY-UPDATE, 0x09 ACK
    add('RA-CAPABILITY-UPDATE', bytes([0x08]) + tlli_ie + telv(0x1e, b'\x05'))
    add('RA-CAPABILITY-UPDATE-ACK', bytes([0x09]) + tlli_ie + telv(0x1e, b'\x05') +
        imsi_ie + telv(0x1a, b'\x00') + telv(0x13, MS_RAC))
    # 0x0a RADIO-STATUS
    add('RADIO-STATUS', bytes([0x0a]) + tlli_ie + telv(0x20, TMSI) + imsi_ie +
        telv(0x19, b'\x02'))
    # 0x0b - 0x10 SUSPEND / RESUME
    rai_ie = telv(0x1b, RAI)
    add('SUSPEND', bytes([0x0b]) + tlli_ie + rai_ie)
    add('SUSPEND-ACK', bytes([0x0c]) + tlli_ie + rai_ie + telv(0x1d, b'\x2a'))
    add('SUSPEND-NACK', bytes([0x0d]) + tlli_ie + rai_ie + telv(0x07, b'\x04'))
    add('RESUME', bytes([0x0e]) + tlli_ie + rai_ie + telv(0x1d, b'\x2a'))
    add('RESUME-ACK', bytes([0x0f]) + tlli_ie + rai_ie)
    add('RESUME-NACK', bytes([0x10]) + tlli_ie + rai_ie + telv(0x07, b'\x04'))
    # 0x11 PAGING-PS-REJECT, 0x12 DUMMY-PAGING-PS, 0x13 response
    add('PAGING-PS-REJECT', bytes([0x11]) + imsi_ie + telv(0x20, TMSI) +
        telv(0x93, b'\x05\x1e'))
    add('DUMMY-PAGING-PS', bytes([0x12]) + imsi_ie + rai_ie + telv(0x92, b'\x0b'))
    add('DUMMY-PAGING-PS-RESPONSE', bytes([0x13]) + imsi_ie + telv(0x93, b'\x01\x02'))
    # 0x14 MS-REGISTRATION-ENQUIRY (no function)
    add('MS-REGISTRATION-ENQUIRY', bytes([0x14]) + imsi_ie)

    # 0x20 - 0x25 BVC block/reset/unblock
    bvci_ie = telv(0x04, b'\x00\x02')
    add('BVC-BLOCK', bytes([0x20]) + bvci_ie + telv(0x07, b'\x08'), bvci=0)
    add('BVC-BLOCK-ACK', bytes([0x21]) + bvci_ie, bvci=0)
    add('BVC-RESET', bytes([0x22]) + bvci_ie + telv(0x07, b'\x08') +
        telv(0x08, CELL_ID) + telv(0x3b, b'\xff') + telv(0x69, b'\x7f'), bvci=0)
    add('BVC-RESET-ACK', bytes([0x23]) + bvci_ie + telv(0x08, CELL_ID) +
        telv(0x3b, b'\x14') + telv(0x69, b'\x01'), bvci=0)
    add('BVC-UNBLOCK', bytes([0x24]) + bvci_ie, bvci=0)
    add('BVC-UNBLOCK-ACK', bytes([0x25]) + bvci_ie, bvci=0)
    # 0x26 - 0x29 flow control
    add('FLOW-CONTROL-BVC', bytes([0x26]) + telv(0x1e, b'\x01') +
        telv(0x05, b'\x01\x00') + telv(0x03, b'\x00\x50') + telv(0x01, b'\x00\x20') +
        telv(0x1c, b'\x00\x10') + telv(0x3c, b'\x40') + telv(0x06, b'\x00\x0a') +
        telv(0x7e, b'\x01'))
    add('FLOW-CONTROL-BVC-ACK', bytes([0x27]) + telv(0x1e, b'\x01'))
    add('FLOW-CONTROL-MS', bytes([0x28]) + tlli_ie + telv(0x1e, b'\x02') +
        telv(0x12, b'\x00\x30') + telv(0x03, b'\x00\x08') + telv(0x3c, b'\x80') +
        telv(0x7e, b'\x02'))
    add('FLOW-CONTROL-MS-ACK', bytes([0x29]) + tlli_ie + telv(0x1e, b'\x02'))
    # 0x2a FLUSH-LL with the new BVCI and NSEI, 0x2b FLUSH-LL-ACK
    add('FLUSH-LL', bytes([0x2a]) + tlli_ie + telv(0x04, b'\x00\x02') +
        telv(0x04, b'\x00\x03') + telv(0x3e, b'\x12\x34'), bvci=0)
    add('FLUSH-LL-ACK', bytes([0x2b]) + tlli_ie + telv(0x0c, b'\x01') +
        telv(0x04, b'\x00\x03') + telv(0x25, b'\x00\x01\x00') +
        telv(0x3e, b'\x43\x21'), bvci=0)
    add('LLC-DISCARDED', bytes([0x2c]) + tlli_ie + telv(0x0f, b'\x03') +
        bvci_ie + telv(0x25, b'\x00\x00\x40') + telv(0x28, b'\x05'), bvci=0)
    # 0x2d FLOW-CONTROL-PFC (two PFCs with B_PFC), 0x2e ACK
    add('FLOW-CONTROL-PFC', bytes([0x2d]) + tlli_ie + telv(0x1e, b'\x03') +
        telv(0x12, b'\x00\x30') + telv(0x3b, b'\x0c') + telv(0x3c, b'\x20') +
        telv(0x52, b'\x02' + b'\x05\x00\x10\x00\x20\x30' + b'\x06\x00\x11\x00\x21\x31') +
        telv(0x7e, b'\x00'))
    add('FLOW-CONTROL-PFC (no B_PFC)', bytes([0x2d]) + tlli_ie + telv(0x1e, b'\x04') +
        telv(0x52, b'\x01' + b'\x05\x00\x10\x00\x20'))
    add('FLOW-CONTROL-PFC (no PFC)', bytes([0x2d]) + tlli_ie + telv(0x1e, b'\x05') +
        telv(0x52, b'\x00'))
    add('FLOW-CONTROL-PFC-ACK', bytes([0x2e]) + tlli_ie + telv(0x1e, b'\x03'))

    # 0x40 SGSN-INVOKE-TRACE with OMC Id and Transaction Id
    add('SGSN-INVOKE-TRACE', bytes([0x40]) + telv(0x22, b'\x01') +
        telv(0x21, b'\x00\x01') + telv(0x24, b'TRIGGER') + telv(0x11, IMEISV) +
        telv(0x14, b'OMC-ID-TEST') + telv(0x23, b'\xab\xcd'), bvci=0)
    # 0x41 STATUS
    add('STATUS', bytes([0x41]) + telv(0x07, b'\x27') + bvci_ie +
        telv(0x15, bytes([0x22]) + bvci_ie), bvci=0)
    # 0x42 OVERLOAD
    add('OVERLOAD', bytes([0x42]) + telv(0x8f, b'\x01'), bvci=0)

    # 0x50 - 0x58 PFC management
    pfi_ie = telv(0x28, b'\x05')
    add('DOWNLOAD-BSS-PFC', bytes([0x50]) + tlli_ie + pfi_ie)
    add('CREATE-BSS-PFC', bytes([0x51]) + tlli_ie + imsi_ie + pfi_ie +
        telv(0x29, b'\x45') + telv(0x3a, QOS) + telv(0x3d, b'\x01') +
        telv(0x13, MS_RAC) + telv(0x17, b'\x45') + telv(0x29, b'\x22') +
        telv(0x73, b'\x00') + telv(0x80, UE_EUTRA_CAP) + telv(0x81, b'\x00'))
    add('CREATE-BSS-PFC-ACK', bytes([0x52]) + tlli_ie + pfi_ie + telv(0x3a, QOS) +
        telv(0x07, b'\x2e'))
    add('CREATE-BSS-PFC-NACK', bytes([0x53]) + tlli_ie + pfi_ie + telv(0x07, b'\x0a'))
    add('MODIFY-BSS-PFC', bytes([0x54]) + tlli_ie + pfi_ie + telv(0x3a, QOS))
    add('MODIFY-BSS-PFC-ACK', bytes([0x55]) + tlli_ie + pfi_ie + telv(0x29, b'\x45') +
        telv(0x3a, QOS))
    add('DELETE-BSS-PFC', bytes([0x56]) + tlli_ie + pfi_ie)
    add('DELETE-BSS-PFC-ACK', bytes([0x57]) + tlli_ie + pfi_ie)
    add('DELETE-BSS-PFC-REQ', bytes([0x58]) + tlli_ie + pfi_ie + telv(0x07, b'\x0b'))

    # 0x59 - 0x5e, 0x91 - 0x93 PS handover
    s2t = (telv(0x13, MS_RAC) + telv(0x73, b'\x00') + telv(0x6d, b'\x01') +
           telv(0x6e, b'\x01') + telv(0x6f, b'\x25') + telv(0x75, b'\x01') +
           telv(0x7a, b'\x07'))
    add('PS-HANDOVER-REQUIRED', bytes([0x59]) + tlli_ie + telv(0x07, b'\x36') +
        telv(0x08, CELL_ID) + telv(0x08, RAI + b'\x00\x02') + telv(0x64, s2t) +
        telv(0x6c, RAI + b'\x00\x10') + telv(0x6a, b'\x01\x02\x03\x04') +
        telv(0x77, b'\x02\x05\x06') + telv(0x7f, TAI + GLOBAL_ENB_ID) +
        telv(0x83, b'\x01') + telv(0x85, b'\x00\x00\x01\x00\x01') +
        telv(0x86, TAI))
    t2s_si = telv(0x74, b'\x11\x22\x33') + telv(0x76, b'\x04' + bytes(21) + bytes(21)) + \
        telv(0x79, bytes(22))
    add('PS-HANDOVER-REQUIRED-ACK', bytes([0x5a]) + tlli_ie + telv(0x68, b'\x02\x05\x06') +
        telv(0x65, t2s_si) + telv(0x6b, b'\x0a\x0b\x0c'))
    add('PS-HANDOVER-REQUIRED-NACK', bytes([0x5b]) + tlli_ie + telv(0x07, b'\x42'))
    pfc_item = (b'\x05' + bytes.fromhex('290145') + QOS + b'\x00\x00' +
                b'\x45' + bytes.fromhex('290122'))
    add('PS-HANDOVER-REQUEST', bytes([0x5c]) + tlli_ie + imsi_ie + telv(0x07, b'\x36') +
        telv(0x08, CELL_ID) + telv(0x6c, RAI + b'\x00\x10') +
        telv(0x08, RAI + b'\x00\x02') + telv(0x64, s2t) +
        telv(0x67, b'\x01' + pfc_item) + telv(0x66, b'\x01\x02\x03\x04\x05') +
        telv(0x3d, b'\x02') + telv(0x81, b'\x05') + telv(0x83, b'\x01'))
    t2s_psi = telv(0x76, b'\x03' + bytes(22))
    add('PS-HANDOVER-REQUEST-ACK', bytes([0x5d]) + tlli_ie + telv(0x68, b'\x01\x05') +
        telv(0x65, t2s_psi))
    add('PS-HANDOVER-REQUEST-NACK', bytes([0x5e]) + tlli_ie + telv(0x07, b'\x3f'))
    add('PS-HANDOVER-COMPLETE', bytes([0x91]) + tlli_ie + imsi_ie +
        telv(0x08, CELL_ID) + telv(0x82, b'\x03'))
    add('PS-HANDOVER-CANCEL', bytes([0x92]) + tlli_ie + telv(0x07, b'\x2f') +
        telv(0x08, CELL_ID) + telv(0x08, RAI + b'\x00\x02') +
        telv(0x6c, RAI + b'\x00\x10') + telv(0x7f, TAI + GLOBAL_ENB_ID))
    add('PS-HANDOVER-COMPLETE-ACK', bytes([0x93]) + tlli_ie + telv(0x73, b'\x00') +
        telv(0x80, UE_EUTRA_CAP))
    # Source BSS to Target BSS container with E-UTRAN Inter RAT HO Info and a
    # downlink Global TFI; no PFCs to set up / active PFCs, reserved count
    s2t_b = (telv(0x13, MS_RAC) + telv(0x6f, b'\x35') + telv(0x80, UE_EUTRA_CAP))
    add('PS-HANDOVER-REQUIRED, DL TFI, no active PFC', bytes([0x59]) + tlli_ie +
        telv(0x07, b'\x36') + telv(0x08, CELL_ID) + telv(0x64, s2t_b) +
        telv(0x77, b'\x00'))
    add('PS-HANDOVER-REQUIRED-ACK, no PFC', bytes([0x5a]) + tlli_ie + telv(0x68, b'\x00'))
    add('PS-HANDOVER-REQUEST, no PFC to set up', bytes([0x5c]) + tlli_ie + imsi_ie +
        telv(0x07, b'\x36') + telv(0x67, b'\x00'))
    add('PS-HANDOVER-REQUEST, reserved PFC count', bytes([0x5c]) + tlli_ie + imsi_ie +
        telv(0x07, b'\x36') + telv(0x67, b'\x0c\x00\x00'))

    # 0x60 - 0x64 location services
    add('PERFORM-LOCATION-REQUEST', bytes([0x60]) + tlli_ie + imsi_ie +
        telv(0x0a, b'\x00\x00') + telv(0x04, b'\x00\x02') + telv(0x3e, b'\x00\x07') +
        telv(0x43, b'\x00') + telv(0x08, CELL_ID) + telv(0x49, b'\x1f') +
        telv(0x47, b'\x00') + telv(0x40, b'\x00\x80\x80\x00') + telv(0x41, b'\x00') +
        telv(0x42, b'\xff\x00') + telv(0x70, IMEI) + telv(0x7c, b'\x01\x00') +
        tlv(0x7b, b'\x00\x01') + telv(0x92, b'\x01') + telv(0x98, b'\x11') +
        telv(0x13, MS_RAC))
    add('PERFORM-LOCATION-RESPONSE', bytes([0x61]) + tlli_ie + bvci_ie +
        telv(0x44, bytes.fromhex('00' '123456' '123456')) +
        telv(0x45, b'\x00\x43') + telv(0x48, b'\x00') +
        telv(0x78, bytes.fromhex('00100010')) + telv(0x7d, b'\x01'))
    add('PERFORM-LOCATION-ABORT', bytes([0x62]) + tlli_ie + bvci_ie + telv(0x48, b'\x01'))
    add('POSITION-RESPONSE', bytes([0x64]) + tlli_ie + bvci_ie +
        telv(0x3f, b'\x06') + telv(0x48, b'\x00'))

    # 0x80 - 0x85 MBMS
    sess = telv(0x5d, b'\x09')
    # MBMS Routing Area List: one RAI, length 8 (the dissector reads the RAI
    # from the count octet and steps 8 octets, see README)
    ra_list = telv(0x61, bytes.fromhex('10f010000101') + b'\x00\x00')
    start = (tmgi + sess + telv(0x3a, QOS) + telv(0x5f, b'\x01\x00\x01\x00\x02') +
             ra_list + telv(0x5e, b'\x00\x00\x10') + telv(0x62, b'\x01') +
             telv(0x71, b'\x04') + telv(0x17, b'\x45') + telv(0x72, b'\x02'))
    add('MBMS-SESSION-START-REQUEST', bytes([0x80]) + start, bvci=0)
    add('MBMS-SESSION-START-RESPONSE', bytes([0x81]) + tmgi + sess + telv(0x60, b'\x01'), bvci=0)
    add('MBMS-SESSION-STOP-REQUEST', bytes([0x82]) + tmgi + sess + telv(0x63, b'\x01'), bvci=0)
    add('MBMS-SESSION-STOP-RESPONSE', bytes([0x83]) + tmgi + sess + telv(0x60, b'\x00'), bvci=0)
    add('MBMS-SESSION-UPDATE-REQUEST', bytes([0x84]) + start, bvci=0)
    add('MBMS-SESSION-UPDATE-RESPONSE', bytes([0x85]) + tmgi + sess + telv(0x60, b'\x02'), bvci=0)

    # RIM -------------------------------------------------------------------
    rim_rt_cell = telv(0x54, b'\x00' + CELL_ID)
    rim_rt_rnc = telv(0x54, b'\x01' + RAI + b'\x00\x10')
    rim_rt_enb = telv(0x54, b'\x02' + TAI + GLOBAL_ENB_ID)
    seq = telv(0x4c, b'\x00\x00\x00\x01')
    ver = telv(0x55, b'\x01')
    son_app = telv(0x84, b'\x00')

    def rim(app, ind=None, extra=b''):
        r = telv(0x4b, bytes([app])) + seq
        if ind is not None:
            r += telv(0x4f, bytes([ind]))
        return r + ver + extra

    # RAN-INFORMATION-REQUEST for NACC, SI3, MBMS data channel, UTRA SI
    add('RAN-INFORMATION-REQUEST NACC', bytes([0x71]) + rim_rt_cell + rim_rt_cell +
        telv(0x57, rim(1, 0x01, telv(0x4d, CELL_ID))), bvci=0)
    add('RAN-INFORMATION-REQUEST SI3', bytes([0x71]) + rim_rt_rnc + rim_rt_cell +
        telv(0x57, rim(2, 0x02, telv(0x4d, CELL_ID))), bvci=0)
    add('RAN-INFORMATION-REQUEST MBMS', bytes([0x71]) + rim_rt_enb + rim_rt_cell +
        telv(0x57, rim(3, 0x00, telv(0x4d, CELL_ID))), bvci=0)
    add('RAN-INFORMATION-REQUEST UTRA SI', bytes([0x71]) + rim_rt_rnc + rim_rt_cell +
        telv(0x57, rim(5, 0x01, telv(0x4d, SRC_CELL_GERAN))), bvci=0)
    add('RAN-INFORMATION-REQUEST SON (no app container)', bytes([0x71]) + rim_rt_enb +
        rim_rt_cell + telv(0x57, rim(4, 0x01, son_app)), bvci=0)

    # RAN-INFORMATION
    nacc_si = CELL_ID + bytes([(3 << 1) | 0]) + si3() + si1() + si13()
    add('RAN-INFORMATION NACC SI', bytes([0x70]) + rim_rt_cell + rim_rt_cell +
        telv(0x58, rim(1, 0x03, telv(0x4e, nacc_si))), bvci=0)
    nacc_psi = CELL_ID + bytes([(2 << 1) | 1]) + bytes(22) + bytes(22)
    add('RAN-INFORMATION NACC PSI', bytes([0x70]) + rim_rt_cell + rim_rt_cell +
        telv(0x58, rim(1, 0x02, telv(0x4e, nacc_psi))), bvci=0)
    # Reproducer: first SI item of an unknown message type (asserted)
    unk = CELL_ID + bytes([(2 << 1) | 0]) + bytes([0xff]) + bytes(20) + si3()
    add('RAN-INFORMATION NACC unknown SI (reproducer)', bytes([0x70]) + rim_rt_cell +
        rim_rt_cell + telv(0x58, telv(0x4b, b'\x01') + seq + telv(0x4f, b'\x02') +
                           telv(0x4e, unk)), bvci=0)
    add('RAN-INFORMATION SI3', bytes([0x70]) + rim_rt_cell + rim_rt_cell +
        telv(0x58, rim(2, 0x01, telv(0x4e, CELL_ID + si3()))), bvci=0)
    add('RAN-INFORMATION MBMS', bytes([0x70]) + rim_rt_cell + rim_rt_cell +
        telv(0x58, rim(3, 0x02, telv(0x4e, CELL_ID + b'\x01\x02\x03\x04') + son_app)), bvci=0)
    add('RAN-INFORMATION SON GERAN', bytes([0x70]) + rim_rt_enb + rim_rt_cell +
        telv(0x58, rim(4, 0x02, telv(0x4e, b'\x00' + CELL_ID) + son_app)), bvci=0)
    add('RAN-INFORMATION SON UTRAN', bytes([0x70]) + rim_rt_enb + rim_rt_cell +
        telv(0x58, rim(4, 0x04, telv(0x4e, b'\x01' + SRC_CELL_GERAN) + son_app)), bvci=0)
    add('RAN-INFORMATION SON reserved RAT', bytes([0x70]) + rim_rt_enb + rim_rt_cell +
        telv(0x58, rim(4, 0x02, telv(0x4e, b'\x03'))), bvci=0)
    add('RAN-INFORMATION SON E-UTRAN', bytes([0x70]) + rim_rt_enb + rim_rt_cell +
        telv(0x58, rim(4, 0x06, telv(0x4e, b'\x02' + GLOBAL_ENB_ID) + son_app)), bvci=0)
    add('RAN-INFORMATION UTRA SI End', bytes([0x70]) + rim_rt_rnc + rim_rt_cell +
        telv(0x58, rim(5, 0x08, telv(0x4e, SRC_CELL_GERAN))), bvci=0)
    add('RAN-INFORMATION UTRA SI Stop', bytes([0x70]) + rim_rt_rnc + rim_rt_cell +
        telv(0x58, rim(5, 0x00, telv(0x4e, SRC_CELL_GERAN))), bvci=0)
    # with an Application Error Container instead
    add('RAN-INFORMATION NACC app error', bytes([0x70]) + rim_rt_cell + rim_rt_cell +
        telv(0x58, rim(1, 0x01, telv(0x56, b'\x01' + telv(0x4e, CELL_ID)))), bvci=0)

    # RAN-INFORMATION-ACK
    add('RAN-INFORMATION-ACK', bytes([0x72]) + rim_rt_cell + rim_rt_cell +
        telv(0x5a, telv(0x4b, b'\x01') + seq + ver), bvci=0)
    add('RAN-INFORMATION-ACK SON', bytes([0x72]) + rim_rt_cell + rim_rt_enb +
        telv(0x5a, telv(0x4b, b'\x04') + seq + ver + son_app), bvci=0)
    # RAN-INFORMATION-ERROR
    add('RAN-INFORMATION-ERROR', bytes([0x73]) + rim_rt_cell + rim_rt_cell +
        telv(0x5b, telv(0x4b, b'\x01') + telv(0x07, b'\x2b') + ver +
             telv(0x15, b'\x71' + rim_rt_cell)), bvci=0)
    add('RAN-INFORMATION-ERROR SON', bytes([0x73]) + rim_rt_cell + rim_rt_enb +
        telv(0x5b, telv(0x4b, b'\x04') + telv(0x07, b'\x2c') +
             telv(0x15, b'\x71\x00') + son_app), bvci=0)
    # RAN-INFORMATION-APPLICATION-ERROR for every application
    for app, cont in ((1, b'\x02' + telv(0x4e, CELL_ID)),
                      (2, b'\x03' + telv(0x4e, CELL_ID)),
                      (3, b'\x04' + telv(0x4e, CELL_ID)),
                      (4, b'\x00' + telv(0x4e, b'\x00' + CELL_ID)),
                      (5, b'\x02')):
        extra = telv(0x56, cont) + (son_app if app == 4 else b'')
        add('RAN-INFORMATION-APPLICATION-ERROR app %d' % app, bytes([0x74]) +
            rim_rt_cell + rim_rt_cell + telv(0x58 + 1, rim(app, 0x01, extra)), bvci=0)

    # Reproducers of the fixes on the branch, as generated by
    # bssgp_small_fixes.py (1-3), bssgp_small_fixes2.py (2) and
    # bssgp_si_unknown_assert.py
    add('repro FLUSH-LL with NSEI', bytes([0x2a]) + tlli_ie + telv(0x04, b'\x00\x02') +
        telv(0x3e, b'\x12\x34'))
    add('repro SGSN-INVOKE-TRACE with OMC Id', bytes([0x40]) + telv(0x22, b'\x01') +
        telv(0x21, b'\x00\x01') + telv(0x14, b'OMC-ID-TEST') + telv(0x23, b'\xab\xcd'))
    add('repro PAGING-CS, TMSI after Channel Needed', bytes([0x07]) + imsi_ie +
        telv(0x0a, b'\x00\x00') + telv(0x09, b'\x00') +
        telv(0x20, bytes.fromhex('11223344')))
    add('repro SGSN-INVOKE-TRACE with Transaction Id', bytes([0x40]) + telv(0x22, b'\x01') +
        telv(0x21, b'\x00\x01') + telv(0x23, b'\xab\xcd'))
    si = bytes([0xff]) + bytes(20)
    app = CELL_ID + bytes([(1 << 1) | 0]) + si
    add('repro NACC unknown first SI item', bytes([0x70]) + rim_rt_cell + rim_rt_cell +
        telv(0x58, telv(0x4b, b'\x01') + seq + telv(0x4f, b'\x02') + telv(0x4e, app)))

    # NS over the second default port and a two octet length indicator
    add('BVC-UNBLOCK-ACK, UDP 19999, two octet length', bytes([0x25]) +
        telv2(0x04, b'\x00\x07'), bvci=0, port=19999)
    return P, note


def pdus_malformed():
    P = []
    note = []

    def add(desc, b, **kw):
        P.append((b, kw))
        note.append(desc)

    tlli_ie = telv(0x1f, TLLI)
    imsi_ie = telv(0x0d, IMSI)
    bvci_ie = telv(0x04, b'\x00\x02')
    rim_rt_cell = telv(0x54, b'\x00' + CELL_ID)
    seq = telv(0x4c, b'\x00\x00\x00\x01')
    son_app = telv(0x84, b'\x00')

    # Unknown message type (warning, stops)
    add('unknown PDU type 0xff', bytes([0xff, 0x01, 0x02]))
    # POSITION-COMMAND: RRLP Flags does not step over its value (README), so
    # the mandatory RRLP APDU is reported missing
    add('POSITION-COMMAND', bytes([0x63]) + tlli_ie + bvci_ie + telv(0x4a, b'\x01') +
        telv(0x3f, b'\x06'))
    add('POSITION-RESPONSE with RRLP Flags', bytes([0x64]) + tlli_ie + bvci_ie +
        telv(0x4a, b'\x00') + telv(0x3f, b'\x06'))
    # RAN-INFORMATION-REQUEST, SON Transfer application container: byte/bit
    # offset mix-up in de_bssgp_ran_information_request_app_cont()
    son_req = GLOBAL_ENB_ID + b'\x00\x00'
    add('RAN-INFORMATION-REQUEST SON app container', bytes([0x71]) + rim_rt_cell +
        rim_rt_cell + telv(0x57, telv(0x4b, b'\x04') + seq + telv(0x4f, b'\x02') +
                           telv(0x4d, son_req) + son_app))
    # Unknown RIM application identity in the three containers
    add('RAN-INFORMATION-REQUEST app 0', bytes([0x71]) + rim_rt_cell + rim_rt_cell +
        telv(0x57, telv(0x4b, b'\x00') + seq + telv(0x4f, b'\x02') +
             telv(0x4d, CELL_ID)))
    add('RAN-INFORMATION app 6', bytes([0x70]) + rim_rt_cell + rim_rt_cell +
        telv(0x58, telv(0x4b, b'\x06') + seq + telv(0x4f, b'\x02') +
             telv(0x4e, CELL_ID)))
    add('RAN-INFORMATION-APPLICATION-ERROR app 7', bytes([0x74]) + rim_rt_cell +
        rim_rt_cell + telv(0x59, telv(0x4b, b'\x07') + seq + telv(0x4f, b'\x01') +
                           telv(0x56, b'\x00\x01')))
    # Unknown RIM routing address discriminator
    add('RAN-INFORMATION-REQUEST routing discriminator 3', bytes([0x71]) +
        telv(0x54, b'\x03' + CELL_ID) + rim_rt_cell)
    # MBMS data channel report at the end of the PDU: the expert item is 2
    # octets too long
    add('RAN-INFORMATION MBMS at end', bytes([0x70]) + rim_rt_cell + rim_rt_cell +
        telv(0x58, telv(0x4b, b'\x03') + seq + telv(0x4f, b'\x02') +
             telv(0x4e, CELL_ID + b'\x01\x02\x03\x04')))
    # UTRA SI: the presence check compares a tvb offset with the length
    add('RAN-INFORMATION UTRA SI single report (repro bssgp_small_fixes2.py 3)',
        bytes([0x70]) + rim_rt_cell + rim_rt_cell +
        telv(0x58, telv(0x4b, b'\x05') + seq + telv(0x4f, b'\x02') +
             telv(0x4e, SRC_CELL_GERAN + b'\x01\x02\x03\x04')))
    add('RAN-INFORMATION UTRA SI long container', bytes([0x70]) + rim_rt_cell +
        rim_rt_cell + telv(0x58, telv(0x4b, b'\x05') + seq + telv(0x4f, b'\x02') +
                           telv(0x4e, SRC_CELL_GERAN + bytes(80))))
    # Reserved PFC counts in the lists that then return 0
    add('FLOW-CONTROL-PFC reserved count', bytes([0x2d]) + tlli_ie + telv(0x1e, b'\x01') +
        telv(0x52, b'\x0c'))
    add('PS-HANDOVER-REQUIRED-ACK reserved count', bytes([0x5a]) + tlli_ie +
        telv(0x68, b'\x0c'))
    add('PS-HANDOVER-REQUIRED reserved active PFC count', bytes([0x59]) + tlli_ie +
        telv(0x07, b'\x36') + telv(0x08, CELL_ID) + telv(0x77, b'\x0c'))
    # MBMS Routing Area List as specified (count + 8 octet RAI), (repro
    # bssgp_small_fixes.py 5 and bssgp_small_fixes2.py 1)
    add('MBMS-SESSION-START-REQUEST (repro small_fixes 5)', bytes([0x80]) +
        telv(0x5f, b'\x00\x01\x02') +
        telv(0x61, bytes([0x10]) + bytes.fromhex('00f110000101') + b'\x00\x00') +
        telv(0x5e, b'\x00\x00\x10'))
    add('MBMS-SESSION-START-REQUEST RA list only (repro small_fixes2 1)', bytes([0x80]) +
        telv(0x61, bytes([0x10]) + bytes.fromhex('00f110000101') + b'\x00\x00'))
    # PERFORM-LOCATION-RESPONSE (repro bssgp_small_fixes.py 4)
    add('PERFORM-LOCATION-RESPONSE (repro small_fixes 4)', bytes([0x61]) + tlli_ie +
        telv(0x04, b'\x00\x02') + telv(0x78, bytes.fromhex('00100010')) +
        telv(0x7d, b'\x01\x02\x03'))
    # Missing mandatory IEs at PDU level and inside containers
    add('BVC-BLOCK without Cause', bytes([0x20]) + bvci_ie)
    add('DL-UNITDATA without LLC-PDU', bytes([0x00]) + TLLI + b'\x00\x00\x01' +
        telv(0x16, b'\x00\x10'))
    add('RAN-INFORMATION empty RIM container', bytes([0x70]) + rim_rt_cell + rim_rt_cell +
        telv(0x58, b''))
    add('RAN-INFORMATION-ERROR container without PDU in Error', bytes([0x73]) +
        rim_rt_cell + rim_rt_cell + telv(0x5b, telv(0x4b, b'\x01') + telv(0x07, b'\x2b')))
    add('PS-HANDOVER-REQUIRED, S2T container without MS RAC', bytes([0x59]) + tlli_ie +
        telv(0x07, b'\x36') + telv(0x08, CELL_ID) + telv(0x64, telv(0x6d, b'\x00')))
    add('PS-HANDOVER-CANCEL without Cause', bytes([0x92]) + tlli_ie)
    add('PERFORM-LOCATION-REQUEST without MS RAC', bytes([0x60]) + tlli_ie + imsi_ie +
        bvci_ie + telv(0x3e, b'\x00\x07') + telv(0x43, b'\x00'))
    add('UL-UNITDATA extraneous data', bytes([0x01]) + TLLI + b'\x00\x00\x01' +
        telv(0x0e, LLC_GMM) + b'\xee\xee')
    # Truncated
    add('DL-UNITDATA truncated in TLLI', bytes([0x00, 0xc0, 0x00]))
    add('BVC-RESET truncated Cell Identifier', bytes([0x22]) + bvci_ie + telv(0x07, b'\x08') +
        bytes([0x08, 0x88]) + CELL_ID[:3])
    add('PDU In Error with length 0 data', bytes([0x41]) + telv(0x07, b'\x27') +
        telv(0x15, b''))
    add('QoS profile truncated', bytes([0x01]) + TLLI + b'\x01\x00')
    return P, note


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    P, _ = pdus_main()
    write_pcap(os.path.join(out, 'bssgp-coverage.pcap'), P)
    M, _ = pdus_malformed()
    write_pcap(os.path.join(out, 'bssgp-coverage-malformed.pcap'), M)


if __name__ == '__main__':
    main()
