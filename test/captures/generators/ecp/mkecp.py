#!/usr/bin/env python3
# Generates test/captures/ecp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the ECP21 and VDP21
dissectors (packet-ecp.c, Solaris ECP/VDP after IEEE 802.1Qbg draft
2.1).

ECP runs directly over Ethernet with ethertype 0x8940. A 16 bit header
(4 bit version, 2 bit operation, 10 bit subtype) and a sequence number
are followed, for subtype 1, by VDP TLVs (7 bit type, 9 bit length):
PreAssociate, PreAssociate with RR, Associate and DeAssociate (reason
or error and flags, VSI type ID and version, VSIID format and VSIID,
filter format with VID or MAC/VID), VSI Manager ID (16 octets) and
organizationally defined TLVs (Oracle VSI manager encoding). Other
subtypes go to the data dissector. Every packet is built from scratch
with struct; no captured traffic is used.

Usage: mkecp.py <output directory>

Writes:
  ecp-coverage.pcap            requests and ACKs, every VDP TLV type,
                               request and response flags, every filter
                               and VSIID format, Oracle TLVs, other
                               subtypes, padding
  ecp-coverage-malformed.pcap  Manager ID and organizationally defined
                               TLVs with a bad length (error expert
                               infos), TLVs cut short
"""

import os
import struct
import sys

MAC_STATION = bytes.fromhex('020000000011')
MAC_BRIDGE = bytes.fromhex('0180c2000000')
MAC_BR_SRC = bytes.fromhex('020000000022')
VM1 = bytes.fromhex('525400000001')
VM2 = bytes.fromhex('525400000002')


def pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)


def eth(payload, from_station=True, pad=True):
    src = MAC_STATION if from_station else MAC_BR_SRC
    fr = MAC_BRIDGE + src + struct.pack('>H', 0x8940) + payload
    if pad:
        fr += b'\0' * max(0, 60 - len(fr))
    return fr


def ecp(op, seq, payload, subtype=1, ver=1):
    return struct.pack('>HH', (ver << 12) | (op << 10) | subtype, seq) + payload


def tlv(t, body, length=None):
    if length is None:
        length = len(body)
    return struct.pack('>H', (t << 9) | (length & 0x1ff)) + body


def assoc(t, reason, filt, vsiid_fmt=5, vidstr=0x000a, mac=VM1,
          typeid=0x010203, ver=1):
    body = bytes([reason]) + struct.pack('>I', typeid)[1:] + bytes([ver, vsiid_fmt])
    body += bytes(range(0xa0, 0xb0)) + bytes([filt])
    if filt == 1:
        body += struct.pack('>H', vidstr)
    elif filt == 2:
        body += mac + struct.pack('>H', vidstr)
    elif filt in (3, 4):
        # GroupID/VID and GroupID/MAC/VID: not decoded, but in the TLV
        body += struct.pack('>I', 77) + (mac if filt == 4 else b'') + struct.pack('>H', vidstr)
    return tlv(t, body)


MGRID = tlv(5, bytes.fromhex('20010db8000000000000000000000001'))


def org(oui, payload):
    return tlv(0x7f, struct.pack('>I', oui)[1:] + payload)


def main_frames():
    F = []
    # 1: request: PreAssociate (no body), Associate with a VID filter
    #    (PS 1, PCP 3, VID 10), VSI Manager ID
    F.append(eth(ecp(0, 1, tlv(1, b'') + assoc(3, 0x00, 1, vidstr=0xb00a) + MGRID)))
    # 2: ACK: Associate response (bit 0x40) with error "Success", no flags
    F.append(eth(ecp(1, 1, assoc(3, 0x40, 1, vidstr=0xb00a)), False))
    # 3: request: PreAssociate with RR (body ignored), Associate with a
    #    MAC/VID filter, M-bit and S-bit set, reason 2
    F.append(eth(ecp(0, 2, tlv(2, b'\x01\x02') + assoc(3, 0x32, 2, vsiid_fmt=3, vidstr=0x7fff, mac=VM2))))
    # 4: ACK: hard error and keep flags, "Insufficient Resource"
    F.append(eth(ecp(1, 2, assoc(3, 0x72, 2, vsiid_fmt=3, vidstr=0x7fff, mac=VM2)), False))
    # 5: DeAssociate request and response in one PDU, IPv4 and IPv6 VSIID
    #    formats, GroupID/VID filter (not decoded)
    F.append(eth(ecp(0, 3, assoc(4, 0x01, 3, vsiid_fmt=1) + assoc(4, 0x45, 3, vsiid_fmt=2))))
    # 6: GroupID/MAC/VID and unknown filter formats, Local and unknown
    #    VSIID formats, errors 3, 4 and unknown error 0xf
    F.append(eth(ecp(1, 4, assoc(3, 0x43, 4, vsiid_fmt=4) + assoc(4, 0x44, 9, vsiid_fmt=0x77)
                     + assoc(3, 0x4f, 1, vsiid_fmt=0))))
    # 7: Oracle organizationally defined TLV: VSI manager subtype with
    #    the encoding oracle_vsi_v1, then an unknown encoding
    F.append(eth(ecp(0, 5, org(0x0003BA, b'\x01\x01') + org(0x0003BA, b'\x01\x07'))))
    # 8: Oracle TLV with an unknown subtype and an OUI other than Oracle
    #    (IEEE 802.1, not decoded further)
    F.append(eth(ecp(0, 6, org(0x0003BA, b'\x02\xff') + org(0x0080C2, b'\x02\x00\x00'))))
    # 9: unknown VDP TLV types 6 and 100 (data)
    F.append(eth(ecp(0, 7, tlv(6, b'\xde\xad') + tlv(100, b'\xbe\xef\x00\x01'))))
    # 10: TLV type 0 (padding) stops the TLVs, followed by more data
    F.append(eth(ecp(1, 7, MGRID + tlv(0, b'') + b'\x55' * 8), False))
    # 11: no padding, PDU ends exactly at the end of the frame
    F.append(eth(ecp(0, 8, assoc(3, 0x10, 2)), pad=False))
    # 12: subtype 2 (PECSP), not registered: data
    F.append(eth(ecp(0, 9, b'\x01\x02\x03\x04\x05\x06', subtype=2)))
    # 13: operations 2 and 3 (no SEQ/ACK in the Info column), version 0
    F.append(eth(ecp(2, 10, MGRID, ver=0)))
    F.append(eth(ecp(3, 11, MGRID, ver=15), False))
    # 15: only the ECP header (no VDP TLVs), sequence number 0xffff
    F.append(eth(ecp(1, 0xffff, b''), False, pad=False))
    # 16: maximum subtype 0x3ff, data
    F.append(eth(ecp(0, 12, b'\xaa' * 4, subtype=0x3ff)))
    # 17: Associate with the largest VSI type ID and version
    F.append(eth(ecp(0, 13, assoc(3, 0x0f, 1, vidstr=0xffff, typeid=0xffffff, ver=0xff))))
    return F


def malformed_frames():
    F = []
    # 1: VSI Manager ID with length 4 (error expert info)
    F.append(eth(ecp(0, 1, tlv(5, b'\x00' * 4))))
    # 2: organizationally defined TLV of 3 octets (OUI only; the fix
    #    requires 4 for OUI and subtype)
    F.append(eth(ecp(0, 2, org(0x0003BA, b'') + MGRID)))
    # 3: Oracle VSI manager subtype without the encoding octet (length 4;
    #    the fix requires 5)
    F.append(eth(ecp(0, 3, org(0x0003BA, b'\x01') + MGRID)))
    # 4: organizationally defined TLV of 2 octets
    F.append(eth(ecp(0, 4, tlv(0x7f, b'\x00\x03'))))
    # 5: Associate TLV cut in the VSIID
    F.append(eth(ecp(0, 5, assoc(3, 0, 2)[:12]), pad=False))
    # 6: unknown TLV whose length runs past the end
    F.append(eth(ecp(0, 6, tlv(6, b'\x01\x02', length=300)), pad=False))
    # 7: one octet after the header
    F.append(eth(ecp(0, 7, b'\x02'), pad=False))
    # 8: ECP header cut short
    F.append(eth(b'\x10', pad=False))
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcap(os.path.join(out, 'ecp-coverage.pcap'), main_frames())
    pcap(os.path.join(out, 'ecp-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()
