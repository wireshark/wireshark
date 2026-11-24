#!/usr/bin/env python3
# Generates test/captures/ecp_oui_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the ECP-OUI dissector
(packet-ecp-oui.c, ECP/VDP after IEEE 802.1Qbg draft 0).

This ECP is carried in the IEEE 802a OUI Extended Ethertype (0x88B7)
with OUI 00:1B:3F (IEEE 802.1Qbg) and protocol ID 0x0000. After a
subtype, mode and sequence number come LLDP style TLVs (7 bit type, 9
bit length): organizationally specific VDP TLVs (type 127) with a
mode, response, manager ID, VSI type ID and version, VSI instance ID
and a filter info format followed, for formats 1 and 2, by MAC/VID
pairs; an End of VDPDU TLV (type 0); anything else is an unknown TLV
that ends the PDU. Every packet is built from scratch with struct; no
captured traffic is used.

Usage: mkecp_oui.py <output directory>

Writes:
  ecp-oui-coverage.pcap            requests and ACKs, every VDP mode,
                                   response and filter format, OUIs
                                   with and without a manufacturer
                                   name, End of VDPDU and unknown TLVs
  ecp-oui-coverage-malformed.pcap  a TLV header cut to one octet, a VDP
                                   TLV and MAC/VID pairs cut short
"""

import os
import struct
import sys

MAC_STATION = bytes.fromhex('020000000011')
MAC_BRIDGE = bytes.fromhex('0180c2000000')
MAC_BR_SRC = bytes.fromhex('020000000022')


def pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)


def eth(payload, from_station=True):
    src = MAC_STATION if from_station else MAC_BR_SRC
    fr = MAC_BRIDGE + src + struct.pack('>H', 0x88B7) + payload
    return fr + b'\0' * max(0, 60 - len(fr))


def ieee802a(payload, oui=0x001B3F, pid=0):
    return struct.pack('>I', oui)[1:] + struct.pack('>H', pid) + payload


def tlv(t, body, length=None):
    if length is None:
        length = len(body)
    return struct.pack('>H', (t << 9) | (length & 0x1ff)) + body


def ecp(mode, seq, tlvs, subtype=0):
    return struct.pack('>BBH', subtype, mode, seq) + b''.join(tlvs)


def vdp(mode, resp, fmt, pairs=(), oui=0x001B3F, sub=2, mgrid=1,
        typeid=0x123456, ver=1, extra=b'', length=None):
    body = struct.pack('>I', oui)[1:] + bytes([sub, mode, resp, mgrid])
    body += struct.pack('>I', typeid)[1:] + bytes([ver])
    body += bytes(range(0x10, 0x20)) + bytes([fmt])
    if fmt in (1, 2):
        body += struct.pack('>H', len(pairs))
        for mac, vid in pairs:
            body += mac + struct.pack('>H', vid)
    body += extra
    return tlv(0x7f, body, length)


END = tlv(0, b'')
VM1 = bytes.fromhex('525400000001')
VM2 = bytes.fromhex('525400000002')
VM3 = bytes.fromhex('525400000003')


def main_frames():
    F = []
    # 1: Pre-Associate request, one MAC/VID pair, End of VDPDU
    F.append(eth(ieee802a(ecp(0, 1, [vdp(0, 0, 2, [(VM1, 10)]), END]))))
    # 2: its ACK, response success
    F.append(eth(ieee802a(ecp(1, 1, [vdp(0, 0, 2, [(VM1, 10)]), END])), False))
    # 3: Pre-Associate with resource reservation, format 1 (VID values,
    #    read as MAC/VID pairs), three pairs
    F.append(eth(ieee802a(ecp(0, 2, [vdp(1, 0, 1, [(VM1, 10), (VM2, 20), (VM3, 4095)]), END]))))
    # 4: ACK with response "insufficient resources"
    F.append(eth(ieee802a(ecp(1, 2, [vdp(1, 2, 1, [(VM1, 10)]), END])), False))
    # 5: Associate with no pairs, then De-Associate in the same PDU
    F.append(eth(ieee802a(ecp(0, 3, [vdp(2, 0, 2, []), vdp(3, 0, 2, [(VM2, 20)]), END]))))
    # 6: ACK with responses "invalid format" and "unused VTID"
    F.append(eth(ieee802a(ecp(1, 3, [vdp(2, 1, 2, []), vdp(3, 3, 2, [(VM2, 20)]), END])), False))
    # 7: filter format 3 (GROUPID/VID) and 4 (GROUPID/MAC/VID), not
    #    decoded, with responses "VTID violation" and "VTID version
    #    violation"
    F.append(eth(ieee802a(ecp(1, 4, [vdp(2, 4, 3), vdp(2, 5, 4), END])), False))
    # 8: unknown filter format, unknown mode and response "out of sync"
    #    and an unknown response 7
    F.append(eth(ieee802a(ecp(1, 5, [vdp(9, 6, 0x77), vdp(2, 7, 0), END])), False))
    # 9: VDP TLV with the 802.1Qbg OUI and the EVB and CDCP subtypes and
    #    an unknown one
    F.append(eth(ieee802a(ecp(0, 6, [vdp(0, 0, 3, sub=0), vdp(0, 0, 3, sub=1),
                                    vdp(0, 0, 3, sub=9), END]))))
    # 10: other OUIs: IEEE 802.1 (00:80:C2, known manufacturer name) and an
    #     unassigned one (FF:FF:FE): subtype "Unknown"
    F.append(eth(ieee802a(ecp(0, 7, [vdp(2, 0, 3, oui=0x0080C2), vdp(2, 0, 3, oui=0xFFFFFE), END]))))
    # 11: unknown TLV type 5 ends the PDU (the following End is not read)
    F.append(eth(ieee802a(ecp(0, 8, [vdp(2, 0, 2, [(VM1, 1)]), tlv(5, b'\x01\x02\x03'), END]))))
    # 12: no End of VDPDU: the PDU ends at the end of the frame
    #     (no Ethernet padding: frame of exactly 60 octets)
    body = ecp(0, 9, [vdp(2, 0, 2, [(VM1, 2)])])
    F.append(MAC_BRIDGE + MAC_STATION + struct.pack('>H', 0x88B7) + ieee802a(body))
    # 13: only the ECP header, unknown subtype 1 and mode 2
    F.append(eth(ieee802a(ecp(2, 10, [], subtype=1))))
    # 14: End of VDPDU with a length of 4
    F.append(eth(ieee802a(ecp(1, 10, [tlv(0, b'\0\0\0\0')]))))
    # 15: sequence number 0xffff, maximum VSI type ID and version, 50 pairs
    pairs = [(bytes([0x52, 0x54, 0, 0, 1, k]), 100 + k) for k in range(50)]
    F.append(eth(ieee802a(ecp(0, 0xffff, [vdp(2, 0, 2, pairs, mgrid=0xff,
                                              typeid=0xffffff, ver=0xff), END]))))
    return F


def malformed_frames():
    F = []
    # 1: one octet left after a VDP TLV: the TLV header read throws
    body = ecp(0, 1, [vdp(2, 0, 2, [(VM1, 1)])]) + b'\x00'
    F.append(MAC_BRIDGE + MAC_STATION + struct.pack('>H', 0x88B7) + ieee802a(body))
    # 2: VDP TLV cut in the VSI instance ID
    body = ecp(0, 2, [vdp(2, 0, 2, [(VM1, 1)])])[:20]
    F.append(MAC_BRIDGE + MAC_STATION + struct.pack('>H', 0x88B7) + ieee802a(body))
    # 3: 1000 MAC/VID pairs announced, two present
    v = bytearray(vdp(2, 0, 2, [(VM1, 1), (VM2, 2)]))
    v[-18:-16] = struct.pack('>H', 1000)
    F.append(MAC_BRIDGE + MAC_STATION + struct.pack('>H', 0x88B7) + ieee802a(ecp(0, 3, [bytes(v)])))
    # 4: ECP header cut short
    F.append(MAC_BRIDGE + MAC_STATION + struct.pack('>H', 0x88B7) + ieee802a(b'\x00\x00'))
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcap(os.path.join(out, 'ecp-oui-coverage.pcap'), main_frames())
    pcap(os.path.join(out, 'ecp-oui-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()
