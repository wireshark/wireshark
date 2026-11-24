#!/usr/bin/env python3
# Generates test/captures/cisco_mcp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the Cisco Miscabling
Protocol dissector (packet-cisco-mcp.c).

MCP runs over IEEE 802.3 with LLC/SNAP, Cisco OUI 00:00:0c and PID
0x0139, to 01:00:0c:cc:cc:cd. The PDU is a plain sequence of 1 octet
type, 1 octet length TLVs. A PDU of exactly 62 octets is the original
(non-strict) format, where type 6 is the digest and type 7 the end; any
other length is taken as strict mode (ACI 5.2(4)), which adds type 6
(strict mode) and moves the digest and end to 7 and 8. Every packet is
built from scratch with struct; no captured traffic is used.

Usage: mkcisco-mcp.py <output directory>

Writes:
  cisco-mcp-coverage.pcap            non-strict and strict PDUs, VPC and
                                     non-VPC ports, unknown TLVs, every
                                     unexpected TLV length, trailing
                                     octets, the VPC Info reproducer
  cisco-mcp-coverage-malformed.pcap  TLVs past the end of the PDU, a
                                     single trailing octet (reproducer),
                                     PDUs cut short
"""

import os
import struct
import sys


def llc_frame(payload, src='020000000001'):
    llc = b'\xaa\xaa\x03' + b'\x00\x00\x0c' + struct.pack('>H', 0x0139) + payload
    return (bytes.fromhex('01000ccccccd') + bytes.fromhex(src)
            + struct.pack('>H', len(llc)) + llc)


def tlv(t, v):
    return struct.pack('>BB', t, len(v)) + v


def u32(v):
    return struct.pack('>I', v)


def ip(a):
    return bytes(a)


DIGEST = bytes(range(0xa0, 0xb4))   # 20 octets


def nonstrict(fabric=1, node=101, vpc=(0, 0, (0, 0, 0, 0)), port=0x1a000000,
              t=1700000000, digest=DIGEST):
    d, i, v = vpc
    pdu = (tlv(1, u32(fabric)) + tlv(2, u32(node)) + tlv(3, u32(d) + u32(i) + ip(v))
           + tlv(4, u32(port)) + tlv(5, u32(t)) + tlv(6, digest) + tlv(7, b''))
    assert len(pdu) == 62
    return pdu


def strict(fabric=1, node=101, vpc=(0, 0, (0, 0, 0, 0)), port=0x1a000000,
           t=1700000000, mode=1, digest=DIGEST, end=True):
    d, i, v = vpc
    pdu = (tlv(1, u32(fabric)) + tlv(2, u32(node)) + tlv(3, u32(d) + u32(i) + ip(v))
           + tlv(4, u32(port)) + tlv(5, u32(t)) + tlv(6, u32(mode)) + tlv(7, digest))
    if end:
        pdu += tlv(8, b'')
    return pdu


def pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)


def main_frames():
    p = []
    # 1-2: non-strict (62 octets): a non-VPC port and a VPC port
    p.append(nonstrict(fabric=1, node=101, port=0x1a000005, t=1700000000))
    p.append(nonstrict(fabric=2, node=102, vpc=(10, 20, (10, 0, 0, 1)),
                       port=0x1a010010, t=1700000060))
    # 3-4: strict (68 octets): a non-VPC port with strict mode 1, a VPC
    #      port with strict mode 0
    p.append(strict(fabric=1, node=201, port=0x1a000101, t=1700000120, mode=1))
    p.append(strict(fabric=1, node=202, vpc=(1000, 2000, (192, 0, 2, 77)),
                    port=0x1a000202, t=1700000180, mode=0))
    # 5: maximum values (strict)
    p.append(strict(fabric=0xffffffff, node=0xffffffff,
                    vpc=(0xffffffff, 0xffffffff, (255, 255, 255, 255)),
                    port=0xffffffff, t=0x7fffffff, mode=0xffffffff, digest=b'\xff' * 20))
    # 6: unknown TLV types (0, 9 and 255) before the end (strict)
    p.append(tlv(1, u32(1)) + tlv(0, b'\x01\x02') + tlv(9, b'') + tlv(255, b'unknown') + tlv(8, b''))
    # 7: no end TLV (strict): stops at the end of the PDU
    p.append(strict(node=207, end=False))
    # 8: reproducer mcp_vpc_len frame 1: a VPC Info TLV of length 2 is
    #    flagged and skipped; the Node ID after it is still read
    p.append(bytes([3, 2, 0xAA, 0xBB]) + tlv(2, u32(101)) + bytes([8, 0]))
    # 9: every other TLV with an unexpected length (strict): Fabric ID 2,
    #    Node ID 3, Port ID 5, Send Time 1, strict mode 0, digest 16, and
    #    an end TLV of length 1 followed by 2 trailing octets
    p.append(tlv(1, b'\x00\x01') + tlv(2, b'\x00\x00\x01') + tlv(4, b'\x00' * 5)
             + tlv(5, b'\x01') + tlv(6, b'') + tlv(7, DIGEST[:16])
             + tlv(8, b'\x00') + b'\xee\xee')
    # 10: non-strict TLVs with unexpected lengths: a 62 octet PDU of
    #     Fabric ID 1, Node ID 2, Port ID 3, Send Time 5, digest 30,
    #     end 3
    pdu = (tlv(1, b'\x01') + tlv(2, b'\x00\x02') + tlv(4, b'\x00\x00\x03')
           + tlv(5, b'\x00' * 5) + tlv(6, b'\x5a' * 30) + tlv(7, b'\x00' * 3))
    pdu += bytes(62 - len(pdu))
    assert len(pdu) == 62
    p.append(pdu)
    # 11: non-strict VPC Info of the wrong length (62 octets)
    pdu = tlv(3, b'\x00' * 8) + tlv(1, u32(5))
    pdu += tlv(9, bytes(62 - len(pdu) - 4)) + tlv(7, b'')
    assert len(pdu) == 62
    p.append(pdu)
    # 12: non-strict with octets after the end TLV (62 octets)
    pdu = tlv(1, u32(12)) + tlv(7, b'')
    pdu += b'\x00' * (62 - len(pdu))
    p.append(pdu)
    return [llc_frame(x) for x in p]


def malformed_frames():
    p = []
    # 1: reproducer mcp_vpc_len frame 2: one octet left after a TLV
    p.append(tlv(2, u32(101)) + b'\x09')
    # 2: a TLV length past the end of the PDU
    p.append(tlv(1, u32(1)) + bytes([2, 40]) + b'\x00\x00')
    # 3: a single octet PDU
    p.append(b'\x01')
    # 4: an empty PDU
    p.append(b'')
    # 5: a strict PDU cut in the digest (length runs past the end)
    p.append(strict()[:50])
    return [llc_frame(x) for x in p]


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcap(os.path.join(out, 'cisco-mcp-coverage.pcap'), main_frames())
    pcap(os.path.join(out, 'cisco-mcp-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()
