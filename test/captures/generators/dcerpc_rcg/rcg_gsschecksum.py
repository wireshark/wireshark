#!/usr/bin/env python3
# Helper module for the dcerpc_rcg capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# RDPEAR / RCG CreateApReqAuthenticatorReq with a GssChecksum
# (KERB_ASN1_DATA_CHECKSUM) to exercise the hand-written
# rcg_dissect_element_KERB_ASN1_DATA_CHECKSUM_checksum_() in rcg.cnf.
# The checksum's Length field says 4 and its conformant count says 4, but
# the .cnf code ignores both and BER-parses a 36-byte Checksum, so the
# following KeyUsage-independent trailing data is mis-placed.
import struct
from rcg_rdpear_common import rdpear_frame, write_pcap, ber

class B:
    def __init__(s, n): s.b = bytearray(b'\0' * n)
    def a(s, n):
        while len(s.b) % n: s.b += b'\0'
    def u16(s, v): s.a(2); s.b += struct.pack('<H', v)
    def u32(s, v): s.a(4); s.b += struct.pack('<I', v)
    def u64(s, v): s.a(8); s.b += struct.pack('<Q', v)
    def raw(s, d): s.b += d

cks = ber(0x30, ber(0xa0, b'\x02\x03\x00\x80\x03') +
                ber(0xa1, ber(0x04, struct.pack('<I', 16) + b'\x11' * 16 + struct.pack('<I', 0x3e))))
b = B(40)                     # 16 reserved + 24 NDR header
b.u16(0x103); b.u16(0x103)    # CallId, union discriminant
for v in (0x20000, 7, 0x20004, 0x20008, 0x2000c, 0, 0, 0x20010, 11):
    b.u32(v)
# EncryptionKey -> reserved1, reserved2, octet string {length, value*}
b.u32(0); b.u32(0x17); b.u32(0); b.u32(0x20014)
b.u32(0)                      # value: conformant count 0
# ClientName -> NameType, NameCount, Names*
b.u16(1); b.u16(0); b.u32(0x20018)
b.u32(0)                      # Names: count 0
# ClientRealm -> Length, MaximumLength, Buffer*
b.u16(0); b.u16(0); b.u32(0x2001c)
b.u32(0); b.u32(0); b.u32(0)  # cvstring max, offset, actual
# SkewTime
b.u64(0x0102030405060708)
# GssChecksum -> Pdu, Length, checksum*
b.u32(0); b.u32(4); b.u32(0x20020)
b.u32(4); b.raw(cks)          # conformant count 4, then BER Checksum
b.raw(b'\xaa' * 8)
write_pcap('rcg_gsschecksum.pcap', [rdpear_frame('Kerberos', bytes(b.b))])
