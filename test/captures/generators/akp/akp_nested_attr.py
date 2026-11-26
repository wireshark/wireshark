#!/usr/bin/env python3
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# AKP (Exported PDU "akp_private_key"): PrivateKeyInfo whose attributes carry
# an id-ct-privateKeyInfo attribute holding another PrivateKeyInfo, nested
# deeply, to check that the OID-callback recursion is bounded.
import struct

def tlv(tag, body):
    n = len(body)
    if n < 0x80: l = bytes([n])
    elif n < 0x100: l = b'\x81' + bytes([n])
    elif n < 0x10000: l = b'\x82' + struct.pack('>H', n)
    else: l = b'\x83' + n.to_bytes(3, 'big')
    return bytes([tag]) + l + body

def oid(s):
    p = [int(x) for x in s.split('.')]
    out = bytes([p[0] * 40 + p[1]])
    for v in p[2:]:
        b = [v & 0x7f]; v >>= 7
        while v: b.insert(0, 0x80 | (v & 0x7f)); v >>= 7
        out += bytes(b)
    return tlv(0x06, out)

ALG = tlv(0x30, oid('1.2.840.113549.1.1.1') + b'\x05\x00')
def pki(attrs=b''):
    body = tlv(0x02, b'\x00') + ALG + tlv(0x04, b'\x01\x02\x03\x04')
    if attrs: body += tlv(0xa0, attrs)
    return tlv(0x30, body)

inner = pki()
for _ in range(400):
    attr = tlv(0x30, oid('1.2.840.113549.1.9.16.1.52') + tlv(0x31, inner))
    inner = pki(attr)

def exp_pdu(proto, payload):
    name = proto.encode(); pad = (4 - len(name) % 4) % 4
    return struct.pack('>HH', 12, len(name) + pad) + name + b'\0' * pad + struct.pack('>HH', 0, 0) + payload

d = exp_pdu('akp_private_key', inner)
with open('akp_nested_attr.pcap', 'wb') as f:
    f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 252))
    f.write(struct.pack('<IIII', 1700000000, 0, len(d), len(d)) + d)
