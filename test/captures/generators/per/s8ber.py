# Helper module for the per capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Shared helpers for group s8 reproducers (BER TLVs, Exported PDU pcap).
import struct

def tlv(tag, body):
    n = len(body)
    if n < 0x80:
        l = bytes([n])
    elif n < 0x100:
        l = bytes([0x81, n])
    else:
        l = bytes([0x82, n >> 8, n & 0xff])
    return bytes([tag]) + l + body

def oid(s):
    a = [int(x) for x in s.split('.')]
    out = bytes([a[0] * 40 + a[1]])
    for v in a[2:]:
        enc = [v & 0x7f]
        v >>= 7
        while v:
            enc.insert(0, 0x80 | (v & 0x7f))
            v >>= 7
        out += bytes(enc)
    return tlv(0x06, out)

def exp_pdu(name, payload):
    n = name.encode()
    pad = (4 - len(n) % 4) % 4
    return struct.pack('!HH', 12, len(n) + pad) + n + b'\0' * pad + \
        struct.pack('!HH', 0, 0) + payload

def write_pcap(fname, pkts, linktype=252):
    with open(fname, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, p in enumerate(pkts):
            f.write(struct.pack('<IIII', 1 + i, 0, len(p), len(p)) + p)
