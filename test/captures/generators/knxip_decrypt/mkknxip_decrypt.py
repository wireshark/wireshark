#!/usr/bin/env python3
# Generates test/captures/knxip_decrypt_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the capture for packet-knxip_decrypt.c (the AES-CCM helpers of the KNX/IP Secure services).
Usage: mkknxip_decrypt.py <outdir>.  Writes knxip_decrypt-coverage.pcap and knxip_decrypt-coverage-malformed.pcap.

The frames carry placeholder bytes only: no key, MAC or ciphertext is computed. The dissector is
given made-up keys with -o kip.key_1:... so that it runs its decryption code, which fails the
MAC check for every frame. The decrypted-data paths (and the keyring file) are not reached."""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import struct
from _lib import Pcap

C, S = '192.0.2.10', '192.0.2.20'
MC = '224.0.23.12'
KP = 3671
u16 = lambda v: struct.pack('!H', v)

def hdr(svc, body=b'', hl=6, ver=0x10, total=None):
    return struct.pack('!BBHH', hl, ver, svc, (hl + len(body)) if total is None else total) + body

SER = b'\x00\x01\x02\x03\x04\x05'
def filler(n, k): return bytes((i * 5 + k) & 0xff for i in range(n))

def wrapper(sess, seq, tag, enc, hl=6):
    return hdr(0x0950, u16(sess) + seq.to_bytes(6, 'big') + SER + u16(tag) + enc, hl=hl)
def timer(ts, tag, mac, hl=6):
    return hdr(0x0955, ts.to_bytes(6, 'big') + SER + u16(tag) + mac, hl=hl)

def mk_main(path):
    p = Pcap()
    p.tcp(C, S, 52200, KP, b'', flags=0x02); p.tcp(S, C, KP, 52200, b'', flags=0x12); p.tcp(C, S, 52200, KP, b'', flags=0x10)
    # Secure wrappers: the encrypted part is the payload and a 16 octet MAC; every payload size
    # around the AES block size (0 octets = MAC only), UDP unicast, multicast and TCP
    for size in (0, 1, 15, 16, 17, 31, 32, 33, 47, 48, 64, 100, 255):
        enc = filler(size + 16, size)
        p.udp(C, S, 50010, KP, wrapper(1, size, 0x0001, enc))
        p.udp(C, MC, 50010, KP, wrapper(1, size + 1000, 0x0001, enc))
    for size in (0, 16, 33, 60):
        p.tcp(C, S, 52200, KP, wrapper(2, size, 0xf000, filler(size + 16, size + 1)))
        p.tcp(S, C, KP, 52200, wrapper(2, size + 50, 0xf001, filler(size + 16, size + 2)))
    p.udp(C, MC, 50010, KP, wrapper(0, 7, 0x0000, bytes(range(16))))
    # an embedded KNXnet/IP-looking packet inside the "ciphertext" (not decrypted: the MAC is wrong)
    p.udp(C, MC, 50010, KP, wrapper(3, 8, 0x0001, hdr(0x0208, bytes([1, 0])) + bytes(16)))
    # Timer notifications: the MAC is checked with every key
    for k in range(4):
        p.udp(C, MC, 50011, KP, timer(100 + k, k, filler(16, k)))
    p.udp(C, S, 50011, KP, timer(5, 7, bytes(16)))
    p.udp(C, S, 50011, KP, timer(6, 8, b'\xff' * 16))
    p.write(path)

def mk_mal(path):
    p = Pcap()
    # secure wrapper and timer notification cut short in every field
    full_w = wrapper(1, 1, 1, filler(32, 1))
    full_t = timer(1, 1, filler(16, 2))
    for full in (full_w, full_t):
        for n in range(6, len(full)):
            p.udp(C, MC, 50012, KP, hdr(struct.unpack('!H', full[2:4])[0], full[6:n]))
    # a wrapper with a header length of 7 and more: the leading, not encrypted data is longer
    p.udp(C, S, 50012, KP, wrapper(1, 1, 1, filler(40, 3), hl=7))
    p.udp(C, S, 50012, KP, timer(1, 1, filler(16, 4), hl=8))
    p.write(path)

if __name__ == '__main__':
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    mk_main(os.path.join(out, 'knxip_decrypt-coverage.pcap'))
    mk_mal(os.path.join(out, 'knxip_decrypt-coverage-malformed.pcap'))
