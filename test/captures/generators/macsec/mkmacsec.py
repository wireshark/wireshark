#!/usr/bin/env python3
# Generates test/captures/macsec_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic MACsec captures.  Usage: mkmacsec.py <outdir>
Writes macsec-coverage.pcap and macsec-coverage-malformed.pcap.
No keys, no real cryptography: the ICV is a constant placeholder and the
"encrypted" Secure Data is a placeholder pattern, so the frames never verify
and the decryption and ICV check code is not exercised."""
import os
import struct
import sys

SRC = bytes.fromhex('020000000001')
DST = bytes.fromhex('020000000002')
V, ES, SC, SCB, E, C = 0x80, 0x40, 0x20, 0x10, 0x08, 0x04
ICV = b'\xcc' * 16        # placeholder, not an ICV


def pcap(name, frames):
    with open(name, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)


def macsec(tci, an, sl, pn, data, icv=ICV, sci=None, trailer=b'', src=SRC, dst=DST, etype=0x88e5):
    hdr = bytes([tci | an, sl]) + struct.pack('>I', pn)
    if tci & SC:
        hdr += sci if sci is not None else SRC + struct.pack('>H', 1)
    return dst + src + struct.pack('>H', etype) + hdr + data + icv + trailer


def ipv4_udp(payload):
    udp = struct.pack('>HHHH', 4000, 61000, 8 + len(payload), 0) + payload
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
                     bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2]))
    return ip + udp


def plain(etype, body):
    """Secure Data of an integrity-only frame: the original EtherType + payload."""
    return struct.pack('>H', etype) + body


def build():
    main, bad = [], []
    f = main.append
    # integrity only (E=0, C=0), SCI present, short length: 2 + 20 + 8 + 10 = 40
    d = plain(0x0800, ipv4_udp(b'0123456789'))
    f(macsec(SC, 0, len(d), 1, d))
    # every association number
    for an in (1, 2, 3):
        f(macsec(SC, an, len(d), 10 + an, d))
    # ES set (system identifier from the source address), no SC; SCB too
    f(macsec(ES, 0, len(d), 20, d))
    f(macsec(ES | SCB, 1, len(d), 21, d))
    # neither SC nor ES (the Arista case: SCI unknown)
    f(macsec(0, 2, len(d), 22, d))
    # 47 is the largest short length; 0 means 48 or more (the length is taken from the frame)
    d47 = plain(0x0800, ipv4_udp(b'x' * 17))
    f(macsec(SC, 0, len(d47), 30, d47))
    d_long = plain(0x0800, ipv4_udp(b'long payload ' * 8))
    f(macsec(SC, 0, 0, 31, d_long))
    f(macsec(SC, 0, 0, 32, plain(0x0800, ipv4_udp(b'y' * 600))))
    # other inner EtherTypes
    arp = struct.pack('>HHBBH', 1, 0x0800, 6, 4, 1) + SRC + bytes([192, 0, 2, 1]) + bytes(6) + bytes([192, 0, 2, 2])
    f(macsec(SC, 0, 0, 40, plain(0x0806, arp)))
    src6 = b'\x20\x01\x0d\xb8' + bytes(11) + b'\x01'
    dst6 = b'\x20\x01\x0d\xb8' + bytes(11) + b'\x02'
    udp6 = struct.pack('>HHHH', 4000, 61000, 12, 0) + b'abcd'
    pseudo = src6 + dst6 + struct.pack('>IBBBB', len(udp6), 0, 0, 0, 17) + udp6
    total = sum(struct.unpack('>%dH' % (len(pseudo) // 2), pseudo))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    udp6 = udp6[:6] + struct.pack('>H', ~total & 0xffff) + udp6[8:]
    ip6 = struct.pack('>IHBB', 0x60000000, len(udp6), 17, 64) + src6 + dst6 + udp6
    f(macsec(SC, 0, 0, 41, plain(0x86dd, ip6)))
    f(macsec(SC, 0, 0, 42, plain(0x88cc, b'\x02\x07\x04' + SRC + b'\x04\x02\x07\x31' + b'\x06\x02\x00\x78' + b'\x00\x00' + bytes(10))))
    f(macsec(SC, 0, 0, 43, plain(0x8100, struct.pack('>HH', 5, 0x0800) + ipv4_udp(b'vlan tagged payload'))))
    f(macsec(SC, 0, 0, 44, plain(0x9999, b'unknown ethertype' + bytes(40))))
    # trailing bytes after the ICV (an Ethernet FCS/trailer: fcs_length path), short length set
    f(macsec(SC, 0, len(d), 50, d, trailer=b'\x01\x02\x03\x04'))
    # KaY frames: E set, C clear (note, no ICV); non-standard cipher: E clear, C set (note, no ICV)
    f(macsec(SC | E, 0, 0, 60, bytes(range(40)), icv=b''))
    f(macsec(SC | C, 0, 0, 61, bytes(range(40)), icv=b''))
    # E and C set: confidentiality.  Placeholder bytes as the Secure Data (no keys,
    # so the ICV is never verified and the data stays undecoded).
    f(macsec(SC | E | C, 0, 44, 70, b'\xa5' * 44))
    f(macsec(SC | E | C, 1, 0, 71, b'\x5a' * 100))
    f(macsec(ES | E | C, 2, 0, 72, b'\xa5' * 60))
    f(macsec(E | C, 3, 0, 73, b'\xa5' * 60))
    # Secure Data larger than MAX_PAYLOAD_LEN (1514)
    f(macsec(SC | E | C, 0, 0, 74, b'\x5a' * 1600))
    # the version bit set: not MACsec we know, left to the Ethernet dissector
    f(macsec(V | SC, 0, len(d), 80, d))
    # a frame with captured length not longer than SecTAG + ICV
    f(macsec(SC, 0, 0, 81, b'', icv=ICV[:15]))
    # another EtherType value in the Ethernet header (a custom MACsec EtherType)
    # is not reached here.

    # ---- malformed capture
    g = bad.append
    # integrity only with fewer than two bytes of Secure Data (the reproducers)
    g(macsec(SC, 1, 1, 100, b'\x08'))                        # short length 1
    g(macsec(SC, 0, 0, 101, b'\x08'))                        # short length 0, one byte
    g(macsec(ES, 0, 1, 102, b'\x08'))                        # no SCI
    # encrypted with a short length of 1 and placeholder data
    g(macsec(SC | E | C, 0, 1, 103, b'\xa5'))
    # short length longer than the data present
    g(macsec(SC, 0, 47, 104, d))
    # truncated in the SecTAG
    g(macsec(SC, 0, 10, 105, b'', icv=b'')[:14 + 8])
    g(macsec(SC | E | C, 0, 0, 106, b'\xa5' * 3, icv=b'')[:20])
    return main, bad


if __name__ == '__main__':
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    m, b = build()
    pcap(os.path.join(out, 'macsec-coverage.pcap'), m)
    pcap(os.path.join(out, 'macsec-coverage-malformed.pcap'), b)
