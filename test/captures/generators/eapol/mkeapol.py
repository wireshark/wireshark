#!/usr/bin/env python3
# Generates test/captures/eapol_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the EAPOL dissector
(packet-eapol.c, IEEE 802.1X).

EAPOL runs directly over Ethernet with ethertype 0x888E (and 0x88C7 for
802.11i pre-authentication), both registered by default. A frame has a
4 octet header (version, type, body length) and a body that the
"eapol.type" table hands to EAP, MKA or the EAPOL-Key code; EAPOL-Key
bodies go by descriptor type to the RC4 descriptor (in this file) or to
the 802.11 RSN and WPA key dissectors. Every packet is built from
scratch with struct; no captured traffic is used, and the key fields
hold made-up bytes, no real or derived keys.

Usage: mkeapol.py <output directory>

Writes:
  eapol-coverage.pcap            every version and packet type, EAP
                                 inside, the RC4 key descriptor without
                                 a key, with a key and with a key
                                 generated locally, RSN and WPA key
                                 descriptors, an unknown descriptor,
                                 MKA, announcements, pre-authentication
                                 and a body shorter than the frame
  eapol-coverage-malformed.pcap  header cut short, RC4 descriptor cut
                                 short, a key length beyond the frame
"""

import os
import struct
import sys

from pcaplib import eth, write_pcap  # noqa: E402

SUPP = bytes.fromhex('020000000011')
AUTH = bytes.fromhex('020000000022')
PAE = bytes.fromhex('0180c2000003')


def frame(eapol, to_supp=False, ethertype=0x888E, pad=True):
    src, dst = (AUTH, SUPP) if to_supp else (SUPP, PAE)
    fr = eth(eapol, ethertype, src, dst)
    if pad and len(fr) < 60:
        fr += b'\0' * (60 - len(fr))
    return fr


def eapol(version, ptype, body=b'', length=None):
    if length is None:
        length = len(body)
    return struct.pack('>BBH', version, ptype, length) + body


def eap(code, ident, body=b''):
    return struct.pack('>BBH', code, ident, 4 + len(body)) + body


def rc4_key(key_len, key=b'', index=0x81):
    return (bytes([1]) + struct.pack('>HQ', key_len, 7) + bytes(range(16))
            + bytes([index]) + b'\x5a' * 16 + key)


def rsn_key(desc, key_info, nonce_byte):
    body = bytes([desc]) + struct.pack('>HH', key_info, 16) + struct.pack('>Q', 1)
    body += bytes([nonce_byte]) * 32 + b'\0' * 16 + b'\0' * 8 + b'\0' * 8 + b'\0' * 16
    return body + struct.pack('>H', 0)


def mka_basic():
    # MKA basic parameter set: version 1, key server priority, flags and
    # body length, SCI, actor member ID and number, algorithm agility,
    # CAK name; then the ICV indicator with a made-up ICV
    cak_name = b'\x01' * 16
    body = b'\x02\x00\x00\x00\x00\x11\x00\x01'  # SCI
    body += b'\x11' * 12 + struct.pack('>I', 1) + bytes.fromhex('0080c201') + cak_name
    plen = len(body)
    bps = bytes([1, 0x10]) + struct.pack('>H', 0x8000 | 0x4000 | plen) + body
    icv = bytes([255, 0]) + struct.pack('>H', 16) + b'\x3c' * 16
    return bps + icv


def main_frames():
    F = []
    # 1: 802.1X-2001 Start
    F.append(frame(eapol(1, 1)))
    # 2-3: 802.1X-2004 EAP Request/Identity and Response/Identity
    F.append(frame(eapol(2, 0, eap(1, 1, b'\x01')), True))
    F.append(frame(eapol(2, 0, eap(2, 1, b'\x01user@example.org'))))
    # 4: EAP Success
    F.append(frame(eapol(2, 0, eap(3, 1)), True))
    # 5: RC4 key descriptor, key length 0 (no key)
    F.append(frame(eapol(1, 3, rc4_key(0)), True))
    # 6: RC4 key descriptor with a 13 octet key
    F.append(frame(eapol(1, 3, rc4_key(13, b'\xa5' * 13)), True))
    # 7: RC4 key descriptor with key length 5 and no key: generated locally
    F.append(frame(eapol(1, 3, rc4_key(5, index=0x02)), True))
    # 8: RSN key descriptor (802.11 dissector), 4-way handshake message 1
    F.append(frame(eapol(2, 3, rsn_key(2, 0x008a, 0x41)), True))
    # 9: WPA key descriptor (802.11 dissector)
    F.append(frame(eapol(1, 3, rsn_key(254, 0x0089, 0x42)), True))
    # 10: unknown key descriptor type 5: body as bytes
    F.append(frame(eapol(2, 3, b'\x05' + b'\x99' * 20), True))
    # 11: Encapsulated ASF Alert (no dissector: data)
    F.append(frame(eapol(2, 4, b'\x10\x11\x12\x13')))
    # 12: MKA (802.1X-2010)
    F.append(frame(eapol(3, 5, mka_basic())))
    # 13-15: announcements (generic, specific) and announcement request
    F.append(frame(eapol(3, 6, b'\x00\x01\x02\x03'), True))
    F.append(frame(eapol(3, 7, b'\x00\x01\x02\x03'), True))
    F.append(frame(eapol(3, 8)))
    # 16: unknown packet type 9 and unknown version 4
    F.append(frame(eapol(4, 9, b'\xde\xad')))
    # 17: 802.3 Logoff
    F.append(frame(eapol(3, 2)))
    # 18: pre-authentication (ethertype 0x88C7) Start, without padding
    F.append(frame(eapol(2, 1), ethertype=0x88C7, pad=False))
    # 19: body length 4 in a longer frame: the rest is Ethernet trailer
    F.append(frame(eapol(2, 0, eap(4, 2) + b'\0' * 8, length=4), True))
    return F


def malformed_frames():
    F = []
    # 1: 3 octets of header
    F.append(eth(b'\x02\x00\x00', 0x888E, SUPP, PAE))
    # 2: RC4 key descriptor cut short
    F.append(eth(eapol(1, 3, rc4_key(0)[:20], length=44), 0x888E, AUTH, SUPP))
    # 3: RC4 key length 32 but only 4 octets of key
    F.append(eth(eapol(1, 3, rc4_key(32, b'\x01\x02\x03\x04')), 0x888E, AUTH, SUPP))
    # 4: body length larger than the frame
    F.append(eth(eapol(2, 0, eap(1, 3, b'\x01'), length=200), 0x888E, AUTH, SUPP))
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'eapol-coverage.pcap'), main_frames())
    write_pcap(os.path.join(out, 'eapol-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()
